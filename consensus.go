package panarchy

import (
	"errors"
	"math/big"
	"time"
	"fmt"
	"bytes"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params/mutations"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/crypto"

	"golang.org/x/crypto/sha3"
)

var (
	errInvalidTimestamp = errors.New("invalid timestamp")
	errMissingExtraData = errors.New("extra-data length is wrong")
)

func (p *Panarchy) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return p.verifyHeader(chain, header)
}
func (p *Panarchy) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for _, header := range headers {
			err := p.verifyHeader(chain, header)

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}
func (p *Panarchy) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)

	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+p.config.Period > header.Time {
		return errInvalidTimestamp
	}
	if header.GasLimit > vars.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, vars.MaxGasLimit)
	}
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	return nil
}

func (p *Panarchy) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	return nil
}

func (p *Panarchy) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {

	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = parent.Time + p.config.Period
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}
	header.Difficulty = common.Big1
	return nil
}

func (p *Panarchy) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal) {
	if err := p.blockValidator(chain, header, state); err != nil {
		header.GasUsed=0
		log.Error("Error in Finalize. Will now force ValidateState to fail by altering block.Header.GasUsed")
	}
	mutations.AccumulateRewards(chain.Config(), state, header, uncles)
}

func (p *Panarchy) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {

	if len(withdrawals) > 0 {
		return nil, errors.New("panarchy does not support withdrawals")
	}
	if err := p.blockProducer(chain, header, state); err != nil {
		return nil, err
	}
	mutations.AccumulateRewards(chain.Config(), state, header, uncles)
	header.Root = state.IntermediateRoot(true)
	return types.NewBlock(header, txs, uncles, receipts, trie.NewStackTrie(nil)), nil
}

func (p *Panarchy) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	
	go func() {
		header := block.Header()
		parentHeader := chain.GetHeaderByHash(header.ParentHash)
		delay := time.Unix(int64(header.Time), 0).Sub(time.Now())
		i := big.NewInt(0)
		loop:
		for {
			select {
			case <-stop:
				return
			case <-time.After(delay):
				validator := p.getValidator(parentHeader, i);
				if validator == p.signer {
					break loop
				}
				i.Add(i, common.Big1)
				delay += time.Duration(p.config.Deadline) * time.Second
			}
		}
		header.Difficulty.Sub(header.Difficulty, i)

		headerRlp := new(bytes.Buffer)
		if err := rlp.Encode(headerRlp, header); err != nil {
			log.Error("failed to RLP encode header during Seal method: %v", err)
		}

		sig, err := p.signFn(accounts.Account{Address: p.signer}, "", headerRlp.Bytes())
		if err != nil {
			log.Error("failed to sign the header for account %s: %v", p.signer.Hex(), err)
		}
		header.Extra = append(header.Extra, sig...)

		select {
			case results <- block.WithSeal(header):
			default:
				log.Warn("Sealing result is not read by miner")
		}
	}()

	return nil
}

func (p *Panarchy) SealHash(header *types.Header) (hash common.Hash) {

	sealHeader := *header
	sealHeader.Difficulty = nil

	if len(sealHeader.Extra) == 129 { 
		sealHeader.Extra = sealHeader.Extra[:64]
	}
	return SealHash(&sealHeader)
}

func SealHash(sealHeader *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

	if err := rlp.Encode(hasher, sealHeader); err != nil {
		panic("can't encode: " + err.Error())
	}
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

func (p *Panarchy) Author(header *types.Header) (common.Address, error) {
	if len(header.Extra) != 129 {
		return common.Address{}, errMissingExtraData
	}
	signature := header.Extra[64:]
	sealHeader := *header
	sealHeader.Extra = header.Extra[:64]

	pubkey, err := crypto.Ecrecover(SealHash(&sealHeader).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	return signer, nil
}

func (p *Panarchy) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return nil
}
func (p *Panarchy) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{}
}
func (p *Panarchy) Close() error {
	return nil
}
