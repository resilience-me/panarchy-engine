package panarchy

import (
	"math/big"
	"sync"
	"fmt"
	"encoding/binary"
	"os"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/trie/triestate"
	"github.com/ethereum/go-ethereum/log"
)
const (
	compensateForPossibleReorg = 20
)

type StorageSlots struct {
	election []byte
	hashOnion []byte
	validSince []byte
}
type Schedule struct {
	genesis uint64
	period uint64
}
type ValidatorContract struct {
	slots StorageSlots
	addr common.Address
	schedule Schedule
}

type HashOnion struct {
	Root common.Hash `json:"root"`
	Layers int `json:"layers"`
}

type Panarchy struct {
	config	*ctypes.PanarchyConfig
	contract ValidatorContract
	hashOnion HashOnion
	lock sync.RWMutex
	signer common.Address
	signFn SignerFn
	state *state.StateDB
}

type OnionStored struct {
    Hash	common.Hash
    ValidSince	*big.Int
}

func pad(val []byte) []byte {
	return common.LeftPadBytes(val, 32)
}
func weeksToSeconds(weeks uint64) uint64 {
	return weeks*7*24*60*60
}

type SignerFn func(signer accounts.Account, mimeType string, message []byte) ([]byte, error)

func New(config *ctypes.PanarchyConfig, db ethdb.Database) *Panarchy {
	return &Panarchy{
		config: config,
		contract: ValidatorContract{
			slots: StorageSlots{
				election: pad([]byte{2}),
				hashOnion: pad([]byte{3}),
				validSince: pad([]byte{4}),
			},
			addr: common.HexToAddress("0x0000000000000000000000000000000000000020"),
			schedule: Schedule {
				genesis: 1709960400,
				period: weeksToSeconds(4),
			},
		},
	}
}

func (p *Panarchy) blockValidator(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {

	p.state = state
	signer, err := p.Author(header)
	if err != nil {
		return err
	}
	
	parentHeader := chain.GetHeaderByHash(header.ParentHash)
	if len(header.Extra) != 129 {
	        return errMissingExtraData
	}
	parentTrieRoot := common.BytesToHash(parentHeader.Extra[: 32])

	trie, err := p.state.Database().OpenTrie(parentTrieRoot)
	if err != nil {
		return fmt.Errorf("Failed to open trie: %v", err)
	}

	onion, err := p.hashOnionFromStorageOrNew(signer, header.Number, trie)
	if err != nil {
		return err
	}

	preimage := common.BytesToHash(header.Extra[32: 64])
	hash := crypto.Keccak256Hash(preimage.Bytes())
	if hash != onion.Hash {
		return fmt.Errorf("block rng hash not valid")
	}
	onion.Hash = preimage

	newTrieRoot, err := p.updateAndCloseTrie(signer, onion, header.Number.Uint64(), parentTrieRoot, trie)

	if err != nil {
		return err
	}
	signedTrieRoot := common.BytesToHash(header.Extra[: 32])

	if signedTrieRoot != newTrieRoot {
		return fmt.Errorf("The RNG trie root is not valid")
	}
	skipped := new(big.Int).Sub(common.Big1, parentHeader.Difficulty)
	if signer != p.getValidator(header, skipped) {
		return fmt.Errorf("Validator is not elected to sign the block")
	}
	return nil
}

func (p *Panarchy) blockProducer(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {

	p.state = state
	signer := p.signer

	parentHeader := chain.GetHeaderByHash(header.ParentHash)
	if len(parentHeader.Extra) != 129 {
	        return errMissingExtraData
	}
	trieRoot := common.BytesToHash(parentHeader.Extra[: 32])

	trie, err := state.Database().OpenTrie(trieRoot)
	if err != nil {
		return fmt.Errorf("Failed to open trie: %v", err)
	}
	onion, err := p.hashOnionFromStorageOrNew(signer, header.Number, trie)
	if err != nil {
		return err
	}

	if err := p.getHashOnionPreimage(onion); err != nil {
		return err
	}

	newTrieRoot, err := p.updateAndCloseTrie(signer, onion, header.Number.Uint64(), trieRoot, trie)

	if err != nil {
		return err
	}

	header.Extra = make([]byte, 129)
	copy(header.Extra[:32], newTrieRoot.Bytes())
	copy(header.Extra[32:64], onion.Hash.Bytes())

	return nil
}

func (p *Panarchy) hashOnionFromStorageOrNew(signer common.Address, blockNumber *big.Int, trie state.Trie) (*OnionStored, error) {

	addrAndSlot := append(pad(signer.Bytes()), p.contract.slots.validSince...)
	key := crypto.Keccak256Hash(addrAndSlot)
	data := p.state.GetState(p.contract.addr, key)
	validSince := new(big.Int).SetBytes(data.Bytes())

	if validSince == common.Big0 {
		return nil, fmt.Errorf("no registered hash onion in validator contract")
	}
	value, err := trie.GetStorage(common.Address{}, signer.Bytes())

	if err != nil {
		return nil, fmt.Errorf("get hash onion failed: %w", err)
	}
	var onion OnionStored
	if len(value) != 0 {

		if err := rlp.DecodeBytes(value, &onion); err != nil {
			return nil, fmt.Errorf("decode hash onion failed: %w", err)
		}
	} else {
		onion = OnionStored{}
	}

	if blockNumber.Cmp(validSince) >= 0 {
		if onion.ValidSince == nil || onion.ValidSince.Cmp(validSince) < 0 {

			addrAndSlot := append(pad(signer.Bytes()), p.contract.slots.hashOnion...)
			key := crypto.Keccak256Hash(addrAndSlot)
			onion.Hash = p.state.GetState(p.contract.addr, key)
			onion.ValidSince = validSince
		}
	}

	return &onion, nil
}

func (p *Panarchy) getHashOnionPreimage(onion *OnionStored) error {

	preimage := p.hashOnion.Root.Bytes()
	for i := 0; i < p.hashOnion.Layers-1; i++ {
		preimage = crypto.Keccak256(preimage)
	}
	var hash []byte

	for i := 0; i < compensateForPossibleReorg; i++ {
		hash = crypto.Keccak256(preimage)

		if onion.Hash == common.BytesToHash(hash) {
			onion.Hash = common.BytesToHash(preimage)
			if i == 0 {
				p.hashOnion.Layers--
				if err := p.WriteHashOnion(); err != nil {
					return fmt.Errorf("Unable to update %s", p.config.HashOnionFilePath)
				}
			}
			return nil
		}
		preimage = hash
	}
	return fmt.Errorf("Validator hash onion cannot be verified")
}

func (p *Panarchy) updateAndCloseTrie(signer common.Address, onion *OnionStored, blockNumber uint64, trieRoot common.Hash, trie state.Trie) (common.Hash, error) {

	encoded, err := rlp.EncodeToBytes(onion)
	if err != nil {
		return common.Hash{}, fmt.Errorf("Error encoding hashOnion:", err)
	}
	if err := trie.UpdateStorage(common.Address{}, signer.Bytes(), encoded); err != nil {
		return common.Hash{}, fmt.Errorf("update hash onion storage failed: %w", err)
	}
	newTrieRoot, nodes, err := trie.Commit(false)

	if err != nil {
		return common.Hash{}, fmt.Errorf("Commit trie failed", err)
	}

	triedb := p.state.Database().TrieDB()
	mergedNodes := trienode.NewWithNodeSet(nodes)
	if err := triedb.Update(newTrieRoot, trieRoot, blockNumber, mergedNodes, &triestate.Set{}); err != nil {
		return common.Hash{}, fmt.Errorf("Failed to store tree to database", err)
	}
	if err := triedb.Commit(newTrieRoot, false); err != nil {
		return common.Hash{}, fmt.Errorf("Failed to commit tree to database", err)
	}

	return newTrieRoot, nil
}

func (p *Panarchy) getValidator(header *types.Header, skipped *big.Int) common.Address {

	schedule := ((header.Time - p.contract.schedule.genesis) / p.contract.schedule.period)

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, schedule)
	index := pad(buf)

	trieRoot := common.BytesToHash(header.Extra[: 32])

	random := new(big.Int).SetBytes(trieRoot.Bytes())
	random.Add(random, skipped)

	slot := p.contract.slots.election
	lengthKey := crypto.Keccak256Hash(append(index, slot...))
	electionLength := p.state.GetState(p.contract.addr, lengthKey)

	modulus := new(big.Int).SetBytes(electionLength.Bytes())
	random.Mod(random, modulus)
	
	key := new(big.Int).SetBytes(crypto.Keccak256(crypto.Keccak256(append(index, slot...))))
	key.Add(key, random)

	validator := p.state.GetState(p.contract.addr, common.BytesToHash(key.Bytes()))
	return common.BytesToAddress(validator.Bytes())
}

func (p *Panarchy) LoadHashOnion() error {
	filePath := p.config.HashOnionFilePath
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %v, hashOnionFilePath: %v", err, filePath)
	}
	defer file.Close()
	
	err = json.NewDecoder(file).Decode(&p.hashOnion)
	if err != nil {
		return fmt.Errorf("error decoding JSON: %v", err)
	}
	return nil
}

func (p *Panarchy) WriteHashOnion() error {
    filePath := p.config.HashOnionFilePath
    file, err := os.Create(filePath)
    if err != nil {
        return fmt.Errorf("error creating file: %v, hashOnionFilePath: %v", err, filePath)
    }
    defer file.Close()

    err = json.NewEncoder(file).Encode(p.hashOnion)
    if err != nil {
        return fmt.Errorf("error encoding hashOnion to JSON: %v", err)
    }

    return nil
}

func (p *Panarchy) Authorize(signer common.Address, signFn SignerFn) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.signer = signer
	p.signFn = signFn
	if err := p.LoadHashOnion(); err != nil {
		log.Error("LoadHashOnion error:", err)
	}
}
