contract BitPeople {
    function schedule() public view returns(uint) { }
    mapping (uint => mapping (address => bool)) public proofOfUniqueHuman;
}

contract Engine {

    address bitPeopleContract;
    BitPeople bitPeople = BitPeople(bitPeopleContract);

    function schedule() internal view returns (uint) { return bitPeople.schedule(); }

    mapping (uint => address[]) election;

    mapping(address => bytes32) hashOnion;
    mapping(address => uint) validSince;

    mapping (uint => mapping (address => bool)) suffrageToken;

    mapping (uint => mapping (address => uint)) public balanceOf;
    mapping (uint => mapping (address => mapping (address => uint))) public allowed;

    function vote(address _validator) public {
        uint t = schedule();
        require(balanceOf[t][msg.sender] >= 1);
        balanceOf[t][msg.sender]--;
        election[t+2].push(_validator);
    }

    function allocateSuffrageToken() public {
        uint t = schedule();
        require(bitPeople.proofOfUniqueHuman(t, msg.sender));
        require(!suffrageToken[t][msg.sender]);
        balanceOf[t][msg.sender]++;
        suffrageToken[t][msg.sender] = true;
    }
    function newHashOnion(bytes32 _hashRoot) public {
        hashOnion[msg.sender] = _hashRoot;
        validSince[msg.sender] = schedule()+2;
    }
}
