pragma solidity ^0.5.8;
pragma experimental ABIEncoderV2;

import "./EC.sol";
import "./Utils.sol";
import "./SafeMath.sol";

contract KeepingContract {
  uint256 constant public KEY_CLAIM_PERIOD = 1 hours;

  event KeysNeeded();

  address public owner = msg.sender;

  modifier ownerOnly() {
    require(msg.sender == owner);
    _;
  }

  enum State {
    CallForKeepers,
    Active,
    CallForKeys,
    Cancelled
  }

  State public state = State.CallForKeepers;

  modifier atState(State state_) {
    require(state == state_);
    _;
  }

  uint256 public minStake;
  uint256 public checkInInterval;
  uint256 public lastOwnerCheckInAt;
  uint256 public lastOwnerPaymentAt;

  struct Keeper {
    bytes publicKey; // 64-byte
    uint256 stake;
    uint256 distributedStake;
    uint256 keepingFee;
    uint256 balance;
    uint256 lastCheckInAt;
    uint256 totalClaimers;
    uint256 keyClaimedAt;
    uint256 privateKey;
  }

  mapping(address => Keeper) public keepers;
  address[] public keeperAddresses;

  enum ClaimerState {
    None,
    StakeClaimed,
    StakeReceived
  }

  mapping(uint256 => mapping(address => ClaimerState)) claimerState;

  struct EncryptedData {
    bytes encryptedData;
    bytes16 aesCounter;
    bytes32 dataHash; // sha-3 hash
    uint16 shareLength;
  }

  EncryptedData public data;
  bytes[] public encryptedKeyParts;

  constructor(
    uint256 minStake_,
    uint256 checkInInterval_,
    bytes[] memory publicKeys,
    uint256[] memory keepingFees
  ) public {
    minStake = minStake_;
    checkInInterval = checkInInterval_;

    uint256 timestamp = getBlockTimestamp();

    for (uint256 i = 0; i < publicKeys.length; ++i) {
      address addr = Utils.publicKeyToAddress(publicKeys[i]);
      keeperAddresses.push(addr);
      keepers[addr] = Keeper({
        publicKey: publicKeys[i],
        stake: 0,
        distributedStake: 0,
        keepingFee: keepingFees[i],
        balance: 0,
        lastCheckInAt: timestamp,
        totalClaimers: 0,
        keyClaimedAt: 0,
        privateKey: 0
      });
    }
  }

  function join(bytes memory publicKey, bytes memory sig)
    payable
    public
    atState(State.CallForKeepers)
  {
    require(msg.value >= minStake);

    address addr = Utils.publicKeyToAddress(publicKey);
    Keeper storage keeper = keepers[addr];

    require(keeper.lastCheckInAt > 0);

    address recoveredAddr = recoverPublicKeyAddr(keeper, sig);
    require(recoveredAddr == addr);

    keeper.stake = msg.value;
  }

  function activate(
    bytes[] memory encryptedKeyParts_,
    bytes memory encryptedData,
    bytes16 aesCounter,
    bytes32 dataHash,
    uint16 shareLength
  )
    payable
    public
    ownerOnly()
    atState(State.CallForKeepers)
  {
    data = EncryptedData({
      encryptedData: encryptedData,
      aesCounter: aesCounter,
      dataHash: dataHash,
      shareLength: shareLength
    });

    encryptedKeyParts = encryptedKeyParts_;

    uint256 timestamp = getBlockTimestamp();

    for (uint256 i = 0; i < keeperAddresses.length; i++) {
      Keeper storage keeper = keepers[keeperAddresses[i]];
      keeper.lastCheckInAt = timestamp;
    }

    creditKeepers();

    lastOwnerCheckInAt = timestamp;
    lastOwnerPaymentAt = timestamp;

    state = State.Active;
  }

  function ownerCheckIn() payable public ownerOnly() atState(State.Active) {
    lastOwnerCheckInAt = getBlockTimestamp();

    if (lastOwnerCheckInAt - lastOwnerPaymentAt >= checkInInterval) {
      creditKeepers();
      lastOwnerPaymentAt = lastOwnerCheckInAt;
    }
  }

  function keeperCheckIn(uint256 keeperIndex, bytes memory sig)
    public
    atState(State.Active)
  {
    address addr = keeperAddresses[keeperIndex];
    Keeper storage keeper = keepers[addr];

    require(keeper.lastCheckInAt > 0 && keeper.keyClaimedAt == 0);

    address recoveredAddr = recoverPublicKeyAddr(keeper, sig);
    require(recoveredAddr == addr);

    uint256 timestamp = getBlockTimestamp();
    keeper.lastCheckInAt = timestamp;

    if (state == State.Active) {
      uint256 timeSinceLastOwnerCheckIn = SafeMath.sub(timestamp, lastOwnerCheckInAt);
      if (timeSinceLastOwnerCheckIn > checkInInterval) {
        state = State.CallForKeys;
        emit KeysNeeded();
      }
    }

    uint256 keeperBalance = keeper.balance;
    if (keeperBalance > 0) {
      keeper.balance = 0;
      msg.sender.transfer(keeperBalance);
    }
  }

  function claimKey(uint256 keeperIndex, bytes memory sig) public {
    require(claimerState[keeperIndex][msg.sender] == ClaimerState.None);

    address addr = keeperAddresses[keeperIndex];
    Keeper storage keeper = keepers[addr];
    require(keeper.lastCheckInAt > 0);

    if (keeper.keyClaimedAt > 0) {
      require(getBlockTimestamp() - keeper.keyClaimedAt <= KEY_CLAIM_PERIOD);
    } else {
      keeper.keyClaimedAt = getBlockTimestamp();
    }

    address recoveredAddr = recoverPublicKeyAddr(keeper, sig);
    require(recoveredAddr == addr);

    claimerState[keeperIndex][msg.sender] = ClaimerState.StakeClaimed;
    keeper.totalClaimers++;
  }

  function supplyKey(uint256 keeperIndex, uint256 privateKey) public {
    address addr = keeperAddresses[keeperIndex];
    Keeper storage keeper = keepers[addr];

    require(
      keeper.keyClaimedAt > 0 &&
      getBlockTimestamp() - keeper.keyClaimedAt > KEY_CLAIM_PERIOD
    );

    require(EC.publicKeyVerify(privateKey, keeper.publicKey));

    keeper.privateKey = privateKey;
  }

  function getClaimedStake(uint256 keeperIndex) public {
    address addr = keeperAddresses[keeperIndex];
    Keeper storage keeper = keepers[addr];

    uint256 timestamp = getBlockTimestamp();

    require(
      keeper.keyClaimedAt > 0 &&
      timestamp - keeper.keyClaimedAt > KEY_CLAIM_PERIOD
    );

    if (keeper.privateKey == 0) {
      // Nobody supplied the key => give the stake to any caller
      if (keeper.distributedStake == 0) {
        keeper.distributedStake = keeper.stake;
        msg.sender.transfer(keeper.stake);
      }
      return;
    }

    // The key was supplied => distribute the stake between claimers
    require(claimerState[keeperIndex][msg.sender] == ClaimerState.StakeClaimed);
    claimerState[keeperIndex][msg.sender] = ClaimerState.StakeReceived;

    uint256 amountToDistribute = SafeMath.div(keeper.stake, keeper.totalClaimers);
    keeper.distributedStake = SafeMath.add(keeper.distributedStake, amountToDistribute);

    msg.sender.transfer(amountToDistribute);
  }

  function recoverPublicKeyAddr(Keeper storage keeper, bytes memory sig)
    internal
    view
    returns (address)
  {
    bytes memory message = Utils.packTwoUints(uint256(msg.sender), keeper.lastCheckInAt);
    return EC.recover(sha256(message), sig);
  }

  function creditKeepers() internal {
    uint256 requiredBalance = 0;

    for (uint256 i = 0; i < keeperAddresses.length; i++) {
      Keeper storage keeper = keepers[keeperAddresses[i]];
      if (keeper.stake > 0) {
        keeper.balance = SafeMath.add(keeper.balance, keeper.keepingFee);
        requiredBalance = SafeMath.add(requiredBalance, keeper.balance);
        requiredBalance = SafeMath.add(
          requiredBalance,
          SafeMath.sub(keeper.stake, keeper.distributedStake)
        );
      }
    }

    require(address(this).balance >= requiredBalance);
  }

  function getBlockTimestamp() internal view returns (uint256) {
    return now;
  }
}













