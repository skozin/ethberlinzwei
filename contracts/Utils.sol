pragma solidity ^0.5.8;

library Utils {

  function publicKeyToAddress(bytes memory publicKey) internal pure returns (address addr) {
    bytes32 hash = keccak256(publicKey);
    assembly {
      mstore(0, hash)
      addr := mload(0)
    }
  }

  function packTwoUints(uint256 x, uint256 y) internal pure returns (bytes memory) {
    return abi.encodePacked(x, y);
  }

  function unpackTwoUints(bytes memory data) internal pure returns (uint256 x, uint256 y) {
    assembly {
      x := mload(add(data, 32))
      y := mload(add(data, 64))
    }
  }
}
