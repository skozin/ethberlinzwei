pragma solidity ^0.5.8;

import "./Utils.sol";

library EC {
    uint256 constant public gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant public gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    function publicKeyVerify(uint256 privKey, bytes memory pubKey) internal pure returns (bool) {
      (bytes32 x, bytes32 y) = split64(pubKey);
      return publicKeyVerify(privKey, uint256(x), uint256(y));
    }

    function split64(bytes memory data) internal pure returns (bytes32 x, bytes32 y) {
      require(data.length == 64);
      assembly {
        x := mload(add(data, 32))
        y := mload(add(data, 64))
      }
    }

    function publicKeyVerify(uint256 privKey, uint256 x, uint256 y) internal pure returns (bool) {
      return ecmulVerify(gx, gy, privKey, x, y);
    }

    //
    // Based on the original idea of Vitalik Buterin:
    // https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384/9
    //
    function ecmulVerify(uint256 x1, uint256 y1, uint256 scalar, uint256 qx, uint256 qy) internal pure
        returns(bool)
    {
        uint256 m = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        address signer = ecrecover(0, y1 % 2 != 0 ? 28 : 27, bytes32(x1), bytes32(mulmod(scalar, x1, m)));
        address xyAddress = address(uint256(keccak256(abi.encodePacked(qx, qy))) & 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
        return xyAddress == signer;
    }

    function verify(bytes memory publicKey, bytes memory message, bytes memory sig) public pure returns (bool, address) {
      require(publicKey.length == 64);
      address expectedAddr = Utils.publicKeyToAddress(publicKey);
      address actualAddress = recover(sha256(message), sig);
      return (expectedAddr == actualAddress, actualAddress);
    }

    function recover(bytes32 hash, bytes memory sig) public pure returns (address) {
      require(sig.length == 65);

      bytes32 r;
      bytes32 s;
      uint8 v;

      assembly {
        r := mload(add(sig, 32))
        s := mload(add(sig, 64))
        v := and(mload(add(sig, 65)), 255)
      }

      if (v < 27) {
        v += 27;
      }

      if (v != 27 && v != 28) {
        return address(0);
      }

      return ecrecover(hash, v, r, s);
    }
}
