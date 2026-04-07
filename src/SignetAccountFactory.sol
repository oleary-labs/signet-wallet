// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {SignetAccount} from "./SignetAccount.sol";

/// @title SignetAccountFactory
/// @notice CREATE2 factory for SignetAccount.
///
/// Callers supply only the 33-byte compressed secp256k1 group public key; the
/// factory decompresses it on-chain to derive the Ethereum signer address
/// (keccak256(uncompressed_x || uncompressed_y)[12:]), so no separately
/// computed address is required.
///
/// The same (entryPoint, groupPublicKey, salt) triple always produces the same
/// counterfactual address. Calling createAccount a second time with the same
/// args is a no-op that returns the already-deployed account.
contract SignetAccountFactory {
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /// @dev secp256k1 field prime.
    uint256 private constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// @dev Exponent for the modular square root: (P + 1) / 4.
    ///      Valid because P ≡ 3 (mod 4), so sqrt(a) mod P = a^((P+1)/4) mod P.
    uint256 private constant SQRT_EXP =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event AccountCreated(address indexed account, bytes groupPublicKey, uint256 salt);

    // -------------------------------------------------------------------------
    // External
    // -------------------------------------------------------------------------

    /// @notice Deploy the SignetAccount for (entryPoint, groupPublicKey, salt),
    ///         or return the existing one if it was already deployed.
    /// @param entryPoint     ERC-4337 EntryPoint address.
    /// @param groupPublicKey 33-byte compressed secp256k1 group public key.
    /// @param salt           CREATE2 salt — use 0 for a single account per key.
    function createAccount(
        address entryPoint,
        bytes calldata groupPublicKey,
        uint256 salt
    ) external returns (SignetAccount account) {
        address signer = _signerAddress(groupPublicKey);
        address predicted = _predict(_initcodeHash(entryPoint, groupPublicKey, signer), salt);

        if (predicted.code.length > 0) {
            return SignetAccount(payable(predicted));
        }

        account = new SignetAccount{salt: bytes32(salt)}(entryPoint, groupPublicKey, signer);
        emit AccountCreated(address(account), groupPublicKey, salt);
    }

    /// @notice Compute the counterfactual address for a SignetAccount before deployment.
    ///         Fund this address with ETH before the first UserOp to cover prefunding.
    function getAddress(
        address entryPoint,
        bytes calldata groupPublicKey,
        uint256 salt
    ) external view returns (address) {
        address signer = _signerAddress(groupPublicKey);
        return _predict(_initcodeHash(entryPoint, groupPublicKey, signer), salt);
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    /// @dev Decompress a 33-byte secp256k1 key and return the Ethereum signer
    ///      address: keccak256(uncompressed_x || uncompressed_y)[12:].
    ///
    ///      Decompression: given prefix ∈ {0x02, 0x03} and x,
    ///        y = sqrt(x³ + 7) mod P, choosing the root that matches the prefix parity.
    function _signerAddress(bytes calldata key) internal view returns (address) {
        require(key.length == 33, "SignetAccountFactory: key must be 33 bytes");
        uint8 prefix = uint8(key[0]);
        require(prefix == 0x02 || prefix == 0x03, "SignetAccountFactory: invalid prefix");

        uint256 px;
        assembly { px := calldataload(add(key.offset, 1)) }
        require(px != 0 && px < P, "SignetAccountFactory: x out of range");

        // y² = x³ + 7 mod P
        uint256 rhs = addmod(mulmod(mulmod(px, px, P), px, P), 7, P);
        uint256 py = _modexp(rhs, SQRT_EXP, P);

        // Select the root whose parity matches the prefix byte (0x02 → even, 0x03 → odd).
        if ((py & 1) != (prefix & 1)) {
            py = P - py;
        }

        return address(uint160(uint256(keccak256(abi.encodePacked(px, py)))));
    }

    /// @dev Compute keccak256 of (creationCode || abi.encode(constructor args)).
    ///      This is the initcode hash used in the CREATE2 address formula.
    function _initcodeHash(
        address entryPoint,
        bytes calldata groupPublicKey,
        address signer
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            type(SignetAccount).creationCode,
            abi.encode(entryPoint, groupPublicKey, signer)
        ));
    }

    /// @dev Standard CREATE2 address: keccak256(0xff || factory || salt || initcodeHash)[12:].
    function _predict(bytes32 initcodeHash, uint256 salt) internal view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            bytes32(salt),
            initcodeHash
        )))));
    }

    /// @dev Modular exponentiation via the precompile at address 0x05.
    function _modexp(uint256 base, uint256 exp, uint256 mod) private view returns (uint256 result) {
        bytes memory input = abi.encodePacked(
            uint256(32), uint256(32), uint256(32), base, exp, mod
        );
        (bool ok, bytes memory output) = address(0x05).staticcall(input);
        require(ok && output.length >= 32, "SignetAccountFactory: modexp failed");
        assembly { result := mload(add(output, 32)) }
    }
}
