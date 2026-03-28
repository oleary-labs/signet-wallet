// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {PackedUserOperation} from "./interfaces/IAccount.sol";
import {IValidator, MODULE_TYPE_VALIDATOR} from "./interfaces/IERC7579Modules.sol";
import {FROSTVerifier} from "./FROSTVerifier.sol";

/// @title FROSTValidator
/// @notice ERC-7579 validator module that authenticates UserOperations via FROST threshold
///         Schnorr signatures (RFC 9591, FROST-secp256k1-SHA256-v1).
///
/// Each account installs this module with its FROST group public key (px, py). The group
/// signs the userOpHash off-chain using the FROST protocol, producing a 96-byte signature
/// (rx, ry, z). On-chain verification is delegated to FROSTVerifier, which uses the
/// ecrecover precompile to check the Schnorr equation at ~6,000 gas.
///
/// Signature format (UserOp and ERC-1271): 96 bytes — rx(32) || ry(32) || z(32).
/// ry is used only to extract the R.y parity bit (v = ry & 1) for FROSTVerifier.
///
/// @dev Singleton deployment — all per-account state lives in mappings keyed on the account
///      address, satisfying ERC-4337 associated storage rules.
contract FROSTValidator is IValidator {
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /// @dev secp256k1 field prime.
    uint256 private constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    uint256 private constant SIG_VALIDATION_FAILED = 1;
    bytes4  private constant ERC1271_SUCCESS        = 0x1626ba7e;
    bytes4  private constant ERC1271_FAILED         = 0xffffffff;

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    struct PublicKey {
        uint256 x;
        uint256 y;
        /// @dev Precomputed at install: address(uint160(uint256(keccak256(abi.encodePacked(x, y))))).
        ///      Used as the expected output of ecrecover inside FROSTVerifier.
        ///      Also serves as the "is installed" sentinel: zero means not installed.
        address signer;
    }

    mapping(address account => PublicKey) public groupKeys;

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error AlreadyInstalled();
    error NotInstalled();
    error InvalidPublicKey();

    // -------------------------------------------------------------------------
    // IModule
    // -------------------------------------------------------------------------

    /// @notice Install this validator for msg.sender (the account).
    /// @param data ABI-encoded (uint256 px, uint256 py) — uncompressed group public key coordinates.
    function onInstall(bytes calldata data) external {
        if (groupKeys[msg.sender].signer != address(0)) revert AlreadyInstalled();

        (uint256 px, uint256 py) = abi.decode(data, (uint256, uint256));

        _requireOnCurve(px, py);

        address signer = address(uint160(uint256(keccak256(abi.encodePacked(px, py)))));
        groupKeys[msg.sender] = PublicKey({ x: px, y: py, signer: signer });
    }

    /// @notice Uninstall this validator from msg.sender (the account).
    function onUninstall(bytes calldata) external {
        if (groupKeys[msg.sender].signer == address(0)) revert NotInstalled();
        delete groupKeys[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    // -------------------------------------------------------------------------
    // IValidator
    // -------------------------------------------------------------------------

    /// @inheritdoc IValidator
    /// @dev msg.sender is the account (Kernel calls the validator directly).
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        PublicKey storage pk = groupKeys[msg.sender];
        if (pk.signer == address(0)) return SIG_VALIDATION_FAILED;
        if (!_verify(userOpHash, userOp.signature, pk)) return SIG_VALIDATION_FAILED;
        return 0;
    }

    /// @inheritdoc IValidator
    /// @dev msg.sender is the account. sender (the ERC-1271 caller) is unused —
    ///      authority is determined solely by the stored group key.
    function isValidSignatureWithSender(
        address,
        bytes32 hash,
        bytes calldata data
    ) external view returns (bytes4) {
        PublicKey storage pk = groupKeys[msg.sender];
        if (pk.signer == address(0)) return ERC1271_FAILED;
        if (!_verify(hash, data, pk)) return ERC1271_FAILED;
        return ERC1271_SUCCESS;
    }

    // -------------------------------------------------------------------------
    // View helpers
    // -------------------------------------------------------------------------

    /// @notice Returns true if this validator has been installed for the given account.
    function isInitialized(address account) external view returns (bool) {
        return groupKeys[account].signer != address(0);
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    /// @dev Decode a 96-byte (rx, ry, z) signature, derive the R.y parity bit, and
    ///      call FROSTVerifier with the 65-byte format FROSTVerifier expects.
    function _verify(
        bytes32 hash,
        bytes calldata sigData,
        PublicKey storage pk
    ) internal view returns (bool) {
        if (sigData.length != 96) return false;

        uint256 rx;
        uint256 ry;
        uint256 z;
        assembly {
            let ptr := sigData.offset
            rx := calldataload(ptr)
            ry := calldataload(add(ptr, 32))
            z  := calldataload(add(ptr, 64))
        }

        // FROSTVerifier expects: rx(32) || z(32) || v(1) where v = ry parity.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 v = uint8(ry & 1); // safe: ry & 1 is always 0 or 1
        bytes memory sig65 = abi.encodePacked(bytes32(rx), bytes32(z), v);

        // Reconstruct 33-byte compressed group public key: prefix || px.
        bytes memory compressedKey = abi.encodePacked(
            bytes1(uint8(2 + (pk.y & 1))),
            bytes32(pk.x)
        );

        return FROSTVerifier.verify(abi.encodePacked(hash), sig65, compressedKey, pk.signer);
    }

    /// @dev Validate that (x, y) is a non-identity point on secp256k1.
    ///      Checks: x, y ∈ [1, p-1] and y² ≡ x³ + 7 (mod p).
    function _requireOnCurve(uint256 x, uint256 y) internal pure {
        if (x == 0 || y == 0 || x >= P || y >= P) revert InvalidPublicKey();
        uint256 lhs = mulmod(y, y, P);
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        if (lhs != rhs) revert InvalidPublicKey();
    }
}
