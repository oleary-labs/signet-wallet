// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {PackedUserOperation} from "./IAccount.sol";

uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant MODULE_TYPE_EXECUTOR  = 2;
uint256 constant MODULE_TYPE_FALLBACK  = 3;
uint256 constant MODULE_TYPE_HOOK      = 4;

/// @notice Base interface for all ERC-7579 modules.
interface IModule {
    /// @notice Called by the account on module installation.
    function onInstall(bytes calldata data) external;

    /// @notice Called by the account on module uninstallation.
    function onUninstall(bytes calldata data) external;

    /// @notice Returns true if this module implements the given ERC-7579 module type.
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
}

/// @notice ERC-7579 validator module interface.
interface IValidator is IModule {
    /// @notice Validate a user operation. Called by the account during ERC-4337 validation.
    /// @param userOp  The packed user operation.
    /// @param userOpHash Hash of the user operation that was signed.
    /// @return validationData 0 on success, 1 (SIG_VALIDATION_FAILED) on failure,
    ///         or a packed (sigFailed || validUntil || validAfter) for time-bounded validation.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external returns (uint256 validationData);

    /// @notice ERC-1271 signature check routed through the account.
    /// @param sender The address that called isValidSignature on the account.
    /// @param hash   The hash that was signed.
    /// @param data   The signature bytes.
    /// @return 0x1626ba7e on success, 0xffffffff on failure.
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external view returns (bytes4);
}
