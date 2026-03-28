// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {FROSTValidator} from "../src/FROSTValidator.sol";
import {PackedUserOperation} from "../src/interfaces/IAccount.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "../src/interfaces/IERC7579Modules.sol";

contract FROSTValidatorTest is Test {
    FROSTValidator validator;

    // Same test vector as FROSTVerifier.t.sol — FROST 2-of-3, signers=["alice","bob"].
    bytes constant GROUP_PUB_KEY_COMPRESSED =
        hex"023f7604a1c4b0d0d27fa514d44e641e13ccb8f24598e4e702e502026a9ea5c92e";
    bytes32 constant MSG_HASH = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
    address constant SIGNER   = 0xaAF830452688305749D3e306eB54095C7411d276;
    bytes32 constant SIG_RX   = 0x7d02f48940f10854f148a07fbb86b7af2b6764318772c648fbd37452c290ffd5;
    bytes32 constant SIG_Z    = 0x56cc68b7bf192683e1015431da5884788f9280846270c10b00ed7b493b34e790;
    // SIG_V = 0 → even R.y; the 96-byte sig uses any even value for ry (only the parity matters).

    uint256 constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    address account;
    uint256 px;
    uint256 py;

    function setUp() public {
        validator = new FROSTValidator();
        account = makeAddr("account");

        (px, py) = _decompressKey(GROUP_PUB_KEY_COMPRESSED);

        vm.prank(account);
        validator.onInstall(abi.encode(px, py));
    }

    // -------------------------------------------------------------------------
    // Signature helpers
    // -------------------------------------------------------------------------

    /// @dev 96-byte valid sig. ry=2 (even) gives v=0, matching SIG_V=0.
    function _validSig() internal pure returns (bytes memory) {
        return abi.encodePacked(SIG_RX, uint256(2), SIG_Z);
    }

    /// @dev Build a 96-byte sig with the given ry parity (0=even, 1=odd).
    function _sigWithParity(uint8 parity) internal pure returns (bytes memory) {
        uint256 ry = parity == 0 ? uint256(2) : uint256(1);
        return abi.encodePacked(SIG_RX, ry, SIG_Z);
    }

    // -------------------------------------------------------------------------
    // onInstall
    // -------------------------------------------------------------------------

    function testInstall_storesGroupKey() public view {
        (uint256 storedX, uint256 storedY, address storedSigner) = validator.groupKeys(account);
        assertEq(storedX, px);
        assertEq(storedY, py);
        assertEq(storedSigner, SIGNER);
    }

    function testInstall_precomputedSignerMatchesDerivedAddress() public view {
        (, , address storedSigner) = validator.groupKeys(account);
        address expected = address(uint160(uint256(keccak256(abi.encodePacked(px, py)))));
        assertEq(storedSigner, expected);
    }

    function testInstall_revertsIfAlreadyInstalled() public {
        vm.prank(account);
        vm.expectRevert(FROSTValidator.AlreadyInstalled.selector);
        validator.onInstall(abi.encode(px, py));
    }

    function testInstall_revertsOnIdentityPoint() public {
        address acct2 = makeAddr("acct2");
        vm.prank(acct2);
        vm.expectRevert(FROSTValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(uint256(0), uint256(0)));
    }

    function testInstall_revertsOnZeroX() public {
        address acct2 = makeAddr("acct2");
        vm.prank(acct2);
        vm.expectRevert(FROSTValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(uint256(0), py));
    }

    function testInstall_revertsOnZeroY() public {
        address acct2 = makeAddr("acct2");
        vm.prank(acct2);
        vm.expectRevert(FROSTValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(px, uint256(0)));
    }

    function testInstall_revertsOnXEqualToP() public {
        address acct2 = makeAddr("acct2");
        vm.prank(acct2);
        vm.expectRevert(FROSTValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(P, py));
    }

    function testInstall_revertsOnYEqualToP() public {
        address acct2 = makeAddr("acct2");
        vm.prank(acct2);
        vm.expectRevert(FROSTValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(px, P));
    }

    function testInstall_revertsOnPointNotOnCurve() public {
        // (1, 1): 1² = 1 ≠ 1³ + 7 = 8 mod p
        address acct2 = makeAddr("acct2");
        vm.prank(acct2);
        vm.expectRevert(FROSTValidator.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(uint256(1), uint256(1)));
    }

    // -------------------------------------------------------------------------
    // onUninstall
    // -------------------------------------------------------------------------

    function testUninstall_clearsGroupKey() public {
        vm.prank(account);
        validator.onUninstall("");

        (uint256 storedX, uint256 storedY, address storedSigner) = validator.groupKeys(account);
        assertEq(storedX, 0);
        assertEq(storedY, 0);
        assertEq(storedSigner, address(0));
    }

    function testUninstall_revertsIfNotInstalled() public {
        address acct2 = makeAddr("acct2");
        vm.prank(acct2);
        vm.expectRevert(FROSTValidator.NotInstalled.selector);
        validator.onUninstall("");
    }

    function testUninstall_allowsReinstall() public {
        vm.prank(account);
        validator.onUninstall("");

        vm.prank(account);
        validator.onInstall(abi.encode(px, py)); // must not revert
        assertTrue(validator.isInitialized(account));
    }

    // -------------------------------------------------------------------------
    // isModuleType / isInitialized
    // -------------------------------------------------------------------------

    function testIsModuleType_validator() public view {
        assertTrue(validator.isModuleType(MODULE_TYPE_VALIDATOR));
    }

    function testIsModuleType_rejectsOtherTypes() public view {
        assertFalse(validator.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(validator.isModuleType(3));
        assertFalse(validator.isModuleType(4));
        assertFalse(validator.isModuleType(0));
    }

    function testIsInitialized_trueAfterInstall() public view {
        assertTrue(validator.isInitialized(account));
    }

    function testIsInitialized_falseForUnknownAccount() public {
        assertFalse(validator.isInitialized(makeAddr("nobody")));
    }

    function testIsInitialized_falseAfterUninstall() public {
        vm.prank(account);
        validator.onUninstall("");
        assertFalse(validator.isInitialized(account));
    }

    // -------------------------------------------------------------------------
    // validateUserOp
    // -------------------------------------------------------------------------

    function testValidateUserOp_validSig_returnsZero() public {
        vm.prank(account);
        uint256 result = validator.validateUserOp(_userOp(_validSig()), MSG_HASH);
        assertEq(result, 0);
    }

    function testValidateUserOp_tamperedZ_returnsOne() public {
        bytes memory sig = abi.encodePacked(SIG_RX, uint256(2), bytes32(uint256(SIG_Z) ^ 1));
        vm.prank(account);
        assertEq(validator.validateUserOp(_userOp(sig), MSG_HASH), 1);
    }

    function testValidateUserOp_tamperedRx_returnsOne() public {
        bytes memory sig = abi.encodePacked(bytes32(uint256(SIG_RX) ^ 1), uint256(2), SIG_Z);
        vm.prank(account);
        assertEq(validator.validateUserOp(_userOp(sig), MSG_HASH), 1);
    }

    function testValidateUserOp_wrongParity_returnsOne() public {
        // ry parity 1 (odd) → v=1, but the valid sig has v=0
        vm.prank(account);
        assertEq(validator.validateUserOp(_userOp(_sigWithParity(1)), MSG_HASH), 1);
    }

    function testValidateUserOp_wrongMessage_returnsOne() public {
        vm.prank(account);
        assertEq(validator.validateUserOp(_userOp(_validSig()), bytes32(uint256(MSG_HASH) ^ 1)), 1);
    }

    function testValidateUserOp_wrongSigLength_returnsOne() public {
        vm.prank(account);
        assertEq(validator.validateUserOp(_userOp(hex"deadbeef"), MSG_HASH), 1);
    }

    function testValidateUserOp_emptySig_returnsOne() public {
        vm.prank(account);
        assertEq(validator.validateUserOp(_userOp(""), MSG_HASH), 1);
    }

    function testValidateUserOp_notInstalled_returnsOne() public {
        address acct2 = makeAddr("acct2");
        vm.prank(acct2);
        assertEq(validator.validateUserOp(_userOp(_validSig()), MSG_HASH), 1);
    }

    function testValidateUserOp_gas() public {
        PackedUserOperation memory userOp = _userOp(_validSig());

        vm.prank(account);
        uint256 gasBefore = gasleft();
        validator.validateUserOp(userOp, MSG_HASH);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("FROSTValidator.validateUserOp gas", gasUsed);
        assertLt(gasUsed, 40_000);
    }

    // -------------------------------------------------------------------------
    // isValidSignatureWithSender
    // -------------------------------------------------------------------------

    function testIsValidSignature_validSig_returnsSuccess() public {
        vm.prank(account);
        bytes4 result = validator.isValidSignatureWithSender(address(0xdead), MSG_HASH, _validSig());
        assertEq(result, bytes4(0x1626ba7e));
    }

    function testIsValidSignature_invalidSig_returnsFailed() public {
        bytes memory badSig = abi.encodePacked(SIG_RX, uint256(2), bytes32(uint256(SIG_Z) ^ 1));
        vm.prank(account);
        bytes4 result = validator.isValidSignatureWithSender(address(0), MSG_HASH, badSig);
        assertEq(result, bytes4(0xffffffff));
    }

    function testIsValidSignature_notInstalled_returnsFailed() public {
        address acct2 = makeAddr("acct2");
        vm.prank(acct2);
        bytes4 result = validator.isValidSignatureWithSender(address(0), MSG_HASH, _validSig());
        assertEq(result, bytes4(0xffffffff));
    }

    function testIsValidSignature_senderParamIsIgnored() public {
        // Authority is the stored key; the `sender` argument must not affect the result.
        vm.prank(account);
        bytes4 r1 = validator.isValidSignatureWithSender(address(0), MSG_HASH, _validSig());
        vm.prank(account);
        bytes4 r2 = validator.isValidSignatureWithSender(address(0xdead), MSG_HASH, _validSig());
        vm.prank(account);
        bytes4 r3 = validator.isValidSignatureWithSender(account, MSG_HASH, _validSig());

        assertEq(r1, bytes4(0x1626ba7e));
        assertEq(r1, r2);
        assertEq(r2, r3);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    function _userOp(bytes memory sig) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: sig
        });
    }

    /// @dev Decompress a 33-byte secp256k1 public key to (x, y).
    ///      Valid since p ≡ 3 mod 4: y = (x³ + 7)^((p+1)/4) mod p.
    function _decompressKey(bytes memory compressed)
        internal view returns (uint256 x, uint256 y)
    {
        uint8 prefix;
        assembly {
            prefix := byte(0, mload(add(compressed, 32)))
            x := mload(add(compressed, 33))
        }

        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        uint256 exp = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C;
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), rhs, exp, P);
        (bool ok, bytes memory out) = address(0x05).staticcall(input);
        require(ok && out.length >= 32, "modexp failed");
        assembly { y := mload(add(out, 32)) }

        uint256 wantParity = prefix == 0x03 ? 1 : 0;
        if ((y & 1) != wantParity) y = P - y;
    }
}
