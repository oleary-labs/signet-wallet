// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {SignetAccountFactory} from "../src/SignetAccountFactory.sol";

/// @title CreateSignetAccount
/// @notice Calls SignetAccountFactory.createAccount for a given group public key.
///
/// Required environment variables:
///   FACTORY          - SignetAccountFactory address
///   ENTRY_POINT      - EntryPoint v0.7 address (default: 0x0000000071727De22E5E9d8BAf0edAc6f37da032)
///   GROUP_PUBLIC_KEY - 33-byte compressed secp256k1 public key (0x-prefixed hex)
///   SALT             - CREATE2 salt, decimal or 0x hex (default: 0)
///
/// Simulation (no broadcast):
///   forge script script/CreateSignetAccount.s.sol \
///     --rpc-url <RPC_URL> \
///     --env-file .env
///
/// Broadcast:
///   forge script script/CreateSignetAccount.s.sol \
///     --rpc-url <RPC_URL> \
///     --broadcast \
///     --private-key <DEPLOYER_KEY> \
///     --env-file .env
contract CreateSignetAccount is Script {
    address constant DEFAULT_ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function run() external {
        address factory = vm.envAddress("FACTORY");
        address entryPoint = vm.envOr("ENTRY_POINT", DEFAULT_ENTRY_POINT);
        bytes memory groupPublicKey = vm.envBytes("GROUP_PUBLIC_KEY");
        uint256 salt = vm.envOr("SALT", uint256(0));

        require(groupPublicKey.length == 33, "GROUP_PUBLIC_KEY must be 33 bytes (compressed secp256k1)");

        address predicted = SignetAccountFactory(factory).getAddress(entryPoint, groupPublicKey, salt);
        console2.log("factory     :", factory);
        console2.log("entryPoint  :", entryPoint);
        console2.log("salt        :", salt);
        console2.log("predicted   :", predicted);

        if (predicted.code.length > 0) {
            console2.log("status      : already deployed");
            console2.log(string.concat("DEPLOY:account=", vm.toString(predicted)));
            return;
        }

        vm.startBroadcast();
        address account = address(SignetAccountFactory(factory).createAccount(entryPoint, groupPublicKey, salt));
        vm.stopBroadcast();

        console2.log("status      : deployed");
        console2.log("account     :", account);
        console2.log(string.concat("DEPLOY:account=", vm.toString(account)));
    }
}
