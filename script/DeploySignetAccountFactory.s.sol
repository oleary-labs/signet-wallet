// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {SignetAccountFactory} from "../src/SignetAccountFactory.sol";

/// @title DeploySignetAccountFactory
/// @notice Deploys the SignetAccountFactory.
///
/// Run (simulation, no broadcast):
///   forge script script/DeploySignetAccountFactory.s.sol --rpc-url <RPC_URL>
///
/// Run (broadcast):
///   forge script script/DeploySignetAccountFactory.s.sol \
///     --rpc-url <RPC_URL> \
///     --broadcast \
///     --private-key <DEPLOYER_PRIVATE_KEY>
///
/// With a hardware wallet (Ledger):
///   forge script script/DeploySignetAccountFactory.s.sol \
///     --rpc-url <RPC_URL> \
///     --broadcast \
///     --ledger \
///     --sender <SENDER_ADDRESS>
contract DeploySignetAccountFactory is Script {
    function run() external {
        vm.startBroadcast();
        SignetAccountFactory factory = new SignetAccountFactory();
        vm.stopBroadcast();

        console2.log("deployer :", msg.sender);
        console2.log("factory  :", address(factory));

        // Machine-readable line for scripts / CI.
        console2.log(string.concat("DEPLOY:factory=", vm.toString(address(factory))));
    }
}
