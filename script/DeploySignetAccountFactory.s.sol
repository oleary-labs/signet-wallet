// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {SignetAccountFactory} from "../src/SignetAccountFactory.sol";

/// @title DeploySignetAccountFactory
/// @notice Deploys the SignetAccountFactory via CREATE2 for deterministic addresses.
///
/// Optional environment variables:
///   SALT — uint256 salt for CREATE2 deployment (default: 0).
///          Increment to deploy a new version at a different address.
///
/// Run (simulation, no broadcast):
///   forge script script/DeploySignetAccountFactory.s.sol --rpc-url <RPC_URL>
///
/// Run (broadcast):
///   forge script script/DeploySignetAccountFactory.s.sol \
///     --rpc-url <RPC_URL> \
///     --broadcast \
///     --private-key <DEPLOYER_PRIVATE_KEY>
contract DeploySignetAccountFactory is Script {
    function run() external {
        bytes32 salt = bytes32(vm.envOr("SALT", uint256(0)));

        vm.startBroadcast();
        SignetAccountFactory factory = new SignetAccountFactory{salt: salt}();
        vm.stopBroadcast();

        console2.log("deployer :", msg.sender);
        console2.log("salt     :", vm.toString(salt));
        console2.log("factory  :", address(factory));

        // Machine-readable line for scripts / CI.
        console2.log(string.concat("DEPLOY:accountFactory=", vm.toString(address(factory))));
    }
}
