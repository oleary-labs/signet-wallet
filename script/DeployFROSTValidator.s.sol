// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {FROSTValidator} from "../src/FROSTValidator.sol";

/// @title DeployFROSTValidator
/// @notice Deploys the FROSTValidator singleton via CREATE2 for deterministic addresses.
///
/// Optional environment variables:
///   SALT — uint256 salt for CREATE2 deployment (default: 0).
///
/// Run (broadcast):
///   forge script script/DeployFROSTValidator.s.sol \
///     --rpc-url <RPC_URL> \
///     --broadcast \
///     --private-key <DEPLOYER_PRIVATE_KEY>
contract DeployFROSTValidator is Script {
    function run() external {
        bytes32 salt = bytes32(vm.envOr("SALT", uint256(0)));

        vm.startBroadcast();
        FROSTValidator validator = new FROSTValidator{salt: salt}();
        vm.stopBroadcast();

        console2.log("deployer  :", msg.sender);
        console2.log("salt      :", vm.toString(salt));
        console2.log("validator :", address(validator));

        // Machine-readable line for scripts / CI.
        console2.log(string.concat("DEPLOY:frostValidator=", vm.toString(address(validator))));
    }
}
