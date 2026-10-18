// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../src/HonkVerifier.sol";
import {GhostPool} from "../src/GhostPool.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";

/// @notice Deploys HonkVerifier + GhostPool. Linked libraries (PoseidonT3, PoseidonT5, and the verifier's
///         RelationsLib / ZKTranscriptLib) are deployed and linked automatically by forge.
///
///   forge script script/Deploy.s.sol --rpc-url $BASE_RPC_URL --broadcast --private-key $PRIVATE_KEY
///
/// Env: TOKEN (optional, default Base USDC 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913).
/// The broadcaster (msg.sender) becomes both owner and ASP operator.
contract Deploy is Script {
    address internal constant BASE_USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    uint256 internal constant MAX_DEPOSIT = 100e6; // 100 USDC
    uint256 internal constant TVL_CAP = 1000e6; // 1,000 USDC

    function run() external returns (HonkVerifier verifier, GhostPool pool) {
        address token = vm.envOr("TOKEN", BASE_USDC);

        vm.startBroadcast();
        // The broadcasting account (from --private-key / --account / --sender).
        (, address deployer,) = vm.readCallers();

        verifier = new HonkVerifier();
        pool = new GhostPool(IERC20(token), IVerifier(address(verifier)), deployer, deployer, MAX_DEPOSIT, TVL_CAP);
        vm.stopBroadcast();

        console.log("Deployer / owner / aspOperator:", deployer);
        console.log("Token:", token);
        console.log("HonkVerifier:", address(verifier));
        console.log("GhostPool:", address(pool));
    }
}
