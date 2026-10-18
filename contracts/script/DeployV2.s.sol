// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {GhostPool} from "../src/GhostPool.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";

/// @notice Deploys ONLY GhostPool v2 (EIP-3009 `depositWithAuthorization`, deposit-only pause) as a new contract,
///         reusing the live HonkVerifier and the live PoseidonT3 / PoseidonT5 libraries on Base.
///         Link the existing libraries with --libraries so forge does NOT deploy new ones:
///
///   forge script script/DeployV2.s.sol --rpc-url <rpc> --broadcast --slow --private-key <key> \
///     --libraries src/poseidon/PoseidonT3.sol:PoseidonT3:0xa6e3d33abef457db3a2f1504c91eee1a77375891 \
///     --libraries src/poseidon/PoseidonT5.sol:PoseidonT5:0x95d619151c18632fd0e6271d8376a44da2a2290e
///
///   Afterwards broadcast/DeployV2.s.sol/<chainId>/run-latest.json must contain exactly one CREATE (GhostPool)
///   plus, if OWNER was set, one transferOwnership CALL, and no library deployment.
///
/// Env (all optional):
///   VERIFIER  HonkVerifier address  (default: live Base verifier 0x519a6d1022586ca29071e6d8c7a92180d5397d4f)
///   TOKEN     USDC address          (default: Base USDC 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)
///   OWNER     cold owner; if set and different from the deployer, ownership is transferred to it at the end.
/// The broadcaster (deployer) is the initial owner and the ASP operator.
contract DeployV2 is Script {
    address internal constant BASE_USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address internal constant LIVE_VERIFIER = 0x519A6D1022586Ca29071e6d8C7A92180D5397D4f;
    uint256 internal constant MAX_DEPOSIT = 100e6; // 100 USDC
    uint256 internal constant TVL_CAP = 1000e6; // 1,000 USDC

    function run() external returns (GhostPool pool) {
        address verifier = vm.envOr("VERIFIER", LIVE_VERIFIER);
        address token = vm.envOr("TOKEN", BASE_USDC);
        address coldOwner = vm.envOr("OWNER", address(0));
        require(verifier.code.length != 0, "DeployV2: VERIFIER has no code on this chain");
        require(token.code.length != 0, "DeployV2: TOKEN has no code on this chain");

        vm.startBroadcast();
        // The broadcasting account (from --private-key / --account / --sender).
        (, address deployer,) = vm.readCallers();

        pool = new GhostPool(IERC20(token), IVerifier(verifier), deployer, deployer, MAX_DEPOSIT, TVL_CAP);
        if (coldOwner != address(0) && coldOwner != deployer) pool.transferOwnership(coldOwner);
        vm.stopBroadcast();

        console.log("Deployer / aspOperator:", deployer);
        console.log("Owner:", pool.owner());
        console.log("Token:", token);
        console.log("HonkVerifier (reused):", verifier);
        console.log("GhostPoolV2:", address(pool));
    }
}
