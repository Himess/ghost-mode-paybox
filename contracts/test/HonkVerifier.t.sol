// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier, Errors} from "../src/HonkVerifier.sol";
import {GhostPool} from "../src/GhostPool.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {MockUSDC} from "./mocks/MockUSDC.sol";

/// @notice Smoke tests against the real bb.js-generated verifier (no real proof available here).
contract HonkVerifierTest is Test {
    /// @dev UltraKeccakZK proof size for log_n = 18 (298 field elements, incl. 8 pairing-point limbs).
    uint256 constant PROOF_SIZE = 9536;

    HonkVerifier honk;

    function setUp() public {
        honk = new HonkVerifier();
    }

    function test_rejectsWrongProofLength() public {
        bytes32[] memory inputs = new bytes32[](14);
        vm.expectRevert(abi.encodeWithSelector(Errors.ProofLengthWrongWithLogN.selector, 18, 0, PROOF_SIZE));
        honk.verify("", inputs);
    }

    function test_requiresExactly14PublicInputs() public {
        bytes memory proof = new bytes(PROOF_SIZE);
        vm.expectRevert(Errors.PublicInputsLengthWrong.selector);
        honk.verify(proof, new bytes32[](13));
        vm.expectRevert(Errors.PublicInputsLengthWrong.selector);
        honk.verify(proof, new bytes32[](22));
    }

    function test_rejectsGarbageProof() public {
        bytes memory proof = new bytes(PROOF_SIZE);
        vm.expectRevert();
        honk.verify(proof, new bytes32[](14));
    }

    function test_poolWithRealVerifierRejectsGarbageProof() public {
        MockUSDC usdc = new MockUSDC();
        GhostPool pool =
            new GhostPool(IERC20(address(usdc)), IVerifier(address(honk)), address(this), address(this), 100e6, 1000e6);
        usdc.mint(address(this), 10e6);
        usdc.approve(address(pool), 10e6);
        pool.deposit(10e6, 1, "");
        pool.setAspRoot(1);

        GhostPool.TransactArgs memory a;
        a.root = pool.getLastRoot();
        a.aspRoot = 1;
        a.nullifiers = [uint256(1), uint256(2)];
        a.outCommitments = [uint256(3), uint256(4)];
        a.deadline = block.timestamp;
        vm.expectRevert();
        pool.transact(new bytes(PROOF_SIZE), a);
        assertFalse(pool.nullifierSpent(1));
    }
}
