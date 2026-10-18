// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {PoseidonT3} from "../src/poseidon/PoseidonT3.sol";
import {PoseidonT5} from "../src/poseidon/PoseidonT5.sol";
import {MerkleTreeWithHistory} from "../src/MerkleTreeWithHistory.sol";
import {MerkleTreeHarness} from "./mocks/MerkleTreeHarness.sol";

/// @dev Expected values were computed off-chain with poseidon-lite 0.3.0 (`poseidon2` / `poseidon4`),
///      i.e. independently of the Solidity implementation.
contract PoseidonTest is Test {
    uint256 constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // poseidon2([1, 2])
    uint256 constant P2_1_2 = 7853200120776062878684798364095072458815029376092732009249414926327459813530;
    // poseidon4([1, 2, 3, 4])
    uint256 constant P4_1_2_3_4 = 18821383157269793795438455681495246036402687001665670618754263018637548127333;
    // Empty depth-16 root = zeros[16]
    uint256 constant EMPTY_ROOT = 19217088683336594659449020493828377907203207941212636669271704950158751593251;
    // Roots after inserting [c0], [c0, c1], [c0, c1, c2] with c0 = P4_1_2_3_4, c1 = P2_1_2, c2 = 42
    uint256 constant ROOT_1 = 19060070580709451930700358804591396945187018760452222167678017583790262682146;
    uint256 constant ROOT_2 = 410696047675644246594416952718005727612127880141938073402231064926853902902;
    uint256 constant ROOT_3 = 21830728175261532192688547337738430730556570236655242129972092566411619475394;

    MerkleTreeHarness tree;

    function setUp() public {
        tree = new MerkleTreeHarness();
    }

    function test_PoseidonT3_vector() public pure {
        assertEq(PoseidonT3.hash([uint256(1), uint256(2)]), P2_1_2);
    }

    function test_PoseidonT5_vector() public pure {
        assertEq(PoseidonT5.hash([uint256(1), uint256(2), uint256(3), uint256(4)]), P4_1_2_3_4);
    }

    function test_zeroChain() public {
        assertEq(tree.zeros(0), 0);
        for (uint256 i; i < 16; ++i) {
            assertEq(tree.zeros(i + 1), PoseidonT3.hash([tree.zeros(i), tree.zeros(i)]), "zero chain");
        }
        assertEq(tree.zeros(16), EMPTY_ROOT);
        vm.expectRevert(MerkleTreeWithHistory.LevelOutOfRange.selector);
        tree.zeros(17);
    }

    function test_initialState() public view {
        assertEq(tree.getLastRoot(), EMPTY_ROOT);
        assertTrue(tree.isKnownRoot(EMPTY_ROOT));
        assertFalse(tree.isKnownRoot(0));
        assertEq(tree.nextIndex(), 0);
        for (uint256 i; i < 16; ++i) {
            assertEq(tree.filledSubtrees(i), tree.zeros(i));
        }
    }

    function test_rootsMatchOffchain() public {
        assertEq(tree.insert(P4_1_2_3_4), 0);
        assertEq(tree.getLastRoot(), ROOT_1);
        assertEq(tree.insert(P2_1_2), 1);
        assertEq(tree.getLastRoot(), ROOT_2);
        assertEq(tree.insert(42), 2);
        assertEq(tree.getLastRoot(), ROOT_3);
        assertEq(tree.nextIndex(), 3);
        assertTrue(tree.isKnownRoot(EMPTY_ROOT));
        assertTrue(tree.isKnownRoot(ROOT_1));
        assertTrue(tree.isKnownRoot(ROOT_2));
        assertTrue(tree.isKnownRoot(ROOT_3));
        assertFalse(tree.isKnownRoot(ROOT_3 + 1));
    }

    function test_rootHistoryRingBuffer() public {
        tree.insert(1);
        uint256 firstRoot = tree.getLastRoot();
        // 63 more inserts: 64 inserts in total overwrite slot 0 (the empty root) but keep `firstRoot`.
        for (uint256 i = 2; i <= 64; ++i) {
            tree.insert(i);
        }
        assertFalse(tree.isKnownRoot(EMPTY_ROOT), "empty root evicted");
        assertTrue(tree.isKnownRoot(firstRoot), "first root still in history");
        tree.insert(65);
        assertFalse(tree.isKnownRoot(firstRoot), "first root evicted");
        assertTrue(tree.isKnownRoot(tree.getLastRoot()));
    }

    function test_treeFullReverts() public {
        tree.forceNextIndex(uint32(1) << 16);
        vm.expectRevert(MerkleTreeWithHistory.MerkleTreeFull.selector);
        tree.insert(1);
        // Last slot is still insertable.
        tree.forceNextIndex((uint32(1) << 16) - 1);
        assertEq(tree.insert(1), (uint32(1) << 16) - 1);
    }

    function test_hashLeftRight() public view {
        assertEq(tree.hashLeftRight(1, 2), P2_1_2);
    }
}
