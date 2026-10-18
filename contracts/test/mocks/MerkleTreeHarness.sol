// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {MerkleTreeWithHistory} from "../../src/MerkleTreeWithHistory.sol";

/// @notice Exposes the internal tree insert for tests.
contract MerkleTreeHarness is MerkleTreeWithHistory {
    function insert(uint256 leaf) external returns (uint32) {
        return _insert(leaf);
    }

    /// @dev Test-only shortcut to reach the "tree full" state without 2^16 inserts.
    function forceNextIndex(uint32 index) external {
        nextIndex = index;
    }
}
