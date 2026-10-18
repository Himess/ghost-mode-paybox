// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PoseidonT3} from "./poseidon/PoseidonT3.sol";

/// @title MerkleTreeWithHistory
/// @notice Tornado-style incremental Poseidon Merkle tree (depth 16) with a 64-entry root history.
/// @dev Must match the `transact` circuit:
///      - node = PoseidonT3([left, right]) (circomlib-compatible, = noir `poseidon::bn254::hash_2`)
///      - leaf index bit i == 0 => the running node is the LEFT child at level i
///      - zero leaf zeros(0) = 0, zeros(i + 1) = PoseidonT3([zeros(i), zeros(i)]), empty root = zeros(16).
abstract contract MerkleTreeWithHistory {
    /// @notice BN254 scalar field (the circuit's native field).
    uint256 public constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint32 public constant DEPTH = 16;
    uint32 public constant ROOT_HISTORY_SIZE = 64;
    uint32 internal constant MAX_LEAVES = uint32(1) << DEPTH;

    /// @notice Last left node seen at each level (Tornado `filledSubtrees`).
    uint256[DEPTH] public filledSubtrees;
    /// @notice Ring buffer of the last ROOT_HISTORY_SIZE roots.
    uint256[ROOT_HISTORY_SIZE] public roots;
    uint32 public currentRootIndex;
    /// @notice Index the next inserted leaf will get (= number of leaves).
    uint32 public nextIndex;

    error MerkleTreeFull();
    error LevelOutOfRange();

    constructor() {
        for (uint256 i; i < DEPTH; ++i) {
            filledSubtrees[i] = zeros(i);
        }
        roots[0] = zeros(DEPTH);
    }

    /// @notice PoseidonT3([left, right]).
    function hashLeftRight(uint256 left, uint256 right) public pure returns (uint256) {
        return PoseidonT3.hash([left, right]);
    }

    /// @dev Inserts `leaf` at `nextIndex`, pushes the new root into the history, returns the leaf index.
    function _insert(uint256 leaf) internal returns (uint32 index) {
        uint32 _nextIndex = nextIndex;
        if (_nextIndex == MAX_LEAVES) revert MerkleTreeFull();

        uint32 currentIndex = _nextIndex;
        uint256 currentLevelHash = leaf;
        uint256 left;
        uint256 right;
        for (uint256 i; i < DEPTH; ++i) {
            if (currentIndex & 1 == 0) {
                left = currentLevelHash;
                right = zeros(i);
                filledSubtrees[i] = currentLevelHash;
            } else {
                left = filledSubtrees[i];
                right = currentLevelHash;
            }
            currentLevelHash = PoseidonT3.hash([left, right]);
            currentIndex >>= 1;
        }

        uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = currentLevelHash;
        nextIndex = _nextIndex + 1;
        return _nextIndex;
    }

    /// @notice True if `root` is one of the last ROOT_HISTORY_SIZE roots. 0 is never known.
    function isKnownRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        uint32 _currentRootIndex = currentRootIndex;
        uint32 i = _currentRootIndex;
        do {
            if (root == roots[i]) return true;
            if (i == 0) i = ROOT_HISTORY_SIZE;
            unchecked {
                --i;
            }
        } while (i != _currentRootIndex);
        return false;
    }

    /// @notice Current (latest) root.
    function getLastRoot() public view returns (uint256) {
        return roots[currentRootIndex];
    }

    /// @notice Root of an empty subtree of height `i` (zeros(0) = 0 is the empty leaf, zeros(16) = empty root).
    /// @dev Hardcoded; test/Poseidon.t.sol checks zeros(i + 1) == PoseidonT3([zeros(i), zeros(i)]) on-chain and
    ///      the values were generated with poseidon-lite `poseidon2`.
    function zeros(uint256 i) public pure returns (uint256) {
        if (i == 0) return 0;
        else if (i == 1) return 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864;
        else if (i == 2) return 0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1;
        else if (i == 3) return 0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238;
        else if (i == 4) return 0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a;
        else if (i == 5) return 0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55;
        else if (i == 6) return 0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78;
        else if (i == 7) return 0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d;
        else if (i == 8) return 0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61;
        else if (i == 9) return 0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747;
        else if (i == 10) return 0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2;
        else if (i == 11) return 0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636;
        else if (i == 12) return 0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a;
        else if (i == 13) return 0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0;
        else if (i == 14) return 0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c;
        else if (i == 15) return 0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92;
        else if (i == 16) return 0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323;
        else revert LevelOutOfRange();
    }
}
