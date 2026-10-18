// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @notice Same ABI as the bb.js-generated `HonkVerifier` (src/HonkVerifier.sol).
/// @dev `publicInputs` must hold exactly the circuit's 14 public inputs. The verifier's
///      NUMBER_OF_PUBLIC_INPUTS = 22 also counts the 8 pairing-point limbs (PAIRING_POINTS_SIZE),
///      which travel inside the proof, and it enforces
///      `publicInputs.length == 22 - 8 == 14` (reverts `PublicInputsLengthWrong`). Every entry must be
///      < the BN254 scalar field (reverts `ValueGeFieldOrder`).
interface IVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}
