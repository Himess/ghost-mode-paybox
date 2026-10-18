// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IVerifier} from "../../src/interfaces/IVerifier.sol";

/// @notice Verifier stub: returns `result` (default true). Mirrors HonkVerifier's 14-input length check.
contract MockVerifier is IVerifier {
    bool public result = true;

    function setResult(bool value) external {
        result = value;
    }

    function verify(bytes calldata, bytes32[] calldata publicInputs) external view returns (bool) {
        require(publicInputs.length == 14, "MockVerifier: bad public inputs length");
        return result;
    }
}
