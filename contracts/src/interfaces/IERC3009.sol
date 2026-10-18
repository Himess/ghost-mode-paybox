// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @notice EIP-3009 subset used by GhostPool (Circle FiatToken v2.2, e.g. USDC on Base).
/// @dev `receiveWithAuthorization` requires msg.sender == to, so only the payee (the pool) can consume
///      an authorization; a third party who sees the signature cannot redirect the funds.
///      EIP-712 domain of USDC on Base: name "USD Coin", version "2", chainId, verifyingContract = token.
interface IERC3009 {
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    /// @notice keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /// @notice True if `nonce` was already used (or canceled) by `authorizer`.
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
}
