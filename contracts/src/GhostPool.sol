// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC20} from "./interfaces/IERC20.sol";
import {IERC3009} from "./interfaces/IERC3009.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {MerkleTreeWithHistory} from "./MerkleTreeWithHistory.sol";
import {PoseidonT5} from "./poseidon/PoseidonT5.sol";

/// @title GhostPool (v2)
/// @notice Ghost Mode: a ZK shielded USDC pool (2-in / 2-out UltraHonk `transact` circuit) with an
///         Association Set Provider (ASP) root that every spend must prove label membership in.
///         v2 adds `depositWithAuthorization` (single-signature, gasless shield via USDC EIP-3009
///         `receiveWithAuthorization`) and makes `pause` stop deposits only: `transact` is never paused.
///         The circuit, the verifier and the transact public inputs are unchanged from v1.
/// @dev Encodings that MUST match the circuit (circuits/transact/src/main.nr) and the TS client:
///      - label      = uint256(keccak256(abi.encodePacked(address(pool), uint256(depositCount)))) % FIELD_SIZE
///                     (52 packed bytes; depositCount = number of previous deposits, starting at 0)
///      - commitment = PoseidonT5([uint160(token), amount, label, precommitment])
///      - extDataHash = uint256(keccak256(abi.encode(relayer, encryptedOutput0, encryptedOutput1))) % FIELD_SIZE
///      - publicInputs (14 x bytes32, exactly this order):
///        [0] root, [1] aspRoot, [2] nullifiers[0], [3] nullifiers[1], [4] outCommitments[0],
///        [5] outCommitments[1], [6] publicOut, [7] extDataHash, [8] uint160(token), [9] uint160(recipient),
///        [10] fee, [11] deadline, [12] uint256(DOMAIN_SEPARATOR) >> 128, [13] uint256(DOMAIN_SEPARATOR) & (2^128 - 1)
///      The HonkVerifier's NUMBER_OF_PUBLIC_INPUTS = 22 includes 8 pairing-point limbs carried in the proof;
///      it requires publicInputs.length == 22 - 8 == 14.
///      - EIP-3009 nonce (depositWithAuthorization) =
///                     keccak256(abi.encode(address(pool), precommitment, keccak256(encryptedNote), fee))
contract GhostPool is MerkleTreeWithHistory {
    struct TransactArgs {
        uint256 root;
        uint256 aspRoot;
        uint256[2] nullifiers;
        uint256[2] outCommitments;
        uint256 publicOut;
        address recipient;
        uint256 fee;
        uint256 deadline;
        address relayer;
        bytes encryptedOutput0;
        bytes encryptedOutput1;
    }

    /// @notice Number of entries passed to `verifier.verify` (circuit public inputs, without pairing limbs).
    uint256 public constant NUM_PUBLIC_INPUTS = 14;
    uint256 public constant ASP_ROOT_HISTORY_SIZE = 16;
    /// @dev public_out / fee / deadline / note amounts are u64 in the circuit.
    uint256 internal constant U64_LIMIT = 1 << 64;
    uint256 internal constant LOW_128_MASK = (1 << 128) - 1;
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    IERC20 public immutable token;
    IVerifier public immutable verifier;
    /// @notice EIP-712 domain of the in-circuit `GhostSpend` signature (name "GhostMode", version "1").
    bytes32 public immutable DOMAIN_SEPARATOR;

    address public owner;
    /// @notice Deposit pause flag. While true, `deposit` and `depositWithAuthorization` revert `EnforcedPause`.
    ///         `transact` (shielded transfers and withdrawals) ignores it, so users can always exit.
    bool public paused;
    address public aspOperator;
    uint256 public maxDeposit;
    uint256 public tvlCap;
    /// @notice Number of deposits so far (the next deposit's label uses this value).
    uint256 public depositCount;

    mapping(uint256 => bool) public nullifierSpent;

    /// @notice Ring buffer of the last ASP_ROOT_HISTORY_SIZE ASP roots.
    uint256[ASP_ROOT_HISTORY_SIZE] public aspRoots;
    uint256 public currentAspRootIndex;

    uint256 private _reentrancyStatus;

    event NewCommitment(uint256 indexed commitment, uint32 leafIndex, bytes encryptedOutput);
    event NewNullifier(uint256 indexed nullifier);
    event Deposited(
        address indexed depositor, uint256 indexed commitment, uint256 label, uint256 amount, uint32 leafIndex
    );
    event Transacted(address indexed relayer, address indexed recipient, uint256 publicOut, uint256 fee);
    event AspRootUpdated(uint256 indexed root, uint256 index);
    event AspOperatorUpdated(address indexed previousOperator, address indexed newOperator);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Paused(address account);
    event Unpaused(address account);
    event MaxDepositUpdated(uint256 maxDeposit);
    event TvlCapUpdated(uint256 tvlCap);

    error ZeroAddress();
    error NotOwner();
    error NotAspOperator();
    error EnforcedPause();
    error Reentrancy();
    error InvalidAmount();
    error InvalidPrecommitment();
    error TvlCapExceeded();
    error TransferFailed();
    error InvalidAspRoot();
    error UnknownRoot();
    error UnknownAspRoot();
    error InvalidNullifier();
    error DuplicateNullifier();
    error NullifierAlreadySpent();
    error InvalidCommitment();
    error DeadlineExpired();
    error ValueOutOfRange();
    error FeeExceedsPublicOut();
    error ZeroRecipient();
    error RecipientWithoutPayout();
    error ZeroRelayer();
    error InvalidProof();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @dev Only deposits are pausable; `transact` deliberately has no pause check.
    modifier whenDepositsNotPaused() {
        if (paused) revert EnforcedPause();
        _;
    }

    modifier nonReentrant() {
        if (_reentrancyStatus == 2) revert Reentrancy();
        _reentrancyStatus = 2;
        _;
        _reentrancyStatus = 1;
    }

    constructor(
        IERC20 _token,
        IVerifier _verifier,
        address _owner,
        address _aspOperator,
        uint256 _maxDeposit,
        uint256 _tvlCap
    ) {
        if (
            address(_token) == address(0) || address(_verifier) == address(0) || _owner == address(0)
                || _aspOperator == address(0)
        ) revert ZeroAddress();
        token = _token;
        verifier = _verifier;
        owner = _owner;
        aspOperator = _aspOperator;
        maxDeposit = _maxDeposit;
        tvlCap = _tvlCap;
        _reentrancyStatus = 1;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256("GhostMode"), keccak256("1"), block.chainid, address(this))
        );
        emit OwnershipTransferred(address(0), _owner);
        emit AspOperatorUpdated(address(0), _aspOperator);
        emit MaxDepositUpdated(_maxDeposit);
        emit TvlCapUpdated(_tvlCap);
    }

    // ------------------------------------------------------------------------------------------------
    // Deposit
    // ------------------------------------------------------------------------------------------------

    /// @notice Shield `amount` USDC. The caller must have approved this pool for `amount`.
    /// @param precommitment H2(ownerTag, blinding), must be < FIELD_SIZE.
    /// @param encryptedNote Opaque note ciphertext, emitted in `NewCommitment`.
    function deposit(uint256 amount, uint256 precommitment, bytes calldata encryptedNote)
        external
        whenDepositsNotPaused
        nonReentrant
        returns (uint256 commitment, uint32 leafIndex)
    {
        _checkDeposit(amount, precommitment);
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        (commitment, leafIndex) = _recordDeposit(msg.sender, amount, precommitment, encryptedNote);
    }

    /// @notice Gasless, single-signature shield: `from` signs one USDC EIP-3009 `ReceiveWithAuthorization`
    ///         (to = this pool, value, validAfter, validBefore, nonce) and anyone (a relayer) submits it.
    ///         The pool pulls `value` from `from`, pays `fee` to msg.sender, and shields `value - fee`.
    /// @dev The EIP-3009 nonce is `authorizationNonce(precommitment, encryptedNote, fee)`, so the signature
    ///      commits to the deposit contents and the fee: a relayer cannot change them (the token rejects the
    ///      signature). A front-runner replaying the same parameters produces the same deposit (harmless;
    ///      only the fee recipient differs) and consumes the nonce, so the later submission reverts.
    ///      `fee >= value` reverts `InvalidAmount` (the shielded amount must be > 0).
    /// @param from The USDC holder who signed the authorization; reported as the depositor.
    /// @param value Gross USDC pulled from `from` (signed).
    /// @param fee Part of `value` paid to msg.sender (bound through the nonce).
    /// @param validAfter EIP-3009 lower time bound (exclusive, signed).
    /// @param validBefore EIP-3009 upper time bound (exclusive, signed).
    /// @param precommitment H2(ownerTag, blinding), must be < FIELD_SIZE (bound through the nonce).
    /// @param encryptedNote Opaque note ciphertext, emitted in `NewCommitment` (bound through the nonce).
    function depositWithAuthorization(
        address from,
        uint256 value,
        uint256 fee,
        uint256 validAfter,
        uint256 validBefore,
        uint256 precommitment,
        bytes calldata encryptedNote,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenDepositsNotPaused nonReentrant returns (uint256 commitment, uint32 leafIndex) {
        if (fee >= value) revert InvalidAmount();
        uint256 amount = value - fee;
        _checkDeposit(amount, precommitment);
        {
            bytes32 nonce = _authorizationNonce(fee, precommitment, encryptedNote);
            _receiveWithAuthorization(from, value, validAfter, validBefore, nonce, v, r, s);
        }
        if (fee != 0) _transferOut(msg.sender, fee);
        (commitment, leafIndex) = _recordDeposit(from, amount, precommitment, encryptedNote);
    }

    /// @notice The EIP-3009 nonce `from` must sign for `depositWithAuthorization`:
    ///         keccak256(abi.encode(address(this), precommitment, keccak256(encryptedNote), fee)).
    function authorizationNonce(uint256 precommitment, bytes calldata encryptedNote, uint256 fee)
        external
        view
        returns (bytes32)
    {
        return _authorizationNonce(fee, precommitment, encryptedNote);
    }

    // ------------------------------------------------------------------------------------------------
    // Transact (shielded transfer / withdrawal). Anyone may submit (relayers).
    // Never paused: users can always exit.
    // ------------------------------------------------------------------------------------------------

    function transact(bytes calldata proof, TransactArgs calldata a) external nonReentrant {
        if (!isKnownRoot(a.root)) revert UnknownRoot();
        if (!isKnownAspRoot(a.aspRoot)) revert UnknownAspRoot();

        uint256 n0 = a.nullifiers[0];
        uint256 n1 = a.nullifiers[1];
        // Defense in depth against nullifier malleability (the HonkVerifier also rejects inputs >= field).
        if (n0 >= FIELD_SIZE || n1 >= FIELD_SIZE) revert InvalidNullifier();
        if (n0 == n1) revert DuplicateNullifier();
        if (nullifierSpent[n0] || nullifierSpent[n1]) revert NullifierAlreadySpent();
        if (a.outCommitments[0] >= FIELD_SIZE || a.outCommitments[1] >= FIELD_SIZE) revert InvalidCommitment();
        if (block.timestamp > a.deadline) revert DeadlineExpired();
        if (a.publicOut >= U64_LIMIT || a.fee >= U64_LIMIT || a.deadline >= U64_LIMIT) revert ValueOutOfRange();
        if (a.fee > a.publicOut) revert FeeExceedsPublicOut();
        uint256 toRecipient = a.publicOut - a.fee;
        if (toRecipient != 0 && a.recipient == address(0)) revert ZeroRecipient();
        // v3: with no public payout the signed publicRecipient must be zero, so the approval screen
        // never shows a recipient that receives nothing.
        if (toRecipient == 0 && a.recipient != address(0)) revert RecipientWithoutPayout();
        if (a.fee != 0 && a.relayer == address(0)) revert ZeroRelayer();

        if (!verifier.verify(proof, buildPublicInputs(a))) revert InvalidProof();

        nullifierSpent[n0] = true;
        emit NewNullifier(n0);
        nullifierSpent[n1] = true;
        emit NewNullifier(n1);

        uint32 index0 = _insert(a.outCommitments[0]);
        emit NewCommitment(a.outCommitments[0], index0, a.encryptedOutput0);
        uint32 index1 = _insert(a.outCommitments[1]);
        emit NewCommitment(a.outCommitments[1], index1, a.encryptedOutput1);

        if (toRecipient != 0) _transferOut(a.recipient, toRecipient);
        if (a.fee != 0) _transferOut(a.relayer, a.fee);

        emit Transacted(a.relayer, a.recipient, a.publicOut, a.fee);
    }

    /// @notice The exact 14 public inputs `transact` passes to the verifier (handy for off-chain checks).
    function buildPublicInputs(TransactArgs calldata a) public view returns (bytes32[] memory inputs) {
        uint256 domain = uint256(DOMAIN_SEPARATOR);
        inputs = new bytes32[](NUM_PUBLIC_INPUTS);
        inputs[0] = bytes32(a.root);
        inputs[1] = bytes32(a.aspRoot);
        inputs[2] = bytes32(a.nullifiers[0]);
        inputs[3] = bytes32(a.nullifiers[1]);
        inputs[4] = bytes32(a.outCommitments[0]);
        inputs[5] = bytes32(a.outCommitments[1]);
        inputs[6] = bytes32(a.publicOut);
        inputs[7] = bytes32(extDataHash(a.relayer, a.encryptedOutput0, a.encryptedOutput1));
        inputs[8] = bytes32(uint256(uint160(address(token))));
        inputs[9] = bytes32(uint256(uint160(a.recipient)));
        inputs[10] = bytes32(a.fee);
        inputs[11] = bytes32(a.deadline);
        inputs[12] = bytes32(domain >> 128);
        inputs[13] = bytes32(domain & LOW_128_MASK);
    }

    /// @notice uint256(keccak256(abi.encode(relayer, encryptedOutput0, encryptedOutput1))) % FIELD_SIZE.
    function extDataHash(address relayer, bytes calldata encryptedOutput0, bytes calldata encryptedOutput1)
        public
        pure
        returns (uint256)
    {
        return uint256(keccak256(abi.encode(relayer, encryptedOutput0, encryptedOutput1))) % FIELD_SIZE;
    }

    // ------------------------------------------------------------------------------------------------
    // ASP (Association Set Provider)
    // ------------------------------------------------------------------------------------------------

    function setAspRoot(uint256 root) external {
        if (msg.sender != aspOperator) revert NotAspOperator();
        if (root == 0 || root >= FIELD_SIZE) revert InvalidAspRoot();
        uint256 index = (currentAspRootIndex + 1) % ASP_ROOT_HISTORY_SIZE;
        currentAspRootIndex = index;
        aspRoots[index] = root;
        emit AspRootUpdated(root, index);
    }

    /// @notice Latest ASP root (0 until the operator publishes one).
    function currentAspRoot() public view returns (uint256) {
        return aspRoots[currentAspRootIndex];
    }

    /// @notice True if `root` is one of the last ASP_ROOT_HISTORY_SIZE ASP roots. 0 is never known.
    function isKnownAspRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        for (uint256 i; i < ASP_ROOT_HISTORY_SIZE; ++i) {
            if (aspRoots[i] == root) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------------------------------------
    // Admin
    // ------------------------------------------------------------------------------------------------

    function setAspOperator(address newOperator) external onlyOwner {
        if (newOperator == address(0)) revert ZeroAddress();
        emit AspOperatorUpdated(aspOperator, newOperator);
        aspOperator = newOperator;
    }

    /// @notice Stop new deposits (`deposit`, `depositWithAuthorization`). `transact` stays callable.
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Resume deposits.
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function setMaxDeposit(uint256 newMaxDeposit) external onlyOwner {
        maxDeposit = newMaxDeposit;
        emit MaxDepositUpdated(newMaxDeposit);
    }

    function setTvlCap(uint256 newTvlCap) external onlyOwner {
        tvlCap = newTvlCap;
        emit TvlCapUpdated(newTvlCap);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ------------------------------------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------------------------------------

    function _transferOut(address to, uint256 amount) internal {
        if (!token.transfer(to, amount)) revert TransferFailed();
    }

    /// @dev Deposit checks shared by both deposit paths (run before any funds move).
    function _checkDeposit(uint256 amount, uint256 precommitment) internal view {
        // amount < 2^64 additionally keeps the note spendable (circuit amounts are u64).
        if (amount == 0 || amount > maxDeposit || amount >= U64_LIMIT) revert InvalidAmount();
        if (precommitment >= FIELD_SIZE) revert InvalidPrecommitment();
        if (token.balanceOf(address(this)) + amount > tvlCap) revert TvlCapExceeded();
    }

    /// @dev Deposit bookkeeping shared by both deposit paths, after `amount` has been received:
    ///      label from depositCount, commitment, leaf insertion, events.
    function _recordDeposit(address depositor, uint256 amount, uint256 precommitment, bytes calldata encryptedNote)
        internal
        returns (uint256 commitment, uint32 leafIndex)
    {
        uint256 count = depositCount;
        uint256 label = uint256(keccak256(abi.encodePacked(address(this), count))) % FIELD_SIZE;
        depositCount = count + 1;

        commitment = PoseidonT5.hash([uint256(uint160(address(token))), amount, label, precommitment]);
        leafIndex = _insert(commitment);

        emit NewCommitment(commitment, leafIndex, encryptedNote);
        emit Deposited(depositor, commitment, label, amount, leafIndex);
    }

    function _authorizationNonce(uint256 fee, uint256 precommitment, bytes calldata encryptedNote)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(address(this), precommitment, keccak256(encryptedNote), fee));
    }

    /// @dev Separate frame to keep `depositWithAuthorization` below the legacy-codegen stack limit.
    ///      USDC requires msg.sender == to, i.e. the pool.
    function _receiveWithAuthorization(
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        IERC3009(address(token))
            .receiveWithAuthorization(from, address(this), value, validAfter, validBefore, nonce, v, r, s);
    }
}
