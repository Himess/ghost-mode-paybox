// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {GhostPool} from "../src/GhostPool.sol";
import {MerkleTreeWithHistory} from "../src/MerkleTreeWithHistory.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {PoseidonT3} from "../src/poseidon/PoseidonT3.sol";
import {PoseidonT5} from "../src/poseidon/PoseidonT5.sol";
import {MockUSDC} from "./mocks/MockUSDC.sol";
import {MockVerifier} from "./mocks/MockVerifier.sol";

contract GhostPoolTest is Test {
    uint256 constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant MAX_DEPOSIT = 100e6;
    uint256 constant TVL_CAP = 1000e6;

    event NewCommitment(uint256 indexed commitment, uint32 leafIndex, bytes encryptedOutput);
    event NewNullifier(uint256 indexed nullifier);
    event Deposited(
        address indexed depositor, uint256 indexed commitment, uint256 label, uint256 amount, uint32 leafIndex
    );
    event Transacted(address indexed relayer, address indexed recipient, uint256 publicOut, uint256 fee);

    MockUSDC usdc;
    MockVerifier verifier;
    GhostPool pool;

    address owner = makeAddr("owner");
    address asp = makeAddr("asp");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address relayer = makeAddr("relayer");
    uint256 constant CAROL_KEY = 0xCA401C0FFEE5EED;
    address carol = vm.addr(CAROL_KEY);

    uint256 constant ASP_ROOT = 0x1234567890abcdef;
    uint256[] leaves; // mirror of the pool's leaves, for an independent root computation

    function setUp() public {
        vm.warp(1_760_000_000);
        usdc = new MockUSDC();
        verifier = new MockVerifier();
        pool = new GhostPool(IERC20(address(usdc)), IVerifier(address(verifier)), owner, asp, MAX_DEPOSIT, TVL_CAP);
        usdc.mint(alice, 10_000e6);
        vm.prank(alice);
        usdc.approve(address(pool), type(uint256).max);
        usdc.mint(carol, 10_000e6); // EIP-3009 signer: no approval needed
    }

    // ---------------------------------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------------------------------

    function _label(uint256 count) internal view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(address(pool), count))) % FIELD_SIZE;
    }

    function _commitment(uint256 amount, uint256 label, uint256 precommitment) internal view returns (uint256) {
        return PoseidonT5.hash([uint256(uint160(address(usdc))), amount, label, precommitment]);
    }

    function _deposit(uint256 amount, uint256 precommitment) internal returns (uint256 commitment, uint32 index) {
        vm.prank(alice);
        (commitment, index) = pool.deposit(amount, precommitment, hex"c0ffee");
        leaves.push(commitment);
    }

    /// @dev Full (non-incremental) recomputation of the depth-16 root over `leaves`.
    function _referenceRoot() internal view returns (uint256) {
        uint256 n = leaves.length;
        uint256[] memory level = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            level[i] = leaves[i];
        }
        for (uint256 d; d < 16; ++d) {
            uint256 m = n == 0 ? 1 : (n + 1) / 2;
            uint256[] memory next = new uint256[](m);
            uint256 z = pool.zeros(d);
            for (uint256 i; i < m; ++i) {
                uint256 l = 2 * i < n ? level[2 * i] : z;
                uint256 r = 2 * i + 1 < n ? level[2 * i + 1] : z;
                next[i] = PoseidonT3.hash([l, r]);
            }
            level = next;
            n = m;
        }
        return level[0];
    }

    function _args() internal view returns (GhostPool.TransactArgs memory a) {
        a.root = pool.getLastRoot();
        a.aspRoot = ASP_ROOT;
        a.nullifiers = [uint256(111), uint256(222)];
        a.outCommitments = [uint256(333), uint256(444)];
        a.publicOut = 30e6;
        a.recipient = bob;
        a.fee = 1e6;
        a.deadline = block.timestamp + 1 hours;
        a.relayer = relayer;
        a.encryptedOutput0 = hex"aa01";
        a.encryptedOutput1 = hex"bb0202";
    }

    function _fundedPoolWithAsp() internal {
        _deposit(50e6, 7);
        _deposit(40e6, 8);
        vm.prank(asp);
        pool.setAspRoot(ASP_ROOT);
    }

    function _expectedInputs(GhostPool.TransactArgs memory a) internal view returns (bytes32[] memory p) {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("GhostMode"),
                keccak256("1"),
                block.chainid,
                address(pool)
            )
        );
        p = new bytes32[](14);
        p[0] = bytes32(a.root);
        p[1] = bytes32(a.aspRoot);
        p[2] = bytes32(a.nullifiers[0]);
        p[3] = bytes32(a.nullifiers[1]);
        p[4] = bytes32(a.outCommitments[0]);
        p[5] = bytes32(a.outCommitments[1]);
        p[6] = bytes32(a.publicOut);
        p[7] = bytes32(uint256(keccak256(abi.encode(a.relayer, a.encryptedOutput0, a.encryptedOutput1))) % FIELD_SIZE);
        p[8] = bytes32(uint256(uint160(address(usdc))));
        p[9] = bytes32(uint256(uint160(a.recipient)));
        p[10] = bytes32(a.fee);
        p[11] = bytes32(a.deadline);
        p[12] = bytes32(uint256(domain) >> 128);
        p[13] = bytes32(uint256(domain) & ((1 << 128) - 1));
    }

    // ---------------------------------------------------------------------------------------------
    // constructor / domain
    // ---------------------------------------------------------------------------------------------

    function test_constructorState() public view {
        assertEq(address(pool.token()), address(usdc));
        assertEq(address(pool.verifier()), address(verifier));
        assertEq(pool.owner(), owner);
        assertEq(pool.aspOperator(), asp);
        assertEq(pool.maxDeposit(), MAX_DEPOSIT);
        assertEq(pool.tvlCap(), TVL_CAP);
        assertEq(pool.depositCount(), 0);
        assertEq(pool.nextIndex(), 0);
        assertEq(pool.getLastRoot(), pool.zeros(16));
        assertEq(pool.currentAspRoot(), 0);
        assertFalse(pool.isKnownAspRoot(0));
        assertFalse(pool.paused());
    }

    function test_constructorRejectsZeroAddresses() public {
        vm.expectRevert(GhostPool.ZeroAddress.selector);
        new GhostPool(IERC20(address(0)), IVerifier(address(verifier)), owner, asp, 1, 1);
        vm.expectRevert(GhostPool.ZeroAddress.selector);
        new GhostPool(IERC20(address(usdc)), IVerifier(address(0)), owner, asp, 1, 1);
        vm.expectRevert(GhostPool.ZeroAddress.selector);
        new GhostPool(IERC20(address(usdc)), IVerifier(address(verifier)), address(0), asp, 1, 1);
        vm.expectRevert(GhostPool.ZeroAddress.selector);
        new GhostPool(IERC20(address(usdc)), IVerifier(address(verifier)), owner, address(0), 1, 1);
    }

    function test_domainSeparator() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("GhostMode"),
                keccak256("1"),
                block.chainid,
                address(pool)
            )
        );
        assertEq(pool.DOMAIN_SEPARATOR(), expected);
    }

    // ---------------------------------------------------------------------------------------------
    // deposit
    // ---------------------------------------------------------------------------------------------

    function test_deposit() public {
        uint256 amount = 25e6;
        uint256 pre = 123456789;
        uint256 label = _label(0);
        uint256 expectedCommitment = _commitment(amount, label, pre);
        uint256 rootBefore = pool.getLastRoot();

        vm.expectEmit(true, true, true, true, address(pool));
        emit NewCommitment(expectedCommitment, 0, hex"c0ffee");
        vm.expectEmit(true, true, true, true, address(pool));
        emit Deposited(alice, expectedCommitment, label, amount, 0);
        (uint256 commitment, uint32 index) = _deposit(amount, pre);

        assertEq(commitment, expectedCommitment);
        assertEq(index, 0);
        assertEq(pool.nextIndex(), 1);
        assertEq(pool.depositCount(), 1);
        assertEq(usdc.balanceOf(address(pool)), amount);
        assertEq(usdc.balanceOf(alice), 10_000e6 - amount);

        uint256 rootAfter = pool.getLastRoot();
        assertTrue(rootAfter != rootBefore);
        assertEq(rootAfter, _referenceRoot());
        assertTrue(pool.isKnownRoot(rootAfter));
        assertTrue(pool.isKnownRoot(rootBefore));
        assertEq(pool.filledSubtrees(0), expectedCommitment);

        // Second deposit: label uses depositCount = 1, next leaf index.
        uint256 label1 = _label(1);
        assertTrue(label1 != label);
        uint256 expected1 = _commitment(10e6, label1, pre);
        vm.expectEmit(true, true, true, true, address(pool));
        emit Deposited(alice, expected1, label1, 10e6, 1);
        (uint256 c1, uint32 i1) = _deposit(10e6, pre);
        assertEq(c1, expected1);
        assertEq(i1, 1);
        assertEq(pool.getLastRoot(), _referenceRoot());
        assertTrue(pool.isKnownRoot(rootAfter));
        assertEq(pool.depositCount(), 2);
    }

    function test_depositManyMatchesReferenceRoot() public {
        for (uint256 i; i < 5; ++i) {
            _deposit(1e6 + i, 1000 + i);
        }
        assertEq(pool.nextIndex(), 5);
        assertEq(pool.getLastRoot(), _referenceRoot());
    }

    function test_depositRevertsZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(GhostPool.InvalidAmount.selector);
        pool.deposit(0, 1, "");
    }

    function test_depositRevertsAboveMaxDeposit() public {
        vm.prank(alice);
        vm.expectRevert(GhostPool.InvalidAmount.selector);
        pool.deposit(MAX_DEPOSIT + 1, 1, "");
        // exactly maxDeposit is fine
        _deposit(MAX_DEPOSIT, 1);
    }

    function test_depositRevertsAboveU64EvenIfMaxDepositAllows() public {
        vm.prank(owner);
        pool.setMaxDeposit(type(uint256).max);
        vm.prank(owner);
        pool.setTvlCap(type(uint256).max);
        usdc.mint(alice, 1 << 64);
        vm.prank(alice);
        vm.expectRevert(GhostPool.InvalidAmount.selector);
        pool.deposit(1 << 64, 1, "");
    }

    function test_depositRevertsPrecommitmentOutOfField() public {
        vm.prank(alice);
        vm.expectRevert(GhostPool.InvalidPrecommitment.selector);
        pool.deposit(1e6, FIELD_SIZE, "");
    }

    function test_depositRevertsTvlCap() public {
        for (uint256 i; i < 10; ++i) {
            _deposit(MAX_DEPOSIT, i); // reaches exactly TVL_CAP
        }
        assertEq(usdc.balanceOf(address(pool)), TVL_CAP);
        vm.prank(alice);
        vm.expectRevert(GhostPool.TvlCapExceeded.selector);
        pool.deposit(1, 1, "");
    }

    function test_depositTvlCapCountsDirectTransfers() public {
        usdc.mint(address(pool), TVL_CAP - 5e6);
        vm.prank(alice);
        vm.expectRevert(GhostPool.TvlCapExceeded.selector);
        pool.deposit(5e6 + 1, 1, "");
        _deposit(5e6, 1);
    }

    function test_depositRevertsWhenPaused() public {
        vm.prank(owner);
        pool.pause();
        vm.prank(alice);
        vm.expectRevert(GhostPool.EnforcedPause.selector);
        pool.deposit(1e6, 1, "");
        vm.prank(owner);
        pool.unpause();
        _deposit(1e6, 1);
    }

    function test_depositRevertsWithoutAllowance() public {
        vm.prank(alice);
        usdc.approve(address(pool), 0);
        vm.prank(alice);
        vm.expectRevert(bytes("ERC20: insufficient allowance"));
        pool.deposit(1e6, 1, "");
    }

    function test_depositRevertsWhenTransferFromReturnsFalse() public {
        usdc.setReturnFalse(true);
        vm.prank(alice);
        vm.expectRevert(GhostPool.TransferFailed.selector);
        pool.deposit(1e6, 1, "");
    }

    // ---------------------------------------------------------------------------------------------
    // ASP
    // ---------------------------------------------------------------------------------------------

    function test_setAspRootOnlyOperator() public {
        vm.prank(alice);
        vm.expectRevert(GhostPool.NotAspOperator.selector);
        pool.setAspRoot(5);
        vm.prank(owner);
        vm.expectRevert(GhostPool.NotAspOperator.selector);
        pool.setAspRoot(5);

        vm.prank(asp);
        pool.setAspRoot(5);
        assertEq(pool.currentAspRoot(), 5);
        assertTrue(pool.isKnownAspRoot(5));
        assertFalse(pool.isKnownAspRoot(6));
        assertFalse(pool.isKnownAspRoot(0));
    }

    function test_setAspRootValidation() public {
        vm.startPrank(asp);
        vm.expectRevert(GhostPool.InvalidAspRoot.selector);
        pool.setAspRoot(0);
        vm.expectRevert(GhostPool.InvalidAspRoot.selector);
        pool.setAspRoot(FIELD_SIZE);
        pool.setAspRoot(FIELD_SIZE - 1);
        vm.stopPrank();
        assertTrue(pool.isKnownAspRoot(FIELD_SIZE - 1));
    }

    function test_aspRootHistoryKeepsLast16() public {
        vm.startPrank(asp);
        for (uint256 r = 1; r <= 16; ++r) {
            pool.setAspRoot(r);
        }
        for (uint256 r = 1; r <= 16; ++r) {
            assertTrue(pool.isKnownAspRoot(r));
        }
        pool.setAspRoot(17);
        vm.stopPrank();
        assertFalse(pool.isKnownAspRoot(1), "oldest evicted");
        for (uint256 r = 2; r <= 17; ++r) {
            assertTrue(pool.isKnownAspRoot(r));
        }
        assertEq(pool.currentAspRoot(), 17);
    }

    function test_ownerCanChangeAspOperator() public {
        address newAsp = makeAddr("newAsp");
        vm.prank(alice);
        vm.expectRevert(GhostPool.NotOwner.selector);
        pool.setAspOperator(newAsp);
        vm.prank(asp);
        vm.expectRevert(GhostPool.NotOwner.selector);
        pool.setAspOperator(newAsp);
        vm.prank(owner);
        vm.expectRevert(GhostPool.ZeroAddress.selector);
        pool.setAspOperator(address(0));

        vm.prank(owner);
        pool.setAspOperator(newAsp);
        assertEq(pool.aspOperator(), newAsp);
        vm.prank(asp);
        vm.expectRevert(GhostPool.NotAspOperator.selector);
        pool.setAspRoot(9);
        vm.prank(newAsp);
        pool.setAspRoot(9);
        assertEq(pool.currentAspRoot(), 9);
    }

    // ---------------------------------------------------------------------------------------------
    // transact: positive path (mock verifier)
    // ---------------------------------------------------------------------------------------------

    function test_transactHappyPath() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        bytes memory proof = hex"deadbeef";

        // The verifier receives exactly the 14 expected public inputs, in order.
        bytes32[] memory expected = _expectedInputs(a);
        assertEq(pool.buildPublicInputs(a), expected);
        vm.expectCall(address(verifier), abi.encodeCall(IVerifier.verify, (proof, expected)));

        vm.expectEmit(true, true, true, true, address(pool));
        emit NewNullifier(111);
        vm.expectEmit(true, true, true, true, address(pool));
        emit NewNullifier(222);
        vm.expectEmit(true, true, true, true, address(pool));
        emit NewCommitment(333, 2, hex"aa01");
        vm.expectEmit(true, true, true, true, address(pool));
        emit NewCommitment(444, 3, hex"bb0202");
        vm.expectEmit(true, true, true, true, address(pool));
        emit Transacted(relayer, bob, 30e6, 1e6);

        vm.prank(makeAddr("anyone")); // anyone may submit
        pool.transact(proof, a);

        assertTrue(pool.nullifierSpent(111));
        assertTrue(pool.nullifierSpent(222));
        assertEq(pool.nextIndex(), 4);
        leaves.push(333);
        leaves.push(444);
        assertEq(pool.getLastRoot(), _referenceRoot());
        assertTrue(pool.isKnownRoot(a.root));
        assertEq(usdc.balanceOf(bob), 29e6);
        assertEq(usdc.balanceOf(relayer), 1e6);
        assertEq(usdc.balanceOf(address(pool)), 90e6 - 30e6);

        // Replay is rejected.
        a.root = pool.getLastRoot();
        vm.expectRevert(GhostPool.NullifierAlreadySpent.selector);
        pool.transact(proof, a);
    }

    function test_transactInternalTransferNoPayouts() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.publicOut = 0;
        a.fee = 0;
        a.recipient = address(0);
        a.relayer = address(0);
        pool.transact(hex"01", a);
        assertEq(usdc.balanceOf(address(pool)), 90e6);
        assertEq(pool.nextIndex(), 4);
        assertTrue(pool.nullifierSpent(111));
    }

    function test_transactFeeOnlyToRelayer() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.publicOut = 2e6;
        a.fee = 2e6;
        a.recipient = address(0); // nothing goes to the recipient
        pool.transact(hex"01", a);
        assertEq(usdc.balanceOf(relayer), 2e6);
        assertEq(usdc.balanceOf(address(pool)), 88e6);
    }

    function test_transactWithOlderRoots() public {
        _fundedPoolWithAsp();
        uint256 oldRoot = pool.getLastRoot();
        _deposit(1e6, 9);
        vm.prank(asp);
        pool.setAspRoot(ASP_ROOT + 1);
        GhostPool.TransactArgs memory a = _args();
        a.root = oldRoot; // still in the 64-root history
        a.aspRoot = ASP_ROOT; // still in the 16-root ASP history
        pool.transact(hex"01", a);
        assertTrue(pool.nullifierSpent(222));
    }

    // ---------------------------------------------------------------------------------------------
    // transact: negative paths
    // ---------------------------------------------------------------------------------------------

    function test_transactRevertsUnknownRoot() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.root = 42;
        vm.expectRevert(GhostPool.UnknownRoot.selector);
        pool.transact(hex"01", a);
        a.root = 0;
        vm.expectRevert(GhostPool.UnknownRoot.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsUnknownAspRoot() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.aspRoot = ASP_ROOT + 1;
        vm.expectRevert(GhostPool.UnknownAspRoot.selector);
        pool.transact(hex"01", a);
        a.aspRoot = 0;
        vm.expectRevert(GhostPool.UnknownAspRoot.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsWithoutAnyAspRoot() public {
        _deposit(50e6, 7);
        GhostPool.TransactArgs memory a = _args();
        a.aspRoot = 0;
        vm.expectRevert(GhostPool.UnknownAspRoot.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsSpentNullifier() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.publicOut = 0;
        a.fee = 0;
        a.recipient = address(0); // v3: no public payout means no public recipient
        pool.transact(hex"01", a);

        GhostPool.TransactArgs memory b = _args();
        b.nullifiers = [uint256(999), uint256(222)]; // second one already spent
        b.outCommitments = [uint256(555), uint256(666)];
        vm.expectRevert(GhostPool.NullifierAlreadySpent.selector);
        pool.transact(hex"01", b);
        b.nullifiers = [uint256(111), uint256(999)]; // first one already spent
        vm.expectRevert(GhostPool.NullifierAlreadySpent.selector);
        pool.transact(hex"01", b);
    }

    function test_transactRevertsDuplicateNullifiers() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.nullifiers = [uint256(777), uint256(777)];
        vm.expectRevert(GhostPool.DuplicateNullifier.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsNullifierOutOfField() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.nullifiers = [uint256(111) + FIELD_SIZE, uint256(222)];
        vm.expectRevert(GhostPool.InvalidNullifier.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsCommitmentOutOfField() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.outCommitments = [uint256(1), FIELD_SIZE];
        vm.expectRevert(GhostPool.InvalidCommitment.selector);
        pool.transact(hex"01", a);
        a.outCommitments = [FIELD_SIZE + 5, uint256(1)];
        vm.expectRevert(GhostPool.InvalidCommitment.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsExpiredDeadline() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.deadline = block.timestamp - 1;
        vm.expectRevert(GhostPool.DeadlineExpired.selector);
        pool.transact(hex"01", a);
        // deadline == now is still valid
        a.deadline = block.timestamp;
        pool.transact(hex"01", a);
    }

    function test_transactRevertsValuesOutOfU64() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.publicOut = 1 << 64;
        vm.expectRevert(GhostPool.ValueOutOfRange.selector);
        pool.transact(hex"01", a);

        a = _args();
        a.fee = 1 << 64;
        vm.expectRevert(GhostPool.ValueOutOfRange.selector);
        pool.transact(hex"01", a);

        a = _args();
        a.deadline = 1 << 64;
        vm.expectRevert(GhostPool.ValueOutOfRange.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsFeeAbovePublicOut() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.publicOut = 1e6;
        a.fee = 1e6 + 1;
        vm.expectRevert(GhostPool.FeeExceedsPublicOut.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsZeroRecipientWithValue() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.recipient = address(0);
        vm.expectRevert(GhostPool.ZeroRecipient.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsRecipientWithoutPayout() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.publicOut = a.fee; // nothing leaves the pool except the relayer fee
        vm.expectRevert(GhostPool.RecipientWithoutPayout.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsZeroRelayerWithFee() public {
        _fundedPoolWithAsp();
        GhostPool.TransactArgs memory a = _args();
        a.relayer = address(0);
        vm.expectRevert(GhostPool.ZeroRelayer.selector);
        pool.transact(hex"01", a);
    }

    function test_transactRevertsInvalidProof() public {
        _fundedPoolWithAsp();
        verifier.setResult(false);
        GhostPool.TransactArgs memory a = _args();
        vm.expectRevert(GhostPool.InvalidProof.selector);
        pool.transact(hex"01", a);
        assertFalse(pool.nullifierSpent(111));
    }

    /// @dev v2: pause stops deposits only; exits (transact) stay open.
    function test_transactWorksWhenPaused() public {
        _fundedPoolWithAsp();
        vm.prank(owner);
        pool.pause();
        GhostPool.TransactArgs memory a = _args();
        pool.transact(hex"01", a);
        assertTrue(pool.nullifierSpent(111));
        assertTrue(pool.nullifierSpent(222));
        assertEq(usdc.balanceOf(bob), 29e6);
        assertEq(usdc.balanceOf(relayer), 1e6);
        assertTrue(pool.paused());
    }

    function test_transactRevertsWhenPayoutTransferReturnsFalse() public {
        _fundedPoolWithAsp();
        usdc.setReturnFalse(true);
        GhostPool.TransactArgs memory a = _args();
        vm.expectRevert(GhostPool.TransferFailed.selector);
        pool.transact(hex"01", a);
    }

    function test_extDataHashBindsAllFields() public view {
        uint256 h = pool.extDataHash(relayer, hex"aa01", hex"bb0202");
        assertEq(h, uint256(keccak256(abi.encode(relayer, bytes(hex"aa01"), bytes(hex"bb0202")))) % FIELD_SIZE);
        assertTrue(h != pool.extDataHash(bob, hex"aa01", hex"bb0202"));
        assertTrue(h != pool.extDataHash(relayer, hex"aa02", hex"bb0202"));
        assertTrue(h != pool.extDataHash(relayer, hex"aa01", hex"bb0203"));
        assertTrue(h < FIELD_SIZE);
    }

    // ---------------------------------------------------------------------------------------------
    // admin
    // ---------------------------------------------------------------------------------------------

    function test_adminOnlyOwner() public {
        vm.startPrank(alice);
        vm.expectRevert(GhostPool.NotOwner.selector);
        pool.pause();
        vm.expectRevert(GhostPool.NotOwner.selector);
        pool.unpause();
        vm.expectRevert(GhostPool.NotOwner.selector);
        pool.setMaxDeposit(1);
        vm.expectRevert(GhostPool.NotOwner.selector);
        pool.setTvlCap(1);
        vm.expectRevert(GhostPool.NotOwner.selector);
        pool.transferOwnership(alice);
        vm.stopPrank();
    }

    function test_adminSetters() public {
        vm.startPrank(owner);
        pool.setMaxDeposit(5e6);
        pool.setTvlCap(7e6);
        pool.pause();
        assertTrue(pool.paused());
        pool.unpause();
        assertFalse(pool.paused());
        vm.expectRevert(GhostPool.ZeroAddress.selector);
        pool.transferOwnership(address(0));
        pool.transferOwnership(bob);
        vm.stopPrank();
        assertEq(pool.maxDeposit(), 5e6);
        assertEq(pool.tvlCap(), 7e6);
        assertEq(pool.owner(), bob);

        vm.prank(owner);
        vm.expectRevert(GhostPool.NotOwner.selector);
        pool.pause();
        vm.prank(bob);
        pool.pause();
        assertTrue(pool.paused());
    }

    // ---------------------------------------------------------------------------------------------
    // depositWithAuthorization (USDC EIP-3009 receiveWithAuthorization)
    // ---------------------------------------------------------------------------------------------

    bytes32 constant RECEIVE_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    struct Auth {
        address from;
        uint256 key;
        uint256 value;
        uint256 fee;
        uint256 validAfter;
        uint256 validBefore;
        uint256 precommitment;
        bytes note;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// @dev Independent re-implementation of the nonce + USDC EIP-712 digest a client signs.
    function _authDigest(Auth memory a) internal view returns (bytes32) {
        bytes32 nonce = keccak256(abi.encode(address(pool), a.precommitment, keccak256(a.note), a.fee));
        bytes32 structHash =
            keccak256(abi.encode(RECEIVE_TYPEHASH, a.from, address(pool), a.value, a.validAfter, a.validBefore, nonce));
        return keccak256(abi.encodePacked("\x19\x01", usdc.DOMAIN_SEPARATOR(), structHash));
    }

    function _sign(Auth memory a) internal view {
        (a.v, a.r, a.s) = vm.sign(a.key, _authDigest(a));
    }

    /// @dev Carol signs `value` (incl. `fee`) for the pool, valid now for one hour.
    function _auth(uint256 value, uint256 fee, uint256 precommitment) internal view returns (Auth memory a) {
        a.from = carol;
        a.key = CAROL_KEY;
        a.value = value;
        a.fee = fee;
        a.validAfter = block.timestamp - 1;
        a.validBefore = block.timestamp + 1 hours;
        a.precommitment = precommitment;
        a.note = hex"5ea1ed01";
        _sign(a);
    }

    function _submit(address sender, Auth memory a) internal returns (uint256 commitment, uint32 leafIndex) {
        vm.prank(sender);
        (commitment, leafIndex) = pool.depositWithAuthorization(
            a.from, a.value, a.fee, a.validAfter, a.validBefore, a.precommitment, a.note, a.v, a.r, a.s
        );
    }

    function test_mockUsdcEip712Domain() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("USD Coin"),
                keccak256("2"),
                block.chainid,
                address(usdc)
            )
        );
        assertEq(usdc.DOMAIN_SEPARATOR(), expected);
        // Clients build the domain from the token's on-chain name() / version(), as on Base USDC.
        assertEq(
            usdc.DOMAIN_SEPARATOR(),
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256(bytes(usdc.name())),
                    keccak256(bytes(usdc.version())),
                    block.chainid,
                    address(usdc)
                )
            )
        );
        assertEq(usdc.name(), "USD Coin");
        assertEq(usdc.version(), "2");
        assertEq(usdc.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(), RECEIVE_TYPEHASH);
    }

    function test_authorizationNonceFormula() public view {
        bytes memory note = hex"5ea1ed01";
        bytes32 n = pool.authorizationNonce(7, note, 3);
        assertEq(n, keccak256(abi.encode(address(pool), uint256(7), keccak256(note), uint256(3))));
        assertTrue(n != pool.authorizationNonce(8, note, 3));
        assertTrue(n != pool.authorizationNonce(7, hex"5ea1ed02", 3));
        assertTrue(n != pool.authorizationNonce(7, note, 4));
    }

    function test_depositWithAuthorizationHappyPath() public {
        Auth memory a = _auth(25e6, 5e5, 987654321);
        uint256 amount = 25e6 - 5e5;
        bytes32 nonce = keccak256(abi.encode(address(pool), a.precommitment, keccak256(a.note), a.fee));
        assertEq(pool.authorizationNonce(a.precommitment, a.note, a.fee), nonce);
        assertFalse(usdc.authorizationState(carol, nonce));

        uint256 label = _label(0);
        uint256 expected = _commitment(amount, label, a.precommitment);

        vm.expectEmit(true, true, true, true, address(pool));
        emit NewCommitment(expected, 0, a.note);
        vm.expectEmit(true, true, true, true, address(pool));
        emit Deposited(carol, expected, label, amount, 0); // depositor == from, not the relayer
        (uint256 commitment, uint32 index) = _submit(relayer, a);
        leaves.push(commitment);

        assertEq(commitment, expected);
        assertEq(index, 0);
        assertEq(pool.depositCount(), 1);
        assertEq(pool.nextIndex(), 1);
        assertEq(pool.getLastRoot(), _referenceRoot());
        assertTrue(pool.isKnownRoot(pool.getLastRoot()));
        assertEq(usdc.balanceOf(address(pool)), amount);
        assertEq(usdc.balanceOf(relayer), 5e5); // fee to msg.sender
        assertEq(usdc.balanceOf(carol), 10_000e6 - 25e6);
        assertTrue(usdc.authorizationState(carol, nonce));

        // Label counter is shared with `deposit`: the next classic deposit uses depositCount = 1.
        uint256 label1 = _label(1);
        uint256 expected1 = _commitment(10e6, label1, 5);
        vm.expectEmit(true, true, true, true, address(pool));
        emit Deposited(alice, expected1, label1, 10e6, 1);
        _deposit(10e6, 5);
        assertEq(pool.getLastRoot(), _referenceRoot());
    }

    function test_depositWithAuthorizationZeroFee() public {
        Auth memory a = _auth(MAX_DEPOSIT, 0, 42);
        address anyone = makeAddr("anyone");
        (uint256 commitment, uint32 index) = _submit(anyone, a);
        assertEq(commitment, _commitment(MAX_DEPOSIT, _label(0), 42));
        assertEq(index, 0);
        assertEq(usdc.balanceOf(anyone), 0);
        assertEq(usdc.balanceOf(address(pool)), MAX_DEPOSIT);
    }

    function test_depositWithAuthorizationNonceBindsContents() public {
        Auth memory a = _auth(20e6, 1e6, 77);

        a.precommitment = 78;
        vm.expectRevert(bytes("FiatTokenV2: invalid signature"));
        _submit(relayer, a);
        a.precommitment = 77;

        a.note = hex"5ea1ed02";
        vm.expectRevert(bytes("FiatTokenV2: invalid signature"));
        _submit(relayer, a);
        a.note = hex"5ea1ed01";

        a.fee = 2e6; // relayer tries to raise its fee
        vm.expectRevert(bytes("FiatTokenV2: invalid signature"));
        _submit(relayer, a);
        a.fee = 0; // or to drop it
        vm.expectRevert(bytes("FiatTokenV2: invalid signature"));
        _submit(relayer, a);
        a.fee = 1e6;

        a.value = 21e6;
        vm.expectRevert(bytes("FiatTokenV2: invalid signature"));
        _submit(relayer, a);
        a.value = 20e6;

        a.validBefore += 1;
        vm.expectRevert(bytes("FiatTokenV2: invalid signature"));
        _submit(relayer, a);
        a.validBefore -= 1;

        assertEq(pool.depositCount(), 0);
        assertEq(usdc.balanceOf(address(pool)), 0);

        // The untouched authorization still works.
        (uint256 commitment,) = _submit(relayer, a);
        assertEq(commitment, _commitment(19e6, _label(0), 77));
    }

    function test_depositWithAuthorizationRejectsWrongSigner() public {
        Auth memory a = _auth(10e6, 0, 12);
        a.key = 0xBAD; // someone else signs for carol's funds
        _sign(a);
        vm.expectRevert(bytes("FiatTokenV2: invalid signature"));
        _submit(relayer, a);
    }

    function test_depositWithAuthorizationFrontRunIsHarmless() public {
        Auth memory a = _auth(30e6, 1e6, 99);
        address frontRunner = makeAddr("frontRunner");
        uint256 label = _label(0);
        uint256 expected = _commitment(29e6, label, 99);

        vm.expectEmit(true, true, true, true, address(pool));
        emit Deposited(carol, expected, label, 29e6, 0);
        (uint256 commitment,) = _submit(frontRunner, a);
        assertEq(commitment, expected); // same deposit the user signed
        assertEq(usdc.balanceOf(frontRunner), 1e6);

        vm.expectRevert(bytes("FiatTokenV2: authorization is used or canceled"));
        _submit(relayer, a);
        assertEq(pool.depositCount(), 1);
        assertEq(usdc.balanceOf(relayer), 0);
        assertEq(usdc.balanceOf(address(pool)), 29e6);
    }

    function test_receiveWithAuthorizationOnlyByPayee() public {
        Auth memory a = _auth(10e6, 0, 1);
        bytes32 nonce = pool.authorizationNonce(a.precommitment, a.note, a.fee);
        // A third party cannot consume the pool's authorization on the token directly...
        vm.prank(relayer);
        vm.expectRevert(bytes("FiatTokenV2: caller must be the payee"));
        usdc.receiveWithAuthorization(carol, address(pool), a.value, a.validAfter, a.validBefore, nonce, a.v, a.r, a.s);
        // ...nor redirect it to itself.
        vm.prank(relayer);
        vm.expectRevert(bytes("FiatTokenV2: invalid signature"));
        usdc.receiveWithAuthorization(carol, relayer, a.value, a.validAfter, a.validBefore, nonce, a.v, a.r, a.s);
        assertFalse(usdc.authorizationState(carol, nonce));
    }

    function test_depositWithAuthorizationRejectsMalleableSignature() public {
        Auth memory a = _auth(10e6, 1e5, 3);
        assertLe(uint256(a.s), SECP256K1_N / 2, "vm.sign returns low-s");
        uint8 v0 = a.v;
        bytes32 s0 = a.s;

        // High-s twin of the same signature: s' = n - s, recovery id flipped (27 <-> 28).
        a.s = bytes32(SECP256K1_N - uint256(s0));
        a.v = v0 == 27 ? 28 : 27;
        assertEq(ecrecover(_authDigest(a), a.v, a.r, a.s), carol); // valid for raw ecrecover...
        vm.expectRevert(bytes("ECRecover: invalid signature 's' value")); // ...rejected by the token
        _submit(relayer, a);

        // v outside {27, 28} (raw recovery id 0/1) is rejected.
        a.s = s0;
        a.v = v0 - 27;
        vm.expectRevert(bytes("ECRecover: invalid signature 'v' value"));
        _submit(relayer, a);

        // Normalizing the high-s twin (n - s', 27 <-> 28) yields the canonical signature, which works.
        uint8 vHigh = v0 == 27 ? 28 : 27;
        a.s = bytes32(SECP256K1_N - (SECP256K1_N - uint256(s0)));
        a.v = vHigh == 27 ? 28 : 27;
        assertEq(a.s, s0);
        assertEq(a.v, v0);
        _submit(relayer, a);
        assertEq(pool.depositCount(), 1);
    }

    function test_depositWithAuthorizationTimeWindow() public {
        Auth memory a = _auth(10e6, 0, 4);

        a.validBefore = block.timestamp; // validBefore is exclusive
        _sign(a);
        vm.expectRevert(bytes("FiatTokenV2: authorization is expired"));
        _submit(relayer, a);

        a.validBefore = block.timestamp + 1 hours;
        a.validAfter = block.timestamp; // validAfter is exclusive
        _sign(a);
        vm.expectRevert(bytes("FiatTokenV2: authorization is not yet valid"));
        _submit(relayer, a);

        vm.warp(block.timestamp + 1);
        _submit(relayer, a);
        assertEq(pool.depositCount(), 1);

        Auth memory b = _auth(10e6, 0, 5);
        vm.warp(b.validBefore); // expired after its window
        vm.expectRevert(bytes("FiatTokenV2: authorization is expired"));
        _submit(relayer, b);
    }

    function test_depositWithAuthorizationRevertsFeeNotBelowValue() public {
        Auth memory a = _auth(5e6, 5e6, 1); // fee == value
        vm.expectRevert(GhostPool.InvalidAmount.selector);
        _submit(relayer, a);
        a = _auth(5e6, 5e6 + 1, 1); // fee > value
        vm.expectRevert(GhostPool.InvalidAmount.selector);
        _submit(relayer, a);
        a = _auth(0, 0, 1);
        vm.expectRevert(GhostPool.InvalidAmount.selector);
        _submit(relayer, a);
    }

    function test_depositWithAuthorizationCaps() public {
        // maxDeposit applies to the shielded amount (value - fee).
        Auth memory a = _auth(MAX_DEPOSIT + 2e6, 2e6 - 1, 1);
        vm.expectRevert(GhostPool.InvalidAmount.selector);
        _submit(relayer, a);
        a = _auth(MAX_DEPOSIT + 2e6, 2e6, 1);
        _submit(relayer, a);
        assertEq(usdc.balanceOf(address(pool)), MAX_DEPOSIT);

        a = _auth(1e6, 0, FIELD_SIZE);
        vm.expectRevert(GhostPool.InvalidPrecommitment.selector);
        _submit(relayer, a);
    }

    function test_depositWithAuthorizationTvlCap() public {
        usdc.mint(address(pool), TVL_CAP - 5e6);
        Auth memory a = _auth(6e6 + 1, 1e6, 1); // net 5e6 + 1
        vm.expectRevert(GhostPool.TvlCapExceeded.selector);
        _submit(relayer, a);
        a = _auth(6e6, 1e6, 1); // net exactly fills the cap
        _submit(relayer, a);
        assertEq(usdc.balanceOf(address(pool)), TVL_CAP);
        assertEq(usdc.balanceOf(relayer), 1e6);
    }

    function test_depositWithAuthorizationRevertsAboveU64() public {
        vm.startPrank(owner);
        pool.setMaxDeposit(type(uint256).max);
        pool.setTvlCap(type(uint256).max);
        vm.stopPrank();
        usdc.mint(carol, 1 << 65);
        Auth memory a = _auth((1 << 64) + 1, 1, 1); // net 2^64
        vm.expectRevert(GhostPool.InvalidAmount.selector);
        _submit(relayer, a);
        a = _auth(1 << 64, 1, 1); // net 2^64 - 1
        (uint256 commitment,) = _submit(relayer, a);
        assertEq(commitment, _commitment((1 << 64) - 1, _label(0), 1));
    }

    function test_pauseBlocksBothDepositPathsButNotTransact() public {
        _fundedPoolWithAsp();
        Auth memory a = _auth(10e6, 1e5, 11);
        vm.prank(owner);
        pool.pause();

        vm.prank(alice);
        vm.expectRevert(GhostPool.EnforcedPause.selector);
        pool.deposit(1e6, 1, "");
        vm.expectRevert(GhostPool.EnforcedPause.selector);
        _submit(relayer, a);

        // Exits stay open while paused.
        GhostPool.TransactArgs memory t = _args();
        pool.transact(hex"01", t);
        assertTrue(pool.nullifierSpent(111));
        assertEq(usdc.balanceOf(bob), 29e6);

        vm.prank(owner);
        pool.unpause();
        _submit(relayer, a); // the reverted attempt did not consume the authorization
        assertEq(pool.depositCount(), 3);
    }
}
