// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ContractValidation} from "./ContractValidation.sol";

/**
 * @title BSCookMultiSig
 * @dev 2-of-3 multi-signature wallet with daily withdrawal limits, transaction
 *      expiry, and a mandatory cooling-off period for calls whose value-at-risk
 *      cannot be measured on-chain.
 *
 *      Owners: You + Partner + Backup wallet. Any 2 can approve.
 *
 *      THREAT MODEL / EXECUTION RULES
 *      ------------------------------
 *      Every transaction needs REQUIRED (2) confirmations from *currently
 *      valid* owners. On top of that, a transaction is classified by what
 *      it does, and each class gets a different guard. The class is
 *      pinned at SUBMISSION time (Transaction.cls) and never re-derived,
 *      so post-submission state changes (e.g. SELFDESTRUCT of the target)
 *      cannot downgrade a delayed call into an immediate one.
 *
 *        PlainEth      (data.length == 0, target is an EOA)
 *          -> 2-of-3, immediate. Bounded by dailyWithdrawLimit.
 *          FIX (Y-1): a call to a CONTRACT with empty data executes that
 *          contract's receive()/fallback() with msg.sender = this wallet,
 *          i.e. arbitrary attacker-chosen code. Only EOA targets keep the
 *          fast path; contract targets are Unrecognized (24h delay).
 *
 *        KnownErc20    (transfer / transferFrom / approve on an OWNER-TRUSTED
 *                       token, exact ABI length)
 *          -> 2-of-3, immediate. Bounded by dailyERC20WithdrawLimit, with
 *             `approve` charged at its full face value because an approved
 *             spender can pull it later with zero further multisig involvement.
 *          FIX (Y-1): the selector alone proved nothing about the target's
 *          semantics — any contract exposing a `transfer(address,uint256)`
 *          got the fast path. Tokens must now be registered in
 *          `trustedErc20` (via the Unrecognized path: 24h or 3-of-3).
 *
 *        SelfAdmin     (this contract's own bounded admin entry points)
 *          -> 2-of-3, immediate. Each entry point enforces its own hard caps
 *             and/or its own timelock (see replaceOwner).
 *
 *        Unrecognized  (everything else: routers, proxies, permit(), timelock
 *                       schedule/execute, unknown selectors)
 *          -> 2-of-3 PLUS a mandatory UNRECOGNIZED_CALL_DELAY cooling-off
 *             window measured from quorum. Any owner may veto a pending call;
 *             a 3-of-3 confirmation overrides the veto (and delay).
 *
 *      Why not simply demand 3-of-3 for Unrecognized calls (the previous
 *      design)? Because it silently converts a 2-of-3 wallet into a 3-of-3 one
 *      for every meaningful operation - including calling the governance
 *      Timelock and including replaceOwner itself. Losing or bricking a single
 *      key would then permanently and irrecoverably freeze protocol
 *      governance: the factory could never be unpaused, the locker could never
 *      resume a paused fee redirect, and the dead key could never be rotated
 *      out (you would need the dead key to approve its own replacement).
 *      A delay preserves the 2-of-3 liveness guarantee while still giving the
 *      third key holder a public window to react to a 2-key compromise.
 */
contract BSCookMultiSig is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // =========================================================================
    // Events
    // =========================================================================
    event TransactionSubmitted(uint256 indexed txId, address target, uint256 value, bytes data);
    event TransactionConfirmed(uint256 indexed txId, address indexed owner);
    /// @notice Emitted once when a transaction first reaches REQUIRED confirmations.
    event ThresholdReached(uint256 indexed txId, uint256 at);
    event TransactionExecuted(uint256 indexed txId);
    event TransactionRevoked(uint256 indexed txId, address indexed owner);
    event TransactionVetoed(uint256 indexed txId, address indexed owner);
    event PauseTargetUpdated(address indexed oldTarget, address indexed newTarget);
    event AutoExecutionFailed(uint256 indexed txId);
    event DailyLimitUpdated(uint256 oldLimit, uint256 newLimit);
    event Erc20DailyLimitUpdated(uint256 oldLimit, uint256 newLimit);
    event TokenDailyLimitUpdated(address indexed token, uint256 oldLimit, uint256 newLimit);
    event TransactionExpiryUpdated(uint256 oldExpiry, uint256 newExpiry);
    event OwnerReplacementProposed(bytes32 indexed replacementHash, uint256 index, address newOwner, uint256 eta);
    event OwnerReplaced(uint256 indexed index, address indexed oldOwner, address indexed newOwner);
    event TrustedErc20Updated(address indexed token, bool trusted);
    event DefensiveCallUpdated(address indexed target, bytes4 indexed selector, bool allowed);
    event LockerUpdated(address indexed oldLocker, address indexed newLocker);

    address public immutable BOOTSTRAP;
    address public locker;
    /// @notice Factory whose launch-only pause is permitted on the instant defensive path.
    address public pauseTarget;

    // =========================================================================
    // Owners
    // =========================================================================
    address[3] public owners;
    mapping(address => bool) public isOwner;
    uint256 public constant REQUIRED = 2;

    // =========================================================================
    // Transactions
    // =========================================================================
    /// @dev Order is security-relevant: the ZERO value must be the MOST
    ///      restrictive class, so a never-initialised Transaction.cls can
    ///      never default into a fast path.
    enum CallClass {
        Unrecognized,
        PlainEth,
        KnownErc20,
        SelfAdmin,
        Defensive
    }

    struct Transaction {
        address target;
        uint256 value;
        bytes data;
        bool executed;
        bool vetoed;
        /// @notice FIX (Y-1): class pinned at submission time. Execution and
        ///         executability checks read this value and NEVER re-derive it
        ///         from mutable state at execute time.
        CallClass cls;
        uint256 confirmations; // informational only; authorization always uses _countValidConfirmations
        uint256 createdAt;
        /// @notice Timestamp when this transaction first reaches the threshold.
        ///         The Unrecognized cooling-off starts when quorum forms.
        uint256 thresholdReachedAt;
    }

    Transaction[] public transactions;
    mapping(uint256 => mapping(address => bool)) private txConfirmations;

    /// @notice FIX (O-2): tracks the "generation" of each owner address.
    ///         Incremented on every replaceOwner so stale confirmations from a
    ///         re-added address are not counted.
    mapping(address => uint256) public ownerGeneration;
    mapping(uint256 => mapping(address => uint256)) private txConfirmationGen;

    // ERC20 selectors we can bound on-chain.
    bytes4 private constant SEL_TRANSFER = 0xa9059cbb;      // transfer(address,uint256)
    bytes4 private constant SEL_TRANSFER_FROM = 0x23b872dd; // transferFrom(address,address,uint256)
    bytes4 private constant SEL_APPROVE = 0x095ea7b3;       // approve(address,uint256)

    // FIX (M-1): the ONLY selectors that may ever be registered as Defensive.
    // The Defensive class skips the 24h Unrecognized delay and the daily ERC20
    // limit, and its safety argument is "the target function can move no funds
    // by construction". That argument holds for the two Locker freeze functions
    // and for nothing else - a free-form (target, selector) map would let two
    // colluding owners register WBNB.transfer and execute unlimited, immediate
    // ERC20 movements through the Defensive fast path. Enforce the claim
    // on-chain instead of relying on operator discipline.
    bytes4 private constant SEL_FREEZE_WALLET = bytes4(keccak256("emergencyFreezeWallet(address)"));
    bytes4 private constant SEL_FREEZE_FEES = bytes4(keccak256("emergencyFreezeFees(address)"));
    bytes4 private constant SEL_PAUSE = bytes4(keccak256("pause()"));

    /// @notice FIX (Y-1): tokens whose transfer/transferFrom/approve semantics
    ///         are trusted for the KnownErc20 fast path. Registration happens
    ///         only through the Unrecognized path (24h delay or 3-of-3), so
    ///         two colluding keys cannot instantly widen their own power.
    mapping(address => bool) public trustedErc20;

    /// @notice FIX (Y-1 #1): pre-approved DEFENSIVE calls (target => selector =>
    ///         allowed). These are freeze-only / fund-protecting actions such as
    ///         BSCookLocker.emergencyFreezeFees. They are classified as
    ///         CallClass.Defensive, so 2-of-3 can execute them IMMEDIATELY with
    ///         no UNRECOGNIZED_CALL_DELAY — the whole point is to stop a stolen
    ///         key from draining fees faster than a 24h cooling-off would allow.
    /// @dev A Defensive call can move no funds by construction (the target
    ///      function is freeze-only), so bypassing the delay adds no theft risk;
    ///      it only lets the guardian pause things. Registration itself is NOT
    ///      defensive (goes through the normal Unrecognized 24h / 3-of-3 path),
    ///      so two colluding keys cannot instantly widen this set.
    ///      FIX (M-1): setDefensiveCall now REJECTS any selector other than
    ///      emergencyFreezeWallet/emergencyFreezeFees, so the "freeze-only"
    ///      property is enforced on-chain, not just by convention.
    mapping(address => mapping(bytes4 => bool)) public defensiveCalls;

    // =========================================================================
    // Limits & delays
    // =========================================================================
    /// @notice FIX (O-2): BNB daily withdrawal hard cap = 100 BNB. The previous
    ///         100_000 BNB default made the limit meaningless against a 2-of-3
    ///         key compromise on the immediate PlainEth path. Governance can
    ///         only lower it, never raise it above MAX_DAILY_WITHDRAW_LIMIT.
    /// @notice BNB daily withdrawal hard cap = 1000 BNB.
    uint256 public dailyWithdrawLimit = 1000 ether;
    uint256 public constant MAX_DAILY_WITHDRAW_LIMIT = 1000 ether;
    uint256 public dailyWithdrawn;
    uint256 public lastWithdrawDay;

    mapping(address => uint256) public dailyERC20Withdrawn;
    mapping(address => uint256) public lastERC20WithdrawDay;
    /// @notice FIX (Audit M-3): Per-token daily withdrawal cap in token native units.
    ///         Default is 0 (fast path disabled unless explicitly configured).
    ///         Tokens seeded at constructor (e.g. WBNB) receive a 100 ether limit matching BNB.
    mapping(address => uint256) public dailyErc20Cap;
    /// @notice FIX (O-2): per-token ERC20 daily cap = 100M tokens (1e26 base
    ///         units, i.e. 18-decimal tokens like WBNB/USDT-BSC; for tokens
    ///         with fewer decimals the cap is proportionally larger in base
    ///         units). Each token has its own independent counter
    ///         (dailyERC20Withdrawn[token]), so one token's budget is never
    ///         consumed by another.
    uint256 public dailyERC20WithdrawLimit = 100_000_000 ether;
    uint256 public constant MAX_DAILY_ERC20_WITHDRAW_LIMIT = 100_000_000 ether;

    /// @notice Cooling-off window for calls whose value-at-risk is unmeasurable.
    uint256 public constant UNRECOGNIZED_CALL_DELAY = 24 hours;

    uint256 public txExpiry = 48 hours;
    uint256 public constant MAX_TX_EXPIRY = 30 days;
    /// @dev Expiry must comfortably exceed UNRECOGNIZED_CALL_DELAY, otherwise
    ///      unrecognized transactions would expire before they ever became
    ///      executable - a one-call denial of service against governance.
    uint256 public constant MIN_TX_EXPIRY = UNRECOGNIZED_CALL_DELAY + 12 hours;

    // Owner replacement timelock (24 hours)
    uint256 public constant OWNER_REPLACEMENT_DELAY = 24 hours;

    struct OwnerReplacement {
        uint8 index;
        address newOwner;
        uint256 eta;
    }

    /// @notice replacementHash => the exact replacement it authorizes.
    /// @dev Storing (index, newOwner) alongside the eta - rather than only the
    ///      eta - is a security requirement, not bookkeeping. See replaceOwner.
    mapping(bytes32 => OwnerReplacement) public pendingOwnerReplacement;

    /// @dev Monotonic nonce so two proposals for the same (index, newOwner) in
    ///      the same block cannot collide onto one hash.
    uint256 public ownerReplacementNonce;

    // =========================================================================
    // Modifiers
    // =========================================================================
    modifier onlyOwner() {
        require(isOwner[msg.sender], "Not an owner");
        _;
    }

    modifier onlySelf() {
        require(msg.sender == address(this), "Only via proposal");
        _;
    }

    modifier txExists(uint256 txId) {
        require(txId < transactions.length, "Tx does not exist");
        _;
    }

    modifier notExecuted(uint256 txId) {
        require(!transactions[txId].executed, "Tx already executed");
        _;
    }

    /// @dev FIX (D-2): generation-aware. A raw `txConfirmations` flag left over
    ///      from a previous owner-generation must NOT block a re-added owner
    ///      from re-confirming. Previously an owner who confirmed, was replaced,
    ///      then re-added could never re-confirm (stale flag), while their old
    ///      confirmation was already ignored by _countValidConfirmations -> the
    ///      tx was permanently stuck below threshold.
    modifier notConfirmed(uint256 txId) {
        require(
            !txConfirmations[txId][msg.sender] ||
            txConfirmationGen[txId][msg.sender] != ownerGeneration[msg.sender],
            "Tx already confirmed"
        );
        _;
    }

    /// @dev L-04 FIX: Anchor the expiry to thresholdReachedAt once quorum is reached,
    ///      ensuring owners always have a full txExpiry execution window after cooling-off.
    function _expiryTimestamp(Transaction storage t) internal view returns (uint256 expiry) {
        uint256 anchor = (t.thresholdReachedAt > t.createdAt) ? t.thresholdReachedAt : t.createdAt;
        expiry = anchor + txExpiry;
    }

    modifier notExpired(uint256 txId) {
        require(block.timestamp <= _expiryTimestamp(transactions[txId]), "Tx expired");
        _;
    }

    /**
     * @param _owners 3 wallet addresses. Order doesn't matter.
     * @param _trustedErc20 tokens seeded into the KnownErc20 fast path
     *        (e.g. WBNB). May be empty; later additions go through the
     *        Unrecognized path (24h delay / 3-of-3) via addTrustedErc20.
     */
    constructor(address[3] memory _owners, address[] memory _trustedErc20) {
        BOOTSTRAP = msg.sender;
        require(
            _owners[0] != address(0) && _owners[1] != address(0) && _owners[2] != address(0),
            "Invalid owner"
        );
        // Guard against the wallet being able to act as its own owner, which
        // would let a single executed transaction manufacture confirmations.
        for (uint256 i = 0; i < 3; i++) {
            require(_owners[i] != address(this), "Self cannot be owner");
            require(!isOwner[_owners[i]], "Duplicate owner");
            isOwner[_owners[i]] = true;
            owners[i] = _owners[i];
        }
        for (uint256 i = 0; i < _trustedErc20.length; i++) {
            address token = _trustedErc20[i];
            require(token != address(0) && token != address(this), "Invalid trusted token");
            if (!trustedErc20[token]) {
                trustedErc20[token] = true;
                // FIX (Audit M-3): Seed initial daily limit to 1000 ether (matching native 1000 BNB cap for WBNB)
                dailyErc20Cap[token] = 1000 ether;
                emit TrustedErc20Updated(token, true);
                emit TokenDailyLimitUpdated(token, 0, 1000 ether);
            }
        }
    }

    // =========================================================================
    // Submission / confirmation / execution
    // =========================================================================

    /// @notice Submit a new transaction. Returns tx ID to share with other owners.
    function submitTransaction(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwner returns (uint256 txId) {
        txId = _submitTransaction(msg.sender, target, value, data);
    }

    /// @dev Internal helper used both by the external submitTransaction and by
    ///      convenience functions (withdrawEth, proposeReplaceOwner, etc.).
    function _submitTransaction(
        address submitter,
        address target,
        uint256 value,
        bytes memory data
    ) internal returns (uint256 txId) {
        // A call to address(0) carrying value irreversibly burns treasury funds
        // and is never intentional.
        require(target != address(0), "Invalid target");

        txId = transactions.length;
        Transaction storage t = transactions.push();
        t.target = target;
        t.value = value;
        t.data = data;
        t.createdAt = block.timestamp;
        // FIX (Y-1): pin the class NOW, against the exact bytes that will be
        // executed. If it were re-derived at execute time, two colluding
        // owners could submit an empty-data call to a contract they control
        // (Unrecognized -> 24h cooling-off), have that contract SELFDESTRUCT,
        // and watch the class silently downgrade to PlainEth at execute time,
        // bypassing the delay entirely.
        t.cls = _classifyOf(target, value, data);
        emit TransactionSubmitted(txId, target, value, data);

        // Auto-confirm for submitter
        txConfirmations[txId][submitter] = true;
        txConfirmationGen[txId][submitter] = ownerGeneration[submitter];
        t.confirmations = 1;
        emit TransactionConfirmed(txId, submitter);

        // FIX (M-2): with REQUIRED == 1 (or a future config change) a tx can
        // reach quorum at submission; stamp it immediately.
        if (t.thresholdReachedAt == 0 && _countValidConfirmations(txId) >= REQUIRED) {
            t.thresholdReachedAt = block.timestamp;
            emit ThresholdReached(txId, block.timestamp);
        }
    }

    /// @notice Confirm a pending transaction. Opportunistically executes it when
    ///         it becomes executable.
    function confirmTransaction(uint256 txId)
        external
        nonReentrant
        onlyOwner
        txExists(txId)
        notExecuted(txId)
        notConfirmed(txId)
        notExpired(txId)
    {
        Transaction storage t = transactions[txId];
        // FIX (Audit L-2): If quorum was previously lost (e.g. by owner replacement or generation change),
        // reset thresholdReachedAt so that reaching quorum again requires a fresh cooling-off window.
        if (_countValidConfirmations(txId) < REQUIRED) {
            t.thresholdReachedAt = 0;
        }
        txConfirmations[txId][msg.sender] = true;
        txConfirmationGen[txId][msg.sender] = ownerGeneration[msg.sender];
        t.confirmations++;
        emit TransactionConfirmed(txId, msg.sender);

        // Stamp the moment quorum is first reached so the veto/cooling period
        // begins when the transaction becomes actionable.
        if (t.thresholdReachedAt == 0 && _countValidConfirmations(txId) >= REQUIRED) {
            t.thresholdReachedAt = block.timestamp;
            emit ThresholdReached(txId, block.timestamp);
        }

        // Opportunistic auto-execution.
        //
        // FIX: this MUST NOT be able to unwind the confirmation we just
        // recorded. Previously a direct internal call was used, so any revert
        // inside the executed payload (most notably proposeReplaceOwner's own
        // 24h timelock, which by construction is not yet elapsed when the
        // second owner signs) rolled back the whole call, silently discarding
        // that owner's signature. The transaction could then never accumulate
        // its second confirmation and would sit dead until expiry.
        //
        // Routing through an external self-call inside try/catch isolates the
        // payload's failure from the confirmation bookkeeping.
        if (_isExecutable(txId)) {
            try this.selfExecute(txId) {
                // executed
            } catch {
                emit AutoExecutionFailed(txId);
            }
        }
    }

    /// @notice Revoke your confirmation for a transaction.
    function revokeConfirmation(uint256 txId)
        external
        onlyOwner
        txExists(txId)
        notExecuted(txId)
    {
        Transaction storage t = transactions[txId];
        require(txConfirmations[txId][msg.sender], "Not confirmed");
        txConfirmations[txId][msg.sender] = false;
        t.confirmations--;
        // FIX (M-2): if the tx drops back below quorum, the cooling-off clock
        // resets; the next quorum must wait a fresh full window.
        if (_countValidConfirmations(txId) < REQUIRED) {
            t.thresholdReachedAt = 0;
        }
        emit TransactionRevoked(txId, msg.sender);
    }

    /// @notice Veto a pending operation before it executes.
    /// @dev Any owner can veto once at least one valid confirmation exists.
    ///      The veto raises the threshold to unanimity for every call class.
    ///      A third valid confirmation remains an explicit override and can
    ///      execute the transaction immediately. Owner replacement is excluded:
    ///      otherwise a compromised owner could veto its own removal forever.
    function vetoTransaction(uint256 txId)
        external
        onlyOwner
        txExists(txId)
        notExecuted(txId)
        notExpired(txId)
    {
        Transaction storage t = transactions[txId];
        bytes memory data = t.data;
        require(
            !(t.target == address(this) && _selectorOf(data) == this.replaceOwner.selector),
            "Owner replacement cannot be vetoed"
        );
        uint256 confs = _countValidConfirmations(txId);
        require(confs > 0 && confs < owners.length, "Veto unavailable");
        require(!t.vetoed, "Already vetoed");
        t.vetoed = true;
        emit TransactionVetoed(txId, msg.sender);
    }

    /// @notice Execute a transaction that satisfies its class's requirements.
    function executeTransaction(uint256 txId)
        external
        nonReentrant
        txExists(txId)
        notExecuted(txId)
        notExpired(txId)
    {
        require(_isExecutable(txId), "Not executable yet");
        _executeTransaction(txId);
    }

    /// @dev External re-entry point reserved for `confirmTransaction`'s
    ///      try/catch. Not callable by anyone else.
    function selfExecute(uint256 txId) external onlySelf {
        _executeTransaction(txId);
    }

    // =========================================================================
    // Classification & authorization
    // =========================================================================

    /// @dev Extracts the 4-byte selector from an ABI-encoded payload held in memory.
    function _selectorOf(bytes memory data) internal pure returns (bytes4 sel) {
        if (data.length < 4) return bytes4(0);
        assembly {
            sel := mload(add(data, 32))
        }
    }

    /// @dev FIX (Y-1): classification is performed ONCE at submission time
    ///      (see _submitTransaction) and stored in Transaction.cls. All
    ///      authorization paths read the pinned value via _classify(txId), so
    ///      later mutations of extcodesize / trustedErc20 / defensiveCalls can
    ///      never move a transaction into a more permissive class after the
    ///      other owners have already signed it.
    function _classifyOf(address target, uint256 value, bytes memory data) internal view returns (CallClass) {
        uint256 len = data.length;

        if (len == 0) {
            // FIX (Y-1): empty data to a CONTRACT runs its receive()/fallback()
            // = arbitrary code with msg.sender = this wallet. The daily ETH
            // limit (satisfiable with 1 wei) protects nothing there, so only
            // EOA targets keep the immediate PlainEth path.
            uint256 size;
            assembly {
                size := extcodesize(target)
            }
            return size == 0 ? CallClass.PlainEth : CallClass.Unrecognized;
        }
        if (len < 4) {
            return CallClass.Unrecognized; // malformed / non-standard
        }

        bytes4 sel = _selectorOf(data);

        // Factory.pause() only stops new launches and cannot move funds.
        // Register exactly one factory at bootstrap and require its pauser role
        // to point back to this multisig before granting the immediate path.
        if (value == 0 && len == 4 && target == pauseTarget && sel == SEL_PAUSE) {
            return CallClass.Defensive;
        }

        // Self-administration. Deliberately checked BEFORE the ERC20 branch so
        // a self-call can never be mistaken for a token movement (which would
        // have applied the ERC20 daily limit against `address(this)` as if the
        // wallet itself were the token).
        if (target == address(this)) {
            if (value != 0) {
                return CallClass.Unrecognized;
            }
            if (
                sel == this.replaceOwner.selector ||
                sel == this.updateDailyLimit.selector ||
                sel == this.updateErc20DailyLimit.selector ||
                sel == this.updateTxExpiry.selector
            ) {
                return CallClass.SelfAdmin;
            }
            return CallClass.Unrecognized;
        }

        // FIX (Y-1 #1): pre-approved defensive (freeze-only) calls on EXTERNAL
        // targets. Checked before the ERC20 branch; requires value == 0 and the
        // exact selector registered. Because the target function can move no
        // funds, these skip the 24h cooling-off and run on 2-of-3 immediately.
        // HARDENING FIX: Target MUST be the authorized BSCookLocker contract.
        if (value == 0 && target == locker && defensiveCalls[target][sel]) {
            return CallClass.Defensive;
        }

        // FIX (Y-1): the selector alone proved nothing about the target's
        // semantics — any contract exposing transfer(address,uint256) got the
        // immediate path. Only owner-registered tokens qualify, and only at
        // the EXACT ABI length (trailing junk could be interpreted differently
        // by a non-standard target).
        // FIX (D-2): reject calls that attach ETH value to an ERC20 operation.
        // A transfer() call with value != 0 would send ETH to the token
        // contract where it may be irrecoverable.
        if (
            value == 0 &&
            trustedErc20[target] &&
            (
                (sel == SEL_TRANSFER && len == 68) ||
                (sel == SEL_TRANSFER_FROM && len == 100) ||
                (sel == SEL_APPROVE && len == 68)
            )
        ) {
            return CallClass.KnownErc20;
        }

        return CallClass.Unrecognized;
    }

    /// @dev Returns the class pinned at submission time. Never re-derived.
    function _classify(uint256 txId) internal view returns (CallClass) {
        return transactions[txId].cls;
    }

    /// @dev Counts confirmations from addresses that are *currently* owners
    ///      AND whose confirmation was recorded in their current generation.
    ///      FIX (O-2): guards against a stale confirmation surviving an owner
    ///      removal + re-addition cycle.
    function _countValidConfirmations(uint256 txId) internal view returns (uint256 validConfirmations) {
        for (uint256 i = 0; i < owners.length; i++) {
            address ownerAddr = owners[i];
            if (
                isOwner[ownerAddr] &&
                txConfirmations[txId][ownerAddr] &&
                txConfirmationGen[txId][ownerAddr] == ownerGeneration[ownerAddr]
            ) {
                validConfirmations++;
            }
        }
    }

    /// @dev Full executability predicate: threshold + expiry + class cooling-off.
    function _isExecutable(uint256 txId) internal view returns (bool) {
        Transaction storage t = transactions[txId];
        if (t.executed) return false;
        if (block.timestamp > _expiryTimestamp(t)) return false;

        uint256 confs = _countValidConfirmations(txId);
        if (confs < REQUIRED) return false;

        if (t.vetoed && confs < owners.length) return false;

        if (_classify(txId) == CallClass.Unrecognized) {
            // Unanimity waives both veto and cooling-off requirements.
            // FIX (M-2): the window runs from the moment quorum was reached
            // (thresholdReachedAt), not from submission (createdAt). The
            // createdAt fallback only applies to legacy/unstamped states and
            // is unreachable for transactions confirmed through the current
            // code paths, which always stamp thresholdReachedAt at quorum.
            if (confs < owners.length) {
                // Fail-closed: an unstamped quorum (unreachable through the
                // current submit/confirm paths) is never executable.
                if (t.thresholdReachedAt == 0) return false;
                if (block.timestamp < t.thresholdReachedAt + UNRECOGNIZED_CALL_DELAY) {
                    return false;
                }
            }
        }
        return true;
    }

    /// @notice Public view of whether a transaction can be executed right now.
    function isExecutable(uint256 txId) external view txExists(txId) returns (bool) {
        return _isExecutable(txId);
    }

    /// @notice The confirmation threshold that applies to a transaction.
    /// @dev Returns unanimity while a veto is active, or while an
    ///      Unrecognized transaction is still in its cooling-off window.
    function requiredConfirmations(uint256 txId) external view txExists(txId) returns (uint256) {
        if (transactions[txId].vetoed && _countValidConfirmations(txId) < owners.length) {
            return owners.length;
        }
        if (_classify(txId) == CallClass.Unrecognized) {
            Transaction storage t = transactions[txId];
            bool windowOpen = t.thresholdReachedAt == 0
                || block.timestamp < t.thresholdReachedAt + UNRECOGNIZED_CALL_DELAY;
            if (windowOpen) return owners.length;
        }
        return REQUIRED;
    }

    /// @notice Earliest timestamp at which a transaction may execute with only
    ///         REQUIRED confirmations.
    /// @dev FIX (M-2/L-6): Unrecognized transactions now cool off from the
    ///      moment quorum was reached (see ThresholdReached event), so this
    ///      returns 0 ("unknown yet") until quorum forms, and
    ///      thresholdReachedAt + UNRECOGNIZED_CALL_DELAY afterwards. A tx that
    ///      reaches quorum later than txExpiry - UNRECOGNIZED_CALL_DELAY will
    ///      expire before its window completes — indexers should surface that.
    ///      Unanimity (all owners) waives the window entirely.
    function executableFrom(uint256 txId) external view txExists(txId) returns (uint256) {
        Transaction storage t = transactions[txId];
        if (t.vetoed && _countValidConfirmations(txId) < owners.length) {
            return type(uint256).max;
        }
        if (_classify(txId) == CallClass.Unrecognized) {
            return t.thresholdReachedAt == 0 ? 0 : t.thresholdReachedAt + UNRECOGNIZED_CALL_DELAY;
        }
        return t.createdAt;
    }

    /// @notice The class assigned to a transaction (see contract docs).
    function callClassOf(uint256 txId) external view txExists(txId) returns (CallClass) {
        return _classify(txId);
    }

    // =========================================================================
    // Execution internals
    // =========================================================================

    /// @dev Rolls the daily ERC20 window for `token` if needed, then enforces
    ///      and updates the daily withdrawn amount.
    function _applyErc20DailyLimit(address token, uint256 amount) internal {
        uint256 today = block.timestamp / 1 days;
        if (today > lastERC20WithdrawDay[token]) {
            dailyERC20Withdrawn[token] = 0;
            lastERC20WithdrawDay[token] = today;
        }
        uint256 cap = dailyErc20Cap[token];
        // FIX (M-04): Sıfır cap için global 100M-token fallback'i kaldırıldı.
        // Explicit cap ayarlanmamış token'lar için sınırsız transfere izin vermek
        // iki kolluding owner'ın yeni eklenen trusted token'ları anında boşaltmasına
        // olanak tanır. Her token için setTokenDailyLimit() çağrısı zorunludur.
        require(cap > 0, "BSCookMultiSig: no daily limit set for this token");
        require(cap <= MAX_DAILY_ERC20_WITHDRAW_LIMIT, "BSCookMultiSig: token cap exceeds maximum");
        require(
            dailyERC20Withdrawn[token] + amount <= cap,
            "Exceeds daily ERC20 limit"
        );
        dailyERC20Withdrawn[token] += amount;
    }

    function _executeTransaction(uint256 txId) internal {
        require(_isExecutable(txId), "Not executable yet");
        Transaction storage t = transactions[txId];

        // ETH daily limit
        if (t.value > 0) {
            uint256 today = block.timestamp / 1 days;
            if (today > lastWithdrawDay) {
                dailyWithdrawn = 0;
                lastWithdrawDay = today;
            }
            require(dailyWithdrawn + t.value <= dailyWithdrawLimit, "Exceeds daily ETH limit");
            dailyWithdrawn += t.value;
        }

        // ERC20 daily limit for the selectors we can bound.
        if (_classify(txId) == CallClass.KnownErc20) {
            bytes memory data = t.data;
            bytes4 sel = _selectorOf(data);
            uint256 amount;
            if (sel == SEL_TRANSFER || sel == SEL_APPROVE) {
                // layout: [len][selector 4][arg0 32][arg1 32] -> arg1 at data+32+36
                assembly {
                    amount := mload(add(data, 68))
                }
            } else {
                // transferFrom: [len][selector 4][from 32][to 32][amount 32]
                assembly {
                    amount := mload(add(data, 100))
                }
            }
            _applyErc20DailyLimit(t.target, amount);
        }

        // Effects before interaction.
        t.executed = true;

        (bool success, ) = t.target.call{value: t.value}(t.data);
        require(success, "Execution failed");
        emit TransactionExecuted(txId);
    }

    // =========================================================================
    // Views
    // =========================================================================

    function isExpired(uint256 txId) external view txExists(txId) returns (bool) {
        return block.timestamp > _expiryTimestamp(transactions[txId]);
    }

    function transactionCount() external view returns (uint256) {
        return transactions.length;
    }

    function isConfirmed(uint256 txId, address owner_) external view returns (bool) {
        // FIX (D-2): generation-aware, consistent with _countValidConfirmations.
        // A raw flag left over from a previous owner-generation (owner removed
        // and re-added) must not read as "confirmed".
        return
            txConfirmations[txId][owner_] &&
            txConfirmationGen[txId][owner_] == ownerGeneration[owner_];
    }

    function confirmationCount(uint256 txId) external view txExists(txId) returns (uint256) {
        return _countValidConfirmations(txId);
    }

    function getOwners() external view returns (address[3] memory) {
        return owners;
    }

    function balance() external view returns (uint256) {
        return address(this).balance;
    }

    // =========================================================================
    // Convenience proposal helpers
    // =========================================================================

    /// @notice Withdraw BNB from multisig (follows submit -> confirm -> execute flow)
    function withdrawEth(address payable to, uint256 amount) external onlyOwner returns (uint256 txId) {
        txId = _submitTransaction(msg.sender, to, amount, "");
    }

    /// @notice Withdraw all BNB from multisig (still capped by dailyWithdrawLimit at execution)
    /// @dev FIX (O-5): the value is SNAPSHOTTED at submission time. If the
    ///      balance changes between submit and execute, execution may revert
    ///      (retriable) or under-send relative to the new balance. Prefer
    ///      withdrawEth(to, exactAmount) whenever the balance is expected to
    ///      change before execution.
    function withdrawAllEth(address payable to) external onlyOwner returns (uint256 txId) {
        txId = _submitTransaction(msg.sender, to, address(this).balance, "");
    }

    /// @notice Propose to replace an owner. Subject to OWNER_REPLACEMENT_DELAY.
    function proposeReplaceOwner(uint256 index, address newOwner)
        external
        onlyOwner
        returns (uint256 txId)
    {
        require(index < 3, "Invalid index");
        require(newOwner != address(0), "Invalid owner");
        require(newOwner != address(this), "Self cannot be owner");
        require(!isOwner[newOwner], "Already owner");
        require(owners[index] != address(0), "Slot empty");

        uint256 eta = block.timestamp + OWNER_REPLACEMENT_DELAY;
        // abi.encode (not encodePacked) + a monotonic nonce: no ambiguity, no
        // same-block collisions between two distinct proposals.
        bytes32 replacementHash = keccak256(
            abi.encode(index, newOwner, block.timestamp, ownerReplacementNonce++, address(this))
        );
        require(pendingOwnerReplacement[replacementHash].eta == 0, "Hash in use");

        pendingOwnerReplacement[replacementHash] = OwnerReplacement({
            index: uint8(index),
            newOwner: newOwner,
            eta: eta
        });
        emit OwnerReplacementProposed(replacementHash, index, newOwner, eta);

        // txExpiry (>= MIN_TX_EXPIRY = 36h) always outlives OWNER_REPLACEMENT_DELAY
        // (24h), so the proposal remains executable after the timelock matures.
        txId = _submitTransaction(
            msg.sender,
            address(this),
            0,
            abi.encodeWithSelector(this.replaceOwner.selector, index, newOwner, replacementHash)
        );
    }

    /// @notice Replace owner (only callable by the multisig itself, after timelock).
    function replaceOwner(uint256 index, address newOwner, bytes32 replacementHash) external onlySelf {
        OwnerReplacement memory r = pendingOwnerReplacement[replacementHash];
        require(r.eta != 0, "No pending replacement");

        // CRITICAL FIX - replacement-hash confusion.
        // The old code only checked that `replacementHash` mapped to a non-zero
        // eta; it never checked that the hash actually authorized THIS
        // (index, newOwner) pair. Any owner could therefore take an unrelated
        // pending hash H (created for, say, index 0 -> Alice, and already past
        // its 24h delay) and submit
        //     replaceOwner(2, attackerAddr, H)
        // to evict a *different* owner and install an arbitrary address with
        // ZERO waiting period - completely defeating OWNER_REPLACEMENT_DELAY
        // and, with 2 colluding keys, seizing the wallet before the third
        // owner could react. Binding the stored parameters to the arguments
        // closes this.
        require(r.index == index && r.newOwner == newOwner, "Replacement param mismatch");
        require(block.timestamp >= r.eta, "Owner replacement timelock not elapsed");

        require(index < 3, "Invalid index");
        require(newOwner != address(0), "Invalid owner");
        require(newOwner != address(this), "Self cannot be owner");
        require(!isOwner[newOwner], "Already owner");
        require(owners[index] != address(0), "Slot empty");

        // Single use.
        delete pendingOwnerReplacement[replacementHash];

        address oldOwner = owners[index];
        isOwner[oldOwner] = false;
        // FIX (O-2): bump generation for both addresses so any stale
        // confirmations from either are invalidated.
        ownerGeneration[oldOwner]++;
        ownerGeneration[newOwner]++;
        owners[index] = newOwner;
        isOwner[newOwner] = true;

        emit OwnerReplaced(index, oldOwner, newOwner);
    }

    /// @notice Propose an ETH daily withdrawal limit change.
    function setDailyWithdrawLimit(uint256 newLimit) external onlyOwner returns (uint256 txId) {
        require(newLimit <= MAX_DAILY_WITHDRAW_LIMIT, "Exceeds max limit");
        txId = _submitTransaction(
            msg.sender,
            address(this),
            0,
            abi.encodeWithSelector(this.updateDailyLimit.selector, newLimit)
        );
    }

    function updateDailyLimit(uint256 newLimit) external onlySelf {
        require(newLimit <= MAX_DAILY_WITHDRAW_LIMIT, "Exceeds max limit");
        emit DailyLimitUpdated(dailyWithdrawLimit, newLimit);
        dailyWithdrawLimit = newLimit;
    }

    /// @notice Propose an ERC20 daily withdrawal limit change.
    /// @dev Previously this limit had no setter at all, so it was frozen at its
    ///      deploy-time value for the lifetime of the wallet.
    function setErc20DailyWithdrawLimit(uint256 newLimit) external onlyOwner returns (uint256 txId) {
        require(newLimit <= MAX_DAILY_ERC20_WITHDRAW_LIMIT, "Exceeds max limit");
        txId = _submitTransaction(
            msg.sender,
            address(this),
            0,
            abi.encodeWithSelector(this.updateErc20DailyLimit.selector, newLimit)
        );
    }

    function updateErc20DailyLimit(uint256 newLimit) external onlySelf {
        require(newLimit <= MAX_DAILY_ERC20_WITHDRAW_LIMIT, "Exceeds max limit");
        emit Erc20DailyLimitUpdated(dailyERC20WithdrawLimit, newLimit);
        dailyERC20WithdrawLimit = newLimit;
    }

    /// @notice Propose a transaction expiry change.
    function setTxExpiry(uint256 newExpiry) external onlyOwner returns (uint256 txId) {
        require(newExpiry >= MIN_TX_EXPIRY, "Below min expiry");
        require(newExpiry <= MAX_TX_EXPIRY, "Exceeds max expiry");
        txId = _submitTransaction(
            msg.sender,
            address(this),
            0,
            abi.encodeWithSelector(this.updateTxExpiry.selector, newExpiry)
        );
    }

    function updateTxExpiry(uint256 newExpiry) external onlySelf {
        // Lower bound is a liveness guard: an expiry shorter than
        // UNRECOGNIZED_CALL_DELAY would make every Unrecognized transaction
        // expire before it could ever satisfy its cooling-off window,
        // permanently disabling governance calls with a single proposal.
        require(newExpiry >= MIN_TX_EXPIRY, "Below min expiry");
        require(newExpiry <= MAX_TX_EXPIRY, "Exceeds max expiry");
        emit TransactionExpiryUpdated(txExpiry, newExpiry);
        txExpiry = newExpiry;
    }

    /// @notice FIX (M-01): Register a token for the KnownErc20 fast path with an explicit atomic daily cap.
    /// @dev Intentionally NOT in the SelfAdmin selector list: widening the
    ///      trust set must cost the 24h Unrecognized delay (or 3-of-3), so
    ///      two compromised keys can never expand their own immediate reach.
    function addTrustedErc20(address token, uint256 cap) external onlySelf {
        require(token != address(0) && token != address(this), "Invalid token");
        require(cap > 0 && cap <= MAX_DAILY_ERC20_WITHDRAW_LIMIT, "Invalid cap");
        trustedErc20[token] = true;
        dailyErc20Cap[token] = cap;
        emit TrustedErc20Updated(token, true);
        emit TokenDailyLimitUpdated(token, 0, cap);
    }

    function removeTrustedErc20(address token) external onlySelf {
        trustedErc20[token] = false;
        emit TrustedErc20Updated(token, false);
    }

    /// @notice FIX (Audit M-3): Set or update the per-token daily withdrawal cap.
    /// @dev Requires Unrecognized path (24h cooling-off or 3-of-3) since onlySelf is not in SelfAdmin.
    function setTokenDailyLimit(address token, uint256 cap) external onlySelf {
        require(token != address(0) && token != address(this), "Invalid token");
        require(cap > 0 && cap <= MAX_DAILY_ERC20_WITHDRAW_LIMIT, "Invalid token cap");
        emit TokenDailyLimitUpdated(token, dailyErc20Cap[token], cap);
        dailyErc20Cap[token] = cap;
    }

    /// @notice FIX (Y-1 #1): propose registering a defensive (freeze-only) call
    ///         such as BSCookLocker.emergencyFreezeFees. The resulting
    ///         setDefensiveCall self-call is intentionally NOT in the SelfAdmin
    ///         list, so it must clear the 24h Unrecognized delay (or 3-of-3).
    function proposeDefensiveCall(address target, bytes4 selector, bool allowed)
        external
        onlyOwner
        returns (uint256 txId)
    {
        txId = _submitTransaction(
            msg.sender,
            address(this),
            0,
            abi.encodeWithSelector(this.setDefensiveCall.selector, target, selector, allowed)
        );
    }

    /// @notice Propose a batch withdrawal of multiple ERC20 tokens to a recipient
    function proposeBatchWithdraw(address to, address[] calldata tokens)
        external
        onlyOwner
        returns (uint256 txId)
    {
        require(to != address(0), "Invalid recipient");
        txId = _submitTransaction(
            msg.sender,
            address(this),
            0,
            abi.encodeWithSelector(this.batchWithdraw.selector, to, tokens)
        );
    }

    /// @notice Batch withdraw multiple ERC20 tokens directly to a recipient in a single transaction
    /// @dev SECURITY: every token in the batch MUST be in `trustedErc20`, exactly
    ///      like the single-token KnownErc20 fast path. Without this check,
    ///      registering batchWithdraw as SelfAdmin (immediate, 2-of-3) would
    ///      have created a blanket bypass of the Y-1 design: untrusted tokens
    ///      normally require the 24h Unrecognized cooling-off, but could here
    ///      be swept instantly. The trusted-only rule also removes the
    ///      malicious-token-callback reentrancy surface (trusted tokens are
    ///      vetted standard ERC20s without transfer hooks).
    function batchWithdraw(address to, address[] calldata tokens) external onlySelf {
        require(to != address(0), "Invalid recipient");
        uint256 len = tokens.length;
        for (uint256 i = 0; i < len;) {
            address t = tokens[i];
            if (t != address(0)) {
                require(trustedErc20[t], "Untrusted token");
                uint256 bal = IERC20(t).balanceOf(address(this));
                if (bal > 0) {
                    _applyErc20DailyLimit(t, bal);
                    IERC20(t).safeTransfer(to, bal);
                }
            }
            unchecked { ++i; }
        }
    }

    /// @notice Sets the authorized BSCookLocker contract. BOOTSTRAP for one-shot wiring, or via self-proposal.
    function setLocker(address _locker) external {
        require(msg.sender == BOOTSTRAP || msg.sender == address(this), "Not authorized");
        require(locker == address(0) || msg.sender == address(this), "Locker already set");
        require(_locker != address(0) && _locker != address(this), "Invalid locker");
        ContractValidation.requireContract(_locker, "Locker must be contract");
        emit LockerUpdated(locker, _locker);
        locker = _locker;

        // Auto-whitelist freeze selectors for this locker
        defensiveCalls[_locker][SEL_FREEZE_WALLET] = true;
        defensiveCalls[_locker][SEL_FREEZE_FEES] = true;
        emit DefensiveCallUpdated(_locker, SEL_FREEZE_WALLET, true);
        emit DefensiveCallUpdated(_locker, SEL_FREEZE_FEES, true);
    }

    /// @notice One-time bootstrap registration for the Factory's emergency pause.
    /// @dev Later migrations require a multisig self-call; only a contract whose
    ///      pauser is this wallet can use the immediate defensive classification.
    function setPauseTarget(address target) external {
        require(msg.sender == BOOTSTRAP || msg.sender == address(this), "Not authorized");
        require(pauseTarget == address(0) || msg.sender == address(this), "Pause target already set");
        ContractValidation.requireContract(target, "Pause target must be contract");
        (bool ok, bytes memory result) = target.staticcall(abi.encodeWithSignature("pauser()"));
        require(ok && result.length >= 32 && abi.decode(result, (address)) == address(this), "Invalid pause target");
        emit PauseTargetUpdated(pauseTarget, target);
        pauseTarget = target;
    }

    /// @dev Applies a defensive-call registration. onlySelf (via governance).
    ///      FIX (M-1): Hard-coded to the two freeze selectors AND only authorized locker.
    function setDefensiveCall(address target, bytes4 selector, bool allowed) external onlySelf {
        require(target != address(0) && target != address(this), "Invalid target");
        require(locker != address(0), "Locker not set");
        require(target == locker, "Target is not the locker");
        require(selector != bytes4(0), "Zero selector");
        require(
            selector == SEL_FREEZE_WALLET || selector == SEL_FREEZE_FEES,
            "Only freeze selectors are Defensive"
        );
        defensiveCalls[target][selector] = allowed;
        emit DefensiveCallUpdated(target, selector, allowed);
    }

    receive() external payable {}
}
