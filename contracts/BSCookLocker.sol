// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {ContractValidation} from "./ContractValidation.sol";

struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

interface IPositionManagerV4 {
    function poolManager() external view returns (address);
    function getPoolAndPositionInfo(uint256 tokenId) external view returns (PoolKey memory poolKey, uint256 info);
    function modifyLiquidities(bytes calldata unlockData, uint256 deadline) external payable;
}

interface IFactoryWiring {
    function bscookLocker() external view returns (address);
    function positionManager() external view returns (address);
}

/// @title INonfungiblePositionManager
/// @notice Minimal interface for Uniswap V3 NonfungiblePositionManager
interface INonfungiblePositionManager {
    struct CollectParams {
        uint256 tokenId;
        address recipient;
        uint128 amount0Max;
        uint128 amount1Max;
    }

    function collect(CollectParams calldata params) external payable returns (uint256 amount0, uint256 amount1);

    function ownerOf(uint256 tokenId) external view returns (address);

    function positions(uint256 tokenId)
        external
        view
        returns (
            uint96 nonce,
            address operator,
            address token0,
            address token1,
            uint24 fee,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        );
}

/// @title BSCookLocker
/// @notice Permanent Liquidity Locker for BSCOOK platform on BNB Smart Chain (BSC)
/// @dev Permanently locks Uniswap V3 LP NFTs while allowing fee collection.
///
///      FEE MODEL (simplified, no redirection): the deployer share of every
///      position's fees is paid to the wallet that CREATED the token
///      (LockedPosition.deployer), fixed at lock time and immutable thereafter.
///      There is deliberately NO setFeeRedirect / recovery-address / balance-
///      sweep mechanism: fees can never be pointed at, or moved to, an address
///      other than the original creator. The only privileged action on fees is
///      an emergency FREEZE (see claimFrozen), which blocks a compromised
///      creator wallet from withdrawing; it can never redirect funds elsewhere.
contract BSCookLocker is Ownable2Step, ReentrancyGuard, IERC721Receiver {
    using SafeERC20 for IERC20;

    address public factory;
    address public nonfungiblePositionManager;
    address public protocolFeeRecipient;

    /// @notice Official dead address
    address public constant BURN_ADDRESS = 0x000000000000000000000000000000000000dEaD;

    /// @notice Automated protocol burning disabled (0% burn)
    uint256 public constant BURN_SHARE_OF_PROTOCOL = 0;

    /// @notice Protocol fee share out of 100 (25 = 25% protocol share, 75% to token creator)
    uint256 public constant MAX_PROTOCOL_FEE_SHARE = 90;
    uint256 public protocolFeeShare = 25;

    /// @dev Mandatory delay before a factory change can take effect. The
    ///      factory decides which tokens get locked here and which deployers
    ///      are accepted, so an instant, single-signature swap to a malicious
    ///      factory could let the owner redirect every future LP NFT to a
    ///      contract that extracts funds. A public window gives users time to
    ///      notice and react (same pattern as BSCookFactory.queueLockerChange).
    uint256 public constant FACTORY_CHANGE_DELAY = 2 days;
    uint256 public constant PROTOCOL_FEE_CHANGE_DELAY = 2 days;
    address public pendingFactory;
    uint256 public pendingFactoryEta;

    address public pendingProtocolFeeRecipient;
    uint256 public pendingProtocolFeeRecipientEta;
    uint256 public pendingProtocolFeeShare;
    uint256 public pendingProtocolFeeShareEta;

    struct LockedPosition {
        address token;      // token address
        bool locked;        // packed with token (21/32 bytes)
        uint8 protocolFeeShareAtLock; // FIX (Audit #5): snapshot of protocolFeeShare at lock time (22/32 bytes)
        address deployer;   // token creator; the PERMANENT fee recipient
        address token0;     // cached pool asset 0 (immutable) - avoids re-reading NFPM.positions() per collect
        address token1;     // cached pool asset 1 (immutable)
        uint256 tokenId;    // Uniswap V3 LP NFT token ID
    }

    /// @notice Maps token address to its LockedPosition
    mapping(address => LockedPosition) private _lockedPositions;

    /// @notice Maps fee recipient to token address to claimable amount
    mapping(address => mapping(address => uint256)) public claimableFees;

    /// @notice Tracks if a specific tokenId is locked to prevent accidental rescue
    mapping(uint256 => bool) public isPositionLocked;

    /// @notice Emergency freeze: a frozen address cannot call claimFees.
    ///         Set by emergencyFreezeWallet / emergencyFreezeFees (2-of-3
    ///         guardian, instant); cleared only by ownerUnfreeze (timelocked).
    ///         This is the ONLY privileged action on fees: it blocks a
    ///         compromised creator wallet from withdrawing. It never moves or
    ///         redirects funds.
    /// @notice Tracks until when an address is frozen from claiming fees (timestamp).
    ///         FIX (Audit M-5): Guardian freeze auto-expires after GUARDIAN_FREEZE_MAX (7 days)
    ///         to prevent permanent hostage holding, while timelocked owner() can freeze permanently.
    mapping(address => uint256) public claimFrozenUntil;
    uint256 public constant GUARDIAN_FREEZE_MAX = 7 days;
    /// @notice A guardian cannot renew a wallet freeze until 14 days after it starts.
    ///         The 7-day freeze therefore expires with a 7-day unfreeze window.
    uint256 public constant GUARDIAN_FREEZE_COOLDOWN = 14 days;
    mapping(address => uint256) public guardianNextFreezeAt;

    /// @notice Returns true if claims for the wallet are currently frozen
    function claimFrozen(address wallet) public view returns (bool) {
        return block.timestamp < claimFrozenUntil[wallet];
    }

    /// @notice FIX (Y-1 #1): Emergency fee guardian - typically the 2-of-3
    ///         MultiSig. May ONLY freeze fee claims to contain a compromised
    ///         creator key; can never move, redirect or claim funds. Kept
    ///         separate from owner() (the Timelock) so containment is instant
    ///         while every other privileged action stays timelocked.
    address public feeGuardian;

    /// @notice Tracks total claimable fees per ERC20 token (owed to users + protocol)
    mapping(address => uint256) public totalOwed;

    /// @notice Tracks last time fees were collected per token (for rescue timing protection)
    mapping(address => uint256) public lastCollectTime;

    /// @notice Minimum delay after last fee collection before rescueERC20 can be called
    uint256 public constant RESCUE_DELAY = 7 days;

    /// @notice Trusted token whitelist for fee collection (blocks malicious ERC777 callbacks)
    mapping(address => bool) public trustedTokens;

    /// @notice Pool assets for live locked positions or tokens with owed fees that must never be untrusted.
    ///         Computed dynamically to avoid expensive SSTORE writes (~40k gas) per launch.
    function mandatoryTrustedTokens(address token) public view returns (bool) {
        return _lockedPositions[token].locked || totalOwed[token] > 0;
    }

    // Events
    event PositionLocked(address indexed token, uint256 indexed tokenId, address indexed deployer);
    event FeesCollected(address indexed token, uint256 amount0, uint256 amount1, address deployerRecipient, address protocolRecipient);
    event FeesClaimed(address indexed claimer, address indexed token, uint256 amount);
    /// @notice Emitted by claimFeesTo. Separate from FeesClaimed so indexers
    ///         can see the actual destination address of redirected claims.
    event FeesClaimedTo(address indexed claimer, address indexed recipient, address indexed token, uint256 amount);
    event FeesBurned(address indexed token, uint256 amount);
    event ERC20Rescued(address indexed tokenAddress, address indexed to, uint256 amount);
    event ERC721Rescued(address indexed nftAddress, uint256 indexed tokenId, address indexed to);
    event TrustedTokenUpdated(address indexed token, bool trusted);
    event FactoryUpdated(address oldFactory, address newFactory);
    event FactoryChangeQueued(address indexed newFactory, uint256 eta);
    event FactoryChangeCancelled(address indexed newFactory);
    event ProtocolFeeRecipientUpdated(address oldRecipient, address newRecipient);
    event ProtocolFeeRecipientChangeQueued(address indexed newRecipient, uint256 eta);
    event ProtocolFeeRecipientChangeCancelled(address indexed newRecipient);
    event ProtocolFeeShareUpdated(uint256 oldShare, uint256 newShare);
    event ProtocolFeeShareChangeQueued(uint256 newShare, uint256 eta);
    event ProtocolFeeShareChangeCancelled(uint256 newShare);
    event FeeGuardianUpdated(address indexed oldGuardian, address indexed newGuardian);
    event WalletClaimsFrozen(address indexed wallet, address indexed frozenBy);
    event ClaimUnfrozen(address indexed account);

    /// @notice Restricts functions to the factory contract
    modifier onlyFactory() {
        require(msg.sender == factory, "BSCookLocker: caller is not factory");
        _;
    }

    /// @notice Validates that an address is a deployed contract (extcodesize > 0)
    function _validateContract(address _addr) internal view {
        ContractValidation.requireContract(_addr, "BSCookLocker: not a contract");
    }

    function _validateFactory(address candidate) internal view {
        _validateContract(candidate);
        require(
            IFactoryWiring(candidate).positionManager() == nonfungiblePositionManager,
            "BSCookLocker: position manager mismatch"
        );
    }

    /// @notice Hardens Ownable2Step so ownership can never land on an EOA by
    ///         mistake. On-chain enforcement of the "owner must be
    ///         Timelock/MultiSig" requirement instead of relying purely on
    ///         deploy-script discipline.
    function transferOwnership(address newOwner) public virtual override onlyOwner {
        _validateContract(newOwner);
        super.transferOwnership(newOwner);
    }

    /// @notice Renouncing ownership is permanently disabled.
    /// @dev Ownable.renounceOwnership() bypasses the contract-only guard above
    ///      and would irreversibly destroy every recovery path this contract
    ///      depends on (emergency freeze/unfreeze, stray-token rescue). "No
    ///      owner" is strictly worse than "timelocked owner" here.
    function renounceOwnership() public view override onlyOwner {
        revert("Renounce disabled");
    }

    /// @notice FIX (M-6): deploy-time EOA, used ONLY for the one-shot
    ///         setFactory wiring. It is never owner(): ownership is set to
    ///         the governance contract from block 0.
    address public immutable BOOTSTRAP;

    /// @param _nonfungiblePositionManager The address of the Uniswap V3 NFPM
    /// @param _protocolFeeRecipient The initial address to receive protocol fees
    /// @param _protocolFeeShare Initial protocol fee share (max 90%)
    /// @param _initialOwner Governance contract (Timelock/MultiSig) that owns
    ///        the locker from block 0. FIX (M-6): the deployer EOA is never
    ///        owner(), closing the deploy -> acceptOwnership fee-theft window.
    constructor(
        address _nonfungiblePositionManager,
        address _protocolFeeRecipient,
        uint256 _protocolFeeShare,
        address _initialOwner,
        address _initialFeeGuardian
    ) Ownable(_initialOwner) {
        _validateContract(_initialOwner);
        _validateContract(_nonfungiblePositionManager);
        _validateContract(_initialFeeGuardian);
        require(_protocolFeeRecipient != address(0), "BSCookLocker: invalid recipient");
        require(_protocolFeeShare <= MAX_PROTOCOL_FEE_SHARE, "BSCookLocker: share exceeds max");

        BOOTSTRAP = msg.sender;
        nonfungiblePositionManager = _nonfungiblePositionManager;
        protocolFeeRecipient = _protocolFeeRecipient;
        protocolFeeShare = _protocolFeeShare;
        feeGuardian = _initialFeeGuardian;
    }

    /// @notice One-time bootstrap: sets the factory the FIRST time
    ///         (factory == address(0)), since there is nothing locked yet.
    ///         All subsequent changes must go through queueFactoryChange.
    function setFactory(address _factory) external {
        require(msg.sender == BOOTSTRAP || msg.sender == owner(), "BSCookLocker: not authorized");
        require(factory == address(0), "Use queueFactoryChange after initial setup");
        require(_factory != address(0), "BSCookLocker: invalid factory");
        _validateFactory(_factory);
        emit FactoryUpdated(factory, _factory);
        factory = _factory;
    }

    /// @notice Step 1/2: queue a new factory address. Takes effect only after
    ///         FACTORY_CHANGE_DELAY, giving users a public, on-chain window to
    ///         notice and react before it can be swapped to a malicious contract.
    function queueFactoryChange(address _factory) external onlyOwner {
        require(_factory != address(0), "BSCookLocker: invalid factory");
        _validateFactory(_factory);
        require(IFactoryWiring(_factory).bscookLocker() == address(this), "BSCookLocker: factory locker mismatch");
        pendingFactory = _factory;
        pendingFactoryEta = block.timestamp + FACTORY_CHANGE_DELAY;
        emit FactoryChangeQueued(_factory, pendingFactoryEta);
    }

    /// @notice Step 2/2: execute a previously queued factory change once the delay has elapsed.
    function executeFactoryChange() external onlyOwner {
        require(pendingFactory != address(0), "BSCookLocker: no pending change");
        require(block.timestamp >= pendingFactoryEta, "BSCookLocker: timelock not elapsed");
        // FIX (O-4): re-validate at execute time in case the target was
        // destroyed during the 2-day delay window.
        _validateFactory(pendingFactory);
        require(IFactoryWiring(pendingFactory).bscookLocker() == address(this), "BSCookLocker: factory locker mismatch");
        address oldFactory = factory;
        factory = pendingFactory;
        emit FactoryUpdated(oldFactory, pendingFactory);
        pendingFactory = address(0);
        pendingFactoryEta = 0;
    }

    /// @notice Cancel a queued factory change (e.g. if the owner key looks compromised).
    function cancelFactoryChange() external onlyOwner {
        emit FactoryChangeCancelled(pendingFactory);
        pendingFactory = address(0);
        pendingFactoryEta = 0;
    }

    /// @notice Queue a fee recipient change. Takes effect only after PROTOCOL_FEE_CHANGE_DELAY.
    function queueProtocolFeeRecipientChange(address _recipient) external onlyOwner {
        require(_recipient != address(0), "BSCookLocker: invalid recipient");
        pendingProtocolFeeRecipient = _recipient;
        pendingProtocolFeeRecipientEta = block.timestamp + PROTOCOL_FEE_CHANGE_DELAY;
        emit ProtocolFeeRecipientChangeQueued(_recipient, pendingProtocolFeeRecipientEta);
    }

    function executeProtocolFeeRecipientChange() external onlyOwner {
        require(pendingProtocolFeeRecipient != address(0), "BSCookLocker: no pending change");
        require(block.timestamp >= pendingProtocolFeeRecipientEta, "BSCookLocker: timelock not elapsed");
        emit ProtocolFeeRecipientUpdated(protocolFeeRecipient, pendingProtocolFeeRecipient);
        protocolFeeRecipient = pendingProtocolFeeRecipient;
        pendingProtocolFeeRecipient = address(0);
        pendingProtocolFeeRecipientEta = 0;
    }

    function cancelProtocolFeeRecipientChange() external onlyOwner {
        emit ProtocolFeeRecipientChangeCancelled(pendingProtocolFeeRecipient);
        pendingProtocolFeeRecipient = address(0);
        pendingProtocolFeeRecipientEta = 0;
    }

    /// @notice Queue a fee share change. Takes effect only after PROTOCOL_FEE_CHANGE_DELAY.
    function queueProtocolFeeShareChange(uint256 _share) external onlyOwner {
        require(_share <= MAX_PROTOCOL_FEE_SHARE, "BSCookLocker: max share is 90");
        pendingProtocolFeeShare = _share;
        pendingProtocolFeeShareEta = block.timestamp + PROTOCOL_FEE_CHANGE_DELAY;
        emit ProtocolFeeShareChangeQueued(_share, pendingProtocolFeeShareEta);
    }

    function executeProtocolFeeShareChange() external onlyOwner {
        require(pendingProtocolFeeShareEta > 0, "BSCookLocker: no pending change");
        require(block.timestamp >= pendingProtocolFeeShareEta, "BSCookLocker: timelock not elapsed");
        emit ProtocolFeeShareUpdated(protocolFeeShare, pendingProtocolFeeShare);
        protocolFeeShare = pendingProtocolFeeShare;
        pendingProtocolFeeShare = 0;
        pendingProtocolFeeShareEta = 0;
    }

    function cancelProtocolFeeShareChange() external onlyOwner {
        emit ProtocolFeeShareChangeCancelled(pendingProtocolFeeShare);
        pendingProtocolFeeShare = 0;
        pendingProtocolFeeShareEta = 0;
    }

    /// @notice Locks an LP NFT permanently for a specific token
    /// @dev LP NFT must already be transferred to this contract. `deployer` is
    ///      the token creator and becomes the PERMANENT fee recipient.
    /// @param tokenId The ID of the Uniswap V3 LP NFT
    /// @param token The address of the launched token
    /// @param deployer The address of the deployer who created the token
    function lockPosition(uint256 tokenId, address token, address deployer) external onlyFactory {
        require(token != address(0), "BSCookLocker: invalid token");
        require(deployer != address(0), "BSCookLocker: invalid deployer");
        // FIX (O-1): a tokenId may be locked only ONCE, under whichever token
        // it was first bound. Without this check a compromised factory could
        // re-bind the WBNB side of an already-locked position (token0/token1
        // both match) under a different `token` key and reassign that fee
        // stream to a new deployer.
        require(!isPositionLocked[tokenId], "BSCookLocker: tokenId already locked");
        require(!_lockedPositions[token].locked, "BSCookLocker: position already locked");

        // Ensure the NFT is actually owned by this contract
        require(IERC721(nonfungiblePositionManager).ownerOf(tokenId) == address(this), "BSCookLocker: nfpm token not received");

        // Verify the position belongs to the requested token (Uniswap V4 with V3 fallback)
        address token0;
        address token1;
        try IPositionManagerV4(nonfungiblePositionManager).getPoolAndPositionInfo(tokenId) returns (PoolKey memory key, uint256) {
            token0 = key.currency0;
            token1 = key.currency1;
        } catch {
            (,, address t0, address t1, , , , , , , ,) = INonfungiblePositionManager(nonfungiblePositionManager).positions(tokenId);
            token0 = t0;
            token1 = t1;
        }
        require(token0 == token || token1 == token, "BSCookLocker: token mismatch");

        _lockedPositions[token] = LockedPosition({
            tokenId: tokenId,
            token: token,
            deployer: deployer,
            token0: token0,
            token1: token1,
            locked: true,
            protocolFeeShareAtLock: uint8(protocolFeeShare)
        });

        isPositionLocked[tokenId] = true;

        // KRİTİK #1 FIX: Whitelist both pool tokens at lock time so collectFees
        // can immediately work. Without this, trustedTokens[token0/token1] is
        // never set and every collectFees call reverts.
        trustedTokens[token0] = true;
        trustedTokens[token1] = true;

        emit PositionLocked(token, tokenId, deployer);
    }

    /// @notice Harvests trading fees for a locked position and distributes them
    /// @dev Can be called by anyone. Uses CEI pattern with whitelist check.
    ///      The deployer share is always credited to the immutable creator
    ///      address (LockedPosition.deployer) - there is no redirect.
    /// @param token The address of the token whose LP fees are being collected
    function collectFees(address token) external nonReentrant {
        LockedPosition memory position = _lockedPositions[token];
        require(position.locked, "BSCookLocker: position not locked");

        INonfungiblePositionManager nfpm = INonfungiblePositionManager(nonfungiblePositionManager);

        // GAS: token0/token1 are immutable for a given position and were cached
        // at lock time, so we read them from storage instead of re-decoding the
        // full 12-field NFPM.positions() struct on every harvest.
        address token0 = position.token0;
        address token1 = position.token1;

        // Kritik #3: Verify both tokens are trusted before collection
        // This prevents malicious ERC777 callback reentrancy during safeTransfer.
        require(trustedTokens[token0], "BSCookLocker: untrusted token0");
        require(trustedTokens[token1], "BSCookLocker: untrusted token1");

        // FIX (Y-2): measure what ACTUALLY entered the locker instead of
        // trusting NFPM's reported amounts. If a pool token ever turns out to
        // be fee-on-transfer / rebase-on-transfer (e.g. locked through a
        // compromised factory), crediting the *reported* amount would make
        // totalOwed exceed the real balance, permanently bricking every
        // honest claimFees call (safeTransfer revert) AND rescueERC20
        // (balance - owed underflow). Accounting to the received balance
        // delta keeps `totalOwed <= balance` true by construction.
        uint256 bal0Before = IERC20(token0).balanceOf(address(this));
        uint256 bal1Before = IERC20(token1).balanceOf(address(this));

        // Collect fees directly to this contract first (Uniswap V4 with V3 fallback)
        bool collectedV4 = false;
        try IPositionManagerV4(nonfungiblePositionManager).poolManager() returns (address) {
            bytes memory actions = bytes.concat(bytes1(0x01), bytes1(0x11)); // DECREASE_LIQUIDITY (0x01) + TAKE_PAIR (0x11)
            bytes[] memory params = new bytes[](2);
            params[0] = abi.encode(position.tokenId, uint256(0), uint128(0), uint128(0), bytes(""));
            params[1] = abi.encode(token0, token1, address(this));
            IPositionManagerV4(nonfungiblePositionManager).modifyLiquidities(abi.encode(actions, params), block.timestamp);
            collectedV4 = true;
        } catch {}

        if (!collectedV4) {
            nfpm.collect(
                INonfungiblePositionManager.CollectParams({
                    tokenId: position.tokenId,
                    recipient: address(this),
                    amount0Max: type(uint128).max,
                    amount1Max: type(uint128).max
                })
            );
        }

        // Checked subtraction: a negative delta (token rebasing down mid-call)
        // reverts rather than crediting phantom fees - fail closed.
        uint256 amount0 = IERC20(token0).balanceOf(address(this)) - bal0Before;
        uint256 amount1 = IERC20(token1).balanceOf(address(this)) - bal1Before;

        // FIX (no-redirect): the deployer share is credited to the immutable
        // creator address. If that wallet is compromised, the guardian FREEZES
        // it (claimFrozen) so neither the thief nor anyone else can withdraw;
        // the balance is never redirected elsewhere.
        address deployerRecipient = position.deployer;

        // FIX (Audit #5): Use snapshot fee share fixed at lock time, preventing governance from diluting creator share.
        // Unconditionally use protocolFeeShareAtLock because 0 is a valid 0% fee rate.
        uint256 currentShare = uint256(position.protocolFeeShareAtLock);

        // Calculate fee splits
        uint256 protocolAmount0 = (amount0 * currentShare) / 100;
        uint256 protocolAmount1 = (amount1 * currentShare) / 100;

        uint256 deployerAmount0 = amount0 - protocolAmount0;
        uint256 deployerAmount1 = amount1 - protocolAmount1;

        // Protocol share goes 100% to protocolFeeRecipient (0% automated burn)
        uint256 treasuryAmount0 = protocolAmount0;
        uint256 treasuryAmount1 = protocolAmount1;

        // Effects: Update internal accounting BEFORE any external calls
        // Distribute token0 (Creator gets 75%, Protocol gets 25%)
        if (deployerAmount0 > 0) {
            claimableFees[deployerRecipient][token0] += deployerAmount0;
            totalOwed[token0] += deployerAmount0;
        }
        if (treasuryAmount0 > 0) {
            claimableFees[protocolFeeRecipient][token0] += treasuryAmount0;
            totalOwed[token0] += treasuryAmount0;
        }

        // Distribute token1 (Creator gets 75%, Protocol gets 25%)
        if (deployerAmount1 > 0) {
            claimableFees[deployerRecipient][token1] += deployerAmount1;
            totalOwed[token1] += deployerAmount1;
        }
        if (treasuryAmount1 > 0) {
            claimableFees[protocolFeeRecipient][token1] += treasuryAmount1;
            totalOwed[token1] += treasuryAmount1;
        }

        // Stamp both real pool token addresses so the rescue delay applies
        // symmetrically to whichever token is being rescued.
        // FIX (M-3): stamp ONLY when that side actually received fees.
        // collectFees is permissionless; stamping on zero-fee collects let
        // anyone keep lastCollectTime[WBNB] permanently fresh (one tx per
        // 7 days is enough) and thereby block rescueERC20(WBNB) forever.
        // A real fee harvest still legitimately restarts the quiet period.
        if (amount0 > 0) lastCollectTime[token0] = block.timestamp;
        if (amount1 > 0) lastCollectTime[token1] = block.timestamp;
        emit FeesCollected(token, amount0, amount1, deployerRecipient, protocolFeeRecipient);
    }

    /// @notice Allows recipients to claim their accumulated fees
    /// @dev CEI pattern: zero out accounting before external transfer.
    ///      A frozen address (compromised creator wallet) cannot claim.
    /// @param tokens Array of ERC20 token addresses to claim fees for
    function claimFees(address[] calldata tokens) external nonReentrant {
        // FIX (M-01): Sınırsız array ile gas griefing / DoS saldırısını önle.
        // 50 token limiti gerçek kullanım senaryolarını kapsar; daha fazlası
        // için birden fazla çağrı yapılabilir.
        require(tokens.length <= 50, "BSCookLocker: too many tokens");
        require(!claimFrozen(msg.sender), "BSCookLocker: claims frozen");
        uint256 len = tokens.length;
        for (uint256 i = 0; i < len;) {
            address t = tokens[i];
            uint256 amount = claimableFees[msg.sender][t];
            if (amount > 0) {
                // Effects before Interactions
                claimableFees[msg.sender][t] = 0;
                totalOwed[t] -= amount;
                // Interaction last
                IERC20(t).safeTransfer(msg.sender, amount);
                emit FeesClaimed(msg.sender, t, amount);
            }
            unchecked { ++i; }
        }
    }

    /// @notice Allows recipients to claim their accumulated fees directly to a designated address
    /// @dev CEI pattern: zero out accounting before external transfer.
    ///      Only transfers caller's own claimable balance. A frozen caller cannot claim.
    /// @param recipient The address to receive the claimed fees
    /// @param tokens Array of ERC20 token addresses to claim fees for
    function claimFeesTo(address recipient, address[] calldata tokens) external nonReentrant {
        // FIX (M-01): claimFees ile aynı DoS koruması.
        require(tokens.length <= 50, "BSCookLocker: too many tokens");
        require(recipient != address(0), "BSCookLocker: invalid recipient");
        require(!claimFrozen(msg.sender), "BSCookLocker: claims frozen");
        uint256 len = tokens.length;
        for (uint256 i = 0; i < len;) {
            address t = tokens[i];
            uint256 amount = claimableFees[msg.sender][t];
            if (amount > 0) {
                // Effects before Interactions
                claimableFees[msg.sender][t] = 0;
                totalOwed[t] -= amount;
                // Interaction last
                IERC20(t).safeTransfer(recipient, amount);
                emit FeesClaimedTo(msg.sender, recipient, t, amount);
            }
            unchecked { ++i; }
        }
    }

    /// @notice Anyone can trigger permanent transfer of accumulated burn fees to the dead address
    /// @param tokens Array of ERC20 token addresses (e.g., WBNB or tokens) to burn
    function executeBurn(address[] calldata tokens) external nonReentrant {
        uint256 len = tokens.length;
        for (uint256 i = 0; i < len;) {
            address t = tokens[i];
            uint256 amount = claimableFees[BURN_ADDRESS][t];
            if (amount > 0) {
                claimableFees[BURN_ADDRESS][t] = 0;
                totalOwed[t] -= amount;
                IERC20(t).safeTransfer(BURN_ADDRESS, amount);
                emit FeesBurned(t, amount);
            }
            unchecked { ++i; }
        }
    }

    /// @notice Rescues mistakenly sent ERC20 tokens (excess over totalOwed only)
    /// @dev Requires RESCUE_DELAY after last fee collection to prevent timing attacks.
    ///      FIX (Y-2): explicit `balance >= owed` guard instead of relying on an
    ///      arithmetic underflow revert; with balance-delta accounting in
    ///      collectFees, owed can never exceed balance, so this is defence in
    ///      depth with a clear error message.
    function rescueERC20(address tokenAddress, uint256 amount) external onlyOwner {
        require(block.timestamp >= lastCollectTime[tokenAddress] + RESCUE_DELAY,
            "BSCookLocker: must wait after fee collection");
        uint256 balance = IERC20(tokenAddress).balanceOf(address(this));
        uint256 owed = totalOwed[tokenAddress];
        require(balance >= owed, "BSCookLocker: accounting invariant broken");
        require(amount <= balance - owed, "BSCookLocker: cannot rescue owed fees");
        IERC20(tokenAddress).safeTransfer(owner(), amount);
        emit ERC20Rescued(tokenAddress, owner(), amount);
    }

    /// @notice Rescues mistakenly sent ERC721 tokens
    function rescueERC721(address nftAddress, uint256 tokenId) external onlyOwner {
        _validateContract(nftAddress);
        // FIX (M-03): Önceki `!trustedTokens[nftAddress]` guard'ı kaldırıldı.
        // trustedTokens bir ERC20 whitelist'idir, ERC721 sınıflandırıcısı değil.
        // Gerçek guard: ERC20 token'ları ownerOf() fonksiyonuna sahip olmadığı için
        // aşağıdaki require() satırı zaten ERC20'lere karşı revert eder (H-1 fix korundu).
        // FIX (Audit H-1): Guard against ERC20 transferFrom selector collision (0x23b872dd).
        // WBNB / ERC20 tokens lack ownerOf() and revert during ABI decoding.
        require(IERC721(nftAddress).ownerOf(tokenId) == address(this), "BSCookLocker: not NFT owner");
        if (nftAddress == nonfungiblePositionManager) {
            require(!isPositionLocked[tokenId], "BSCookLocker: cannot rescue locked LP");
        }
        IERC721(nftAddress).transferFrom(address(this), owner(), tokenId);
        emit ERC721Rescued(nftAddress, tokenId, owner());
    }

    // ==========================================
    // Emergency fee freeze (no redirection)
    // ==========================================

    /// @notice FIX (Y-1 #1): Set the emergency fee guardian (e.g. the 2-of-3
    ///         MultiSig). Owner-only (goes through the Timelock). Changing the
    ///         guardian is itself a sensitive action, so it stays timelocked;
    ///         only the *freeze* below is fast.
    function setFeeGuardian(address guardian) external onlyOwner {
        require(guardian != address(0), "BSCookLocker: zero guardian");
        _validateContract(guardian);
        emit FeeGuardianUpdated(feeGuardian, guardian);
        feeGuardian = guardian;
    }

    /// @notice FIX (Y-1 #1): Wallet-scoped freeze for the admin "freeze wallet"
    ///         action. A creator reports a stolen wallet; the 2-of-3 guardian
    ///         freezes it so the thief can no longer withdraw ANY still-unclaimed
    ///         fee sitting under that address (across every token). FREEZE-ONLY:
    ///         moves no funds and cannot redirect anything.
    function emergencyFreezeWallet(address wallet) external {
        require(
            msg.sender == feeGuardian || msg.sender == owner(),
            "BSCookLocker: not guardian"
        );
        // FIX (O-2): the FAST guardian path may never freeze the treasury's
        // (protocolFeeRecipient) claims — a compromised guardian could
        // otherwise block every treasury withdrawal until ownerUnfreeze.
        // Genuine treasury-key containment stays with the timelocked owner,
        // who is exempt from this guard.
        if (msg.sender != owner()) {
            require(
                wallet != protocolFeeRecipient,
                "BSCookLocker: guardian cannot freeze treasury"
            );
            require(block.timestamp >= guardianNextFreezeAt[wallet], "BSCookLocker: guardian cooldown");
            guardianNextFreezeAt[wallet] = block.timestamp + GUARDIAN_FREEZE_COOLDOWN;
        }
        require(wallet != address(0), "BSCookLocker: zero wallet");
        claimFrozenUntil[wallet] = msg.sender == owner() ? type(uint256).max : block.timestamp + GUARDIAN_FREEZE_MAX;
        emit WalletClaimsFrozen(wallet, msg.sender);
    }

    /// @notice FIX (Y-1 #1): Freeze a token's fee stream by freezing its
    ///         immutable creator wallet. Convenience wrapper so the admin can
    ///         act knowing only the token address. Callable by the fee guardian
    ///         with NO timelock delay (2-of-3), to stop the bleeding the moment
    ///         a key is reported compromised.
    function emergencyFreezeFees(address token) external {
        require(
            msg.sender == feeGuardian || msg.sender == owner(),
            "BSCookLocker: not guardian"
        );
        LockedPosition memory p = _lockedPositions[token];
        require(p.locked, "BSCookLocker: position not locked");
        // FIX (O-2): same treasury guard as emergencyFreezeWallet — freezing a
        // deployer that doubles as protocolFeeRecipient would block treasury
        // claims. The timelocked owner remains exempt.
        if (msg.sender != owner()) {
            require(
                p.deployer != protocolFeeRecipient,
                "BSCookLocker: guardian cannot freeze treasury"
            );
            require(block.timestamp >= guardianNextFreezeAt[p.deployer], "BSCookLocker: guardian cooldown");
            guardianNextFreezeAt[p.deployer] = block.timestamp + GUARDIAN_FREEZE_COOLDOWN;
        }
        claimFrozenUntil[p.deployer] = msg.sender == owner() ? type(uint256).max : block.timestamp + GUARDIAN_FREEZE_MAX;
        emit WalletClaimsFrozen(p.deployer, msg.sender);
    }

    /// @notice Owner (timelocked) can unfreeze a previously frozen address after
    ///         verifying the real owner's identity through an off-chain process.
    /// @dev claimFrozen is address-global: unfreezing affects ALL tokens whose
    ///      creator is this address. Only use after confirming the address is no
    ///      longer compromised. This is the ONLY way frozen fees become
    ///      claimable again; there is no redirect-to-new-wallet path.
    function ownerUnfreeze(address account) external onlyOwner {
        require(account != address(0), "BSCookLocker: invalid address");
        require(claimFrozen(account), "BSCookLocker: not frozen");
        claimFrozenUntil[account] = 0;
        emit ClaimUnfrozen(account);
    }

    /// @notice Required to accept ERC721 tokens via safeTransferFrom
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external view override returns (bytes4) {
        // FIX (L-02): Yalnızca güvenilen PositionManager'dan gelen NFT transferlerini kabul et.
        // Herhangi bir NFT'yi kabul etmek spam ve kötü niyetli tokenId injection saldırılarına
        // kapı aralar. lockPosition'daki ownerOf() kontrolü ek güvence katmanı sağlar.
        require(
            msg.sender == nonfungiblePositionManager,
            "BSCookLocker: only NFPM transfers accepted"
        );
        return this.onERC721Received.selector;
    }

    // ==========================================
    // Admin Functions
    // ==========================================

    /// @notice Add a token to the trusted whitelist for fee collection
    function setTrustedToken(address token, bool trusted) external onlyOwner {
        require(token != address(0), "Invalid token");
        require(
            trusted || !mandatoryTrustedTokens(token),
            "Cannot untrust active pool token or token with owed fees"
        );
        trustedTokens[token] = trusted;
        emit TrustedTokenUpdated(token, trusted);
    }

    // ==========================================
    // View Functions
    // ==========================================

    /// @notice Returns the address of this locker
    function locker() external view returns (address) {
        return address(this);
    }

    /// @notice Returns the protocol fee share for a given token (locked snapshot if locked, else global)
    /// @return The protocol fee share percentage
    function tokenProtocolFeeShares(address token) external view returns (uint256) {
        if (_lockedPositions[token].locked) {
            return _lockedPositions[token].protocolFeeShareAtLock;
        }
        return protocolFeeShare;
    }

    /// @notice Gets the locked position struct for a given token
    /// @param token The token address
    function getLockedPosition(address token) external view returns (LockedPosition memory) {
        return _lockedPositions[token];
    }
}
