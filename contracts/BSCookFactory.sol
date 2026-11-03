// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "./BSCookToken.sol";
import "./ContractValidation.sol";

interface INonfungiblePositionManager {
    struct MintParams {
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
    }

    function mint(MintParams calldata params)
        external
        payable
        returns (
            uint256 tokenId,
            uint128 liquidity,
            uint256 amount0,
            uint256 amount1
        );

    function createAndInitializePoolIfNecessary(
        address token0,
        address token1,
        uint24 fee,
        uint160 sqrtPriceX96
    ) external payable returns (address pool);

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    function factory() external view returns (address);
}

interface IUniswapV3Pool {
    function slot0() external view returns (
        uint160 sqrtPriceX96,
        int24 tick,
        uint16 observationIndex,
        uint16 observationCardinality,
        uint16 observationCardinalityNext,
        uint32 feeProtocol,
        bool unlocked
    );
}

interface IUniswapV3Factory {
    function getPool(
        address tokenA,
        address tokenB,
        uint24 fee
    ) external view returns (address pool);
}

interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(ExactInputSingleParams calldata params)
        external
        payable
        returns (uint256 amountOut);
}

interface IWBNB {
    function deposit() external payable;

    function approve(address spender, uint256 amount) external returns (bool);

    function transfer(address to, uint256 amount) external returns (bool);

    function balanceOf(address account) external view returns (uint256);
}

interface IBSCookLocker {
    function protocolFeeShare() external view returns (uint256);
    function factory() external view returns (address);
    function nonfungiblePositionManager() external view returns (address);
    function lockPosition(
        uint256 tokenId,
        address token,
        address deployer
    ) external;
}

struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

interface IPositionManagerV4 {
    function poolManager() external view returns (address);
    function permit2() external view returns (address);
    function nextTokenId() external view returns (uint256);
    function initializePool(PoolKey calldata key, uint160 sqrtPriceX96) external payable returns (int24);
    function modifyLiquidities(bytes calldata unlockData, uint256 deadline) external payable;
}

interface IPermit2 {
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
}

interface IUniversalRouter {
    function execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline) external payable;
}

/// @notice Uniswap V4 Router interface for ExactInputSingle swaps
interface IV4Router {
    struct ExactInputSingleParams {
        PoolKey poolKey;
        bool zeroForOne;
        uint128 amountIn;
        uint128 amountOutMinimum;
        bytes hookData;
    }
}

library TickMath {
    int24 internal constant MIN_TICK = -887272;
    int24 internal constant MAX_TICK = 887272;

    function getSqrtPriceAtTick(int24 tick) internal pure returns (uint160 sqrtPriceX96) {
        unchecked {
            uint256 absTick;
            assembly ("memory-safe") {
                tick := signextend(2, tick)
                let mask := sar(255, tick)
                absTick := xor(mask, add(mask, tick))
            }
            require(absTick <= uint256(int256(MAX_TICK)), "Invalid tick");

            uint256 price;
            assembly ("memory-safe") {
                price := xor(shl(128, 1), mul(xor(shl(128, 1), 0xfffcb933bd6fad37aa2d162d1a594001), and(absTick, 0x1)))
            }
            if (absTick & 0x2 != 0) price = (price * 0xfff97272373d413259a46990580e213a) >> 128;
            if (absTick & 0x4 != 0) price = (price * 0xfff2e50f5f656932ef12357cf3c7fdcc) >> 128;
            if (absTick & 0x8 != 0) price = (price * 0xffe5caca7e10e4e61c3624eaa0941cd0) >> 128;
            if (absTick & 0x10 != 0) price = (price * 0xffcb9843d60f6159c9db58835c926644) >> 128;
            if (absTick & 0x20 != 0) price = (price * 0xff973b41fa98c081472e6896dfb254c0) >> 128;
            if (absTick & 0x40 != 0) price = (price * 0xff2ea16466c96a3843ec78b326b52861) >> 128;
            if (absTick & 0x80 != 0) price = (price * 0xfe5dee046a99a2a811c461f1969c3053) >> 128;
            if (absTick & 0x100 != 0) price = (price * 0xfcbe86c7900a88aedcffc83b479aa3a4) >> 128;
            if (absTick & 0x200 != 0) price = (price * 0xf987a7253ac413176f2b074cf7815e54) >> 128;
            // FIX (Audit M-1): Correct official Uniswap V3/V4 constant for 0x400
            if (absTick & 0x400 != 0) price = (price * 0xf3392b0822b70005940c7a398e4b70f3) >> 128;
            if (absTick & 0x800 != 0) price = (price * 0xe7159475a2c29b7443b29c7fa6e889d9) >> 128;
            if (absTick & 0x1000 != 0) price = (price * 0xd097f3bdfd2022b8845ad8f792aa5825) >> 128;
            if (absTick & 0x2000 != 0) price = (price * 0xa9f746462d870fdf8a65dc1f90e061e5) >> 128;
            if (absTick & 0x4000 != 0) price = (price * 0x70d869a156d2a1b890bb3df62baf32f7) >> 128;
            // FIX (Audit M-1): Correct official Uniswap V3/V4 constant for 0x8000
            if (absTick & 0x8000 != 0) price = (price * 0x31be135f97d08fd981231505542fcfa6) >> 128;
            if (absTick & 0x10000 != 0) price = (price * 0x9aa508b5b7a84e1c677de54f3e99bc9) >> 128;
            if (absTick & 0x20000 != 0) price = (price * 0x5d6af8dedb81196699c329225ee604) >> 128;
            if (absTick & 0x40000 != 0) price = (price * 0x2216e584f5fa1ea926041bedfe98) >> 128;
            // FIX (Audit M-1): Correct official Uniswap V3/V4 constant for 0x80000
            if (absTick & 0x80000 != 0) price = (price * 0x48a170391f7dc42444e8fa2) >> 128;

            if (tick > 0) price = type(uint256).max / price;

            sqrtPriceX96 = uint160((price >> 32) + (price % (1 << 32) == 0 ? 0 : 1));
        }
    }
}

library LiquidityAmounts {
    uint256 internal constant Q96 = 0x1000000000000000000000000;

    function getLiquidityForAmount0(uint160 sqrtPriceAX96, uint160 sqrtPriceBX96, uint256 amount0)
        internal
        pure
        returns (uint128)
    {
        if (sqrtPriceAX96 > sqrtPriceBX96) (sqrtPriceAX96, sqrtPriceBX96) = (sqrtPriceBX96, sqrtPriceAX96);
        uint256 intermediate = (uint256(sqrtPriceAX96) * sqrtPriceBX96) / Q96;
        return uint128((amount0 * intermediate) / (sqrtPriceBX96 - sqrtPriceAX96));
    }

    function getLiquidityForAmount1(uint160 sqrtPriceAX96, uint160 sqrtPriceBX96, uint256 amount1)
        internal
        pure
        returns (uint128)
    {
        if (sqrtPriceAX96 > sqrtPriceBX96) (sqrtPriceAX96, sqrtPriceBX96) = (sqrtPriceBX96, sqrtPriceAX96);
        return uint128((amount1 * Q96) / (sqrtPriceBX96 - sqrtPriceAX96));
    }
}

struct Socials {
    string twitter;
    string telegram;
    string discord;
    string website;
    string farcaster;
}

struct LaunchParams {
    string name;
    string symbol;
    string logo;
    string description;
    Socials socials;
    // NOTE: no feeWallet field. Fees are permanently paid to the token
    // creator (msg.sender); there is no fee-address selection or redirection.
}

struct LaunchedToken {
    address token;
    bool isToken0;
    bool exists;
    uint24 poolFee;
    address deployer;
    address pairedToken;
    address positionManager;
    uint256 positionId;
    uint256 dexId;
    uint256 launchConfigId;
    // O-1 FIX: removed dead field `restrictionsEndBlock` (always written 0,
    // never read by any code path).
    uint256 supply;
    uint256 initialBuyAmount;
}

/// @notice Internal storage representation packed into 2 slots (~140k gas saved)
struct StoredLaunchedToken {
    address deployer;         // 20 bytes
    uint32 dexId;             // 4 bytes
    uint32 launchConfigId;    // 4 bytes
    bool isToken0;            // 1 byte
    bool exists;              // 1 byte (total 30 bytes in Slot 1)
    uint128 positionId;       // 16 bytes
    uint128 initialBuyAmount; // 16 bytes (total 32 bytes in Slot 2)
}

contract BSCookFactory is ReentrancyGuard, Ownable2Step, Pausable {
    using SafeERC20 for IERC20;

    address public immutable tokenImplementation;
    address public immutable WBNB;
    INonfungiblePositionManager public immutable positionManager;
    ISwapRouter public immutable swapRouter;

    // Uniswap V4 native integration support
    bool public immutable isV4;
    address public immutable poolManager;
    address public immutable permit2;

    address public bscookLocker;

    // --- FIX (Critical #2): setLocker can no longer take effect instantly.
    // Even if `owner` ends up being a single EOA instead of the intended
    // Timelock+MultiSig, changing where future LP NFTs get locked now
    // requires a mandatory public delay, giving users a chance to notice
    // and exit before a malicious/compromised owner can redirect new LPs.
    uint256 public constant LOCKER_CHANGE_DELAY = 2 days;
    address public pendingLocker;
    uint256 public pendingLockerEta;

    uint256 public launchFee = 0 ether; // 0 BNB (Free Token Launch)
    // --- FIX (Medium #6): hard upper bound so owner can't grief the
    // platform by setting an absurd launch fee.
    uint256 public constant MAX_LAUNCH_FEE = 10 ether;
    /// @notice Mandatory public delay before a launch fee *increase* can apply.
    uint256 public constant LAUNCH_FEE_CHANGE_DELAY = 2 days;
    uint256 public pendingLaunchFee;
    uint256 public pendingLaunchFeeEta;
    uint24 public constant POOL_FEE = 10000; // 1%
    /// @notice Tick spacing enforced by Uniswap V3 for the 1% fee tier.
    int24 public constant TICK_SPACING = 200;
    /// @notice Largest tick that is both <= TickMath.MAX_TICK (887272) and a
    ///         multiple of TICK_SPACING.
    int24 public constant MAX_USABLE_TICK = 887200;
    uint256 public constant FIXED_SUPPLY = 1_000_000_000 * 1e18;
    /// @notice O-1 FIX: graduation threshold is a compile-time constant.
    ///         There is deliberately NO on-chain `graduate()` action in this
    ///         protocol (LP is permanently one-sided locked; the pool simply
    ///         continues trading), so a mutable, owner-controlled threshold
    ///         that nothing consumes was a dead admin surface. The value is
    ///         used ONLY by the display-only `graduationStatus()` view. If a
    ///         real graduation action is ever specced, reintroduce it as a
    ///         queued/delayed change, never an instant setter.
    uint256 public constant GRADUATION_THRESHOLD = 5_000 ether; // 5,000 * 1e18

    /// @notice WBNB side of the initial pool price ratio.
    ///         The pool is initialised at FIXED_SUPPLY token : INITIAL_WBNB_QUOTE WBNB.
    /// @dev SECURITY (O-12): exposed publicly so off-chain callers can DERIVE the
    ///      initial price instead of hardcoding it.
    ///      Must stay consistent with _getInitialSqrtPrice().
    uint256 public constant INITIAL_WBNB_QUOTE = 6 ether;
    /// @notice On-chain cap matching the launch UI's 5% anti-sniper dev-buy limit.
    uint256 public constant MAX_DEV_BUY_AMOUNT = 0.32 ether;

    /// @notice Initial pool price as sqrtPriceX96, for both token orderings.
    /// @dev Read-only mirror of the internal _getInitialSqrtPrice() so integrators
    ///      and the frontend can verify the launch price without guessing.
    function getInitialSqrtPriceX96(bool isToken0) external pure returns (uint160) {
        return _getInitialSqrtPrice(isToken0);
    }

    /// @notice How many whole tokens one whole WBNB buys at the initial price.
    /// @dev FIXED_SUPPLY / INITIAL_WBNB_QUOTE = 1,000,000,000 / 6 = ~166,666,666 tokens per WBNB.
    function initialTokensPerWbnb() external pure returns (uint256) {
        return FIXED_SUPPLY / INITIAL_WBNB_QUOTE;
    }

    mapping(address => StoredLaunchedToken) private _launchedTokens;
    
    /// @notice Tracks all launched token addresses for rescueERC20 protection and external integrators
    function isLaunchedToken(address token) external view returns (bool) {
        return _launchedTokens[token].exists;
    }

    /// @notice Dedicated fast-pause role (e.g. MultiSig) that can pause without Timelock delay
    address public pauser;

    /// @notice Maximum slippage tolerance for LP mint (basis points, 500 = 5%)
    uint256 public constant MAX_SLIPPAGE_BPS = 500;

    /// @notice FIX (#5): Uniswap's `amountDesired -> liquidity -> amount`
    ///         round-trip can floor the actually-deposited amount a few wei
    ///         below FIXED_SUPPLY. A caller demanding `minAmountToken ==
    ///         FIXED_SUPPLY` would then revert on rounding alone (1-2 wei).
    ///         The upper bound keeps a dust margin so a "100%" intent still
    ///         tolerates worst-case rounding. 1e12 wei = 0.000001 token.
    uint256 public constant MAX_MINT_DUST = 1e12;

    /// @notice O-3 FIX: hard upper bound on how far in the future a launch
    ///         `deadline` may be. Without it a caller could sign a launch with a
    ///         deadline days/weeks out; if it sat unbroadcast in a relayer queue
    ///         or was re-submitted later, the (now stale) `minTokensOut` /
    ///         `minAmountToken` bounds would no longer reflect live chain state
    ///         and the dev-buy could execute at a wildly off price. Capping the
    ///         window keeps every launch's slippage bounds meaningfully fresh.
    uint256 public constant MAX_DEADLINE_WINDOW = 30 minutes;

    event TokenLaunched(
        address indexed token,
        address indexed deployer,
        address indexed dexFactory,
        address pairToken,
        address pool,
        uint256 dexId,
        uint256 launchConfigId,
        uint256 positionId,
        uint256 initialBuyAmount
    );

    event LockerChangeQueued(address indexed newLocker, uint256 eta);
    event LockerChangeCancelled(address indexed newLocker);
    event LockerChangeExecuted(address indexed oldLocker, address indexed newLocker);
    event LaunchFeeUpdated(uint256 oldFee, uint256 newFee);
    event LaunchFeeChangeQueued(uint256 newFee, uint256 eta);
    event LaunchFeeChangeCancelled(uint256 newFee);
    event ERC20Rescued(address indexed token, address indexed to, uint256 amount);
    event FeesWithdrawn(address indexed to, uint256 amount);
    event DevBuyExecuted(address indexed token, address indexed buyer, uint256 devBuyAmount, uint256 tokensBought);
    event PauserUpdated(address indexed oldPauser, address indexed newPauser);

    /// @notice Validates that an address is a deployed contract (extcodesize > 0)
    function _validateContract(address _addr) internal view {
        ContractValidation.requireContract(_addr, "Address is not a contract");
    }

    function _validateLocker(address candidate) internal view {
        _validateContract(candidate);
        require(IBSCookLocker(candidate).factory() == address(this), "Locker factory mismatch");
        require(
            IBSCookLocker(candidate).nonfungiblePositionManager() == address(positionManager),
            "Locker position manager mismatch"
        );
    }

    /// @notice Hardens Ownable2Step so ownership can never be transferred to an
    ///         EOA. This is the on-chain enforcement for the documented
    ///         requirement that owner MUST be a Timelock/MultiSig contract:
    ///         even if a deploy script forgets to route ownership correctly,
    ///         the transfer itself reverts instead of silently leaving
    ///         onlyOwner-gated power on a single private key.
    /// @dev Deploying to a chain with contract accounts that legitimately have
    ///      extcodesize == 0 mid-construction is not a concern here since this
    ///      only runs post-deployment, on already-deployed target addresses.
    function transferOwnership(address newOwner) public virtual override onlyOwner {
        _validateContract(newOwner);
        super.transferOwnership(newOwner);
    }

    /// @notice Renouncing ownership is permanently disabled.
    /// @dev Ownable.renounceOwnership() calls _transferOwnership(address(0))
    ///      directly, bypassing the contract-only guard in transferOwnership
    ///      above. Left enabled it is a one-transaction, irreversible bricking
    ///      of the whole platform: a paused factory could never be unpaused,
    ///      accumulated launch fees could never be withdrawn (withdrawFees
    ///      sends to owner()), and the locker could never be repointed. Since
    ///      "no owner" is strictly worse than "timelocked owner" here, the
    ///      function is disabled outright.
    function renounceOwnership() public view override onlyOwner {
        revert("Renounce disabled");
    }

    /// @notice FIX (M-6): the deployer EOA NEVER becomes owner(). Ownership is
    ///         handed to the governance contract (Timelock/MultiSig) from
    ///         block 0 and validated as a contract, closing the
    ///         deploy -> acceptOwnership window during which a single phished
    ///         hot key could withdrawFees()/pause()/repoint the locker.
    ///         The deployer keeps a one-shot BOOTSTRAP role used ONLY for the
    ///         initial setLocker wiring (which is itself one-time).
    address public immutable BOOTSTRAP;

    constructor(
        address _tokenImplementation,
        address _wbnb,
        address _positionManager,
        address _swapRouter,
        address initialOwner,
        address initialPauser
    ) Ownable(initialOwner) {
        _validateContract(_tokenImplementation);
        _validateContract(initialOwner);
        _validateContract(_wbnb);
        _validateContract(_positionManager);
        _validateContract(_swapRouter);
        _validateContract(initialPauser);

        tokenImplementation = _tokenImplementation;
        BOOTSTRAP = msg.sender;
        WBNB = _wbnb;
        positionManager = INonfungiblePositionManager(_positionManager);
        swapRouter = ISwapRouter(_swapRouter);
        pauser = initialPauser;

        address _pm = address(0);
        address _p2 = address(0);
        bool _isV4 = false;
        try IPositionManagerV4(_positionManager).poolManager() returns (address pm) {
            if (pm != address(0)) {
                _isV4 = true;
                _pm = pm;
                try IPositionManagerV4(_positionManager).permit2() returns (address p2) {
                    _p2 = p2;
                } catch {}
            }
        } catch {}
        isV4 = _isV4;
        poolManager = _pm;
        permit2 = _p2;
    }

    /// @notice Launches a new BSCookToken, creates a V3 pool, provides liquidity and locks it
    /// @dev LIQUIDITY MODEL: the launch is deliberately ONE-SIDED. The entire
    ///      FIXED_SUPPLY is deposited as the launched token only, into a tick
    ///      range that sits strictly on the "not yet traded" side of the
    ///      initial price. No WBNB is required or deposited. Buyers push the
    ///      price into the range; the range boundary therefore acts as a hard
    ///      price floor below which the supply cannot be dumped back.
    /// @param deadline Unix timestamp after which the transaction will revert
    /// @param minAmountToken Minimum amount of the launched token to deposit as LP.
    ///        Must be between 95% and (100% - MAX_MINT_DUST) of FIXED_SUPPLY.
    /// @param minAmountWBNB MUST BE ZERO. Retained for ABI compatibility. A
    ///        one-sided launch deposits no WBNB, so any non-zero bound is
    ///        unsatisfiable and is rejected rather than silently ignored.
    /// @param minTokensOut Minimum tokens the caller accepts from the optional dev-buy swap.
    ///        Caller (frontend) should compute these off-chain from the *current* chain state
    ///        right before submitting, exactly like a normal DEX swap.
    /// @param maxDevBuyAmount Maximum WBNB (in wei) the caller wants to spend on the optional
    ///        dev-buy. Any ETH sent above `launchFee + maxDevBuyAmount` is refunded. Use
    ///        `type(uint256).max` to spend the entire remaining value (old behaviour).
    /// @param salt User-provided entropy for CREATE2. Mixed with msg.sender and
    ///        block data so the token address is not derivable from the public
    ///        mempool ALONE. O-3 NOTE: this is defence-in-depth, NOT a strong
    ///        unpredictability guarantee - on BSC `block.prevrandao` is the
    ///        (low-entropy, validator-set) difficulty value and `block.number`
    ///        is guessable, so a determined observer who knows `salt` can still
    ///        narrow candidate addresses. The authoritative front-run defence is
    ///        the exact `sqrtPriceX96` re-check after pool init below, which
    ///        makes a pre-initialised (attacker-priced) pool revert the launch.
    function launchToken(
        LaunchParams calldata params,
        uint256 launchConfigId,
        uint256 dexId,
        bytes32 salt,
        uint256 deadline,
        uint256 minAmountToken,
        uint256 minAmountWBNB,
        uint256 minTokensOut,
        uint256 maxDevBuyAmount,
        address expectedLocker,
        uint8 maxProtocolFeeShare
    ) external payable nonReentrant whenNotPaused returns (address) {
        require(deadline >= block.timestamp, "Expired");
        // O-3 FIX: reject absurdly far-future deadlines so a launch cannot be
        // cached and executed much later against stale slippage bounds.
        require(deadline <= block.timestamp + MAX_DEADLINE_WINDOW, "Deadline too far");
        // GAS: cache launchFee once (read 3x below). Safe: nonReentrant + no
        // external call in this function can mutate the factory's launchFee.
        uint256 fee = launchFee;
        require(msg.value >= fee, "Insufficient launch fee");
        require(bscookLocker != address(0), "Locker not set");
        require(bscookLocker == expectedLocker, "Locker changed; refresh launch quote");
        require(maxProtocolFeeShare <= 90, "Invalid fee-share bound");
        require(
            IBSCookLocker(bscookLocker).protocolFeeShare() <= maxProtocolFeeShare,
            "Protocol fee share exceeds user bound"
        );

        // L-01 FIX: Mix in block entropy, previous blockhash, and timestamp so a mempool
        // observer on BSC (where block.prevrandao is low entropy) cannot pre-compute
        // the exact token address ahead of inclusion to frontrun initializePool.
        bytes32 actualSalt = keccak256(
            abi.encodePacked(
                msg.sender,
                salt,
                block.prevrandao,
                block.number,
                address(this),
                blockhash(block.number - 1),
                block.timestamp
            )
        );

        address tokenAddress = Clones.cloneDeterministic(tokenImplementation, actualSalt);
        BSCookfun(tokenAddress).initialize(
            params.name,
            params.symbol,
            params.logo,
            params.description,
            BSCookfun.Socials({
                twitter: params.socials.twitter,
                telegram: params.socials.telegram,
                discord: params.socials.discord,
                website: params.socials.website,
                farcaster: params.socials.farcaster
            }),
            FIXED_SUPPLY,
            address(this)
        );

        BSCookfun token = BSCookfun(tokenAddress);

        // 2. Initialize Pool & Mint LP (Uniswap V4 with V3 fallback)
        bool isToken0 = address(token) < WBNB;
        address token0 = isToken0 ? address(token) : WBNB;
        address token1 = isToken0 ? WBNB : address(token);
        uint160 sqrtPriceX96 = _getInitialSqrtPrice(isToken0);

        address pool;
        uint256 tokenId;
        address dexFactory;

        if (isV4) {
            (pool, tokenId) = _initAndMintV4(
                address(token),
                token0,
                token1,
                isToken0,
                sqrtPriceX96,
                minAmountToken,
                minAmountWBNB,
                deadline
            );
            dexFactory = poolManager;
        } else {
            (pool, dexFactory, tokenId) = _initAndMintV3(
                address(token),
                token0,
                token1,
                isToken0,
                sqrtPriceX96,
                minAmountToken,
                minAmountWBNB,
                deadline
            );
        }

        // Set pool address on token (only for V3 where pool is a distinct contract) & lock LP
        if (!isV4) {
            token.setLiquidityPool(pool);
        }
        IBSCookLocker(bscookLocker).lockPosition(
            tokenId,
            address(token),
            msg.sender
        );

        // 5. Initial Swap (Dev Buy)
        uint256 availableForDevBuy = msg.value - fee;
        uint256 devBuyAmount = availableForDevBuy;
        if (devBuyAmount > maxDevBuyAmount) {
            devBuyAmount = maxDevBuyAmount;
        }
        require(devBuyAmount <= MAX_DEV_BUY_AMOUNT, "Dev buy exceeds 5% launch cap");

        if (devBuyAmount > 0) {
            _executeDevBuy(
                address(token),
                token0,
                token1,
                devBuyAmount,
                minTokensOut,
                deadline
            );
        }

        // 6. Save State (tightly packed into 2 storage slots = ~140k gas saving)
        require(tokenId <= type(uint128).max, "Position ID overflow");
        require(dexId <= type(uint32).max && launchConfigId <= type(uint32).max, "Config ID overflow");

        _launchedTokens[address(token)] = StoredLaunchedToken({
            deployer: msg.sender,
            dexId: uint32(dexId),
            launchConfigId: uint32(launchConfigId),
            isToken0: isToken0,
            exists: true,
            positionId: uint128(tokenId),
            initialBuyAmount: uint128(devBuyAmount)
        });

        // 7. Emit Event
        emit TokenLaunched(
            address(token),
            msg.sender,
            dexFactory,
            WBNB,
            pool,
            dexId,
            launchConfigId,
            tokenId,
            devBuyAmount
        );

        // 8. Refund LAST (strict Checks-Effects-Interactions).
        //
        // KRİTİK FIX (a): the refund is scoped strictly to *this call's* leftover
        // ETH, never to address(this).balance. The contract can be holding
        // previously accumulated, unwithdrawn launchFee revenue (owner hasn't
        // called withdrawFees() yet) or stray ETH from receive(); using the raw
        // contract balance here would let any caller siphon that unrelated
        // balance out via the refund path.
        //
        // KRİTİK FIX (b): this ETH transfer hands control to msg.sender, which
        // may be a contract. It is now the very last statement, after every
        // storage write and event, so a re-entrant observer can never see this
        // launch in a half-written state (nonReentrant already blocks re-entry
        // into launchToken itself, but CEI ordering also protects every *other*
        // reader of _launchedTokens / isLaunchedToken).
        {
            uint256 spent = fee + devBuyAmount;
            uint256 refundAmount = msg.value > spent ? msg.value - spent : 0;
            if (refundAmount > 0) {
                (bool ok, ) = payable(msg.sender).call{value: refundAmount}("");
                require(ok, "Refund failed");
            }
        }

        return address(token);
    }

    /// @notice Gets information about a launched token (unpacks 2 storage slots into standard ABI format)
    function getLaunchedToken(address token)
        external
        view
        returns (LaunchedToken memory)
    {
        StoredLaunchedToken storage stored = _launchedTokens[token];
        return LaunchedToken({
            token: token,
            isToken0: stored.isToken0,
            exists: stored.exists,
            poolFee: POOL_FEE,
            deployer: stored.deployer,
            pairedToken: WBNB,
            positionManager: address(positionManager),
            positionId: uint256(stored.positionId),
            dexId: uint256(stored.dexId),
            launchConfigId: uint256(stored.launchConfigId),
            supply: FIXED_SUPPLY,
            initialBuyAmount: uint256(stored.initialBuyAmount)
        });
    }

    /// @notice Evaluates if the token has met graduation thresholds
    /// @dev !!! MANIPULABLE - DISPLAY ONLY !!!
    ///      `pairedPrincipal` is the pool's *spot* WBNB balance, which anyone
    ///      can inflate for the duration of a single transaction with a flash
    ///      loan or a plain donation. This function must NEVER be used as an
    ///      oracle, nor gate any transfer of value, on-chain or off-chain.
    ///      It exists purely to render a progress bar. Nothing in this
    ///      contract consumes it.
    function graduationStatus(address token)
        external
        view
        returns (
            uint256 pairedPrincipal,
            uint256 threshold,
            bool graduated
        )
    {
        require(_launchedTokens[token].exists, "Token not launched");

        if (isV4) {
            // FIX (Audit Informational): In Uniswap V4, PoolManager is a singleton custodying
            // all DEX pools combined. Measuring WBNB.balanceOf(poolManager) would falsely attribute
            // the entire DEX's WBNB balance to this token. Paired principal calculation for V4
            // is handled off-chain via pool state indexing.
            pairedPrincipal = 0;
        } else {
            address factory = positionManager.factory();
            address pool = IUniswapV3Factory(factory).getPool(
                token,
                WBNB,
                POOL_FEE
            );
            if (pool != address(0)) {
                pairedPrincipal = IWBNB(WBNB).balanceOf(pool);
            }
        }
        threshold = GRADUATION_THRESHOLD;
        graduated = pairedPrincipal >= threshold;
    }

    /// @notice Returns the raw creation code hash of the token to be launched.
    /// @dev The final deployed address also depends on the runtime salt mixed
    ///      with block entropy inside launchToken(), so it is no longer fully
    ///      pre-computable off-chain from this hash alone.
    function getBytecodeHash(LaunchParams calldata) external view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes10(0x3d602d80600a3d3981f3),
                bytes10(0x363d3d373d3d3d363d73),
                bytes20(tokenImplementation),
                bytes15(0x5af43d82803e903d91602b57fd5bf3)
            )
        );
    }

    /// @dev Rounds `tick` DOWN (towards -infinity) to the nearest multiple of
    ///      TICK_SPACING. Solidity's `/` truncates towards zero, which rounds
    ///      the wrong way for negative ticks - getting this wrong would place
    ///      tickLower below the spot tick and silently turn the one-sided
    ///      position into a two-sided one (which then reverts, or worse,
    ///      requires WBNB the factory does not have).
    function _floorToSpacing(int24 tick) internal pure returns (int24) {
        int24 compressed = tick / TICK_SPACING;
        if (tick < 0 && (tick % TICK_SPACING != 0)) {
            compressed--;
        }
        return compressed * TICK_SPACING;
    }

    /// @dev Calculates initial sqrtPriceX96 for a 1B Token : 6 WBNB ratio

    function _getInitialSqrtPrice(bool isToken0)
        internal
        pure
        returns (uint160)
    {
        if (isToken0) {
            // Token is token0, WBNB is token1. Price = WBNB / Token = 6 / 1,000,000,000.
            // sqrt(6 / 1B) * 2^96
            return 6136987079367210512574055;
        } else {
            // WBNB is token0, Token is token1. Price = Token / WBNB = 1,000,000,000 / 6.
            // sqrt(1B / 6) * 2^96
            return 1022831179894535085429009273225883;
        }
    }

    function _initAndMintV4(
        address token,
        address token0,
        address token1,
        bool isToken0,
        uint160 sqrtPriceX96,
        uint256 minAmountToken,
        uint256 minAmountWBNB,
        uint256 deadline
    ) internal returns (address pool, uint256 tokenId) {
        PoolKey memory poolKey = PoolKey({
            currency0: token0,
            currency1: token1,
            fee: POOL_FEE,
            tickSpacing: TICK_SPACING,
            hooks: address(0)
        });

        int24 currentTick = IPositionManagerV4(address(positionManager)).initializePool(poolKey, sqrtPriceX96);
        // FIX (Audit M-2): Verify that pool was initialized at exactly the expected initial tick.
        // Prevents front-running initialization attacks or unintended sentinel returns from v4-core.
        require(currentTick == (isToken0 ? int24(-189325) : int24(189324)), "Unexpected initial tick");
        pool = poolManager;

        int24 tickLower;
        int24 tickUpper;
        if (isToken0) {
            tickLower = _floorToSpacing(currentTick) + TICK_SPACING;
            tickUpper = MAX_USABLE_TICK;
        } else {
            tickUpper = _floorToSpacing(currentTick);
            tickLower = -MAX_USABLE_TICK;
        }
        require(tickLower < tickUpper, "Invalid tick range");
        require(tickLower >= -MAX_USABLE_TICK && tickUpper <= MAX_USABLE_TICK, "Tick out of range");

        uint256 minAcceptableToken = (FIXED_SUPPLY * (10000 - MAX_SLIPPAGE_BPS)) / 10000;
        require(minAmountToken >= minAcceptableToken, "Slippage: token amount too low");
        require(minAmountToken <= FIXED_SUPPLY - MAX_MINT_DUST, "Slippage: token amount too high");
        require(minAmountWBNB == 0, "minAmountWBNB must be 0");

        uint160 sqrtRatioAX96 = TickMath.getSqrtPriceAtTick(tickLower);
        uint160 sqrtRatioBX96 = TickMath.getSqrtPriceAtTick(tickUpper);
        uint128 liquidity = isToken0
            ? LiquidityAmounts.getLiquidityForAmount0(sqrtRatioAX96, sqrtRatioBX96, FIXED_SUPPLY)
            : LiquidityAmounts.getLiquidityForAmount1(sqrtRatioAX96, sqrtRatioBX96, FIXED_SUPPLY);

        if (permit2 != address(0)) {
            require(IERC20(token).approve(permit2, FIXED_SUPPLY), "Permit2 approve failed");
            IPermit2(permit2).approve(token, address(positionManager), uint160(FIXED_SUPPLY), uint48(deadline));
        } else {
            require(IERC20(token).approve(address(positionManager), FIXED_SUPPLY), "Approve failed");
        }

        // FIX (H-01): tokenId artık mint SONRASINDA türetiliyor.
        // Mint öncesi nextTokenId() snapshot'ı almak kritik bir race condition yaratıyordu:
        // launchToken mempool'dayken araya giren herhangi bir V4 mint işlemi sayacı
        // artırır; bu durumda snapshot değeri hatalı NFT ID'yi gösterir ve
        // lockPosition'daki ownerOf() kontrolü revert eder — tüm launch başarısız olur.
        // Çözüm: modifyLiquidities SONRASI nextTokenId()-1 = gerçek mint edilen ID.

        bytes memory actions = bytes.concat(bytes1(0x02), bytes1(0x0d));
        bytes[] memory mintActionParams = new bytes[](2);
        mintActionParams[0] = abi.encode(
            poolKey,
            tickLower,
            tickUpper,
            uint256(liquidity),
            isToken0 ? uint128(FIXED_SUPPLY) : uint128(0),
            isToken0 ? uint128(0) : uint128(FIXED_SUPPLY),
            bscookLocker,
            bytes("")
        );
        mintActionParams[1] = abi.encode(token0, token1);

        // FIX (Audit #2): Strictly enforce minAmountToken on V4 liquidity minting
        uint256 tokenBefore = IERC20(token).balanceOf(address(this));
        IPositionManagerV4(address(positionManager)).modifyLiquidities(abi.encode(actions, mintActionParams), deadline);
        uint256 tokenAfter = IERC20(token).balanceOf(address(this));
        require(tokenAfter <= tokenBefore, "Unexpected token balance");
        require(tokenBefore - tokenAfter >= minAmountToken, "Mint slippage");

        // FIX (H-01): V4 PositionManager mint sonrası nextTokenId'yi 1 artırır.
        // Çıkarma işlemi gerçek minted NFT ID'yi güvenli biçimde verir.
        // Bu satır modifyLiquidities'DEN SONRA çalıştığı için race condition yoktur.
        tokenId = IPositionManagerV4(address(positionManager)).nextTokenId() - 1;

        if (permit2 != address(0)) {
            // FIX (Audit Hardening): Reset both Permit2 internal allowance and ERC20 allowance
            IPermit2(permit2).approve(token, address(positionManager), 0, 0);
            IERC20(token).approve(permit2, 0);
        } else {
            IERC20(token).approve(address(positionManager), 0);
        }
    }

    function _initAndMintV3(
        address token,
        address token0,
        address token1,
        bool isToken0,
        uint160 sqrtPriceX96,
        uint256 minAmountToken,
        uint256 minAmountWBNB,
        uint256 deadline
    ) internal returns (address pool, address dexFactory, uint256 tokenId) {
        pool = positionManager.createAndInitializePoolIfNecessary(
            token0,
            token1,
            POOL_FEE,
            sqrtPriceX96
        );
        require(pool != address(0), "Pool creation failed");

        (uint160 actualSqrtPriceX96, int24 currentTick, , , , , ) = IUniswapV3Pool(pool).slot0();
        require(actualSqrtPriceX96 == sqrtPriceX96, "Pool already initialized");

        dexFactory = positionManager.factory();
        require(
            IUniswapV3Factory(dexFactory).getPool(token0, token1, POOL_FEE) == pool,
            "Pool address mismatch"
        );

        int24 tickLower;
        int24 tickUpper;
        if (isToken0) {
            tickLower = _floorToSpacing(currentTick) + TICK_SPACING;
            tickUpper = MAX_USABLE_TICK;
        } else {
            tickUpper = _floorToSpacing(currentTick);
            tickLower = -MAX_USABLE_TICK;
        }
        require(tickLower < tickUpper, "Invalid tick range");
        require(tickLower >= -MAX_USABLE_TICK && tickUpper <= MAX_USABLE_TICK, "Tick out of range");

        uint256 minAcceptableToken = (FIXED_SUPPLY * (10000 - MAX_SLIPPAGE_BPS)) / 10000;
        require(minAmountToken >= minAcceptableToken, "Slippage: token amount too low");
        require(minAmountToken <= FIXED_SUPPLY - MAX_MINT_DUST, "Slippage: token amount too high");
        require(minAmountWBNB == 0, "minAmountWBNB must be 0");

        require(IERC20(token).approve(address(positionManager), FIXED_SUPPLY), "Approve failed");

        INonfungiblePositionManager.MintParams memory mintParams = INonfungiblePositionManager.MintParams({
            token0: token0,
            token1: token1,
            fee: POOL_FEE,
            tickLower: tickLower,
            tickUpper: tickUpper,
            amount0Desired: isToken0 ? FIXED_SUPPLY : 0,
            amount1Desired: isToken0 ? 0 : FIXED_SUPPLY,
            amount0Min: isToken0 ? minAmountToken : 0,
            amount1Min: isToken0 ? 0 : minAmountToken,
            recipient: address(this),
            deadline: deadline
        });

        (tokenId, , , ) = positionManager.mint(mintParams);
        require(IERC20(token).approve(address(positionManager), 0), "Approve reset failed");
        positionManager.transferFrom(address(this), bscookLocker, tokenId);
    }

    function _executeDevBuy(
        address token,
        address token0,
        address token1,
        uint256 devBuyAmount,
        uint256 minTokensOut,
        uint256 deadline
    ) internal {
        require(minTokensOut > 0, "minTokensOut must be > 0");
        // FIX (Audit #3): Snapshot WBNB balance so we only refund excess from THIS call
        uint256 wbnbBefore = IWBNB(WBNB).balanceOf(address(this));
        IWBNB(WBNB).deposit{value: devBuyAmount}();

        bool swapped = false;
        if (!isV4 && IWBNB(WBNB).approve(address(swapRouter), devBuyAmount)) {
            ISwapRouter.ExactInputSingleParams memory swapParams = ISwapRouter.ExactInputSingleParams({
                tokenIn: WBNB,
                tokenOut: token,
                fee: POOL_FEE,
                recipient: msg.sender,
                deadline: deadline,
                amountIn: devBuyAmount,
                amountOutMinimum: minTokensOut,
                sqrtPriceLimitX96: 0
            });
            try swapRouter.exactInputSingle(swapParams) returns (uint256 amountOut) {
                require(amountOut >= minTokensOut, "Dev buy slippage");
                swapped = true;
                emit DevBuyExecuted(token, msg.sender, devBuyAmount, amountOut);
            } catch {}
        }

        if (!swapped && isV4) {
            if (permit2 != address(0)) {
                IERC20(WBNB).forceApprove(permit2, devBuyAmount);
                IPermit2(permit2).approve(WBNB, address(swapRouter), uint160(devBuyAmount), uint48(deadline));
            }
            IERC20(WBNB).forceApprove(address(swapRouter), devBuyAmount);

            PoolKey memory pKey = PoolKey({
                currency0: token0,
                currency1: token1,
                fee: POOL_FEE,
                tickSpacing: TICK_SPACING,
                hooks: address(0)
            });
            bytes memory commands = hex"10";
            bytes memory v4Actions = bytes.concat(bytes1(0x06), bytes1(0x0c), bytes1(0x0f));
            bytes[] memory v4Params = new bytes[](3);
            // FIX (Audit H-2): SWAP_EXACT_IN_SINGLE expects abi.decode(params, (ExactInputSingleParams))
            // Encoding as struct produces the required offset pointer instead of flat arguments.
            v4Params[0] = abi.encode(
                IV4Router.ExactInputSingleParams({
                    poolKey: pKey,
                    zeroForOne: WBNB < token,
                    amountIn: uint128(devBuyAmount),
                    amountOutMinimum: uint128(minTokensOut),
                    hookData: bytes("")
                })
            );
            v4Params[1] = abi.encode(WBNB, devBuyAmount);
            v4Params[2] = abi.encode(token, minTokensOut);

            bytes[] memory routerInputs = new bytes[](1);
            routerInputs[0] = abi.encode(v4Actions, v4Params);

            // FIX (Audit #1): Universal Router TAKE_ALL sends token to caller (BSCookFactory).
            // Measure factory balance delta, verify slippage, and forward tokens to msg.sender.
            uint256 factoryTokenBefore = IERC20(token).balanceOf(address(this));
            IUniversalRouter(address(swapRouter)).execute(commands, routerInputs, deadline);
            uint256 factoryTokenAfter = IERC20(token).balanceOf(address(this));
            require(factoryTokenAfter >= factoryTokenBefore, "Unexpected token balance");
            uint256 bought = factoryTokenAfter - factoryTokenBefore;
            require(bought >= minTokensOut, "Dev buy slippage");
            IERC20(token).safeTransfer(msg.sender, bought);
            emit DevBuyExecuted(token, msg.sender, devBuyAmount, bought);
            swapped = true;
        }

        require(swapped, "Dev buy execution failed");
        IERC20(WBNB).forceApprove(address(swapRouter), 0);
        if (permit2 != address(0)) {
            // FIX (Audit Hardening): Reset Permit2 internal allowance and ERC20 allowance for WBNB
            IPermit2(permit2).approve(WBNB, address(swapRouter), 0, 0);
            IERC20(WBNB).forceApprove(permit2, 0);
        }

        // FIX (Audit #3): Refund strictly leftover WBNB from this operation only
        uint256 wbnbAfter = IWBNB(WBNB).balanceOf(address(this));
        if (wbnbAfter > wbnbBefore) {
            uint256 wbnbRefund = wbnbAfter - wbnbBefore;
            require(IWBNB(WBNB).transfer(msg.sender, wbnbRefund), "WBNB refund failed");
        }
    }

    // =========================================================================
    // Admin Functions
    // =========================================================================

    /// @notice Step 1/2: queue a launch fee change.
    /// @dev Fee changes are delayed for the same reason locker changes are: an
    ///      instantly-effective `setLaunchFee` lets the owner front-run an
    ///      in-flight `launchToken` and skim up to MAX_LAUNCH_FEE extra out of
    ///      the caller's msg.value (which would otherwise have gone into their
    ///      dev-buy). A public, mandatory delay means the fee charged is always
    ///      knowable LAUNCH_FEE_CHANGE_DELAY in advance.
    function queueLaunchFeeChange(uint256 _launchFee) external onlyOwner {
        require(_launchFee <= MAX_LAUNCH_FEE, "Fee exceeds max");
        pendingLaunchFee = _launchFee;
        pendingLaunchFeeEta = block.timestamp + LAUNCH_FEE_CHANGE_DELAY;
        emit LaunchFeeChangeQueued(_launchFee, pendingLaunchFeeEta);
    }

    /// @notice Step 2/2: apply a queued launch fee change once the delay elapsed.
    function executeLaunchFeeChange() external onlyOwner {
        require(pendingLaunchFeeEta != 0, "No pending change");
        require(block.timestamp >= pendingLaunchFeeEta, "Timelock not elapsed");
        require(pendingLaunchFee <= MAX_LAUNCH_FEE, "Fee exceeds max");
        emit LaunchFeeUpdated(launchFee, pendingLaunchFee);
        launchFee = pendingLaunchFee;
        pendingLaunchFee = 0;
        pendingLaunchFeeEta = 0;
    }

    /// @notice Cancel a queued launch fee change.
    function cancelLaunchFeeChange() external onlyOwner {
        emit LaunchFeeChangeCancelled(pendingLaunchFee);
        pendingLaunchFee = 0;
        pendingLaunchFeeEta = 0;
    }

    /// @notice Lowering the fee is always safe for users and takes effect
    ///         immediately; raising it must go through queue/execute.
    function setLaunchFee(uint256 _launchFee) external onlyOwner {
        require(_launchFee <= MAX_LAUNCH_FEE, "Fee exceeds max");
        require(_launchFee <= launchFee, "Use queueLaunchFeeChange to raise");
        emit LaunchFeeUpdated(launchFee, _launchFee);
        launchFee = _launchFee;
    }

    /// @notice Step 1/2: queue a new locker address. Takes effect only after
    ///         LOCKER_CHANGE_DELAY, giving users a public, on-chain window to
    ///         notice and react before it can be swapped to a malicious contract.
    function queueLockerChange(address _locker) external onlyOwner {
        require(_locker != address(0), "Invalid address");
        _validateLocker(_locker);
        pendingLocker = _locker;
        pendingLockerEta = block.timestamp + LOCKER_CHANGE_DELAY;
        emit LockerChangeQueued(_locker, pendingLockerEta);
    }

    /// @notice Step 2/2: execute a previously queued locker change once the delay has elapsed.
    function executeLockerChange() external onlyOwner {
        require(pendingLocker != address(0), "No pending change");
        require(block.timestamp >= pendingLockerEta, "Timelock not elapsed");
        // FIX (O-4): re-validate at execute time in case the target was
        // destroyed during the 2-day delay window.
        _validateLocker(pendingLocker);
        address oldLocker = bscookLocker;
        bscookLocker = pendingLocker;
        emit LockerChangeExecuted(oldLocker, pendingLocker);
        pendingLocker = address(0);
        pendingLockerEta = 0;
    }

    /// @notice Cancel a queued locker change (e.g. if the owner key looks compromised).
    function cancelLockerChange() external onlyOwner {
        emit LockerChangeCancelled(pendingLocker);
        pendingLocker = address(0);
        pendingLockerEta = 0;
    }

    /// @dev One-time bootstrap only: allows setting the locker instantly the
    ///      FIRST time (bscookLocker == address(0)), since there's nothing
    ///      to rug yet. All subsequent changes must go through the timelock above.
    ///      FIX (M-6): callable by the deploy-time BOOTSTRAP (owner is the
    ///      Timelock from block 0 and cannot act mid-deploy); still one-shot.
    function setLocker(address _locker) external {
        require(msg.sender == BOOTSTRAP || msg.sender == owner(), "Not authorized");
        require(bscookLocker == address(0), "Use queueLockerChange after initial setup");
        require(_locker != address(0), "Invalid address");
        _validateLocker(_locker);
        bscookLocker = _locker;
        emit LockerChangeExecuted(address(0), _locker);
    }

    /// @notice Recovers genuinely foreign ERC20 tokens accidentally sent to the
    ///         factory (e.g. an unrelated airdrop token, or a wrong-address
    ///         transfer). O-4 FIX: the previous doc cited "V3 mint rounding dust"
    ///         as the use case, but that dust is a LAUNCHED token and is
    ///         explicitly blocked below, so the example was self-contradictory.
    /// @dev Two categories are deliberately NOT rescuable:
    ///      - WBNB: the factory holds WBNB only transiently during a dev-buy;
    ///        allowing a rescue would be a back-door to pull paired liquidity
    ///        value out of every pool. Use withdrawFees for the native balance.
    ///      - any isLaunchedToken: the same rounding-dust argument applies, but
    ///        the security property (owner can never touch a token that has an
    ///        active locked pool) outweighs recovering a few wei of dust, so the
    ///        dust is intentionally left stranded. It is non-custodial dust with
    ///        no economic impact.
    function rescueERC20(address token, address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Invalid recipient");
        require(token != WBNB, "Cannot rescue WBNB");
        // Orta #10: Block rescue of launched tokens (paired tokens in LP positions)
        require(!_launchedTokens[token].exists, "Cannot rescue launched token");
        IERC20(token).safeTransfer(to, amount);
        emit ERC20Rescued(token, to, amount);
    }

    /// @notice Set dedicated fast-pause address (e.g. BSCookMultiSig)
    function setPauser(address newPauser) external onlyOwner {
        if (newPauser != address(0)) _validateContract(newPauser);
        emit PauserUpdated(pauser, newPauser);
        pauser = newPauser;
    }

    /// @notice Emergency pause: callable by owner (timelocked) or pauser (MultiSig fast-path)
    function pause() external {
        require(msg.sender == owner() || (pauser != address(0) && msg.sender == pauser), "Not authorized to pause");
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function withdrawFees() external onlyOwner nonReentrant {
        uint256 balance = address(this).balance;
        require(balance > 0, "No fees to withdraw");
        
        address payable recipient = payable(owner());
        require(recipient != address(0), "Invalid recipient");
        
        (bool success, ) = recipient.call{value: balance}("");
        require(success, "Withdrawal failed");
        emit FeesWithdrawn(address(recipient), balance);
    }

    // Needed to receive ETH from failed swaps or direct transfers
    // FIX (O-6): stray BNB is now traceable on-chain (previously silent).
    // Note: funds sent here by mistake can only be recovered by the owner
    // via withdrawFees() — there is no per-user refund path.
    event StrayBNBReceived(address indexed from, uint256 amount);
    receive() external payable {
        emit StrayBNBReceived(msg.sender, msg.value);
    }
}
