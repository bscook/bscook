// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 * @title BSCookfun
 * @dev Ultra-gas-optimized ERC-20 token contract for the BSCOOK launchpad on BNB Smart Chain (BSC).
 *      Designed for EIP-1167 Minimal Proxy (Clones) to achieve sub-0.01$ token creation.
 *      Tokens are minted fully to the factory upon initialization.
 *      Stores on-chain metadata for the launchpad ecosystem.
 */
contract BSCookfun is ERC20, Initializable {
    struct Socials {
        string twitter;
        string telegram;
        string discord;
        string website;
        string farcaster;
    }

    // Custom Name & Symbol for Clone instances
    string private _customName;
    string private _customSymbol;

    // State variables for metadata (Name, Symbol & Logo strictly preserved on-chain)
    string private _logo;
    
    // Launchpad ecosystem state
    address public factory;
    address private _liquidityPool;
    // FIX (D-1): declared adjacent to _liquidityPool so Solidity packs both
    // into a single storage slot (20 + 1 bytes) — one SSTORE saved on every
    // setLiquidityPool call.
    /// @notice Tracks if setLiquidityPool was successfully called
    bool public liquidityPoolSet;

    // Events
    event LiquidityPoolSet(address indexed lp);
    /// @notice Emitted during clone initialization so indexers and UI consume description and socials
    ///         without burning ~750,000 gas on expensive on-chain SSTORE operations.
    event TokenMetadata(string description, Socials socials);

    // Custom errors
    error Unauthorized();

    /**
     * @dev Constructor locks master implementation from being initialized directly.
     */
    constructor() ERC20("", "") {
        _disableInitializers();
    }

    /**
     * @dev Initializes a new clone proxy instance. Callable only once via EIP-1167.
     * @param name_ The name of the token.
     * @param symbol_ The symbol of the token.
     * @param logo_ The logo URI/URL of the token.
     * @param description_ A short description of the token project.
     * @param socials_ A struct containing social links.
     * @param totalSupply_ The total supply to mint initially.
     * @param factory_ The address of the launchpad factory.
     */
    function initialize(
        string memory name_,
        string memory symbol_,
        string memory logo_,
        string memory description_,
        Socials memory socials_,
        uint256 totalSupply_,
        address factory_
    ) external initializer {
        uint256 nameChars = _validateAndCountUtf8(bytes(name_));
        require(nameChars > 0 && nameChars <= 32 && bytes(name_).length <= 128, "Name must be 1-32 chars");
        uint256 symbolChars = _validateAndCountUtf8(bytes(symbol_));
        require(symbolChars > 0 && symbolChars <= 20 && bytes(symbol_).length <= 64, "Symbol must be 1-20 chars");
        _validateIdentifier(bytes(name_), true);
        _validateIdentifier(bytes(symbol_), false);
        require(bytes(logo_).length <= 256, "Logo URL too long");
        require(bytes(description_).length <= 512, "Description too long");
        require(bytes(socials_.twitter).length <= 128, "Twitter URL too long");
        require(bytes(socials_.telegram).length <= 128, "Telegram URL too long");
        require(bytes(socials_.discord).length <= 128, "Discord URL too long");
        require(bytes(socials_.website).length <= 128, "Website URL too long");
        require(bytes(socials_.farcaster).length <= 128, "Farcaster URL too long");
        require(totalSupply_ > 0, "Supply must be > 0");
        require(factory_ != address(0), "Invalid factory");

        // Validate on-chain metadata with RFC-3629 UTF-8 compliance and anti-spoof checks
        _validateAndCountUtf8(bytes(logo_));
        _customName = name_;
        _customSymbol = symbol_;
        _logo = logo_;
        factory = factory_;

        // Gas Optimization: emit description and socials via event instead of 40+ SSTORE slots.
        // Saves ~750,000 gas per launch, beating competitors while keeping logo on-chain.
        emit TokenMetadata(description_, socials_);

        _mint(factory_, totalSupply_);
    }

    /// @dev Token identifiers are ASCII-only to prevent cross-script homoglyphs,
    ///      invisible spacing, and combining-mark display attacks. Metadata fields
    ///      remain UTF-8 and are sanitized by the frontend before rendering.
    function _validateIdentifier(bytes memory value, bool allowSpaces) internal pure {
        require(value.length > 0, "Empty identifier");
        bool hasAlphaNumeric;
        bool previousSpace;
        for (uint256 i; i < value.length; ++i) {
            uint8 c = uint8(value[i]);
            bool upper = c >= 0x41 && c <= 0x5A;
            bool lower = c >= 0x61 && c <= 0x7A;
            bool digit = c >= 0x30 && c <= 0x39;
            bool space = c == 0x20;
            if (upper || lower || digit) {
                hasAlphaNumeric = true;
                previousSpace = false;
            } else if (allowSpaces && space) {
                require(i != 0 && i + 1 < value.length && !previousSpace, "Invalid name spacing");
                previousSpace = true;
            } else {
                revert("Identifier must be ASCII alphanumeric");
            }
        }
        require(hasAlphaNumeric, "Identifier must contain a letter or digit");
    }

    /**
     * @dev Returns the name of the token.
     */
    function name() public view virtual override returns (string memory) {
        return _customName;
    }

    /**
     * @dev Returns the symbol of the token.
     */
    function symbol() public view virtual override returns (string memory) {
        return _customSymbol;
    }

    /**
     * @dev Rejects strings containing dangerous Unicode control characters that
     *      could be used to spoof token names in UIs (RTL override, zero-width
     *      joiners, BiDi control codes, C0/C1 control characters).
     *
     *      Blocked byte patterns:
     *        - 0x00–0x1F  : C0 controls (includes NUL, tab, newline, etc.)
     *        - 0x7F       : DEL
     *        - 0x80–0x9F  : C1 controls (often encoded as 0xC2 0x80–0x9F in UTF-8)
     *        - 0xE2 0x80-0x86 : UTF-8 sequences for RTL/BiDi/zero-width Unicode codepoints
     *          (U+202A–U+202E), zero-width chars (U+200B–U+200F), BiDi isolates
     *          (U+2066–U+2069), and word joiner (U+2060).
     *        - 0xC2 0x80-0x9F : C1 control characters in UTF-8 encoding
     *        - 0xED 0xA0-0xBF : UTF-8 surrogates (U+D800-U+DFFF, invalid in JSON)
     */
    /**
     * @dev Validates that a byte array conforms strictly to RFC-3629 UTF-8 rules,
     *      blocks dangerous BiDi/Unicode spoofing characters, and counts code points.
     */
    function _validateAndCountUtf8(bytes memory b) internal pure returns (uint256 charCount) {
        uint256 len = b.length;
        uint256 i = 0;
        while (i < len) {
            uint8 c = uint8(b[i]);
            // 1-byte sequence (ASCII 0x00-0x7F)
            if (c < 0x80) {
                // Reject C0 controls (< 0x20) and DEL (0x7F)
                require(c >= 0x20 && c != 0x7F, "Unsafe ASCII character");
                charCount++;
                i++;
            }
            // 2-byte sequence (0xC2-0xDF)
            else if (c >= 0xC2 && c <= 0xDF) {
                require(i + 1 < len, "Truncated UTF-8");
                uint8 b1 = uint8(b[i + 1]);
                require((b1 & 0xC0) == 0x80, "Invalid UTF-8 continuation");
                // Block C1 controls: U+0080-U+009F (encoded as 0xC2 0x80-0x9F)
                if (c == 0xC2 && b1 <= 0x9F) revert("Unsafe C1 control");
                // Block U+00A0 (No-Break Space: 0xC2 0xA0)
                if (c == 0xC2 && b1 == 0xA0) revert("Unsafe no-break space");
                // Block U+00AD (Soft Hyphen, invisible spoofing: 0xC2 0xAD)
                if (c == 0xC2 && b1 == 0xAD) revert("Unsafe soft hyphen");
                // Block U+034F (Combining Grapheme Joiner: 0xCD 0x8F)
                if (c == 0xCD && b1 == 0x8F) revert("Unsafe grapheme joiner");
                // Block U+061C (Arabic Letter Mark, BiDi control: 0xD8 0x9C)
                if (c == 0xD8 && b1 == 0x9C) revert("Unsafe BiDi control");
                charCount++;
                i += 2;
            }
            // 3-byte sequence (0xE0-0xEF)
            else if (c >= 0xE0 && c <= 0xEF) {
                require(i + 2 < len, "Truncated UTF-8");
                uint8 b1 = uint8(b[i + 1]);
                uint8 b2 = uint8(b[i + 2]);
                require((b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80, "Invalid UTF-8 continuation");

                // Overlong check for E0 (must be >= 0xA0)
                if (c == 0xE0) {
                    require(b1 >= 0xA0, "Overlong UTF-8 sequence");
                }
                // Surrogate check for ED (U+D800 - U+DFFF, b1 must be <= 0x9F)
                else if (c == 0xED) {
                    require(b1 <= 0x9F, "UTF-8 surrogate codepoint");
                }

                // Block U+180E (Mongolian Vowel Separator, invisible format: 0xE1 0xA0 0x8E)
                if (c == 0xE1 && b1 == 0xA0 && b2 == 0x8E) revert("Unsafe invisible separator");
                // Mongolian free variation selectors U+180B-U+180D/U+180F.
                if (c == 0xE1 && b1 == 0xA0 && (b2 == 0x8B || b2 == 0x8C || b2 == 0x8D || b2 == 0x8F)) {
                    revert("Unsafe Mongolian variation selector");
                }
                // Block U+115F-U+1160 (Hangul Choseong/Jungseong Filler: 0xE1 0x85 0x9F / 0xA0)
                if (c == 0xE1 && b1 == 0x85 && (b2 == 0x9F || b2 == 0xA0)) revert("Unsafe Hangul filler");
                // Block U+17B4-U+17B5 (Khmer Vowel Inherent: 0xE1 0x9E 0xB4 / 0xB5)
                if (c == 0xE1 && b1 == 0x9E && (b2 == 0xB4 || b2 == 0xB5)) revert("Unsafe Khmer invisible");

                // Block dangerous BiDi & zero-width ranges:
                // U+200B-U+200F, U+2028-U+2029 (line separators), U+202A-U+202E, U+2060-U+2064, U+2066-U+2069, U+2800 (Braille blank)
                if (c == 0xE2) {
                    bool zeroWidthOrBidi = (b1 == 0x80 && (b2 <= 0x8F || (b2 >= 0xA8 && b2 <= 0xAF)))
                        || (b1 == 0x81 && b2 >= 0x9F && b2 <= 0xA9)
                        || (b1 == 0xA0 && b2 == 0x80);
                    if (zeroWidthOrBidi) revert("Unsafe unicode in string");
                }

                // Additional Unicode space characters commonly rendered like ASCII space.
                if (c == 0xE3 && b1 == 0x80 && b2 == 0x80) revert("Unsafe ideographic space"); // U+3000
                if (c == 0xE1 && b1 == 0x9A && b2 == 0x80) revert("Unsafe Ogham space"); // U+1680

                // Block U+3164 (Hangul Filler: 0xE3 0x85 0xA4)
                if (c == 0xE3 && b1 == 0x85 && b2 == 0xA4) revert("Unsafe Hangul filler");

                // Block BOM / ZWNBSP (U+FEFF = EF BB BF), Interlinear annotations (EF BF B9-BB), Variation Selectors (U+FE00-U+FE0F = EF B8 80-8F)
                if (c == 0xEF) {
                    if (b1 == 0xBB && b2 == 0xBF) revert("Unsafe BOM in string");
                    if (b1 == 0xBE && b2 == 0xA0) revert("Unsafe Hangul halfwidth filler"); // U+FFA0
                    if (b1 == 0xBF && b2 >= 0xB9 && b2 <= 0xBB) revert("Unsafe annotation in string");
                    if (b1 == 0xB8 && b2 >= 0x80 && b2 <= 0x8F) revert("Unsafe variation selector");
                }

                charCount++;
                i += 3;
            }
            // 4-byte sequence (0xF0-0xF4, e.g. Emojis)
            else if (c >= 0xF0 && c <= 0xF4) {
                require(i + 3 < len, "Truncated UTF-8");
                uint8 b1 = uint8(b[i + 1]);
                uint8 b2 = uint8(b[i + 2]);
                uint8 b3 = uint8(b[i + 3]);
                require(
                    (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80,
                    "Invalid UTF-8 continuation"
                );

                // Overlong check for F0 (must be >= 0x90)
                if (c == 0xF0) {
                    require(b1 >= 0x90, "Overlong UTF-8 sequence");
                }
                // Upper bound check for F4 (max U+10FFFF, b1 must be <= 0x8F)
                else if (c == 0xF4) {
                    require(b1 <= 0x8F, "UTF-8 codepoint above U+10FFFF");
                }

                // Block Unicode Tag characters: U+E0000 - U+E007F (lead bytes 0xF3 0xA0)
                if (c == 0xF3 && b1 == 0xA0) {
                    revert("Unsafe unicode tag character");
                }

                charCount++;
                i += 4;
            }
            // Invalid lead byte (0x80-0xBF standalone continuation, 0xC0-0xC1 overlong, 0xF5-0xFF)
            else {
                revert("Invalid UTF-8 byte");
            }
        }
    }

    /**
     * @notice Returns the logo of the token.
     * @return The logo string.
     */
    function logo() external view returns (string memory) {
        return _logo;
    }

    /**
     * @notice Returns the description of the token.
     * @dev Maintained for full ABI backward-compatibility. Description is emitted via TokenMetadata event.
     */
    function description() external pure returns (string memory) {
        return "";
    }

    /**
     * @notice Returns the social links associated with the token.
     * @dev Maintained for full ABI backward-compatibility. Socials are emitted via TokenMetadata event.
     */
    function socials() external pure returns (
        string memory twitter,
        string memory telegram,
        string memory discord,
        string memory website,
        string memory farcaster
    ) {
        return ("", "", "", "", "");
    }

    /**
     * @notice Returns the liquidity pool address.
     * @return The address of the liquidity pool.
     */
    function liquidityPool() external view returns (address) {
        return _liquidityPool;
    }

    /**
     * @notice Sets the liquidity pool address. Can only be called by the factory.
     * @dev Orta #9: Allows retry if previous call failed (gas, etc.)
     * @param lp_ The address of the liquidity pool.
     */
    function setLiquidityPool(address lp_) external {
        if (msg.sender != factory) revert Unauthorized();
        // FIX (D-3): reject zero address to prevent frontend confusion
        require(lp_ != address(0), "Zero LP address");
        // Allow retry if not yet set, or if lp_ is same (idempotent)
        require(!liquidityPoolSet || lp_ == _liquidityPool, "Already set with different address");
        
        _liquidityPool = lp_;
        liquidityPoolSet = true;
        emit LiquidityPoolSet(lp_);
    }

    /**
     * @notice Official platform protocol identifier
     */
    string public constant PROTOCOL = "BSCook.fun";

    /**
     * @notice Returns the contract owner for BEP-20 compatibility on BNB Smart Chain.
     * @return The address of the factory contract.
     */
    function getOwner() external view returns (address) {
        return factory;
    }
}
