# BSCook Protocol - Smart Contracts

[![Chain: BNB Smart Chain](https://img.shields.io/badge/Network-BNB%20Smart%20Chain%20(BSC)-F3BA2F?style=flat&logo=binance)](https://bscscan.com)
[![DEX: Uniswap V4](https://img.shields.io/badge/DEX-Uniswap%20V4-ff007a?style=flat&logo=uniswap)](https://uniswap.org)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-363636?style=flat&logo=solidity)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Internal Security Assessment](https://img.shields.io/badge/Security-Internal%20Assessment%20Documented-blue)](BSCook-Security-Audit.pdf)

Official smart contract repository for **BSCook**, a decentralized token launch protocol on the **BNB Smart Chain (BSC)** utilizing a **Single-Sided Uniswap V4 Liquidity Engine** with permanent LP locking.

Token liquidity is initialized directly into native **Uniswap V4** single-sided pools at launch.

---

## 🏛 Architecture & Design

The on-chain protocol consists of five core smart contracts designed for gas efficiency, rug-pull immunity, and multi-layered governance:

```
                +-------------------+
                |  BSCookMultiSig   | (2-of-3 Multi-Signature Guardians)
                +---------+---------+
                          |
                +---------v---------+
                |  BSCookTimelock   | (12h - 48h Delayed Execution)
                +---------+---------+
                          |
             +------------+------------+
             |                         |
    +--------v--------+       +--------v--------+
    | BSCookFactory   | ----> |  BSCookLocker   | (Permanent V4 LP Vault)
    +--------+--------+       +-----------------+
             |
   +---------+---------+
   | (Clones / EIP1167)|
   v                   v
[BSCookToken #1]  [BSCookToken #2] ...
```

### Core Contracts

* **`BSCookFactory.sol`**
  Deploys tokens via gas-optimized EIP-1167 minimal proxies, initializes single-sided Uniswap V4 liquidity pools with verified `TickMath` parameters, and deposits the liquidity position NFT directly into `BSCookLocker`. 
  - **Fixed Supply**: 1,000,000,000 tokens (18 decimals).
  - **Single-Sided Pool**: Entire token supply is placed above the initial price (`INITIAL_WBNB_QUOTE = 6 ether`, `MAX_USABLE_TICK = 887200`).
  - **Anti-Sniper Dev-Buy**: Hard-capped on-chain at `0.32 BNB` maximum per creator launch transaction (approx. 5% supply).
  - **No Migration Required**: Trading occurs natively on Uniswap V4 from block 1 without artificial graduation delays.

* **`BSCookToken.sol`**
  Standard OpenZeppelin ERC20 implementation cloned for each launch.
  - **Zero Honeypot Risk**: No blacklist, no transfer taxes, no trading pause on users, and no post-initialization mint capability.

* **`BSCookLocker.sol`**
  Non-custodial, permanent liquidity vault for Uniswap V4 LP NFT positions.
  - **Permanent Lock**: No withdrawal function exists for locked LP positions; `rescueERC721` strictly forbids touching locked position tokens.
  - **Creator Fee Claims & Dispute Freezes**: Allows token creators to claim their 75% fee share. In the event of compromised keys or disputes:
    - **Fee Guardian (2-of-3 MultiSig)**: Can enforce a temporary freeze of up to **7 days** (with a 14-day cooldown per wallet).
    - **Timelocked Owner**: Can freeze claims **indefinitely** (`type(uint256).max`), and only the Timelocked Owner can unfreeze after off-chain identity verification.
    - *Note: Underlying LP principal remains permanently locked in Uniswap V4 and is completely unaffected by fee freezes.*

* **`BSCookTimelock.sol`**
  Time-delayed governance controller enforcing a 12 to 48-hour delay window on all critical administrative actions.

* **`BSCookMultiSig.sol`**
  2-of-3 threshold multi-signature contract governing emergency pause triggers and temporary fee-freeze disputes.

* **`ContractValidation.sol`**
  Shared library enforcing input sanity checks, contract address verifications, and execution guards.

---

## 🚀 Deployed Addresses (BNB Smart Chain Mainnet)

All protocol contracts are deployed and verified on **BNB Smart Chain (Chain ID: 56)**:

| Contract | Mainnet Address | Explorer Link |
| :--- | :--- | :--- |
| **BSCookFactory** | `0xe8a0beEEdd39af3a87De11d6b120D0fFa874867D` | [View on BscScan](https://bscscan.com/address/0xe8a0beEEdd39af3a87De11d6b120D0fFa874867D#code) |
| **BSCookToken Implementation** | `0x66aEfEE3B1f3163f036Aeee733035df09F49Fc02` | [View on BscScan](https://bscscan.com/address/0x66aEfEE3B1f3163f036Aeee733035df09F49Fc02#code) |
| **BSCookLocker** | `0x3a8587057f85eb318F52c2C9ae148940741CFCfD` | [View on BscScan](https://bscscan.com/address/0x3a8587057f85eb318F52c2C9ae148940741CFCfD#code) |
| **BSCookTimelock** | `0x4cec2C1DA4D2f460402aC38aF04Ed29D0C922c83` | [View on BscScan](https://bscscan.com/address/0x4cec2C1DA4D2f460402aC38aF04Ed29D0C922c83#code) |
| **BSCookMultiSig** | `0xAa2699E1737052869c97a681d3d6d1C9b969120e` | [View on BscScan](https://bscscan.com/address/0xAa2699E1737052869c97a681d3d6d1C9b969120e#code) |

---

## 🛡 Security & Governance Transparency

1. **Permanent LP Lock (Existing Launches)**: For all launched tokens, LP positions are deposited and locked permanently in `BSCookLocker`. The contract contains no code path to withdraw, burn, or reduce active liquidity once locked.
2. **Immutable Token Logic**: Deployed tokens have no owner, no transfer tax logic, and no post-deployment minting capability.
3. **Admin Token Safety**: `BSCookFactory.rescueERC20` contains explicit safeguards forbidding the rescue of launched tokens or WBNB.
4. **Future Locker Migration Vector**: The protocol owner can call `queueLockerChange` with a mandatory 2-day queue delay (`LOCKER_CHANGE_DELAY = 2 days`). Existing launched tokens and their LP positions remain permanently locked in their original locker. However, *future* tokens launched after the 2-day queue would deposit LP into the new locker address. Integrators and token buyers should monitor the `LockerChangeQueued` event.
5. **MultiSig Governance**: Requires 2-of-3 threshold consensus. If keys are not held by independent parties, effective decentralization is reduced.
6. **Internal Security Document**: For detailed architectural analysis, refer to [BSCook-Security-Audit.pdf](BSCook-Security-Audit.pdf).

---

## 📄 License

This repository is licensed under the [MIT License](LICENSE).
