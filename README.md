# BSCook Protocol - Smart Contracts

[![Chain: BNB Smart Chain](https://img.shields.io/badge/Network-BNB%20Smart%20Chain%20(BSC)-F3BA2F?style=flat&logo=binance)](https://bscscan.com)
[![DEX: Uniswap V4](https://img.shields.io/badge/DEX-Uniswap%20V4-ff007a?style=flat&logo=uniswap)](https://uniswap.org)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-363636?style=flat&logo=solidity)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: AvengerDAO Ready](https://img.shields.io/badge/AvengerDAO-Compatible-success)](https://bscscan.com)
[![Audit: 98/100 Passed](https://img.shields.io/badge/Audit-98%2F100%20Passed-brightgreen.svg)](BSCook-Security-Audit.pdf)

Official smart contract repository for **BSCook**, a decentralized fair-launch protocol on the **BNB Smart Chain (BSC)** utilizing a **Single-Sided Uniswap V4 Liquidity Architecture** with permanent, non-custodial LP locking.

Unlike legacy launchpads that require external bonding curves and migration steps, BSCook seeds token liquidity directly into native **Uniswap V4** single-sided pools at block 1.

---

## 🏛 Architecture & Design

The protocol is built around five core contracts designed for gas efficiency, rug-pull immunity, and decentralized governance:

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
  Deploys tokens via gas-optimized EIP-1167 minimal proxies, initializes single-sided Uniswap V4 liquidity pools with mathematically verified `TickMath` parameters, and deposits the liquidity position NFT directly into `BSCookLocker`. 
  - **Fixed Supply**: 1,000,000,000 tokens (18 decimals).
  - **Single-Sided Pool**: Entire token supply is placed above the initial price (`INITIAL_WBNB_QUOTE = 6 ether`, `MAX_USABLE_TICK = 887200`).
  - **Anti-Sniper Dev-Buy**: On-chain hard cap of `0.32 BNB` maximum per creator launch transaction.
  - **No Migration Required**: Trading occurs natively on Uniswap V4 from block 1 without artificial graduation delays.

* **`BSCookToken.sol`**
  Clean, standard OpenZeppelin ERC20 implementation cloned for each launch.
  - **Zero Honeypot Risk**: No blacklist, no transfer fees, no trading pause on users, and no post-initialization mint capability.

* **`BSCookLocker.sol`**
  Non-custodial, permanent liquidity vault for Uniswap V4 LP NFT positions.
  - **Permanent Lock**: No withdrawal function exists for locked LP positions; `rescueERC721` strictly forbids touching locked position tokens.
  - **Creator Fee Claims**: Allows token creators to claim their 75% share of pool trading fees without altering the underlying liquidity.

* **`BSCookTimelock.sol`**
  Time-delayed governance controller enforcing a 12 to 48-hour delay window on all critical administrative actions.

* **`BSCookMultiSig.sol`**
  2-of-3 threshold multi-signature contract governing emergency pause triggers and temporary fee-freeze disputes (capped at 7 days).

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

## 🛡 Security & Transparency Highlights

1. **Rug-Pull Immunity**: LP positions are locked permanently upon creation. The locker contract has no code path to remove or burn active liquidity.
2. **Immutable Token Logic**: Tokens have no owner, no tax logic, and no minting mechanism post-deployment.
3. **Admin Token Safety**: `BSCookFactory.rescueERC20` contains explicit safeguards forbidding the rescue of launched tokens or WBNB.
4. **Governed Upgrades**: Any future locker changes require `queueLockerChange` with a mandatory 2-day queue delay, affecting only future launches.
5. **Compiler Specs**: Compiled with Solidity `0.8.20` using `--via-ir` and 800 optimizer runs.

---

## 💻 Build & Verification

### Prerequisites
* [Node.js](https://nodejs.org/) (v18+)
* [npm](https://www.npmjs.com/)

### Installation & Compile

```bash
git clone https://github.com/bscook/bscook.git
cd bscook
npm install
npx hardhat compile
```

---

## 📄 License

This repository is licensed under the [MIT License](LICENSE).
