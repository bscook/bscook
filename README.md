# BSCook Protocol - Smart Contracts

[![Chain: BNB Smart Chain](https://img.shields.io/badge/Network-BNB%20Smart%20Chain%20(BSC)-F3BA2F?style=flat&logo=binance)](https://bscscan.com)
[![DEX: Uniswap V4](https://img.shields.io/badge/DEX-Uniswap%20V4-ff007a?style=flat&logo=uniswap)](https://uniswap.org)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-363636?style=flat&logo=solidity)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: AvengerDAO Ready](https://img.shields.io/badge/AvengerDAO-Compatible-success)](https://bscscan.com)

Welcome to the official smart contract repository for **BSCook**, a decentralized fair-launch token launchpad and liquidity management protocol built on the **BNB Smart Chain (BSC)** with native **Uniswap V4** integration.

BSCook provides a transparent, secure, and rug-proof token creation and bonding-curve trading environment with automated decentralized exchange (**Uniswap V4**) liquidity migration and locking.

---

## 🏛 Architecture & Contracts

The protocol is designed around a modular, gas-optimized architecture:

```
                +-------------------+
                |  BSCookMultiSig   | (Multi-Signature Authorization)
                +---------+---------+
                          |
                +---------v---------+
                |  BSCookTimelock   | (Time-Delayed Execution)
                +---------+---------+
                          |
             +------------+------------+
             |                         |
    +--------v--------+       +--------v--------+
    | BSCookFactory   |       |  BSCookLocker   | (Uniswap V4 LP Vault)
    +--------+--------+       +-----------------+
             |
   +---------+---------+
   | (Clones / EIP1167)|
   v                   v
[BSCookToken #1]  [BSCookToken #2] ...
```

### Core Contracts

* **`BSCookFactory.sol`**
  The central hub of the protocol. Deploys tokens via gas-efficient EIP-1167 minimal proxies, administers bonding curve trading, and automatically migrates liquidity to **Uniswap V4** (via `IPositionManagerV4` / `IV4Router`) with V3 compatibility when the bonding curve reaches its goal.

* **`BSCookToken.sol`**
  The master ERC20 implementation cloned for each launch. Complies with BEP20/ERC20 standards, features customizable initial supplies, decimals, metadata, and fair-launch initial allocations.

* **`BSCookLocker.sol`**
  Secure liquidity vault designed for **Uniswap V4** (`IPositionManagerV4`) and V3 LP positions. Prevents rug-pulls by locking LP positions with custom lock duration, fee-claiming rules, and optional burn addresses (`0x00...dEaD`).

* **`BSCookTimelock.sol`**
  Governance execution module enforcing delay windows for any protocol parameter changes or critical administrative actions, protecting users from sudden changes.

* **`BSCookMultiSig.sol`**
  Multi-signature contract ensuring that sensitive administrative operations require consensus among designated protocol guardians.

* **`ContractValidation.sol`**
  Shared utility library enforcing input sanity checks, address validations, and call verifications across contracts.

---

## 🚀 Deployed Addresses (BNB Smart Chain Mainnet)

All core protocol contracts are deployed and verified on **BNB Smart Chain (Chain ID: 56)**:

| Contract | Mainnet Address | Explorer Link |
| :--- | :--- | :--- |
| **BSCookFactory** | `0xe8a0beEEdd39af3a87De11d6b120D0fFa874867D` | [View on BscScan](https://bscscan.com/address/0xe8a0beEEdd39af3a87De11d6b120D0fFa874867D#code) |
| **BSCookToken Implementation** | `0x66aEfEE3B1f3163f036Aeee733035df09F49Fc02` | [View on BscScan](https://bscscan.com/address/0x66aEfEE3B1f3163f036Aeee733035df09F49Fc02#code) |
| **BSCookLocker** | `0x3a8587057f85eb318F52c2C9ae148940741CFCfD` | [View on BscScan](https://bscscan.com/address/0x3a8587057f85eb318F52c2C9ae148940741CFCfD#code) |
| **BSCookTimelock** | `0x4cec2C1DA4D2f460402aC38aF04Ed29D0C922c83` | [View on BscScan](https://bscscan.com/address/0x4cec2C1DA4D2f460402aC38aF04Ed29D0C922c83#code) |
| **BSCookMultiSig** | `0xAa2699E1737052869c97a681d3d6d1C9b969120e` | [View on BscScan](https://bscscan.com/address/0xAa2699E1737052869c97a681d3d6d1C9b969120e#code) |

---

## 🛡 Security & Best Practices

1. **Native Uniswap V4 Architecture**: Leverages singleton PoolManager architecture, hook validation, and `Permit2` for gas efficiency.
2. **Reentrancy Protection**: All user and liquidity interactions utilize OpenZeppelin's `ReentrancyGuard`.
3. **Safe Token Transfers**: Token balances and distributions leverage OpenZeppelin's `SafeERC20`.
4. **Decentralized Ownership**: Two-step ownership transfers (`Ownable2Step`) managed by the `BSCookTimelock` and multi-signature consensus.
5. **Transparent Liquidity**: LP positions locked transparently in `BSCookLocker` verifiable on-chain.
6. **Via-IR Optimized**: Compiled with Solidity `0.8.20` using `--via-ir` and 800 optimizer runs for maximum bytecode efficiency.

---

## 💻 Build & Compile

### Prerequisites
* [Node.js](https://nodejs.org/) (v18 or higher recommended)
* [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/)

### Installation

```bash
git clone <your-repo-url>
cd bscdapp
npm install
```

### Compile Contracts

```bash
npx hardhat compile
```

### Run Tests

```bash
npx hardhat test
```

---

## 📄 License

This repository is licensed under the [MIT License](LICENSE).
