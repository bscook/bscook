// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ContractValidation} from "./ContractValidation.sol";

/**
 * @title BSCookTimelock
 * @dev TimelockController for BSCookFactory and BSCookLocker admin functions.
 *      All sensitive operations (fee changes, pause, withdrawals) require a
 *      configurable delay before execution. Users can monitor pending transactions.
 *
 *      Deployment:
 *        1. Deploy BSCookTimelock with desired minDelay (>= MIN_ALLOWED_DELAY)
 *        2. Set BSCookFactory and BSCookLocker owner to BSCookTimelock address
 *        3. All admin calls go through: schedule() -> wait minDelay -> execute()
 *        4. PROPOSER/CANCELLER = BSCookMultiSig (or a Safe)
 *
 *      HARDENING NOTE - renounce the admin role.
 *      TimelockController grants DEFAULT_ADMIN_ROLE to `admin` at construction.
 *      That role can grant PROPOSER/EXECUTOR/CANCELLER to arbitrary addresses
 *      with no delay. It cannot shorten the delay itself, but it can widen who
 *      is allowed to propose. Once the intended proposer/executor set is
 *      configured, `admin` SHOULD renounce DEFAULT_ADMIN_ROLE so that all
 *      future role changes must themselves pass through the timelock.
 */
contract BSCookTimelock is TimelockController {
    /// @notice Hard floor on the effective timelock delay.
    /// @dev 12h matches the recommended deployment default; 24-48h is preferred
    ///      for a launchpad that custodies permanently-locked LP positions.
    uint256 public constant MIN_ALLOWED_DELAY = 12 hours;
    /// @notice FIX (Audit L-3): Hard ceiling on the timelock delay to prevent governance lock-in.
    uint256 public constant MAX_ALLOWED_DELAY = 48 hours;

    /// @notice FIX (O-3): on-chain traceability for every BNB that enters this
    ///         timelock (e.g. BSCookFactory.withdrawFees() sweeping launch
    ///         fees into owner() == this contract, or stray transfers).
    event TimelockBNBReceived(address indexed from, uint256 amount);

    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {
        require(minDelay >= MIN_ALLOWED_DELAY, "Delay too short");
        require(minDelay <= MAX_ALLOWED_DELAY, "Delay exceeds max 48 hours");
        // FIX (Audit #6): Prevent accidental EOA admin deployment.
        // Admin must either be address(0) (pure self-administration via timelock)
        // or a verified multi-sig contract.
        if (admin != address(0)) {
            ContractValidation.requireContract(admin, "Admin must be contract or address(0)");
        }
    }

    /**
     * @notice Effective minimum delay, floored at MIN_ALLOWED_DELAY.
     *
     * @dev SECURITY FIX - the constructor check alone was cosmetic.
     *      `TimelockController.updateDelay(uint256)` is callable by the timelock
     *      itself through an ordinary scheduled operation and accepts ANY value,
     *      including 0. So a compromised or colluding proposer set could:
     *          schedule(updateDelay(0)) -> wait out one final delay -> execute
     *      and from that moment every privileged action against the factory and
     *      the locker (repointing the locker, unpausing, moving fee recipients,
     *      rescuing tokens) would execute with ZERO public warning. That single
     *      operation erases the reaction window the entire governance design
     *      rests on.
     *
     *      `_minDelay` is private in the base contract and `updateDelay` is
     *      `external`, so it cannot be usefully wrapped. Instead the floor is
     *      enforced where it actually matters: `_schedule()` validates every
     *      new operation against `getMinDelay()`, which is `virtual`. Overriding
     *      it here means that even if `_minDelay` is driven to 0, no operation
     *      can ever be scheduled with a delay shorter than MIN_ALLOWED_DELAY.
     */
    function getMinDelay() public view virtual override returns (uint256) {
        uint256 configured = super.getMinDelay();
        return configured < MIN_ALLOWED_DELAY ? MIN_ALLOWED_DELAY : configured;
    }

    /**
     * @dev REJECTED AUDIT FINDING (#7) - DO NOT "FIX" BY REVERTING receive().
     *      An external review suggested overriding receive() to revert so
     *      stray BNB cannot land here. That would be a CRITICAL regression:
     *      BSCookFactory.withdrawFees() sends ALL accumulated launch fees to
     *      owner() (this Timelock) via a plain `call{value}`, so a rejecting
     *      receive() would brick platform fee withdrawal permanently.
     *
     *      The premise ("BNB here is stuck") is also false: execute() and
     *      executeBatch() are payable and forward `value` to any target from
     *      this contract's own balance, so ETH held here is recoverable
     *      through the normal (timelocked) governance flow.
     */

    /**
     * @notice FIX (O-4): denylist the self-administered `updateDelay` operation.
     *
     * @dev The `getMinDelay()` override above already neutralises the *effect*
     *      of `updateDelay(0)` at scheduling time, but `_minDelay` itself could
     *      still be mutated. This defence-in-depth layer makes the mutation
     *      outright impossible: any scheduled operation whose calldata targets
     *      this contract with the `updateDelay` selector reverts at execution.
     *      Nothing in this protocol legitimately needs to change the raw
     *      `_minDelay` storage (the floored `getMinDelay()` is the single
     *      source of truth for scheduling), so there is no liveness cost.
     */
    function _execute(
        address target,
        uint256 value,
        bytes calldata data
    ) internal virtual override {
        if (target == address(this) && data.length >= 4) {
            bytes4 sel;
            assembly {
                sel := calldataload(data.offset)
            }
            if (sel == this.updateDelay.selector) {
                revert("BSCookTimelock: updateDelay disabled");
            }
        }
        super._execute(target, value, data);
    }

    /**
     * @notice FIX (O-3): emit an event for every incoming BNB instead of the
     *         base contract's silent accept. BNB must keep flowing IN because
     *         `BSCookFactory.withdrawFees()` sweeps accumulated launch fees to
     *         `owner()` == this contract — reverting here would strand those
     *         fees in the factory forever.
     *
     * @dev RECOVERY PATH for BNB held by this timelock: the base contract's
     *      `execute()` supports value-carrying operations, so governance can
     *      move funds out with
     *          schedule(treasuryAddress, amount, "", 0, salt) -> wait -> execute
     *      (e.g. forward to the MultiSig treasury). Any scheduled operation
     *      needs no special handling for this — the base implementation sends
     *      `value` with the call.
     */
    receive() external payable override {
        emit TimelockBNBReceived(msg.sender, msg.value);
    }
}
