// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice Shared code-account validation for BSC after EIP-7702 activation.
library ContractValidation {
    uint24 private constant EIP7702_DELEGATION_PREFIX = 0xef0100;

    function requireContract(address account, string memory errorMessage) internal view {
        uint256 size;
        uint24 prefix;
        assembly ("memory-safe") {
            size := extcodesize(account)
            if gt(size, 2) {
                let ptr := mload(0x40)
                extcodecopy(account, ptr, 0, 3)
                prefix := shr(232, mload(ptr))
            }
        }
        require(size > 0, errorMessage);
        require(prefix != EIP7702_DELEGATION_PREFIX, "Delegated EOA not allowed");
    }
}
