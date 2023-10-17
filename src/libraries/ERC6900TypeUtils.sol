// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

struct Execution {
    // The target contract for account to execute.
    address target;
    // The value for the execution.
    uint256 value;
    // The call data for the execution.
    bytes data;
}
