// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

function getEmptyCalldataSlice() pure returns (bytes calldata) {
    bytes calldata empty;

    assembly ("memory-safe") {
        empty.length := 0
    }

    return empty;
}
