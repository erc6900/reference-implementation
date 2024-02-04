// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

struct Version {
    uint256 major;
    uint256 minor;
    uint256 patch;
}

function decodeVersion(string memory versionString) pure returns (Version memory) {
    uint256 major;
    uint256 minor;
    uint256 patch;
    uint256 lastIndex = 0;
    uint256 dotCount = 0;

    // Convert the versionString to bytes for manipulation
    bytes memory versionBytes = bytes(versionString);

    for (uint256 i = 0; i < versionBytes.length; i++) {
        if (versionBytes[i] == 0x2E) {
            if (dotCount == 0) {
                major = _parseUint256(versionBytes, lastIndex, i);
            } else if (dotCount == 1) {
                minor = _parseUint256(versionBytes, lastIndex, i);
            }
            lastIndex = i + 1;
            dotCount++;
        }
    }

    // Parse the patch version, which is after the last dot
    patch = _parseUint256(versionBytes, lastIndex, versionBytes.length);

    return Version(major, minor, patch);
}

function _parseUint256(bytes memory b, uint256 start, uint256 end) pure returns (uint256) {
    uint256 result = 0;
    for (uint256 i = start; i < end; i++) {
        // Ensure the character is a digit
        require(b[i] >= 0x30 && b[i] <= 0x39, "Non-digit characters present");
        result = result * 10 + (uint256(uint8(b[i])) - 0x30);
    }
    return result;
}
