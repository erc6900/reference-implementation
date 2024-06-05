// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

library SparseCalldataSegmentLib {
    /// @notice Splits out a segment of calldata, sparsely-packed
    /// @param source The calldata to extract the segment from
    /// @return segment The extracted segment
    /// @return remainder The remaining calldata
    function getNextSegment(bytes calldata source)
        internal
        pure
        returns (bytes calldata segment, bytes calldata remainder)
    {
        // The first 8 bytes hold the length of the segment.
        uint64 length = uint64(bytes8(source[:8]));

        // The segment is the next `length` bytes.
        // By convention, the first byte of each segmet is the index of the segment, excluding the 1-byte index.
        segment = source[8:8 + length + 1];

        // The remainder is the rest of the calldata.
        remainder = source[8 + length:];
    }

    /// @notice Extracts the index from a segment
    /// @param segment The segment to extract the index from
    /// @return The index of the segment
    function getIndex(bytes calldata segment) internal pure returns (uint8) {
        return uint8(segment[0]);
    }

    /// @notice Extracts the body from a segment
    /// @param segment The segment to extract the body from
    /// @return The body of the segment
    function getBody(bytes calldata segment) internal pure returns (bytes calldata) {
        return segment[1:];
    }
}
