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
        // The first 8 bytes hold the length of the segment, excluding the index.
        uint64 length = uint64(bytes8(source[:8]));

        // The offset of the remainder of the calldata.
        uint256 remainderOffset = 8 + length + 1;

        // The segment is the next `length` + 1 bytes, to account for the index.
        // By convention, the first byte of each segment is the index of the segment.
        segment = source[8:remainderOffset];

        // The remainder is the rest of the calldata.
        remainder = source[remainderOffset:];
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
