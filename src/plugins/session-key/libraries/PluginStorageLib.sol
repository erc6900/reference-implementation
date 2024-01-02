/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

/// @title Plugin Storage Library for ERC-4337 Address-associated Storage
/// @author Adam Egyed
/// @notice This library treats storage available to associated addresses as one big global mapping of (bytes32 =>
/// bytes).
///
/// THIS IS HIGHLY EXPERIMENTAL AND NOT READY FOR PRODUCTION USE.
///
/// It is up to the implementer to define the serialization and deserialization of structs,
/// since Solidity itself does not provide ways to encode structs into their storage representations easily.
/// While you can use `abi.encode` and `abi.decode`, this is not recommended because it will result in
/// extraneous data being stored in storage, which will unreasonably increase gas costs.
library PluginStorageLib {
    /// @notice Writes a bytes array to storage using a key and an associated address.
    /// @notice This function will write the length of the bytes array to storage.
    /// @param addr The address associated with the storage
    /// @param key The key used to identify the bytes array
    /// @param val The bytes array to write to storage
    function writeBytesChecked(address addr, bytes32 key, bytes memory val) internal {
        assembly ("memory-safe") {
            // compute total length, including the extra word for the length field itself
            let len := add(mload(val), 32)

            // reserve 3 words in memory (96 bytes) for hash inputs
            let hashInput := mload(0x40)
            mstore(0x40, add(hashInput, 96))
            // Hash inputs will always be:
            // 1. caller address
            // 2. key
            // 3. batch index
            // So we can set the caller address and key here to reuse,
            // but we'll need to set the batch index for each batch
            mstore(hashInput, addr)
            mstore(add(hashInput, 32), key)

            // Compute the number of batches we need to write, rounded up
            let batches := div(add(len, 4095), 4096)

            // Copy the bytes array into storage
            for { let batchIndex := 0 } lt(batchIndex, batches) { batchIndex := add(batchIndex, 1) } {
                // Hash the batch index with the caller address and key to get a new 128 associated slots
                mstore(add(hashInput, 64), batchIndex)
                let batchStart := keccak256(hashInput, 96)

                // Write the batch to storage, 128 slots at a time
                let end := false
                for { let slotIndex := 0 } and(lt(slotIndex, 128), not(end)) { slotIndex := add(slotIndex, 1) } {
                    // Compute the current slot in storage, and the current offset in memory
                    let slot := add(batchStart, slotIndex)
                    let offset := add(mul(slotIndex, 32), mul(batchIndex, 4096))

                    // Is this the last word we need to write? Stop one word before offset = len
                    end := iszero(sub(len, add(offset, 32)))

                    // Copy the word from the bytes array into storage
                    let dataStart := add(val, offset)
                    let data := mload(dataStart)
                    sstore(slot, data)
                }
            }
        }
    }

    /// @notice Writes a bytes array to storage using a key and an associated address.
    /// @notice This function will write NOT the length of the bytes array to storage,
    ///         but will use the length of the array to determine how much to write.
    ///         It is the responsibility of the caller to preserve length information.
    /// @param addr The address associated with the storage
    /// @param key The key used to identify the bytes array
    /// @param val The bytes array to write to storage
    function writeBytesUnchecked(address addr, bytes32 key, bytes memory val) internal {
        assembly ("memory-safe") {
            // compute total length, excluding the length field itself
            let len := mload(val)

            // reserve 3 words in memory (96 bytes) for hash inputs
            let hashInput := mload(0x40)
            mstore(0x40, add(hashInput, 96))
            // Hash inputs will always be:
            // 1. caller address
            // 2. key
            // 3. batch index
            // So we can set the caller address and key here to reuse,
            // but we'll need to set the batch index for each batch
            mstore(hashInput, addr)
            mstore(add(hashInput, 32), key)

            // Compute the number of batches we need to write, rounded up
            let batches := div(add(len, 4095), 4096)

            // Copy the bytes array into storage
            for { let batchIndex := 0 } lt(batchIndex, batches) { batchIndex := add(batchIndex, 1) } {
                // Hash the batch index with the caller address and key to get a new 128 associated slots
                mstore(add(hashInput, 64), batchIndex)
                let batchStart := keccak256(hashInput, 96)

                // Write the batch to storage, 128 slots at a time
                let end := false
                for { let slotIndex := 0 } and(lt(slotIndex, 128), not(end)) { slotIndex := add(slotIndex, 1) } {
                    // Compute the current slot in storage, and the current offset in memory
                    let slot := add(batchStart, slotIndex)
                    let offset := add(mul(slotIndex, 32), mul(batchIndex, 4096))

                    // Is this the last word we need to write? Stop one word before offset = len
                    end := iszero(sub(len, add(offset, 32)))

                    // Copy the word from the bytes array into storage
                    let dataStart := add(add(val, 32), offset)
                    let data := mload(dataStart)
                    sstore(slot, data)
                }
            }
        }
    }

    /// @notice Reads a bytes array from storage using a key and an associated address
    /// @param addr The address associated with the storage
    /// @param key The key used to identify the bytes array
    /// @return ret The bytes array stored in storage
    function readBytesChecked(address addr, bytes32 key) internal view returns (bytes memory ret) {
        assembly ("memory-safe") {
            // reserve 3 words in memory (96 bytes) for hash inputs
            let hashInput := mload(0x40)
            mstore(0x40, add(hashInput, 96))

            // Hash inputs will always be:
            // 1. caller address
            // 2. key
            // 3. batch index
            // So we can set the caller address and key here to reuse,
            // but we'll need to set the batch index for each batch
            mstore(hashInput, addr)
            mstore(add(hashInput, 32), key)

            // Get the length of the stored bytes array first, then copy everything else over
            // Set the batch index to 0 to get the length only
            mstore(add(hashInput, 64), 0)
            let hash := keccak256(hashInput, 96)
            // Include the extra word for the length field itself
            let len := add(sload(hash), 32)

            // Allocate memory for the returned bytes array
            ret := mload(0x40)
            mstore(0x40, add(ret, len))

            // Copy storage into the bytes array
            let batches := div(add(len, 4095), 4096) // num batches rounded up
            for { let batchIndex := 0 } lt(batchIndex, batches) { batchIndex := add(batchIndex, 1) } {
                // Hash the batch index with the caller address and key to get a new 128 associated slots
                mstore(add(hashInput, 64), batchIndex)
                let batchStart := keccak256(hashInput, 96)

                // Read the batch from storage, 128 slots at a time
                let end := false
                for { let slotIndex := 0 } and(lt(slotIndex, 128), not(end)) { slotIndex := add(slotIndex, 1) } {
                    // Compute the current slot in storage, and the current offset in memory
                    let slot := add(batchStart, slotIndex)
                    let offset := add(mul(slotIndex, 32), mul(batchIndex, 4096))

                    // Is this the last word we need to read? Stop one word before offset = len
                    end := iszero(sub(len, add(offset, 32)))

                    // Copy the data from storage to memory
                    let dataLoc := add(ret, offset)
                    mstore(dataLoc, sload(slot))
                }
            }
        }
    }

    /// @notice Reads a bytes array from storage using a key and an associated address, of a specified length
    /// @param addr The address associated with the storage
    /// @param key The key used to identify the bytes array
    /// @param len The length of the bytes array to read
    /// @return ret The bytes array stored in storage
    function readBytesUnchecked(address addr, bytes32 key, uint256 len) internal view returns (bytes memory ret) {
        assembly ("memory-safe") {
            // reserve 3 words in memory (96 bytes) for hash inputs
            let hashInput := mload(0x40)
            mstore(0x40, add(hashInput, 96))

            // Hash inputs will always be:
            // 1. caller address
            // 2. key
            // 3. batch index
            // So we can set the caller address and key here to reuse,
            // but we'll need to set the batch index for each batch
            mstore(hashInput, addr)
            mstore(add(hashInput, 32), key)

            // Get the length of the stored bytes array first, then copy everything else over
            // Set the batch index to 0 to get the length only
            mstore(add(hashInput, 64), 0)
            let hash := keccak256(hashInput, 96)

            // Allocate memory for the returned bytes array
            ret := mload(0x40)
            // Include the extra word for the length field itself.
            // The length field is not in storage, but must be set in the returned memory array.
            mstore(0x40, add(ret, add(len, 32)))

            // Store the length of the bytes array in memory
            mstore(ret, len)

            // Copy storage into the bytes array
            let batches := div(add(len, 4095), 4096) // num batches rounded up
            for { let batchIndex := 0 } lt(batchIndex, batches) { batchIndex := add(batchIndex, 1) } {
                // Hash the batch index with the caller address and key to get a new 128 associated slots
                mstore(add(hashInput, 64), batchIndex)
                let batchStart := keccak256(hashInput, 96)

                // Read the batch from storage, 128 slots at a time
                let end := false
                for { let slotIndex := 0 } and(lt(slotIndex, 128), not(end)) { slotIndex := add(slotIndex, 1) } {
                    // Compute the current slot in storage, and the current offset in memory
                    let slot := add(batchStart, slotIndex)
                    let offset := add(mul(slotIndex, 32), mul(batchIndex, 4096))

                    // Is this the last word we need to read? Stop one word before offset = len
                    end := iszero(sub(len, add(offset, 32)))

                    // Copy the data from storage to memory
                    // data location is the offset plus the length word
                    let dataLoc := add(add(ret, 32), offset)
                    mstore(dataLoc, sload(slot))
                }
            }
        }
    }

    /// @notice Efficiently retrieve a full word from a bytes array in memory.
    /// The returned value can be casted to any primitive type as needed.
    /// @param val The bytes array to read from
    /// @param index The index of the word to read
    /// @return ret The word at the given index
    function wordAt(bytes memory val, uint256 index) internal pure returns (bytes32 ret) {
        assembly ("memory-safe") {
            ret := mload(add(add(val, 32), mul(index, 32)))
        }
    }

    /// @notice Efficiently retrieve a single byte from a bytes32 word.
    /// The returned value can be casted to any primitive type as needed.
    /// @param val The word to read from
    /// @param index The index of the byte to read
    /// @return ret The byte at the given index
    function byteAt(bytes32 val, uint8 index) internal pure returns (bytes1 ret) {
        assembly ("memory-safe") {
            ret := byte(index, val)
        }
    }
}
