// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";

library AppendedCalldataLib {
    function ExtractBytesArrayFromExecuteCall(bytes calldata executeCall, bytes memory innerCall)
        internal
        pure
        returns (bytes[] memory)
    {
        bytes[] calldata decodedSignatures;

        // Assembly procedure:
        //      1. Get the raw, "innerCalldata" length via mload-ing the pointer
        //      2. Calculate the padding that abi-encoding adds to the innerCall bytes parameter
        //          - Calculate the remainder (length mod 32)
        //          - If the remainder is nonzero, add 32 minus the remainder to the abiEncodedInnerCallLength.
        //      3. Calculate the offset in calldata of the signature array's length by adding together:
        //          - The executeCall parameter offset (0x04 (selector) + 0x20 (data offset := 0x20)
        //            + 0x20 (length calldata offset)) = 0x44 (accessed via executeCall.offset)
        //          - The execute call parameters (0x04 (selector) + 0x20 (target) + 0x20 (value)
        //            + 0x20 (inner call offset) + 0x20 (inner call length offset) + 0x20 (offset of abi encoded
        //            signature array)) = 0xa4
        //          - The abiEncodedInnerCallLength calculated in step 1
        //      4. Load and assign the signature array length at the offset calculated in step 3
        //      5. Assign the signature array offset (plus 0x20 for the length offset)
        assembly ("memory-safe") {
            // Need to check fullcalldata length
            let innerCallLength := mload(innerCall)

            let abiEncodedInnerCallLength := innerCallLength

            let remainder := mod(abiEncodedInnerCallLength, 0x20)

            // if (totalEncodedInnerCallSize % 32 != 0)
            if remainder { abiEncodedInnerCallLength := add(abiEncodedInnerCallLength, sub(0x20, remainder)) }

            let signatureLengthOffset := add(add(executeCall.offset, 0xa4), abiEncodedInnerCallLength)

            // Need to add 0x20 to account for length
            decodedSignatures.offset := add(0x20, signatureLengthOffset)
            decodedSignatures.length := calldataload(signatureLengthOffset)
        }

        // This approach has the benefit that the full call data can be encoded in solidity
        return decodedSignatures;
    }

    function buildExecuteCallWithSignatures(
        address target,
        uint256 value,
        bytes memory innerCall,
        bytes[] memory signatures
    ) internal pure returns (bytes memory) {
        bytes memory encodedExecuteCall = abi.encodeCall(IStandardExecutor.execute, (target, value, innerCall));
        return AppendBytesArrayToExecuteCall(encodedExecuteCall, signatures);
    }

    function AppendBytesArrayToExecuteCall(bytes memory executeCall, bytes[] memory signatures)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(executeCall, abi.encode(signatures));
    }
}

library AccountCallLib {
    function executeWithAppendedSignatures(
        IStandardExecutor account,
        address target,
        uint256 value,
        bytes memory innerCall,
        bytes[] memory signatures
    ) internal {
        bytes memory call =
            AppendedCalldataLib.buildExecuteCallWithSignatures(target, value, innerCall, signatures);
        //TODO Add a custom error
        (bool res, bytes memory returnData) = payable(address(account)).call(call);
    }
}
