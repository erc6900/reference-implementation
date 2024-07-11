// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

import {ExecutionHook} from "../interfaces/IAccountLoupe.sol";
import {FunctionReference} from "../interfaces/IPluginManager.sol";

// bytes = keccak256("ERC6900.UpgradeableModularAccount.Storage")
bytes32 constant _ACCOUNT_STORAGE_SLOT = 0x9f09680beaa4e5c9f38841db2460c401499164f368baef687948c315d9073e40;

// Represents data associated with a specifc function selector.
struct SelectorData {
    // The plugin that implements this execution function.
    // If this is a native function, the address must remain address(0).
    address plugin;
    // Whether or not the function needs runtime validation, or can be called by anyone.
    // Note that even if this is set to true, user op validation will still be required, otherwise anyone could
    // drain the account of native tokens by wasting gas.
    bool isPublic;
    // Whether or not a global validation function may be used to validate this function.
    bool allowGlobalValidation;
    // The execution hooks for this function selector.
    EnumerableSet.Bytes32Set executionHooks;
}

struct ValidationData {
    // Whether or not this validation can be used as a global validation function.
    bool isGlobal;
    // Whether or not this validation is a signature validator.
    bool isSignatureValidation;
    // The pre validation hooks for this function selector.
    FunctionReference[] preValidationHooks;
    // Permission hooks for this validation function.
    EnumerableSet.Bytes32Set permissionHooks;
    // The set of selectors that may be validated by this validation function.
    EnumerableSet.Bytes32Set selectors;
}

struct AccountStorage {
    // AccountStorageInitializable variables
    uint8 initialized;
    bool initializing;
    // Plugin metadata storage
    EnumerableMap.AddressToUintMap pluginManifestHashes;
    // Execution functions and their associated functions
    mapping(bytes4 => SelectorData) selectorData;
    mapping(FunctionReference validationFunction => ValidationData) validationData;
    // For ERC165 introspection
    mapping(bytes4 => uint256) supportedIfaces;
}

function getAccountStorage() pure returns (AccountStorage storage _storage) {
    assembly ("memory-safe") {
        _storage.slot := _ACCOUNT_STORAGE_SLOT
    }
}

using EnumerableSet for EnumerableSet.Bytes32Set;

function toSetValue(FunctionReference functionReference) pure returns (bytes32) {
    return bytes32(FunctionReference.unwrap(functionReference));
}

function toFunctionReference(bytes32 setValue) pure returns (FunctionReference) {
    return FunctionReference.wrap(bytes24(setValue));
}

// ExecutionHook layout:
// 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF______________________ Hook Function Reference
// 0x__________________________________________AA____________________ is pre hook
// 0x____________________________________________BB__________________ is post hook

function toSetValue(ExecutionHook memory executionHook) pure returns (bytes32) {
    return bytes32(FunctionReference.unwrap(executionHook.hookFunction))
        | bytes32(executionHook.isPreHook ? uint256(1) << 56 : 0)
        | bytes32(executionHook.isPostHook ? uint256(1) << 48 : 0);
}

function toExecutionHook(bytes32 setValue)
    pure
    returns (FunctionReference hookFunction, bool isPreHook, bool isPostHook)
{
    hookFunction = FunctionReference.wrap(bytes24(setValue));
    isPreHook = (uint256(setValue) >> 56) & 0xFF == 1;
    isPostHook = (uint256(setValue) >> 48) & 0xFF == 1;
}

function toSetValue(bytes4 selector) pure returns (bytes32) {
    return bytes32(selector);
}

function toSelector(bytes32 setValue) pure returns (bytes4) {
    return bytes4(setValue);
}

/// @dev Helper function to get all elements of a set into memory.
function toFunctionReferenceArray(EnumerableSet.Bytes32Set storage set)
    view
    returns (FunctionReference[] memory)
{
    uint256 length = set.length();
    FunctionReference[] memory result = new FunctionReference[](length);
    for (uint256 i = 0; i < length; ++i) {
        bytes32 key = set.at(i);
        result[i] = FunctionReference.wrap(bytes24(key));
    }
    return result;
}
