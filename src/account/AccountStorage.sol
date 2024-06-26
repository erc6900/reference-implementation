// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ExecutionHook} from "../interfaces/IAccountLoupe.sol";
import {FunctionReference} from "../interfaces/IPluginManager.sol";

// bytes = keccak256("ERC6900.UpgradeableModularAccount.Storage")
bytes32 constant _ACCOUNT_STORAGE_SLOT = 0x9f09680beaa4e5c9f38841db2460c401499164f368baef687948c315d9073e40;

struct PluginData {
    bytes32 manifestHash;
    FunctionReference[] dependencies;
    // Tracks the number of times this plugin has been used as a dependency function
    uint256 dependentCount;
}

// Represents data associated with a specifc function selector.
struct SelectorData {
    // The plugin that implements this execution function.
    // If this is a native function, the address must remain address(0).
    address plugin;
    // Whether or not the function needs runtime validation, or can be called by anyone.
    // Note that even if this is set to true, user op validation will still be required, otherwise anyone could
    // drain the account of native tokens by wasting gas.
    bool isPublic;
    // Whether or not a default validation function may be used to validate this function.
    bool allowDefaultValidation;
    // The execution hooks for this function selector.
    EnumerableSet.Bytes32Set executionHooks;
    // Which validation functions are associated with this function selector.
    EnumerableSet.Bytes32Set validations;
}

struct ValidationData {
    // Whether or not this validation can be used as a default validation function.
    bool isDefault;
    // Whether or not this validation is a signature validator.
    bool isSignatureValidation;
    // How many execution hooks require the UO context.
    uint8 requireUOHookCount;
    // The pre validation hooks for this function selector.
    EnumerableSet.Bytes32Set preValidationHooks;
    // Permission hooks for this validation function.
    EnumerableSet.Bytes32Set permissionHooks;
}

struct AccountStorage {
    // AccountStorageInitializable variables
    uint8 initialized;
    bool initializing;
    // Plugin metadata storage
    EnumerableSet.AddressSet plugins;
    mapping(address => PluginData) pluginData;
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
    return FunctionReference.wrap(bytes21(setValue));
}

// ExecutionHook layout:
// 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF______________________ Hook Function Reference
// 0x__________________________________________AA____________________ is pre hook
// 0x____________________________________________BB__________________ is post hook
// 0x______________________________________________CC________________ require UO context

function toSetValue(ExecutionHook memory executionHook) pure returns (bytes32) {
    return bytes32(FunctionReference.unwrap(executionHook.hookFunction))
        | bytes32(executionHook.isPreHook ? uint256(1) << 80 : 0)
        | bytes32(executionHook.isPostHook ? uint256(1) << 72 : 0)
        | bytes32(executionHook.requireUOContext ? uint256(1) << 64 : 0);
}

function toExecutionHook(bytes32 setValue)
    pure
    returns (FunctionReference hookFunction, bool isPreHook, bool isPostHook, bool requireUOContext)
{
    hookFunction = FunctionReference.wrap(bytes21(setValue));
    isPreHook = (uint256(setValue) >> 80) & 0xFF == 1;
    isPostHook = (uint256(setValue) >> 72) & 0xFF == 1;
    requireUOContext = (uint256(setValue) >> 64) & 0xFF == 1;
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
        result[i] = FunctionReference.wrap(bytes21(key));
    }
    return result;
}
