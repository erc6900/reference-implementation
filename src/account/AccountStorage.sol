// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IPlugin} from "../interfaces/IPlugin.sol";
import {FunctionReference} from "../interfaces/IPluginManager.sol";

// bytes = keccak256("ERC6900.UpgradeableModularAccount.Storage")
bytes32 constant _ACCOUNT_STORAGE_SLOT = 0x9f09680beaa4e5c9f38841db2460c401499164f368baef687948c315d9073e40;

struct PluginData {
    bool anyExternalExecPermitted;
    // boolean to indicate if the plugin can spend native tokens from the account.
    bool canSpendNativeToken;
    bytes32 manifestHash;
    FunctionReference[] dependencies;
    // Tracks the number of times this plugin has been used as a dependency function
    uint256 dependentCount;
}

// Represents data associated with a plugin's permission to use `executeFromPluginExternal`
// to interact with contracts and addresses external to the account and its plugins.
struct PermittedExternalCallData {
    // Is this address on the permitted addresses list? If it is, we either have a
    // list of allowed selectors, or the flag that allows any selector.
    bool addressPermitted;
    bool anySelectorPermitted;
    mapping(bytes4 => bool) permittedSelectors;
}

// Represents data associated with a specifc function selector.
struct SelectorData {
    // The plugin that implements this execution function.
    // If this is a native function, the address must remain address(0).
    address plugin;
    // How many times a `PRE_HOOK_ALWAYS_DENY` has been added for this function.
    // Since that is the only type of hook that may overlap, we can use this to track the number of times it has
    // been applied, and whether or not the deny should apply. The size `uint48` was chosen somewhat arbitrarily,
    // but it packs alongside `plugin` while still leaving some other space in the slot for future packing.
    uint48 denyExecutionCount;
    // User operation validation and runtime validation share a function reference.
    FunctionReference validation;
    // The pre validation hooks for this function selector.
    EnumerableSet.Bytes32Set preValidationHooks;
    // The execution hooks for this function selector.
    EnumerableSet.Bytes32Set preHooks;
    // bytes21 key = pre hook function reference
    mapping(FunctionReference => FunctionReference) associatedPostHooks;
    EnumerableSet.Bytes32Set postOnlyHooks;
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
    // bytes24 key = address(calling plugin) || bytes4(selector of execution function)
    mapping(bytes24 => bool) callPermitted;
    // key = address(calling plugin) || target address
    mapping(IPlugin => mapping(address => PermittedExternalCallData)) permittedExternalCalls;
    // For ERC165 introspection
    mapping(bytes4 => uint256) supportedIfaces;
}

function getAccountStorage() pure returns (AccountStorage storage _storage) {
    assembly ("memory-safe") {
        _storage.slot := _ACCOUNT_STORAGE_SLOT
    }
}

function getPermittedCallKey(address addr, bytes4 selector) pure returns (bytes24) {
    return bytes24(bytes20(addr)) | (bytes24(selector) >> 160);
}

using EnumerableSet for EnumerableSet.Bytes32Set;

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
