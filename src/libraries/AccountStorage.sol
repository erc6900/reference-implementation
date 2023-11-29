// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {IPlugin} from "../interfaces/IPlugin.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {FunctionReference} from "../libraries/FunctionReferenceLib.sol";

// bytes = keccak256("ERC6900.UpgradeableModularAccount.Storage")
bytes32 constant _ACCOUNT_STORAGE_SLOT = 0x9f09680beaa4e5c9f38841db2460c401499164f368baef687948c315d9073e40;

struct PluginData {
    bool anyExternalExecPermitted;
    // boolean to indicate if the plugin can spend native tokens, if any of the execution function can spend
    // native tokens, a plugin is considered to be able to spend native tokens of the accounts
    bool canSpendNativeToken;
    bytes32 manifestHash;
    FunctionReference[] dependencies;
    // Tracks the number of times this plugin has been used as a dependency function
    uint256 dependentCount;
    StoredInjectedHook[] injectedHooks;
}

// A version of IPluginManager. InjectedHook used to track injected hooks in storage.
// Omits the hookApplyData field, which is not needed for storage, and flattens the struct.
struct StoredInjectedHook {
    // The plugin that provides the hook
    address providingPlugin;
    // Either a plugin-defined execution function, or the native function executeFromPluginExternal
    bytes4 selector;
    // Contents of the InjectedHooksInfo struct
    uint8 preExecHookFunctionId;
    bool isPostHookUsed;
    uint8 postExecHookFunctionId;
}

// Represents data associated with a plugin's permission to use `executeFromPlugin`
// to interact with another plugin installed on the account.
struct PermittedCallData {
    bool callPermitted;
    EnumerableSet.Bytes32Set prePermittedCallHooks;
    // bytes21 key = pre exec hook function reference
    mapping(FunctionReference => FunctionReference) associatedPostPermittedCallHooks;
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
    FunctionReference userOpValidation;
    FunctionReference runtimeValidation;
    // The pre validation hooks for this function selector.
    EnumerableSet.Bytes32Set preUserOpValidationHooks;
    EnumerableSet.Bytes32Set preRuntimeValidationHooks;
    // The execution hooks for this function selector.
    EnumerableSet.Bytes32Set preExecHooks;
    // bytes21 key = pre exec hook function reference
    mapping(FunctionReference => FunctionReference) associatedPostExecHooks;
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
    mapping(bytes24 => PermittedCallData) permittedCalls;
    // key = address(calling plugin) || target address
    mapping(IPlugin => mapping(address => PermittedExternalCallData)) permittedExternalCalls;
    // For ERC165 introspection
    mapping(bytes4 => uint256) supportedIfaces;
}

function getAccountStorage() pure returns (AccountStorage storage _storage) {
    assembly {
        _storage.slot := _ACCOUNT_STORAGE_SLOT
    }
}

function getPermittedCallKey(address addr, bytes4 selector) pure returns (bytes24) {
    return bytes24(bytes20(addr)) | (bytes24(selector) >> 160);
}

// Helper function to get all elements of a set into memory.
using EnumerableSet for EnumerableSet.Bytes32Set;

function toFunctionReferenceArray(EnumerableSet.Bytes32Set storage set)
    view
    returns (FunctionReference[] memory)
{
    FunctionReference[] memory result = new FunctionReference[](set.length());
    for (uint256 i = 0; i < set.length(); i++) {
        result[i] = FunctionReference.wrap(bytes21(set.at(i)));
    }
    return result;
}
