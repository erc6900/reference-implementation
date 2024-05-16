// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {BaseAccount} from "@eth-infinitism/account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {FunctionReferenceLib} from "../helpers/FunctionReferenceLib.sol";
import {_coalescePreValidation, _coalesceValidation} from "../helpers/ValidationDataHelpers.sol";
import {IPlugin, IValidation, IValidationHook, IExecutionHook, PluginManifest} from "../interfaces/IPlugin.sol";
import {IPluginExecutor} from "../interfaces/IPluginExecutor.sol";
import {FunctionReference, IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor, Call} from "../interfaces/IStandardExecutor.sol";
import {AccountExecutor} from "./AccountExecutor.sol";
import {AccountLoupe} from "./AccountLoupe.sol";
import {
    AccountStorage,
    getAccountStorage,
    getPermittedCallKey,
    SelectorData,
    toFunctionReference,
    toExecutionHook
} from "./AccountStorage.sol";
import {AccountStorageInitializable} from "./AccountStorageInitializable.sol";
import {PluginManagerInternals} from "./PluginManagerInternals.sol";

contract UpgradeableModularAccount is
    AccountExecutor,
    AccountLoupe,
    AccountStorageInitializable,
    BaseAccount,
    IERC165,
    IPluginExecutor,
    IStandardExecutor,
    PluginManagerInternals,
    UUPSUpgradeable
{
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using FunctionReferenceLib for FunctionReference;

    struct PostExecToRun {
        bytes preExecHookReturnData;
        FunctionReference postExecHook;
    }

    IEntryPoint private immutable _ENTRY_POINT;

    // As per the EIP-165 spec, no interface should ever match 0xffffffff
    bytes4 internal constant _INTERFACE_ID_INVALID = 0xffffffff;
    bytes4 internal constant _IERC165_INTERFACE_ID = 0x01ffc9a7;

    event ModularAccountInitialized(IEntryPoint indexed entryPoint);

    error AlwaysDenyRule();
    error AuthorizeUpgradeReverted(bytes revertReason);
    error ExecFromPluginNotPermitted(address plugin, bytes4 selector);
    error ExecFromPluginExternalNotPermitted(address plugin, address target, uint256 value, bytes data);
    error NativeTokenSpendingNotPermitted(address plugin);
    error PostExecHookReverted(address plugin, uint8 functionId, bytes revertReason);
    error PreExecHookReverted(address plugin, uint8 functionId, bytes revertReason);
    error PreRuntimeValidationHookFailed(address plugin, uint8 functionId, bytes revertReason);
    error RuntimeValidationFunctionMissing(bytes4 selector);
    error RuntimeValidationFunctionReverted(address plugin, uint8 functionId, bytes revertReason);
    error UnexpectedAggregator(address plugin, uint8 functionId, address aggregator);
    error UnrecognizedFunction(bytes4 selector);
    error UserOpValidationFunctionMissing(bytes4 selector);

    // Wraps execution of a native function with runtime validation and hooks
    // Used for upgradeTo, upgradeToAndCall, execute, executeBatch, installPlugin, uninstallPlugin
    modifier wrapNativeFunction() {
        _doRuntimeValidationIfNotFromEP();

        PostExecToRun[] memory postExecHooks = _doPreExecHooks(msg.sig, msg.data);

        _;

        _doCachedPostExecHooks(postExecHooks);
    }

    constructor(IEntryPoint anEntryPoint) {
        _ENTRY_POINT = anEntryPoint;
        _disableInitializers();
    }

    // EXTERNAL FUNCTIONS

    /// @notice Initializes the account with a set of plugins
    /// @dev No dependencies may be provided with this installation.
    /// @param plugins The plugins to install
    /// @param manifestHashes The manifest hashes of the plugins to install
    /// @param pluginInstallDatas The plugin install datas of the plugins to install
    function initialize(
        address[] memory plugins,
        bytes32[] memory manifestHashes,
        bytes[] memory pluginInstallDatas
    ) external initializer {
        uint256 length = plugins.length;

        if (length != manifestHashes.length || length != pluginInstallDatas.length) {
            revert ArrayLengthMismatch();
        }

        FunctionReference[] memory emptyDependencies = new FunctionReference[](0);

        for (uint256 i = 0; i < length; ++i) {
            _installPlugin(plugins[i], manifestHashes[i], pluginInstallDatas[i], emptyDependencies);
        }

        emit ModularAccountInitialized(_ENTRY_POINT);
    }

    receive() external payable {}

    /// @notice Fallback function
    /// @dev We route calls to execution functions based on incoming msg.sig
    /// @dev If there's no plugin associated with this function selector, revert
    fallback(bytes calldata) external payable returns (bytes memory) {
        address execPlugin = getAccountStorage().selectorData[msg.sig].plugin;
        if (execPlugin == address(0)) {
            revert UnrecognizedFunction(msg.sig);
        }

        _doRuntimeValidationIfNotFromEP();

        PostExecToRun[] memory postExecHooks;
        // Cache post-exec hooks in memory
        postExecHooks = _doPreExecHooks(msg.sig, msg.data);

        // execute the function, bubbling up any reverts
        (bool execSuccess, bytes memory execReturnData) = execPlugin.call(msg.data);

        if (!execSuccess) {
            // Bubble up revert reasons from plugins
            assembly ("memory-safe") {
                revert(add(execReturnData, 32), mload(execReturnData))
            }
        }

        _doCachedPostExecHooks(postExecHooks);

        return execReturnData;
    }

    /// @inheritdoc IStandardExecutor
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        override
        wrapNativeFunction
        returns (bytes memory result)
    {
        result = _exec(target, value, data);
    }

    /// @inheritdoc IStandardExecutor
    function executeBatch(Call[] calldata calls)
        external
        payable
        override
        wrapNativeFunction
        returns (bytes[] memory results)
    {
        uint256 callsLength = calls.length;
        results = new bytes[](callsLength);

        for (uint256 i = 0; i < callsLength; ++i) {
            results[i] = _exec(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /// @inheritdoc IPluginExecutor
    function executeFromPlugin(bytes calldata data) external payable override returns (bytes memory) {
        bytes4 selector = bytes4(data[:4]);
        address callingPlugin = msg.sender;

        bytes24 execFromPluginKey = getPermittedCallKey(callingPlugin, selector);

        AccountStorage storage _storage = getAccountStorage();

        if (!_storage.callPermitted[execFromPluginKey]) {
            revert ExecFromPluginNotPermitted(callingPlugin, selector);
        }

        address execFunctionPlugin = _storage.selectorData[selector].plugin;

        if (execFunctionPlugin == address(0)) {
            revert UnrecognizedFunction(selector);
        }

        PostExecToRun[] memory postExecHooks = _doPreExecHooks(selector, data);

        (bool success, bytes memory returnData) = execFunctionPlugin.call(data);

        if (!success) {
            assembly ("memory-safe") {
                revert(add(returnData, 32), mload(returnData))
            }
        }

        _doCachedPostExecHooks(postExecHooks);

        return returnData;
    }

    /// @inheritdoc IPluginExecutor
    function executeFromPluginExternal(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        bytes4 selector = bytes4(data);
        AccountStorage storage _storage = getAccountStorage();

        // Make sure plugin is allowed to spend native token.
        if (value > 0 && value > msg.value && !_storage.pluginData[msg.sender].canSpendNativeToken) {
            revert NativeTokenSpendingNotPermitted(msg.sender);
        }

        // Check the caller plugin's permission to make this call

        // Check the target contract permission.
        // This first checks that the intended target is permitted at all. If it is, then it checks if any selector
        // is permitted. If any selector is permitted, then it skips the selector-level permission check.
        // If only a subset of selectors are permitted, then it also checks the selector-level permission.
        // By checking in the order of [address specified with any selector allowed], [any address allowed],
        // [address specified and selector specified], along with the extra bool `permittedCall`, we can
        // reduce the number of `sload`s in the worst-case from 3 down to 2.
        bool targetContractPermittedCall = _storage.permittedExternalCalls[IPlugin(msg.sender)][target]
            .addressPermitted
            && (
                _storage.permittedExternalCalls[IPlugin(msg.sender)][target].anySelectorPermitted
                    || _storage.permittedExternalCalls[IPlugin(msg.sender)][target].permittedSelectors[selector]
            );

        // If the target contract is not permitted, check if the caller plugin is permitted to make any external
        // calls.
        if (!(targetContractPermittedCall || _storage.pluginData[msg.sender].anyExternalExecPermitted)) {
            revert ExecFromPluginExternalNotPermitted(msg.sender, target, value, data);
        }

        // Run any pre exec hooks for this selector
        PostExecToRun[] memory postExecHooks =
            _doPreExecHooks(IPluginExecutor.executeFromPluginExternal.selector, msg.data);

        // Perform the external call
        bytes memory returnData = _exec(target, value, data);

        // Run any post exec hooks for this selector
        _doCachedPostExecHooks(postExecHooks);

        return returnData;
    }

    /// @inheritdoc IPluginManager
    function installPlugin(
        address plugin,
        bytes32 manifestHash,
        bytes calldata pluginInstallData,
        FunctionReference[] calldata dependencies
    ) external override wrapNativeFunction {
        _installPlugin(plugin, manifestHash, pluginInstallData, dependencies);
    }

    /// @inheritdoc IPluginManager
    function uninstallPlugin(address plugin, bytes calldata config, bytes calldata pluginUninstallData)
        external
        override
        wrapNativeFunction
    {
        PluginManifest memory manifest;

        if (config.length > 0) {
            manifest = abi.decode(config, (PluginManifest));
        } else {
            manifest = IPlugin(plugin).pluginManifest();
        }

        _uninstallPlugin(plugin, manifest, pluginUninstallData);
    }

    /// @notice ERC165 introspection
    /// @dev returns true for `IERC165.interfaceId` and false for `0xFFFFFFFF`
    /// @param interfaceId interface id to check against
    /// @return bool support for specific interface
    function supportsInterface(bytes4 interfaceId) external view override returns (bool) {
        if (interfaceId == _INTERFACE_ID_INVALID) {
            return false;
        }
        if (interfaceId == _IERC165_INTERFACE_ID) {
            return true;
        }

        return getAccountStorage().supportedIfaces[interfaceId] > 0;
    }

    /// @inheritdoc UUPSUpgradeable
    function upgradeToAndCall(address newImplementation, bytes memory data)
        public
        payable
        override
        onlyProxy
        wrapNativeFunction
    {
        super.upgradeToAndCall(newImplementation, data);
    }

    /// @notice Gets the entry point for this account
    /// @return entryPoint The entry point for this account
    function entryPoint() public view override returns (IEntryPoint) {
        return _ENTRY_POINT;
    }

    // INTERNAL FUNCTIONS

    // Parent function validateUserOp enforces that this call can only be made by the EntryPoint
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        if (userOp.callData.length < 4) {
            revert UnrecognizedFunction(bytes4(userOp.callData));
        }
        bytes4 selector = bytes4(userOp.callData);

        AccountStorage storage _storage = getAccountStorage();

        if (_storage.selectorData[selector].denyExecutionCount > 0) {
            revert AlwaysDenyRule();
        }

        FunctionReference userOpValidationFunction = getAccountStorage().selectorData[selector].validation;

        validationData = _doUserOpValidation(selector, userOpValidationFunction, userOp, userOpHash);
    }

    // To support gas estimation, we don't fail early when the failure is caused by a signature failure
    function _doUserOpValidation(
        bytes4 selector,
        FunctionReference userOpValidationFunction,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal returns (uint256 validationData) {
        if (userOpValidationFunction.isEmptyOrMagicValue()) {
            // If the validation function is empty, then the call cannot proceed.
            // Alternatively, the validation function may be set to the RUNTIME_VALIDATION_ALWAYS_ALLOW magic
            // value, in which case we also revert.
            revert UserOpValidationFunctionMissing(selector);
        }

        uint256 currentValidationData;

        // Do preUserOpValidation hooks
        EnumerableSet.Bytes32Set storage preUserOpValidationHooks =
            getAccountStorage().selectorData[selector].preValidationHooks;

        uint256 preUserOpValidationHooksLength = preUserOpValidationHooks.length();
        for (uint256 i = 0; i < preUserOpValidationHooksLength; ++i) {
            bytes32 key = preUserOpValidationHooks.at(i);
            FunctionReference preUserOpValidationHook = toFunctionReference(key);

            (address plugin, uint8 functionId) = preUserOpValidationHook.unpack();
            currentValidationData = IValidationHook(plugin).preUserOpValidationHook(functionId, userOp, userOpHash);

            if (uint160(currentValidationData) > 1) {
                // If the aggregator is not 0 or 1, it is an unexpected value
                revert UnexpectedAggregator(plugin, functionId, address(uint160(currentValidationData)));
            }
            validationData = _coalescePreValidation(validationData, currentValidationData);
        }

        // Run the user op validationFunction
        {
            (address plugin, uint8 functionId) = userOpValidationFunction.unpack();
            currentValidationData = IValidation(plugin).userOpValidationFunction(functionId, userOp, userOpHash);

            if (preUserOpValidationHooksLength != 0) {
                // If we have other validation data we need to coalesce with
                validationData = _coalesceValidation(validationData, currentValidationData);
            } else {
                validationData = currentValidationData;
            }
        }
    }

    function _doRuntimeValidationIfNotFromEP() internal {
        AccountStorage storage _storage = getAccountStorage();

        if (_storage.selectorData[msg.sig].denyExecutionCount > 0) {
            revert AlwaysDenyRule();
        }

        if (msg.sender == address(_ENTRY_POINT)) return;

        FunctionReference runtimeValidationFunction = _storage.selectorData[msg.sig].validation;
        // run all preRuntimeValidation hooks
        EnumerableSet.Bytes32Set storage preRuntimeValidationHooks =
            getAccountStorage().selectorData[msg.sig].preValidationHooks;

        uint256 preRuntimeValidationHooksLength = preRuntimeValidationHooks.length();
        for (uint256 i = 0; i < preRuntimeValidationHooksLength; ++i) {
            bytes32 key = preRuntimeValidationHooks.at(i);
            FunctionReference preRuntimeValidationHook = toFunctionReference(key);

            (address plugin, uint8 functionId) = preRuntimeValidationHook.unpack();
            // solhint-disable-next-line no-empty-blocks
            try IValidationHook(plugin).preRuntimeValidationHook(functionId, msg.sender, msg.value, msg.data) {}
            catch (bytes memory revertReason) {
                revert PreRuntimeValidationHookFailed(plugin, functionId, revertReason);
            }
        }

        // Identifier scope limiting
        {
            if (!runtimeValidationFunction.isEmptyOrMagicValue()) {
                (address plugin, uint8 functionId) = runtimeValidationFunction.unpack();
                // solhint-disable-next-line no-empty-blocks
                try IValidation(plugin).runtimeValidationFunction(functionId, msg.sender, msg.value, msg.data) {}
                catch (bytes memory revertReason) {
                    revert RuntimeValidationFunctionReverted(plugin, functionId, revertReason);
                }
            } else {
                if (runtimeValidationFunction.isEmpty()) {
                    revert RuntimeValidationFunctionMissing(msg.sig);
                }
                // If _RUNTIME_VALIDATION_ALWAYS_ALLOW, just let the function finish.
            }
        }
    }

    function _doPreExecHooks(bytes4 selector, bytes calldata data)
        internal
        returns (PostExecToRun[] memory postHooksToRun)
    {
        SelectorData storage selectorData = getAccountStorage().selectorData[selector];

        uint256 hooksLength = selectorData.executionHooks.length();

        // Overallocate on length - not all of this may get filled up. We set the correct length later.
        postHooksToRun = new PostExecToRun[](hooksLength);

        // Copy all post hooks to the array. This happens before any pre hooks are run, so we can
        // be sure that the set of hooks to run will not be affected by state changes mid-execution.
        for (uint256 i = 0; i < hooksLength; ++i) {
            bytes32 key = selectorData.executionHooks.at(i);
            (FunctionReference hookFunction,, bool isPostHook) = toExecutionHook(key);
            if (isPostHook) {
                postHooksToRun[i].postExecHook = hookFunction;
            }
        }

        // Run the pre hooks and copy their return data to the post hooks array, if an associated post-exec hook
        // exists.
        for (uint256 i = 0; i < hooksLength; ++i) {
            bytes32 key = selectorData.executionHooks.at(i);
            (FunctionReference hookFunction, bool isPreHook, bool isPostHook) = toExecutionHook(key);

            if (isPreHook) {
                bytes memory preExecHookReturnData = _runPreExecHook(hookFunction, data);

                // If there is an associated post-exec hook, save the return data.
                if (isPostHook) {
                    postHooksToRun[i].preExecHookReturnData = preExecHookReturnData;
                }
            }
        }
    }

    function _runPreExecHook(FunctionReference preExecHook, bytes calldata data)
        internal
        returns (bytes memory preExecHookReturnData)
    {
        (address plugin, uint8 functionId) = preExecHook.unpack();
        try IExecutionHook(plugin).preExecutionHook(functionId, msg.sender, msg.value, data) returns (
            bytes memory returnData
        ) {
            preExecHookReturnData = returnData;
        } catch (bytes memory revertReason) {
            revert PreExecHookReverted(plugin, functionId, revertReason);
        }
    }

    /// @dev Associated post hooks are run in reverse order of their pre hooks.
    function _doCachedPostExecHooks(PostExecToRun[] memory postHooksToRun) internal {
        uint256 postHooksToRunLength = postHooksToRun.length;
        for (uint256 i = postHooksToRunLength; i > 0;) {
            // Decrement here, instead of in the loop body, to handle the case where length is 0.
            --i;

            PostExecToRun memory postHookToRun = postHooksToRun[i];

            if (postHookToRun.postExecHook.isEmpty()) {
                // This is an empty post hook, from a pre-only hook, so we skip it.
                continue;
            }

            (address plugin, uint8 functionId) = postHookToRun.postExecHook.unpack();
            // solhint-disable-next-line no-empty-blocks
            try IExecutionHook(plugin).postExecutionHook(functionId, postHookToRun.preExecHookReturnData) {}
            catch (bytes memory revertReason) {
                revert PostExecHookReverted(plugin, functionId, revertReason);
            }
        }
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override {}
}
