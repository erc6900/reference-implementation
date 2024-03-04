// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {BaseAccount} from "@eth-infinitism/account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {FunctionReferenceLib} from "../helpers/FunctionReferenceLib.sol";
import {_coalescePreValidation, _coalesceValidation} from "../helpers/ValidationDataHelpers.sol";
import {IPlugin, PluginManifest} from "../interfaces/IPlugin.sol";
import {IPluginExecutor} from "../interfaces/IPluginExecutor.sol";
import {FunctionReference, IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor, Call} from "../interfaces/IStandardExecutor.sol";
import {AccountExecutor} from "./AccountExecutor.sol";
import {AccountLoupe} from "./AccountLoupe.sol";
import {AccountStorage, HookGroup, getAccountStorage, getPermittedCallKey} from "./AccountStorage.sol";
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
    using EnumerableMap for EnumerableMap.Bytes32ToUintMap;
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
    error InvalidConfiguration();
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

        for (uint256 i = 0; i < length;) {
            _installPlugin(plugins[i], manifestHashes[i], pluginInstallDatas[i], emptyDependencies);

            unchecked {
                ++i;
            }
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

        for (uint256 i = 0; i < callsLength;) {
            results[i] = _exec(calls[i].target, calls[i].value, calls[i].data);

            unchecked {
                ++i;
            }
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
    function upgradeTo(address newImplementation) public override onlyProxy wrapNativeFunction {
        _upgradeToAndCallUUPS(newImplementation, new bytes(0), false);
    }

    /// @inheritdoc UUPSUpgradeable
    function upgradeToAndCall(address newImplementation, bytes memory data)
        public
        payable
        override
        onlyProxy
        wrapNativeFunction
    {
        _upgradeToAndCallUUPS(newImplementation, data, true);
    }

    /// @notice Gets the entry point for this account
    /// @return entryPoint The entry point for this account
    function entryPoint() public view override returns (IEntryPoint) {
        return _ENTRY_POINT;
    }

    // INTERNAL FUNCTIONS

    // Parent function validateUserOp enforces that this call can only be made by the EntryPoint
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        if (userOp.callData.length < 4) {
            revert UnrecognizedFunction(bytes4(userOp.callData));
        }
        bytes4 selector = bytes4(userOp.callData);

        FunctionReference userOpValidationFunction = getAccountStorage().selectorData[selector].userOpValidation;

        validationData = _doUserOpValidation(selector, userOpValidationFunction, userOp, userOpHash);
    }

    // To support gas estimation, we don't fail early when the failure is caused by a signature failure
    function _doUserOpValidation(
        bytes4 selector,
        FunctionReference userOpValidationFunction,
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal returns (uint256 validationData) {
        if (userOpValidationFunction.isEmpty()) {
            revert UserOpValidationFunctionMissing(selector);
        }

        uint256 currentValidationData;

        // Do preUserOpValidation hooks
        EnumerableMap.Bytes32ToUintMap storage preUserOpValidationHooks =
            getAccountStorage().selectorData[selector].preUserOpValidationHooks;

        uint256 preUserOpValidationHooksLength = preUserOpValidationHooks.length();
        for (uint256 i = 0; i < preUserOpValidationHooksLength;) {
            (bytes32 key,) = preUserOpValidationHooks.at(i);
            FunctionReference preUserOpValidationHook = _toFunctionReference(key);

            if (!preUserOpValidationHook.isEmptyOrMagicValue()) {
                (address plugin, uint8 functionId) = preUserOpValidationHook.unpack();
                currentValidationData = IPlugin(plugin).preUserOpValidationHook(functionId, userOp, userOpHash);

                if (uint160(currentValidationData) > 1) {
                    // If the aggregator is not 0 or 1, it is an unexpected value
                    revert UnexpectedAggregator(plugin, functionId, address(uint160(currentValidationData)));
                }
                validationData = _coalescePreValidation(validationData, currentValidationData);
            } else {
                // Function reference cannot be 0 and _RUNTIME_VALIDATION_ALWAYS_ALLOW is not permitted here.
                revert InvalidConfiguration();
            }

            unchecked {
                ++i;
            }
        }

        // Run the user op validationFunction
        {
            if (!userOpValidationFunction.isEmptyOrMagicValue()) {
                (address plugin, uint8 functionId) = userOpValidationFunction.unpack();
                currentValidationData = IPlugin(plugin).userOpValidationFunction(functionId, userOp, userOpHash);

                if (preUserOpValidationHooksLength != 0) {
                    // If we have other validation data we need to coalesce with
                    validationData = _coalesceValidation(validationData, currentValidationData);
                } else {
                    validationData = currentValidationData;
                }
            } else {
                // _RUNTIME_VALIDATION_ALWAYS_ALLOW and _PRE_HOOK_ALWAYS_DENY is not permitted here.
                revert InvalidConfiguration();
            }
        }
    }

    function _doRuntimeValidationIfNotFromEP() internal {
        if (msg.sender == address(_ENTRY_POINT)) return;

        AccountStorage storage _storage = getAccountStorage();
        FunctionReference runtimeValidationFunction = _storage.selectorData[msg.sig].runtimeValidation;
        // run all preRuntimeValidation hooks
        EnumerableMap.Bytes32ToUintMap storage preRuntimeValidationHooks =
            getAccountStorage().selectorData[msg.sig].preRuntimeValidationHooks;

        uint256 preRuntimeValidationHooksLength = preRuntimeValidationHooks.length();
        for (uint256 i = 0; i < preRuntimeValidationHooksLength;) {
            (bytes32 key,) = preRuntimeValidationHooks.at(i);
            FunctionReference preRuntimeValidationHook = _toFunctionReference(key);

            if (!preRuntimeValidationHook.isEmptyOrMagicValue()) {
                (address plugin, uint8 functionId) = preRuntimeValidationHook.unpack();
                // solhint-disable-next-line no-empty-blocks
                try IPlugin(plugin).preRuntimeValidationHook(functionId, msg.sender, msg.value, msg.data) {}
                catch (bytes memory revertReason) {
                    revert PreRuntimeValidationHookFailed(plugin, functionId, revertReason);
                }

                unchecked {
                    ++i;
                }
            } else {
                if (preRuntimeValidationHook.eq(FunctionReferenceLib._PRE_HOOK_ALWAYS_DENY)) {
                    revert AlwaysDenyRule();
                }
                // Function reference cannot be 0 or _RUNTIME_VALIDATION_ALWAYS_ALLOW.
                revert InvalidConfiguration();
            }
        }

        // Identifier scope limiting
        {
            if (!runtimeValidationFunction.isEmptyOrMagicValue()) {
                (address plugin, uint8 functionId) = runtimeValidationFunction.unpack();
                // solhint-disable-next-line no-empty-blocks
                try IPlugin(plugin).runtimeValidationFunction(functionId, msg.sender, msg.value, msg.data) {}
                catch (bytes memory revertReason) {
                    revert RuntimeValidationFunctionReverted(plugin, functionId, revertReason);
                }
            } else {
                if (runtimeValidationFunction.isEmpty()) {
                    revert RuntimeValidationFunctionMissing(msg.sig);
                } else if (runtimeValidationFunction.eq(FunctionReferenceLib._PRE_HOOK_ALWAYS_DENY)) {
                    revert InvalidConfiguration();
                }
                // If _RUNTIME_VALIDATION_ALWAYS_ALLOW, just let the function finish.
            }
        }
    }

    function _doPreExecHooks(bytes4 selector, bytes calldata data)
        internal
        returns (PostExecToRun[] memory postHooksToRun)
    {
        HookGroup storage hooks = getAccountStorage().selectorData[selector].executionHooks;
        uint256 preExecHooksLength = hooks.preHooks.length();
        uint256 postOnlyHooksLength = hooks.postOnlyHooks.length();
        uint256 maxPostExecHooksLength = postOnlyHooksLength;

        // There can only be as many associated post hooks to run as there are pre hooks.
        for (uint256 i = 0; i < preExecHooksLength;) {
            (, uint256 count) = hooks.preHooks.at(i);
            unchecked {
                maxPostExecHooksLength += (count + 1);
                ++i;
            }
        }

        // Overallocate on length - not all of this may get filled up. We set the correct length later.
        postHooksToRun = new PostExecToRun[](maxPostExecHooksLength);
        uint256 actualPostHooksToRunLength;

        // Copy post-only hooks to the array.
        for (uint256 i = 0; i < postOnlyHooksLength;) {
            (bytes32 key,) = hooks.postOnlyHooks.at(i);
            postHooksToRun[actualPostHooksToRunLength].postExecHook = _toFunctionReference(key);
            unchecked {
                ++actualPostHooksToRunLength;
                ++i;
            }
        }

        // Then run the pre hooks and copy the associated post hooks (along with their pre hook's return data) to
        // the array.
        for (uint256 i = 0; i < preExecHooksLength;) {
            (bytes32 key,) = hooks.preHooks.at(i);
            FunctionReference preExecHook = _toFunctionReference(key);

            if (preExecHook.isEmptyOrMagicValue()) {
                // The function reference must be PRE_HOOK_ALWAYS_DENY in this case, because zero and any other
                // magic value is unassignable here.
                revert AlwaysDenyRule();
            }

            bytes memory preExecHookReturnData = _runPreExecHook(preExecHook, data);

            uint256 associatedPostExecHooksLength = hooks.associatedPostHooks[preExecHook].length();
            if (associatedPostExecHooksLength > 0) {
                for (uint256 j = 0; j < associatedPostExecHooksLength;) {
                    (key,) = hooks.associatedPostHooks[preExecHook].at(j);
                    postHooksToRun[actualPostHooksToRunLength].postExecHook = _toFunctionReference(key);
                    postHooksToRun[actualPostHooksToRunLength].preExecHookReturnData = preExecHookReturnData;

                    unchecked {
                        ++actualPostHooksToRunLength;
                        ++j;
                    }
                }
            }

            unchecked {
                ++i;
            }
        }

        // Trim the post hook array to the actual length, since we may have overallocated.
        assembly ("memory-safe") {
            mstore(postHooksToRun, actualPostHooksToRunLength)
        }
    }

    function _runPreExecHook(FunctionReference preExecHook, bytes calldata data)
        internal
        returns (bytes memory preExecHookReturnData)
    {
        (address plugin, uint8 functionId) = preExecHook.unpack();
        try IPlugin(plugin).preExecutionHook(functionId, msg.sender, msg.value, data) returns (
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
            unchecked {
                --i;
            }

            PostExecToRun memory postHookToRun = postHooksToRun[i];
            (address plugin, uint8 functionId) = postHookToRun.postExecHook.unpack();
            // solhint-disable-next-line no-empty-blocks
            try IPlugin(plugin).postExecutionHook(functionId, postHookToRun.preExecHookReturnData) {}
            catch (bytes memory revertReason) {
                revert PostExecHookReverted(plugin, functionId, revertReason);
            }
        }
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override {}
}
