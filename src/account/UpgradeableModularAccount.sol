// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {BaseAccount} from "@eth-infinitism/account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {FunctionReferenceLib} from "../helpers/FunctionReferenceLib.sol";
import {_coalescePreValidation, _coalesceValidation} from "../helpers/ValidationDataHelpers.sol";
import {IPlugin, PluginManifest} from "../interfaces/IPlugin.sol";
import {IValidation} from "../interfaces/IValidation.sol";
import {IValidationHook} from "../interfaces/IValidationHook.sol";
import {IExecutionHook} from "../interfaces/IExecutionHook.sol";
import {FunctionReference, IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor, Call} from "../interfaces/IStandardExecutor.sol";
import {AccountExecutor} from "./AccountExecutor.sol";
import {AccountLoupe} from "./AccountLoupe.sol";
import {
    AccountStorage,
    getAccountStorage,
    toSetValue,
    toFunctionReference,
    toExecutionHook
} from "./AccountStorage.sol";
import {AccountStorageInitializable} from "./AccountStorageInitializable.sol";
import {PluginManagerInternals} from "./PluginManagerInternals.sol";
import {PluginManager2} from "./PluginManager2.sol";

contract UpgradeableModularAccount is
    AccountExecutor,
    AccountLoupe,
    AccountStorageInitializable,
    BaseAccount,
    IERC165,
    IERC1271,
    IStandardExecutor,
    IAccountExecute,
    PluginManagerInternals,
    PluginManager2,
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

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    event ModularAccountInitialized(IEntryPoint indexed entryPoint);

    error AuthorizeUpgradeReverted(bytes revertReason);
    error ExecFromPluginNotPermitted(address plugin, bytes4 selector);
    error ExecFromPluginExternalNotPermitted(address plugin, address target, uint256 value, bytes data);
    error NativeTokenSpendingNotPermitted(address plugin);
    error NotEntryPoint();
    error PostExecHookReverted(address plugin, uint8 functionId, bytes revertReason);
    error PreExecHookReverted(address plugin, uint8 functionId, bytes revertReason);
    error PreRuntimeValidationHookFailed(address plugin, uint8 functionId, bytes revertReason);
    error RequireUserOperationContext();
    error RuntimeValidationFunctionMissing(bytes4 selector);
    error RuntimeValidationFunctionReverted(address plugin, uint8 functionId, bytes revertReason);
    error SignatureValidationInvalid(address plugin, uint8 functionId);
    error UnexpectedAggregator(address plugin, uint8 functionId, address aggregator);
    error UnrecognizedFunction(bytes4 selector);
    error UserOpValidationFunctionMissing(bytes4 selector);
    error ValidationDoesNotApply(bytes4 selector, address plugin, uint8 functionId, bool shared);

    // Wraps execution of a native function with runtime validation and hooks
    // Used for upgradeTo, upgradeToAndCall, execute, executeBatch, installPlugin, uninstallPlugin
    modifier wrapNativeFunction() {
        _checkPermittedCallerIfNotFromEP();

        PostExecToRun[] memory postExecHooks =
            _doPreHooks(getAccountStorage().selectorData[msg.sig].executionHooks, msg.data, false);

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

        _checkPermittedCallerIfNotFromEP();

        PostExecToRun[] memory postExecHooks;
        // Cache post-exec hooks in memory
        postExecHooks = _doPreHooks(getAccountStorage().selectorData[msg.sig].executionHooks, msg.data, false);

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

    /// @notice Execution function that allows UO context to be passed to execution hooks
    /// @dev This function is only callable by the EntryPoint
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external {
        if (msg.sender != address(_ENTRY_POINT)) {
            revert NotEntryPoint();
        }

        FunctionReference userOpValidationFunction = FunctionReference.wrap(bytes21(userOp.signature[:21]));

        PostExecToRun[] memory postPermissionHooks = _doPreHooks(
            getAccountStorage().validationData[userOpValidationFunction].permissionHooks, abi.encode(userOp), true
        );

        PostExecToRun[] memory postExecHooks = _doPreHooks(
            getAccountStorage().selectorData[bytes4(userOp.callData[4:8])].executionHooks, abi.encode(userOp), true
        );

        (bool success, bytes memory result) = address(this).call(userOp.callData[4:]);

        if (!success) {
            // Directly bubble up revert messages
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }

        _doCachedPostExecHooks(postExecHooks);
        _doCachedPostExecHooks(postPermissionHooks);
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

    /// @inheritdoc IStandardExecutor
    function executeWithAuthorization(bytes calldata data, bytes calldata authorization)
        external
        payable
        returns (bytes memory)
    {
        bytes4 execSelector = bytes4(data[0:4]);

        FunctionReference runtimeValidationFunction = FunctionReference.wrap(bytes21(authorization[0:21]));

        // Check if the runtime validation function is allowed to be called
        bool isSharedValidation = uint8(authorization[21]) == 1;
        _checkIfValidationApplies(execSelector, runtimeValidationFunction, isSharedValidation);

        _doRuntimeValidation(runtimeValidationFunction, data, authorization[22:]);

        // If runtime validation passes, do runtime permission checks
        PostExecToRun[] memory postPermissionHooks =
            _doPreHooks(getAccountStorage().validationData[runtimeValidationFunction].permissionHooks, data, false);

        // Execute the call
        (bool success, bytes memory returnData) = address(this).call(data);

        if (!success) {
            assembly ("memory-safe") {
                revert(add(returnData, 32), mload(returnData))
            }
        }

        _doCachedPostExecHooks(postPermissionHooks);

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

    /// @notice Initializes the account with a validation function added to the default pool.
    /// TODO: remove and merge with regular initialization, after we figure out a better install/uninstall workflow
    /// with user install configs.
    /// @dev This function is only callable once, and only by the EntryPoint.

    function initializeDefaultValidation(FunctionReference validationFunction, bytes calldata installData)
        external
        initializer
    {
        _installValidation(validationFunction, true, new bytes4[](0), installData, bytes(""), bytes(""));
        emit ModularAccountInitialized(_ENTRY_POINT);
    }

    /// @inheritdoc IPluginManager
    function installValidation(
        FunctionReference validationFunction,
        bool shared,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes calldata preValidationHooks,
        bytes calldata permissionHooks
    ) external wrapNativeFunction {
        _installValidation(validationFunction, shared, selectors, installData, preValidationHooks, permissionHooks);
    }

    /// @inheritdoc IPluginManager
    function uninstallValidation(
        FunctionReference validationFunction,
        bytes4[] calldata selectors,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData,
        bytes calldata permissionHookUninstallData
    ) external wrapNativeFunction {
        _uninstallValidation(
            validationFunction,
            selectors,
            uninstallData,
            preValidationHookUninstallData,
            permissionHookUninstallData
        );
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

    function isValidSignature(bytes32 hash, bytes calldata signature) public view override returns (bytes4) {
        AccountStorage storage _storage = getAccountStorage();

        FunctionReference sigValidation = FunctionReference.wrap(bytes21(signature));

        (address plugin, uint8 functionId) = sigValidation.unpack();
        if (!_storage.validationData[sigValidation].isSignatureValidation) {
            revert SignatureValidationInvalid(plugin, functionId);
        }

        if (
            IValidation(plugin).validateSignature(functionId, msg.sender, hash, signature[21:])
                == _1271_MAGIC_VALUE
        ) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID;
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
        if (selector == this.executeUserOp.selector) {
            selector = bytes4(userOp.callData[4:8]);
        }

        FunctionReference userOpValidationFunction = FunctionReference.wrap(bytes21(userOp.signature[:21]));
        bool isSharedValidation = uint8(userOp.signature[21]) == 1;

        _checkIfValidationApplies(selector, userOpValidationFunction, isSharedValidation);

        // Check if there are exec hooks associated with the validator that require UO context, and revert if the
        // call isn't to `executeUserOp`
        // This check must be here because if context isn't passed, we wouldn't be able to get the exec hooks
        // associated with the validator
        if (
            getAccountStorage().validationData[userOpValidationFunction].requireUOHookCount > 0
                && bytes4(userOp.callData[:4]) != this.executeUserOp.selector
        ) {
            revert RequireUserOperationContext();
        }

        validationData =
            _doUserOpValidation(selector, userOpValidationFunction, userOp, userOp.signature[22:], userOpHash);
    }

    // To support gas estimation, we don't fail early when the failure is caused by a signature failure
    function _doUserOpValidation(
        bytes4 selector,
        FunctionReference userOpValidationFunction,
        PackedUserOperation memory userOp,
        bytes calldata signature,
        bytes32 userOpHash
    ) internal returns (uint256 validationData) {
        userOp.signature = signature;

        if (userOpValidationFunction.isEmpty()) {
            // If the validation function is empty, then the call cannot proceed.
            revert UserOpValidationFunctionMissing(selector);
        }

        uint256 currentValidationData;

        // Do preUserOpValidation hooks
        EnumerableSet.Bytes32Set storage preUserOpValidationHooks =
            getAccountStorage().validationData[userOpValidationFunction].preValidationHooks;

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
            currentValidationData = IValidation(plugin).validateUserOp(functionId, userOp, userOpHash);

            if (preUserOpValidationHooksLength != 0) {
                // If we have other validation data we need to coalesce with
                validationData = _coalesceValidation(validationData, currentValidationData);
            } else {
                validationData = currentValidationData;
            }
        }
    }

    function _doRuntimeValidation(
        FunctionReference runtimeValidationFunction,
        bytes calldata callData,
        bytes calldata authorizationData
    ) internal {
        // run all preRuntimeValidation hooks
        EnumerableSet.Bytes32Set storage preRuntimeValidationHooks =
            getAccountStorage().validationData[runtimeValidationFunction].preValidationHooks;

        uint256 preRuntimeValidationHooksLength = preRuntimeValidationHooks.length();
        for (uint256 i = 0; i < preRuntimeValidationHooksLength; ++i) {
            bytes32 key = preRuntimeValidationHooks.at(i);
            FunctionReference preRuntimeValidationHook = toFunctionReference(key);

            (address hookPlugin, uint8 hookFunctionId) = preRuntimeValidationHook.unpack();
            try IValidationHook(hookPlugin).preRuntimeValidationHook(
                hookFunctionId, msg.sender, msg.value, callData
            )
            // forgefmt: disable-start
            // solhint-disable-next-line no-empty-blocks
            {} catch (bytes memory revertReason) {
            // forgefmt: disable-end
                revert PreRuntimeValidationHookFailed(hookPlugin, hookFunctionId, revertReason);
            }
        }

        (address plugin, uint8 functionId) = runtimeValidationFunction.unpack();

        try IValidation(plugin).validateRuntime(functionId, msg.sender, msg.value, callData, authorizationData)
        // forgefmt: disable-start
        // solhint-disable-next-line no-empty-blocks
        {} catch (bytes memory revertReason) {
        // forgefmt: disable-end
            revert RuntimeValidationFunctionReverted(plugin, functionId, revertReason);
        }
    }

    function _doPreHooks(EnumerableSet.Bytes32Set storage executionHooks, bytes memory data, bool isPackedUO)
        internal
        returns (PostExecToRun[] memory postHooksToRun)
    {
        uint256 hooksLength = executionHooks.length();
        // Overallocate on length - not all of this may get filled up. We set the correct length later.
        postHooksToRun = new PostExecToRun[](hooksLength);

        // Copy all post hooks to the array. This happens before any pre hooks are run, so we can
        // be sure that the set of hooks to run will not be affected by state changes mid-execution.
        for (uint256 i = 0; i < hooksLength; ++i) {
            bytes32 key = executionHooks.at(i);
            (FunctionReference hookFunction,, bool isPostHook, bool requireUOContext) = toExecutionHook(key);
            if (requireUOContext) {
                /**
                 * && msg.sig != this.executeUserOp.selector
                 */
                revert RequireUserOperationContext();
            }
            if (isPostHook) {
                postHooksToRun[i].postExecHook = hookFunction;
            }
        }

        // Run the pre hooks and copy their return data to the post hooks array, if an associated post-exec hook
        // exists.
        for (uint256 i = 0; i < hooksLength; ++i) {
            bytes32 key = executionHooks.at(i);
            (FunctionReference hookFunction, bool isPreHook, bool isPostHook, bool requireUOContext) =
                toExecutionHook(key);

            if (!isPackedUO && requireUOContext) {
                revert RequireUserOperationContext();
            }

            if (isPreHook) {
                bytes memory preExecHookReturnData;

                if (isPackedUO) {
                    if (requireUOContext) {
                        preExecHookReturnData = _runPreExecHook(hookFunction, data);
                    } else {
                        PackedUserOperation memory uo = abi.decode(data, (PackedUserOperation));
                        preExecHookReturnData =
                            _runPreExecHook(hookFunction, abi.encodePacked(msg.sender, msg.value, uo.callData));
                    }
                } else {
                    preExecHookReturnData =
                        _runPreExecHook(hookFunction, abi.encodePacked(msg.sender, msg.value, data));
                }

                // If there is an associated post-exec hook, save the return data.
                if (isPostHook) {
                    postHooksToRun[i].preExecHookReturnData = preExecHookReturnData;
                }
            }
        }
    }

    function _runPreExecHook(FunctionReference preExecHook, bytes memory data)
        internal
        returns (bytes memory preExecHookReturnData)
    {
        (address plugin, uint8 functionId) = preExecHook.unpack();
        try IExecutionHook(plugin).preExecutionHook(functionId, data) returns (bytes memory returnData) {
            preExecHookReturnData = returnData;
        } catch (bytes memory revertReason) {
            // TODO: same issue with EP0.6 - we can't do bytes4 error codes in plugins
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

    function _checkIfValidationApplies(bytes4 selector, FunctionReference validationFunction, bool shared)
        internal
        view
    {
        AccountStorage storage _storage = getAccountStorage();

        // Check that the provided validation function is applicable to the selector
        if (shared) {
            if (!_sharedValidationAllowed(selector) || !_storage.validationData[validationFunction].isShared) {
                revert UserOpValidationFunctionMissing(selector);
            }
        } else {
            // Not shared validation, but per-selector
            if (!getAccountStorage().selectorData[selector].validations.contains(toSetValue(validationFunction))) {
                revert UserOpValidationFunctionMissing(selector);
            }
        }
    }

    function _sharedValidationAllowed(bytes4 selector) internal view returns (bool) {
        if (
            selector == this.execute.selector || selector == this.executeBatch.selector
                || selector == this.installPlugin.selector || selector == this.uninstallPlugin.selector
                || selector == this.installValidation.selector || selector == this.uninstallValidation.selector
                || selector == this.upgradeToAndCall.selector
        ) {
            return true;
        }

        return getAccountStorage().selectorData[selector].allowSharedValidation;
    }

    function _checkPermittedCallerIfNotFromEP() internal view {
        AccountStorage storage _storage = getAccountStorage();

        if (
            msg.sender != address(_ENTRY_POINT) && msg.sender != address(this)
                && !_storage.selectorData[msg.sig].isPublic
        ) {
            revert ExecFromPluginNotPermitted(msg.sender, msg.sig);
        }
    }
}
