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
import {ValidationConfigLib} from "../helpers/ValidationConfigLib.sol";
import {SparseCalldataSegmentLib} from "../helpers/SparseCalldataSegmentLib.sol";
import {_coalescePreValidation, _coalesceValidation} from "../helpers/ValidationDataHelpers.sol";
import {IPlugin, PluginManifest} from "../interfaces/IPlugin.sol";
import {IValidation} from "../interfaces/IValidation.sol";
import {IValidationHook} from "../interfaces/IValidationHook.sol";
import {IExecutionHook} from "../interfaces/IExecutionHook.sol";
import {FunctionReference, IPluginManager, ValidationConfig} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor, Call} from "../interfaces/IStandardExecutor.sol";
import {AccountExecutor} from "./AccountExecutor.sol";
import {AccountLoupe} from "./AccountLoupe.sol";
import {AccountStorage, getAccountStorage, toSetValue, toExecutionHook} from "./AccountStorage.sol";
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
    using ValidationConfigLib for ValidationConfig;
    using SparseCalldataSegmentLib for bytes;

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
    error NonCanonicalEncoding();
    error NotEntryPoint();
    error PostExecHookReverted(address plugin, uint8 functionId, bytes revertReason);
    error PreExecHookReverted(address plugin, uint8 functionId, bytes revertReason);
    error PreRuntimeValidationHookFailed(address plugin, uint8 functionId, bytes revertReason);
    error RequireUserOperationContext();
    error RuntimeValidationFunctionMissing(bytes4 selector);
    error RuntimeValidationFunctionReverted(address plugin, uint8 functionId, bytes revertReason);
    error SelfCallRecursionDepthExceeded();
    error SignatureValidationInvalid(address plugin, uint8 functionId);
    error UnexpectedAggregator(address plugin, uint8 functionId, address aggregator);
    error UnrecognizedFunction(bytes4 selector);
    error ValidationFunctionMissing(bytes4 selector);
    error ValidationDoesNotApply(bytes4 selector, address plugin, uint8 functionId, bool isGlobal);
    error ValidationSignatureSegmentMissing();
    error SignatureSegmentOutOfOrder();

    // Wraps execution of a native function with runtime validation and hooks
    // Used for upgradeTo, upgradeToAndCall, execute, executeBatch, installPlugin, uninstallPlugin
    modifier wrapNativeFunction() {
        (PostExecToRun[] memory postPermissionHooks, PostExecToRun[] memory postExecHooks) =
            _checkPermittedCallerAndAssociatedHooks();

        _;

        _doCachedPostExecHooks(postExecHooks);
        _doCachedPostExecHooks(postPermissionHooks);
    }

    constructor(IEntryPoint anEntryPoint) {
        _ENTRY_POINT = anEntryPoint;
        _disableInitializers();
    }

    // EXTERNAL FUNCTIONS

    /// @notice Initializes the account with a set of plugins
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

        for (uint256 i = 0; i < length; ++i) {
            _installPlugin(plugins[i], manifestHashes[i], pluginInstallDatas[i]);
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

        _checkPermittedCallerAndAssociatedHooks();

        PostExecToRun[] memory postExecHooks;
        // Cache post-exec hooks in memory
        postExecHooks = _doPreHooks(getAccountStorage().selectorData[msg.sig].executionHooks, msg.data);

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

        PostExecToRun[] memory postPermissionHooks =
            _doPreHooks(getAccountStorage().validationData[userOpValidationFunction].permissionHooks, msg.data);

        (bool success, bytes memory result) = address(this).call(userOp.callData[4:]);

        if (!success) {
            // Directly bubble up revert messages
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }

        _doCachedPostExecHooks(postPermissionHooks);
    }

    /// @inheritdoc IStandardExecutor
    /// @notice May be validated by a global validation.
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
    /// @notice May be validated by a global validation function.
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
        // Revert if the provided `authorization` less than 21 bytes long, rather than right-padding.
        FunctionReference runtimeValidationFunction = FunctionReference.wrap(bytes21(authorization[:21]));

        // Check if the runtime validation function is allowed to be called
        bool isGlobalValidation = uint8(authorization[21]) == 1;
        _checkIfValidationAppliesCallData(data, runtimeValidationFunction, isGlobalValidation);

        _doRuntimeValidation(runtimeValidationFunction, data, authorization[22:]);

        // If runtime validation passes, do runtime permission checks
        PostExecToRun[] memory postPermissionHooks =
            _doPreHooks(getAccountStorage().validationData[runtimeValidationFunction].permissionHooks, data);

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
    /// @notice May be validated by a global validation.
    function installPlugin(address plugin, bytes32 manifestHash, bytes calldata pluginInstallData)
        external
        override
        wrapNativeFunction
    {
        _installPlugin(plugin, manifestHash, pluginInstallData);
    }

    /// @inheritdoc IPluginManager
    /// @notice May be validated by a global validation.
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

    /// @notice Initializes the account with a validation function added to the global pool.
    /// TODO: remove and merge with regular initialization, after we figure out a better install/uninstall workflow
    /// with user install configs.
    /// @dev This function is only callable once, and only by the EntryPoint.
    function initializeWithValidation(
        ValidationConfig validationConfig,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes calldata preValidationHooks,
        bytes calldata permissionHooks
    ) external initializer {
        _installValidation(validationConfig, selectors, installData, preValidationHooks, permissionHooks);
        emit ModularAccountInitialized(_ENTRY_POINT);
    }

    /// @inheritdoc IPluginManager
    /// @notice May be validated by a global validation.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes calldata preValidationHooks,
        bytes calldata permissionHooks
    ) external wrapNativeFunction {
        _installValidation(validationConfig, selectors, installData, preValidationHooks, permissionHooks);
    }

    /// @inheritdoc IPluginManager
    /// @notice May be validated by a global validation.
    function uninstallValidation(
        FunctionReference validationFunction,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData,
        bytes calldata permissionHookUninstallData
    ) external wrapNativeFunction {
        _uninstallValidation(
            validationFunction, uninstallData, preValidationHookUninstallData, permissionHookUninstallData
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
    /// @notice May be validated by a global validation.
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

        // Revert if the provided `authorization` less than 21 bytes long, rather than right-padding.
        FunctionReference userOpValidationFunction = FunctionReference.wrap(bytes21(userOp.signature[:21]));
        bool isGlobalValidation = uint8(userOp.signature[21]) == 1;

        _checkIfValidationAppliesCallData(userOp.callData, userOpValidationFunction, isGlobalValidation);

        // Check if there are permission hooks associated with the validator, and revert if the call isn't to
        // `executeUserOp`
        // This check must be here because if context isn't passed, we can't tell in execution which hooks should
        // have ran
        if (
            getAccountStorage().validationData[userOpValidationFunction].permissionHooks.length() > 0
                && bytes4(userOp.callData[:4]) != this.executeUserOp.selector
        ) {
            revert RequireUserOperationContext();
        }

        validationData = _doUserOpValidation(userOpValidationFunction, userOp, userOp.signature[22:], userOpHash);
    }

    // To support gas estimation, we don't fail early when the failure is caused by a signature failure
    function _doUserOpValidation(
        FunctionReference userOpValidationFunction,
        PackedUserOperation memory userOp,
        bytes calldata signature,
        bytes32 userOpHash
    ) internal returns (uint256) {
        // Set up the per-hook data tracking fields
        bytes calldata signatureSegment;
        (signatureSegment, signature) = signature.getNextSegment();

        uint256 validationData;

        // Do preUserOpValidation hooks
        FunctionReference[] memory preUserOpValidationHooks =
            getAccountStorage().validationData[userOpValidationFunction].preValidationHooks;

        for (uint256 i = 0; i < preUserOpValidationHooks.length; ++i) {
            // Load per-hook data, if any is present
            // The segment index is the first byte of the signature
            if (signatureSegment.getIndex() == i) {
                // Use the current segment
                userOp.signature = signatureSegment.getBody();

                if (userOp.signature.length == 0) {
                    revert NonCanonicalEncoding();
                }

                // Load the next per-hook data segment
                (signatureSegment, signature) = signature.getNextSegment();

                if (signatureSegment.getIndex() <= i) {
                    revert SignatureSegmentOutOfOrder();
                }
            } else {
                userOp.signature = "";
            }

            (address plugin, uint8 functionId) = preUserOpValidationHooks[i].unpack();
            uint256 currentValidationData =
                IValidationHook(plugin).preUserOpValidationHook(functionId, userOp, userOpHash);

            if (uint160(currentValidationData) > 1) {
                // If the aggregator is not 0 or 1, it is an unexpected value
                revert UnexpectedAggregator(plugin, functionId, address(uint160(currentValidationData)));
            }
            validationData = _coalescePreValidation(validationData, currentValidationData);
        }

        // Run the user op validationFunction
        {
            if (signatureSegment.getIndex() != _RESERVED_VALIDATION_DATA_INDEX) {
                revert ValidationSignatureSegmentMissing();
            }

            userOp.signature = signatureSegment.getBody();

            (address plugin, uint8 functionId) = userOpValidationFunction.unpack();
            uint256 currentValidationData = IValidation(plugin).validateUserOp(functionId, userOp, userOpHash);

            if (preUserOpValidationHooks.length != 0) {
                // If we have other validation data we need to coalesce with
                validationData = _coalesceValidation(validationData, currentValidationData);
            } else {
                validationData = currentValidationData;
            }
        }

        return validationData;
    }

    function _doRuntimeValidation(
        FunctionReference runtimeValidationFunction,
        bytes calldata callData,
        bytes calldata authorizationData
    ) internal {
        // Set up the per-hook data tracking fields
        bytes calldata authSegment;
        (authSegment, authorizationData) = authorizationData.getNextSegment();

        // run all preRuntimeValidation hooks
        FunctionReference[] memory preRuntimeValidationHooks =
            getAccountStorage().validationData[runtimeValidationFunction].preValidationHooks;

        for (uint256 i = 0; i < preRuntimeValidationHooks.length; ++i) {
            bytes memory currentAuthData;

            if (authSegment.getIndex() == i) {
                // Use the current segment
                currentAuthData = authSegment.getBody();

                if (currentAuthData.length == 0) {
                    revert NonCanonicalEncoding();
                }

                // Load the next per-hook data segment
                (authSegment, authorizationData) = authorizationData.getNextSegment();

                if (authSegment.getIndex() <= i) {
                    revert SignatureSegmentOutOfOrder();
                }
            } else {
                currentAuthData = "";
            }
            _doPreRuntimeValidationHook(preRuntimeValidationHooks[i], callData, currentAuthData);
        }

        if (authSegment.getIndex() != _RESERVED_VALIDATION_DATA_INDEX) {
            revert ValidationSignatureSegmentMissing();
        }

        (address plugin, uint8 functionId) = runtimeValidationFunction.unpack();

        try IValidation(plugin).validateRuntime(functionId, msg.sender, msg.value, callData, authSegment.getBody())
        // forgefmt: disable-start
        // solhint-disable-next-line no-empty-blocks
        {} catch (bytes memory revertReason) {
        // forgefmt: disable-end
            revert RuntimeValidationFunctionReverted(plugin, functionId, revertReason);
        }
    }

    function _doPreHooks(EnumerableSet.Bytes32Set storage executionHooks, bytes memory data)
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
            (FunctionReference hookFunction,, bool isPostHook) = toExecutionHook(key);
            if (isPostHook) {
                postHooksToRun[i].postExecHook = hookFunction;
            }
        }

        // Run the pre hooks and copy their return data to the post hooks array, if an associated post-exec hook
        // exists.
        for (uint256 i = 0; i < hooksLength; ++i) {
            bytes32 key = executionHooks.at(i);
            (FunctionReference hookFunction, bool isPreHook, bool isPostHook) = toExecutionHook(key);

            if (isPreHook) {
                bytes memory preExecHookReturnData;

                preExecHookReturnData = _runPreExecHook(hookFunction, data);

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
        try IExecutionHook(plugin).preExecutionHook(functionId, msg.sender, msg.value, data) returns (
            bytes memory returnData
        ) {
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

    function _doPreRuntimeValidationHook(
        FunctionReference validationHook,
        bytes memory callData,
        bytes memory currentAuthData
    ) internal {
        (address hookPlugin, uint8 hookFunctionId) = validationHook.unpack();
        try IValidationHook(hookPlugin).preRuntimeValidationHook(
            hookFunctionId, msg.sender, msg.value, callData, currentAuthData
        )
        // forgefmt: disable-start
        // solhint-disable-next-line no-empty-blocks
        {} catch (bytes memory revertReason) {
        // forgefmt: disable-end
            revert PreRuntimeValidationHookFailed(hookPlugin, hookFunctionId, revertReason);
        }
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override {}

    /**
     * Order of operations:
     *      1. Check if the sender is the entry point, the account itself, or the selector called is public.
     *          - Yes: Return an empty array, there are no post-permissionHooks.
     *          - No: Continue
     *      2. Check if the called selector (msg.sig) is included in the set of selectors the msg.sender can
     *         directly call.
     *          - Yes: Continue
     *          - No: Revert, the caller is not allowed to call this selector
     *      3. If there are runtime validation hooks associated with this caller-sig combination, run them.
     *      4. Run the pre-permissionHooks associated with this caller-sig combination, and return the
     *         post-permissionHooks to run later.
     */
    function _checkPermittedCallerAndAssociatedHooks()
        internal
        returns (PostExecToRun[] memory, PostExecToRun[] memory)
    {
        AccountStorage storage _storage = getAccountStorage();

        if (
            msg.sender == address(_ENTRY_POINT) || msg.sender == address(this)
                || _storage.selectorData[msg.sig].isPublic
        ) {
            return (new PostExecToRun[](0), new PostExecToRun[](0));
        }

        FunctionReference directCallValidationKey =
            FunctionReferenceLib.pack(msg.sender, _SELF_PERMIT_VALIDATION_FUNCTIONID);

        _checkIfValidationAppliesCallData(msg.data, directCallValidationKey, false);

        // Direct call is allowed, run associated permission & validation hooks

        // Validation hooks
        FunctionReference[] memory preRuntimeValidationHooks =
            _storage.validationData[directCallValidationKey].preValidationHooks;

        uint256 hookLen = preRuntimeValidationHooks.length;
        for (uint256 i = 0; i < hookLen; ++i) {
            _doPreRuntimeValidationHook(preRuntimeValidationHooks[i], msg.data, "");
        }

        // Permission hooks
        PostExecToRun[] memory postPermissionHooks =
            _doPreHooks(_storage.validationData[directCallValidationKey].permissionHooks, msg.data);

        // Exec hooks
        PostExecToRun[] memory postExecutionHooks =
            _doPreHooks(_storage.selectorData[msg.sig].executionHooks, msg.data);

        return (postPermissionHooks, postExecutionHooks);
    }

    function _checkIfValidationAppliesCallData(
        bytes calldata callData,
        FunctionReference validationFunction,
        bool isGlobal
    ) internal view {
        bytes4 outerSelector = bytes4(callData[:4]);
        if (outerSelector == this.executeUserOp.selector) {
            // If the selector is executeUserOp, pull the actual selector from the following data,
            // and trim the calldata to ensure the self-call decoding is still accurate.
            callData = callData[4:];
            outerSelector = bytes4(callData[:4]);
        }

        _checkIfValidationAppliesSelector(outerSelector, validationFunction, isGlobal);

        if (outerSelector == IStandardExecutor.execute.selector) {
            (address target,,) = abi.decode(callData[4:], (address, uint256, bytes));

            if (target == address(this)) {
                // There is no point to call `execute` to recurse exactly once - this is equivalent to just having
                // the calldata as a top-level call.
                revert SelfCallRecursionDepthExceeded();
            }
        } else if (outerSelector == IStandardExecutor.executeBatch.selector) {
            // executeBatch may be used to batch account actions together, by targetting the account itself.
            // If this is done, we must ensure all of the inner calls are allowed by the provided validation
            // function.

            (Call[] memory calls) = abi.decode(callData[4:], (Call[]));

            for (uint256 i = 0; i < calls.length; ++i) {
                if (calls[i].target == address(this)) {
                    bytes4 nestedSelector = bytes4(calls[i].data);

                    if (
                        nestedSelector == IStandardExecutor.execute.selector
                            || nestedSelector == IStandardExecutor.executeBatch.selector
                    ) {
                        // To prevent arbitrarily-deep recursive checking, we limit the depth of self-calls to one
                        // for the purposes of batching.
                        // This means that all self-calls must occur at the top level of the batch.
                        // Note that plugins of other contracts using `executeWithAuthorization` may still
                        // independently call into this account with a different validation function, allowing
                        // composition of multiple batches.
                        revert SelfCallRecursionDepthExceeded();
                    }

                    _checkIfValidationAppliesSelector(nestedSelector, validationFunction, isGlobal);
                }
            }
        }
    }

    function _globalValidationAllowed(bytes4 selector) internal view returns (bool) {
        if (
            selector == this.execute.selector || selector == this.executeBatch.selector
                || selector == this.installPlugin.selector || selector == this.uninstallPlugin.selector
                || selector == this.installValidation.selector || selector == this.uninstallValidation.selector
                || selector == this.upgradeToAndCall.selector
        ) {
            return true;
        }

        return getAccountStorage().selectorData[selector].allowGlobalValidation;
    }

    function _checkIfValidationAppliesSelector(
        bytes4 selector,
        FunctionReference validationFunction,
        bool isGlobal
    ) internal view {
        AccountStorage storage _storage = getAccountStorage();

        // Check that the provided validation function is applicable to the selector
        if (isGlobal) {
            if (!_globalValidationAllowed(selector) || !_storage.validationData[validationFunction].isGlobal) {
                revert ValidationFunctionMissing(selector);
            }
        } else {
            // Not global validation, but per-selector
            if (!getAccountStorage().validationData[validationFunction].selectors.contains(toSetValue(selector))) {
                revert ValidationFunctionMissing(selector);
            }
        }
    }
}
