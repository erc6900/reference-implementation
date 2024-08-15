// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {BaseAccount} from "@eth-infinitism/account-abstraction/core/BaseAccount.sol";

import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {HookConfig, HookConfigLib} from "../helpers/HookConfigLib.sol";
import {ModuleEntityLib} from "../helpers/ModuleEntityLib.sol";

import {SparseCalldataSegmentLib} from "../helpers/SparseCalldataSegmentLib.sol";
import {ValidationConfigLib} from "../helpers/ValidationConfigLib.sol";
import {_coalescePreValidation, _coalesceValidation} from "../helpers/ValidationResHelpers.sol";

import {DIRECT_CALL_VALIDATION_ENTITYID, RESERVED_VALIDATION_DATA_INDEX} from "../helpers/Constants.sol";

import {IExecutionHookModule} from "../interfaces/IExecutionHookModule.sol";
import {ExecutionManifest} from "../interfaces/IExecutionModule.sol";
import {IModuleManager, ModuleEntity, ValidationConfig} from "../interfaces/IModuleManager.sol";
import {Call, IStandardExecutor} from "../interfaces/IStandardExecutor.sol";

import {IValidationHookModule} from "../interfaces/IValidationHookModule.sol";
import {IValidationModule} from "../interfaces/IValidationModule.sol";
import {AccountExecutor} from "./AccountExecutor.sol";
import {AccountLoupe} from "./AccountLoupe.sol";
import {AccountStorage, getAccountStorage, toHookConfig, toSetValue} from "./AccountStorage.sol";
import {AccountStorageInitializable} from "./AccountStorageInitializable.sol";
import {ModuleManagerInternals} from "./ModuleManagerInternals.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract UpgradeableModularAccount is
    AccountExecutor,
    AccountLoupe,
    AccountStorageInitializable,
    BaseAccount,
    IERC165,
    IERC1271,
    IStandardExecutor,
    IAccountExecute,
    ModuleManagerInternals,
    UUPSUpgradeable
{
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for ValidationConfig;
    using HookConfigLib for HookConfig;
    using SparseCalldataSegmentLib for bytes;
    using MessageHashUtils for bytes32;
    using ECDSA for bytes32;

    struct PostExecToRun {
        bytes preExecHookReturnData;
        ModuleEntity postExecHook;
    }

    IEntryPoint private immutable _ENTRY_POINT;

    // As per the EIP-165 spec, no interface should ever match 0xffffffff
    bytes4 internal constant _INTERFACE_ID_INVALID = 0xffffffff;
    bytes4 internal constant _IERC165_INTERFACE_ID = 0x01ffc9a7;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    event ModularAccountInitialized(IEntryPoint indexed entryPoint);

    error NonCanonicalEncoding();
    error NotEntryPoint();
    error PostExecHookReverted(address module, uint32 entityId, bytes revertReason);
    error PreExecHookReverted(address module, uint32 entityId, bytes revertReason);
    error PreRuntimeValidationHookFailed(address module, uint32 entityId, bytes revertReason);
    error RequireUserOperationContext();
    error RuntimeValidationFunctionReverted(address module, uint32 entityId, bytes revertReason);
    error SelfCallRecursionDepthExceeded();
    error SignatureValidationInvalid(address module, uint32 entityId);
    error UnexpectedAggregator(address module, uint32 entityId, address aggregator);
    error UnrecognizedFunction(bytes4 selector);
    error ValidationFunctionMissing(bytes4 selector);
    error ValidationSignatureSegmentMissing();
    error SignatureSegmentOutOfOrder();

    // Wraps execution of a native function with runtime validation and hooks
    // Used for upgradeTo, upgradeToAndCall, execute, executeBatch, installExecution, uninstallExecution
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

    receive() external payable {}

    /// @notice Fallback function
    /// @dev We route calls to execution functions based on incoming msg.sig
    /// @dev If there's no module associated with this function selector, revert
    fallback(bytes calldata) external payable returns (bytes memory) {
        address execModule = getAccountStorage().executionData[msg.sig].module;
        if (execModule == address(0)) {
            revert UnrecognizedFunction(msg.sig);
        }
        (PostExecToRun[] memory postPermissionHooks, PostExecToRun[] memory postExecHooks) =
            _checkPermittedCallerAndAssociatedHooks();

        // execute the function, bubbling up any reverts
        (bool execSuccess, bytes memory execReturnData) = execModule.call(msg.data);

        if (!execSuccess) {
            // Bubble up revert reasons from modules
            assembly ("memory-safe") {
                revert(add(execReturnData, 32), mload(execReturnData))
            }
        }

        _doCachedPostExecHooks(postExecHooks);
        _doCachedPostExecHooks(postPermissionHooks);

        return execReturnData;
    }

    /// @inheritdoc IAccountExecute
    /// @notice Execution function that allows UO context to be passed to execution hooks
    /// @dev This function is only callable by the EntryPoint
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external override {
        if (msg.sender != address(_ENTRY_POINT)) {
            revert NotEntryPoint();
        }

        ModuleEntity userOpValidationFunction = ModuleEntity.wrap(bytes24(userOp.signature[:24]));

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
        ModuleEntity runtimeValidationFunction = ModuleEntity.wrap(bytes24(authorization[:24]));

        // Check if the runtime validation function is allowed to be called
        bool isGlobalValidation = uint8(authorization[24]) == 1;
        _checkIfValidationAppliesCallData(data, runtimeValidationFunction, isGlobalValidation);

        _doRuntimeValidation(runtimeValidationFunction, data, authorization[25:]);

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

    /// @inheritdoc IModuleManager
    /// @notice May be validated by a global validation.
    function installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleInstallData
    ) external override wrapNativeFunction {
        _installExecution(module, manifest, moduleInstallData);
    }

    /// @inheritdoc IModuleManager
    /// @notice May be validated by a global validation.
    function uninstallExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleUninstallData
    ) external override wrapNativeFunction {
        _uninstallExecution(module, manifest, moduleUninstallData);
    }

    /// @notice Initializes the account with a validation function added to the global pool.
    /// TODO: remove and merge with regular initialization, after we figure out a better install/uninstall
    // workflow
    /// with user install configs.
    /// @dev This function is only callable once.
    function initializeWithValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external virtual initializer {
        _installValidation(validationConfig, selectors, installData, hooks);
    }

    /// @inheritdoc IModuleManager
    /// @notice May be validated by a global validation.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external wrapNativeFunction {
        _installValidation(validationConfig, selectors, installData, hooks);
    }

    /// @inheritdoc IModuleManager
    /// @notice May be validated by a global validation.
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) external wrapNativeFunction {
        _uninstallValidation(validationFunction, uninstallData, hookUninstallData);
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
        ModuleEntity sigValidation = ModuleEntity.wrap(bytes24(signature));

        return _exec1271Validation(sigValidation, hash, signature[24:]);
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
        override
        returns (uint256 validationData)
    {
        if (userOp.callData.length < 4) {
            revert UnrecognizedFunction(bytes4(userOp.callData));
        }

        // Revert if the provided `authorization` less than 21 bytes long, rather than right-padding.
        ModuleEntity userOpValidationFunction = ModuleEntity.wrap(bytes24(userOp.signature[:24]));
        bool isGlobalValidation = uint8(userOp.signature[24]) == 1;

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

        validationData = _doUserOpValidation(userOpValidationFunction, userOp, userOp.signature[25:], userOpHash);
    }

    // To support gas estimation, we don't fail early when the failure is caused by a signature failure
    function _doUserOpValidation(
        ModuleEntity userOpValidationFunction,
        PackedUserOperation memory userOp,
        bytes calldata signature,
        bytes32 userOpHash
    ) internal returns (uint256) {
        // Set up the per-hook data tracking fields
        bytes calldata signatureSegment;
        (signatureSegment, signature) = signature.getNextSegment();

        uint256 validationRes;

        // Do preUserOpValidation hooks
        ModuleEntity[] memory preUserOpValidationHooks =
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

            (address module, uint32 entityId) = preUserOpValidationHooks[i].unpack();
            uint256 currentValidationRes =
                IValidationHookModule(module).preUserOpValidationHook(entityId, userOp, userOpHash);

            if (uint160(currentValidationRes) > 1) {
                // If the aggregator is not 0 or 1, it is an unexpected value
                revert UnexpectedAggregator(module, entityId, address(uint160(currentValidationRes)));
            }
            validationRes = _coalescePreValidation(validationRes, currentValidationRes);
        }

        // Run the user op validationFunction
        {
            if (signatureSegment.getIndex() != RESERVED_VALIDATION_DATA_INDEX) {
                revert ValidationSignatureSegmentMissing();
            }

            userOp.signature = signatureSegment.getBody();

            uint256 currentValidationRes = _execUserOpValidation(userOpValidationFunction, userOp, userOpHash);

            if (preUserOpValidationHooks.length != 0) {
                // If we have other validation data we need to coalesce with
                validationRes = _coalesceValidation(validationRes, currentValidationRes);
            } else {
                validationRes = currentValidationRes;
            }
        }

        return validationRes;
    }

    function _doRuntimeValidation(
        ModuleEntity runtimeValidationFunction,
        bytes calldata callData,
        bytes calldata authorizationData
    ) internal {
        // Set up the per-hook data tracking fields
        bytes calldata authSegment;
        (authSegment, authorizationData) = authorizationData.getNextSegment();

        // run all preRuntimeValidation hooks
        ModuleEntity[] memory preRuntimeValidationHooks =
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

        if (authSegment.getIndex() != RESERVED_VALIDATION_DATA_INDEX) {
            revert ValidationSignatureSegmentMissing();
        }

        _execRuntimeValidation(runtimeValidationFunction, callData, authSegment.getBody());
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
            HookConfig hookConfig = toHookConfig(executionHooks.at(i));
            if (hookConfig.hasPostHook()) {
                postHooksToRun[i].postExecHook = hookConfig.moduleEntity();
            }
        }

        // Run the pre hooks and copy their return data to the post hooks array, if an associated post-exec hook
        // exists.
        for (uint256 i = 0; i < hooksLength; ++i) {
            HookConfig hookConfig = toHookConfig(executionHooks.at(i));

            if (hookConfig.hasPreHook()) {
                bytes memory preExecHookReturnData;

                preExecHookReturnData = _runPreExecHook(hookConfig.moduleEntity(), data);

                // If there is an associated post-exec hook, save the return data.
                if (hookConfig.hasPostHook()) {
                    postHooksToRun[i].preExecHookReturnData = preExecHookReturnData;
                }
            }
        }
    }

    function _runPreExecHook(ModuleEntity preExecHook, bytes memory data)
        internal
        returns (bytes memory preExecHookReturnData)
    {
        (address module, uint32 entityId) = preExecHook.unpack();
        try IExecutionHookModule(module).preExecutionHook(entityId, msg.sender, msg.value, data) returns (
            bytes memory returnData
        ) {
            preExecHookReturnData = returnData;
        } catch (bytes memory revertReason) {
            // TODO: same issue with EP0.6 - we can't do bytes4 error codes in modules
            revert PreExecHookReverted(module, entityId, revertReason);
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

            (address module, uint32 entityId) = postHookToRun.postExecHook.unpack();
            // solhint-disable-next-line no-empty-blocks
            try IExecutionHookModule(module).postExecutionHook(entityId, postHookToRun.preExecHookReturnData) {}
            catch (bytes memory revertReason) {
                revert PostExecHookReverted(module, entityId, revertReason);
            }
        }
    }

    function _doPreRuntimeValidationHook(
        ModuleEntity validationHook,
        bytes memory callData,
        bytes memory currentAuthData
    ) internal {
        (address hookModule, uint32 hookEntityId) = validationHook.unpack();
        try IValidationHookModule(hookModule).preRuntimeValidationHook(
            hookEntityId, msg.sender, msg.value, callData, currentAuthData
        )
        // forgefmt: disable-start
        // solhint-disable-next-line no-empty-blocks
        {} catch (bytes memory revertReason){
        // forgefmt: disable-end
            revert PreRuntimeValidationHookFailed(hookModule, hookEntityId, revertReason);
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
        PostExecToRun[] memory postPermissionHooks;

        // We only need to handle permission hooks when the sender is not the entry point or the account itself,
        // and the selector isn't public.
        if (
            msg.sender != address(_ENTRY_POINT) && msg.sender != address(this)
                && !_storage.executionData[msg.sig].isPublic
        ) {
            ModuleEntity directCallValidationKey =
                ModuleEntityLib.pack(msg.sender, DIRECT_CALL_VALIDATION_ENTITYID);

            _checkIfValidationAppliesCallData(msg.data, directCallValidationKey, false);

            // Direct call is allowed, run associated permission & validation hooks

            // Validation hooks
            ModuleEntity[] memory preRuntimeValidationHooks =
                _storage.validationData[directCallValidationKey].preValidationHooks;

            uint256 hookLen = preRuntimeValidationHooks.length;
            for (uint256 i = 0; i < hookLen; ++i) {
                _doPreRuntimeValidationHook(preRuntimeValidationHooks[i], msg.data, "");
            }

            // Permission hooks
            postPermissionHooks =
                _doPreHooks(_storage.validationData[directCallValidationKey].permissionHooks, msg.data);
        }

        // Exec hooks
        PostExecToRun[] memory postExecutionHooks =
            _doPreHooks(_storage.executionData[msg.sig].executionHooks, msg.data);

        return (postPermissionHooks, postExecutionHooks);
    }

    function _execUserOpValidation(
        ModuleEntity userOpValidationFunction,
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    ) internal virtual returns (uint256) {
        (address module, uint32 entityId) = userOpValidationFunction.unpack();

        return IValidationModule(module).validateUserOp(entityId, userOp, userOpHash);
    }

    function _execRuntimeValidation(
        ModuleEntity runtimeValidationFunction,
        bytes calldata callData,
        bytes calldata authorization
    ) internal virtual {
        (address module, uint32 entityId) = runtimeValidationFunction.unpack();

        try IValidationModule(module).validateRuntime(
            address(this), entityId, msg.sender, msg.value, callData, authorization
        )
        // forgefmt: disable-start
        // solhint-disable-next-line no-empty-blocks
        {} catch (bytes memory revertReason){
        // forgefmt: disable-end
            revert RuntimeValidationFunctionReverted(module, entityId, revertReason);
        }
    }

    function _exec1271Validation(ModuleEntity sigValidation, bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        returns (bytes4)
    {
        AccountStorage storage _storage = getAccountStorage();

        (address module, uint32 entityId) = sigValidation.unpack();
        if (!_storage.validationData[sigValidation].isSignatureValidation) {
            revert SignatureValidationInvalid(module, entityId);
        }

        if (
            IValidationModule(module).validateSignature(address(this), entityId, msg.sender, hash, signature)
                == _1271_MAGIC_VALUE
        ) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID;
    }

    function _globalValidationAllowed(bytes4 selector) internal view virtual returns (bool) {
        if (
            selector == this.execute.selector || selector == this.executeBatch.selector
                || selector == this.installExecution.selector || selector == this.uninstallExecution.selector
                || selector == this.installValidation.selector || selector == this.uninstallValidation.selector
                || selector == this.upgradeToAndCall.selector
        ) {
            return true;
        }

        return getAccountStorage().executionData[selector].allowGlobalValidation;
    }

    function _isValidationGlobal(ModuleEntity validationFunction) internal view virtual returns (bool) {
        return getAccountStorage().validationData[validationFunction].isGlobal;
    }

    function _checkIfValidationAppliesCallData(
        bytes calldata callData,
        ModuleEntity validationFunction,
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
                        // Note that modules of other contracts using `executeWithAuthorization` may still
                        // independently call into this account with a different validation function, allowing
                        // composition of multiple batches.
                        revert SelfCallRecursionDepthExceeded();
                    }

                    _checkIfValidationAppliesSelector(nestedSelector, validationFunction, isGlobal);
                }
            }
        }
    }

    function _checkIfValidationAppliesSelector(bytes4 selector, ModuleEntity validationFunction, bool isGlobal)
        internal
        view
    {
        // Check that the provided validation function is applicable to the selector
        if (isGlobal) {
            if (_globalValidationAllowed(selector) && _isValidationGlobal(validationFunction)) {
                return;
            }
            revert ValidationFunctionMissing(selector);
        } else {
            // Not global validation, but per-selector
            if (!getAccountStorage().validationData[validationFunction].selectors.contains(toSetValue(selector))) {
                revert ValidationFunctionMissing(selector);
            }
        }
    }
}
