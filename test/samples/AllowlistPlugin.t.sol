// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {Call} from "../../src/interfaces/IStandardExecutor.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {AllowlistPlugin} from "../../src/samples/permissionhooks/AllowlistPlugin.sol";

import {CustomValidationTestBase} from "../utils/CustomValidationTestBase.sol";
import {Counter} from "../mocks/Counter.sol";

contract AllowlistPluginTest is CustomValidationTestBase {
    AllowlistPlugin public allowlistPlugin;

    AllowlistPlugin.AllowlistInit[] public allowlistInit;

    Counter[] public counters;

    function setUp() public {
        allowlistPlugin = new AllowlistPlugin();

        counters = new Counter[](10);

        for (uint256 i = 0; i < counters.length; i++) {
            counters[i] = new Counter();
        }

        // Don't call `_customValidationSetup` here, as we want to test various configurations of install data.
    }

    function testFuzz_allowlistHook_userOp_single(uint256 seed) public {
        AllowlistPlugin.AllowlistInit[] memory inits;
        (inits, seed) = _generateRandomizedAllowlistInit(seed);

        _copyInitToStorage(inits);
        _customValidationSetup();

        Call[] memory calls = new Call[](1);
        (calls[0], seed) = _generateRandomCall(seed);
        bytes memory expectedError = _getExpectedUserOpError(calls);

        _runExecUserOp(calls[0].target, calls[0].data, expectedError);
    }

    function testFuzz_allowlistHook_userOp_batch(uint256 seed) public {
        AllowlistPlugin.AllowlistInit[] memory inits;
        (inits, seed) = _generateRandomizedAllowlistInit(seed);

        _copyInitToStorage(inits);
        _customValidationSetup();

        Call[] memory calls;
        (calls, seed) = _generateRandomCalls(seed);
        bytes memory expectedError = _getExpectedUserOpError(calls);

        _runExecBatchUserOp(calls, expectedError);
    }

    function testFuzz_allowlistHook_runtime_single(uint256 seed) public {
        AllowlistPlugin.AllowlistInit[] memory inits;
        (inits, seed) = _generateRandomizedAllowlistInit(seed);

        _copyInitToStorage(inits);
        _customValidationSetup();

        Call[] memory calls = new Call[](1);
        (calls[0], seed) = _generateRandomCall(seed);
        bytes memory expectedError = _getExpectedRuntimeError(calls);

        if (keccak256(expectedError) == keccak256("emptyrevert")) {
            _runtimeExecExpFail(calls[0].target, calls[0].data, "");
        } else {
            _runtimeExec(calls[0].target, calls[0].data, expectedError);
        }
    }

    function testFuzz_allowlistHook_runtime_batch(uint256 seed) public {
        AllowlistPlugin.AllowlistInit[] memory inits;
        (inits, seed) = _generateRandomizedAllowlistInit(seed);

        _copyInitToStorage(inits);
        _customValidationSetup();

        Call[] memory calls;
        (calls, seed) = _generateRandomCalls(seed);
        bytes memory expectedError = _getExpectedRuntimeError(calls);

        if (keccak256(expectedError) == keccak256("emptyrevert")) {
            _runtimeExecBatchExpFail(calls, "");
        } else {
            _runtimeExecBatch(calls, expectedError);
        }
    }

    function _generateRandomCalls(uint256 seed) internal view returns (Call[] memory, uint256) {
        uint256 length = seed % 10;
        seed = _next(seed);

        Call[] memory calls = new Call[](length);

        for (uint256 i = 0; i < length; i++) {
            (calls[i], seed) = _generateRandomCall(seed);
        }

        return (calls, seed);
    }

    function _generateRandomCall(uint256 seed) internal view returns (Call memory call, uint256 newSeed) {
        // Half of the time, the target is a random counter, the other half, it's a random address.
        bool isCounter = seed % 2 == 0;
        seed = _next(seed);

        call.target = isCounter ? address(counters[seed % counters.length]) : address(uint160(uint256(seed)));
        seed = _next(seed);

        bool validSelector = seed % 2 == 0;
        seed = _next(seed);

        if (validSelector) {
            uint256 selectorIndex = seed % 3;
            seed = _next(seed);

            if (selectorIndex == 0) {
                call.data = abi.encodeCall(Counter.setNumber, (seed % 100));
            } else if (selectorIndex == 1) {
                call.data = abi.encodeCall(Counter.increment, ());
            } else {
                call.data = abi.encodeWithSignature("number()");
            }

            seed = _next(seed);
        } else {
            call.data = abi.encodePacked(bytes4(uint32(uint256(seed))));
            seed = _next(seed);
        }

        return (call, seed);
    }

    function _getExpectedUserOpError(Call[] memory calls) internal view returns (bytes memory) {
        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];

            (bool allowed, bool hasSelectorAllowlist) =
                allowlistPlugin.targetAllowlist(call.target, address(account1));
            if (allowed) {
                if (
                    hasSelectorAllowlist
                        && !allowlistPlugin.selectorAllowlist(call.target, bytes4(call.data), address(account1))
                ) {
                    return abi.encodeWithSelector(
                        IEntryPoint.FailedOpWithRevert.selector,
                        0,
                        "AA23 reverted",
                        abi.encodeWithSelector(AllowlistPlugin.SelectorNotAllowed.selector)
                    );
                }
            } else {
                return abi.encodeWithSelector(
                    IEntryPoint.FailedOpWithRevert.selector,
                    0,
                    "AA23 reverted",
                    abi.encodeWithSelector(AllowlistPlugin.TargetNotAllowed.selector)
                );
            }
        }

        return "";
    }

    function _getExpectedRuntimeError(Call[] memory calls) internal view returns (bytes memory) {
        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];

            (bool allowed, bool hasSelectorAllowlist) =
                allowlistPlugin.targetAllowlist(call.target, address(account1));
            if (allowed) {
                if (
                    hasSelectorAllowlist
                        && !allowlistPlugin.selectorAllowlist(call.target, bytes4(call.data), address(account1))
                ) {
                    return abi.encodeWithSelector(
                        UpgradeableModularAccount.PreRuntimeValidationHookFailed.selector,
                        address(allowlistPlugin),
                        uint8(AllowlistPlugin.FunctionId.PRE_VALIDATION_HOOK),
                        abi.encodeWithSelector(AllowlistPlugin.SelectorNotAllowed.selector)
                    );
                }
            } else {
                return abi.encodeWithSelector(
                    UpgradeableModularAccount.PreRuntimeValidationHookFailed.selector,
                    address(allowlistPlugin),
                    uint8(AllowlistPlugin.FunctionId.PRE_VALIDATION_HOOK),
                    abi.encodeWithSelector(AllowlistPlugin.TargetNotAllowed.selector)
                );
            }
        }

        // At this point, we have returned any error that would come from the AllowlistPlugin.
        // But, because this is in the runtime path, the Counter itself may throw if it is not a valid selector.

        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];
            bytes4 selector = bytes4(call.data);

            if (
                selector != Counter.setNumber.selector && selector != Counter.increment.selector
                    && selector != bytes4(abi.encodeWithSignature("number()"))
            ) {
                //todo: better define a way to handle empty reverts.
                return "emptyrevert";
            }
        }

        return "";
    }

    function _generateRandomizedAllowlistInit(uint256 seed)
        internal
        view
        returns (AllowlistPlugin.AllowlistInit[] memory, uint256)
    {
        uint256 length = seed % 10;
        seed = _next(seed);

        AllowlistPlugin.AllowlistInit[] memory init = new AllowlistPlugin.AllowlistInit[](length);

        for (uint256 i = 0; i < length; i++) {
            // Half the time, the target is a random counter, the other half, it's a random address.
            bool isCounter = seed % 2 == 0;
            seed = _next(seed);

            address target =
                isCounter ? address(counters[seed % counters.length]) : address(uint160(uint256(seed)));

            bool hasSelectorAllowlist = seed % 2 == 0;
            seed = _next(seed);

            uint256 selectorLength = seed % 10;
            seed = _next(seed);

            bytes4[] memory selectors = new bytes4[](selectorLength);

            for (uint256 j = 0; j < selectorLength; j++) {
                // half of the time, the selector is a valid selector on counter, the other half it's a random
                // selector

                bool isCounterSelector = seed % 2 == 0;
                seed = _next(seed);

                if (isCounterSelector) {
                    uint256 selectorIndex = seed % 3;
                    seed = _next(seed);

                    if (selectorIndex == 0) {
                        selectors[j] = Counter.setNumber.selector;
                    } else if (selectorIndex == 1) {
                        selectors[j] = Counter.increment.selector;
                    } else {
                        selectors[j] = bytes4(abi.encodeWithSignature("number()"));
                    }
                } else {
                    selectors[j] = bytes4(uint32(uint256(seed)));
                    seed = _next(seed);
                }

                selectors[j] = bytes4(uint32(uint256(keccak256(abi.encodePacked(seed, j)))));
                seed = _next(seed);
            }

            init[i] = AllowlistPlugin.AllowlistInit(target, hasSelectorAllowlist, selectors);
        }

        return (init, seed);
    }

    // todo: runtime paths

    // fuzz targets, fuzz target selectors.

    // Maybe pull out the helper function for running user ops and possibly expect a failure?

    function _next(uint256 seed) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(seed)));
    }

    function _initialValidationConfig()
        internal
        virtual
        override
        returns (FunctionReference, bool, bytes4[] memory, bytes memory, bytes memory, bytes memory)
    {
        FunctionReference accessControlHook = FunctionReferenceLib.pack(
            address(allowlistPlugin), uint8(AllowlistPlugin.FunctionId.PRE_VALIDATION_HOOK)
        );

        FunctionReference[] memory preValidationHooks = new FunctionReference[](1);
        preValidationHooks[0] = accessControlHook;

        bytes[] memory preValidationHookData = new bytes[](1);
        // Access control is restricted to only the counter
        preValidationHookData[0] = abi.encode(allowlistInit);

        bytes memory packedPreValidationHooks = abi.encode(preValidationHooks, preValidationHookData);

        return (_ownerValidation, true, new bytes4[](0), abi.encode(owner1), packedPreValidationHooks, "");
    }

    // Unfortunately, this is a feature that solidity has only implemented in via-ir, so we need to do it manually
    // to be able to run the tests in lite mode.
    function _copyInitToStorage(AllowlistPlugin.AllowlistInit[] memory init) internal {
        for (uint256 i = 0; i < init.length; i++) {
            allowlistInit.push(init[i]);
        }
    }
}
