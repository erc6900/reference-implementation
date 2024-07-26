// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {ModuleMetadata} from "../../../src/interfaces/IModule.sol";
import {IStandardExecutor} from "../../../src/interfaces/IStandardExecutor.sol";
import {IValidationHook} from "../../../src/interfaces/IValidationHook.sol";
import {BaseModule} from "../../../src/modules/BaseModule.sol";

// A pre validaiton hook module that uses per-hook data.
// This example enforces that the target of an `execute` call must only be the previously specified address.
// This is just a mock - it does not enforce this over `executeBatch` and other methods of making calls, and should
// not be used in production..
contract MockAccessControlHookModule is IValidationHook, BaseModule {
    enum EntityId {
        PRE_VALIDATION_HOOK
    }

    mapping(address account => address allowedTarget) public allowedTargets;

    function onInstall(bytes calldata data) external override {
        address allowedTarget = abi.decode(data, (address));
        allowedTargets[msg.sender] = allowedTarget;
    }

    function onUninstall(bytes calldata) external override {
        delete allowedTargets[msg.sender];
    }

    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        returns (uint256)
    {
        if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK)) {
            if (bytes4(userOp.callData[:4]) == IStandardExecutor.execute.selector) {
                address target = abi.decode(userOp.callData[4:36], (address));

                // Simulate a merkle proof - require that the target address is also provided in the signature
                address proof = address(bytes20(userOp.signature));
                require(proof == target, "Proof doesn't match target");
                require(target == allowedTargets[msg.sender], "Target not allowed");
                return 0;
            }
        }
        revert NotImplemented();
    }

    function preRuntimeValidationHook(
        uint32 entityId,
        address,
        uint256,
        bytes calldata data,
        bytes calldata authorization
    ) external view override {
        if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK)) {
            if (bytes4(data[:4]) == IStandardExecutor.execute.selector) {
                address target = abi.decode(data[4:36], (address));

                // Simulate a merkle proof - require that the target address is also provided in the authorization
                // data
                address proof = address(bytes20(authorization));
                require(proof == target, "Proof doesn't match target");
                require(target == allowedTargets[msg.sender], "Target not allowed");

                return;
            }
        }

        revert NotImplemented();
    }

    function moduleMetadata() external pure override returns (ModuleMetadata memory) {}
}
