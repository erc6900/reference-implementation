// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {ModuleMetadata} from "../../interfaces/IModule.sol";

import {Call, IStandardExecutor} from "../../interfaces/IStandardExecutor.sol";
import {IValidationHook} from "../../interfaces/IValidationHook.sol";
import {BaseModule} from "../../modules/BaseModule.sol";

contract AllowlistModule is IValidationHook, BaseModule {
    struct AllowlistInit {
        address target;
        bool hasSelectorAllowlist;
        bytes4[] selectors;
    }

    struct AllowlistEntry {
        bool allowed;
        bool hasSelectorAllowlist;
    }

    mapping(uint32 entityId => mapping(address target => mapping(address account => AllowlistEntry))) public
        targetAllowlist;
    mapping(
        uint32 entityId => mapping(address target => mapping(bytes4 selector => mapping(address account => bool)))
    ) public selectorAllowlist;

    error TargetNotAllowed();
    error SelectorNotAllowed();
    error NoSelectorSpecified();

    function onInstall(bytes calldata data) external override {
        (uint32 entityId, AllowlistInit[] memory init) = abi.decode(data, (uint32, AllowlistInit[]));

        for (uint256 i = 0; i < init.length; i++) {
            targetAllowlist[entityId][init[i].target][msg.sender] =
                AllowlistEntry(true, init[i].hasSelectorAllowlist);

            if (init[i].hasSelectorAllowlist) {
                for (uint256 j = 0; j < init[i].selectors.length; j++) {
                    selectorAllowlist[entityId][init[i].target][init[i].selectors[j]][msg.sender] = true;
                }
            }
        }
    }

    function onUninstall(bytes calldata data) external override {
        (uint32 entityId, AllowlistInit[] memory init) = abi.decode(data, (uint32, AllowlistInit[]));

        for (uint256 i = 0; i < init.length; i++) {
            delete targetAllowlist[entityId][init[i].target][msg.sender];

            if (init[i].hasSelectorAllowlist) {
                for (uint256 j = 0; j < init[i].selectors.length; j++) {
                    delete selectorAllowlist[entityId][init[i].target][init[i].selectors[j]][msg.sender];
                }
            }
        }
    }

    function setAllowlistTarget(uint32 entityId, address target, bool allowed, bool hasSelectorAllowlist)
        external
    {
        targetAllowlist[entityId][target][msg.sender] = AllowlistEntry(allowed, hasSelectorAllowlist);
    }

    function setAllowlistSelector(uint32 entityId, address target, bytes4 selector, bool allowed) external {
        selectorAllowlist[entityId][target][selector][msg.sender] = allowed;
    }

    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        returns (uint256)
    {
        checkAllowlistCalldata(entityId, userOp.callData);
        return 0;
    }

    function preRuntimeValidationHook(uint32 entityId, address, uint256, bytes calldata data, bytes calldata)
        external
        view
        override
    {
        checkAllowlistCalldata(entityId, data);
        return;
    }

    function moduleMetadata() external pure override returns (ModuleMetadata memory) {
        ModuleMetadata memory metadata;
        metadata.name = "Allowlist Module";
        metadata.version = "v0.0.1";
        metadata.author = "ERC-6900 Working Group";

        return metadata;
    }

    function checkAllowlistCalldata(uint32 entityId, bytes calldata callData) public view {
        if (bytes4(callData[:4]) == IStandardExecutor.execute.selector) {
            (address target,, bytes memory data) = abi.decode(callData[4:], (address, uint256, bytes));
            _checkCallPermission(entityId, msg.sender, target, data);
        } else if (bytes4(callData[:4]) == IStandardExecutor.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData[4:], (Call[]));

            for (uint256 i = 0; i < calls.length; i++) {
                _checkCallPermission(entityId, msg.sender, calls[i].target, calls[i].data);
            }
        }
    }

    function _checkCallPermission(uint32 entityId, address account, address target, bytes memory data)
        internal
        view
    {
        AllowlistEntry storage entry = targetAllowlist[entityId][target][account];
        (bool allowed, bool hasSelectorAllowlist) = (entry.allowed, entry.hasSelectorAllowlist);

        if (!allowed) {
            revert TargetNotAllowed();
        }

        if (hasSelectorAllowlist) {
            if (data.length < 4) {
                revert NoSelectorSpecified();
            }

            bytes4 selector = bytes4(data);

            if (!selectorAllowlist[entityId][target][selector][account]) {
                revert SelectorNotAllowed();
            }
        }
    }
}
