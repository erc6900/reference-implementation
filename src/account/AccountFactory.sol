// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {Ownable} from "solady/auth/Ownable.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {UpgradeableModularAccount} from "../account/UpgradeableModularAccount.sol";
import {ValidationConfigLib} from "../helpers/ValidationConfigLib.sol";

contract AccountFactory is Ownable {
    UpgradeableModularAccount public immutable ACCOUNT_IMPL;
    uint32 public constant UNSTAKE_DELAY = 1 weeks;
    IEntryPoint public immutable ENTRY_POINT;
    address public immutable SINGLE_SIGNER_VALIDATION;

    constructor(
        IEntryPoint _entryPoint,
        UpgradeableModularAccount _accountImpl,
        address _singleSignerValidation,
        address owner
    ) {
        _initializeOwner(owner);
        ENTRY_POINT = _entryPoint;
        ACCOUNT_IMPL = _accountImpl;
        SINGLE_SIGNER_VALIDATION = _singleSignerValidation;
    }

    /**
     * Create an account, and return its address.
     * Returns the address even if the account is already deployed.
     * Note that during user operation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
     * account creation
     */
    function createAccount(address owner, uint256 salt, uint32 entityId)
        external
        returns (UpgradeableModularAccount)
    {
        bytes32 combinedSalt = getSalt(owner, salt, entityId);
        address addr =
            LibClone.predictDeterministicAddressERC1967(address(ACCOUNT_IMPL), combinedSalt, address(this));
        // short circuit if exists
        if (addr.code.length == 0) {
            bytes memory pluginInstallData = abi.encode(entityId, owner);
            // not necessary to check return addr since next call will fail if so
            LibClone.deployDeterministicERC1967(address(ACCOUNT_IMPL), combinedSalt);
            // point proxy to actual implementation and init plugins
            UpgradeableModularAccount(payable(addr)).initializeWithValidation(
                ValidationConfigLib.pack(SINGLE_SIGNER_VALIDATION, entityId, true, true),
                new bytes4[](0),
                pluginInstallData,
                new bytes[](0)
            );
        }

        return UpgradeableModularAccount(payable(addr));
    }

    function addStake() external payable onlyOwner {
        ENTRY_POINT.addStake{value: msg.value}(UNSTAKE_DELAY);
    }

    function unlockStake() external onlyOwner {
        ENTRY_POINT.unlockStake();
    }

    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        ENTRY_POINT.withdrawStake(withdrawAddress);
    }

    /**
     * Calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(address owner, uint256 salt, uint32 entityId) external view returns (address) {
        return LibClone.predictDeterministicAddressERC1967(
            address(ACCOUNT_IMPL), getSalt(owner, salt, entityId), address(this)
        );
    }

    function getSalt(address owner, uint256 salt, uint32 entityId) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt, entityId));
    }
}
