// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {UpgradeableModularAccount} from "../account/UpgradeableModularAccount.sol";
import {ValidationConfigLib} from "../helpers/ValidationConfigLib.sol";
import {LibClone} from "solady/utils/LibClone.sol";

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
    ) Ownable(owner) {
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
        bytes32 fullSalt = getSalt(owner, salt, entityId);
        bytes memory immutables = _getImmutableArgs(owner, entityId);

        address addr = getAddress(immutables, fullSalt);
        // short circuit if exists
        if (addr.code.length == 0) {
            LibClone.createDeterministicERC1967(address(ACCOUNT_IMPL), immutables, fullSalt);
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
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(bytes memory immutables, bytes32 salt) public view returns (address) {
        return LibClone.predictDeterministicAddressERC1967(address(ACCOUNT_IMPL), immutables, salt, address(this));
    }

    function getSalt(address owner, uint256 salt, uint32 entityId) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt, entityId));
    }

    function _getImmutableArgs(address owner, uint32 entityId) private view returns (bytes memory) {
        return abi.encodePacked(ModuleEntityLib.pack(address(SINGLE_SIGNER_VALIDATION), entityId), owner);
    }
}
