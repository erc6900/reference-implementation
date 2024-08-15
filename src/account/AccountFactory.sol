// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {UpgradeableModularAccount} from "../account/UpgradeableModularAccount.sol";
import {ValidationConfigLib} from "../helpers/ValidationConfigLib.sol";

contract AccountFactory is Ownable {
    UpgradeableModularAccount public immutable ACCOUNT_IMPL;
    bytes32 private immutable _PROXY_BYTECODE_HASH;
    IEntryPoint public immutable ENTRY_POINT;
    address public immutable SINGLE_SIGNER_VALIDATION_MODULE;

    event ModularAccountDeployed(address indexed account, address indexed owner, uint256 salt);

    constructor(
        IEntryPoint _entryPoint,
        UpgradeableModularAccount _accountImpl,
        address _singleSignerValidationModule,
        address owner
    ) Ownable(owner) {
        ENTRY_POINT = _entryPoint;
        _PROXY_BYTECODE_HASH =
            keccak256(abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(address(_accountImpl), "")));
        ACCOUNT_IMPL = _accountImpl;
        SINGLE_SIGNER_VALIDATION_MODULE = _singleSignerValidationModule;
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
        address addr = Create2.computeAddress(combinedSalt, _PROXY_BYTECODE_HASH);

        // short circuit if exists
        if (addr.code.length == 0) {
            bytes memory pluginInstallData = abi.encode(entityId, owner);
            // not necessary to check return addr since next call will fail if so
            new ERC1967Proxy{salt: combinedSalt}(address(ACCOUNT_IMPL), "");
            // point proxy to actual implementation and init plugins
            UpgradeableModularAccount(payable(addr)).initializeWithValidation(
                ValidationConfigLib.pack(SINGLE_SIGNER_VALIDATION_MODULE, entityId, true, true),
                new bytes4[](0),
                pluginInstallData,
                new bytes[](0)
            );
            emit ModularAccountDeployed(addr, owner, salt);
        }

        return UpgradeableModularAccount(payable(addr));
    }

    function addStake(uint32 unstakeDelay) external payable onlyOwner {
        ENTRY_POINT.addStake{value: msg.value}(unstakeDelay);
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
        return Create2.computeAddress(getSalt(owner, salt, entityId), _PROXY_BYTECODE_HASH);
    }

    function getSalt(address owner, uint256 salt, uint32 entityId) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt, entityId));
    }
}
