// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";

import {SingleSignerValidation} from "../../src/modules/validation/SingleSignerValidation.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";

import {OptimizedTest} from "../utils/OptimizedTest.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID} from "../utils/TestConstants.sol";

contract SingleSignerFactoryFixture is OptimizedTest {
    UpgradeableModularAccount public accountImplementation;
    SingleSignerValidation public singleSignerValidation;
    bytes32 private immutable _PROXY_BYTECODE_HASH;

    uint32 public constant UNSTAKE_DELAY = 1 weeks;

    IEntryPoint public entryPoint;

    address public self;

    constructor(IEntryPoint _entryPoint, SingleSignerValidation _singleSignerValidation) {
        entryPoint = _entryPoint;
        accountImplementation = _deployUpgradeableModularAccount(_entryPoint);
        _PROXY_BYTECODE_HASH =
            keccak256(abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(address(accountImplementation), "")));
        singleSignerValidation = _singleSignerValidation;
        self = address(this);
    }

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during user operation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
     * account creation
     */
    function createAccount(address owner, uint256 salt) public returns (UpgradeableModularAccount) {
        // address addr = Create2.computeAddress(getSalt(owner, salt), _PROXY_BYTECODE_HASH);
        address addr = getAddress(owner, salt);

        // short circuit if exists
        if (addr.code.length == 0) {
            LibClone.createDeterministicERC1967(
                address(accountImplementation), _getImmutableArgs(owner), getSalt(owner, salt)
            );
        }

        return UpgradeableModularAccount(payable(addr));
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(address owner, uint256 salt) public view returns (address) {
        // return Create2.computeAddress(getSalt(owner, salt), _PROXY_BYTECODE_HASH);
        return LibClone.predictDeterministicAddressERC1967(
            address(accountImplementation), _getImmutableArgs(owner), getSalt(owner, salt), address(this)
        );
    }

    function addStake() external payable {
        entryPoint.addStake{value: msg.value}(UNSTAKE_DELAY);
    }

    function getSalt(address owner, uint256 salt) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt));
    }

    function _getImmutableArgs(address owner) private view returns (bytes memory) {
        return abi.encodePacked(
            ModuleEntityLib.pack(address(singleSignerValidation), TEST_DEFAULT_VALIDATION_ENTITY_ID), owner
        );
    }
}
