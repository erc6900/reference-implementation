// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

import {OptimizedTest} from "../utils/OptimizedTest.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID} from "../utils/TestConstants.sol";

import {LibClone} from "solady/utils/LibClone.sol";

contract SingleSignerFactoryFixture is OptimizedTest {
    UpgradeableModularAccount public accountImplementation;
    SingleSignerValidationModule public singleSignerValidationModule;
    bytes32 private immutable _PROXY_BYTECODE_HASH;

    uint32 public constant UNSTAKE_DELAY = 1 weeks;

    IEntryPoint public entryPoint;

    address public self;

    constructor(IEntryPoint _entryPoint, SingleSignerValidationModule _singleSignerValidationModule) {
        entryPoint = _entryPoint;
        accountImplementation = _deployUpgradeableModularAccount(_entryPoint);
        _PROXY_BYTECODE_HASH = keccak256(
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(address(accountImplementation), ""))
        );
        singleSignerValidationModule = _singleSignerValidationModule;
        self = address(this);
    }

    // TODO: Make createAccount use createAccountFallbackSigner for testing

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during user operation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
     * account creation
     */
    function createAccount(address owner, uint256 salt) public returns (UpgradeableModularAccount) {
        address addr = Create2.computeAddress(getSalt(owner, salt), _PROXY_BYTECODE_HASH);

        // short circuit if exists
        if (addr.code.length == 0) {
            bytes memory moduleInstallData = abi.encode(TEST_DEFAULT_VALIDATION_ENTITY_ID, owner);
            // not necessary to check return addr since next call will fail if so
            new ERC1967Proxy{salt: getSalt(owner, salt)}(address(accountImplementation), "");

            // point proxy to actual implementation and init modules
            UpgradeableModularAccount(payable(addr)).initializeWithValidation(
                ValidationConfigLib.pack(
                    address(singleSignerValidationModule), TEST_DEFAULT_VALIDATION_ENTITY_ID, true, true
                ),
                new bytes4[](0),
                moduleInstallData,
                new bytes[](0)
            );
        }

        return UpgradeableModularAccount(payable(addr));
    }

    function createAccountWithFallbackValidation(address owner, uint256 salt)
        public
        returns (UpgradeableModularAccount)
    {
        bytes32 fullSalt = getSalt(owner, salt);

        bytes memory immutables = _getImmutableArgs(owner);

        address addr = _getAddressFallbackSigner(immutables, fullSalt);

        // short circuit if exists
        if (addr.code.length == 0) {
            // not necessary to check return addr since next call will fail if so
            // new ERC1967Proxy{salt: getSalt(owner, salt, type(uint32).max)}(address(ACCOUNT_IMPL), "");
            // UpgradeableModularAccount(payable(addr)).initialize(owner);
            LibClone.createDeterministicERC1967(address(accountImplementation), immutables, fullSalt);
        }

        return UpgradeableModularAccount(payable(addr));
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(address owner, uint256 salt) public view returns (address) {
        return Create2.computeAddress(getSalt(owner, salt), _PROXY_BYTECODE_HASH);
    }

    function getAddressFallbackSigner(address owner, uint256 salt) public view returns (address) {
        bytes32 fullSalt = getSalt(owner, salt);
        bytes memory immutables = _getImmutableArgs(owner);
        return _getAddressFallbackSigner(immutables, fullSalt);
    }

    function addStake() external payable {
        entryPoint.addStake{value: msg.value}(UNSTAKE_DELAY);
    }

    function getSalt(address owner, uint256 salt) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt));
    }

    function _getAddressFallbackSigner(bytes memory immutables, bytes32 salt) internal view returns (address) {
        return LibClone.predictDeterministicAddressERC1967(
            address(accountImplementation), immutables, salt, address(this)
        );
    }

    function _getImmutableArgs(address owner) private pure returns (bytes memory) {
        return abi.encodePacked(owner);
    }
}
