// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";

import {OptimizedTest} from "../utils/OptimizedTest.sol";

/**
 * @title MSCAFactoryFixture
 * @dev a factory that initializes UpgradeableModularAccounts with a single plugin, SingleOwnerPlugin
 * intended for unit tests and local development, not for production.
 */
contract MSCAFactoryFixture is OptimizedTest {
    UpgradeableModularAccount public accountImplementation;
    SingleOwnerPlugin public singleOwnerPlugin;
    bytes32 private immutable _PROXY_BYTECODE_HASH;

    uint32 public constant UNSTAKE_DELAY = 1 weeks;

    IEntryPoint public entryPoint;

    address public self;

    bytes32 public singleOwnerPluginManifestHash;

    constructor(IEntryPoint _entryPoint, SingleOwnerPlugin _singleOwnerPlugin) {
        entryPoint = _entryPoint;
        accountImplementation = _deployUpgradeableModularAccount(_entryPoint);
        _PROXY_BYTECODE_HASH = keccak256(
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(address(accountImplementation), ""))
        );
        singleOwnerPlugin = _singleOwnerPlugin;
        self = address(this);
        // The manifest hash is set this way in this factory just for testing purposes.
        // For production factories the manifest hashes should be passed as a constructor argument.
        singleOwnerPluginManifestHash = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
    }

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
     * account creation
     */
    function createAccount(address owner, uint256 salt) public returns (UpgradeableModularAccount) {
        address addr = Create2.computeAddress(getSalt(owner, salt), _PROXY_BYTECODE_HASH);

        // short circuit if exists
        if (addr.code.length == 0) {
            address[] memory plugins = new address[](1);
            plugins[0] = address(singleOwnerPlugin);
            bytes32[] memory pluginManifestHashes = new bytes32[](1);
            pluginManifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
            bytes[] memory pluginInstallData = new bytes[](1);
            pluginInstallData[0] = abi.encode(owner);
            // not necessary to check return addr since next call will fail if so
            new ERC1967Proxy{salt: getSalt(owner, salt)}(address(accountImplementation), "");

            // point proxy to actual implementation and init plugins
            UpgradeableModularAccount(payable(addr)).initialize(plugins, pluginManifestHashes, pluginInstallData);
        }

        return UpgradeableModularAccount(payable(addr));
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(address owner, uint256 salt) public view returns (address) {
        return Create2.computeAddress(getSalt(owner, salt), _PROXY_BYTECODE_HASH);
    }

    function addStake() external payable {
        entryPoint.addStake{value: msg.value}(UNSTAKE_DELAY);
    }

    function getSalt(address owner, uint256 salt) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt));
    }
}
