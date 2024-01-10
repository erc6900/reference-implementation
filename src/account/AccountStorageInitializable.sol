// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {AccountStorage, getAccountStorage} from "./AccountStorage.sol";

abstract contract AccountStorageInitializable {
    error AlreadyInitialized();
    error AlreadyInitializing();

    /// @notice Modifier to put on function intended to be called only once per implementation
    /// @dev Reverts if the contract has already been initialized
    modifier initializer() {
        AccountStorage storage _storage = getAccountStorage();
        bool isTopLevelCall = !_storage.initializing;
        if (
            isTopLevelCall && _storage.initialized < 1
                || !Address.isContract(address(this)) && _storage.initialized == 1
        ) {
            _storage.initialized = 1;
            if (isTopLevelCall) {
                _storage.initializing = true;
            }
            _;
            if (isTopLevelCall) {
                _storage.initializing = false;
            }
        } else {
            revert AlreadyInitialized();
        }
    }

    /// @notice Internal function to disable calls to initialization functions
    /// @dev Reverts if the contract has already been initialized
    function _disableInitializers() internal virtual {
        AccountStorage storage _storage = getAccountStorage();
        if (_storage.initializing) {
            revert AlreadyInitializing();
        }
        if (_storage.initialized != type(uint8).max) {
            _storage.initialized = type(uint8).max;
        }
    }
}
