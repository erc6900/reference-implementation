// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

interface ITokenSessionKeyPlugin {
    error NotAuthorized();

    /// @notice Route call to executeFromPluginExternal at the MSCA.
    /// @dev This function will call with value = 0, since sending ether
    /// to ERC20 contract is not a normal case.
    /// @param target The target address to execute the call on.
    /// @param from The address to transfer tokens from.
    /// @param to The address to transfer tokens to.
    /// @param amount The amount of tokens to transfer.
    function transferFromSessionKey(address target, address from, address to, uint256 amount)
        external
        returns (bytes memory returnData);
}
