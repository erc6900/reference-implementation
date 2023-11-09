// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

interface ITokenSessionKeyPlugin {
    error NotAuthorized();

    /// @notice Route call to executeFromPluginExternal at the MSCA.
    /// @dev This function will call with value = 0, since sending ether 
    /// for ERC20 contract is not a normal case.
    /// @param target The target address to execute the call on.
    /// @param data The call data to execute.
    function routeCallToExecuteFromPluginExternal(
        address target,
        bytes memory data    
    ) external returns (bytes memory returnData);
}