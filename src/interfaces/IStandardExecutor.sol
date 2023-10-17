// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Execution} from "../libraries/ERC6900TypeUtils.sol";

interface IStandardExecutor {
    /// @notice Standard execute method.
    /// @dev If the target is a plugin, the call SHOULD revert.
    /// @param execution The execution information.
    /// @return The return data from the call.
    function execute(Execution calldata execution) external payable returns (bytes memory);

    /// @notice Standard executeBatch method.
    /// @dev If the target is a plugin, the call SHOULD revert.
    /// @param executions The array of executions.
    /// @return An array containing the return data from the calls.
    function executeBatch(Execution[] calldata executions) external payable returns (bytes[] memory);
}
