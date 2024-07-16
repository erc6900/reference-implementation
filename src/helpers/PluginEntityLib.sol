// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {PluginEntity} from "../interfaces/IPluginManager.sol";

library PluginEntityLib {
    // Magic value for hooks that should always revert.
    PluginEntity internal constant _PRE_HOOK_ALWAYS_DENY = PluginEntity.wrap(bytes24(uint192(2)));

    function pack(address addr, uint32 entityId) internal pure returns (PluginEntity) {
        return PluginEntity.wrap(bytes24(bytes20(addr)) | bytes24(uint192(entityId)));
    }

    function unpack(PluginEntity fr) internal pure returns (address addr, uint32 entityId) {
        bytes24 underlying = PluginEntity.unwrap(fr);
        addr = address(bytes20(underlying));
        entityId = uint32(bytes4(underlying << 160));
    }

    function isEmpty(PluginEntity fr) internal pure returns (bool) {
        return PluginEntity.unwrap(fr) == bytes24(0);
    }

    function notEmpty(PluginEntity fr) internal pure returns (bool) {
        return PluginEntity.unwrap(fr) != bytes24(0);
    }

    function eq(PluginEntity a, PluginEntity b) internal pure returns (bool) {
        return PluginEntity.unwrap(a) == PluginEntity.unwrap(b);
    }

    function notEq(PluginEntity a, PluginEntity b) internal pure returns (bool) {
        return PluginEntity.unwrap(a) != PluginEntity.unwrap(b);
    }
}
