// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {PackedPluginEntity} from "../interfaces/IPluginManager.sol";

library PackedPluginEntityLib {
    // Empty or unset PackedPluginEntity.
    PackedPluginEntity internal constant _EMPTY_PACKED_PLUGIN_ENTITY = PackedPluginEntity.wrap(bytes24(0));
    // Magic value for hooks that should always revert.
    PackedPluginEntity internal constant _PRE_HOOK_ALWAYS_DENY = PackedPluginEntity.wrap(bytes24(uint192(2)));

    function pack(address addr, uint32 entityId) internal pure returns (PackedPluginEntity) {
        return PackedPluginEntity.wrap(bytes24(bytes20(addr)) | bytes24(uint192(entityId)));
    }

    function unpack(PackedPluginEntity fr) internal pure returns (address addr, uint32 entityId) {
        bytes24 underlying = PackedPluginEntity.unwrap(fr);
        addr = address(bytes20(underlying));
        entityId = uint32(bytes4(underlying << 160));
    }

    function isEmpty(PackedPluginEntity fr) internal pure returns (bool) {
        return PackedPluginEntity.unwrap(fr) == bytes24(0);
    }

    function notEmpty(PackedPluginEntity fr) internal pure returns (bool) {
        return PackedPluginEntity.unwrap(fr) != bytes24(0);
    }

    function eq(PackedPluginEntity a, PackedPluginEntity b) internal pure returns (bool) {
        return PackedPluginEntity.unwrap(a) == PackedPluginEntity.unwrap(b);
    }

    function notEq(PackedPluginEntity a, PackedPluginEntity b) internal pure returns (bool) {
        return PackedPluginEntity.unwrap(a) != PackedPluginEntity.unwrap(b);
    }
}
