// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

// Index marking the start of the data for the validation function.
uint8 constant RESERVED_VALIDATION_DATA_INDEX = 255;

// Magic value for the Entity ID of direct call validation.
uint32 constant SELF_PERMIT_VALIDATION_FUNCTIONID = type(uint32).max;
