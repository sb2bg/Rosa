#pragma once

#include "x86/Flags.h"
#include "x86/Registers.h"

#include <bit>
#include <cstdint>

namespace rosa::dbt::runtime {

// Shared width-parametric flag semantics, inlined into register and memory helpers.
template <typename Value>
x86::X86State *updateIncFlags(x86::X86State *state, std::uint64_t originalValue,
                              std::uint64_t resultValue) {
    const auto original = static_cast<Value>(originalValue);
    const auto result = static_cast<Value>(resultValue);
    auto flags = (state->rflags & ~(x86::arithmeticFlagMask & ~x86::flagCarry)) | x86::flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= x86::flagParity;
    }
    if (((original ^ Value{1} ^ result) & Value{0x10}) != 0) {
        flags |= x86::flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= x86::flagZero;
    }
    constexpr auto signBit = static_cast<Value>(Value{1} << (sizeof(Value) * 8U - 1U));
    if ((result & signBit) != 0) {
        flags |= x86::flagSign;
    }
    if (original == static_cast<Value>(signBit - 1U)) {
        flags |= x86::flagOverflow;
    }
    state->rflags = flags;
    return state;
}

template <typename Value>
x86::X86State *updateDecFlags(x86::X86State *state, std::uint64_t originalValue,
                              std::uint64_t resultValue) {
    const auto original = static_cast<Value>(originalValue);
    const auto result = static_cast<Value>(resultValue);
    auto flags = (state->rflags & ~(x86::arithmeticFlagMask & ~x86::flagCarry)) | x86::flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= x86::flagParity;
    }
    if (((original ^ Value{1} ^ result) & Value{0x10}) != 0) {
        flags |= x86::flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= x86::flagZero;
    }
    constexpr auto signBit = static_cast<Value>(Value{1} << (sizeof(Value) * 8U - 1U));
    if ((result & signBit) != 0) {
        flags |= x86::flagSign;
    }
    if (original == signBit) {
        flags |= x86::flagOverflow;
    }
    state->rflags = flags;
    return state;
}

} // namespace rosa::dbt::runtime
