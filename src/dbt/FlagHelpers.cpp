#include "dbt/RuntimeHelpers.h"
#include "x86/Flags.h"
#include "dbt/FlagSemantics.h"

#include <bit>
#include <cstdint>

namespace rosa::dbt::runtime {
using namespace x86;

extern "C" __attribute__((noinline)) x86::X86State *
updateAddFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs, std::uint64_t result) {
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (result < lhs) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if (((~(lhs ^ rhs) & (lhs ^ result)) >> 63U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAddFlags8(x86::X86State *state,
                                                                    std::uint64_t lhsValue,
                                                                    std::uint64_t rhsValue,
                                                                    std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto rhs = static_cast<std::uint8_t>(rhsValue);
    const auto result = static_cast<std::uint8_t>(resultValue);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint16_t>(lhs) + static_cast<std::uint16_t>(rhs) > UINT8_MAX) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x80U) != 0) {
        flags |= flagSign;
    }
    if (((~(lhs ^ rhs) & (lhs ^ result)) & 0x80U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAddFlags16(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint16_t>(lhsValue);
    const auto rhs = static_cast<std::uint16_t>(rhsValue);
    const auto result = static_cast<std::uint16_t>(resultValue);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint32_t>(lhs) + static_cast<std::uint32_t>(rhs) > UINT16_MAX) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x8000U) != 0) {
        flags |= flagSign;
    }
    if (((~(lhs ^ rhs) & (lhs ^ result)) & 0x8000U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAddFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto rhs = static_cast<std::uint32_t>(rhsValue);
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs) > UINT32_MAX) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x80000000U) != 0) {
        flags |= flagSign;
    }
    if (((~(lhs ^ rhs) & (lhs ^ result)) & 0x80000000U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAdcFlags8(x86::X86State *state,
                                                                    std::uint64_t lhsValue,
                                                                    std::uint64_t rhsValue,
                                                                    std::uint64_t carryValue) {
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto rhs = static_cast<std::uint8_t>(rhsValue);
    const auto carry = static_cast<std::uint8_t>(carryValue & 1U);
    const auto wideResult =
        static_cast<std::uint16_t>(lhs) + static_cast<std::uint16_t>(rhs) + carry;
    const auto result = static_cast<std::uint8_t>(wideResult);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (wideResult > UINT8_MAX) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if ((lhs & 0xFU) + (rhs & 0xFU) + carry > 0xFU) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x80U) != 0) {
        flags |= flagSign;
    }
    const auto signedResult = static_cast<std::int16_t>(static_cast<std::int8_t>(lhs)) +
                              static_cast<std::int16_t>(static_cast<std::int8_t>(rhs)) + carry;
    if (signedResult > INT8_MAX || signedResult < INT8_MIN) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAdcFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t carryValue) {
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto rhs = static_cast<std::uint32_t>(rhsValue);
    const auto carry = static_cast<std::uint32_t>(carryValue & 1U);
    const auto wideResult =
        static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs) + carry;
    const auto result = static_cast<std::uint32_t>(wideResult);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (wideResult > UINT32_MAX) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if ((lhs & 0xFU) + (rhs & 0xFU) + carry > 0xFU) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x80000000U) != 0) {
        flags |= flagSign;
    }
    const auto signedResult = static_cast<std::int64_t>(static_cast<std::int32_t>(lhs)) +
                              static_cast<std::int64_t>(static_cast<std::int32_t>(rhs)) + carry;
    if (signedResult > INT32_MAX || signedResult < INT32_MIN) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAdcFlags64(x86::X86State *state,
                                                                     std::uint64_t lhs,
                                                                     std::uint64_t rhs,
                                                                     std::uint64_t carryValue) {
    const auto carry = carryValue & 1U;
    const auto sum = lhs + rhs;
    const auto result = sum + carry;
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (sum < lhs || result < sum) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if ((lhs & 0xFU) + (rhs & 0xFU) + carry > 0xFU) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if (((~(lhs ^ rhs) & (lhs ^ result)) >> 63U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSbbFlags8(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t borrowValue) {
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto rhs = static_cast<std::uint8_t>(rhsValue);
    const auto borrow = static_cast<std::uint8_t>(borrowValue & 1U);
    const auto wideSubtrahend = static_cast<std::uint16_t>(rhs) + borrow;
    const auto result =
        static_cast<std::uint8_t>(static_cast<std::uint16_t>(lhs) - wideSubtrahend);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint16_t>(lhs) < wideSubtrahend) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x80U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) & 0x80U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSbbFlags16(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t borrowValue) {
    const auto lhs = static_cast<std::uint16_t>(lhsValue);
    const auto rhs = static_cast<std::uint16_t>(rhsValue);
    const auto borrow = static_cast<std::uint16_t>(borrowValue & 1U);
    const auto wideSubtrahend = static_cast<std::uint32_t>(rhs) + borrow;
    const auto result =
        static_cast<std::uint16_t>(static_cast<std::uint32_t>(lhs) - wideSubtrahend);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint32_t>(lhs) < wideSubtrahend) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x8000U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) & 0x8000U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSbbFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t borrowValue) {
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto rhs = static_cast<std::uint32_t>(rhsValue);
    const auto borrow = static_cast<std::uint32_t>(borrowValue & 1U);
    const auto wideSubtrahend = static_cast<std::uint64_t>(rhs) + borrow;
    const auto result =
        static_cast<std::uint32_t>(static_cast<std::uint64_t>(lhs) - wideSubtrahend);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint64_t>(lhs) < wideSubtrahend) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x80000000U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) & 0x80000000U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSbbFlags64(x86::X86State *state,
                                                                     std::uint64_t lhs,
                                                                     std::uint64_t rhs,
                                                                     std::uint64_t borrowValue) {
    const auto borrow = borrowValue & 1U;
    const auto subtrahend = rhs + borrow;
    const auto result = lhs - subtrahend;
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (subtrahend < rhs || lhs < subtrahend) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) >> 63U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}


extern "C" __attribute__((noinline)) x86::X86State *
updateIncFlags32(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateIncFlags<std::uint32_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateIncFlags16(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateIncFlags<std::uint16_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateIncFlags8(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateIncFlags<std::uint8_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateIncFlags64(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateIncFlags<std::uint64_t>(state, original, result);
}


extern "C" __attribute__((noinline)) x86::X86State *
updateDecFlags32(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateDecFlags<std::uint32_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateDecFlags16(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateDecFlags<std::uint16_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateDecFlags8(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateDecFlags<std::uint8_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateDecFlags64(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateDecFlags<std::uint64_t>(state, original, result);
}

extern "C" x86::X86State *updateSubFlags64(x86::X86State *state, std::uint64_t lhs,
                                           std::uint64_t rhs, std::uint64_t result);
extern "C" x86::X86State *updateSubFlags32(x86::X86State *state, std::uint64_t lhsValue,
                                           std::uint64_t rhsValue, std::uint64_t resultValue);

extern "C" __attribute__((noinline)) x86::X86State *
updateSubFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs, std::uint64_t result) {
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (lhs < rhs) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) >> 63U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSubFlags8(x86::X86State *state,
                                                                    std::uint64_t lhsValue,
                                                                    std::uint64_t rhsValue,
                                                                    std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto rhs = static_cast<std::uint8_t>(rhsValue);
    const auto result = static_cast<std::uint8_t>(resultValue);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (lhs < rhs) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 7U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) >> 7U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSubFlags16(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint16_t>(lhsValue);
    const auto rhs = static_cast<std::uint16_t>(rhsValue);
    const auto result = static_cast<std::uint16_t>(resultValue);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (lhs < rhs) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 15U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) >> 15U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSubFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto rhs = static_cast<std::uint32_t>(rhsValue);
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (lhs < rhs) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 31U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) >> 31U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateLogicFlags64(x86::X86State *state,
                                                                       std::uint64_t result) {
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateLogicFlags32(x86::X86State *state,
                                                                       std::uint64_t result) {
    const auto result32 = static_cast<std::uint32_t>(result);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result32 & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result32 == 0) {
        flags |= flagZero;
    }
    if ((result32 >> 31U) != 0) {
        flags |= flagSign;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateLogicFlags16(x86::X86State *state,
                                                                       std::uint64_t result) {
    const auto result16 = static_cast<std::uint16_t>(result);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result16 & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result16 == 0) {
        flags |= flagZero;
    }
    if ((result16 >> 15U) != 0) {
        flags |= flagSign;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateLogicFlags8(x86::X86State *state,
                                                                      std::uint64_t result) {
    const auto result8 = static_cast<std::uint8_t>(result);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result8)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result8 == 0) {
        flags |= flagZero;
    }
    if ((result8 >> 7U) != 0) {
        flags |= flagSign;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftLeftFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t result,
                       std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    const auto carry = (lhs >> (64U - count)) & 1U;
    flags |= carry;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (((result >> 63U) & 1U) ^ carry) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" x86::X86State *updateShiftRightFlags32(x86::X86State *state, std::uint64_t lhsValue,
                                                   std::uint64_t resultValue,
                                                   std::uint64_t unmaskedCount);
extern "C" x86::X86State *updateShiftRightFlags64(x86::X86State *state, std::uint64_t lhs,
                                                   std::uint64_t result,
                                                   std::uint64_t unmaskedCount);

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftLeftFlags32(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                       std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    const auto carry = (lhs >> (32U - count)) & 1U;
    flags |= carry;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 31U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (((result >> 31U) & 1U) ^ carry) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftLeftFlags8(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                      std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto result = static_cast<std::uint8_t>(resultValue);
    auto replacedFlags = flagParity | flagZero | flagSign;
    if (count < 8) {
        replacedFlags |= flagCarry;
    }
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    std::uint64_t carry = 0;
    if (count < 8) {
        carry = (static_cast<unsigned>(lhs) >> (8U - count)) & 1U;
        flags |= carry;
    }
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 7U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && ((((result >> 7U) & 1U) ^ carry) != 0)) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateRotateLeftFlags16(x86::X86State *state, std::uint64_t resultValue,
                        std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    const auto effectiveCount = static_cast<std::uint8_t>(count % 16U);
    if (effectiveCount == 0) {
        return state;
    }
    const auto result = static_cast<std::uint16_t>(resultValue);
    auto replacedFlags = flagCarry;
    if (effectiveCount == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    const auto carry = static_cast<std::uint64_t>(result & 1U);
    flags |= carry;
    if (effectiveCount == 1 && ((((result >> 15U) & 1U) ^ carry) != 0)) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateRotateLeftFlags32(x86::X86State *state, std::uint64_t resultValue,
                        std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto replacedFlags = flagCarry;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    const auto carry = static_cast<std::uint64_t>(result & 1U);
    flags |= carry;
    if (count == 1 && ((((result >> 31U) & 1U) ^ carry) != 0)) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateRotateLeftFlags64(x86::X86State *state, std::uint64_t result, std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    const auto carry = result & 1U;
    flags |= carry;
    if (count == 1 && ((((result >> 63U) & 1U) ^ carry) != 0)) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateRotateRightFlags64(x86::X86State *state, std::uint64_t result, std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= result >> 63U;
    if (count == 1 && (((result >> 63U) ^ (result >> 62U)) & 1U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightFlags8(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                       std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto result = static_cast<std::uint8_t>(resultValue);
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (static_cast<unsigned>(lhs) >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 7U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (lhs >> 7U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightFlags32(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                        std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (lhs >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 31U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (lhs >> 31U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t result,
                        std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (lhs >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (lhs >> 63U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightArithmeticFlags32(x86::X86State *state, std::uint64_t lhsValue,
                                  std::uint64_t resultValue, std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (lhs >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 31U) != 0) {
        flags |= flagSign;
    }
    // SAR defines OF as zero for a one-bit shift. It is undefined for
    // larger counts, so Rosa preserves the incoming value in that case.
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightArithmeticFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t result,
                                  std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (lhs >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    // SAR defines OF as zero for a one-bit shift. It is undefined for
    // larger counts, so Rosa preserves the incoming value in that case.
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateMultiplyFlags64(x86::X86State *state,
                                                                          std::uint64_t high) {
    auto flags = (state->rflags & ~(flagCarry | flagOverflow)) | flagReservedOne;
    if (high != 0) {
        flags |= flagCarry | flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateSignedMultiplyFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs) {
    std::int64_t ignoredResult = 0;
    const bool overflow = __builtin_mul_overflow(std::bit_cast<std::int64_t>(lhs),
                                                 std::bit_cast<std::int64_t>(rhs), &ignoredResult);
    state->rflags = (state->rflags & ~(flagCarry | flagOverflow)) | flagReservedOne;
    if (overflow) {
        state->rflags |= flagCarry | flagOverflow;
    }
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateSignedMultiplyFlags32(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs) {
    std::int32_t ignoredResult = 0;
    const bool overflow = __builtin_mul_overflow(
        std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(lhs)),
        std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(rhs)), &ignoredResult);
    state->rflags = (state->rflags & ~(flagCarry | flagOverflow)) | flagReservedOne;
    if (overflow) {
        state->rflags |= flagCarry | flagOverflow;
    }
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateBitTestFlags32(x86::X86State *state, std::uint64_t value, std::uint64_t unmaskedBitIndex) {
    const auto bitIndex = static_cast<std::uint8_t>(unmaskedBitIndex & 0x1FU);
    auto flags = (state->rflags & ~flagCarry) | flagReservedOne;
    flags |= (value >> bitIndex) & 1U;
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateBitTestFlags64(x86::X86State *state, std::uint64_t value, std::uint64_t unmaskedBitIndex) {
    const auto bitIndex = static_cast<std::uint8_t>(unmaskedBitIndex & 0x3FU);
    auto flags = (state->rflags & ~flagCarry) | flagReservedOne;
    flags |= (value >> bitIndex) & 1U;
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightDoubleFlags64(x86::X86State *state, std::uint64_t original, std::uint64_t result,
                              std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (original >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (((original ^ result) >> 63U) & 1U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

} // namespace rosa::dbt::runtime
