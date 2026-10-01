#pragma once

#include <cstdint>

namespace rosa::x86 {

constexpr std::uint64_t flagCarry = 1U << 0U;
constexpr std::uint64_t flagReservedOne = 1U << 1U;
constexpr std::uint64_t flagParity = 1U << 2U;
constexpr std::uint64_t flagAuxiliaryCarry = 1U << 4U;
constexpr std::uint64_t flagZero = 1U << 6U;
constexpr std::uint64_t flagSign = 1U << 7U;
constexpr std::uint64_t flagOverflow = 1U << 11U;
constexpr std::uint64_t flagDirection = 1U << 10U;
constexpr std::uint64_t arithmeticFlagMask =
    flagCarry | flagParity | flagAuxiliaryCarry | flagZero | flagSign | flagOverflow;

} // namespace rosa::x86
