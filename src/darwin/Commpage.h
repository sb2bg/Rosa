#pragma once

#include "guest/Address.h"
#include "guest/AddressSpace.h"

#include <cstdint>

namespace rosa::darwin {

inline constexpr guest::GuestAddress x86CommpageBase{0x00007FFFFFE00000ULL};
inline constexpr std::size_t x86CommpageVersionOffset = 0x1E;
inline constexpr std::uint16_t x86CommpageVersion = 14;
inline constexpr std::size_t x86CommpageKdebugEnableOffset = 0x44;
inline constexpr std::size_t x86CommpageContinuousTimebaseOffset = 0xC0;
inline constexpr std::size_t x86CommpageNanotimeTscBaseOffset = 0x50;
inline constexpr std::size_t x86CommpageNanotimeScaleOffset = 0x58;
inline constexpr std::size_t x86CommpageNanotimeShiftOffset = 0x5C;
inline constexpr std::size_t x86CommpageNanotimeNanosecondsBaseOffset = 0x60;
inline constexpr std::size_t x86CommpageNanotimeGenerationOffset = 0x68;
inline constexpr std::uint32_t x86CommpageNanotimeScale = 0x80000000U;

void mapX86Commpage(guest::AddressSpace &addressSpace, std::uint64_t continuousTimebase);
[[nodiscard]] std::uint64_t sampleHostContinuousTimebase();
[[nodiscard]] std::uint64_t sampleX86TimestampCounter();

} // namespace rosa::darwin
