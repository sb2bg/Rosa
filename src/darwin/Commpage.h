#pragma once

#include "guest/Address.h"
#include "guest/AddressSpace.h"

#include <cstdint>

namespace rosa::darwin {

inline constexpr guest::GuestAddress x86CommpageBase{0x00007FFFFFE00000ULL};
inline constexpr std::size_t x86CommpageContinuousTimebaseOffset = 0xC0;
inline constexpr std::size_t x86CommpageNanotimeGenerationOffset = 0x68;

void mapX86CommpageContinuousTimebase(guest::AddressSpace &addressSpace,
                                      std::uint64_t continuousTimebase);
[[nodiscard]] std::uint64_t sampleHostContinuousTimebase();

} // namespace rosa::darwin
