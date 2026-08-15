#include "darwin/Commpage.h"

#include <mach/mach_time.h>

#include <array>
#include <limits>

namespace rosa::darwin {

void mapX86CommpageContinuousTimebase(guest::AddressSpace &addressSpace,
                                      std::uint64_t continuousTimebase) {
    std::array<std::uint8_t, sizeof(continuousTimebase)> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] =
            static_cast<std::uint8_t>((continuousTimebase >> (index * 8U)) & 0xFFU);
    }
    addressSpace.mapSparseReadOnly(x86CommpageBase, guest::guestPageSize,
                                   x86CommpageContinuousTimebaseOffset, bytes,
                                   "Darwin x86_64 commpage");
    constexpr std::array<std::uint8_t, sizeof(std::uint32_t)> generation{
        1, 0, 0, 0,
    };
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value + x86CommpageNanotimeGenerationOffset},
        generation);
}

std::uint64_t sampleHostContinuousTimebase() {
    auto bestInterval = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t bestTimebase = 0;
    for (std::size_t attempt = 0; attempt < 8; ++attempt) {
        const auto absoluteBefore = mach_absolute_time();
        const auto continuous = mach_continuous_time();
        const auto absoluteAfter = mach_absolute_time();
        const auto interval = absoluteAfter - absoluteBefore;
        if (interval < bestInterval) {
            bestInterval = interval;
            const auto lowerBound =
                continuous > absoluteAfter ? continuous - absoluteAfter : 0;
            const auto upperBound = continuous - absoluteBefore;
            bestTimebase = lowerBound + ((upperBound - lowerBound) / 2U);
        }
    }
    return bestTimebase;
}

} // namespace rosa::darwin
