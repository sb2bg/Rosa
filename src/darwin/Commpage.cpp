#include "darwin/Commpage.h"

#include <mach/mach_time.h>

#include <array>
#include <limits>
#include <span>
#include <stdexcept>

namespace rosa::darwin {
namespace {

void writeLittleEndian(std::span<std::uint8_t> bytes, std::size_t offset,
                       std::uint64_t value, std::size_t width) {
    for (std::size_t index = 0; index < width; ++index) {
        bytes[offset + index] =
            static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU);
    }
}

std::uint64_t hostTicksToNanoseconds(std::uint64_t ticks) {
    static const auto timebase = [] {
        mach_timebase_info_data_t result{};
        if (mach_timebase_info(&result) != KERN_SUCCESS || result.denom == 0) {
            throw std::runtime_error("cannot query the host Mach timebase");
        }
        return result;
    }();
    const auto whole = ticks / timebase.denom;
    const auto remainder = ticks % timebase.denom;
    if (whole > std::numeric_limits<std::uint64_t>::max() / timebase.numer) {
        throw std::runtime_error("host Mach time conversion overflows");
    }
    return (whole * timebase.numer) + ((remainder * timebase.numer) / timebase.denom);
}

} // namespace

void mapX86Commpage(guest::AddressSpace &addressSpace,
                    std::uint64_t continuousTimebase) {
    constexpr auto nanotimeDataSize =
        x86CommpageNanotimeGenerationOffset + sizeof(std::uint32_t) -
        x86CommpageNanotimeTscBaseOffset;
    std::array<std::uint8_t, nanotimeDataSize> nanotimeData{};
    writeLittleEndian(nanotimeData,
                      x86CommpageNanotimeScaleOffset - x86CommpageNanotimeTscBaseOffset,
                      x86CommpageNanotimeScale, sizeof(std::uint32_t));
    writeLittleEndian(nanotimeData,
                      x86CommpageNanotimeGenerationOffset -
                          x86CommpageNanotimeTscBaseOffset,
                      1, sizeof(std::uint32_t));
    addressSpace.mapSparseReadOnly(x86CommpageBase, guest::guestPageSize,
                                   x86CommpageNanotimeTscBaseOffset, nanotimeData,
                                   "Darwin x86_64 commpage");
    // Rosa does not forward guest kdebug tracing. XNU specifies that this field
    // is zero whenever global tracing is disabled.
    constexpr std::array<std::uint8_t, sizeof(std::uint32_t)> kdebugDisabled{};
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value + x86CommpageKdebugEnableOffset},
        kdebugDisabled);
    std::array<std::uint8_t, sizeof(continuousTimebase)> continuousTimebaseBytes{};
    writeLittleEndian(continuousTimebaseBytes, 0, continuousTimebase,
                      sizeof(continuousTimebase));
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value + x86CommpageContinuousTimebaseOffset},
        continuousTimebaseBytes);
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
    return hostTicksToNanoseconds(bestTimebase);
}

std::uint64_t sampleX86TimestampCounter() {
    const auto absoluteNanoseconds = hostTicksToNanoseconds(mach_absolute_time());
    if (absoluteNanoseconds > std::numeric_limits<std::uint64_t>::max() / 2U) {
        throw std::runtime_error("virtual x86 timestamp counter overflows");
    }
    return absoluteNanoseconds * 2U;
}

} // namespace rosa::darwin
