#include "darwin/Commpage.h"

#include <mach/mach_time.h>
#include <sys/sysctl.h>
#include <sys/time.h>

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
    const auto wholeNanoseconds = whole * timebase.numer;
    const auto remainderNanoseconds =
        (remainder * timebase.numer) / timebase.denom;
    if (wholeNanoseconds > std::numeric_limits<std::uint64_t>::max() -
                               remainderNanoseconds) {
        throw std::runtime_error("host Mach time conversion overflows");
    }
    return wholeNanoseconds + remainderNanoseconds;
}

} // namespace

void mapX86Commpage(guest::AddressSpace &addressSpace,
                    std::uint64_t continuousTimebase,
                    std::uint64_t bootTimeUsec,
                    std::uint64_t dyldFlags) {
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
    std::array<std::uint8_t, sizeof(x86CommpageCpuCapabilities64)>
        cpuCapabilitiesBytes{};
    writeLittleEndian(cpuCapabilitiesBytes, 0, x86CommpageCpuCapabilities64,
                      sizeof(x86CommpageCpuCapabilities64));
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value +
                            x86CommpageCpuCapabilities64Offset},
        cpuCapabilitiesBytes);
    std::array<std::uint8_t, sizeof(x86CommpageVersion)> versionBytes{};
    writeLittleEndian(versionBytes, 0, x86CommpageVersion,
                      sizeof(x86CommpageVersion));
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value + x86CommpageVersionOffset},
        versionBytes);
    // XNU retains a 32-bit capabilities view for compatibility. Its CPU-count
    // byte at +0x22 overlaps kNumCPUs in this word, so publish the low half of
    // the same coherent 64-bit value rather than an independent copy.
    std::array<std::uint8_t, sizeof(std::uint32_t)>
        legacyCpuCapabilitiesBytes{};
    writeLittleEndian(legacyCpuCapabilitiesBytes, 0,
                      x86CommpageCpuCapabilities64,
                      legacyCpuCapabilitiesBytes.size());
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value +
                            x86CommpageCpuCapabilitiesOffset},
        legacyCpuCapabilitiesBytes);
    // Rosa exposes one executable guest thread. Publish a coherent one-CPU,
    // one-cluster topology so allocators size per-CPU metadata conservatively.
    constexpr std::array<std::uint8_t, 4> cpuTopology{
        x86CommpageActiveCpuCount, x86CommpagePhysicalCpuCount,
        x86CommpageLogicalCpuCount, x86CommpageCpuClusterCount};
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value +
                            x86CommpageActiveCpuCountOffset},
        cpuTopology);
    std::array<std::uint8_t, sizeof(x86CommpageMemorySize)>
        memorySizeBytes{};
    writeLittleEndian(memorySizeBytes, 0, x86CommpageMemorySize,
                      sizeof(x86CommpageMemorySize));
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value +
                            x86CommpageMemorySizeOffset},
        memorySizeBytes);
    // An unknown x86 CPU family selects libsystem_platform's conservative
    // resolver. Do not claim a particular Intel microarchitecture until Rosa
    // implements every instruction used by that family's optimized routines.
    constexpr std::array<std::uint8_t, sizeof(x86CommpageCpuFamily)>
        cpuFamilyBytes{};
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value +
                            x86CommpageCpuFamilyOffset},
        cpuFamilyBytes);
    constexpr std::array<std::uint8_t, 1> kernelPageShift{
        x86CommpageKernelPageShift};
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value +
                            x86CommpageKernelPageShiftOffset},
        kernelPageShift);
    constexpr std::array<std::uint8_t, 1> userPageShift{
        x86CommpageUserPageShift};
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value +
                            x86CommpageUserPageShiftOffset},
        userPageShift);
    // Rosa does not forward guest kdebug tracing. XNU specifies that this field
    // is zero whenever global tracing is disabled.
    constexpr std::array<std::uint8_t, sizeof(std::uint32_t)> kdebugDisabled{};
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value + x86CommpageKdebugEnableOffset},
        kdebugDisabled);
    // Rosa does not register guest DTrace DOF sections with the host kernel.
    // XNU publishes a defined zero byte here when userspace DOF registration
    // is disabled; dyld uses it to avoid /dev/dtracehelper entirely.
    constexpr std::array<std::uint8_t, 1> dtraceDofDisabled{};
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value +
                            x86CommpageDtraceDofEnabledOffset},
        dtraceDofDisabled);
    std::array<std::uint8_t, sizeof(continuousTimebase)> continuousTimebaseBytes{};
    writeLittleEndian(continuousTimebaseBytes, 0, continuousTimebase,
                      sizeof(continuousTimebase));
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value + x86CommpageContinuousTimebaseOffset},
        continuousTimebaseBytes);
    // XNU exposes the wall-clock boot timestamp in microseconds. libsystem
    // reads it directly when constructing boot-unique state.
    std::array<std::uint8_t, sizeof(bootTimeUsec)> bootTimeUsecBytes{};
    writeLittleEndian(bootTimeUsecBytes, 0, bootTimeUsec,
                      sizeof(bootTimeUsec));
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value + x86CommpageBootTimeUsecOffset},
        bootTimeUsecBytes);
    // A zero TimeStamp_tick is XNU's defined "timestamp unavailable" state.
    // Publish the complete record so libsystem can take its syscall fallback
    // while still rejecting reads from genuinely unsupported commpage slots.
    constexpr std::array<std::uint8_t, x86CommpageNewTimeOfDayDataSize>
        disabledTimeOfDayData{};
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value +
                            x86CommpageNewTimeOfDayDataOffset},
        disabledTimeOfDayData);
    // XNU publishes the opaque kern.dyld_flags value here. The compatible
    // guest cache should observe the current system-wide value, not an arm64
    // commpage pointer or a guessed interpretation of its bits.
    std::array<std::uint8_t, sizeof(dyldFlags)> dyldFlagBytes{};
    writeLittleEndian(dyldFlagBytes, 0, dyldFlags, sizeof(dyldFlags));
    addressSpace.populateSparseReadOnly(
        guest::GuestAddress{x86CommpageBase.value + x86CommpageDyldFlagsOffset},
        dyldFlagBytes);
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

std::uint64_t sampleHostBootTimeUsec() {
    timeval bootTime{};
    auto size = sizeof(bootTime);
    if (::sysctlbyname("kern.boottime", &bootTime, &size, nullptr, 0) != 0 ||
        size != sizeof(bootTime) || bootTime.tv_sec < 0 ||
        bootTime.tv_usec < 0 || bootTime.tv_usec >= 1'000'000) {
        throw std::runtime_error("cannot query kern.boottime");
    }
    const auto seconds = static_cast<std::uint64_t>(bootTime.tv_sec);
    const auto microseconds = static_cast<std::uint64_t>(bootTime.tv_usec);
    if (seconds > (std::numeric_limits<std::uint64_t>::max() - microseconds) /
                      1'000'000U) {
        throw std::runtime_error("host boot time conversion overflows");
    }
    return seconds * 1'000'000U + microseconds;
}

std::uint64_t sampleHostDyldFlags() {
    std::uint64_t value{};
    auto size = sizeof(value);
    if (::sysctlbyname("kern.dyld_flags", &value, &size, nullptr, 0) != 0 ||
        size != sizeof(value)) {
        throw std::runtime_error("cannot query kern.dyld_flags");
    }
    return value;
}

std::uint64_t sampleX86TimestampCounter() {
    const auto absoluteNanoseconds = hostTicksToNanoseconds(mach_absolute_time());
    if (absoluteNanoseconds > std::numeric_limits<std::uint64_t>::max() / 2U) {
        throw std::runtime_error("virtual x86 timestamp counter overflows");
    }
    return absoluteNanoseconds * 2U;
}

} // namespace rosa::darwin
