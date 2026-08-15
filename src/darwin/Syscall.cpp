#include "darwin/Syscall.h"

#include <sys/random.h>
#include <unistd.h>

#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace rosa::darwin {
namespace {

constexpr std::uint64_t unixSyscallClass = 2U << 24U;
constexpr std::uint64_t machdepSyscallClass = 3U << 24U;
constexpr std::uint64_t syscallClassMask = 0xFF000000U;
constexpr std::uint64_t syscallNumberMask = 0x00FFFFFFU;
constexpr std::uint64_t syscallExit = unixSyscallClass | 1U;
constexpr std::uint64_t syscallWrite = unixSyscallClass | 4U;
constexpr std::uint64_t syscallSharedRegionCheck = unixSyscallClass | 294U;
constexpr std::uint64_t syscallThreadSelfid = unixSyscallClass | 372U;
constexpr std::uint64_t syscallFsgetpath = unixSyscallClass | 427U;
constexpr std::uint64_t syscallGetentropy = unixSyscallClass | 500U;
constexpr std::uint64_t machdepThreadFastSetCthreadSelf = 3U;
constexpr std::uint64_t x86UserCthreadSelector = 0x0FU;
constexpr std::uint64_t x86MaximumUserPageAddress = 0x00007FFFFFFFF000ULL;
// Rosa currently executes exactly one guest thread. Keep its identity in the
// guest namespace rather than exposing a host pthread or Mach identifier.
constexpr std::uint64_t initialGuestThreadId = 1;
constexpr std::uint64_t carryFlag = 1U << 0U;
constexpr std::uint64_t reservedOneFlag = 1U << 1U;
constexpr std::size_t maximumControlledWrite = 16U * 1024U * 1024U;
constexpr std::size_t maximumLongPath = 8192;

struct GuestFsid {
    std::int32_t value[2];
};

static_assert(sizeof(GuestFsid) == 8);

void setSuccess(x86::X86State &state, std::uint64_t result) {
    state.rax = result;
    state.rflags = (state.rflags & ~carryFlag) | reservedOneFlag;
}

void setError(x86::X86State &state, int error) {
    state.rax = static_cast<std::uint64_t>(error);
    state.rflags = state.rflags | carryFlag | reservedOneFlag;
}

std::runtime_error unsupported(const x86::X86State &state, guest::GuestAddress rip,
                               const std::string &reason) {
    std::ostringstream stream;
    stream << "unsupported Darwin guest syscall\n"
           << "  number: 0x" << std::hex << state.rax << '\n'
           << "  RIP: 0x" << rip.value << '\n'
           << "  args: 0x" << state.rdi << " 0x" << state.rsi << " 0x" << state.rdx << " 0x"
           << state.r10 << " 0x" << state.r8 << " 0x" << state.r9 << '\n'
           << "  reason: " << reason;
    return std::runtime_error(stream.str());
}

std::runtime_error unsupportedMachdep(const x86::X86State &state,
                                      guest::GuestAddress rip) {
    std::ostringstream stream;
    stream << "unsupported Darwin guest x86 machdep call\n"
           << "  number: " << std::dec << (state.rax & syscallNumberMask) << '\n'
           << "  RIP: 0x" << std::hex << rip.value << '\n'
           << "  args: 0x" << state.rdi << " 0x" << state.rsi << " 0x" << state.rdx;
    return std::runtime_error(stream.str());
}

} // namespace

SyscallOutcome SyscallDispatcher::dispatch(guest::AddressSpace &addressSpace, x86::X86State &state,
                                           guest::GuestAddress syscallRip) {
    const auto number = state.rax;
    if (MachDispatcher::isMachTrap(number)) {
        machDispatcher_.dispatch(addressSpace, state, syscallRip);
        return {};
    }
    if ((number & syscallClassMask) == machdepSyscallClass) {
        const auto call = number & syscallNumberMask;
        if (call != machdepThreadFastSetCthreadSelf) {
            throw unsupportedMachdep(state, syscallRip);
        }
        // XNU's 64-bit call stores a canonical user pointer as the thread's GS
        // base, clears an invalid pointer to zero, and returns USER_CTHREAD.
        state.gsBase = state.rdi < x86MaximumUserPageAddress ? state.rdi : 0;
        state.rax = x86UserCthreadSelector;
        return {};
    }
    if (number == syscallExit) {
        const auto rawStatus = static_cast<std::uint32_t>(state.rdi);
        return SyscallOutcome{
            .exited = true,
            .exitStatus = static_cast<int>(std::bit_cast<std::int32_t>(rawStatus)),
        };
    }
    if (number == syscallThreadSelfid) {
        setSuccess(state, initialGuestThreadId);
        return {};
    }
    if (number == syscallSharedRegionCheck) {
        // Rosa has not provisioned or mapped an Intel shared region. XNU's
        // shared_region_check_np returns EINVAL in this state without reading
        // or writing the start-address pointer.
        setError(state, EINVAL);
        return {};
    }
    if (number == syscallGetentropy) {
        constexpr std::size_t maximumEntropySize = 256;
        if (state.rsi > maximumEntropySize) {
            // XNU randomdev.c rejects requests larger than its 256-byte
            // kernel buffer before touching userspace.
            setError(state, EINVAL);
            return {};
        }
        const auto size = static_cast<std::size_t>(state.rsi);
        try {
            addressSpace.validateAccess(guest::GuestAddress{state.rdi}, size,
                                        guest::Permission::Write);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        std::array<std::uint8_t, maximumEntropySize> bytes{};
        if (::getentropy(bytes.data(), size) != 0) {
            setError(state, errno);
            return {};
        }
        try {
            addressSpace.writeBytes(
                guest::GuestAddress{state.rdi},
                std::span<const std::uint8_t>(bytes).first(size));
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallFsgetpath) {
        GuestFsid guestFsid{};
        try {
            const auto bytes = addressSpace.readBytes(
                guest::GuestAddress{state.rdx}, sizeof(guestFsid));
            std::memcpy(&guestFsid, bytes.data(), sizeof(guestFsid));
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (state.rsi == 0 || state.rsi > maximumLongPath) {
            setError(state, EINVAL);
            return {};
        }

        if (guestFsid.value[0] == 0 && guestFsid.value[1] == 0 && state.r10 == 0) {
            // dyld uses an empty FileIdTuple as a probe before falling back to
            // its known pathname. XNU cannot resolve volume zero and reports
            // ENOTSUP without touching the output buffer.
            setError(state, ENOTSUP);
            return {};
        }
        throw unsupported(
            state, syscallRip,
            "fsgetpath requires a guest VFS identity resolver for a nonempty fsid/object ID");
    }
    if (number != syscallWrite) {
        throw unsupported(state, syscallRip,
                          "only BSD write(2), exit(2), shared_region_check_np(2), "
                          "thread_selfid(2), fsgetpath(2), and getentropy(2) are "
                          "implemented");
    }
    if (state.rdi != STDOUT_FILENO && state.rdi != STDERR_FILENO) {
        throw unsupported(state, syscallRip,
                          "controlled write currently accepts only stdout or stderr");
    }
    if (state.rdx > maximumControlledWrite) {
        throw unsupported(state, syscallRip, "controlled write exceeds the 16 MiB limit");
    }

    const auto bytes =
        addressSpace.readBytes(guest::GuestAddress{state.rsi}, static_cast<std::size_t>(state.rdx));
    const auto result = ::write(static_cast<int>(state.rdi), bytes.data(), bytes.size());
    if (result < 0) {
        setError(state, errno);
    } else {
        setSuccess(state, static_cast<std::uint64_t>(result));
    }
    return {};
}

} // namespace rosa::darwin
