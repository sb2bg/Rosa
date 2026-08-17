#include "darwin/Syscall.h"

#include "darwin/SharedCache.h"

#include <sys/random.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace rosa::darwin {
namespace {

constexpr std::uint64_t unixSyscallClass = 2U << 24U;
constexpr std::uint64_t machdepSyscallClass = 3U << 24U;
constexpr std::uint64_t syscallClassMask = 0xFF000000U;
constexpr std::uint64_t syscallNumberMask = 0x00FFFFFFU;
constexpr std::uint64_t syscallExit = unixSyscallClass | 1U;
constexpr std::uint64_t syscallWrite = unixSyscallClass | 4U;
constexpr std::uint64_t syscallOpen = unixSyscallClass | 5U;
constexpr std::uint64_t syscallClose = unixSyscallClass | 6U;
constexpr std::uint64_t syscallGetpid = unixSyscallClass | 20U;
constexpr std::uint64_t syscallMunmap = unixSyscallClass | 73U;
constexpr std::uint64_t syscallFcntl = unixSyscallClass | 92U;
constexpr std::uint64_t syscallSysctl = unixSyscallClass | 202U;
constexpr std::uint64_t syscallSharedRegionCheck = unixSyscallClass | 294U;
constexpr std::uint64_t syscallProcInfo = unixSyscallClass | 336U;
constexpr std::uint64_t syscallThreadSelfid = unixSyscallClass | 372U;
constexpr std::uint64_t syscallMac = unixSyscallClass | 381U;
constexpr std::uint64_t syscallFsgetpath = unixSyscallClass | 427U;
constexpr std::uint64_t syscallCsrctl = unixSyscallClass | 483U;
constexpr std::uint64_t syscallGetentropy = unixSyscallClass | 500U;
constexpr std::uint64_t csrSyscallCheck = 0;
// Rosa exposes a fully restrictive guest System Integrity Protection
// configuration. This is guest policy state, not a host kernel pointer or
// an assertion about the host's current configuration.
constexpr std::uint32_t guestCsrActiveConfig = 0;
constexpr std::uint64_t machdepThreadFastSetCthreadSelf = 3U;
constexpr std::uint64_t x86UserCthreadSelector = 0x0FU;
constexpr std::uint64_t x86MaximumUserPageAddress = 0x00007FFFFFFFF000ULL;
// Rosa currently executes exactly one guest thread. Keep its identity in the
// guest namespace rather than exposing a host pthread or Mach identifier.
constexpr std::uint64_t initialGuestThreadId = 1;
constexpr std::int32_t procInfoCallSetDyldImages = 0x0F;
constexpr std::uint64_t carryFlag = 1U << 0U;
constexpr std::uint64_t reservedOneFlag = 1U << 1U;
constexpr std::size_t maximumControlledWrite = 16U * 1024U * 1024U;
constexpr std::size_t maximumLongPath = 8192;
constexpr std::size_t guestPathMaximum = 1024;
constexpr std::uint32_t guestOpenDirectory = 0x00100000;
constexpr std::uint32_t guestFcntlGetPath = 50;
constexpr std::uint32_t guestSandboxCheckCall = 2;
constexpr std::uint64_t guestSandboxSyscallFilterType = 0x41;
constexpr std::uint64_t guestSandboxObservedFlags = 1;
constexpr std::uint64_t guestMapWithLinkingSyscall = 550;
constexpr std::array<std::uint32_t, 2> guestSysctlNameToOid{0, 3};
constexpr std::array<std::uint32_t, 3> guestLockdownModeOid{103, 101, 101};
constexpr std::string_view guestLockdownModeName =
    "security.mac.lockdown_mode_state";
constexpr std::uint32_t guestLockdownModeState = 0;

struct GuestFsid {
    std::int32_t value[2];
};

static_assert(sizeof(GuestFsid) == 8);

// Private x86_64 Sandbox policy call-2 ABI observed in the guest dyld cache.
// Every address remains a guest integer until copied through AddressSpace.
struct GuestSandboxCheckRequest {
    std::uint64_t resultAddress;
    std::uint64_t pid;
    std::uint64_t operationAddress;
    std::uint64_t filterType;
    std::uint64_t value;
    std::uint64_t flags;
};

static_assert(sizeof(GuestSandboxCheckRequest) == 48);

void setSuccess(x86::X86State &state, std::uint64_t result) {
    state.rax = result;
    state.rflags = (state.rflags & ~carryFlag) | reservedOneFlag;
}

void setError(x86::X86State &state, int error) {
    state.rax = static_cast<std::uint64_t>(error);
    state.rflags = state.rflags | carryFlag | reservedOneFlag;
}

std::optional<std::string> readGuestCString(
    const guest::AddressSpace &addressSpace, guest::GuestAddress address,
    std::size_t maximumSize) {
    std::string result;
    result.reserve(maximumSize);
    for (std::size_t index = 0; index < maximumSize; ++index) {
        const auto byte = addressSpace.readBytes(address, 1).front();
        if (byte == 0) {
            return result;
        }
        result.push_back(static_cast<char>(byte));
        ++address.value;
    }
    return std::nullopt;
}

bool isWithinDirectory(const std::filesystem::path &directory,
                       const std::filesystem::path &candidate) {
    const auto relative = candidate.lexically_relative(directory);
    if (relative.empty() || relative.is_absolute()) {
        return false;
    }
    const auto first = relative.begin();
    return first == relative.end() || *first != "..";
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
    if (number == syscallMac) {
        std::optional<std::string> policy;
        try {
            policy = readGuestCString(
                addressSpace, guest::GuestAddress{state.rdi},
                guestPathMaximum);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (!policy) {
            setError(state, ENAMETOOLONG);
            return {};
        }
        const auto call = static_cast<std::uint32_t>(state.rsi);
        if (*policy != "Sandbox" || call != guestSandboxCheckCall) {
            std::ostringstream reason;
            reason << "only Sandbox policy call 2 is implemented; got policy=\""
                   << *policy << "\" call=" << std::dec << call;
            throw unsupported(state, syscallRip, reason.str());
        }

        GuestSandboxCheckRequest request{};
        std::optional<std::string> operation;
        try {
            const auto requestBytes = addressSpace.readBytes(
                guest::GuestAddress{state.rdx}, sizeof(request));
            std::memcpy(&request, requestBytes.data(), sizeof(request));
            operation = readGuestCString(
                addressSpace,
                guest::GuestAddress{request.operationAddress},
                guestPathMaximum);
            addressSpace.validateAccess(
                guest::GuestAddress{request.resultAddress},
                sizeof(std::uint64_t), guest::Permission::Write);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (!operation) {
            setError(state, ENAMETOOLONG);
            return {};
        }

        const auto guestPid = static_cast<std::uint64_t>(::getpid());
        if (request.pid != guestPid || *operation != "syscall-unix" ||
            request.filterType != guestSandboxSyscallFilterType ||
            request.value != guestMapWithLinkingSyscall ||
            request.flags != guestSandboxObservedFlags) {
            std::ostringstream reason;
            reason << "unsupported Sandbox check: pid=0x" << std::hex
                   << request.pid << " operation=\"" << *operation
                   << "\" filter-type=0x" << request.filterType
                   << " value=0x" << request.value << " flags=0x"
                   << request.flags;
            throw unsupported(state, syscallRip, reason.str());
        }

        // Rosa has not installed a sandbox profile for this controlled guest,
        // so the exact observed syscall check is allowed. The x86 policy ABI
        // writes a 64-bit zero decision and returns success.
        addressSpace.writeU64(guest::GuestAddress{request.resultAddress}, 0);
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallSysctl) {
        if (state.rsi > 12) {
            setError(state, EINVAL);
            return {};
        }
        std::vector<std::uint32_t> name;
        name.reserve(static_cast<std::size_t>(state.rsi));
        try {
            for (std::size_t index = 0; index < state.rsi; ++index) {
                name.push_back(addressSpace.readU32(guest::GuestAddress{
                    state.rdi + index * sizeof(std::uint32_t)}));
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }

        if (std::ranges::equal(name, guestSysctlNameToOid)) {
            if (state.r8 == 0 || state.r9 != guestLockdownModeName.size() ||
                state.rdx == 0 || state.r10 == 0) {
                throw unsupported(
                    state, syscallRip,
                    "only the observed CTL_SYSCTL/CTL_SYSCTL_NAME2OID request is implemented");
            }
            std::string requestedName;
            std::uint64_t outputCapacity = 0;
            try {
                const auto bytes = addressSpace.readBytes(
                    guest::GuestAddress{state.r8},
                    static_cast<std::size_t>(state.r9));
                requestedName.assign(bytes.begin(), bytes.end());
                outputCapacity = addressSpace.readU64(
                    guest::GuestAddress{state.r10});
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            if (requestedName != guestLockdownModeName) {
                std::ostringstream reason;
                reason << "unsupported guest sysctl name \"" << requestedName
                       << '"';
                throw unsupported(state, syscallRip, reason.str());
            }
            constexpr auto resultSize = sizeof(guestLockdownModeOid);
            if (outputCapacity < resultSize) {
                setError(state, ENOMEM);
                return {};
            }
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx}, resultSize,
                    guest::Permission::Write);
                addressSpace.validateAccess(
                    guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                    guest::Permission::Write);
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            std::array<std::uint8_t, resultSize> oidBytes{};
            std::memcpy(oidBytes.data(), guestLockdownModeOid.data(),
                        resultSize);
            addressSpace.writeBytes(guest::GuestAddress{state.rdx}, oidBytes);
            addressSpace.writeU64(guest::GuestAddress{state.r10}, resultSize);
            setSuccess(state, 0);
            return {};
        }

        if (std::ranges::equal(name, guestLockdownModeOid)) {
            if (state.rdx == 0 || state.r10 == 0 || state.r8 != 0 ||
                state.r9 != 0) {
                throw unsupported(
                    state, syscallRip,
                    "only a read of the guest lockdown-mode sysctl is implemented");
            }
            std::uint64_t outputCapacity = 0;
            try {
                outputCapacity = addressSpace.readU64(
                    guest::GuestAddress{state.r10});
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            if (outputCapacity < sizeof(guestLockdownModeState)) {
                setError(state, ENOMEM);
                return {};
            }
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx},
                    sizeof(guestLockdownModeState), guest::Permission::Write);
                addressSpace.validateAccess(
                    guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                    guest::Permission::Write);
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            std::array<std::uint8_t, sizeof(guestLockdownModeState)>
                valueBytes{};
            std::memcpy(valueBytes.data(), &guestLockdownModeState,
                        sizeof(guestLockdownModeState));
            addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                    valueBytes);
            addressSpace.writeU64(guest::GuestAddress{state.r10},
                                  sizeof(guestLockdownModeState));
            setSuccess(state, 0);
            return {};
        }

        std::ostringstream reason;
        reason << "unsupported guest sysctl MIB";
        for (const auto component : name) {
            reason << ' ' << std::dec << component;
        }
        throw unsupported(state, syscallRip, reason.str());
    }
    if (number == syscallGetpid) {
        // Rosa currently has one guest process hosted by one Rosa process, so
        // the host PID is also its externally observable guest process ID.
        setSuccess(state, static_cast<std::uint64_t>(::getpid()));
        return {};
    }
    if (number == syscallOpen) {
        std::optional<std::string> path;
        try {
            path = readGuestCString(addressSpace,
                                    guest::GuestAddress{state.rdi},
                                    guestPathMaximum);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (!path) {
            setError(state, ENAMETOOLONG);
            return {};
        }
        const auto flags = static_cast<std::uint32_t>(state.rsi);
        const auto mode = static_cast<std::uint32_t>(state.rdx);
        if (*path == "." && flags == guestOpenDirectory && mode == 0) {
            const auto descriptor = fileSpace_.openCurrentDirectory(flags);
            setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
            return {};
        }
        if (flags == 0 && mode == 0 &&
            std::filesystem::path(*path).is_absolute()) {
            std::error_code error;
            const auto canonicalPath = std::filesystem::canonical(*path, error);
            if (error) {
                setError(state, error.value());
                return {};
            }
            if (!isWithinDirectory(fileSpace_.currentDirectory(),
                                   canonicalPath)) {
                std::ostringstream reason;
                reason << "guest VFS has no mapping for read-only path \""
                       << *path << '"';
                throw unsupported(state, syscallRip, reason.str());
            }
            if (!std::filesystem::is_regular_file(canonicalPath, error) ||
                error) {
                setError(state, error ? error.value() : EINVAL);
                return {};
            }
            const auto descriptor =
                fileSpace_.openReadOnlyFile(canonicalPath, flags);
            setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
            return {};
        }
        {
            std::ostringstream reason;
            reason << "only the observed current-directory and mapped user-file open operations are implemented; got path=\""
                   << *path << "\" flags=0x" << std::hex << flags
                   << " mode=0x" << mode;
            throw unsupported(state, syscallRip, reason.str());
        }
    }
    if (number == syscallClose) {
        const auto descriptor = GuestFileDescriptor{
            std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdi))};
        if (!fileSpace_.close(descriptor)) {
            setError(state, EBADF);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallFcntl) {
        const auto descriptor = GuestFileDescriptor{
            std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdi))};
        const auto command = static_cast<std::uint32_t>(state.rsi);
        if (command != guestFcntlGetPath) {
            throw unsupported(
                state, syscallRip,
                "only the observed fcntl(F_GETPATH) operation is implemented");
        }
        const auto *file = fileSpace_.lookup(descriptor);
        if (file == nullptr) {
            setError(state, EBADF);
            return {};
        }
        const auto path = file->guestPath.string();
        if (path.size() >= guestPathMaximum) {
            setError(state, ENAMETOOLONG);
            return {};
        }
        std::vector<std::uint8_t> bytes(path.begin(), path.end());
        bytes.push_back(0);
        try {
            addressSpace.writeBytes(guest::GuestAddress{state.rdx}, bytes);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallMunmap) {
        // XNU's BSD munmap requires a page-aligned start and nonzero size,
        // rounds the end up, and accepts holes in the range. Keep the entire
        // operation inside Rosa's guest map.
        if ((state.rdi % guest::guestPageSize) != 0 || state.rsi == 0) {
            setError(state, EINVAL);
            return {};
        }
        switch (addressSpace.deallocate(guest::GuestAddress{state.rdi},
                                        state.rsi)) {
        case guest::DeallocateResult::Success:
            setSuccess(state, 0);
            return {};
        case guest::DeallocateResult::InvalidArgument:
            setError(state, EINVAL);
            return {};
        }
        throw std::runtime_error("unreachable guest munmap result");
    }
    if (number == syscallSharedRegionCheck) {
        if (sharedCache_ == nullptr) {
            // Preserve XNU's no-cache result without touching the guest pointer.
            setError(state, EINVAL);
            return {};
        }
        try {
            addressSpace.writeU64(guest::GuestAddress{state.rdi},
                                  sharedCache_->regionStart().value +
                                      sharedCache_->slide());
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallProcInfo) {
        const auto callNumber = std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.rdi));
        if (callNumber != procInfoCallSetDyldImages) {
            throw unsupported(
                state, syscallRip,
                "only the observed PROC_INFO_CALL_SET_DYLD_IMAGES operation is implemented");
        }

        const auto pid = std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.rsi));
        const auto hostPid = static_cast<std::int32_t>(::getpid());
        if (pid != hostPid || state.r8 == 0) {
            setError(state, EINVAL);
            return {};
        }

        // XNU registers this userspace address range as TASK_DYLD_INFO. It
        // neither copies the buffer nor passes it to another kernel API. Keep
        // the same metadata in the guest task namespace. The address need not
        // currently be mapped, but the range must not wrap.
        const auto signedSize = std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.r9));
        const auto size = static_cast<std::uint64_t>(signedSize);
        std::uint64_t end = 0;
        if (__builtin_add_overflow(state.r8, size, &end) || dyldInfoFinal_) {
            setError(state, EINVAL);
            return {};
        }
        dyldInfo_ = GuestDyldInfo{
            .address = guest::GuestAddress{state.r8},
            .size = size,
        };
        // In a real dynamic process, the kernel loader has already installed
        // dyld's initial __all_image_info range. This dyld-issued update is the
        // one permitted nonzero-to-nonzero transition, which finalizes it.
        dyldInfoFinal_ = true;
        setSuccess(state, 0);
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
    if (number == syscallCsrctl) {
        if (state.rdi != csrSyscallCheck) {
            throw unsupported(
                state, syscallRip,
                "only the observed csrctl CSR_SYSCALL_CHECK operation is implemented");
        }
        if (state.rsi == 0 || state.rdx != sizeof(std::uint32_t)) {
            setError(state, EINVAL);
            return {};
        }
        std::uint32_t requestedMask = 0;
        try {
            requestedMask = addressSpace.readU32(
                guest::GuestAddress{state.rsi});
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if ((guestCsrActiveConfig & requestedMask) == requestedMask) {
            setSuccess(state, 0);
        } else {
            setError(state, EPERM);
        }
        return {};
    }
    if (number != syscallWrite) {
        throw unsupported(state, syscallRip,
                          "only BSD write(2), exit(2), open(2), close(2), getpid(2), munmap(2), fcntl(2), "
                          "shared_region_check_np(2), proc_info(2), thread_selfid(2), "
                          "fsgetpath(2), csrctl(2), and getentropy(2) are "
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
