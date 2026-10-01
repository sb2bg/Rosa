#pragma once

// Shared vocabulary for the Darwin syscall handlers. Each handler receives one
// SyscallCall and reports its result through setSuccess/setError or throws
// unsupported() for a call outside the modeled surface.

#include "darwin/Syscall.h"

#include "darwin/Commpage.h"
#include "darwin/Process.h"
#include "darwin/SharedCache.h"

#include <libproc.h>
#include <mach/mach.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <vector>

#include <expected>
#include <filesystem>
#include <optional>
#include <string>

namespace rosa::darwin::detail {

struct SyscallCall {
    guest::AddressSpace &addressSpace;
    x86::X86State &state;
    guest::GuestAddress syscallRip;
    GuestTask &task;
};

using SyscallHandler = SyscallOutcome (*)(SyscallCall &call);

inline constexpr std::uint64_t unixSyscallClass = 2U << 24U;
inline constexpr std::uint64_t machdepSyscallClass = 3U << 24U;
inline constexpr std::uint64_t syscallClassMask = 0xFF000000U;
inline constexpr std::uint64_t syscallNumberMask = 0x00FFFFFFU;
inline constexpr std::uint64_t syscallExit = unixSyscallClass | 1U;
inline constexpr std::uint64_t syscallRead = unixSyscallClass | 3U;
inline constexpr std::uint64_t syscallWrite = unixSyscallClass | 4U;
inline constexpr std::uint64_t syscallOpen = unixSyscallClass | 5U;
inline constexpr std::uint64_t syscallClose = unixSyscallClass | 6U;
inline constexpr std::uint64_t syscallGetpid = unixSyscallClass | 20U;
inline constexpr std::uint64_t syscallGetuid = unixSyscallClass | 24U;
inline constexpr std::uint64_t syscallGeteuid = unixSyscallClass | 25U;
inline constexpr std::uint64_t syscallGettid = unixSyscallClass | 286U;
inline constexpr std::uint64_t syscallGetegid = unixSyscallClass | 43U;
inline constexpr std::uint64_t syscallGetrlimit = unixSyscallClass | 194U;
inline constexpr std::uint32_t guestRlimitPosixFlag = 0x1000U;
inline constexpr std::uint32_t guestRlimitCount = 9U;
inline constexpr std::uint64_t syscallSigaction = unixSyscallClass | 46U;
inline constexpr std::uint64_t syscallAccess = unixSyscallClass | 33U;
inline constexpr std::uint64_t syscallDup = unixSyscallClass | 41U;
inline constexpr std::uint64_t syscallIoctl = unixSyscallClass | 54U;
inline constexpr std::uint64_t syscallMunmap = unixSyscallClass | 73U;
inline constexpr std::uint64_t syscallMprotect = unixSyscallClass | 74U;
inline constexpr std::uint64_t syscallMadvise = unixSyscallClass | 75U;
inline constexpr std::uint64_t syscallFcntl = unixSyscallClass | 92U;
inline constexpr std::uint64_t syscallFcntlNoCancel = unixSyscallClass | 406U;
inline constexpr std::uint64_t syscallSocket = unixSyscallClass | 97U;
inline constexpr std::uint64_t syscallConnect = unixSyscallClass | 98U;
inline constexpr std::uint64_t syscallGettimeofday = unixSyscallClass | 116U;
inline constexpr std::uint64_t syscallCsops = unixSyscallClass | 169U;
inline constexpr std::uint64_t syscallCsopsAuditToken = unixSyscallClass | 170U;
inline constexpr std::uint64_t syscallMmap = unixSyscallClass | 197U;
inline constexpr std::uint64_t syscallLseek = unixSyscallClass | 199U;
inline constexpr std::uint64_t syscallSysctl = unixSyscallClass | 202U;
inline constexpr std::uint64_t syscallGetattrlist = unixSyscallClass | 220U;
inline constexpr std::uint64_t syscallFgetattrlist = unixSyscallClass | 228U;
inline constexpr std::uint64_t syscallGetattrlistbulk = unixSyscallClass | 461U;
inline constexpr std::uint64_t syscallShmOpen = unixSyscallClass | 266U;
inline constexpr std::uint64_t syscallSharedRegionCheck = unixSyscallClass | 294U;
inline constexpr std::uint64_t syscallIssetugid = unixSyscallClass | 327U;
inline constexpr std::uint64_t syscallProcInfo = unixSyscallClass | 336U;
inline constexpr std::uint64_t syscallStat64 = unixSyscallClass | 338U;
inline constexpr std::uint64_t syscallLstat64 = unixSyscallClass | 340U;
inline constexpr std::uint64_t syscallFstat64 = unixSyscallClass | 339U;
inline constexpr std::uint64_t syscallGetfsstat64 = unixSyscallClass | 347U;
inline constexpr std::uint64_t syscallFstatfs64 = unixSyscallClass | 346U;
inline constexpr std::uint64_t syscallGetdirentries64 = unixSyscallClass | 344U;
inline constexpr std::uint64_t syscallBsdthreadRegister = unixSyscallClass | 366U;
inline constexpr std::uint64_t syscallThreadSelfid = unixSyscallClass | 372U;
inline constexpr std::uint64_t syscallMac = unixSyscallClass | 381U;
inline constexpr std::uint64_t syscallReadNoCancel = unixSyscallClass | 396U;
inline constexpr std::uint64_t syscallWriteNoCancel = unixSyscallClass | 397U;
inline constexpr std::uint64_t syscallOpenNoCancel = unixSyscallClass | 398U;
inline constexpr std::uint64_t syscallCloseNoCancel = unixSyscallClass | 399U;
inline constexpr std::uint64_t syscallFsgetpath = unixSyscallClass | 427U;
inline constexpr std::uint64_t syscallCsrctl = unixSyscallClass | 483U;
inline constexpr std::uint64_t syscallGetentropy = unixSyscallClass | 500U;
inline constexpr std::uint64_t syscallOpenat = unixSyscallClass | 463U;
inline constexpr std::uint64_t syscallFstatat64 = unixSyscallClass | 470U;
inline constexpr std::uint64_t syscallMapWithLinking = unixSyscallClass | 550U;
inline constexpr std::uint64_t csrSyscallCheck = 0;
// Rosa exposes a fully restrictive guest System Integrity Protection
// configuration. This is guest policy state, not a host kernel pointer or
// an assertion about the host's current configuration.
inline constexpr std::uint32_t guestCsrActiveConfig = 0;
inline constexpr std::uint64_t machdepThreadFastSetCthreadSelf = 3U;
inline constexpr std::uint64_t x86UserCthreadSelector = 0x0FU;
inline constexpr std::uint64_t x86MaximumUserPageAddress = 0x00007FFFFFFFF000ULL;
// Rosa currently executes exactly one guest thread. Keep its identity in the
// guest namespace rather than exposing a host pthread or Mach identifier.
inline constexpr std::uint64_t initialGuestThreadId = 1;
inline constexpr std::int32_t procInfoCallPidInfo = 0x02;
inline constexpr std::int32_t procInfoCallSetDyldImages = 0x0F;
inline constexpr std::uint32_t procPidShortBsdInfo = 0x0D;
inline constexpr std::uint32_t procPidUniqueIdentifierInfo = 0x11;
inline constexpr std::uint64_t carryFlag = 1U << 0U;
inline constexpr std::uint64_t reservedOneFlag = 1U << 1U;
inline constexpr std::size_t maximumControlledWrite = 16U * 1024U * 1024U;
inline constexpr std::size_t maximumLongPath = 8192;
inline constexpr std::size_t guestPathMaximum = 1024;
inline constexpr std::uint32_t guestOpenAccessMode = 0x3;
inline constexpr std::int32_t guestAtCurrentDirectory = -2;
inline constexpr std::uint64_t guestAtSymlinkNoFollow = 0x20;
inline constexpr std::uint32_t guestOpenReadOnly = 0x0;
inline constexpr std::uint32_t guestOpenNonblock = 0x4;
inline constexpr std::uint32_t guestOpenNoFollow = 0x100;
inline constexpr std::uint32_t guestOpenDirectory = 0x00100000;
inline constexpr std::uint32_t guestOpenNoFollowAny = 0x20000000;
inline constexpr std::uint32_t guestOpenCloseOnExec = 0x01000000;
inline constexpr std::uint32_t guestOpenRootDirectory =
    guestOpenDirectory | guestOpenNoFollowAny;
inline constexpr std::uint64_t guestProtectionRead = 0x1;
inline constexpr std::uint64_t guestProtectionWrite = 0x2;
inline constexpr std::uint64_t guestProtectionExecute = 0x4;
inline constexpr std::uint64_t guestProtectionMask =
    guestProtectionRead | guestProtectionWrite | guestProtectionExecute;
inline constexpr std::uint64_t guestMapPrivate = 0x2;
inline constexpr std::uint64_t guestMapResilientCodesign = 0x00040000;
inline constexpr std::uint64_t guestMapNoCache = 0x00000400;
// Flags that only advise the kernel and never change what a private file
// mapping contains.
inline constexpr std::uint64_t guestAdvisoryFileMapFlags =
    guestMapResilientCodesign | guestMapNoCache;
inline constexpr std::uint64_t minimumMmapAddress = 0x0000000100000000ULL;
inline constexpr std::uint64_t maximumUserMapEnd = 0x00007FFFFFFFF000ULL;
inline constexpr std::string_view guestCryptexDirectory = "System/Cryptexes/OS";
inline constexpr std::string_view guestDyldDirectory =
    "/System/Cryptexes/OS/System/Library/dyld";
inline constexpr std::string_view guestChrootMarker =
    "/AppleInternal/XBS/.isChrooted";
inline constexpr std::string_view guestRandomDevice = "/dev/urandom";
inline constexpr std::string_view guestPasswdDatabase = "/etc/passwd";
inline constexpr std::string_view guestMasterPasswdDatabase = "/etc/master.passwd";
inline constexpr std::string_view guestGroupDatabase = "/etc/group";
inline constexpr std::string_view guestFeatureFlagsSharedMemory =
    "com.apple.featureflags.shm";
inline constexpr std::string_view guestFeatureFlagsPathComponent = "/FeatureFlags/";
inline constexpr std::uint16_t guestModeDirectory = 0040000;
inline constexpr std::uint16_t guestModeReadExecute = 0555;
inline constexpr std::uint32_t guestFcntlDupFd = 0;
inline constexpr std::uint32_t guestFcntlGetFd = 1;
inline constexpr std::uint32_t guestFcntlSetFd = 2;
inline constexpr std::uint32_t guestFcntlGetFl = 3;
inline constexpr std::uint32_t guestFcntlGetLock = 7;
inline constexpr std::uint32_t guestFcntlSetLock = 8;
inline constexpr std::uint32_t guestFcntlSetLockWait = 9;
inline constexpr std::uint32_t guestFcntlGetPath = 50;
inline constexpr std::uint32_t guestFcntlDupFdCloseOnExec = 67;
inline constexpr std::uint32_t guestFdCloseOnExec = 1;
inline constexpr std::uint32_t guestAddressFamilyUnix = 1;
inline constexpr std::uint32_t guestSocketDatagram = 2;
inline constexpr std::size_t guestSockaddrUnixSize = 106;
inline constexpr std::string_view guestSystemLogSocket = "/var/run/syslog";
inline constexpr std::uint64_t guestIoctlFileDescriptorType = 0x4004667A;
inline constexpr std::uint64_t guestIoctlWindowSize = 0x40087468U;
inline constexpr std::uint64_t guestIoctlGetTermios = 0x40487413U;
inline constexpr std::uint32_t guestDeviceTypeTerminal = 3;
inline constexpr std::uint32_t guestMountWait = 1;
inline constexpr std::uint32_t guestMountNowait = 2;
inline constexpr std::uint32_t guestMountDwait = 4;
inline constexpr std::uint32_t guestMountReadOnly = 0x00000001;
inline constexpr std::uint32_t guestMountLocal = 0x00001000;
inline constexpr std::uint32_t guestMountRootfs = 0x00004000;
inline constexpr std::uint32_t guestSandboxCheckCall = 2;
inline constexpr std::uint32_t guestCsOpsStatus = 0;
inline constexpr std::uint32_t guestCsOpsDerEntitlementsBlob = 16;
inline constexpr std::uint32_t guestUnsignedCodeSigningStatus = 0;
inline constexpr std::uint64_t observedGuestDerEntitlementsBufferSize = 0x408;
inline constexpr std::uint64_t guestSandboxSyscallFilterType = 0x41;
inline constexpr std::uint64_t guestSandboxMachLookupFilterType = 0x6;
inline constexpr std::uint64_t guestSandboxObservedFlags = 1;
// The self form of a Sandbox check names no pid and filters by one of the
// caller's file descriptors.
inline constexpr std::uint64_t guestSandboxSelfTarget = 1;
inline constexpr std::uint64_t guestSandboxDescriptorFilterType = 0xF0;
inline constexpr std::uint64_t guestSandboxSelfDescriptorFlags = 0x20000005;
inline constexpr std::uint64_t guestMapWithLinkingSyscall = 550;
inline constexpr std::uint32_t guestAmfiDyldPolicyCall = 90;
inline constexpr std::uint64_t guestAmfiUnrestrictedDyldPolicy = 0x1DF;
inline constexpr std::array<std::uint32_t, 2> guestSysctlNameToOid{0, 3};
inline constexpr std::array<std::uint32_t, 3> guestLockdownModeOid{103, 101, 101};
inline constexpr std::array<std::uint32_t, 2> guestBootArgsOid{1, 143};
inline constexpr std::array<std::uint32_t, 2> guestOsversionOid{1, 65};
inline constexpr std::array<std::uint32_t, 2> guestKernelVersionOid{1, 4};
inline constexpr std::array<std::uint32_t, 2> guestProductVersionOid{1, 138};
inline constexpr std::array<std::uint32_t, 2> guestIosSupportVersionOid{1, 140};
inline constexpr std::array<std::uint32_t, 2> guestOsVariantStatusOid{1, 141};
inline constexpr std::array<std::uint32_t, 2> guestUserStack64Oid{1, 59};
inline constexpr std::array<std::uint32_t, 2> guestHwNcpuOid{6, 3};
inline constexpr std::array<std::uint32_t, 2> guestHwPagesizeOid{6, 7};
inline constexpr std::string_view guestLockdownModeName =
    "security.mac.lockdown_mode_state";
inline constexpr std::string_view guestBootArgsName = "kern.bootargs";
inline constexpr std::string_view guestKernelVersionName = "kern.version";
inline constexpr std::string_view guestProductVersionName =
    "kern.osproductversion";
inline constexpr std::string_view guestIosSupportVersionName =
    "kern.iossupportversion";
inline constexpr std::string_view guestOsVariantStatusName =
    "kern.osvariant_status";
inline constexpr std::string_view guestHwNcpuName = "hw.ncpu";
inline constexpr std::string_view guestHwPagesizeName = "hw.pagesize";
inline constexpr std::uint32_t guestLockdownModeState = 0;
inline constexpr std::array<std::uint8_t, 1> guestBootArgs{0};
inline constexpr std::size_t guestPthreadRegistrationDataSize = 56;
inline constexpr std::uint32_t observedGuestPthreadSize = 0x2000;
inline constexpr std::uint64_t observedDispatchQueueOffset = 0xA0;

struct GuestFsid {
    std::int32_t value[2];
};

static_assert(sizeof(GuestFsid) == 8);

inline void setSuccess(x86::X86State &state, std::uint64_t result) {
    state.rax = result;
    state.rflags = (state.rflags & ~carryFlag) | reservedOneFlag;
}

inline void setError(x86::X86State &state, int error) {
    state.rax = static_cast<std::uint64_t>(error);
    state.rflags = state.rflags | carryFlag | reservedOneFlag;
}

inline std::optional<std::string> readGuestCString(
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

inline bool isWithinDirectory(const std::filesystem::path &directory,
                       const std::filesystem::path &candidate) {
    const auto relative = candidate.lexically_relative(directory);
    if (relative.empty() || relative.is_absolute()) {
        return false;
    }
    const auto first = relative.begin();
    return first == relative.end() || *first != "..";
}

inline GuestFileDescriptor guestDescriptor(std::uint64_t argument) {
    return GuestFileDescriptor{std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(argument))};
}

// Reports a host call's result: a negative value means errno holds the error.
template <typename Result>
void setHostResult(x86::X86State &state, Result result) {
    if (result < 0) {
        setError(state, errno);
    } else {
        setSuccess(state, static_cast<std::uint64_t>(result));
    }
}

// Resolves a guest path against a base directory to a canonical host path.
// Intermediate symlinks always resolve; the final component resolves only
// when following, so lstat-style queries keep the link's own identity.
// Callers still apply GuestFileSpace::permitsHostPath where it matters.
inline std::expected<std::filesystem::path, int>
canonicalGuestPathFrom(const std::filesystem::path &base, const std::string &path,
                       bool followFinal = true) {
    if (path.empty()) {
        return std::unexpected(ENOENT);
    }
    const auto direct = std::filesystem::path{path};
    const auto query = direct.is_absolute() ? direct : base / direct;
    const auto finalName = query.filename();
    std::error_code error;
    if (followFinal || finalName.empty() || finalName == "." || finalName == "..") {
        auto canonical = std::filesystem::canonical(query, error);
        if (error) {
            return std::unexpected(error.value());
        }
        return canonical;
    }
    auto parent = std::filesystem::canonical(query.parent_path(), error);
    if (error) {
        return std::unexpected(error.value());
    }
    return parent / finalName;
}

inline std::expected<std::filesystem::path, int>
canonicalGuestPath(const GuestFileSpace &files, const std::string &path) {
    return canonicalGuestPathFrom(files.currentDirectory(), path);
}

inline bool isHostDirectory(const GuestOpenFile &file) {
    struct stat metadata {};
    return file.hostBacked() && ::fstat(file.host.get(), &metadata) == 0 &&
           S_ISDIR(metadata.st_mode);
}

inline std::runtime_error unsupported(const x86::X86State &state, guest::GuestAddress rip,
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

inline std::runtime_error unsupportedMachdep(const x86::X86State &state,
                                       guest::GuestAddress rip) {
    std::ostringstream stream;
    stream << "unsupported Darwin guest x86 machdep call\n"
           << "  number: " << std::dec << (state.rax & syscallNumberMask) << '\n'
           << "  RIP: 0x" << std::hex << rip.value << '\n'
           << "  args: 0x" << state.rdi << " 0x" << state.rsi << " 0x" << state.rdx;
    return std::runtime_error(stream.str());
}

// SyscallProcess.cpp
SyscallOutcome handleExit(SyscallCall &call);
SyscallOutcome handleBsdthreadRegister(SyscallCall &call);
SyscallOutcome handleThreadSelfid(SyscallCall &call);
SyscallOutcome handleGettimeofday(SyscallCall &call);
SyscallOutcome handleIssetugid(SyscallCall &call);
SyscallOutcome handleGetpid(SyscallCall &call);
SyscallOutcome handleGetuid(SyscallCall &call);
SyscallOutcome handleGeteuid(SyscallCall &call);
SyscallOutcome handleGettid(SyscallCall &call);
SyscallOutcome handleGetegid(SyscallCall &call);
SyscallOutcome handleGetrlimit(SyscallCall &call);
SyscallOutcome handleSigaction(SyscallCall &call);
SyscallOutcome handleCsops(SyscallCall &call);
SyscallOutcome handleCsopsAuditToken(SyscallCall &call);
SyscallOutcome handleProcInfo(SyscallCall &call);
SyscallOutcome handleGetentropy(SyscallCall &call);
SyscallOutcome handleCsrctl(SyscallCall &call);
SyscallOutcome handleMac(SyscallCall &call);

// SyscallSysctl.cpp
SyscallOutcome handleSysctl(SyscallCall &call);

// SyscallFiles.cpp
SyscallOutcome handleDup(SyscallCall &call);
SyscallOutcome handleIoctl(SyscallCall &call);
SyscallOutcome handleAccess(SyscallCall &call);
SyscallOutcome handleShmOpen(SyscallCall &call);
SyscallOutcome handleOpen(SyscallCall &call);
SyscallOutcome handleOpenat(SyscallCall &call);
SyscallOutcome handleStat64(SyscallCall &call);
SyscallOutcome handleLseek(SyscallCall &call);
SyscallOutcome handleFstat64(SyscallCall &call);
SyscallOutcome handleGetattrlist(SyscallCall &call);
SyscallOutcome handleFgetattrlist(SyscallCall &call);
SyscallOutcome handleGetattrlistbulk(SyscallCall &call);
SyscallOutcome handleGetfsstat64(SyscallCall &call);
SyscallOutcome handleFstatfs64(SyscallCall &call);
SyscallOutcome handleGetdirentries64(SyscallCall &call);
SyscallOutcome handleFstatat64(SyscallCall &call);
SyscallOutcome handleSocket(SyscallCall &call);
SyscallOutcome handleConnect(SyscallCall &call);
SyscallOutcome handleClose(SyscallCall &call);
SyscallOutcome handleRead(SyscallCall &call);
SyscallOutcome handleFcntl(SyscallCall &call);
SyscallOutcome handleFsgetpath(SyscallCall &call);
SyscallOutcome handleWrite(SyscallCall &call);

// SyscallMemory.cpp
SyscallOutcome handleMprotect(SyscallCall &call);
SyscallOutcome handleMadvise(SyscallCall &call);
SyscallOutcome handleMunmap(SyscallCall &call);
SyscallOutcome handleMmap(SyscallCall &call);
SyscallOutcome handleMapWithLinking(SyscallCall &call);
SyscallOutcome handleSharedRegionCheck(SyscallCall &call);

} // namespace rosa::darwin::detail
