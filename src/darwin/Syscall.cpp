#include "darwin/Syscall.h"

#include "darwin/Commpage.h"
#include "darwin/Process.h"
#include "darwin/SharedCache.h"

#include <libproc.h>
#include <mach/mach.h>
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

namespace rosa::darwin {
namespace {

constexpr std::uint64_t unixSyscallClass = 2U << 24U;
constexpr std::uint64_t machdepSyscallClass = 3U << 24U;
constexpr std::uint64_t syscallClassMask = 0xFF000000U;
constexpr std::uint64_t syscallNumberMask = 0x00FFFFFFU;
constexpr std::uint64_t syscallExit = unixSyscallClass | 1U;
constexpr std::uint64_t syscallRead = unixSyscallClass | 3U;
constexpr std::uint64_t syscallWrite = unixSyscallClass | 4U;
constexpr std::uint64_t syscallOpen = unixSyscallClass | 5U;
constexpr std::uint64_t syscallClose = unixSyscallClass | 6U;
constexpr std::uint64_t syscallGetpid = unixSyscallClass | 20U;
constexpr std::uint64_t syscallGetuid = unixSyscallClass | 24U;
constexpr std::uint64_t syscallGeteuid = unixSyscallClass | 25U;
constexpr std::uint64_t syscallGetrlimit = unixSyscallClass | 194U;
constexpr std::uint32_t guestRlimitPosixFlag = 0x1000U;
constexpr std::uint32_t guestRlimitCount = 9U;
constexpr std::uint64_t syscallSigaction = unixSyscallClass | 46U;
constexpr std::uint64_t syscallAccess = unixSyscallClass | 33U;
constexpr std::uint64_t syscallDup = unixSyscallClass | 41U;
constexpr std::uint64_t syscallIoctl = unixSyscallClass | 54U;
constexpr std::uint64_t syscallMunmap = unixSyscallClass | 73U;
constexpr std::uint64_t syscallMprotect = unixSyscallClass | 74U;
constexpr std::uint64_t syscallFcntl = unixSyscallClass | 92U;
constexpr std::uint64_t syscallSocket = unixSyscallClass | 97U;
constexpr std::uint64_t syscallConnect = unixSyscallClass | 98U;
constexpr std::uint64_t syscallGettimeofday = unixSyscallClass | 116U;
constexpr std::uint64_t syscallCsops = unixSyscallClass | 169U;
constexpr std::uint64_t syscallCsopsAuditToken = unixSyscallClass | 170U;
constexpr std::uint64_t syscallMmap = unixSyscallClass | 197U;
constexpr std::uint64_t syscallSysctl = unixSyscallClass | 202U;
constexpr std::uint64_t syscallGetattrlist = unixSyscallClass | 220U;
constexpr std::uint64_t syscallShmOpen = unixSyscallClass | 266U;
constexpr std::uint64_t syscallSharedRegionCheck = unixSyscallClass | 294U;
constexpr std::uint64_t syscallIssetugid = unixSyscallClass | 327U;
constexpr std::uint64_t syscallProcInfo = unixSyscallClass | 336U;
constexpr std::uint64_t syscallStat64 = unixSyscallClass | 338U;
constexpr std::uint64_t syscallFstat64 = unixSyscallClass | 339U;
constexpr std::uint64_t syscallGetfsstat64 = unixSyscallClass | 347U;
constexpr std::uint64_t syscallBsdthreadRegister = unixSyscallClass | 366U;
constexpr std::uint64_t syscallThreadSelfid = unixSyscallClass | 372U;
constexpr std::uint64_t syscallMac = unixSyscallClass | 381U;
constexpr std::uint64_t syscallReadNoCancel = unixSyscallClass | 396U;
constexpr std::uint64_t syscallWriteNoCancel = unixSyscallClass | 397U;
constexpr std::uint64_t syscallOpenNoCancel = unixSyscallClass | 398U;
constexpr std::uint64_t syscallCloseNoCancel = unixSyscallClass | 399U;
constexpr std::uint64_t syscallFsgetpath = unixSyscallClass | 427U;
constexpr std::uint64_t syscallCsrctl = unixSyscallClass | 483U;
constexpr std::uint64_t syscallGetentropy = unixSyscallClass | 500U;
constexpr std::uint64_t syscallOpenat = unixSyscallClass | 463U;
constexpr std::uint64_t syscallFstatat64 = unixSyscallClass | 470U;
constexpr std::uint64_t syscallMapWithLinking = unixSyscallClass | 550U;
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
constexpr std::int32_t procInfoCallPidInfo = 0x02;
constexpr std::int32_t procInfoCallSetDyldImages = 0x0F;
constexpr std::uint32_t procPidShortBsdInfo = 0x0D;
constexpr std::uint32_t procPidUniqueIdentifierInfo = 0x11;
constexpr std::uint64_t carryFlag = 1U << 0U;
constexpr std::uint64_t reservedOneFlag = 1U << 1U;
constexpr std::size_t maximumControlledWrite = 16U * 1024U * 1024U;
constexpr std::size_t maximumLongPath = 8192;
constexpr std::size_t guestPathMaximum = 1024;
constexpr std::uint32_t guestOpenDirectory = 0x00100000;
constexpr std::uint32_t guestOpenNoFollowAny = 0x20000000;
constexpr std::uint32_t guestOpenRootDirectory =
    guestOpenDirectory | guestOpenNoFollowAny;
constexpr std::uint64_t guestProtectionRead = 0x1;
constexpr std::uint64_t guestProtectionWrite = 0x2;
constexpr std::uint64_t guestProtectionExecute = 0x4;
constexpr std::uint64_t guestProtectionMask =
    guestProtectionRead | guestProtectionWrite | guestProtectionExecute;
constexpr std::uint64_t guestMapPrivate = 0x2;
constexpr std::uint64_t guestMapResilientCodesign = 0x00040000;
constexpr std::uint64_t guestObservedFileMapFlags =
    guestMapPrivate | guestMapResilientCodesign;
constexpr std::uint64_t minimumMmapAddress = 0x0000000100000000ULL;
constexpr std::uint64_t maximumUserMapEnd = 0x00007FFFFFFFF000ULL;
constexpr std::string_view guestCryptexDirectory = "System/Cryptexes/OS";
constexpr std::string_view guestDyldDirectory =
    "/System/Cryptexes/OS/System/Library/dyld";
constexpr std::string_view guestChrootMarker =
    "/AppleInternal/XBS/.isChrooted";
constexpr std::string_view guestRandomDevice = "/dev/urandom";
constexpr std::string_view guestFeatureFlagsSharedMemory =
    "com.apple.featureflags.shm";
constexpr std::uint16_t guestModeDirectory = 0040000;
constexpr std::uint16_t guestModeReadExecute = 0555;
constexpr std::uint32_t guestFcntlGetPath = 50;
constexpr std::uint32_t guestFcntlSetFd = 2;
constexpr std::uint32_t guestFdCloseOnExec = 1;
constexpr std::uint32_t guestAddressFamilyUnix = 1;
constexpr std::uint32_t guestSocketDatagram = 2;
constexpr std::size_t guestSockaddrUnixSize = 106;
constexpr std::string_view guestSystemLogSocket = "/var/run/syslog";
constexpr std::uint64_t guestIoctlFileDescriptorType = 0x4004667A;
constexpr std::uint32_t guestDeviceTypeTerminal = 3;
constexpr std::uint32_t guestMountWait = 1;
constexpr std::uint32_t guestMountNowait = 2;
constexpr std::uint32_t guestMountDwait = 4;
constexpr std::uint32_t guestMountReadOnly = 0x00000001;
constexpr std::uint32_t guestMountLocal = 0x00001000;
constexpr std::uint32_t guestMountRootfs = 0x00004000;
constexpr std::uint32_t guestSandboxCheckCall = 2;
constexpr std::uint32_t guestCsOpsStatus = 0;
constexpr std::uint32_t guestCsOpsDerEntitlementsBlob = 16;
constexpr std::uint32_t guestUnsignedCodeSigningStatus = 0;
constexpr std::uint64_t observedGuestDerEntitlementsBufferSize = 0x408;
constexpr std::uint64_t guestSandboxSyscallFilterType = 0x41;
constexpr std::uint64_t guestSandboxObservedFlags = 1;
constexpr std::uint64_t guestMapWithLinkingSyscall = 550;
constexpr std::uint32_t guestAmfiDyldPolicyCall = 90;
constexpr std::uint64_t guestAmfiUnrestrictedDyldPolicy = 0x1DF;
constexpr std::array<std::uint32_t, 2> guestSysctlNameToOid{0, 3};
constexpr std::array<std::uint32_t, 3> guestLockdownModeOid{103, 101, 101};
constexpr std::array<std::uint32_t, 2> guestBootArgsOid{1, 143};
constexpr std::array<std::uint32_t, 2> guestKernelVersionOid{1, 4};
constexpr std::array<std::uint32_t, 2> guestProductVersionOid{1, 138};
constexpr std::array<std::uint32_t, 2> guestIosSupportVersionOid{1, 140};
constexpr std::array<std::uint32_t, 2> guestOsVariantStatusOid{1, 141};
constexpr std::array<std::uint32_t, 2> guestUserStack64Oid{1, 59};
constexpr std::array<std::uint32_t, 2> guestHwNcpuOid{6, 3};
constexpr std::string_view guestLockdownModeName =
    "security.mac.lockdown_mode_state";
constexpr std::string_view guestBootArgsName = "kern.bootargs";
constexpr std::string_view guestKernelVersionName = "kern.version";
constexpr std::string_view guestProductVersionName =
    "kern.osproductversion";
constexpr std::string_view guestIosSupportVersionName =
    "kern.iossupportversion";
constexpr std::string_view guestOsVariantStatusName =
    "kern.osvariant_status";
constexpr std::string_view guestHwNcpuName = "hw.ncpu";
constexpr std::uint32_t guestLockdownModeState = 0;
constexpr std::array<std::uint8_t, 1> guestBootArgs{0};
constexpr std::size_t guestPthreadRegistrationDataSize = 56;
constexpr std::uint32_t observedGuestPthreadSize = 0x2000;
constexpr std::uint64_t observedDispatchQueueOffset = 0xA0;

template <typename T>
T decodeGuestPthreadField(std::span<const std::uint8_t> bytes,
                          std::size_t offset) {
    static_assert(std::is_integral_v<T>);
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        throw std::runtime_error(
            "guest pthread registration field exceeds its record");
    }
    T value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}
std::vector<std::uint8_t> hostKernelVersion() {
    std::size_t size = 0;
    if (::sysctlbyname("kern.version", nullptr, &size, nullptr, 0) != 0 ||
        size == 0) {
        throw std::runtime_error("failed to query host kern.version size");
    }
    std::vector<std::uint8_t> bytes(size);
    if (::sysctlbyname("kern.version", bytes.data(), &size, nullptr, 0) != 0) {
        throw std::runtime_error("failed to query host kern.version");
    }
    bytes.resize(size);
    return bytes;
}

std::int32_t hostLogicalCpuCount() {
    std::int32_t count = 0;
    std::size_t size = sizeof(count);
    if (::sysctlbyname(guestHwNcpuName.data(), &count, &size, nullptr, 0) != 0 ||
        size != sizeof(count) || count <= 0) {
        throw std::runtime_error("failed to query host hw.ncpu");
    }
    return count;
}

audit_token_t currentProcessAuditToken() {
    audit_token_t token{};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    const auto result = task_info(
        mach_task_self(), TASK_AUDIT_TOKEN,
        reinterpret_cast<task_info_t>(&token), &count);
    if (result != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT) {
        std::ostringstream stream;
        stream << "task_info(TASK_AUDIT_TOKEN) failed for guest syscall: "
               << result << " count=" << count;
        throw std::runtime_error(stream.str());
    }
    return token;
}

std::vector<std::uint8_t> hostProductVersion() {
    std::size_t size = 0;
    if (::sysctlbyname(guestProductVersionName.data(), nullptr, &size,
                       nullptr, 0) != 0 ||
        size == 0) {
        throw std::runtime_error(
            "failed to query host kern.osproductversion size");
    }
    std::vector<std::uint8_t> bytes(size);
    if (::sysctlbyname(guestProductVersionName.data(), bytes.data(), &size,
                       nullptr, 0) != 0) {
        throw std::runtime_error(
            "failed to query host kern.osproductversion");
    }
    bytes.resize(size);
    return bytes;
}

std::vector<std::uint8_t> hostIosSupportVersion() {
    std::size_t size = 0;
    if (::sysctlbyname(guestIosSupportVersionName.data(), nullptr, &size,
                       nullptr, 0) != 0 ||
        size == 0) {
        throw std::runtime_error(
            "failed to query host kern.iossupportversion size");
    }
    std::vector<std::uint8_t> bytes(size);
    if (::sysctlbyname(guestIosSupportVersionName.data(), bytes.data(), &size,
                       nullptr, 0) != 0) {
        throw std::runtime_error(
            "failed to query host kern.iossupportversion");
    }
    bytes.resize(size);
    return bytes;
}

std::vector<std::uint8_t> hostOsVariantStatus() {
    std::size_t size = 0;
    if (::sysctlbyname(guestOsVariantStatusName.data(), nullptr, &size,
                       nullptr, 0) != 0 ||
        size != sizeof(std::uint64_t)) {
        throw std::runtime_error(
            "failed to query host kern.osvariant_status size");
    }
    std::vector<std::uint8_t> bytes(size);
    if (::sysctlbyname(guestOsVariantStatusName.data(), bytes.data(), &size,
                       nullptr, 0) != 0 ||
        size != bytes.size()) {
        throw std::runtime_error(
            "failed to query host kern.osvariant_status");
    }
    return bytes;
}

struct GuestFsid {
    std::int32_t value[2];
};

static_assert(sizeof(GuestFsid) == 8);

struct GuestAttrlist {
    std::uint16_t bitmapCount;
    std::uint16_t reserved;
    std::uint32_t commonAttributes;
    std::uint32_t volumeAttributes;
    std::uint32_t directoryAttributes;
    std::uint32_t fileAttributes;
    std::uint32_t forkAttributes;
};

static_assert(sizeof(GuestAttrlist) == 24);

struct GuestAttributeReference {
    std::int32_t dataOffset;
    std::uint32_t length;
};

static_assert(sizeof(GuestAttributeReference) == 8);

struct GuestRootVolumeAttributes {
    std::uint32_t length;
    std::uint32_t device;
    GuestFsid fsid;
    std::uint32_t capabilities[4];
    std::uint32_t validCapabilities[4];
    std::uint8_t uuid[16];
};

static_assert(sizeof(GuestRootVolumeAttributes) == 64);
static_assert(offsetof(GuestRootVolumeAttributes, device) == 4);
static_assert(offsetof(GuestRootVolumeAttributes, fsid) == 8);
static_assert(offsetof(GuestRootVolumeAttributes, capabilities) == 16);
static_assert(offsetof(GuestRootVolumeAttributes, validCapabilities) == 32);
static_assert(offsetof(GuestRootVolumeAttributes, uuid) == 48);

struct GuestProcUniqueIdentifierInfo {
    std::array<std::uint8_t, 16> uuid{};
    std::uint64_t uniqueId{};
    std::uint64_t parentUniqueId{};
    std::int32_t idVersion{};
    std::uint32_t reserved2{};
    std::uint64_t reserved3{};
    std::uint64_t reserved4{};
};

static_assert(sizeof(GuestProcUniqueIdentifierInfo) == 56);
static_assert(offsetof(GuestProcUniqueIdentifierInfo, uniqueId) == 16);
static_assert(offsetof(GuestProcUniqueIdentifierInfo, idVersion) == 32);

struct GuestProcBsdShortInfo {
    std::uint32_t pid{};
    std::uint32_t parentPid{};
    std::uint32_t processGroupId{};
    std::uint32_t status{};
    std::array<char, 16> command{};
    std::uint32_t flags{};
    std::uint32_t uid{};
    std::uint32_t gid{};
    std::uint32_t realUid{};
    std::uint32_t realGid{};
    std::uint32_t savedUid{};
    std::uint32_t savedGid{};
    std::uint32_t reserved{};
};

static_assert(sizeof(GuestProcBsdShortInfo) == 64);
static_assert(offsetof(GuestProcBsdShortInfo, command) == 16);
static_assert(offsetof(GuestProcBsdShortInfo, flags) == 32);

GuestProcBsdShortInfo guestProcBsdShortInfo(std::uint64_t argument) {
    GuestProcBsdShortInfo result{};
    const auto returned = ::proc_pidinfo(
        ::getpid(), procPidShortBsdInfo, argument, &result,
        static_cast<int>(sizeof(result)));
    if (returned != sizeof(result)) {
        std::ostringstream reason;
        reason << "cannot query host short BSD process information: returned="
               << returned << " errno=" << errno;
        throw std::runtime_error(reason.str());
    }
    return result;
}

GuestProcUniqueIdentifierInfo guestProcUniqueIdentifierInfo(
    const std::array<std::uint8_t, 16> &executableUuid) {
    GuestProcUniqueIdentifierInfo result{};
    const auto returned = ::proc_pidinfo(
        ::getpid(), procPidUniqueIdentifierInfo, 0, &result,
        static_cast<int>(sizeof(result)));
    if (returned != sizeof(result)) {
        std::ostringstream reason;
        reason << "cannot query host process-generation identifiers: returned="
               << returned << " errno=" << errno;
        throw std::runtime_error(reason.str());
    }
    result.uuid = executableUuid;
    return result;
}

GuestRootVolumeAttributes guestRootVolumeAttributes() {
    GuestRootVolumeAttributes attributes{};
    attributes.length = sizeof(attributes);
    attributes.device = 1;
    attributes.fsid.value[0] = 1;
    // Match the modern root-volume properties dyld is probing: the root is a
    // sealed member of a volume group and supports getattrlist itself.
    constexpr std::uint32_t volumeGroupsAndSealed = 0x03000000;
    constexpr std::uint32_t attributeListInterface = 0x00000002;
    attributes.capabilities[0] = volumeGroupsAndSealed;
    attributes.validCapabilities[0] = volumeGroupsAndSealed;
    attributes.capabilities[1] = attributeListInterface;
    attributes.validCapabilities[1] = attributeListInterface;
    constexpr std::array<std::uint8_t, 16> rootUuid{
        'R', 'O', 'S', 'A', '-', 'R', 'O', 'O',
        'T', '-', 'V', 'O', 'L', 'U', 'M', 'E'};
    std::ranges::copy(rootUuid, attributes.uuid);
    return attributes;
}

std::vector<std::uint8_t> guestFullPathAttributes(
    std::string_view path) {
    constexpr std::size_t fixedSize =
        sizeof(std::uint32_t) + sizeof(GuestAttributeReference);
    const auto pathSize = path.size() + 1U;
    const auto unalignedSize = fixedSize + pathSize;
    const auto resultSize = (unalignedSize + 3U) & ~std::size_t{3U};
    std::vector<std::uint8_t> result(resultSize);
    const auto length = static_cast<std::uint32_t>(resultSize);
    const GuestAttributeReference reference{
        .dataOffset = static_cast<std::int32_t>(
            sizeof(GuestAttributeReference)),
        .length = static_cast<std::uint32_t>(pathSize),
    };
    std::memcpy(result.data(), &length, sizeof(length));
    std::memcpy(result.data() + sizeof(length), &reference,
                sizeof(reference));
    std::memcpy(result.data() + fixedSize, path.data(), path.size());
    return result;
}

// Darwin's x86_64 stat64 ABI is not the same record as the arm64 host's
// struct stat. Keep the guest layout explicit so host SDK changes cannot
// silently alter the bytes copied into guest memory.
struct GuestTimespec64 {
    std::int64_t seconds;
    std::int64_t nanoseconds;
};

struct GuestStat64 {
    std::int32_t device;
    std::uint16_t mode;
    std::uint16_t linkCount;
    std::uint64_t inode;
    std::uint32_t userId;
    std::uint32_t groupId;
    std::int32_t specialDevice;
    std::uint32_t padding;
    GuestTimespec64 accessTime;
    GuestTimespec64 modificationTime;
    GuestTimespec64 statusChangeTime;
    GuestTimespec64 birthTime;
    std::int64_t size;
    std::int64_t blockCount;
    std::int32_t blockSize;
    std::uint32_t flags;
    std::uint32_t generation;
    std::int32_t spare;
    std::int64_t quadSpare[2];
};

static_assert(sizeof(GuestTimespec64) == 16);
static_assert(sizeof(GuestStat64) == 144);
static_assert(offsetof(GuestStat64, mode) == 4);
static_assert(offsetof(GuestStat64, inode) == 8);
static_assert(offsetof(GuestStat64, accessTime) == 32);
static_assert(offsetof(GuestStat64, size) == 96);
static_assert(offsetof(GuestStat64, blockSize) == 112);
static_assert(offsetof(GuestStat64, quadSpare) == 128);

// getfsstat64 predates the host architecture split, but keep its guest ABI
// explicit just like stat64. In particular, both mount-name arrays are
// MAXPATHLEN bytes in the 64-bit-inode layout.
struct GuestStatfs64 {
    std::uint32_t blockSize;
    std::int32_t ioSize;
    std::uint64_t blocks;
    std::uint64_t blocksFree;
    std::uint64_t blocksAvailable;
    std::uint64_t files;
    std::uint64_t filesFree;
    GuestFsid fsid;
    std::uint32_t owner;
    std::uint32_t type;
    std::uint32_t flags;
    std::uint32_t subtype;
    char filesystemType[16];
    char mountedOn[1024];
    char mountedFrom[1024];
    std::uint32_t extendedFlags;
    std::uint32_t reserved[7];
};

static_assert(sizeof(GuestStatfs64) == 2168);
static_assert(offsetof(GuestStatfs64, fsid) == 48);
static_assert(offsetof(GuestStatfs64, flags) == 64);
static_assert(offsetof(GuestStatfs64, filesystemType) == 72);
static_assert(offsetof(GuestStatfs64, mountedOn) == 88);
static_assert(offsetof(GuestStatfs64, mountedFrom) == 1112);
static_assert(offsetof(GuestStatfs64, extendedFlags) == 2136);

GuestStatfs64 guestRootFilesystem() {
    GuestStatfs64 filesystem{};
    filesystem.blockSize = static_cast<std::uint32_t>(guest::guestPageSize);
    filesystem.ioSize = static_cast<std::int32_t>(guest::guestPageSize);
    filesystem.blocks = 1;
    filesystem.files = 1;
    filesystem.fsid = {{1, 0}};
    filesystem.flags =
        guestMountReadOnly | guestMountLocal | guestMountRootfs;
    constexpr std::string_view type = "apfs";
    constexpr std::string_view mountedOn = "/";
    constexpr std::string_view mountedFrom = "rosa-root";
    std::copy(type.begin(), type.end(), filesystem.filesystemType);
    std::copy(mountedOn.begin(), mountedOn.end(), filesystem.mountedOn);
    std::copy(mountedFrom.begin(), mountedFrom.end(),
              filesystem.mountedFrom);
    return filesystem;
}

GuestStat64 guestStat64FromHost(const struct stat &host) {
    GuestStat64 guest{};
    guest.device = static_cast<std::int32_t>(host.st_dev);
    guest.mode = static_cast<std::uint16_t>(host.st_mode);
    guest.linkCount = static_cast<std::uint16_t>(host.st_nlink);
    guest.inode = static_cast<std::uint64_t>(host.st_ino);
    guest.userId = static_cast<std::uint32_t>(host.st_uid);
    guest.groupId = static_cast<std::uint32_t>(host.st_gid);
    guest.specialDevice = static_cast<std::int32_t>(host.st_rdev);
    guest.accessTime = {
        .seconds = static_cast<std::int64_t>(host.st_atimespec.tv_sec),
        .nanoseconds = static_cast<std::int64_t>(host.st_atimespec.tv_nsec),
    };
    guest.modificationTime = {
        .seconds = static_cast<std::int64_t>(host.st_mtimespec.tv_sec),
        .nanoseconds = static_cast<std::int64_t>(host.st_mtimespec.tv_nsec),
    };
    guest.statusChangeTime = {
        .seconds = static_cast<std::int64_t>(host.st_ctimespec.tv_sec),
        .nanoseconds = static_cast<std::int64_t>(host.st_ctimespec.tv_nsec),
    };
    guest.birthTime = {
        .seconds = static_cast<std::int64_t>(host.st_birthtimespec.tv_sec),
        .nanoseconds = static_cast<std::int64_t>(host.st_birthtimespec.tv_nsec),
    };
    guest.size = static_cast<std::int64_t>(host.st_size);
    guest.blockCount = static_cast<std::int64_t>(host.st_blocks);
    guest.blockSize = static_cast<std::int32_t>(host.st_blksize);
    guest.flags = static_cast<std::uint32_t>(host.st_flags);
    guest.generation = static_cast<std::uint32_t>(host.st_gen);
    return guest;
}

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

struct GuestAmfiDyldPolicyRequest {
    std::uint64_t inputFlags;
    std::uint64_t outputAddress;
};

static_assert(sizeof(GuestAmfiDyldPolicyRequest) == 16);

struct GuestTimeval64 {
    std::int64_t seconds;
    std::int32_t microseconds;
    std::int32_t padding;
};

static_assert(sizeof(GuestTimeval64) == 16);

struct GuestTimezone {
    std::int32_t minutesWest;
    std::int32_t daylightSavingsTime;
};

static_assert(sizeof(GuestTimezone) == 8);

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

std::optional<guest::GuestAddress>
findMmapRange(const guest::AddressSpace &addressSpace, std::uint64_t size) {
    const auto alignUpToPage = [](std::uint64_t value)
        -> std::optional<std::uint64_t> {
        constexpr auto mask =
            static_cast<std::uint64_t>(guest::guestPageSize - 1U);
        if (value > std::numeric_limits<std::uint64_t>::max() - mask) {
            return std::nullopt;
        }
        return (value + mask) & ~mask;
    };

    auto candidate = minimumMmapAddress;
    auto mappings = addressSpace.mappingInfos();
    std::ranges::sort(mappings, {}, [](const guest::MappingInfo &mapping) {
        return mapping.base.value;
    });
    for (const auto &mapping : mappings) {
        const auto mappingEnd = mapping.base.value + mapping.size;
        if (mappingEnd <= candidate) {
            continue;
        }
        if (candidate <= mapping.base.value &&
            size <= mapping.base.value - candidate) {
            return guest::GuestAddress{candidate};
        }
        const auto next = alignUpToPage(mappingEnd);
        if (!next) {
            return std::nullopt;
        }
        candidate = *next;
    }
    if (candidate <= maximumUserMapEnd &&
        size <= maximumUserMapEnd - candidate) {
        return guest::GuestAddress{candidate};
    }
    return std::nullopt;
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

// Layouts mirror Apple's mach/dyld_pager.h and mach-o/fixup-chains.h for the
// map_with_linking_np blob. All integers are little-endian.
struct MapWithLinkingRegion {
    std::int32_t fd{};
    std::uint32_t protections{};
    std::uint64_t fileOffset{};
    std::uint64_t address{};
    std::uint64_t size{};
};

template <typename T>
T readMapWithLinkingField(const std::vector<std::uint8_t> &bytes, std::size_t offset) {
    static_assert(std::is_integral_v<T>);
    T value{};
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        throw std::out_of_range("map_with_linking field exceeds its extent");
    }
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

// Applies one page of DYLD_CHAINED_PTR_64 chained fixups exactly like XNU's
// fixupPage64: bind entries resolve through the blob's pre-resolved address
// table, rebase entries add the blob slide (or image address for
// offset-based chains). Throws std::out_of_range for a structurally short
// blob and std::runtime_error for guest-memory faults so the caller can map
// each to the right guest-visible result.
void applyMapWithLinkingPageFixups(guest::AddressSpace &addressSpace,
                                   const std::vector<std::uint8_t> &blob,
                                   std::uint64_t pageAddress) {
    constexpr std::uint16_t chainStartNone = 0xFFFF;
    constexpr std::uint64_t bindBit = 1ULL << 63U;
    constexpr std::uint64_t pageSize = guest::guestPageSize;

    const auto pointerFormat = readMapWithLinkingField<std::uint16_t>(blob, 6);
    const bool offsetBased = pointerFormat == 6;
    const auto bindsOffset = readMapWithLinkingField<std::uint32_t>(blob, 8);
    const auto bindsCount = readMapWithLinkingField<std::uint32_t>(blob, 12);
    const auto chainsOffset = readMapWithLinkingField<std::uint32_t>(blob, 16);
    const auto slide = readMapWithLinkingField<std::uint64_t>(blob, 24);
    const auto imageAddress = readMapWithLinkingField<std::uint64_t>(blob, 32);

    const auto segCount = readMapWithLinkingField<std::uint32_t>(blob, chainsOffset);
    for (std::uint32_t segIndex = 0; segIndex < segCount; ++segIndex) {
        const auto segInfoOffset =
            readMapWithLinkingField<std::uint32_t>(blob, chainsOffset + 4 + segIndex * 4U);
        const auto segOffset = static_cast<std::uint64_t>(chainsOffset) + segInfoOffset;
        if (segOffset > blob.size()) {
            throw std::out_of_range("map_with_linking chained segment escapes its blob");
        }
        const auto segSize = readMapWithLinkingField<std::uint32_t>(blob, segOffset);
        const auto segmentOffset = readMapWithLinkingField<std::uint64_t>(blob, segOffset + 8);
        const auto pageCount = readMapWithLinkingField<std::uint16_t>(blob, segOffset + 20);
        if (segSize < 24 ||
            segOffset + segSize > blob.size() ||
            segOffset + 22 > blob.size() ||
            static_cast<std::uint64_t>(pageCount) * 2U > blob.size() - (segOffset + 22)) {
            throw std::out_of_range("map_with_linking chained segment exceeds its blob");
        }
        const auto segStart = imageAddress + segmentOffset;
        const auto segEnd = segStart + static_cast<std::uint64_t>(pageCount) * pageSize;
        if (segStart > pageAddress || pageAddress >= segEnd) {
            continue;
        }
        const auto pageIndex = (pageAddress - segStart) / pageSize;
        const auto firstStart = readMapWithLinkingField<std::uint16_t>(
            blob, segOffset + 22 + pageIndex * 2U);
        if (firstStart == chainStartNone) {
            return;
        }
        auto location = pageAddress + firstStart;
        while (true) {
            if (location < pageAddress || location + sizeof(std::uint64_t) > pageAddress + pageSize) {
                throw std::out_of_range("map_with_linking chain leaves its page");
            }
            const auto value = addressSpace.readU64(guest::GuestAddress{location});
            const bool isBind = (value & bindBit) != 0;
            const auto delta = ((value >> 51U) & 0xFFFU) * 4U;
            if (isBind) {
                const auto ordinal = value & 0xFFFFFFULL;
                if (ordinal >= bindsCount) {
                    throw std::out_of_range("map_with_linking bind ordinal exceeds its table");
                }
                const auto addend = (value >> 24U) & 0xFFULL;
                const auto target = readMapWithLinkingField<std::uint64_t>(
                    blob, static_cast<std::uint64_t>(bindsOffset) + ordinal * 8U);
                addressSpace.writeU64(guest::GuestAddress{location}, target + addend);
            } else {
                const auto target = value & 0xFFFFFFFFFULL;
                const auto high8 = (value >> 36U) & 0xFFULL;
                const auto adjust = offsetBased ? imageAddress : slide;
                addressSpace.writeU64(guest::GuestAddress{location},
                                      target + adjust + (high8 << 56U));
            }
            if (delta == 0) {
                return;
            }
            if (delta > pageSize || location + delta < pageAddress ||
                location + delta + sizeof(std::uint64_t) > pageAddress + pageSize) {
                throw std::out_of_range("map_with_linking chain delta leaves its page");
            }
            location += delta;
        }
    }
    throw std::out_of_range("no map_with_linking chained segment covers the page");
}

} // namespace

SyscallOutcome SyscallDispatcher::dispatch(guest::AddressSpace &addressSpace,
                                           x86::X86State &state,
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
    if (number == syscallBsdthreadRegister) {
        if (pthreadRegistration_) {
            setError(state, EINVAL);
            return {};
        }
        if (state.r8 != guestPthreadRegistrationDataSize) {
            std::ostringstream reason;
            reason << "unsupported bsdthread_register data size 0x"
                   << std::hex << state.r8;
            throw unsupported(state, syscallRip, reason.str());
        }
        std::vector<std::uint8_t> data;
        try {
            addressSpace.validateAccess(guest::GuestAddress{state.rdi}, 1,
                                        guest::Permission::Execute);
            addressSpace.validateAccess(guest::GuestAddress{state.rsi}, 1,
                                        guest::Permission::Execute);
            data = addressSpace.readBytes(
                guest::GuestAddress{state.r10},
                guestPthreadRegistrationDataSize);
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10},
                guestPthreadRegistrationDataSize,
                guest::Permission::Write);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }

        const auto version =
            decodeGuestPthreadField<std::uint64_t>(data, 0);
        const auto dispatchQueueOffset =
            decodeGuestPthreadField<std::uint64_t>(data, 8);
        const auto mainQos =
            decodeGuestPthreadField<std::uint64_t>(data, 16);
        const auto tsdOffset =
            decodeGuestPthreadField<std::uint32_t>(data, 24);
        const auto returnToKernelOffset =
            decodeGuestPthreadField<std::uint32_t>(data, 28);
        const auto machThreadSelfOffset =
            decodeGuestPthreadField<std::uint32_t>(data, 32);
        const auto stackAddressHint =
            decodeGuestPthreadField<std::uint64_t>(data, 36);
        const auto mutexDefaultPolicy =
            decodeGuestPthreadField<std::uint32_t>(data, 44);
        const auto joinableOffsetBits =
            decodeGuestPthreadField<std::uint32_t>(data, 48);
        const auto workqueueQuantumExpiryOffset =
            decodeGuestPthreadField<std::uint32_t>(data, 52);
        if (state.rdx != observedGuestPthreadSize ||
            version != guestPthreadRegistrationDataSize ||
            state.r9 != observedDispatchQueueOffset ||
            dispatchQueueOffset != observedDispatchQueueOffset ||
            mainQos != 0 || tsdOffset != 0xE0 ||
            returnToKernelOffset != 0x28 ||
            machThreadSelfOffset != 0x18 || stackAddressHint != 0 ||
            mutexDefaultPolicy != 0 || joinableOffsetBits != 0x188 ||
            workqueueQuantumExpiryOffset != 0x3C0) {
            std::ostringstream reason;
            reason << "unsupported bsdthread_register record: pthread-size=0x"
                   << std::hex << state.rdx << " version=0x" << version
                   << " dq-offset=0x" << dispatchQueueOffset
                   << " tsd-offset=0x" << tsdOffset
                   << " return-offset=0x" << returnToKernelOffset
                   << " thread-port-offset=0x" << machThreadSelfOffset
                   << " joinable-bits=0x" << joinableOffsetBits
                   << " quantum-offset=0x"
                   << workqueueQuantumExpiryOffset;
            throw unsupported(state, syscallRip, reason.str());
        }

        // The kernel ABI copies this packed record back even when outgoing
        // values are zero. Preserve those zeros: Rosa has no child-thread
        // stack allocator or QoS/mutex policy to advertise yet.
        addressSpace.writeBytes(guest::GuestAddress{state.r10}, data);
        pthreadRegistration_ = GuestPthreadRegistration{
            .threadStart = guest::GuestAddress{state.rdi},
            .workqueueThreadStart = guest::GuestAddress{state.rsi},
            .pthreadSize = static_cast<std::uint32_t>(state.rdx),
            .dataAddress = guest::GuestAddress{state.r10},
            .dataSize = state.r8,
            .dispatchQueueOffset = dispatchQueueOffset,
            .tsdOffset = tsdOffset,
            .returnToKernelOffset = returnToKernelOffset,
            .machThreadSelfOffset = machThreadSelfOffset,
            .joinableOffsetBits = joinableOffsetBits,
            .workqueueQuantumExpiryOffset = workqueueQuantumExpiryOffset,
        };
        // A zero return is the ABI's documented old-kernel compatibility
        // value. It avoids advertising workqueue/kevent/QoS features Rosa
        // cannot yet provide while allowing single-thread pthread startup.
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallThreadSelfid) {
        setSuccess(state, initialGuestThreadId);
        return {};
    }
    if (number == syscallGettimeofday) {
        const auto timevalAddress = guest::GuestAddress{state.rdi};
        const auto timezoneAddress = guest::GuestAddress{state.rsi};
        const auto absoluteTimeAddress = guest::GuestAddress{state.rdx};
        try {
            if (state.rdi != 0) {
                addressSpace.validateAccess(timevalAddress,
                                            sizeof(GuestTimeval64),
                                            guest::Permission::Write);
            }
            if (state.rsi != 0) {
                addressSpace.validateAccess(timezoneAddress,
                                            sizeof(GuestTimezone),
                                            guest::Permission::Write);
            }
            if (state.rdx != 0) {
                addressSpace.validateAccess(absoluteTimeAddress,
                                            sizeof(std::uint64_t),
                                            guest::Permission::Write);
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }

        GuestTimeval64 guestTime{};
        std::uint64_t absoluteTime = 0;
        if (state.rdi != 0 || state.rdx != 0) {
            const auto absoluteBefore = sampleX86TimestampCounter() / 2U;
            timeval hostTime{};
            if (::gettimeofday(&hostTime, nullptr) != 0 ||
                hostTime.tv_sec < 0 || hostTime.tv_usec < 0 ||
                hostTime.tv_usec >= 1'000'000) {
                throw std::runtime_error("cannot sample the host wall clock");
            }
            const auto absoluteAfter = sampleX86TimestampCounter() / 2U;
            absoluteTime =
                absoluteBefore + ((absoluteAfter - absoluteBefore) / 2U);
            // XNU deliberately narrows seconds through uint32_t so x86 and
            // arm64 observe the same 64-bit user timeval representation.
            guestTime.seconds = static_cast<std::uint32_t>(hostTime.tv_sec);
            guestTime.microseconds =
                static_cast<std::int32_t>(hostTime.tv_usec);
        }

        if (state.rdi != 0) {
            std::array<std::uint8_t, sizeof(guestTime)> bytes{};
            std::memcpy(bytes.data(), &guestTime, sizeof(guestTime));
            addressSpace.writeBytes(timevalAddress, bytes);
        }
        if (state.rsi != 0) {
            // Darwin's kernel timezone is obsolete process-global state. Rosa
            // exposes the normal UTC/no-DST default without borrowing host
            // kernel policy.
            constexpr std::array<std::uint8_t, sizeof(GuestTimezone)>
                utcTimezone{};
            addressSpace.writeBytes(timezoneAddress, utcTimezone);
        }
        if (state.rdx != 0) {
            addressSpace.writeU64(absoluteTimeAddress, absoluteTime);
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallIssetugid) {
        // The controlled guest image is launched directly by Rosa without a
        // set-user-ID or set-group-ID transition. Keep this guest process
        // policy independent of the credentials of Rosa's host process.
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallDup) {
        const auto descriptor = GuestFileDescriptor{
            std::bit_cast<std::int32_t>(
                static_cast<std::uint32_t>(state.rdi))};
        const auto duplicate = fileSpace_.duplicate(descriptor);
        if (!duplicate) {
            setError(state, EBADF);
            return {};
        }
        setSuccess(state, static_cast<std::uint32_t>(duplicate->value));
        return {};
    }
    if (number == syscallIoctl) {
        const auto descriptor = std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.rdi));
        if (state.rsi != guestIoctlFileDescriptorType) {
            std::ostringstream reason;
            reason << "only ioctl(FIODTYPE) on a standard guest descriptor is implemented; got fd="
                   << std::dec << descriptor << " request=0x" << std::hex
                   << state.rsi;
            throw unsupported(state, syscallRip, reason.str());
        }
        if (descriptor < STDIN_FILENO || descriptor > STDERR_FILENO) {
            setError(state, EBADF);
            return {};
        }
        try {
            addressSpace.writeU32(guest::GuestAddress{state.rdx},
                                  guestDeviceTypeTerminal);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        // The initial standard streams are Rosa's synthetic console. Model
        // them as a Darwin tty without exposing a host fd or host ioctl.
        setSuccess(state, 0);
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
        if (*policy == "AMFI" && call == guestAmfiDyldPolicyCall) {
            GuestAmfiDyldPolicyRequest request{};
            try {
                const auto requestBytes = addressSpace.readBytes(
                    guest::GuestAddress{state.rdx}, sizeof(request));
                std::memcpy(&request, requestBytes.data(), sizeof(request));
                addressSpace.validateAccess(
                    guest::GuestAddress{request.outputAddress},
                    sizeof(std::uint64_t), guest::Permission::Write);
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            if (request.inputFlags != 0) {
                std::ostringstream reason;
                reason << "unsupported AMFI dyld-policy input flags 0x"
                       << std::hex << request.inputFlags;
                throw unsupported(state, syscallRip, reason.str());
            }

            // This initial guest process is an unsigned, unrestricted,
            // unencrypted development executable. A matching x86_64 process
            // reports these dyld policy bits: @ paths, path variables, custom
            // cache, fallback paths, print variables, interposing, embedded
            // variables, and development variables. Restricted/encrypted
            // process policy remains unsupported above.
            addressSpace.writeU64(
                guest::GuestAddress{request.outputAddress},
                guestAmfiUnrestrictedDyldPolicy);
            setSuccess(state, 0);
            return {};
        }
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
            if (state.r8 == 0 || state.r9 == 0 ||
                state.r9 > guestPathMaximum || state.rdx == 0 ||
                state.r10 == 0) {
                throw unsupported(
                    state, syscallRip,
                    "malformed CTL_SYSCTL/CTL_SYSCTL_NAME2OID request");
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
            std::span<const std::uint32_t> resultOid;
            if (requestedName == guestLockdownModeName) {
                resultOid = guestLockdownModeOid;
            } else if (requestedName == guestBootArgsName) {
                resultOid = guestBootArgsOid;
            } else if (requestedName == guestKernelVersionName) {
                resultOid = guestKernelVersionOid;
            } else if (requestedName == guestProductVersionName) {
                resultOid = guestProductVersionOid;
            } else if (requestedName == guestIosSupportVersionName) {
                resultOid = guestIosSupportVersionOid;
            } else if (requestedName == guestOsVariantStatusName) {
                resultOid = guestOsVariantStatusOid;
            } else if (requestedName == guestHwNcpuName) {
                resultOid = guestHwNcpuOid;
            } else {
                std::ostringstream reason;
                reason << "unsupported guest sysctl name \"" << requestedName
                       << '"';
                throw unsupported(state, syscallRip, reason.str());
            }
            const auto resultSize =
                resultOid.size() * sizeof(std::uint32_t);
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
            std::vector<std::uint8_t> oidBytes(resultSize);
            std::memcpy(oidBytes.data(), resultOid.data(), resultSize);
            addressSpace.writeBytes(guest::GuestAddress{state.rdx}, oidBytes);
            addressSpace.writeU64(guest::GuestAddress{state.r10}, resultSize);
            setSuccess(state, 0);
            return {};
        }

        if (std::ranges::equal(name, guestKernelVersionOid)) {
            if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
                throw unsupported(
                    state, syscallRip,
                    "only a read or size query of guest kern.version is implemented");
            }
            const auto version = hostKernelVersion();
            std::uint64_t outputCapacity = 0;
            try {
                outputCapacity = addressSpace.readU64(
                    guest::GuestAddress{state.r10});
                addressSpace.validateAccess(
                    guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                    guest::Permission::Write);
                if (state.rdx != 0 && outputCapacity >= version.size()) {
                    addressSpace.validateAccess(
                        guest::GuestAddress{state.rdx}, version.size(),
                        guest::Permission::Write);
                }
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            if (state.rdx != 0 && outputCapacity < version.size()) {
                // The x86_64 Darwin kernel returns ENOMEM, leaves the short
                // output untouched, and reports zero bytes copied.
                addressSpace.writeU64(guest::GuestAddress{state.r10}, 0);
                setError(state, ENOMEM);
                return {};
            }
            if (state.rdx != 0) {
                addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                        version);
            }
            addressSpace.writeU64(guest::GuestAddress{state.r10},
                                  version.size());
            setSuccess(state, 0);
            return {};
        }

        if (std::ranges::equal(name, guestHwNcpuOid)) {
            if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
                throw unsupported(
                    state, syscallRip,
                    "only a read or size query of guest hw.ncpu is implemented");
            }
            // Native and Rosetta x86 callers observe the same host CPU
            // count, so report it from a host-owned value like kern.version.
            const auto count = hostLogicalCpuCount();
            std::uint64_t outputCapacity = 0;
            try {
                outputCapacity = addressSpace.readU64(
                    guest::GuestAddress{state.r10});
                addressSpace.validateAccess(
                    guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                    guest::Permission::Write);
                if (state.rdx != 0) {
                    addressSpace.validateAccess(
                        guest::GuestAddress{state.rdx}, sizeof(count),
                        guest::Permission::Write);
                }
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            if (state.rdx != 0 && outputCapacity < sizeof(count)) {
                addressSpace.writeU64(guest::GuestAddress{state.r10}, 0);
                setError(state, ENOMEM);
                return {};
            }
            if (state.rdx != 0) {
                std::array<std::uint8_t, sizeof(count)> countBytes{};
                std::memcpy(countBytes.data(), &count, sizeof(count));
                addressSpace.writeBytes(guest::GuestAddress{state.rdx}, countBytes);
            }
            addressSpace.writeU64(guest::GuestAddress{state.r10}, sizeof(count));
            setSuccess(state, 0);
            return {};
        }

        if (std::ranges::equal(name, guestProductVersionOid)) {
            if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
                throw unsupported(
                    state, syscallRip,
                    "only a read or size query of guest kern.osproductversion is implemented");
            }
            const auto version = hostProductVersion();
            std::uint64_t outputCapacity = 0;
            try {
                outputCapacity = addressSpace.readU64(
                    guest::GuestAddress{state.r10});
                addressSpace.validateAccess(
                    guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                    guest::Permission::Write);
                if (state.rdx != 0 && outputCapacity >= version.size()) {
                    addressSpace.validateAccess(
                        guest::GuestAddress{state.rdx}, version.size(),
                        guest::Permission::Write);
                }
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            if (state.rdx != 0 && outputCapacity < version.size()) {
                addressSpace.writeU64(guest::GuestAddress{state.r10}, 0);
                setError(state, ENOMEM);
                return {};
            }
            if (state.rdx != 0) {
                addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                        version);
            }
            addressSpace.writeU64(guest::GuestAddress{state.r10},
                                  version.size());
            setSuccess(state, 0);
            return {};
        }

        if (std::ranges::equal(name, guestIosSupportVersionOid)) {
            if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
                throw unsupported(
                    state, syscallRip,
                    "only a read or size query of guest kern.iossupportversion is implemented");
            }
            const auto version = hostIosSupportVersion();
            std::uint64_t outputCapacity = 0;
            try {
                outputCapacity = addressSpace.readU64(
                    guest::GuestAddress{state.r10});
                addressSpace.validateAccess(
                    guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                    guest::Permission::Write);
                if (state.rdx != 0 && outputCapacity >= version.size()) {
                    addressSpace.validateAccess(
                        guest::GuestAddress{state.rdx}, version.size(),
                        guest::Permission::Write);
                }
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            if (state.rdx != 0 && outputCapacity < version.size()) {
                addressSpace.writeU64(guest::GuestAddress{state.r10}, 0);
                setError(state, ENOMEM);
                return {};
            }
            if (state.rdx != 0) {
                addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                        version);
            }
            addressSpace.writeU64(guest::GuestAddress{state.r10},
                                  version.size());
            setSuccess(state, 0);
            return {};
        }

        if (std::ranges::equal(name, guestOsVariantStatusOid)) {
            if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
                throw unsupported(
                    state, syscallRip,
                    "only a read or size query of guest kern.osvariant_status is implemented");
            }
            const auto status = hostOsVariantStatus();
            std::uint64_t outputCapacity = 0;
            try {
                outputCapacity = addressSpace.readU64(
                    guest::GuestAddress{state.r10});
                addressSpace.validateAccess(
                    guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                    guest::Permission::Write);
                if (state.rdx != 0 && outputCapacity >= status.size()) {
                    addressSpace.validateAccess(
                        guest::GuestAddress{state.rdx}, status.size(),
                        guest::Permission::Write);
                }
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            if (state.rdx != 0 && outputCapacity < status.size()) {
                addressSpace.writeU64(guest::GuestAddress{state.r10}, 0);
                setError(state, ENOMEM);
                return {};
            }
            if (state.rdx != 0) {
                addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                        status);
            }
            addressSpace.writeU64(guest::GuestAddress{state.r10},
                                  status.size());
            setSuccess(state, 0);
            return {};
        }

        if (std::ranges::equal(name, guestUserStack64Oid)) {
            if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
                throw unsupported(
                    state, syscallRip,
                    "only a read or size query of guest kern.usrstack64 is implemented");
            }
            std::uint64_t outputCapacity = 0;
            try {
                outputCapacity = addressSpace.readU64(
                    guest::GuestAddress{state.r10});
                addressSpace.validateAccess(
                    guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                    guest::Permission::Write);
                if (state.rdx != 0 &&
                    outputCapacity >= sizeof(initialUserStackTop)) {
                    addressSpace.validateAccess(
                        guest::GuestAddress{state.rdx},
                        sizeof(initialUserStackTop), guest::Permission::Write);
                }
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            if (state.rdx != 0 &&
                outputCapacity < sizeof(initialUserStackTop)) {
                setError(state, ENOMEM);
                return {};
            }
            if (state.rdx != 0) {
                addressSpace.writeU64(guest::GuestAddress{state.rdx},
                                      initialUserStackTop);
            }
            addressSpace.writeU64(guest::GuestAddress{state.r10},
                                  sizeof(initialUserStackTop));
            setSuccess(state, 0);
            return {};
        }

        if (std::ranges::equal(name, guestBootArgsOid)) {
            if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
                throw unsupported(
                    state, syscallRip,
                    "only a read or size query of guest kern.bootargs is implemented");
            }
            std::uint64_t outputCapacity = 0;
            try {
                outputCapacity = addressSpace.readU64(
                    guest::GuestAddress{state.r10});
                addressSpace.validateAccess(
                    guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                    guest::Permission::Write);
                if (state.rdx != 0) {
                    addressSpace.validateAccess(
                        guest::GuestAddress{state.rdx}, guestBootArgs.size(),
                        guest::Permission::Write);
                }
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            if (state.rdx != 0 && outputCapacity < guestBootArgs.size()) {
                setError(state, ENOMEM);
                return {};
            }
            if (state.rdx != 0) {
                addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                        guestBootArgs);
            }
            addressSpace.writeU64(guest::GuestAddress{state.r10},
                                  guestBootArgs.size());
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
    if (number == syscallGetuid) {
        // Same one-process model as getpid: the host user ID is the guest's
        // externally observable real user ID.
        setSuccess(state, static_cast<std::uint64_t>(::getuid()));
        return {};
    }
    if (number == syscallGeteuid) {
        // Same one-process model: the host effective user ID is the guest's.
        setSuccess(state, static_cast<std::uint64_t>(::geteuid()));
        return {};
    }
    if (number == syscallGetrlimit) {
        // The libc wrapper ORs in _RLIMIT_POSIX_FLAG (0x1000); XNU masks it
        // out and rejects resources past RLIM_NLIMITS. Answer from the host
        // process limits, which launchd provisions identically for the
        // translated guest. struct rlimit is two little-endian u64s.
        const auto resource =
            static_cast<std::uint32_t>(state.rdi) & ~guestRlimitPosixFlag;
        if (resource >= guestRlimitCount) {
            setError(state, EINVAL);
            return {};
        }
        struct rlimit limits{};
        if (::getrlimit(resource, &limits) != 0) {
            setError(state, errno);
            return {};
        }
        std::array<std::uint8_t, sizeof(limits)> limitBytes{};
        static_assert(sizeof(limitBytes) == 16);
        std::memcpy(limitBytes.data(), &limits, sizeof(limits));
        try {
            addressSpace.writeBytes(guest::GuestAddress{state.rsi}, limitBytes);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallSigaction) {
        // Rosa has no signal delivery: the single guest thread never receives
        // a host signal. Keep dispositions as task-local guest state so
        // library initialization can install and query handlers and proceed.
        // Arguments are the signal number in RDI, the new 16-byte struct
        // sigaction in RSI (or null to query), and the old-action copyout in
        // RDX (or null to skip it).
        if (state.rdi < 1 || state.rdi > 31) {
            setError(state, EINVAL);
            return {};
        }
        const auto signum = static_cast<std::int32_t>(state.rdi);
        const auto previous = signalDispositions_.contains(signum)
                                  ? signalDispositions_.at(signum)
                                  : GuestSignalDisposition{};
        if (state.rsi != 0) {
            GuestSignalDisposition next{};
            try {
                const auto bytes =
                    addressSpace.readBytes(guest::GuestAddress{state.rsi}, 16);
                std::memcpy(&next.handlerAddress, bytes.data(), 8);
                std::memcpy(&next.mask, bytes.data() + 8, 4);
                std::memcpy(&next.flags, bytes.data() + 12, 4);
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            signalDispositions_[signum] = next;
        }
        if (state.rdx != 0) {
            std::array<std::uint8_t, 16> previousBytes{};
            std::memcpy(previousBytes.data(), &previous.handlerAddress, 8);
            std::memcpy(previousBytes.data() + 8, &previous.mask, 4);
            std::memcpy(previousBytes.data() + 12, &previous.flags, 4);
            try {
                addressSpace.writeBytes(guest::GuestAddress{state.rdx}, previousBytes);
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallCsops) {
        const auto pid = static_cast<std::uint32_t>(state.rdi);
        const auto operation = static_cast<std::uint32_t>(state.rsi);
        if (pid == static_cast<std::uint32_t>(::getpid()) &&
            operation == guestCsOpsDerEntitlementsBlob) {
            // Same unsigned-guest reasoning as the audit-token DER
            // entitlements path below: no code signing blob exists, so the
            // query fails with EINVAL without touching the output buffer.
            setError(state, EINVAL);
            return {};
        }
        if (pid != static_cast<std::uint32_t>(::getpid()) ||
            operation != guestCsOpsStatus || state.r10 != sizeof(std::uint32_t)) {
            std::ostringstream reason;
            reason << "only CS_OPS_STATUS and unsigned CS_OPS_DER_ENTITLEMENTS_BLOB for the current guest process are implemented; got pid="
                   << std::dec << pid << " operation=" << operation
                   << " size=" << state.r10;
            throw unsupported(state, syscallRip, reason.str());
        }
        try {
            addressSpace.writeU32(guest::GuestAddress{state.rdx},
                                  guestUnsignedCodeSigningStatus);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallCsopsAuditToken) {
        const auto pid = static_cast<std::uint32_t>(state.rdi);
        const auto operation = static_cast<std::uint32_t>(state.rsi);
        if (pid != static_cast<std::uint32_t>(::getpid()) ||
            operation != guestCsOpsDerEntitlementsBlob ||
            state.r10 != observedGuestDerEntitlementsBufferSize ||
            state.r8 == 0) {
            std::ostringstream reason;
            reason << "only CS_OPS_DER_ENTITLEMENTS_BLOB with an audit token for the current unsigned guest process is implemented; got pid="
                   << std::dec << pid << " operation=" << operation
                   << " size=" << state.r10 << " token=0x" << std::hex
                   << state.r8;
            throw unsupported(state, syscallRip, reason.str());
        }

        audit_token_t guestToken{};
        try {
            const auto bytes = addressSpace.readBytes(
                guest::GuestAddress{state.r8}, sizeof(guestToken));
            std::memcpy(&guestToken, bytes.data(), sizeof(guestToken));
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        const auto expectedToken = currentProcessAuditToken();
        if (guestToken.val[5] != expectedToken.val[5] ||
            guestToken.val[7] != expectedToken.val[7]) {
            setError(state, ESRCH);
            return {};
        }

        // XNU validates the supplied audit token before consulting the code
        // signing blob. Rosa's controlled guest image is unsigned (matching
        // CS_OPS_STATUS above), so DER entitlements fail with EINVAL without
        // reading or writing the caller's output buffer.
        setError(state, EINVAL);
        return {};
    }
    if (number == syscallAccess) {
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
        const auto mode = static_cast<std::uint32_t>(state.rsi);
        if (*path == guestChrootMarker && mode == F_OK) {
            // This private marker only exists in Apple's chrooted build
            // environments. Rosa's synthetic root deliberately presents the
            // normal installed-system case.
            setError(state, ENOENT);
            return {};
        }
        if (mode > (F_OK | R_OK | W_OK | X_OK)) {
            setError(state, EINVAL);
            return {};
        }
        // Resolve relative guest paths against the task's current directory,
        // mirroring the read-only open policy: paths inside it are answered
        // from host metadata, paths outside it have no guest VFS mapping.
        const auto directPath = std::filesystem::path{*path};
        const auto queryPath = directPath.is_absolute()
                                   ? directPath
                                   : fileSpace_.currentDirectory() / directPath;
        std::error_code canonicalError;
        const auto canonicalPath =
            std::filesystem::canonical(queryPath, canonicalError);
        if (canonicalError) {
            setError(state, canonicalError.value());
            return {};
        }
        if (!isWithinDirectory(fileSpace_.currentDirectory(),
                               canonicalPath)) {
            std::ostringstream reason;
            reason << "guest VFS has no mapping for access path \""
                   << *path << '"';
            throw unsupported(state, syscallRip, reason.str());
        }
        if (::access(canonicalPath.c_str(), static_cast<int>(mode)) != 0) {
            setError(state, errno);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallShmOpen) {
        std::optional<std::string> name;
        try {
            name = readGuestCString(addressSpace,
                                    guest::GuestAddress{state.rdi},
                                    guestPathMaximum);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (!name) {
            setError(state, ENAMETOOLONG);
            return {};
        }
        if (*name == guestFeatureFlagsSharedMemory && state.rsi == 0) {
            // FeatureFlags treats an absent read-only shared-memory snapshot as
            // a normal cold-start condition. Keep this entirely in the guest
            // namespace instead of opening or observing a host POSIX shm object.
            setError(state, ENOENT);
            return {};
        }
        std::ostringstream reason;
        reason << "only the absent read-only FeatureFlags shared-memory probe is implemented; got name=\""
               << *name << "\" flags=0x" << std::hex << state.rsi;
        throw unsupported(state, syscallRip, reason.str());
    }
    if (number == syscallOpen || number == syscallOpenNoCancel) {
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
        if (*path == guestRandomDevice && flags == 0 && mode == 0) {
            const auto descriptor = fileSpace_.openRandomDevice(flags);
            setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
            return {};
        }
        if (*path == "." && flags == guestOpenDirectory && mode == 0) {
            const auto descriptor = fileSpace_.openCurrentDirectory(flags);
            setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
            return {};
        }
        if (*path == "/" && flags == guestOpenRootDirectory && mode == 0) {
            const auto descriptor = fileSpace_.openRootDirectory(flags);
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
    if (number == syscallOpenat) {
        const auto directoryDescriptor = GuestFileDescriptor{
            std::bit_cast<std::int32_t>(
                static_cast<std::uint32_t>(state.rdi))};
        const auto *directory = fileSpace_.lookup(directoryDescriptor);
        if (directory == nullptr ||
            directory->kind != GuestFileKind::RootDirectory) {
            setError(state, EBADF);
            return {};
        }
        std::optional<std::string> path;
        try {
            path = readGuestCString(addressSpace,
                                    guest::GuestAddress{state.rsi},
                                    guestPathMaximum);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (!path) {
            setError(state, ENAMETOOLONG);
            return {};
        }
        const auto flags = static_cast<std::uint32_t>(state.rdx);
        const auto mode = static_cast<std::uint32_t>(state.r10);
        if (*path != guestCryptexDirectory || flags != guestOpenDirectory ||
            mode != 0) {
            std::ostringstream reason;
            reason << "only openat of the provisioned guest cryptex directory is implemented; got dirfd="
                   << directoryDescriptor.value << " path=\"" << *path
                   << "\" flags=0x" << std::hex << flags << " mode=0x"
                   << mode;
            throw unsupported(state, syscallRip, reason.str());
        }
        const auto descriptor = fileSpace_.openSyntheticDirectory(
            std::filesystem::path{"/"} / *path, flags);
        setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
        return {};
    }
    if (number == syscallStat64) {
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
        if (!std::filesystem::path{*path}.is_absolute()) {
            throw unsupported(state, syscallRip,
                              "only absolute mapped user-file stat64 is implemented");
        }
        std::error_code error;
        const auto canonicalPath = std::filesystem::canonical(*path, error);
        if (error) {
            setError(state, error.value());
            return {};
        }
        if (!isWithinDirectory(fileSpace_.currentDirectory(), canonicalPath)) {
            std::ostringstream reason;
            reason << "guest VFS has no mapping for stat64 path \""
                   << *path << '"';
            throw unsupported(state, syscallRip, reason.str());
        }

        struct stat hostMetadata {};
        if (::stat(canonicalPath.c_str(), &hostMetadata) != 0) {
            setError(state, errno);
            return {};
        }
        if (!S_ISREG(hostMetadata.st_mode)) {
            std::ostringstream reason;
            reason << "only mapped regular-file stat64 is implemented; got path=\""
                   << *path << '"';
            throw unsupported(state, syscallRip, reason.str());
        }
        const auto metadata = guestStat64FromHost(hostMetadata);
        try {
            addressSpace.validateAccess(guest::GuestAddress{state.rsi},
                                        sizeof(metadata),
                                        guest::Permission::Write);
            addressSpace.writeBytes(
                guest::GuestAddress{state.rsi},
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t *>(&metadata),
                    sizeof(metadata)});
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallFstat64) {
        const auto descriptor = std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.rdi));
        if (descriptor != STDIN_FILENO && descriptor != STDOUT_FILENO &&
            descriptor != STDERR_FILENO) {
            throw unsupported(
                state, syscallRip,
                "fstat64 currently accepts only a standard guest descriptor");
        }

        struct stat hostMetadata {};
        if (::fstat(descriptor, &hostMetadata) != 0) {
            setError(state, errno);
            return {};
        }
        const auto metadata = guestStat64FromHost(hostMetadata);
        try {
            addressSpace.validateAccess(guest::GuestAddress{state.rsi},
                                        sizeof(metadata),
                                        guest::Permission::Write);
            addressSpace.writeBytes(
                guest::GuestAddress{state.rsi},
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t *>(&metadata),
                    sizeof(metadata)});
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallGetattrlist) {
        std::optional<std::string> path;
        GuestAttrlist attributes{};
        try {
            path = readGuestCString(addressSpace,
                                    guest::GuestAddress{state.rdi},
                                    guestPathMaximum);
            const auto bytes = addressSpace.readBytes(
                guest::GuestAddress{state.rsi}, sizeof(attributes));
            std::memcpy(&attributes, bytes.data(), sizeof(attributes));
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (!path) {
            setError(state, ENAMETOOLONG);
            return {};
        }
        constexpr std::uint32_t fullPathCommonAttribute = 0x08000000;
        const bool isFullPathRequest =
            attributes.bitmapCount == 5 && attributes.reserved == 0 &&
            attributes.commonAttributes == fullPathCommonAttribute &&
            attributes.volumeAttributes == 0 &&
            attributes.directoryAttributes == 0 &&
            attributes.fileAttributes == 0 &&
            attributes.forkAttributes == 0 && state.r8 == 0;
        if (isFullPathRequest) {
            const auto requestedPath = std::filesystem::path{*path};
            if (!requestedPath.is_absolute()) {
                setError(state, EINVAL);
                return {};
            }
            std::error_code error;
            const auto canonicalPath =
                std::filesystem::canonical(requestedPath, error);
            if (error) {
                setError(state, error.value());
                return {};
            }
            if (!isWithinDirectory(fileSpace_.currentDirectory(),
                                   canonicalPath)) {
                std::ostringstream reason;
                reason << "guest VFS has no mapping for full-path getattrlist path \""
                       << *path << '"';
                throw unsupported(state, syscallRip, reason.str());
            }
            const auto result = guestFullPathAttributes(*path);
            const auto outputSize =
                static_cast<std::size_t>(std::min<std::uint64_t>(
                    state.r10, result.size()));
            if (outputSize < sizeof(std::uint32_t)) {
                setError(state, ERANGE);
                return {};
            }
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx}, outputSize,
                    guest::Permission::Write);
                addressSpace.writeBytes(
                    guest::GuestAddress{state.rdx},
                    std::span<const std::uint8_t>{result}.first(outputSize));
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            setSuccess(state, 0);
            return {};
        }

        constexpr std::uint32_t rootCommonAttributes = 0x00000006;
        constexpr std::uint32_t rootVolumeAttributes = 0x80060000;
        if (*path != "/" || attributes.bitmapCount != 5 ||
            attributes.reserved != 0 ||
            attributes.commonAttributes != rootCommonAttributes ||
            attributes.volumeAttributes != rootVolumeAttributes ||
            attributes.directoryAttributes != 0 ||
            attributes.fileAttributes != 0 ||
            attributes.forkAttributes != 0 || state.r8 != 0) {
            std::ostringstream reason;
            reason << "only root-volume and mapped-file FULLPATH getattrlist requests are implemented; got path=\""
                   << *path << "\" common=0x" << std::hex
                   << attributes.commonAttributes << " volume=0x"
                   << attributes.volumeAttributes << " options=0x"
                   << state.r8;
            throw unsupported(state, syscallRip, reason.str());
        }
        const auto result = guestRootVolumeAttributes();
        const auto outputSize = static_cast<std::size_t>(std::min<std::uint64_t>(
            state.r10, sizeof(result)));
        if (outputSize < sizeof(result.length)) {
            setError(state, ERANGE);
            return {};
        }
        auto bytes = std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t *>(&result),
            sizeof(result)};
        std::vector<std::uint8_t> output(
            bytes.begin(),
            bytes.begin() + static_cast<std::ptrdiff_t>(outputSize));
        const auto returnedLength = static_cast<std::uint32_t>(outputSize);
        std::memcpy(output.data(), &returnedLength, sizeof(returnedLength));
        try {
            addressSpace.validateAccess(
                guest::GuestAddress{state.rdx}, output.size(),
                guest::Permission::Write);
            addressSpace.writeBytes(guest::GuestAddress{state.rdx}, output);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallGetfsstat64) {
        const auto flags = static_cast<std::uint32_t>(state.rdx);
        if (flags != guestMountWait && flags != guestMountNowait &&
            flags != guestMountDwait) {
            setError(state, EINVAL);
            return {};
        }
        constexpr std::uint64_t filesystemCount = 1;
        if (state.rdi == 0) {
            setSuccess(state, filesystemCount);
            return {};
        }
        const auto bufferSize = static_cast<std::uint32_t>(state.rsi);
        if (bufferSize < sizeof(GuestStatfs64)) {
            setSuccess(state, 0);
            return {};
        }
        const auto filesystem = guestRootFilesystem();
        try {
            addressSpace.validateAccess(
                guest::GuestAddress{state.rdi}, sizeof(filesystem),
                guest::Permission::Write);
            addressSpace.writeBytes(
                guest::GuestAddress{state.rdi},
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t *>(&filesystem),
                    sizeof(filesystem)});
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, filesystemCount);
        return {};
    }
    if (number == syscallFstatat64) {
        std::optional<std::string> path;
        try {
            path = readGuestCString(addressSpace,
                                    guest::GuestAddress{state.rsi},
                                    guestPathMaximum);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (!path) {
            setError(state, ENAMETOOLONG);
            return {};
        }
        const auto descriptor = GuestFileDescriptor{
            std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdi))};
        const auto *directory = fileSpace_.lookup(descriptor);
        if (directory == nullptr) {
            setError(state, EBADF);
            return {};
        }
        if (directory->kind != GuestFileKind::RootDirectory &&
            directory->kind != GuestFileKind::CurrentDirectory &&
            directory->kind != GuestFileKind::SyntheticDirectory) {
            setError(state, ENOTDIR);
            return {};
        }
        if (state.r10 != 0) {
            std::ostringstream reason;
            reason << "only fstatat64 flags=0 is implemented; got flags=0x"
                   << std::hex << state.r10;
            throw unsupported(state, syscallRip, reason.str());
        }

        auto relativePath = std::filesystem::path{*path};
        if (relativePath.filename().empty()) {
            relativePath = relativePath.parent_path();
        }
        const auto candidate =
            (directory->guestPath / relativePath).lexically_normal();
        const auto expected = std::filesystem::path{guestDyldDirectory};
        if (!isWithinDirectory(directory->guestPath, candidate) ||
            candidate != expected) {
            setError(state, ENOENT);
            return {};
        }

        GuestStat64 metadata{};
        metadata.device = 1;
        metadata.mode = guestModeDirectory | guestModeReadExecute;
        metadata.linkCount = 2;
        metadata.inode = 2;
        metadata.blockSize = static_cast<std::int32_t>(guest::guestPageSize);
        try {
            addressSpace.validateAccess(guest::GuestAddress{state.rdx},
                                        sizeof(metadata),
                                        guest::Permission::Write);
            addressSpace.writeBytes(
                guest::GuestAddress{state.rdx},
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t *>(&metadata),
                    sizeof(metadata)});
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallSocket) {
        const auto domain = static_cast<std::uint32_t>(state.rdi);
        const auto type = static_cast<std::uint32_t>(state.rsi);
        const auto protocol = static_cast<std::uint32_t>(state.rdx);
        if (domain != guestAddressFamilyUnix ||
            type != guestSocketDatagram || protocol != 0) {
            std::ostringstream reason;
            reason << "only guest AF_UNIX SOCK_DGRAM sockets are implemented; got domain="
                   << domain << " type=" << type
                   << " protocol=" << protocol;
            throw unsupported(state, syscallRip, reason.str());
        }
        const auto descriptor = fileSpace_.openUnixDatagramSocket();
        setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
        return {};
    }
    if (number == syscallConnect) {
        const auto descriptor = GuestFileDescriptor{
            std::bit_cast<std::int32_t>(
                static_cast<std::uint32_t>(state.rdi))};
        const auto *socket = fileSpace_.lookup(descriptor);
        if (socket == nullptr) {
            setError(state, EBADF);
            return {};
        }
        if (socket->kind != GuestFileKind::UnixDatagramSocket) {
            setError(state, ENOTSOCK);
            return {};
        }
        if (state.rdx != guestSockaddrUnixSize) {
            setError(state, EINVAL);
            return {};
        }
        std::vector<std::uint8_t> sockaddr;
        try {
            sockaddr = addressSpace.readBytes(
                guest::GuestAddress{state.rsi}, guestSockaddrUnixSize);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (sockaddr[0] != guestSockaddrUnixSize ||
            sockaddr[1] != guestAddressFamilyUnix) {
            setError(state, EINVAL);
            return {};
        }
        const auto pathEnd = std::find(sockaddr.begin() + 2,
                                       sockaddr.end(), 0);
        if (pathEnd == sockaddr.end()) {
            setError(state, ENAMETOOLONG);
            return {};
        }
        const std::string_view path{
            reinterpret_cast<const char *>(sockaddr.data() + 2),
            static_cast<std::size_t>(pathEnd - (sockaddr.begin() + 2))};
        if (path == guestSystemLogSocket) {
            // Rosa's guest root intentionally has no ASL daemon. Keep the
            // endpoint in the guest namespace and report the same missing-node
            // result that connect(2) can legitimately return.
            setError(state, ENOENT);
            return {};
        }
        std::ostringstream reason;
        reason << "guest Unix datagram endpoint is not modeled: \""
               << path << '"';
        throw unsupported(state, syscallRip, reason.str());
    }
    if (number == syscallClose || number == syscallCloseNoCancel) {
        const auto descriptor = GuestFileDescriptor{
            std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdi))};
        if (!fileSpace_.close(descriptor)) {
            setError(state, EBADF);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (number == syscallRead || number == syscallReadNoCancel) {
        const auto descriptor = GuestFileDescriptor{
            std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdi))};
        const auto *file = fileSpace_.lookup(descriptor);
        if (file == nullptr) {
            setError(state, EBADF);
            return {};
        }
        if (file->kind != GuestFileKind::RandomDevice || state.rdx > 256U) {
            std::ostringstream reason;
            reason << "only reads of at most 256 bytes from the synthetic /dev/urandom are implemented; got fd="
                   << descriptor.value << " count=" << state.rdx;
            throw unsupported(state, syscallRip, reason.str());
        }
        const auto count = static_cast<std::size_t>(state.rdx);
        if (count == 0) {
            setSuccess(state, 0);
            return {};
        }
        try {
            addressSpace.validateAccess(guest::GuestAddress{state.rsi}, count,
                                        guest::Permission::Write);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        std::vector<std::uint8_t> bytes(count);
        if (::getentropy(bytes.data(), bytes.size()) != 0) {
            setError(state, errno);
            return {};
        }
        addressSpace.writeBytes(guest::GuestAddress{state.rsi}, bytes);
        setSuccess(state, count);
        return {};
    }
    if (number == syscallFcntl) {
        const auto descriptor = GuestFileDescriptor{
            std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdi))};
        const auto command = static_cast<std::uint32_t>(state.rsi);
        const auto *file = fileSpace_.lookup(descriptor);
        if (file == nullptr) {
            setError(state, EBADF);
            return {};
        }
        if (command == guestFcntlSetFd &&
            state.rdx == guestFdCloseOnExec) {
            setSuccess(state, 0);
            return {};
        }
        if (command != guestFcntlGetPath) {
            throw unsupported(
                state, syscallRip,
                "only observed fcntl(F_SETFD/F_GETPATH) operations are implemented");
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
    if (number == syscallMprotect) {
        if ((state.rdi % guest::guestPageSize) != 0 ||
            (state.rdx & ~guestProtectionMask) != 0) {
            setError(state, EINVAL);
            return {};
        }
        auto permissions = guest::Permission::None;
        if ((state.rdx & guestProtectionRead) != 0) {
            permissions = permissions | guest::Permission::Read;
        }
        if ((state.rdx & guestProtectionWrite) != 0) {
            permissions = permissions | guest::Permission::Write;
        }
        if ((state.rdx & guestProtectionExecute) != 0) {
            permissions = permissions | guest::Permission::Execute;
        }
        switch (addressSpace.protect(guest::GuestAddress{state.rdi},
                                     state.rsi, permissions)) {
        case guest::ProtectResult::Success:
            setSuccess(state, 0);
            return {};
        case guest::ProtectResult::InvalidAddress:
            setError(state, ENOMEM);
            return {};
        case guest::ProtectResult::ProtectionFailure:
            setError(state, EACCES);
            return {};
        case guest::ProtectResult::InvalidArgument:
            setError(state, EINVAL);
            return {};
        }
        throw std::runtime_error("unreachable guest mprotect result");
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
    if (number == syscallMmap) {
        const auto descriptor = GuestFileDescriptor{
            std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.r8))};
        const auto *file = fileSpace_.lookup(descriptor);
        if (file == nullptr || file->kind != GuestFileKind::HostReadOnlyFile) {
            setError(state, EBADF);
            return {};
        }
        if (state.rdi != 0 || state.rdx != guestProtectionRead ||
            state.r10 != guestObservedFileMapFlags ||
            (state.r9 % guest::guestPageSize) != 0) {
            std::ostringstream reason;
            reason << "only the observed anywhere read-only private resilient-codesign file mmap is implemented; got address=0x"
                   << std::hex << state.rdi << " length=0x" << state.rsi
                   << " protection=0x" << state.rdx << " flags=0x"
                   << state.r10 << " fd=" << std::dec << descriptor.value
                   << " offset=0x" << std::hex << state.r9;
            throw unsupported(state, syscallRip, reason.str());
        }
        if (state.rsi == 0 ||
            state.rsi > std::numeric_limits<std::size_t>::max() ||
            state.rsi > std::numeric_limits<std::uint64_t>::max() -
                            (guest::guestPageSize - 1U)) {
            setError(state, EINVAL);
            return {};
        }
        const auto roundedSize =
            (state.rsi + guest::guestPageSize - 1U) &
            ~(static_cast<std::uint64_t>(guest::guestPageSize) - 1U);
        const auto mappedAddress = findMmapRange(addressSpace, roundedSize);
        if (!mappedAddress) {
            setError(state, ENOMEM);
            return {};
        }
        try {
            addressSpace.mapFileSegment(
                *mappedAddress, static_cast<std::size_t>(roundedSize),
                guest::Permission::Read, guest::Permission::Read,
                file->guestPath, state.r9, "mmap private file");
        } catch (const std::invalid_argument &) {
            setError(state, EINVAL);
            return {};
        }
        setSuccess(state, mappedAddress->value);
        return {};
    }
    if (number == syscallMapWithLinking) {
        // dyld's page-in linking: over-map file ranges, then apply the
        // chained fixups in the blob. Like XNU's dyld pager this resolves
        // binds through the blob's pre-resolved address table, so no
        // userspace symbol lookup is involved. Guest arguments are the
        // regions pointer in RDI, region count in RSI, blob pointer in RDX,
        // and blob size in R10.
        constexpr std::uint64_t maximumLinkInfoSize = 64U * 1024U * 1024U;
        const auto regionCount = state.rsi;
        const auto blobSize = state.r10;
        if (regionCount == 0 || regionCount > 5 || blobSize <= 40 ||
            blobSize > maximumLinkInfoSize) {
            setError(state, EINVAL);
            return {};
        }
        std::vector<std::uint8_t> regionBytes;
        std::vector<std::uint8_t> blob;
        try {
            regionBytes = addressSpace.readBytes(guest::GuestAddress{state.rdi},
                                                 regionCount * sizeof(MapWithLinkingRegion));
            blob = addressSpace.readBytes(guest::GuestAddress{state.rdx},
                                          static_cast<std::size_t>(blobSize));
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        std::vector<MapWithLinkingRegion> regions;
        regions.reserve(static_cast<std::size_t>(regionCount));
        for (std::uint64_t index = 0; index < regionCount; ++index) {
            const auto base = index * sizeof(MapWithLinkingRegion);
            MapWithLinkingRegion region{};
            std::memcpy(&region.fd, regionBytes.data() + base, sizeof(region.fd));
            std::memcpy(&region.protections, regionBytes.data() + base + 4,
                        sizeof(region.protections));
            std::memcpy(&region.fileOffset, regionBytes.data() + base + 8,
                        sizeof(region.fileOffset));
            std::memcpy(&region.address, regionBytes.data() + base + 16,
                        sizeof(region.address));
            std::memcpy(&region.size, regionBytes.data() + base + 24, sizeof(region.size));
            regions.push_back(region);
        }
        for (std::size_t index = 1; index < regions.size(); ++index) {
            if (regions[index].fd != regions.front().fd) {
                std::ostringstream reason;
                reason << "map_with_linking with multiple backing files is not implemented; got fd="
                       << regions[index].fd << " after fd=" << regions.front().fd;
                throw unsupported(state, syscallRip, reason.str());
            }
        }
        const auto descriptor = GuestFileDescriptor{std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(regions.front().fd))};
        const auto *file = fileSpace_.lookup(descriptor);
        if (file == nullptr) {
            setError(state, EBADF);
            return {};
        }
        if (file->kind != GuestFileKind::HostReadOnlyFile) {
            std::ostringstream reason;
            reason << "map_with_linking requires a read-only file descriptor; got fd="
                   << descriptor.value;
            throw unsupported(state, syscallRip, reason.str());
        }
        std::uint64_t blobVersion = 0;
        std::uint64_t blobPageSize = 0;
        std::uint64_t blobPointerFormat = 0;
        std::uint64_t bindsOffset = 0;
        std::uint64_t bindsCount = 0;
        std::uint64_t chainsOffset = 0;
        std::uint64_t chainsSize = 0;
        try {
            blobVersion = readMapWithLinkingField<std::uint32_t>(blob, 0);
            blobPageSize = readMapWithLinkingField<std::uint16_t>(blob, 4);
            blobPointerFormat = readMapWithLinkingField<std::uint16_t>(blob, 6);
            bindsOffset = readMapWithLinkingField<std::uint32_t>(blob, 8);
            bindsCount = readMapWithLinkingField<std::uint32_t>(blob, 12);
            chainsOffset = readMapWithLinkingField<std::uint32_t>(blob, 16);
            chainsSize = readMapWithLinkingField<std::uint32_t>(blob, 20);
        } catch (const std::out_of_range &) {
            setError(state, EFAULT);
            return {};
        }
        if (blobVersion != 7 || blobPageSize != guest::guestPageSize ||
            (blobPointerFormat != 2 && blobPointerFormat != 6) ||
            bindsOffset > blob.size() ||
            bindsCount > (blob.size() - static_cast<std::size_t>(bindsOffset)) / 8U ||
            chainsOffset > blob.size() ||
            chainsSize > blob.size() - static_cast<std::size_t>(chainsOffset)) {
            std::ostringstream reason;
            reason << "unsupported map_with_linking blob; got version=" << blobVersion
                   << " page-size=" << blobPageSize << " pointer-format=" << blobPointerFormat
                   << " binds=[" << bindsOffset << "+"
                   << bindsCount * 8U << "] chains=[" << chainsOffset << "+"
                   << chainsSize << "] blob-size=" << blob.size();
            throw unsupported(state, syscallRip, reason.str());
        }
        std::error_code fileSizeError;
        const auto hostFileSize = std::filesystem::file_size(file->guestPath, fileSizeError);
        if (fileSizeError) {
            setError(state, EIO);
            return {};
        }
        std::ifstream hostFile(file->guestPath, std::ios::binary);
        if (!hostFile) {
            setError(state, EIO);
            return {};
        }
        for (const auto &region : regions) {
            if (region.size == 0 || region.size > std::numeric_limits<std::size_t>::max() ||
                (region.address % guest::guestPageSize) != 0 ||
                (region.size % guest::guestPageSize) != 0) {
                std::ostringstream reason;
                reason << "map_with_linking region is not page aligned; got address=0x"
                       << std::hex << region.address << " size=0x" << region.size;
                throw unsupported(state, syscallRip, reason.str());
            }
            if ((region.protections & 0x4U) != 0) {
                std::ostringstream reason;
                reason << "executable map_with_linking region is not implemented; got address=0x"
                       << std::hex << region.address << " protections=0x"
                       << region.protections;
                throw unsupported(state, syscallRip, reason.str());
            }
            if (region.fileOffset > hostFileSize ||
                region.size > hostFileSize - region.fileOffset) {
                std::ostringstream reason;
                reason << "map_with_linking region extends past its file; got file-offset=0x"
                       << std::hex << region.fileOffset << " size=0x" << region.size;
                throw unsupported(state, syscallRip, reason.str());
            }
            const auto regionSize = static_cast<std::size_t>(region.size);
            try {
                addressSpace.validateAccess(guest::GuestAddress{region.address}, regionSize,
                                            guest::Permission::Read);
            } catch (const std::runtime_error &) {
                setError(state, EINVAL);
                return {};
            }
            // The kernel pager writes file bytes and fixups beneath the new
            // mapping's protections. Model that atomically: grant write
            // access, materialize the pages, then install the final
            // permissions. No guest thread can observe the intermediate
            // state in Rosa's single-threaded model.
            if (addressSpace.protect(guest::GuestAddress{region.address}, regionSize,
                                     guest::Permission::Read | guest::Permission::Write) !=
                guest::ProtectResult::Success) {
                setError(state, EACCES);
                return {};
            }
            constexpr std::size_t copyChunkSize = 1024U * 1024U;
            std::vector<std::uint8_t> chunk(copyChunkSize);
            std::uint64_t copied = 0;
            bool copyFailed = false;
            hostFile.clear();
            hostFile.seekg(static_cast<std::streamoff>(region.fileOffset));
            while (copied < region.size) {
                const auto want =
                    static_cast<std::streamsize>(std::min<std::uint64_t>(
                        copyChunkSize, region.size - copied));
                hostFile.read(reinterpret_cast<char *>(chunk.data()), want);
                if (hostFile.gcount() != want) {
                    copyFailed = true;
                    break;
                }
                try {
                    addressSpace.writeBytes(
                        guest::GuestAddress{region.address + copied},
                        std::span<const std::uint8_t>(chunk.data(),
                                                      static_cast<std::size_t>(want)));
                } catch (const std::runtime_error &) {
                    copyFailed = true;
                    break;
                }
                copied += static_cast<std::uint64_t>(want);
            }
            if (copyFailed) {
                setError(state, EIO);
                return {};
            }
            for (std::uint64_t page = region.address; page < region.address + region.size;
                 page += guest::guestPageSize) {
                try {
                    applyMapWithLinkingPageFixups(addressSpace, blob, page);
                } catch (const std::out_of_range &error) {
                    std::ostringstream reason;
                    reason << "map_with_linking fixups failed at page=0x" << std::hex << page
                           << ": " << error.what();
                    throw unsupported(state, syscallRip, reason.str());
                } catch (const std::runtime_error &) {
                    setError(state, EFAULT);
                    return {};
                }
            }
            auto finalPermissions = guest::Permission::None;
            if ((region.protections & 0x1U) != 0) {
                finalPermissions = finalPermissions | guest::Permission::Read;
            }
            if ((region.protections & 0x2U) != 0) {
                finalPermissions = finalPermissions | guest::Permission::Write;
            }
            if (addressSpace.protect(guest::GuestAddress{region.address}, regionSize,
                                     finalPermissions) != guest::ProtectResult::Success) {
                setError(state, EACCES);
                return {};
            }
        }
        setSuccess(state, 0);
        return {};
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
        if (callNumber == procInfoCallPidInfo) {
            const auto pid = std::bit_cast<std::int32_t>(
                static_cast<std::uint32_t>(state.rsi));
            const auto flavor = static_cast<std::uint32_t>(state.rdx);
            if (pid != static_cast<std::int32_t>(::getpid())) {
                setError(state, ESRCH);
                return {};
            }
            if (flavor != procPidUniqueIdentifierInfo &&
                flavor != procPidShortBsdInfo) {
                throw unsupported(
                    state, syscallRip,
                    "only PROC_PIDT_SHORTBSDINFO and PROC_PIDUNIQIDENTIFIERINFO for the current guest process are implemented");
            }
            const auto signedSize = std::bit_cast<std::int32_t>(
                static_cast<std::uint32_t>(state.r9));
            const auto requiredSize =
                flavor == procPidShortBsdInfo
                    ? sizeof(GuestProcBsdShortInfo)
                    : sizeof(GuestProcUniqueIdentifierInfo);
            if (signedSize < static_cast<std::int32_t>(requiredSize)) {
                setError(state, ENOMEM);
                return {};
            }
            if (flavor == procPidUniqueIdentifierInfo && state.r10 != 0) {
                throw unsupported(
                    state, syscallRip,
                    "only active-process PROC_PIDUNIQIDENTIFIERINFO is implemented");
            }
            const auto writeResult = [&](const auto &result) {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.r8}, sizeof(result),
                    guest::Permission::Write);
                addressSpace.writeBytes(
                    guest::GuestAddress{state.r8},
                    std::span<const std::uint8_t>{
                        reinterpret_cast<const std::uint8_t *>(&result),
                        sizeof(result)});
            };
            if (flavor == procPidShortBsdInfo) {
                const auto result = guestProcBsdShortInfo(state.r10);
                try {
                    writeResult(result);
                } catch (const std::runtime_error &) {
                    setError(state, EFAULT);
                    return {};
                }
            } else {
                const auto result =
                    guestProcUniqueIdentifierInfo(executableUuid_);
                try {
                    writeResult(result);
                } catch (const std::runtime_error &) {
                    setError(state, EFAULT);
                    return {};
                }
            }
            setSuccess(state, requiredSize);
            return {};
        }
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
        const auto resolvedPath =
            sharedCache_ == nullptr
                ? std::optional<std::string_view>{}
                : sharedCache_->pathForFileIdentity(
                      {guestFsid.value[0], guestFsid.value[1]}, state.r10);
        if (resolvedPath) {
            if (resolvedPath->size() + 1U > state.rsi) {
                setError(state, ENOSPC);
                return {};
            }
            std::vector<std::uint8_t> bytes(resolvedPath->begin(),
                                            resolvedPath->end());
            bytes.push_back(0);
            try {
                addressSpace.writeBytes(guest::GuestAddress{state.rdi}, bytes);
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            setSuccess(state, bytes.size());
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
    if (number != syscallWrite && number != syscallWriteNoCancel) {
        throw unsupported(state, syscallRip,
                          "only the currently provisioned Darwin bootstrap syscalls are implemented; this call is outside that set");
    }
    if (state.rdi != STDOUT_FILENO && state.rdi != STDERR_FILENO) {
        throw unsupported(state, syscallRip,
                          "controlled write currently accepts only stdout or stderr");
    }
    if (state.rdx > maximumControlledWrite) {
        throw unsupported(state, syscallRip, "controlled write exceeds the 16 MiB limit");
    }

    try {
        const auto bytes = addressSpace.readBytes(
            guest::GuestAddress{state.rsi}, static_cast<std::size_t>(state.rdx));
        const auto result =
            ::write(static_cast<int>(state.rdi), bytes.data(), bytes.size());
        if (result < 0) {
            setError(state, errno);
        } else {
            setSuccess(state, static_cast<std::uint64_t>(result));
        }
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
    }
    return {};
}

} // namespace rosa::darwin
