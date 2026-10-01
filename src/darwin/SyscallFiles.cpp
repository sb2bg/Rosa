#include "darwin/SyscallInternal.h"

#include <sys/attr.h>
#include <sys/ioctl.h>
#include <sys/param.h>

namespace rosa::darwin::detail {
namespace {

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

GuestStatfs64 guestStatfs64FromHost(const struct statfs &host) {
    GuestStatfs64 guest{};
    guest.blockSize = static_cast<std::uint32_t>(host.f_bsize);
    guest.ioSize = static_cast<std::int32_t>(host.f_iosize);
    guest.blocks = static_cast<std::uint64_t>(host.f_blocks);
    guest.blocksFree = static_cast<std::uint64_t>(host.f_bfree);
    guest.blocksAvailable = static_cast<std::uint64_t>(host.f_bavail);
    guest.files = static_cast<std::uint64_t>(host.f_files);
    guest.filesFree = static_cast<std::uint64_t>(host.f_ffree);
    guest.fsid = {{host.f_fsid.val[0], host.f_fsid.val[1]}};
    guest.owner = static_cast<std::uint32_t>(host.f_owner);
    guest.type = static_cast<std::uint32_t>(host.f_type);
    guest.flags = static_cast<std::uint32_t>(host.f_flags);
    std::strncpy(guest.filesystemType, host.f_fstypename,
                 sizeof(guest.filesystemType) - 1);
    std::strncpy(guest.mountedOn, host.f_mntonname,
                 sizeof(guest.mountedOn) - 1);
    std::strncpy(guest.mountedFrom, host.f_mntfromname,
                 sizeof(guest.mountedFrom) - 1);
    return guest;
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

} // namespace

SyscallOutcome handleDup(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    const auto duplicate = task.fileSpace.duplicate(guestDescriptor(state.rdi));
    if (!duplicate) {
        setError(state, EBADF);
        return {};
    }
    setSuccess(state, static_cast<std::uint32_t>(duplicate->value));
    return {};
}

SyscallOutcome handleIoctl(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = guestDescriptor(state.rdi);
    const auto request = state.rsi;
    // Read-only requests whose Darwin result layouts (an int device type,
    // struct winsize, struct termios) match on x86_64 and arm64.
    constexpr std::array forwardedRequests{guestIoctlFileDescriptorType, guestIoctlWindowSize,
                                           guestIoctlGetTermios};
    if (std::ranges::find(forwardedRequests, request) == forwardedRequests.end()) {
        std::ostringstream reason;
        reason << "only ioctl(FIODTYPE/TIOCGWINSZ/TIOCGETA) is implemented; got fd="
               << std::dec << descriptor.value << " request=0x" << std::hex << request;
        throw unsupported(state, syscallRip, reason.str());
    }
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    std::array<std::uint8_t, IOCPARM_MAX> result{};
    const auto resultSize = static_cast<std::size_t>(IOCPARM_LEN(request));
    if (file->kind == GuestFileKind::StandardStream &&
        task.fileSpace.hostAccess() == GuestHostAccess::Controlled) {
        // A controlled guest's standard streams are Rosa's synthetic
        // console: a Darwin tty with the conventional 80x24 size.
        if (request == guestIoctlWindowSize) {
            constexpr std::array<std::uint8_t, 8> console{24, 0, 80, 0, 0, 0, 0, 0};
            std::ranges::copy(console, result.begin());
        } else if (request == guestIoctlFileDescriptorType) {
            std::memcpy(result.data(), &guestDeviceTypeTerminal, sizeof(guestDeviceTypeTerminal));
        } else {
            throw unsupported(state, syscallRip,
                              "the synthetic console has no terminal attributes (TIOCGETA)");
        }
    } else if (file->hostBacked()) {
        if (::ioctl(file->host.get(), static_cast<unsigned long>(request), result.data()) != 0) {
            setError(state, errno);
            return {};
        }
    } else {
        setError(state, ENOTTY);
        return {};
    }
    try {
        addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                std::span<const std::uint8_t>{result}.first(resultSize));
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleAccess(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
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
    const auto canonicalPath = canonicalGuestPath(task.fileSpace, *path);
    if (!canonicalPath) {
        setError(state, canonicalPath.error());
        return {};
    }
    if (!task.fileSpace.permitsHostPath(*canonicalPath)) {
        std::ostringstream reason;
        reason << "guest VFS has no mapping for access path \""
               << *path << '"';
        throw unsupported(state, syscallRip, reason.str());
    }
    if (::access(canonicalPath->c_str(), static_cast<int>(mode)) != 0) {
        setError(state, errno);
        return {};
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleShmOpen(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(task);
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

SyscallOutcome handleOpen(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
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
    if (*path == guestRandomDevice && mode == 0 &&
        (flags == 0 || flags == guestOpenCloseOnExec)) {
        // Close-on-exec is meaningless without an exec boundary: guest
        // descriptors never escape the single Rosa process.
        const auto descriptor = task.fileSpace.openRandomDevice(flags);
        setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
        return {};
    }
    if (flags == 0 && mode == 0 &&
        (*path == guestPasswdDatabase || *path == guestMasterPasswdDatabase ||
         *path == guestGroupDatabase)) {
        // Rosa provisions no system user/group databases; DirectoryService
        // backs real users on hardware. libsystem_info's file backend
        // already handles a missing database, so report it absent.
        setError(state, ENOENT);
        return {};
    }
    if ((flags & guestOpenAccessMode) == guestOpenReadOnly &&
        std::string_view(*path).find(guestFeatureFlagsPathComponent) !=
            std::string_view::npos) {
        // Rosa provisions no FeatureFlags disclosure domains anywhere;
        // the framework falls back to compiled-in defaults when a domain
        // file is absent, so report it absent.
        setError(state, ENOENT);
        return {};
    }
    if (*path == "/" && flags == guestOpenRootDirectory && mode == 0) {
        const auto descriptor = task.fileSpace.openRootDirectory(flags);
        setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
        return {};
    }
    // Read-only opens of files and directories become host descriptors
    // owned by the guest's open file description. Without O_CREAT the
    // kernel ignores the mode argument.
    // Darwin's open flag values are identical for x86_64 and arm64.
    constexpr std::uint32_t hostedReadOnlyFlags =
        guestOpenDirectory | guestOpenCloseOnExec | guestOpenNonblock | guestOpenNoFollow;
    if ((flags & guestOpenAccessMode) != guestOpenReadOnly ||
        (flags & ~(guestOpenAccessMode | hostedReadOnlyFlags)) != 0) {
        std::ostringstream reason;
        reason << "only read-only open of host files and directories is implemented; got path=\""
               << *path << "\" flags=0x" << std::hex << flags
               << " mode=0x" << mode;
        throw unsupported(state, syscallRip, reason.str());
    }
    // O_NOFOLLOW must reach the host with the final symlink intact.
    const bool followFinal = (flags & guestOpenNoFollow) == 0;
    const auto canonicalPath =
        canonicalGuestPathFrom(task.fileSpace.currentDirectory(), *path, followFinal);
    if (!canonicalPath) {
        setError(state, canonicalPath.error());
        return {};
    }
    const bool wantsDirectory = (flags & guestOpenDirectory) != 0;
    if (!task.fileSpace.permitsHostPath(*canonicalPath)) {
        std::ostringstream reason;
        reason << "guest VFS has no mapping for read-only "
               << (wantsDirectory ? "directory path \"" : "path \"") << *path << '"';
        throw unsupported(state, syscallRip, reason.str());
    }
    const int host = ::open(canonicalPath->c_str(),
                            static_cast<int>(flags & hostedReadOnlyFlags) | O_RDONLY | O_CLOEXEC);
    if (host < 0) {
        setError(state, errno);
        return {};
    }
    const auto descriptor =
        task.fileSpace.openHostFile(*canonicalPath, flags, HostDescriptor{host});
    static_cast<void>(task.fileSpace.setCloseOnExec(descriptor,
                                                    (flags & guestOpenCloseOnExec) != 0));
    setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
    return {};
}

SyscallOutcome handleOpenat(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto directoryDescriptor = GuestFileDescriptor{
        std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.rdi))};
    const auto *directory = task.fileSpace.lookup(directoryDescriptor);
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
    const auto descriptor = task.fileSpace.openSyntheticDirectory(
        std::filesystem::path{"/"} / *path, flags);
    setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
    return {};
}

// Copies host metadata for a guest path into the explicit x86_64 stat64
// layout. Metadata is disclosure-only, so unlike open it answers for any
// path that resolves: bundle-path ancestor walks stat containers outside
// the working directory (for example /Users above a fixture tree).
SyscallOutcome answerHostMetadata(SyscallCall &call, const std::filesystem::path &base,
                                  const std::string &path, bool followFinal,
                                  std::uint64_t outputAddress) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    const auto hostPath = canonicalGuestPathFrom(base, path, followFinal);
    if (!hostPath) {
        setError(state, hostPath.error());
        return {};
    }
    struct stat hostMetadata {};
    const int sampled = followFinal ? ::stat(hostPath->c_str(), &hostMetadata)
                                    : ::lstat(hostPath->c_str(), &hostMetadata);
    if (sampled != 0) {
        setError(state, errno);
        return {};
    }
    const auto metadata = guestStat64FromHost(hostMetadata);
    try {
        addressSpace.validateAccess(guest::GuestAddress{outputAddress}, sizeof(metadata),
                                    guest::Permission::Write);
        addressSpace.writeBytes(guest::GuestAddress{outputAddress},
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

SyscallOutcome handleStat64(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    const bool followFinal = state.rax == syscallStat64;
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
    if (*path == guestPasswdDatabase || *path == guestMasterPasswdDatabase ||
        *path == guestGroupDatabase) {
        // Matches the unprovisioned open() above: libsystem_info's file
        // backend falls back across open, stat, and fstat probes.
        setError(state, ENOENT);
        return {};
    }
    return answerHostMetadata(call, task.fileSpace.currentDirectory(), *path, followFinal,
                              state.rsi);
}

SyscallOutcome handleLseek(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    const auto descriptor = guestDescriptor(state.rdi);
    const auto offset = std::bit_cast<std::int64_t>(state.rsi);
    const auto whence = std::bit_cast<int>(static_cast<std::uint32_t>(state.rdx));
    auto *file = task.fileSpace.lookupMutable(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (!file->hostBacked()) {
        std::ostringstream reason;
        reason << "lseek is not implemented for synthetic guest descriptors; got fd="
               << descriptor.value;
        throw unsupported(state, syscallRip, reason.str());
    }
    if (!isHostDirectory(*file)) {
        // Regular files, pipes, and terminals: the host descriptor owns the
        // position, so host semantics (including ESPIPE) are exact.
        setHostResult(state, ::lseek(file->host.get(), offset, whence));
        return {};
    }
    // Directory positions are getdirentries64 resume indexes.
    if (whence == SEEK_SET && offset >= 0) {
        file->directoryIndex = static_cast<std::uint64_t>(offset);
    } else if (whence != SEEK_CUR || offset != 0) {
        setError(state, EINVAL);
        return {};
    }
    setSuccess(state, file->directoryIndex);
    return {};
}

SyscallOutcome handleFstat64(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = guestDescriptor(state.rdi);
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (!file->hostBacked()) {
        std::ostringstream reason;
        reason << "fstat64 is not implemented for synthetic guest descriptors; got fd="
               << descriptor.value;
        throw unsupported(state, syscallRip, reason.str());
    }
    struct stat hostMetadata {};
    if (::fstat(file->host.get(), &hostMetadata) != 0) {
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

SyscallOutcome handleGetattrlist(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
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
        if (!task.fileSpace.permitsHostPath(canonicalPath)) {
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

SyscallOutcome handleFgetattrlist(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = guestDescriptor(state.rdi);
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (!file->hostBacked()) {
        std::ostringstream reason;
        reason << "fgetattrlist is not implemented for synthetic guest descriptors; got fd="
               << descriptor.value;
        throw unsupported(state, syscallRip, reason.str());
    }
    struct attrlist attributes {};
    static_assert(sizeof(attributes) == sizeof(GuestAttrlist));
    try {
        const auto bytes = addressSpace.readBytes(guest::GuestAddress{state.rsi}, sizeof(attributes));
        std::memcpy(&attributes, bytes.data(), sizeof(attributes));
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    // Attribute buffers hold self-relative references and LP64 types whose
    // layouts match on x86_64 and arm64 Darwin, so the host answer is the
    // guest answer. The returned length leads the buffer.
    const auto size = static_cast<std::size_t>(
        std::min<std::uint64_t>(state.rdx, maximumControlledWrite));
    std::vector<std::uint8_t> output(size);
    if (::fgetattrlist(file->host.get(), &attributes, output.data(), output.size(),
                       static_cast<unsigned int>(state.r10)) != 0) {
        setError(state, errno);
        return {};
    }
    std::uint32_t length = 0;
    if (output.size() >= sizeof(length)) {
        std::memcpy(&length, output.data(), sizeof(length));
    }
    output.resize(std::min<std::size_t>(output.size(), length));
    try {
        addressSpace.writeBytes(guest::GuestAddress{state.rdx}, output);
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleGetattrlistbulk(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = guestDescriptor(state.rdi);
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (!file->hostBacked()) {
        std::ostringstream reason;
        reason << "getattrlistbulk is not implemented for synthetic guest descriptors; got fd="
               << descriptor.value;
        throw unsupported(state, syscallRip, reason.str());
    }
    struct attrlist attributes {};
    try {
        const auto bytes = addressSpace.readBytes(guest::GuestAddress{state.rsi}, sizeof(attributes));
        std::memcpy(&attributes, bytes.data(), sizeof(attributes));
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    // Each returned entry leads with its own u32 length and holds
    // self-relative references to LP64 types laid out identically on x86_64
    // and arm64. The host descriptor carries the directory position.
    // Arguments: fd, attrlist, buffer (RDX), buffer size (R10), options (R8).
    const auto size = static_cast<std::size_t>(
        std::min<std::uint64_t>(state.r10, maximumControlledWrite));
    std::vector<std::uint8_t> output(size);
    const int count = ::getattrlistbulk(file->host.get(), &attributes, output.data(),
                                        output.size(), state.r8);
    if (count < 0) {
        setError(state, errno);
        return {};
    }
    std::size_t used = 0;
    for (int entry = 0; entry < count; ++entry) {
        std::uint32_t length = 0;
        if (output.size() - used < sizeof(length)) {
            throw std::runtime_error("host getattrlistbulk returned a truncated entry");
        }
        std::memcpy(&length, output.data() + used, sizeof(length));
        if (length < sizeof(length) || length > output.size() - used) {
            throw std::runtime_error("host getattrlistbulk returned a malformed entry");
        }
        used += length;
    }
    output.resize(used);
    try {
        if (!output.empty()) {
            addressSpace.writeBytes(guest::GuestAddress{state.rdx}, output);
        }
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    setSuccess(state, static_cast<std::uint64_t>(count));
    return {};
}

SyscallOutcome handleGetfsstat64(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    static_cast<void>(task);
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

SyscallOutcome handleFstatfs64(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = guestDescriptor(state.rdi);
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    GuestStatfs64 filesystem{};
    if (file->hostBacked()) {
        struct statfs host {};
        if (::fstatfs(file->host.get(), &host) != 0) {
            setError(state, errno);
            return {};
        }
        filesystem = guestStatfs64FromHost(host);
    } else if (file->kind == GuestFileKind::RootDirectory ||
               file->kind == GuestFileKind::SyntheticDirectory) {
        filesystem = guestRootFilesystem();
    } else {
        std::ostringstream reason;
        reason << "fstatfs64 is not implemented for this guest descriptor kind; got fd="
               << descriptor.value;
        throw unsupported(state, syscallRip, reason.str());
    }
    try {
        addressSpace.validateAccess(
            guest::GuestAddress{state.rsi}, sizeof(filesystem),
            guest::Permission::Write);
        addressSpace.writeBytes(
            guest::GuestAddress{state.rsi},
            std::span<const std::uint8_t>{
                reinterpret_cast<const std::uint8_t *>(&filesystem),
                sizeof(filesystem)});
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleGetdirentries64(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = GuestFileDescriptor{
        std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.rdi))};
    auto *file = task.fileSpace.lookupMutable(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (!file->hostBacked() || !isHostDirectory(*file)) {
        std::ostringstream reason;
        reason << "getdirentries64 is only implemented for hosted directory descriptors; got fd="
               << descriptor.value;
        throw unsupported(state, syscallRip, reason.str());
    }
    const auto byteCount = static_cast<std::uint64_t>(state.rdx);
    if (byteCount > maximumControlledWrite) {
        setError(state, EINVAL);
        return {};
    }
    try {
        addressSpace.validateAccess(
            guest::GuestAddress{state.rsi}, static_cast<std::size_t>(byteCount),
            guest::Permission::Write);
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    // Each call rereads the host directory by path and skips the entries
    // already returned; the resume index doubles as each entry's seek offset.
    const std::uint64_t startIndex = file->directoryIndex;
    std::uint64_t resumeIndex = startIndex;
    std::vector<std::uint8_t> output;
    output.reserve(static_cast<std::size_t>(byteCount));
    int hostError = 0;
    if (DIR *directory = ::opendir(file->guestPath.c_str())) {
        std::uint64_t entryIndex = 0;
        for (const auto *entry = ::readdir(directory); entry != nullptr;
             entry = ::readdir(directory)) {
            if (entryIndex < startIndex) {
                ++entryIndex;
                continue;
            }
            const std::string_view name{entry->d_name};
            const auto recordLength =
                (21U + static_cast<std::uint32_t>(name.size()) + 1U + 7U) & ~7U;
            if (output.size() + recordLength > byteCount) {
                break;
            }
            const auto recordOffset = output.size();
            output.resize(recordOffset + recordLength, 0);
            const auto ino = static_cast<std::uint64_t>(entry->d_ino);
            std::memcpy(output.data() + recordOffset, &ino, sizeof(ino));
            std::memcpy(output.data() + recordOffset + 8, &entryIndex,
                        sizeof(entryIndex));
            const auto reclen = static_cast<std::uint16_t>(recordLength);
            std::memcpy(output.data() + recordOffset + 16, &reclen, sizeof(reclen));
            const auto namlen = static_cast<std::uint16_t>(name.size());
            std::memcpy(output.data() + recordOffset + 18, &namlen, sizeof(namlen));
            output[recordOffset + 20] = static_cast<std::uint8_t>(entry->d_type);
            std::memcpy(output.data() + recordOffset + 21, name.data(), name.size());
            ++entryIndex;
        }
        resumeIndex = entryIndex;
        ::closedir(directory);
    } else {
        hostError = errno;
    }
    if (hostError != 0) {
        setError(state, hostError);
        return {};
    }
    file->directoryIndex = resumeIndex;
    if (!output.empty()) {
        addressSpace.writeBytes(guest::GuestAddress{state.rsi}, output);
    }
    if (state.rcx != 0) {
        try {
            addressSpace.validateAccess(
                guest::GuestAddress{state.rcx}, sizeof(resumeIndex),
                guest::Permission::Write);
            addressSpace.writeBytes(
                guest::GuestAddress{state.rcx},
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t *>(&resumeIndex),
                    sizeof(resumeIndex)});
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
    }
    setSuccess(state, static_cast<std::uint32_t>(output.size()));
    return {};
}

SyscallOutcome handleFstatat64(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
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
    if ((state.r10 & ~guestAtSymlinkNoFollow) != 0) {
        std::ostringstream reason;
        reason << "only fstatat64 flags 0 and AT_SYMLINK_NOFOLLOW are implemented; got flags=0x"
               << std::hex << state.r10;
        throw unsupported(state, syscallRip, reason.str());
    }
    const bool followFinal = (state.r10 & guestAtSymlinkNoFollow) == 0;
    const auto descriptor = guestDescriptor(state.rdi);
    // As in XNU's nameiat, an absolute path never consults the descriptor.
    if (descriptor.value == guestAtCurrentDirectory ||
        std::filesystem::path{*path}.is_absolute()) {
        return answerHostMetadata(call, task.fileSpace.currentDirectory(), *path, followFinal,
                                  state.rdx);
    }
    const auto *directory = task.fileSpace.lookup(descriptor);
    if (directory == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (directory->hostBacked()) {
        if (!isHostDirectory(*directory)) {
            setError(state, ENOTDIR);
            return {};
        }
        return answerHostMetadata(call, directory->guestPath, *path, followFinal, state.rdx);
    }
    // Synthetic root and cryptex directories answer only the provisioned
    // dyld directory, without touching the host root.
    if (directory->kind != GuestFileKind::RootDirectory &&
        directory->kind != GuestFileKind::SyntheticDirectory) {
        setError(state, ENOTDIR);
        return {};
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

SyscallOutcome handleSocket(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
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
    const auto descriptor = task.fileSpace.openUnixDatagramSocket();
    setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
    return {};
}

SyscallOutcome handleConnect(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = GuestFileDescriptor{
        std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.rdi))};
    const auto *socket = task.fileSpace.lookup(descriptor);
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

SyscallOutcome handleClose(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    const auto descriptor = GuestFileDescriptor{
        std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdi))};
    if (!task.fileSpace.close(descriptor)) {
        setError(state, EBADF);
        return {};
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleRead(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = guestDescriptor(state.rdi);
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (file->kind == GuestFileKind::RandomDevice && state.rdx > 256U) {
        std::ostringstream reason;
        reason << "only reads of at most 256 bytes from the synthetic /dev/urandom are implemented; got fd="
               << descriptor.value << " count=" << state.rdx;
        throw unsupported(state, syscallRip, reason.str());
    }
    if (file->kind != GuestFileKind::RandomDevice && !file->hostBacked()) {
        std::ostringstream reason;
        reason << "read is not implemented for this synthetic guest descriptor; got fd="
               << descriptor.value << " count=" << state.rdx;
        throw unsupported(state, syscallRip, reason.str());
    }
    // A short read is always legal, which bounds Rosa's staging buffer.
    const auto count = static_cast<std::size_t>(
        std::min<std::uint64_t>(state.rdx, maximumControlledWrite));
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
    if (file->kind == GuestFileKind::RandomDevice) {
        if (::getentropy(bytes.data(), bytes.size()) != 0) {
            setError(state, errno);
            return {};
        }
    } else {
        const auto result = ::read(file->host.get(), bytes.data(), bytes.size());
        if (result < 0) {
            setError(state, errno);
            return {};
        }
        bytes.resize(static_cast<std::size_t>(result));
    }
    addressSpace.writeBytes(guest::GuestAddress{state.rsi}, bytes);
    setSuccess(state, bytes.size());
    return {};
}
SyscallOutcome handleFcntl(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = guestDescriptor(state.rdi);
    const auto command = static_cast<std::uint32_t>(state.rsi);
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    switch (command) {
    case guestFcntlDupFd:
    case guestFcntlDupFdCloseOnExec: {
        const auto minimum = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdx));
        if (minimum < 0) {
            setError(state, EINVAL);
            return {};
        }
        const auto duplicate = task.fileSpace.duplicate(
            descriptor, minimum, command == guestFcntlDupFdCloseOnExec);
        setSuccess(state, static_cast<std::uint32_t>(duplicate->value));
        return {};
    }
    case guestFcntlGetFd:
        setSuccess(state, *task.fileSpace.closeOnExec(descriptor) ? guestFdCloseOnExec : 0U);
        return {};
    case guestFcntlSetFd:
        static_cast<void>(task.fileSpace.setCloseOnExec(
            descriptor, (state.rdx & guestFdCloseOnExec) != 0));
        setSuccess(state, 0);
        return {};
    case guestFcntlGetFl:
        if (file->hostBacked()) {
            setHostResult(state, ::fcntl(file->host.get(), F_GETFL));
        } else {
            setSuccess(state, file->flags & guestOpenAccessMode);
        }
        return {};
    case guestFcntlGetLock:
    case guestFcntlSetLock:
    case guestFcntlSetLockWait: {
        // struct flock is {off_t, off_t, pid_t, short, short} on both
        // architectures, and the guest pid is the host pid.
        if (!file->hostBacked()) {
            setError(state, EBADF);
            return {};
        }
        struct flock lock {};
        static_assert(sizeof(lock) == 24);
        try {
            const auto bytes = addressSpace.readBytes(guest::GuestAddress{state.rdx}, sizeof(lock));
            std::memcpy(&lock, bytes.data(), sizeof(lock));
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (::fcntl(file->host.get(), static_cast<int>(command), &lock) != 0) {
            setError(state, errno);
            return {};
        }
        if (command == guestFcntlGetLock) {
            addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                    std::span<const std::uint8_t>{
                                        reinterpret_cast<const std::uint8_t *>(&lock), sizeof(lock)});
        }
        setSuccess(state, 0);
        return {};
    }
    case guestFcntlGetPath:
        break;
    default: {
        std::ostringstream reason;
        reason << "only fcntl F_DUPFD/F_GETFD/F_SETFD/F_GETFL/F_GETLK/F_SETLK/F_SETLKW/F_GETPATH/F_DUPFD_CLOEXEC are implemented; got command="
               << std::dec << command;
        throw unsupported(state, syscallRip, reason.str());
    }
    }
    std::string path = file->guestPath.string();
    if (file->kind == GuestFileKind::StandardStream) {
        std::array<char, MAXPATHLEN> hostPath{};
        if (::fcntl(file->host.get(), F_GETPATH, hostPath.data()) != 0) {
            setError(state, errno);
            return {};
        }
        path = hostPath.data();
    }
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

SyscallOutcome handleFsgetpath(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
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
        task.sharedCache == nullptr
            ? std::optional<std::string_view>{}
            : task.sharedCache->pathForFileIdentity(
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

SyscallOutcome handleWrite(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = guestDescriptor(state.rdi);
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (!file->hostBacked()) {
        std::ostringstream reason;
        reason << "write is not implemented for synthetic guest descriptors; got fd="
               << descriptor.value;
        throw unsupported(state, syscallRip, reason.str());
    }
    // A short write is always legal, which bounds Rosa's staging buffer.
    const auto count = static_cast<std::size_t>(
        std::min<std::uint64_t>(state.rdx, maximumControlledWrite));
    std::vector<std::uint8_t> bytes;
    try {
        bytes = addressSpace.readBytes(guest::GuestAddress{state.rsi}, count);
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    setHostResult(state, ::write(file->host.get(), bytes.data(), bytes.size()));
    return {};
}

} // namespace rosa::darwin::detail
