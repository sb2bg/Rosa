#include "darwin/SyscallInternal.h"

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
    const auto descriptor = GuestFileDescriptor{
        std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.rdi))};
    const auto duplicate = task.fileSpace.duplicate(descriptor);
    if (!duplicate) {
        setError(state, EBADF);
        return {};
    }
    setSuccess(state, static_cast<std::uint32_t>(duplicate->value));
    return {};
}

SyscallOutcome handleIoctl(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(task);
    const auto descriptor = std::bit_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.rdi));
    if (state.rsi == guestIoctlWindowSize) {
        if (descriptor < STDIN_FILENO || descriptor > STDERR_FILENO) {
            setError(state, EBADF);
            return {};
        }
        // The synthetic console has no host terminal behind it; report
        // the conventional 80x24 size callers use for formatting.
        constexpr std::array<std::uint8_t, 8> windowSize{24, 0, 80, 0,
                                                        0,  0, 0,  0};
        try {
            addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                    windowSize);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        setSuccess(state, 0);
        return {};
    }
    if (state.rsi != guestIoctlFileDescriptorType) {
        std::ostringstream reason;
        reason << "only ioctl(FIODTYPE/TIOCGWINSZ) on a standard guest descriptor is implemented; got fd="
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
    // Resolve relative guest paths against the task's current directory,
    // mirroring the read-only open policy: paths inside it are answered
    // from host metadata, paths outside it have no guest VFS mapping.
    const auto directPath = std::filesystem::path{*path};
    const auto queryPath = directPath.is_absolute()
                               ? directPath
                               : task.fileSpace.currentDirectory() / directPath;
    std::error_code canonicalError;
    const auto canonicalPath =
        std::filesystem::canonical(queryPath, canonicalError);
    if (canonicalError) {
        setError(state, canonicalError.value());
        return {};
    }
    if (!isWithinDirectory(task.fileSpace.currentDirectory(),
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
    if ((flags & O_ACCMODE) == O_RDONLY &&
        std::string_view(*path).find(guestFeatureFlagsPathComponent) !=
            std::string_view::npos) {
        // Rosa provisions no FeatureFlags disclosure domains anywhere;
        // the framework falls back to compiled-in defaults when a domain
        // file is absent, so report it absent.
        setError(state, ENOENT);
        return {};
    }
    if (*path == "." && flags == guestOpenDirectory && mode == 0) {
        const auto descriptor = task.fileSpace.openCurrentDirectory(flags);
        setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
        return {};
    }
    if (*path == "/" && flags == guestOpenRootDirectory && mode == 0) {
        const auto descriptor = task.fileSpace.openRootDirectory(flags);
        setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
        return {};
    }
    if (mode == 0 && (flags == guestOpenDirectory ||
                      flags == (guestOpenDirectory | guestOpenCloseOnExec))) {
        // Read-only directory opens (NSBundle main-bundle probing opens
        // the application directory). Resolve and confine exactly like
        // regular files, but require a directory: the descriptors stay
        // metadata-only and each operation reopens the host path.
        const auto directPath = std::filesystem::path{*path};
        const auto queryPath = directPath.is_absolute()
                                   ? directPath
                                   : task.fileSpace.currentDirectory() / directPath;
        std::error_code error;
        const auto canonicalPath = std::filesystem::canonical(queryPath, error);
        if (error) {
            setError(state, error.value());
            return {};
        }
        if (!isWithinDirectory(task.fileSpace.currentDirectory(),
                               canonicalPath)) {
            std::ostringstream reason;
            reason << "guest VFS has no mapping for read-only directory path \""
                   << *path << '"';
            throw unsupported(state, syscallRip, reason.str());
        }
        if (!std::filesystem::is_directory(canonicalPath, error) ||
            error) {
            setError(state, error ? error.value() : ENOTDIR);
            return {};
        }
        const auto descriptor =
            task.fileSpace.openReadOnlyFile(canonicalPath, flags);
        setSuccess(state, static_cast<std::uint32_t>(descriptor.value));
        return {};
    }
    if (flags == 0 && mode == 0) {
        // Resolve relative guest paths against the task's current
        // directory, mirroring the stat64 policy below. The sandbox
        // check still confines the result to the current directory.
        const auto directPath = std::filesystem::path{*path};
        const auto queryPath = directPath.is_absolute()
                                   ? directPath
                                   : task.fileSpace.currentDirectory() / directPath;
        std::error_code error;
        const auto canonicalPath = std::filesystem::canonical(queryPath, error);
        if (error) {
            setError(state, error.value());
            return {};
        }
        if (!isWithinDirectory(task.fileSpace.currentDirectory(),
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
            task.fileSpace.openReadOnlyFile(canonicalPath, flags);
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

SyscallOutcome handleStat64(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto number = state.rax;
    const char *callName = number == syscallStat64 ? "stat64" : "lstat64";
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
    // Resolve relative guest paths against the task's current directory,
    // mirroring the read-only open and access policy.
    const auto directPath = std::filesystem::path{*path};
    const auto queryPath = directPath.is_absolute()
                               ? directPath
                               : task.fileSpace.currentDirectory() / directPath;
    std::error_code error;
    const auto canonicalPath = std::filesystem::canonical(queryPath, error);
    if (error) {
        setError(state, error.value());
        return {};
    }
    // Bundle-path ancestor walks stat containers outside the working
    // directory (for example /Users above the fixture tree). Metadata is
    // disclosure-only: open and read stay confined, but stat answers real
    // host metadata for any absolute path that canonicalizes.
    struct stat hostMetadata {};
    // Sandbox canonicalization resolves intermediate symlinks, matching
    // the stat64 policy; only the final component keeps link identity.
    const int sampled =
        number == syscallStat64
            ? ::stat(canonicalPath.c_str(), &hostMetadata)
            : ::lstat(canonicalPath.c_str(), &hostMetadata);
    if (sampled != 0) {
        setError(state, errno);
        return {};
    }
    if (!S_ISREG(hostMetadata.st_mode) && !S_ISDIR(hostMetadata.st_mode)) {
        std::ostringstream reason;
        reason << "only mapped regular-file and directory " << callName
               << " is implemented; got path=\"" << *path << '"';
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

SyscallOutcome handleLseek(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    const auto descriptor = std::bit_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.rdi));
    const auto offset = std::bit_cast<std::int64_t>(state.rsi);
    const auto whence = std::bit_cast<int>(static_cast<std::uint32_t>(state.rdx));
    if (descriptor == STDIN_FILENO || descriptor == STDOUT_FILENO ||
        descriptor == STDERR_FILENO) {
        // Guest standard descriptors alias the host ones, so host
        // semantics (including ESPIPE) are exactly right.
        const auto result = ::lseek(descriptor, offset, whence);
        if (result < 0) {
            setError(state, errno);
            return {};
        }
        setSuccess(state, static_cast<std::uint64_t>(result));
        return {};
    }
    auto *file = task.fileSpace.lookupMutable(GuestFileDescriptor{descriptor});
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (file->kind != GuestFileKind::HostReadOnlyFile) {
        std::ostringstream reason;
        reason << "lseek currently accepts only standard descriptors and mapped read-only files; got fd="
               << descriptor;
        throw unsupported(state, syscallRip, reason.str());
    }
    if (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END) {
        setError(state, EINVAL);
        return {};
    }
    __int128 base = 0;
    if (whence == SEEK_CUR) {
        base = static_cast<__int128>(file->offset);
    } else if (whence == SEEK_END) {
        struct stat hostMetadata {};
        if (::stat(file->guestPath.c_str(), &hostMetadata) != 0) {
            setError(state, errno);
            return {};
        }
        base = static_cast<__int128>(hostMetadata.st_size);
    }
    const __int128 positioned = base + static_cast<__int128>(offset);
    if (positioned < 0 ||
        positioned > static_cast<__int128>(
                          std::numeric_limits<std::int64_t>::max())) {
        setError(state, EINVAL);
        return {};
    }
    file->offset = static_cast<std::uint64_t>(positioned);
    setSuccess(state, file->offset);
    return {};
}

SyscallOutcome handleFstat64(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = std::bit_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.rdi));
    struct stat hostMetadata {};
    if (descriptor == STDIN_FILENO || descriptor == STDOUT_FILENO ||
        descriptor == STDERR_FILENO) {
        if (::fstat(descriptor, &hostMetadata) != 0) {
            setError(state, errno);
            return {};
        }
    } else {
        // Guest descriptors stay metadata-only: stat the mapped host
        // path instead of interpreting the guest descriptor as a host
        // descriptor.
        const auto *file = task.fileSpace.lookup(GuestFileDescriptor{descriptor});
        if (file == nullptr) {
            setError(state, EBADF);
            return {};
        }
        if (file->kind != GuestFileKind::HostReadOnlyFile) {
            std::ostringstream reason;
            reason << "fstat64 currently accepts only standard descriptors and mapped read-only files; got fd="
                   << descriptor;
            throw unsupported(state, syscallRip, reason.str());
        }
        if (::stat(file->guestPath.c_str(), &hostMetadata) != 0) {
            setError(state, errno);
            return {};
        }
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
        if (!isWithinDirectory(task.fileSpace.currentDirectory(),
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
    const auto descriptor = GuestFileDescriptor{
        std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.rdi))};
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    GuestStatfs64 filesystem{};
    if (file->kind == GuestFileKind::HostReadOnlyFile ||
        file->kind == GuestFileKind::CurrentDirectory) {
        struct statfs host {};
        if (::statfs(file->guestPath.c_str(), &host) != 0) {
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
    if ((file->kind != GuestFileKind::HostReadOnlyFile &&
         file->kind != GuestFileKind::CurrentDirectory) ||
        !std::filesystem::is_directory(file->guestPath)) {
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
    // The descriptor offset doubles as the directory resume index:
    // descriptors are metadata-only, so each call reopens the host
    // directory and skips entries already returned.
    const std::uint64_t startIndex = file->offset;
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
    file->offset = resumeIndex;
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
    const auto descriptor = GuestFileDescriptor{
        std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdi))};
    const auto *directory = task.fileSpace.lookup(descriptor);
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
    const auto descriptor = GuestFileDescriptor{
        std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdi))};
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (file->kind != GuestFileKind::RandomDevice &&
        file->kind != GuestFileKind::HostReadOnlyFile) {
        std::ostringstream reason;
        reason << "only reads from the synthetic /dev/urandom and mapped read-only files are implemented; got fd="
               << descriptor.value << " count=" << state.rdx;
        throw unsupported(state, syscallRip, reason.str());
    }
    if (file->kind == GuestFileKind::HostReadOnlyFile) {
        // Guest descriptors stay metadata-only: bridge each read with a
        // freshly opened host descriptor and the stored file position.
        auto *mutableFile = task.fileSpace.lookupMutable(descriptor);
        if (mutableFile == nullptr) {
            setError(state, EBADF);
            return {};
        }
        const auto count = static_cast<std::size_t>(state.rdx);
        if (count == 0) {
    setSuccess(state, 0);
    return {};
}
        try {
            addressSpace.validateAccess(guest::GuestAddress{state.rsi},
                                        count,
                                        guest::Permission::Write);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        const int hostDescriptor =
            ::open(mutableFile->guestPath.c_str(), O_RDONLY | O_CLOEXEC);
        if (hostDescriptor < 0) {
            setError(state, errno);
            return {};
        }
        std::vector<std::uint8_t> bytes(count);
        const auto readResult =
            ::pread(hostDescriptor, bytes.data(), bytes.size(),
                    static_cast<off_t>(mutableFile->offset));
        const auto readErrno = errno;
        ::close(hostDescriptor);
        if (readResult < 0) {
            setError(state, readErrno);
            return {};
        }
        bytes.resize(static_cast<std::size_t>(readResult));
        addressSpace.writeBytes(guest::GuestAddress{state.rsi}, bytes);
        mutableFile->offset += static_cast<std::uint64_t>(readResult);
        setSuccess(state, static_cast<std::uint64_t>(readResult));
        return {};
    }
    if (state.rdx > 256U) {
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

SyscallOutcome handleFcntl(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = GuestFileDescriptor{
        std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdi))};
    const auto command = static_cast<std::uint32_t>(state.rsi);
    const auto *file = task.fileSpace.lookup(descriptor);
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
    static_cast<void>(task);
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

} // namespace rosa::darwin::detail
