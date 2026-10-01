#include "darwin/Files.h"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace rosa::darwin {
namespace {

// Matches XNU's default per-process maxfilesperproc soft limit.
constexpr std::int32_t maximumGuestDescriptors = 10240;

} // namespace

HostDescriptor::HostDescriptor(HostDescriptor &&other) noexcept
    : descriptor_(std::exchange(other.descriptor_, -1)) {}

HostDescriptor &HostDescriptor::operator=(HostDescriptor &&other) noexcept {
    if (this != &other) {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
        descriptor_ = std::exchange(other.descriptor_, -1);
    }
    return *this;
}

HostDescriptor::~HostDescriptor() {
    if (descriptor_ >= 0) {
        ::close(descriptor_);
    }
}

GuestFileSpace::GuestFileSpace()
    : GuestFileSpace(std::filesystem::current_path()) {}

GuestFileSpace::GuestFileSpace(std::filesystem::path currentDirectory)
    : currentDirectory_(std::move(currentDirectory)) {
    if (!currentDirectory_.is_absolute()) {
        throw std::invalid_argument(
            "guest current-directory backing must be absolute");
    }
    inheritStandardStreams();
}

void GuestFileSpace::inheritStandardStreams() {
    for (const int stream : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO}) {
        // Duplicate rather than alias, so a guest close never closes Rosa's
        // own diagnostics stream. A stream Rosa was not given stays closed.
        const int duplicate = ::fcntl(stream, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
        if (duplicate < 0) {
            continue;
        }
        const int statusFlags = ::fcntl(duplicate, F_GETFL);
        static_cast<void>(install(
            GuestOpenFile{
                .kind = GuestFileKind::StandardStream,
                .flags = statusFlags < 0 ? 0U : static_cast<std::uint32_t>(statusFlags),
                .host = HostDescriptor{duplicate},
            },
            false, stream));
    }
}

bool GuestFileSpace::permitsHostPath(const std::filesystem::path &canonicalPath) const {
    if (hostAccess_ == GuestHostAccess::HostReadOnly) {
        return true;
    }
    const auto relative = canonicalPath.lexically_relative(currentDirectory_);
    if (relative.empty() || relative.is_absolute()) {
        return false;
    }
    const auto first = relative.begin();
    return first == relative.end() || *first != "..";
}

GuestFileDescriptor GuestFileSpace::lowestFreeDescriptor(std::int32_t minimum) const {
    auto candidate = std::max(minimum, std::int32_t{0});
    for (auto iterator = descriptors_.lower_bound(GuestFileDescriptor{candidate});
         iterator != descriptors_.end() && iterator->first.value == candidate; ++iterator) {
        ++candidate;
    }
    if (candidate >= maximumGuestDescriptors) {
        throw std::runtime_error("guest file-descriptor namespace exhausted");
    }
    return GuestFileDescriptor{candidate};
}

GuestFileDescriptor GuestFileSpace::install(GuestOpenFile file, bool closeOnExec,
                                            std::int32_t minimum) {
    const auto descriptor = lowestFreeDescriptor(minimum);
    if (file.descriptionId == 0) {
        file.descriptionId = nextDescriptionId_++;
    }
    descriptors_.emplace(descriptor,
                         DescriptorEntry{
                             .description = std::make_shared<GuestOpenFile>(std::move(file)),
                             .closeOnExec = closeOnExec,
                         });
    return descriptor;
}

GuestFileDescriptor GuestFileSpace::openCurrentDirectory(std::uint32_t flags) {
    const int host = ::open(currentDirectory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (host < 0) {
        throw std::runtime_error("cannot open the guest current directory on the host");
    }
    return openHostFile(currentDirectory_, flags, HostDescriptor{host});
}

GuestFileDescriptor GuestFileSpace::openRootDirectory(std::uint32_t flags) {
    return install(GuestOpenFile{
        .kind = GuestFileKind::RootDirectory,
        .guestPath = "/",
        .flags = flags,
    });
}

GuestFileDescriptor GuestFileSpace::openSyntheticDirectory(
    std::filesystem::path guestPath, std::uint32_t flags) {
    if (!guestPath.is_absolute()) {
        throw std::invalid_argument(
            "synthetic guest directory path must be absolute");
    }
    return install(GuestOpenFile{
        .kind = GuestFileKind::SyntheticDirectory,
        .guestPath = std::move(guestPath),
        .flags = flags,
    });
}

GuestFileDescriptor GuestFileSpace::openHostFile(std::filesystem::path canonicalPath,
                                                 std::uint32_t flags, HostDescriptor host) {
    if (!host.valid()) {
        throw std::invalid_argument("hosted guest file requires an open host descriptor");
    }
    const auto kind = canonicalPath == currentDirectory_ ? GuestFileKind::CurrentDirectory
                                                         : GuestFileKind::HostReadOnlyFile;
    return install(GuestOpenFile{
        .kind = kind,
        .guestPath = std::move(canonicalPath),
        .flags = flags,
        .host = std::move(host),
    });
}

GuestFileDescriptor GuestFileSpace::openRandomDevice(std::uint32_t flags) {
    return install(GuestOpenFile{
        .kind = GuestFileKind::RandomDevice,
        .guestPath = "/dev/urandom",
        .flags = flags,
    });
}

GuestFileDescriptor GuestFileSpace::openUnixDatagramSocket() {
    return install(GuestOpenFile{.kind = GuestFileKind::UnixDatagramSocket});
}

std::optional<GuestFileDescriptor> GuestFileSpace::duplicate(GuestFileDescriptor descriptor,
                                                             std::int32_t minimum,
                                                             bool closeOnExec) {
    const auto source = descriptors_.find(descriptor);
    if (source == descriptors_.end()) {
        return std::nullopt;
    }
    const auto duplicateDescriptor = lowestFreeDescriptor(minimum);
    descriptors_.emplace(duplicateDescriptor,
                         DescriptorEntry{
                             .description = source->second.description,
                             .closeOnExec = closeOnExec,
                         });
    return duplicateDescriptor;
}

const GuestOpenFile *GuestFileSpace::lookup(
    GuestFileDescriptor descriptor) const noexcept {
    const auto iterator = descriptors_.find(descriptor);
    return iterator == descriptors_.end() ? nullptr : iterator->second.description.get();
}

GuestOpenFile *GuestFileSpace::lookupMutable(
    GuestFileDescriptor descriptor) noexcept {
    const auto iterator = descriptors_.find(descriptor);
    return iterator == descriptors_.end() ? nullptr : iterator->second.description.get();
}

std::optional<bool> GuestFileSpace::closeOnExec(GuestFileDescriptor descriptor) const noexcept {
    const auto iterator = descriptors_.find(descriptor);
    if (iterator == descriptors_.end()) {
        return std::nullopt;
    }
    return iterator->second.closeOnExec;
}

bool GuestFileSpace::setCloseOnExec(GuestFileDescriptor descriptor, bool enabled) noexcept {
    const auto iterator = descriptors_.find(descriptor);
    if (iterator == descriptors_.end()) {
        return false;
    }
    iterator->second.closeOnExec = enabled;
    return true;
}

bool GuestFileSpace::close(GuestFileDescriptor descriptor) noexcept {
    return descriptors_.erase(descriptor) != 0;
}

} // namespace rosa::darwin
