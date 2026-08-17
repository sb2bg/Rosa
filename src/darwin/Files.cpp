#include "darwin/Files.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace rosa::darwin {

GuestFileSpace::GuestFileSpace()
    : GuestFileSpace(std::filesystem::current_path()) {}

GuestFileSpace::GuestFileSpace(std::filesystem::path currentDirectory)
    : currentDirectory_(std::move(currentDirectory)) {
    if (!currentDirectory_.is_absolute()) {
        throw std::invalid_argument(
            "guest current-directory backing must be absolute");
    }
}

GuestFileDescriptor GuestFileSpace::openCurrentDirectory(
    std::uint32_t flags) {
    if (nextDescriptor_ == std::numeric_limits<std::int32_t>::max()) {
        throw std::runtime_error("guest file-descriptor namespace exhausted");
    }
    const GuestFileDescriptor descriptor{nextDescriptor_++};
    files_.emplace(descriptor,
                   GuestOpenFile{
                       .descriptor = descriptor,
                       .kind = GuestFileKind::CurrentDirectory,
                       .guestPath = currentDirectory_,
                       .flags = flags,
                   });
    return descriptor;
}

const GuestOpenFile *GuestFileSpace::lookup(
    GuestFileDescriptor descriptor) const noexcept {
    const auto iterator = files_.find(descriptor);
    return iterator == files_.end() ? nullptr : &iterator->second;
}

bool GuestFileSpace::close(GuestFileDescriptor descriptor) noexcept {
    return files_.erase(descriptor) != 0;
}

} // namespace rosa::darwin
