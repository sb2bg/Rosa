#include "macho/Loader.h"

#include <limits>
#include <optional>
#include <stdexcept>
#include <string>

namespace rosa::macho {
namespace {

guest::Permission translatePermissions(std::uint32_t machProtection) {
    auto result = guest::Permission::None;
    if ((machProtection & 0x1U) != 0) {
        result = result | guest::Permission::Read;
    }
    if ((machProtection & 0x2U) != 0) {
        result = result | guest::Permission::Write;
    }
    if ((machProtection & 0x4U) != 0) {
        result = result | guest::Permission::Execute;
    }
    return result;
}

guest::GuestAddress slidAddress(guest::GuestAddress address, std::uint64_t slide) {
    if (address.value > std::numeric_limits<std::uint64_t>::max() - slide) {
        throw std::runtime_error("Mach-O slide overflows a guest virtual address");
    }
    return guest::GuestAddress{address.value + slide};
}

} // namespace

LoadedImage Loader::mapImage(const MachOFile &file, guest::AddressSpace &addressSpace,
                             std::uint64_t slide, std::string_view imageName) const {
    std::size_t mappedSegments = 0;
    std::optional<guest::GuestAddress> loadAddress;
    const auto bytes = file.bytes();
    for (const auto &segment : file.segments()) {
        if (segment.virtualSize == 0) {
            continue;
        }
        if (segment.virtualSize > std::numeric_limits<std::size_t>::max()) {
            throw std::runtime_error("Mach-O segment is too large for this host");
        }
        const auto begin = static_cast<std::size_t>(segment.fileOffset);
        const auto size = static_cast<std::size_t>(segment.fileSize);
        const auto mappingLabel = imageName.empty()
                                      ? segment.name
                                      : std::string(imageName) + ":" + segment.name;
        addressSpace.mapSegment(slidAddress(segment.virtualAddress, slide),
                                static_cast<std::size_t>(segment.virtualSize),
                                translatePermissions(segment.initialProtection),
                                bytes.subspan(begin, size), mappingLabel);
        if (segment.fileOffset == 0 && segment.fileSize >= 32) {
            if (loadAddress) {
                throw std::runtime_error(
                    "Mach-O has multiple segments containing its header");
            }
            loadAddress = slidAddress(segment.virtualAddress, slide);
        }
        ++mappedSegments;
    }
    if (!loadAddress) {
        throw std::runtime_error("Mach-O has no mapped segment containing its header");
    }
    const auto entry = slidAddress(file.entryPoint(), slide);
    static_cast<void>(addressSpace.executableBytes(entry));
    return LoadedImage{.loadAddress = *loadAddress,
                       .entryPoint = entry,
                       .slide = slide,
                       .mappedSegments = mappedSegments};
}

LoadedImage Loader::mapImage(const std::filesystem::path &path, guest::AddressSpace &addressSpace,
                             std::uint64_t slide) const {
    const auto pathString = path.string();
    return mapImage(MachOFile::open(path), addressSpace, slide, pathString);
}

} // namespace rosa::macho
