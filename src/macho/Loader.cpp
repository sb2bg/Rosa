#include "macho/Loader.h"

#include <limits>
#include <stdexcept>

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
                             std::uint64_t slide) const {
    std::size_t mappedSegments = 0;
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
        addressSpace.mapSegment(slidAddress(segment.virtualAddress, slide),
                                static_cast<std::size_t>(segment.virtualSize),
                                translatePermissions(segment.initialProtection),
                                bytes.subspan(begin, size));
        ++mappedSegments;
    }
    const auto entry = slidAddress(file.entryPoint(), slide);
    static_cast<void>(addressSpace.executableBytes(entry));
    return LoadedImage{.entryPoint = entry, .slide = slide, .mappedSegments = mappedSegments};
}

LoadedImage Loader::mapImage(const std::filesystem::path &path, guest::AddressSpace &addressSpace,
                             std::uint64_t slide) const {
    return mapImage(MachOFile::open(path), addressSpace, slide);
}

} // namespace rosa::macho
