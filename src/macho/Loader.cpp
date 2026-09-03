#include "macho/Loader.h"

#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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

bool hasPermission(guest::Permission actual, guest::Permission required) {
    return (static_cast<std::uint8_t>(actual) &
            static_cast<std::uint8_t>(required)) ==
           static_cast<std::uint8_t>(required);
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
    const auto bytes = file.bytes();
    std::vector<guest::SegmentMapping> mappings;
    mappings.reserve(file.segments().size());
    std::optional<guest::GuestAddress> loadAddress;

    // Preflight every fallible property before installing any guest mapping.
    for (const auto &segment : file.segments()) {
        if (segment.virtualSize == 0) {
            continue;
        }
        if (segment.virtualSize > std::numeric_limits<std::size_t>::max()) {
            throw std::runtime_error("Mach-O segment is too large for this host");
        }
        // Real loaders map at page granularity: vmsize is rounded up and the
        // tail beyond filesize is zero-filled. sqlite's __LINKEDIT, for
        // example, is 0x5888 bytes and would otherwise fail the 4 KiB
        // guest-page contract. mapSegments zero-fills backing past
        // initialBytes, so rounding the request size is sufficient.
        constexpr std::size_t page = guest::guestPageSize;
        const auto rawSize = static_cast<std::size_t>(segment.virtualSize);
        if (rawSize > std::numeric_limits<std::size_t>::max() - (page - 1U)) {
            throw std::runtime_error("Mach-O segment size overflows page rounding");
        }
        const auto roundedSize = (rawSize + (page - 1U)) & ~(page - 1U);
        const auto mappedAddress = slidAddress(segment.virtualAddress, slide);
        const auto begin = static_cast<std::size_t>(segment.fileOffset);
        const auto size = static_cast<std::size_t>(segment.fileSize);
        auto mappingLabel = imageName.empty()
                                ? segment.name
                                : std::string(imageName) + ":" + segment.name;
        mappings.push_back(guest::SegmentMapping{
            .base = mappedAddress,
            .size = roundedSize,
            .permissions = translatePermissions(segment.initialProtection),
            .maximumPermissions =
                translatePermissions(segment.maximumProtection),
            .initialBytes = bytes.subspan(begin, size),
            .label = std::move(mappingLabel),
        });
        if (segment.fileOffset == 0 && segment.fileSize >= 32) {
            if (loadAddress) {
                throw std::runtime_error(
                    "Mach-O has multiple segments containing its header");
            }
            loadAddress = mappedAddress;
        }
    }
    if (!loadAddress) {
        throw std::runtime_error("Mach-O has no mapped segment containing its header");
    }

    const auto entry = slidAddress(file.entryPoint(), slide);
    bool entryIsExecutable = false;
    for (const auto &mapping : mappings) {
        if (!hasPermission(mapping.permissions, guest::Permission::Execute) ||
            entry.value < mapping.base.value) {
            continue;
        }
        if (entry.value - mapping.base.value < mapping.size) {
            entryIsExecutable = true;
            break;
        }
    }
    if (!entryIsExecutable) {
        throw std::runtime_error(
            "Mach-O entry point is not inside an executable segment");
    }

    addressSpace.mapSegments(mappings);
    return LoadedImage{
        .loadAddress = *loadAddress,
        .entryPoint = entry,
        .slide = slide,
        .mappedSegments = mappings.size(),
    };
}

LoadedImage Loader::mapImage(const std::filesystem::path &path, guest::AddressSpace &addressSpace,
                             std::uint64_t slide) const {
    const auto pathString = path.string();
    return mapImage(MachOFile::open(path), addressSpace, slide, pathString);
}

} // namespace rosa::macho
