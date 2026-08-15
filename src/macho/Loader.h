#pragma once

#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "macho/MachOFile.h"

#include <cstdint>
#include <filesystem>
#include <string_view>
#include <vector>

namespace rosa::macho {

struct LoadedImage {
    guest::GuestAddress loadAddress{};
    guest::GuestAddress entryPoint{};
    std::uint64_t slide{};
    std::size_t mappedSegments{};
};

class Loader {
  public:
    [[nodiscard]] LoadedImage mapImage(const MachOFile &file, guest::AddressSpace &addressSpace,
                                       std::uint64_t slide = 0,
                                       std::string_view imageName = {}) const;
    [[nodiscard]] LoadedImage mapImage(const std::filesystem::path &path,
                                       guest::AddressSpace &addressSpace,
                                       std::uint64_t slide = 0) const;
};

} // namespace rosa::macho
