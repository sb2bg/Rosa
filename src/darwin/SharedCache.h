#pragma once

#include "guest/Address.h"
#include "guest/AddressSpace.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rosa::darwin {

enum class SharedCacheArchitecture : std::uint8_t {
    X86_64,
    X86_64h,
};

struct SharedCacheMapping {
    guest::GuestAddress address{};
    std::uint64_t size{};
    std::uint64_t fileOffset{};
    std::uint64_t slideInfoFileOffset{};
    std::uint64_t slideInfoFileSize{};
    std::uint64_t flags{};
    guest::Permission maximumPermissions{guest::Permission::None};
    guest::Permission initialPermissions{guest::Permission::None};
    std::filesystem::path sourcePath;
    std::string sourceSuffix;
};

struct SharedCacheFile {
    std::filesystem::path path;
    std::string suffix;
    std::array<std::uint8_t, 16> uuid{};
    std::uint64_t cacheVmOffset{};
    std::vector<SharedCacheMapping> mappings;
};

class GuestSharedCache {
  public:
    [[nodiscard]] static GuestSharedCache open(const std::filesystem::path &path);

    void mapInto(guest::AddressSpace &addressSpace) const;

    [[nodiscard]] SharedCacheArchitecture architecture() const noexcept {
        return architecture_;
    }
    [[nodiscard]] std::string_view architectureName() const noexcept;
    [[nodiscard]] std::string_view magic() const noexcept { return magic_; }
    [[nodiscard]] const std::array<std::uint8_t, 16> &uuid() const noexcept {
        return uuid_;
    }
    [[nodiscard]] guest::GuestAddress regionStart() const noexcept {
        return regionStart_;
    }
    [[nodiscard]] std::uint64_t regionSize() const noexcept { return regionSize_; }
    [[nodiscard]] std::uint64_t maximumSlide() const noexcept { return maximumSlide_; }
    [[nodiscard]] std::uint64_t slide() const noexcept { return 0; }
    [[nodiscard]] guest::GuestAddress dyldMachHeader() const noexcept {
        return dyldMachHeader_;
    }
    [[nodiscard]] guest::GuestAddress dyldEntryPoint() const noexcept {
        return dyldEntryPoint_;
    }
    [[nodiscard]] std::uint32_t platform() const noexcept { return platform_; }
    [[nodiscard]] std::uint32_t osVersion() const noexcept { return osVersion_; }
    [[nodiscard]] std::uint32_t imageCount() const noexcept { return imageCount_; }
    [[nodiscard]] guest::GuestAddress dynamicDataAddress() const noexcept {
        return dynamicDataAddress_;
    }
    [[nodiscard]] std::uint64_t dynamicDataSize() const noexcept {
        return dynamicDataSize_;
    }
    [[nodiscard]] const std::vector<SharedCacheFile> &files() const noexcept {
        return files_;
    }
    [[nodiscard]] const std::vector<SharedCacheMapping> &mappings() const noexcept {
        return mappings_;
    }

  private:
    SharedCacheArchitecture architecture_{SharedCacheArchitecture::X86_64};
    std::string magic_;
    std::array<std::uint8_t, 16> uuid_{};
    guest::GuestAddress regionStart_{};
    std::uint64_t regionSize_{};
    std::uint64_t maximumSlide_{};
    guest::GuestAddress dyldMachHeader_{};
    guest::GuestAddress dyldEntryPoint_{};
    std::uint32_t platform_{};
    std::uint32_t osVersion_{};
    std::uint32_t imageCount_{};
    guest::GuestAddress dynamicDataAddress_{};
    std::uint64_t dynamicDataSize_{};
    std::vector<SharedCacheFile> files_;
    std::vector<SharedCacheMapping> mappings_;
};

[[nodiscard]] std::string formatSharedCacheUuid(
    const std::array<std::uint8_t, 16> &uuid);

} // namespace rosa::darwin
