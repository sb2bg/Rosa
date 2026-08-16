#pragma once

#include "guest/Address.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rosa::darwin {
class GuestSharedCache;
}

namespace rosa::guest {

class PrivateFileMapping;

inline constexpr std::size_t guestPageSize = 4096;

enum class Permission : std::uint8_t {
    None = 0,
    Read = 1U << 0U,
    Write = 1U << 1U,
    Execute = 1U << 2U,
};

constexpr Permission operator|(Permission lhs, Permission rhs) {
    return static_cast<Permission>(static_cast<std::uint8_t>(lhs) | static_cast<std::uint8_t>(rhs));
}

struct MappingInfo {
    GuestAddress base{};
    std::size_t size{};
    Permission permissions{Permission::None};
    Permission maximumPermissions{Permission::None};
    std::string label;
};

enum class ProtectResult : std::uint8_t {
    Success,
    InvalidAddress,
    ProtectionFailure,
    InvalidArgument,
};

enum class DeallocateResult : std::uint8_t {
    Success,
    InvalidArgument,
};

class AddressSpace {
  public:
    void mapAnonymous(GuestAddress base, std::size_t size, Permission permissions,
                      std::string_view label = {});
    void mapAnonymous(GuestAddress base, std::size_t size,
                      Permission permissions,
                      Permission maximumPermissions,
                      std::string_view label = {});
    void mapSegment(GuestAddress base, std::size_t size, Permission permissions,
                    std::span<const std::uint8_t> fileBytes, std::string_view label = {});
    void mapFileSegment(GuestAddress base, std::size_t size,
                        Permission permissions, Permission maximumPermissions,
                        const std::filesystem::path &path, std::uint64_t fileOffset,
                        std::string_view label = {});
    void mapSparseReadOnly(GuestAddress base, std::size_t size, std::size_t dataOffset,
                           std::span<const std::uint8_t> data, std::string_view label);
    void populateSparseReadOnly(GuestAddress address, std::span<const std::uint8_t> data);
    [[nodiscard]] ProtectResult protect(GuestAddress address, std::uint64_t size,
                                        Permission permissions,
                                        bool makePrivateCopy = false);
    [[nodiscard]] DeallocateResult deallocate(GuestAddress address,
                                              std::uint64_t size);

    [[nodiscard]] std::uint64_t readU64(GuestAddress address) const;
    [[nodiscard]] std::uint32_t readU32(GuestAddress address) const;
    [[nodiscard]] std::vector<std::uint8_t> readBytes(GuestAddress address, std::size_t size) const;
    void validateAccess(GuestAddress address, std::size_t size,
                        Permission required) const;
    void writeU64(GuestAddress address, std::uint64_t value);
    void writeBytes(GuestAddress address, std::span<const std::uint8_t> bytes);

    [[nodiscard]] std::span<const std::uint8_t> executableBytes(GuestAddress address) const;
    [[nodiscard]] std::size_t mappingCount() const noexcept { return mappings_.size(); }
    [[nodiscard]] std::vector<MappingInfo> mappingInfos() const;

  private:
    friend class darwin::GuestSharedCache;

    struct Mapping {
        GuestAddress base{};
        std::size_t size{};
        Permission permissions{Permission::None};
        Permission maximumPermissions{Permission::None};
        std::vector<std::uint8_t> bytes;
        std::shared_ptr<PrivateFileMapping> fileBytes;
        std::size_t fileDataOffset{};
        std::vector<std::uint8_t> readableBytes;
        std::string label;
    };

    [[nodiscard]] const Mapping &find(GuestAddress address, std::size_t size,
                                      Permission required) const;
    [[nodiscard]] Mapping &find(GuestAddress address, std::size_t size, Permission required);
    void addMapping(GuestAddress base, std::size_t size,
                    Permission permissions,
                    Permission maximumPermissions,
                    std::span<const std::uint8_t> initialBytes,
                    std::string_view label);
    void validateNewMapping(GuestAddress base, std::size_t size,
                            Permission permissions,
                            Permission maximumPermissions) const;
    [[nodiscard]] std::span<std::uint8_t>
    mutablePrivateFileMappingBytes(GuestAddress base);

    std::vector<Mapping> mappings_;
};

} // namespace rosa::guest
