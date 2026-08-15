#pragma once

#include "guest/Address.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rosa::guest {

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
    std::string label;
};

class AddressSpace {
  public:
    void mapAnonymous(GuestAddress base, std::size_t size, Permission permissions,
                      std::string_view label = {});
    void mapSegment(GuestAddress base, std::size_t size, Permission permissions,
                    std::span<const std::uint8_t> fileBytes, std::string_view label = {});

    [[nodiscard]] std::uint64_t readU64(GuestAddress address) const;
    [[nodiscard]] std::vector<std::uint8_t> readBytes(GuestAddress address, std::size_t size) const;
    void writeU64(GuestAddress address, std::uint64_t value);
    void writeBytes(GuestAddress address, std::span<const std::uint8_t> bytes);

    [[nodiscard]] std::span<const std::uint8_t> executableBytes(GuestAddress address) const;
    [[nodiscard]] std::size_t mappingCount() const noexcept { return mappings_.size(); }
    [[nodiscard]] std::vector<MappingInfo> mappingInfos() const;

  private:
    struct Mapping {
        GuestAddress base{};
        std::size_t size{};
        Permission permissions{Permission::None};
        std::vector<std::uint8_t> bytes;
        std::string label;
    };

    [[nodiscard]] const Mapping &find(GuestAddress address, std::size_t size,
                                      Permission required) const;
    [[nodiscard]] Mapping &find(GuestAddress address, std::size_t size, Permission required);
    void addMapping(GuestAddress base, std::size_t size, Permission permissions,
                    std::span<const std::uint8_t> initialBytes, std::string_view label);

    std::vector<Mapping> mappings_;
};

} // namespace rosa::guest
