#include "guest/AddressSpace.h"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace rosa::guest {
namespace {

bool hasPermission(Permission actual, Permission required) {
    return (static_cast<std::uint8_t>(actual) & static_cast<std::uint8_t>(required)) ==
           static_cast<std::uint8_t>(required);
}

bool rangeContains(GuestAddress base, std::size_t mappingSize, GuestAddress address,
                   std::size_t accessSize) {
    if (address.value < base.value || accessSize > mappingSize) {
        return false;
    }
    const auto offset = address.value - base.value;
    return offset <= mappingSize - accessSize;
}

} // namespace

void AddressSpace::mapAnonymous(GuestAddress base, std::size_t size, Permission permissions,
                                std::string_view label) {
    addMapping(base, size, permissions, {}, label);
}

void AddressSpace::mapSegment(GuestAddress base, std::size_t size, Permission permissions,
                              std::span<const std::uint8_t> fileBytes, std::string_view label) {
    if (fileBytes.size() > size) {
        throw std::invalid_argument("guest segment file bytes exceed virtual size");
    }
    addMapping(base, size, permissions, fileBytes, label);
}

void AddressSpace::mapSparseReadOnly(GuestAddress base, std::size_t size,
                                     std::size_t dataOffset,
                                     std::span<const std::uint8_t> data,
                                     std::string_view label) {
    if (dataOffset > size || data.size() > size - dataOffset) {
        throw std::invalid_argument("sparse guest data lies outside its mapping");
    }
    addMapping(base, size, Permission::Read, {}, label);
    auto &mapping = mappings_.back();
    mapping.readableBytes.resize(size);
    std::fill_n(mapping.readableBytes.begin() + static_cast<std::ptrdiff_t>(dataOffset),
                data.size(), std::uint8_t{1});
    std::copy(data.begin(), data.end(),
              mapping.bytes.begin() + static_cast<std::ptrdiff_t>(dataOffset));
}

void AddressSpace::addMapping(GuestAddress base, std::size_t size, Permission permissions,
                              std::span<const std::uint8_t> initialBytes,
                              std::string_view label) {
    if (size == 0 || (base.value % guestPageSize) != 0 || (size % guestPageSize) != 0) {
        throw std::invalid_argument("guest mappings must be nonempty and 4 KiB aligned");
    }
    if (base.value > std::numeric_limits<std::uint64_t>::max() - size) {
        throw std::invalid_argument("guest anonymous mapping address overflows");
    }
    const auto end = base.value + size;
    for (const auto &mapping : mappings_) {
        const auto existingEnd = mapping.base.value + mapping.size;
        if (base.value < existingEnd && mapping.base.value < end) {
            throw std::invalid_argument("guest anonymous mapping overlaps an existing mapping");
        }
    }
    std::vector<std::uint8_t> backing;
    if (permissions != Permission::None) {
        backing.resize(size);
        std::copy(initialBytes.begin(), initialBytes.end(), backing.begin());
    }
    mappings_.push_back(Mapping{
        .base = base,
        .size = size,
        .permissions = permissions,
        .bytes = std::move(backing),
        .label = std::string(label),
    });
}

std::vector<MappingInfo> AddressSpace::mappingInfos() const {
    std::vector<MappingInfo> result;
    result.reserve(mappings_.size());
    for (const auto &mapping : mappings_) {
        result.push_back(MappingInfo{
            .base = mapping.base,
            .size = mapping.size,
            .permissions = mapping.permissions,
            .label = mapping.label,
        });
    }
    return result;
}

const AddressSpace::Mapping &AddressSpace::find(GuestAddress address, std::size_t size,
                                                Permission required) const {
    for (const auto &mapping : mappings_) {
        if (rangeContains(mapping.base, mapping.size, address, size)) {
            if (!hasPermission(mapping.permissions, required)) {
                throw std::runtime_error("guest memory access violates mapping permissions");
            }
            return mapping;
        }
    }
    throw std::runtime_error("guest memory access is unmapped");
}

AddressSpace::Mapping &AddressSpace::find(GuestAddress address, std::size_t size,
                                          Permission required) {
    return const_cast<Mapping &>(std::as_const(*this).find(address, size, required));
}

std::uint64_t AddressSpace::readU64(GuestAddress address) const {
    const auto bytes = readBytes(address, sizeof(std::uint64_t));
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
    }
    return value;
}

std::vector<std::uint8_t> AddressSpace::readBytes(GuestAddress address, std::size_t size) const {
    std::vector<std::uint8_t> result;
    result.reserve(size);
    auto cursor = address;
    while (result.size() < size) {
        const auto &mapping = find(cursor, 1, Permission::Read);
        const auto offset = static_cast<std::size_t>(cursor.value - mapping.base.value);
        const auto chunk = std::min(size - result.size(), mapping.size - offset);
        if (!mapping.readableBytes.empty() &&
            std::find(mapping.readableBytes.begin() + static_cast<std::ptrdiff_t>(offset),
                      mapping.readableBytes.begin() +
                          static_cast<std::ptrdiff_t>(offset + chunk),
                      std::uint8_t{0}) !=
                mapping.readableBytes.begin() +
                    static_cast<std::ptrdiff_t>(offset + chunk)) {
            throw std::runtime_error("guest read targets unsupported sparse mapping data");
        }
        result.insert(result.end(), mapping.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                      mapping.bytes.begin() + static_cast<std::ptrdiff_t>(offset + chunk));
        cursor.value += chunk;
    }
    return result;
}

void AddressSpace::writeU64(GuestAddress address, std::uint64_t value) {
    std::array<std::uint8_t, sizeof(value)> bytes{};
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        bytes[index] = static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU);
    }
    writeBytes(address, bytes);
}

void AddressSpace::writeBytes(GuestAddress address, std::span<const std::uint8_t> bytes) {
    std::size_t validated = 0;
    auto validationCursor = address;
    while (validated < bytes.size()) {
        const auto &mapping = std::as_const(*this).find(validationCursor, 1, Permission::Write);
        const auto offset = static_cast<std::size_t>(validationCursor.value - mapping.base.value);
        const auto chunk = std::min(bytes.size() - validated, mapping.size - offset);
        validated += chunk;
        validationCursor.value += chunk;
    }

    std::size_t copied = 0;
    auto cursor = address;
    while (copied < bytes.size()) {
        auto &mapping = find(cursor, 1, Permission::Write);
        const auto offset = static_cast<std::size_t>(cursor.value - mapping.base.value);
        const auto chunk = std::min(bytes.size() - copied, mapping.size - offset);
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(copied), chunk,
                    mapping.bytes.begin() + static_cast<std::ptrdiff_t>(offset));
        copied += chunk;
        cursor.value += chunk;
    }
}

std::span<const std::uint8_t> AddressSpace::executableBytes(GuestAddress address) const {
    const auto &mapping = find(address, 1, Permission::Execute);
    const auto offset = static_cast<std::size_t>(address.value - mapping.base.value);
    return std::span<const std::uint8_t>(mapping.bytes).subspan(offset);
}

} // namespace rosa::guest
