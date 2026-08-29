#include "guest/AddressSpace.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace rosa::guest {

class PrivateFileMapping {
  public:
    PrivateFileMapping(void *address, std::size_t size)
        : address_(address), size_(size) {}

    PrivateFileMapping(const PrivateFileMapping &) = delete;
    PrivateFileMapping &operator=(const PrivateFileMapping &) = delete;

    PrivateFileMapping(PrivateFileMapping &&other) noexcept
        : address_(std::exchange(other.address_, MAP_FAILED)),
          size_(std::exchange(other.size_, 0)) {}

    ~PrivateFileMapping() {
        if (address_ != MAP_FAILED) {
            ::munmap(address_, size_);
        }
    }

    [[nodiscard]] std::uint8_t *data() const noexcept {
        return static_cast<std::uint8_t *>(address_);
    }

  private:
    void *address_{MAP_FAILED};
    std::size_t size_{};
};

namespace {

class FileDescriptor final {
  public:
    explicit FileDescriptor(int descriptor) : descriptor_(descriptor) {}

    FileDescriptor(const FileDescriptor &) = delete;
    FileDescriptor &operator=(const FileDescriptor &) = delete;

    ~FileDescriptor() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    [[nodiscard]] int get() const noexcept { return descriptor_; }

  private:
    int descriptor_{-1};
};

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

void addMappingCount(std::size_t &count, std::size_t amount) {
    if (amount > std::numeric_limits<std::size_t>::max() - count) {
        throw std::overflow_error("guest mapping transformation count overflows");
    }
    count += amount;
}

std::runtime_error fileMappingError(std::string_view operation,
                                    const std::filesystem::path &path,
                                    int error) {
    return std::runtime_error(std::string(operation) + " " + path.string() + ": " +
                              std::strerror(error));
}

} // namespace

void AddressSpace::mapAnonymous(GuestAddress base, std::size_t size, Permission permissions,
                                std::string_view label) {
    addMapping(base, size, permissions, permissions, {}, label);
}

void AddressSpace::mapAnonymous(GuestAddress base, std::size_t size,
                                Permission permissions,
                                Permission maximumPermissions,
                                std::string_view label) {
    addMapping(base, size, permissions, maximumPermissions, {}, label);
}

void AddressSpace::mapSegment(GuestAddress base, std::size_t size,
                              Permission permissions,
                              std::span<const std::uint8_t> fileBytes,
                              std::string_view label) {
    mapSegment(base, size, permissions, permissions, fileBytes, label);
}

void AddressSpace::mapSegment(GuestAddress base, std::size_t size,
                              Permission permissions,
                              Permission maximumPermissions,
                              std::span<const std::uint8_t> fileBytes,
                              std::string_view label) {
    if (fileBytes.size() > size) {
        throw std::invalid_argument("guest segment file bytes exceed virtual size");
    }
    addMapping(base, size, permissions, maximumPermissions, fileBytes, label);
}

void AddressSpace::mapFileSegment(GuestAddress base, std::size_t size,
                                  Permission permissions,
                                  Permission maximumPermissions,
                                  const std::filesystem::path &path,
                                  std::uint64_t fileOffset,
                                  std::string_view label) {
    validateNewMapping(base, size, permissions, maximumPermissions);
    const auto rawDescriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (rawDescriptor < 0) {
        throw fileMappingError("cannot open guest file backing", path, errno);
    }
    const FileDescriptor descriptor(rawDescriptor);

    struct stat information {};
    if (::fstat(descriptor.get(), &information) != 0) {
        throw fileMappingError("cannot inspect guest file backing", path, errno);
    }
    if (information.st_size < 0 ||
        fileOffset > static_cast<std::uint64_t>(information.st_size) ||
        size > static_cast<std::uint64_t>(information.st_size) - fileOffset) {
        throw std::invalid_argument("guest file-backed mapping exceeds source file");
    }

    const auto rawHostPageSize = ::sysconf(_SC_PAGESIZE);
    if (rawHostPageSize <= 0) {
        throw std::runtime_error("cannot query host page size for guest file backing");
    }
    const auto hostPageSize = static_cast<std::uint64_t>(rawHostPageSize);
    const auto alignedOffset = fileOffset - (fileOffset % hostPageSize);
    const auto prefixValue = fileOffset - alignedOffset;
    if (prefixValue > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument("guest file-backed mapping prefix overflows");
    }
    const auto prefix = static_cast<std::size_t>(prefixValue);
    if (prefix > std::numeric_limits<std::size_t>::max() - size) {
        throw std::invalid_argument("guest file-backed mapping size overflows");
    }
    const auto hostMappingSize = prefix + size;
    const auto hostAddress = ::mmap(nullptr, hostMappingSize, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE, descriptor.get(),
                                    static_cast<off_t>(alignedOffset));
    if (hostAddress == MAP_FAILED) {
        throw fileMappingError("cannot map guest file backing", path, errno);
    }

    // Keep the raw mapping owned while allocating the shared control block.
    // If allocation throws, the stack owner unmaps it during unwinding.
    PrivateFileMapping pendingMapping(hostAddress, hostMappingSize);
    auto fileBytes =
        std::make_shared<PrivateFileMapping>(std::move(pendingMapping));
    insertMapping(Mapping{
        .base = base,
        .size = size,
        .permissions = permissions,
        .maximumPermissions = maximumPermissions,
        .fileBytes = std::move(fileBytes),
        .fileDataOffset = prefix,
        .label = std::string(label),
    });
}

void AddressSpace::mapSparseReadOnly(GuestAddress base, std::size_t size,
                                     std::size_t dataOffset,
                                     std::span<const std::uint8_t> data,
                                     std::string_view label) {
    if (dataOffset > size || data.size() > size - dataOffset) {
        throw std::invalid_argument("sparse guest data lies outside its mapping");
    }
    validateNewMapping(base, size, Permission::Read, Permission::Read);

    std::vector<std::uint8_t> backing(size);
    std::vector<std::uint8_t> readableBytes(size);
    std::fill_n(readableBytes.begin() + static_cast<std::ptrdiff_t>(dataOffset),
                data.size(), std::uint8_t{1});
    std::copy(data.begin(), data.end(),
              backing.begin() + static_cast<std::ptrdiff_t>(dataOffset));
    insertMapping(Mapping{
        .base = base,
        .size = size,
        .permissions = Permission::Read,
        .maximumPermissions = Permission::Read,
        .bytes = std::move(backing),
        .readableBytes = std::move(readableBytes),
        .label = std::string(label),
    });
}

void AddressSpace::populateSparseReadOnly(GuestAddress address,
                                          std::span<const std::uint8_t> data) {
    if (data.empty()) {
        return;
    }
    auto &mapping = find(address, data.size(), Permission::Read);
    if (mapping.readableBytes.empty()) {
        throw std::invalid_argument("guest mapping is not sparse read-only data");
    }
    const auto offset = static_cast<std::size_t>(address.value - mapping.base.value);
    std::fill_n(mapping.readableBytes.begin() + static_cast<std::ptrdiff_t>(offset),
                data.size(), std::uint8_t{1});
    std::copy(data.begin(), data.end(),
              mapping.bytes.begin() + static_cast<std::ptrdiff_t>(offset));
}

ProtectResult AddressSpace::protect(GuestAddress address, std::uint64_t size,
                                    Permission permissions,
                                    bool makePrivateCopy) {
    if (size == 0) {
        return ProtectResult::Success;
    }
    if (address.value > std::numeric_limits<std::uint64_t>::max() - size) {
        return ProtectResult::InvalidArgument;
    }
    const auto unroundedEnd = address.value + size;
    if (unroundedEnd > std::numeric_limits<std::uint64_t>::max() -
                           (guestPageSize - 1U)) {
        return ProtectResult::InvalidArgument;
    }
    const auto start = address.value & ~(static_cast<std::uint64_t>(guestPageSize) - 1U);
    const auto end = (unroundedEnd + guestPageSize - 1U) &
                     ~(static_cast<std::uint64_t>(guestPageSize) - 1U);

    auto cursor = start;
    while (cursor < end) {
        const auto *mapping = mappingContaining(GuestAddress{cursor});
        if (mapping == nullptr) {
            return ProtectResult::InvalidAddress;
        }
        if (!makePrivateCopy &&
            !hasPermission(mapping->maximumPermissions, permissions)) {
            return ProtectResult::ProtectionFailure;
        }
        cursor = std::min(end, mapping->base.value + mapping->size);
    }

    const auto slice = [](const Mapping &source, std::uint64_t sliceStart,
                          std::uint64_t sliceEnd, Permission currentPermissions,
                          Permission maximumPermissions) {
        const auto offset = static_cast<std::size_t>(sliceStart - source.base.value);
        const auto sliceSize = static_cast<std::size_t>(sliceEnd - sliceStart);
        Mapping result{
            .base = GuestAddress{sliceStart},
            .size = sliceSize,
            .permissions = currentPermissions,
            .maximumPermissions = maximumPermissions,
            .fileBytes = source.fileBytes,
            .fileDataOffset = source.fileDataOffset + offset,
            .label = source.label,
        };
        if (!source.bytes.empty()) {
            result.bytes.assign(
                source.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                source.bytes.begin() + static_cast<std::ptrdiff_t>(offset + sliceSize));
        }
        if (!source.readableBytes.empty()) {
            result.readableBytes.assign(
                source.readableBytes.begin() + static_cast<std::ptrdiff_t>(offset),
                source.readableBytes.begin() +
                    static_cast<std::ptrdiff_t>(offset + sliceSize));
        }
        return result;
    };

    struct Replacement {
        bool applies{};
        std::vector<Mapping> pieces;
    };
    std::vector<Replacement> replacements(mappings_.size());
    std::size_t resultCount = 0;
    for (std::size_t index = 0; index < mappings_.size(); ++index) {
        const auto &mapping = mappings_[index];
        const auto currentStart = mapping.base.value;
        const auto currentEnd = currentStart + mapping.size;
        if (currentEnd <= start || currentStart >= end) {
            addMappingCount(resultCount, 1);
            continue;
        }

        auto &replacement = replacements[index];
        replacement.applies = true;
        replacement.pieces.reserve(3);
        if (currentStart < start) {
            replacement.pieces.push_back(slice(
                mapping, currentStart, start, mapping.permissions,
                mapping.maximumPermissions));
        }
        const auto protectedStart = std::max(currentStart, start);
        const auto protectedEnd = std::min(currentEnd, end);
        replacement.pieces.push_back(slice(
            mapping, protectedStart, protectedEnd, permissions,
            makePrivateCopy ? permissions : mapping.maximumPermissions));
        if (protectedEnd < currentEnd) {
            replacement.pieces.push_back(slice(
                mapping, protectedEnd, currentEnd, mapping.permissions,
                mapping.maximumPermissions));
        }
        addMappingCount(resultCount, replacement.pieces.size());
    }

    static_assert(std::is_nothrow_move_constructible_v<Mapping>);
    std::vector<Mapping> updated;
    updated.reserve(resultCount);
    for (std::size_t index = 0; index < mappings_.size(); ++index) {
        auto &replacement = replacements[index];
        if (!replacement.applies) {
            updated.push_back(std::move(mappings_[index]));
            continue;
        }
        for (auto &piece : replacement.pieces) {
            updated.push_back(std::move(piece));
        }
    }
    mappings_.swap(updated);
    return ProtectResult::Success;
}

DeallocateResult AddressSpace::deallocate(GuestAddress address,
                                          std::uint64_t size) {
    if (size == 0) {
        return DeallocateResult::Success;
    }
    if (address.value > std::numeric_limits<std::uint64_t>::max() - size) {
        return DeallocateResult::InvalidArgument;
    }
    const auto unroundedEnd = address.value + size;
    if (unroundedEnd > std::numeric_limits<std::uint64_t>::max() -
                           (guestPageSize - 1U)) {
        return DeallocateResult::InvalidArgument;
    }
    const auto start =
        address.value & ~(static_cast<std::uint64_t>(guestPageSize) - 1U);
    const auto end =
        (unroundedEnd + guestPageSize - 1U) &
        ~(static_cast<std::uint64_t>(guestPageSize) - 1U);

    const auto slice = [](const Mapping &source, std::uint64_t sliceStart,
                          std::uint64_t sliceEnd) {
        const auto offset =
            static_cast<std::size_t>(sliceStart - source.base.value);
        const auto sliceSize =
            static_cast<std::size_t>(sliceEnd - sliceStart);
        Mapping result{
            .base = GuestAddress{sliceStart},
            .size = sliceSize,
            .permissions = source.permissions,
            .maximumPermissions = source.maximumPermissions,
            .fileBytes = source.fileBytes,
            .fileDataOffset = source.fileDataOffset + offset,
            .label = source.label,
        };
        if (!source.bytes.empty()) {
            result.bytes.assign(
                source.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                source.bytes.begin() +
                    static_cast<std::ptrdiff_t>(offset + sliceSize));
        }
        if (!source.readableBytes.empty()) {
            result.readableBytes.assign(
                source.readableBytes.begin() +
                    static_cast<std::ptrdiff_t>(offset),
                source.readableBytes.begin() +
                    static_cast<std::ptrdiff_t>(offset + sliceSize));
        }
        return result;
    };

    struct Replacement {
        bool applies{};
        std::vector<Mapping> pieces;
    };
    std::vector<Replacement> replacements(mappings_.size());
    std::size_t resultCount = 0;
    for (std::size_t index = 0; index < mappings_.size(); ++index) {
        const auto &mapping = mappings_[index];
        const auto mappingStart = mapping.base.value;
        const auto mappingEnd = mappingStart + mapping.size;
        if (mappingEnd <= start || mappingStart >= end) {
            addMappingCount(resultCount, 1);
            continue;
        }

        auto &replacement = replacements[index];
        replacement.applies = true;
        replacement.pieces.reserve(2);
        if (mappingStart < start) {
            replacement.pieces.push_back(slice(mapping, mappingStart, start));
        }
        if (end < mappingEnd) {
            replacement.pieces.push_back(slice(mapping, end, mappingEnd));
        }
        addMappingCount(resultCount, replacement.pieces.size());
    }

    static_assert(std::is_nothrow_move_constructible_v<Mapping>);
    std::vector<Mapping> updated;
    updated.reserve(resultCount);
    for (std::size_t index = 0; index < mappings_.size(); ++index) {
        auto &replacement = replacements[index];
        if (!replacement.applies) {
            updated.push_back(std::move(mappings_[index]));
            continue;
        }
        for (auto &piece : replacement.pieces) {
            updated.push_back(std::move(piece));
        }
    }
    mappings_.swap(updated);
    return DeallocateResult::Success;
}

void AddressSpace::insertMapping(Mapping mapping) {
    const auto position = std::lower_bound(
        mappings_.begin(), mappings_.end(), mapping.base.value,
        [](const Mapping &candidate, std::uint64_t value) {
            return candidate.base.value < value;
        });
    mappings_.insert(position, std::move(mapping));
}

void AddressSpace::addMapping(GuestAddress base, std::size_t size,
                              Permission permissions,
                              Permission maximumPermissions,
                              std::span<const std::uint8_t> initialBytes,
                              std::string_view label) {
    validateNewMapping(base, size, permissions, maximumPermissions);
    std::vector<std::uint8_t> backing;
    if (maximumPermissions != Permission::None) {
        backing.resize(size);
        std::copy(initialBytes.begin(), initialBytes.end(), backing.begin());
    }
    insertMapping(Mapping{
        .base = base,
        .size = size,
        .permissions = permissions,
        .maximumPermissions = maximumPermissions,
        .bytes = std::move(backing),
        .label = std::string(label),
    });
}

void AddressSpace::validateNewMapping(GuestAddress base, std::size_t size,
                                      Permission permissions,
                                      Permission maximumPermissions) const {
    if (size == 0 || (base.value % guestPageSize) != 0 || (size % guestPageSize) != 0) {
        throw std::invalid_argument("guest mappings must be nonempty and 4 KiB aligned");
    }
    if (base.value > std::numeric_limits<std::uint64_t>::max() - size) {
        throw std::invalid_argument("guest mapping address overflows");
    }
    if (!hasPermission(maximumPermissions, permissions)) {
        throw std::invalid_argument(
            "guest mapping permissions exceed maximum permissions");
    }

    const auto end = base.value + size;
    const auto next = std::lower_bound(
        mappings_.begin(), mappings_.end(), base.value,
        [](const Mapping &candidate, std::uint64_t value) {
            return candidate.base.value < value;
        });
    if (next != mappings_.end() && end > next->base.value) {
        throw std::invalid_argument("guest mapping overlaps an existing mapping");
    }
    if (next != mappings_.begin()) {
        const auto previous = next - 1;
        if (previous->base.value + previous->size > base.value) {
            throw std::invalid_argument("guest mapping overlaps an existing mapping");
        }
    }
}

std::vector<MappingInfo> AddressSpace::mappingInfos() const {
    std::vector<MappingInfo> result;
    result.reserve(mappings_.size());
    for (const auto &mapping : mappings_) {
        result.push_back(MappingInfo{
            .base = mapping.base,
            .size = mapping.size,
            .permissions = mapping.permissions,
            .maximumPermissions = mapping.maximumPermissions,
            .label = mapping.label,
        });
    }
    return result;
}

const AddressSpace::Mapping *
AddressSpace::mappingContaining(GuestAddress address) const noexcept {
    auto next = std::upper_bound(
        mappings_.begin(), mappings_.end(), address.value,
        [](std::uint64_t value, const Mapping &candidate) {
            return value < candidate.base.value;
        });
    if (next == mappings_.begin()) {
        return nullptr;
    }
    --next;
    return rangeContains(next->base, next->size, address, 1) ? &*next : nullptr;
}

const AddressSpace::Mapping &AddressSpace::find(GuestAddress address, std::size_t size,
                                                Permission required) const {
    auto next = std::upper_bound(
        mappings_.begin(), mappings_.end(), address.value,
        [](std::uint64_t value, const Mapping &candidate) {
            return value < candidate.base.value;
        });
    if (next != mappings_.begin()) {
        --next;
        if (rangeContains(next->base, next->size, address, size)) {
            if (!hasPermission(next->permissions, required)) {
                throw std::runtime_error(
                    "guest memory access violates mapping permissions");
            }
            return *next;
        }
    }
    throw std::runtime_error("guest memory access is unmapped");
}

AddressSpace::Mapping &AddressSpace::find(GuestAddress address, std::size_t size,
                                          Permission required) {
    return const_cast<Mapping &>(std::as_const(*this).find(address, size, required));
}

void AddressSpace::readInto(GuestAddress address,
                            std::span<std::uint8_t> destination) const {
    std::size_t copied = 0;
    auto cursor = address;
    while (copied < destination.size()) {
        const auto &mapping = find(cursor, 1, Permission::Read);
        const auto offset = static_cast<std::size_t>(cursor.value - mapping.base.value);
        const auto chunk = std::min(destination.size() - copied, mapping.size - offset);
        if (!mapping.readableBytes.empty()) {
            const auto sparseBegin =
                mapping.readableBytes.begin() + static_cast<std::ptrdiff_t>(offset);
            const auto sparseEnd =
                sparseBegin + static_cast<std::ptrdiff_t>(chunk);
            if (std::find(sparseBegin, sparseEnd, std::uint8_t{0}) != sparseEnd) {
                throw std::runtime_error(
                    "guest read targets unsupported sparse mapping data");
            }
        }

        auto output = destination.begin() + static_cast<std::ptrdiff_t>(copied);
        if (mapping.fileBytes) {
            const auto *source =
                mapping.fileBytes->data() + mapping.fileDataOffset + offset;
            std::copy_n(source, chunk, output);
        } else {
            std::copy_n(mapping.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                        chunk, output);
        }
        copied += chunk;
        cursor.value += chunk;
    }
}

std::uint64_t AddressSpace::readU64(GuestAddress address) const {
    std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
    readInto(address, bytes);
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
    }
    return value;
}

std::uint32_t AddressSpace::readU32(GuestAddress address) const {
    std::array<std::uint8_t, sizeof(std::uint32_t)> bytes{};
    readInto(address, bytes);
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<std::uint32_t>(bytes[index]) << (index * 8U);
    }
    return value;
}

std::vector<std::uint8_t> AddressSpace::readBytes(GuestAddress address,
                                                  std::size_t size) const {
    std::vector<std::uint8_t> result(size);
    readInto(address, result);
    return result;
}

void AddressSpace::validateAccess(GuestAddress address, std::size_t size,
                                  Permission required) const {
    std::size_t validated = 0;
    auto cursor = address;
    while (validated < size) {
        const auto &mapping = find(cursor, 1, required);
        const auto offset = static_cast<std::size_t>(cursor.value - mapping.base.value);
        const auto chunk = std::min(size - validated, mapping.size - offset);
        validated += chunk;
        cursor.value += chunk;
    }
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
        if (mapping.fileBytes) {
            std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(copied), chunk,
                        mapping.fileBytes->data() + mapping.fileDataOffset + offset);
        } else {
            std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(copied), chunk,
                        mapping.bytes.begin() + static_cast<std::ptrdiff_t>(offset));
        }
        copied += chunk;
        cursor.value += chunk;
    }
}

std::span<const std::uint8_t> AddressSpace::executableBytes(GuestAddress address) const {
    const auto &mapping = find(address, 1, Permission::Execute);
    const auto offset = static_cast<std::size_t>(address.value - mapping.base.value);
    if (mapping.fileBytes) {
        return {mapping.fileBytes->data() + mapping.fileDataOffset + offset,
                mapping.size - offset};
    }
    return std::span<const std::uint8_t>(mapping.bytes).subspan(offset);
}

std::span<std::uint8_t>
AddressSpace::mutablePrivateFileMappingBytes(GuestAddress base) {
    const auto mapping = std::lower_bound(
        mappings_.begin(), mappings_.end(), base.value,
        [](const Mapping &candidate, std::uint64_t value) {
            return candidate.base.value < value;
        });
    if (mapping == mappings_.end() || mapping->base != base ||
        !mapping->fileBytes) {
        throw std::runtime_error(
            "guest loader requested a non-file-backed mapping");
    }
    return {mapping->fileBytes->data() + mapping->fileDataOffset,
            mapping->size};
}

} // namespace rosa::guest
