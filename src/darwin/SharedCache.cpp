#include "darwin/SharedCache.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>

namespace rosa::darwin {
namespace {

constexpr std::size_t magicSize = 16;
constexpr std::size_t minimumHeaderSize = 24;
constexpr std::size_t currentHeaderSize = 0x228;
constexpr std::size_t mappingRecordSize = 32;
constexpr std::size_t mappingWithSlideRecordSize = 56;
constexpr std::size_t legacySubcacheRecordSize = 24;
constexpr std::size_t modernSubcacheRecordSize = 56;
constexpr std::uint32_t maximumMappingCount = 64;
constexpr std::uint32_t maximumSubcacheCount = 64;
constexpr std::uint32_t supportedProtectionMask = 7;
constexpr std::size_t imageTextRecordSize = 32;
constexpr std::uint64_t maximumImageCount = 1'000'000;
constexpr std::size_t maximumImagePathSize = 4096;

constexpr std::size_t mappingOffsetField = 0x10;
constexpr std::size_t mappingCountField = 0x14;
constexpr std::size_t uuidField = 0x58;
constexpr std::size_t dyldMachHeaderField = 0x78;
constexpr std::size_t dyldEntryPointField = 0x80;
constexpr std::size_t imagesTextOffsetField = 0x88;
constexpr std::size_t imagesTextCountField = 0x90;
constexpr std::size_t platformField = 0xD8;
constexpr std::size_t regionStartField = 0xE0;
constexpr std::size_t regionSizeField = 0xE8;
constexpr std::size_t maximumSlideField = 0xF0;
constexpr std::size_t mappingWithSlideOffsetField = 0x138;
constexpr std::size_t mappingWithSlideCountField = 0x13C;
constexpr std::size_t osVersionField = 0x16C;
constexpr std::size_t subcacheOffsetField = 0x188;
constexpr std::size_t subcacheCountField = 0x18C;
constexpr std::size_t imageOffsetField = 0x1C0;
constexpr std::size_t imageCountField = 0x1C4;
constexpr std::size_t cacheSubtypeField = 0x1C8;
constexpr std::size_t dynamicDataOffsetField = 0x1F0;
constexpr std::size_t dynamicDataSizeField = 0x1F8;

constexpr std::uint32_t machHeader64Magic = 0xFEEDFACFU;
constexpr std::uint32_t x86_64CpuType = 0x01000007U;
constexpr std::uint16_t slidePageAttributes = 0xC000;
constexpr std::uint16_t slidePageExtra = 0x8000;
constexpr std::uint16_t slidePageNoRebase = 0x4000;
constexpr std::uint16_t slidePageEnd = 0x8000;
constexpr std::uint16_t slidePageIndexMask = 0x3FFF;

class FileReader {
  public:
    explicit FileReader(const std::filesystem::path &path) : path_(path) {
        descriptor_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (descriptor_ < 0) {
            throw std::runtime_error("cannot open dyld shared cache " + path.string() +
                                     ": " + std::strerror(errno));
        }
        struct stat information {};
        if (::fstat(descriptor_, &information) != 0) {
            const auto error = errno;
            ::close(descriptor_);
            descriptor_ = -1;
            throw std::runtime_error("cannot inspect dyld shared cache " + path.string() +
                                     ": " + std::strerror(error));
        }
        if (!S_ISREG(information.st_mode) || information.st_size < 0) {
            throw std::runtime_error("dyld shared cache is not a regular file: " +
                                     path.string());
        }
        size_ = static_cast<std::uint64_t>(information.st_size);
    }

    FileReader(const FileReader &) = delete;
    FileReader &operator=(const FileReader &) = delete;

    ~FileReader() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }

    [[nodiscard]] std::vector<std::uint8_t> read(std::uint64_t offset,
                                                  std::size_t size,
                                                  std::string_view description) const {
        if (offset > size_ || size > size_ - offset) {
            throw std::runtime_error("dyld shared cache " + std::string(description) +
                                     " exceeds " + path_.string());
        }
        std::vector<std::uint8_t> result(size);
        std::size_t consumed = 0;
        while (consumed < size) {
            const auto count = ::pread(
                descriptor_, result.data() + consumed, size - consumed,
                static_cast<off_t>(offset + consumed));
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                const auto detail = count < 0 ? std::strerror(errno) : "unexpected end of file";
                throw std::runtime_error("cannot read dyld shared cache " +
                                         std::string(description) + " from " + path_.string() +
                                         ": " + detail);
            }
            consumed += static_cast<std::size_t>(count);
        }
        return result;
    }

    [[nodiscard]] std::string readCString(
        std::uint64_t offset, std::string_view description) const {
        if (offset >= size_) {
            throw std::runtime_error("dyld shared cache " +
                                     std::string(description) + " exceeds " +
                                     path_.string());
        }
        const auto available = static_cast<std::size_t>(
            std::min<std::uint64_t>(maximumImagePathSize, size_ - offset));
        const auto bytes = read(offset, available, description);
        const auto terminator =
            std::ranges::find(bytes, static_cast<std::uint8_t>(0));
        if (terminator == bytes.end()) {
            throw std::runtime_error("dyld shared cache " +
                                     std::string(description) +
                                     " is not NUL-terminated");
        }
        if (terminator == bytes.begin()) {
            throw std::runtime_error("dyld shared cache " +
                                     std::string(description) + " is empty");
        }
        return std::string(bytes.begin(), terminator);
    }

  private:
    std::filesystem::path path_;
    int descriptor_{-1};
    std::uint64_t size_{};
};

std::uint32_t readU32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || sizeof(std::uint32_t) > bytes.size() - offset) {
        throw std::runtime_error("dyld shared cache header field is truncated");
    }
    std::uint32_t result = 0;
    for (std::size_t index = 0; index < sizeof(result); ++index) {
        result |= static_cast<std::uint32_t>(bytes[offset + index]) << (index * 8U);
    }
    return result;
}

std::uint16_t readU16(std::span<const std::uint8_t> bytes,
                      std::size_t offset) {
    if (offset > bytes.size() || sizeof(std::uint16_t) > bytes.size() - offset) {
        throw std::runtime_error("dyld shared cache slide field is truncated");
    }
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(
               static_cast<std::uint16_t>(bytes[offset + 1]) << 8U);
}

std::uint64_t readU64(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || sizeof(std::uint64_t) > bytes.size() - offset) {
        throw std::runtime_error("dyld shared cache header field is truncated");
    }
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < sizeof(result); ++index) {
        result |= static_cast<std::uint64_t>(bytes[offset + index]) << (index * 8U);
    }
    return result;
}

void writeU32(std::span<std::uint8_t> bytes, std::size_t offset,
              std::uint32_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

void writeU64(std::span<std::uint8_t> bytes, std::size_t offset,
              std::uint64_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

struct SlideInfo2 {
    std::uint32_t pageSize{};
    std::uint32_t pageStartsOffset{};
    std::uint32_t pageStartsCount{};
    std::uint32_t pageExtrasOffset{};
    std::uint32_t pageExtrasCount{};
    std::uint64_t deltaMask{};
    std::uint64_t valueAdd{};
};

std::size_t checkedTableSize(std::uint32_t count, std::size_t recordSize,
                             std::uint32_t maximumCount,
                             std::string_view description);

SlideInfo2 parseSlideInfo2(std::span<const std::uint8_t> bytes,
                           const SharedCacheMapping &mapping) {
    constexpr std::size_t headerSize = 40;
    if (bytes.size() < headerSize || readU32(bytes, 0) != 2) {
        throw std::runtime_error(
            "x86_64 dyld shared cache requires slide-info version 2");
    }
    const SlideInfo2 result{
        .pageSize = readU32(bytes, 4),
        .pageStartsOffset = readU32(bytes, 8),
        .pageStartsCount = readU32(bytes, 12),
        .pageExtrasOffset = readU32(bytes, 16),
        .pageExtrasCount = readU32(bytes, 20),
        .deltaMask = readU64(bytes, 24),
        .valueAdd = readU64(bytes, 32),
    };
    if (result.pageSize != guest::guestPageSize ||
        mapping.size / result.pageSize != result.pageStartsCount ||
        (mapping.size % result.pageSize) != 0) {
        throw std::runtime_error(
            "dyld shared cache slide page geometry differs from its mapping");
    }
    const auto startsSize = checkedTableSize(
        result.pageStartsCount, sizeof(std::uint16_t),
        std::numeric_limits<std::uint32_t>::max(), "slide page-start");
    const auto extrasSize = checkedTableSize(
        result.pageExtrasCount, sizeof(std::uint16_t),
        std::numeric_limits<std::uint32_t>::max(), "slide page-extra");
    if (result.pageStartsOffset > bytes.size() ||
        startsSize > bytes.size() - result.pageStartsOffset ||
        result.pageExtrasOffset > bytes.size() ||
        extrasSize > bytes.size() - result.pageExtrasOffset) {
        throw std::runtime_error("dyld shared cache slide tables are truncated");
    }
    if (result.deltaMask == 0) {
        throw std::runtime_error("dyld shared cache slide delta mask is empty");
    }
    const auto trailingZeros = std::countr_zero(result.deltaMask);
    const auto normalizedMask = result.deltaMask >> trailingZeros;
    if (trailingZeros < 2 ||
        (normalizedMask & (normalizedMask + 1U)) != 0) {
        throw std::runtime_error(
            "dyld shared cache slide delta mask is not contiguous");
    }

    for (std::uint32_t page = 0; page < result.pageStartsCount; ++page) {
        const auto start = readU16(
            bytes, result.pageStartsOffset +
                       static_cast<std::size_t>(page) * sizeof(std::uint16_t));
        const auto attributes = static_cast<std::uint16_t>(
            start & slidePageAttributes);
        if (attributes == slidePageNoRebase) {
            continue;
        }
        if (attributes == 0) {
            const auto offset = static_cast<std::uint64_t>(start) * 4U;
            if (offset > result.pageSize - sizeof(std::uint64_t)) {
                throw std::runtime_error(
                    "dyld shared cache slide chain starts outside its page");
            }
            continue;
        }
        if (attributes != slidePageExtra) {
            throw std::runtime_error(
                "dyld shared cache slide page has invalid attributes");
        }
        auto extraIndex = static_cast<std::uint32_t>(
            start & slidePageIndexMask);
        bool sawEnd = false;
        while (extraIndex < result.pageExtrasCount) {
            const auto extra = readU16(
                bytes, result.pageExtrasOffset +
                           static_cast<std::size_t>(extraIndex) *
                               sizeof(std::uint16_t));
            if ((extra & 0x4000U) != 0) {
                throw std::runtime_error(
                    "dyld shared cache slide extra has invalid attributes");
            }
            const auto offset = static_cast<std::uint64_t>(
                                    extra & slidePageIndexMask) *
                                4U;
            if (offset > result.pageSize - sizeof(std::uint64_t)) {
                throw std::runtime_error(
                    "dyld shared cache extra slide chain starts outside its page");
            }
            ++extraIndex;
            if ((extra & slidePageEnd) != 0) {
                sawEnd = true;
                break;
            }
        }
        if (!sawEnd) {
            throw std::runtime_error(
                "dyld shared cache extra slide chains are unterminated");
        }
    }
    return result;
}

void applySlideInfo2(std::span<std::uint8_t> mappingBytes,
                     const SharedCacheMapping &mapping, std::uint64_t slide) {
    const auto info = parseSlideInfo2(mapping.slideInfo, mapping);
    const auto valueMask = ~info.deltaMask;
    const auto deltaShift =
        static_cast<unsigned>(std::countr_zero(info.deltaMask)) - 2U;
    const auto applyChain = [&](std::uint32_t pageIndex,
                                std::uint16_t start) {
        auto pageOffset = static_cast<std::uint64_t>(
                              start & slidePageIndexMask) *
                          4U;
        const auto pageBase = static_cast<std::size_t>(pageIndex) *
                              info.pageSize;
        while (true) {
            if (pageOffset > info.pageSize - sizeof(std::uint64_t)) {
                throw std::runtime_error(
                    "dyld shared cache slide chain leaves its page");
            }
            const auto location = pageBase +
                                  static_cast<std::size_t>(pageOffset);
            const auto raw = readU64(mappingBytes, location);
            const auto delta = (raw & info.deltaMask) >> deltaShift;
            auto value = raw & valueMask;
            if (value != 0) {
                if (value > std::numeric_limits<std::uint64_t>::max() -
                                info.valueAdd ||
                    value + info.valueAdd >
                        std::numeric_limits<std::uint64_t>::max() - slide) {
                    throw std::runtime_error(
                        "dyld shared cache rebased pointer overflows");
                }
                value += info.valueAdd + slide;
            }
            writeU64(mappingBytes, location, value);
            if (delta == 0) {
                break;
            }
            if (pageOffset > info.pageSize - delta) {
                throw std::runtime_error(
                    "dyld shared cache slide delta leaves its page");
            }
            pageOffset += delta;
        }
    };

    for (std::uint32_t page = 0; page < info.pageStartsCount; ++page) {
        const auto start = readU16(
            mapping.slideInfo,
            info.pageStartsOffset +
                static_cast<std::size_t>(page) * sizeof(std::uint16_t));
        const auto attributes = static_cast<std::uint16_t>(
            start & slidePageAttributes);
        if (attributes == slidePageNoRebase) {
            continue;
        }
        if (attributes == 0) {
            applyChain(page, start);
            continue;
        }
        auto extraIndex = static_cast<std::uint32_t>(
            start & slidePageIndexMask);
        while (true) {
            const auto extra = readU16(
                mapping.slideInfo,
                info.pageExtrasOffset +
                    static_cast<std::size_t>(extraIndex) *
                        sizeof(std::uint16_t));
            applyChain(page, extra);
            ++extraIndex;
            if ((extra & slidePageEnd) != 0) {
                break;
            }
        }
    }
}

std::array<std::uint8_t, 16> readUuid(std::span<const std::uint8_t> bytes,
                                      std::size_t offset) {
    if (offset > bytes.size() || 16 > bytes.size() - offset) {
        throw std::runtime_error("dyld shared cache UUID is truncated");
    }
    std::array<std::uint8_t, 16> result{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), result.size(),
                result.begin());
    return result;
}

std::size_t checkedTableSize(std::uint32_t count, std::size_t recordSize,
                             std::uint32_t maximumCount,
                             std::string_view description) {
    if (count > maximumCount) {
        throw std::runtime_error("dyld shared cache " + std::string(description) +
                                 " count is unreasonable");
    }
    if (count != 0 && recordSize > std::numeric_limits<std::size_t>::max() / count) {
        throw std::runtime_error("dyld shared cache " + std::string(description) +
                                 " table size overflows");
    }
    return static_cast<std::size_t>(count) * recordSize;
}

std::pair<std::string, SharedCacheArchitecture>
parseMagic(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < magicSize) {
        throw std::runtime_error("dyld shared cache magic is truncated");
    }
    std::string magic(reinterpret_cast<const char *>(bytes.data()), magicSize);
    while (!magic.empty() && (magic.back() == '\0' || magic.back() == ' ')) {
        magic.pop_back();
    }
    if (!magic.starts_with("dyld_v")) {
        throw std::runtime_error("unrecognized dyld shared cache magic");
    }
    if (magic.ends_with("x86_64h")) {
        return {magic, SharedCacheArchitecture::X86_64h};
    }
    if (magic.ends_with("x86_64")) {
        return {magic, SharedCacheArchitecture::X86_64};
    }
    throw std::runtime_error("dyld shared cache is not x86_64 or x86_64h");
}

guest::Permission parsePermissions(std::uint32_t raw, std::string_view description) {
    if ((raw & ~supportedProtectionMask) != 0) {
        throw std::runtime_error("dyld shared cache " + std::string(description) +
                                 " contains unsupported protection bits");
    }
    return static_cast<guest::Permission>(raw);
}

bool contains(guest::GuestAddress base, std::uint64_t size, guest::GuestAddress address,
              std::size_t accessSize) {
    if (address.value < base.value || accessSize > size) {
        return false;
    }
    return address.value - base.value <= size - accessSize;
}

struct ParsedFile {
    std::string magic;
    SharedCacheArchitecture architecture{SharedCacheArchitecture::X86_64};
    std::array<std::uint8_t, 16> uuid{};
    std::uint32_t mappingOffset{};
    guest::GuestAddress sharedRegionStart{};
    std::uint64_t sharedRegionSize{};
    std::uint64_t maximumSlide{};
    guest::GuestAddress dyldMachHeader{};
    guest::GuestAddress dyldEntryPoint{};
    std::uint32_t platform{};
    std::uint32_t osVersion{};
    std::uint32_t imageOffset{};
    std::uint32_t imageCount{};
    std::uint64_t imagesTextOffset{};
    std::uint64_t imagesTextCount{};
    std::uint32_t subcacheOffset{};
    std::uint32_t subcacheCount{};
    bool hasModernSubcaches{};
    std::uint64_t dynamicDataOffset{};
    std::uint64_t dynamicDataSize{};
    std::vector<SharedCacheMapping> mappings;
};

ParsedFile parseFile(const std::filesystem::path &path, std::string_view suffix) {
    const FileReader reader(path);
    const auto prefix = reader.read(0, minimumHeaderSize, "header prefix");
    const auto mappingOffset = readU32(prefix, mappingOffsetField);
    if (mappingOffset < minimumHeaderSize || mappingOffset > currentHeaderSize ||
        mappingOffset > reader.size()) {
        throw std::runtime_error("dyld shared cache header size is invalid");
    }
    const auto header = reader.read(0, mappingOffset, "header");
    auto [magic, architecture] = parseMagic(header);

    ParsedFile result{
        .magic = std::move(magic),
        .architecture = architecture,
        .uuid = readUuid(header, uuidField),
        .mappingOffset = mappingOffset,
    };
    if (mappingOffset > dyldEntryPointField + sizeof(std::uint64_t) - 1U) {
        result.dyldMachHeader = guest::GuestAddress{readU64(header, dyldMachHeaderField)};
        result.dyldEntryPoint = guest::GuestAddress{readU64(header, dyldEntryPointField)};
    }
    if (mappingOffset > imagesTextCountField + sizeof(std::uint64_t) - 1U) {
        result.imagesTextOffset = readU64(header, imagesTextOffsetField);
        result.imagesTextCount = readU64(header, imagesTextCountField);
        if ((result.imagesTextOffset == 0) != (result.imagesTextCount == 0)) {
            throw std::runtime_error(
                "dyld shared cache image-text table is incomplete");
        }
        if (result.imagesTextCount > maximumImageCount ||
            result.imagesTextCount >
                std::numeric_limits<std::size_t>::max() /
                    imageTextRecordSize) {
            throw std::runtime_error(
                "dyld shared cache image-text count is unreasonable");
        }
        const auto tableSize = static_cast<std::size_t>(
            result.imagesTextCount * imageTextRecordSize);
        if (result.imagesTextOffset > reader.size() ||
            tableSize > reader.size() - result.imagesTextOffset) {
            throw std::runtime_error(
                "dyld shared cache image-text table exceeds source file");
        }
    }
    if (mappingOffset > platformField + sizeof(std::uint32_t) - 1U) {
        result.platform = readU32(header, platformField);
    }
    if (mappingOffset > maximumSlideField + sizeof(std::uint64_t) - 1U) {
        result.sharedRegionStart = guest::GuestAddress{readU64(header, regionStartField)};
        result.sharedRegionSize = readU64(header, regionSizeField);
        result.maximumSlide = readU64(header, maximumSlideField);
    }
    if (mappingOffset > osVersionField + sizeof(std::uint32_t) - 1U) {
        result.osVersion = readU32(header, osVersionField);
    }
    if (mappingOffset > subcacheCountField + sizeof(std::uint32_t) - 1U) {
        result.subcacheOffset = readU32(header, subcacheOffsetField);
        result.subcacheCount = readU32(header, subcacheCountField);
        result.hasModernSubcaches = mappingOffset > cacheSubtypeField;
    }
    if (mappingOffset > imageCountField + sizeof(std::uint32_t) - 1U) {
        result.imageCount = readU32(header, imageCountField);
        result.imageOffset = readU32(header, imageOffsetField);
        constexpr std::size_t imageRecordSize = 32;
        const auto imageTableSize = checkedTableSize(
            result.imageCount, imageRecordSize, 1'000'000, "image");
        if (result.imageOffset > reader.size() ||
            imageTableSize > reader.size() - result.imageOffset) {
            throw std::runtime_error("dyld shared cache image table exceeds source file");
        }
    }
    if (mappingOffset > dynamicDataSizeField + sizeof(std::uint64_t) - 1U) {
        result.dynamicDataOffset = readU64(header, dynamicDataOffsetField);
        result.dynamicDataSize = readU64(header, dynamicDataSizeField);
        if ((result.dynamicDataOffset == 0) != (result.dynamicDataSize == 0)) {
            throw std::runtime_error(
                "dyld shared cache dynamic-data reservation is incomplete");
        }
        if (result.dynamicDataSize != 0 &&
            (result.dynamicDataSize < 0x4000 ||
             (result.dynamicDataOffset % guest::guestPageSize) != 0 ||
             (result.dynamicDataSize % guest::guestPageSize) != 0)) {
            throw std::runtime_error(
                "dyld shared cache dynamic-data reservation is invalid");
        }
    }

    const auto mappingCount = readU32(header, mappingCountField);
    if (mappingCount == 0) {
        throw std::runtime_error("dyld shared cache has no mappings");
    }
    const auto tableSize = checkedTableSize(mappingCount, mappingRecordSize,
                                            maximumMappingCount, "mapping");
    const auto table = reader.read(mappingOffset, tableSize, "mapping table");
    result.mappings.reserve(mappingCount);
    for (std::uint32_t index = 0; index < mappingCount; ++index) {
        const auto offset = static_cast<std::size_t>(index) * mappingRecordSize;
        const auto address = readU64(table, offset);
        const auto size = readU64(table, offset + 8);
        const auto fileOffset = readU64(table, offset + 16);
        const auto maximumRaw = readU32(table, offset + 24);
        const auto initialRaw = readU32(table, offset + 28);
        if (size == 0 || (address % guest::guestPageSize) != 0 ||
            (size % guest::guestPageSize) != 0 ||
            (fileOffset % guest::guestPageSize) != 0 ||
            address > std::numeric_limits<std::uint64_t>::max() - size) {
            throw std::runtime_error("dyld shared cache mapping range is invalid");
        }
        if (fileOffset > reader.size() || size > reader.size() - fileOffset) {
            throw std::runtime_error("dyld shared cache mapping exceeds source file");
        }
        const auto maximum = parsePermissions(maximumRaw, "maximum mapping");
        const auto initial = parsePermissions(initialRaw, "initial mapping");
        if ((initialRaw & ~maximumRaw) != 0) {
            throw std::runtime_error(
                "dyld shared cache initial permissions exceed maximum permissions");
        }
        result.mappings.push_back(SharedCacheMapping{
            .address = guest::GuestAddress{address},
            .size = size,
            .fileOffset = fileOffset,
            .maximumPermissions = maximum,
            .initialPermissions = initial,
            .sourcePath = path,
            .sourceSuffix = std::string(suffix),
        });
    }

    if (mappingOffset > mappingWithSlideCountField + sizeof(std::uint32_t) - 1U) {
        const auto slideOffset = readU32(header, mappingWithSlideOffsetField);
        const auto slideCount = readU32(header, mappingWithSlideCountField);
        if ((slideOffset == 0) != (slideCount == 0)) {
            throw std::runtime_error("dyld shared cache mapping-with-slide table is incomplete");
        }
        if (slideCount != 0) {
            if (slideCount != mappingCount) {
                throw std::runtime_error(
                    "dyld shared cache mapping-with-slide count differs");
            }
            const auto slideTableSize = checkedTableSize(
                slideCount, mappingWithSlideRecordSize, maximumMappingCount,
                "mapping-with-slide");
            const auto slideTable = reader.read(slideOffset, slideTableSize,
                                                "mapping-with-slide table");
            for (std::uint32_t index = 0; index < slideCount; ++index) {
                const auto offset = static_cast<std::size_t>(index) *
                                    mappingWithSlideRecordSize;
                auto &mapping = result.mappings[index];
                if (readU64(slideTable, offset) != mapping.address.value ||
                    readU64(slideTable, offset + 8) != mapping.size ||
                    readU64(slideTable, offset + 16) != mapping.fileOffset ||
                    readU32(slideTable, offset + 48) !=
                        static_cast<std::uint32_t>(mapping.maximumPermissions) ||
                    readU32(slideTable, offset + 52) !=
                        static_cast<std::uint32_t>(mapping.initialPermissions)) {
                    throw std::runtime_error(
                        "dyld shared cache mapping-with-slide metadata disagrees");
                }
                mapping.slideInfoFileOffset = readU64(slideTable, offset + 24);
                mapping.slideInfoFileSize = readU64(slideTable, offset + 32);
                mapping.flags = readU64(slideTable, offset + 40);
                if (mapping.slideInfoFileOffset > reader.size() ||
                    mapping.slideInfoFileSize >
                        reader.size() - mapping.slideInfoFileOffset) {
                    throw std::runtime_error(
                        "dyld shared cache slide metadata exceeds source file");
                }
                if ((mapping.slideInfoFileOffset == 0) !=
                    (mapping.slideInfoFileSize == 0)) {
                    throw std::runtime_error(
                        "dyld shared cache slide metadata range is incomplete");
                }
                if (mapping.slideInfoFileSize != 0) {
                    mapping.slideInfo = reader.read(
                        mapping.slideInfoFileOffset,
                        static_cast<std::size_t>(mapping.slideInfoFileSize),
                        "slide metadata");
                    static_cast<void>(parseSlideInfo2(mapping.slideInfo, mapping));
                }
            }
        }
    }

    std::ranges::sort(result.mappings, [](const auto &lhs, const auto &rhs) {
        return lhs.address.value < rhs.address.value;
    });
    for (std::size_t index = 1; index < result.mappings.size(); ++index) {
        const auto previousEnd = result.mappings[index - 1].address.value +
                                 result.mappings[index - 1].size;
        if (previousEnd > result.mappings[index].address.value) {
            throw std::runtime_error("dyld shared cache mappings overlap");
        }
    }
    return result;
}

std::string parseSuffix(std::span<const std::uint8_t> bytes) {
    const auto terminator = std::ranges::find(bytes, std::uint8_t{0});
    if (terminator == bytes.end() || terminator == bytes.begin()) {
        throw std::runtime_error("dyld shared cache subcache suffix is not terminated");
    }
    std::string result(bytes.begin(), terminator);
    if (result.front() != '.' || result.find('/') != std::string::npos ||
        result.find("..") != std::string::npos ||
        !std::ranges::all_of(result, [](unsigned char character) {
            return std::isalnum(character) != 0 || character == '.' || character == '_' ||
                   character == '-';
        })) {
        throw std::runtime_error("dyld shared cache subcache suffix is unsafe");
    }
    return result;
}

std::optional<std::pair<const SharedCacheMapping *, std::uint64_t>>
locate(const std::vector<SharedCacheMapping> &mappings, guest::GuestAddress address,
       std::size_t size) {
    for (const auto &mapping : mappings) {
        if (contains(mapping.address, mapping.size, address, size)) {
            return std::pair{&mapping,
                             mapping.fileOffset + address.value - mapping.address.value};
        }
    }
    return std::nullopt;
}

std::vector<SharedCacheImage>
parseImages(const FileReader &reader, const ParsedFile &main,
            const std::vector<SharedCacheMapping> &mappings) {
    if (main.imagesTextCount == 0) {
        return {};
    }
    if (main.imageCount != 0 && main.imageCount != main.imagesTextCount) {
        throw std::runtime_error(
            "dyld shared cache image tables have different counts");
    }
    const auto count = static_cast<std::size_t>(main.imagesTextCount);
    const auto table = reader.read(main.imagesTextOffset,
                                   count * imageTextRecordSize,
                                   "image-text table");
    const auto legacyTable = main.imageCount == 0
                                 ? std::vector<std::uint8_t>{}
                                 : reader.read(main.imageOffset,
                                               count * imageTextRecordSize,
                                               "legacy image table");
    std::vector<SharedCacheImage> images;
    images.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto offset = index * imageTextRecordSize;
        const auto address = readU64(table, offset + 16);
        const auto textSize = readU32(table, offset + 24);
        const auto pathOffset = readU32(table, offset + 28);
        if (!legacyTable.empty() &&
            (readU64(legacyTable, offset) != address ||
             readU32(legacyTable, offset + 24) != pathOffset)) {
            throw std::runtime_error(
                "dyld shared cache image tables disagree");
        }
        if (textSize == 0 ||
            address > std::numeric_limits<std::uint64_t>::max() - textSize) {
            throw std::runtime_error(
                "dyld shared cache image text range is invalid");
        }
        const auto location = locate(mappings, guest::GuestAddress{address},
                                     textSize);
        if (!location ||
            (static_cast<std::uint8_t>(
                 location->first->initialPermissions) &
             static_cast<std::uint8_t>(guest::Permission::Execute)) == 0) {
            throw std::runtime_error(
                "dyld shared cache image text is not in one executable mapping");
        }
        images.push_back(SharedCacheImage{
            .index = index,
            .loadAddress = guest::GuestAddress{address},
            .textSize = textSize,
            .uuid = readUuid(table, offset),
            .path = reader.readCString(pathOffset, "image path"),
            .sourceSuffix = location->first->sourceSuffix,
        });
    }
    std::ranges::sort(images, [](const auto &lhs, const auto &rhs) {
        return lhs.loadAddress.value < rhs.loadAddress.value;
    });
    for (std::size_t index = 1; index < images.size(); ++index) {
        const auto previousEnd = images[index - 1].loadAddress.value +
                                 images[index - 1].textSize;
        if (previousEnd > images[index].loadAddress.value) {
            throw std::runtime_error(
                "dyld shared cache image text ranges overlap");
        }
    }
    return images;
}

} // namespace

GuestSharedCache GuestSharedCache::open(const std::filesystem::path &path) {
    const auto main = parseFile(path, {});
    if (main.mappingOffset <= subcacheCountField || main.sharedRegionSize == 0 ||
        main.sharedRegionStart.value == 0) {
        throw std::runtime_error(
            "dyld shared cache lacks required shared-region metadata");
    }
    if (main.sharedRegionStart.value >
        std::numeric_limits<std::uint64_t>::max() - main.sharedRegionSize) {
        throw std::runtime_error("dyld shared cache shared region overflows");
    }

    GuestSharedCache result;
    result.architecture_ = main.architecture;
    result.magic_ = main.magic;
    result.uuid_ = main.uuid;
    result.regionStart_ = main.sharedRegionStart;
    result.regionSize_ = main.sharedRegionSize;
    result.maximumSlide_ = main.maximumSlide;
    result.dyldMachHeader_ = main.dyldMachHeader;
    result.dyldEntryPoint_ = main.dyldEntryPoint;
    result.platform_ = main.platform;
    result.osVersion_ = main.osVersion;
    result.imageCount_ = main.imageCount;
    if (main.dynamicDataSize != 0) {
        if (main.dynamicDataOffset > main.sharedRegionSize ||
            main.dynamicDataSize > main.sharedRegionSize - main.dynamicDataOffset) {
            throw std::runtime_error(
                "dyld shared cache dynamic data lies outside shared region");
        }
        result.dynamicDataAddress_ = guest::GuestAddress{
            main.sharedRegionStart.value + main.dynamicDataOffset};
        result.dynamicDataSize_ = main.dynamicDataSize;
    }
    result.files_.push_back(SharedCacheFile{
        .path = path,
        .uuid = main.uuid,
        .mappings = main.mappings,
    });

    const FileReader mainReader(path);
    const auto subcacheRecordSize = main.hasModernSubcaches ? modernSubcacheRecordSize
                                                            : legacySubcacheRecordSize;
    const auto subcacheTableSize = checkedTableSize(
        main.subcacheCount, subcacheRecordSize, maximumSubcacheCount, "subcache");
    const auto subcacheTable =
        mainReader.read(main.subcacheOffset, subcacheTableSize, "subcache table");
    for (std::uint32_t index = 0; index < main.subcacheCount; ++index) {
        const auto offset = static_cast<std::size_t>(index) * subcacheRecordSize;
        const auto expectedUuid = readUuid(subcacheTable, offset);
        const auto vmOffset = readU64(subcacheTable, offset + 16);
        const auto suffix = main.hasModernSubcaches
                                ? parseSuffix(std::span<const std::uint8_t>(subcacheTable)
                                                  .subspan(offset + 24, 32))
                                : "." + std::to_string(index + 1U);
        if (std::ranges::any_of(result.files_, [&suffix](const auto &file) {
                return file.suffix == suffix;
            })) {
            throw std::runtime_error("dyld shared cache repeats a subcache suffix");
        }
        auto subcachePath = path;
        subcachePath += suffix;
        const auto subcache = parseFile(subcachePath, suffix);
        if (subcache.architecture != main.architecture || subcache.magic != main.magic) {
            throw std::runtime_error("dyld subcache architecture differs from main cache");
        }
        if (subcache.uuid != expectedUuid) {
            throw std::runtime_error("dyld subcache UUID differs from main cache metadata");
        }
        if (subcache.subcacheCount != 0) {
            throw std::runtime_error("nested dyld subcaches are unsupported");
        }
        if (main.sharedRegionStart.value >
                std::numeric_limits<std::uint64_t>::max() - vmOffset ||
            subcache.sharedRegionStart.value != main.sharedRegionStart.value + vmOffset) {
            throw std::runtime_error("dyld subcache VM offset disagrees with its mappings");
        }
        result.files_.push_back(SharedCacheFile{
            .path = subcachePath,
            .suffix = suffix,
            .uuid = subcache.uuid,
            .cacheVmOffset = vmOffset,
            .mappings = subcache.mappings,
        });
    }

    for (const auto &file : result.files_) {
        result.mappings_.insert(result.mappings_.end(), file.mappings.begin(),
                                file.mappings.end());
    }
    std::ranges::sort(result.mappings_, [](const auto &lhs, const auto &rhs) {
        return lhs.address.value < rhs.address.value;
    });
    const auto regionEnd = result.regionStart_.value + result.regionSize_;
    for (std::size_t index = 0; index < result.mappings_.size(); ++index) {
        const auto &mapping = result.mappings_[index];
        const auto mappingEnd = mapping.address.value + mapping.size;
        if (mapping.address.value < result.regionStart_.value || mappingEnd > regionEnd) {
            throw std::runtime_error("dyld shared cache mapping lies outside shared region");
        }
        if (index != 0) {
            const auto previousEnd = result.mappings_[index - 1].address.value +
                                     result.mappings_[index - 1].size;
            if (previousEnd > mapping.address.value) {
                throw std::runtime_error("dyld shared cache files overlap in guest memory");
            }
        }
    }
    if (result.dynamicDataSize_ != 0) {
        for (const auto &mapping : result.mappings_) {
            const auto dynamicEnd = result.dynamicDataAddress_.value +
                                    result.dynamicDataSize_;
            const auto mappingEnd = mapping.address.value + mapping.size;
            if (result.dynamicDataAddress_.value < mappingEnd &&
                mapping.address.value < dynamicEnd) {
                throw std::runtime_error(
                    "dyld shared cache dynamic data overlaps a file mapping");
            }
        }
    }

    result.images_ = parseImages(mainReader, main, result.mappings_);
    if (!result.images_.empty()) {
        result.imageCount_ = static_cast<std::uint32_t>(result.images_.size());
    }

    if (result.dyldMachHeader_.value != 0 || result.dyldEntryPoint_.value != 0) {
        const auto headerLocation = locate(result.mappings_, result.dyldMachHeader_, 8);
        const auto entryLocation = locate(result.mappings_, result.dyldEntryPoint_, 1);
        if (!headerLocation || !entryLocation ||
            (static_cast<std::uint8_t>(entryLocation->first->initialPermissions) &
             static_cast<std::uint8_t>(guest::Permission::Execute)) == 0) {
            throw std::runtime_error("dyld-in-cache addresses are not mapped executable data");
        }
        const FileReader dyldFile(headerLocation->first->sourcePath);
        const auto machHeader = dyldFile.read(headerLocation->second, 8,
                                              "dyld-in-cache Mach-O header");
        if (readU32(machHeader, 0) != machHeader64Magic ||
            readU32(machHeader, 4) != x86_64CpuType) {
            throw std::runtime_error("dyld-in-cache Mach-O header is not x86_64");
        }
    }
    return result;
}

void GuestSharedCache::mapInto(guest::AddressSpace &addressSpace) const {
    for (std::size_t index = 0; index < mappings_.size(); ++index) {
        const auto &mapping = mappings_[index];
        addressSpace.mapFileSegment(
            guest::GuestAddress{mapping.address.value + slide()},
            static_cast<std::size_t>(mapping.size), mapping.initialPermissions,
            mapping.maximumPermissions, mapping.sourcePath, mapping.fileOffset,
            "dyld-cache" + mapping.sourceSuffix + ":mapping-" +
                std::to_string(index));
    }
    for (const auto &mapping : mappings_) {
        if (!mapping.slideInfo.empty()) {
            auto bytes = addressSpace.mutablePrivateFileMappingBytes(
                guest::GuestAddress{mapping.address.value + slide()});
            applySlideInfo2(bytes, mapping, slide());
        }
    }
    if (dynamicDataSize_ == 0) {
        return;
    }

    // Apple constructs this page outside the cache files before asking XNU to
    // install it. Keep the guest structure explicit and independent of the
    // host ABI. Zero function-variant masks select baseline cache functions.
    std::vector<std::uint8_t> dynamicData(static_cast<std::size_t>(dynamicDataSize_));
    constexpr std::string_view dynamicMagic = "dyld_data    v3";
    std::copy(dynamicMagic.begin(), dynamicMagic.end(), dynamicData.begin());

    struct stat information {};
    if (::stat(files_.front().path.c_str(), &information) != 0) {
        throw std::runtime_error("cannot inspect guest shared-cache identity: " +
                                 std::string(std::strerror(errno)));
    }
    // Guest FileIdTuple: fsid_t (two 32-bit words), then fsobj_id_t (8 bytes).
    writeU32(dynamicData, 16, static_cast<std::uint32_t>(information.st_dev));
    writeU32(dynamicData, 20, 0);
    writeU64(dynamicData, 24, static_cast<std::uint64_t>(information.st_ino));
    constexpr std::uint32_t dynamicRegionStructureSize = 80;
    writeU32(dynamicData, 32, 0); // no OS cryptex prefix
    writeU32(dynamicData, 36, dynamicRegionStructureSize);
    const auto cachePath = std::filesystem::canonical(files_.front().path).string();
    if (cachePath.size() + 1U > dynamicData.size() - dynamicRegionStructureSize) {
        throw std::runtime_error("guest shared-cache path exceeds dynamic-data page");
    }
    std::copy(cachePath.begin(), cachePath.end(),
              dynamicData.begin() + dynamicRegionStructureSize);
    addressSpace.mapSegment(dynamicDataAddress_, static_cast<std::size_t>(dynamicDataSize_),
                            guest::Permission::Read, dynamicData,
                            "dyld-cache:dynamic-data");
}

std::string_view GuestSharedCache::architectureName() const noexcept {
    return architecture_ == SharedCacheArchitecture::X86_64h ? "x86_64h" : "x86_64";
}

const SharedCacheImage *GuestSharedCache::imageForAddress(
    guest::GuestAddress address) const noexcept {
    const auto candidate = std::ranges::upper_bound(
        images_, address.value, {}, [](const SharedCacheImage &image) {
            return image.loadAddress.value;
        });
    if (candidate == images_.begin()) {
        return nullptr;
    }
    const auto &image = *std::prev(candidate);
    if (address.value - image.loadAddress.value >= image.textSize) {
        return nullptr;
    }
    return &image;
}

std::string formatSharedCacheUuid(const std::array<std::uint8_t, 16> &uuid) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < uuid.size(); ++index) {
        if (index == 4 || index == 6 || index == 8 || index == 10) {
            output << '-';
        }
        output << std::setw(2) << static_cast<unsigned>(uuid[index]);
    }
    return output.str();
}

} // namespace rosa::darwin
