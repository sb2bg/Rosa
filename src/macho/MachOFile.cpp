#include "macho/MachOFile.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <limits>
#include <stdexcept>

namespace rosa::macho {
namespace {

constexpr std::uint32_t machMagic64 = 0xFEEDFACFU;
constexpr std::uint32_t cpuTypeX86_64 = 0x01000007U;
constexpr std::uint32_t vmProtectionMask = 0x7U;
constexpr std::size_t headerSize64 = 32;
constexpr std::size_t segmentCommandSize64 = 72;
constexpr std::size_t sectionSize64 = 80;

void requireRange(std::span<const std::uint8_t> bytes, std::size_t offset, std::size_t size,
                  const char *description) {
    if (offset > bytes.size() || size > bytes.size() - offset) {
        throw std::runtime_error(std::string("malformed Mach-O: out-of-range ") + description);
    }
}

std::uint32_t readU32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    requireRange(bytes, offset, 4, "32-bit field");
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(bytes[offset + index]) << (index * 8U);
    }
    return value;
}

std::uint64_t readU64(std::span<const std::uint8_t> bytes, std::size_t offset) {
    requireRange(bytes, offset, 8, "64-bit field");
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(bytes[offset + index]) << (index * 8U);
    }
    return value;
}

std::uint32_t readBigU32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    requireRange(bytes, offset, 4, "fat 32-bit field");
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value = (value << 8U) | bytes[offset + index];
    }
    return value;
}

std::uint64_t readBigU64(std::span<const std::uint8_t> bytes, std::size_t offset) {
    requireRange(bytes, offset, 8, "fat 64-bit field");
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value = (value << 8U) | bytes[offset + index];
    }
    return value;
}

std::string readFixedString(std::span<const std::uint8_t> bytes, std::size_t offset,
                            std::size_t size) {
    requireRange(bytes, offset, size, "fixed string");
    const auto begin = bytes.begin() + static_cast<std::ptrdiff_t>(offset);
    const auto end = std::find(begin, begin + static_cast<std::ptrdiff_t>(size), 0);
    return std::string(begin, end);
}

bool addOverflows(std::uint64_t lhs, std::uint64_t rhs) {
    return lhs > std::numeric_limits<std::uint64_t>::max() - rhs;
}

std::vector<std::uint8_t> selectX86Slice(std::vector<std::uint8_t> bytes) {
    requireRange(bytes, 0, 4, "magic");
    const std::span<const std::uint8_t> view(bytes);
    if (readU32(view, 0) == machMagic64) {
        return bytes;
    }

    const bool fat32 =
        bytes[0] == 0xCAU && bytes[1] == 0xFEU && bytes[2] == 0xBAU && bytes[3] == 0xBEU;
    const bool fat64 =
        bytes[0] == 0xCAU && bytes[1] == 0xFEU && bytes[2] == 0xBAU && bytes[3] == 0xBFU;
    if (!fat32 && !fat64) {
        throw std::runtime_error(
            "unsupported Mach-O magic (expected MH_MAGIC_64 or a universal binary)");
    }

    requireRange(view, 0, 8, "fat header");
    const auto architectureCount = readBigU32(view, 4);
    const std::size_t architectureSize = fat64 ? 32 : 20;
    if (architectureCount > (view.size() - 8) / architectureSize) {
        throw std::runtime_error("malformed universal Mach-O architecture table");
    }
    for (std::uint32_t index = 0; index < architectureCount; ++index) {
        const auto offset = 8 + (static_cast<std::size_t>(index) * architectureSize);
        if (readBigU32(view, offset) != cpuTypeX86_64) {
            continue;
        }
        const auto sliceOffset =
            fat64 ? readBigU64(view, offset + 8) : readBigU32(view, offset + 8);
        const auto sliceSize =
            fat64 ? readBigU64(view, offset + 16) : readBigU32(view, offset + 12);
        if (sliceOffset > view.size() || sliceSize > view.size() - sliceOffset) {
            throw std::runtime_error("malformed universal Mach-O x86_64 slice range");
        }
        const auto begin = view.begin() + static_cast<std::ptrdiff_t>(sliceOffset);
        return std::vector<std::uint8_t>(begin, begin + static_cast<std::ptrdiff_t>(sliceSize));
    }
    throw std::runtime_error("universal Mach-O has no x86_64 slice");
}

} // namespace

MachOFile MachOFile::open(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open Mach-O file: " + path.string());
    }
    std::vector<std::uint8_t> bytes(std::istreambuf_iterator<char>(input), {});
    if (input.bad()) {
        throw std::runtime_error("failed while reading Mach-O file: " + path.string());
    }
    return parse(std::move(bytes));
}

MachOFile MachOFile::parse(std::vector<std::uint8_t> bytes) {
    bytes = selectX86Slice(std::move(bytes));
    requireRange(bytes, 0, headerSize64, "64-bit header");
    if (readU32(bytes, 0) != machMagic64) {
        throw std::runtime_error("unsupported Mach-O magic (expected little-endian MH_MAGIC_64)");
    }

    MachOFile file;
    file.bytes_ = std::move(bytes);
    const std::span<const std::uint8_t> view(file.bytes_);
    file.cpuType_ = readU32(view, 4);
    file.fileType_ = readU32(view, 12);
    if (file.cpuType_ != cpuTypeX86_64) {
        throw std::runtime_error("Mach-O is not x86_64");
    }
    if (file.fileType_ != mhExecute && file.fileType_ != mhDylinker) {
        throw std::runtime_error("Mach-O is neither an executable nor a dynamic linker");
    }

    const auto commandCount = readU32(view, 16);
    const auto commandBytes = readU32(view, 20);
    requireRange(view, headerSize64, commandBytes, "load-command region");
    const auto commandEnd = headerSize64 + commandBytes;
    std::size_t cursor = headerSize64;
    for (std::uint32_t index = 0; index < commandCount; ++index) {
        requireRange(view, cursor, 8, "load-command header");
        const auto command = readU32(view, cursor);
        const auto commandSize = readU32(view, cursor + 4);
        if (commandSize < 8 || commandSize > commandEnd - cursor) {
            throw std::runtime_error("malformed Mach-O: invalid load-command size");
        }
        file.loadCommands_.push_back(LoadCommand{command, commandSize, cursor});

        if (command == lcSegment64) {
            if (commandSize < segmentCommandSize64) {
                throw std::runtime_error("malformed Mach-O: short LC_SEGMENT_64");
            }
            const auto sectionCount = readU32(view, cursor + 64);
            if (sectionCount > (commandSize - segmentCommandSize64) / sectionSize64) {
                throw std::runtime_error("malformed Mach-O: LC_SEGMENT_64 sections exceed command");
            }
            Segment segment{
                .name = readFixedString(view, cursor + 8, 16),
                .virtualAddress = guest::GuestAddress{readU64(view, cursor + 24)},
                .virtualSize = readU64(view, cursor + 32),
                .fileOffset = readU64(view, cursor + 40),
                .fileSize = readU64(view, cursor + 48),
                .maximumProtection = readU32(view, cursor + 56),
                .initialProtection = readU32(view, cursor + 60),
            };
            if (segment.fileSize > segment.virtualSize ||
                addOverflows(segment.virtualAddress.value, segment.virtualSize) ||
                addOverflows(segment.fileOffset, segment.fileSize) ||
                segment.fileOffset + segment.fileSize > view.size()) {
                throw std::runtime_error("malformed Mach-O: invalid segment range");
            }
            if ((segment.maximumProtection & ~vmProtectionMask) != 0 ||
                (segment.initialProtection & ~vmProtectionMask) != 0) {
                throw std::runtime_error(
                    "malformed Mach-O: segment contains unsupported protection bits");
            }
            if ((segment.initialProtection & ~segment.maximumProtection) != 0) {
                throw std::runtime_error(
                    "malformed Mach-O: segment initial protection exceeds maximum protection");
            }
            file.segments_.push_back(std::move(segment));
        } else if (command == lcMain) {
            if (commandSize < 24) {
                throw std::runtime_error("malformed Mach-O: short LC_MAIN");
            }
            file.mainEntryFileOffset_ = readU64(view, cursor + 8);
        } else if (command == lcUnixThread) {
            // x86_THREAD_STATE64: flavor/count followed by 16 GPRs, then RIP.
            constexpr std::size_t ripOffset = 16 + (16 * sizeof(std::uint64_t));
            constexpr std::uint32_t x86ThreadState64 = 4;
            constexpr std::uint32_t x86ThreadState64Count = 42;
            if (commandSize >= ripOffset + sizeof(std::uint64_t) &&
                readU32(view, cursor + 8) == x86ThreadState64 &&
                readU32(view, cursor + 12) == x86ThreadState64Count) {
                file.unixThreadEntry_ = guest::GuestAddress{readU64(view, cursor + ripOffset)};
            }
        }
        cursor += commandSize;
    }
    if (cursor != commandEnd) {
        throw std::runtime_error("malformed Mach-O: load-command count/size mismatch");
    }
    return file;
}

guest::GuestAddress MachOFile::entryPoint() const {
    if (mainEntryFileOffset_) {
        for (const auto &segment : segments_) {
            if (*mainEntryFileOffset_ >= segment.fileOffset &&
                *mainEntryFileOffset_ < segment.fileOffset + segment.fileSize) {
                return guest::GuestAddress{segment.virtualAddress.value +
                                           (*mainEntryFileOffset_ - segment.fileOffset)};
            }
        }
        throw std::runtime_error("LC_MAIN entry offset is not inside a file-backed segment");
    }
    if (unixThreadEntry_) {
        return *unixThreadEntry_;
    }
    throw std::runtime_error("Mach-O has neither LC_MAIN nor a usable LC_UNIXTHREAD entry");
}

std::string loadCommandName(std::uint32_t command) {
    switch (command) {
    case lcSegment64:
        return "LC_SEGMENT_64";
    case lcUnixThread:
        return "LC_UNIXTHREAD";
    case lcMain:
        return "LC_MAIN";
    case 0xCU:
        return "LC_LOAD_DYLIB";
    case 0xEU:
        return "LC_LOAD_DYLINKER";
    case 0x1BU:
        return "LC_UUID";
    case 0x32U:
        return "LC_BUILD_VERSION";
    case 0x8000001CU:
        return "LC_RPATH";
    default:
        return "LC_0x" + std::to_string(command);
    }
}

} // namespace rosa::macho
