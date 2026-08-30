#include "dbt/BlockCache.h"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace rosa::dbt {
namespace {

constexpr std::array<std::uint8_t, 8> persistentMagic{
    'R', 'O', 'S', 'A', 'C', '0', '1', 0};
constexpr std::uint32_t persistentVersion = 2;
constexpr std::size_t maximumPersistentFileSize = 512U * 1024U * 1024U;
constexpr std::size_t maximumPersistentRecords = 1U << 20U;
constexpr std::size_t maximumPersistentSourceSize = 4096;
constexpr std::size_t maximumPersistentProgramSize = 1U << 20U;
constexpr std::size_t maximumPersistentRelocations = 1U << 16U;

void appendU32(std::vector<std::uint8_t> &bytes, std::uint32_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        bytes.push_back(static_cast<std::uint8_t>(value >> (index * 8U)));
    }
}

void appendU64(std::vector<std::uint8_t> &bytes, std::uint64_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        bytes.push_back(static_cast<std::uint8_t>(value >> (index * 8U)));
    }
}

class PersistentReader {
  public:
    explicit PersistentReader(std::span<const std::uint8_t> bytes)
        : bytes_(bytes) {}

    [[nodiscard]] std::uint32_t readU32() {
        const auto bytes = readBytes(sizeof(std::uint32_t));
        std::uint32_t value{};
        for (std::size_t index = 0; index < sizeof(value); ++index) {
            value |= static_cast<std::uint32_t>(bytes[index]) <<
                     (index * 8U);
        }
        return value;
    }

    [[nodiscard]] std::uint64_t readU64() {
        const auto bytes = readBytes(sizeof(std::uint64_t));
        std::uint64_t value{};
        for (std::size_t index = 0; index < sizeof(value); ++index) {
            value |= static_cast<std::uint64_t>(bytes[index]) <<
                     (index * 8U);
        }
        return value;
    }

    [[nodiscard]] std::span<const std::uint8_t> readBytes(std::size_t size) {
        if (size > bytes_.size() - offset_) {
            throw std::runtime_error("persistent translation cache is truncated");
        }
        const auto result = bytes_.subspan(offset_, size);
        offset_ += size;
        return result;
    }

    [[nodiscard]] bool finished() const noexcept {
        return offset_ == bytes_.size();
    }

  private:
    std::span<const std::uint8_t> bytes_;
    std::size_t offset_{};
};

std::uint32_t readArmWord(std::span<const std::uint8_t> bytes,
                          std::size_t offset) {
    std::uint32_t word{};
    for (std::size_t index = 0; index < sizeof(word); ++index) {
        word |= static_cast<std::uint32_t>(bytes[offset + index]) <<
                (index * 8U);
    }
    return word;
}

void writeArmWord(std::span<std::uint8_t> bytes, std::size_t offset,
                  std::uint32_t word) {
    for (std::size_t index = 0; index < sizeof(word); ++index) {
        bytes[offset + index] =
            static_cast<std::uint8_t>(word >> (index * 8U));
    }
}

void relocateProgram(arm64::Program &program, std::uint64_t oldAnchor) {
    const auto slide = translationHelperAnchor() - oldAnchor;
    auto bytes = std::span<std::uint8_t>(program.bytes);
    for (const auto rawOffset : program.pointerRelocations) {
        const auto offset = static_cast<std::size_t>(rawOffset);
        constexpr auto relocationSize = 4U * sizeof(std::uint32_t);
        if ((offset % sizeof(std::uint32_t)) != 0 || offset > bytes.size() ||
            relocationSize > bytes.size() - offset) {
            throw std::runtime_error(
                "persistent translation cache has an invalid relocation");
        }
        std::uint64_t oldPointer{};
        std::array<std::uint32_t, 4> words{};
        for (std::uint32_t halfword = 0; halfword < words.size(); ++halfword) {
            const auto wordOffset =
                offset + halfword * sizeof(std::uint32_t);
            words[halfword] = readArmWord(bytes, wordOffset);
            const auto expectedBase =
                halfword == 0 ? 0xD2800000U : 0xF2800000U;
            if ((words[halfword] & 0xFFE00000U) !=
                    ((expectedBase | (halfword << 21U)) & 0xFFE00000U) ||
                (words[halfword] & 0x1FU) != arm64::x16.encoding) {
                throw std::runtime_error(
                    "persistent translation cache relocation code is invalid");
            }
            oldPointer |= static_cast<std::uint64_t>(
                              (words[halfword] >> 5U) & 0xFFFFU)
                          << (halfword * 16U);
        }
        const auto pointer = oldPointer + slide;
        for (std::uint32_t halfword = 0; halfword < words.size(); ++halfword) {
            words[halfword] &= ~(UINT32_C(0xFFFF) << 5U);
            words[halfword] |=
                static_cast<std::uint32_t>(
                    (pointer >> (halfword * 16U)) & UINT64_C(0xFFFF))
                << 5U;
            writeArmWord(bytes,
                         offset + halfword * sizeof(std::uint32_t),
                         words[halfword]);
        }
    }
}

bool sourceMatches(const TranslatedBlock &block,
                   std::span<const std::uint8_t> code) {
    const auto source = block.sourceBytes();
    return source.size() <= code.size() &&
           std::equal(source.begin(), source.end(), code.begin());
}

} // namespace

BlockCache::BlockCache(
    bool retainProgramListings,
    std::optional<std::filesystem::path> persistentPath)
    : translator_(retainProgramListings),
      persistentPath_(retainProgramListings ? std::nullopt
                                            : std::move(persistentPath)) {
    if (persistentPath_) {
        try {
            loadPersistent();
        } catch (...) {
            persistentBlocks_.clear();
        }
    }
}

BlockCache::~BlockCache() { savePersistent(); }

void BlockCache::loadPersistent() {
    std::error_code error;
    if (!std::filesystem::exists(*persistentPath_, error)) {
        if (error) {
            throw std::runtime_error(
                "cannot inspect persistent translation cache: " +
                error.message());
        }
        return;
    }
    const auto fileSize = std::filesystem::file_size(*persistentPath_, error);
    if (error || fileSize > maximumPersistentFileSize) {
        throw std::runtime_error(
            "persistent translation cache has an invalid file size");
    }
    std::ifstream input(*persistentPath_, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open persistent translation cache");
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(fileSize));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char *>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    if (!input || input.gcount() !=
                      static_cast<std::streamsize>(bytes.size())) {
        throw std::runtime_error("cannot read persistent translation cache");
    }

    PersistentReader reader(bytes);
    const auto magic = reader.readBytes(persistentMagic.size());
    if (!std::equal(magic.begin(), magic.end(), persistentMagic.begin()) ||
        reader.readU32() != persistentVersion ||
        reader.readU64() != translationCacheBuildFingerprint()) {
        persistentBlocks_.clear();
        return;
    }
    const auto oldAnchor = reader.readU64();
    const auto recordCount = reader.readU32();
    if (recordCount > maximumPersistentRecords) {
        throw std::runtime_error(
            "persistent translation cache has too many records");
    }
    persistentBlocks_.reserve(recordCount);
    for (std::uint32_t index = 0; index < recordCount; ++index) {
        const auto address = reader.readU64();
        const auto maximumInstructions = reader.readU64();
        const auto sourceSize = reader.readU32();
        const auto programSize = reader.readU32();
        const auto relocationCount = reader.readU32();
        const auto flags = reader.readU32();
        const auto callReturnAddress = reader.readU64();
        const auto lastInstructionAddress = reader.readU64();
        if (maximumInstructions == 0 ||
            maximumInstructions > std::numeric_limits<std::size_t>::max() ||
            sourceSize == 0 || sourceSize > maximumPersistentSourceSize ||
            programSize == 0 || programSize > maximumPersistentProgramSize ||
            relocationCount > maximumPersistentRelocations ||
            (flags & ~UINT32_C(3)) != 0 ||
            lastInstructionAddress < address ||
            lastInstructionAddress - address >= sourceSize) {
            throw std::runtime_error(
                "persistent translation cache record is invalid");
        }
        PersistentBlock block;
        const auto source = reader.readBytes(sourceSize);
        block.sourceBytes.assign(source.begin(), source.end());
        const auto program = reader.readBytes(programSize);
        block.program.bytes.assign(program.begin(), program.end());
        block.program.pointerRelocations.reserve(relocationCount);
        for (std::uint32_t relocation = 0; relocation < relocationCount;
             ++relocation) {
            block.program.pointerRelocations.push_back(reader.readU32());
        }
        block.maximumInstructions =
            static_cast<std::size_t>(maximumInstructions);
        block.hasInternalSelfEdge = (flags & 1U) != 0;
        if ((flags & 2U) != 0) {
            block.callReturnAddress =
                guest::GuestAddress{callReturnAddress};
        }
        block.lastInstructionAddress =
            guest::GuestAddress{lastInstructionAddress};
        relocateProgram(block.program, oldAnchor);
        if (!persistentBlocks_.emplace(address, std::move(block)).second) {
            throw std::runtime_error(
                "persistent translation cache repeats a guest address");
        }
    }
    if (!reader.finished()) {
        throw std::runtime_error(
            "persistent translation cache has trailing data");
    }
    std::vector<PersistentBlock *> cachedBlocks;
    std::vector<std::span<const std::uint8_t>> cachedPrograms;
    cachedBlocks.reserve(persistentBlocks_.size());
    cachedPrograms.reserve(persistentBlocks_.size());
    for (auto &[address, block] : persistentBlocks_) {
        static_cast<void>(address);
        cachedBlocks.push_back(&block);
        cachedPrograms.emplace_back(block.program.bytes);
    }
    auto executable = arm64::ExecutableCode::publishBatch(
        translator_.executableArena(), cachedPrograms);
    for (std::size_t index = 0; index < cachedBlocks.size(); ++index) {
        cachedBlocks[index]->executable.emplace(std::move(executable[index]));
    }
}

void BlockCache::savePersistent() const noexcept {
    if (!persistentPath_ || !persistentDirty_) {
        return;
    }
    try {
        std::vector<std::uint8_t> bytes;
        bytes.reserve(64 + blocks_.size() * 256);
        bytes.insert(bytes.end(), persistentMagic.begin(),
                     persistentMagic.end());
        appendU32(bytes, persistentVersion);
        appendU64(bytes, translationCacheBuildFingerprint());
        appendU64(bytes, translationHelperAnchor());
        std::size_t unusedPersistent = 0;
        for (const auto &[address, block] : persistentBlocks_) {
            static_cast<void>(block);
            unusedPersistent += blocks_.contains(address) ? 0U : 1U;
        }
        if (blocks_.size() > std::numeric_limits<std::uint32_t>::max() -
                                 unusedPersistent) {
            return;
        }
        appendU32(bytes, static_cast<std::uint32_t>(blocks_.size() +
                                                    unusedPersistent));

        const auto appendRecord = [&bytes](
                                      std::uint64_t address,
                                      std::size_t maximumInstructions,
                                      std::span<const std::uint8_t> source,
                                      const arm64::Program &program,
                                      bool internalSelfEdge,
                                      std::optional<guest::GuestAddress>
                                          callReturnAddress,
                                      guest::GuestAddress
                                          lastInstructionAddress) {
            if (source.size() > std::numeric_limits<std::uint32_t>::max() ||
                program.bytes.size() >
                    std::numeric_limits<std::uint32_t>::max() ||
                program.pointerRelocations.size() >
                    std::numeric_limits<std::uint32_t>::max()) {
                throw std::overflow_error(
                    "persistent translation cache record is too large");
            }
            appendU64(bytes, address);
            appendU64(bytes, maximumInstructions);
            appendU32(bytes, static_cast<std::uint32_t>(source.size()));
            appendU32(bytes,
                      static_cast<std::uint32_t>(program.bytes.size()));
            appendU32(bytes, static_cast<std::uint32_t>(
                                 program.pointerRelocations.size()));
            appendU32(bytes, (internalSelfEdge ? 1U : 0U) |
                                 (callReturnAddress ? 2U : 0U));
            appendU64(bytes,
                      callReturnAddress ? callReturnAddress->value : 0);
            appendU64(bytes, lastInstructionAddress.value);
            bytes.insert(bytes.end(), source.begin(), source.end());
            bytes.insert(bytes.end(), program.bytes.begin(),
                         program.bytes.end());
            for (const auto relocation : program.pointerRelocations) {
                appendU32(bytes, relocation);
            }
        };

        for (const auto &[address, block] : blocks_) {
            const auto maximum = maximumInstructions_.find(address);
            if (maximum == maximumInstructions_.end()) {
                return;
            }
            appendRecord(address, maximum->second, block->sourceBytes(),
                         block->program(),
                         block->hasInternalSelfEdge(),
                         block->callReturnAddress(),
                         block->lastInstructionAddress());
        }
        for (const auto &[address, block] : persistentBlocks_) {
            if (blocks_.contains(address)) {
                continue;
            }
            appendRecord(address, block.maximumInstructions,
                         block.sourceBytes, block.program,
                         block.hasInternalSelfEdge,
                         block.callReturnAddress,
                         block.lastInstructionAddress);
        }

        auto temporary = *persistentPath_;
        temporary += ".tmp." + std::to_string(::getpid());
        {
            std::ofstream output(temporary,
                                 std::ios::binary | std::ios::trunc);
            if (!output) {
                return;
            }
            output.write(reinterpret_cast<const char *>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()));
            if (!output) {
                output.close();
                std::filesystem::remove(temporary);
                return;
            }
        }
        std::error_code error;
        std::filesystem::rename(temporary, *persistentPath_, error);
        if (error) {
            std::filesystem::remove(temporary);
        } else {
            persistentDirty_ = false;
        }
    } catch (...) {
        // Cache persistence must never change guest execution semantics.
    }
}

TranslatedBlock *BlockCache::findCurrent(
    guest::GuestAddress address, std::uint64_t executableVersion) noexcept {
    const auto existing = lookup_.find(address.value);
    if (existing == lookup_.end() ||
        existing->second.executableVersion != executableVersion) {
        return nullptr;
    }
    return existing->second.block;
}

void BlockCache::resetExecutionCounts() noexcept {
    for (const auto &[address, block] : blocks_) {
        static_cast<void>(address);
        block->resetExecutionCount();
    }
}

TranslatedBlock &BlockCache::getOrTranslate(guest::GuestAddress address,
                                            std::span<const std::uint8_t> code,
                                            std::size_t maximumInstructions,
                                            std::uint64_t executableVersion) {
    if (const auto existing = lookup_.find(address.value);
        existing != lookup_.end()) {
        if (sourceMatches(*existing->second.block, code)) {
            existing->second.executableVersion = executableVersion;
            return *existing->second.block;
        }

        // Guest code may be writable, deallocated, and remapped at the same
        // RIP. Build the replacement completely before retiring executable
        // code so a failed translation leaves the valid old cache entry intact.
        auto replacement = std::make_unique<TranslatedBlock>(
            translator_.translate(code, address, maximumInstructions));
        persistentDirty_ = persistentPath_.has_value();
        const auto ordered = blocks_.find(address.value);
        if (ordered == blocks_.end() ||
            ordered->second.get() != existing->second.block) {
            throw std::logic_error(
                "translated block ownership/index disagree");
        }
        ordered->second.swap(replacement);
        existing->second = LookupEntry{ordered->second.get(),
                                       executableVersion};
        maximumInstructions_[address.value] = maximumInstructions;
        return *ordered->second;
    }

    std::unique_ptr<TranslatedBlock> block;
    if (const auto cached = persistentBlocks_.find(address.value);
        cached != persistentBlocks_.end() &&
        cached->second.maximumInstructions == maximumInstructions &&
        cached->second.sourceBytes.size() <= code.size() &&
        std::equal(cached->second.sourceBytes.begin(),
                   cached->second.sourceBytes.end(), code.begin())) {
        auto persistent = std::move(cached->second);
        persistentBlocks_.erase(cached);
        if (!persistent.executable) {
            throw std::logic_error(
                "persistent translation cache block has no executable code");
        }
        block = std::make_unique<TranslatedBlock>(translator_.loadCached(
            std::move(persistent.sourceBytes), address,
            persistent.lastInstructionAddress, maximumInstructions,
            std::move(persistent.program),
            std::move(*persistent.executable),
            persistent.hasInternalSelfEdge,
            persistent.callReturnAddress));
        ++persistentHitCount_;
    } else {
        block = std::make_unique<TranslatedBlock>(
            translator_.translate(code, address, maximumInstructions));
        persistentDirty_ = persistentPath_.has_value();
    }
    const auto [ordered, inserted] =
        blocks_.emplace(address.value, std::move(block));
    if (!inserted) {
        throw std::logic_error("translated block ownership/index disagree");
    }

    try {
        const auto indexed =
            lookup_
                .emplace(address.value,
                         LookupEntry{ordered->second.get(), executableVersion})
                .second;
        if (!indexed) {
            throw std::logic_error("translated block index already exists");
        }
    } catch (...) {
        blocks_.erase(ordered);
        throw;
    }
    maximumInstructions_[address.value] = maximumInstructions;
    return *ordered->second;
}

} // namespace rosa::dbt
