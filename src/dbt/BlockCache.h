#pragma once

#include "dbt/Translator.h"
#include "guest/Address.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <unordered_map>

namespace rosa::dbt {

class BlockCache {
  public:
    explicit BlockCache(
        bool retainProgramListings = false,
        std::optional<std::filesystem::path> persistentPath = std::nullopt);
    ~BlockCache();

    [[nodiscard]] TranslatedBlock *findCurrent(
        guest::GuestAddress address, std::uint64_t executableVersion) noexcept;
    TranslatedBlock &getOrTranslate(guest::GuestAddress address,
                                    std::span<const std::uint8_t> code,
                                    std::size_t maximumInstructions,
                                    std::uint64_t executableVersion);
    void resetExecutionCounts() noexcept;
    void flushPersistent() const noexcept { savePersistent(); }

    [[nodiscard]] std::size_t size() const noexcept { return blocks_.size(); }
    [[nodiscard]] std::size_t persistentHitCount() const noexcept {
        return persistentHitCount_;
    }
    [[nodiscard]] std::size_t executableMappingCount() const noexcept {
        return translator_.executableArena()->mappingCount();
    }
    [[nodiscard]] std::size_t executableAllocatedBytes() const noexcept {
        return translator_.executableArena()->allocatedBytes();
    }
    [[nodiscard]] std::size_t executableUsedBytes() const noexcept {
        return translator_.executableArena()->usedBytes();
    }
    [[nodiscard]] const std::map<std::uint64_t, std::unique_ptr<TranslatedBlock>> &
    blocks() const noexcept {
        return blocks_;
    }

  private:
    struct PersistentBlock {
        std::vector<std::uint8_t> sourceBytes;
        arm64::Program program;
        std::optional<arm64::ExecutableCode> executable;
        std::size_t maximumInstructions{};
        bool hasInternalSelfEdge{};
        std::optional<guest::GuestAddress> callReturnAddress;
        guest::GuestAddress lastInstructionAddress{};
    };

    void loadPersistent();
    void savePersistent() const noexcept;

    Translator translator_;
    // Preserve ordered ownership for deterministic diagnostics while the hot
    // dispatch lookup uses a hash index.
    std::map<std::uint64_t, std::unique_ptr<TranslatedBlock>> blocks_;
    struct LookupEntry {
        TranslatedBlock *block{};
        std::uint64_t executableVersion{};
    };
    std::unordered_map<std::uint64_t, LookupEntry> lookup_;
    std::unordered_map<std::uint64_t, std::size_t> maximumInstructions_;
    std::optional<std::filesystem::path> persistentPath_;
    std::unordered_map<std::uint64_t, PersistentBlock> persistentBlocks_;
    std::size_t persistentHitCount_{};
    mutable bool persistentDirty_{};
};

} // namespace rosa::dbt
