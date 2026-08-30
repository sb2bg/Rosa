#pragma once

#include "dbt/Translator.h"
#include "guest/Address.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <unordered_map>

namespace rosa::dbt {

class BlockCache {
  public:
    [[nodiscard]] TranslatedBlock *findCurrent(
        guest::GuestAddress address, std::uint64_t executableVersion) noexcept;
    TranslatedBlock &getOrTranslate(guest::GuestAddress address,
                                    std::span<const std::uint8_t> code,
                                    std::size_t maximumInstructions,
                                    std::uint64_t executableVersion);
    void resetExecutionCounts() noexcept;

    [[nodiscard]] std::size_t size() const noexcept { return blocks_.size(); }
    [[nodiscard]] const std::map<std::uint64_t, std::unique_ptr<TranslatedBlock>> &
    blocks() const noexcept {
        return blocks_;
    }

  private:
    Translator translator_;
    // Preserve ordered ownership for deterministic diagnostics while the hot
    // dispatch lookup uses a hash index.
    std::map<std::uint64_t, std::unique_ptr<TranslatedBlock>> blocks_;
    struct LookupEntry {
        TranslatedBlock *block{};
        std::uint64_t executableVersion{};
    };
    std::unordered_map<std::uint64_t, LookupEntry> lookup_;
};

} // namespace rosa::dbt
