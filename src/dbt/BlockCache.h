#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <unordered_map>

#include "dbt/Translator.h"

namespace rosa::dbt {

class BlockCache final {
public:
    [[nodiscard]] const TranslatedBlock *find(std::uint64_t rip) const;
    [[nodiscard]] const TranslatedBlock &insert(std::uint64_t rip,
                                                std::unique_ptr<TranslatedBlock> block);
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] const std::map<std::uint64_t, std::unique_ptr<TranslatedBlock>> &blocks()
        const;

private:
    // Keep ownership ordered for deterministic diagnostics while dispatch uses
    // a hash index. Translation is cold relative to cache lookup, so the small
    // insertion cost avoids paying a tree walk on every executed block.
    std::map<std::uint64_t, std::unique_ptr<TranslatedBlock>> blocks_;
    std::unordered_map<std::uint64_t, TranslatedBlock *> lookup_;
};

}  // namespace rosa::dbt
