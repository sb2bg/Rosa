#include "dbt/BlockCache.h"

#include <utility>

namespace rosa::dbt {

TranslatedBlock &BlockCache::getOrTranslate(guest::GuestAddress address,
                                            std::span<const std::uint8_t> code,
                                            std::size_t maximumInstructions) {
    if (const auto existing = blocks_.find(address.value); existing != blocks_.end()) {
        return *existing->second;
    }

    auto block = std::make_unique<TranslatedBlock>(
        translator_.translate(code, address, maximumInstructions));
    auto *result = block.get();
    blocks_.emplace(address.value, std::move(block));
    return *result;
}

} // namespace rosa::dbt
