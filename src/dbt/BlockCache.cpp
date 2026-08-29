#include "dbt/BlockCache.h"

#include <stdexcept>
#include <utility>

namespace rosa::dbt {

TranslatedBlock &BlockCache::getOrTranslate(guest::GuestAddress address,
                                            std::span<const std::uint8_t> code,
                                            std::size_t maximumInstructions) {
    if (const auto existing = lookup_.find(address.value); existing != lookup_.end()) {
        return *existing->second;
    }

    auto block = std::make_unique<TranslatedBlock>(
        translator_.translate(code, address, maximumInstructions));
    const auto [ordered, inserted] =
        blocks_.emplace(address.value, std::move(block));
    if (!inserted) {
        throw std::logic_error("translated block ownership/index disagree");
    }

    try {
        const auto indexed =
            lookup_.emplace(address.value, ordered->second.get()).second;
        if (!indexed) {
            throw std::logic_error("translated block index already exists");
        }
    } catch (...) {
        blocks_.erase(ordered);
        throw;
    }
    return *ordered->second;
}

} // namespace rosa::dbt
