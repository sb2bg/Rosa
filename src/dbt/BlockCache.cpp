#include "dbt/BlockCache.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace rosa::dbt {
namespace {

bool sourceMatches(const TranslatedBlock &block,
                   std::span<const std::uint8_t> code) {
    std::size_t offset = 0;
    for (const auto &instruction : block.decoded()) {
        const auto length = static_cast<std::size_t>(instruction.length);
        if (offset > code.size() || length > code.size() - offset) {
            return false;
        }
        if (!std::equal(instruction.bytes.begin(),
                        instruction.bytes.begin() +
                            static_cast<std::ptrdiff_t>(length),
                        code.begin() + static_cast<std::ptrdiff_t>(offset))) {
            return false;
        }
        offset += length;
    }
    return true;
}

} // namespace

TranslatedBlock &BlockCache::getOrTranslate(guest::GuestAddress address,
                                            std::span<const std::uint8_t> code,
                                            std::size_t maximumInstructions) {
    if (const auto existing = lookup_.find(address.value);
        existing != lookup_.end()) {
        if (sourceMatches(*existing->second, code)) {
            return *existing->second;
        }

        // Guest code may be writable, deallocated, and remapped at the same
        // RIP. Build the replacement completely before retiring executable
        // code so a failed translation leaves the valid old cache entry intact.
        auto replacement = std::make_unique<TranslatedBlock>(
            translator_.translate(code, address, maximumInstructions));
        const auto ordered = blocks_.find(address.value);
        if (ordered == blocks_.end() ||
            ordered->second.get() != existing->second) {
            throw std::logic_error(
                "translated block ownership/index disagree");
        }
        ordered->second.swap(replacement);
        existing->second = ordered->second.get();
        return *ordered->second;
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
