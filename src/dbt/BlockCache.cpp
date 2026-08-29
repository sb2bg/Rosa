#include "dbt/BlockCache.h"

#include <stdexcept>
#include <utility>

namespace rosa::dbt {

const TranslatedBlock *BlockCache::find(std::uint64_t rip) const {
    const auto it = lookup_.find(rip);
    return it == lookup_.end() ? nullptr : it->second;
}

const TranslatedBlock &BlockCache::insert(std::uint64_t rip,
                                          std::unique_ptr<TranslatedBlock> block) {
    if (!block) {
        throw std::runtime_error("cannot insert a null translated block");
    }
    const auto [it, inserted] = blocks_.emplace(rip, std::move(block));
    if (!inserted) {
        throw std::runtime_error("translated block already exists");
    }

    try {
        const auto [_, indexed] = lookup_.emplace(rip, it->second.get());
        if (!indexed) {
            throw std::runtime_error("translated block index already exists");
        }
    } catch (...) {
        blocks_.erase(it);
        throw;
    }
    return *it->second;
}

std::size_t BlockCache::size() const {
    return blocks_.size();
}

const std::map<std::uint64_t, std::unique_ptr<TranslatedBlock>> &BlockCache::blocks() const {
    return blocks_;
}

}  // namespace rosa::dbt
