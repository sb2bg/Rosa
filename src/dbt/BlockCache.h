#pragma once

#include "dbt/Translator.h"
#include "guest/Address.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <span>

namespace rosa::dbt {

class BlockCache {
  public:
    TranslatedBlock &getOrTranslate(guest::GuestAddress address, std::span<const std::uint8_t> code,
                                    std::size_t maximumInstructions);

    [[nodiscard]] std::size_t size() const noexcept { return blocks_.size(); }
    [[nodiscard]] const std::map<std::uint64_t, std::unique_ptr<TranslatedBlock>> &
    blocks() const noexcept {
        return blocks_;
    }

  private:
    Translator translator_;
    std::map<std::uint64_t, std::unique_ptr<TranslatedBlock>> blocks_;
};

} // namespace rosa::dbt
