#pragma once

#include "dbt/TranslatedBlock.h"
#include "x86/Decoder.h"

#include <limits>

namespace rosa::dbt {

class Translator {
  public:
    explicit Translator(bool retainProgramListing = true)
        : executableArena_(std::make_shared<arm64::ExecutableArena>()),
          retainProgramListing_(retainProgramListing) {}

    [[nodiscard]] TranslatedBlock
    translate(std::span<const std::uint8_t> code, guest::GuestAddress start,
              std::size_t maximumInstructions = std::numeric_limits<std::size_t>::max()) const;
    [[nodiscard]] TranslatedBlock
    loadCached(std::vector<std::uint8_t> sourceBytes, guest::GuestAddress start,
               guest::GuestAddress lastInstructionAddress, std::size_t maximumInstructions,
               arm64::Program program, arm64::ExecutableCode executable, bool hasInternalSelfEdge,
               std::optional<guest::GuestAddress> callReturnAddress) const;

    [[nodiscard]] const std::shared_ptr<arm64::ExecutableArena> &executableArena() const noexcept {
        return executableArena_;
    }

  private:
    x86::Decoder decoder_;
    std::shared_ptr<arm64::ExecutableArena> executableArena_;
    bool retainProgramListing_{};
};

} // namespace rosa::dbt
