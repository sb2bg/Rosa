#pragma once

#include "darwin/Syscall.h"
#include "dbt/BlockCache.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "x86/Registers.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>

namespace rosa::dbt {

struct DispatchResult {
    std::size_t executedBlocks{};
    std::size_t translatedBlocks{};
    bool exited{};
    int exitStatus{};
};

class Dispatcher {
  public:
    explicit Dispatcher(
        guest::AddressSpace &addressSpace,
        std::size_t maximumInstructionsPerBlock = std::numeric_limits<std::size_t>::max())
        : addressSpace_(addressSpace), maximumInstructionsPerBlock_(maximumInstructionsPerBlock) {}

    [[nodiscard]] DispatchResult
    run(x86::X86State &state, std::size_t maximumBlocks,
        std::optional<guest::GuestAddress> returnSentinel = std::nullopt);

    [[nodiscard]] const BlockCache &cache() const noexcept { return cache_; }

  private:
    [[nodiscard]] std::span<const std::uint8_t> codeAt(guest::GuestAddress address) const;

    guest::AddressSpace &addressSpace_;
    BlockCache cache_;
    darwin::SyscallDispatcher syscallDispatcher_;
    std::size_t maximumInstructionsPerBlock_;
};

} // namespace rosa::dbt
