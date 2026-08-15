#pragma once

#include "darwin/Syscall.h"
#include "dbt/BlockCache.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "x86/Registers.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace rosa::dbt {

struct DispatchResult {
    std::size_t executedBlocks{};
    std::size_t translatedBlocks{};
    bool exited{};
    int exitStatus{};
};

struct BlockExecutionCount {
    guest::GuestAddress address;
    std::size_t count{};
};

class Dispatcher {
  public:
    explicit Dispatcher(
        guest::AddressSpace &addressSpace,
        std::size_t maximumInstructionsPerBlock = std::numeric_limits<std::size_t>::max(),
        TimestampCounterReader timestampCounterReader = nullptr)
        : addressSpace_(addressSpace), maximumInstructionsPerBlock_(maximumInstructionsPerBlock),
          timestampCounterReader_(timestampCounterReader) {}

    [[nodiscard]] DispatchResult
    run(x86::X86State &state, std::size_t maximumBlocks,
        std::optional<guest::GuestAddress> returnSentinel = std::nullopt);

    [[nodiscard]] const BlockCache &cache() const noexcept { return cache_; }
    [[nodiscard]] std::size_t executedBlocks() const noexcept { return executedBlocks_; }
    [[nodiscard]] std::size_t translatedBlocks() const noexcept { return cache_.size(); }
    [[nodiscard]] const std::deque<guest::GuestAddress> &recentBlocks() const noexcept {
        return recentBlocks_;
    }
    [[nodiscard]] std::vector<BlockExecutionCount>
    hotBlocks(std::size_t minimumExecutions = 16, std::size_t limit = 8) const;

  private:
    [[nodiscard]] std::span<const std::uint8_t> codeAt(guest::GuestAddress address) const;

    guest::AddressSpace &addressSpace_;
    BlockCache cache_;
    darwin::SyscallDispatcher syscallDispatcher_;
    std::size_t maximumInstructionsPerBlock_;
    TimestampCounterReader timestampCounterReader_{};
    std::size_t executedBlocks_{};
    std::deque<guest::GuestAddress> recentBlocks_;
    std::unordered_map<std::uint64_t, std::size_t> blockExecutionCounts_;
};

} // namespace rosa::dbt
