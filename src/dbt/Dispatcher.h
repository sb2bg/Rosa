#pragma once

#include "darwin/SharedCache.h"
#include "darwin/Syscall.h"
#include "dbt/BlockCache.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "x86/Registers.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <optional>
#include <span>
#include <unordered_map>
#include <unordered_set>
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

struct CacheImageExecution {
    const darwin::SharedCacheImage *image{};
    guest::GuestAddress firstRip;
    std::size_t executedBlock{};
};

class Dispatcher {
  public:
    explicit Dispatcher(
        guest::AddressSpace &addressSpace,
        std::size_t maximumInstructionsPerBlock = std::numeric_limits<std::size_t>::max(),
        TimestampCounterReader timestampCounterReader = nullptr,
        const darwin::GuestSharedCache *sharedCache = nullptr,
        const std::array<std::uint8_t, 16> &executableUuid = {})
        : addressSpace_(addressSpace),
          syscallDispatcher_(sharedCache, executableUuid),
          sharedCache_(sharedCache),
          maximumInstructionsPerBlock_(maximumInstructionsPerBlock),
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
    [[nodiscard]] const darwin::MachDispatcher &machDispatcher() const noexcept {
        return syscallDispatcher_.machDispatcher();
    }
    [[nodiscard]] const std::vector<CacheImageExecution> &
    cacheImageExecutions() const noexcept {
        return cacheImageExecutions_;
    }

  private:
    [[nodiscard]] std::span<const std::uint8_t> codeAt(guest::GuestAddress address) const;

    guest::AddressSpace &addressSpace_;
    BlockCache cache_;
    darwin::SyscallDispatcher syscallDispatcher_;
    const darwin::GuestSharedCache *sharedCache_{};
    std::size_t maximumInstructionsPerBlock_;
    TimestampCounterReader timestampCounterReader_{};
    std::size_t executedBlocks_{};
    std::deque<guest::GuestAddress> recentBlocks_;
    std::unordered_map<std::uint64_t, std::size_t> blockExecutionCounts_;
    std::unordered_set<std::size_t> executedCacheImageIndexes_;
    std::vector<CacheImageExecution> cacheImageExecutions_;
};

} // namespace rosa::dbt
