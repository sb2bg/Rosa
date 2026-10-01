#pragma once

#include <cstddef>
#include <cstdint>

namespace rosa::dbt {

using TimestampCounterReader = std::uint64_t (*)();

enum class BlockExit : std::uint64_t {
    Continue,
    Call,
    Return,
    Syscall,
    MemoryFault,
    ExecutionFault,
};

struct BlockExecutionResult {
    BlockExit exit{BlockExit::Continue};
    std::size_t executionCount{};
};

} // namespace rosa::dbt
