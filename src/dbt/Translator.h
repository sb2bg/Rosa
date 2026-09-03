#pragma once

#include "arm64/Assembler.h"
#include "arm64/CodeBuffer.h"
#include "dbt/LlvmBackend.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "ir/IR.h"
#include "x86/Decoder.h"
#include "x86/Registers.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <vector>

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

class TranslatedBlock {
  public:
    static constexpr std::size_t optimizedLoopWarmupExecutions = 1024;
    static constexpr std::size_t optimizedMemoryLoopWarmupExecutions = 100'000'000;
    static constexpr std::size_t optimizedLoopMinimumRemainingExecutions = 10000000;

    TranslatedBlock(std::vector<x86::DecodedInstruction> decoded, ir::Block ir,
                    arm64::Program program, std::shared_ptr<arm64::ExecutableArena> executableArena,
                    std::size_t maximumInstructions,
                    std::optional<bool> cachedInternalSelfEdge = std::nullopt,
                    std::optional<guest::GuestAddress> cachedCallReturnAddress = std::nullopt);
    TranslatedBlock(std::vector<std::uint8_t> sourceBytes, guest::GuestAddress start,
                    guest::GuestAddress lastInstructionAddress, std::size_t maximumInstructions,
                    arm64::Program program, arm64::ExecutableCode executable,
                    bool cachedInternalSelfEdge,
                    std::optional<guest::GuestAddress> cachedCallReturnAddress);

    [[nodiscard]] BlockExit execute(x86::X86State &state,
                                    guest::AddressSpace *addressSpace = nullptr,
                                    TimestampCounterReader timestampCounterReader = nullptr) const;
    [[nodiscard]] BlockExecutionResult
    executeRepeated(x86::X86State &state, guest::AddressSpace &addressSpace,
                    TimestampCounterReader timestampCounterReader,
                    std::size_t maximumExecutions) const;

    [[nodiscard]] const std::vector<x86::DecodedInstruction> &decoded() const;
    [[nodiscard]] std::span<const std::uint8_t> sourceBytes() const noexcept {
        return sourceBytes_;
    }
    [[nodiscard]] guest::GuestAddress lastInstructionAddress() const noexcept {
        return lastInstructionAddress_;
    }
    [[nodiscard]] const ir::Block &intermediateRepresentation() const noexcept { return ir_; }
    [[nodiscard]] const arm64::Program &program() const noexcept { return program_; }
    [[nodiscard]] std::optional<guest::GuestAddress> callReturnAddress() const noexcept {
        return callReturnAddress_;
    }
    void resetExecutionCount() noexcept { executionCount_ = 0; }
    void recordExecutions(std::size_t count) noexcept { executionCount_ += count; }
    [[nodiscard]] std::size_t executionCount() const noexcept { return executionCount_; }
    [[nodiscard]] bool isOptimizationCandidate() const noexcept { return optimizationCandidate_; }
    [[nodiscard]] bool usesOptimizedLoop() const noexcept { return optimizedLoop_ != nullptr; }
    [[nodiscard]] bool hasInternalSelfEdge() const noexcept { return hasInternalSelfEdge_; }
    void promoteOptimizedLoopIfHot(std::size_t remainingBudget);
    [[nodiscard]] std::size_t executionBatchLimit(std::size_t requested) const noexcept;

  private:
    mutable std::vector<x86::DecodedInstruction> decoded_;
    std::vector<std::uint8_t> sourceBytes_;
    guest::GuestAddress lastInstructionAddress_{};
    std::size_t maximumInstructions_{};
    ir::Block ir_;
    arm64::Program program_;
    arm64::ExecutableCode executable_;
    std::optional<guest::GuestAddress> callReturnAddress_;
    std::size_t executionCount_{};
    bool hasInternalSelfEdge_{};
    bool optimizationCandidate_{};
    std::size_t optimizationWarmupExecutions_{optimizedLoopWarmupExecutions};
    std::unique_ptr<OptimizedLoop> optimizedLoop_;
};

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

[[nodiscard]] std::uint64_t translationHelperAnchor() noexcept;
[[nodiscard]] std::uint64_t translationCacheBuildFingerprint() noexcept;

} // namespace rosa::dbt
