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
    TranslatedBlock(std::vector<x86::DecodedInstruction> decoded, ir::Block ir,
                    arm64::Program program);

    [[nodiscard]] BlockExit execute(x86::X86State &state,
                                    guest::AddressSpace *addressSpace = nullptr,
                                    TimestampCounterReader timestampCounterReader = nullptr) const;
    [[nodiscard]] BlockExecutionResult executeRepeated(
        x86::X86State &state, guest::AddressSpace &addressSpace,
        TimestampCounterReader timestampCounterReader,
        std::size_t maximumExecutions) const;

    [[nodiscard]] const std::vector<x86::DecodedInstruction> &decoded() const noexcept {
        return decoded_;
    }
    [[nodiscard]] const ir::Block &intermediateRepresentation() const noexcept { return ir_; }
    [[nodiscard]] const arm64::Program &program() const noexcept { return program_; }
    [[nodiscard]] std::optional<guest::GuestAddress> callReturnAddress() const noexcept {
        return callReturnAddress_;
    }
    void resetExecutionCount() noexcept { executionCount_ = 0; }
    void recordExecutions(std::size_t count) noexcept { executionCount_ += count; }
    [[nodiscard]] std::size_t executionCount() const noexcept {
        return executionCount_;
    }
    [[nodiscard]] bool usesOptimizedLoop() const noexcept {
        return optimizedLoop_ != nullptr;
    }

  private:
    std::vector<x86::DecodedInstruction> decoded_;
    ir::Block ir_;
    arm64::Program program_;
    arm64::ExecutableCode executable_;
    std::optional<guest::GuestAddress> callReturnAddress_;
    std::size_t executionCount_{};
    bool hasInternalSelfEdge_{};
    std::unique_ptr<OptimizedLoop> optimizedLoop_;
};

class Translator {
  public:
    [[nodiscard]] TranslatedBlock
    translate(std::span<const std::uint8_t> code, guest::GuestAddress start,
              std::size_t maximumInstructions = std::numeric_limits<std::size_t>::max()) const;

  private:
    x86::Decoder decoder_;
};

} // namespace rosa::dbt
