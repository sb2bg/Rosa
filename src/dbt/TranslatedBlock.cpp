#include "dbt/TranslatedBlock.h"
#include "dbt/ExecutionContext.h"
#include "ir/Optimization.h"
#include "x86/Decoder.h"
#include "x86/Lowering.h"

#include <stdexcept>
#include <utility>

namespace rosa::dbt {
using runtime::GuestExecutionContext;

namespace {

BlockExit checkedExit(std::uint64_t rawExit, GuestExecutionContext &context,
                      x86::X86State &state) {
    if (context.fault) {
        state.rip = context.faultRip.value;
        std::rethrow_exception(context.fault.take());
    }
    if (rawExit > static_cast<std::uint64_t>(BlockExit::ExecutionFault)) {
        throw std::runtime_error("generated block returned an invalid exit reason");
    }
    if (rawExit == static_cast<std::uint64_t>(BlockExit::MemoryFault) ||
        rawExit == static_cast<std::uint64_t>(BlockExit::ExecutionFault)) {
        state.rip = context.faultRip.value;
        throw std::runtime_error("generated block reported a guest fault without detail");
    }
    return static_cast<BlockExit>(rawExit);
}

} // namespace

TranslatedBlock::TranslatedBlock(std::vector<x86::DecodedInstruction> decoded, ir::Block ir,
                                 arm64::Program program,
                                 std::shared_ptr<arm64::ExecutableArena> executableArena,
                                 std::size_t maximumInstructions,
                                 std::optional<bool> cachedInternalSelfEdge,
                                 std::optional<guest::GuestAddress> cachedCallReturnAddress)
    : decoded_(std::move(decoded)), ir_(std::move(ir)), program_(std::move(program)),
      executable_(std::move(executableArena), program_.bytes) {
    if (decoded_.empty()) {
        throw std::invalid_argument("translated block has no decoded instructions");
    }
    maximumInstructions_ = maximumInstructions;
    lastInstructionAddress_ = decoded_.back().address;
    for (const auto &instruction : decoded_) {
        sourceBytes_.insert(sourceBytes_.end(), instruction.bytes.begin(),
                            instruction.bytes.begin() + instruction.length);
    }
    hasInternalSelfEdge_ = cachedInternalSelfEdge.value_or(ir::hasInternalSelfEdge(ir_));
    optimizationCandidate_ = llvmBackendAvailable() && canCompileOptimizedLoop(ir_);
    if (optimizationCandidate_ && optimizedLoopUsesMemory(ir_)) {
        optimizationWarmupExecutions_ = optimizedMemoryLoopWarmupExecutions;
    }
    for (const auto &operation : ir_.operations) {
        if (operation.opcode == ir::Opcode::ExitBlock && operation.exitKind == ir::ExitKind::Call) {
            callReturnAddress_ = operation.fallthrough;
        }
    }
    if (cachedCallReturnAddress) {
        callReturnAddress_ = cachedCallReturnAddress;
    }
}

TranslatedBlock::TranslatedBlock(std::vector<std::uint8_t> sourceBytes, guest::GuestAddress start,
                                 guest::GuestAddress lastInstructionAddress,
                                 std::size_t maximumInstructions, arm64::Program program,
                                 arm64::ExecutableCode executable, bool cachedInternalSelfEdge,
                                 std::optional<guest::GuestAddress> cachedCallReturnAddress)
    : sourceBytes_(std::move(sourceBytes)), lastInstructionAddress_(lastInstructionAddress),
      maximumInstructions_(maximumInstructions), ir_(ir::Block{.start = start}),
      program_(std::move(program)), executable_(std::move(executable)),
      callReturnAddress_(cachedCallReturnAddress), hasInternalSelfEdge_(cachedInternalSelfEdge) {
    // Persistent entries intentionally omit IR. A self edge is a cheap
    // over-approximation: rebuild IR only after that block becomes hot, then
    // let the optimizing tier perform its full structural check once.
    optimizationCandidate_ = llvmBackendAvailable() && hasInternalSelfEdge_;
}

const std::vector<x86::DecodedInstruction> &TranslatedBlock::decoded() const {
    if (decoded_.empty()) {
        decoded_ = x86::Decoder{}.decodeBlock(sourceBytes_, ir_.start, maximumInstructions_);
    }
    return decoded_;
}

void TranslatedBlock::promoteOptimizedLoopIfHot(std::size_t remainingBudget) {
    if (optimizationCandidate_ && optimizedLoop_ == nullptr &&
        executionCount_ >= optimizationWarmupExecutions_ &&
        remainingBudget >= optimizedLoopMinimumRemainingExecutions) {
        if (ir_.operations.empty()) {
            decoded_ = x86::Decoder{}.decodeBlock(sourceBytes_, ir_.start, maximumInstructions_);
            ir_ = x86::lowerToIr(decoded_);
            ir::optimizeBlock(ir_);
        }
        if (!canCompileOptimizedLoop(ir_)) {
            optimizationCandidate_ = false;
            return;
        }
        if (optimizedLoopUsesMemory(ir_)) {
            optimizationWarmupExecutions_ = optimizedMemoryLoopWarmupExecutions;
            if (executionCount_ < optimizationWarmupExecutions_) {
                return;
            }
        }
        optimizedLoop_ = compileOptimizedLoop(ir_);
        optimizationCandidate_ = optimizedLoop_ != nullptr;
    }
}

std::size_t TranslatedBlock::executionBatchLimit(std::size_t requested) const noexcept {
    if (!optimizationCandidate_ || optimizedLoop_ != nullptr ||
        executionCount_ >= optimizationWarmupExecutions_) {
        return requested;
    }
    const auto remainingWarmup = optimizationWarmupExecutions_ - executionCount_;
    return requested < remainingWarmup ? requested : remainingWarmup;
}

BlockExit TranslatedBlock::execute(x86::X86State &state, guest::AddressSpace *addressSpace,
                                   TimestampCounterReader timestampCounterReader) const {
    if (optimizedLoop_ != nullptr) {
        const auto executionCount = optimizedLoop_->execute(state, addressSpace, 1);
        if (executionCount && *executionCount != 1) {
            throw std::runtime_error("optimized loop executed an invalid number of blocks");
        }
        if (executionCount) {
            return BlockExit::Continue;
        }
    }
    GuestExecutionContext context{
        .addressSpace = addressSpace,
        .timestampCounterReader = timestampCounterReader,
        .faultRip = guest::GuestAddress{state.rip},
    };
    using Entry = std::uint64_t (*)(x86::X86State *, GuestExecutionContext *);
    const auto rawExit = executable_.entry<Entry>()(&state, &context);
    return checkedExit(rawExit, context, state);
}

BlockExecutionResult TranslatedBlock::executeRepeated(x86::X86State &state,
                                                      guest::AddressSpace &addressSpace,
                                                      TimestampCounterReader timestampCounterReader,
                                                      std::size_t maximumExecutions) const {
    if (maximumExecutions == 0) {
        throw std::invalid_argument("repeated block execution requires a nonzero limit");
    }
    if (optimizedLoop_ != nullptr) {
        const auto executionCount =
            optimizedLoop_->execute(state, &addressSpace, maximumExecutions);
        if (executionCount && (*executionCount == 0 || *executionCount > maximumExecutions)) {
            throw std::runtime_error("optimized loop executed an invalid number of blocks");
        }
        if (executionCount) {
            return BlockExecutionResult{BlockExit::Continue, *executionCount};
        }
    }
    if (!hasInternalSelfEdge_) {
        return BlockExecutionResult{execute(state, &addressSpace, timestampCounterReader), 1};
    }

    GuestExecutionContext context{
        .addressSpace = &addressSpace,
        .timestampCounterReader = timestampCounterReader,
        .remainingBlockExecutions = maximumExecutions,
        .directMemoryEnabled = true,
        .faultRip = guest::GuestAddress{state.rip},
    };
    using Entry = std::uint64_t (*)(x86::X86State *, GuestExecutionContext *);
    const auto entry = executable_.entry<Entry>();
    const auto rawExit = entry(&state, &context);
    const auto executionCount = maximumExecutions - context.remainingBlockExecutions;

    return BlockExecutionResult{checkedExit(rawExit, context, state), executionCount};
}

} // namespace rosa::dbt
