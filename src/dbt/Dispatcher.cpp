#include "dbt/Dispatcher.h"

#include <algorithm>
#include <stdexcept>

namespace rosa::dbt {

std::vector<guest::GuestAddress> Dispatcher::recentBlocks() const {
    std::vector<guest::GuestAddress> result;
    result.reserve(recentBlockCount_);
    const auto first =
        (nextRecentBlock_ + recentBlockCapacity - recentBlockCount_) %
        recentBlockCapacity;
    for (std::size_t index = 0; index < recentBlockCount_; ++index) {
        result.push_back(recentBlocks_[(first + index) % recentBlockCapacity]);
    }
    return result;
}

std::vector<BlockExecutionCount>
Dispatcher::hotBlocks(std::size_t minimumExecutions, std::size_t limit) const {
    std::vector<BlockExecutionCount> result;
    result.reserve(cache_.size());
    for (const auto &[address, block] : cache_.blocks()) {
        const auto count = block->executionCount();
        if (count >= minimumExecutions) {
            result.push_back(BlockExecutionCount{guest::GuestAddress{address}, count});
        }
    }
    std::ranges::sort(result, [](const auto &lhs, const auto &rhs) {
        if (lhs.count != rhs.count) {
            return lhs.count > rhs.count;
        }
        return lhs.address.value < rhs.address.value;
    });
    if (result.size() > limit) {
        result.resize(limit);
    }
    return result;
}

std::span<const std::uint8_t> Dispatcher::codeAt(guest::GuestAddress address) const {
    return addressSpace_.executableBytes(address);
}

DispatchResult Dispatcher::run(x86::X86State &state, std::size_t maximumBlocks,
                               std::optional<guest::GuestAddress> returnSentinel) {
    DispatchResult result;
    executedBlocks_ = 0;
    recentBlockCount_ = 0;
    nextRecentBlock_ = 0;
    cache_.resetExecutionCounts();
    translationTime_ = {};
    executedCacheImageIndexes_.clear();
    cacheImageExecutions_.clear();
    while (result.executedBlocks < maximumBlocks) {
        const auto blockAddress = guest::GuestAddress{state.rip};
        const auto executableVersion = addressSpace_.executableVersion();
        auto &dispatchEntry = dispatchCache_[
            (blockAddress.value >> 1U) & (dispatchCacheSize - 1U)];
        auto *block =
            dispatchEntry.block != nullptr &&
                    dispatchEntry.address == blockAddress.value &&
                    dispatchEntry.executableVersion == executableVersion
                ? dispatchEntry.block
                : cache_.findCurrent(blockAddress, executableVersion);
        if (block == nullptr) {
            const auto translationStart = collectTimings_
                                              ? std::chrono::steady_clock::now()
                                              : std::chrono::steady_clock::time_point{};
            block = &cache_.getOrTranslate(
                blockAddress, codeAt(blockAddress),
                maximumInstructionsPerBlock_, executableVersion);
            if (collectTimings_) {
                translationTime_ += std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - translationStart);
            }
        }
        dispatchEntry = DispatchCacheEntry{blockAddress.value,
                                           executableVersion, block};
        if (sharedCache_ != nullptr && block->executionCount() == 0) {
            if (const auto *image = sharedCache_->imageForAddress(blockAddress);
                image != nullptr &&
                executedCacheImageIndexes_.insert(image->index).second) {
                cacheImageExecutions_.push_back(CacheImageExecution{
                    .image = image,
                    .firstRip = blockAddress,
                    .executedBlock = result.executedBlocks + 1,
                });
            }
        }
        const auto remainingBlocks = maximumBlocks - result.executedBlocks;
        auto batchLimit = remainingBlocks;
        if (block->isOptimizationCandidate()) {
            block->promoteOptimizedLoopIfHot(remainingBlocks);
            batchLimit = block->executionBatchLimit(remainingBlocks);
        }
        const auto execution = block->executeRepeated(
            state, addressSpace_, timestampCounterReader_,
            batchLimit);
        result.executedBlocks += execution.executionCount;
        executedBlocks_ += execution.executionCount;
        block->recordExecutions(execution.executionCount);
        if (execution.executionCount >= recentBlockCapacity) {
            recentBlocks_.fill(blockAddress);
            recentBlockCount_ = recentBlockCapacity;
            nextRecentBlock_ = 0;
        } else {
            for (std::size_t repeated = 0;
                 repeated < execution.executionCount; ++repeated) {
                recentBlocks_[nextRecentBlock_] = blockAddress;
                nextRecentBlock_ =
                    (nextRecentBlock_ + 1) % recentBlockCapacity;
                if (recentBlockCount_ < recentBlockCapacity) {
                    ++recentBlockCount_;
                }
            }
        }

        switch (execution.exit) {
        case BlockExit::Continue:
            break;
        case BlockExit::Call: {
            if (!block->callReturnAddress()) {
                throw std::runtime_error("call block has no return-address metadata");
            }
            if (state.rsp < sizeof(std::uint64_t)) {
                throw std::runtime_error("guest stack underflow while executing call");
            }
            const auto newStackPointer = state.rsp - sizeof(std::uint64_t);
            try {
                addressSpace_.writeU64(guest::GuestAddress{newStackPointer},
                                       block->callReturnAddress()->value);
            } catch (...) {
                state.rip = blockAddress.value;
                throw;
            }
            state.rsp = newStackPointer;
            break;
        }
        case BlockExit::Return: {
            const auto target = addressSpace_.readU64(guest::GuestAddress{state.rsp});
            state.rsp += sizeof(std::uint64_t);
            if (returnSentinel && target == returnSentinel->value) {
                result.translatedBlocks = cache_.size();
                return result;
            }
            state.rip = target;
            break;
        }
        case BlockExit::Syscall: {
            const auto outcome =
                syscallDispatcher_.dispatch(addressSpace_, state,
                                            block->lastInstructionAddress());
            if (outcome.exited) {
                result.translatedBlocks = cache_.size();
                result.exited = true;
                result.exitStatus = outcome.exitStatus;
                return result;
            }
            break;
        }
        case BlockExit::MemoryFault:
            throw std::runtime_error("generated block reported a guest-memory fault without detail");
        case BlockExit::ExecutionFault:
            throw std::runtime_error("generated block reported a guest execution fault without detail");
        }
    }
    throw std::runtime_error("guest block limit reached before exit or return sentinel");
}

} // namespace rosa::dbt
