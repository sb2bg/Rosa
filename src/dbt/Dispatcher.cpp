#include "dbt/Dispatcher.h"

#include <algorithm>
#include <stdexcept>

namespace rosa::dbt {

std::vector<BlockExecutionCount>
Dispatcher::hotBlocks(std::size_t minimumExecutions, std::size_t limit) const {
    std::vector<BlockExecutionCount> result;
    result.reserve(blockExecutionCounts_.size());
    for (const auto &[address, count] : blockExecutionCounts_) {
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
    recentBlocks_.clear();
    blockExecutionCounts_.clear();
    while (result.executedBlocks < maximumBlocks) {
        const auto blockAddress = guest::GuestAddress{state.rip};
        auto &block =
            cache_.getOrTranslate(blockAddress, codeAt(blockAddress), maximumInstructionsPerBlock_);
        ++result.executedBlocks;
        ++executedBlocks_;
        ++blockExecutionCounts_[blockAddress.value];
        recentBlocks_.push_back(blockAddress);
        if (recentBlocks_.size() > 16) {
            recentBlocks_.pop_front();
        }

        switch (block.execute(state, &addressSpace_, timestampCounterReader_)) {
        case BlockExit::Continue:
            break;
        case BlockExit::Call: {
            if (!block.callReturnAddress()) {
                throw std::runtime_error("call block has no return-address metadata");
            }
            if (state.rsp < sizeof(std::uint64_t)) {
                throw std::runtime_error("guest stack underflow while executing call");
            }
            const auto newStackPointer = state.rsp - sizeof(std::uint64_t);
            try {
                addressSpace_.writeU64(guest::GuestAddress{newStackPointer},
                                       block.callReturnAddress()->value);
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
                syscallDispatcher_.dispatch(addressSpace_, state, block.decoded().back().address);
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
