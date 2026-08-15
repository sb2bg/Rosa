#include "dbt/Dispatcher.h"

#include <stdexcept>

namespace rosa::dbt {

std::span<const std::uint8_t> Dispatcher::codeAt(guest::GuestAddress address) const {
    return addressSpace_.executableBytes(address);
}

DispatchResult Dispatcher::run(x86::X86State &state, std::size_t maximumBlocks,
                               std::optional<guest::GuestAddress> returnSentinel) {
    DispatchResult result;
    while (result.executedBlocks < maximumBlocks) {
        const auto blockAddress = guest::GuestAddress{state.rip};
        auto &block =
            cache_.getOrTranslate(blockAddress, codeAt(blockAddress), maximumInstructionsPerBlock_);
        ++result.executedBlocks;

        switch (block.execute(state)) {
        case BlockExit::Continue:
            break;
        case BlockExit::Call: {
            if (!block.callReturnAddress()) {
                throw std::runtime_error("call block has no return-address metadata");
            }
            if (state.rsp < sizeof(std::uint64_t)) {
                throw std::runtime_error("guest stack underflow while executing call");
            }
            state.rsp -= sizeof(std::uint64_t);
            addressSpace_.writeU64(guest::GuestAddress{state.rsp},
                                   block.callReturnAddress()->value);
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
        }
    }
    throw std::runtime_error("guest block limit reached before exit or return sentinel");
}

} // namespace rosa::dbt
