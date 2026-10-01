#include "dbt/Translator.h"
#include "arm64/Backend.h"
#include "ir/Optimization.h"
#include "x86/Lowering.h"

#include <utility>

namespace rosa::dbt {

TranslatedBlock Translator::translate(std::span<const std::uint8_t> code, guest::GuestAddress start,
                                      std::size_t maximumInstructions) const {
    auto decoded = decoder_.decodeBlock(code, start, maximumInstructions);
    auto intermediate = x86::lowerToIr(decoded);
    ir::optimizeBlock(intermediate);
    auto program = arm64::compile(intermediate, retainProgramListing_);
    return TranslatedBlock(std::move(decoded), std::move(intermediate), std::move(program),
                           executableArena_, maximumInstructions);
}

TranslatedBlock Translator::loadCached(std::vector<std::uint8_t> sourceBytes,
                                       guest::GuestAddress start,
                                       guest::GuestAddress lastInstructionAddress,
                                       std::size_t maximumInstructions, arm64::Program program,
                                       arm64::ExecutableCode executable, bool internalSelfEdge,
                                       std::optional<guest::GuestAddress> callReturnAddress) const {
    return TranslatedBlock(std::move(sourceBytes), start, lastInstructionAddress,
                           maximumInstructions, std::move(program), std::move(executable),
                           internalSelfEdge, callReturnAddress);
}

} // namespace rosa::dbt
