#include "arm64/Backend.h"
#include "dbt/RuntimeHelpers.h"
#include "ir/Optimization.h"
#include "x86/Flags.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace rosa::arm64 {
using namespace dbt;
using namespace dbt::runtime;
using namespace x86;
namespace {

template <typename Pointer> arm64::RelocatablePointer pointerBits(Pointer pointer) {
    static_assert(std::is_pointer_v<Pointer>);
    static_assert(sizeof(pointer) == sizeof(std::uint64_t));
    std::uint64_t result = 0;
    std::memcpy(&result, &pointer, sizeof(result));
    return arm64::RelocatablePointer{result};
}

struct ZeroFlagSource {
    ir::ValueId value;
    ir::Width width;
};

std::optional<ZeroFlagSource> zeroFlagSourceForUpdate(const ir::Operation &operation) noexcept {
    switch (operation.opcode) {
    case ir::Opcode::UpdateAddFlags:
        if (operation.third) {
            return ZeroFlagSource{*operation.third, operation.width};
        }
        return std::nullopt;
    case ir::Opcode::UpdateSubFlags:
        if ((operation.width == ir::Width::I8 || operation.width == ir::Width::I64) &&
            operation.third) {
            return ZeroFlagSource{*operation.third, operation.width};
        }
        return std::nullopt;
    case ir::Opcode::UpdateLogicFlags:
        if (operation.lhs) {
            return ZeroFlagSource{*operation.lhs, operation.width};
        }
        return std::nullopt;
    default:
        return std::nullopt;
    }
}

bool isAnyFlagUpdate(ir::Opcode opcode) noexcept {
    switch (opcode) {
    case ir::Opcode::UpdateAddFlags:
    case ir::Opcode::UpdateAdcFlags:
    case ir::Opcode::UpdateSbbFlags:
    case ir::Opcode::UpdateIncFlags:
    case ir::Opcode::UpdateDecFlags:
    case ir::Opcode::UpdateSubFlags:
    case ir::Opcode::UpdateLogicFlags:
    case ir::Opcode::UpdateShiftLeftFlags:
    case ir::Opcode::UpdateShiftRightFlags:
    case ir::Opcode::UpdateShiftRightArithmeticFlags:
    case ir::Opcode::UpdateRotateLeftFlags:
    case ir::Opcode::UpdateRotateRightFlags:
    case ir::Opcode::UpdateMultiplyFlags:
    case ir::Opcode::UpdateSignedMultiplyFlags:
    case ir::Opcode::UpdateShiftRightDoubleFlags:
    case ir::Opcode::UpdateBitTestFlags:
        return true;
    default:
        return false;
    }
}

bool preservesZeroFlagSource(ir::Opcode opcode) noexcept {
    switch (opcode) {
    case ir::Opcode::Constant:
    case ir::Opcode::ReadGuestReg:
    case ir::Opcode::WriteGuestReg:
    case ir::Opcode::Add:
    case ir::Opcode::Sub:
    case ir::Opcode::ShiftLeft:
    case ir::Opcode::ShiftRightLogical:
    case ir::Opcode::ShiftRightArithmetic:
    case ir::Opcode::MultiplyLow:
    case ir::Opcode::MultiplyHighUnsigned:
    case ir::Opcode::MultiplyHighSigned:
    case ir::Opcode::ShiftRightDouble:
    case ir::Opcode::And:
    case ir::Opcode::Or:
    case ir::Opcode::Xor:
    case ir::Opcode::SignExtend32:
    case ir::Opcode::ByteSwap:
    case ir::Opcode::EvaluateCondition:
    case ir::Opcode::ConditionalMoveGuestReg:
        return true;
    default:
        return false;
    }
}

bool fullyReplacesArithmeticFlags(ir::Opcode opcode) noexcept {
    return opcode == ir::Opcode::UpdateAddFlags || opcode == ir::Opcode::UpdateAdcFlags ||
           opcode == ir::Opcode::UpdateSbbFlags || opcode == ir::Opcode::UpdateSubFlags ||
           opcode == ir::Opcode::UpdateLogicFlags;
}

bool isFlagSinkPure(ir::Opcode opcode) noexcept {
    switch (opcode) {
    case ir::Opcode::Constant:
    case ir::Opcode::ReadGuestReg:
    case ir::Opcode::WriteGuestReg:
    case ir::Opcode::Add:
    case ir::Opcode::Sub:
    case ir::Opcode::ShiftLeft:
    case ir::Opcode::ShiftRightLogical:
    case ir::Opcode::ShiftRightArithmetic:
    case ir::Opcode::MultiplyLow:
    case ir::Opcode::MultiplyHighUnsigned:
    case ir::Opcode::MultiplyHighSigned:
    case ir::Opcode::ShiftRightDouble:
    case ir::Opcode::And:
    case ir::Opcode::Or:
    case ir::Opcode::Xor:
    case ir::Opcode::SignExtend32:
    case ir::Opcode::ByteSwap:
        return true;
    default:
        return false;
    }
}

std::optional<std::size_t> logicFlagSinkTarget(const ir::Block &block,
                                               std::size_t updateIndex) noexcept {
    if (updateIndex >= block.operations.size() ||
        block.operations[updateIndex].opcode != ir::Opcode::UpdateLogicFlags) {
        return std::nullopt;
    }
    std::optional<std::size_t> target;
    for (auto index = updateIndex + 1; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        if (isFlagSinkPure(operation.opcode)) {
            continue;
        }
        if (!target && operation.opcode == ir::Opcode::LoadGuest &&
            operation.width == ir::Width::I8) {
            target = index;
            continue;
        }
        if (target && fullyReplacesArithmeticFlags(operation.opcode)) {
            return target;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::size_t> sunkLogicFlagUpdateAt(const ir::Block &block,
                                                 std::size_t loadIndex) noexcept {
    for (std::size_t index = 0; index < loadIndex; ++index) {
        if (logicFlagSinkTarget(block, index) == loadIndex) {
            return index;
        }
    }
    return std::nullopt;
}

std::optional<ZeroFlagSource> zeroFlagSourceAt(const ir::Block &block,
                                               std::size_t operationIndex) noexcept {
    while (operationIndex != 0) {
        const auto &candidate = block.operations[--operationIndex];
        if (isAnyFlagUpdate(candidate.opcode)) {
            return zeroFlagSourceForUpdate(candidate);
        }
        if (!preservesZeroFlagSource(candidate.opcode)) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> zeroFlagUpdateIndexAt(const ir::Block &block,
                                                 std::size_t operationIndex) noexcept {
    while (operationIndex != 0) {
        const auto index = --operationIndex;
        const auto &candidate = block.operations[index];
        if (isAnyFlagUpdate(candidate.opcode)) {
            return zeroFlagSourceForUpdate(candidate) ? std::optional<std::size_t>{index}
                                                      : std::nullopt;
        }
        if (!preservesZeroFlagSource(candidate.opcode)) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> deferredExitFlagUpdate(const ir::Block &block,
                                                  bool internalSelfEdge) noexcept {
    if (!internalSelfEdge || block.operations.empty()) {
        return std::nullopt;
    }
    const auto exitIndex = block.operations.size() - 1;
    const auto &exit = block.operations[exitIndex];
    if (exit.opcode != ir::Opcode::ExitBlock || exit.exitKind != ir::ExitKind::Conditional ||
        !exit.condition) {
        return std::nullopt;
    }
    if (*exit.condition == x86::Condition::ParityEven ||
        *exit.condition == x86::Condition::ParityOdd) {
        // ARM64 NZCV cannot express parity: always materialize guest PF and
        // take the flag-test exit path instead.
        return std::nullopt;
    }
    const auto updateIndex = zeroFlagUpdateIndexAt(block, exitIndex);
    if (!updateIndex) {
        return std::nullopt;
    }
    const auto &update = block.operations[*updateIndex];
    if (update.opcode != ir::Opcode::UpdateSubFlags || update.width != ir::Width::I64) {
        return std::nullopt;
    }
    return updateIndex;
}

bool consumesOnlyZeroFlag(const ir::Operation &operation) noexcept {
    return (operation.opcode == ir::Opcode::EvaluateCondition ||
            operation.opcode == ir::Opcode::ConditionalMoveGuestReg) &&
           operation.condition &&
           (*operation.condition == x86::Condition::Equal ||
            *operation.condition == x86::Condition::NotEqual);
}

std::vector<arm64::XRegister> allocateHostRegisters(const ir::Block &block,
                                                    bool fuseZeroFlagConsumers, bool sinkLogicFlags,
                                                    std::optional<std::size_t> deferredExitUpdate) {
    constexpr std::uint8_t firstRegister = 8;
    constexpr std::size_t registerCount = 8;
    std::vector<std::size_t> lastUses(block.valueCount);
    std::vector<bool> defined(block.valueCount);

    const auto checkValue = [&](ir::ValueId value) {
        if (value.value >= block.valueCount) {
            throw std::runtime_error("R1 register allocation saw an out-of-range IR value");
        }
    };
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        if (operation.result) {
            checkValue(*operation.result);
            defined[operation.result->value] = true;
            lastUses[operation.result->value] = index;
        }
        for (const auto value : {operation.lhs, operation.rhs, operation.third}) {
            if (value) {
                checkValue(*value);
                lastUses[value->value] = std::max(lastUses[value->value], index);
            }
        }
        if (fuseZeroFlagConsumers && consumesOnlyZeroFlag(operation)) {
            if (const auto source = zeroFlagSourceAt(block, index)) {
                checkValue(source->value);
                lastUses[source->value.value] = std::max(lastUses[source->value.value], index);
            }
        }
        if (sinkLogicFlags) {
            if (const auto target = logicFlagSinkTarget(block, index)) {
                if (operation.lhs) {
                    checkValue(*operation.lhs);
                    lastUses[operation.lhs->value] =
                        std::max(lastUses[operation.lhs->value], *target);
                }
            }
        }
    }

    if (deferredExitUpdate) {
        const auto &update = block.operations[*deferredExitUpdate];
        for (const auto value : {update.lhs, update.rhs, update.third}) {
            if (value) {
                checkValue(*value);
                lastUses[value->value] = block.operations.size() - 1;
            }
        }
    }

    std::vector<arm64::XRegister> assignments(block.valueCount);
    std::vector<bool> assigned(block.valueCount);
    std::array<std::optional<ir::ValueId>, registerCount> active;
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        for (auto &value : active) {
            if (value && lastUses[value->value] < index) {
                value.reset();
            }
        }
        const auto result = block.operations[index].result;
        if (!result) {
            continue;
        }
        const auto available =
            std::ranges::find_if(active, [](const auto &value) { return !value; });
        if (available == active.end()) {
            std::ostringstream reason;
            reason << "R1 linear-scan register allocator exhausted x8...x15"
                   << " at guest RIP 0x" << std::hex << block.operations[index].guestRip.value;
            throw std::runtime_error(reason.str());
        }
        const auto slot = static_cast<std::size_t>(std::distance(active.begin(), available));
        *available = *result;
        assignments[result->value] =
            arm64::XRegister{static_cast<std::uint8_t>(firstRegister + slot)};
        assigned[result->value] = true;
    }

    for (std::size_t value = 0; value < defined.size(); ++value) {
        if (defined[value] && !assigned[value]) {
            throw std::runtime_error("R1 register allocation left an IR value unassigned");
        }
    }
    return assignments;
}

bool replacesArithmeticFlags(ir::Opcode opcode) noexcept {
    return fullyReplacesArithmeticFlags(opcode);
}

bool isPureBetweenFlagUpdates(ir::Opcode opcode) noexcept {
    switch (opcode) {
    case ir::Opcode::Constant:
    case ir::Opcode::ReadGuestReg:
    case ir::Opcode::WriteGuestReg:
    case ir::Opcode::Add:
    case ir::Opcode::Sub:
    case ir::Opcode::ShiftLeft:
    case ir::Opcode::ShiftRightLogical:
    case ir::Opcode::ShiftRightArithmetic:
    case ir::Opcode::MultiplyLow:
    case ir::Opcode::MultiplyHighUnsigned:
    case ir::Opcode::MultiplyHighSigned:
    case ir::Opcode::ShiftRightDouble:
    case ir::Opcode::And:
    case ir::Opcode::Or:
    case ir::Opcode::Xor:
    case ir::Opcode::SignExtend32:
    case ir::Opcode::ByteSwap:
        return true;
    default:
        return false;
    }
}

bool isDeadFlagUpdate(const ir::Block &block, std::size_t index,
                      bool fuseZeroFlagConsumers) noexcept {
    if (index >= block.operations.size() ||
        !replacesArithmeticFlags(block.operations[index].opcode)) {
        return false;
    }
    if (fuseZeroFlagConsumers && !zeroFlagSourceForUpdate(block.operations[index])) {
        return false;
    }
    for (++index; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        const auto opcode = operation.opcode;
        if (replacesArithmeticFlags(opcode)) {
            return true;
        }
        if (fuseZeroFlagConsumers && consumesOnlyZeroFlag(operation)) {
            continue;
        }
        if (!isPureBetweenFlagUpdates(opcode)) {
            return false;
        }
    }
    return false;
}

} // namespace

Program compile(const ir::Block &block, bool retainProgramListing) {
    arm64::Assembler assembler(retainProgramListing);
    const auto internalSelfEdge = hasInternalSelfEdge(block);
    // Keep condition consumption and flag-update elimination independently
    // switchable: the former is useful even when precise architectural flags
    // still need to be materialized for a later fault or side exit.
    const bool fuseZeroFlagConsumers = internalSelfEdge;
    const bool eliminateFusedFlagUpdates = fuseZeroFlagConsumers;
    const bool sinkLogicFlags = internalSelfEdge;
    const auto deferredExitUpdate = deferredExitFlagUpdate(block, internalSelfEdge);
    const auto hostRegisters =
        allocateHostRegisters(block, fuseZeroFlagConsumers, sinkLogicFlags, deferredExitUpdate);
    std::vector<std::optional<arm64::XRegister>> pinnedValueRegisters(block.valueCount);
    const auto hostRegister = [&](ir::ValueId value) {
        if (value.value >= hostRegisters.size()) {
            throw std::runtime_error("R1 code generation referenced an unallocated IR value");
        }
        if (pinnedValueRegisters[value.value]) {
            return *pinnedValueRegisters[value.value];
        }
        return hostRegisters[value.value];
    };
    std::vector<const ir::Operation *> definitions(block.valueCount);
    std::vector<std::size_t> definitionIndices(block.valueCount);
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        if (operation.result) {
            definitions[operation.result->value] = &operation;
            definitionIndices[operation.result->value] = index;
        }
    }
    const auto definingOperation = [&](ir::ValueId value) -> const ir::Operation * {
        if (value.value >= definitions.size()) {
            return nullptr;
        }
        return definitions[value.value];
    };
    std::vector<std::size_t> emittedUseCounts(block.valueCount);
    std::vector<std::size_t> emittedLastUses(block.valueCount);
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        if (isDeadFlagUpdate(block, index, eliminateFusedFlagUpdates)) {
            continue;
        }
        const auto &operation = block.operations[index];
        for (const auto value : {operation.lhs, operation.rhs, operation.third}) {
            if (value) {
                ++emittedUseCounts[value->value];
                emittedLastUses[value->value] = index;
            }
        }
    }
    const auto isZeroExtendedDefinition = [](const ir::Operation *definition) {
        return definition != nullptr && definition->width == ir::Width::I32 &&
               (definition->opcode == ir::Opcode::Constant ||
                definition->opcode == ir::Opcode::ReadGuestReg ||
                definition->opcode == ir::Opcode::Add || definition->opcode == ir::Opcode::Sub ||
                definition->opcode == ir::Opcode::And || definition->opcode == ir::Opcode::Or ||
                definition->opcode == ir::Opcode::Xor ||
                definition->opcode == ir::Opcode::LoadGuest);
    };
    std::optional<std::size_t> deferredExitResultOperation;
    if (deferredExitUpdate) {
        const auto &update = block.operations[*deferredExitUpdate];
        if (update.third) {
            const auto *definition = definingOperation(*update.third);
            if (definition != nullptr && definition->opcode == ir::Opcode::Sub &&
                definition->width == ir::Width::I64 && emittedUseCounts[update.third->value] == 1) {
                deferredExitResultOperation = definitionIndices[update.third->value];
            }
        }
    }
    std::vector<bool> foldedImmediate(block.valueCount);
    for (const auto &operation : block.operations) {
        if ((operation.opcode != ir::Opcode::Add && operation.opcode != ir::Opcode::Sub) ||
            (operation.width != ir::Width::I32 && operation.width != ir::Width::I64) ||
            !operation.rhs) {
            continue;
        }
        const auto *definition = definingOperation(*operation.rhs);
        if (definition != nullptr && definition->opcode == ir::Opcode::Constant &&
            definition->immediate <= 0x0FFFU && emittedUseCounts[operation.rhs->value] == 1) {
            foldedImmediate[operation.rhs->value] = true;
        }
    }
    const auto constantMaterializationCost = [](std::uint64_t value) {
        std::size_t movzCost = 0;
        std::size_t movnCost = 0;
        for (std::uint32_t shift = 0; shift < 64; shift += 16) {
            const auto halfword = static_cast<std::uint16_t>(value >> shift);
            movzCost += halfword != 0;
            movnCost += halfword != UINT16_MAX;
        }
        return std::max<std::size_t>(1, std::min(movzCost, movnCost));
    };
    std::optional<ir::ValueId> pinnedLoopConstant;
    std::size_t pinnedLoopConstantCost{};
    if (internalSelfEdge && deferredExitUpdate) {
        for (const auto &operation : block.operations) {
            if (operation.opcode != ir::Opcode::Constant || !operation.result ||
                foldedImmediate[operation.result->value] ||
                emittedUseCounts[operation.result->value] == 0) {
                continue;
            }
            const auto value = operation.width == ir::Width::I32 ? operation.immediate & UINT32_MAX
                                                                 : operation.immediate;
            const auto cost = constantMaterializationCost(value);
            if (cost > pinnedLoopConstantCost) {
                pinnedLoopConstant = *operation.result;
                pinnedLoopConstantCost = cost;
            }
        }
    }
    if (pinnedLoopConstant) {
        pinnedValueRegisters[pinnedLoopConstant->value] = arm64::x24;
    }
    const auto pinsDirectRead =
        internalSelfEdge && std::ranges::any_of(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::LoadGuest && operation.width == ir::Width::I8;
        });
    const auto pinsDirectWrite =
        internalSelfEdge && !pinsDirectRead &&
        std::ranges::any_of(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::StoreGuest && operation.width == ir::Width::I8;
        });
    const auto mayStopRepeating =
        internalSelfEdge && std::ranges::any_of(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::StoreGuest;
        });
    const auto canPinCallerSavedGuestRegisters =
        (pinsDirectRead || pinsDirectWrite) &&
        std::ranges::all_of(block.operations, [](const auto &operation) {
            switch (operation.opcode) {
            case ir::Opcode::Constant:
            case ir::Opcode::ReadGuestReg:
            case ir::Opcode::WriteGuestReg:
            case ir::Opcode::Add:
            case ir::Opcode::Sub:
            case ir::Opcode::And:
            case ir::Opcode::Or:
            case ir::Opcode::Xor:
            case ir::Opcode::EvaluateCondition:
            case ir::Opcode::ConditionalMoveGuestReg:
            case ir::Opcode::ExitBlock:
                return true;
            case ir::Opcode::LoadGuest:
            case ir::Opcode::StoreGuest:
                return operation.width == ir::Width::I8;
            case ir::Opcode::UpdateAddFlags:
            case ir::Opcode::UpdateLogicFlags:
                return true;
            case ir::Opcode::UpdateSubFlags:
                return operation.width == ir::Width::I8 || operation.width == ir::Width::I64;
            default:
                return false;
            }
        });
    std::array<std::size_t, 16> guestRegisterUses{};
    if (internalSelfEdge) {
        for (const auto &operation : block.operations) {
            if (operation.guestRegister &&
                (operation.opcode == ir::Opcode::ReadGuestReg ||
                 operation.opcode == ir::Opcode::WriteGuestReg ||
                 operation.opcode == ir::Opcode::ConditionalMoveGuestReg)) {
                ++guestRegisterUses[static_cast<std::size_t>(*operation.guestRegister)];
            }
        }
    }
    std::array<std::optional<arm64::XRegister>, 16> pinnedGuestRegisters;
    std::array<std::optional<arm64::XRegister>, 7> pinCandidates{
        arm64::x26, arm64::x27, arm64::x28, std::nullopt, std::nullopt, std::nullopt, std::nullopt};
    if (canPinCallerSavedGuestRegisters) {
        pinCandidates[3] = arm64::x5;
        pinCandidates[4] = arm64::x6;
        pinCandidates[5] = arm64::x7;
        pinCandidates[6] = arm64::x30;
    }
    for (const auto candidate : pinCandidates) {
        if (!candidate) {
            continue;
        }
        const auto mostUsed = std::ranges::max_element(guestRegisterUses);
        if (mostUsed == guestRegisterUses.end() || *mostUsed == 0) {
            break;
        }
        const auto index =
            static_cast<std::size_t>(std::distance(guestRegisterUses.begin(), mostUsed));
        pinnedGuestRegisters[index] = *candidate;
        *mostUsed = 0;
    }
    const auto pinnedGuestRegister = [&](x86::Register guestRegister) {
        return pinnedGuestRegisters[static_cast<std::size_t>(guestRegister)];
    };
    const auto nextGuestWrite = [&](std::size_t operationIndex, x86::Register guestRegister) {
        for (auto index = operationIndex + 1; index < block.operations.size(); ++index) {
            const auto &candidate = block.operations[index];
            if (candidate.guestRegister == guestRegister &&
                (candidate.opcode == ir::Opcode::WriteGuestReg ||
                 candidate.opcode == ir::Opcode::ConditionalMoveGuestReg)) {
                return index;
            }
        }
        return block.operations.size();
    };
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        if (!operation.guestRegister) {
            continue;
        }
        const auto pinned = pinnedGuestRegister(*operation.guestRegister);
        if (!pinned) {
            continue;
        }
        if (operation.opcode == ir::Opcode::ReadGuestReg && operation.result) {
            if (emittedLastUses[operation.result->value] <=
                nextGuestWrite(index, *operation.guestRegister)) {
                pinnedValueRegisters[operation.result->value] = *pinned;
            }
            continue;
        }
        if (operation.opcode != ir::Opcode::WriteGuestReg || !operation.lhs ||
            (operation.width != ir::Width::I64 &&
             !isZeroExtendedDefinition(definingOperation(*operation.lhs)))) {
            continue;
        }
        const auto source = *operation.lhs;
        const auto nextWrite = nextGuestWrite(index, *operation.guestRegister);
        if (emittedLastUses[source.value] > nextWrite ||
            (pinnedValueRegisters[source.value] &&
             pinnedValueRegisters[source.value]->encoding != pinned->encoding)) {
            continue;
        }
        const auto definitionIndex = definitionIndices[source.value];
        const auto interferes = [&] {
            for (std::size_t value = 0; value < pinnedValueRegisters.size(); ++value) {
                if (pinnedValueRegisters[value] &&
                    pinnedValueRegisters[value]->encoding == pinned->encoding &&
                    emittedLastUses[value] > definitionIndex) {
                    return true;
                }
            }
            return false;
        }();
        if (!interferes) {
            pinnedValueRegisters[source.value] = *pinned;
        }
    }
    const auto hasPinnedGuestRegisters = std::ranges::any_of(
        pinnedGuestRegisters, [](const auto &value) { return value.has_value(); });
    std::vector<bool> promotesNarrowGuestWrite(block.operations.size());
    std::array<bool, 16> guestRegisterKnownZero{};
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        if (operation.opcode == ir::Opcode::WriteGuestReg && operation.guestRegister &&
            operation.lhs) {
            const auto guestIndex = static_cast<std::size_t>(*operation.guestRegister);
            const auto *definition = definingOperation(*operation.lhs);
            if ((operation.width == ir::Width::I32 || operation.width == ir::Width::I64) &&
                definition != nullptr && definition->opcode == ir::Opcode::Constant &&
                definition->immediate == 0) {
                guestRegisterKnownZero[guestIndex] = true;
            } else if (operation.width == ir::Width::I8 && guestRegisterKnownZero[guestIndex] &&
                       definition != nullptr &&
                       definition->opcode == ir::Opcode::EvaluateCondition) {
                promotesNarrowGuestWrite[index] = true;
                guestRegisterKnownZero[guestIndex] = false;
            } else {
                guestRegisterKnownZero[guestIndex] = false;
            }
        } else if (operation.opcode == ir::Opcode::ConditionalMoveGuestReg &&
                   operation.guestRegister) {
            guestRegisterKnownZero[static_cast<std::size_t>(*operation.guestRegister)] = false;
        } else if (operation.opcode == ir::Opcode::Push ||
                   operation.opcode == ir::Opcode::RepeatMoveByte ||
            operation.opcode == ir::Opcode::RepeatStore ||
                   operation.opcode == ir::Opcode::DivideUnsignedByte ||
                   operation.opcode == ir::Opcode::DivideUnsignedDword ||
                   operation.opcode == ir::Opcode::DivideUnsignedQword ||
                   operation.opcode == ir::Opcode::DivideSignedDword) {
            guestRegisterKnownZero.fill(false);
        }
    }
    struct DirectReadSpan {
        std::size_t firstLoadOperationIndex{};
        ir::ValueId address;
        ir::ValueId induction;
        std::uint16_t step{};
        std::uint16_t maximumOffset{};
        std::uint64_t limit{};
    };
    std::optional<DirectReadSpan> directReadSpan;
    struct AdjacentDirectRead {
        bool first{};
        std::uint16_t offset{};
        std::uint16_t maximumOffset{};
    };
    std::vector<std::optional<AdjacentDirectRead>> adjacentDirectReads(block.operations.size());
    if (canPinCallerSavedGuestRegisters && pinsDirectRead) {
        struct ReadCandidate {
            std::size_t operationIndex{};
            ir::ValueId root;
            std::uint64_t offset{};
        };
        std::vector<ReadCandidate> candidates;
        for (std::size_t index = 0; index < block.operations.size(); ++index) {
            const auto &operation = block.operations[index];
            if (operation.opcode != ir::Opcode::LoadGuest || operation.width != ir::Width::I8 ||
                !operation.lhs) {
                continue;
            }
            auto root = *operation.lhs;
            std::uint64_t offset{};
            while (const auto *definition = definingOperation(root)) {
                if (definition->opcode != ir::Opcode::Add || definition->width != ir::Width::I64 ||
                    !definition->lhs || !definition->rhs) {
                    break;
                }
                const auto *rhs = definingOperation(*definition->rhs);
                if (rhs == nullptr || rhs->opcode != ir::Opcode::Constant ||
                    rhs->immediate > UINT16_MAX - offset) {
                    break;
                }
                offset += rhs->immediate;
                root = *definition->lhs;
            }
            candidates.push_back(ReadCandidate{index, root, offset});
        }
        for (const auto &first : candidates) {
            if (first.offset != 0) {
                continue;
            }
            std::vector<ReadCandidate> group;
            for (const auto &candidate : candidates) {
                if (candidate.operationIndex >= first.operationIndex &&
                    candidate.root == first.root && candidate.offset <= 0x0FFFU) {
                    group.push_back(candidate);
                }
            }
            if (group.size() < 2) {
                continue;
            }
            const auto lastIndex = group.back().operationIndex;
            const auto keepsScratchRegisters = [&] {
                for (auto index = first.operationIndex + 1; index < lastIndex; ++index) {
                    const auto &operation = block.operations[index];
                    if (operation.opcode == ir::Opcode::LoadGuest &&
                        std::ranges::none_of(group, [&](const auto &member) {
                            return member.operationIndex == index;
                        })) {
                        return false;
                    }
                    if (isAnyFlagUpdate(operation.opcode) &&
                        !isDeadFlagUpdate(block, index, eliminateFusedFlagUpdates) &&
                        !(sinkLogicFlags && logicFlagSinkTarget(block, index)) &&
                        deferredExitUpdate != index) {
                        return false;
                    }
                }
                return true;
            }();
            if (!keepsScratchRegisters) {
                continue;
            }
            const auto maximumOffset = std::ranges::max_element(
                group, {}, [](const auto &candidate) { return candidate.offset; });
            adjacentDirectReads[first.operationIndex] =
                AdjacentDirectRead{true, 0, static_cast<std::uint16_t>(maximumOffset->offset)};
            for (std::size_t memberIndex = 1; memberIndex < group.size(); ++memberIndex) {
                const auto &candidate = group[memberIndex];
                adjacentDirectReads[candidate.operationIndex] =
                    AdjacentDirectRead{false, static_cast<std::uint16_t>(candidate.offset), 0};
            }
            if (deferredExitUpdate) {
                const auto &exit = block.operations.back();
                const auto &update = block.operations[*deferredExitUpdate];
                const auto *limit = update.rhs ? definingOperation(*update.rhs) : nullptr;
                const auto *address = definingOperation(first.root);
                if (exit.opcode == ir::Opcode::ExitBlock &&
                    exit.exitKind == ir::ExitKind::Conditional &&
                    exit.condition == x86::Condition::NotEqual && exit.target &&
                    *exit.target == block.start && update.opcode == ir::Opcode::UpdateSubFlags &&
                    update.width == ir::Width::I64 && limit != nullptr &&
                    limit->opcode == ir::Opcode::Constant && limit->immediate != 0 &&
                    address != nullptr && address->opcode == ir::Opcode::Add &&
                    address->width == ir::Width::I64 && address->lhs && address->rhs) {
                    for (const auto [induction, offset] :
                         {std::pair{*address->lhs, *address->rhs},
                          std::pair{*address->rhs, *address->lhs}}) {
                        const auto *inductionRead = definingOperation(induction);
                        const auto *offsetRead = definingOperation(offset);
                        if (inductionRead == nullptr || offsetRead == nullptr ||
                            inductionRead->opcode != ir::Opcode::ReadGuestReg ||
                            offsetRead->opcode != ir::Opcode::ReadGuestReg ||
                            inductionRead->width != ir::Width::I64 ||
                            offsetRead->width != ir::Width::I64 || !inductionRead->guestRegister ||
                            !offsetRead->guestRegister) {
                            continue;
                        }
                        const auto offsetChanges =
                            std::ranges::any_of(block.operations, [&](const auto &operation) {
                                return operation.guestRegister == offsetRead->guestRegister &&
                                       (operation.opcode == ir::Opcode::WriteGuestReg ||
                                        operation.opcode == ir::Opcode::ConditionalMoveGuestReg);
                            });
                        if (offsetChanges) {
                            continue;
                        }
                        for (auto writeIndex = lastIndex + 1; writeIndex < block.operations.size();
                             ++writeIndex) {
                            const auto &write = block.operations[writeIndex];
                            if (write.opcode != ir::Opcode::WriteGuestReg ||
                                write.guestRegister != inductionRead->guestRegister ||
                                write.width != ir::Width::I64 || !write.lhs ||
                                update.lhs != write.lhs) {
                                continue;
                            }
                            const auto *increment = definingOperation(*write.lhs);
                            if (increment == nullptr || increment->opcode != ir::Opcode::Add ||
                                increment->width != ir::Width::I64 || !increment->lhs ||
                                !increment->rhs) {
                                continue;
                            }
                            const auto stepValue = *increment->lhs == induction   ? increment->rhs
                                                   : *increment->rhs == induction ? increment->lhs
                                                                                  : std::nullopt;
                            const auto *step = stepValue ? definingOperation(*stepValue) : nullptr;
                            if (step == nullptr || step->opcode != ir::Opcode::Constant ||
                                step->immediate == 0 || step->immediate > 0x0FFFU) {
                                continue;
                            }
                            directReadSpan = DirectReadSpan{
                                first.operationIndex,
                                first.root,
                                induction,
                                static_cast<std::uint16_t>(step->immediate),
                                static_cast<std::uint16_t>(maximumOffset->offset),
                                limit->immediate,
                            };
                            break;
                        }
                        if (directReadSpan) {
                            break;
                        }
                    }
                }
            }
            break;
        }
    }
    struct DirectWriteSpan {
        std::size_t storeOperationIndex{};
        ir::ValueId address;
        ir::ValueId addressLhs;
        ir::ValueId addressRhs;
        ir::ValueId induction;
        ir::ValueId offset;
        arm64::XRegister step;
        std::uint64_t limit{};
    };
    std::optional<DirectWriteSpan> directWriteSpan;
    const auto directByteStoreCount =
        std::ranges::count_if(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::StoreGuest && operation.width == ir::Width::I8;
        });
    if (canPinCallerSavedGuestRegisters && pinsDirectWrite && deferredExitUpdate &&
        directByteStoreCount == 1) {
        const auto &exit = block.operations.back();
        const auto &update = block.operations[*deferredExitUpdate];
        const auto *limit = update.rhs ? definingOperation(*update.rhs) : nullptr;
        for (std::size_t storeIndex = 0; storeIndex < block.operations.size() && !directWriteSpan;
             ++storeIndex) {
            const auto &store = block.operations[storeIndex];
            if (store.opcode != ir::Opcode::StoreGuest || store.width != ir::Width::I8 ||
                !store.lhs) {
                continue;
            }
            const auto *address = definingOperation(*store.lhs);
            if (address == nullptr || address->opcode != ir::Opcode::Add ||
                address->width != ir::Width::I64 || !address->lhs || !address->rhs ||
                exit.opcode != ir::Opcode::ExitBlock ||
                exit.exitKind != ir::ExitKind::Conditional ||
                exit.condition != x86::Condition::Below || !exit.target ||
                *exit.target != block.start || limit == nullptr ||
                limit->opcode != ir::Opcode::Constant || limit->immediate == 0) {
                continue;
            }
            for (const auto [induction, offset] : {std::pair{*address->lhs, *address->rhs},
                                                   std::pair{*address->rhs, *address->lhs}}) {
                const auto *inductionRead = definingOperation(induction);
                const auto *offsetRead = definingOperation(offset);
                if (inductionRead == nullptr || offsetRead == nullptr ||
                    inductionRead->opcode != ir::Opcode::ReadGuestReg ||
                    offsetRead->opcode != ir::Opcode::ReadGuestReg ||
                    inductionRead->width != ir::Width::I64 || offsetRead->width != ir::Width::I64 ||
                    !inductionRead->guestRegister || !offsetRead->guestRegister) {
                    continue;
                }
                const auto offsetChanges =
                    std::ranges::any_of(block.operations, [&](const auto &operation) {
                        return operation.guestRegister == offsetRead->guestRegister &&
                               (operation.opcode == ir::Opcode::WriteGuestReg ||
                                operation.opcode == ir::Opcode::ConditionalMoveGuestReg);
                    });
                if (offsetChanges) {
                    continue;
                }
                for (std::size_t writeIndex = storeIndex + 1; writeIndex < block.operations.size();
                     ++writeIndex) {
                    const auto &write = block.operations[writeIndex];
                    if (write.opcode != ir::Opcode::WriteGuestReg ||
                        write.guestRegister != inductionRead->guestRegister ||
                        write.width != ir::Width::I64 || !write.lhs || update.lhs != write.lhs) {
                        continue;
                    }
                    const auto *increment = definingOperation(*write.lhs);
                    if (increment == nullptr || increment->opcode != ir::Opcode::Add ||
                        increment->width != ir::Width::I64 || !increment->lhs || !increment->rhs) {
                        continue;
                    }
                    const auto stepValue = *increment->lhs == induction   ? increment->rhs
                                           : *increment->rhs == induction ? increment->lhs
                                                                          : std::nullopt;
                    const auto *stepRead = stepValue ? definingOperation(*stepValue) : nullptr;
                    if (stepRead == nullptr || stepRead->opcode != ir::Opcode::ReadGuestReg ||
                        !stepRead->guestRegister) {
                        continue;
                    }
                    const auto step = pinnedGuestRegister(*stepRead->guestRegister);
                    if (!step) {
                        continue;
                    }
                    directWriteSpan =
                        DirectWriteSpan{storeIndex, *store.lhs, *address->lhs, *address->rhs,
                                        induction,  offset,     *step,         limit->immediate};
                    break;
                }
                if (directWriteSpan) {
                    break;
                }
            }
        }
    }
    const auto pinnedDirectCacheOffset = pinsDirectRead
                                             ? offsetof(GuestExecutionContext, directRead)
                                             : offsetof(GuestExecutionContext, directWrite);
    bool hasHelperCall = false;
    bool hasExecutionContextCall = false;
    for (const auto &operation : block.operations) {
        hasHelperCall |=
            operation.opcode == ir::Opcode::UpdateAdcFlags ||
            operation.opcode == ir::Opcode::UpdateSbbFlags ||
            operation.opcode == ir::Opcode::UpdateIncFlags ||
            (operation.opcode == ir::Opcode::UpdateDecFlags && operation.width != ir::Width::I64) ||
            (operation.opcode == ir::Opcode::UpdateSubFlags && operation.width != ir::Width::I8 &&
             operation.width != ir::Width::I64) ||
            operation.opcode == ir::Opcode::UpdateShiftLeftFlags ||
            operation.opcode == ir::Opcode::UpdateShiftRightFlags ||
            operation.opcode == ir::Opcode::UpdateShiftRightArithmeticFlags ||
            operation.opcode == ir::Opcode::UpdateRotateLeftFlags ||
            operation.opcode == ir::Opcode::UpdateRotateRightFlags ||
            operation.opcode == ir::Opcode::UpdateMultiplyFlags ||
            operation.opcode == ir::Opcode::UpdateSignedMultiplyFlags ||
            operation.opcode == ir::Opcode::UpdateShiftRightDoubleFlags ||
            operation.opcode == ir::Opcode::UpdateBitTestFlags ||
            operation.opcode == ir::Opcode::Push ||
            operation.opcode == ir::Opcode::AddGuestMemory ||
            operation.opcode == ir::Opcode::SubGuestMemory ||
            operation.opcode == ir::Opcode::OrGuestMemory ||
            operation.opcode == ir::Opcode::AndGuestMemory ||
            operation.opcode == ir::Opcode::ShiftLeftGuestMemory ||
            operation.opcode == ir::Opcode::ShiftRightGuestMemory ||
            operation.opcode == ir::Opcode::IncrementGuestMemory ||
            operation.opcode == ir::Opcode::DecrementGuestMemory ||
            operation.opcode == ir::Opcode::CompareExchangeGuestMemory ||
            operation.opcode == ir::Opcode::CompareExchangeGuestPair ||
            operation.opcode == ir::Opcode::ExchangeGuestMemory ||
            operation.opcode == ir::Opcode::LockedAddGuestMemory ||
            operation.opcode == ir::Opcode::LockedExchangeAddGuestMemory ||
            operation.opcode == ir::Opcode::LockedIncrementGuestMemory ||
            operation.opcode == ir::Opcode::LockedDecrementGuestMemory ||
            operation.opcode == ir::Opcode::LockedOrGuestMemory ||
            operation.opcode == ir::Opcode::LockedBitSetGuestMemory ||
            operation.opcode == ir::Opcode::LockedAndGuestMemory ||
            operation.opcode == ir::Opcode::StoreGuestIdtr ||
            operation.opcode == ir::Opcode::StoreGuest ||
            operation.opcode == ir::Opcode::StoreGuestXmm ||
            operation.opcode == ir::Opcode::StoreGuestYmm ||
            operation.opcode == ir::Opcode::LoadGuestXmm ||
            operation.opcode == ir::Opcode::LoadGuestYmm ||
            operation.opcode == ir::Opcode::LoadGuestSignExtendedBytesXmm ||
            operation.opcode == ir::Opcode::LoadGuestSignExtendedDwordsXmm ||
            operation.opcode == ir::Opcode::XorGuestMemoryXmm ||
            operation.opcode == ir::Opcode::AndGuestMemoryXmm ||
            operation.opcode == ir::Opcode::AddGuestMemoryXmm ||
            operation.opcode == ir::Opcode::TestXmmBits ||
            operation.opcode == ir::Opcode::CompareEqualGuestBytesXmm ||
            operation.opcode == ir::Opcode::CompareEqualGuestQwordsXmm ||
            operation.opcode == ir::Opcode::ArithmeticGuestMemoryPackedDoubleXmm ||
            operation.opcode == ir::Opcode::UnpackHighGuestPackedSingleXmm ||
            operation.opcode == ir::Opcode::HorizontalAddGuestPackedDoubleXmm ||
            operation.opcode == ir::Opcode::UnpackLowGuestPackedSingleXmm ||
            operation.opcode == ir::Opcode::CompareEqualXmmBytes ||
            operation.opcode == ir::Opcode::CompareEqualXmmDwords ||
            operation.opcode == ir::Opcode::CompareEqualXmmQwords ||
            operation.opcode == ir::Opcode::ShiftLeftXmmDwords ||
            operation.opcode == ir::Opcode::AddXmmWords ||
            operation.opcode == ir::Opcode::ComparePackedDoubleXmm ||
            operation.opcode == ir::Opcode::ArithmeticPackedDoubleXmm ||
            operation.opcode == ir::Opcode::UnpackHighPackedSingleXmm ||
            operation.opcode == ir::Opcode::HorizontalAddPackedDoubleXmm ||
            operation.opcode == ir::Opcode::UnpackLowPackedSingleXmm ||
            operation.opcode == ir::Opcode::UpdateUnorderedDoubleFlags ||
            operation.opcode == ir::Opcode::UpdateUnorderedFloatFlags ||
            operation.opcode == ir::Opcode::ConvertIntToDoubleXmm ||
            operation.opcode == ir::Opcode::ConvertDoubleToInt ||
            operation.opcode == ir::Opcode::ConvertFloatToDoubleXmm ||
            operation.opcode == ir::Opcode::ConvertInt32x2ToDoubleXmm ||
            operation.opcode == ir::Opcode::ScalarDoubleXmm ||
            operation.opcode == ir::Opcode::AddXmmDwords ||
            operation.opcode == ir::Opcode::HorizontalAddXmmDwords ||
            operation.opcode == ir::Opcode::AndNotXmm ||
            operation.opcode == ir::Opcode::MoveXmmByteMask ||
            operation.opcode == ir::Opcode::ShuffleXmmBytes ||
            operation.opcode == ir::Opcode::ShuffleXmmDwords ||
            operation.opcode == ir::Opcode::AlignRightXmmBytes ||
            operation.opcode == ir::Opcode::BlendXmmWords ||
            operation.opcode == ir::Opcode::UnpackLowXmmWords ||
            operation.opcode == ir::Opcode::BitScanForward ||
            operation.opcode == ir::Opcode::BitScanReverse ||
            operation.opcode == ir::Opcode::RepeatMoveByte ||
            operation.opcode == ir::Opcode::RepeatStore ||
            operation.opcode == ir::Opcode::DivideUnsignedByte ||
            operation.opcode == ir::Opcode::DivideUnsignedDword ||
            operation.opcode == ir::Opcode::DivideUnsignedQword ||
            operation.opcode == ir::Opcode::DivideSignedDword ||
            operation.opcode == ir::Opcode::LoadGuest ||
            operation.opcode == ir::Opcode::ReadTimestampCounter ||
            operation.opcode == ir::Opcode::Cpuid;
        hasExecutionContextCall |=
            operation.opcode == ir::Opcode::Push ||
            operation.opcode == ir::Opcode::DivideUnsignedByte ||
            operation.opcode == ir::Opcode::DivideUnsignedDword ||
            operation.opcode == ir::Opcode::DivideUnsignedQword ||
            operation.opcode == ir::Opcode::DivideSignedDword ||
            operation.opcode == ir::Opcode::AddGuestMemory ||
            operation.opcode == ir::Opcode::SubGuestMemory ||
            operation.opcode == ir::Opcode::OrGuestMemory ||
            operation.opcode == ir::Opcode::AndGuestMemory ||
            operation.opcode == ir::Opcode::ShiftLeftGuestMemory ||
            operation.opcode == ir::Opcode::ShiftRightGuestMemory ||
            operation.opcode == ir::Opcode::IncrementGuestMemory ||
            operation.opcode == ir::Opcode::DecrementGuestMemory ||
            operation.opcode == ir::Opcode::CompareExchangeGuestMemory ||
            operation.opcode == ir::Opcode::CompareExchangeGuestPair ||
            operation.opcode == ir::Opcode::ExchangeGuestMemory ||
            operation.opcode == ir::Opcode::LockedAddGuestMemory ||
            operation.opcode == ir::Opcode::LockedExchangeAddGuestMemory ||
            operation.opcode == ir::Opcode::LockedIncrementGuestMemory ||
            operation.opcode == ir::Opcode::LockedDecrementGuestMemory ||
            operation.opcode == ir::Opcode::LockedOrGuestMemory ||
            operation.opcode == ir::Opcode::LockedBitSetGuestMemory ||
            operation.opcode == ir::Opcode::LockedAndGuestMemory ||
            operation.opcode == ir::Opcode::StoreGuestIdtr ||
            operation.opcode == ir::Opcode::StoreGuest ||
            operation.opcode == ir::Opcode::StoreGuestXmm ||
            operation.opcode == ir::Opcode::StoreGuestYmm ||
            operation.opcode == ir::Opcode::LoadGuestXmm ||
            operation.opcode == ir::Opcode::LoadGuestYmm ||
            operation.opcode == ir::Opcode::LoadGuestSignExtendedBytesXmm ||
            operation.opcode == ir::Opcode::LoadGuestSignExtendedDwordsXmm ||
            operation.opcode == ir::Opcode::XorGuestMemoryXmm ||
            operation.opcode == ir::Opcode::AndGuestMemoryXmm ||
            operation.opcode == ir::Opcode::AddGuestMemoryXmm ||
            operation.opcode == ir::Opcode::CompareEqualGuestBytesXmm ||
            operation.opcode == ir::Opcode::CompareEqualGuestQwordsXmm ||
            operation.opcode == ir::Opcode::ArithmeticGuestMemoryPackedDoubleXmm ||
            operation.opcode == ir::Opcode::UnpackHighGuestPackedSingleXmm ||
            operation.opcode == ir::Opcode::HorizontalAddGuestPackedDoubleXmm ||
            operation.opcode == ir::Opcode::UnpackLowGuestPackedSingleXmm ||
            (operation.opcode == ir::Opcode::ShuffleXmmBytes && operation.lhs.has_value()) ||
            operation.opcode == ir::Opcode::RepeatMoveByte ||
            operation.opcode == ir::Opcode::RepeatStore ||
            operation.opcode == ir::Opcode::LoadGuest ||
            operation.opcode == ir::Opcode::ReadTimestampCounter;
    }
    hasExecutionContextCall |= internalSelfEdge;
    if (hasHelperCall) {
        assembler.pushFrameRecord();
    }
    if (hasExecutionContextCall) {
        if (internalSelfEdge) {
            assembler.pushCalleeSaved19Through24();
            if (hasPinnedGuestRegisters) {
                assembler.pushCalleeSaved25Through28();
            }
        } else {
            assembler.pushCalleeSaved19Through22();
        }
        assembler.mov(arm64::x19, arm64::x1);
        if (internalSelfEdge) {
            if (hasPinnedGuestRegisters) {
                assembler.mov(arm64::x25, arm64::x0);
                for (std::size_t index = 0; index < pinnedGuestRegisters.size(); ++index) {
                    if (pinnedGuestRegisters[index]) {
                        assembler.ldr(*pinnedGuestRegisters[index], arm64::x25,
                                      static_cast<std::uint32_t>(
                                          x86::registerOffset(static_cast<x86::Register>(index))));
                    }
                }
            }
            assembler.ldr(arm64::x23, arm64::x19,
                          static_cast<std::uint32_t>(
                              offsetof(GuestExecutionContext, remainingBlockExecutions)));
            if (pinnedLoopConstant) {
                const auto *definition = definingOperation(*pinnedLoopConstant);
                assembler.movImmediate(arm64::x24, definition->width == ir::Width::I32
                                                       ? definition->immediate & UINT32_MAX
                                                       : definition->immediate);
            } else {
                assembler.movImmediate(arm64::x24, block.start.value);
            }
        }
        if (pinsDirectRead || pinsDirectWrite) {
            assembler.ldr(arm64::x20, arm64::x19,
                          static_cast<std::uint32_t>(pinnedDirectCacheOffset +
                                                     offsetof(DirectGuestMemoryCache, bytes)));
            assembler.ldr(arm64::x21, arm64::x19,
                          static_cast<std::uint32_t>(pinnedDirectCacheOffset +
                                                     offsetof(DirectGuestMemoryCache, base)));
            assembler.ldr(arm64::x22, arm64::x19,
                          static_cast<std::uint32_t>(pinnedDirectCacheOffset +
                                                     offsetof(DirectGuestMemoryCache, size)));
        }
        if (directWriteSpan) {
            assembler.movImmediate(arm64::x4, 0);
        }
    }
    const auto repeatedEntry = assembler.makeLabel();
    assembler.bind(repeatedEntry);
    std::optional<arm64::Label> directReadFastEntry;
    std::optional<arm64::Label> directWriteFastEntry;

    const auto emitEpilogue = [&] {
        if (hasExecutionContextCall) {
            if (internalSelfEdge) {
                if (hasPinnedGuestRegisters) {
                    for (std::size_t index = 0; index < pinnedGuestRegisters.size(); ++index) {
                        if (pinnedGuestRegisters[index]) {
                            assembler.str(*pinnedGuestRegisters[index], arm64::x25,
                                          static_cast<std::uint32_t>(x86::registerOffset(
                                              static_cast<x86::Register>(index))));
                        }
                    }
                    assembler.popCalleeSaved25Through28();
                }
                assembler.str(arm64::x23, arm64::x19,
                              static_cast<std::uint32_t>(
                                  offsetof(GuestExecutionContext, remainingBlockExecutions)));
                assembler.popCalleeSaved19Through24();
            } else {
                assembler.popCalleeSaved19Through22();
            }
        }
        if (hasHelperCall) {
            assembler.popFrameRecord();
        }
    };

    // Fault paths share state restoration and precise instruction provenance.
    // Record the RIP only after failure, keeping successful helper calls unchanged.
    const auto emitFaultExit = [&](BlockExit exit, guest::GuestAddress rip) {
        assembler.movImmediate(arm64::x16, rip.value);
        assembler.str(arm64::x16, arm64::x19,
                      static_cast<std::uint32_t>(offsetof(GuestExecutionContext, faultRip)));
        emitEpilogue();
        assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(exit));
        assembler.ret();
    };

    const auto emitStopRepeatingCheck = [&](arm64::Label returnToDispatcher) {
        if (!mayStopRepeating) {
            return;
        }
        if (pinsDirectWrite) {
            const auto directMapping = assembler.makeLabel();
            assembler.cbnz(arm64::x20, directMapping);
            assembler.ldr(
                arm64::x1, arm64::x19,
                static_cast<std::uint32_t>(offsetof(GuestExecutionContext, stopRepeating)));
            assembler.cbnz(arm64::x1, returnToDispatcher);
            assembler.bind(directMapping);
            return;
        }
        assembler.ldr(arm64::x1, arm64::x19,
                      static_cast<std::uint32_t>(offsetof(GuestExecutionContext, stopRepeating)));
        assembler.cbnz(arm64::x1, returnToDispatcher);
    };

    const auto emitLogicFlags = [&](arm64::XRegister result, ir::Width width) {
        const auto parityDone = assembler.makeLabel();
        const auto zeroDone = assembler.makeLabel();
        const auto signBit = width == ir::Width::I8    ? 7U
                             : width == ir::Width::I16 ? 15U
                             : width == ir::Width::I32 ? 31U
                                                       : 63U;

        if (width == ir::Width::I64) {
            assembler.mov(arm64::x1, result);
        } else {
            const auto valueMask = width == ir::Width::I8    ? std::uint64_t{UINT8_MAX}
                                   : width == ir::Width::I16 ? std::uint64_t{UINT16_MAX}
                                                             : std::uint64_t{UINT32_MAX};
            assembler.movImmediate(arm64::x17, valueMask);
            assembler.bitAnd(arm64::x1, result, arm64::x17);
        }

        assembler.ldr(arm64::x16, arm64::x0,
                      static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
        assembler.movImmediate(arm64::x17, ~arithmeticFlagMask);
        assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
        assembler.movImmediate(arm64::x17, flagReservedOne);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);

        assembler.mov(arm64::x17, arm64::x1);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 4);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 2);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 1);
        assembler.tbnz(arm64::x17, 0, parityDone);
        assembler.movImmediate(arm64::x17, flagParity);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(parityDone);

        assembler.cbnz(arm64::x1, zeroDone);
        assembler.movImmediate(arm64::x17, flagZero);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(zeroDone);

        assembler.lsrImmediate(arm64::x17, arm64::x1, static_cast<std::uint8_t>(signBit));
        assembler.bitOrShiftedLeft(arm64::x16, arm64::x16, arm64::x17, 7);
        assembler.str(arm64::x16, arm64::x0,
                      static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
    };

    const auto emitSubFlags64 = [&](arm64::XRegister lhs, arm64::XRegister rhs,
                                    arm64::XRegister result) {
        const auto carryDone = assembler.makeLabel();
        const auto parityDone = assembler.makeLabel();
        const auto auxiliaryDone = assembler.makeLabel();
        const auto zeroDone = assembler.makeLabel();
        const auto overflowDone = assembler.makeLabel();

        assembler.ldr(arm64::x16, arm64::x0,
                      static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
        assembler.movImmediate(arm64::x17, ~arithmeticFlagMask);
        assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
        assembler.movImmediate(arm64::x17, flagReservedOne);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);

        assembler.compare(lhs, rhs);
        assembler.bUnsignedHigherOrSame(carryDone);
        assembler.movImmediate(arm64::x17, flagCarry);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(carryDone);

        assembler.mov(arm64::x17, result);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 4);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 2);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 1);
        assembler.tbnz(arm64::x17, 0, parityDone);
        assembler.movImmediate(arm64::x17, flagParity);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(parityDone);

        assembler.bitXor(arm64::x17, lhs, rhs);
        assembler.bitXor(arm64::x17, arm64::x17, result);
        assembler.tbz(arm64::x17, 4, auxiliaryDone);
        assembler.movImmediate(arm64::x17, flagAuxiliaryCarry);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(auxiliaryDone);

        assembler.cbnz(result, zeroDone);
        assembler.movImmediate(arm64::x17, flagZero);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(zeroDone);

        assembler.lsrImmediate(arm64::x17, result, 63);
        assembler.bitOrShiftedLeft(arm64::x16, arm64::x16, arm64::x17, 7);

        assembler.bitXor(arm64::x17, lhs, rhs);
        assembler.bitXor(arm64::x1, lhs, result);
        assembler.bitAnd(arm64::x17, arm64::x17, arm64::x1);
        assembler.tbz(arm64::x17, 63, overflowDone);
        assembler.movImmediate(arm64::x17, flagOverflow);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(overflowDone);

        assembler.str(arm64::x16, arm64::x0,
                      static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
    };

    for (std::size_t operationIndex = 0; operationIndex < block.operations.size();
         ++operationIndex) {
        const auto &operation = block.operations[operationIndex];
        if (isDeadFlagUpdate(block, operationIndex, eliminateFusedFlagUpdates)) {
            continue;
        }
        if (sinkLogicFlags && logicFlagSinkTarget(block, operationIndex)) {
            continue;
        }
        if (deferredExitUpdate == operationIndex) {
            continue;
        }
        if (deferredExitResultOperation == operationIndex) {
            continue;
        }
        switch (operation.opcode) {
        case ir::Opcode::Constant:
            if (foldedImmediate[operation.result->value] ||
                (pinnedLoopConstant && *operation.result == *pinnedLoopConstant)) {
                break;
            }
            assembler.movImmediate(hostRegister(*operation.result),
                                   operation.width == ir::Width::I32
                                       ? operation.immediate & UINT32_MAX
                                       : operation.immediate);
            break;
        case ir::Opcode::ReadGuestReg:
            if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                if (hostRegister(*operation.result).encoding == pinned->encoding) {
                    break;
                }
                if (operation.width == ir::Width::I32) {
                    assembler.mov32(hostRegister(*operation.result), *pinned);
                } else {
                    assembler.mov(hostRegister(*operation.result), *pinned);
                }
            } else if (operation.width == ir::Width::I32) {
                assembler.ldr32(
                    hostRegister(*operation.result), arm64::x0,
                    static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
            } else {
                assembler.ldr(
                    hostRegister(*operation.result), arm64::x0,
                    static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
            }
            break;
        case ir::Opcode::ReadGuestGsBase:
            assembler.ldr(hostRegister(*operation.result), arm64::x0,
                          static_cast<std::uint32_t>(offsetof(x86::X86State, gsBase)));
            break;
        case ir::Opcode::ReadGuestXmmLane:
            assembler.ldr(hostRegister(*operation.result), arm64::x0,
                          static_cast<std::uint32_t>(x86::xmmLaneOffset(*operation.guestXmmRegister,
                                                                        operation.immediate != 0)));
            break;
        case ir::Opcode::ReadGuestYmmUpperLane:
            assembler.ldr(hostRegister(*operation.result), arm64::x0,
                          static_cast<std::uint32_t>(x86::ymmUpperLaneOffset(
                              *operation.guestXmmRegister, operation.immediate != 0)));
            break;
        case ir::Opcode::WriteGuestReg: {
            if (promotesNarrowGuestWrite[operationIndex]) {
                if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                    if (hostRegister(*operation.lhs).encoding != pinned->encoding) {
                        assembler.mov(*pinned, hostRegister(*operation.lhs));
                    }
                } else {
                    assembler.str(
                        hostRegister(*operation.lhs), arm64::x0,
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
                }
                break;
            }
            if (operation.width == ir::Width::I8 || operation.width == ir::Width::I16) {
                const auto offset =
                    static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister));
                const auto pinned = pinnedGuestRegister(*operation.guestRegister);
                if (pinned) {
                    assembler.mov(arm64::x16, *pinned);
                } else {
                    assembler.ldr(arm64::x16, arm64::x0, offset);
                }
                const auto valueMask =
                    operation.width == ir::Width::I8 ? std::uint64_t{0xFF} : std::uint64_t{0xFFFF};
                assembler.movImmediate(arm64::x17, ~valueMask);
                assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
                assembler.movImmediate(arm64::x17, valueMask);
                assembler.bitAnd(arm64::x17, hostRegister(*operation.lhs), arm64::x17);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                if (pinned) {
                    assembler.mov(*pinned, arm64::x16);
                } else {
                    assembler.str(arm64::x16, arm64::x0, offset);
                }
            } else if (operation.width == ir::Width::I32) {
                const auto *definition = definingOperation(*operation.lhs);
                const auto alreadyZeroExtended = isZeroExtendedDefinition(definition);
                if (alreadyZeroExtended) {
                    if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                        if (hostRegister(*operation.lhs).encoding != pinned->encoding) {
                            assembler.mov(*pinned, hostRegister(*operation.lhs));
                        }
                    } else {
                        assembler.str(hostRegister(*operation.lhs), arm64::x0,
                                      static_cast<std::uint32_t>(
                                          x86::registerOffset(*operation.guestRegister)));
                    }
                } else if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                    assembler.mov32(*pinned, hostRegister(*operation.lhs));
                } else {
                    assembler.movImmediate(arm64::x16, UINT32_MAX);
                    assembler.bitAnd(arm64::x16, hostRegister(*operation.lhs), arm64::x16);
                    assembler.str(
                        arm64::x16, arm64::x0,
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
                }
            } else {
                if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                    if (hostRegister(*operation.lhs).encoding != pinned->encoding) {
                        assembler.mov(*pinned, hostRegister(*operation.lhs));
                    }
                } else {
                    assembler.str(
                        hostRegister(*operation.lhs), arm64::x0,
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
                }
            }
            break;
        }
        case ir::Opcode::ConditionalMoveGuestReg: {
            if ((operation.width != ir::Width::I32 && operation.width != ir::Width::I64) ||
                (*operation.condition != x86::Condition::Below &&
                 *operation.condition != x86::Condition::BelowOrEqual &&
                 *operation.condition != x86::Condition::AboveOrEqual &&
                 *operation.condition != x86::Condition::Above &&
                 *operation.condition != x86::Condition::Equal &&
                 *operation.condition != x86::Condition::NotEqual &&
                 *operation.condition != x86::Condition::Overflow &&
                 *operation.condition != x86::Condition::NotOverflow &&
                 *operation.condition != x86::Condition::ParityEven &&
                 *operation.condition != x86::Condition::ParityOdd &&
                 *operation.condition != x86::Condition::Sign &&
                 *operation.condition != x86::Condition::NotSign &&
                 *operation.condition != x86::Condition::Less &&
                 *operation.condition != x86::Condition::GreaterOrEqual &&
                 *operation.condition != x86::Condition::LessOrEqual &&
                 *operation.condition != x86::Condition::Greater)) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32- and 64-bit register "
                    "CMOVO/CMOVNO/CMOVP/CMOVNP/CMOVB/CMOVBE/CMOVAE/CMOVE/CMOVNE/CMOVA/CMOVS/CMOVNS/CMOVL/CMOVGE/CMOVLE/CMOVG");
            }
            constexpr std::uint8_t carryFlagBit = 0;
            constexpr std::uint8_t zeroFlagBit = 6;
            constexpr std::uint8_t signFlagBit = 7;
            const auto notTaken = assembler.makeLabel();
            const auto zeroSource = fuseZeroFlagConsumers && consumesOnlyZeroFlag(operation)
                                        ? zeroFlagSourceAt(block, operationIndex)
                                        : std::nullopt;
            if (zeroSource) {
                const auto zeroSourceRegister = hostRegister(zeroSource->value);
                auto compared = zeroSourceRegister;
                if (zeroSource->width != ir::Width::I64) {
                    const auto valueMask =
                        zeroSource->width == ir::Width::I8    ? std::uint64_t{UINT8_MAX}
                        : zeroSource->width == ir::Width::I16 ? std::uint64_t{UINT16_MAX}
                                                              : std::uint64_t{UINT32_MAX};
                    assembler.movImmediate(arm64::x17, valueMask);
                    assembler.bitAnd(arm64::x16, zeroSourceRegister, arm64::x17);
                    compared = arm64::x16;
                }
                assembler.compareZero(compared);

                arm64::XRegister trueValue{};
                if (operation.lhs) {
                    trueValue = hostRegister(*operation.lhs);
                } else {
                    const auto source = static_cast<x86::Register>(operation.immediate);
                    if (const auto pinned = pinnedGuestRegister(source)) {
                        trueValue = *pinned;
                    } else {
                        assembler.ldr(arm64::x17, arm64::x0,
                                      static_cast<std::uint32_t>(x86::registerOffset(source)));
                        trueValue = arm64::x17;
                    }
                }

                const auto destinationPinned = pinnedGuestRegister(*operation.guestRegister);
                arm64::XRegister falseValue{};
                arm64::XRegister destination{};
                if (destinationPinned) {
                    falseValue = *destinationPinned;
                    destination = *destinationPinned;
                } else {
                    assembler.ldr(
                        arm64::x16, arm64::x0,
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
                    falseValue = arm64::x16;
                    destination = arm64::x17;
                }
                const auto condition = *operation.condition == x86::Condition::Equal
                                           ? arm64::BranchCondition::Equal
                                           : arm64::BranchCondition::NotEqual;
                if (operation.width == ir::Width::I32) {
                    assembler.conditionalSelect32(destination, trueValue, falseValue, condition);
                } else {
                    assembler.conditionalSelect(destination, trueValue, falseValue, condition);
                }
                if (!destinationPinned) {
                    assembler.str(
                        destination, arm64::x0,
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
                }
                break;
            }
            if (zeroSource) {
                const auto sourceRegister = hostRegister(zeroSource->value);
                if (zeroSource->width == ir::Width::I64) {
                    assembler.mov(arm64::x16, sourceRegister);
                } else {
                    const auto valueMask =
                        zeroSource->width == ir::Width::I8    ? std::uint64_t{UINT8_MAX}
                        : zeroSource->width == ir::Width::I16 ? std::uint64_t{UINT16_MAX}
                                                              : std::uint64_t{UINT32_MAX};
                    assembler.movImmediate(arm64::x17, valueMask);
                    assembler.bitAnd(arm64::x16, sourceRegister, arm64::x17);
                }
                if (*operation.condition == x86::Condition::Equal) {
                    assembler.cbnz(arm64::x16, notTaken);
                } else {
                    assembler.cbz(arm64::x16, notTaken);
                }
            } else {
                assembler.ldr(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                if (*operation.condition == x86::Condition::Below) {
                    assembler.tbz(arm64::x16, carryFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::BelowOrEqual) {
                    const auto taken = assembler.makeLabel();
                    assembler.tbnz(arm64::x16, carryFlagBit, taken);
                    assembler.tbz(arm64::x16, zeroFlagBit, notTaken);
                    assembler.bind(taken);
                } else if (*operation.condition == x86::Condition::AboveOrEqual) {
                    assembler.tbnz(arm64::x16, carryFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::Equal) {
                    assembler.tbz(arm64::x16, zeroFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::NotEqual) {
                    assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::Sign) {
                    assembler.tbz(arm64::x16, signFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::NotSign) {
                    assembler.tbnz(arm64::x16, signFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::Overflow) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    assembler.tbz(arm64::x16, overflowFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::NotOverflow) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    assembler.tbnz(arm64::x16, overflowFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::ParityEven) {
                    constexpr std::uint8_t parityFlagBit = 2;
                    assembler.tbz(arm64::x16, parityFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::ParityOdd) {
                    constexpr std::uint8_t parityFlagBit = 2;
                    assembler.tbnz(arm64::x16, parityFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::Less) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    assembler.lsrImmediate(arm64::x17, arm64::x16, overflowFlagBit - signFlagBit);
                    assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                    assembler.tbz(arm64::x17, signFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::GreaterOrEqual) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    assembler.lsrImmediate(arm64::x17, arm64::x16, overflowFlagBit - signFlagBit);
                    assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                    assembler.tbnz(arm64::x17, signFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::LessOrEqual) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    const auto taken = assembler.makeLabel();
                    assembler.tbnz(arm64::x16, zeroFlagBit, taken);
                    assembler.lsrImmediate(arm64::x17, arm64::x16, overflowFlagBit - signFlagBit);
                    assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                    assembler.tbz(arm64::x17, signFlagBit, notTaken);
                    assembler.bind(taken);
                } else if (*operation.condition == x86::Condition::Greater) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                    assembler.lsrImmediate(arm64::x17, arm64::x16, overflowFlagBit - signFlagBit);
                    assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                    assembler.tbnz(arm64::x17, signFlagBit, notTaken);
                } else {
                    assembler.tbnz(arm64::x16, carryFlagBit, notTaken);
                    assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                }
            }
            if (operation.lhs) {
                assembler.mov(arm64::x17, hostRegister(*operation.lhs));
            } else {
                const auto source = static_cast<x86::Register>(operation.immediate);
                if (const auto pinned = pinnedGuestRegister(source)) {
                    assembler.mov(arm64::x17, *pinned);
                } else {
                    assembler.ldr(arm64::x17, arm64::x0,
                                  static_cast<std::uint32_t>(x86::registerOffset(source)));
                }
            }
            if (operation.width == ir::Width::I32) {
                assembler.mov32(arm64::x17, arm64::x17);
            }
            if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                assembler.mov(*pinned, arm64::x17);
            } else {
                assembler.str(
                    arm64::x17, arm64::x0,
                    static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
            }
            assembler.bind(notTaken);
            if (operation.width == ir::Width::I32) {
                // CMOV r32 performs a 32-bit architectural destination write
                // even when the condition is false, clearing the upper half.
                if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                    assembler.mov32(*pinned, *pinned);
                } else {
                    const auto destinationOffset =
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister));
                    assembler.ldr(arm64::x17, arm64::x0, destinationOffset);
                    assembler.mov32(arm64::x17, arm64::x17);
                    assembler.str(arm64::x17, arm64::x0, destinationOffset);
                }
            }
            break;
        }
        case ir::Opcode::WriteGuestXmmLane:
            assembler.str(hostRegister(*operation.lhs), arm64::x0,
                          static_cast<std::uint32_t>(x86::xmmLaneOffset(*operation.guestXmmRegister,
                                                                        operation.immediate != 0)));
            break;
        case ir::Opcode::WriteGuestYmmUpperLane:
            assembler.str(hostRegister(*operation.lhs), arm64::x0,
                          static_cast<std::uint32_t>(x86::ymmUpperLaneOffset(
                              *operation.guestXmmRegister, operation.immediate != 0)));
            break;
        case ir::Opcode::WriteGuestXmmByte: {
            const auto lane = static_cast<std::uint8_t>(operation.immediate);
            const auto byte = static_cast<std::uint8_t>(lane & 7U);
            const auto shift = static_cast<std::uint8_t>(byte * 8U);
            const auto offset = static_cast<std::uint32_t>(
                x86::xmmLaneOffset(*operation.guestXmmRegister, lane >= 8));
            assembler.ldr(arm64::x16, arm64::x0, offset);
            assembler.movImmediate(arm64::x17, ~(std::uint64_t{0xFF} << shift));
            assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
            assembler.movImmediate(arm64::x17, 0xFF);
            assembler.bitAnd(arm64::x17, hostRegister(*operation.lhs), arm64::x17);
            if (shift != 0) {
                assembler.lslImmediate(arm64::x17, arm64::x17, shift);
            }
            assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
            assembler.str(arm64::x16, arm64::x0, offset);
            break;
        }
        case ir::Opcode::WriteGuestXmmDword: {
            const auto lane = static_cast<std::uint8_t>(operation.immediate);
            const auto offset = static_cast<std::uint32_t>(
                x86::xmmLaneOffset(*operation.guestXmmRegister, lane >= 2));
            assembler.ldr(arm64::x16, arm64::x0, offset);
            assembler.movImmediate(arm64::x17,
                                   (lane & 1U) == 0 ? 0xFFFFFFFF00000000ULL : UINT32_MAX);
            assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
            assembler.movImmediate(arm64::x17, UINT32_MAX);
            assembler.bitAnd(arm64::x17, hostRegister(*operation.lhs), arm64::x17);
            if ((lane & 1U) != 0) {
                assembler.lslImmediate(arm64::x17, arm64::x17, 32);
            }
            assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
            assembler.str(arm64::x16, arm64::x0, offset);
            break;
        }
        case ir::Opcode::Add:
            if (directWriteSpan && operation.result == directWriteSpan->address) {
                break;
            }
            if (operation.rhs && foldedImmediate[operation.rhs->value]) {
                const auto immediate =
                    static_cast<std::uint16_t>(definingOperation(*operation.rhs)->immediate);
                if (operation.width == ir::Width::I32) {
                    assembler.addImmediate32(hostRegister(*operation.result),
                                             hostRegister(*operation.lhs), immediate);
                } else {
                    assembler.addImmediate(hostRegister(*operation.result),
                                           hostRegister(*operation.lhs), immediate);
                }
            } else if (operation.width == ir::Width::I32) {
                assembler.add32(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                hostRegister(*operation.rhs));
            } else {
                assembler.add(hostRegister(*operation.result), hostRegister(*operation.lhs),
                              hostRegister(*operation.rhs));
            }
            break;
        case ir::Opcode::Sub:
            if (operation.rhs && foldedImmediate[operation.rhs->value]) {
                const auto immediate =
                    static_cast<std::uint16_t>(definingOperation(*operation.rhs)->immediate);
                if (operation.width == ir::Width::I32) {
                    assembler.subImmediate32(hostRegister(*operation.result),
                                             hostRegister(*operation.lhs), immediate);
                } else {
                    assembler.subImmediate(hostRegister(*operation.result),
                                           hostRegister(*operation.lhs), immediate);
                }
            } else if (operation.width == ir::Width::I32) {
                assembler.sub32(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                hostRegister(*operation.rhs));
            } else {
                assembler.sub(hostRegister(*operation.result), hostRegister(*operation.lhs),
                              hostRegister(*operation.rhs));
            }
            break;
        case ir::Opcode::ShiftLeft:
            if (operation.rhs) {
                assembler.lslVariable(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                      hostRegister(*operation.rhs));
            } else {
                assembler.lslImmediate(hostRegister(*operation.result),
                                       hostRegister(*operation.lhs),
                                       static_cast<std::uint8_t>(operation.immediate));
            }
            break;
        case ir::Opcode::ShiftRightLogical:
            if (operation.rhs) {
                assembler.lsrVariable(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                      hostRegister(*operation.rhs));
            } else {
                assembler.lsrImmediate(hostRegister(*operation.result),
                                       hostRegister(*operation.lhs),
                                       static_cast<std::uint8_t>(operation.immediate));
            }
            break;
        case ir::Opcode::ShiftRightArithmetic:
            if (operation.rhs) {
                if (operation.width == ir::Width::I32) {
                    assembler.asrVariable32(hostRegister(*operation.result),
                                            hostRegister(*operation.lhs),
                                            hostRegister(*operation.rhs));
                } else {
                    assembler.asrVariable(hostRegister(*operation.result),
                                          hostRegister(*operation.lhs),
                                          hostRegister(*operation.rhs));
                }
            } else if (operation.width == ir::Width::I32) {
                assembler.asrImmediate32(hostRegister(*operation.result),
                                         hostRegister(*operation.lhs),
                                         static_cast<std::uint8_t>(operation.immediate));
            } else {
                assembler.asrImmediate(hostRegister(*operation.result),
                                       hostRegister(*operation.lhs),
                                       static_cast<std::uint8_t>(operation.immediate));
            }
            break;
        case ir::Opcode::MultiplyLow:
            assembler.multiplyLow(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                  hostRegister(*operation.rhs));
            break;
        case ir::Opcode::MultiplyHighUnsigned:
            assembler.multiplyHighUnsigned(hostRegister(*operation.result),
                                           hostRegister(*operation.lhs),
                                           hostRegister(*operation.rhs));
            break;
        case ir::Opcode::MultiplyHighSigned:
            assembler.multiplyHighSigned(hostRegister(*operation.result),
                                         hostRegister(*operation.lhs),
                                         hostRegister(*operation.rhs));
            break;
        case ir::Opcode::ShiftRightDouble:
            assembler.extract(hostRegister(*operation.result), hostRegister(*operation.rhs),
                              hostRegister(*operation.lhs),
                              static_cast<std::uint8_t>(operation.immediate));
            break;
        case ir::Opcode::And:
            if (operation.width == ir::Width::I32) {
                assembler.bitAnd32(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                   hostRegister(*operation.rhs));
            } else {
                assembler.bitAnd(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                 hostRegister(*operation.rhs));
            }
            break;
        case ir::Opcode::Or:
            if (operation.width == ir::Width::I32) {
                assembler.bitOr32(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                  hostRegister(*operation.rhs));
            } else {
                assembler.bitOr(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                hostRegister(*operation.rhs));
            }
            break;
        case ir::Opcode::Xor:
            if (operation.width == ir::Width::I32) {
                assembler.bitXor32(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                   hostRegister(*operation.rhs));
            } else {
                assembler.bitXor(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                 hostRegister(*operation.rhs));
            }
            break;
        case ir::Opcode::SignExtend32:
            assembler.signExtend32(hostRegister(*operation.result), hostRegister(*operation.lhs));
            break;
        case ir::Opcode::ByteSwap:
            if (operation.width == ir::Width::I32) {
                assembler.reverseBytes32(hostRegister(*operation.result),
                                         hostRegister(*operation.lhs));
            } else {
                assembler.reverseBytes64(hostRegister(*operation.result),
                                         hostRegister(*operation.lhs));
            }
            break;
        case ir::Opcode::EvaluateCondition: {
            if (*operation.condition != x86::Condition::Overflow &&
                *operation.condition != x86::Condition::NotOverflow &&
                *operation.condition != x86::Condition::ParityEven &&
                *operation.condition != x86::Condition::ParityOdd &&
                *operation.condition != x86::Condition::Equal &&
                *operation.condition != x86::Condition::NotEqual &&
                *operation.condition != x86::Condition::Below &&
                *operation.condition != x86::Condition::BelowOrEqual &&
                *operation.condition != x86::Condition::Less &&
                *operation.condition != x86::Condition::Greater &&
                *operation.condition != x86::Condition::GreaterOrEqual &&
                *operation.condition != x86::Condition::LessOrEqual &&
                *operation.condition != x86::Condition::AboveOrEqual &&
                *operation.condition != x86::Condition::Above &&
                *operation.condition != x86::Condition::Sign &&
                *operation.condition != x86::Condition::NotSign) {
                throw std::runtime_error("ARM64 backend only implements "
                                          "overflow/not-overflow/parity/parity-odd/equality/below/"
                                          "below-or-equal/less/greater/"
                                          "greater-or-equal/less-or-equal/"
                                          "above-or-equal/above/sign/not-sign condition values");
            }
            constexpr std::uint8_t carryFlagBit = 0;
            constexpr std::uint8_t zeroFlagBit = 6;
            constexpr std::uint8_t signFlagBit = 7;
            constexpr std::uint8_t overflowFlagBit = 11;
            const auto done = assembler.makeLabel();
            const auto satisfied = assembler.makeLabel();
            const auto destination = hostRegister(*operation.result);
            if (fuseZeroFlagConsumers && consumesOnlyZeroFlag(operation)) {
                if (const auto source = zeroFlagSourceAt(block, operationIndex)) {
                    const auto sourceRegister = hostRegister(source->value);
                    auto compared = sourceRegister;
                    if (source->width == ir::Width::I64) {
                        compared = sourceRegister;
                    } else {
                        const auto valueMask =
                            source->width == ir::Width::I8    ? std::uint64_t{UINT8_MAX}
                            : source->width == ir::Width::I16 ? std::uint64_t{UINT16_MAX}
                                                              : std::uint64_t{UINT32_MAX};
                        assembler.movImmediate(arm64::x17, valueMask);
                        assembler.bitAnd(arm64::x16, sourceRegister, arm64::x17);
                        compared = arm64::x16;
                    }
                    assembler.compareZero(compared);
                    assembler.conditionalSet(destination,
                                             *operation.condition == x86::Condition::Equal
                                                 ? arm64::BranchCondition::Equal
                                                 : arm64::BranchCondition::NotEqual);
                    break;
                }
            }
            assembler.movImmediate(destination, 0);
            assembler.ldr(arm64::x16, arm64::x0,
                          static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
            if (*operation.condition == x86::Condition::Overflow) {
                assembler.tbz(arm64::x16, overflowFlagBit, done);
            } else if (*operation.condition == x86::Condition::NotOverflow) {
                assembler.tbnz(arm64::x16, overflowFlagBit, done);
            } else if (*operation.condition == x86::Condition::ParityEven) {
                constexpr std::uint8_t parityFlagBit = 2;
                assembler.tbz(arm64::x16, parityFlagBit, done);
            } else if (*operation.condition == x86::Condition::ParityOdd) {
                constexpr std::uint8_t parityFlagBit = 2;
                assembler.tbnz(arm64::x16, parityFlagBit, done);
            } else if (*operation.condition == x86::Condition::Equal) {
                assembler.tbz(arm64::x16, zeroFlagBit, done);
            } else if (*operation.condition == x86::Condition::NotEqual) {
                assembler.tbnz(arm64::x16, zeroFlagBit, done);
            } else if (*operation.condition == x86::Condition::Below) {
                assembler.tbz(arm64::x16, carryFlagBit, done);
            } else if (*operation.condition == x86::Condition::BelowOrEqual) {
                assembler.tbnz(arm64::x16, carryFlagBit, satisfied);
                assembler.tbz(arm64::x16, zeroFlagBit, done);
            } else if (*operation.condition == x86::Condition::AboveOrEqual) {
                assembler.tbnz(arm64::x16, carryFlagBit, done);
            } else if (*operation.condition == x86::Condition::Above) {
                assembler.tbnz(arm64::x16, carryFlagBit, done);
                assembler.tbnz(arm64::x16, zeroFlagBit, done);
            } else if (*operation.condition == x86::Condition::Sign) {
                assembler.tbz(arm64::x16, signFlagBit, done);
            } else if (*operation.condition == x86::Condition::NotSign) {
                assembler.tbnz(arm64::x16, signFlagBit, done);
            } else if (*operation.condition == x86::Condition::Less) {
                // OF is bit 11; align it with SF at bit 7 and require inequality.
                assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                assembler.tbz(arm64::x17, signFlagBit, done);
            } else if (*operation.condition == x86::Condition::GreaterOrEqual) {
                // OF is bit 11; align it with SF at bit 7 and require equality.
                assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                assembler.tbnz(arm64::x17, signFlagBit, done);
            } else if (*operation.condition == x86::Condition::LessOrEqual) {
                assembler.tbnz(arm64::x16, zeroFlagBit, satisfied);
                // OF is bit 11; align it with SF at bit 7 and require equality.
                assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                assembler.tbz(arm64::x17, signFlagBit, done);
            } else {
                assembler.tbnz(arm64::x16, zeroFlagBit, done);
                // OF is bit 11; align it with SF at bit 7 and require equality.
                assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                assembler.tbnz(arm64::x17, signFlagBit, done);
            }
            assembler.bind(satisfied);
            assembler.movImmediate(destination, 1);
            assembler.bind(done);
            break;
        }
        case ir::Opcode::Push: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&commitPush64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::RepeatMoveByte: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&repeatMoveByte));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::RepeatStore: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.movImmediate(arm64::x2, operation.width == ir::Width::I8     ? 1U
                                                 : operation.width == ir::Width::I16 ? 2U
                                                 : operation.width == ir::Width::I32 ? 4U
                                                                                      : 8U);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&repeatStore));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::DivideUnsignedByte: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&divideUnsignedByte));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::ExecutionFault, operation.guestRip);
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::DivideUnsignedDword: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&divideUnsignedDword));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::ExecutionFault, operation.guestRip);
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::DivideSignedDword: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&divideSignedDword));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::ExecutionFault, operation.guestRip);
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::DivideUnsignedQword: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&divideUnsignedQword));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::ExecutionFault, operation.guestRip);
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::AddGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error("ARM64 backend only implements 8-, 16-, 32-, or 64-bit "
                                         "guest memory add");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&addGuest8)
                                                   : operation.width == ir::Width::I16
                                                         ? pointerBits(&addGuest16)
                                                         : operation.width == ir::Width::I32
                                                               ? pointerBits(&addGuest32)
                                                               : pointerBits(&addGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::SubGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I32 &&
                operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 8-, 32-, or 64-bit guest memory subtract");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&subGuest8)
                                            : operation.width == ir::Width::I32 ? pointerBits(&subGuest32)
                                                                                : pointerBits(&subGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::OrGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 8-, 16-, 32-, or 64-bit guest memory OR");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16,
                                   operation.width == ir::Width::I8    ? pointerBits(&orGuest8)
                                   : operation.width == ir::Width::I16 ? pointerBits(&orGuest16)
                                   : operation.width == ir::Width::I32 ? pointerBits(&orGuest32)
                                                                       : pointerBits(&orGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::AndGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 8-, 16-, 32-, or 64-bit guest memory AND");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16,
                                   operation.width == ir::Width::I8    ? pointerBits(&andGuest8)
                                   : operation.width == ir::Width::I16 ? pointerBits(&andGuest16)
                                   : operation.width == ir::Width::I32 ? pointerBits(&andGuest32)
                                                                       : pointerBits(&andGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::ShiftLeftGuestMemory: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&shiftLeftGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::ShiftRightGuestMemory: {
            if (operation.width != ir::Width::I32 &&
                operation.width != ir::Width::I64) {
                throw std::runtime_error("ARM64 backend only implements 32- and 64-bit "
                                         "guest memory shift right");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&shiftRightGuest32)
                                                   : pointerBits(&shiftRightGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::IncrementGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error("ARM64 backend only implements 8-, 16-, 32-, and 64-bit "
                                         "guest memory increment");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(
                arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&incrementGuest8)
                            : operation.width == ir::Width::I16 ? pointerBits(&incrementGuest16)
                            : operation.width == ir::Width::I32 ? pointerBits(&incrementGuest32)
                                                                : pointerBits(&incrementGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::DecrementGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error("ARM64 backend only implements 8-, 16-, 32-, and 64-bit "
                                         "guest memory decrement");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(
                arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&decrementGuest8)
                             : operation.width == ir::Width::I16 ? pointerBits(&decrementGuest16)
                             : operation.width == ir::Width::I32 ? pointerBits(&decrementGuest32)
                                                                 : pointerBits(&decrementGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::CompareExchangeGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I32 &&
                operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 8-, 32-, and 64-bit guest-memory CMPXCHG");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&compareExchangeGuest8)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&compareExchangeGuest32)
                                                   : pointerBits(&compareExchangeGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::CompareExchangeGuestPair: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&compareExchangeGuestPair));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::ExchangeGuestMemory: {
            if ((operation.width != ir::Width::I8 && operation.width != ir::Width::I32 &&
                 operation.width != ir::Width::I64) ||
                !operation.guestRegister) {
                throw std::runtime_error(
                    "ARM64 backend only implements 8-bit, 32-bit and 64-bit guest-memory XCHG");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.movImmediate(arm64::x4, static_cast<std::uint64_t>(*operation.guestRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&exchangeGuest8)
                                                   : operation.width == ir::Width::I32
                                                         ? pointerBits(&exchangeGuest32)
                                                         : pointerBits(&exchangeGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedAddGuestMemory: {
            if (operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32- and 64-bit guest-memory LOCK ADD");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&lockedAddGuest32)
                                                   : pointerBits(&lockedAddGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedExchangeAddGuestMemory: {
            if ((operation.width != ir::Width::I16 && operation.width != ir::Width::I32 &&
                 operation.width != ir::Width::I64) ||
                !operation.guestRegister) {
                throw std::runtime_error(
                    "ARM64 backend only implements 16-, 32-, and 64-bit guest-memory LOCK XADD");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.movImmediate(arm64::x4, static_cast<std::uint64_t>(*operation.guestRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I16
                                                   ? pointerBits(&lockedExchangeAddGuest16)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&lockedExchangeAddGuest32)
                                                   : pointerBits(&lockedExchangeAddGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedOrGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 8-, 16-, 32-, and 64-bit guest-memory LOCK OR");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&lockedOrGuest8)
                                               : operation.width == ir::Width::I16
                                                   ? pointerBits(&lockedOrGuest16)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&lockedOrGuest32)
                                                   : pointerBits(&lockedOrGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedBitSetGuestMemory: {
            if (operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32- and 64-bit guest-memory LOCK BTS");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&lockedBitSetGuest32)
                                                   : pointerBits(&lockedBitSetGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedAndGuestMemory: {
            if (operation.width != ir::Width::I16 && operation.width != ir::Width::I32 &&
                operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 16-, 32-, and 64-bit guest-memory LOCK AND");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I16
                                                   ? pointerBits(&lockedAndGuest16)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&lockedAndGuest32)
                                                   : pointerBits(&lockedAndGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedIncrementGuestMemory:
        case ir::Opcode::LockedDecrementGuestMemory: {
            if (operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32- and 64-bit guest-memory LOCK INC/DEC");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16,
                                   operation.opcode == ir::Opcode::LockedIncrementGuestMemory
                                       ? (operation.width == ir::Width::I32
                                              ? pointerBits(&lockedIncrementGuest32)
                                              : pointerBits(&lockedIncrementGuest64))
                                       : operation.width == ir::Width::I32
                                             ? pointerBits(&lockedDecrementGuest32)
                                             : pointerBits(&lockedDecrementGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::StoreGuest: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            const auto directByteWrite = pinsDirectWrite && operation.width == ir::Width::I8;
            const auto checkedHelper = assembler.makeLabel();
            const auto directFast = assembler.makeLabel();
            if (directWriteSpan) {
                directWriteFastEntry = directFast;
            }
            if (directByteWrite) {
                assembler.cbnz(directWriteSpan ? arm64::x4 : arm64::x20, directFast);
                assembler.bind(checkedHelper);
            }
            if (directWriteSpan) {
                assembler.add(hostRegister(directWriteSpan->address),
                              hostRegister(directWriteSpan->addressLhs),
                              hostRegister(directWriteSpan->addressRhs));
            }
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(
                arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&storeGuest8)
                            : operation.width == ir::Width::I16 ? pointerBits(&storeGuest16)
                            : operation.width == ir::Width::I32 ? pointerBits(&storeGuest32)
                                                                : pointerBits(&storeGuest64));
            if (directByteWrite) {
                assembler.pushCallerSaved5Through15();
            }
            assembler.blr(arm64::x16);
            if (directByteWrite) {
                assembler.popCallerSaved5Through15();
            }
            assembler.cbz(arm64::x0, fault);
            if (directByteWrite) {
                assembler.ldr(
                    arm64::x20, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directWrite) +
                                               offsetof(DirectGuestMemoryCache, bytes)));
                assembler.ldr(
                    arm64::x21, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directWrite) +
                                               offsetof(DirectGuestMemoryCache, base)));
                assembler.ldr(
                    arm64::x22, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directWrite) +
                                               offsetof(DirectGuestMemoryCache, size)));
                if (directWriteSpan) {
                    const auto rejected = assembler.makeLabel();
                    const auto guarded = assembler.makeLabel();
                    assembler.cbz(arm64::x20, rejected);
                    assembler.compareZero(directWriteSpan->step);
                    assembler.bConditional(arm64::BranchCondition::Equal, rejected);
                    assembler.movImmediate(arm64::x16, directWriteSpan->limit);
                    assembler.compare(hostRegister(directWriteSpan->induction), arm64::x16);
                    assembler.bUnsignedHigherOrSame(rejected);
                    assembler.movImmediate(arm64::x17, UINT64_MAX - (directWriteSpan->limit - 1));
                    assembler.compare(directWriteSpan->step, arm64::x17);
                    assembler.bConditional(arm64::BranchCondition::UnsignedHigher, rejected);
                    assembler.movImmediate(arm64::x17, directWriteSpan->limit - 1);
                    assembler.add(arm64::x16, hostRegister(directWriteSpan->offset), arm64::x17);
                    assembler.compare(arm64::x16, hostRegister(directWriteSpan->offset));
                    assembler.bConditional(arm64::BranchCondition::UnsignedLower, rejected);
                    assembler.sub(arm64::x17, arm64::x16, arm64::x21);
                    assembler.compare(arm64::x17, arm64::x22);
                    assembler.bUnsignedHigherOrSame(rejected);
                    assembler.sub(arm64::x17, hostRegister(directWriteSpan->address), arm64::x21);
                    assembler.compare(arm64::x17, arm64::x22);
                    assembler.bUnsignedHigherOrSame(rejected);
                    assembler.add(arm64::x3, arm64::x20, arm64::x17);
                    assembler.add(arm64::x3, arm64::x3, directWriteSpan->step);
                    assembler.movImmediate(arm64::x4, 1);
                    assembler.b(guarded);
                    assembler.bind(rejected);
                    assembler.movImmediate(arm64::x4, 0);
                    assembler.bind(guarded);
                }
            }
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            if (directByteWrite) {
                assembler.bind(directFast);
                if (directWriteSpan) {
                    assembler.str8(hostRegister(*operation.rhs), arm64::x3, 0);
                    assembler.add(arm64::x3, arm64::x3, directWriteSpan->step);
                } else {
                    assembler.sub(arm64::x17, hostRegister(*operation.lhs), arm64::x21);
                    assembler.compare(arm64::x17, arm64::x22);
                    assembler.bUnsignedHigherOrSame(checkedHelper);
                    assembler.add(arm64::x16, arm64::x20, arm64::x17);
                    assembler.str8(hostRegister(*operation.rhs), arm64::x16, 0);
                }
            }
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::StoreGuestIdtr: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&storeGuestIdtr));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::StoreGuestXmm: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x4, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&storeGuestXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::StoreGuestYmm: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x4, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&storeGuestYmm256));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LoadGuestXmm: {
            const auto fault = assembler.makeLabel();
            const auto loaded = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x4, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&loadGuestXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(loaded);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(loaded);
            break;
        }
        case ir::Opcode::LoadGuestYmm: {
            const auto fault = assembler.makeLabel();
            const auto loaded = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x4, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&loadGuestYmm256));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(loaded);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(loaded);
            break;
        }
        case ir::Opcode::LoadGuestSignExtendedBytesXmm: {
            const auto fault = assembler.makeLabel();
            const auto loaded = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&loadGuestSignExtendedBytesXmm));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(loaded);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(loaded);
            break;
        }
        case ir::Opcode::LoadGuestSignExtendedDwordsXmm: {
            const auto fault = assembler.makeLabel();
            const auto loaded = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&loadGuestSignExtendedDwordsXmm));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(loaded);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(loaded);
            break;
        }
        case ir::Opcode::CompareEqualGuestBytesXmm: {
            const auto fault = assembler.makeLabel();
            const auto compared = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&compareEqualGuestBytesXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(compared);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(compared);
            break;
        }
        case ir::Opcode::CompareEqualGuestQwordsXmm: {
            const auto fault = assembler.makeLabel();
            const auto compared = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&compareEqualGuestQwordsXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(compared);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(compared);
            break;
        }
        case ir::Opcode::ArithmeticGuestMemoryPackedDoubleXmm: {
            const auto fault = assembler.makeLabel();
            const auto applied = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x4, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16,
                                   pointerBits(&arithmeticGuestMemoryPackedDoubleXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(applied);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(applied);
            break;
        }
        case ir::Opcode::UnpackHighGuestPackedSingleXmm: {
            const auto fault = assembler.makeLabel();
            const auto unpacked = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&unpackHighGuestPackedSingleXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(unpacked);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(unpacked);
            break;
        }
        case ir::Opcode::HorizontalAddGuestPackedDoubleXmm: {
            const auto fault = assembler.makeLabel();
            const auto added = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&horizontalAddGuestPackedDoubleXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(added);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(added);
            break;
        }
        case ir::Opcode::UnpackLowGuestPackedSingleXmm: {
            const auto fault = assembler.makeLabel();
            const auto unpacked = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&unpackLowGuestPackedSingleXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(unpacked);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(unpacked);
            break;
        }
        case ir::Opcode::XorGuestMemoryXmm: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&xorGuestMemoryXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::AndGuestMemoryXmm: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&andGuestMemoryXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::AddGuestMemoryXmm: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&addGuestMemoryXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::TestXmmBits:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&testXmmBits128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::CompareEqualXmmBytes:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&compareEqualXmmBytes128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::CompareEqualXmmDwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&compareEqualXmmDwords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::CompareEqualXmmQwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&compareEqualXmmQwords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ShiftLeftXmmDwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&shiftLeftXmmDwords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::AddXmmWords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&addXmmWords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ComparePackedDoubleXmm:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&comparePackedDoubleXmm));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ArithmeticPackedDoubleXmm:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&arithmeticPackedDoubleXmm));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UnpackHighPackedSingleXmm:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&unpackHighPackedSingleXmm));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::HorizontalAddPackedDoubleXmm:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&horizontalAddPackedDoubleXmm));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UnpackLowPackedSingleXmm:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&unpackLowPackedSingleXmm));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateUnorderedDoubleFlags: {
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.movImmediate(arm64::x16, pointerBits(&updateUnorderedDoubleFlags));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateUnorderedFloatFlags: {
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.movImmediate(arm64::x16, pointerBits(&updateUnorderedFloatFlags));
            assembler.blr(arm64::x16);
            break;
        }
        }
        case ir::Opcode::ConvertIntToDoubleXmm: {
            if (operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32- and 64-bit integer to double conversion");
            }
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x16,
                                   operation.width == ir::Width::I32
                                       ? pointerBits(&convertInt32ToDoubleXmm)
                                       : pointerBits(&convertInt64ToDoubleXmm));
            assembler.blr(arm64::x16);
            break;
        }
        case ir::Opcode::ConvertDoubleToInt: {
            if (operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32- and 64-bit double to integer conversion");
            }
            const auto destination = static_cast<std::uint64_t>(*operation.guestRegister);
            assembler.movImmediate(arm64::x1, destination);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x16,
                                   operation.width == ir::Width::I32
                                       ? pointerBits(&convertDoubleToInt32)
                                       : pointerBits(&convertDoubleToInt64));
            assembler.blr(arm64::x16);
            break;
        }
        case ir::Opcode::ConvertFloatToDoubleXmm: {
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x16, pointerBits(&convertFloatToDoubleXmm));
            assembler.blr(arm64::x16);
            break;
        }
        case ir::Opcode::ConvertInt32x2ToDoubleXmm: {
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x16, pointerBits(&convertInt32x2ToDoubleXmm));
            assembler.blr(arm64::x16);
            break;
        }
        case ir::Opcode::ScalarDoubleXmm: {
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&scalarDoubleXmm));
            assembler.blr(arm64::x16);
            break;
        }
        case ir::Opcode::AddXmmDwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&addXmmDwords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::HorizontalAddXmmDwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&horizontalAddXmmDwords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::AndNotXmm:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&andNotXmm128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::MoveXmmByteMask:
            assembler.movImmediate(arm64::x1, static_cast<std::uint64_t>(*operation.guestRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&moveXmmByteMask32));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ShuffleXmmBytes:
            if (operation.lhs) {
                const auto fault = assembler.makeLabel();
                const auto completed = assembler.makeLabel();
                assembler.mov(arm64::x1, arm64::x0);
                assembler.mov(arm64::x2, hostRegister(*operation.lhs));
                assembler.movImmediate(arm64::x3,
                                       static_cast<std::uint64_t>(*operation.guestXmmRegister));
                assembler.mov(arm64::x0, arm64::x19);
                assembler.movImmediate(arm64::x16, pointerBits(&shuffleGuestMemoryXmmBytes));
                assembler.blr(arm64::x16);
                assembler.cbz(arm64::x0, fault);
                assembler.b(completed);
                assembler.bind(fault);
                emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
                assembler.bind(completed);
            } else {
                assembler.movImmediate(arm64::x1,
                                       static_cast<std::uint64_t>(*operation.guestXmmRegister));
                assembler.movImmediate(
                    arm64::x2, static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
                assembler.movImmediate(arm64::x16, pointerBits(&shuffleXmmBytes));
                assembler.blr(arm64::x16);
            }
            break;
        case ir::Opcode::ShuffleXmmDwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&shuffleXmmDwords));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::AlignRightXmmBytes:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&alignRightXmmBytes));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::BlendXmmWords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&blendXmmWords));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UnpackLowXmmWords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&unpackLowXmmWords));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::BitScanForward:
            assembler.movImmediate(arm64::x1, static_cast<std::uint64_t>(*operation.guestRegister));
            assembler.movImmediate(arm64::x2, operation.immediate);
            assembler.movImmediate(arm64::x3, static_cast<std::uint64_t>(operation.width));
            assembler.movImmediate(arm64::x16, pointerBits(&bitScanForward));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::BitScanReverse:
            assembler.movImmediate(arm64::x1, static_cast<std::uint64_t>(*operation.guestRegister));
            assembler.movImmediate(arm64::x2, operation.immediate);
            assembler.movImmediate(arm64::x3, static_cast<std::uint64_t>(operation.width));
            assembler.movImmediate(arm64::x16, pointerBits(&bitScanReverse));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::LoadGuest: {
            const auto fault = assembler.makeLabel();
            const auto loaded = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            const auto directByteRead = pinsDirectRead && operation.width == ir::Width::I8;
            const auto checkedHelper = assembler.makeLabel();
            const auto directFast = assembler.makeLabel();
            const auto adjacent = adjacentDirectReads[operationIndex];
            if (directReadSpan && operationIndex == directReadSpan->firstLoadOperationIndex) {
                directReadFastEntry = directFast;
            }
            if (directByteRead) {
                assembler.cbnz(adjacent && !adjacent->first ? arm64::x4 : arm64::x20, directFast);
                assembler.bind(checkedHelper);
                if (sinkLogicFlags) {
                    if (const auto updateIndex = sunkLogicFlagUpdateAt(block, operationIndex)) {
                        const auto &update = block.operations[*updateIndex];
                        emitLogicFlags(hostRegister(*update.lhs), update.width);
                    }
                }
            }
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16,
                                   operation.width == ir::Width::I8    ? pointerBits(&loadGuest8)
                                   : operation.width == ir::Width::I16 ? pointerBits(&loadGuest16)
                                   : operation.width == ir::Width::I32 ? pointerBits(&loadGuest32)
                                                                       : pointerBits(&loadGuest64));
            if (directByteRead) {
                assembler.pushCallerSaved5Through15();
            }
            assembler.blr(arm64::x16);
            if (directByteRead) {
                assembler.popCallerSaved5Through15();
            }
            assembler.cbz(arm64::x0, fault);
            assembler.b(loaded);
            assembler.bind(fault);
            emitFaultExit(BlockExit::MemoryFault, operation.guestRip);
            assembler.bind(loaded);
            assembler.ldr(hostRegister(*operation.result), arm64::x19,
                          static_cast<std::uint32_t>(offsetof(GuestExecutionContext, loadedValue)));
            if (directByteRead) {
                assembler.ldr(
                    arm64::x20, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directRead) +
                                               offsetof(DirectGuestMemoryCache, bytes)));
                assembler.ldr(
                    arm64::x21, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directRead) +
                                               offsetof(DirectGuestMemoryCache, base)));
                assembler.ldr(
                    arm64::x22, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directRead) +
                                               offsetof(DirectGuestMemoryCache, size)));
                if (directReadSpan && operationIndex == directReadSpan->firstLoadOperationIndex) {
                    const auto rejected = assembler.makeLabel();
                    const auto guarded = assembler.makeLabel();
                    assembler.pushCallerSaved5Through15();
                    assembler.mov(arm64::x1, hostRegister(directReadSpan->address));
                    assembler.mov(arm64::x2, hostRegister(directReadSpan->induction));
                    assembler.movImmediate(arm64::x3, directReadSpan->step);
                    assembler.movImmediate(arm64::x4, directReadSpan->limit);
                    assembler.movImmediate(arm64::x5, directReadSpan->maximumOffset);
                    assembler.mov(arm64::x0, arm64::x19);
                    assembler.movImmediate(arm64::x16, pointerBits(&validateDirectGuestReadSpan));
                    assembler.blr(arm64::x16);
                    assembler.popCallerSaved5Through15();
                    assembler.mov(arm64::x3, arm64::x0);
                    assembler.mov(arm64::x0, arm64::x25);
                    assembler.cbz(arm64::x3, rejected);
                    assembler.movImmediate(arm64::x4, 1);
                    assembler.b(guarded);
                    assembler.bind(rejected);
                    assembler.movImmediate(arm64::x4, 0);
                    assembler.movImmediate(arm64::x20, 0);
                    assembler.bind(guarded);
                } else if (adjacent) {
                    assembler.movImmediate(arm64::x4, 0);
                }
                assembler.b(completed);
                assembler.bind(directFast);
                if (directReadSpan && operationIndex == directReadSpan->firstLoadOperationIndex) {
                    assembler.ldr8(hostRegister(*operation.result), arm64::x3, 0);
                } else if (adjacent && !adjacent->first) {
                    assembler.ldr8(hostRegister(*operation.result), arm64::x3, adjacent->offset);
                } else {
                    assembler.sub(arm64::x17, hostRegister(*operation.lhs), arm64::x21);
                    if (adjacent) {
                        assembler.addImmediate(arm64::x16, arm64::x17, adjacent->maximumOffset);
                        assembler.compare(arm64::x16, arm64::x22);
                    } else {
                        assembler.compare(arm64::x17, arm64::x22);
                    }
                    assembler.bUnsignedHigherOrSame(checkedHelper);
                    assembler.add(adjacent ? arm64::x3 : arm64::x16, arm64::x20, arm64::x17);
                    assembler.ldr8(hostRegister(*operation.result),
                                   adjacent ? arm64::x3 : arm64::x16, 0);
                    if (adjacent) {
                        assembler.movImmediate(arm64::x4, 1);
                    }
                }
            }
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::LoadFence:
            assembler.dmbIsh();
            assembler.isb();
            break;
        case ir::Opcode::StoreFence:
            assembler.dmbIsh();
            break;
        case ir::Opcode::WriteDirectionFlag:
            assembler.ldr(arm64::x16, arm64::x0,
                          static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
            assembler.movImmediate(arm64::x17,
                                   operation.immediate != 0 ? x86::flagDirection
                                                            : ~x86::flagDirection);
            if (operation.immediate != 0) {
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
            } else {
                assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
            }
            assembler.str(arm64::x16, arm64::x0,
                          static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
            break;
        case ir::Opcode::Cpuid:
            assembler.movImmediate(arm64::x16, pointerBits(&cpuidGuest));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ReadTimestampCounter: {
            const auto fault = assembler.makeLabel();
            const auto sampled = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&readTimestampCounter));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(sampled);
            assembler.bind(fault);
            emitFaultExit(BlockExit::ExecutionFault, operation.guestRip);
            assembler.bind(sampled);
            break;
        }
        case ir::Opcode::UpdateAddFlags:
        case ir::Opcode::UpdateSubFlags: {
            if (operation.opcode == ir::Opcode::UpdateAddFlags) {
                const auto lhs = hostRegister(*operation.lhs);
                const auto rhs = hostRegister(*operation.rhs);
                const auto result = hostRegister(*operation.third);
                const auto carryDone = assembler.makeLabel();
                const auto parityDone = assembler.makeLabel();
                const auto auxiliaryDone = assembler.makeLabel();
                const auto zeroDone = assembler.makeLabel();
                const auto overflowDone = assembler.makeLabel();
                const auto signBit = operation.width == ir::Width::I8    ? 7U
                                     : operation.width == ir::Width::I16 ? 15U
                                     : operation.width == ir::Width::I32 ? 31U
                                                                         : 63U;

                if (operation.width == ir::Width::I64) {
                    assembler.mov(arm64::x1, lhs);
                    assembler.mov(arm64::x2, rhs);
                    assembler.mov(arm64::x3, result);
                } else {
                    const auto valueMask =
                        operation.width == ir::Width::I8    ? std::uint64_t{UINT8_MAX}
                        : operation.width == ir::Width::I16 ? std::uint64_t{UINT16_MAX}
                                                            : std::uint64_t{UINT32_MAX};
                    assembler.movImmediate(arm64::x17, valueMask);
                    assembler.bitAnd(arm64::x1, lhs, arm64::x17);
                    assembler.bitAnd(arm64::x2, rhs, arm64::x17);
                    assembler.bitAnd(arm64::x3, result, arm64::x17);
                }

                assembler.ldr(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                assembler.movImmediate(arm64::x17, ~arithmeticFlagMask);
                assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
                assembler.movImmediate(arm64::x17, flagReservedOne);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);

                assembler.compare(arm64::x3, arm64::x1);
                assembler.bUnsignedHigherOrSame(carryDone);
                assembler.movImmediate(arm64::x17, flagCarry);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(carryDone);

                assembler.mov(arm64::x17, arm64::x3);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 4);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 2);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 1);
                assembler.tbnz(arm64::x17, 0, parityDone);
                assembler.movImmediate(arm64::x17, flagParity);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(parityDone);

                assembler.bitXor(arm64::x17, arm64::x1, arm64::x2);
                assembler.bitXor(arm64::x17, arm64::x17, arm64::x3);
                assembler.tbz(arm64::x17, 4, auxiliaryDone);
                assembler.movImmediate(arm64::x17, flagAuxiliaryCarry);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(auxiliaryDone);

                assembler.cbnz(arm64::x3, zeroDone);
                assembler.movImmediate(arm64::x17, flagZero);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(zeroDone);

                assembler.lsrImmediate(arm64::x17, arm64::x3, static_cast<std::uint8_t>(signBit));
                assembler.bitOrShiftedLeft(arm64::x16, arm64::x16, arm64::x17, 7);

                assembler.bitXor(arm64::x17, arm64::x1, arm64::x3);
                assembler.bitXor(arm64::x1, arm64::x2, arm64::x3);
                assembler.bitAnd(arm64::x17, arm64::x17, arm64::x1);
                assembler.tbz(arm64::x17, static_cast<std::uint8_t>(signBit), overflowDone);
                assembler.movImmediate(arm64::x17, flagOverflow);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(overflowDone);

                assembler.str(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                break;
            }
            if (operation.opcode == ir::Opcode::UpdateSubFlags &&
                operation.width == ir::Width::I8) {
                const auto lhs = hostRegister(*operation.lhs);
                const auto rhs = hostRegister(*operation.rhs);
                const auto result = hostRegister(*operation.third);
                const auto carryDone = assembler.makeLabel();
                const auto parityDone = assembler.makeLabel();
                const auto auxiliaryDone = assembler.makeLabel();
                const auto zeroDone = assembler.makeLabel();
                const auto overflowDone = assembler.makeLabel();

                // The R1 allocator keeps live IR values in x8...x15, so the
                // ordinary argument registers are available as narrow-value
                // temporaries.  Mask first: byte operations intentionally
                // leave unrelated high bits in their host registers.
                assembler.movImmediate(arm64::x17, UINT8_MAX);
                assembler.bitAnd(arm64::x1, lhs, arm64::x17);
                assembler.bitAnd(arm64::x2, rhs, arm64::x17);
                assembler.bitAnd(arm64::x3, result, arm64::x17);

                assembler.ldr(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                assembler.movImmediate(arm64::x17, ~arithmeticFlagMask);
                assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
                assembler.movImmediate(arm64::x17, flagReservedOne);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);

                assembler.compare(arm64::x1, arm64::x2);
                assembler.bUnsignedHigherOrSame(carryDone);
                assembler.movImmediate(arm64::x17, flagCarry);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(carryDone);

                assembler.mov(arm64::x17, arm64::x3);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 4);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 2);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 1);
                assembler.tbnz(arm64::x17, 0, parityDone);
                assembler.movImmediate(arm64::x17, flagParity);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(parityDone);

                assembler.bitXor(arm64::x17, arm64::x1, arm64::x2);
                assembler.bitXor(arm64::x17, arm64::x17, arm64::x3);
                assembler.tbz(arm64::x17, 4, auxiliaryDone);
                assembler.movImmediate(arm64::x17, flagAuxiliaryCarry);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(auxiliaryDone);

                assembler.cbnz(arm64::x3, zeroDone);
                assembler.movImmediate(arm64::x17, flagZero);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(zeroDone);

                assembler.lsrImmediate(arm64::x17, arm64::x3, 7);
                assembler.bitOrShiftedLeft(arm64::x16, arm64::x16, arm64::x17, 7);

                assembler.bitXor(arm64::x17, arm64::x1, arm64::x2);
                assembler.bitXor(arm64::x1, arm64::x1, arm64::x3);
                assembler.bitAnd(arm64::x17, arm64::x17, arm64::x1);
                assembler.tbz(arm64::x17, 7, overflowDone);
                assembler.movImmediate(arm64::x17, flagOverflow);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(overflowDone);

                assembler.str(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                break;
            }
            if (operation.opcode == ir::Opcode::UpdateSubFlags &&
                operation.width == ir::Width::I64) {
                emitSubFlags64(hostRegister(*operation.lhs), hostRegister(*operation.rhs),
                               hostRegister(*operation.third));
                break;
            }
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.mov(arm64::x3, hostRegister(*operation.third));
            if (operation.opcode == ir::Opcode::UpdateAddFlags) {
                assembler.movImmediate(
                    arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&updateAddFlags8)
                                : operation.width == ir::Width::I16 ? pointerBits(&updateAddFlags16)
                                : operation.width == ir::Width::I32
                                    ? pointerBits(&updateAddFlags32)
                                    : pointerBits(&updateAddFlags64));
            } else {
                assembler.movImmediate(
                    arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&updateSubFlags8)
                                : operation.width == ir::Width::I16 ? pointerBits(&updateSubFlags16)
                                : operation.width == ir::Width::I32
                                    ? pointerBits(&updateSubFlags32)
                                    : pointerBits(&updateSubFlags64));
            }
            assembler.blr(arm64::x16);
            break;
        }
        case ir::Opcode::UpdateAdcFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.mov(arm64::x3, hostRegister(*operation.third));
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&updateAdcFlags8)
                                                   : operation.width == ir::Width::I32
                                                         ? pointerBits(&updateAdcFlags32)
                                                         : pointerBits(&updateAdcFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateSbbFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.mov(arm64::x3, hostRegister(*operation.third));
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&updateSbbFlags8)
                                               : operation.width == ir::Width::I16
                                                   ? pointerBits(&updateSbbFlags16)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&updateSbbFlags32)
                                                   : pointerBits(&updateSbbFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateIncFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.movImmediate(
                arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&updateIncFlags8)
                             : operation.width == ir::Width::I16 ? pointerBits(&updateIncFlags16)
                             : operation.width == ir::Width::I32 ? pointerBits(&updateIncFlags32)
                                                                 : pointerBits(&updateIncFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateDecFlags:
            if (operation.width == ir::Width::I64) {
                const auto original = hostRegister(*operation.lhs);
                const auto result = hostRegister(*operation.rhs);
                const auto parityDone = assembler.makeLabel();
                const auto auxiliaryDone = assembler.makeLabel();
                const auto zeroDone = assembler.makeLabel();

                assembler.ldr(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                assembler.movImmediate(arm64::x17, ~(arithmeticFlagMask & ~flagCarry));
                assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
                assembler.movImmediate(arm64::x17, flagReservedOne);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);

                assembler.mov(arm64::x17, result);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 4);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 2);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 1);
                assembler.tbnz(arm64::x17, 0, parityDone);
                assembler.movImmediate(arm64::x17, flagParity);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(parityDone);

                assembler.bitXor(arm64::x17, original, result);
                assembler.tbz(arm64::x17, 4, auxiliaryDone);
                assembler.movImmediate(arm64::x17, flagAuxiliaryCarry);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(auxiliaryDone);

                assembler.cbnz(result, zeroDone);
                assembler.movImmediate(arm64::x17, flagZero);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(zeroDone);

                assembler.lsrImmediate(arm64::x17, result, 63);
                assembler.bitOrShiftedLeft(arm64::x16, arm64::x16, arm64::x17, 7);

                assembler.movImmediate(arm64::x17, UINT64_C(1) << 63U);
                assembler.compare(original, arm64::x17);
                assembler.movImmediate(arm64::x17, flagOverflow);
                assembler.bitOr(arm64::x17, arm64::x16, arm64::x17);
                assembler.conditionalSelectEqual(arm64::x16, arm64::x17, arm64::x16);
                assembler.str(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
            } else {
                assembler.mov(arm64::x1, hostRegister(*operation.lhs));
                assembler.mov(arm64::x2, hostRegister(*operation.rhs));
                assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                       ? pointerBits(&updateDecFlags8)
                                                       : operation.width == ir::Width::I16
                                                             ? pointerBits(&updateDecFlags16)
                                                             : pointerBits(&updateDecFlags32));
                assembler.blr(arm64::x16);
            }
            break;
        case ir::Opcode::UpdateLogicFlags:
            emitLogicFlags(hostRegister(*operation.lhs), operation.width);
            break;
        case ir::Opcode::UpdateShiftLeftFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            if (operation.third) {
                assembler.mov(arm64::x3, hostRegister(*operation.third));
            } else {
                assembler.movImmediate(arm64::x3, operation.immediate);
            }
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&updateShiftLeftFlags8)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&updateShiftLeftFlags32)
                                                   : pointerBits(&updateShiftLeftFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateShiftRightFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            if (operation.third) {
                assembler.mov(arm64::x3, hostRegister(*operation.third));
            } else {
                assembler.movImmediate(arm64::x3, operation.immediate);
            }
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&updateShiftRightFlags8)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&updateShiftRightFlags32)
                                                   : pointerBits(&updateShiftRightFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateShiftRightArithmeticFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            if (operation.third) {
                assembler.mov(arm64::x3, hostRegister(*operation.third));
            } else {
                assembler.movImmediate(arm64::x3, operation.immediate);
            }
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&updateShiftRightArithmeticFlags32)
                                                   : pointerBits(&updateShiftRightArithmeticFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateRotateLeftFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            if (operation.rhs) {
                assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            } else {
                assembler.movImmediate(arm64::x2, operation.immediate);
            }
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I16
                                                   ? pointerBits(&updateRotateLeftFlags16)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&updateRotateLeftFlags32)
                                                   : pointerBits(&updateRotateLeftFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateRotateRightFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            if (operation.rhs) {
                assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            } else {
                assembler.movImmediate(arm64::x2, operation.immediate);
            }
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&updateRotateRightFlags32)
                                                   : pointerBits(&updateRotateRightFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateMultiplyFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x16, pointerBits(&updateMultiplyFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateSignedMultiplyFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&updateSignedMultiplyFlags32)
                                                   : pointerBits(&updateSignedMultiplyFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateShiftRightDoubleFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&updateShiftRightDoubleFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateBitTestFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x2, operation.immediate);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I64
                                                   ? pointerBits(&updateBitTestFlags64)
                                                   : pointerBits(&updateBitTestFlags32));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ExitBlock: {
            BlockExit exit = BlockExit::Continue;
            bool emittedInternalConditionalExit = false;
            switch (operation.exitKind) {
            case ir::ExitKind::Return:
                assembler.movImmediate(arm64::x16, operation.guestRip.value);
                exit = BlockExit::Return;
                break;
            case ir::ExitKind::Direct:
                if (operation.lhs) {
                    assembler.mov(arm64::x16, hostRegister(*operation.lhs));
                } else {
                    assembler.movImmediate(arm64::x16, operation.target->value);
                }
                break;
            case ir::ExitKind::Call:
                if (operation.lhs) {
                    assembler.mov(arm64::x16, hostRegister(*operation.lhs));
                } else {
                    assembler.movImmediate(arm64::x16, operation.target->value);
                }
                exit = BlockExit::Call;
                break;
            case ir::ExitKind::Syscall:
                assembler.movImmediate(arm64::x16, operation.target->value);
                assembler.str(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rcx)));
                assembler.ldr(arm64::x17, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                assembler.str(arm64::x17, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, r11)));
                exit = BlockExit::Syscall;
                break;
            case ir::ExitKind::Conditional: {
                constexpr std::uint8_t zeroFlagBit = 6;
                constexpr std::uint8_t carryFlagBit = 0;
                constexpr std::uint8_t signFlagBit = 7;
                constexpr std::uint8_t overflowFlagBit = 11;
                const auto notTaken = assembler.makeLabel();
                const auto taken = assembler.makeLabel();
                const auto selected = assembler.makeLabel();
                if (internalSelfEdge) {
                    assembler.subImmediate(arm64::x23, arm64::x23, 1);
                }
                if (deferredExitUpdate) {
                    const auto &update = block.operations[*deferredExitUpdate];
                    assembler.compare(hostRegister(*update.lhs), hostRegister(*update.rhs));
                    switch (*operation.condition) {
                    case x86::Condition::Overflow:
                        assembler.bConditional(arm64::BranchCondition::NoOverflow, notTaken);
                        break;
                    case x86::Condition::NotOverflow:
                        assembler.bConditional(arm64::BranchCondition::Overflow, notTaken);
                        break;
                    case x86::Condition::ParityEven:
                    case x86::Condition::ParityOdd:
                        // Unreachable: flag deferral is disabled for parity
                        // exits, which always take the flag-test path below.
                        throw std::runtime_error(
                            "ARM64 backend cannot test parity from deferred NZCV");
                    case x86::Condition::Equal:
                        assembler.bConditional(arm64::BranchCondition::NotEqual, notTaken);
                        break;
                    case x86::Condition::NotEqual:
                        assembler.bConditional(arm64::BranchCondition::Equal, notTaken);
                        break;
                    case x86::Condition::Below:
                        assembler.bConditional(arm64::BranchCondition::UnsignedHigherOrSame,
                                               notTaken);
                        break;
                    case x86::Condition::AboveOrEqual:
                        assembler.bConditional(arm64::BranchCondition::UnsignedLower, notTaken);
                        break;
                    case x86::Condition::Above:
                        assembler.bConditional(arm64::BranchCondition::UnsignedLowerOrSame,
                                               notTaken);
                        break;
                    case x86::Condition::BelowOrEqual:
                        assembler.bConditional(arm64::BranchCondition::UnsignedHigher, notTaken);
                        break;
                    case x86::Condition::Sign:
                        assembler.bConditional(arm64::BranchCondition::NonNegative, notTaken);
                        break;
                    case x86::Condition::NotSign:
                        assembler.bConditional(arm64::BranchCondition::Negative, notTaken);
                        break;
                    case x86::Condition::Less:
                        assembler.bConditional(arm64::BranchCondition::SignedGreaterOrEqual,
                                               notTaken);
                        break;
                    case x86::Condition::GreaterOrEqual:
                        assembler.bConditional(arm64::BranchCondition::SignedLess, notTaken);
                        break;
                    case x86::Condition::LessOrEqual:
                        assembler.bConditional(arm64::BranchCondition::SignedGreater, notTaken);
                        break;
                    case x86::Condition::Greater:
                        assembler.bConditional(arm64::BranchCondition::SignedLessOrEqual, notTaken);
                        break;
                    }
                } else {
                    assembler.ldr(arm64::x16, arm64::x0,
                                  static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                    if (*operation.condition == x86::Condition::Overflow) {
                        assembler.tbz(arm64::x16, overflowFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::NotOverflow) {
                        assembler.tbnz(arm64::x16, overflowFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::ParityEven) {
                        constexpr std::uint8_t parityFlagBit = 2;
                        assembler.tbz(arm64::x16, parityFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::ParityOdd) {
                        constexpr std::uint8_t parityFlagBit = 2;
                        assembler.tbnz(arm64::x16, parityFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Equal) {
                        assembler.tbz(arm64::x16, zeroFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::NotEqual) {
                        assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Below) {
                        assembler.tbz(arm64::x16, carryFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::AboveOrEqual) {
                        assembler.tbnz(arm64::x16, carryFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Above) {
                        assembler.tbnz(arm64::x16, carryFlagBit, notTaken);
                        assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::BelowOrEqual) {
                        assembler.tbnz(arm64::x16, carryFlagBit, taken);
                        assembler.tbz(arm64::x16, zeroFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Sign) {
                        assembler.tbz(arm64::x16, signFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::NotSign) {
                        assembler.tbnz(arm64::x16, signFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Less) {
                        // OF is bit 11, so shifting it down by four aligns it with SF.
                        assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                        assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                        assembler.tbz(arm64::x17, signFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::GreaterOrEqual) {
                        // OF is bit 11, so shifting it down by four aligns it with SF.
                        assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                        assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                        assembler.tbnz(arm64::x17, signFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Greater) {
                        assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                        assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                        assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                        assembler.tbnz(arm64::x17, signFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::LessOrEqual) {
                        assembler.tbnz(arm64::x16, zeroFlagBit, taken);
                        // OF is bit 11, so shifting it down by four aligns it with SF.
                        assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                        assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                        assembler.tbz(arm64::x17, signFlagBit, notTaken);
                    } else {
                        throw std::runtime_error(
                            "ARM64 backend received unsupported branch condition");
                    }
                }
                if (internalSelfEdge) {
                    const auto returnSelf = assembler.makeLabel();
                    const auto returnSelected = assembler.makeLabel();
                    const auto emitSelfEdge = [&] {
                        assembler.cbz(arm64::x23, returnSelf);
                        if (directWriteFastEntry) {
                            assembler.cbnz(arm64::x4, *directWriteFastEntry);
                        }
                        if (directReadFastEntry) {
                            const auto checkedEntry = assembler.makeLabel();
                            assembler.cbz(arm64::x4, checkedEntry);
                            assembler.addImmediate(arm64::x3, arm64::x3, directReadSpan->step);
                            assembler.b(*directReadFastEntry);
                            assembler.bind(checkedEntry);
                        }
                        emitStopRepeatingCheck(returnSelf);
                        assembler.b(repeatedEntry);
                    };
                    const auto emitSideExit = [&](guest::GuestAddress address) {
                        assembler.movImmediate(arm64::x16, address.value);
                        assembler.b(returnSelected);
                    };

                    assembler.bind(taken);
                    if (*operation.target == block.start) {
                        emitSelfEdge();
                    } else {
                        emitSideExit(*operation.target);
                    }
                    assembler.bind(notTaken);
                    if (*operation.fallthrough == block.start) {
                        emitSelfEdge();
                    } else {
                        emitSideExit(*operation.fallthrough);
                    }
                    assembler.bind(returnSelf);
                    if (pinnedLoopConstant) {
                        assembler.movImmediate(arm64::x16, block.start.value);
                    } else {
                        assembler.mov(arm64::x16, arm64::x24);
                    }
                    assembler.bind(returnSelected);
                    assembler.str(arm64::x16, arm64::x0,
                                  static_cast<std::uint32_t>(offsetof(x86::X86State, rip)));
                    if (deferredExitUpdate) {
                        const auto &update = block.operations[*deferredExitUpdate];
                        if (deferredExitResultOperation) {
                            assembler.sub(hostRegister(*update.third), hostRegister(*update.lhs),
                                          hostRegister(*update.rhs));
                        }
                        emitSubFlags64(hostRegister(*update.lhs), hostRegister(*update.rhs),
                                       hostRegister(*update.third));
                    }
                    emitEpilogue();
                    assembler.movImmediate(arm64::x0,
                                           static_cast<std::uint64_t>(BlockExit::Continue));
                    assembler.ret();
                    emittedInternalConditionalExit = true;
                    break;
                }
                assembler.bind(taken);
                assembler.movImmediate(arm64::x16, operation.target->value);
                assembler.b(selected);
                assembler.bind(notTaken);
                assembler.movImmediate(arm64::x16, operation.fallthrough->value);
                assembler.bind(selected);
                break;
            }
            }
            if (emittedInternalConditionalExit) {
                break;
            }
            assembler.str(arm64::x16, arm64::x0,
                          static_cast<std::uint32_t>(offsetof(x86::X86State, rip)));
            if (internalSelfEdge && exit == BlockExit::Continue) {
                const auto returnToDispatcher = assembler.makeLabel();
                assembler.subImmediate(arm64::x23, arm64::x23, 1);
                assembler.cbz(arm64::x23, returnToDispatcher);
                emitStopRepeatingCheck(returnToDispatcher);
                if (pinnedLoopConstant) {
                    assembler.movImmediate(arm64::x1, block.start.value);
                    assembler.bitXor(arm64::x1, arm64::x16, arm64::x1);
                } else {
                    assembler.bitXor(arm64::x1, arm64::x16, arm64::x24);
                }
                assembler.cbnz(arm64::x1, returnToDispatcher);
                assembler.b(repeatedEntry);
                assembler.bind(returnToDispatcher);
                if (deferredExitUpdate) {
                    const auto &update = block.operations[*deferredExitUpdate];
                    if (deferredExitResultOperation) {
                        assembler.sub(hostRegister(*update.third), hostRegister(*update.lhs),
                                      hostRegister(*update.rhs));
                    }
                    emitSubFlags64(hostRegister(*update.lhs), hostRegister(*update.rhs),
                                   hostRegister(*update.third));
                }
            }
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(exit));
            assembler.ret();
            break;
        }
        }
    }
    return std::move(assembler).finish();
}

} // namespace rosa::arm64
