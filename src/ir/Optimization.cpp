#include "ir/Optimization.h"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

namespace rosa::ir {
namespace {

bool isSafelyRepeatableOperation(const ir::Operation &operation) {
    switch (operation.opcode) {
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
    case ir::Opcode::LoadGuest:
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
    case ir::Opcode::StoreGuest:
    case ir::Opcode::ExitBlock:
        return true;
    default:
        return false;
    }
}

void forwardFullWidthGuestReads(ir::Block &block, bool directMemoryLoop) {
    constexpr std::size_t registerCount = 16;
    const auto forwardsAcrossLoads =
        directMemoryLoop && std::ranges::any_of(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::LoadGuest && operation.width == ir::Width::I8;
        });
    const auto forwardsAcrossStores =
        directMemoryLoop && !forwardsAcrossLoads &&
        std::ranges::any_of(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::StoreGuest && operation.width == ir::Width::I8;
        });
    std::array<std::optional<ir::ValueId>, registerCount> currentValues;
    std::array<bool, registerCount> currentValuesAreFull{};
    std::array<bool, registerCount> currentValuesAreZeroExtended{};
    std::array<bool, registerCount> currentValuesAreZero{};
    std::vector<ir::ValueId> replacements(block.valueCount);
    std::vector<bool> zeroExtendedValues(block.valueCount);
    std::vector<bool> zeroValues(block.valueCount);
    std::vector<bool> conditionValues(block.valueCount);
    for (std::size_t value = 0; value < replacements.size(); ++value) {
        replacements[value] = ir::ValueId{static_cast<std::uint32_t>(value)};
    }
    const auto resolve = [&](ir::ValueId value) {
        while (replacements[value.value] != value) {
            value = replacements[value.value];
        }
        return value;
    };
    const auto canonicalize = [&](std::optional<ir::ValueId> &value) {
        if (value) {
            *value = resolve(*value);
        }
    };
    const auto isZeroExtended = [&](ir::ValueId value) {
        return zeroExtendedValues[resolve(value).value];
    };
    const auto isZero = [&](ir::ValueId value) { return zeroValues[resolve(value).value]; };
    const auto preservesHostValues = [&](const ir::Operation &operation) {
        switch (operation.opcode) {
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
        case ir::Opcode::UpdateAddFlags:
        case ir::Opcode::UpdateLogicFlags:
            return true;
        case ir::Opcode::UpdateSubFlags:
            return operation.width == ir::Width::I8 || operation.width == ir::Width::I64;
        case ir::Opcode::LoadGuest:
            return forwardsAcrossLoads && operation.width == ir::Width::I8;
        case ir::Opcode::StoreGuest:
            return forwardsAcrossStores && operation.width == ir::Width::I8;
        default:
            return false;
        }
    };

    std::vector<ir::Operation> operations;
    operations.reserve(block.operations.size());
    for (auto operation : block.operations) {
        canonicalize(operation.lhs);
        canonicalize(operation.rhs);
        canonicalize(operation.third);

        if (forwardsAcrossLoads && operation.result && operation.opcode == ir::Opcode::Add) {
            const auto equivalent = std::ranges::find_if(operations, [&](const auto &candidate) {
                return candidate.result && candidate.opcode == operation.opcode &&
                       candidate.width == operation.width && candidate.lhs == operation.lhs &&
                       candidate.rhs == operation.rhs && candidate.third == operation.third &&
                       candidate.immediate == operation.immediate;
            });
            if (equivalent != operations.end()) {
                const auto source = resolve(*equivalent->result);
                replacements[operation.result->value] = source;
                zeroExtendedValues[operation.result->value] = zeroExtendedValues[source.value];
                zeroValues[operation.result->value] = zeroValues[source.value];
                conditionValues[operation.result->value] = conditionValues[source.value];
                continue;
            }
        }

        if (operation.opcode == ir::Opcode::ReadGuestReg && operation.guestRegister &&
            operation.result &&
            (operation.width == ir::Width::I32 || operation.width == ir::Width::I64)) {
            const auto index = static_cast<std::size_t>(*operation.guestRegister);
            if (index < currentValues.size() && currentValues[index] &&
                ((operation.width == ir::Width::I64 && currentValuesAreFull[index]) ||
                 (operation.width == ir::Width::I32 && currentValuesAreZeroExtended[index]))) {
                replacements[operation.result->value] = resolve(*currentValues[index]);
                zeroExtendedValues[operation.result->value] = currentValuesAreZeroExtended[index];
                zeroValues[operation.result->value] = currentValuesAreZero[index];
                continue;
            }
            if (index < currentValues.size()) {
                currentValues[index] = *operation.result;
                currentValuesAreFull[index] = operation.width == ir::Width::I64;
                currentValuesAreZeroExtended[index] = operation.width == ir::Width::I32;
                currentValuesAreZero[index] = false;
            }
        } else if (operation.opcode == ir::Opcode::WriteGuestReg && operation.guestRegister) {
            const auto index = static_cast<std::size_t>(*operation.guestRegister);
            if (index < currentValues.size()) {
                if ((operation.width == ir::Width::I32 || operation.width == ir::Width::I64) &&
                    operation.lhs) {
                    currentValues[index] = operation.lhs;
                    currentValuesAreFull[index] =
                        operation.width == ir::Width::I64 || isZeroExtended(*operation.lhs);
                    currentValuesAreZeroExtended[index] = isZeroExtended(*operation.lhs);
                    currentValuesAreZero[index] = isZero(*operation.lhs);
                } else if (operation.width == ir::Width::I8 && operation.lhs &&
                           currentValuesAreZero[index] &&
                           conditionValues[resolve(*operation.lhs).value]) {
                    currentValues[index] = operation.lhs;
                    currentValuesAreFull[index] = true;
                    currentValuesAreZeroExtended[index] = isZeroExtended(*operation.lhs);
                    currentValuesAreZero[index] = isZero(*operation.lhs);
                } else {
                    currentValues[index].reset();
                    currentValuesAreFull[index] = false;
                    currentValuesAreZeroExtended[index] = false;
                    currentValuesAreZero[index] = false;
                }
            }
        } else if (operation.opcode == ir::Opcode::ConditionalMoveGuestReg &&
                   operation.guestRegister) {
            const auto index = static_cast<std::size_t>(*operation.guestRegister);
            if (index < currentValues.size()) {
                currentValues[index].reset();
                currentValuesAreFull[index] = false;
                currentValuesAreZeroExtended[index] = false;
                currentValuesAreZero[index] = false;
            }
        } else if (!preservesHostValues(operation)) {
            currentValues.fill(std::nullopt);
            currentValuesAreFull.fill(false);
            currentValuesAreZeroExtended.fill(false);
            currentValuesAreZero.fill(false);
        }

        if (operation.result) {
            const auto result = operation.result->value;
            zeroValues[result] =
                operation.opcode == ir::Opcode::Constant && operation.immediate == 0;
            conditionValues[result] = operation.opcode == ir::Opcode::EvaluateCondition;
            zeroExtendedValues[result] =
                zeroValues[result] || conditionValues[result] ||
                (operation.width == ir::Width::I32 &&
                 (operation.opcode == ir::Opcode::Constant ||
                  operation.opcode == ir::Opcode::ReadGuestReg ||
                  operation.opcode == ir::Opcode::Add || operation.opcode == ir::Opcode::Sub ||
                  operation.opcode == ir::Opcode::And || operation.opcode == ir::Opcode::Or ||
                  operation.opcode == ir::Opcode::Xor ||
                  operation.opcode == ir::Opcode::LoadGuest));
        }
        operations.push_back(std::move(operation));
    }
    block.operations = std::move(operations);
}

} // namespace

bool hasInternalSelfEdge(const ir::Block &block) {
    if (!std::ranges::all_of(block.operations, isSafelyRepeatableOperation)) {
        return false;
    }
    return std::ranges::any_of(block.operations, [&block](const auto &operation) {
        return operation.opcode == ir::Opcode::ExitBlock &&
               ((operation.target && *operation.target == block.start) ||
                (operation.fallthrough && *operation.fallthrough == block.start));
    });
}

void optimizeBlock(Block &block) {
    forwardFullWidthGuestReads(block, hasInternalSelfEdge(block));
#ifndef NDEBUG
    const auto errors = verify(block);
    if (!errors.empty()) {
        throw std::runtime_error("optimized IR verification failed: " + errors.front());
    }
#endif
}

} // namespace rosa::ir
