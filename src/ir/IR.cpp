#include "ir/IR.h"

#include <array>
#include <utility>

namespace rosa::ir {

ValueId Builder::nextValue() { return ValueId{block_.valueCount++}; }

ValueId Builder::constant(std::uint64_t value, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::Constant,
        .width = width,
        .guestRip = rip,
        .result = result,
        .immediate = value,
    });
    return result;
}

ValueId Builder::readGuestRegister(x86::Register reg, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ReadGuestReg,
        .width = width,
        .guestRip = rip,
        .result = result,
        .guestRegister = reg,
    });
    return result;
}

ValueId Builder::readGuestGsBase(guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ReadGuestGsBase,
        .width = Width::I64,
        .guestRip = rip,
        .result = result,
    });
    return result;
}

void Builder::writeGuestRegister(x86::Register reg, ValueId value, Width width,
                                 guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::WriteGuestReg,
        .width = width,
        .guestRip = rip,
        .lhs = value,
        .guestRegister = reg,
    });
}

void Builder::conditionalMoveGuestRegister(x86::Register destination,
                                           x86::Register source,
                                           x86::Condition condition, Width width,
                                           guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ConditionalMoveGuestReg,
        .width = width,
        .guestRip = rip,
        .guestRegister = destination,
        .condition = condition,
        .immediate = static_cast<std::uint64_t>(source),
    });
}

ValueId Builder::readGuestXmmLane(x86::XmmRegister reg, bool high,
                                  guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ReadGuestXmmLane,
        .width = Width::I64,
        .guestRip = rip,
        .result = result,
        .guestXmmRegister = reg,
        .immediate = high ? 1U : 0U,
    });
    return result;
}

void Builder::writeGuestXmmLane(x86::XmmRegister reg, bool high, ValueId value,
                                guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::WriteGuestXmmLane,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = value,
        .guestXmmRegister = reg,
        .immediate = high ? 1U : 0U,
    });
}

ValueId Builder::add(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::Add,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::sub(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::Sub,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::shiftLeft(ValueId value, std::uint8_t count, Width width,
                           guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftLeft,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = value,
        .immediate = count,
    });
    return result;
}

ValueId Builder::shiftLeft(ValueId value, ValueId count, Width width,
                           guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftLeft,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = value,
        .rhs = count,
    });
    return result;
}

ValueId Builder::shiftRightLogical(ValueId value, std::uint8_t count, Width width,
                                   guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftRightLogical,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = value,
        .immediate = count,
    });
    return result;
}

ValueId Builder::multiplyLow(ValueId lhs, ValueId rhs, Width width,
                             guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::MultiplyLow,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::multiplyHighUnsigned(ValueId lhs, ValueId rhs, Width width,
                                      guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::MultiplyHighUnsigned,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::shiftRightDouble(ValueId low, ValueId high, std::uint8_t count,
                                  Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftRightDouble,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = low,
        .rhs = high,
        .immediate = count,
    });
    return result;
}

ValueId Builder::bitAnd(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::And,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::bitOr(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::Or,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::bitXor(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::Xor,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::signExtend32(ValueId value, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::SignExtend32,
        .width = Width::I64,
        .guestRip = rip,
        .result = result,
        .lhs = value,
    });
    return result;
}

ValueId Builder::evaluateCondition(x86::Condition condition,
                                   guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::EvaluateCondition,
        .width = Width::I8,
        .guestRip = rip,
        .result = result,
        .condition = condition,
    });
    return result;
}

ValueId Builder::loadGuest(ValueId address, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::LoadGuest,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = address,
    });
    return result;
}

void Builder::storeGuest(ValueId address, ValueId value, Width width,
                         guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::StoreGuest,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = value,
    });
}

void Builder::storeGuestXmm(ValueId address, x86::XmmRegister reg, bool aligned,
                            guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::StoreGuestXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
        .immediate = aligned ? 1U : 0U,
    });
}

void Builder::loadGuestXmm(ValueId address, x86::XmmRegister reg, bool aligned,
                           guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LoadGuestXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
        .immediate = aligned ? 1U : 0U,
    });
}

void Builder::compareEqualGuestBytesXmm(ValueId address, x86::XmmRegister reg,
                                        guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::CompareEqualGuestBytesXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
    });
}

void Builder::moveXmmByteMask(x86::Register destination, x86::XmmRegister source,
                              guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::MoveXmmByteMask,
        .width = Width::I32,
        .guestRip = rip,
        .guestRegister = destination,
        .guestXmmRegister = source,
    });
}

void Builder::shuffleXmmDwords(x86::XmmRegister destination,
                               x86::XmmRegister source,
                               std::uint8_t control,
                               guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShuffleXmmDwords,
        .width = Width::I32,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
        .immediate = control,
    });
}

void Builder::bitScanForward(x86::Register destination, x86::Register source,
                             Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::BitScanForward,
        .width = width,
        .guestRip = rip,
        .guestRegister = destination,
        .immediate = static_cast<std::uint64_t>(source),
    });
}

void Builder::push(ValueId newStackPointer, ValueId value, Width width,
                   guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::Push,
        .width = width,
        .guestRip = rip,
        .lhs = newStackPointer,
        .rhs = value,
    });
}

void Builder::addGuestMemory(ValueId address, ValueId source, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::AddGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
    });
}

void Builder::incrementGuestMemory(ValueId address, Width width,
                                   guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::IncrementGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
    });
}

void Builder::decrementGuestMemory(ValueId address, Width width,
                                   guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::DecrementGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
    });
}

void Builder::compareExchangeGuestMemory(ValueId address, ValueId source,
                                         Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::CompareExchangeGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
    });
}

void Builder::exchangeGuestMemory(ValueId address, ValueId source,
                                  x86::Register destination, Width width,
                                  guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExchangeGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
        .guestRegister = destination,
    });
}

void Builder::lockedIncrementGuestMemory(ValueId address, Width width,
                                         guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LockedIncrementGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
    });
}

void Builder::lockedOrGuestMemory(ValueId address, ValueId immediate,
                                  Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LockedOrGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = immediate,
    });
}

void Builder::loadFence(guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LoadFence,
        .width = Width::I64,
        .guestRip = rip,
    });
}

void Builder::readTimestampCounter(guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ReadTimestampCounter,
        .width = Width::I64,
        .guestRip = rip,
    });
}

void Builder::updateAddFlags(ValueId lhs, ValueId rhs, ValueId result, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateAddFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = rhs,
        .third = result,
    });
}

void Builder::updateIncFlags(ValueId original, ValueId result, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateIncFlags,
        .width = width,
        .guestRip = rip,
        .lhs = original,
        .rhs = result,
    });
}

void Builder::updateDecFlags(ValueId original, ValueId result, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateDecFlags,
        .width = width,
        .guestRip = rip,
        .lhs = original,
        .rhs = result,
    });
}

void Builder::updateSubFlags(ValueId lhs, ValueId rhs, ValueId result, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateSubFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = rhs,
        .third = result,
    });
}

void Builder::updateLogicFlags(ValueId result, Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateLogicFlags,
        .width = width,
        .guestRip = rip,
        .lhs = result,
    });
}

void Builder::updateShiftLeftFlags(ValueId lhs, ValueId result, std::uint8_t count,
                                   Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftLeftFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = result,
        .immediate = count,
    });
}

void Builder::updateShiftLeftFlags(ValueId lhs, ValueId result, ValueId count,
                                   Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftLeftFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = result,
        .third = count,
    });
}

void Builder::updateShiftRightFlags(ValueId lhs, ValueId result, std::uint8_t count,
                                    Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftRightFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = result,
        .immediate = count,
    });
}

void Builder::updateMultiplyFlags(ValueId high, Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateMultiplyFlags,
        .width = width,
        .guestRip = rip,
        .lhs = high,
    });
}

void Builder::updateSignedMultiplyFlags(ValueId lhs, ValueId rhs, Width width,
                                        guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateSignedMultiplyFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = rhs,
    });
}

void Builder::updateShiftRightDoubleFlags(ValueId original, ValueId result,
                                          std::uint8_t count, Width width,
                                          guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftRightDoubleFlags,
        .width = width,
        .guestRip = rip,
        .lhs = original,
        .rhs = result,
        .immediate = count,
    });
}

void Builder::exitBlock(guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .exitKind = ExitKind::Return,
    });
}

void Builder::exitDirect(guest::GuestAddress target, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .target = target,
        .exitKind = ExitKind::Direct,
    });
}

void Builder::exitDirect(ValueId target, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = target,
        .exitKind = ExitKind::Direct,
    });
}

void Builder::exitConditional(x86::Condition condition, guest::GuestAddress target,
                              guest::GuestAddress fallthrough, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .target = target,
        .fallthrough = fallthrough,
        .condition = condition,
        .exitKind = ExitKind::Conditional,
    });
}

void Builder::exitCall(guest::GuestAddress target, guest::GuestAddress returnAddress,
                       guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .target = target,
        .fallthrough = returnAddress,
        .exitKind = ExitKind::Call,
    });
}

void Builder::exitCall(ValueId target, guest::GuestAddress returnAddress,
                       guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = target,
        .fallthrough = returnAddress,
        .exitKind = ExitKind::Call,
    });
}

void Builder::exitSyscall(guest::GuestAddress nextRip, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .target = nextRip,
        .exitKind = ExitKind::Syscall,
    });
}

Block Builder::finish() && { return std::move(block_); }

std::vector<std::string> verify(const Block &block) {
    std::vector<std::string> errors;
    std::vector<bool> defined(block.valueCount, false);
    bool sawExit = false;

    const auto checkUse = [&](std::optional<ValueId> value, const char *role) {
        if (!value) {
            errors.emplace_back(std::string("missing ") + role + " value");
            return;
        }
        if (value->value >= defined.size() || !defined[value->value]) {
            errors.emplace_back(std::string("use of undefined ") + role + " value");
        }
    };

    for (const auto &operation : block.operations) {
        if (sawExit) {
            errors.emplace_back("operation follows exit_block");
        }
        switch (operation.opcode) {
        case Opcode::Constant:
        case Opcode::ReadGuestReg:
        case Opcode::ReadGuestGsBase:
            break;
        case Opcode::ReadGuestXmmLane:
            if (!operation.guestXmmRegister) {
                errors.emplace_back("read_guest_xmm_lane has no register");
            }
            break;
        case Opcode::WriteGuestReg:
            checkUse(operation.lhs, "source");
            if (!operation.guestRegister) {
                errors.emplace_back("write_guest_reg has no register");
            }
            break;
        case Opcode::ConditionalMoveGuestReg:
            if (!operation.guestRegister || !operation.condition ||
                operation.immediate >= 16) {
                errors.emplace_back("conditional_move_guest_reg is incomplete");
            }
            break;
        case Opcode::WriteGuestXmmLane:
            checkUse(operation.lhs, "source");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("write_guest_xmm_lane has no register");
            }
            break;
        case Opcode::Add:
        case Opcode::Sub:
        case Opcode::And:
        case Opcode::Or:
        case Opcode::Xor:
        case Opcode::MultiplyLow:
        case Opcode::MultiplyHighUnsigned:
        case Opcode::ShiftRightDouble:
            checkUse(operation.lhs, "left");
            checkUse(operation.rhs, "right");
            break;
        case Opcode::ShiftLeft:
            checkUse(operation.lhs, "shifted");
            if (operation.rhs) {
                checkUse(operation.rhs, "shift count");
            }
            break;
        case Opcode::ShiftRightLogical:
            checkUse(operation.lhs, "shifted");
            break;
        case Opcode::SignExtend32:
            checkUse(operation.lhs, "source");
            break;
        case Opcode::EvaluateCondition:
            if (!operation.condition) {
                errors.emplace_back("evaluate_condition has no condition");
            }
            break;
        case Opcode::Push:
            checkUse(operation.lhs, "new stack pointer");
            checkUse(operation.rhs, "pushed value");
            break;
        case Opcode::AddGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (operation.width != Width::I64) {
                errors.emplace_back("add_guest_memory currently requires i64");
            }
            break;
        case Opcode::IncrementGuestMemory:
        case Opcode::DecrementGuestMemory:
            checkUse(operation.lhs, "guest address");
            break;
        case Opcode::CompareExchangeGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (operation.width != Width::I32) {
                errors.emplace_back(
                    "compare_exchange_guest_memory currently requires i32");
            }
            break;
        case Opcode::ExchangeGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (!operation.guestRegister) {
                errors.emplace_back(
                    "exchange_guest_memory lacks a destination register");
            }
            if (operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "exchange_guest_memory currently requires i32 or i64");
            }
            break;
        case Opcode::LockedIncrementGuestMemory:
            checkUse(operation.lhs, "guest address");
            if (operation.width != Width::I32) {
                errors.emplace_back(
                    "locked_increment_guest_memory currently requires i32");
            }
            break;
        case Opcode::LockedOrGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "immediate");
            if (operation.width != Width::I32) {
                errors.emplace_back(
                    "locked_or_guest_memory currently requires i32");
            }
            break;
        case Opcode::StoreGuest:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "stored value");
            break;
        case Opcode::StoreGuestXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("store_guest_xmm has no register");
            }
            break;
        case Opcode::LoadGuestXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("load_guest_xmm has no register");
            }
            break;
        case Opcode::CompareEqualGuestBytesXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("compare_equal_guest_bytes_xmm has no register");
            }
            break;
        case Opcode::MoveXmmByteMask:
            if (!operation.guestRegister || !operation.guestXmmRegister) {
                errors.emplace_back("move_xmm_byte_mask has incomplete registers");
            }
            break;
        case Opcode::ShuffleXmmDwords:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister || operation.immediate > 0xFFU) {
                errors.emplace_back("shuffle_xmm_dwords is incomplete");
            }
            break;
        case Opcode::BitScanForward:
            if (!operation.guestRegister) {
                errors.emplace_back("bit_scan_forward has no destination register");
            }
            break;
        case Opcode::LoadGuest:
            checkUse(operation.lhs, "guest address");
            break;
        case Opcode::LoadFence:
        case Opcode::ReadTimestampCounter:
            break;
        case Opcode::UpdateAddFlags:
        case Opcode::UpdateSubFlags:
            checkUse(operation.lhs, "left");
            checkUse(operation.rhs, "right");
            checkUse(operation.third, "result");
            break;
        case Opcode::UpdateIncFlags:
        case Opcode::UpdateDecFlags:
            checkUse(operation.lhs, "original");
            checkUse(operation.rhs, "result");
            break;
        case Opcode::UpdateLogicFlags:
            checkUse(operation.lhs, "result");
            break;
        case Opcode::UpdateMultiplyFlags:
            checkUse(operation.lhs, "high result");
            break;
        case Opcode::UpdateSignedMultiplyFlags:
            checkUse(operation.lhs, "left");
            checkUse(operation.rhs, "right");
            break;
        case Opcode::UpdateShiftRightDoubleFlags:
            checkUse(operation.lhs, "original");
            checkUse(operation.rhs, "result");
            break;
        case Opcode::UpdateShiftLeftFlags:
            checkUse(operation.lhs, "original");
            checkUse(operation.rhs, "result");
            if (operation.third) {
                checkUse(operation.third, "shift count");
            }
            break;
        case Opcode::UpdateShiftRightFlags:
            checkUse(operation.lhs, "original");
            checkUse(operation.rhs, "result");
            break;
        case Opcode::ExitBlock:
            if ((operation.exitKind == ExitKind::Call ||
                 operation.exitKind == ExitKind::Direct) &&
                operation.lhs) {
                checkUse(operation.lhs, "indirect exit target");
            } else if (operation.exitKind != ExitKind::Return && !operation.target) {
                errors.emplace_back("non-return exit has no target");
            }
            if ((operation.exitKind == ExitKind::Conditional ||
                 operation.exitKind == ExitKind::Call) &&
                !operation.fallthrough) {
                errors.emplace_back("conditional/call exit has no fallthrough");
            }
            if (operation.exitKind == ExitKind::Conditional && !operation.condition) {
                errors.emplace_back("conditional exit has no condition");
            }
            sawExit = true;
            break;
        }

        if (operation.result) {
            if (operation.result->value >= defined.size()) {
                errors.emplace_back("result value is outside block value table");
            } else if (defined[operation.result->value]) {
                errors.emplace_back("SSA value is defined more than once");
            } else {
                defined[operation.result->value] = true;
            }
        }
    }

    if (!sawExit) {
        errors.emplace_back("block has no exit_block");
    }
    return errors;
}

} // namespace rosa::ir
