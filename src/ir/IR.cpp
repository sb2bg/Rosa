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

void Builder::updateMultiplyFlags(ValueId high, Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateMultiplyFlags,
        .width = width,
        .guestRip = rip,
        .lhs = high,
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
            break;
        case Opcode::WriteGuestReg:
            checkUse(operation.lhs, "source");
            if (!operation.guestRegister) {
                errors.emplace_back("write_guest_reg has no register");
            }
            break;
        case Opcode::Add:
        case Opcode::Sub:
        case Opcode::And:
        case Opcode::Or:
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
        case Opcode::Push:
            checkUse(operation.lhs, "new stack pointer");
            checkUse(operation.rhs, "pushed value");
            break;
        case Opcode::StoreGuest:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "stored value");
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
        case Opcode::UpdateLogicFlags:
            checkUse(operation.lhs, "result");
            break;
        case Opcode::UpdateMultiplyFlags:
            checkUse(operation.lhs, "high result");
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
        case Opcode::ExitBlock:
            if (operation.exitKind != ExitKind::Return && !operation.target) {
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
