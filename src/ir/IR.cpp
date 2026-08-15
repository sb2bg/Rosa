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
            checkUse(operation.lhs, "left");
            checkUse(operation.rhs, "right");
            break;
        case Opcode::Push:
            checkUse(operation.lhs, "new stack pointer");
            checkUse(operation.rhs, "pushed value");
            break;
        case Opcode::StoreGuest:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "stored value");
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
