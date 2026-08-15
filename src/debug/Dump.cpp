#include "debug/Dump.h"

#include "x86/Registers.h"

#include <iomanip>
#include <sstream>
#include <variant>

namespace rosa::debug {
namespace {

const char *widthName(ir::Width width) {
    switch (width) {
    case ir::Width::I64:
        return "i64";
    }
    return "invalid";
}

std::string valueName(ir::ValueId value) { return "%" + std::to_string(value.value); }

const char *conditionName(x86::Condition condition) {
    return condition == x86::Condition::Equal ? "e" : "ne";
}

} // namespace

std::string dumpX86(std::span<const x86::DecodedInstruction> instructions) {
    std::ostringstream stream;
    for (const auto &instruction : instructions) {
        stream << "0x" << std::hex << instruction.address.value << ": ";
        for (std::size_t index = 0; index < instruction.length; ++index) {
            stream << std::setw(2) << std::setfill('0')
                   << static_cast<unsigned>(instruction.bytes[index]) << ' ';
        }
        stream << std::setfill(' ') << "  ";
        switch (instruction.opcode) {
        case x86::Opcode::MovRegImm:
            stream << "mov "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::MovRegReg:
            stream << "mov "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::LeaRegRipRelative:
            stream << "lea "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", [rip] ; 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::AddRegImm:
            stream << "add "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::AndRegImm:
            stream << "and "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::CmpRegImm:
            stream << "cmp "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::JmpRelative:
            stream << "jmp 0x" << instruction.branchTarget->value;
            break;
        case x86::Opcode::JccRelative:
            stream << 'j' << conditionName(*instruction.condition) << " 0x"
                   << instruction.branchTarget->value;
            break;
        case x86::Opcode::CallRelative:
            stream << "call 0x" << instruction.branchTarget->value;
            break;
        case x86::Opcode::Syscall:
            stream << "syscall";
            break;
        case x86::Opcode::Ret:
            stream << "ret";
            break;
        }
        stream << '\n';
    }
    return stream.str();
}

std::string dumpIr(const ir::Block &block) {
    std::ostringstream stream;
    stream << "block 0x" << std::hex << block.start.value << ":\n";
    for (const auto &operation : block.operations) {
        stream << "  ";
        if (operation.result) {
            stream << valueName(*operation.result) << " = ";
        }
        switch (operation.opcode) {
        case ir::Opcode::Constant:
            stream << "constant." << widthName(operation.width) << " 0x" << std::hex
                   << operation.immediate;
            break;
        case ir::Opcode::ReadGuestReg:
            stream << "read_guest_reg." << widthName(operation.width) << ' '
                   << x86::registerName(*operation.guestRegister);
            break;
        case ir::Opcode::WriteGuestReg:
            stream << "write_guest_reg." << widthName(operation.width) << ' '
                   << x86::registerName(*operation.guestRegister) << ", "
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::Add:
            stream << "add." << widthName(operation.width) << ' ' << valueName(*operation.lhs)
                   << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::Sub:
            stream << "sub." << widthName(operation.width) << ' ' << valueName(*operation.lhs)
                   << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::And:
            stream << "and." << widthName(operation.width) << ' ' << valueName(*operation.lhs)
                   << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::UpdateAddFlags:
            stream << "update_add_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs) << ", "
                   << valueName(*operation.third);
            break;
        case ir::Opcode::UpdateSubFlags:
            stream << "update_sub_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs) << ", "
                   << valueName(*operation.third);
            break;
        case ir::Opcode::UpdateLogicFlags:
            stream << "update_logic_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::ExitBlock:
            stream << "exit_block ";
            switch (operation.exitKind) {
            case ir::ExitKind::Return:
                stream << "return ret_at=0x" << std::hex << operation.guestRip.value;
                break;
            case ir::ExitKind::Direct:
                stream << "direct target=0x" << std::hex << operation.target->value;
                break;
            case ir::ExitKind::Call:
                stream << "call target=0x" << std::hex << operation.target->value << " return=0x"
                       << operation.fallthrough->value;
                break;
            case ir::ExitKind::Conditional:
                stream << "j" << conditionName(*operation.condition) << " target=0x" << std::hex
                       << operation.target->value << " fallthrough=0x"
                       << operation.fallthrough->value;
                break;
            case ir::ExitKind::Syscall:
                stream << "syscall next=0x" << std::hex << operation.target->value;
                break;
            }
            break;
        }
        stream << '\n';
    }
    return stream.str();
}

std::string dumpArm64(const arm64::Program &program) {
    std::ostringstream stream;
    for (std::size_t index = 0; index < program.listing.size(); ++index) {
        const auto byteOffset = index * sizeof(std::uint32_t);
        stream << std::setw(4) << std::setfill('0') << std::hex << byteOffset << ": ";
        for (std::size_t byte = 0; byte < sizeof(std::uint32_t); ++byte) {
            stream << std::setw(2) << static_cast<unsigned>(program.bytes[byteOffset + byte])
                   << ' ';
        }
        stream << "  " << program.listing[index] << '\n';
    }
    return stream.str();
}

} // namespace rosa::debug
