#include "debug/Dump.h"

#include "x86/Decoder.h"
#include "x86/Registers.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <limits>
#include <sstream>
#include <variant>

namespace rosa::debug {
namespace {

const char *widthName(ir::Width width) {
    switch (width) {
    case ir::Width::I8:
        return "i8";
    case ir::Width::I16:
        return "i16";
    case ir::Width::I32:
        return "i32";
    case ir::Width::I64:
        return "i64";
    }
    return "invalid";
}

std::string valueName(ir::ValueId value) { return "%" + std::to_string(value.value); }

std::string registerOperandName(x86::RegisterOperand operand) {
    if (operand.width == 8) {
        constexpr std::array legacyByteNames{"al", "cl", "dl", "bl"};
        return std::string(legacyByteNames.at(static_cast<std::size_t>(operand.reg)));
    }
    if (operand.width != 32) {
        return std::string(x86::registerName(operand.reg));
    }
    constexpr std::array legacyNames{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    const auto encoding = static_cast<std::size_t>(operand.reg);
    if (encoding < legacyNames.size()) {
        return legacyNames[encoding];
    }
    return "r" + std::to_string(encoding) + "d";
}

const char *conditionName(x86::Condition condition) {
    switch (condition) {
    case x86::Condition::Equal:
        return "e";
    case x86::Condition::NotEqual:
        return "ne";
    case x86::Condition::Below:
        return "b";
    case x86::Condition::Above:
        return "a";
    case x86::Condition::BelowOrEqual:
        return "be";
    case x86::Condition::LessOrEqual:
        return "le";
    }
    return "?";
}

std::string permissionName(guest::Permission permission) {
    const auto bits = static_cast<std::uint8_t>(permission);
    std::string result;
    result.push_back((bits & static_cast<std::uint8_t>(guest::Permission::Read)) != 0 ? 'r' : '-');
    result.push_back((bits & static_cast<std::uint8_t>(guest::Permission::Write)) != 0 ? 'w' : '-');
    result.push_back((bits & static_cast<std::uint8_t>(guest::Permission::Execute)) != 0 ? 'x' : '-');
    return result;
}

bool contains(const guest::MappingInfo &mapping, std::uint64_t address) {
    return address >= mapping.base.value && address < mapping.base.value + mapping.size;
}

std::uint64_t distanceTo(const guest::MappingInfo &mapping, std::uint64_t address) {
    if (contains(mapping, address)) {
        return 0;
    }
    if (address < mapping.base.value) {
        return mapping.base.value - address;
    }
    return address - (mapping.base.value + mapping.size - 1U);
}

const guest::MappingInfo *nearestMapping(std::span<const guest::MappingInfo> mappings,
                                         std::uint64_t address) {
    const guest::MappingInfo *result = nullptr;
    auto bestDistance = std::numeric_limits<std::uint64_t>::max();
    for (const auto &mapping : mappings) {
        const auto distance = distanceTo(mapping, address);
        if (distance < bestDistance) {
            bestDistance = distance;
            result = &mapping;
        }
    }
    return result;
}

void dumpMapping(std::ostringstream &stream, std::string_view role,
                 const guest::MappingInfo *mapping) {
    stream << "  " << role << ": ";
    if (mapping == nullptr) {
        stream << "<no guest mappings>\n";
        return;
    }
    stream << "[0x" << std::hex << mapping->base.value << ",0x"
           << mapping->base.value + mapping->size << ") "
           << permissionName(mapping->permissions);
    if (!mapping->label.empty()) {
        stream << ' ' << mapping->label;
    }
    stream << '\n';
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
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::MovRegReg:
            stream << "mov "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::MovMemReg: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "mov [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.index) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        }
        case x86::Opcode::MovRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "mov "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::MovzxRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "movzx "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", word [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::MovsxdRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "movsxd "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", dword [" << x86::registerName(memory.base);
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::MovMemImm: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 8 ? "mov byte [" : "mov qword [")
                   << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        }
        case x86::Opcode::LeaRegRipRelative:
            stream << "lea "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", [rip] ; 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::LeaRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "lea "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", [";
            if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index);
                if (memory.scale != 1) {
                    stream << '*' << static_cast<unsigned>(memory.scale);
                }
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::AddRegImm:
            stream << "add "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::AddRegReg:
            stream << "add "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::AddRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "add "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::IncReg:
            stream << "inc "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]));
            break;
        case x86::Opcode::SubRegImm:
            stream << "sub "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::SubRegReg:
            stream << "sub "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::SubRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "sub "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::ShlRegImm:
            stream << "shl "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::ShlRegCl:
            stream << "shl "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", cl";
            break;
        case x86::Opcode::ShrRegImm:
            stream << "shr "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::MulReg:
            stream << "mul "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]).reg);
            break;
        case x86::Opcode::ShrdRegRegImm:
            stream << "shrd "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]).reg)
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[2]).value;
            break;
        case x86::Opcode::OrRegReg:
            stream << "or "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::OrRegImm:
            stream << "or "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::XorRegReg:
            stream << "xor "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::XorRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "xor "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::XorRegImm:
            stream << "xor "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::AndRegReg:
            stream << "and "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::BitScanForwardRegReg:
            stream << "bsf "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::AndRegImm:
            stream << "and "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::TestRegReg:
            stream << "test "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::TestReg8Reg8:
            stream << "test "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::TestRegImm:
            stream << "test "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::CmpRegImm:
            stream << "cmp "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::CmpRegReg:
            stream << "cmp "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::CmpRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "cmp "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::CmpMemImm: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "cmp "
                   << (memory.width == 8 ? "byte" : memory.width == 32 ? "dword" : "qword")
                   << " ["
                   << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        }
        case x86::Opcode::SetccReg:
            stream << "set" << conditionName(*instruction.condition) << ' '
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]));
            break;
        case x86::Opcode::XorpsRegReg:
            stream << "xorps "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::PxorRegReg:
            stream << "pxor "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::PcmpeqbRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "pcmpeqb "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::PmovmskbRegXmm:
            stream << "pmovmskb "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::MovapsMemReg: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "movaps [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        }
        case x86::Opcode::MovupsMemReg: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "movups [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        }
        case x86::Opcode::MovdqaRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "movdqa "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::MovdquMemReg: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "movdqu [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        }
        case x86::Opcode::Push:
            stream << "push ";
            if (std::holds_alternative<x86::ImmediateOperand>(instruction.operands[0])) {
                stream << "0x"
                       << std::get<x86::ImmediateOperand>(instruction.operands[0]).value;
            } else {
                stream << x86::registerName(
                    std::get<x86::RegisterOperand>(instruction.operands[0]).reg);
            }
            break;
        case x86::Opcode::Pop:
            stream << "pop "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]).reg);
            break;
        case x86::Opcode::Lfence:
            stream << "lfence";
            break;
        case x86::Opcode::Rdtsc:
            stream << "rdtsc";
            break;
        case x86::Opcode::JmpRelative:
            stream << "jmp 0x" << instruction.branchTarget->value;
            break;
        case x86::Opcode::JmpReg:
            stream << "jmp "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]).reg);
            break;
        case x86::Opcode::JccRelative:
            stream << 'j' << conditionName(*instruction.condition) << " 0x"
                   << instruction.branchTarget->value;
            break;
        case x86::Opcode::CallRelative:
            stream << "call 0x" << instruction.branchTarget->value;
            break;
        case x86::Opcode::CallMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "call [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
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
        case ir::Opcode::ReadGuestXmmLane:
            stream << "read_guest_xmm_lane.i64 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << '.'
                   << (operation.immediate == 0 ? "low" : "high");
            break;
        case ir::Opcode::WriteGuestReg:
            stream << "write_guest_reg." << widthName(operation.width) << ' '
                   << x86::registerName(*operation.guestRegister) << ", "
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::WriteGuestXmmLane:
            stream << "write_guest_xmm_lane.i64 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << '.'
                   << (operation.immediate == 0 ? "low" : "high") << ", "
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
        case ir::Opcode::ShiftLeft:
            stream << "shift_left." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", ";
            if (operation.rhs) {
                stream << valueName(*operation.rhs);
            } else {
                stream << std::dec << operation.immediate;
            }
            break;
        case ir::Opcode::ShiftRightLogical:
            stream << "shift_right_logical." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << std::dec << operation.immediate;
            break;
        case ir::Opcode::MultiplyLow:
            stream << "multiply_low." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::MultiplyHighUnsigned:
            stream << "multiply_high_unsigned." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::ShiftRightDouble:
            stream << "shift_right_double." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs)
                   << ", " << std::dec << operation.immediate;
            break;
        case ir::Opcode::And:
            stream << "and." << widthName(operation.width) << ' ' << valueName(*operation.lhs)
                   << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::Or:
            stream << "or." << widthName(operation.width) << ' ' << valueName(*operation.lhs)
                   << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::Xor:
            stream << "xor." << widthName(operation.width) << ' ' << valueName(*operation.lhs)
                   << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::SignExtend32:
            stream << "sign_extend_32 " << valueName(*operation.lhs);
            break;
        case ir::Opcode::EvaluateCondition:
            stream << "condition." << conditionName(*operation.condition);
            break;
        case ir::Opcode::Push:
            stream << "push." << widthName(operation.width) << ' ' << valueName(*operation.rhs)
                   << ", new_rsp=" << valueName(*operation.lhs);
            break;
        case ir::Opcode::StoreGuest:
            stream << "store_guest." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::StoreGuestXmm:
            stream << "store_guest_xmm.i128 " << valueName(*operation.lhs) << ", "
                   << x86::xmmRegisterName(*operation.guestXmmRegister)
                   << (operation.immediate != 0 ? ", aligned" : ", unaligned");
            break;
        case ir::Opcode::LoadGuestXmm:
            stream << "load_guest_xmm.i128 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << ", "
                   << valueName(*operation.lhs)
                   << (operation.immediate != 0 ? ", aligned" : ", unaligned");
            break;
        case ir::Opcode::CompareEqualGuestBytesXmm:
            stream << "compare_equal_guest_bytes_xmm " << valueName(*operation.lhs)
                   << ", " << x86::xmmRegisterName(*operation.guestXmmRegister);
            break;
        case ir::Opcode::MoveXmmByteMask:
            stream << "move_xmm_byte_mask "
                   << x86::registerName(*operation.guestRegister) << ", "
                   << x86::xmmRegisterName(*operation.guestXmmRegister);
            break;
        case ir::Opcode::BitScanForward:
            stream << "bit_scan_forward." << widthName(operation.width) << ' '
                   << x86::registerName(*operation.guestRegister) << ", "
                   << x86::registerName(static_cast<x86::Register>(operation.immediate));
            break;
        case ir::Opcode::LoadGuest:
            stream << "load_guest." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::LoadFence:
            stream << "load_fence";
            break;
        case ir::Opcode::ReadTimestampCounter:
            stream << "read_timestamp_counter";
            break;
        case ir::Opcode::UpdateAddFlags:
            stream << "update_add_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs) << ", "
                   << valueName(*operation.third);
            break;
        case ir::Opcode::UpdateIncFlags:
            stream << "update_inc_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs);
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
        case ir::Opcode::UpdateShiftLeftFlags:
            stream << "update_shift_left_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs)
                   << ", ";
            if (operation.third) {
                stream << valueName(*operation.third);
            } else {
                stream << std::dec << operation.immediate;
            }
            break;
        case ir::Opcode::UpdateShiftRightFlags:
            stream << "update_shift_right_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs)
                   << ", " << std::dec << operation.immediate;
            break;
        case ir::Opcode::UpdateMultiplyFlags:
            stream << "update_multiply_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::UpdateShiftRightDoubleFlags:
            stream << "update_shift_right_double_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs)
                   << ", " << std::dec << operation.immediate;
            break;
        case ir::Opcode::ExitBlock:
            stream << "exit_block ";
            switch (operation.exitKind) {
            case ir::ExitKind::Return:
                stream << "return ret_at=0x" << std::hex << operation.guestRip.value;
                break;
            case ir::ExitKind::Direct:
                if (operation.lhs) {
                    stream << "indirect target=" << valueName(*operation.lhs);
                } else {
                    stream << "direct target=0x" << std::hex << operation.target->value;
                }
                break;
            case ir::ExitKind::Call:
                if (operation.lhs) {
                    stream << "call_indirect target=" << valueName(*operation.lhs);
                } else {
                    stream << "call target=0x" << std::hex << operation.target->value;
                }
                stream << " return=0x" << std::hex << operation.fallthrough->value;
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

std::string dumpGuestFailure(std::string_view imageHint, const std::exception &error,
                             const x86::X86State &state,
                             const guest::AddressSpace &addressSpace,
                             const dbt::Dispatcher &dispatcher) {
    const auto mappings = addressSpace.mappingInfos();
    const auto *ripMapping = nearestMapping(mappings, state.rip);
    const auto *rspMapping = nearestMapping(mappings, state.rsp);

    std::ostringstream stream;
    stream << "guest fatal: image=";
    if (ripMapping != nullptr && contains(*ripMapping, state.rip) &&
        !ripMapping->label.empty()) {
        stream << ripMapping->label;
    } else {
        stream << imageHint;
    }
    stream << "\n  reason: " << error.what() << '\n'
           << "  RIP=0x" << std::hex << state.rip << " RSP=0x" << state.rsp
           << " RFLAGS=0x" << state.rflags << '\n'
           << "  GPRs: RAX=0x" << state.rax << " RBX=0x" << state.rbx << " RCX=0x"
           << state.rcx << " RDX=0x" << state.rdx << " RSI=0x" << state.rsi << " RDI=0x"
           << state.rdi << " RBP=0x" << state.rbp << '\n'
           << "        R8=0x" << state.r8 << " R9=0x" << state.r9 << " R10=0x"
           << state.r10 << " R11=0x" << state.r11 << " R12=0x" << state.r12 << " R13=0x"
           << state.r13 << " R14=0x" << state.r14 << " R15=0x" << state.r15 << '\n'
           << "  current instruction:\n";

    if (const auto *decodeError = dynamic_cast<const x86::DecodeError *>(&error)) {
        stream << "    0x" << std::hex << decodeError->address().value << ':';
        const auto shown = std::min<std::size_t>(decodeError->remainingBytes().size(), 15);
        for (std::size_t index = 0; index < shown; ++index) {
            stream << ' ' << std::setw(2) << std::setfill('0')
                   << static_cast<unsigned>(decodeError->remainingBytes()[index]);
        }
        stream << std::setfill(' ') << "  <unsupported or malformed>\n";
    } else if (const auto block = dispatcher.cache().blocks().find(state.rip);
               block != dispatcher.cache().blocks().end()) {
        stream << dumpX86(block->second->decoded());
    } else {
        stream << "    <not decoded>\n";
    }

    std::vector<std::string> history;
    for (const auto address : dispatcher.recentBlocks()) {
        const auto block = dispatcher.cache().blocks().find(address.value);
        if (block == dispatcher.cache().blocks().end()) {
            continue;
        }
        for (const auto &instruction : block->second->decoded()) {
            history.push_back(dumpX86(std::span(&instruction, 1)));
        }
    }
    if (history.size() > 16) {
        history.erase(history.begin(), history.end() - 16);
    }
    stream << "  recent guest instructions:\n";
    if (history.empty()) {
        stream << "    <none>\n";
    } else {
        for (const auto &line : history) {
            stream << "    " << line;
        }
    }
    stream << "  mappings near RIP/RSP:\n";
    dumpMapping(stream, "RIP", ripMapping);
    dumpMapping(stream, "RSP", rspMapping);
    stream << "  blocks: executed=" << std::dec << dispatcher.executedBlocks()
           << " translations=" << dispatcher.translatedBlocks() << '\n';
    return stream.str();
}

} // namespace rosa::debug
