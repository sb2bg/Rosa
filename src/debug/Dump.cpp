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
        if (operand.byteOffset == 1) {
            constexpr std::array highByteNames{"ah", "ch", "dh", "bh"};
            const auto encoding = static_cast<std::size_t>(operand.reg);
            if (encoding < highByteNames.size()) {
                return highByteNames[encoding];
            }
        }
        constexpr std::array byteNames{
            "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"};
        const auto encoding = static_cast<std::size_t>(operand.reg);
        if (encoding < byteNames.size()) {
            return std::string(byteNames[encoding]);
        }
        return "r" + std::to_string(encoding) + "b";
    }
    if (operand.width == 16) {
        constexpr std::array legacyWordNames{
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
        const auto encoding = static_cast<std::size_t>(operand.reg);
        if (encoding < legacyWordNames.size()) {
            return legacyWordNames[encoding];
        }
        return "r" + std::to_string(encoding) + "w";
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
    case x86::Condition::Overflow:
        return "o";
    case x86::Condition::Equal:
        return "e";
    case x86::Condition::NotEqual:
        return "ne";
    case x86::Condition::Below:
        return "b";
    case x86::Condition::AboveOrEqual:
        return "ae";
    case x86::Condition::Above:
        return "a";
    case x86::Condition::BelowOrEqual:
        return "be";
    case x86::Condition::Sign:
        return "s";
    case x86::Condition::NotSign:
        return "ns";
    case x86::Condition::Less:
        return "l";
    case x86::Condition::GreaterOrEqual:
        return "ge";
    case x86::Condition::LessOrEqual:
        return "le";
    case x86::Condition::Greater:
        return "g";
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
            stream << "mov [";
            if (memory.segment == x86::Segment::Gs) {
                stream << "gs:";
            }
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.index || memory.ripRelative) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            if (memory.ripRelative) {
                const auto target = instruction.address.value + instruction.length +
                                    static_cast<std::uint64_t>(memory.displacement);
                stream << " ; 0x" << target;
            }
            break;
        }
        case x86::Opcode::MovRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "mov "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", [";
            if (memory.segment == x86::Segment::Gs) {
                stream << "gs:";
            }
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.index || memory.ripRelative) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << ']';
            if (memory.ripRelative) {
                const auto target = instruction.address.value + instruction.length +
                                    static_cast<std::uint64_t>(memory.displacement);
                stream << " ; 0x" << target;
            }
            break;
        }
        case x86::Opcode::MovzxRegReg:
            stream << "movzx "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::MovsxRegReg:
            stream << "movsx "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::MovsxRegMem: {
            const auto destination =
                std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "movsx " << registerOperandName(destination)
                   << (memory.width == 8 ? ", byte [" : ", word [");
            if (memory.segment == x86::Segment::Gs) {
                stream << "gs:";
            }
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.index || memory.ripRelative) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << ']';
            if (memory.ripRelative) {
                const auto target = instruction.address.value +
                                    instruction.length +
                                    static_cast<std::uint64_t>(
                                        memory.displacement);
                stream << " ; 0x" << target;
            }
            break;
        }
        case x86::Opcode::CmpxchgMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "lock cmpxchg "
                   << (memory.width == 32 ? "dword" : "qword") << " [";
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.index || memory.ripRelative) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::Cmpxchg16bMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "lock cmpxchg16b ["
                   << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::XchgMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "xchg " << (memory.width == 32 ? "dword" : "qword")
                   << " [";
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.ripRelative || memory.hasBase) {
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
                if (memory.ripRelative || memory.hasBase || memory.index) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::LockAddMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "lock add qword [";
            if (memory.ripRelative) {
                stream << "rip";
            } else {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index);
                if (memory.scale != 1) {
                    stream << '*' << static_cast<unsigned>(memory.scale);
                }
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]));
            break;
        }
        case x86::Opcode::LockXaddMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "lock xadd "
                   << (memory.width == 32 ? "dword" : "qword") << " ["
                   << (memory.ripRelative ? "rip" : x86::registerName(memory.base));
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]));
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(
                                  memory.displacement);
            }
            break;
        }
        case x86::Opcode::LockOrMemImm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto immediate =
                std::get<x86::ImmediateOperand>(instruction.operands[1]);
            stream << (memory.width == 16 ? "lock or word ["
                                          : "lock or dword [")
                   << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], 0x" << immediate.value;
            break;
        }
        case x86::Opcode::LockIncMem:
        case x86::Opcode::LockDecMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (instruction.opcode == x86::Opcode::LockIncMem
                           ? "lock inc dword ["
                           : memory.width == 32 ? "lock dec dword ["
                                                : "lock dec qword [")
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
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
                   << ", " << (memory.width == 8 ? "byte" : "word") << " ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
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
        case x86::Opcode::MovsxdRegReg:
            stream << "movsxd "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::MovsxdRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "movsxd "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", dword ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
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
        case x86::Opcode::Cdqe:
            stream << "cdqe";
            break;
        case x86::Opcode::Cwde:
            stream << "cwde";
            break;
        case x86::Opcode::MovMemImm: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 8    ? "mov byte ["
                       : memory.width == 16 ? "mov word ["
                       : memory.width == 32 ? "mov dword ["
                                            : "mov qword [");
            if (memory.segment == x86::Segment::Gs) {
                stream << "gs:";
            }
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.index || memory.ripRelative) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            if (memory.ripRelative) {
                const auto target = instruction.address.value + instruction.length +
                                    static_cast<std::uint64_t>(memory.displacement);
                stream << " ; 0x" << target;
            }
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
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
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
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::AddRegReg:
            stream << "add "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::AddRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "add "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
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
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::AddMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 16    ? "add word ["
                       : memory.width == 32 ? "add dword ["
                                            : "add qword [");
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.index || memory.ripRelative) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(
                                  memory.displacement);
            }
            break;
        }
        case x86::Opcode::AddMemImm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 32 ? "add dword [" : "add qword [");
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.ripRelative) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[1])
                          .value;
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(
                                  memory.displacement);
            }
            break;
        }
        case x86::Opcode::IncMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "inc " << (memory.width == 8    ? "byte"
                                  : memory.width == 16 ? "word"
                                  : memory.width == 32 ? "dword"
                                                       : "qword")
                   << " ["
                   << (memory.ripRelative
                           ? "rip"
                           : memory.hasBase ? x86::registerName(memory.base)
                                            : "");
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.index || memory.ripRelative) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << ']';
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::DecMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "dec " << (memory.width == 8    ? "byte"
                                  : memory.width == 16  ? "word"
                                  : memory.width == 32  ? "dword"
                                                        : "qword")
                   << " [" << (memory.ripRelative ? "rip" : x86::registerName(memory.base));
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
            if (memory.ripRelative) {
                const auto target = instruction.address.value + instruction.length +
                                    static_cast<std::uint64_t>(memory.displacement);
                stream << " ; 0x" << target;
            }
            break;
        }
        case x86::Opcode::IncReg:
            stream << "inc "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]));
            break;
        case x86::Opcode::DecReg:
            stream << "dec "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]));
            break;
        case x86::Opcode::SubRegImm:
            stream << "sub "
                   << x86::registerName(std::get<x86::RegisterOperand>(instruction.operands[0]).reg)
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::AdcRegImm:
            stream << "adc "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[1])
                          .value;
            break;
        case x86::Opcode::SbbRegImm:
            stream << "sbb "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[1])
                          .value;
            break;
        case x86::Opcode::SbbRegReg:
            stream << "sbb "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]));
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
                   << ", ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::SubMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "sub "
                   << (memory.width == 8    ? "byte"
                       : memory.width == 32 ? "dword"
                                            : "qword")
                   << " [";
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.index || memory.ripRelative) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]));
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(
                                  memory.displacement);
            }
            break;
        }
        case x86::Opcode::ShlRegImm:
            stream << "shl "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::ShlMemImm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "shl qword [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        }
        case x86::Opcode::ShrMemImm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 32 ? "shr dword [" : "shr qword [")
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
        case x86::Opcode::ShlRegCl:
            stream << "shl "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", cl";
            break;
        case x86::Opcode::ShrRegCl:
            stream << "shr "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", cl";
            break;
        case x86::Opcode::SarRegCl:
            stream << "sar "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", cl";
            break;
        case x86::Opcode::ShrRegImm:
            stream << "shr "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::SarRegImm:
            stream << "sar "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::RolRegImm:
            stream << "rol "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::RolRegCl:
            stream << "rol "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", cl";
            break;
        case x86::Opcode::RorRegImm:
            stream << "ror "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::BswapReg:
            stream << "bswap "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]));
            break;
        case x86::Opcode::NotReg:
            stream << "not "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]));
            break;
        case x86::Opcode::NegReg:
            stream << "neg "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]));
            break;
        case x86::Opcode::MulReg:
            stream << "mul "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]));
            break;
        case x86::Opcode::ImulReg:
            stream << "imul "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]));
            break;
        case x86::Opcode::MulMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 32 ? "mul dword [" : "mul qword [")
                   << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::ImulMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 32 ? "imul dword [" : "imul qword [")
                   << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::DivReg:
            stream << "div "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]));
            break;
        case x86::Opcode::IdivReg:
            stream << "idiv "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]));
            break;
        case x86::Opcode::DivMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "div dword [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::ImulRegReg:
            stream << "imul "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::ImulRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "imul "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", qword [rip";
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::ImulRegRegImm:
            stream << "imul "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[2]).value;
            break;
        case x86::Opcode::ImulRegMemImm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "imul "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", " << (memory.width == 64 ? "qword" : "dword")
                   << " [";
            if (memory.ripRelative) {
                stream << "rip";
            } else {
                stream << x86::registerName(memory.base);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[2]).value;
            break;
        }
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
        case x86::Opcode::ShldRegRegImm:
            stream << "shld "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[2]).value;
            break;
        case x86::Opcode::OrRegReg:
            stream << "or "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::OrRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "or "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", "
                   << (memory.width == 8    ? "byte"
                        : memory.width == 16 ? "word"
                        : memory.width == 32 ? "dword"
                                             : "qword")
                   << " ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
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
            if (memory.ripRelative) {
                const auto target = instruction.address.value +
                                    instruction.length +
                                    static_cast<std::uint64_t>(
                                        memory.displacement);
                stream << " ; 0x" << target;
            }
            break;
        }
        case x86::Opcode::OrMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 8    ? "or byte ["
                       : memory.width == 32  ? "or dword ["
                                             : "or qword [");
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.ripRelative || memory.hasBase) {
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
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]));
            break;
        }
        case x86::Opcode::OrMemImm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 8    ? "or byte ["
                       : memory.width == 16  ? "or word ["
                       : memory.width == 32  ? "or dword ["
                                             : "or qword [")
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[1]).value;
            if (memory.ripRelative) {
                const auto target = instruction.address.value +
                                    instruction.length +
                                    static_cast<std::uint64_t>(
                                        memory.displacement);
                stream << " ; 0x" << target;
            }
            break;
        }
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
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index);
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
        case x86::Opcode::AndMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 32 ? "and dword [" : "and qword [");
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.ripRelative || memory.hasBase) {
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
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]));
            break;
        }
        case x86::Opcode::BitScanForwardRegReg:
            stream << "bsf "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::BitTestRegImm:
            stream << "bt "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1])
                          .value;
            break;
        case x86::Opcode::BitSetRegImm:
        case x86::Opcode::BitResetRegImm:
            stream << (instruction.opcode == x86::Opcode::BitSetRegImm
                           ? "bts "
                           : "btr ")
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[1])
                          .value;
            break;
        case x86::Opcode::BitTestRegReg:
            stream << "bt "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]));
            break;
        case x86::Opcode::BitSetRegReg:
            stream << "bts "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]));
            break;
        case x86::Opcode::BitTestMemImm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "bt dword [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1])
                          .value;
            break;
        }
        case x86::Opcode::BitScanReverseRegReg:
            stream << "bsr "
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
        case x86::Opcode::AndMemImm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 8    ? "and byte ["
                       : memory.width == 16  ? "and word ["
                       : memory.width == 32  ? "and dword ["
                                             : "and qword [");
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.hasBase || memory.index || memory.ripRelative) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[1])
                          .value;
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(
                                  memory.displacement);
            }
            break;
        }
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
        case x86::Opcode::TestMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "test "
                   << (memory.width == 8   ? "byte"
                       : memory.width == 32 ? "dword"
                                            : "qword")
                   << " [";
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
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
                if (memory.hasBase || memory.ripRelative || memory.index) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]));
            break;
        }
        case x86::Opcode::TestRegImm:
            stream << "test "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", 0x" << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            break;
        case x86::Opcode::TestMemImm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (memory.width == 8    ? "test byte ["
                       : memory.width == 16 ? "test word ["
                       : memory.width == 32 ? "test dword ["
                                            : "test qword [");
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase || memory.ripRelative) {
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
                if (memory.hasBase || memory.ripRelative || memory.index) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1])
                          .value;
            break;
        }
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
                   << ", [";
            if (memory.segment == x86::Segment::Gs) {
                stream << "gs:";
            }
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.hasBase) {
                    stream << '+';
                }
                stream << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                if (memory.ripRelative || memory.hasBase || memory.index) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << ']';
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::CmpMemReg: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "cmp "
                   << (memory.width == 8    ? "byte "
                       : memory.width == 16 ? "word "
                                            : "")
                   << '[';
            if (memory.segment == x86::Segment::Gs) {
                stream << "gs:";
            }
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (!memory.hasBase && !memory.ripRelative && !memory.index &&
                memory.displacement != 0) {
                stream << "0x"
                       << static_cast<std::uint64_t>(memory.displacement);
            } else if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::CmpMemImm: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "cmp "
                   << (memory.width == 8    ? "byte"
                       : memory.width == 16 ? "word"
                   : memory.width == 32 ? "dword"
                                            : "qword")
                   << " [";
            if (memory.ripRelative) {
                stream << "rip";
            } else {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[1]).value;
            if (memory.ripRelative) {
                const auto target = instruction.address.value + instruction.length +
                                    static_cast<std::uint64_t>(memory.displacement);
                stream << " ; 0x" << target;
            }
            break;
        }
        case x86::Opcode::SetccReg:
            stream << "set" << conditionName(*instruction.condition) << ' '
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]));
            break;
        case x86::Opcode::SetccMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "set" << conditionName(*instruction.condition)
                   << " byte [";
            if (memory.ripRelative) {
                stream << "rip";
            } else {
                stream << x86::registerName(memory.base);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::AndRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "and "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << (memory.width == 8    ? "byte"
                       : memory.width == 32 ? "dword"
                                            : "qword")
                   << " [";
            if (memory.ripRelative) {
                stream << "rip";
            } else {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index);
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
            if (memory.ripRelative) {
                const auto target = instruction.address.value +
                                    instruction.length +
                                    static_cast<std::uint64_t>(
                                        memory.displacement);
                stream << " ; 0x" << target;
            }
            break;
        }
        case x86::Opcode::CmovccReg:
            stream << "cmov" << conditionName(*instruction.condition) << ' '
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[1]));
            break;
        case x86::Opcode::CmovccRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "cmov" << conditionName(*instruction.condition) << ' '
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << (memory.width == 32 ? "dword" : "qword") << " [";
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.ripRelative || memory.hasBase) {
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
                if (memory.ripRelative || memory.hasBase || memory.index) {
                    stream << '+';
                }
                stream << "0x" << memory.displacement;
            }
            stream << ']';
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::XorpsRegReg:
            stream << "xorps "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::XorpdRegReg:
            stream << "xorpd "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::VxorpsRegRegReg:
        case x86::Opcode::VxorpsYmmRegRegReg: {
            const auto ymm =
                instruction.opcode == x86::Opcode::VxorpsYmmRegRegReg;
            const auto registerName = [ymm](x86::XmmRegister reg) {
                return ymm ? x86::ymmRegisterName(reg)
                           : x86::xmmRegisterName(reg);
            };
            stream << "vxorps "
                   << registerName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << registerName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg)
                   << ", "
                   << registerName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[2])
                              .reg);
            break;
        }
        case x86::Opcode::VbroadcastssYmmReg:
            stream << "vbroadcastss "
                   << x86::ymmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::PxorRegReg:
            stream << "pxor "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::PxorRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "pxor "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0]).reg)
                   << ", ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::XorpsRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "xorps "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0]).reg)
                   << ", ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::PtestRegReg:
            stream << "ptest "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1]).reg);
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
        case x86::Opcode::PcmpeqbRegReg:
            stream << "pcmpeqb "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::PcmpeqdRegReg:
            stream << "pcmpeqd "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::PslldRegImm:
            stream << "pslld "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << std::dec
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[1])
                          .value;
            break;
        case x86::Opcode::PsrlqRegImm:
            stream << "psrlq "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << std::dec
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[1])
                          .value;
            break;
        case x86::Opcode::PadddRegReg:
            stream << "paddd "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::PaddqRegReg:
            stream << "paddq "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::PhadddRegReg:
            stream << "phaddd "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::PandRegReg:
            stream << "pand "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::PandRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "pand "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", [";
            if (memory.ripRelative) {
                stream << "rip";
            } else {
                stream << x86::registerName(memory.base);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
        case x86::Opcode::PandnRegReg:
            stream << "pandn "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::PorRegReg:
            stream << "por "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1]).reg);
            break;
        case x86::Opcode::PmovmskbRegXmm:
            stream << "pmovmskb "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]))
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            break;
        case x86::Opcode::PmovsxbdRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "pmovsxbd "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", dword [rip";
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "] ; 0x"
                   << instruction.address.value + instruction.length +
                          static_cast<std::uint64_t>(memory.displacement);
            break;
        }
        case x86::Opcode::PmovsxdqRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "pmovsxdq "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", qword [rip";
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "] ; 0x"
                   << instruction.address.value + instruction.length +
                          static_cast<std::uint64_t>(memory.displacement);
            break;
        }
        case x86::Opcode::PshufbRegReg:
            stream << "pshufb "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1]).reg);
            break;
        case x86::Opcode::PshufbRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "pshufb "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0]).reg)
                   << ", [rip";
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "] ; 0x"
                   << instruction.address.value + instruction.length +
                          static_cast<std::uint64_t>(memory.displacement);
            break;
        }
        case x86::Opcode::PshufdRegRegImm:
            stream << "pshufd "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg)
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(instruction.operands[2]).value;
            break;
        case x86::Opcode::ShufpdRegRegImm:
            stream << "shufpd "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg)
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[2])
                          .value;
            break;
        case x86::Opcode::PunpcklwdRegReg:
            stream << "punpcklwd "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::PunpcklqdqRegReg:
            stream << "punpcklqdq "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::PinsrbXmmReg:
            stream << "pinsrb "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[2])
                          .value;
            break;
        case x86::Opcode::PinsrdXmmMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "pinsrd "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0]).reg)
                   << ", dword [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[2]).value;
            break;
        }
        case x86::Opcode::PinsrdXmmReg:
            stream << (std::get<x86::RegisterOperand>(
                              instruction.operands[1])
                                  .width == 64
                           ? "pinsrq "
                           : "pinsrd ")
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]))
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[2])
                          .value;
            break;
        case x86::Opcode::ExtractpsMemXmmImm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "extractps dword [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg)
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[2])
                          .value;
            break;
        }
        case x86::Opcode::PblendwRegRegImm:
            stream << "pblendw "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0]).reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1]).reg)
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[2]).value;
            break;
        case x86::Opcode::PalignrRegRegImm:
            stream << "palignr "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg)
                   << ", 0x"
                   << std::get<x86::ImmediateOperand>(
                          instruction.operands[2])
                          .value;
            break;
        case x86::Opcode::MovapsMemReg:
        case x86::Opcode::MovapdMemReg: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (instruction.opcode == x86::Opcode::MovapdMemReg
                           ? "movapd ["
                           : "movaps [");
            if (memory.ripRelative) {
                stream << "rip";
            } else {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
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
            stream << "movups [";
            if (memory.ripRelative) {
                stream << "rip";
            } else {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
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
        case x86::Opcode::VmovupsMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "vmovups ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        }
        case x86::Opcode::VmovupsYmmRegMem:
        case x86::Opcode::VmovapsYmmRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << (instruction.opcode == x86::Opcode::VmovapsYmmRegMem
                           ? "vmovaps "
                           : "vmovups ")
                   << x86::ymmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
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
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::VmovupsYmmMemReg:
        case x86::Opcode::VmovapsYmmMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (instruction.opcode == x86::Opcode::VmovapsYmmMemReg
                           ? "vmovaps ["
                           : "vmovups [")
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << x86::ymmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        }
        case x86::Opcode::MovapdRegReg:
        case x86::Opcode::MovdqaRegReg:
            stream << (instruction.opcode == x86::Opcode::MovapdRegReg
                           ? "movapd "
                           : "movdqa ")
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::MovlhpsRegReg:
            stream << "movlhps "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::MovdXmmReg:
        case x86::Opcode::MovqXmmReg:
            stream << (instruction.opcode == x86::Opcode::MovqXmmReg
                           ? "movq "
                           : "movd ")
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[1]));
            break;
        case x86::Opcode::MovdXmmMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "movd "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", dword ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index);
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
        case x86::Opcode::MovdMemXmm:
        case x86::Opcode::MovssMemXmm: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << (instruction.opcode == x86::Opcode::MovssMemXmm
                           ? "movss dword ["
                           : "movd dword [")
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index);
                if (memory.scale != 1) {
                    stream << '*' << static_cast<unsigned>(memory.scale);
                }
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        }
        case x86::Opcode::MovdRegXmm:
            stream << "movd "
                   << registerOperandName(
                          std::get<x86::RegisterOperand>(
                              instruction.operands[0]))
                   << ", "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        case x86::Opcode::MovdqaMemReg: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "movdqa [" << x86::registerName(memory.base);
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[1])
                              .reg);
            break;
        }
        case x86::Opcode::MovdqaRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "movdqa "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", [" << (memory.ripRelative ? "rip" : x86::registerName(memory.base));
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
            if (memory.ripRelative) {
                const auto target = instruction.address.value + instruction.length +
                                    static_cast<std::uint64_t>(memory.displacement);
                stream << " ; 0x" << target;
            }
            break;
        }
        case x86::Opcode::MovapsRegMem:
        case x86::Opcode::MovapdRegMem:
        case x86::Opcode::MovupsRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << (instruction.opcode == x86::Opcode::MovapsRegMem
                           ? "movaps "
                       : instruction.opcode == x86::Opcode::MovapdRegMem
                           ? "movapd "
                           : "movups ")
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
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
        case x86::Opcode::VmovupsRegMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "vmovups "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0])
                              .reg)
                   << ", ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
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
        case x86::Opcode::MovdquRegMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "movdqu "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg)
                   << ", ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
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
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::RepMovsb:
            stream << "rep movsb";
            break;
        case x86::Opcode::MovqMemXmm: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "movq [" << x86::registerName(memory.base);
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index) << '*'
                       << static_cast<unsigned>(memory.scale);
            }
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
        case x86::Opcode::MovqXmmMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[1]);
            stream << "movq "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(
                              instruction.operands[0]).reg)
                   << ", qword [";
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.index) {
                if (memory.ripRelative || memory.hasBase) {
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
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::MovdquMemReg: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "movdqu ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index);
                if (memory.scale != 1) {
                    stream << '*' << static_cast<unsigned>(memory.scale);
                }
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << "], "
                   << x86::xmmRegisterName(
                          std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg);
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::Push:
            stream << "push ";
            if (std::holds_alternative<x86::ImmediateOperand>(instruction.operands[0])) {
                stream << "0x"
                       << std::get<x86::ImmediateOperand>(instruction.operands[0]).value;
            } else if (std::holds_alternative<x86::RegisterOperand>(
                           instruction.operands[0])) {
                stream << x86::registerName(
                    std::get<x86::RegisterOperand>(instruction.operands[0]).reg);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[0]);
                stream << '[' << x86::registerName(memory.base);
                if (memory.index) {
                    stream << '+' << x86::registerName(*memory.index);
                    if (memory.scale != 1) {
                        stream << '*' << static_cast<unsigned>(memory.scale);
                    }
                }
                if (memory.displacement < 0) {
                    stream << "-0x" << std::hex << -memory.displacement;
                } else if (memory.displacement > 0) {
                    stream << "+0x" << std::hex << memory.displacement;
                }
                stream << ']';
            }
            break;
        case x86::Opcode::Pop:
            stream << "pop "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]).reg);
            break;
        case x86::Opcode::Leave:
            stream << "leave";
            break;
        case x86::Opcode::Nop:
            stream << "nop";
            break;
        case x86::Opcode::Vzeroupper:
            stream << "vzeroupper";
            break;
        case x86::Opcode::Lfence:
            stream << "lfence";
            break;
        case x86::Opcode::Mfence:
            stream << "mfence";
            break;
        case x86::Opcode::SidtMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "sidt [" << x86::registerName(memory.base);
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            break;
        }
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
        case x86::Opcode::JmpMem: {
            const auto memory =
                std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "jmp qword [";
            if (memory.ripRelative) {
                stream << "rip";
            } else if (memory.hasBase) {
                stream << x86::registerName(memory.base);
            }
            if (memory.displacement < 0) {
                stream << "-0x" << -memory.displacement;
            } else if (memory.displacement > 0) {
                stream << "+0x" << memory.displacement;
            }
            stream << ']';
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
            break;
        }
        case x86::Opcode::JccRelative:
            stream << 'j' << conditionName(*instruction.condition) << " 0x"
                   << instruction.branchTarget->value;
            break;
        case x86::Opcode::CallRelative:
            stream << "call 0x" << instruction.branchTarget->value;
            break;
        case x86::Opcode::CallReg:
            stream << "call "
                   << x86::registerName(
                          std::get<x86::RegisterOperand>(instruction.operands[0]).reg);
            break;
        case x86::Opcode::CallMem: {
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            stream << "call qword ["
                   << (memory.ripRelative ? "rip"
                                          : x86::registerName(memory.base));
            if (memory.index) {
                stream << '+' << x86::registerName(*memory.index);
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
            if (memory.ripRelative) {
                stream << " ; 0x"
                       << instruction.address.value + instruction.length +
                              static_cast<std::uint64_t>(memory.displacement);
            }
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
        case ir::Opcode::ReadGuestGsBase:
            stream << "read_guest_gs_base.i64";
            break;
        case ir::Opcode::ReadGuestXmmLane:
            stream << "read_guest_xmm_lane.i64 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << '.'
                   << (operation.immediate == 0 ? "low" : "high");
            break;
        case ir::Opcode::ReadGuestYmmUpperLane:
            stream << "read_guest_ymm_upper_lane.i64 "
                   << x86::ymmRegisterName(*operation.guestXmmRegister) << '.'
                   << (operation.immediate == 0 ? "low" : "high");
            break;
        case ir::Opcode::WriteGuestReg:
            stream << "write_guest_reg." << widthName(operation.width) << ' '
                   << x86::registerName(*operation.guestRegister) << ", "
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::ConditionalMoveGuestReg:
            stream << "conditional_move_guest_reg."
                   << conditionName(*operation.condition) << '.'
                   << widthName(operation.width) << ' '
                   << x86::registerName(*operation.guestRegister) << ", ";
            if (operation.lhs) {
                stream << valueName(*operation.lhs);
            } else {
                stream << x86::registerName(
                    static_cast<x86::Register>(operation.immediate));
            }
            break;
        case ir::Opcode::WriteGuestXmmLane:
            stream << "write_guest_xmm_lane.i64 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << '.'
                   << (operation.immediate == 0 ? "low" : "high") << ", "
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::WriteGuestYmmUpperLane:
            stream << "write_guest_ymm_upper_lane.i64 "
                   << x86::ymmRegisterName(*operation.guestXmmRegister) << '.'
                   << (operation.immediate == 0 ? "low" : "high") << ", "
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::WriteGuestXmmByte:
            stream << "write_guest_xmm_byte.i8 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << '.'
                   << std::dec << operation.immediate << ", "
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::WriteGuestXmmDword:
            stream << "write_guest_xmm_dword.i32 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << '.'
                   << std::dec << operation.immediate << ", "
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
                   << valueName(*operation.lhs) << ", ";
            if (operation.rhs) {
                stream << valueName(*operation.rhs);
            } else {
                stream << std::dec << operation.immediate;
            }
            break;
        case ir::Opcode::ShiftRightArithmetic:
            stream << "shift_right_arithmetic." << widthName(operation.width)
                   << ' ' << valueName(*operation.lhs) << ", ";
            if (operation.rhs) {
                stream << valueName(*operation.rhs);
            } else {
                stream << std::dec << operation.immediate;
            }
            break;
        case ir::Opcode::MultiplyLow:
            stream << "multiply_low." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::MultiplyHighUnsigned:
            stream << "multiply_high_unsigned." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::MultiplyHighSigned:
            stream << "multiply_high_signed." << widthName(operation.width) << ' '
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
        case ir::Opcode::ByteSwap:
            stream << "byte_swap." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::EvaluateCondition:
            stream << "condition." << conditionName(*operation.condition);
            break;
        case ir::Opcode::RepeatMoveByte:
            stream << "repeat_move_byte";
            break;
        case ir::Opcode::Push:
            stream << "push." << widthName(operation.width) << ' ' << valueName(*operation.rhs)
                   << ", new_rsp=" << valueName(*operation.lhs);
            break;
        case ir::Opcode::AddGuestMemory:
            stream << "add_guest_memory." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs);
            break;
        case ir::Opcode::SubGuestMemory:
            stream << "sub_guest_memory." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs);
            break;
        case ir::Opcode::OrGuestMemory:
            stream << "or_guest_memory." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs);
            break;
        case ir::Opcode::AndGuestMemory:
            stream << "and_guest_memory." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs);
            break;
        case ir::Opcode::ShiftLeftGuestMemory:
            stream << "shift_left_guest_memory." << widthName(operation.width)
                   << ' ' << valueName(*operation.lhs) << ", " << std::dec
                   << operation.immediate;
            break;
        case ir::Opcode::ShiftRightGuestMemory:
            stream << "shift_right_guest_memory." << widthName(operation.width)
                   << ' ' << valueName(*operation.lhs) << ", " << std::dec
                   << operation.immediate;
            break;
        case ir::Opcode::IncrementGuestMemory:
            stream << "increment_guest_memory." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::DecrementGuestMemory:
            stream << "decrement_guest_memory." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::CompareExchangeGuestMemory:
            stream << "compare_exchange_guest_memory."
                   << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs);
            break;
        case ir::Opcode::CompareExchangeGuestPair:
            stream << "compare_exchange_guest_pair "
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::ExchangeGuestMemory:
            stream << "exchange_guest_memory." << widthName(operation.width)
                   << ' ' << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs) << ", "
                   << x86::registerName(*operation.guestRegister);
            break;
        case ir::Opcode::LockedAddGuestMemory:
            stream << "locked_add_guest_memory."
                   << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs);
            break;
        case ir::Opcode::LockedExchangeAddGuestMemory:
            stream << "locked_exchange_add_guest_memory."
                   << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs) << ", "
                   << x86::registerName(*operation.guestRegister);
            break;
        case ir::Opcode::LockedOrGuestMemory:
            stream << "locked_or_guest_memory." << widthName(operation.width)
                   << ' ' << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs);
            break;
        case ir::Opcode::LockedIncrementGuestMemory:
            stream << "locked_increment_guest_memory."
                   << widthName(operation.width) << ' '
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::LockedDecrementGuestMemory:
            stream << "locked_decrement_guest_memory."
                   << widthName(operation.width) << ' '
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::StoreGuestIdtr:
            stream << "store_guest_idtr " << valueName(*operation.lhs);
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
        case ir::Opcode::LoadGuestSignExtendedBytesXmm:
            stream << "load_guest_sign_extended_bytes_xmm "
                   << valueName(*operation.lhs) << ", "
                   << x86::xmmRegisterName(*operation.guestXmmRegister);
            break;
        case ir::Opcode::LoadGuestSignExtendedDwordsXmm:
            stream << "load_guest_sign_extended_dwords_xmm "
                   << valueName(*operation.lhs) << ", "
                   << x86::xmmRegisterName(*operation.guestXmmRegister);
            break;
        case ir::Opcode::StoreGuestYmm:
            stream << "store_guest_ymm.i256 " << valueName(*operation.lhs)
                   << ", "
                   << x86::ymmRegisterName(*operation.guestXmmRegister)
                   << (operation.immediate != 0 ? ", aligned"
                                                : ", unaligned");
            break;
        case ir::Opcode::LoadGuestXmm:
            stream << "load_guest_xmm.i128 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << ", "
                   << valueName(*operation.lhs)
                   << (operation.immediate != 0 ? ", aligned" : ", unaligned");
            break;
        case ir::Opcode::LoadGuestYmm:
            stream << "load_guest_ymm.i256 "
                   << x86::ymmRegisterName(*operation.guestXmmRegister) << ", "
                   << valueName(*operation.lhs)
                   << (operation.immediate != 0 ? ", aligned" : ", unaligned");
            break;
        case ir::Opcode::XorGuestMemoryXmm:
            stream << "xor_guest_memory_xmm.i128 "
                   << valueName(*operation.lhs) << ", "
                   << x86::xmmRegisterName(*operation.guestXmmRegister);
            break;
        case ir::Opcode::AndGuestMemoryXmm:
            stream << "and_guest_memory_xmm.i128 "
                   << valueName(*operation.lhs) << ", "
                   << x86::xmmRegisterName(*operation.guestXmmRegister);
            break;
        case ir::Opcode::TestXmmBits:
            stream << "test_xmm_bits "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << ", "
                   << x86::xmmRegisterName(
                          *operation.sourceGuestXmmRegister);
            break;
        case ir::Opcode::CompareEqualGuestBytesXmm:
            stream << "compare_equal_guest_bytes_xmm " << valueName(*operation.lhs)
                   << ", " << x86::xmmRegisterName(*operation.guestXmmRegister);
            break;
        case ir::Opcode::CompareEqualXmmBytes:
            stream << "compare_equal_xmm_bytes "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << ", "
                   << x86::xmmRegisterName(*operation.sourceGuestXmmRegister);
            break;
        case ir::Opcode::CompareEqualXmmDwords:
            stream << "compare_equal_xmm_dwords.i32 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << ", "
                   << x86::xmmRegisterName(*operation.sourceGuestXmmRegister);
            break;
        case ir::Opcode::ShiftLeftXmmDwords:
            stream << "shift_left_xmm_dwords.i32 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister)
                   << ", " << operation.immediate;
            break;
        case ir::Opcode::AddXmmDwords:
            stream << "add_xmm_dwords.i32 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister)
                   << ", "
                   << x86::xmmRegisterName(
                          *operation.sourceGuestXmmRegister);
            break;
        case ir::Opcode::HorizontalAddXmmDwords:
            stream << "horizontal_add_xmm_dwords.i32 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister)
                   << ", "
                   << x86::xmmRegisterName(
                          *operation.sourceGuestXmmRegister);
            break;
        case ir::Opcode::AndNotXmm:
            stream << "and_not_xmm "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << ", "
                   << x86::xmmRegisterName(*operation.sourceGuestXmmRegister);
            break;
        case ir::Opcode::MoveXmmByteMask:
            stream << "move_xmm_byte_mask "
                   << x86::registerName(*operation.guestRegister) << ", "
                   << x86::xmmRegisterName(*operation.guestXmmRegister);
            break;
        case ir::Opcode::ShuffleXmmBytes:
            stream << "shuffle_xmm_bytes "
                   << x86::xmmRegisterName(*operation.guestXmmRegister)
                   << ", ";
            if (operation.lhs) {
                stream << '%' << operation.lhs->value;
            } else {
                stream << x86::xmmRegisterName(
                    *operation.sourceGuestXmmRegister);
            }
            break;
        case ir::Opcode::ShuffleXmmDwords:
            stream << "shuffle_xmm_dwords "
                   << x86::xmmRegisterName(*operation.guestXmmRegister) << ", "
                   << x86::xmmRegisterName(*operation.sourceGuestXmmRegister)
                   << ", 0x" << std::hex << operation.immediate;
            break;
        case ir::Opcode::AlignRightXmmBytes:
            stream << "align_right_xmm_bytes "
                   << x86::xmmRegisterName(*operation.guestXmmRegister)
                   << ", "
                   << x86::xmmRegisterName(
                          *operation.sourceGuestXmmRegister)
                   << ", " << std::dec << operation.immediate;
            break;
        case ir::Opcode::BlendXmmWords:
            stream << "blend_xmm_words.i16 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister)
                   << ", "
                   << x86::xmmRegisterName(
                          *operation.sourceGuestXmmRegister)
                   << ", 0x" << operation.immediate;
            break;
        case ir::Opcode::UnpackLowXmmWords:
            stream << "unpack_low_xmm_words.i16 "
                   << x86::xmmRegisterName(*operation.guestXmmRegister)
                   << ", "
                   << x86::xmmRegisterName(
                          *operation.sourceGuestXmmRegister);
            break;
        case ir::Opcode::BitScanForward:
            stream << "bit_scan_forward." << widthName(operation.width) << ' '
                   << x86::registerName(*operation.guestRegister) << ", "
                   << x86::registerName(static_cast<x86::Register>(operation.immediate));
            break;
        case ir::Opcode::BitScanReverse:
            stream << "bit_scan_reverse." << widthName(operation.width) << ' '
                   << x86::registerName(*operation.guestRegister) << ", "
                   << x86::registerName(
                          static_cast<x86::Register>(operation.immediate));
            break;
        case ir::Opcode::DivideUnsignedByte:
            stream << "divide_unsigned_byte " << valueName(*operation.lhs);
            break;
        case ir::Opcode::DivideUnsignedDword:
            stream << "divide_unsigned_dword " << valueName(*operation.lhs);
            break;
        case ir::Opcode::DivideUnsignedQword:
            stream << "divide_unsigned_qword " << valueName(*operation.lhs);
            break;
        case ir::Opcode::DivideSignedDword:
            stream << "divide_signed_dword " << valueName(*operation.lhs);
            break;
        case ir::Opcode::LoadGuest:
            stream << "load_guest." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::LoadFence:
            stream << "load_fence";
            break;
        case ir::Opcode::StoreFence:
            stream << "store_fence";
            break;
        case ir::Opcode::ReadTimestampCounter:
            stream << "read_timestamp_counter";
            break;
        case ir::Opcode::UpdateAddFlags:
            stream << "update_add_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs) << ", "
                   << valueName(*operation.third);
            break;
        case ir::Opcode::UpdateAdcFlags:
            stream << "update_adc_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs) << ", "
                   << valueName(*operation.third);
            break;
        case ir::Opcode::UpdateSbbFlags:
            stream << "update_sbb_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs) << ", "
                   << valueName(*operation.third);
            break;
        case ir::Opcode::UpdateIncFlags:
            stream << "update_inc_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs);
            break;
        case ir::Opcode::UpdateDecFlags:
            stream << "update_dec_flags." << widthName(operation.width) << ' '
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
                   << ", ";
            if (operation.third) {
                stream << valueName(*operation.third);
            } else {
                stream << std::dec << operation.immediate;
            }
            break;
        case ir::Opcode::UpdateShiftRightArithmeticFlags:
            stream << "update_shift_right_arithmetic_flags."
                   << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs) << ", ";
            if (operation.third) {
                stream << valueName(*operation.third);
            } else {
                stream << std::dec << operation.immediate;
            }
            break;
        case ir::Opcode::UpdateRotateLeftFlags:
            stream << "update_rotate_left_flags." << widthName(operation.width)
                   << ' ' << valueName(*operation.lhs) << ", ";
            if (operation.rhs) {
                stream << valueName(*operation.rhs);
            } else {
                stream << std::dec << operation.immediate;
            }
            break;
        case ir::Opcode::UpdateRotateRightFlags:
            stream << "update_rotate_right_flags." << widthName(operation.width)
                   << ' ' << valueName(*operation.lhs) << ", " << std::dec
                   << operation.immediate;
            break;
        case ir::Opcode::UpdateMultiplyFlags:
            stream << "update_multiply_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs);
            break;
        case ir::Opcode::UpdateSignedMultiplyFlags:
            stream << "update_signed_multiply_flags." << widthName(operation.width)
                   << ' ' << valueName(*operation.lhs) << ", "
                   << valueName(*operation.rhs);
            break;
        case ir::Opcode::UpdateShiftRightDoubleFlags:
            stream << "update_shift_right_double_flags." << widthName(operation.width) << ' '
                   << valueName(*operation.lhs) << ", " << valueName(*operation.rhs)
                   << ", " << std::dec << operation.immediate;
            break;
        case ir::Opcode::UpdateBitTestFlags:
            stream << "update_bit_test_flags." << widthName(operation.width)
                   << ' ' << valueName(*operation.lhs) << ", " << std::dec
                   << operation.immediate;
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
                             const dbt::Dispatcher &dispatcher,
                             const darwin::GuestSharedCache *sharedCache) {
    const auto mappings = addressSpace.mappingInfos();
    const auto *ripMapping = nearestMapping(mappings, state.rip);
    const auto *rspMapping = nearestMapping(mappings, state.rsp);
    const auto *cacheImage = sharedCache == nullptr
                                 ? nullptr
                                 : sharedCache->imageForAddress(
                                       guest::GuestAddress{state.rip});

    std::ostringstream stream;
    stream << "guest fatal: image=";
    if (cacheImage != nullptr) {
        stream << cacheImage->path;
    } else if (ripMapping != nullptr && contains(*ripMapping, state.rip) &&
        !ripMapping->label.empty()) {
        stream << ripMapping->label;
    } else {
        stream << imageHint;
    }
    stream << "\n";
    if (cacheImage != nullptr) {
        stream << "  cache image: index=" << cacheImage->index
               << " uuid=" << darwin::formatSharedCacheUuid(cacheImage->uuid)
               << " text=[0x" << std::hex << cacheImage->loadAddress.value
               << ",0x" << (cacheImage->loadAddress.value +
                              cacheImage->textSize)
               << ") source="
               << (cacheImage->sourceSuffix.empty() ? "main"
                                                    : cacheImage->sourceSuffix)
               << '\n';
    }
    stream << "  reason: " << error.what() << '\n'
           << "  RIP=0x" << std::hex << state.rip << " RSP=0x" << state.rsp
           << " RFLAGS=0x" << state.rflags << " GSBASE=0x" << state.gsBase
           << '\n'
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
    if (dispatcher.machDispatcher().lastPortConstruct()) {
        stream << "  guest Mach port namespace:\n    "
               << dispatcher.machDispatcher().portSpaceSummary() << '\n';
    }
    if (!dispatcher.cacheImageExecutions().empty()) {
        stream << "  cache images executed:\n";
        for (const auto &execution : dispatcher.cacheImageExecutions()) {
            stream << "    block=" << std::dec << execution.executedBlock
                   << " RIP=0x" << std::hex << execution.firstRip.value
                   << std::dec << " index=" << execution.image->index << ' '
                   << execution.image->path << '\n';
        }
    }
    const auto hotBlocks = dispatcher.hotBlocks();
    if (!hotBlocks.empty()) {
        stream << "  hot guest blocks:\n";
        for (const auto &hot : hotBlocks) {
            stream << "    0x" << std::hex << hot.address.value << std::dec
                   << " count=" << hot.count;
            const auto block = dispatcher.cache().blocks().find(hot.address.value);
            if (block != dispatcher.cache().blocks().end() &&
                !block->second->decoded().empty()) {
                stream << "  " << dumpX86(
                    std::span(&block->second->decoded().front(), 1));
            } else {
                stream << '\n';
            }
        }
    }
    return stream.str();
}

} // namespace rosa::debug
