#pragma once

#include "guest/Address.h"
#include "x86/Registers.h"

#include <array>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

namespace rosa::x86 {

enum class Opcode {
    MovRegImm,
    MovRegReg,
    MovMemReg,
    MovRegMem,
    LeaRegRipRelative,
    AddRegImm,
    AddRegMem,
    SubRegImm,
    SubRegMem,
    ShlRegImm,
    ShlRegCl,
    ShrRegImm,
    MulReg,
    ShrdRegRegImm,
    OrRegReg,
    XorRegReg,
    AndRegImm,
    TestRegReg,
    TestReg8Reg8,
    CmpRegImm,
    CmpRegMem,
    CmpMemImm,
    XorpsRegReg,
    MovapsMemReg,
    MovupsMemReg,
    MovdqaRegMem,
    MovdquMemReg,
    Push,
    Pop,
    Lfence,
    Rdtsc,
    JmpRelative,
    JccRelative,
    CallRelative,
    Syscall,
    Ret,
};

enum class Condition {
    Equal,
    NotEqual,
};

struct RegisterOperand {
    Register reg{};
    std::uint8_t width{};
};

struct ImmediateOperand {
    std::uint64_t value{};
    std::uint8_t width{};
};

struct MemoryOperand {
    Register base{};
    std::int64_t displacement{};
    std::uint8_t width{};
};

struct XmmRegisterOperand {
    XmmRegister reg{};
};

using Operand = std::variant<RegisterOperand, ImmediateOperand, MemoryOperand,
                             XmmRegisterOperand>;

struct DecodedInstruction {
    guest::GuestAddress address{};
    Opcode opcode{};
    std::array<std::uint8_t, 15> bytes{};
    std::uint8_t length{};
    std::vector<Operand> operands;
    std::optional<guest::GuestAddress> branchTarget;
    std::optional<guest::GuestAddress> fallthrough;
    std::optional<Condition> condition;
};

} // namespace rosa::x86
