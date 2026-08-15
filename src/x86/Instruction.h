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
    MovMemImm,
    LeaRegRipRelative,
    LeaRegMem,
    AddRegImm,
    AddRegReg,
    AddRegMem,
    IncReg,
    SubRegImm,
    SubRegMem,
    ShlRegImm,
    ShlRegCl,
    ShrRegImm,
    MulReg,
    ShrdRegRegImm,
    OrRegReg,
    OrRegImm,
    XorRegReg,
    AndRegReg,
    AndRegImm,
    BitScanForwardRegReg,
    TestRegReg,
    TestReg8Reg8,
    TestRegImm,
    CmpRegImm,
    CmpRegReg,
    CmpRegMem,
    CmpMemImm,
    XorpsRegReg,
    PxorRegReg,
    PcmpeqbRegMem,
    PmovmskbRegXmm,
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
    CallMem,
    Syscall,
    Ret,
};

enum class Condition {
    Equal,
    NotEqual,
    Below,
    Above,
    BelowOrEqual,
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
    MemoryOperand() = default;
    MemoryOperand(Register baseValue, std::int64_t displacementValue,
                  std::uint8_t widthValue,
                  std::optional<Register> indexValue = std::nullopt,
                  std::uint8_t scaleValue = 1)
        : base(baseValue), displacement(displacementValue), width(widthValue),
          index(indexValue), scale(scaleValue) {}

    Register base{};
    std::int64_t displacement{};
    std::uint8_t width{};
    std::optional<Register> index;
    std::uint8_t scale{1};
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
