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
    MovzxRegReg,
    MovzxRegMem,
    MovsxdRegMem,
    Cdqe,
    MovMemImm,
    LeaRegRipRelative,
    LeaRegMem,
    AddRegImm,
    AddRegReg,
    AddRegMem,
    IncReg,
    IncMem,
    DecReg,
    SubRegImm,
    SubRegReg,
    SubRegMem,
    ShlRegImm,
    ShlRegCl,
    ShrRegImm,
    MulReg,
    ImulRegReg,
    ShrdRegRegImm,
    OrRegReg,
    OrRegImm,
    XorRegReg,
    XorRegMem,
    XorRegImm,
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
    SetccReg,
    CmovccReg,
    XorpsRegReg,
    PxorRegReg,
    PcmpeqbRegMem,
    PmovmskbRegXmm,
    PshufdRegRegImm,
    MovapsMemReg,
    MovapsRegMem,
    MovupsMemReg,
    MovupsRegMem,
    MovdqaRegMem,
    MovdquRegMem,
    MovdquMemReg,
    MovqMemXmm,
    Push,
    Pop,
    Lfence,
    Rdtsc,
    JmpRelative,
    JmpReg,
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
    AboveOrEqual,
    Above,
    BelowOrEqual,
    Sign,
    LessOrEqual,
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
                  std::uint8_t scaleValue = 1, bool hasBaseValue = true,
                  bool ripRelativeValue = false)
        : base(baseValue), displacement(displacementValue), width(widthValue),
          index(indexValue), scale(scaleValue), hasBase(hasBaseValue),
          ripRelative(ripRelativeValue) {}

    Register base{};
    std::int64_t displacement{};
    std::uint8_t width{};
    std::optional<Register> index;
    std::uint8_t scale{1};
    bool hasBase{true};
    bool ripRelative{};
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
