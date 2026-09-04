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
    MovsxRegReg,
    MovsxRegMem,
    MovzxRegMem,
    MovsxdRegReg,
    MovsxdRegMem,
    Cdqe,
    Cwde,
    MovMemImm,
    LeaRegRipRelative,
    LeaRegMem,
    AddRegImm,
    AdcRegImm,
    AdcRegReg,
    AddRegReg,
    AddRegMem,
    AddMemReg,
    AddMemImm,
    IncReg,
    IncMem,
    DecReg,
    DecMem,
    SubRegImm,
    SbbRegImm,
    SbbRegReg,
    SubRegReg,
    SubRegMem,
    SubMemReg,
    ShlRegImm,
    ShlMemImm,
    ShlRegCl,
    ShrRegImm,
    ShrMemImm,
    ShrRegCl,
    SarRegImm,
    SarRegCl,
    RolRegImm,
    RolRegCl,
    RorRegImm,
    RorRegCl,
    BswapReg,
    NotReg,
    NegReg,
    MulReg,
    MulMem,
    DivReg,
    DivMem,
    IdivReg,
    ImulRegReg,
    ImulRegMem,
    ImulMem,
    ImulReg,
    ImulRegRegImm,
    ImulRegMemImm,
    ShldRegRegImm,
    ShrdRegRegImm,
    OrRegReg,
    OrRegMem,
    OrMemReg,
    OrMemImm,
    OrRegImm,
    XorRegReg,
    XorRegMem,
    XorRegImm,
    AndRegReg,
    AndRegMem,
    AndMemReg,
    AndRegImm,
    AndMemImm,
    BitTestRegImm,
    BitSetRegImm,
    BitResetRegImm,
    BitTestRegReg,
    BitSetRegReg,
    BitTestMemImm,
    BitScanForwardRegReg,
    BitScanReverseRegReg,
    TestRegReg,
    TestReg8Reg8,
    TestMemReg,
    TestRegImm,
    TestMemImm,
    CmpRegImm,
    CmpRegReg,
    CmpRegMem,
    CmpMemReg,
    CmpMemImm,
    CmpxchgMemReg,
    Cmpxchg16bMem,
    XchgMemReg,
    LockAddMemReg,
    LockXaddMemReg,
    LockIncMem,
    LockDecMem,
    LockOrMemImm,
    LockAndMemImm,
    SetccReg,
    SetccMem,
    CmovccReg,
    CmovccRegMem,
    XorpsRegReg,
    XorpsRegMem,
    XorpdRegReg,
    VxorpsRegRegReg,
    VxorpsYmmRegRegReg,
    VbroadcastssYmmReg,
    PxorRegReg,
    PxorRegMem,
    PorRegReg,
    PtestRegReg,
    PcmpeqbRegReg,
    PcmpeqbRegMem,
    PcmpeqdRegReg,
    PslldRegImm,
    PsrldRegImm,
    PsrlqRegImm,
    PadddRegReg,
    PadddRegMem,
    PaddwRegReg,
    CmppdRegRegImm,
    PaddqRegReg,
    PhadddRegReg,
    PmovzxbdXmmReg,
    PmovsxbdRegMem,
    PmovsxdqRegMem,
    PandRegReg,
    PandRegMem,
    PandnRegReg,
    PmovmskbRegXmm,
    PshufbRegReg,
    PshufbRegMem,
    PshufdRegRegImm,
    ShufpdRegRegImm,
    ShufpsRegRegImm,
    PunpcklwdRegReg,
    PunpcklqdqRegReg,
    PalignrRegRegImm,
    PblendwRegRegImm,
    PinsrbXmmReg,
    PinsrbXmmMem,
    PinsrdXmmMem,
    PinsrdXmmReg,
    ExtractpsMemXmmImm,
    PextrwRegXmmImm,
    PextrdRegXmmImm,
    PinsrwXmmMem,
    PinsrwXmmReg,
    MovmskpsRegXmm,
    UcomisdRegReg,
    UcomissRegReg,
    UcomissRegMem,
    MovapsMemReg,
    MovapdMemReg,
    MovapsRegMem,
    MovapdRegMem,
    MovapdRegReg,
    MovupsMemReg,
    MovupsRegMem,
    VmovupsMemReg,
    VmovupsRegMem,
    VmovupsYmmRegMem,
    VmovupsYmmMemReg,
    VmovapsYmmRegMem,
    VmovapsYmmMemReg,
    Vzeroupper,
    MovdqaRegReg,
    MovdqaMemReg,
    MovdqaRegMem,
    MovdquRegMem,
    MovdquMemReg,
    MovlhpsRegReg,
    MovlhpsRegMem,
    MovddupRegReg,
    MovddupRegMem,
    PcmpeqqRegReg,
    PcmpeqqRegMem,
    BlendvpdRegReg,
    MovdXmmReg,
    MovdXmmMem,
    MovqXmmReg,
    MovdMemXmm,
    MovssMemXmm,
    MovssRegMem,
    MovsdRegMem,
    MovsdMemXmm,
    Cvtsi2sdXmmReg,
    Cvtsi2sdXmmMem,
    Cvtss2sdXmmReg,
    Cvtss2sdXmmMem,
    Cvtdq2pdXmmReg,
    Cvtdq2pdXmmMem,
    AddsdXmmReg,
    AddsdXmmMem,
    SubsdXmmReg,
    SubsdXmmMem,
    MulsdXmmReg,
    MulsdXmmMem,
    DivsdXmmReg,
    DivsdXmmMem,
    MovlpsRegMem,
    MovlpsMemXmm,
    MovdRegXmm,
    MovqRegXmm,
    MovqXmmMem,
    MovqMemXmm,
    RepMovsb,
    Push,
    Pop,
    Leave,
    Nop,
    Lfence,
    Mfence,
    Rdtsc,
    SidtMem,
    JmpRelative,
    JmpReg,
    JmpMem,
    JccRelative,
    CallRelative,
    CallReg,
    CallMem,
    Syscall,
    Ret,
};

enum class Condition {
    Overflow,
    NotOverflow,
    ParityEven,
    ParityOdd,
    Equal,
    NotEqual,
    Below,
    AboveOrEqual,
    Above,
    BelowOrEqual,
    Sign,
    NotSign,
    Less,
    GreaterOrEqual,
    LessOrEqual,
    Greater,
};

struct RegisterOperand {
    Register reg{};
    std::uint8_t width{};
    std::uint8_t byteOffset{};
};

struct ImmediateOperand {
    std::uint64_t value{};
    std::uint8_t width{};
};

enum class Segment {
    None,
    Gs,
};

struct MemoryOperand {
    MemoryOperand() = default;
    MemoryOperand(Register baseValue, std::int64_t displacementValue,
                  std::uint16_t widthValue,
                  std::optional<Register> indexValue = std::nullopt,
                  std::uint8_t scaleValue = 1, bool hasBaseValue = true,
                  bool ripRelativeValue = false,
                  Segment segmentValue = Segment::None)
        : base(baseValue), displacement(displacementValue), width(widthValue),
          index(indexValue), scale(scaleValue), hasBase(hasBaseValue),
          ripRelative(ripRelativeValue), segment(segmentValue) {}

    Register base{};
    std::int64_t displacement{};
    std::uint16_t width{};
    std::optional<Register> index;
    std::uint8_t scale{1};
    bool hasBase{true};
    bool ripRelative{};
    Segment segment{Segment::None};
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
