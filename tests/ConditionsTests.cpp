#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testSetOverflowLowByteRegister() {
    constexpr std::uint64_t overflow = std::uint64_t{1} << 11U;
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x90, 0xC2, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802A3EFE5ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg &&
               decoded[0].condition == rosa::x86::Condition::Overflow,
           "SETO opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "SETO length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 8,
           "SETO DL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("seto dl") != std::string::npos,
           "SETO DL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    rosa::x86::X86State state;
    state.rdx = 0x1122334455667788ULL;
    state.rflags = 0xD6 | overflow;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0x1122334455667701ULL},
                "taken SETO did not merge one into DL");
    expectEqual(state.rflags, std::uint64_t{0xD6 | overflow}, "taken SETO changed flags");

    state.rdx = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0xD6;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "not-taken SETO did not merge zero into DL");
    expectEqual(state.rflags, std::uint64_t{0xD6}, "not-taken SETO changed flags");
}

void testSetBelowLowByteRegister() {
    constexpr std::uint64_t carry = std::uint64_t{1} << 0U;
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x92, 0xC3, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AEB6D1ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg &&
               decoded[0].condition == rosa::x86::Condition::Below,
           "SETB opcode or condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rbx && destination.width == 8,
           "SETB BL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("setb bl") != std::string::npos, "SETB dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AEB6D1ULL});
    rosa::x86::X86State state;
    state.rbx = 0x1122334455667788ULL;
    state.rflags = 0x896 | carry;
    static_cast<void>(block.execute(state));
    expectEqual(state.rbx, std::uint64_t{0x1122334455667701ULL},
                "taken SETB did not merge one into BL");
    expectEqual(state.rflags, std::uint64_t{0x896 | carry}, "taken SETB changed flags");

    state.rbx = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x896 & ~carry;
    static_cast<void>(block.execute(state));
    expectEqual(state.rbx, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "not-taken SETB did not merge zero into BL");
    expectEqual(state.rflags, std::uint64_t{0x896 & ~carry}, "not-taken SETB changed flags");
}

void testSetGreaterOrEqualLowByteRegister() {
    // Observed in libsqlite3: SETGE CL (0F 9D).
    constexpr std::uint64_t sign = std::uint64_t{1} << 7U;
    constexpr std::uint64_t overflow = std::uint64_t{1} << 11U;
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x9D, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10007A5A9ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg &&
               decoded[0].condition == rosa::x86::Condition::GreaterOrEqual,
           "SETGE opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "SETGE length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 8,
           "SETGE CL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("setge cl") != std::string::npos,
           "SETGE CL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10007A5A9ULL});
    rosa::x86::X86State state;
    state.rcx = 0x1122334455667788ULL;
    state.rflags = 0x46;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x1122334455667701ULL},
                "taken SETGE did not merge one into CL");
    expectEqual(state.rflags, std::uint64_t{0x46}, "taken SETGE changed flags");

    state.rcx = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x46 | sign;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "not-taken SETGE did not merge zero into CL");
    expectEqual(state.rflags, std::uint64_t{0x46 | sign}, "not-taken SETGE changed flags");

    state.rcx = 0;
    state.rflags = 0x46 | sign | overflow;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{1}, "overflowed SETGE did not merge one into CL");

    // SETLE shares the new less-or-equal evaluation: ZF set takes it.
    constexpr std::array<std::uint8_t, 4> lessEqualCode{0x0F, 0x9E, 0xC1, 0xC3};
    const auto lessEqualDecoded =
        decoder.decodeBlock(lessEqualCode, rosa::guest::GuestAddress{0x2000});
    expect(lessEqualDecoded[0].opcode == rosa::x86::Opcode::SetccReg &&
               lessEqualDecoded[0].condition == rosa::x86::Condition::LessOrEqual,
           "SETLE opcode or condition differs");
    expect(rosa::debug::dumpX86(lessEqualDecoded).find("setle cl") != std::string::npos,
           "SETLE CL dump differs");
    const auto lessEqualBlock =
        translator.translate(lessEqualCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State lessEqualState;
    lessEqualState.rcx = 0xFF00ULL;
    lessEqualState.rflags = 0x8D6 | zeroFlag;
    static_cast<void>(lessEqualBlock.execute(lessEqualState));
    expectEqual(lessEqualState.rcx, std::uint64_t{0xFF01ULL}, "taken SETLE did not merge one");

    lessEqualState.rcx = 0xFF00ULL;
    lessEqualState.rflags = 0x06;
    static_cast<void>(lessEqualBlock.execute(lessEqualState));
    expectEqual(lessEqualState.rcx, std::uint64_t{0xFF00ULL}, "untaken SETLE merged one");
}

void testSetAboveLowByteRegister() {
    constexpr std::uint64_t carryFlag = std::uint64_t{1} << 0U;
    constexpr std::uint64_t zeroFlag = std::uint64_t{1} << 6U;
    constexpr std::array<std::uint8_t, 4> observedCode{0x0F, 0x97, 0xC0, 0xC3}; // seta al
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802AC1311ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg &&
               decoded[0].condition == rosa::x86::Condition::Above,
           "SETA opcode or condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8,
           "SETA AL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("seta al") != std::string::npos, "SETA dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    rosa::x86::X86State state;
    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x896 & ~(carryFlag | zeroFlag);
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL},
                "taken SETA did not merge one into AL");
    expectEqual(state.rflags, std::uint64_t{0x896 & ~(carryFlag | zeroFlag)},
                "taken SETA changed flags");

    state.rax = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x896 | carryFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "carry-blocked SETA did not merge zero into AL");
    expectEqual(state.rflags, std::uint64_t{0x896 | carryFlag}, "carry-blocked SETA changed flags");

    state.rax = 0x8877665544332211ULL;
    state.rflags = 0x896 | zeroFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x8877665544332200ULL},
                "zero-blocked SETA did not merge zero into AL");
    expectEqual(state.rflags, std::uint64_t{0x896 | zeroFlag}, "zero-blocked SETA changed flags");
}

void testSetEqualLowByteRegister() {
    constexpr std::uint64_t zeroFlag = std::uint64_t{1} << 6U;
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x94, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg, "SETE opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Equal, "SETE condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8,
           "SETE AL destination differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x897 | zeroFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL},
                "taken SETE did not merge one into AL");
    expectEqual(state.rflags, std::uint64_t{0x897 | zeroFlag}, "taken SETE changed flags");

    state.rax = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x891 & ~zeroFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "not-taken SETE did not merge zero into AL");
    expectEqual(state.rflags, std::uint64_t{0x891 & ~zeroFlag}, "not-taken SETE changed flags");

    constexpr std::array<std::uint8_t, 3> highByte{0x0F, 0x94, 0xE0};
    bool rejectedHighByte = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByte, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejectedHighByte = true;
    }
    expect(rejectedHighByte, "SETE AH was not rejected explicitly");
}

void testSetNotEqualLowByteRegister() {
    constexpr std::uint64_t zeroFlag = std::uint64_t{1} << 6U;
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x95, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg, "SETNE opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::NotEqual, "SETNE condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x897 & ~zeroFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL},
                "taken SETNE did not merge one into AL");
    expectEqual(state.rflags, std::uint64_t{0x897 & ~zeroFlag}, "taken SETNE changed flags");

    state.rax = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x891 | zeroFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "not-taken SETNE did not merge zero into AL");
    expectEqual(state.rflags, std::uint64_t{0x891 | zeroFlag}, "not-taken SETNE changed flags");
}

void testSetNotSignLowByteRegister() {
    constexpr std::uint64_t signFlag = std::uint64_t{1} << 7U;
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x99, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AEB275ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg &&
               decoded[0].condition == rosa::x86::Condition::NotSign,
           "SETNS opcode or condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 8,
           "SETNS CL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("setns cl") != std::string::npos,
           "SETNS dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AEB275ULL});
    rosa::x86::X86State state;
    state.rcx = 0x1122334455667788ULL;
    state.rflags = 0x846 & ~signFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x1122334455667701ULL},
                "taken SETNS did not merge one into CL");
    expectEqual(state.rflags, std::uint64_t{0x846 & ~signFlag}, "taken SETNS changed flags");

    state.rcx = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x846 | signFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "not-taken SETNS did not merge zero into CL");
    expectEqual(state.rflags, std::uint64_t{0x846 | signFlag}, "not-taken SETNS changed flags");

    constexpr std::array<std::uint8_t, 4> signCode{0x0F, 0x98, 0xC0, 0xC3};
    const auto signDecoded =
        decoder.decodeBlock(signCode, rosa::guest::GuestAddress{0x7FF802AC41BAULL});
    expect(signDecoded[0].opcode == rosa::x86::Opcode::SetccReg &&
               signDecoded[0].condition == rosa::x86::Condition::Sign,
           "SETS opcode or condition differs");
    const auto signDestination = std::get<rosa::x86::RegisterOperand>(signDecoded[0].operands[0]);
    expect(signDestination.reg == rosa::x86::Register::Rax && signDestination.width == 8,
           "SETS AL destination differs");
    expect(rosa::debug::dumpX86(signDecoded).find("sets al") != std::string::npos,
           "SETS AL dump differs");
    const auto signBlock =
        translator.translate(signCode, rosa::guest::GuestAddress{0x7FF802AC41BAULL});
    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x846 | signFlag;
    static_cast<void>(signBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL},
                "taken SETS did not merge one into AL");
    expectEqual(state.rflags, std::uint64_t{0x846 | signFlag}, "taken SETS changed flags");

    state.rax = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x846 & ~signFlag;
    static_cast<void>(signBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "not-taken SETS did not merge zero into AL");
    expectEqual(state.rflags, std::uint64_t{0x846 & ~signFlag}, "not-taken SETS changed flags");
}

void testSetBelowOrEqualLowByteRegister() {
    constexpr std::uint64_t carryFlag = std::uint64_t{1} << 0U;
    constexpr std::uint64_t zeroFlag = std::uint64_t{1} << 6U;
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x96, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802B09399ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg &&
               decoded[0].condition == rosa::x86::Condition::BelowOrEqual,
           "SETBE opcode or condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8,
           "SETBE AL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("setbe al") != std::string::npos,
           "SETBE dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802B09399ULL});
    rosa::x86::X86State state;
    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x2 | carryFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL}, "SETBE did not take with CF set");

    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x2 | zeroFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL}, "SETBE did not take with ZF set");

    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x2;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667700ULL}, "SETBE took with CF and ZF clear");
    expectEqual(state.rflags, std::uint64_t{0x2}, "SETBE changed flags");
}

void testSetLessLowByteRegister() {
    constexpr std::uint64_t signFlag = std::uint64_t{1} << 7U;
    constexpr std::uint64_t overflowFlag = std::uint64_t{1} << 11U;
    constexpr std::array<std::uint8_t, 4> observedCode{0x0F, 0x9C, 0xC0, 0xC3}; // setl al
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C71C4CULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg &&
               decoded[0].condition == rosa::x86::Condition::Less,
           "SETL opcode or condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8,
           "SETL AL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("setl al") != std::string::npos, "SETL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    rosa::x86::X86State state;
    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x2 | signFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL},
                "SETL did not take with SF set and OF clear");
    expectEqual(state.rflags, std::uint64_t{0x2 | signFlag}, "taken SETL changed flags");

    state.rax = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x2 | overflowFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFEEDDCCBBAA9901ULL},
                "SETL did not take with SF clear and OF set");
    expectEqual(state.rflags, std::uint64_t{0x2 | overflowFlag}, "overflow SETL changed flags");

    state.rax = 0x8877665544332211ULL;
    state.rflags = 0x2 | signFlag | overflowFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x8877665544332200ULL}, "SETL took with equal SF and OF");
    expectEqual(state.rflags, std::uint64_t{0x2 | signFlag | overflowFlag},
                "not-taken SETL changed flags");
}

void testSetGreaterExtendedLowByteRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0x0F, 0x9F, 0xC6, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg, "SETG opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Greater, "SETG condition differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "SETG length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::R14 && destination.width == 8,
           "SETG extended low-byte destination differs");
    expect(rosa::debug::dumpX86(decoded).find("setg r14b") != std::string::npos,
           "SETG dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0x1122334455667788ULL;
    state.rflags = 0x882; // ZF=0, SF=OF=1.
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0x1122334455667701ULL},
                "taken SETG did not merge one into R14B");
    expectEqual(state.rflags, std::uint64_t{0x882}, "taken SETG changed flags");

    state.r14 = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x802; // ZF=0, SF=0, OF=1.
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0xFFEEDDCCBBAA9900ULL}, "SETG accepted unequal SF and OF");
    expectEqual(state.rflags, std::uint64_t{0x802}, "not-taken SETG changed flags");

    state.r14 = UINT64_MAX;
    state.rflags = 0x42; // ZF=1, SF=OF=0.
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0xFFFFFFFFFFFFFF00ULL}, "SETG ignored ZF");
    expectEqual(state.rflags, std::uint64_t{0x42}, "zero SETG changed flags");

    constexpr std::array<std::uint8_t, 3> highByte{0x0F, 0x9F, 0xC6};
    bool rejectedHighByte = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByte, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejectedHighByte = true;
    }
    expect(rejectedHighByte, "SETG DH was silently treated as a low-byte register");
}

void testSetEqualRipRelativeGuestByte() {
    constexpr std::array<std::uint8_t, 8> code{0x0F, 0x94, 0x05, 0x07, 0x68, 0xBC, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802AEA562ULL};
    constexpr rosa::guest::GuestAddress destination{0x7FF8436B0D70ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccMem &&
               decoded[0].condition == rosa::x86::Condition::Equal,
           "RIP-relative SETE opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative SETE length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0x40BC6807,
           "RIP-relative SETE operand differs");
    expect(rosa::debug::dumpX86(decoded).find("sete byte [rip+0x40bc6807]") != std::string::npos,
           "RIP-relative SETE dump differs");

    constexpr auto page =
        rosa::guest::GuestAddress{destination.value & ~(rosa::guest::guestPageSize - 1)};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "RIP-relative SETE destination");
    addressSpace.writeBytes(destination, std::array<std::uint8_t, 1>{0xA5});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State state;
    state.rflags = 0x8D7 | (std::uint64_t{1} << 6U);
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(destination, 1).front(), std::uint8_t{1},
                "taken RIP-relative SETE stored the wrong byte");
    expectEqual(state.rflags, std::uint64_t{0x8D7 | (std::uint64_t{1} << 6U)},
                "RIP-relative SETE changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[destination.value - page.value] = 0xA5;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, readOnlyBytes.size(), rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only SETE destination");
    rosa::x86::X86State faultState;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative SETE accepted a read-only destination");
    expectEqual(readOnlyAddressSpace.readBytes(destination, 1).front(), std::uint8_t{0xA5},
                "faulted RIP-relative SETE changed guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted RIP-relative SETE changed flags");
}

void testSetEqualSibGuestByte() {
    constexpr std::array<std::uint8_t, 7> code{0x41, 0x0F, 0x94, 0x44, 0x24, 0x08, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802C25F8CULL};
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress destination{0x8008};
    constexpr std::uint64_t zeroFlag = std::uint64_t{1} << 6U;
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expectEqual(decoded.size(), std::size_t{2}, "SIB SETE decoded an unexpected instruction count");
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccMem &&
               decoded[0].condition == rosa::x86::Condition::Equal,
           "SIB SETE opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "SIB SETE length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::R12 && memory.hasBase && !memory.index &&
               !memory.ripRelative && memory.width == 8 && memory.displacement == 8,
           "SIB SETE operand differs");
    expect(rosa::debug::dumpX86(decoded).find("sete byte [r12+0x8]") != std::string::npos,
           "SIB SETE dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State state;
    state.r12 = page.value;
    state.rflags = 0x897 | zeroFlag;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(destination, 1).front(), std::uint8_t{1},
                "taken SIB SETE stored the wrong byte");
    expectEqual(state.r12, page.value, "SIB SETE changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x897 | zeroFlag}, "SIB SETE changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[destination.value - page.value] = 0xA5;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, readOnlyBytes.size(), rosa::guest::Permission::Read,
                                    readOnlyBytes);
    rosa::x86::X86State faultState;
    faultState.r12 = page.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "SIB SETE accepted a read-only destination");
    expectEqual(readOnlyAddressSpace.readBytes(destination, 1).front(), std::uint8_t{0xA5},
                "faulted SIB SETE changed guest memory");
    expectEqual(faultState.r12, page.value, "faulted SIB SETE changed its base register");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted SIB SETE changed flags");
}

void testSetAboveOrEqualGuestByte() {
    constexpr std::array<std::uint8_t, 8> observed{0x0F, 0x93, 0x83, 0xCE, 0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded =
        decoder.decodeBlock(observed, rosa::guest::GuestAddress{0x7FF802AA05C8ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccMem &&
               decoded[0].condition == rosa::x86::Condition::AboveOrEqual,
           "SETAE byte memory opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "SETAE byte memory length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.width == 8 &&
               memory.displacement == 0xCE,
           "SETAE byte [rbx+0xce] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("setae byte [rbx+0xce]") != std::string::npos,
           "SETAE byte memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress destination{0x80CE};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(destination, std::array<std::uint8_t, 1>{0xA5});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observed, rosa::guest::GuestAddress{0x7FF802AA05C8ULL});

    rosa::x86::X86State taken;
    taken.rbx = page.value;
    taken.rflags = 0xAD6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(taken, &addressSpace));
    expectEqual(addressSpace.readBytes(destination, 1).front(), std::uint8_t{1},
                "taken SETAE byte memory stored the wrong value");
    expectEqual(taken.rbx, page.value, "SETAE byte memory changed its base");
    expectEqual(taken.rflags, std::uint64_t{0xAD6 & ~std::uint64_t{1}},
                "taken SETAE byte memory changed flags");

    addressSpace.writeBytes(destination, std::array<std::uint8_t, 1>{0xA5});
    rosa::x86::X86State notTaken;
    notTaken.rbx = page.value;
    notTaken.rflags = 0xAD7 | 1U;
    static_cast<void>(block.execute(notTaken, &addressSpace));
    expectEqual(addressSpace.readBytes(destination, 1).front(), std::uint8_t{0},
                "not-taken SETAE byte memory stored the wrong value");
    expectEqual(notTaken.rflags, std::uint64_t{0xAD7 | 1U},
                "not-taken SETAE byte memory changed flags");

    constexpr std::array<std::uint8_t, 8> setneCode{0x0F, 0x95, 0x83, 0xCF, 0x00, 0x00, 0x00, 0xC3};
    const auto setneDecoded =
        decoder.decodeBlock(setneCode, rosa::guest::GuestAddress{0x7FF802AA05E5ULL});
    expect(setneDecoded[0].opcode == rosa::x86::Opcode::SetccMem &&
               setneDecoded[0].condition == rosa::x86::Condition::NotEqual,
           "SETNE byte memory opcode or condition differs");
    expect(rosa::debug::dumpX86(setneDecoded).find("setne byte [rbx+0xcf]") != std::string::npos,
           "SETNE byte memory dump differs");
    const auto setneBlock =
        translator.translate(setneCode, rosa::guest::GuestAddress{0x7FF802AA05E5ULL});
    constexpr rosa::guest::GuestAddress setneDestination{0x80CF};
    rosa::x86::X86State setneTaken;
    setneTaken.rbx = page.value;
    setneTaken.rflags = 0x896 & ~(std::uint64_t{1} << 6U);
    static_cast<void>(setneBlock.execute(setneTaken, &addressSpace));
    expectEqual(addressSpace.readBytes(setneDestination, 1).front(), std::uint8_t{1},
                "taken SETNE byte memory stored the wrong value");
    expectEqual(setneTaken.rflags, std::uint64_t{0x896 & ~(std::uint64_t{1} << 6U)},
                "taken SETNE byte memory changed flags");
    rosa::x86::X86State setneNotTaken;
    setneNotTaken.rbx = page.value;
    setneNotTaken.rflags = 0x8D7 | (std::uint64_t{1} << 6U);
    static_cast<void>(setneBlock.execute(setneNotTaken, &addressSpace));
    expectEqual(addressSpace.readBytes(setneDestination, 1).front(), std::uint8_t{0},
                "not-taken SETNE byte memory stored the wrong value");
    expectEqual(setneNotTaken.rflags, std::uint64_t{0x8D7 | (std::uint64_t{1} << 6U)},
                "not-taken SETNE byte memory changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    rosa::x86::X86State faultState;
    faultState.rbx = page.value;
    faultState.rflags = 0xAD6;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "SETAE wrote a non-writable guest byte");
    expectEqual(readOnlyAddressSpace.readBytes(destination, 1).front(), std::uint8_t{0},
                "faulted SETAE changed guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xAD6}, "faulted SETAE changed flags");
}

void testConditionalMoveNotEqual32FromGuestMemory() {
    constexpr std::array<std::uint8_t, 8> code{0x0F, 0x45, 0x85, 0x08, 0xFF, 0xFF, 0xFF, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802A186CFULL};
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress source{0x8008};
    constexpr std::uint64_t zeroFlag = std::uint64_t{1} << 6U;
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccRegMem &&
               decoded[0].condition == rosa::x86::Condition::NotEqual,
           "memory CMOVNE opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "memory CMOVNE length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               memory.base == rosa::x86::Register::Rbp && memory.width == 32 && memory.hasBase &&
               !memory.index && memory.displacement == -0xF8,
           "memory CMOVNE operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovne eax, dword [rbp-0xf8]") != std::string::npos,
           "memory CMOVNE dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(source, 0xAABBCCDDU);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State taken;
    taken.rax = 0x1122334455667788ULL;
    taken.rbp = page.value + 0x100;
    taken.rflags = 0x897 & ~zeroFlag;
    static_cast<void>(block.execute(taken, &addressSpace));
    expectEqual(taken.rax, std::uint64_t{0xAABBCCDD}, "taken memory CMOVNE result differs");
    expectEqual(taken.rbp, page.value + 0x100, "memory CMOVNE changed its base register");
    expectEqual(taken.rflags, std::uint64_t{0x897 & ~zeroFlag},
                "taken memory CMOVNE changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rax = 0x1122334455667788ULL;
    notTaken.rbp = page.value + 0x100;
    notTaken.rflags = 0x897 | zeroFlag;
    static_cast<void>(block.execute(notTaken, &addressSpace));
    expectEqual(notTaken.rax, std::uint64_t{0x55667788},
                "untaken memory CMOVNE destination differs");
    expectEqual(notTaken.rflags, std::uint64_t{0x897 | zeroFlag},
                "untaken memory CMOVNE changed flags");

    for (const auto flags : std::array<std::uint64_t, 2>{std::uint64_t{0x897 & ~zeroFlag},
                                                         std::uint64_t{0x897 | zeroFlag}}) {
        rosa::guest::AddressSpace unmappedAddressSpace;
        rosa::x86::X86State faultState;
        faultState.rax = 0x1122334455667788ULL;
        faultState.rbp = page.value + 0x100;
        faultState.rip = rip.value;
        faultState.rflags = flags;
        bool rejected = false;
        try {
            static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
        } catch (const std::runtime_error &error) {
            rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
        }
        expect(rejected, "memory CMOVNE skipped its architectural source read");
        expectEqual(faultState.rax, std::uint64_t{0x1122334455667788ULL},
                    "faulted memory CMOVNE changed its destination");
        expectEqual(faultState.rbp, page.value + 0x100, "faulted memory CMOVNE changed its base");
        expectEqual(faultState.rip, rip.value, "faulted memory CMOVNE changed RIP");
        expectEqual(faultState.rflags, flags, "faulted memory CMOVNE changed flags");
    }
}

void testConditionalMoveBelow64() {
    constexpr std::array<std::uint8_t, 5> code{0x4C, 0x0F, 0x42, 0xE8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg, "CMOVB opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Below, "CMOVB condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R13 && destination.width == 64,
           "CMOVB destination differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 64, "CMOVB source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rax = 0x1122334455667788ULL;
    taken.r13 = UINT64_MAX;
    taken.rflags = 0x8D7 | 1U;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.r13, std::uint64_t{0x1122334455667788ULL}, "taken CMOVB result differs");
    expectEqual(taken.rax, std::uint64_t{0x1122334455667788ULL}, "CMOVB changed its source");
    expectEqual(taken.rflags, std::uint64_t{0x8D7 | 1U}, "taken CMOVB changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rax = UINT64_MAX;
    notTaken.r13 = 0xAABBCCDDEEFF0011ULL;
    notTaken.rflags = 0x8D6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.r13, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "untaken CMOVB changed destination");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D6 & ~std::uint64_t{1}},
                "untaken CMOVB changed flags");
}

void testConditionalMoveBelow32() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x42, 0xC8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A8F255ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               decoded[0].condition == rosa::x86::Condition::Below,
           "CMOVB r32 opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "CMOVB r32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32 &&
               source.reg == rosa::x86::Register::Rax && source.width == 32,
           "CMOVB ecx, eax operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovb ecx, eax") != std::string::npos,
           "CMOVB r32 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A8F255ULL});
    rosa::x86::X86State taken;
    taken.rax = 0xAABBCCDD11223344ULL;
    taken.rcx = UINT64_MAX;
    taken.rflags = 0x8D7 | 1U;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rcx, std::uint64_t{0x11223344},
                "taken CMOVB r32 did not zero-extend its destination");
    expectEqual(taken.rax, std::uint64_t{0xAABBCCDD11223344ULL}, "CMOVB r32 changed its source");
    expectEqual(taken.rflags, std::uint64_t{0x8D7 | 1U}, "taken CMOVB r32 changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rax = UINT64_MAX;
    notTaken.rcx = 0xAABBCCDD55667788ULL;
    notTaken.rflags = 0x8D6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rcx, std::uint64_t{0x55667788},
                "untaken CMOVB r32 did not clear destination upper bits");
    expectEqual(notTaken.rax, UINT64_MAX, "untaken CMOVB r32 changed its source");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D6 & ~std::uint64_t{1}},
                "untaken CMOVB r32 changed flags");
}

void testConditionalMoveAboveOrEqual64() {
    constexpr std::array<std::uint8_t, 5> code{0x4C, 0x0F, 0x43, 0xFE, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg, "CMOVAE opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "CMOVAE length differs");
    expect(decoded[0].condition == rosa::x86::Condition::AboveOrEqual, "CMOVAE condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R15 && destination.width == 64,
           "CMOVAE destination differs");
    expect(source.reg == rosa::x86::Register::Rsi && source.width == 64, "CMOVAE source differs");
    expect(rosa::debug::dumpX86(decoded).find("cmovae r15, rsi") != std::string::npos,
           "CMOVAE dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rsi = 0x0123456789ABCDEFULL;
    taken.r15 = UINT64_MAX;
    taken.rflags = 0x8D6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(taken));
    expectEqual(taken.r15, std::uint64_t{0x0123456789ABCDEFULL}, "taken CMOVAE result differs");
    expectEqual(taken.rsi, std::uint64_t{0x0123456789ABCDEFULL}, "CMOVAE changed its source");
    expectEqual(taken.rflags, std::uint64_t{0x8D6 & ~std::uint64_t{1}},
                "taken CMOVAE changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rsi = UINT64_MAX;
    notTaken.r15 = 0xAABBCCDDEEFF0011ULL;
    notTaken.rflags = 0xAD7 | 1U;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.r15, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "untaken CMOVAE changed destination");
    expectEqual(notTaken.rsi, UINT64_MAX, "untaken CMOVAE changed source");
    expectEqual(notTaken.rflags, std::uint64_t{0xAD7 | 1U}, "untaken CMOVAE changed flags");
}

void testConditionalMoveAboveOrEqual32() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x43, 0xF1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF8000517F4ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               decoded[0].condition == rosa::x86::Condition::AboveOrEqual,
           "CMOVAE r32 opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "CMOVAE r32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 32 &&
               source.reg == rosa::x86::Register::Rcx && source.width == 32,
           "CMOVAE esi, ecx operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovae esi, ecx") != std::string::npos,
           "CMOVAE r32 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF8000517F4ULL});
    rosa::x86::X86State taken;
    taken.rcx = 0xAABBCCDD11223344ULL;
    taken.rsi = 0xFFFFFFFF55667788ULL;
    taken.rflags = 0x8D6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rsi, std::uint64_t{0x11223344},
                "taken CMOVAE r32 did not zero-extend its destination");
    expectEqual(taken.rcx, std::uint64_t{0xAABBCCDD11223344ULL}, "CMOVAE r32 changed its source");
    expectEqual(taken.rflags, std::uint64_t{0x8D6 & ~std::uint64_t{1}},
                "taken CMOVAE r32 changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rcx = UINT64_MAX;
    notTaken.rsi = 0xAABBCCDD55667788ULL;
    notTaken.rflags = 0xAD7 | 1U;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rsi, std::uint64_t{0x55667788},
                "untaken CMOVAE r32 did not clear destination upper bits");
    expectEqual(notTaken.rcx, UINT64_MAX, "untaken CMOVAE r32 changed its source");
    expectEqual(notTaken.rflags, std::uint64_t{0xAD7 | 1U}, "untaken CMOVAE r32 changed flags");
}

void testConditionalMoveAbove64() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x0F, 0x47, 0xD0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg, "CMOVA opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "CMOVA length differs");
    expect(decoded[0].condition == rosa::x86::Condition::Above, "CMOVA condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 64,
           "CMOVA destination differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 64, "CMOVA source differs");
    expect(rosa::debug::dumpX86(decoded).find("cmova rdx, rax") != std::string::npos,
           "CMOVA dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rax = 0x0123456789ABCDEFULL;
    taken.rdx = UINT64_MAX;
    taken.rflags = 0x892; // CF=0, ZF=0; unrelated defined flags are set.
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rdx, std::uint64_t{0x0123456789ABCDEFULL}, "taken CMOVA result differs");
    expectEqual(taken.rflags, std::uint64_t{0x892}, "taken CMOVA changed flags");

    for (const auto flags : std::array<std::uint64_t, 3>{0x893, 0x8D2, 0x8D3}) {
        rosa::x86::X86State notTaken;
        notTaken.rax = UINT64_MAX;
        notTaken.rdx = 0xAABBCCDDEEFF0011ULL;
        notTaken.rflags = flags;
        static_cast<void>(block.execute(notTaken));
        expectEqual(notTaken.rdx, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                    "untaken CMOVA changed destination");
        expectEqual(notTaken.rax, UINT64_MAX, "untaken CMOVA changed source");
        expectEqual(notTaken.rflags, flags, "untaken CMOVA changed flags");
    }
}

void testConditionalMoveBelowOrEqual32() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x46, 0xD9, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802D0504AULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               decoded[0].condition == rosa::x86::Condition::BelowOrEqual,
           "CMOVBE r32 opcode or condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rbx && destination.width == 32 &&
               source.reg == rosa::x86::Register::Rcx && source.width == 32,
           "CMOVBE ebx, ecx operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovbe ebx, ecx") != std::string::npos,
           "CMOVBE ebx, ecx dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    for (const auto flags : {std::uint64_t{0x3}, std::uint64_t{0x42}, std::uint64_t{0x43}}) {
        rosa::x86::X86State taken;
        taken.rbx = UINT64_C(0xFFFFFFFF89ABCDEF);
        taken.rcx = UINT64_C(0xFEDCBA9812345678);
        taken.rflags = flags;
        static_cast<void>(block.execute(taken));
        expectEqual(taken.rbx, std::uint64_t{0x12345678},
                    "taken CMOVBE r32 did not zero-extend its source");
        expectEqual(taken.rcx, UINT64_C(0xFEDCBA9812345678), "CMOVBE changed its source");
        expectEqual(taken.rflags, flags, "taken CMOVBE changed flags");
    }

    rosa::x86::X86State notTaken;
    notTaken.rbx = UINT64_C(0xFFFFFFFF89ABCDEF);
    notTaken.rcx = UINT64_C(0xFEDCBA9812345678);
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rbx, std::uint64_t{0x89ABCDEF},
                "untaken CMOVBE r32 did not clear destination upper bits");
    expectEqual(notTaken.rcx, UINT64_C(0xFEDCBA9812345678), "untaken CMOVBE changed its source");
    expectEqual(notTaken.rflags, std::uint64_t{0x2}, "untaken CMOVBE changed flags");
}

void testConditionalMoveEqual64() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x0F, 0x44, 0xC8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg, "CMOVE opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Equal, "CMOVE condition differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 64,
           "CMOVE destination differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 64, "CMOVE source differs");
    expect(rosa::debug::dumpX86(decoded).find("cmove rcx, rax") != std::string::npos,
           "CMOVE dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rax = 0x1122334455667788ULL;
    taken.rcx = UINT64_MAX;
    taken.rflags = 0x8D7 | zeroFlag;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rcx, std::uint64_t{0x1122334455667788ULL}, "taken CMOVE result differs");
    expectEqual(taken.rax, std::uint64_t{0x1122334455667788ULL}, "CMOVE changed its source");
    expectEqual(taken.rflags, std::uint64_t{0x8D7 | zeroFlag}, "taken CMOVE changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rax = UINT64_MAX;
    notTaken.rcx = 0xAABBCCDDEEFF0011ULL;
    notTaken.rflags = 0x8D7 & ~zeroFlag;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rcx, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "untaken CMOVE changed destination");
    expectEqual(notTaken.rax, UINT64_MAX, "untaken CMOVE changed source");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D7 & ~zeroFlag}, "untaken CMOVE changed flags");
}

void testConditionalMoveEqual64FromGuestMemory() {
    // Observed in libsqlite3: CMOVE R14, qword [RBP-0x68] with REX.WR.
    constexpr std::array<std::uint8_t, 6> code{0x4C, 0x0F, 0x44, 0x75, 0x98, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10007DC64ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccRegMem, "CMOVE memory opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Equal, "CMOVE memory condition differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "CMOVE memory length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R14 && destination.width == 64,
           "CMOVE memory destination differs");
    expect(memory.base == rosa::x86::Register::Rbp && memory.displacement == -0x68 &&
               memory.width == 64,
           "CMOVE memory source differs");
    expect(rosa::debug::dumpX86(decoded).find("cmove r14, qword [rbp-0x68]") != std::string::npos,
           "CMOVE memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x1122334455667788ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10007DC64ULL});
    rosa::x86::X86State taken;
    taken.rbp = target.value + 0x68;
    taken.r14 = UINT64_MAX;
    taken.rflags = 0x8D7 | zeroFlag;
    static_cast<void>(block.execute(taken, &addressSpace));
    expectEqual(taken.r14, std::uint64_t{0x1122334455667788ULL}, "taken CMOVE memory differs");
    expectEqual(taken.rflags, std::uint64_t{0x8D7 | zeroFlag}, "taken CMOVE memory changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rbp = target.value + 0x68;
    notTaken.r14 = 0xAABBCCDDEEFF0011ULL;
    notTaken.rflags = 0x8D7 & ~zeroFlag;
    static_cast<void>(block.execute(notTaken, &addressSpace));
    expectEqual(notTaken.r14, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "untaken CMOVE memory changed destination");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D7 & ~zeroFlag},
                "untaken CMOVE memory changed flags");
}

void testConditionalMoveNotEqual64Extended() {
    constexpr std::array<std::uint8_t, 5> code{0x4C, 0x0F, 0x45, 0xE1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF80004EA65ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg, "CMOVNE opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::NotEqual, "CMOVNE condition differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "CMOVNE length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R12 && destination.width == 64 &&
               source.reg == rosa::x86::Register::Rcx && source.width == 64,
           "CMOVNE r12, rcx operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovne r12, rcx") != std::string::npos,
           "CMOVNE dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF80004EA65ULL});
    rosa::x86::X86State taken;
    taken.rcx = 0x1122334455667788ULL;
    taken.r12 = UINT64_MAX;
    taken.rflags = 0x897 & ~zeroFlag;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.r12, std::uint64_t{0x1122334455667788ULL}, "taken CMOVNE result differs");
    expectEqual(taken.rcx, std::uint64_t{0x1122334455667788ULL}, "CMOVNE changed its source");
    expectEqual(taken.rflags, std::uint64_t{0x897 & ~zeroFlag}, "taken CMOVNE changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rcx = UINT64_MAX;
    notTaken.r12 = 0xAABBCCDDEEFF0011ULL;
    notTaken.rflags = 0x897 | zeroFlag;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.r12, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "untaken CMOVNE changed destination");
    expectEqual(notTaken.rcx, UINT64_MAX, "untaken CMOVNE changed source");
    expectEqual(notTaken.rflags, std::uint64_t{0x897 | zeroFlag}, "untaken CMOVNE changed flags");
}

void testConditionalMoveNotEqual32Legacy() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x45, 0xC2, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802AB296BULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               decoded[0].condition == rosa::x86::Condition::NotEqual,
           "legacy CMOVNE r32 opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "legacy CMOVNE r32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               source.reg == rosa::x86::Register::Rdx && source.width == 32,
           "legacy CMOVNE eax, edx operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovne eax, edx") != std::string::npos,
           "legacy CMOVNE eax, edx dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State taken;
    taken.rax = UINT64_MAX;
    taken.rdx = 0xAABBCCDD10203040ULL;
    taken.rflags = 0x8D7 & ~zeroFlag;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rax, std::uint64_t{0x10203040},
                "taken legacy CMOVNE r32 did not zero-extend its result");
    expectEqual(taken.rdx, std::uint64_t{0xAABBCCDD10203040ULL},
                "legacy CMOVNE r32 changed its source");
    expectEqual(taken.rflags, std::uint64_t{0x8D7 & ~zeroFlag},
                "taken legacy CMOVNE r32 changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rax = 0xAABBCCDD11223344ULL;
    notTaken.rdx = UINT64_MAX;
    notTaken.rflags = 0x8D7 | zeroFlag;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rax, std::uint64_t{0x11223344},
                "untaken legacy CMOVNE r32 did not clear upper bits");
    expectEqual(notTaken.rdx, UINT64_MAX, "untaken legacy CMOVNE r32 changed its source");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D7 | zeroFlag},
                "untaken legacy CMOVNE r32 changed flags");
}

void testConditionalMoveSign64() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x0F, 0x48, 0xCF, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802ADEDBDULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               decoded[0].condition == rosa::x86::Condition::Sign,
           "CMOVS opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "CMOVS length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 64 &&
               source.reg == rosa::x86::Register::Rdi && source.width == 64,
           "CMOVS rcx, rdi operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovs rcx, rdi") != std::string::npos,
           "CMOVS rcx, rdi dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State taken;
    taken.rcx = 0x1111;
    taken.rdi = 0xAABBCCDDEEFF0011ULL;
    taken.rflags = 0x8D7 | (1U << 7U);
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rcx, std::uint64_t{0xAABBCCDDEEFF0011ULL}, "taken CMOVS result differs");
    expectEqual(taken.rflags, std::uint64_t{0x8D7 | (1U << 7U)}, "taken CMOVS changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rcx = 0x1122334455667788ULL;
    notTaken.rdi = UINT64_MAX;
    notTaken.rflags = 0x8D7 & ~(1U << 7U);
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rcx, std::uint64_t{0x1122334455667788ULL},
                "untaken CMOVS changed destination");
    expectEqual(notTaken.rdi, UINT64_MAX, "untaken CMOVS changed source");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D7 & ~(1U << 7U)}, "untaken CMOVS changed flags");

    constexpr std::array<std::uint8_t, 5> notSignCode{0x48, 0x0F, 0x49, 0xF1, 0xC3};
    const auto notSignDecoded =
        decoder.decodeBlock(notSignCode, rosa::guest::GuestAddress{0x7FF802ADF87DULL});
    expect(notSignDecoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               notSignDecoded[0].condition == rosa::x86::Condition::NotSign,
           "CMOVNS opcode or condition differs");
    const auto notSignDestination =
        std::get<rosa::x86::RegisterOperand>(notSignDecoded[0].operands[0]);
    const auto notSignSource = std::get<rosa::x86::RegisterOperand>(notSignDecoded[0].operands[1]);
    expect(notSignDestination.reg == rosa::x86::Register::Rsi && notSignDestination.width == 64 &&
               notSignSource.reg == rosa::x86::Register::Rcx && notSignSource.width == 64,
           "CMOVNS rsi, rcx operands differ");
    expect(rosa::debug::dumpX86(notSignDecoded).find("cmovns rsi, rcx") != std::string::npos,
           "CMOVNS rsi, rcx dump differs");
    const auto notSignBlock =
        translator.translate(notSignCode, rosa::guest::GuestAddress{0x7FF802ADF87DULL});
    rosa::x86::X86State notSignTaken;
    notSignTaken.rsi = 0x1111;
    notSignTaken.rcx = 0xAABBCCDDEEFF0011ULL;
    notSignTaken.rflags = 0x8D7 & ~(1U << 7U);
    static_cast<void>(notSignBlock.execute(notSignTaken));
    expectEqual(notSignTaken.rsi, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "taken CMOVNS result differs");

    rosa::x86::X86State notSignNotTaken;
    notSignNotTaken.rsi = 0x1122334455667788ULL;
    notSignNotTaken.rcx = UINT64_MAX;
    notSignNotTaken.rflags = 0x8D7 | (1U << 7U);
    static_cast<void>(notSignBlock.execute(notSignNotTaken));
    expectEqual(notSignNotTaken.rsi, std::uint64_t{0x1122334455667788ULL},
                "untaken CMOVNS changed destination");

    constexpr std::array<std::uint8_t, 4> legacyCode{0x0F, 0x48, 0xCA, 0xC3};
    constexpr rosa::guest::GuestAddress legacyAddress{0x7FF802A1B206ULL};
    const auto legacyDecoded = decoder.decodeBlock(legacyCode, legacyAddress);
    expect(legacyDecoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               legacyDecoded[0].condition == rosa::x86::Condition::Sign,
           "legacy CMOVS r32 opcode or condition differs");
    expectEqual(legacyDecoded[0].length, std::uint8_t{3}, "legacy CMOVS r32 length differs");
    const auto legacyDestination =
        std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[0]);
    const auto legacySource = std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[1]);
    expect(legacyDestination.reg == rosa::x86::Register::Rcx && legacyDestination.width == 32 &&
               legacySource.reg == rosa::x86::Register::Rdx && legacySource.width == 32,
           "cmovs ecx, edx operands differ");
    expect(rosa::debug::dumpX86(legacyDecoded).find("cmovs ecx, edx") != std::string::npos,
           "cmovs ecx, edx dump differs");

    const auto legacyBlock = translator.translate(legacyCode, legacyAddress);
    rosa::x86::X86State legacyTaken;
    legacyTaken.rcx = 0xAABBCCDD11223344ULL;
    legacyTaken.rdx = 0x88776655DEADBEEFULL;
    legacyTaken.rflags = 0x8D7 | (1U << 7U);
    static_cast<void>(legacyBlock.execute(legacyTaken));
    expectEqual(legacyTaken.rcx, std::uint64_t{0xDEADBEEFULL},
                "taken legacy CMOVS r32 result differs");
    expectEqual(legacyTaken.rdx, std::uint64_t{0x88776655DEADBEEFULL},
                "legacy CMOVS r32 changed its source");
    expectEqual(legacyTaken.rflags, std::uint64_t{0x8D7 | (1U << 7U)},
                "taken legacy CMOVS r32 changed flags");

    rosa::x86::X86State legacyNotTaken;
    legacyNotTaken.rcx = 0xAABBCCDD11223344ULL;
    legacyNotTaken.rdx = UINT64_MAX;
    legacyNotTaken.rflags = 0x8D7 & ~(1U << 7U);
    static_cast<void>(legacyBlock.execute(legacyNotTaken));
    expectEqual(legacyNotTaken.rcx, std::uint64_t{0x11223344},
                "untaken legacy CMOVS r32 did not clear upper bits");
    expectEqual(legacyNotTaken.rdx, UINT64_MAX, "untaken legacy CMOVS r32 changed its source");
    expectEqual(legacyNotTaken.rflags, std::uint64_t{0x8D7 & ~(1U << 7U)},
                "untaken legacy CMOVS r32 changed flags");
}

void testConditionalMoveLessOrEqual64() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x0F, 0x4E, 0xC8,
                                               0xC3}; // cmovle rcx, rax; ret
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802D19EC6ULL};
    constexpr std::uint64_t zero = std::uint64_t{1} << 6U;
    constexpr std::uint64_t sign = std::uint64_t{1} << 7U;
    constexpr std::uint64_t overflow = std::uint64_t{1} << 11U;

    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               decoded[0].condition == rosa::x86::Condition::LessOrEqual,
           "CMOVLE opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "CMOVLE length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 64 &&
               source.reg == rosa::x86::Register::Rax && source.width == 64,
           "CMOVLE rcx, rax operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovle rcx, rax") != std::string::npos,
           "CMOVLE rcx, rax dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    const auto expectMove = [&block](std::uint64_t flags, std::string_view context) {
        rosa::x86::X86State state;
        state.rax = 0xAABBCCDDEEFF0011ULL;
        state.rcx = 0x1122334455667788ULL;
        state.rflags = flags;
        static_cast<void>(block.execute(state));
        expectEqual(state.rcx, std::uint64_t{0xAABBCCDDEEFF0011ULL}, context);
        expectEqual(state.rax, std::uint64_t{0xAABBCCDDEEFF0011ULL}, "CMOVLE changed its source");
        expectEqual(state.rflags, flags, "taken CMOVLE changed flags");
    };
    expectMove(0x2 | zero, "CMOVLE did not take when ZF was set");
    expectMove(0x2 | sign, "CMOVLE did not take when SF differed from OF");
    expectMove(0x2 | overflow, "CMOVLE did not take when OF differed from SF");

    const auto expectNoMove = [&block](std::uint64_t flags, std::string_view context) {
        rosa::x86::X86State state;
        state.rax = 0x1A;
        state.rcx = 1;
        state.rflags = flags;
        static_cast<void>(block.execute(state));
        expectEqual(state.rcx, std::uint64_t{1}, context);
        expectEqual(state.rax, std::uint64_t{0x1A}, "untaken CMOVLE changed its source");
        expectEqual(state.rflags, flags, "untaken CMOVLE changed flags");
    };
    expectNoMove(0x2, "live CMOVLE case moved when ZF=0 and SF equaled OF");
    expectNoMove(0x2 | sign | overflow, "CMOVLE moved when SF and OF were both set");
}

void testConditionalMoveGreaterOrEqual32() {
    // Observed in libsystem_c: cmovge eax, ecx without a REX prefix.
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x4D, 0xC1, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802D27CFEULL};
    constexpr std::uint64_t sign = std::uint64_t{1} << 7U;
    constexpr std::uint64_t overflow = std::uint64_t{1} << 11U;

    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               decoded[0].condition == rosa::x86::Condition::GreaterOrEqual,
           "CMOVGE opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "CMOVGE length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               source.reg == rosa::x86::Register::Rcx && source.width == 32,
           "CMOVGE eax, ecx operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovge eax, ecx") != std::string::npos,
           "CMOVGE eax, ecx dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    const auto execute = [&block](std::uint64_t flags) {
        rosa::x86::X86State state;
        state.rax = 0xAABBCCDD11223344ULL;
        state.rcx = 0x88776655DEADBEEFULL;
        state.rflags = flags;
        static_cast<void>(block.execute(state));
        return state;
    };
    const auto taken = execute(0x2);
    expectEqual(taken.rax, std::uint64_t{0xDEADBEEFULL},
                "CMOVGE did not take when SF=OF=0");
    expectEqual(taken.rflags, std::uint64_t{0x2}, "taken CMOVGE changed flags");
    const auto alsoTaken = execute(0x2 | sign | overflow);
    expectEqual(alsoTaken.rax, std::uint64_t{0xDEADBEEFULL},
                "CMOVGE did not take when SF and OF were both set");
    const auto notTaken = execute(0x2 | sign);
    expectEqual(notTaken.rax, std::uint64_t{0x11223344},
                "CMOVGE moved when SF differed from OF");
    const auto overflowOnly = execute(0x2 | overflow);
    expectEqual(overflowOnly.rax, std::uint64_t{0x11223344},
                "CMOVGE moved when OF differed from SF");
}

void testConditionalMoveLessAndOverflow64() {
    constexpr std::array<std::uint8_t, 5> lessCode{0x48, 0x0F, 0x4C, 0xC1, 0xC3};
    constexpr std::array<std::uint8_t, 5> overflowCode{0x48, 0x0F, 0x40, 0xC1, 0xC3};
    constexpr std::uint64_t sign = std::uint64_t{1} << 7U;
    constexpr std::uint64_t overflow = std::uint64_t{1} << 11U;

    const rosa::x86::Decoder decoder;
    const auto lessDecoded =
        decoder.decodeBlock(lessCode, rosa::guest::GuestAddress{0x1000});
    expect(lessDecoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               lessDecoded[0].condition == rosa::x86::Condition::Less,
           "CMOVL opcode or condition differs");
    expect(rosa::debug::dumpX86(lessDecoded).find("cmovl rax, rcx") != std::string::npos,
           "CMOVL rax, rcx dump differs");
    const auto overflowDecoded =
        decoder.decodeBlock(overflowCode, rosa::guest::GuestAddress{0x2000});
    expect(overflowDecoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               overflowDecoded[0].condition == rosa::x86::Condition::Overflow,
           "CMOVO opcode or condition differs");
    expect(rosa::debug::dumpX86(overflowDecoded).find("cmovo rax, rcx") != std::string::npos,
           "CMOVO rax, rcx dump differs");

    const rosa::dbt::Translator translator;
    const auto lessBlock =
        translator.translate(lessCode, rosa::guest::GuestAddress{0x1000});
    const auto executeLess = [&lessBlock](std::uint64_t flags) {
        rosa::x86::X86State state;
        state.rax = 0x1111;
        state.rcx = UINT64_C(0xAABBCCDDEEFF0011);
        state.rflags = flags;
        static_cast<void>(lessBlock.execute(state));
        return state;
    };
    expectEqual(executeLess(0x2 | sign).rax, UINT64_C(0xAABBCCDDEEFF0011),
                "CMOVL did not take when SF differed from OF");
    expectEqual(executeLess(0x2 | overflow).rax, UINT64_C(0xAABBCCDDEEFF0011),
                "CMOVL did not take when OF differed from SF");
    expectEqual(executeLess(0x2).rax, std::uint64_t{0x1111},
                "CMOVL moved when SF equaled OF");
    expectEqual(executeLess(0x2 | sign | overflow).rax, std::uint64_t{0x1111},
                "CMOVL moved when SF and OF were both set");

    const auto overflowBlock =
        translator.translate(overflowCode, rosa::guest::GuestAddress{0x2000});
    const auto executeOverflow = [&overflowBlock](std::uint64_t flags) {
        rosa::x86::X86State state;
        state.rax = 0x1111;
        state.rcx = UINT64_C(0xAABBCCDDEEFF0011);
        state.rflags = flags;
        static_cast<void>(overflowBlock.execute(state));
        return state;
    };
    expectEqual(executeOverflow(0x2 | overflow).rax, UINT64_C(0xAABBCCDDEEFF0011),
                "CMOVO did not take when OF was set");
    expectEqual(executeOverflow(0x2).rax, std::uint64_t{0x1111},
                "CMOVO moved when OF was clear");
}

void testConditionalMoveGreater64() {
    constexpr std::array<std::uint8_t, 5> code{0x49, 0x0F, 0x4F, 0xCE, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802D07632ULL};
    constexpr std::uint64_t zero = std::uint64_t{1} << 6U;
    constexpr std::uint64_t sign = std::uint64_t{1} << 7U;
    constexpr std::uint64_t overflow = std::uint64_t{1} << 11U;
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               decoded[0].condition == rosa::x86::Condition::Greater && decoded[0].length == 4,
           "CMOVG opcode, condition, or length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 64 &&
               source.reg == rosa::x86::Register::R14 && source.width == 64,
           "CMOVG rcx, r14 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovg rcx, r14") != std::string::npos,
           "CMOVG rcx, r14 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    const auto execute = [&block](std::uint64_t flags) {
        rosa::x86::X86State state;
        state.rcx = 0x1111;
        state.r14 = UINT64_C(0xAABBCCDDEEFF0011);
        state.rflags = flags;
        static_cast<void>(block.execute(state));
        return state;
    };
    const auto taken = execute(0x2);
    expectEqual(taken.rcx, UINT64_C(0xAABBCCDDEEFF0011),
                "CMOVG did not take when ZF=0 and SF=OF=0");
    expectEqual(taken.rflags, std::uint64_t{0x2}, "taken CMOVG changed flags");
    const auto alsoTaken = execute(0x2 | sign | overflow);
    expectEqual(alsoTaken.rcx, UINT64_C(0xAABBCCDDEEFF0011),
                "CMOVG did not take when ZF=0 and SF=OF=1");
    expectEqual(execute(0x2 | zero).rcx, std::uint64_t{0x1111}, "CMOVG took with ZF set");
    expectEqual(execute(0x2 | sign).rcx, std::uint64_t{0x1111},
                "CMOVG took when SF differed from OF");
}

void testConditionalMoveGreater32Legacy() {
    // Observed in sqlite: CMOVG EAX, EBX without a REX prefix.
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x4F, 0xC3, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000600A2ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               decoded[0].condition == rosa::x86::Condition::Greater,
           "legacy CMOVG opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "legacy CMOVG length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               source.reg == rosa::x86::Register::Rbx && source.width == 32,
           "CMOVG EAX, EBX operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmovg eax, ebx") != std::string::npos,
           "CMOVG EAX, EBX dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000600A2ULL});
    const auto execute = [&block](std::uint64_t flags) {
        rosa::x86::X86State state;
        state.rax = 0xAABBCCDD11223344ULL;
        state.rbx = 0x88776655DEADBEEFULL;
        state.rflags = flags;
        static_cast<void>(block.execute(state));
        return state;
    };
    // Greater means ZF=0 and SF=OF: cleared flags take, ZF set does not.
    const auto taken = execute(0x2);
    expectEqual(taken.rax, std::uint64_t{0xDEADBEEF}, "legacy CMOVG did not take when greater");
    expectEqual(taken.rflags, std::uint64_t{0x2}, "taken legacy CMOVG changed flags");
    const auto notTaken = execute(0x2 | (std::uint64_t{1} << 6U));
    expectEqual(notTaken.rax, std::uint64_t{0x11223344},
                "legacy CMOVG moved when ZF was set");
}

void testConditionalMoveEqual32Extended() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0x0F, 0x44, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF800059944ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg &&
               decoded[0].condition == rosa::x86::Condition::Equal,
           "CMOVE extended r32 opcode or condition differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "CMOVE extended r32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               source.reg == rosa::x86::Register::R8 && source.width == 32,
           "CMOVE eax, r8d operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmove eax, r8d") != std::string::npos,
           "CMOVE extended r32 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF800059944ULL});
    rosa::x86::X86State taken;
    taken.rax = UINT64_MAX;
    taken.r8 = 0xAABBCCDD11223344ULL;
    taken.rflags = 0x8D7 | zeroFlag;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rax, std::uint64_t{0x11223344},
                "taken CMOVE r32 did not zero-extend its destination");
    expectEqual(taken.r8, std::uint64_t{0xAABBCCDD11223344ULL},
                "CMOVE r32 changed its extended source");
    expectEqual(taken.rflags, std::uint64_t{0x8D7 | zeroFlag}, "taken CMOVE r32 changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rax = 0xAABBCCDD55667788ULL;
    notTaken.r8 = UINT64_MAX;
    notTaken.rflags = 0x897 & ~zeroFlag;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rax, std::uint64_t{0x55667788},
                "untaken CMOVE r32 did not clear destination upper bits");
    expectEqual(notTaken.r8, UINT64_MAX, "untaken CMOVE r32 changed its source");
    expectEqual(notTaken.rflags, std::uint64_t{0x897 & ~zeroFlag},
                "untaken CMOVE r32 changed flags");
}

void testUnsignedAboveConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x77, 0x02}; // ja 0x1004
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::Above, "JA rel8 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x2;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1004}, "JA did not take with CF and ZF clear");
    expectEqual(taken.rflags, std::uint64_t{0x2}, "JA changed guest flags");

    rosa::x86::X86State carrySet;
    carrySet.rflags = 0x3;
    static_cast<void>(block.execute(carrySet));
    expectEqual(carrySet.rip, std::uint64_t{0x1002}, "JA took with CF set");

    rosa::x86::X86State zeroSet;
    zeroSet.rflags = 0x42;
    static_cast<void>(block.execute(zeroSet));
    expectEqual(zeroSet.rip, std::uint64_t{0x1002}, "JA took with ZF set");
}

void testUnsignedAboveLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x87, 0x02, 0, 0, 0};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::Above, "JA rel32 condition differs");
    expectEqual(decoded[0].branchTarget->value, std::uint64_t{0x1008}, "JA rel32 target differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x2;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1008}, "JA rel32 did not take");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x3;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1006}, "JA rel32 took with CF set");
}

void testUnsignedAboveOrEqualLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x83, 0x02, 0, 0, 0};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::AboveOrEqual,
           "JAE rel32 condition differs");
    expectEqual(decoded[0].branchTarget->value, std::uint64_t{0x1008}, "JAE rel32 target differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x8D6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1008}, "JAE did not take with CF clear");
    expectEqual(taken.rflags, std::uint64_t{0x8D6 & ~std::uint64_t{1}}, "taken JAE changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x8D7 | 1U;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1006}, "JAE took with CF set");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D7 | 1U}, "not-taken JAE changed flags");
}

void testUnsignedBelowOrEqualConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x76, 0x02}; // jbe 0x1004
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::BelowOrEqual,
           "JBE rel8 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State carrySet;
    carrySet.rflags = 0x3;
    static_cast<void>(block.execute(carrySet));
    expectEqual(carrySet.rip, std::uint64_t{0x1004}, "JBE did not take with CF set");

    rosa::x86::X86State zeroSet;
    zeroSet.rflags = 0x42;
    static_cast<void>(block.execute(zeroSet));
    expectEqual(zeroSet.rip, std::uint64_t{0x1004}, "JBE did not take with ZF set");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1002}, "JBE took with CF and ZF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x2}, "JBE changed guest flags");
}

void testUnsignedBelowOrEqualLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x86, 0x02, 0, 0, 0};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::BelowOrEqual,
           "JBE rel32 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State carryTaken;
    carryTaken.rflags = 0x3;
    static_cast<void>(block.execute(carryTaken));
    expectEqual(carryTaken.rip, std::uint64_t{0x1008}, "JBE rel32 did not take with CF set");

    rosa::x86::X86State zeroTaken;
    zeroTaken.rflags = 0x42;
    static_cast<void>(block.execute(zeroTaken));
    expectEqual(zeroTaken.rip, std::uint64_t{0x1008}, "JBE rel32 did not take with ZF set");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1006}, "JBE rel32 took with CF and ZF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x2}, "JBE rel32 changed flags");
}

void testSignedLessConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x7C, 0x28};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF80004F144ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::JccRelative &&
               decoded[0].condition == rosa::x86::Condition::Less,
           "JL rel8 condition differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "JL rel8 length differs");
    expect(decoded[0].branchTarget && decoded[0].branchTarget->value == 0x7FF80004F16EULL,
           "JL rel8 target differs");
    expect(rosa::debug::dumpX86(decoded).find("jl 0x7ff80004f16e") != std::string::npos,
           "JL rel8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF80004F144ULL});

    rosa::x86::X86State signOnly;
    signOnly.rflags = 0x82;
    static_cast<void>(block.execute(signOnly));
    expectEqual(signOnly.rip, std::uint64_t{0x7FF80004F16EULL},
                "JL did not take with SF set and OF clear");
    expectEqual(signOnly.rflags, std::uint64_t{0x82}, "JL changed flags on a taken branch");

    rosa::x86::X86State overflowOnly;
    overflowOnly.rflags = 0x802;
    static_cast<void>(block.execute(overflowOnly));
    expectEqual(overflowOnly.rip, std::uint64_t{0x7FF80004F16EULL},
                "JL did not take with SF clear and OF set");

    rosa::x86::X86State equalBits;
    equalBits.rflags = 0x882;
    static_cast<void>(block.execute(equalBits));
    expectEqual(equalBits.rip, std::uint64_t{0x7FF80004F146ULL}, "JL took with SF and OF both set");
    expectEqual(equalBits.rflags, std::uint64_t{0x882}, "JL changed flags on a fallthrough branch");

    rosa::x86::X86State clearBits;
    clearBits.rflags = 0x2;
    static_cast<void>(block.execute(clearBits));
    expectEqual(clearBits.rip, std::uint64_t{0x7FF80004F146ULL},
                "JL took with SF and OF both clear");
}

void testSignedGreaterConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x7F, 0x23};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF80004F157ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::JccRelative &&
               decoded[0].condition == rosa::x86::Condition::Greater,
           "JG rel8 condition differs");
    expect(decoded[0].branchTarget && decoded[0].branchTarget->value == 0x7FF80004F17CULL,
           "JG rel8 target differs");
    expect(rosa::debug::dumpX86(decoded).find("jg 0x7ff80004f17c") != std::string::npos,
           "JG rel8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF80004F157ULL});

    rosa::x86::X86State clear;
    clear.rflags = 0x2;
    static_cast<void>(block.execute(clear));
    expectEqual(clear.rip, std::uint64_t{0x7FF80004F17CULL},
                "JG did not take with ZF clear and SF equal to OF");

    rosa::x86::X86State both;
    both.rflags = 0x882;
    static_cast<void>(block.execute(both));
    expectEqual(both.rip, std::uint64_t{0x7FF80004F17CULL},
                "JG did not take with SF and OF both set");

    rosa::x86::X86State zero;
    zero.rflags = 0x42;
    static_cast<void>(block.execute(zero));
    expectEqual(zero.rip, std::uint64_t{0x7FF80004F159ULL}, "JG took with ZF set");
    expectEqual(zero.rflags, std::uint64_t{0x42}, "JG changed flags on fallthrough");

    rosa::x86::X86State mismatch;
    mismatch.rflags = 0x82;
    static_cast<void>(block.execute(mismatch));
    expectEqual(mismatch.rip, std::uint64_t{0x7FF80004F159ULL},
                "JG took with SF different from OF");
    expectEqual(mismatch.rflags, std::uint64_t{0x82}, "JG changed flags on signed fallthrough");

    constexpr std::array<std::uint8_t, 6> nearCode{0x0F, 0x8F, 0xBF, 0x01, 0x00, 0x00};
    const auto nearDecoded =
        decoder.decodeBlock(nearCode, rosa::guest::GuestAddress{0x7FF80004F593ULL});
    expect(nearDecoded[0].condition == rosa::x86::Condition::Greater &&
               nearDecoded[0].branchTarget &&
               nearDecoded[0].branchTarget->value == 0x7FF80004F758ULL &&
               nearDecoded[0].fallthrough && nearDecoded[0].fallthrough->value == 0x7FF80004F599ULL,
           "JG rel32 target or fallthrough differs");
    const auto nearBlock =
        translator.translate(nearCode, rosa::guest::GuestAddress{0x7FF80004F593ULL});
    rosa::x86::X86State observedNotTaken;
    observedNotTaken.rflags = 0x46;
    static_cast<void>(nearBlock.execute(observedNotTaken));
    expectEqual(observedNotTaken.rip, std::uint64_t{0x7FF80004F599ULL},
                "JG rel32 took with ZF set");
}

void testSignedGreaterOrEqualConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x7D, 0xE1};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF80004F16CULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::JccRelative &&
               decoded[0].condition == rosa::x86::Condition::GreaterOrEqual,
           "JGE rel8 condition differs");
    expect(decoded[0].branchTarget && decoded[0].branchTarget->value == 0x7FF80004F14FULL,
           "JGE negative rel8 target differs");
    expect(rosa::debug::dumpX86(decoded).find("jge 0x7ff80004f14f") != std::string::npos,
           "JGE rel8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF80004F16CULL});

    rosa::x86::X86State clear;
    clear.rflags = 0x2;
    static_cast<void>(block.execute(clear));
    expectEqual(clear.rip, std::uint64_t{0x7FF80004F14FULL},
                "JGE did not take with SF and OF clear");

    rosa::x86::X86State both;
    both.rflags = 0x882;
    static_cast<void>(block.execute(both));
    expectEqual(both.rip, std::uint64_t{0x7FF80004F14FULL}, "JGE did not take with SF and OF set");

    rosa::x86::X86State signOnly;
    signOnly.rflags = 0x82;
    static_cast<void>(block.execute(signOnly));
    expectEqual(signOnly.rip, std::uint64_t{0x7FF80004F16EULL},
                "JGE took with SF set and OF clear");
    expectEqual(signOnly.rflags, std::uint64_t{0x82}, "JGE changed flags on fallthrough");

    rosa::x86::X86State overflowOnly;
    overflowOnly.rflags = 0x802;
    static_cast<void>(block.execute(overflowOnly));
    expectEqual(overflowOnly.rip, std::uint64_t{0x7FF80004F16EULL},
                "JGE took with SF clear and OF set");
}

void testSignedLessOrEqualConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x7E, 0x02}; // jle 0x1004
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::LessOrEqual, "JLE rel8 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State equal;
    equal.rflags = 0x42;
    static_cast<void>(block.execute(equal));
    expectEqual(equal.rip, std::uint64_t{0x1004}, "JLE did not take with ZF set");

    rosa::x86::X86State less;
    less.rflags = 0x82;
    static_cast<void>(block.execute(less));
    expectEqual(less.rip, std::uint64_t{0x1004}, "JLE did not take with SF different from OF");

    rosa::x86::X86State greater;
    greater.rflags = 0x2;
    static_cast<void>(block.execute(greater));
    expectEqual(greater.rip, std::uint64_t{0x1002}, "JLE took with ZF clear and SF equal to OF");
    expectEqual(greater.rflags, std::uint64_t{0x2}, "JLE changed flags");

    constexpr std::array<std::uint8_t, 6> nearCode{0x0F, 0x8E, 0x83, 0x00, 0x00, 0x00};
    constexpr rosa::guest::GuestAddress nearRip{0x7FF802B08EDEULL};
    const auto nearDecoded = decoder.decodeBlock(nearCode, nearRip);
    expect(nearDecoded[0].condition == rosa::x86::Condition::LessOrEqual &&
               nearDecoded[0].branchTarget &&
               nearDecoded[0].branchTarget->value == 0x7FF802B08F67ULL &&
               nearDecoded[0].fallthrough && nearDecoded[0].fallthrough->value == 0x7FF802B08EE4ULL,
           "JLE rel32 target or fallthrough differs");
    const auto nearBlock = translator.translate(nearCode, nearRip);
    equal.rflags = 0x42;
    static_cast<void>(nearBlock.execute(equal));
    expectEqual(equal.rip, std::uint64_t{0x7FF802B08F67ULL}, "JLE rel32 did not take with ZF set");
    greater.rflags = 0x2;
    static_cast<void>(nearBlock.execute(greater));
    expectEqual(greater.rip, std::uint64_t{0x7FF802B08EE4ULL},
                "JLE rel32 took with ZF clear and SF equal to OF");
}

void testSignLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x88, 0x02, 0, 0, 0};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::Sign, "JS rel32 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x82;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1008}, "JS did not take with SF set");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1006}, "JS took with SF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x2}, "JS changed flags");
}

void testOverflowLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x80, 0xD2, 0x01, 0x00, 0x00};
    constexpr rosa::guest::GuestAddress rip{0x7FF802C8E12EULL};
    constexpr std::uint64_t overflowFlag = std::uint64_t{1} << 11U;
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::JccRelative &&
               decoded[0].condition == rosa::x86::Condition::Overflow,
           "JO rel32 opcode or condition differs");
    expectEqual(decoded[0].branchTarget->value, std::uint64_t{0x7FF802C8E306ULL},
                "JO rel32 target differs");
    expectEqual(decoded[0].fallthrough->value, std::uint64_t{0x7FF802C8E134ULL},
                "JO rel32 fallthrough differs");
    expect(rosa::debug::dumpX86(decoded).find("jo 0x7ff802c8e306") != std::string::npos,
           "JO rel32 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State taken;
    taken.rflags = 0x2 | overflowFlag;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x7FF802C8E306ULL}, "JO rel32 did not take with OF set");
    expectEqual(taken.rflags, std::uint64_t{0x2 | overflowFlag}, "taken JO rel32 changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0xAD7 & ~overflowFlag;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x7FF802C8E134ULL}, "JO rel32 took with OF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0xAD7 & ~overflowFlag},
                "untaken JO rel32 changed flags");
}

void testSignShortConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x78, 0x02};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::Sign, "JS rel8 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x82;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1004}, "short JS did not take with SF set");
    expectEqual(taken.rflags, std::uint64_t{0x82}, "taken short JS changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1002}, "short JS took with SF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x2}, "not-taken short JS changed flags");
}

void testCsHintedShortConditionals() {
    constexpr std::array<std::uint8_t, 3> equalCode{0x2E, 0x74, 0x72};
    constexpr rosa::guest::GuestAddress equalAddress{0x7FF802A1C083ULL};
    const rosa::x86::Decoder decoder;
    const auto equalDecoded = decoder.decodeBlock(equalCode, equalAddress);
    expect(equalDecoded[0].opcode == rosa::x86::Opcode::JccRelative &&
               equalDecoded[0].condition == rosa::x86::Condition::Equal,
           "CS-hinted JE opcode or condition differs");
    expectEqual(equalDecoded[0].length, std::uint8_t{3}, "CS-hinted JE length differs");
    expectEqual(equalDecoded[0].branchTarget->value, std::uint64_t{0x7FF802A1C0F8ULL},
                "CS-hinted JE target differs");
    expectEqual(equalDecoded[0].fallthrough->value, std::uint64_t{0x7FF802A1C086ULL},
                "CS-hinted JE fallthrough differs");
    expect(rosa::debug::dumpX86(equalDecoded).find("je 0x7ff802a1c0f8") != std::string::npos,
           "CS-hinted JE dump differs");

    const rosa::dbt::Translator translator;
    const auto equalBlock = translator.translate(equalCode, equalAddress);
    rosa::x86::X86State taken;
    taken.rflags = 0x2 | (1U << 6U);
    static_cast<void>(equalBlock.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x7FF802A1C0F8ULL},
                "CS-hinted JE did not take with ZF set");
    expectEqual(taken.rflags, std::uint64_t{0x42}, "CS-hinted JE changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(equalBlock.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x7FF802A1C086ULL}, "CS-hinted JE took with ZF clear");

    constexpr std::array<std::uint8_t, 3> notEqualCode{0x2E, 0x75, 0x76};
    constexpr rosa::guest::GuestAddress notEqualAddress{0x2000};
    const auto notEqualDecoded = decoder.decodeBlock(notEqualCode, notEqualAddress);
    expect(notEqualDecoded[0].opcode == rosa::x86::Opcode::JccRelative &&
               notEqualDecoded[0].condition == rosa::x86::Condition::NotEqual &&
               notEqualDecoded[0].length == 3,
           "CS-hinted JNE decode differs");
    const auto notEqualBlock = translator.translate(notEqualCode, notEqualAddress);
    rosa::x86::X86State notEqualTaken;
    notEqualTaken.rflags = 0x2;
    static_cast<void>(notEqualBlock.execute(notEqualTaken));
    expectEqual(notEqualTaken.rip, std::uint64_t{0x2079}, "CS-hinted JNE target differs");
}

void testNotSignShortConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x79, 0x02};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::NotSign, "JNS rel8 condition differs");
    expect(rosa::debug::dumpX86(decoded).find("jns 0x1004") != std::string::npos,
           "JNS dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x2;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1004}, "JNS did not take with SF clear");
    expectEqual(taken.rflags, std::uint64_t{0x2}, "taken JNS changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x82;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1002}, "JNS took with SF set");
    expectEqual(notTaken.rflags, std::uint64_t{0x82}, "not-taken JNS changed flags");

    constexpr std::array<std::uint8_t, 6> nearCode{0x0F, 0x89, 0x53, 0x02, 0x00, 0x00};
    constexpr rosa::guest::GuestAddress nearRip{0x7FF802B087CDULL};
    const auto nearDecoded = decoder.decodeBlock(nearCode, nearRip);
    expect(nearDecoded[0].condition == rosa::x86::Condition::NotSign &&
               nearDecoded[0].branchTarget &&
               nearDecoded[0].branchTarget->value == 0x7FF802B08A26ULL &&
               nearDecoded[0].fallthrough && nearDecoded[0].fallthrough->value == 0x7FF802B087D3ULL,
           "JNS rel32 target or fallthrough differs");
    const auto nearBlock = translator.translate(nearCode, nearRip);
    taken.rflags = 0x2;
    static_cast<void>(nearBlock.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x7FF802B08A26ULL},
                "JNS rel32 did not take with SF clear");
    notTaken.rflags = 0x82;
    static_cast<void>(nearBlock.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x7FF802B087D3ULL}, "JNS rel32 took with SF set");
}

void testUnsignedAboveOrEqualShortConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x73, 0x02};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::AboveOrEqual,
           "JAE rel8 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x2;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1004}, "short JAE did not take with CF clear");
    expectEqual(taken.rflags, std::uint64_t{0x2}, "taken short JAE changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x3;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1002}, "short JAE took with CF set");
    expectEqual(notTaken.rflags, std::uint64_t{0x3}, "not-taken short JAE changed flags");
}

} // namespace

std::span<const TestCase> conditionsTests() {
    static const TestCase cases[]{
        {"set overflow low-byte register", testSetOverflowLowByteRegister},
        {"set below low-byte register", testSetBelowLowByteRegister},
        {"set greater-or-equal low-byte register", testSetGreaterOrEqualLowByteRegister},
        {"set above low-byte register", testSetAboveLowByteRegister},
        {"set equal RIP-relative guest byte", testSetEqualRipRelativeGuestByte},
        {"set equal SIB guest byte", testSetEqualSibGuestByte},
        {"set equal low-byte register", testSetEqualLowByteRegister},
        {"set not-equal low-byte register", testSetNotEqualLowByteRegister},
        {"set not-sign low-byte register", testSetNotSignLowByteRegister},
        {"set below-or-equal low-byte register", testSetBelowOrEqualLowByteRegister},
        {"set less low-byte register", testSetLessLowByteRegister},
        {"set greater extended low-byte register", testSetGreaterExtendedLowByteRegister},
        {"set above-or-equal guest byte", testSetAboveOrEqualGuestByte},
        {"conditional move below 64-bit", testConditionalMoveBelow64},
        {"conditional move not-equal 32-bit from guest memory", testConditionalMoveNotEqual32FromGuestMemory},
        {"conditional move below 32-bit", testConditionalMoveBelow32},
        {"conditional move above-or-equal 64-bit", testConditionalMoveAboveOrEqual64},
        {"conditional move above-or-equal 32-bit", testConditionalMoveAboveOrEqual32},
        {"conditional move above 64-bit", testConditionalMoveAbove64},
        {"conditional move below-or-equal 32-bit", testConditionalMoveBelowOrEqual32},
        {"conditional move equal 64-bit", testConditionalMoveEqual64},
        {"conditional move equal 64-bit from guest memory", testConditionalMoveEqual64FromGuestMemory},
        {"conditional move not-equal extended 64-bit", testConditionalMoveNotEqual64Extended},
        {"conditional move not-equal legacy 32-bit", testConditionalMoveNotEqual32Legacy},
        {"conditional move sign 64-bit", testConditionalMoveSign64},
        {"conditional move less-or-equal 64-bit", testConditionalMoveLessOrEqual64},
        {"conditional move greater-or-equal 32-bit", testConditionalMoveGreaterOrEqual32},
        {"conditional move less and overflow 64-bit", testConditionalMoveLessAndOverflow64},
        {"conditional move greater 64-bit", testConditionalMoveGreater64},
        {"conditional move greater 32-bit legacy", testConditionalMoveGreater32Legacy},
        {"conditional move equal extended 32-bit", testConditionalMoveEqual32Extended},
        {"unsigned-above conditional", testUnsignedAboveConditional},
        {"unsigned-above long conditional", testUnsignedAboveLongConditional},
        {"unsigned-above-or-equal long conditional", testUnsignedAboveOrEqualLongConditional},
        {"unsigned-below-or-equal conditional", testUnsignedBelowOrEqualConditional},
        {"unsigned-below-or-equal long conditional", testUnsignedBelowOrEqualLongConditional},
        {"signed-less conditional", testSignedLessConditional},
        {"signed-greater conditional", testSignedGreaterConditional},
        {"signed-greater-or-equal conditional", testSignedGreaterOrEqualConditional},
        {"signed-less-or-equal conditional", testSignedLessOrEqualConditional},
        {"sign long conditional", testSignLongConditional},
        {"overflow long conditional", testOverflowLongConditional},
        {"sign short conditional", testSignShortConditional},
        {"CS-hinted short conditionals", testCsHintedShortConditionals},
        {"not-sign short conditional", testNotSignShortConditional},
        {"unsigned-above-or-equal short conditional", testUnsignedAboveOrEqualShortConditional},
    };
    return cases;
}

} // namespace rosa::tests
