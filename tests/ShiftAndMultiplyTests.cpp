#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testTestRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x85, 0xC9, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegReg, "TEST r64, r64 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rcx,
           "TEST r64, r64 left operand differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State zeroState;
    zeroState.rcx = 0;
    zeroState.rflags = UINT64_MAX;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rcx, std::uint64_t{0}, "TEST changed its guest register operand");
    constexpr auto expectedZeroFlags = (UINT64_MAX & ~std::uint64_t{0x8D5}) | std::uint64_t{0x46};
    expectEqual(zeroState.rflags, expectedZeroFlags, "TEST zero-result flags differ");

    rosa::x86::X86State signState;
    signState.rcx = 0x8000000000000001ULL;
    static_cast<void>(block.execute(signState));
    expectEqual(signState.rcx, std::uint64_t{0x8000000000000001ULL},
                "TEST changed a nonzero guest register operand");
    expectEqual(signState.rflags, std::uint64_t{0x82}, "TEST sign-result flags differ");
}

void testTest16BitRegistersGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x45, 0x85, 0xF6, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegReg, "TEST r16, r16 opcode differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto rhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(lhs.reg == rosa::x86::Register::R14 && lhs.width == 16 &&
               rhs.reg == rosa::x86::Register::R14 && rhs.width == 16,
           "TEST r14w operands differ");
    expect(rosa::debug::dumpX86(decoded).find("test r14w, r14w") != std::string::npos,
           "TEST r14w dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0xA5A5A5A500000000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0xA5A5A5A500000000ULL}, "TEST r16 changed its operand");
    expectEqual(state.rflags, std::uint64_t{0x46}, "TEST r16 zero flags differ");

    state.r14 = 0x1122334455668000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0x1122334455668000ULL},
                "TEST r16 sign case changed its operand");
    expectEqual(state.rflags, std::uint64_t{0x86}, "TEST r16 sign flags differ");
}

void testTest32BitRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x45, 0x85, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegReg, "TEST r32, r32 opcode differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::R8, "TEST r32, r32 extended register differs");
    expectEqual(operand.width, std::uint8_t{32}, "TEST r32, r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r8 = 0xFFFFFFFF80000000ULL;
    state.rflags = UINT64_MAX;
    static_cast<void>(block.execute(state));
    expectEqual(state.r8, std::uint64_t{0xFFFFFFFF80000000ULL},
                "TEST r32, r32 changed its guest operand");
    constexpr auto expectedFlags = (UINT64_MAX & ~std::uint64_t{0x8D5}) | std::uint64_t{0x86};
    expectEqual(state.rflags, expectedFlags, "TEST r32, r32 flags differ");
}

void testLegacyTest32BitRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x85, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegReg,
           "legacy TEST r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "legacy TEST r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xFFFFFFFF00000000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFFFFFFF00000000ULL}, "legacy TEST changed EAX");
    expectEqual(state.rflags, std::uint64_t{0x46}, "legacy TEST flags differ");
}

void testLegacyTestLowByteGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x84, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestReg8Reg8,
           "legacy TEST r8, r8 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width, std::uint8_t{8},
                "legacy TEST r8 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0xFFFFFFFFFFFFFF00ULL;
    zeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0xFFFFFFFFFFFFFF00ULL}, "TEST al, al changed RAX");
    expectEqual(zeroState.rflags, std::uint64_t{0x46}, "TEST zero AL flags differ");

    rosa::x86::X86State signState;
    signState.rax = 0x80;
    static_cast<void>(block.execute(signState));
    expectEqual(signState.rflags, std::uint64_t{0x82}, "TEST signed AL flags differ");

    constexpr std::array<std::uint8_t, 4> extendedCode{0x45, 0x84, 0xF6, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x2000});
    const auto extendedLhs = std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedRhs = std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]);
    expect(extendedLhs.reg == rosa::x86::Register::R14 && extendedLhs.width == 8 &&
               extendedRhs.reg == rosa::x86::Register::R14 && extendedRhs.width == 8,
           "TEST R14B, R14B operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("test r14b, r14b") != std::string::npos,
           "TEST R14B dump differs");
    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State extendedState;
    extendedState.r14 = 0x1122334455667780ULL;
    extendedState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.r14, std::uint64_t{0x1122334455667780ULL}, "TEST R14B changed R14");
    expectEqual(extendedState.rflags, std::uint64_t{0x82}, "TEST R14B flags differ");
}

void testTestGuestByteRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x84, 0x09, 0xC3};
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeBase);
    expect(decoded[0].opcode == rosa::x86::Opcode::TestMemReg,
           "TEST byte [rcx], cl opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto reg = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rcx && memory.hasBase && !memory.ripRelative &&
               memory.displacement == 0 && memory.width == 8,
           "TEST byte [rcx], cl memory operand differs");
    expect(reg.reg == rosa::x86::Register::Rcx && reg.width == 8,
           "TEST byte [rcx], cl register operand differs");
    expect(rosa::debug::dumpX86(decoded).find("test byte [rcx], cl") != std::string::npos,
           "TEST byte [rcx], cl dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8181};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 1>{0x80});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeBase);
    rosa::x86::X86State state;
    state.rcx = target.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, target.value, "TEST byte [rcx], cl changed RCX");
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0x80},
                "TEST byte [rcx], cl changed memory");
    expectEqual(state.rflags, std::uint64_t{0x82}, "TEST byte [rcx], cl flags differ");

    rosa::x86::X86State faultState;
    faultState.rcx = 0xA181;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected =
            std::string_view(error.what()).find("unmapped") != std::string_view::npos ||
            std::string_view(error.what()).find("outside guest mapping") != std::string_view::npos;
    }
    expect(rejected, "TEST byte [rcx], cl accepted unmapped memory");
    expectEqual(faultState.rcx, std::uint64_t{0xA181}, "faulted TEST byte [rcx], cl changed RCX");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted TEST byte [rcx], cl changed flags");
}

void testTestGuestDwordRegisterWithScaledIndex() {
    constexpr std::array<std::uint8_t, 6> code{0x41, 0x85, 0x74, 0x95, 0x2C, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C6C8ABULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::TestMemReg,
           "TEST dword [R13+RDX*4+0x2c], ESI opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5},
                "TEST dword [R13+RDX*4+0x2c], ESI length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto reg = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R13 && memory.index == rosa::x86::Register::Rdx &&
               memory.scale == 4 && memory.displacement == 0x2C && memory.width == 32 &&
               reg.reg == rosa::x86::Register::Rsi && reg.width == 32,
           "TEST dword [R13+RDX*4+0x2c], ESI operands differ");
    expect(rosa::debug::dumpX86(decoded).find("test dword [r13+rdx*4+0x2c], esi") !=
               std::string::npos,
           "TEST dword [R13+RDX*4+0x2c], ESI dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x804C};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 4> value{0x00, 0x00, 0x20, 0x00};
    addressSpace.writeBytes(target, value);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.r13 = memoryBase.value;
    state.rdx = 8;
    state.rsi = 0x200000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r13, memoryBase.value, "TEST indexed dword changed R13");
    expectEqual(state.rdx, std::uint64_t{8}, "TEST indexed dword changed RDX");
    expectEqual(state.rsi, std::uint64_t{0x200000}, "TEST indexed dword changed RSI");
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x200000},
                "TEST indexed dword changed memory");
    expectEqual(state.rflags, std::uint64_t{0x6}, "TEST indexed dword flags differ");

    rosa::x86::X86State faultState;
    faultState.r13 = memoryBase.value + 3;
    faultState.rdx = 0x3F4;
    faultState.rsi = 0x200000;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page TEST indexed dword did not fault");
    expectEqual(faultState.r13, memoryBase.value + 3, "faulted TEST indexed dword changed R13");
    expectEqual(faultState.rdx, std::uint64_t{0x3F4}, "faulted TEST indexed dword changed RDX");
    expectEqual(faultState.rsi, std::uint64_t{0x200000}, "faulted TEST indexed dword changed RSI");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted TEST indexed dword changed flags");
}

void testTestAccumulatorImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0xA8, 0x03, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegImm, "TEST AL, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width, std::uint8_t{8},
                "TEST AL, imm8 register width differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{3}, "TEST AL, imm8 immediate differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xABCDEF1234567806ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xABCDEF1234567806ULL}, "TEST AL, imm8 changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x2}, "TEST AL, imm8 flags differ");

    constexpr std::array<std::uint8_t, 6> observedCode{0xA9, 0x00, 0x00, 0x00, 0x22, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802E6F7D3ULL};
    const auto observed = decoder.decodeBlock(observedCode, observedRip);
    expect(observed[0].opcode == rosa::x86::Opcode::TestRegImm, "TEST EAX, imm32 opcode differs");
    expectEqual(observed[0].length, std::uint8_t{5}, "TEST EAX, imm32 length differs");
    const auto observedRegister = std::get<rosa::x86::RegisterOperand>(observed[0].operands[0]);
    const auto observedImmediate = std::get<rosa::x86::ImmediateOperand>(observed[0].operands[1]);
    expect(observedRegister.reg == rosa::x86::Register::Rax && observedRegister.width == 32 &&
               observedImmediate.value == 0x22000000 && observedImmediate.width == 32,
           "TEST EAX, 0x22000000 operands differ");
    expect(rosa::debug::dumpX86(observed).find("test eax, 0x22000000") != std::string::npos,
           "TEST EAX, imm32 dump differs");

    const auto observedBlock = translator.translate(observedCode, observedRip);
    rosa::x86::X86State nonzeroState;
    nonzeroState.rax = 0xDEADBEEF22000000ULL;
    nonzeroState.rflags = 0x8D7;
    static_cast<void>(observedBlock.execute(nonzeroState));
    expectEqual(nonzeroState.rax, std::uint64_t{0xDEADBEEF22000000ULL},
                "TEST EAX, imm32 changed RAX");
    expectEqual(nonzeroState.rflags, std::uint64_t{0x6}, "TEST EAX, imm32 nonzero flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0xFFFFFFFF00000000ULL;
    zeroState.rflags = 0x8D7;
    static_cast<void>(observedBlock.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0xFFFFFFFF00000000ULL},
                "TEST EAX, imm32 changed upper RAX bits");
    expectEqual(zeroState.rflags, std::uint64_t{0x46}, "TEST EAX, imm32 zero flags differ");
}

void testTestRegisterImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 8> code{0x48, 0xF7, 0xC7, 0x0F, 0x00, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF700002BCAULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegImm, "TEST r64, imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "TEST r64, imm32 length differs");
    const auto reg = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(reg.reg == rosa::x86::Register::Rdi && reg.width == 64 && immediate.value == 0x0F &&
               immediate.width == 32,
           "TEST rdi, 0xf operands differ");
    expect(rosa::debug::dumpX86(decoded).find("test rdi, 0xf") != std::string::npos,
           "TEST rdi, 0xf dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rdi = 0x100002990ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x100002990ULL}, "TEST rdi, imm32 changed RDI");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "TEST rdi, imm32 defined flags differ");

    constexpr std::array<std::uint8_t, 8> signExtendedCode{0x48, 0xF7, 0xC7, 0x00,
                                                           0x00, 0x00, 0x80, 0xC3};
    const auto signDecoded =
        decoder.decodeBlock(signExtendedCode, rosa::guest::GuestAddress{0x2000});
    const auto signImmediate = std::get<rosa::x86::ImmediateOperand>(signDecoded[0].operands[1]);
    expectEqual(signImmediate.value, std::uint64_t{0xFFFFFFFF80000000ULL},
                "TEST r64 immediate was not sign-extended");
    const auto signBlock =
        translator.translate(signExtendedCode, rosa::guest::GuestAddress{0x2000});
    state.rdi = 0x8000000000000000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(signBlock.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x8000000000000000ULL}, "sign-extended TEST changed RDI");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 7U)},
                "sign-extended TEST defined flags differ");
}

void testTestLowByteRegisterImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0xF6, 0xC2, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegImm, "TEST DL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "TEST DL, imm8 length differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rdx && operand.width == 8,
           "TEST DL, imm8 register differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{1}, "TEST DL, imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("test dl, 0x1") != std::string::npos,
           "TEST DL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0x1122334455667782ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0x1122334455667782ULL}, "TEST DL, imm8 changed RDX");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "TEST DL, imm8 zero-result flags differ");

    constexpr std::array<std::uint8_t, 4> signCode{0xF6, 0xC2, 0x80, 0xC3};
    const auto signBlock = translator.translate(signCode, rosa::guest::GuestAddress{0x2000});
    state.rdx = 0x80;
    state.rflags = 0x8D7;
    static_cast<void>(signBlock.execute(state));
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "TEST DL, imm8 sign-result flags differ");

    constexpr std::array<std::uint8_t, 5> extendedCode{0x41, 0xF6, 0xC6, 0x02, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x3000});
    expectEqual(extendedDecoded[0].length, std::uint8_t{4}, "TEST r14b, imm8 length differs");
    const auto extendedOperand =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    expect(extendedOperand.reg == rosa::x86::Register::R14 && extendedOperand.width == 8,
           "TEST r14b, imm8 register differs");
    expect(rosa::debug::dumpX86(extendedDecoded).find("test r14b, 0x2") != std::string::npos,
           "TEST r14b, imm8 dump differs");
    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State extendedState;
    extendedState.r14 = 0x8877665544332202ULL;
    extendedState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.r14, std::uint64_t{0x8877665544332202ULL},
                "TEST r14b, imm8 changed R14");
    expectEqual(extendedState.rflags & definedLogicFlags, std::uint64_t{0},
                "TEST r14b, imm8 defined flags differ");

    constexpr std::array<std::uint8_t, 4> highByteCode{0xF6, 0xE6, 0x01, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x4000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "TEST DH, imm8 was silently treated as a low-byte register form");
}

void testTestGuestByteImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x41, 0xF6, 0x46, 0x08, 0x01, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF8000598AAULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::TestMemImm,
           "TEST byte [memory], imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "TEST byte [memory], imm8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R14 && memory.hasBase && !memory.ripRelative &&
               !memory.index && memory.displacement == 8 && memory.width == 8,
           "TEST byte [r14+8] memory operand differs");
    expect(immediate.value == 1 && immediate.width == 8, "TEST byte [r14+8] immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("test byte [r14+0x8], 0x1") != std::string::npos,
           "TEST byte [r14+8] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    std::array<std::uint8_t, rosa::guest::guestPageSize> bytes{};
    bytes[8] = 1;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(page, bytes.size(), rosa::guest::Permission::Read, bytes,
                            "read-only TEST byte");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    rosa::x86::X86State state;
    state.rax = 0x1122334455667788ULL;
    state.r14 = page.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0},
                "TEST byte nonzero-result defined flags differ");
    expectEqual(state.rax, std::uint64_t{0x1122334455667788ULL},
                "TEST byte changed an unrelated register");
    expectEqual(state.r14, page.value, "TEST byte changed its base register");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{page.value + 8}, 1).front(),
                std::uint8_t{1}, "TEST byte changed guest memory");

    bytes[8] = 0;
    rosa::guest::AddressSpace zeroAddressSpace;
    zeroAddressSpace.mapSegment(page, bytes.size(), rosa::guest::Permission::Read, bytes,
                                "zero TEST byte");
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &zeroAddressSpace));
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "TEST byte zero-result defined flags differ");

    constexpr std::array<std::uint8_t, 6> signCode{0x41, 0xF6, 0x46, 0x08, 0x80, 0xC3};
    bytes[8] = 0x80;
    rosa::guest::AddressSpace signAddressSpace;
    signAddressSpace.mapSegment(page, bytes.size(), rosa::guest::Permission::Read, bytes,
                                "sign TEST byte");
    const auto signBlock = translator.translate(signCode, codeAddress);
    state.rflags = 0x8D7;
    static_cast<void>(signBlock.execute(state, &signAddressSpace));
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "TEST byte sign-result defined flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0xAABBCCDDEEFF0011ULL;
    faultState.r14 = page.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "TEST byte accepted unmapped guest memory");
    expectEqual(faultState.rax, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "faulted TEST byte changed a register");
    expectEqual(faultState.r14, page.value, "faulted TEST byte changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted TEST byte changed flags");

    rosa::guest::AddressSpace inaccessibleAddressSpace;
    inaccessibleAddressSpace.mapSegment(page, bytes.size(), rosa::guest::Permission::None, bytes,
                                        "inaccessible TEST byte");
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &inaccessibleAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "TEST byte accepted non-readable guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7},
                "permission-faulted TEST byte changed flags");
}

void testDwordMemoryImmediateGeneratedExecution() {
    // Observed in libsqlite3: TEST dword [rbp-0xa0], 0x10000 (opcode F7 /0).
    constexpr std::array<std::uint8_t, 11> code{0xF7, 0x85, 0x60, 0xFF, 0xFF, 0xFF,
                                                0x00, 0x00, 0x01, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x1000C3448ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::TestMemImm,
           "TEST dword [memory], imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{10}, "TEST dword [memory], imm32 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbp && memory.hasBase && !memory.ripRelative &&
               !memory.index && memory.displacement == -160 && memory.width == 32,
           "TEST dword [rbp-0xa0] memory operand differs");
    expect(immediate.value == 0x10000 && immediate.width == 32,
           "TEST dword [rbp-0xa0] immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("test dword [rbp-0xa0], 0x10000") !=
               std::string::npos,
           "TEST dword [rbp-0xa0] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 0x10000);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    rosa::x86::X86State state;
    state.rax = 0x1122334455667788ULL;
    state.rbp = target.value + 160;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "TEST dword nonzero-result defined flags differ");
    expectEqual(state.rax, std::uint64_t{0x1122334455667788ULL},
                "TEST dword changed an unrelated register");
    expectEqual(state.rbp, target.value + 160, "TEST dword changed its base register");
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x10000},
                "TEST dword changed guest memory");

    addressSpace.writeU32(target, 0);
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "TEST dword zero-result defined flags differ");

    addressSpace.writeU32(target, 0x80000000);
    constexpr std::array<std::uint8_t, 11> signCode{0xF7, 0x85, 0x60, 0xFF, 0xFF, 0xFF,
                                                    0x00, 0x00, 0x00, 0x80, 0xC3};
    const auto signBlock = translator.translate(signCode, codeAddress);
    state.rflags = 0x8D7;
    static_cast<void>(signBlock.execute(state, &addressSpace));
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 7U)},
                "TEST dword sign-result defined flags differ");
}

void testLfenceGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0xAE, 0xE8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Lfence, "LFENCE opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "LFENCE length differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x0123456789ABCDEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x0123456789ABCDEFULL}, "LFENCE changed a guest register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "LFENCE changed guest flags");
    expect(std::find(block.program().listing.begin(), block.program().listing.end(), "dmb ish") !=
               block.program().listing.end(),
           "LFENCE did not emit an ARM64 memory barrier");
    expect(std::find(block.program().listing.begin(), block.program().listing.end(), "isb") !=
                block.program().listing.end(),
            "LFENCE did not emit an ARM64 instruction barrier");
}

void testMfenceGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0xAE, 0xF0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000458C9ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::Mfence, "MFENCE opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "MFENCE length differs");
    expect(rosa::debug::dumpX86(decoded).find("mfence") != std::string::npos,
           "MFENCE dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000458C9ULL});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("store_fence") !=
               std::string::npos,
           "MFENCE did not lower through the store-fence IR");
    rosa::x86::X86State state;
    state.rax = 0x0123456789ABCDEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x0123456789ABCDEFULL}, "MFENCE changed a guest register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MFENCE changed guest flags");
    expect(std::find(block.program().listing.begin(), block.program().listing.end(), "dmb ish") !=
               block.program().listing.end(),
           "MFENCE did not emit an ARM64 memory barrier");
}

void testSidtGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x01, 0x4C, 0x24, 0xF0, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C82EA7ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::SidtMem, "SIDT opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "SIDT length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rsp && memory.hasBase && !memory.ripRelative &&
               !memory.index && memory.displacement == -0x10 && memory.width == 80,
           "SIDT stack operand differs");
    expect(rosa::debug::dumpX86(decoded).find("sidt [rsp-0x10]") != std::string::npos,
           "SIDT disassembly differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("store_guest_idtr") !=
               std::string::npos,
           "SIDT IR lacks the guest-IDTR store");

    constexpr rosa::guest::GuestAddress stackPage{0x7000000FC000ULL};
    constexpr rosa::guest::GuestAddress target{stackPage.value + 0x1E8};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "SIDT stack");
    constexpr std::array<std::uint8_t, 10> initial{0xA0, 0xA1, 0xA2, 0xA3, 0xA4,
                                                   0xA5, 0xA6, 0xA7, 0xA8, 0xA9};
    addressSpace.writeBytes(target, initial);
    rosa::x86::X86State state;
    state.rsp = target.value + 0x10;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    constexpr std::array<std::uint8_t, 10> expected{0xFF, 0x0F, 0x00, 0x00, 0x00,
                                                    0x00, 0x00, 0x00, 0x00, 0x00};
    expect(addressSpace.readBytes(target, expected.size()) ==
               std::vector<std::uint8_t>(expected.begin(), expected.end()),
           "SIDT synthetic guest descriptor differs");
    expectEqual(state.rsp, target.value + 0x10, "SIDT changed RSP");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "SIDT changed flags");

    constexpr std::array<std::uint8_t, 5> frameCode{0x0F, 0x01, 0x4D, 0xA0, 0xC3};
    constexpr rosa::guest::GuestAddress frameCodeAddress{0x7FF802C8DB4FULL};
    const auto frameDecoded = decoder.decodeBlock(frameCode, frameCodeAddress);
    expect(frameDecoded[0].opcode == rosa::x86::Opcode::SidtMem,
           "SIDT frame-pointer opcode differs");
    expectEqual(frameDecoded[0].length, std::uint8_t{4}, "SIDT frame-pointer length differs");
    const auto frameMemory = std::get<rosa::x86::MemoryOperand>(frameDecoded[0].operands[0]);
    expect(frameMemory.base == rosa::x86::Register::Rbp && frameMemory.hasBase &&
               !frameMemory.ripRelative && !frameMemory.index &&
               frameMemory.displacement == -0x60 && frameMemory.width == 80,
           "SIDT [rbp-0x60] operand differs");
    expect(rosa::debug::dumpX86(frameDecoded).find("sidt [rbp-0x60]") != std::string::npos,
           "SIDT frame-pointer disassembly differs");

    addressSpace.writeBytes(target, initial);
    const auto frameBlock = translator.translate(frameCode, frameCodeAddress);
    state.rbp = target.value + 0x60;
    state.rsp = 0x7000000FB4D0ULL;
    state.rflags = 0xAD7;
    static_cast<void>(frameBlock.execute(state, &addressSpace));
    expect(addressSpace.readBytes(target, expected.size()) ==
               std::vector<std::uint8_t>(expected.begin(), expected.end()),
           "SIDT frame-pointer synthetic descriptor differs");
    expectEqual(state.rbp, target.value + 0x60, "SIDT frame-pointer form changed RBP");
    expectEqual(state.rsp, std::uint64_t{0x7000000FB4D0ULL}, "SIDT frame-pointer form changed RSP");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "SIDT frame-pointer form changed flags");

    constexpr rosa::guest::GuestAddress faultPage{0x9000};
    constexpr rosa::guest::GuestAddress faultTarget{faultPage.value + rosa::guest::guestPageSize -
                                                    8};
    constexpr std::array<std::uint8_t, 8> sentinel{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87};
    rosa::guest::AddressSpace faultAddressSpace;
    faultAddressSpace.mapAnonymous(faultPage, rosa::guest::guestPageSize,
                                   rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                                   "cross-page SIDT stack");
    faultAddressSpace.writeBytes(faultTarget, sentinel);
    rosa::x86::X86State faultState;
    faultState.rsp = faultTarget.value + 0x10;
    faultState.rflags = 0xBD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &faultAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page SIDT did not fault");
    expect(faultAddressSpace.readBytes(faultTarget, sentinel.size()) ==
               std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
           "cross-page SIDT partially changed guest memory");
    expectEqual(faultState.rsp, faultTarget.value + 0x10, "faulted SIDT changed RSP");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "faulted SIDT changed flags");
}

void testMultiByteNopGeneratedExecution() {
    constexpr std::array<std::uint8_t, 2> singleByteCode{0x90, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto singleByteDecoded =
        decoder.decodeBlock(singleByteCode, rosa::guest::GuestAddress{0x7FF802C692A5ULL});
    expect(singleByteDecoded[0].opcode == rosa::x86::Opcode::Nop, "single-byte NOP opcode differs");
    expectEqual(singleByteDecoded[0].length, std::uint8_t{1}, "single-byte NOP length differs");
    expect(rosa::debug::dumpX86(singleByteDecoded).find("nop") != std::string::npos,
           "single-byte NOP dump differs");

    constexpr std::array<std::uint8_t, 3> operandSizeNopCode{0x66, 0x90, 0xC3};
    const auto operandSizeNopDecoded =
        decoder.decodeBlock(operandSizeNopCode, rosa::guest::GuestAddress{0x7FF802E812BEULL});
    expect(operandSizeNopDecoded[0].opcode == rosa::x86::Opcode::Nop &&
               operandSizeNopDecoded[0].length == 2,
           "operand-size-prefixed NOP differs");
    auto operandSizeNopBlock = rosa::dbt::Translator{}.translate(
        operandSizeNopCode, rosa::guest::GuestAddress{0x7FF802E812BEULL});
    rosa::x86::X86State operandSizeNopState;
    operandSizeNopState.rip = 0x7FF802E812BEULL;
    expect(operandSizeNopBlock.execute(operandSizeNopState) == rosa::dbt::BlockExit::Return,
           "operand-size-prefixed NOP block did not reach RET");

    constexpr std::array<std::uint8_t, 8> code{0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00, 0xC3};
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF700002C09ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::Nop, "multi-byte NOP opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "multi-byte NOP disp32 length differs");
    expect(rosa::debug::dumpX86(decoded).find("nop") != std::string::npos,
           "multi-byte NOP dump differs");

    constexpr std::array<std::uint8_t, 4> registerCode{0x0F, 0x1F, 0xC0, 0xC3};
    const auto registerDecoded =
        decoder.decodeBlock(registerCode, rosa::guest::GuestAddress{0x2000});
    expect(registerDecoded[0].opcode == rosa::x86::Opcode::Nop && registerDecoded[0].length == 3,
           "register-encoded multi-byte NOP differs");

    constexpr std::array<std::uint8_t, 6> sibCode{0x0F, 0x1F, 0x44, 0x00, 0x00, 0xC3};
    const auto sibDecoded = decoder.decodeBlock(sibCode, rosa::guest::GuestAddress{0x3000});
    expect(sibDecoded[0].opcode == rosa::x86::Opcode::Nop && sibDecoded[0].length == 5,
           "SIB disp8 multi-byte NOP length differs");

    constexpr std::array<std::uint8_t, 11> prefixedCode{0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00,
                                                        0x00, 0x00, 0x00, 0x00, 0xC3};
    const auto prefixedDecoded =
        decoder.decodeBlock(prefixedCode, rosa::guest::GuestAddress{0x7FF802A8CAC3ULL});
    expect(prefixedDecoded[0].opcode == rosa::x86::Opcode::Nop && prefixedDecoded[0].length == 10,
           "operand-size/CS-prefixed multi-byte NOP differs");

    constexpr std::array<std::uint8_t, 3> invalidExtension{0x0F, 0x1F, 0xC8};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(invalidExtension, rosa::guest::GuestAddress{0x4000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "multi-byte NOP accepted a nonzero ModRM extension");

    constexpr std::array<std::uint8_t, 5> truncated{0x0F, 0x1F, 0x80, 0x00, 0x00};
    rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(truncated, rosa::guest::GuestAddress{0x5000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "truncated multi-byte NOP was accepted");

    const rosa::dbt::Translator translator;
    const auto singleByteBlock =
        translator.translate(singleByteCode, rosa::guest::GuestAddress{0x7FF802C692A5ULL});
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF700002C09ULL});
    const auto prefixedBlock =
        translator.translate(prefixedCode, rosa::guest::GuestAddress{0x7FF802A8CAC3ULL});
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rbx = 0x0123456789ABCDEFULL;
    state.rflags = 0xAD7;
    static_cast<void>(singleByteBlock.execute(state));
    static_cast<void>(block.execute(state));
    static_cast<void>(prefixedBlock.execute(state));
    expectEqual(state.rax, UINT64_MAX, "multi-byte NOP evaluated its unmapped address");
    expectEqual(state.rbx, std::uint64_t{0x0123456789ABCDEFULL},
                "multi-byte NOP changed a guest register");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "multi-byte NOP changed guest flags");
}

void testRdtscGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x0F, 0x31, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Rdtsc, "RDTSC opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "RDTSC length differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rdx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, nullptr, &fixedTimestampCounter));
    expectEqual(state.rax, std::uint64_t{0xABCDEF01}, "RDTSC did not zero-extend EAX");
    expectEqual(state.rdx, std::uint64_t{0x12345678}, "RDTSC did not zero-extend EDX");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RDTSC changed guest flags");

    rosa::x86::X86State missingSourceState;
    missingSourceState.rax = 0x55;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(missingSourceState));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("timestamp-counter source") !=
                   std::string_view::npos;
    }
    expect(rejected, "RDTSC without a virtual counter source did not fail");
    expectEqual(missingSourceState.rax, std::uint64_t{0x55}, "failed RDTSC changed guest EAX");
}

void testShiftLeftImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0xC1, 0xE2, 0x20, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShlRegImm, "SHL r64, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{32}, "SHL r64, imm8 count differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0x0000000180000001ULL;
    state.rflags = 0x812;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0x8000000100000000ULL}, "SHL r64, 32 result differs");
    expectEqual(state.rflags, std::uint64_t{0x897}, "SHL r64, 32 flags differ");

    constexpr std::array<std::uint8_t, 5> zeroCount{0x48, 0xC1, 0xE2, 0x40, 0xC3};
    const auto zeroBlock = translator.translate(zeroCount, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State zeroState;
    zeroState.rdx = 0x55;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rdx, std::uint64_t{0x55},
                "SHL with a masked zero count changed the value");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHL with a masked zero count changed flags");

    constexpr std::array<std::uint8_t, 4> observedByteCode{0xC0, 0xE2, 0x05, 0xC3};
    constexpr rosa::guest::GuestAddress observedByteRip{0x7FF802AE164AULL};
    const auto observedByte = decoder.decodeBlock(observedByteCode, observedByteRip);
    expect(observedByte[0].opcode == rosa::x86::Opcode::ShlRegImm, "SHL r8, imm8 opcode differs");
    expectEqual(observedByte[0].length, std::uint8_t{3}, "SHL r8, imm8 length differs");
    const auto byteDestination = std::get<rosa::x86::RegisterOperand>(observedByte[0].operands[0]);
    expect(byteDestination.reg == rosa::x86::Register::Rdx && byteDestination.width == 8,
           "SHL dl, 5 destination differs");
    expect(rosa::debug::dumpX86(observedByte).find("shl dl, 0x5") != std::string::npos,
           "SHL dl, 5 dump differs");
    const auto observedByteBlock = translator.translate(observedByteCode, observedByteRip);
    rosa::x86::X86State byteState;
    byteState.rdx = 0x1122334455667787ULL;
    byteState.rflags = 0x812;
    static_cast<void>(observedByteBlock.execute(byteState));
    expectEqual(byteState.rdx, std::uint64_t{0x11223344556677E0ULL},
                "SHL dl, 5 result or upper-byte preservation differs");
    expectEqual(byteState.rflags, std::uint64_t{0x892}, "SHL dl, 5 flags differ");

    constexpr std::array<std::uint8_t, 4> code32{0xC1, 0xE2, 0x04, 0xC3};
    const auto decoded32 = decoder.decodeBlock(code32, rosa::guest::GuestAddress{0x3000});
    expect(decoded32[0].opcode == rosa::x86::Opcode::ShlRegImm, "SHL r32, imm8 opcode differs");
    const auto destination32 = std::get<rosa::x86::RegisterOperand>(decoded32[0].operands[0]);
    expect(destination32.reg == rosa::x86::Register::Rdx && destination32.width == 32,
           "SHL EDX, imm8 destination differs");
    expectEqual(decoded32[0].length, std::uint8_t{3}, "SHL EDX, imm8 length differs");
    expect(rosa::debug::dumpX86(decoded32).find("shl edx, 0x4") != std::string::npos,
           "SHL EDX, imm8 dump differs");
    const auto block32 = translator.translate(code32, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State state32;
    state32.rdx = 0xAAAAAAAA08000001ULL;
    state32.rflags = 0x8D7;
    static_cast<void>(block32.execute(state32));
    expectEqual(state32.rdx, std::uint64_t{0x80000010}, "SHL EDX, 4 result did not zero-extend");
    constexpr std::uint64_t definedManyFlags = (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state32.rflags & definedManyFlags, std::uint64_t{1U << 7U},
                "SHL EDX, 4 defined flags differ");

    constexpr std::array<std::uint8_t, 4> one32{0xC1, 0xE2, 0x01, 0xC3};
    const auto one32Block = translator.translate(one32, rosa::guest::GuestAddress{0x4000});
    state32.rdx = 0xFFFFFFFF40000000ULL;
    state32.rflags = 0;
    static_cast<void>(one32Block.execute(state32));
    expectEqual(state32.rdx, std::uint64_t{0x80000000}, "SHL EDX, 1 result differs");
    constexpr std::uint64_t definedOneFlags = definedManyFlags | (std::uint64_t{1} << 11U);
    expectEqual(state32.rflags & definedOneFlags,
                std::uint64_t{(1U << 2U) | (1U << 7U) | (1U << 11U)},
                "SHL EDX, 1 defined flags differ");

    constexpr std::array<std::uint8_t, 4> zero32{0xC1, 0xE2, 0x20, 0xC3};
    const auto zero32Block = translator.translate(zero32, rosa::guest::GuestAddress{0x5000});
    state32.rdx = 0xAAAAAAAA12345678ULL;
    state32.rflags = 0xAD7;
    static_cast<void>(zero32Block.execute(state32));
    expectEqual(state32.rdx, std::uint64_t{0x12345678},
                "SHL EDX masked-zero result did not zero-extend");
    expectEqual(state32.rflags, std::uint64_t{0xAD7}, "SHL EDX masked-zero count changed flags");
}

void testShiftLeft64GuestMemoryImmediate() {
    constexpr std::array<std::uint8_t, 6> code{0x48, 0xC1, 0x65, 0xC8, 0x03, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF700052BA8ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShlMemImm, "SHL qword memory opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rbp && memory.displacement == -0x38 &&
               memory.width == 64,
           "SHL qword memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("shl qword [rbp-0x38], 0x3") != std::string::npos,
           "SHL qword memory dump differs");

    constexpr rosa::guest::GuestAddress mappingBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x80C8};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(mappingBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x2000000000000001ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF700052BA8ULL});
    rosa::x86::X86State state;
    state.rbp = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{8}, "SHL qword memory result differs");
    constexpr std::uint64_t definedFlags = (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state.rflags & definedFlags, std::uint64_t{1},
                "SHL qword memory defined flags differ");
    expectEqual(state.rbp, std::uint64_t{0x8100}, "SHL qword memory changed its base register");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbp = 0x8100;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "SHL from unmapped guest memory did not fault");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed SHL guest load changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(mappingBase, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    readOnlyAddressSpace.writeU64(target, 0x2000000000000001ULL);
    expectEqual(readOnlyAddressSpace.protect(mappingBase, rosa::guest::guestPageSize,
                                             rosa::guest::Permission::Read),
                rosa::guest::ProtectResult::Success, "could not make SHL test memory read-only");
    faultState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "SHL to read-only guest memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(target), std::uint64_t{0x2000000000000001ULL},
                "failed SHL store changed guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed SHL guest store changed flags");
}

void testShiftRight32GuestMemoryImmediate() {
    // Observed in libsqlite3: SHR dword [rbp-0x98], 3 (opcode C1 /5).
    constexpr std::array<std::uint8_t, 8> code{0xC1, 0xAD, 0x68, 0xFF,
                                               0xFF, 0xFF, 0x03, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000C900EULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShrMemImm, "SHR dword memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "SHR dword memory length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto count = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbp && memory.displacement == -152 &&
               memory.width == 32 && count.value == 3,
           "SHR dword [rbp-0x98], 3 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("shr dword [rbp-0x98], 0x3") != std::string::npos,
           "SHR dword memory dump differs");

    constexpr rosa::guest::GuestAddress mappingBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(mappingBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 0x80000001U);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000C900EULL});
    rosa::x86::X86State state;
    state.rbp = target.value + 152;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x10000000U},
                "SHR dword memory result differs");
    constexpr std::uint64_t definedFlags = (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state.rflags & definedFlags, std::uint64_t{1U << 2U},
                "SHR dword memory defined flags differ");
    expectEqual(state.rbp, target.value + 152, "SHR dword memory changed its base register");

    addressSpace.writeU32(target, 0xFFFFFFFFU);
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x1FFFFFFFU},
                "SHR dword memory carry result differs");
    expectEqual(state.rflags & definedFlags, std::uint64_t{(1U << 0U) | (1U << 2U)},
                "SHR dword memory carry flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbp = target.value + 152;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "SHR from unmapped guest memory did not fault");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed SHR guest load changed flags");
}

void testShiftLeftClGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0xD3, 0xE0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShlRegCl, "SHL r64, CL opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "SHL r64, CL destination differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8000000000000001ULL;
    state.rcx = 65;
    state.rflags = 0x10;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{2}, "SHL r64, CL did not mask the count to six bits");
    expectEqual(state.rcx, std::uint64_t{65}, "SHL r64, CL changed RCX");
    expectEqual(state.rflags, std::uint64_t{0x813}, "SHL r64, CL flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0x55;
    zeroState.rcx = 64;
    zeroState.rflags = 0xAD7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x55},
                "SHL r64, CL with a masked zero count changed the value");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHL r64, CL with a masked zero count changed flags");
}

void testShiftLeft32ClGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0xD3, 0xE0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShlRegCl, "SHL r32, CL opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32,
           "SHL EAX, CL destination differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "SHL EAX, CL length differs");
    expect(rosa::debug::dumpX86(decoded).find("shl eax, cl") != std::string::npos,
           "SHL EAX, CL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xFFFFFFFF80000001ULL;
    state.rcx = 1;
    state.rflags = 0x10;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{2}, "SHL EAX, CL result did not zero-extend");
    expectEqual(state.rcx, std::uint64_t{1}, "SHL EAX, CL changed RCX");
    expectEqual(state.rflags, std::uint64_t{0x813}, "SHL EAX, CL count-one flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0xAAAAAAAA12345678ULL;
    zeroState.rcx = 32;
    zeroState.rflags = 0xAD7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x12345678},
                "SHL EAX, CL masked-zero result did not zero-extend");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHL EAX, CL masked-zero count changed flags");

    rosa::x86::X86State manyState;
    manyState.rax = 0xFFFFFFFF80000001ULL;
    manyState.rcx = 31;
    manyState.rflags = 0x810;
    static_cast<void>(block.execute(manyState));
    expectEqual(manyState.rax, std::uint64_t{0x80000000}, "SHL EAX, CL count-31 result differs");
    constexpr std::uint64_t definedManyFlags = (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(manyState.rflags & definedManyFlags, std::uint64_t{(1U << 2U) | (1U << 7U)},
                "SHL EAX, CL count-31 defined flags differ");
}

void testShiftLeft8ClGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x40, 0xD2, 0xE7, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF70004DB3CULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShlRegCl, "SHL r8, CL opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "SHL r8, CL length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rdi && destination.width == 8,
           "SHL DIL, CL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("shl dil, cl") != std::string::npos,
           "SHL DIL, CL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF70004DB3CULL});
    rosa::x86::X86State state;
    state.rdi = 0x1122334455667741ULL;
    state.rcx = 2;
    state.rflags = 0x810;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x1122334455667704ULL},
                "SHL DIL, CL result or upper-register preservation differs");
    expectEqual(state.rcx, std::uint64_t{2}, "SHL DIL, CL changed RCX");
    constexpr std::uint64_t definedManyFlags = (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state.rflags & definedManyFlags, std::uint64_t{1},
                "SHL DIL, CL count-two defined flags differ");

    state.rdi = 0x1122334455667781ULL;
    state.rcx = 1;
    state.rflags = 0x10;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x1122334455667702ULL},
                "SHL DIL, CL count-one result differs");
    constexpr std::uint64_t definedOneFlags = definedManyFlags | (1U << 11U);
    expectEqual(state.rflags & definedOneFlags, std::uint64_t{0x801},
                "SHL DIL, CL count-one defined flags differ");

    state.rdi = 0x11223344556677A5ULL;
    state.rcx = 0xABCDEF0000000020ULL;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x11223344556677A5ULL},
                "SHL DIL, CL masked-zero changed its destination");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "SHL DIL, CL masked-zero changed flags");

    state.rdi = 0x1122334455667781ULL;
    state.rcx = 8;
    state.rflags = 0x811;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x1122334455667700ULL},
                "SHL DIL, CL count-eight did not use byte width");
    constexpr std::uint64_t widthDefinedFlags = (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state.rflags & widthDefinedFlags, std::uint64_t{0x44},
                "SHL DIL, CL count-eight defined flags differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0xD2, 0xE7, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "SHL BH, CL was silently treated as a representable low byte");
}

void testShiftRight8ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0xC0, 0xE8, 0x03, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShrRegImm, "SHR r8, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "SHR r8, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R8 && destination.width == 8 &&
               immediate.width == 8 && immediate.value == 3,
           "SHR r8b, 3 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("shr r8b, 0x3") != std::string::npos,
           "SHR r8b, 3 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r8 = 0x1122334455667780ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r8, std::uint64_t{0x1122334455667710ULL},
                "SHR r8b allowed upper register bits into the byte result");
    constexpr std::uint64_t manyDefinedFlags = (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state.rflags & manyDefinedFlags, std::uint64_t{0},
                "SHR r8b count-3 defined flags differ");

    constexpr std::array<std::uint8_t, 5> countOne{0x41, 0xC0, 0xE8, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.r8 = 0x1122334455667781ULL;
    oneState.rflags = 0x10;
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.r8, std::uint64_t{0x1122334455667740ULL},
                "SHR r8b count-1 result differs");
    constexpr std::uint64_t oneDefinedFlags = manyDefinedFlags | (1U << 11U);
    expectEqual(oneState.rflags & oneDefinedFlags, std::uint64_t{(1U << 0U) | (1U << 11U)},
                "SHR r8b count-1 flags differ");

    constexpr std::array<std::uint8_t, 3> implicitOne{0xD0, 0xE8, 0xC3};
    const auto implicitDecoded =
        decoder.decodeBlock(implicitOne, rosa::guest::GuestAddress{0x7FF80005998DULL});
    expect(implicitDecoded[0].opcode == rosa::x86::Opcode::ShrRegImm, "SHR AL, 1 opcode differs");
    expectEqual(implicitDecoded[0].length, std::uint8_t{2}, "SHR AL, 1 length differs");
    const auto implicitDestination =
        std::get<rosa::x86::RegisterOperand>(implicitDecoded[0].operands[0]);
    const auto implicitCount =
        std::get<rosa::x86::ImmediateOperand>(implicitDecoded[0].operands[1]);
    expect(implicitDestination.reg == rosa::x86::Register::Rax && implicitDestination.width == 8 &&
               implicitCount.value == 1,
           "SHR AL, 1 operands differ");
    expect(rosa::debug::dumpX86(implicitDecoded).find("shr al, 0x1") != std::string::npos,
           "SHR AL, 1 dump differs");
    const auto implicitBlock =
        translator.translate(implicitOne, rosa::guest::GuestAddress{0x7FF80005998DULL});
    rosa::x86::X86State implicitState;
    implicitState.rax = 0xAABBCCDDEEFF0006ULL;
    implicitState.rflags = 0x10;
    static_cast<void>(implicitBlock.execute(implicitState));
    expectEqual(implicitState.rax, std::uint64_t{0xAABBCCDDEEFF0003ULL},
                "SHR AL, 1 did not preserve upper RAX bits");
    expectEqual(implicitState.rflags & oneDefinedFlags, std::uint64_t{0x4},
                "SHR AL, 1 normal defined flags differ");

    implicitState.rax = 0xAABBCCDDEEFF0081ULL;
    implicitState.rflags = 0x10;
    static_cast<void>(implicitBlock.execute(implicitState));
    expectEqual(implicitState.rax, std::uint64_t{0xAABBCCDDEEFF0040ULL},
                "SHR AL, 1 high-bit result differs");
    expectEqual(implicitState.rflags & oneDefinedFlags, std::uint64_t{(1U << 0U) | (1U << 11U)},
                "SHR AL, 1 high-bit defined flags differ");

    constexpr std::array<std::uint8_t, 3> legacyHighByte{0xC0, 0xEC, 0x01};
    bool highByteRejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(legacyHighByte, rosa::guest::GuestAddress{0x3000}));
    } catch (const rosa::x86::DecodeError &) {
        highByteRejected = true;
    }
    expect(highByteRejected, "SHR silently treated legacy AH as a representable low byte");
}

void testShiftRight32ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0xC1, 0xE8, 0x1F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShrRegImm, "SHR r32, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "SHR r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xFFFFFFFF80000001ULL;
    state.rflags = 0x812;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{1}, "SHR eax, 31 result or zero-extension differs");
    expectEqual(state.rflags, std::uint64_t{0x812}, "SHR eax, 31 flags differ");

    constexpr std::array<std::uint8_t, 4> countOne{0xC1, 0xE8, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.rax = 0x80000001;
    oneState.rflags = 0x10;
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.rax, std::uint64_t{0x40000000}, "SHR eax, 1 result differs");
    expectEqual(oneState.rflags, std::uint64_t{0x817}, "SHR eax, 1 flags differ");

    constexpr std::array<std::uint8_t, 4> zeroCount{0xC1, 0xE8, 0x20, 0xC3};
    const auto zeroBlock = translator.translate(zeroCount, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0x55;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x55}, "SHR masked-zero changed EAX");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7}, "SHR masked-zero changed flags");
}

void testShiftRight64ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0xC1, 0xE8, 0x3E, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShrRegImm, "SHR r64, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "SHR r64 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax, "SHR r64 destination differs");
    expectEqual(destination.width, std::uint8_t{64}, "SHR r64 width differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{62}, "SHR r64 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("shr rax, 0x3e") != std::string::npos,
           "SHR r64 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xE000000000000200ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{3}, "SHR r64 count-62 result differs");
    constexpr std::uint64_t definedManyFlags = (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state.rflags & definedManyFlags, std::uint64_t{(1U << 0U) | (1U << 2U)},
                "SHR r64 count-62 defined flags differ");

    constexpr std::array<std::uint8_t, 5> countOne{0x48, 0xC1, 0xE8, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.rax = 0x8000000000000001ULL;
    oneState.rflags = 0x10;
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.rax, std::uint64_t{0x4000000000000000ULL},
                "SHR r64 count-one result differs");
    constexpr std::uint64_t definedOneFlags = definedManyFlags | (std::uint64_t{1} << 11U);
    expectEqual(oneState.rflags & definedOneFlags,
                std::uint64_t{(1U << 0U) | (1U << 2U) | (1U << 11U)},
                "SHR r64 count-one defined flags differ");

    constexpr std::array<std::uint8_t, 4> implicitOne{0x48, 0xD1, 0xEE, 0xC3};
    const auto implicitDecoded =
        decoder.decodeBlock(implicitOne, rosa::guest::GuestAddress{0x2800});
    expect(implicitDecoded[0].opcode == rosa::x86::Opcode::ShrRegImm,
           "implicit-count SHR opcode differs");
    expectEqual(implicitDecoded[0].length, std::uint8_t{3}, "implicit-count SHR length differs");
    const auto implicitDestination =
        std::get<rosa::x86::RegisterOperand>(implicitDecoded[0].operands[0]);
    const auto implicitCount =
        std::get<rosa::x86::ImmediateOperand>(implicitDecoded[0].operands[1]);
    expect(implicitDestination.reg == rosa::x86::Register::Rsi && implicitDestination.width == 64 &&
               implicitCount.value == 1 && implicitCount.width == 8,
           "implicit-count SHR operands differ");
    expect(rosa::debug::dumpX86(implicitDecoded).find("shr rsi, 0x1") != std::string::npos,
           "implicit-count SHR dump differs");
    const auto implicitBlock = translator.translate(implicitOne, rosa::guest::GuestAddress{0x2800});
    rosa::x86::X86State implicitState;
    implicitState.rsi = 0x8000000000000001ULL;
    implicitState.rflags = 0x10;
    static_cast<void>(implicitBlock.execute(implicitState));
    expectEqual(implicitState.rsi, std::uint64_t{0x4000000000000000ULL},
                "implicit-count SHR result differs");
    expectEqual(implicitState.rflags & definedOneFlags,
                std::uint64_t{(1U << 0U) | (1U << 2U) | (1U << 11U)},
                "implicit-count SHR defined flags differ");

    constexpr std::array<std::uint8_t, 3> implicit32{0xD1, 0xEA, 0xC3};
    const auto implicit32Decoded =
        decoder.decodeBlock(implicit32, rosa::guest::GuestAddress{0x7FF80005986FULL});
    expect(implicit32Decoded[0].opcode == rosa::x86::Opcode::ShrRegImm,
           "implicit-count SHR r32 opcode differs");
    expectEqual(implicit32Decoded[0].length, std::uint8_t{2},
                "implicit-count SHR r32 length differs");
    const auto implicit32Destination =
        std::get<rosa::x86::RegisterOperand>(implicit32Decoded[0].operands[0]);
    expect(implicit32Destination.reg == rosa::x86::Register::Rdx &&
               implicit32Destination.width == 32,
           "implicit-count SHR edx destination differs");
    expect(rosa::debug::dumpX86(implicit32Decoded).find("shr edx, 0x1") != std::string::npos,
           "implicit-count SHR edx dump differs");
    const auto implicit32Block =
        translator.translate(implicit32, rosa::guest::GuestAddress{0x7FF80005986FULL});
    rosa::x86::X86State implicit32State;
    implicit32State.rdx = 0xAABBCCDD80000001ULL;
    implicit32State.rflags = 0x10;
    static_cast<void>(implicit32Block.execute(implicit32State));
    expectEqual(implicit32State.rdx, std::uint64_t{0x40000000},
                "implicit-count SHR edx result or zero extension differs");
    expectEqual(implicit32State.rflags & definedOneFlags,
                std::uint64_t{(1U << 0U) | (1U << 2U) | (1U << 11U)},
                "implicit-count SHR edx defined flags differ");

    constexpr std::array<std::uint8_t, 5> zeroCount{0x48, 0xC1, 0xE8, 0x40, 0xC3};
    const auto zeroBlock = translator.translate(zeroCount, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0xE000000000000200ULL;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0xE000000000000200ULL},
                "SHR r64 masked-zero changed RAX");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7}, "SHR r64 masked-zero changed flags");
}

void testShiftRightArithmetic64ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0xC1, 0xF9, 0x03, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF70005318FULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::SarRegImm, "SAR r64, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "SAR r64 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 64 &&
               immediate.value == 3,
           "SAR rcx, 3 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("sar rcx, 0x3") != std::string::npos,
           "SAR rcx, 3 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF70005318FULL});
    rosa::x86::X86State state;
    state.rcx = 0x8000000000000007ULL;
    state.rflags = 0x810;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xF000000000000000ULL}, "SAR rcx, 3 result differs");
    constexpr std::uint64_t definedManyFlags = (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state.rflags & definedManyFlags,
                std::uint64_t{(1U << 0U) | (1U << 2U) | (1U << 7U)},
                "SAR rcx, 3 defined flags differ");

    constexpr std::array<std::uint8_t, 5> countOne{0x48, 0xC1, 0xF9, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.rcx = 0x8000000000000000ULL;
    oneState.rflags = (1U << 11U) | (1U << 4U);
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.rcx, std::uint64_t{0xC000000000000000ULL}, "SAR rcx, 1 result differs");
    constexpr std::uint64_t definedOneFlags = definedManyFlags | (std::uint64_t{1} << 11U);
    expectEqual(oneState.rflags & definedOneFlags, std::uint64_t{(1U << 2U) | (1U << 7U)},
                "SAR rcx, 1 defined flags differ");

    constexpr std::array<std::uint8_t, 5> maskedZero{0x48, 0xC1, 0xF9, 0x40, 0xC3};
    const auto zeroBlock = translator.translate(maskedZero, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State zeroState;
    zeroState.rcx = 0x8000000000000007ULL;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rcx, std::uint64_t{0x8000000000000007ULL}, "SAR masked-zero changed RCX");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7}, "SAR masked-zero changed flags");
}

void testShiftRightArithmetic32ImmediateGeneratedExecution() {
    // Observed in sqlite: sar ecx, 4 without a REX prefix.
    constexpr std::array<std::uint8_t, 4> code{0xC1, 0xF9, 0x04, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x100045B67ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::SarRegImm, "SAR r32, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "SAR r32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32 &&
               immediate.value == 4,
           "SAR ecx, 4 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("sar ecx, 0x4") != std::string::npos,
           "SAR ecx, 4 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x100045B67ULL});
    rosa::x86::X86State state;
    state.rcx = 0xAABBCCDD80000001ULL;
    state.rflags = 0x810;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xF8000000ULL}, "SAR ecx, 4 result differs");
    constexpr std::uint64_t definedManyFlags = (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state.rflags & definedManyFlags,
                std::uint64_t{(1U << 2U) | (1U << 7U)},
                "SAR ecx, 4 defined flags differ");

    constexpr std::array<std::uint8_t, 4> countOne{0xC1, 0xF9, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.rcx = 0x80000000ULL;
    oneState.rflags = (1U << 11U) | (1U << 4U) | (1U << 0U);
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.rcx, std::uint64_t{0xC0000000ULL}, "SAR ecx, 1 result differs");
    constexpr std::uint64_t definedOneFlags = definedManyFlags | (std::uint64_t{1} << 11U);
    expectEqual(oneState.rflags & definedOneFlags, std::uint64_t{(1U << 2U) | (1U << 7U)},
                "SAR ecx, 1 defined flags differ");

    // Observed in libsqlite3: SAR EBX, 1 with an implicit count (D1 /7).
    constexpr std::array<std::uint8_t, 3> implicitCode{0xD1, 0xFB, 0xC3};
    const auto implicitDecoded =
        decoder.decodeBlock(implicitCode, rosa::guest::GuestAddress{0x1000247B9ULL});
    expect(implicitDecoded[0].opcode == rosa::x86::Opcode::SarRegImm,
           "SAR r32, 1 opcode differs");
    expectEqual(implicitDecoded[0].length, std::uint8_t{2}, "SAR r32, 1 length differs");
    const auto implicitDestination =
        std::get<rosa::x86::RegisterOperand>(implicitDecoded[0].operands[0]);
    const auto implicitCount =
        std::get<rosa::x86::ImmediateOperand>(implicitDecoded[0].operands[1]);
    expect(implicitDestination.reg == rosa::x86::Register::Rbx &&
               implicitDestination.width == 32 && implicitCount.value == 1,
           "SAR ebx, 1 operands differ");
    expect(rosa::debug::dumpX86(implicitDecoded).find("sar ebx, 0x1") != std::string::npos,
           "SAR ebx, 1 dump differs");
    const auto implicitBlock =
        translator.translate(implicitCode, rosa::guest::GuestAddress{0x1000247B9ULL});
    rosa::x86::X86State implicitState;
    implicitState.rbx = 0xAABBCCDD80000000ULL;
    implicitState.rflags = 0x8D7;
    static_cast<void>(implicitBlock.execute(implicitState));
    expectEqual(implicitState.rbx, std::uint64_t{0xC0000000ULL}, "SAR ebx, 1 result differs");
    expectEqual(implicitState.rflags & definedOneFlags, std::uint64_t{(1U << 2U) | (1U << 7U)},
                "SAR ebx, 1 defined flags differ");
}

void testRotateLeft16ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0xC1, 0xC6, 0x08, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF7000355FDULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::RolRegImm, "ROL r16, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "ROL r16, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 16 &&
               immediate.value == 8,
           "ROL si, 8 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("rol si, 0x8") != std::string::npos,
           "ROL si, 8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF7000355FDULL});
    rosa::x86::X86State state;
    state.rsi = 0x11223344556612A5ULL;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rsi, std::uint64_t{0x112233445566A512ULL},
                "ROL si, 8 result or upper-register preservation differs");
    constexpr std::uint64_t unaffectedFlags = (1U << 2U) | (1U << 4U) | (1U << 6U) | (1U << 7U);
    expectEqual(state.rflags & unaffectedFlags, std::uint64_t{0xD4},
                "ROL si, 8 changed unaffected flags");
    expect((state.rflags & 1U) == 0, "ROL si, 8 carry differs");

    constexpr std::array<std::uint8_t, 5> countOne{0x66, 0xC1, 0xC6, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.rsi = 0x1122334455668000ULL;
    oneState.rflags = 0x2;
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.rsi, std::uint64_t{0x1122334455660001ULL}, "ROL si, 1 result differs");
    expectEqual(oneState.rflags & ((1U << 0U) | (1U << 11U)),
                std::uint64_t{(1U << 0U) | (1U << 11U)}, "ROL si, 1 CF/OF differ");

    constexpr std::array<std::uint8_t, 5> zeroEffective{0x66, 0xC1, 0xC6, 0x10, 0xC3};
    const auto zeroBlock = translator.translate(zeroEffective, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State zeroState;
    zeroState.rsi = 0x11223344556612A5ULL;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rsi, std::uint64_t{0x11223344556612A5ULL},
                "ROL si, 16 changed its destination");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7}, "ROL si, 16 changed flags");
}

void testRotateLeft32ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> observedCode{0xC1, 0xC0, 0x1E, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802CEA0D5ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::RolRegImm, "ROL r32, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "ROL r32, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               immediate.value == 30,
           "ROL eax, 30 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("rol eax, 0x1e") != std::string::npos,
           "ROL eax, 30 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("update_rotate_left_flags.i32") != std::string::npos,
           "ROL eax, 30 did not lower through 32-bit rotate flag IR");
    rosa::x86::X86State observedState;
    observedState.rax = 0xFFFFFFFFFFFFFFFBULL;
    observedState.rflags = 0x82;
    static_cast<void>(block.execute(observedState));
    expectEqual(observedState.rax, std::uint64_t{0xFFFFFFFEULL},
                "ROL eax, 30 result or zero-extension differs");
    expectEqual(observedState.rflags, std::uint64_t{0x82}, "ROL eax, 30 flags differ");

    constexpr std::array<std::uint8_t, 4> countOne{0xC1, 0xC0, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.rax = 0xFFFFFFFF80000000ULL;
    oneState.rflags = 0xD6;
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.rax, std::uint64_t{1}, "ROL eax, 1 result or zero-extension differs");
    expectEqual(oneState.rflags, std::uint64_t{0x8D7},
                "ROL eax, 1 CF/OF or unaffected flags differ");

    constexpr std::array<std::uint8_t, 4> maskedZero{0xC1, 0xC0, 0x20, 0xC3};
    const auto zeroBlock = translator.translate(maskedZero, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0xFFFFFFFF89ABCDEFULL;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0xFFFFFFFF89ABCDEFULL}, "ROL masked-zero changed RAX");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7}, "ROL masked-zero changed flags");
}

void testRotateLeft64ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> observedCode{0x49, 0xC1, 0xC2, 0x04, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C6D466ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::RolRegImm, "ROL r64, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "ROL r64, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R10 && destination.width == 64 &&
               immediate.value == 4,
           "ROL R10, 4 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("rol r10, 0x4") != std::string::npos,
           "ROL R10, 4 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("update_rotate_left_flags.i64") != std::string::npos,
           "ROL R10, 4 did not lower through 64-bit rotate flag IR");
    rosa::x86::X86State state;
    state.r10 = 0x0123456789ABCDEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r10, std::uint64_t{0x123456789ABCDEF0ULL}, "ROL R10, 4 result differs");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "ROL R10, 4 flags differ");

    constexpr std::array<std::uint8_t, 5> countOne{0x49, 0xC1, 0xC2, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.r10 = 0x8000000000000000ULL;
    oneState.rflags = 0xD6;
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.r10, std::uint64_t{1}, "ROL R10, 1 result differs");
    expectEqual(oneState.rflags, std::uint64_t{0x8D7},
                "ROL R10, 1 CF/OF or unaffected flags differ");

    constexpr std::array<std::uint8_t, 5> maskedZero{0x49, 0xC1, 0xC2, 0x40, 0xC3};
    const auto zeroBlock = translator.translate(maskedZero, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State zeroState;
    zeroState.r10 = 0x0123456789ABCDEFULL;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.r10, std::uint64_t{0x0123456789ABCDEFULL},
                "ROL R10, masked-zero changed its destination");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7}, "ROL R10, masked-zero changed flags");
}

void testRotateLeft32ClGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x41, 0xD3, 0xC6, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C6D115ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::RolRegCl, "ROL R14D, CL opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "ROL R14D, CL length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::R14 && destination.width == 32,
           "ROL R14D, CL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("rol r14d, cl") != std::string::npos,
           "ROL R14D, CL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("update_rotate_left_flags.i32") != std::string::npos,
           "ROL R14D, CL did not lower through rotate flags IR");

    rosa::x86::X86State observedState;
    observedState.r14 = 0xFFFFFFFFFFFFFFFEULL;
    observedState.rcx = 0x35;
    observedState.rflags = 0x2;
    static_cast<void>(block.execute(observedState));
    expectEqual(observedState.r14, std::uint64_t{0xFFDFFFFF},
                "ROL R14D, CL observed-count result differs");
    expectEqual(observedState.rflags, std::uint64_t{0x3},
                "ROL R14D, CL observed-count flags differ");

    rosa::x86::X86State oneState;
    oneState.r14 = 0xAAAAAAAA80000000ULL;
    oneState.rcx = 1;
    oneState.rflags = 0xD6;
    static_cast<void>(block.execute(oneState));
    expectEqual(oneState.r14, std::uint64_t{1}, "ROL R14D, 1 result differs");
    expectEqual(oneState.rflags, std::uint64_t{0x8D7}, "ROL R14D, 1 carry/overflow flags differ");

    rosa::x86::X86State zeroState;
    zeroState.r14 = 0xAAAAAAAA80000001ULL;
    zeroState.rcx = 0x20;
    zeroState.rflags = 0xAD7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.r14, std::uint64_t{0x80000001},
                "ROL R14D, masked-zero count did not zero-extend R14D");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "ROL R14D, masked-zero count changed flags");
}

void testRotateRight64ByClGeneratedExecution() {
    // Observed in libswiftCore under an Objective-C fixture: ROR rax, cl.
    constexpr std::array<std::uint8_t, 4> code{0x48, 0xD3, 0xC8, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8171A50DFULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::RorRegCl, "ROR rax, cl opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "ROR rax, cl length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64,
           "ROR rax, cl destination differs");
    expect(rosa::debug::dumpX86(decoded).find("ror rax, cl") != std::string::npos,
           "ROR rax, cl dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rax = 0x8000000000000001ULL;
    state.rcx = 1;
    state.rflags = 0x8D6;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xC000000000000000ULL}, "ROR rax, cl result differs");
    expectEqual(state.rcx, std::uint64_t{1}, "ROR rax, cl changed CL");
    // Only CF and (for count 1) OF are replaced: the rotated-out MSB sets
    // CF, and OF reflects MSB xor bit 62 of the result (both set here, so
    // OF clears). PF/SF/ZF/AF are preserved.
    expectEqual(state.rflags, std::uint64_t{0xD7}, "ROR rax, cl flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0x8000000000000001ULL;
    zeroState.rcx = 64;
    zeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x8000000000000001ULL},
                "ROR rax, masked-zero count changed RAX");
    expectEqual(zeroState.rflags, std::uint64_t{0x8D7},
                "ROR rax, masked-zero count changed flags");
}

void testRotateRight64ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> observedCode{0x48, 0xC1, 0xC8, 0x03, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802A729DCULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::RorRegImm, "ROR r64, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "ROR r64, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64 &&
               immediate.value == 3,
           "ROR rax, 3 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("ror rax, 0x3") != std::string::npos,
           "ROR rax, 3 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("update_rotate_right_flags.i64") != std::string::npos,
           "ROR rax, 3 did not lower through rotate-right flag IR");
    rosa::x86::X86State observedState;
    observedState.rax = 8;
    observedState.rflags = 0x847;
    static_cast<void>(block.execute(observedState));
    expectEqual(observedState.rax, std::uint64_t{1}, "ROR rax, 3 result differs");
    expectEqual(observedState.rflags, std::uint64_t{0x846}, "ROR rax, 3 flags differ");

    constexpr std::array<std::uint8_t, 5> countOne{0x48, 0xC1, 0xC8, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.rax = 3;
    oneState.rflags = 0xD6;
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.rax, std::uint64_t{0x8000000000000001ULL}, "ROR rax, 1 result differs");
    expectEqual(oneState.rflags, std::uint64_t{0x8D7},
                "ROR rax, 1 CF/OF or unaffected flags differ");

    constexpr std::array<std::uint8_t, 5> maskedZero{0x48, 0xC1, 0xC8, 0x40, 0xC3};
    const auto zeroBlock = translator.translate(maskedZero, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0x0123456789ABCDEFULL;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x0123456789ABCDEFULL}, "ROR masked-zero changed RAX");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7}, "ROR masked-zero changed flags");
}

void testShiftRightClGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x49, 0xD3, 0xEC, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF80004E899ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShrRegCl, "SHR r64, CL opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "SHR r64, CL length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::R12 && destination.width == 64,
           "SHR r12, CL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("shr r12, cl") != std::string::npos,
           "SHR r12, CL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF80004E899ULL});
    constexpr std::uint64_t countOneFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    rosa::x86::X86State oneState;
    oneState.r12 = 0x8000000000000001ULL;
    oneState.rcx = 1;
    oneState.rflags = 0x10;
    static_cast<void>(block.execute(oneState));
    expectEqual(oneState.r12, std::uint64_t{0x4000000000000000ULL},
                "SHR r12, CL count-one result differs");
    expectEqual(oneState.rcx, std::uint64_t{1}, "SHR r12, CL changed RCX");
    expectEqual(oneState.rflags & countOneFlags, std::uint64_t{0x805},
                "SHR r12, CL count-one defined flags differ");

    constexpr std::uint64_t manyFlags = (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    rosa::x86::X86State manyState;
    manyState.r12 = 0xE000000000000200ULL;
    manyState.rcx = 62;
    manyState.rflags = 0x810;
    static_cast<void>(block.execute(manyState));
    expectEqual(manyState.r12, std::uint64_t{3}, "SHR r12, CL count-62 result differs");
    expectEqual(manyState.rcx, std::uint64_t{62}, "SHR r12, CL count-62 changed RCX");
    expectEqual(manyState.rflags & manyFlags, std::uint64_t{0x5},
                "SHR r12, CL count-62 defined flags differ");

    rosa::x86::X86State zeroState;
    zeroState.r12 = 0x0123456789ABCDEFULL;
    zeroState.rcx = 0xABCDEF0000000040ULL;
    zeroState.rflags = 0xAD7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.r12, std::uint64_t{0x0123456789ABCDEFULL},
                "SHR r12, CL masked-zero changed its destination");
    expectEqual(zeroState.rcx, std::uint64_t{0xABCDEF0000000040ULL},
                "SHR r12, CL masked-zero changed RCX");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7}, "SHR r12, CL masked-zero changed flags");
}

void testShiftRightArithmeticClGeneratedExecution() {
    // Observed in libsqlite3: SAR R13D, CL with REX.B (D3 /7).
    constexpr std::array<std::uint8_t, 4> code{0x41, 0xD3, 0xFD, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10009E9D4ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::SarRegCl, "SAR r32, CL opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "SAR r32, CL length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::R13 && destination.width == 32,
           "SAR r13d, CL destination differs");
    expect(rosa::debug::dumpX86(decoded).find("sar r13d, cl") != std::string::npos,
           "SAR r13d, CL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10009E9D4ULL});
    constexpr std::uint64_t countOneFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    rosa::x86::X86State oneState;
    oneState.r13 = 0xAABBCCDD80000000ULL;
    oneState.rcx = 1;
    oneState.rflags = 0x10;
    static_cast<void>(block.execute(oneState));
    expectEqual(oneState.r13, std::uint64_t{0xC0000000ULL},
                "SAR r13d, CL count-one result differs");
    expectEqual(oneState.rcx, std::uint64_t{1}, "SAR r13d, CL changed RCX");
    expectEqual(oneState.rflags & countOneFlags, std::uint64_t{0x84},
                "SAR r13d, CL count-one defined flags differ");

    rosa::x86::X86State maskedState;
    maskedState.r13 = 0xAABBCCDD80000001ULL;
    maskedState.rcx = 33;
    maskedState.rflags = 0x10;
    static_cast<void>(block.execute(maskedState));
    expectEqual(maskedState.r13, std::uint64_t{0xC0000000ULL},
                "SAR r13d, CL masked-count result differs");
    expectEqual(maskedState.rflags & countOneFlags, std::uint64_t{0x85},
                "SAR r13d, CL masked-count defined flags differ");
}

void testNot32GeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0xF7, 0xD0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF800036677ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::NotReg, "NOT r32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "NOT r32 length differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rax && operand.width == 32,
           "NOT eax operand differs");
    expect(rosa::debug::dumpX86(decoded).find("not eax") != std::string::npos,
           "NOT eax dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF800036677ULL});
    rosa::x86::X86State state;
    state.rax = 0xAABBCCDD10203040ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xEFDFCFBF}, "NOT eax result or zero extension differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "NOT eax changed flags");

    state.rax = UINT64_C(0xFFFFFFFF00000000);
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{UINT32_MAX}, "NOT eax zero edge differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "NOT eax zero edge changed flags");

    constexpr std::array<std::uint8_t, 4> byteCode{0x40, 0xF6, 0xD6, 0xC3};
    const auto byteDecoded =
        decoder.decodeBlock(byteCode, rosa::guest::GuestAddress{0x7FF802B09393ULL});
    const auto byteOperand = std::get<rosa::x86::RegisterOperand>(byteDecoded[0].operands[0]);
    expect(byteDecoded[0].opcode == rosa::x86::Opcode::NotReg && byteDecoded[0].length == 3 &&
               byteOperand.reg == rosa::x86::Register::Rsi && byteOperand.width == 8,
           "NOT SIL decode differs");
    expect(rosa::debug::dumpX86(byteDecoded).find("not sil") != std::string::npos,
           "NOT SIL dump differs");

    const auto byteBlock =
        translator.translate(byteCode, rosa::guest::GuestAddress{0x7FF802B09393ULL});
    state.rsi = 0x1122334455667700ULL;
    state.rflags = 0x846;
    static_cast<void>(byteBlock.execute(state));
    expectEqual(state.rsi, std::uint64_t{0x11223344556677FFULL},
                "NOT SIL changed bytes outside its destination");
    expectEqual(state.rflags, std::uint64_t{0x846}, "NOT SIL changed flags");

    constexpr std::array<std::uint8_t, 3> legacyByteCode{0xF6, 0xD0, 0xC3};
    const auto legacyByteDecoded =
        decoder.decodeBlock(legacyByteCode, rosa::guest::GuestAddress{0x7FF802AB295FULL});
    const auto legacyByteOperand =
        std::get<rosa::x86::RegisterOperand>(legacyByteDecoded[0].operands[0]);
    expect(legacyByteDecoded[0].opcode == rosa::x86::Opcode::NotReg &&
               legacyByteDecoded[0].length == 2 &&
               legacyByteOperand.reg == rosa::x86::Register::Rax && legacyByteOperand.width == 8,
           "legacy NOT AL decode differs");
    expect(rosa::debug::dumpX86(legacyByteDecoded).find("not al") != std::string::npos,
           "legacy NOT AL dump differs");
    const auto legacyByteBlock =
        translator.translate(legacyByteCode, rosa::guest::GuestAddress{0x7FF802AB295FULL});
    state.rax = 0xAABBCCDDEEFF0000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(legacyByteBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0xAABBCCDDEEFF00FFULL},
                "legacy NOT AL changed bytes outside its destination");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "legacy NOT AL changed flags");
}

void testNeg64GeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x49, 0xF7, 0xDD, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::NegReg, "NEG r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "NEG r64 length differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::R13 && operand.width == 64,
           "NEG r13 operand differs");
    expect(rosa::debug::dumpX86(decoded).find("neg r13") != std::string::npos,
           "NEG r13 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});

    rosa::x86::X86State zero;
    zero.r13 = 0;
    zero.rflags = 0x8D7;
    static_cast<void>(block.execute(zero));
    expectEqual(zero.r13, std::uint64_t{0}, "NEG zero result differs");
    expectEqual(zero.rflags, std::uint64_t{0x46}, "NEG zero flags differ");

    rosa::x86::X86State one;
    one.r13 = 1;
    one.rflags = 0;
    static_cast<void>(block.execute(one));
    expectEqual(one.r13, UINT64_MAX, "NEG one result differs");
    expectEqual(one.rflags, std::uint64_t{0x97}, "NEG one flags differ");

    rosa::x86::X86State overflow;
    overflow.r13 = std::uint64_t{1} << 63U;
    overflow.rflags = 0;
    static_cast<void>(block.execute(overflow));
    expectEqual(overflow.r13, std::uint64_t{1} << 63U, "NEG minimum result differs");
    expectEqual(overflow.rflags, std::uint64_t{0x887}, "NEG minimum flags differ");

    constexpr std::array<std::uint8_t, 3> code32{0xF7, 0xD9, 0xC3};
    const auto decoded32 = decoder.decodeBlock(code32, rosa::guest::GuestAddress{0x2000});
    expect(decoded32[0].opcode == rosa::x86::Opcode::NegReg, "NEG r32 opcode differs");
    expectEqual(decoded32[0].length, std::uint8_t{2}, "NEG r32 length differs");
    const auto operand32 = std::get<rosa::x86::RegisterOperand>(decoded32[0].operands[0]);
    expect(operand32.reg == rosa::x86::Register::Rcx && operand32.width == 32,
           "NEG ecx operand differs");
    expect(rosa::debug::dumpX86(decoded32).find("neg ecx") != std::string::npos,
           "NEG ecx dump differs");

    const auto block32 = translator.translate(code32, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State one32;
    one32.rcx = 0xAAAAAAAA00000001ULL;
    one32.rflags = 0;
    static_cast<void>(block32.execute(one32));
    expectEqual(one32.rcx, std::uint64_t{UINT32_MAX}, "NEG r32 result or zero extension differs");
    expectEqual(one32.rflags, std::uint64_t{0x97}, "NEG r32 one flags differ");

    rosa::x86::X86State overflow32;
    overflow32.rcx = 0xBBBBBBBB80000000ULL;
    overflow32.rflags = 0;
    static_cast<void>(block32.execute(overflow32));
    expectEqual(overflow32.rcx, std::uint64_t{0x80000000},
                "NEG r32 minimum result or zero extension differs");
    expectEqual(overflow32.rflags, std::uint64_t{0x887}, "NEG r32 minimum flags differ");

    constexpr std::array<std::uint8_t, 4> wordCode{0x66, 0xF7, 0xDB, 0xC3};
    constexpr rosa::guest::GuestAddress wordRip{0x7FF802D09716ULL};
    const auto wordDecoded = decoder.decodeBlock(wordCode, wordRip);
    expect(wordDecoded[0].opcode == rosa::x86::Opcode::NegReg && wordDecoded[0].length == 3,
           "NEG r16 opcode or length differs");
    const auto wordOperand = std::get<rosa::x86::RegisterOperand>(wordDecoded[0].operands[0]);
    expect(wordOperand.reg == rosa::x86::Register::Rbx && wordOperand.width == 16,
           "NEG BX operand differs");
    expect(rosa::debug::dumpX86(wordDecoded).find("neg bx") != std::string::npos,
           "NEG BX dump differs");
    const auto wordBlock = translator.translate(wordCode, wordRip);

    rosa::x86::X86State wordOne;
    wordOne.rbx = UINT64_C(0x1122334455660001);
    static_cast<void>(wordBlock.execute(wordOne));
    expectEqual(wordOne.rbx, UINT64_C(0x112233445566FFFF), "NEG one BX result or merge differs");
    expectEqual(wordOne.rflags, std::uint64_t{0x97}, "NEG one BX flags differ");

    rosa::x86::X86State wordOverflow;
    wordOverflow.rbx = UINT64_C(0x8877665544338000);
    static_cast<void>(wordBlock.execute(wordOverflow));
    expectEqual(wordOverflow.rbx, UINT64_C(0x8877665544338000),
                "NEG minimum BX result or merge differs");
    expectEqual(wordOverflow.rflags, std::uint64_t{0x887}, "NEG minimum BX flags differ");

    constexpr std::array<std::uint8_t, 3> byteCode{0xF6, 0xD9, 0xC3};
    constexpr rosa::guest::GuestAddress byteRip{0x7FF802A2DD72ULL};
    const auto byteDecoded = decoder.decodeBlock(byteCode, byteRip);
    expect(byteDecoded[0].opcode == rosa::x86::Opcode::NegReg && byteDecoded[0].length == 2,
           "NEG r8 opcode or length differs");
    const auto byteOperand = std::get<rosa::x86::RegisterOperand>(byteDecoded[0].operands[0]);
    expect(byteOperand.reg == rosa::x86::Register::Rcx && byteOperand.width == 8,
           "NEG CL operand differs");
    expect(rosa::debug::dumpX86(byteDecoded).find("neg cl") != std::string::npos,
           "NEG CL dump differs");
    const auto byteBlock = translator.translate(byteCode, byteRip);

    rosa::x86::X86State byteZero;
    byteZero.rcx = 0x1122334455667700ULL;
    byteZero.rflags = 0x8D7;
    static_cast<void>(byteBlock.execute(byteZero));
    expectEqual(byteZero.rcx, std::uint64_t{0x1122334455667700ULL},
                "NEG zero CL changed its register");
    expectEqual(byteZero.rflags, std::uint64_t{0x46}, "NEG zero CL flags differ");

    rosa::x86::X86State byteOne;
    byteOne.rcx = 0xFFEEDDCCBBAA9901ULL;
    static_cast<void>(byteBlock.execute(byteOne));
    expectEqual(byteOne.rcx, std::uint64_t{0xFFEEDDCCBBAA99FFULL},
                "NEG one CL result or merge differs");
    expectEqual(byteOne.rflags, std::uint64_t{0x97}, "NEG one CL flags differ");

    rosa::x86::X86State byteOverflow;
    byteOverflow.rcx = 0x8877665544332280ULL;
    static_cast<void>(byteBlock.execute(byteOverflow));
    expectEqual(byteOverflow.rcx, std::uint64_t{0x8877665544332280ULL},
                "NEG minimum CL result or merge differs");
    expectEqual(byteOverflow.rflags, std::uint64_t{0x883}, "NEG minimum CL flags differ");
}

void testDirectionFlagGeneratedExecution() {
    // memmove's backward path: STD; REP MOVSB; CLD.
    constexpr std::array<std::uint8_t, 5> code{0xFD, 0xF3, 0xA4, 0xFC, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Std && decoded[0].length == 1,
           "STD decode differs");
    expect(decoded[2].opcode == rosa::x86::Opcode::Cld && decoded[2].length == 1,
           "CLD decode differs");
    const auto listing = rosa::debug::dumpX86(decoded);
    expect(listing.find("std") != std::string::npos && listing.find("cld") != std::string::npos,
           "STD/CLD x86 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("write_direction_flag 1") !=
               std::string::npos,
           "STD IR dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 4> bytes{1, 2, 3, 4};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8010}, bytes);
    rosa::x86::X86State state;
    state.rsi = 0x8013;
    state.rdi = 0x8043;
    state.rcx = bytes.size();
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expect(addressSpace.readBytes(rosa::guest::GuestAddress{0x8040}, bytes.size()) ==
               std::vector<std::uint8_t>(bytes.begin(), bytes.end()),
           "STD did not make REP MOVSB copy backward");
    expectEqual(state.rsi, std::uint64_t{0x800F}, "backward copy RSI differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "CLD did not clear DF or STD/CLD changed arithmetic flags");
}

void testRepMovsbGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0xF3, 0xA4, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::RepMovsb, "REP MOVSB opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "REP MOVSB length differs");
    expect(rosa::debug::dumpX86(decoded).find("rep movsb") != std::string::npos,
           "REP MOVSB x86 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("repeat_move_byte") !=
               std::string::npos,
           "REP MOVSB IR dump differs");

    constexpr rosa::guest::GuestAddress memoryPage{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 6> forwardBytes{1, 2, 3, 4, 5, 6};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8010}, forwardBytes);
    rosa::x86::X86State forward;
    forward.rsi = 0x8010;
    forward.rdi = 0x8040;
    forward.rcx = forwardBytes.size();
    forward.rflags = 0x8D7;
    static_cast<void>(block.execute(forward, &addressSpace));
    expect(addressSpace.readBytes(rosa::guest::GuestAddress{0x8040}, forwardBytes.size()) ==
               std::vector<std::uint8_t>(forwardBytes.begin(), forwardBytes.end()),
           "REP MOVSB forward bytes differ");
    expectEqual(forward.rsi, std::uint64_t{0x8016}, "REP MOVSB forward RSI differs");
    expectEqual(forward.rdi, std::uint64_t{0x8046}, "REP MOVSB forward RDI differs");
    expectEqual(forward.rcx, std::uint64_t{0}, "REP MOVSB forward count differs");
    expectEqual(forward.rflags, std::uint64_t{0x8D7}, "REP MOVSB forward changed flags");

    constexpr std::array<std::uint8_t, 6> backwardBytes{7, 8, 9, 10, 11, 12};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8050}, backwardBytes);
    rosa::x86::X86State backward;
    backward.rsi = 0x8055;
    backward.rdi = 0x8085;
    backward.rcx = backwardBytes.size();
    backward.rflags = 0xCD7;
    static_cast<void>(block.execute(backward, &addressSpace));
    expect(addressSpace.readBytes(rosa::guest::GuestAddress{0x8080}, backwardBytes.size()) ==
               std::vector<std::uint8_t>(backwardBytes.begin(), backwardBytes.end()),
           "REP MOVSB backward bytes differ");
    expectEqual(backward.rsi, std::uint64_t{0x804F}, "REP MOVSB backward RSI differs");
    expectEqual(backward.rdi, std::uint64_t{0x807F}, "REP MOVSB backward RDI differs");
    expectEqual(backward.rcx, std::uint64_t{0}, "REP MOVSB backward count differs");
    expectEqual(backward.rflags, std::uint64_t{0xCD7}, "REP MOVSB backward changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State zeroCount;
    zeroCount.rsi = 1;
    zeroCount.rdi = 2;
    zeroCount.rcx = 0;
    zeroCount.rflags = 0x8D7;
    static_cast<void>(block.execute(zeroCount, &unmappedAddressSpace));
    expectEqual(zeroCount.rsi, std::uint64_t{1}, "zero-count REP MOVSB changed RSI");
    expectEqual(zeroCount.rdi, std::uint64_t{2}, "zero-count REP MOVSB changed RDI");
    expectEqual(zeroCount.rflags, std::uint64_t{0x8D7}, "zero-count REP MOVSB changed flags");

    rosa::x86::X86State sourceFaultState;
    sourceFaultState.rsi = 0xB000;
    sourceFaultState.rdi = 0x8040;
    sourceFaultState.rcx = 1;
    sourceFaultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(sourceFaultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "REP MOVSB did not report a source read fault");
    expectEqual(sourceFaultState.rsi, std::uint64_t{0xB000},
                "source-faulted REP MOVSB changed RSI");
    expectEqual(sourceFaultState.rdi, std::uint64_t{0x8040},
                "source-faulted REP MOVSB changed RDI");
    expectEqual(sourceFaultState.rcx, std::uint64_t{1}, "source-faulted REP MOVSB changed RCX");
    expectEqual(sourceFaultState.rflags, std::uint64_t{0xAD7},
                "source-faulted REP MOVSB changed flags");

    constexpr rosa::guest::GuestAddress destinationPage{0xA000};
    addressSpace.mapAnonymous(destinationPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> faultSource{0xAA, 0xBB};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x80F0}, faultSource);
    rosa::x86::X86State faultState;
    faultState.rsi = 0x80F0;
    faultState.rdi = 0xAFFF;
    faultState.rcx = 2;
    faultState.rflags = 0x8D7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "REP MOVSB did not report its second-byte write fault");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0xAFFF}, 1).front(),
                std::uint8_t{0xAA}, "faulted REP MOVSB lost its committed prefix");
    expectEqual(faultState.rsi, std::uint64_t{0x80F1}, "faulted REP MOVSB RSI progress differs");
    expectEqual(faultState.rdi, std::uint64_t{0xB000}, "faulted REP MOVSB RDI progress differs");
    expectEqual(faultState.rcx, std::uint64_t{1}, "faulted REP MOVSB RCX progress differs");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "faulted REP MOVSB changed flags");
}

void testUnsignedMultiplyGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0xF7, 0xE1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MulReg, "MUL r64 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rcx,
           "MUL r64 source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State smallState;
    smallState.rax = 3;
    smallState.rcx = 4;
    smallState.rdx = UINT64_MAX;
    smallState.rflags = 0x8D7;
    static_cast<void>(block.execute(smallState));
    expectEqual(smallState.rax, std::uint64_t{12}, "MUL low result differs");
    expectEqual(smallState.rdx, std::uint64_t{0}, "MUL high result differs");
    expectEqual(smallState.rcx, std::uint64_t{4}, "MUL changed its source register");
    expectEqual(smallState.rflags, std::uint64_t{0xD6}, "MUL zero-high defined flags differ");

    rosa::x86::X86State wideState;
    wideState.rax = UINT64_MAX;
    wideState.rcx = 2;
    wideState.rflags = 0x2;
    static_cast<void>(block.execute(wideState));
    expectEqual(wideState.rax, std::uint64_t{UINT64_MAX - 1}, "MUL wide low result differs");
    expectEqual(wideState.rdx, std::uint64_t{1}, "MUL wide high result differs");
    expectEqual(wideState.rflags, std::uint64_t{0x803}, "MUL nonzero-high defined flags differ");

    constexpr std::array<std::uint8_t, 4> dwordCode{0x41, 0xF7, 0xE4, 0xC3};
    constexpr rosa::guest::GuestAddress dwordAddress{0x7FF802A1AAEAULL};
    const auto dwordDecoded = decoder.decodeBlock(dwordCode, dwordAddress);
    expect(dwordDecoded[0].opcode == rosa::x86::Opcode::MulReg, "MUL r32 opcode differs");
    expectEqual(dwordDecoded[0].length, std::uint8_t{3}, "MUL r32 length differs");
    const auto dwordSource = std::get<rosa::x86::RegisterOperand>(dwordDecoded[0].operands[0]);
    expect(dwordSource.reg == rosa::x86::Register::R12 && dwordSource.width == 32,
           "mul r12d source differs");
    expect(rosa::debug::dumpX86(dwordDecoded).find("mul r12d") != std::string::npos,
           "mul r12d dump differs");

    const auto dwordBlock = translator.translate(dwordCode, dwordAddress);
    rosa::x86::X86State dwordSmallState;
    dwordSmallState.rax = 0xAABBCCDD0000005DULL;
    dwordSmallState.rdx = UINT64_MAX;
    dwordSmallState.r12 = 8;
    dwordSmallState.rflags = 0x8D7;
    static_cast<void>(dwordBlock.execute(dwordSmallState));
    expectEqual(dwordSmallState.rax, std::uint64_t{0x2E8}, "MUL r32 low result differs");
    expectEqual(dwordSmallState.rdx, std::uint64_t{0}, "MUL r32 high result differs");
    expectEqual(dwordSmallState.r12, std::uint64_t{8}, "MUL r32 changed its source");
    expectEqual(dwordSmallState.rflags, std::uint64_t{0xD6},
                "MUL r32 zero-high defined flags differ");

    rosa::x86::X86State dwordWideState;
    dwordWideState.rax = 0xAABBCCDDFFFFFFFFULL;
    dwordWideState.rdx = UINT64_MAX;
    dwordWideState.r12 = 2;
    dwordWideState.rflags = 0x2;
    static_cast<void>(dwordBlock.execute(dwordWideState));
    expectEqual(dwordWideState.rax, std::uint64_t{0xFFFFFFFEULL},
                "wide MUL r32 low result differs");
    expectEqual(dwordWideState.rdx, std::uint64_t{1}, "wide MUL r32 high result differs");
    expectEqual(dwordWideState.rflags, std::uint64_t{0x803},
                "MUL r32 nonzero-high defined flags differ");
}

void testUnsignedMultiplyMemoryGeneratedExecution() {
    // Observed in libsystem_pthread: MUL qword [rdx] with REX.W.
    constexpr std::array<std::uint8_t, 4> code{0x48, 0xF7, 0x22, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802E6FF01ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MulMem, "MUL memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "MUL memory length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rdx && memory.displacement == 0 &&
               memory.width == 64,
           "MUL qword [rdx] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("mul qword [rdx]") != std::string::npos,
           "MUL qword [rdx] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 4);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802E6FF01ULL});
    rosa::x86::X86State state;
    state.rax = 3;
    state.rdx = target.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{12}, "MUL memory low result differs");
    expectEqual(state.rdx, std::uint64_t{0}, "MUL memory high result differs");
    expectEqual(addressSpace.readU64(target), std::uint64_t{4},
                "MUL memory changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0xD6}, "MUL memory zero-high defined flags differ");

    addressSpace.writeU64(target, 2);
    rosa::x86::X86State wideState;
    wideState.rax = UINT64_MAX;
    wideState.rdx = target.value;
    wideState.rflags = 0x2;
    static_cast<void>(block.execute(wideState, &addressSpace));
    expectEqual(wideState.rax, std::uint64_t{UINT64_MAX - 1}, "MUL memory wide low differs");
    expectEqual(wideState.rdx, std::uint64_t{1}, "MUL memory wide high differs");
    expectEqual(wideState.rflags, std::uint64_t{0x803},
                "MUL memory nonzero-high defined flags differ");
}

void testSignedMultiplyMemoryGeneratedExecution() {
    // Observed in libsqlite3: IMUL qword [r10] with REX.W.
    constexpr std::array<std::uint8_t, 4> code{0x49, 0xF7, 0x2A, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802E6FF01ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::ImulMem, "IMUL memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "IMUL memory length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::R10 && memory.displacement == 0 &&
               memory.width == 64,
           "IMUL qword [r10] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("imul qword [r10]") != std::string::npos,
           "IMUL qword [r10] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 5);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802E6FF01ULL});
    rosa::x86::X86State state;
    state.rax = static_cast<std::uint64_t>(-3);
    state.r10 = target.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, static_cast<std::uint64_t>(-15), "IMUL memory low result differs");
    expectEqual(state.rdx, UINT64_MAX, "IMUL memory sign-extended high differs");
    expectEqual(addressSpace.readU64(target), std::uint64_t{5},
                "IMUL memory changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0xD6}, "IMUL memory no-overflow flags differ");

    addressSpace.writeU64(target, 3);
    rosa::x86::X86State wideState;
    wideState.rax = 0x4000000000000000ULL;
    wideState.r10 = target.value;
    wideState.rflags = 0x2;
    static_cast<void>(block.execute(wideState, &addressSpace));
    expectEqual(wideState.rax, std::uint64_t{0xC000000000000000ULL},
                "IMUL memory wide low differs");
    expectEqual(wideState.rdx, std::uint64_t{0}, "IMUL memory wide high differs");
    expectEqual(wideState.rflags, std::uint64_t{0x803},
                "IMUL memory overflow defined flags differ");
}

void testSignedMultiplyRegisterGeneratedExecution() {
    // Observed in libsqlite3: IMUL rdx with REX.W (single-operand F7 /5).
    constexpr std::array<std::uint8_t, 4> code{0x48, 0xF7, 0xEA, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000BE2F5ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::ImulReg, "IMUL register opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "IMUL register length differs");
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(source.reg == rosa::x86::Register::Rdx && source.width == 64,
           "IMUL rdx operand differs");
    expect(rosa::debug::dumpX86(decoded).find("imul rdx") != std::string::npos,
           "IMUL rdx dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000BE2F5ULL});
    rosa::x86::X86State state;
    state.rax = static_cast<std::uint64_t>(-3);
    state.rdx = 5;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, static_cast<std::uint64_t>(-15), "IMUL register low result differs");
    expectEqual(state.rdx, UINT64_MAX, "IMUL register sign-extended high differs");
    expectEqual(state.rflags, std::uint64_t{0xD6}, "IMUL register no-overflow flags differ");

    rosa::x86::X86State wideState;
    wideState.rax = 0x4000000000000000ULL;
    wideState.rdx = 3;
    wideState.rflags = 0x2;
    static_cast<void>(block.execute(wideState));
    expectEqual(wideState.rax, std::uint64_t{0xC000000000000000ULL},
                "IMUL register wide low differs");
    expectEqual(wideState.rdx, std::uint64_t{0}, "IMUL register wide high differs");
    expectEqual(wideState.rflags, std::uint64_t{0x803},
                "IMUL register overflow defined flags differ");
}

void testUnsignedDivideByteGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> observedCode{0xF6, 0xF2, 0xC3}; // div dl
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C75758ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::DivReg, "DIV r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "DIV r8 length differs");
    const auto divisor = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(divisor.reg == rosa::x86::Register::Rdx && divisor.width == 8, "DIV DL operand differs");
    expect(rosa::debug::dumpX86(decoded).find("div dl") != std::string::npos,
           "DIV DL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("divide_unsigned_byte") !=
               std::string::npos,
           "DIV DL IR differs");

    rosa::x86::X86State state;
    state.rip = observedRip.value;
    state.rax = 0x1122334455660100ULL;
    state.rdx = 0x8877665544332203ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455660155ULL},
                "DIV DL quotient/remainder or upper RAX bytes differ");
    expectEqual(state.rdx, std::uint64_t{0x8877665544332203ULL},
                "DIV DL changed its divisor register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "DIV DL changed undefined flags");

    state.rip = observedRip.value;
    state.rax = 0xFFEEDDCCBBAA0001ULL;
    state.rdx = 1;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFEEDDCCBBAA0001ULL},
                "observed one-by-one DIV result differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "observed one-by-one DIV changed flags");

    rosa::x86::X86State zeroDivisor;
    zeroDivisor.rip = observedRip.value;
    zeroDivisor.rax = 0x1122334455661234ULL;
    zeroDivisor.rdx = 0x8877665544332200ULL;
    zeroDivisor.rflags = 0xCD7;
    bool divideError = false;
    try {
        static_cast<void>(block.execute(zeroDivisor));
    } catch (const std::runtime_error &error) {
        divideError = std::string_view(error.what()).find("divide error") != std::string_view::npos;
    }
    expect(divideError, "zero-divisor DIV did not raise a divide error");
    expectEqual(zeroDivisor.rax, std::uint64_t{0x1122334455661234ULL},
                "zero-divisor DIV changed RAX");
    expectEqual(zeroDivisor.rdx, std::uint64_t{0x8877665544332200ULL},
                "zero-divisor DIV changed RDX");
    expectEqual(zeroDivisor.rflags, std::uint64_t{0xCD7}, "zero-divisor DIV changed flags");

    rosa::x86::X86State overflow;
    overflow.rip = observedRip.value;
    overflow.rax = 0x1122334455660100ULL;
    overflow.rdx = 1;
    overflow.rflags = 0xED7;
    divideError = false;
    try {
        static_cast<void>(block.execute(overflow));
    } catch (const std::runtime_error &error) {
        divideError = std::string_view(error.what()).find("overflows AL") != std::string_view::npos;
    }
    expect(divideError, "overflowing byte DIV did not raise a divide error");
    expectEqual(overflow.rax, std::uint64_t{0x1122334455660100ULL},
                "overflowing byte DIV changed RAX");
    expectEqual(overflow.rdx, std::uint64_t{1}, "overflowing byte DIV changed RDX");
    expectEqual(overflow.rflags, std::uint64_t{0xED7}, "overflowing byte DIV changed flags");
}

void testUnsignedDivideQwordRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0xF7, 0xF6, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802A2DACAULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::DivReg, "DIV r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "DIV r64 length differs");
    const auto divisor = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(divisor.reg == rosa::x86::Register::Rsi && divisor.width == 64,
           "DIV RSI operand differs");
    expect(rosa::debug::dumpX86(decoded).find("div rsi") != std::string::npos,
           "DIV RSI dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("divide_unsigned_qword") !=
               std::string::npos,
           "DIV RSI qword IR differs");

    rosa::x86::X86State state;
    state.rax = 0;
    state.rdx = 1;
    state.rsi = 3;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x5555555555555555ULL},
                "DIV r64 128-bit dividend quotient differs");
    expectEqual(state.rdx, std::uint64_t{1}, "DIV r64 128-bit dividend remainder differs");
    expectEqual(state.rsi, std::uint64_t{3}, "DIV r64 changed its divisor register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "DIV r64 changed undefined flags");

    state.rax = 100;
    state.rdx = 0;
    state.rsi = 24;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{4}, "DIV r64 quotient differs");
    expectEqual(state.rdx, std::uint64_t{4}, "DIV r64 remainder differs");

    rosa::x86::X86State zeroDivisor;
    zeroDivisor.rax = 0x1122334455667788ULL;
    zeroDivisor.rdx = 0x8877665544332211ULL;
    zeroDivisor.rsi = 0;
    zeroDivisor.rflags = 0xBD7;
    bool divideError = false;
    try {
        static_cast<void>(block.execute(zeroDivisor));
    } catch (const std::runtime_error &error) {
        divideError = std::string_view(error.what()).find("divide error") != std::string_view::npos;
    }
    expect(divideError, "zero-divisor qword DIV did not fault");
    expectEqual(zeroDivisor.rax, std::uint64_t{0x1122334455667788ULL},
                "zero-divisor qword DIV changed RAX");
    expectEqual(zeroDivisor.rdx, std::uint64_t{0x8877665544332211ULL},
                "zero-divisor qword DIV changed RDX");
    expectEqual(zeroDivisor.rflags, std::uint64_t{0xBD7}, "zero-divisor qword DIV changed flags");

    rosa::x86::X86State overflow;
    overflow.rax = 0;
    overflow.rdx = 3;
    overflow.rsi = 3;
    overflow.rflags = 0xCD7;
    divideError = false;
    try {
        static_cast<void>(block.execute(overflow));
    } catch (const std::runtime_error &error) {
        divideError =
            std::string_view(error.what()).find("overflows RAX") != std::string_view::npos;
    }
    expect(divideError, "overflowing qword DIV did not fault");
    expectEqual(overflow.rax, std::uint64_t{0}, "overflowing qword DIV changed RAX");
    expectEqual(overflow.rdx, std::uint64_t{3}, "overflowing qword DIV changed RDX");
    expectEqual(overflow.rsi, std::uint64_t{3}, "overflowing qword DIV changed RSI");
    expectEqual(overflow.rflags, std::uint64_t{0xCD7}, "overflowing qword DIV changed flags");
}

void testUnsignedDivideDwordRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x41, 0xF7, 0xF3, 0xC3}; // div r11d; ret
    constexpr rosa::guest::GuestAddress instructionAddress{0x1000007FBULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::DivReg, "DIV r32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "DIV r32 length differs");
    const auto divisor = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(divisor.reg == rosa::x86::Register::R11 && divisor.width == 32,
           "DIV R11D operand differs");
    expect(rosa::debug::dumpX86(decoded).find("div r11d") != std::string::npos,
           "DIV R11D dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("divide_unsigned_dword") !=
               std::string::npos,
           "DIV R11D IR differs");

    rosa::x86::X86State state;
    state.rax = UINT64_C(0xAAAAAAAA00000064);
    state.rdx = UINT64_C(0xBBBBBBBB00000000);
    state.r11 = UINT64_C(0xCCCCCCCC00000018);
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{4}, "DIV r32 quotient differs");
    expectEqual(state.rdx, std::uint64_t{4}, "DIV r32 remainder differs");
    expectEqual(state.r11, UINT64_C(0xCCCCCCCC00000018), "DIV r32 changed its divisor register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "DIV r32 changed undefined flags");
}

void testUnsignedDivideQwordMemoryGeneratedExecution() {
    // Observed in libbz2 under grep -J: DIV qword [rbp-0x50].
    constexpr std::array<std::uint8_t, 5> code{0x48, 0xF7, 0x75, 0xB0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::DivMem && decoded[0].length == 4,
           "DIV qword memory decode differs");
    expect(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]).width == 64,
           "DIV qword memory width differs");
    expect(rosa::debug::dumpX86(decoded).find("div qword [rbp-0x50]") != std::string::npos,
           "DIV qword memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    // A divisor above 32 bits proves the full qword is loaded.
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8100 - 0x50}, 0x100000000ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbp = 0x8100;
    state.rdx = 0x5;
    state.rax = 0x0000000700000009ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    // (5 << 64 | 0x0000000700000009) / 2^32
    expectEqual(state.rax, std::uint64_t{0x0000000500000007ULL}, "DIV qword quotient differs");
    expectEqual(state.rdx, std::uint64_t{9}, "DIV qword remainder differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "DIV qword changed undefined flags");
}

void testUnsignedDivideDwordMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 8> code{0x41, 0xF7, 0xB5, 0x60, 0x02, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C68D3AULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::DivMem, "DIV dword memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "DIV dword memory length differs");
    const auto divisor = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(divisor.base == rosa::x86::Register::R13 && divisor.hasBase && !divisor.ripRelative &&
               !divisor.index && divisor.displacement == 0x260 && divisor.width == 32,
           "DIV dword [r13+0x260] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("div dword [r13+0x260]") != std::string::npos,
           "DIV dword memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress divisorAddress{0x8260};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(divisorAddress, 5);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("divide_unsigned_dword") !=
               std::string::npos,
           "DIV dword memory IR differs");

    rosa::x86::X86State state;
    state.r13 = page.value;
    state.rax = 0xAAAAAAAA00000011ULL;
    state.rdx = 0xBBBBBBBB00000000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{3}, "DIV dword quotient differs");
    expectEqual(state.rdx, std::uint64_t{2}, "DIV dword remainder differs");
    expectEqual(state.r13, page.value, "DIV dword changed its memory base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "DIV dword changed undefined flags");

    addressSpace.writeU32(divisorAddress, 0);
    rosa::x86::X86State zeroDivisor;
    zeroDivisor.r13 = page.value;
    zeroDivisor.rax = 0x1122334455667788ULL;
    zeroDivisor.rdx = 0x8877665544332211ULL;
    zeroDivisor.rflags = 0xAD7;
    bool divideError = false;
    try {
        static_cast<void>(block.execute(zeroDivisor, &addressSpace));
    } catch (const std::runtime_error &error) {
        divideError = std::string_view(error.what()).find("divide error") != std::string_view::npos;
    }
    expect(divideError, "zero-divisor dword DIV did not fault");
    expectEqual(zeroDivisor.rax, std::uint64_t{0x1122334455667788ULL},
                "zero-divisor dword DIV changed RAX");
    expectEqual(zeroDivisor.rdx, std::uint64_t{0x8877665544332211ULL},
                "zero-divisor dword DIV changed RDX");
    expectEqual(zeroDivisor.rflags, std::uint64_t{0xAD7}, "zero-divisor dword DIV changed flags");

    addressSpace.writeU32(divisorAddress, 5);
    rosa::x86::X86State overflow;
    overflow.r13 = page.value;
    overflow.rax = 0;
    overflow.rdx = 5;
    overflow.rflags = 0xBD7;
    divideError = false;
    try {
        static_cast<void>(block.execute(overflow, &addressSpace));
    } catch (const std::runtime_error &error) {
        divideError =
            std::string_view(error.what()).find("overflows EAX") != std::string_view::npos;
    }
    expect(divideError, "overflowing dword DIV did not fault");
    expectEqual(overflow.rax, std::uint64_t{0}, "overflowing dword DIV changed RAX");
    expectEqual(overflow.rdx, std::uint64_t{5}, "overflowing dword DIV changed RDX");
    expectEqual(overflow.rflags, std::uint64_t{0xBD7}, "overflowing dword DIV changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State unmapped;
    unmapped.r13 = page.value;
    unmapped.rax = 0x12345678;
    unmapped.rdx = 0x9ABCDEF0;
    unmapped.rflags = 0xCD7;
    bool memoryFault = false;
    try {
        static_cast<void>(block.execute(unmapped, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        memoryFault = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(memoryFault, "unmapped dword DIV did not fault");
    expectEqual(unmapped.rax, std::uint64_t{0x12345678}, "unmapped dword DIV changed RAX");
    expectEqual(unmapped.rdx, std::uint64_t{0x9ABCDEF0}, "unmapped dword DIV changed RDX");
    expectEqual(unmapped.rflags, std::uint64_t{0xCD7}, "unmapped dword DIV changed flags");
}

void testSignedDivideDwordRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x41, 0xF7, 0xFD, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802C8E053ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::IdivReg, "IDIV r32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "IDIV r32 length differs");
    const auto divisor = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(divisor.reg == rosa::x86::Register::R13 && divisor.width == 32,
           "IDIV R13D operand differs");
    expect(rosa::debug::dumpX86(decoded).find("idiv r13d") != std::string::npos,
           "IDIV R13D dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("divide_signed_dword") !=
               std::string::npos,
           "IDIV R13D IR differs");

    rosa::x86::X86State liveShape;
    liveShape.rax = 0x80;
    liveShape.rdx = 0;
    liveShape.r13 = 0x20;
    liveShape.rflags = 0x46;
    static_cast<void>(block.execute(liveShape));
    expectEqual(liveShape.rax, std::uint64_t{4}, "positive IDIV quotient differs");
    expectEqual(liveShape.rdx, std::uint64_t{0}, "positive IDIV remainder differs");
    expectEqual(liveShape.r13, std::uint64_t{0x20}, "IDIV changed its divisor register");
    expectEqual(liveShape.rflags, std::uint64_t{0x46}, "IDIV changed undefined flags");

    rosa::x86::X86State negative;
    negative.rax = 0xFFFFFFF6U;
    negative.rdx = 0xFFFFFFFFU;
    negative.r13 = 3;
    negative.rflags = 0xAD7;
    static_cast<void>(block.execute(negative));
    expectEqual(negative.rax, std::uint64_t{0xFFFFFFFD}, "negative IDIV quotient differs");
    expectEqual(negative.rdx, std::uint64_t{0xFFFFFFFF}, "negative IDIV remainder differs");
    expectEqual(negative.rflags, std::uint64_t{0xAD7}, "negative IDIV changed flags");

    const auto expectDivideFault = [&](rosa::x86::X86State state, std::string_view message) {
        const auto original = state;
        bool divideError = false;
        try {
            static_cast<void>(block.execute(state));
        } catch (const std::runtime_error &error) {
            divideError =
                std::string_view(error.what()).find("divide error") != std::string_view::npos;
        }
        expect(divideError, message);
        expectEqual(state.rax, original.rax, "faulted IDIV changed RAX");
        expectEqual(state.rdx, original.rdx, "faulted IDIV changed RDX");
        expectEqual(state.r13, original.r13, "faulted IDIV changed its divisor");
        expectEqual(state.rflags, original.rflags, "faulted IDIV changed flags");
    };
    expectDivideFault(
        rosa::x86::X86State{.rax = 0x11223344, .rdx = 0x55667788, .r13 = 0, .rflags = 0x8D7},
        "zero-divisor IDIV did not fault");
    expectDivideFault(rosa::x86::X86State{.rax = 0x80000000, .rdx = 0, .r13 = 1, .rflags = 0xBD7},
                      "overflowing positive IDIV did not fault");
    expectDivideFault(
        rosa::x86::X86State{.rax = 0, .rdx = 0x80000000, .r13 = 0xFFFFFFFF, .rflags = 0xCD7},
        "INT64_MIN / -1 IDIV did not fault safely");
}

void testSignedMultiply64GeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x49, 0x0F, 0xAF, 0xCD, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ImulRegReg, "IMUL r64, r64 opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 64 &&
               source.reg == rosa::x86::Register::R13 && source.width == 64,
           "IMUL rcx, r13 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("imul rcx, r13") != std::string::npos,
           "IMUL rcx, r13 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 2;
    state.r13 = static_cast<std::uint64_t>(-3);
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFFFFFFFFFFFFFFFAULL},
                "non-overflowing signed IMUL result differs");
    expectEqual(state.r13, static_cast<std::uint64_t>(-3), "signed IMUL changed its source");
    expectEqual(state.rflags, std::uint64_t{0xD6},
                "non-overflowing signed IMUL defined flags differ");

    state.rcx = static_cast<std::uint64_t>(INT64_MAX);
    state.r13 = 2;
    state.rflags = 0xD6;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFFFFFFFFFFFFFFFEULL},
                "overflowing signed IMUL low result differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "overflowing signed IMUL did not set CF and OF");

    state.rcx = std::uint64_t{1} << 63U;
    state.r13 = UINT64_MAX;
    state.rflags = 0;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{1} << 63U,
                "minimum-times-negative-one IMUL low result differs");
    expectEqual(state.rflags, std::uint64_t{0x803}, "minimum-times-negative-one IMUL flags differ");

    constexpr std::array<std::uint8_t, 4> legacyCode{0x0F, 0xAF, 0xC1, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802ACCF32ULL};
    const auto legacyDecoded = decoder.decodeBlock(legacyCode, observedRip);
    expect(legacyDecoded[0].opcode == rosa::x86::Opcode::ImulRegReg,
           "legacy IMUL r32 opcode differs");
    expectEqual(legacyDecoded[0].length, std::uint8_t{3}, "legacy IMUL r32 length differs");
    const auto legacyDestination =
        std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[0]);
    const auto legacySource = std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[1]);
    expect(legacyDestination.reg == rosa::x86::Register::Rax && legacyDestination.width == 32 &&
               legacySource.reg == rosa::x86::Register::Rcx && legacySource.width == 32,
           "legacy IMUL eax, ecx operands differ");
    expect(rosa::debug::dumpX86(legacyDecoded).find("imul eax, ecx") != std::string::npos,
           "legacy IMUL eax, ecx dump differs");
    const auto legacyBlock = translator.translate(legacyCode, observedRip);
    rosa::x86::X86State legacyState;
    legacyState.rax = 0xAABBCCDD00000010ULL;
    legacyState.rcx = 5;
    legacyState.rflags = 0x8D7;
    static_cast<void>(legacyBlock.execute(legacyState));
    expectEqual(legacyState.rax, std::uint64_t{80},
                "legacy IMUL eax, ecx result or zero-extension differs");
    expectEqual(legacyState.rcx, std::uint64_t{5}, "legacy IMUL eax, ecx changed its source");
    expectEqual(legacyState.rflags, std::uint64_t{0xD6},
                "non-overflowing legacy IMUL flags differ");

    legacyState.rax = static_cast<std::uint32_t>(INT32_MAX);
    legacyState.rcx = 2;
    legacyState.rflags = 0xD6;
    static_cast<void>(legacyBlock.execute(legacyState));
    expectEqual(legacyState.rax, std::uint64_t{0xFFFFFFFE},
                "overflowing legacy IMUL low result differs");
    expectEqual(legacyState.rflags, std::uint64_t{0x8D7},
                "overflowing legacy IMUL did not set CF and OF");

    constexpr std::array<std::uint8_t, 5> extendedCode{0x45, 0x0F, 0xAF, 0xF1, 0xC3};
    constexpr rosa::guest::GuestAddress extendedRip{0x7FF802C685B8ULL};
    const auto extendedDecoded = decoder.decodeBlock(extendedCode, extendedRip);
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::ImulRegReg,
           "REX IMUL r32, r32 opcode differs");
    expectEqual(extendedDecoded[0].length, std::uint8_t{4}, "REX IMUL r32, r32 length differs");
    const auto extendedDestination =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]);
    expect(extendedDestination.reg == rosa::x86::Register::R14 && extendedDestination.width == 32 &&
               extendedSource.reg == rosa::x86::Register::R9 && extendedSource.width == 32,
           "IMUL r14d, r9d operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("imul r14d, r9d") != std::string::npos,
           "REX IMUL r32, r32 dump differs");

    const auto extendedBlock = translator.translate(extendedCode, extendedRip);
    rosa::x86::X86State extendedState;
    extendedState.r14 = 0xAAAAAAAAFFFFFFFDULL;
    extendedState.r9 = 7;
    extendedState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.r14, std::uint64_t{0xFFFFFFEB},
                "REX IMUL r32 result or zero-extension differs");
    expectEqual(extendedState.r9, std::uint64_t{7}, "REX IMUL r32 changed its source");
    expectEqual(extendedState.rflags, std::uint64_t{0xD6},
                "non-overflowing REX IMUL r32 flags differ");

    extendedState.r14 = 0x40000000;
    extendedState.r9 = 4;
    extendedState.rflags = 0xD6;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.r14, std::uint64_t{0}, "overflowing REX IMUL r32 low result differs");
    expectEqual(extendedState.rflags, std::uint64_t{0x8D7},
                "overflowing REX IMUL r32 did not set CF and OF");
}

void testSignedMultiply32BasedMemoryGeneratedExecution() {
    // Observed in dyld under an Objective-C fixture: IMUL esi, dword [rdi+0x4].
    constexpr std::array<std::uint8_t, 5> code{0x0F, 0xAF, 0x77, 0x04, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802A94B04ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::ImulRegMem,
           "IMUL r32, [base+disp8] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "IMUL r32, [base+disp8] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 32,
           "IMUL r32, [base+disp8] destination differs");
    expect(!memory.ripRelative && memory.hasBase &&
               memory.base == rosa::x86::Register::Rdi && !memory.index &&
               memory.displacement == 4 && memory.width == 32,
           "IMUL r32, [base+disp8] memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("imul esi, dword [rdi+0x4]") !=
               std::string::npos,
           "IMUL r32, [base+disp8] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress sourceAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(sourceAddress, 0xFFFFFFFD);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State state;
    state.rsi = 6;
    state.rdi = sourceAddress.value - 4;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    // 6 * -3 == -18, zero-extended into rsi.
    expectEqual(state.rsi, std::uint64_t{0xFFFFFFEE},
                "IMUL r32, [base+disp8] result differs");
    expectEqual(state.rflags, std::uint64_t{0xD6},
                "IMUL r32, [base+disp8] flags differ");
    expectEqual(state.rdi, sourceAddress.value - 4,
                "IMUL r32, [base+disp8] changed its base register");
}

void testSignedMultiply64RipMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 9> code{0x48, 0x0F, 0xAF, 0x35, 0x4D,
                                               0x77, 0x08, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802A8BE0BULL};
    constexpr rosa::guest::GuestAddress target{0x7FF802B13560ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::ImulRegMem,
           "IMUL r64, [RIP+disp32] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "IMUL r64, [RIP+disp32] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 64 &&
               memory.ripRelative && !memory.hasBase && memory.displacement == 0x8774D &&
               memory.width == 64,
           "IMUL rsi, qword [RIP+0x8774d] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("imul rsi, qword [rip+0x8774d]") != std::string::npos,
           "RIP-relative IMUL dump differs");

    constexpr auto pageBase =
        rosa::guest::GuestAddress{target.value & ~(rosa::guest::guestPageSize - 1)};
    std::array<std::uint8_t, rosa::guest::guestPageSize> pageBytes{};
    constexpr std::uint64_t multiplier = 3;
    std::memcpy(pageBytes.data() + (target.value - pageBase.value), &multiplier,
                sizeof(multiplier));
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(pageBase, pageBytes.size(), rosa::guest::Permission::Read, pageBytes,
                            "read-only IMUL source");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State state;
    state.rsi = 7;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rsi, std::uint64_t{21}, "RIP-relative IMUL result differs");
    expectEqual(state.rflags & (carryFlag | overflowFlag), std::uint64_t{0},
                "non-overflowing RIP-relative IMUL flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rsi = 7;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative IMUL accepted unmapped guest memory");
    expectEqual(faultState.rsi, std::uint64_t{7},
                "faulted RIP-relative IMUL changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted RIP-relative IMUL changed flags");
}

void testSignedMultiply64ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x6B, 0xD9, 0x38, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ImulRegRegImm,
           "IMUL r64, r64, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "IMUL r64, r64, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::Register::Rbx && destination.width == 64 &&
               source.reg == rosa::x86::Register::Rcx && source.width == 64 &&
               immediate.value == 0x38 && immediate.width == 8,
           "IMUL rbx, rcx, imm8 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("imul rbx, rcx, 0x38") != std::string::npos,
           "IMUL rbx, rcx, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = UINT64_MAX;
    state.rcx = 6;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rbx, std::uint64_t{0x150}, "positive immediate IMUL result differs");
    expectEqual(state.rcx, std::uint64_t{6}, "immediate IMUL changed its source");
    expectEqual(state.rflags & std::uint64_t{0x801}, std::uint64_t{0},
                "non-overflowing immediate IMUL defined flags differ");

    constexpr std::array<std::uint8_t, 5> negativeCode{0x48, 0x6B, 0xD9, 0xF8, 0xC3};
    const auto negativeDecoded =
        decoder.decodeBlock(negativeCode, rosa::guest::GuestAddress{0x2000});
    expectEqual(std::get<rosa::x86::ImmediateOperand>(negativeDecoded[0].operands[2]).value,
                std::uint64_t{0xFFFFFFFFFFFFFFF8ULL}, "IMUL imm8 was not sign-extended");
    const auto negativeBlock =
        translator.translate(negativeCode, rosa::guest::GuestAddress{0x2000});
    state.rcx = 7;
    state.rflags = 0;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rbx, std::uint64_t{0xFFFFFFFFFFFFFFC8ULL},
                "negative immediate IMUL result differs");
    expectEqual(state.rflags & std::uint64_t{0x801}, std::uint64_t{0},
                "negative non-overflowing IMUL defined flags differ");

    state.rcx = static_cast<std::uint64_t>(INT64_MAX);
    state.rflags = 0;
    static_cast<void>(block.execute(state));
    expectEqual(state.rbx, static_cast<std::uint64_t>(INT64_MAX) * std::uint64_t{0x38},
                "overflowing immediate IMUL low result differs");
    expectEqual(state.rflags & std::uint64_t{0x801}, std::uint64_t{0x801},
                "overflowing immediate IMUL did not set CF and OF");

    constexpr std::array<std::uint8_t, 5> aliasCode{0x48, 0x6B, 0xC9, 0x38, 0xC3};
    const auto aliasBlock = translator.translate(aliasCode, rosa::guest::GuestAddress{0x3000});
    state.rcx = 3;
    state.rflags = 0x8D7;
    static_cast<void>(aliasBlock.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xA8},
                "aliased immediate IMUL did not use the original source");

    constexpr std::array<std::uint8_t, 8> legacyCode{0x41, 0x69, 0xC4, 0x78,
                                                     0x08, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802AC2E3BULL};
    const auto legacyDecoded = decoder.decodeBlock(legacyCode, observedRip);
    expect(legacyDecoded[0].opcode == rosa::x86::Opcode::ImulRegRegImm,
           "IMUL r32, r32, imm32 opcode differs");
    expectEqual(legacyDecoded[0].length, std::uint8_t{7}, "IMUL r32, r32, imm32 length differs");
    const auto legacyDestination =
        std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[0]);
    const auto legacySource = std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[1]);
    const auto legacyImmediate =
        std::get<rosa::x86::ImmediateOperand>(legacyDecoded[0].operands[2]);
    expect(legacyDestination.reg == rosa::x86::Register::Rax && legacyDestination.width == 32 &&
               legacySource.reg == rosa::x86::Register::R12 && legacySource.width == 32 &&
               legacyImmediate.width == 32 && legacyImmediate.value == 0x878,
           "IMUL eax, r12d, 0x878 operands differ");
    expect(rosa::debug::dumpX86(legacyDecoded).find("imul eax, r12d, 0x878") != std::string::npos,
           "IMUL eax, r12d, 0x878 dump differs");
    const auto legacyBlock = translator.translate(legacyCode, observedRip);
    rosa::x86::X86State legacyState;
    legacyState.rax = UINT64_MAX;
    legacyState.r12 = 1;
    legacyState.rflags = 0x8D7;
    static_cast<void>(legacyBlock.execute(legacyState));
    expectEqual(legacyState.rax, std::uint64_t{0x878},
                "IMUL eax, r12d, 0x878 result or zero-extension differs");
    expectEqual(legacyState.r12, std::uint64_t{1}, "IMUL eax, r12d, 0x878 changed its source");
    expectEqual(legacyState.rflags & std::uint64_t{0x801}, std::uint64_t{0},
                "non-overflowing IMUL r32, imm32 flags differ");

    legacyState.r12 = static_cast<std::uint32_t>(INT32_MAX);
    legacyState.rflags = 0;
    static_cast<void>(legacyBlock.execute(legacyState));
    expectEqual(legacyState.rflags & std::uint64_t{0x801}, std::uint64_t{0x801},
                "overflowing IMUL r32, imm32 did not set CF and OF");
}

void testSignedMultiply64MemoryImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 9> code{0x48, 0x69, 0x45, 0xF0, 0x18,
                                               0xFC, 0xFF, 0xFF, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802D04E86ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::ImulRegMemImm,
           "IMUL r64, memory, imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "IMUL r64, memory, imm32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64 &&
               memory.base == rosa::x86::Register::Rbp && memory.hasBase && !memory.ripRelative &&
               memory.displacement == -0x10 && memory.width == 64 &&
               immediate.value == UINT64_C(0xFFFFFFFFFFFFFC18),
           "IMUL rax, qword [rbp-0x10], -1000 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("imul rax, qword [rbp-0x10], 0xfffffffffffffc18") !=
               std::string::npos,
           "memory immediate IMUL dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress source{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(source, 6);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rbp = source.value + 0x10;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, UINT64_C(0xFFFFFFFFFFFFE890), "memory immediate IMUL result differs");
    expectEqual(state.rbp, source.value + 0x10, "memory immediate IMUL changed its address base");
    expectEqual(state.rflags & std::uint64_t{0x801}, std::uint64_t{0},
                "non-overflowing memory immediate IMUL flags differ");

    addressSpace.writeU64(source, static_cast<std::uint64_t>(INT64_MAX));
    state.rflags = 0;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags & std::uint64_t{0x801}, std::uint64_t{0x801},
                "overflowing memory immediate IMUL did not set CF and OF");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x0123456789ABCDEFULL;
    faultState.rbp = source.value + 0x10;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "memory immediate IMUL accepted unmapped guest memory");
    expectEqual(faultState.rax, UINT64_C(0x0123456789ABCDEF),
                "faulted memory immediate IMUL changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted memory immediate IMUL changed flags");
}

void testShiftRightDoubleGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x48, 0x0F, 0xAC, 0xD0, 0x20, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShrdRegRegImm,
           "SHRD r64, r64, imm8 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "SHRD destination differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::Register::Rdx,
           "SHRD source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x0123456789ABCDEFULL;
    state.rdx = 0xFEDCBA9876543210ULL;
    state.rflags = 0x812;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x7654321001234567ULL}, "SHRD result differs");
    expectEqual(state.rdx, std::uint64_t{0xFEDCBA9876543210ULL}, "SHRD changed its source");
    expectEqual(state.rflags, std::uint64_t{0x813}, "SHRD flags differ");

    constexpr std::array<std::uint8_t, 6> zeroCount{
        0x48, 0x0F, 0xAC, 0xD0, 0x40, 0xC3,
    };
    const auto zeroBlock = translator.translate(zeroCount, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0x55;
    zeroState.rdx = UINT64_MAX;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x55},
                "SHRD masked-zero count changed its destination");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7}, "SHRD masked-zero count changed flags");
}

void testShiftLeftDoubleGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x4C, 0x0F, 0xA4, 0xDE, 0x3C, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C6D339ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::ShldRegRegImm,
           "SHLD RSI, R11, 0x3c opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "SHLD RSI, R11, 0x3c length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 64 &&
               source.reg == rosa::x86::Register::R11 && source.width == 64 &&
               immediate.value == 0x3C,
           "SHLD RSI, R11, 0x3c operands differ");
    expect(rosa::debug::dumpX86(decoded).find("shld rsi, r11, 0x3c") != std::string::npos,
           "SHLD RSI, R11, 0x3c dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rsi = 0x0123456789ABCDEFULL;
    state.r11 = 0xFEDCBA9876543210ULL;
    state.rflags = 0x812;
    static_cast<void>(block.execute(state));
    expectEqual(state.rsi, std::uint64_t{0xFFEDCBA987654321ULL},
                "SHLD RSI, R11, 0x3c result differs");
    expectEqual(state.r11, std::uint64_t{0xFEDCBA9876543210ULL}, "SHLD changed R11");
    expectEqual(state.rflags, std::uint64_t{0x896}, "SHLD RSI, R11, 0x3c flags differ");

    constexpr std::array<std::uint8_t, 6> oneCode{0x48, 0x0F, 0xA4, 0xD0, 0x01, 0xC3};
    const auto oneBlock = translator.translate(oneCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.rax = 0x8000000000000000ULL;
    oneState.rdx = 1;
    oneState.rflags = 0x2;
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.rax, std::uint64_t{0}, "SHLD RAX, RDX, 1 result differs");
    expectEqual(oneState.rflags, std::uint64_t{0x847}, "SHLD RAX, RDX, 1 flags differ");

    constexpr std::array<std::uint8_t, 6> zeroCode{0x48, 0x0F, 0xA4, 0xD0, 0x40, 0xC3};
    const auto zeroBlock = translator.translate(zeroCode, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0x0123456789ABCDEFULL;
    zeroState.rdx = UINT64_MAX;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x0123456789ABCDEFULL},
                "SHLD masked-zero count changed RAX");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7}, "SHLD masked-zero count changed flags");
}

void testRepStosdStore() {
    // Observed in libsystem_c under an AppKit fixture: REP STOSD.
    constexpr std::array<std::uint8_t, 3> code{0xF3, 0xAB, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802D2BD80ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::RepStosd,
           "REP STOSD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "REP STOSD length differs");
    expect(rosa::debug::dumpX86(decoded).find("rep stosd") != std::string::npos,
           "REP STOSD dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("repeat_store.i32") != std::string::npos,
           "REP STOSD did not lower through repeat-store IR");
    rosa::x86::X86State state;
    state.rdi = 0x8100;
    state.rax = 0xA5A5A5A5;
    state.rcx = 4;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    for (std::uint64_t offset = 0; offset < 4; ++offset) {
        expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{0x8100 + offset * 4}),
                    std::uint32_t{0xA5A5A5A5}, "REP STOSD stored the wrong dword");
    }
    expectEqual(state.rdi, std::uint64_t{0x8110}, "REP STOSD advanced RDI wrongly");
    expectEqual(state.rcx, std::uint64_t{0}, "REP STOSD did not exhaust RCX");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "REP STOSD changed flags");
}

void testRepStosqStore() {
    constexpr std::array<std::uint8_t, 4> code{0xF3, 0x48, 0xAB, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::RepStosq,
           "REP STOSQ opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "REP STOSQ length differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0x8100;
    state.rax = 0x1122334455667788ULL;
    state.rcx = 2;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8100}),
                std::uint64_t{0x1122334455667788ULL}, "REP STOSQ stored the wrong qword");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8108}),
                std::uint64_t{0x1122334455667788ULL}, "REP STOSQ stored the wrong tail");
    expectEqual(state.rdi, std::uint64_t{0x8110}, "REP STOSQ advanced RDI wrongly");
    expectEqual(state.rcx, std::uint64_t{0}, "REP STOSQ did not exhaust RCX");
}

void testTestR16Immediate() {
    // Observed in libdispatch under an AppKit fixture: TEST R15W, 0x3F00.
    constexpr std::array<std::uint8_t, 7> code{0x66, 0x41, 0xF7, 0xC7, 0x00, 0x3F, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802CEA00AULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegImm,
           "TEST r16 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "TEST r16 length differs");
    const auto reg = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(reg.reg == rosa::x86::Register::R15 && reg.width == 16,
           "TEST R15W operand differs");
    expect(immediate.width == 16 && immediate.value == 0x3F00,
           "TEST r16 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("test r15w, 0x3f00") != std::string::npos,
           "TEST r16 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.r15 = 0xFFFF00000000FF00ULL;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // 0xFF00 & 0x3F00 == 0x3F00: nonzero, positive.
    expectEqual(state.r15, std::uint64_t{0xFFFF00000000FF00ULL},
                "TEST r16 changed its operand");
    expect((state.rflags & 0x40U) == 0, "TEST r16 set ZF for a nonzero result");
    expect((state.rflags & 0x80U) == 0, "TEST r16 set SF for a positive result");
}

} // namespace

std::span<const TestCase> shiftAndMultiplyTests() {
    static const TestCase cases[]{
        {"REP STOSD store", testRepStosdStore},
        {"REP STOSQ store", testRepStosqStore},
        {"TEST r16 immediate", testTestR16Immediate},
        {"TEST register generated execution", testTestRegisterGeneratedExecution},
        {"TEST 16-bit registers generated execution", testTest16BitRegistersGeneratedExecution},
        {"TEST 32-bit register generated execution", testTest32BitRegisterGeneratedExecution},
        {"legacy TEST 32-bit register generated execution", testLegacyTest32BitRegisterGeneratedExecution},
        {"legacy TEST low-byte generated execution", testLegacyTestLowByteGeneratedExecution},
        {"TEST guest byte/register generated execution", testTestGuestByteRegisterGeneratedExecution},
        {"TEST guest dword/register with scaled index", testTestGuestDwordRegisterWithScaledIndex},
        {"TEST accumulator immediate generated execution", testTestAccumulatorImmediateGeneratedExecution},
        {"TEST register immediate generated execution", testTestRegisterImmediateGeneratedExecution},
        {"TEST low-byte register immediate generated execution", testTestLowByteRegisterImmediateGeneratedExecution},
        {"TEST guest byte immediate generated execution", testTestGuestByteImmediateGeneratedExecution},
        {"TEST guest dword immediate generated execution", testDwordMemoryImmediateGeneratedExecution},
        {"LFENCE generated execution", testLfenceGeneratedExecution},
        {"MFENCE generated execution", testMfenceGeneratedExecution},
        {"SIDT generated execution", testSidtGeneratedExecution},
        {"multi-byte NOP generated execution", testMultiByteNopGeneratedExecution},
        {"RDTSC generated execution", testRdtscGeneratedExecution},
        {"SHL immediate generated execution", testShiftLeftImmediateGeneratedExecution},
        {"SHL qword guest memory immediate", testShiftLeft64GuestMemoryImmediate},
        {"SHR dword guest memory immediate", testShiftRight32GuestMemoryImmediate},
        {"SHL CL generated execution", testShiftLeftClGeneratedExecution},
        {"SHL 32-bit CL generated execution", testShiftLeft32ClGeneratedExecution},
        {"SHL 8-bit CL generated execution", testShiftLeft8ClGeneratedExecution},
        {"SHR low-byte immediate generated execution", testShiftRight8ImmediateGeneratedExecution},
        {"SHR 32-bit immediate generated execution", testShiftRight32ImmediateGeneratedExecution},
        {"SHR 64-bit immediate generated execution", testShiftRight64ImmediateGeneratedExecution},
        {"SAR 64-bit immediate generated execution", testShiftRightArithmetic64ImmediateGeneratedExecution},
        {"SAR 32-bit immediate generated execution", testShiftRightArithmetic32ImmediateGeneratedExecution},
        {"ROL 16-bit immediate generated execution", testRotateLeft16ImmediateGeneratedExecution},
        {"ROL 32-bit immediate generated execution", testRotateLeft32ImmediateGeneratedExecution},
        {"ROL 64-bit immediate generated execution", testRotateLeft64ImmediateGeneratedExecution},
        {"ROL 32-bit CL generated execution", testRotateLeft32ClGeneratedExecution},
        {"ROR 64-bit immediate generated execution", testRotateRight64ImmediateGeneratedExecution},
        {"ROR 64-bit by CL generated execution", testRotateRight64ByClGeneratedExecution},
        {"SHR CL generated execution", testShiftRightClGeneratedExecution},
        {"SAR CL generated execution", testShiftRightArithmeticClGeneratedExecution},
        {"NOT 32-bit generated execution", testNot32GeneratedExecution},
        {"NEG 64-bit generated execution", testNeg64GeneratedExecution},
        {"REP MOVSB generated execution", testRepMovsbGeneratedExecution},
        {"STD/CLD direction flag generated execution", testDirectionFlagGeneratedExecution},
        {"unsigned MUL generated execution", testUnsignedMultiplyGeneratedExecution},
        {"unsigned MUL memory generated execution", testUnsignedMultiplyMemoryGeneratedExecution},
        {"signed IMUL memory generated execution", testSignedMultiplyMemoryGeneratedExecution},
        {"signed IMUL register generated execution", testSignedMultiplyRegisterGeneratedExecution},
        {"unsigned byte DIV generated execution", testUnsignedDivideByteGeneratedExecution},
        {"unsigned qword register DIV generated execution", testUnsignedDivideQwordRegisterGeneratedExecution},
        {"unsigned dword register DIV generated execution", testUnsignedDivideDwordRegisterGeneratedExecution},
        {"unsigned dword memory DIV generated execution", testUnsignedDivideDwordMemoryGeneratedExecution},
        {"DIV qword memory generated execution", testUnsignedDivideQwordMemoryGeneratedExecution},
        {"signed dword register IDIV generated execution", testSignedDivideDwordRegisterGeneratedExecution},
        {"signed IMUL 64-bit generated execution", testSignedMultiply64GeneratedExecution},
        {"signed IMUL 64-bit RIP-relative memory execution", testSignedMultiply64RipMemoryGeneratedExecution},
        {"signed IMUL 32-bit based memory execution", testSignedMultiply32BasedMemoryGeneratedExecution},
        {"signed IMUL 64-bit immediate generated execution", testSignedMultiply64ImmediateGeneratedExecution},
        {"signed IMUL 64-bit memory immediate generated execution", testSignedMultiply64MemoryImmediateGeneratedExecution},
        {"SHLD generated execution", testShiftLeftDoubleGeneratedExecution},
        {"SHRD generated execution", testShiftRightDoubleGeneratedExecution},
    };
    return cases;
}

} // namespace rosa::tests
