#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testSubRegImm32GeneratedExecution() {
    constexpr std::array<std::uint8_t, 8> positive{
        0x48, 0x81, 0xEC, 0x58, 0x06, 0x00, 0x00, 0xC3,
    };
    constexpr std::array<std::uint8_t, 8> negative{
        0x49, 0x81, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(positive, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegImm, "SUB r64, imm32 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rsp,
           "SUB r64, imm32 destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0x658}, "SUB r64, imm32 immediate differs");

    const rosa::dbt::Translator translator;
    const auto positiveBlock = translator.translate(positive, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State positiveState;
    positiveState.rsp = 0x1000;
    static_cast<void>(positiveBlock.execute(positiveState));
    expectEqual(positiveState.rsp, std::uint64_t{0x9A8}, "SUB rsp, positive imm32 result differs");
    expectEqual(positiveState.rflags, std::uint64_t{0x12}, "SUB rsp, positive imm32 flags differ");

    const auto negativeBlock = translator.translate(negative, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State negativeState;
    negativeState.r8 = 41;
    static_cast<void>(negativeBlock.execute(negativeState));
    expectEqual(negativeState.r8, std::uint64_t{42},
                "SUB r8, negative imm32 did not use sign extension");
    expectEqual(negativeState.rflags, std::uint64_t{0x13}, "SUB r8, negative imm32 flags differ");

    constexpr std::array<std::uint8_t, 7> accumulatorCode{0x48, 0x2D, 0x00, 0x10, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802B0C788ULL};
    const auto accumulatorDecoded = decoder.decodeBlock(accumulatorCode, observedRip);
    expect(accumulatorDecoded[0].opcode == rosa::x86::Opcode::SubRegImm,
           "SUB RAX, imm32 accumulator opcode differs");
    expectEqual(accumulatorDecoded[0].length, std::uint8_t{6},
                "SUB RAX, imm32 accumulator length differs");
    const auto accumulatorDestination =
        std::get<rosa::x86::RegisterOperand>(accumulatorDecoded[0].operands[0]);
    expect(accumulatorDestination.reg == rosa::x86::Register::Rax &&
               accumulatorDestination.width == 64,
           "SUB RAX, imm32 accumulator destination differs");
    expect(rosa::debug::dumpX86(accumulatorDecoded).find("sub rax, 0x1000") != std::string::npos,
           "SUB RAX, imm32 accumulator dump differs");
    const auto accumulatorBlock = translator.translate(accumulatorCode, observedRip);
    rosa::x86::X86State accumulatorState;
    accumulatorState.rax = 0x2078;
    accumulatorState.rflags = 0x8D7;
    static_cast<void>(accumulatorBlock.execute(accumulatorState));
    expectEqual(accumulatorState.rax, std::uint64_t{0x1078},
                "SUB RAX, imm32 accumulator result differs");
    expectEqual(accumulatorState.rflags, std::uint64_t{0x6},
                "SUB RAX, imm32 accumulator flags differ");

    constexpr std::array<std::uint8_t, 6> legacyAccumulatorCode{0x2D, 0x00, 0x10, 0x00, 0x00, 0xC3};
    const auto legacyAccumulatorBlock =
        translator.translate(legacyAccumulatorCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State legacyAccumulatorState;
    legacyAccumulatorState.rax = 0xAABBCCDD00002078ULL;
    static_cast<void>(legacyAccumulatorBlock.execute(legacyAccumulatorState));
    expectEqual(legacyAccumulatorState.rax, std::uint64_t{0x1078},
                "SUB EAX, imm32 accumulator did not zero-extend");
}

void testSubRegImm8GeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x83, 0xEC, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegImm, "SUB r64, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0x18}, "SUB r64, imm8 immediate differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsp = 0x100;
    static_cast<void>(block.execute(state));
    expectEqual(state.rsp, std::uint64_t{0xE8}, "SUB rsp, imm8 result differs");
    expectEqual(state.rflags, std::uint64_t{0x16}, "SUB rsp, imm8 flags differ");
}

void testSbbRegisterZeroGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x83, 0xD8, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802B05F33ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::SbbRegImm, "SBB EAX, 0 opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               immediate.value == 0,
           "SBB EAX, 0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("sbb eax, 0x0") != std::string::npos,
           "SBB EAX, 0 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802B05F33ULL});
    rosa::x86::X86State borrowState;
    borrowState.rax = 0xFFFFFFFF00000004ULL;
    borrowState.rflags = 0x93;
    static_cast<void>(block.execute(borrowState));
    expectEqual(borrowState.rax, std::uint64_t{3}, "SBB EAX, 0 did not consume incoming carry");
    expectEqual(borrowState.rflags, std::uint64_t{0x6}, "SBB EAX, 0 borrow result flags differ");

    rosa::x86::X86State clearState;
    clearState.rax = 0xFFFFFFFF00000004ULL;
    clearState.rflags = 0x92;
    static_cast<void>(block.execute(clearState));
    expectEqual(clearState.rax, std::uint64_t{4}, "SBB EAX, 0 subtracted with carry clear");
    expectEqual(clearState.rflags, std::uint64_t{0x2}, "SBB EAX, 0 carry-clear flags differ");

    constexpr std::array<std::uint8_t, 5> observedCode{0x48, 0x83, 0xDA, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C75C8CULL};
    const auto observed = decoder.decodeBlock(observedCode, observedRip);
    expect(observed[0].opcode == rosa::x86::Opcode::SbbRegImm, "SBB RDX, 0 opcode differs");
    expectEqual(observed[0].length, std::uint8_t{4}, "SBB RDX, 0 length differs");
    const auto observedDestination = std::get<rosa::x86::RegisterOperand>(observed[0].operands[0]);
    expect(observedDestination.reg == rosa::x86::Register::Rdx && observedDestination.width == 64,
           "SBB RDX, 0 destination differs");
    expect(rosa::debug::dumpX86(observed).find("sbb rdx, 0x0") != std::string::npos,
           "SBB RDX, 0 dump differs");

    const auto observedBlock = translator.translate(observedCode, observedRip);
    rosa::x86::X86State observedBorrowState;
    observedBorrowState.rdx = 2;
    observedBorrowState.rflags = 0x87;
    static_cast<void>(observedBlock.execute(observedBorrowState));
    expectEqual(observedBorrowState.rdx, std::uint64_t{1},
                "SBB RDX, 0 did not consume incoming carry");
    expectEqual(observedBorrowState.rflags, std::uint64_t{0x2},
                "SBB RDX, 0 borrow result flags differ");

    rosa::x86::X86State observedWrapState;
    observedWrapState.rdx = 0;
    observedWrapState.rflags = 0x87;
    static_cast<void>(observedBlock.execute(observedWrapState));
    expectEqual(observedWrapState.rdx, UINT64_MAX, "SBB RDX, 0 wrap result differs");
    expectEqual(observedWrapState.rflags, std::uint64_t{0x97}, "SBB RDX, 0 wrap flags differ");

    constexpr std::array<std::uint8_t, 5> negativeImmediateCode{0x48, 0x83, 0xD9, 0xFF, 0xC3};
    constexpr rosa::guest::GuestAddress negativeImmediateRip{0x7FF802D07612ULL};
    const auto negativeImmediate = decoder.decodeBlock(negativeImmediateCode, negativeImmediateRip);
    expect(negativeImmediate[0].opcode == rosa::x86::Opcode::SbbRegImm &&
               negativeImmediate[0].length == 4,
           "SBB RCX, -1 decode differs");
    expect(rosa::debug::dumpX86(negativeImmediate).find("sbb rcx, 0xffffffffffffffff") !=
               std::string::npos,
           "SBB RCX, -1 dump differs");
    const auto negativeImmediateBlock =
        translator.translate(negativeImmediateCode, negativeImmediateRip);

    rosa::x86::X86State negativeImmediateBorrowState;
    negativeImmediateBorrowState.rcx = 1;
    negativeImmediateBorrowState.rflags = 0x97;
    static_cast<void>(negativeImmediateBlock.execute(negativeImmediateBorrowState));
    expectEqual(negativeImmediateBorrowState.rcx, std::uint64_t{1},
                "SBB RCX, -1 with borrow result differs");
    expectEqual(negativeImmediateBorrowState.rflags, std::uint64_t{0x13},
                "SBB RCX, -1 with borrow flags differ");

    rosa::x86::X86State negativeImmediateOverflowState;
    negativeImmediateOverflowState.rcx = INT64_MAX;
    negativeImmediateOverflowState.rflags = 0x2;
    static_cast<void>(negativeImmediateBlock.execute(negativeImmediateOverflowState));
    expectEqual(negativeImmediateOverflowState.rcx, UINT64_C(0x8000000000000000),
                "SBB RCX, -1 overflow result differs");
    expectEqual(negativeImmediateOverflowState.rflags, std::uint64_t{0x887},
                "SBB RCX, -1 overflow flags differ");
}

void testSbbRegisterFromItselfGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x19, 0xC0, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802D107F0ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::SbbRegReg, "SBB r32, r32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "SBB r32, r32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               source.reg == destination.reg && source.width == destination.width,
           "SBB EAX, EAX operands differ");
    expect(rosa::debug::dumpX86(decoded).find("sbb eax, eax") != std::string::npos,
           "SBB EAX, EAX dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State clearState;
    clearState.rax = 0xAABBCCDD12345678ULL;
    clearState.rflags = 0x8D6;
    static_cast<void>(block.execute(clearState));
    expectEqual(clearState.rax, std::uint64_t{0},
                "SBB EAX, EAX with clear carry did not produce zero");
    expectEqual(clearState.rflags, std::uint64_t{0x46}, "SBB EAX, EAX clear-carry flags differ");

    rosa::x86::X86State setState;
    setState.rax = 0xAABBCCDD12345678ULL;
    setState.rflags = 0x8D7;
    static_cast<void>(block.execute(setState));
    expectEqual(setState.rax, std::uint64_t{UINT32_MAX},
                "SBB EAX, EAX with set carry did not produce -1");
    expectEqual(setState.rflags, std::uint64_t{0x97}, "SBB EAX, EAX set-carry flags differ");
}

void testSbbAccumulatorImmediateGeneratedExecution() {
    // Observed in libsqlite3: SBB AL, 0xFF (opcode 1C).
    constexpr std::array<std::uint8_t, 3> code{0x1C, 0xFF, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x10007A56FULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::SbbRegImm, "SBB AL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "SBB AL, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8 &&
               immediate.value == 0xFF && immediate.width == 8,
           "SBB AL, 0xFF operands differ");
    expect(rosa::debug::dumpX86(decoded).find("sbb al, 0xff") != std::string::npos,
           "SBB AL, 0xFF dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State clearState;
    clearState.rax = 0xAABBCCDD12345600ULL;
    clearState.rflags = 0x8D6;
    static_cast<void>(block.execute(clearState));
    expectEqual(clearState.rax, std::uint64_t{0xAABBCCDD12345601ULL},
                "SBB AL, 0xFF with clear carry result differs");
    expectEqual(clearState.rflags, std::uint64_t{0x13},
                "SBB AL, 0xFF clear-carry flags differ");

    rosa::x86::X86State setState;
    setState.rax = 0xAABBCCDD12345600ULL;
    setState.rflags = 0x8D7;
    static_cast<void>(block.execute(setState));
    expectEqual(setState.rax, std::uint64_t{0xAABBCCDD12345600ULL},
                "SBB AL, 0xFF with set carry result differs");
    expectEqual(setState.rflags, std::uint64_t{0x57}, "SBB AL, 0xFF set-carry flags differ");
}

void testAdcByteRegisterImmediateGeneratedExecution() {
    // Observed in libswiftCore under an Objective-C fixture: ADC dl, 1.
    constexpr std::array<std::uint8_t, 4> code{0x80, 0xD2, 0x01, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8171A2B78ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::AdcRegImm, "ADC dl, 1 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "ADC dl, 1 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 8 &&
               immediate.value == 1 && immediate.width == 8,
           "ADC dl, 1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("adc dl, 0x1") != std::string::npos,
           "ADC dl, 1 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State carryState;
    carryState.rdx = 0x00000000000000FFULL;
    carryState.rflags = 0x8D7;
    static_cast<void>(block.execute(carryState));
    // 0xFF + 1 + CF(1) wraps to 1 with CF set.
    expectEqual(carryState.rdx, std::uint64_t{1}, "ADC dl, 1 carry result differs");
    expectEqual(carryState.rflags, std::uint64_t{0x13}, "ADC dl, 1 carry flags differ");

    rosa::x86::X86State plainState;
    plainState.rdx = 0x1122334455667705ULL;
    plainState.rsi = 0xDEADBEEFDEADBEEFULL;
    plainState.rflags = 0x8D6;
    static_cast<void>(block.execute(plainState));
    expectEqual(plainState.rdx, std::uint64_t{0x1122334455667706ULL},
                "ADC dl, 1 result differs or touched upper bytes");
    expectEqual(plainState.rsi, std::uint64_t{0xDEADBEEFDEADBEEFULL},
                "ADC dl, 1 changed an unrelated register");
    expectEqual(plainState.rflags, std::uint64_t{0x6}, "ADC dl, 1 flags differ");
}

void testAdcRegisterRegisterGeneratedExecution() {
    // Observed in libswiftCore under an Objective-C fixture: ADC rax, rsi.
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x11, 0xF0, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8171A3134ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::AdcRegReg, "ADC rax, rsi opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "ADC rax, rsi length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64 &&
               source.reg == rosa::x86::Register::Rsi && source.width == 64,
           "ADC rax, rsi operands differ");
    expect(rosa::debug::dumpX86(decoded).find("adc rax, rsi") != std::string::npos,
           "ADC rax, rsi dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State carryState;
    carryState.rax = 0xFFFFFFFFFFFFFFFFULL;
    carryState.rsi = 1;
    carryState.rflags = 0x8D7;
    static_cast<void>(block.execute(carryState));
    // 0xFF..FF + 1 + CF(1) wraps to 1 with CF set.
    expectEqual(carryState.rax, std::uint64_t{1}, "ADC rax, rsi carry result differs");
    expectEqual(carryState.rsi, std::uint64_t{1}, "ADC rax, rsi changed its source");
    expectEqual(carryState.rflags, std::uint64_t{0x13},
                "ADC rax, rsi carry flags differ");

    rosa::x86::X86State plainState;
    plainState.rax = 5;
    plainState.rsi = 3;
    plainState.rflags = 0x8D6;
    static_cast<void>(block.execute(plainState));
    expectEqual(plainState.rax, std::uint64_t{8}, "ADC rax, rsi result differs");
    expectEqual(plainState.rflags, std::uint64_t{0x2}, "ADC rax, rsi flags differ");
}

void testAdcRegisterZeroGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0x83, 0xD4, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C71B79ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::AdcRegImm, "ADC r12d, 0 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "ADC r12d, 0 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R12 && destination.width == 32 &&
               immediate.value == 0,
           "ADC r12d, 0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("adc r12d, 0x0") != std::string::npos,
           "ADC r12d, 0 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State carryState;
    carryState.r12 = 0xFFFFFFFFFFFFFFFFULL;
    carryState.rflags = 0x8D7;
    static_cast<void>(block.execute(carryState));
    expectEqual(carryState.r12, std::uint64_t{0},
                "ADC r12d, 0 did not consume incoming carry or zero-extend");
    expectEqual(carryState.rflags, std::uint64_t{0x57}, "ADC r12d, 0 carry result flags differ");

    rosa::x86::X86State clearState;
    clearState.r12 = 0xFFFFFFFF00000001ULL;
    clearState.rflags = 0x8D6;
    static_cast<void>(block.execute(clearState));
    expectEqual(clearState.r12, std::uint64_t{1},
                "ADC r12d, 0 added with carry clear or failed to zero-extend");
    expectEqual(clearState.rflags, std::uint64_t{0x2}, "ADC r12d, 0 carry-clear flags differ");

    rosa::x86::X86State overflowState;
    overflowState.r12 = 0xFFFFFFFF7FFFFFFFULL;
    overflowState.rflags = 0x3;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.r12, std::uint64_t{0x80000000},
                "ADC r12d, 0 signed-overflow result differs");
    expectEqual(overflowState.rflags, std::uint64_t{0x896},
                "ADC r12d, 0 signed-overflow flags differ");

    constexpr std::array<std::uint8_t, 4> shortImmediateCode{0x83, 0xD0, 0x01, 0xC3};
    constexpr rosa::guest::GuestAddress shortImmediateRip{0x7FF802CC0219ULL};
    const auto shortImmediateDecoded = decoder.decodeBlock(shortImmediateCode, shortImmediateRip);
    expect(shortImmediateDecoded[0].opcode == rosa::x86::Opcode::AdcRegImm,
           "ADC EAX, 1 opcode differs");
    expectEqual(shortImmediateDecoded[0].length, std::uint8_t{3}, "ADC EAX, 1 length differs");
    const auto shortImmediateDestination =
        std::get<rosa::x86::RegisterOperand>(shortImmediateDecoded[0].operands[0]);
    const auto shortImmediate =
        std::get<rosa::x86::ImmediateOperand>(shortImmediateDecoded[0].operands[1]);
    expect(shortImmediateDestination.reg == rosa::x86::Register::Rax &&
               shortImmediateDestination.width == 32 && shortImmediate.width == 8 &&
               shortImmediate.value == 1,
           "ADC EAX, 1 operands differ");
    expect(rosa::debug::dumpX86(shortImmediateDecoded).find("adc eax, 0x1") != std::string::npos,
           "ADC EAX, 1 dump differs");
    const auto shortImmediateBlock = translator.translate(shortImmediateCode, shortImmediateRip);
    rosa::x86::X86State shortImmediateState;
    shortImmediateState.rax = 0xFFFFFFFF00000000ULL;
    shortImmediateState.rflags = 0x46;
    static_cast<void>(shortImmediateBlock.execute(shortImmediateState));
    expectEqual(shortImmediateState.rax, std::uint64_t{1},
                "ADC EAX, 1 live result or zero extension differs");
    expectEqual(shortImmediateState.rflags, std::uint64_t{0x2}, "ADC EAX, 1 live flags differ");

    rosa::x86::X86State shortOverflowState;
    shortOverflowState.rax = 0xFFFFFFFF7FFFFFFEULL;
    shortOverflowState.rflags = 0x3;
    static_cast<void>(shortImmediateBlock.execute(shortOverflowState));
    expectEqual(shortOverflowState.rax, std::uint64_t{0x80000000},
                "ADC EAX, 1 carry-in overflow result differs");
    expectEqual(shortOverflowState.rflags, std::uint64_t{0x896},
                "ADC EAX, 1 carry-in overflow flags differ");

    rosa::x86::X86State shortWrapState;
    shortWrapState.rax = 0xFFFFFFFFFFFFFFFEULL;
    shortWrapState.rflags = 0x3;
    static_cast<void>(shortImmediateBlock.execute(shortWrapState));
    expectEqual(shortWrapState.rax, std::uint64_t{0}, "ADC EAX, 1 carry-in wrap result differs");
    expectEqual(shortWrapState.rflags, std::uint64_t{0x57},
                "ADC EAX, 1 carry-in wrap flags differ");

    constexpr std::array<std::uint8_t, 8> immediateCode{0x41, 0x81, 0xD4, 0xFB,
                                                        0x07, 0x00, 0x80, 0xC3};
    constexpr rosa::guest::GuestAddress immediateRip{0x7FF802C68527ULL};
    const auto immediateDecoded = decoder.decodeBlock(immediateCode, immediateRip);
    expect(immediateDecoded[0].opcode == rosa::x86::Opcode::AdcRegImm,
           "ADC r12d, imm32 opcode differs");
    expectEqual(immediateDecoded[0].length, std::uint8_t{7}, "ADC r12d, imm32 length differs");
    const auto immediateDestination =
        std::get<rosa::x86::RegisterOperand>(immediateDecoded[0].operands[0]);
    const auto fullImmediate =
        std::get<rosa::x86::ImmediateOperand>(immediateDecoded[0].operands[1]);
    expect(immediateDestination.reg == rosa::x86::Register::R12 &&
               immediateDestination.width == 32 && fullImmediate.value == 0x800007FB &&
               fullImmediate.width == 32,
           "ADC r12d, 0x800007fb operands differ");
    expect(rosa::debug::dumpX86(immediateDecoded).find("adc r12d, 0x800007fb") != std::string::npos,
           "ADC r12d, imm32 dump differs");

    const auto immediateBlock = translator.translate(immediateCode, immediateRip);
    expect(rosa::debug::dumpIr(immediateBlock.intermediateRepresentation())
                   .find("update_adc_flags.i32") != std::string::npos,
           "ADC r12d, imm32 did not lower through ADC flags IR");
    rosa::x86::X86State immediateClearState;
    immediateClearState.r12 = 0xFFFFFFFF0027F000ULL;
    immediateClearState.rflags = 0x2;
    static_cast<void>(immediateBlock.execute(immediateClearState));
    expectEqual(immediateClearState.r12, std::uint64_t{0x8027F7FB},
                "ADC r12d, imm32 carry-clear result differs");
    expectEqual(immediateClearState.rflags, std::uint64_t{0x82},
                "ADC r12d, imm32 carry-clear flags differ");

    rosa::x86::X86State immediateCarryState;
    immediateCarryState.r12 = 0xFFFFFFFF0027F000ULL;
    immediateCarryState.rflags = 0x3;
    static_cast<void>(immediateBlock.execute(immediateCarryState));
    expectEqual(immediateCarryState.r12, std::uint64_t{0x8027F7FC},
                "ADC r12d, imm32 carry-set result differs");
    expectEqual(immediateCarryState.rflags, std::uint64_t{0x86},
                "ADC r12d, imm32 carry-set flags differ");

    constexpr std::array<std::uint8_t, 5> qwordCode{0x48, 0x83, 0xD0, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress qwordRip{0x7FF802C6E43EULL};
    const auto qwordDecoded = decoder.decodeBlock(qwordCode, qwordRip);
    expect(qwordDecoded[0].opcode == rosa::x86::Opcode::AdcRegImm, "ADC RAX, 0 opcode differs");
    expectEqual(qwordDecoded[0].length, std::uint8_t{4}, "ADC RAX, 0 length differs");
    const auto qwordDestination = std::get<rosa::x86::RegisterOperand>(qwordDecoded[0].operands[0]);
    expect(qwordDestination.reg == rosa::x86::Register::Rax && qwordDestination.width == 64,
           "ADC RAX, 0 destination differs");
    expect(rosa::debug::dumpX86(qwordDecoded).find("adc rax, 0x0") != std::string::npos,
           "ADC RAX, 0 dump differs");

    const auto qwordBlock = translator.translate(qwordCode, qwordRip);
    expect(
        rosa::debug::dumpIr(qwordBlock.intermediateRepresentation()).find("update_adc_flags.i64") !=
            std::string::npos,
        "ADC RAX, 0 did not lower through 64-bit ADC flags IR");

    rosa::x86::X86State qwordClearState;
    qwordClearState.rax = 0x40;
    qwordClearState.rflags = 0x2;
    static_cast<void>(qwordBlock.execute(qwordClearState));
    expectEqual(qwordClearState.rax, std::uint64_t{0x40}, "ADC RAX, 0 carry-clear result differs");
    expectEqual(qwordClearState.rflags, std::uint64_t{0x2}, "ADC RAX, 0 carry-clear flags differ");

    rosa::x86::X86State qwordCarryState;
    qwordCarryState.rax = UINT64_MAX;
    qwordCarryState.rflags = 0x3;
    static_cast<void>(qwordBlock.execute(qwordCarryState));
    expectEqual(qwordCarryState.rax, std::uint64_t{0}, "ADC RAX, 0 carry-set result differs");
    expectEqual(qwordCarryState.rflags, std::uint64_t{0x57}, "ADC RAX, 0 carry-set flags differ");

    rosa::x86::X86State qwordOverflowState;
    qwordOverflowState.rax = INT64_MAX;
    qwordOverflowState.rflags = 0x3;
    static_cast<void>(qwordBlock.execute(qwordOverflowState));
    expectEqual(qwordOverflowState.rax, std::uint64_t{0x8000000000000000ULL},
                "ADC RAX, 0 signed-overflow result differs");
    expectEqual(qwordOverflowState.rflags, std::uint64_t{0x896},
                "ADC RAX, 0 signed-overflow flags differ");
}

void testSubRegisterFromRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x29, 0xD7, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegReg, "SUB r64, r64 opcode differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0x1028;
    state.rdx = 0x1000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x28}, "SUB r64, r64 result differs");
    expectEqual(state.rdx, std::uint64_t{0x1000}, "SUB r64, r64 changed source");
    expectEqual(state.rflags, std::uint64_t{0x6}, "SUB r64, r64 flags differ");

    constexpr std::array<std::uint8_t, 3> byteCode{0x28, 0xC1, 0xC3};
    const auto byteDecoded =
        decoder.decodeBlock(byteCode, rosa::guest::GuestAddress{0x7FF800059936ULL});
    expect(byteDecoded[0].opcode == rosa::x86::Opcode::SubRegReg, "SUB r8, r8 opcode differs");
    expectEqual(byteDecoded[0].length, std::uint8_t{2}, "SUB r8, r8 length differs");
    const auto byteDestination = std::get<rosa::x86::RegisterOperand>(byteDecoded[0].operands[0]);
    const auto byteSource = std::get<rosa::x86::RegisterOperand>(byteDecoded[0].operands[1]);
    expect(byteDestination.reg == rosa::x86::Register::Rcx && byteDestination.width == 8 &&
               byteSource.reg == rosa::x86::Register::Rax && byteSource.width == 8,
           "SUB cl, al operands differ");
    expect(rosa::debug::dumpX86(byteDecoded).find("sub cl, al") != std::string::npos,
           "SUB cl, al dump differs");
    const auto byteBlock =
        translator.translate(byteCode, rosa::guest::GuestAddress{0x7FF800059936ULL});
    rosa::x86::X86State byteBorrow;
    byteBorrow.rcx = 0x1122334455667700ULL;
    byteBorrow.rax = 0x8877665544332201ULL;
    byteBorrow.rflags = 0x8D7;
    static_cast<void>(byteBlock.execute(byteBorrow));
    expectEqual(byteBorrow.rcx, std::uint64_t{0x11223344556677FFULL},
                "SUB cl, al did not merge its low-byte result");
    expectEqual(byteBorrow.rax, std::uint64_t{0x8877665544332201ULL},
                "SUB cl, al changed its source");
    expectEqual(byteBorrow.rflags, std::uint64_t{0x97}, "SUB cl, al borrow flags differ");

    rosa::x86::X86State byteOverflow;
    byteOverflow.rcx = 0x1122334455667780ULL;
    byteOverflow.rax = 0x8877665544332201ULL;
    byteOverflow.rflags = 0x8D7;
    static_cast<void>(byteBlock.execute(byteOverflow));
    expectEqual(byteOverflow.rcx, std::uint64_t{0x112233445566777FULL},
                "SUB cl, al overflow result differs");
    expectEqual(byteOverflow.rflags, std::uint64_t{0x812}, "SUB cl, al overflow flags differ");

    bool rejectedHighByte = false;
    try {
        constexpr std::array<std::uint8_t, 2> highByte{0x28, 0xE1};
        static_cast<void>(decoder.decodeBlock(highByte, rosa::guest::GuestAddress{0x3000}));
    } catch (const rosa::x86::DecodeError &) {
        rejectedHighByte = true;
    }
    expect(rejectedHighByte, "SUB cl, ah was silently treated as a low-byte register");

    constexpr std::array<std::uint8_t, 4> extendedCode{0x45, 0x29, 0xE5, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x2000});
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::SubRegReg,
           "SUB r32, r32 opcode differs");
    expectEqual(extendedDecoded[0].length, std::uint8_t{3}, "SUB r32, r32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R13 && destination.width == 32 &&
               source.reg == rosa::x86::Register::R12 && source.width == 32,
           "SUB extended r32 operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("sub r13d, r12d") != std::string::npos,
           "SUB extended r32 dump differs");

    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State borrowState;
    borrowState.r13 = 0xAAAAAAAA00000005ULL;
    borrowState.r12 = 0xBBBBBBBB00000007ULL;
    borrowState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(borrowState));
    expectEqual(borrowState.r13, std::uint64_t{0xFFFFFFFE},
                "SUB r32 did not zero-extend its destination");
    expectEqual(borrowState.r12, std::uint64_t{0xBBBBBBBB00000007ULL},
                "SUB r32 changed its source");
    expectEqual(borrowState.rflags, std::uint64_t{0x93}, "SUB r32 borrow flags differ");

    rosa::x86::X86State overflowState;
    overflowState.r13 = 0xAAAAAAAA80000000ULL;
    overflowState.r12 = 0xBBBBBBBB00000001ULL;
    overflowState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(overflowState));
    expectEqual(overflowState.r13, std::uint64_t{0x7FFFFFFF}, "SUB r32 overflow result differs");
    expectEqual(overflowState.rflags, std::uint64_t{0x816}, "SUB r32 overflow flags differ");
}

void testSubRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x2B, 0x06, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegMem, "SUB r64, [base] opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "SUB r64, [base] destination differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsi, "SUB r64, [base] base differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8100}, 7);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 5;
    state.rsi = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{UINT64_MAX - 1}, "SUB r64, [base] result differs");
    expectEqual(state.rsi, std::uint64_t{0x8100}, "SUB r64, [base] changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x93}, "SUB r64, [base] flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 5;
    faultState.rsi = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "SUB from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{5},
                "failed memory SUB changed its destination register");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "failed memory SUB changed flags");

    constexpr std::array<std::uint8_t, 8> observedCode{0x48, 0x2B, 0x1D, 0xD8,
                                                       0x26, 0x61, 0x3D, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802A43559ULL};
    constexpr rosa::guest::GuestAddress observedTarget{0x7FF840055C38ULL};
    const auto observed = decoder.decodeBlock(observedCode, observedRip);
    expect(observed[0].opcode == rosa::x86::Opcode::SubRegMem, "RIP-relative SUB opcode differs");
    expectEqual(observed[0].length, std::uint8_t{7}, "RIP-relative SUB length differs");
    const auto observedDestination = std::get<rosa::x86::RegisterOperand>(observed[0].operands[0]);
    const auto observedMemory = std::get<rosa::x86::MemoryOperand>(observed[0].operands[1]);
    expect(observedDestination.reg == rosa::x86::Register::Rbx && observedDestination.width == 64 &&
               observedMemory.ripRelative && !observedMemory.hasBase && !observedMemory.index &&
               observedMemory.width == 64 && observedMemory.displacement == 0x3D6126D8,
           "RIP-relative SUB operands differ");
    expectEqual(observedRip.value + observed[0].length + observedMemory.displacement,
                observedTarget.value, "RIP-relative SUB target differs");
    expect(rosa::debug::dumpX86(observed).find("sub rbx, [rip+0x3d6126d8] ; 0x7ff840055c38") !=
               std::string::npos,
           "RIP-relative SUB dump differs");

    constexpr rosa::guest::GuestAddress observedPage{observedTarget.value &
                                                     ~(rosa::guest::guestPageSize - 1)};
    rosa::guest::AddressSpace observedAddressSpace;
    observedAddressSpace.mapAnonymous(observedPage, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    observedAddressSpace.writeU64(observedTarget, 0x7FF800000000ULL);
    const auto observedBlock = translator.translate(observedCode, observedRip);
    rosa::x86::X86State observedState;
    observedState.rbx = 0x7FF802A561E2ULL;
    observedState.rflags = 0x6;
    static_cast<void>(observedBlock.execute(observedState, &observedAddressSpace));
    expectEqual(observedState.rbx, std::uint64_t{0x2A561E2}, "RIP-relative SUB result differs");
    expectEqual(observedState.rflags, std::uint64_t{0x6}, "RIP-relative SUB flags differ");

    rosa::guest::AddressSpace observedUnmappedAddressSpace;
    observedState.rbx = 0x7FF802A561E2ULL;
    observedState.rflags = 0xAD7;
    bool observedFaulted = false;
    try {
        static_cast<void>(observedBlock.execute(observedState, &observedUnmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        observedFaulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(observedFaulted, "RIP-relative SUB accepted unmapped memory");
    expectEqual(observedState.rbx, std::uint64_t{0x7FF802A561E2ULL},
                "faulted RIP-relative SUB changed RBX");
    expectEqual(observedState.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative SUB changed flags");
}

void testSub32BitRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x2B, 0x56, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegMem,
           "SUB r32, [base+disp8] opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 32,
           "SUB EDX, [base+disp8] destination differs");
    expect(memory.base == rosa::x86::Register::Rsi && memory.displacement == 0x18 &&
               memory.width == 32,
           "SUB EDX, [RSI+disp8] memory operand differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 8> sourceWithUpperSentinel{7,    0,    0,    0,
                                                                  0xEF, 0xBE, 0xAD, 0xDE};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8118}, sourceWithUpperSentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0xA5A5A5A500000005ULL;
    state.rsi = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdx, std::uint64_t{0xFFFFFFFE},
                "SUB r32, [memory] result did not zero-extend");
    expectEqual(state.rflags, std::uint64_t{0x93}, "SUB r32, [memory] flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rdx = 0xA5A5A5A500000005ULL;
    state.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "SUB r32 from unmapped guest memory did not fail");
    expectEqual(state.rdx, std::uint64_t{0xA5A5A5A500000005ULL},
                "failed SUB r32 changed its destination");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "failed SUB r32 changed flags");
}

void testSub64BitRegisterFromIndexedGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x2B, 0x04, 0x0F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegMem, "indexed SUB r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "indexed SUB r64 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64,
           "indexed SUB r64 destination differs");
    expect(memory.base == rosa::x86::Register::Rdi && memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 1 && memory.displacement == 0 && memory.width == 64,
           "indexed SUB r64 memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("sub rax, [rdi+rcx]") != std::string::npos,
           "indexed SUB r64 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8120};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 7);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 5;
    state.rdi = 0x8100;
    state.rcx = 0x20;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{UINT64_MAX - 1}, "indexed SUB r64 result differs");
    expectEqual(state.rdi, std::uint64_t{0x8100}, "indexed SUB r64 changed its base");
    expectEqual(state.rcx, std::uint64_t{0x20}, "indexed SUB r64 changed its index");
    expectEqual(addressSpace.readU64(target), std::uint64_t{7},
                "indexed SUB r64 changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0x93}, "indexed SUB r64 flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rax = 5;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed SUB r64 from unmapped memory did not fault");
    expectEqual(state.rax, std::uint64_t{5}, "faulted indexed SUB r64 changed its destination");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "faulted indexed SUB r64 changed flags");
}

void testSubtractRegisterFromGuestMemoryDestination() {
    constexpr std::array<std::uint8_t, 8> code{0x49, 0x29, 0x86, 0x68, 0x08, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C6C972ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::SubMemReg,
           "SUB qword [R14+0x868], RAX opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "SUB qword [R14+0x868], RAX length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R14 && memory.hasBase && !memory.ripRelative &&
               !memory.index && memory.displacement == 0x868 && memory.width == 64 &&
               source.reg == rosa::x86::Register::Rax && source.width == 64,
           "SUB qword [R14+0x868], RAX operands differ");
    expect(rosa::debug::dumpX86(decoded).find("sub qword [r14+0x868], rax") != std::string::npos,
           "SUB qword [R14+0x868], RAX dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8868};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("sub_guest_memory.i64") !=
               std::string::npos,
           "SUB qword memory destination did not lower through RMW IR");
    rosa::x86::X86State state;
    state.r14 = page.value;
    state.rax = 1;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), UINT64_MAX,
                "SUB qword memory destination stored the wrong result");
    expectEqual(state.r14, page.value, "SUB qword memory destination changed R14");
    expectEqual(state.rax, std::uint64_t{1}, "SUB qword memory destination changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x97}, "SUB qword memory destination flags differ");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t sentinel = 7;
    std::memcpy(readOnlyBytes.data() + 0x868, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only SUB qword target");
    rosa::x86::X86State faultState;
    faultState.r14 = page.value;
    faultState.rax = 1;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "SUB qword accepted a read-only destination");
    expectEqual(readOnlyAddressSpace.readU64(target), sentinel, "faulted SUB qword changed memory");
    expectEqual(faultState.r14, page.value, "faulted SUB qword changed R14");
    expectEqual(faultState.rax, std::uint64_t{1}, "faulted SUB qword changed RAX");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted SUB qword changed flags");
}

void testSubtractByteRegisterFromGuestMemory() {
    // Observed in sqlite: SUB byte [RIP+disp32], R14B with REX.R.
    constexpr std::array<std::uint8_t, 8> code{0x44, 0x28, 0x35, 0x29, 0x9A,
                                              0x1A, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10004BA88ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubMemReg,
           "SUB byte [memory], r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "SUB byte [memory], r8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0x1A9A29 && source.reg == rosa::x86::Register::R14 &&
               source.width == 8,
           "SUB byte [RIP+disp32], R14B operands differ");
    expect(rosa::debug::dumpX86(decoded).find("sub byte [rip+0x1a9a29], r14b") !=
               std::string::npos,
           "SUB byte [RIP+disp32], R14B dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    constexpr rosa::guest::GuestAddress syntheticRip{0x7F00};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> initial{0x30};
    addressSpace.writeBytes(target, initial);
    const rosa::dbt::Translator translator;
    // Execute at a synthetic RIP whose computed target stays in the page.
    constexpr std::array<std::uint8_t, 8> executableCode{0x44, 0x28, 0x35, 0xF9,
                                                         0x01, 0x00, 0x00, 0xC3};
    const auto block = translator.translate(executableCode, syntheticRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("sub_guest_memory.i8") !=
               std::string::npos,
           "SUB byte memory did not lower through 8-bit guest-memory IR");
    rosa::x86::X86State state;
    state.r14 = 0xAABBCCDD00000009ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0x27},
                "SUB byte memory result differs");
    expectEqual(state.r14, std::uint64_t{0xAABBCCDD00000009ULL},
                "SUB byte memory changed its source");
    expectEqual(state.rflags, std::uint64_t{0x16}, "SUB byte memory flags differ");
}

void testAddRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x03, 0x46, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegMem,
           "ADD r64, [base+disp8] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsi, "ADD r64, [base+disp8] base differs");
    expectEqual(memory.displacement, std::int64_t{0x10},
                "ADD r64, [base+disp8] displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8110}, 7);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = UINT64_MAX - 2;
    state.rsi = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{4}, "ADD r64, [base+disp8] result differs");
    expectEqual(state.rflags, std::uint64_t{0x13}, "ADD r64, [base+disp8] flags differ");

    constexpr std::array<std::uint8_t, 4> dwordCode{0x03, 0x42, 0x18, 0xC3};
    const auto dwordDecoded =
        decoder.decodeBlock(dwordCode, rosa::guest::GuestAddress{0x7FF802ACF770ULL});
    expect(dwordDecoded[0].opcode == rosa::x86::Opcode::AddRegMem,
           "ADD r32, [base+disp8] opcode differs");
    const auto dwordDestination = std::get<rosa::x86::RegisterOperand>(dwordDecoded[0].operands[0]);
    const auto dwordMemory = std::get<rosa::x86::MemoryOperand>(dwordDecoded[0].operands[1]);
    expect(dwordDestination.reg == rosa::x86::Register::Rax && dwordDestination.width == 32 &&
               dwordMemory.base == rosa::x86::Register::Rdx && dwordMemory.displacement == 0x18 &&
               dwordMemory.width == 32,
           "ADD eax, [rdx+0x18] operands differ");
    expect(rosa::debug::dumpX86(dwordDecoded).find("add eax, [rdx+0x18]") != std::string::npos,
           "ADD eax, [rdx+0x18] dump differs");
    constexpr std::array<std::uint8_t, 4> eight{8, 0, 0, 0};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8118}, eight);
    const auto dwordBlock =
        translator.translate(dwordCode, rosa::guest::GuestAddress{0x7FF802ACF770ULL});
    state.rax = 0xAAAAAAAA00001000ULL;
    state.rdx = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(dwordBlock.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0x1008}, "ADD r32, [base+disp8] did not zero-extend");
    expectEqual(state.rflags, std::uint64_t{0x2}, "ADD r32, [base+disp8] flags differ");

    constexpr std::array<std::uint8_t, 8> ripRelativeCode{0x48, 0x03, 0x3D, 0xF4,
                                                          0x4B, 0x21, 0x3D, 0xC3};
    constexpr rosa::guest::GuestAddress ripRelativeAddress{0x7FF802E7D14DULL};
    constexpr rosa::guest::GuestAddress ripRelativeTarget{0x7FF840091D48ULL};
    const auto ripRelativeDecoded = decoder.decodeBlock(ripRelativeCode, ripRelativeAddress);
    const auto ripRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(ripRelativeDecoded[0].operands[1]);
    expect(ripRelativeDecoded[0].opcode == rosa::x86::Opcode::AddRegMem &&
               ripRelativeMemory.ripRelative && !ripRelativeMemory.hasBase &&
               !ripRelativeMemory.index && ripRelativeMemory.displacement == 0x3D214BF4 &&
               ripRelativeMemory.width == 64,
           "ADD rdi, [rip+disp32] operands differ");
    expect(rosa::debug::dumpX86(ripRelativeDecoded)
                   .find("add rdi, [rip+0x3d214bf4] ; 0x7ff840091d48") != std::string::npos,
           "ADD rdi, [rip+disp32] dump differs");
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{ripRelativeTarget.value & ~UINT64_C(0xFFF)},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(ripRelativeTarget, 7);
    const auto ripRelativeBlock = translator.translate(ripRelativeCode, ripRelativeAddress);
    state.rdi = 0x150;
    state.rflags = 0x8D7;
    static_cast<void>(ripRelativeBlock.execute(state, &addressSpace));
    expectEqual(state.rdi, std::uint64_t{0x157}, "ADD rdi, [rip+disp32] result differs");
    expectEqual(state.rflags, std::uint64_t{0x2}, "ADD rdi, [rip+disp32] flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 9;
    faultState.rsi = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "ADD from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{9},
                "failed memory ADD changed its destination register");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "failed memory ADD changed flags");
}

void testAddRegisterFromIndexedGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{0x4F, 0x03, 0x6C, 0x37, 0xF0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A9C612ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegMem,
           "indexed ADD r64 memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "indexed ADD r64 memory length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R13 && destination.width == 64 &&
               memory.base == rosa::x86::Register::R15 && memory.index &&
               *memory.index == rosa::x86::Register::R14 && memory.scale == 1 &&
               memory.displacement == -0x10 && memory.width == 64,
           "ADD r13, [r15+r14-0x10] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("add r13, [r15+r14*1-0x10]") != std::string::npos,
           "indexed ADD r64 memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8110};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 7);
    expectEqual(
        addressSpace.protect(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read),
        rosa::guest::ProtectResult::Success, "could not make indexed ADD source read-only");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A9C612ULL}, 1);
    rosa::x86::X86State state;
    state.r13 = UINT64_MAX - 2;
    state.r15 = 0x8100;
    state.r14 = 0x20;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r13, std::uint64_t{4}, "indexed ADD r64 memory result differs");
    expectEqual(state.r15, std::uint64_t{0x8100}, "indexed ADD r64 memory changed its base");
    expectEqual(state.r14, std::uint64_t{0x20}, "indexed ADD r64 memory changed its index");
    expectEqual(state.rflags, std::uint64_t{0x13}, "indexed ADD r64 memory flags differ");
    expectEqual(addressSpace.readU64(target), std::uint64_t{7},
                "indexed ADD r64 changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r13 = 9;
    faultState.r15 = 0x8100;
    faultState.r14 = 0x20;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed ADD r64 accepted unmapped guest memory");
    expectEqual(faultState.r13, std::uint64_t{9},
                "faulted indexed ADD r64 changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted indexed ADD r64 changed flags");
}

void testAddRegisterFromWordGuestMemory() {
    // Observed in libsqlite3: ADD ax, [rcx+rdx*2] with an operand-size override.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x03, 0x04, 0x51, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000C3A3EULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegMem,
           "word ADD r16 memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "word ADD r16 memory length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 16 &&
               memory.base == rosa::x86::Register::Rcx && memory.index &&
               *memory.index == rosa::x86::Register::Rdx && memory.scale == 2 &&
               memory.displacement == 0 && memory.width == 16,
           "ADD ax, [rcx+rdx*2] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("add ax, [rcx+rdx*2]") != std::string::npos,
           "word ADD r16 memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 2>{0x02, 0x00});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000C3A3EULL});
    rosa::x86::X86State state;
    state.rax = 0xABCD0001ULL;
    state.rcx = target.value;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0xABCD0003ULL}, "word ADD r16 memory result differs");
    expectEqual(state.rflags, std::uint64_t{0x6}, "word ADD r16 memory flags differ");
    expectEqual(state.rcx, target.value, "word ADD r16 changed its base");
    expectEqual(state.rdx, std::uint64_t{0}, "word ADD r16 changed its index");

    addressSpace.writeBytes(target, std::array<std::uint8_t, 2>{0x01, 0x00});
    rosa::x86::X86State carryState;
    carryState.rax = 0xABCDFFFFULL;
    carryState.rcx = target.value;
    carryState.rdx = 0;
    carryState.rflags = 0x2;
    static_cast<void>(block.execute(carryState, &addressSpace));
    expectEqual(carryState.rax, std::uint64_t{0xABCD0000ULL},
                "word ADD r16 carry result differs");
    expectEqual(carryState.rflags, std::uint64_t{0x57}, "word ADD r16 carry flags differ");
}

void testAddRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x4C, 0x01, 0x73, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddMemReg,
           "ADD qword [memory], r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "ADD qword [memory], r64 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.displacement == 0x10 &&
               memory.width == 64,
           "ADD qword [memory], r64 memory operand differs");
    expect(source.reg == rosa::x86::Register::R14 && source.width == 64,
           "ADD qword [memory], r64 source differs");
    expect(rosa::debug::dumpX86(decoded).find("add qword [rbx+0x10], r14") != std::string::npos,
           "ADD qword [memory], r64 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8110};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, UINT64_MAX);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.r14 = 1;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0},
                "ADD qword [memory], r64 result differs");
    expectEqual(state.rbx, std::uint64_t{0x8100}, "ADD qword [memory], r64 changed its base");
    expectEqual(state.r14, std::uint64_t{1}, "ADD qword [memory], r64 changed its source");
    expectEqual(state.rflags, std::uint64_t{0x57}, "ADD qword [memory], r64 flags differ");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t sentinel = UINT64_MAX;
    std::memcpy(readOnlyBytes.data() + 0x110, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only ADD target");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "ADD qword accepted read-only guest memory");
    expectEqual(readOnlyAddressSpace.readU64(target), sentinel,
                "faulted ADD qword changed guest memory");
    expectEqual(state.rbx, std::uint64_t{0x8100}, "faulted ADD qword changed its base");
    expectEqual(state.r14, std::uint64_t{1}, "faulted ADD qword changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "faulted ADD qword changed flags");

    constexpr std::array<std::uint8_t, 7> dwordCode{0x01, 0x85, 0x08, 0xFF, 0xFF, 0xFF, 0xC3};
    const auto dwordDecoded =
        decoder.decodeBlock(dwordCode, rosa::guest::GuestAddress{0x7FF802A180BAULL});
    expect(dwordDecoded[0].opcode == rosa::x86::Opcode::AddMemReg && dwordDecoded[0].length == 6,
           "ADD dword [memory], r32 opcode or length differs");
    const auto dwordMemory = std::get<rosa::x86::MemoryOperand>(dwordDecoded[0].operands[0]);
    const auto dwordSource = std::get<rosa::x86::RegisterOperand>(dwordDecoded[0].operands[1]);
    expect(dwordMemory.base == rosa::x86::Register::Rbp && dwordMemory.displacement == -0xF8 &&
               dwordMemory.width == 32 && dwordSource.reg == rosa::x86::Register::Rax &&
               dwordSource.width == 32,
           "ADD dword [rbp-0xf8], eax operands differ");
    expect(rosa::debug::dumpX86(dwordDecoded).find("add dword [rbp-0xf8], eax") !=
               std::string::npos,
           "ADD dword [memory], r32 dump differs");

    constexpr rosa::guest::GuestAddress dwordTarget{0x8108};
    addressSpace.writeU64(dwordTarget, 0x11223344FFFFFFFFULL);
    const auto dwordBlock =
        translator.translate(dwordCode, rosa::guest::GuestAddress{0x7FF802A180BAULL});
    rosa::x86::X86State dwordState;
    dwordState.rbp = 0x8200;
    dwordState.rax = 0xAABBCCDD00000001ULL;
    dwordState.rflags = 0x8D7;
    static_cast<void>(dwordBlock.execute(dwordState, &addressSpace));
    expectEqual(addressSpace.readU64(dwordTarget), std::uint64_t{0x1122334400000000ULL},
                "ADD dword changed its adjacent bytes or stored the wrong result");
    expectEqual(dwordState.rbp, std::uint64_t{0x8200}, "ADD dword changed its base");
    expectEqual(dwordState.rax, std::uint64_t{0xAABBCCDD00000001ULL},
                "ADD dword changed its source");
    expectEqual(dwordState.rflags, std::uint64_t{0x57}, "ADD dword carry/zero flags differ");

    constexpr rosa::guest::GuestAddress boundaryPage{0x9000};
    constexpr rosa::guest::GuestAddress boundaryTarget{0x9FFE};
    constexpr std::array<std::uint8_t, 2> boundaryBytes{0xFF, 0xFF};
    rosa::guest::AddressSpace boundaryAddressSpace;
    boundaryAddressSpace.mapAnonymous(boundaryPage, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    boundaryAddressSpace.writeBytes(boundaryTarget, boundaryBytes);
    rosa::x86::X86State boundaryState;
    boundaryState.rbp = boundaryTarget.value + 0xF8;
    boundaryState.rax = 1;
    boundaryState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(dwordBlock.execute(boundaryState, &boundaryAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page ADD dword did not fault");
    expect(boundaryAddressSpace.readBytes(boundaryTarget, 2) ==
               std::vector<std::uint8_t>(boundaryBytes.begin(), boundaryBytes.end()),
           "faulted cross-page ADD dword partially changed memory");
    expectEqual(boundaryState.rax, std::uint64_t{1},
                "faulted cross-page ADD dword changed its source");
    expectEqual(boundaryState.rflags, std::uint64_t{0xAD7},
                "faulted cross-page ADD dword changed flags");

    // Observed in libsqlite3: ADD word [rcx+0x1c], ax with an operand-size override.
    constexpr std::array<std::uint8_t, 5> wordCode{0x66, 0x01, 0x41, 0x1C, 0xC3};
    const auto wordDecoded =
        decoder.decodeBlock(wordCode, rosa::guest::GuestAddress{0x1000FE9A2ULL});
    expect(wordDecoded[0].opcode == rosa::x86::Opcode::AddMemReg &&
               wordDecoded[0].length == 4,
           "ADD word [memory], r16 opcode or length differs");
    const auto wordMemory = std::get<rosa::x86::MemoryOperand>(wordDecoded[0].operands[0]);
    const auto wordSource = std::get<rosa::x86::RegisterOperand>(wordDecoded[0].operands[1]);
    expect(wordMemory.base == rosa::x86::Register::Rcx && wordMemory.displacement == 0x1C &&
               wordMemory.width == 16 && wordSource.reg == rosa::x86::Register::Rax &&
               wordSource.width == 16,
           "ADD word [rcx+0x1c], ax operands differ");
    expect(rosa::debug::dumpX86(wordDecoded).find("add word [rcx+0x1c], ax") != std::string::npos,
           "ADD word [memory], r16 dump differs");

    constexpr rosa::guest::GuestAddress wordTarget{0x821C};
    addressSpace.writeBytes(wordTarget, std::array<std::uint8_t, 2>{0xFF, 0xFF});
    const auto wordBlock =
        translator.translate(wordCode, rosa::guest::GuestAddress{0x1000FE9A2ULL});
    rosa::x86::X86State wordState;
    wordState.rcx = 0x8200;
    wordState.rax = 0xAABBCCDD00000001ULL;
    wordState.rflags = 0x8D7;
    static_cast<void>(wordBlock.execute(wordState, &addressSpace));
    expectEqual(addressSpace.readU16(wordTarget), std::uint16_t{0},
                "ADD word [memory], r16 result differs");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{wordTarget.value + 2}, 1).front(),
                std::uint8_t{0}, "ADD word changed its adjacent byte");
    expectEqual(wordState.rcx, std::uint64_t{0x8200}, "ADD word changed its base");
    expectEqual(wordState.rax, std::uint64_t{0xAABBCCDD00000001ULL}, "ADD word changed its source");
    expectEqual(wordState.rflags, std::uint64_t{0x57}, "ADD word carry/zero flags differ");
}

void testAddRegisterToSibGuestMemory() {
    constexpr std::array<std::uint8_t, 9> code{0x4D, 0x01, 0xBC, 0x24, 0x68,
                                               0x08, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802C6AA17ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::AddMemReg,
           "SIB ADD qword [memory], r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "SIB ADD qword [memory], r64 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R12 && !memory.index &&
               memory.displacement == 0x868 && memory.width == 64 &&
               source.reg == rosa::x86::Register::R15 && source.width == 64,
           "SIB ADD qword [r12+0x868], r15 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("add qword [r12+0x868], r15") != std::string::npos,
           "SIB ADD qword [memory], r64 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8868};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, UINT64_C(0xFFFFFFFFFFFFFF00));
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.r12 = page.value;
    state.r15 = 0x140;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0x40},
                "SIB ADD qword stored the wrong result");
    expectEqual(state.r12, page.value, "SIB ADD qword changed its base");
    expectEqual(state.r15, std::uint64_t{0x140}, "SIB ADD qword changed its source");
    expectEqual(state.rflags, std::uint64_t{0x3}, "SIB ADD qword flags differ");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t sentinel = 7;
    std::memcpy(readOnlyBytes.data() + 0x868, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only SIB ADD qword target");
    rosa::x86::X86State faultState;
    faultState.r12 = page.value;
    faultState.r15 = 0x140;
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(faulted, "SIB ADD qword accepted read-only memory");
    expectEqual(readOnlyAddressSpace.readU64(target), sentinel,
                "faulted SIB ADD qword changed memory");
    expectEqual(faultState.r12, page.value, "faulted SIB ADD qword changed its base");
    expectEqual(faultState.r15, std::uint64_t{0x140}, "faulted SIB ADD qword changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted SIB ADD qword changed flags");
}

void testAddRegisterToRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x49, 0x01, 0xDD, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegReg, "ADD r64, r64 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::R13,
           "ADD r64, r64 extended destination differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::Register::Rbx,
           "ADD r64, r64 source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r13 = UINT64_MAX;
    state.rbx = 2;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r13, std::uint64_t{1}, "ADD r64, r64 result differs");
    expectEqual(state.rbx, std::uint64_t{2}, "ADD r64, r64 changed its source");
    expectEqual(state.rflags, std::uint64_t{0x13}, "ADD r64, r64 flags differ");

    constexpr std::array<std::uint8_t, 3> code32{0x01, 0xC8, 0xC3};
    const auto decoded32 = decoder.decodeBlock(code32, rosa::guest::GuestAddress{0x2000});
    expect(decoded32[0].opcode == rosa::x86::Opcode::AddRegReg, "ADD r32, r32 opcode differs");
    expectEqual(decoded32[0].length, std::uint8_t{2}, "ADD r32, r32 length differs");
    const auto destination32 = std::get<rosa::x86::RegisterOperand>(decoded32[0].operands[0]);
    const auto source32 = std::get<rosa::x86::RegisterOperand>(decoded32[0].operands[1]);
    expect(destination32.reg == rosa::x86::Register::Rax && destination32.width == 32 &&
               source32.reg == rosa::x86::Register::Rcx && source32.width == 32,
           "ADD r32, r32 operands differ");
    expect(rosa::debug::dumpX86(decoded32).find("add eax, ecx") != std::string::npos,
           "ADD r32, r32 dump differs");

    const auto block32 = translator.translate(code32, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State carryState;
    carryState.rax = UINT64_MAX;
    carryState.rcx = 1;
    carryState.rflags = 0x8D7;
    static_cast<void>(block32.execute(carryState));
    expectEqual(carryState.rax, std::uint64_t{0},
                "ADD r32, r32 did not zero-extend its destination");
    expectEqual(carryState.rcx, std::uint64_t{1}, "ADD r32, r32 changed its source");
    expectEqual(carryState.rflags, std::uint64_t{0x57}, "ADD r32, r32 carry/zero flags differ");

    rosa::x86::X86State overflowState;
    overflowState.rax = 0xAAAAAAAA7FFFFFFFULL;
    overflowState.rcx = 1;
    overflowState.rflags = 0;
    static_cast<void>(block32.execute(overflowState));
    expectEqual(overflowState.rax, std::uint64_t{0x80000000},
                "ADD r32, r32 overflow result differs");
    expectEqual(overflowState.rflags, std::uint64_t{0x896}, "ADD r32, r32 overflow flags differ");

    constexpr std::array<std::uint8_t, 4> code16{0x66, 0x01, 0xCA, 0xC3};
    const auto decoded16 =
        decoder.decodeBlock(code16, rosa::guest::GuestAddress{0x7FF802B05FD0ULL});
    const auto destination16 = std::get<rosa::x86::RegisterOperand>(decoded16[0].operands[0]);
    const auto source16 = std::get<rosa::x86::RegisterOperand>(decoded16[0].operands[1]);
    expect(decoded16[0].opcode == rosa::x86::Opcode::AddRegReg && decoded16[0].length == 3 &&
               destination16.reg == rosa::x86::Register::Rdx && destination16.width == 16 &&
               source16.reg == rosa::x86::Register::Rcx && source16.width == 16,
           "ADD DX, CX decode differs");
    expect(rosa::debug::dumpX86(decoded16).find("add dx, cx") != std::string::npos,
           "ADD r16, r16 dump differs");

    const auto block16 = translator.translate(code16, rosa::guest::GuestAddress{0x7FF802B05FD0ULL});
    rosa::x86::X86State state16;
    state16.rdx = 0x112233445566FFFFULL;
    state16.rcx = 0xFFEEDDCCBBAA0001ULL;
    state16.rflags = 0x8D7;
    static_cast<void>(block16.execute(state16));
    expectEqual(state16.rdx, std::uint64_t{0x1122334455660000ULL},
                "ADD r16, r16 did not preserve upper destination bits");
    expectEqual(state16.rcx, std::uint64_t{0xFFEEDDCCBBAA0001ULL},
                "ADD r16, r16 changed its source");
    expectEqual(state16.rflags, std::uint64_t{0x57}, "ADD r16, r16 carry/zero flags differ");
}

void testAddLowByteRegisters() {
    constexpr std::array<std::uint8_t, 4> code{0x44, 0x00, 0xCE, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegReg, "ADD r8, r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "ADD r8, r8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 8,
           "ADD r8, r8 destination differs");
    expect(source.reg == rosa::x86::Register::R9 && source.width == 8, "ADD r8, r8 source differs");
    expect(rosa::debug::dumpX86(decoded).find("add sil, r9b") != std::string::npos,
           "ADD r8, r8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.rsi = 0x112233445566777FULL;
    overflowState.r9 = 0x8877665544332201ULL;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.rsi, std::uint64_t{0x1122334455667780ULL},
                "ADD r8, r8 did not preserve upper destination bits");
    expectEqual(overflowState.r9, std::uint64_t{0x8877665544332201ULL},
                "ADD r8, r8 changed its source");
    expectEqual(overflowState.rflags, std::uint64_t{0x892}, "ADD r8 signed-overflow flags differ");

    rosa::x86::X86State carryState;
    carryState.rsi = 0xAABBCCDDEEFF00FFULL;
    carryState.r9 = 0x1020304050607001ULL;
    carryState.rflags = 0x802;
    static_cast<void>(block.execute(carryState));
    expectEqual(carryState.rsi, std::uint64_t{0xAABBCCDDEEFF0000ULL},
                "ADD r8 carry result differs");
    expectEqual(carryState.rflags, std::uint64_t{0x57}, "ADD r8 carry flags differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0x00, 0xCE, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "ADD silently represented legacy DH as SIL");
}

void testAddGuestByteToLowRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0x02, 0x34, 0x3A, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegMem,
           "ADD r8, byte [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "ADD r8, byte [memory] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 8,
           "ADD r8, byte [memory] destination differs");
    expect(memory.base == rosa::x86::Register::R10 && memory.index == rosa::x86::Register::Rdi &&
               memory.scale == 1 && memory.displacement == 0 && memory.width == 8,
           "ADD r8, byte [memory] effective address differs");
    expect(rosa::debug::dumpX86(decoded).find("add sil, [r10+rdi*1]") != std::string::npos,
           "ADD r8, byte [memory] dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> value{1};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8018}, value);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r10 = memoryBase.value;
    state.rdi = 0x18;
    state.rsi = 0x112233445566777FULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rsi, std::uint64_t{0x1122334455667780ULL},
                "ADD guest byte did not preserve upper RSI bits");
    expectEqual(state.r10, memoryBase.value, "ADD guest byte changed its base register");
    expectEqual(state.rdi, std::uint64_t{0x18}, "ADD guest byte changed its index register");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0x8018}, 1)[0], std::uint8_t{1},
                "ADD guest byte changed memory");
    expectEqual(state.rflags, std::uint64_t{0x892}, "ADD guest byte flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r10 = memoryBase.value;
    faultState.rdi = 0x18;
    faultState.rsi = 0x887766554433227FULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "ADD from unmapped guest byte did not fault");
    expectEqual(faultState.rsi, std::uint64_t{0x887766554433227FULL},
                "faulted ADD guest byte changed destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted ADD guest byte changed flags");
}

void testAddImmediateToLowByte() {
    constexpr std::array<std::uint8_t, 4> code{0x80, 0xC2, 0x04, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegImm, "ADD r8, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "ADD r8, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 8,
           "ADD DL, imm8 destination differs");
    expect(immediate.width == 8 && immediate.value == 4, "ADD DL, imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("add dl, 0x4") != std::string::npos,
           "ADD DL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.rdx = 0x112233445566777CULL;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.rdx, std::uint64_t{0x1122334455667780ULL},
                "ADD DL, imm8 did not preserve upper RDX bits");
    expectEqual(overflowState.rflags, std::uint64_t{0x892}, "ADD DL, imm8 overflow flags differ");

    rosa::x86::X86State carryState;
    carryState.rdx = 0x88776655443322FDULL;
    carryState.rflags = 0x8D7;
    static_cast<void>(block.execute(carryState));
    expectEqual(carryState.rdx, std::uint64_t{0x8877665544332201ULL},
                "ADD DL, imm8 carry result differs");
    expectEqual(carryState.rflags, std::uint64_t{0x13}, "ADD DL, imm8 carry flags differ");

    constexpr std::array<std::uint8_t, 3> accumulatorCode{0x04, 0x06, 0xC3};
    const auto accumulatorDecoded =
        decoder.decodeBlock(accumulatorCode, rosa::guest::GuestAddress{0x7FF80005997DULL});
    expect(accumulatorDecoded[0].opcode == rosa::x86::Opcode::AddRegImm,
           "ADD AL, imm8 opcode differs");
    expectEqual(accumulatorDecoded[0].length, std::uint8_t{2}, "ADD AL, imm8 length differs");
    const auto accumulatorDestination =
        std::get<rosa::x86::RegisterOperand>(accumulatorDecoded[0].operands[0]);
    const auto accumulatorImmediate =
        std::get<rosa::x86::ImmediateOperand>(accumulatorDecoded[0].operands[1]);
    expect(accumulatorDestination.reg == rosa::x86::Register::Rax &&
               accumulatorDestination.width == 8 && accumulatorImmediate.value == 6 &&
               accumulatorImmediate.width == 8,
           "ADD AL, imm8 operands differ");
    expect(rosa::debug::dumpX86(accumulatorDecoded).find("add al, 0x6") != std::string::npos,
           "ADD AL, imm8 dump differs");
    const auto accumulatorBlock =
        translator.translate(accumulatorCode, rosa::guest::GuestAddress{0x7FF80005997DULL});
    rosa::x86::X86State accumulatorState;
    accumulatorState.rax = 0xAABBCCDDEEFF0001ULL;
    accumulatorState.rflags = 0x8D7;
    static_cast<void>(accumulatorBlock.execute(accumulatorState));
    expectEqual(accumulatorState.rax, std::uint64_t{0xAABBCCDDEEFF0007ULL},
                "ADD AL, imm8 did not preserve upper RAX bits");
    expectEqual(accumulatorState.rflags, std::uint64_t{0x2}, "ADD AL, imm8 normal flags differ");

    accumulatorState.rax = 0xAABBCCDDEEFF007AULL;
    accumulatorState.rflags = 0x8D7;
    static_cast<void>(accumulatorBlock.execute(accumulatorState));
    expectEqual(accumulatorState.rax, std::uint64_t{0xAABBCCDDEEFF0080ULL},
                "ADD AL, imm8 overflow result differs");
    expectEqual(accumulatorState.rflags, std::uint64_t{0x892},
                "ADD AL, imm8 overflow flags differ");

    constexpr std::array<std::uint8_t, 4> highByteCode{0x80, 0xC4, 0x01, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "ADD silently represented legacy AH as SPL");
}

void testIncrement32BitRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x41, 0xFF, 0xC7, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::IncReg, "INC r32 opcode differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::R15, "INC extended register differs");
    expectEqual(operand.width, std::uint8_t{32}, "INC r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.r15 = 0xAAAAAAAA7FFFFFFFULL;
    overflowState.rflags = 0x8D7 | 1U;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.r15, std::uint64_t{0x80000000},
                "INC r32 did not zero-extend its result");
    expectEqual(overflowState.rflags, std::uint64_t{0x897},
                "INC r32 overflow flags differ or CF was not preserved");

    rosa::x86::X86State zeroState;
    zeroState.r15 = UINT64_MAX;
    zeroState.rflags = 0x8D6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.r15, std::uint64_t{0}, "INC r32 wrapped result differs");
    expectEqual(zeroState.rflags, std::uint64_t{0x56},
                "INC r32 zero flags differ or CF was not preserved");
}

void testIncrementLowByteRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x41, 0xFE, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::IncReg, "INC r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "INC r8 length differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::R8 && operand.width == 8, "INC r8 operand differs");
    expect(rosa::debug::dumpX86(decoded).find("inc r8b") != std::string::npos,
           "INC r8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.r8 = 0x112233445566777FULL;
    overflowState.rflags = 0x203;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.r8, std::uint64_t{0x1122334455667780ULL},
                "INC r8 did not preserve upper register bits");
    expectEqual(overflowState.rflags, std::uint64_t{0xA93},
                "INC r8 overflow flags or preserved CF differ");

    rosa::x86::X86State wrapState;
    wrapState.r8 = 0x88776655443322FFULL;
    wrapState.rflags = 0x202;
    static_cast<void>(block.execute(wrapState));
    expectEqual(wrapState.r8, std::uint64_t{0x8877665544332200ULL}, "INC r8 wrap result differs");
    expectEqual(wrapState.rflags, std::uint64_t{0x256}, "INC r8 wrap flags or preserved CF differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0xFE, 0xC4, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "INC silently represented legacy AH as SPL");
}

void testDecrement32BitRegister() {
    constexpr std::array<std::uint8_t, 3> code{0xFF, 0xCF, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::DecReg, "DEC r32 opcode differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rdi && operand.width == 32,
           "DEC EDI operand differs");
    expect(rosa::debug::dumpX86(decoded).find("dec edi") != std::string::npos,
           "DEC EDI dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 6;
    state.rflags = 1;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{5}, "DEC EDI result differs");
    expectEqual(state.rflags, std::uint64_t{0x7}, "DEC EDI flags differ or CF was not preserved");

    state.rdi = 0xAAAAAAAA00000001ULL;
    state.rflags = 0;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0}, "DEC EDI zero result did not clear upper bits");
    expectEqual(state.rflags, std::uint64_t{0x46}, "DEC EDI zero flags differ");

    state.rdi = 0xBBBBBBBB80000000ULL;
    state.rflags = 1;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x7FFFFFFF}, "DEC EDI overflow result differs");
    expectEqual(state.rflags, std::uint64_t{0x817},
                "DEC EDI overflow flags differ or CF was not preserved");
}

void testDecrement16BitRegister() {
    // Observed in libsqlite3: DEC AX with an operand-size override (66 FF /1).
    constexpr std::array<std::uint8_t, 4> code{0x66, 0xFF, 0xC8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000A8B7DULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::DecReg, "DEC r16 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "DEC r16 length differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rax && operand.width == 16,
           "DEC AX operand differs");
    expect(rosa::debug::dumpX86(decoded).find("dec ax") != std::string::npos,
           "DEC AX dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000A8B7DULL});
    rosa::x86::X86State state;
    state.rax = 0xAABBCCDD00000000ULL;
    state.rflags = 0x3;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xAABBCCDD0000FFFFULL},
                "DEC AX did not preserve upper RAX bytes");
    expectEqual(state.rflags, std::uint64_t{0x97},
                "DEC AX flags differ or CF was not preserved");

    state.rax = 0x1122334455668000ULL;
    state.rflags = 0x2;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667FFFULL},
                "DEC AX overflow result differs");
    expectEqual(state.rflags, std::uint64_t{0x816},
                "DEC AX overflow flags differ or CF was not preserved");
}

void testDecrementLowByteRegister() {
    constexpr std::array<std::uint8_t, 3> code{0xFE, 0xC8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::DecReg, "DEC r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "DEC r8 length differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rax && operand.width == 8, "DEC AL operand differs");
    expect(rosa::debug::dumpX86(decoded).find("dec al") != std::string::npos,
           "DEC AL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.rax = 0x1122334455667780ULL;
    overflowState.rflags = 0x203;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.rax, std::uint64_t{0x112233445566777FULL},
                "DEC AL did not preserve upper RAX bits");
    expectEqual(overflowState.rflags, std::uint64_t{0xA13},
                "DEC AL overflow flags or preserved CF differ");

    rosa::x86::X86State wrapState;
    wrapState.rax = 0x8877665544332200ULL;
    wrapState.rflags = 0x203;
    static_cast<void>(block.execute(wrapState));
    expectEqual(wrapState.rax, std::uint64_t{0x88776655443322FFULL}, "DEC AL wrap result differs");
    expectEqual(wrapState.rflags, std::uint64_t{0x297}, "DEC AL wrap flags or preserved CF differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0xFE, 0xCC, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "DEC silently represented legacy AH as SPL");
}

void testIncrement8BitGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0xFE, 0x44, 0x33, 0x58, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF8000500A0ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::IncMem,
           "INC byte [scaled memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "INC byte [scaled memory] length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.index &&
               *memory.index == rosa::x86::Register::Rsi && memory.scale == 1 &&
               memory.displacement == 0x58 && memory.width == 8,
           "INC byte [rbx+rsi+disp8] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("inc byte [rbx+rsi*1+0x58]") != std::string::npos,
           "INC byte [scaled memory] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8078};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF8000500A0ULL});

    constexpr std::array overflowBytes{std::uint8_t{0x11}, std::uint8_t{0x7F}, std::uint8_t{0x22}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{target.value - 1}, overflowBytes);
    rosa::x86::X86State overflowState;
    overflowState.rbx = page.value;
    overflowState.rsi = 0x20;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState, &addressSpace));
    expect(addressSpace.readBytes(rosa::guest::GuestAddress{target.value - 1}, 3) ==
               std::vector<std::uint8_t>({0x11, 0x80, 0x22}),
           "INC byte changed bytes outside its operand");
    expectEqual(overflowState.rbx, page.value, "INC byte changed its base register");
    expectEqual(overflowState.rsi, std::uint64_t{0x20}, "INC byte changed its index register");
    expectEqual(overflowState.rflags, std::uint64_t{0x893},
                "INC byte overflow flags differ or CF changed");

    addressSpace.writeBytes(target, std::array{std::uint8_t{0xFF}});
    rosa::x86::X86State wrapState;
    wrapState.rbx = page.value;
    wrapState.rsi = 0x20;
    wrapState.rflags = 0x8D6;
    static_cast<void>(block.execute(wrapState, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0},
                "INC byte wrap result differs");
    expectEqual(wrapState.rflags, std::uint64_t{0x56}, "INC byte wrap flags differ or CF changed");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0x78] = 0x7F;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only byte increment target");
    rosa::x86::X86State faultState;
    faultState.rbx = page.value;
    faultState.rsi = 0x20;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "INC byte accepted read-only guest memory");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1).front(), std::uint8_t{0x7F},
                "faulted INC byte changed guest memory");
    expectEqual(faultState.rbx, page.value, "faulted INC byte changed its base");
    expectEqual(faultState.rsi, std::uint64_t{0x20}, "faulted INC byte changed its index");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted INC byte changed flags");
}

void testIncrement16BitGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0xFF, 0x40, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::IncMem, "INC word [memory] opcode differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8100;
    state.rflags = 0x3;
    const std::array overflowValue{std::uint8_t{0xFF}, std::uint8_t{0x7F}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8118}, overflowValue);
    static_cast<void>(block.execute(state, &addressSpace));
    const auto overflowResult = addressSpace.readBytes(rosa::guest::GuestAddress{0x8118}, 2);
    expectEqual(overflowResult[0], std::uint8_t{0x00}, "INC word overflow low byte differs");
    expectEqual(overflowResult[1], std::uint8_t{0x80}, "INC word overflow high byte differs");
    expectEqual(state.rflags, std::uint64_t{0x897}, "INC word overflow flags differ or CF changed");

    const std::array wrapValue{std::uint8_t{0xFF}, std::uint8_t{0xFF}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8118}, wrapValue);
    state.rflags = 0x2;
    static_cast<void>(block.execute(state, &addressSpace));
    const auto wrapResult = addressSpace.readBytes(rosa::guest::GuestAddress{0x8118}, 2);
    expectEqual(wrapResult[0], std::uint8_t{0}, "INC word wrap low byte differs");
    expectEqual(wrapResult[1], std::uint8_t{0}, "INC word wrap high byte differs");
    expectEqual(state.rflags, std::uint64_t{0x56}, "INC word wrap flags differ or CF changed");

    constexpr std::array<std::uint8_t, 7> sibCode{0x66, 0x41, 0xFF, 0x44, 0x24, 0x0C, 0xC3};
    constexpr rosa::guest::GuestAddress sibRip{0x7FF802A30D66ULL};
    const auto sibDecoded = decoder.decodeBlock(sibCode, sibRip);
    expect(sibDecoded[0].opcode == rosa::x86::Opcode::IncMem, "SIB INC word opcode differs");
    expectEqual(sibDecoded[0].length, std::uint8_t{6}, "SIB INC word length differs");
    const auto sibMemory = std::get<rosa::x86::MemoryOperand>(sibDecoded[0].operands[0]);
    expect(sibMemory.base == rosa::x86::Register::R12 && !sibMemory.index &&
               sibMemory.displacement == 0x0C && sibMemory.width == 16,
           "INC word [r12+0xc] operand differs");
    expect(rosa::debug::dumpX86(sibDecoded).find("inc word [r12+0xc]") != std::string::npos,
           "SIB INC word dump differs");
    const auto sibBlock = translator.translate(sibCode, sibRip);
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x810C}, wrapValue);
    rosa::x86::X86State sibState;
    sibState.r12 = 0x8100;
    sibState.rflags = 0x3;
    static_cast<void>(sibBlock.execute(sibState, &addressSpace));
    expect(addressSpace.readBytes(rosa::guest::GuestAddress{0x810C}, 2) ==
               std::vector<std::uint8_t>({0, 0}),
           "SIB INC word result differs");
    expectEqual(sibState.r12, std::uint64_t{0x8100}, "SIB INC word changed R12");
    expectEqual(sibState.rflags, std::uint64_t{0x57}, "SIB INC word flags differ or CF changed");

    std::array<std::uint8_t, 0x1A> readOnlyBytes{};
    readOnlyBytes[0x0C] = 0x34;
    readOnlyBytes[0x0D] = 0x12;
    readOnlyBytes[0x18] = 0x34;
    readOnlyBytes[0x19] = 0x12;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only increment test");
    state.rax = 0x9000;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "INC word on read-only guest memory did not fault");
    const auto unchanged = readOnlyAddressSpace.readBytes(rosa::guest::GuestAddress{0x9018}, 2);
    expectEqual(unchanged[0], std::uint8_t{0x34}, "failed INC word changed low memory byte");
    expectEqual(unchanged[1], std::uint8_t{0x12}, "failed INC word changed high memory byte");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "failed INC word changed flags");

    rosa::x86::X86State sibFaultState;
    sibFaultState.r12 = 0x9000;
    sibFaultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(sibBlock.execute(sibFaultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "SIB INC word accepted read-only guest memory");
    expect(readOnlyAddressSpace.readBytes(rosa::guest::GuestAddress{0x900C}, 2) ==
               std::vector<std::uint8_t>({0x34, 0x12}),
           "faulted SIB INC word changed guest memory");
    expectEqual(sibFaultState.r12, std::uint64_t{0x9000}, "faulted SIB INC word changed R12");
    expectEqual(sibFaultState.rflags, std::uint64_t{0xBD7}, "faulted SIB INC word changed flags");
}

void testDecrement16BitGuestMemory() {
    // Observed in libsqlite3: DEC word [rsi+0x16] with an operand-size override.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0xFF, 0x4E, 0x16, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x100119592ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::DecMem, "DEC word [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "DEC word [memory] length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rsi && memory.displacement == 0x16 &&
               memory.width == 16,
           "DEC word [rsi+0x16] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("dec word [rsi+0x16]") != std::string::npos,
           "DEC word [memory] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8116};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 2>{0x00, 0x00});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x100119592ULL});
    rosa::x86::X86State state;
    state.rsi = 0x8100;
    state.rflags = 0x2;
    static_cast<void>(block.execute(state, &addressSpace));
    expect(addressSpace.readBytes(target, 2) == std::vector<std::uint8_t>({0xFF, 0xFF}),
           "DEC word wrap result differs");
    expectEqual(state.rsi, std::uint64_t{0x8100}, "DEC word changed its base");
    expectEqual(state.rflags, std::uint64_t{0x96}, "DEC word wrap flags differ or CF changed");
}

void testIncrement32BitGuestMemory() {
    constexpr std::array<std::uint8_t, 8> code{0x41, 0xFF, 0x86, 0xD0, 0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::IncMem, "INC dword [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "INC dword [memory] length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::R14 && memory.displacement == 0xD0 &&
               memory.width == 32,
           "INC dword [r14+disp32] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("inc dword [r14+0xd0]") != std::string::npos,
           "INC dword [memory] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x80D0};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});

    addressSpace.writeU64(target, 0xDEADBEEF7FFFFFFFULL);
    rosa::x86::X86State overflowState;
    overflowState.r14 = page.value;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0xDEADBEEF80000000ULL},
                "INC dword changed bytes outside its operand");
    expectEqual(overflowState.r14, page.value, "INC dword changed its base register");
    expectEqual(overflowState.rflags, std::uint64_t{0x897},
                "INC dword overflow flags differ or CF changed");

    addressSpace.writeU64(target, 0xA5A5A5A5FFFFFFFFULL);
    rosa::x86::X86State wrapState;
    wrapState.r14 = page.value;
    wrapState.rflags = 0x8D6;
    static_cast<void>(block.execute(wrapState, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0xA5A5A5A500000000ULL},
                "INC dword wrap result differs");
    expectEqual(wrapState.rflags, std::uint64_t{0x56}, "INC dword wrap flags differ or CF changed");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0xD0] = 0xFF;
    readOnlyBytes[0xD1] = 0xFF;
    readOnlyBytes[0xD2] = 0xFF;
    readOnlyBytes[0xD3] = 0x7F;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only dword increment test");
    rosa::x86::X86State faultState;
    faultState.r14 = page.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "INC dword accepted read-only guest memory");
    expectEqual(readOnlyAddressSpace.readU32(target), std::uint32_t{0x7FFFFFFF},
                "faulted INC dword changed guest memory");
    expectEqual(faultState.r14, page.value, "faulted INC dword changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted INC dword changed flags");
}

void testIncrement32BitSibGuestMemory() {
    constexpr std::array<std::uint8_t, 9> code{0x41, 0xFF, 0x84, 0x24, 0x78,
                                               0x08, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802C6AA0BULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::IncMem, "SIB INC dword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "SIB INC dword length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::R12 && !memory.index && memory.hasBase &&
               !memory.ripRelative && memory.displacement == 0x878 && memory.width == 32,
           "SIB INC dword operand differs");
    expect(rosa::debug::dumpX86(decoded).find("inc dword [r12+0x878]") != std::string::npos,
           "SIB INC dword dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8878};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 8);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.r12 = page.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{9},
                "SIB INC dword stored the wrong result");
    expectEqual(state.r12, page.value, "SIB INC dword changed its base");
    expectEqual(state.rflags, std::uint64_t{0x7}, "SIB INC dword flags differ or changed CF");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0x878] = 8;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only SIB INC dword target");
    rosa::x86::X86State faultState;
    faultState.r12 = page.value;
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(faulted, "SIB INC dword accepted read-only memory");
    expectEqual(readOnlyAddressSpace.readU32(target), std::uint32_t{8},
                "faulted SIB INC dword changed memory");
    expectEqual(faultState.r12, page.value, "faulted SIB INC dword changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted SIB INC dword changed flags");
}

void testIncrement64BitGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x49, 0xFF, 0x46, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::IncMem, "INC qword [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "INC qword [memory] length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::R14, "INC qword [memory] base differs");
    expectEqual(memory.displacement, std::int64_t{0x18}, "INC qword [memory] displacement differs");
    expectEqual(memory.width, std::uint8_t{64}, "INC qword [memory] width differs");
    expect(rosa::debug::dumpX86(decoded).find("inc qword [r14+0x18]") != std::string::npos,
           "INC qword [memory] dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0x8100;
    state.rflags = 0x3;
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8118}, INT64_MAX);
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8118}),
                std::uint64_t{0x8000000000000000ULL}, "INC qword overflow result differs");
    expectEqual(state.r14, std::uint64_t{0x8100}, "INC qword changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x897},
                "INC qword overflow flags differ or CF changed");

    addressSpace.writeU64(rosa::guest::GuestAddress{0x8118}, UINT64_MAX);
    state.rflags = 0x2;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8118}), std::uint64_t{0},
                "INC qword wrap result differs");
    expectEqual(state.rflags, std::uint64_t{0x56}, "INC qword wrap flags differ or CF changed");

    std::array<std::uint8_t, 0x20> readOnlyBytes{};
    const std::uint64_t sentinel = 0x0123456789ABCDEFULL;
    std::memcpy(readOnlyBytes.data() + 0x18, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only qword increment test");
    state.r14 = 0x9000;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "INC qword on read-only guest memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(rosa::guest::GuestAddress{0x9018}), sentinel,
                "failed INC qword changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "failed INC qword changed flags");

    constexpr std::array<std::uint8_t, 8> ripCode{0x48, 0xFF, 0x05, 0x0C, 0x3E, 0xC9, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress ripAddress{0x7FF802A1B185ULL};
    constexpr rosa::guest::GuestAddress ripTarget{0x7FF8436AEF98ULL};
    constexpr rosa::guest::GuestAddress ripPage{0x7FF8436AE000ULL};
    const auto ripDecoded = decoder.decodeBlock(ripCode, ripAddress);
    expect(ripDecoded[0].opcode == rosa::x86::Opcode::IncMem,
           "RIP-relative INC qword opcode differs");
    expectEqual(ripDecoded[0].length, std::uint8_t{7}, "RIP-relative INC qword length differs");
    const auto ripMemory = std::get<rosa::x86::MemoryOperand>(ripDecoded[0].operands[0]);
    expect(ripMemory.ripRelative && !ripMemory.hasBase && ripMemory.displacement == 0x40C93E0C &&
               ripMemory.width == 64,
           "RIP-relative INC qword operands differ");
    expect(rosa::debug::dumpX86(ripDecoded).find("inc qword [rip+0x40c93e0c] ; 0x7ff8436aef98") !=
               std::string::npos,
           "RIP-relative INC qword dump differs");

    rosa::guest::AddressSpace ripAddressSpace;
    ripAddressSpace.mapAnonymous(ripPage, rosa::guest::guestPageSize,
                                 rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    ripAddressSpace.writeU64(ripTarget, 0);
    const auto ripBlock = translator.translate(ripCode, ripAddress);
    rosa::x86::X86State ripState;
    ripState.rflags = 0x3;
    static_cast<void>(ripBlock.execute(ripState, &ripAddressSpace));
    expectEqual(ripAddressSpace.readU64(ripTarget), std::uint64_t{1},
                "RIP-relative INC qword result differs");
    expectEqual(ripState.rflags, std::uint64_t{0x3},
                "RIP-relative INC qword flags differ or changed CF");

    rosa::guest::AddressSpace ripFaultAddressSpace;
    rosa::x86::X86State ripFaultState;
    ripFaultState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(ripBlock.execute(ripFaultState, &ripFaultAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative INC qword accepted unmapped memory");
    expectEqual(ripFaultState.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative INC qword changed flags");
}

void testDecrement64BitGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0xFF, 0x4B, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::DecMem, "DEC qword memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "DEC qword memory length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.displacement == 0x18 &&
               memory.width == 64,
           "DEC qword [rbx+0x18] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("dec qword [rbx+0x18]") != std::string::npos,
           "DEC qword memory dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8000;
    state.rflags = 0x3;
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8018}, std::uint64_t{1} << 63U);
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8018}),
                std::uint64_t{0x7FFFFFFFFFFFFFFFULL}, "DEC qword overflow result differs");
    expectEqual(state.rbx, std::uint64_t{0x8000}, "DEC qword changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x817},
                "DEC qword overflow flags differ or CF changed");

    addressSpace.writeU64(rosa::guest::GuestAddress{0x8018}, 0);
    state.rflags = 0x2;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8018}), UINT64_MAX,
                "DEC qword wrap result differs");
    expectEqual(state.rflags, std::uint64_t{0x96}, "DEC qword wrap flags differ or CF changed");

    std::array<std::uint8_t, 0x20> readOnlyBytes{};
    constexpr std::uint64_t sentinel = 7;
    std::memcpy(readOnlyBytes.data() + 0x18, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only qword decrement test");
    rosa::x86::X86State faultState;
    faultState.rbx = 0x9000;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "DEC qword on read-only guest memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(rosa::guest::GuestAddress{0x9018}), sentinel,
                "failed DEC qword changed guest memory");
    expectEqual(faultState.rbx, std::uint64_t{0x9000},
                "failed DEC qword changed its base register");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed DEC qword changed flags");
}

void testDecrementRipRelativeGuestMemory() {
    // Observed in sqlite: dec qword [rip+disp32].
    constexpr std::array<std::uint8_t, 8> code{0x48, 0xFF, 0x0D, 0x02, 0xF3,
                                              0x1A, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000460AFULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::DecMem,
           "RIP-relative DEC qword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative DEC qword length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 64,
           "RIP-relative DEC qword addressing differs");
    expectEqual(memory.displacement, std::int64_t{0x1AF302},
                "RIP-relative DEC qword displacement differs");
    expect(rosa::debug::dumpX86(decoded).find("dec qword [rip+0x1af302]") != std::string::npos,
           "RIP-relative DEC qword dump differs");

    constexpr rosa::guest::GuestAddress page{0x1BF000};
    constexpr rosa::guest::GuestAddress target{0x1BF309};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10000});
    rosa::x86::X86State state;
    state.rflags = 0x3;
    addressSpace.writeU64(target, 5);
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{4},
                "RIP-relative DEC qword result differs");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "RIP-relative DEC qword flags differ or CF changed");
}

void testDecrement32BitGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0xFF, 0x4B, 0x08, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802D0EF1EULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::DecMem, "DEC dword memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "DEC dword memory length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::R11 && memory.displacement == 8 &&
               memory.width == 32,
           "DEC dword [r11+8] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("dec dword [r11+0x8]") != std::string::npos,
           "DEC dword memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8108};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.r11 = 0x8100;
    state.rflags = 0x3;
    addressSpace.writeU32(target, UINT32_C(0x80000000));
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), UINT32_C(0x7FFFFFFF),
                "DEC dword overflow result differs");
    expectEqual(state.r11, std::uint64_t{0x8100}, "DEC dword changed its base");
    expectEqual(state.rflags, std::uint64_t{0x817},
                "DEC dword overflow flags differ or CF changed");

    addressSpace.writeU32(target, 0);
    state.rflags = 0x2;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), UINT32_MAX, "DEC dword wrap result differs");
    expectEqual(state.rflags, std::uint64_t{0x96}, "DEC dword wrap flags differ or CF changed");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FFE};
    addressSpace.writeBytes(crossPageTarget, std::array<std::uint8_t, 2>{0x34, 0x12});
    rosa::x86::X86State faultState;
    faultState.r11 = crossPageTarget.value - 8;
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "cross-page DEC dword did not fault");
    expectEqual(addressSpace.readBytes(crossPageTarget, 2), std::vector<std::uint8_t>{0x34, 0x12},
                "faulted DEC dword partially changed memory");
    expectEqual(faultState.r11, crossPageTarget.value - 8, "faulted DEC dword changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted DEC dword changed flags");

    // Observed in libsqlite3: DEC dword [R12] with a no-index SIB.
    constexpr std::array<std::uint8_t, 5> sibCode{0x41, 0xFF, 0x0C, 0x24, 0xC3};
    const auto sibDecoded =
        decoder.decodeBlock(sibCode, rosa::guest::GuestAddress{0x100050E80ULL});
    expect(sibDecoded[0].opcode == rosa::x86::Opcode::DecMem,
           "DEC dword no-index SIB opcode differs");
    expectEqual(sibDecoded[0].length, std::uint8_t{4}, "DEC dword no-index SIB length differs");
    const auto sibMemory = std::get<rosa::x86::MemoryOperand>(sibDecoded[0].operands[0]);
    expect(sibMemory.base == rosa::x86::Register::R12 && !sibMemory.index &&
               sibMemory.displacement == 0 && sibMemory.width == 32,
           "DEC dword [r12] operand differs");
    expect(rosa::debug::dumpX86(sibDecoded).find("dec dword [r12]") != std::string::npos,
           "DEC dword no-index SIB dump differs");
    const auto sibBlock =
        translator.translate(sibCode, rosa::guest::GuestAddress{0x100050E80ULL});
    constexpr rosa::guest::GuestAddress sibTarget{0x8200};
    addressSpace.writeU32(sibTarget, UINT32_C(0x80000000));
    rosa::x86::X86State sibState;
    sibState.r12 = sibTarget.value;
    sibState.rflags = 0x3;
    static_cast<void>(sibBlock.execute(sibState, &addressSpace));
    expectEqual(addressSpace.readU32(sibTarget), UINT32_C(0x7FFFFFFF),
                "DEC dword no-index SIB result differs");
    expectEqual(sibState.r12, sibTarget.value, "DEC dword no-index SIB changed its base");
    expectEqual(sibState.rflags, std::uint64_t{0x817},
                "DEC dword no-index SIB flags differ or CF changed");
}

void testDecrement8BitScaledGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0xFE, 0x4C, 0x03, 0x58, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF70004F924ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::DecMem,
           "DEC byte [scaled memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "DEC byte [scaled memory] length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.index &&
               *memory.index == rosa::x86::Register::Rax && memory.scale == 1 &&
               memory.displacement == 0x58 && memory.width == 8,
           "DEC byte [rbx+rax+disp8] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("dec byte [rbx+rax*1+0x58]") != std::string::npos,
           "DEC byte [scaled memory] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8078};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF70004F924ULL});

    constexpr std::array overflowBytes{std::uint8_t{0x11}, std::uint8_t{0x80}, std::uint8_t{0x22}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{target.value - 1}, overflowBytes);
    rosa::x86::X86State overflowState;
    overflowState.rbx = page.value;
    overflowState.rax = 0x20;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState, &addressSpace));
    expect(addressSpace.readBytes(rosa::guest::GuestAddress{target.value - 1}, 3) ==
               std::vector<std::uint8_t>({0x11, 0x7F, 0x22}),
           "DEC byte changed bytes outside its operand");
    expectEqual(overflowState.rbx, page.value, "DEC byte changed its base register");
    expectEqual(overflowState.rax, std::uint64_t{0x20}, "DEC byte changed its index register");
    expectEqual(overflowState.rflags, std::uint64_t{0x813},
                "DEC byte overflow flags differ or CF changed");

    addressSpace.writeBytes(target, std::array{std::uint8_t{1}});
    rosa::x86::X86State zeroState;
    zeroState.rbx = page.value;
    zeroState.rax = 0x20;
    zeroState.rflags = 0x8D6;
    static_cast<void>(block.execute(zeroState, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0},
                "DEC byte zero result differs");
    expectEqual(zeroState.rflags, std::uint64_t{0x46}, "DEC byte zero flags differ or CF changed");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0x78] = 0x80;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only byte decrement target");
    rosa::x86::X86State faultState;
    faultState.rbx = page.value;
    faultState.rax = 0x20;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "DEC byte accepted read-only guest memory");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1).front(), std::uint8_t{0x80},
                "faulted DEC byte changed guest memory");
    expectEqual(faultState.rbx, page.value, "faulted DEC byte changed its base register");
    expectEqual(faultState.rax, std::uint64_t{0x20}, "faulted DEC byte changed its index register");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted DEC byte changed flags");
}

} // namespace

std::span<const TestCase> arithmeticTests() {
    static const TestCase cases[]{
        {"SUB register imm32 generated execution", testSubRegImm32GeneratedExecution},
        {"SUB register imm8 generated execution", testSubRegImm8GeneratedExecution},
        {"SBB register zero generated execution", testSbbRegisterZeroGeneratedExecution},
        {"SBB register from itself generated execution", testSbbRegisterFromItselfGeneratedExecution},
        {"SBB accumulator immediate generated execution", testSbbAccumulatorImmediateGeneratedExecution},
        {"ADC register zero generated execution", testAdcRegisterZeroGeneratedExecution},
        {"ADC register register generated execution", testAdcRegisterRegisterGeneratedExecution},
        {"ADC byte register immediate generated execution", testAdcByteRegisterImmediateGeneratedExecution},
        {"SUB register from register", testSubRegisterFromRegister},
        {"SUB register from guest memory", testSubRegisterFromGuestMemory},
        {"SUB 32-bit register from guest memory", testSub32BitRegisterFromGuestMemory},
        {"SUB 64-bit register from indexed guest memory", testSub64BitRegisterFromIndexedGuestMemory},
        {"SUB register from guest memory destination", testSubtractRegisterFromGuestMemoryDestination},
        {"SUB byte register from guest memory", testSubtractByteRegisterFromGuestMemory},
        {"ADD register from guest memory", testAddRegisterFromGuestMemory},
        {"ADD register from indexed guest memory", testAddRegisterFromIndexedGuestMemory},
        {"ADD word register from guest memory", testAddRegisterFromWordGuestMemory},
        {"ADD register to guest memory", testAddRegisterToGuestMemory},
        {"ADD register to SIB guest memory", testAddRegisterToSibGuestMemory},
        {"ADD register to register", testAddRegisterToRegister},
        {"ADD low-byte registers", testAddLowByteRegisters},
        {"ADD guest byte to low register", testAddGuestByteToLowRegister},
        {"ADD immediate to low byte", testAddImmediateToLowByte},
        {"INC 32-bit register", testIncrement32BitRegister},
        {"INC low-byte register", testIncrementLowByteRegister},
        {"DEC 32-bit register", testDecrement32BitRegister},
        {"DEC 16-bit register", testDecrement16BitRegister},
        {"DEC low-byte register", testDecrementLowByteRegister},
        {"INC 8-bit guest memory", testIncrement8BitGuestMemory},
        {"INC 16-bit guest memory", testIncrement16BitGuestMemory},
        {"DEC 16-bit guest memory", testDecrement16BitGuestMemory},
        {"INC 32-bit guest memory", testIncrement32BitGuestMemory},
        {"INC 32-bit SIB guest memory", testIncrement32BitSibGuestMemory},
        {"INC 64-bit guest memory", testIncrement64BitGuestMemory},
        {"DEC 64-bit guest memory", testDecrement64BitGuestMemory},
        {"DEC RIP-relative guest memory", testDecrementRipRelativeGuestMemory},
        {"DEC 32-bit guest memory", testDecrement32BitGuestMemory},
        {"DEC 8-bit scaled guest memory", testDecrement8BitScaledGuestMemory},
    };
    return cases;
}

} // namespace rosa::tests
