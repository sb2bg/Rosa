#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {



rosa::x86::X86State execute(std::span<const std::uint8_t> code) {
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rip = 0x1000;
    static_cast<void>(block.execute(state));
    return state;
}

void testR1ExecutesGeneratedCode() {
    const auto state = execute(r1Code);
    expectEqual(state.rax, std::uint64_t{42}, "R1 guest RAX differs");
    expectEqual(state.rip, std::uint64_t{0x100E}, "R1 exit RIP is not precise");
    expectEqual(state.rflags, std::uint64_t{0x2}, "R1 flags differ for 40 + 2");
}

void testAddFlagsCarryAndZero() {
    constexpr std::array<std::uint8_t, 15> code{
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x83, 0xC0, 0x01, 0xC3,
    };
    const auto state = execute(code);
    constexpr std::uint64_t expectedFlags = 0x2 | 0x1 | 0x4 | 0x10 | 0x40;
    expectEqual(state.rax, std::uint64_t{0}, "wrapping add result differs");
    expectEqual(state.rflags, expectedFlags, "CF/PF/AF/ZF flags differ");
}

void testAddFlagsSignedOverflow() {
    constexpr std::array<std::uint8_t, 15> code{
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x48, 0x83, 0xC0, 0x01, 0xC3,
    };
    const auto state = execute(code);
    constexpr std::uint64_t expectedFlags = 0x2 | 0x4 | 0x10 | 0x80 | 0x800;
    expectEqual(state.rax, std::uint64_t{0x8000000000000000ULL},
                "signed-overflow add result differs");
    expectEqual(state.rflags, expectedFlags, "PF/AF/SF/OF flags differ");
}

void testAddRegisterImmediate32() {
    constexpr std::array<std::uint8_t, 8> positive{0x48, 0x81, 0xC4, 0xB0, 0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(positive, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegImm, "ADD r64, imm32 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rsp,
           "ADD r64, imm32 destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0xB0}, "ADD r64, imm32 immediate differs");

    const rosa::dbt::Translator translator;
    const auto positiveBlock = translator.translate(positive, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsp = 0x1000;
    static_cast<void>(positiveBlock.execute(state));
    expectEqual(state.rsp, std::uint64_t{0x10B0}, "ADD r64, positive imm32 result differs");

    constexpr std::array<std::uint8_t, 8> negative{0x48, 0x81, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3};
    const auto negativeDecoded = decoder.decodeBlock(negative, rosa::guest::GuestAddress{0x2000});
    expectEqual(std::get<rosa::x86::ImmediateOperand>(negativeDecoded[0].operands[1]).value,
                UINT64_MAX, "ADD r64, imm32 did not sign-extend its immediate");
    const auto negativeBlock = translator.translate(negative, rosa::guest::GuestAddress{0x2000});
    state.rax = 0;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rax, UINT64_MAX, "ADD r64, negative imm32 result differs");
    expectEqual(state.rflags, std::uint64_t{0x86}, "ADD r64, negative imm32 flags differ");

    constexpr std::array<std::uint8_t, 8> extended{0x41, 0x81, 0xC5, 0xE0, 0xFF, 0x00, 0x00, 0xC3};
    const auto extendedDecoded = decoder.decodeBlock(extended, rosa::guest::GuestAddress{0x3000});
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::AddRegImm,
           "ADD extended r32, imm32 opcode differs");
    expectEqual(extendedDecoded[0].length, std::uint8_t{7},
                "ADD extended r32, imm32 length differs");
    const auto extendedDestination =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedImmediate =
        std::get<rosa::x86::ImmediateOperand>(extendedDecoded[0].operands[1]);
    expect(extendedDestination.reg == rosa::x86::Register::R13 && extendedDestination.width == 32,
           "ADD extended r32 destination differs");
    expect(extendedImmediate.width == 32 && extendedImmediate.value == 0xFFE0,
           "ADD r32 imm32 did not preserve its raw bit pattern");
    expect(rosa::debug::dumpX86(extendedDecoded).find("add r13d, 0xffe0") != std::string::npos,
           "ADD extended r32 dump differs");

    const auto extendedBlock = translator.translate(extended, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State carryState;
    carryState.r13 = 0xAAAAAAAAFFFF0020ULL;
    carryState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(carryState));
    expectEqual(carryState.r13, std::uint64_t{0},
                "ADD r32 imm32 did not zero-extend its wrapped result");
    expectEqual(carryState.rflags, std::uint64_t{0x47}, "ADD r32 imm32 carry flags differ");

    rosa::x86::X86State overflowState;
    overflowState.r13 = 0xAAAAAAAA7FFF0020ULL;
    overflowState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(overflowState));
    expectEqual(overflowState.r13, std::uint64_t{0x80000000},
                "ADD r32 imm32 overflow result differs");
    expectEqual(overflowState.rflags, std::uint64_t{0x886}, "ADD r32 imm32 overflow flags differ");
}

void testAddRaxAccumulatorImmediate() {
    constexpr std::array<std::uint8_t, 7> observed{0x48, 0x05, 0x5F, 0x40, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegImm,
           "ADD RAX accumulator immediate opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "ADD RAX accumulator immediate length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64,
           "ADD RAX accumulator immediate destination differs");
    expect(immediate.width == 32 && immediate.value == 0x405F,
           "ADD RAX accumulator immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("add rax, 0x405f") != std::string::npos,
           "ADD RAX accumulator immediate dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observed, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x40;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x409F}, "ADD RAX accumulator immediate result differs");
    expectEqual(state.rflags, std::uint64_t{0x6}, "ADD RAX accumulator immediate flags differ");

    constexpr std::array<std::uint8_t, 7> negative{0x48, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3};
    const auto negativeDecoded = decoder.decodeBlock(negative, rosa::guest::GuestAddress{0x2000});
    expectEqual(std::get<rosa::x86::ImmediateOperand>(negativeDecoded[0].operands[1]).value,
                UINT64_MAX, "ADD RAX accumulator imm32 was not sign-extended");
    const auto negativeBlock = translator.translate(negative, rosa::guest::GuestAddress{0x2000});
    state.rax = 0;
    state.rflags = 0;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rax, UINT64_MAX, "ADD RAX negative accumulator immediate result differs");
    expectEqual(state.rflags, std::uint64_t{0x86},
                "ADD RAX negative accumulator immediate flags differ");

    constexpr std::array<std::uint8_t, 6> legacy{0x05, 0x01, 0x00, 0x00, 0x00, 0xC3};
    const auto legacyDecoded = decoder.decodeBlock(legacy, rosa::guest::GuestAddress{0x3000});
    expectEqual(std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[0]).width,
                std::uint8_t{32}, "ADD EAX accumulator width differs");
    const auto legacyBlock = translator.translate(legacy, rosa::guest::GuestAddress{0x3000});
    state.rax = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(legacyBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0}, "ADD EAX accumulator did not zero-extend its result");
    expectEqual(state.rflags, std::uint64_t{0x57}, "ADD EAX accumulator flags differ");
}

void testAdd32BitRegisterShortImmediate() {
    constexpr std::array<std::uint8_t, 4> code{0x83, 0xC0, 0xFC, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegImm, "ADD r32, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "ADD r32, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32,
           "ADD EAX, imm8 destination differs");
    expect(immediate.width == 8 && immediate.value == UINT64_MAX - 3,
           "ADD EAX, imm8 was not sign-extended");
    expect(rosa::debug::dumpX86(decoded).find("add eax, 0xfffffffffffffffc") != std::string::npos,
           "ADD EAX, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.rax = 0xAAAAAAAA80000003ULL;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.rax, std::uint64_t{0x7FFFFFFF},
                "ADD EAX, imm8 did not zero-extend its result");
    expectEqual(overflowState.rflags, std::uint64_t{0x807},
                "ADD EAX, negative imm8 overflow flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0xBBBBBBBB00000004ULL;
    zeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0}, "ADD EAX, negative imm8 zero result differs");
    expectEqual(zeroState.rflags, std::uint64_t{0x57}, "ADD EAX, negative imm8 zero flags differ");
}

void testAndResultAndFlags() {
    constexpr std::array<std::uint8_t, 15> code{
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x83, 0xE0, 0xF0, 0xC3,
    };
    const auto state = execute(code);
    expectEqual(state.rax, std::uint64_t{0xFFFFFFFFFFFFFFF0ULL}, "AND result differs");
    expectEqual(state.rflags, std::uint64_t{0x86}, "AND PF/SF flags differ");
}

void testAnd32BitRegisters() {
    constexpr std::array<std::uint8_t, 3> code{0x21, 0xC6, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegReg, "AND r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "AND r32, r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsi = 0xAAAAAAAA0000C0CEULL;
    state.rax = 0xBBBBBBBBFFFFFF00ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rsi, std::uint64_t{0xC000}, "AND r32, r32 result or zero extension differs");
    expectEqual(state.rax, std::uint64_t{0xBBBBBBBBFFFFFF00ULL}, "AND r32, r32 changed source");
    expectEqual(state.rflags, std::uint64_t{0x6}, "AND r32, r32 flags differ");
}

void testAnd8BitRegisters() {
    constexpr std::array<std::uint8_t, 3> code{0x20, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegReg, "AND r8, r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "AND r8, r8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 8 &&
               source.reg == rosa::x86::Register::Rax && source.width == 8,
           "AND CL, AL operands differ");
    expect(rosa::debug::dumpX86(decoded).find("and cl, al") != std::string::npos,
           "AND CL, AL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1122334455667780ULL;
    state.rcx = 0x88776655443322FFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x8877665544332280ULL},
                "AND CL, AL did not preserve upper RCX bytes");
    expectEqual(state.rax, std::uint64_t{0x1122334455667780ULL}, "AND CL, AL changed its source");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "AND CL, AL defined flags differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0x20, 0xE0, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "AND AL, AH was silently treated as a low-byte register form");
}

void testAnd8BitRegisterWithSibGuestMemory() {
    // Observed in libobjc under an Objective-C fixture: AND r14b, [rdx+rdi+0xc].
    constexpr std::array<std::uint8_t, 6> code{0x44, 0x22, 0x74, 0x3A, 0x0C, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802A342C2ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegMem,
           "AND r8, byte SIB opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "AND r8, byte SIB length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R14 && destination.width == 8,
           "AND r8, byte SIB destination differs");
    expect(!memory.ripRelative && memory.hasBase &&
               memory.base == rosa::x86::Register::Rdx && memory.index &&
               *memory.index == rosa::x86::Register::Rdi && memory.scale == 1 &&
               memory.displacement == 0x0C && memory.width == 8,
           "AND r8, byte SIB memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("and r14b, byte [rdx+rdi+0xc]") !=
               std::string::npos,
           "AND r8, byte SIB dump differs");

    constexpr rosa::guest::GuestAddress sourceAddress{0x2000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(sourceAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(sourceAddress, std::array<std::uint8_t, 1>{0x3C});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = sourceAddress.value - 0x0C - 0x20;
    state.rdi = 0x20;
    state.r14 = 0x1122334455667755ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    // 0x55 & 0x3C == 0x14.
    expectEqual(state.r14, std::uint64_t{0x1122334455667714ULL},
                "AND SIB byte memory produced the wrong result");
    expectEqual(state.rflags & ((1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U)),
                std::uint64_t{1U << 2U},
                "AND SIB byte memory flags differ");
    expectEqual(state.rdx, sourceAddress.value - 0x0C - 0x20,
                "AND SIB byte memory changed its base register");
    expectEqual(state.rdi, std::uint64_t{0x20},
                "AND SIB byte memory changed its index register");
}

void testAnd8BitRegisterWithRipRelativeGuestMemory() {
    constexpr std::array<std::uint8_t, 8> observed{0x44, 0x22, 0x35, 0xE0, 0x9E, 0x06, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF80005C225ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegMem, "AND r8, byte [RIP] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "AND r8, byte [RIP] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R14 && destination.width == 8,
           "AND r8, byte [RIP] destination differs");
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0x69EE0,
           "AND r8, byte [RIP] memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("and r14b, byte [rip+0x69ee0] ; 0x7ff8000c610c") !=
               std::string::npos,
           "AND r8, byte [RIP] dump differs");

    constexpr std::array<std::uint8_t, 8> code{0x44, 0x22, 0x35, 0xF9, 0x0F, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress sourceAddress{0x2000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(sourceAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);

    const std::array sourceParity{std::uint8_t{0x0F}};
    addressSpace.writeBytes(sourceAddress, sourceParity);
    rosa::x86::X86State state;
    state.r14 = 0x11223344556677F3ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0x1122334455667703ULL},
                "AND byte memory did not preserve upper R14 bytes");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "AND byte memory parity flags differ");
    expectEqual(addressSpace.readBytes(sourceAddress, 1).front(), std::uint8_t{0x0F},
                "AND byte memory changed its source");

    const std::array sourceZero{std::uint8_t{0}};
    addressSpace.writeBytes(sourceAddress, sourceZero);
    state.r14 = UINT64_MAX;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0xFFFFFFFFFFFFFF00ULL},
                "zero AND byte memory result differs");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "zero AND byte memory flags differ");

    const std::array sourceSign{std::uint8_t{0x80}};
    addressSpace.writeBytes(sourceAddress, sourceSign);
    state.r14 = UINT64_MAX;
    state.rflags = 0;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0xFFFFFFFFFFFFFF80ULL},
                "signed AND byte memory result differs");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "signed AND byte memory flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r14 = 0xAAAAAAAA55555555ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "AND byte from unmapped guest memory did not fault");
    expectEqual(faultState.r14, std::uint64_t{0xAAAAAAAA55555555ULL},
                "faulted AND byte memory changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted AND byte memory changed flags");
}

void testAnd64BitRegisterWithGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x23, 0x70, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegMem,
           "AND r64, qword [base+disp8] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "AND r64, qword [base+disp8] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 64,
           "AND r64, qword [base+disp8] destination differs");
    expect(memory.base == rosa::x86::Register::Rax && memory.hasBase && !memory.ripRelative &&
               memory.displacement == 0x10 && memory.width == 64,
           "AND r64, qword [base+disp8] memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("and rsi, qword [rax+0x10]") != std::string::npos,
           "AND r64, qword [base+disp8] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress source{0x8010};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(source, 0x0FF00FF00FF00FF0ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = page.value;
    state.rsi = 0xF0F0F0F0F0F0F0F0ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rsi, std::uint64_t{0x00F000F000F000F0ULL},
                "AND r64, qword [base+disp8] result differs");
    expectEqual(state.rax, page.value, "AND r64, qword [base+disp8] changed its base");
    expectEqual(addressSpace.readU64(source), std::uint64_t{0x0FF00FF00FF00FF0ULL},
                "AND r64, qword [base+disp8] changed guest memory");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "AND r64, qword [base+disp8] defined flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = page.value;
    faultState.rsi = 0xAAAAAAAA55555555ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "AND qword from unmapped guest memory did not fault");
    expectEqual(faultState.rsi, std::uint64_t{0xAAAAAAAA55555555ULL},
                "faulted AND qword memory changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted AND qword memory changed flags");
}

void testAnd32BitRegisterWithGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x23, 0x47, 0x04, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegMem,
           "AND r32, dword [base+disp8] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "AND r32, dword [base+disp8] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32,
           "AND r32, dword [base+disp8] destination differs");
    expect(memory.base == rosa::x86::Register::Rdi && memory.hasBase && !memory.ripRelative &&
               memory.displacement == 4 && memory.width == 32,
           "AND r32, dword [base+disp8] memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("and eax, dword [rdi+0x4]") != std::string::npos,
           "AND r32, dword [base+disp8] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress source{0x8004};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 8> sourceAndSentinel{0xF0, 0x0F, 0xF0, 0x0F,
                                                            0xEF, 0xBE, 0xAD, 0xDE};
    addressSpace.writeBytes(source, sourceAndSentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xFFFFFFFFF0F0F0F0ULL;
    state.rdi = page.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0x00F000F0ULL},
                "AND r32, dword [base+disp8] result was not zero-extended");
    expectEqual(state.rdi, page.value, "AND r32, dword [base+disp8] changed its base");
    expect(addressSpace.readBytes(source, sourceAndSentinel.size()) ==
               std::vector<std::uint8_t>(sourceAndSentinel.begin(), sourceAndSentinel.end()),
           "AND r32, dword [base+disp8] changed guest memory");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "AND r32, dword [base+disp8] defined flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0xAAAAAAAA55555555ULL;
    faultState.rdi = page.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "AND dword from unmapped guest memory did not fault");
    expectEqual(faultState.rax, std::uint64_t{0xAAAAAAAA55555555ULL},
                "faulted AND dword memory changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted AND dword memory changed flags");

    constexpr std::array<std::uint8_t, 8> ripCode{0x44, 0x23, 0x3D, 0x9E, 0x6B, 0xE4, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802A19727ULL};
    constexpr rosa::guest::GuestAddress ripSource{rip.value + 7 + 0x40E46B9EULL};
    const auto ripDecoded = decoder.decodeBlock(ripCode, rip);
    expect(ripDecoded[0].opcode == rosa::x86::Opcode::AndRegMem,
           "RIP-relative AND r32 opcode differs");
    expectEqual(ripDecoded[0].length, std::uint8_t{7}, "RIP-relative AND r32 length differs");
    const auto ripDestination = std::get<rosa::x86::RegisterOperand>(ripDecoded[0].operands[0]);
    const auto ripMemory = std::get<rosa::x86::MemoryOperand>(ripDecoded[0].operands[1]);
    expect(ripDestination.reg == rosa::x86::Register::R15 && ripDestination.width == 32 &&
               !ripMemory.hasBase && ripMemory.ripRelative && !ripMemory.index &&
               ripMemory.displacement == 0x40E46B9E && ripMemory.width == 32,
           "AND r15d, dword [rip+disp32] operands differ");
    expect(rosa::debug::dumpX86(ripDecoded).find("and r15d, dword [rip+0x40e46b9e]") !=
               std::string::npos,
           "RIP-relative AND r32 dump differs");

    const rosa::guest::GuestAddress ripSourcePage{ripSource.value &
                                                  ~(rosa::guest::guestPageSize - 1)};
    addressSpace.mapAnonymous(ripSourcePage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(ripSource, 0x80FF00FF);
    const auto ripBlock = translator.translate(ripCode, rip);
    rosa::x86::X86State ripState;
    ripState.r15 = 0xFFFFFFFF7FFFFFFFULL;
    ripState.rflags = 0xAD7;
    static_cast<void>(ripBlock.execute(ripState, &addressSpace));
    expectEqual(ripState.r15, std::uint64_t{0x00FF00FF},
                "RIP-relative AND r32 result or zero-extension differs");
    expectEqual(addressSpace.readU32(ripSource), std::uint32_t{0x80FF00FF},
                "RIP-relative AND r32 changed guest memory");

    rosa::guest::AddressSpace unmappedRipAddressSpace;
    rosa::x86::X86State ripFaultState;
    ripFaultState.r15 = 0xAAAAAAAA55555555ULL;
    ripFaultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(ripBlock.execute(ripFaultState, &unmappedRipAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative AND r32 accepted unmapped memory");
    expectEqual(ripFaultState.r15, std::uint64_t{0xAAAAAAAA55555555ULL},
                "faulted RIP-relative AND r32 changed its destination");
    expectEqual(ripFaultState.rflags, std::uint64_t{0xBD7},
                "faulted RIP-relative AND r32 changed flags");
}

void testAnd32BitRegisterWithRspSibMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x23, 0x4C, 0x24, 0xF0, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C82EB1ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegMem,
           "AND r32, dword [rsp+disp8] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "AND r32, dword [rsp+disp8] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32,
           "AND r32, dword [rsp+disp8] destination differs");
    expect(memory.base == rosa::x86::Register::Rsp && memory.hasBase && !memory.ripRelative &&
               !memory.index && memory.displacement == -0x10 && memory.width == 32,
           "AND r32, dword [rsp+disp8] memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("and ecx, dword [rsp-0x10]") != std::string::npos,
           "AND r32, dword [rsp+disp8] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress source{0x81E8};
    constexpr std::array<std::uint8_t, 4> idtrLimit{0xFF, 0x0F, 0x00, 0x00};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(source, idtrLimit);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    rosa::x86::X86State state;
    state.rcx = 0xFFFFFFFF00000FFFULL;
    state.rsp = source.value + 0x10;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0xFFF}, "AND r32, dword [rsp+disp8] result differs");
    expectEqual(state.rsp, source.value + 0x10, "AND r32, dword [rsp+disp8] changed RSP");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "AND r32, dword [rsp+disp8] flags differ");
    expect(addressSpace.readBytes(source, idtrLimit.size()) ==
               std::vector<std::uint8_t>(idtrLimit.begin(), idtrLimit.end()),
           "AND r32, dword [rsp+disp8] changed guest memory");
}

void testAnd32BitRegisterWithIndexedSibMemory() {
    constexpr std::array<std::uint8_t, 9> code{0x41, 0x23, 0x94, 0xB6, 0x28,
                                               0x08, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C694F9ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegMem, "indexed-SIB AND opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "indexed-SIB AND length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 32,
           "indexed-SIB AND destination differs");
    expect(memory.base == rosa::x86::Register::R14 && memory.index == rosa::x86::Register::Rsi &&
               memory.scale == 4 && memory.displacement == 0x828 && memory.width == 32,
           "indexed-SIB AND memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("and edx, dword [r14+rsi*4+0x828]") !=
               std::string::npos,
           "indexed-SIB AND dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress source{0x8868};
    constexpr std::array<std::uint8_t, 4> sourceBytes{0x0F, 0x0F, 0x0F, 0x0F};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(source, sourceBytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    rosa::x86::X86State state;
    state.r14 = page.value;
    state.rsi = 0x10;
    state.rdx = 0xAAAAAAAAFFFFFFFCULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdx, std::uint64_t{0x0F0F0F0C}, "indexed-SIB AND result differs");
    expectEqual(state.r14, page.value, "indexed-SIB AND changed its base");
    expectEqual(state.rsi, std::uint64_t{0x10}, "indexed-SIB AND changed its index");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "indexed-SIB AND flags differ");
    expect(addressSpace.readBytes(source, sourceBytes.size()) ==
               std::vector<std::uint8_t>(sourceBytes.begin(), sourceBytes.end()),
           "indexed-SIB AND changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r14 = page.value;
    faultState.rsi = 0x10;
    faultState.rdx = 0x11223344FFFFFFFCULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "unmapped indexed-SIB AND did not fault");
    expectEqual(faultState.rdx, std::uint64_t{0x11223344FFFFFFFCULL},
                "faulted indexed-SIB AND changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted indexed-SIB AND changed flags");
}

void testAnd32BitRegisterIntoIndexedGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{0x46, 0x21, 0x44, 0x92, 0x34, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C6ACEAULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::AndMemReg,
           "memory-destination AND opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "memory-destination AND length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdx && memory.index == rosa::x86::Register::R10 &&
               memory.scale == 4 && memory.displacement == 0x34 && memory.width == 32 &&
               source.reg == rosa::x86::Register::R8 && source.width == 32,
           "and dword [rdx+r10*4+0x34], r8d operands differ");
    expect(rosa::debug::dumpX86(decoded).find("and dword [rdx+r10*4+0x34], r8d") !=
               std::string::npos,
           "memory-destination AND dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8050};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 0xF0F00FF0U);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("and_guest_memory.i32") !=
               std::string::npos,
           "memory-destination AND did not lower through guest-memory IR");
    rosa::x86::X86State state;
    state.rdx = page.value;
    state.r10 = 7;
    state.r8 = 0xAABBCCDD0FF0F0FFULL;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x00F000F0U},
                "memory-destination AND result differs");
    expectEqual(state.rdx, page.value, "memory-destination AND changed its base");
    expectEqual(state.r10, std::uint64_t{7}, "memory-destination AND changed its index");
    expectEqual(state.r8, std::uint64_t{0xAABBCCDD0FF0F0FFULL},
                "memory-destination AND changed its source");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "memory-destination AND defined flags differ");

    constexpr rosa::guest::GuestAddress crossPage{0x1000};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(crossPage, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> tailBytes{0xA5, 0x5A};
    crossPageAddressSpace.writeBytes(rosa::guest::GuestAddress{0x1FFE}, tailBytes);
    rosa::x86::X86State faultState;
    faultState.rdx = 0x1FAE;
    faultState.r10 = 7;
    faultState.r8 = 0xAABBCCDD0FF0F0FFULL;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page memory-destination AND did not fault");
    expect(crossPageAddressSpace.readBytes(rosa::guest::GuestAddress{0x1FFE}, tailBytes.size()) ==
               std::vector<std::uint8_t>(tailBytes.begin(), tailBytes.end()),
           "faulted memory-destination AND partially changed memory");
    expectEqual(faultState.rdx, std::uint64_t{0x1FAE},
                "faulted memory-destination AND changed its base");
    expectEqual(faultState.r10, std::uint64_t{7},
                "faulted memory-destination AND changed its index");
    expectEqual(faultState.r8, std::uint64_t{0xAABBCCDD0FF0F0FFULL},
                "faulted memory-destination AND changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "faulted memory-destination AND changed flags");
}

void testAnd16BitRegisterIntoGuestMemory() {
    // Observed in libsqlite3: AND word [r15+0x28], cx with REX.B (66 41 21).
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x41, 0x21, 0x4F, 0x28, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x100084745ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndMemReg,
           "word memory-destination AND opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "word memory-destination AND length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R15 && memory.displacement == 0x28 &&
               memory.width == 16 && source.reg == rosa::x86::Register::Rcx &&
               source.width == 16,
           "and word [r15+0x28], cx operands differ");
    expect(rosa::debug::dumpX86(decoded).find("and word [r15+0x28], cx") != std::string::npos,
           "word memory-destination AND dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8028};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 2>{0xFF, 0xFF});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x100084745ULL});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("and_guest_memory.i16") !=
               std::string::npos,
           "word memory-destination AND did not lower through guest-memory IR");
    rosa::x86::X86State state;
    state.r15 = page.value;
    state.rcx = 0xAABBCCDD0000FF0FULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expect(addressSpace.readBytes(target, 2) == std::vector<std::uint8_t>({0x0F, 0xFF}),
           "word memory-destination AND result differs");
    expectEqual(state.r15, page.value, "word memory-destination AND changed its base");
    expectEqual(state.rcx, std::uint64_t{0xAABBCCDD0000FF0FULL},
                "word memory-destination AND changed its source");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 7U)},
                "word memory-destination AND defined flags differ");
}

void testAndImmediateIntoGuestWord() {
    constexpr std::array<std::uint8_t, 8> code{0x66, 0x41, 0x81, 0x67, 0x2E, 0x7F, 0xFE, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AB4071ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndMemImm,
           "AND word [memory], imm16 opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R15 && memory.displacement == 0x2E &&
               memory.width == 16 && immediate.value == 0xFE7F && immediate.width == 16,
           "AND word [r15+0x2e], 0xfe7f operands differ");
    expect(rosa::debug::dumpX86(decoded).find("and word [r15+0x2e], 0xfe7f") != std::string::npos,
           "AND word [memory], imm16 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x812E};
    constexpr std::array<std::uint8_t, 2> initial{0xFF, 0xFF};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, initial);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AB4071ULL});
    rosa::x86::X86State state;
    state.r15 = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expect(addressSpace.readBytes(target, 2) == std::vector<std::uint8_t>({0x7F, 0xFE}),
           "AND word immediate stored the wrong result");
    expectEqual(state.r15, std::uint64_t{0x8100}, "AND word immediate changed its base");
    expectEqual(state.rflags, std::uint64_t{0x82}, "AND word immediate flags differ");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    readOnlyAddressSpace.writeBytes(target, initial);
    expectEqual(readOnlyAddressSpace.protect(page, rosa::guest::guestPageSize,
                                             rosa::guest::Permission::Read),
                rosa::guest::ProtectResult::Success, "could not make AND word target read-only");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "AND word immediate accepted read-only memory");
    expect(readOnlyAddressSpace.readBytes(target, 2) ==
               std::vector<std::uint8_t>(initial.begin(), initial.end()),
           "faulted AND word immediate changed memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "faulted AND word immediate changed flags");

    constexpr std::array<std::uint8_t, 5> qwordCode{0x48, 0x83, 0x21, 0x03, 0xC3};
    const auto qwordDecoded =
        decoder.decodeBlock(qwordCode, rosa::guest::GuestAddress{0x7FF802A17C66ULL});
    expect(qwordDecoded[0].opcode == rosa::x86::Opcode::AndMemImm && qwordDecoded[0].length == 4,
           "AND qword [memory], imm8 opcode or length differs");
    const auto qwordMemory = std::get<rosa::x86::MemoryOperand>(qwordDecoded[0].operands[0]);
    const auto qwordImmediate = std::get<rosa::x86::ImmediateOperand>(qwordDecoded[0].operands[1]);
    expect(qwordMemory.base == rosa::x86::Register::Rcx && qwordMemory.displacement == 0 &&
               qwordMemory.width == 64 && qwordImmediate.value == 3 && qwordImmediate.width == 8,
           "AND qword [rcx], 3 operands differ");
    expect(rosa::debug::dumpX86(qwordDecoded).find("and qword [rcx], 0x3") != std::string::npos,
           "AND qword [memory], imm8 dump differs");

    constexpr rosa::guest::GuestAddress qwordTarget{0x8180};
    addressSpace.writeU64(qwordTarget, 0xAABBCCDDEEFF0007ULL);
    const auto qwordBlock =
        translator.translate(qwordCode, rosa::guest::GuestAddress{0x7FF802A17C66ULL});
    rosa::x86::X86State qwordState;
    qwordState.rcx = qwordTarget.value;
    qwordState.rflags = 0x8D7;
    static_cast<void>(qwordBlock.execute(qwordState, &addressSpace));
    expectEqual(addressSpace.readU64(qwordTarget), std::uint64_t{3},
                "AND qword immediate stored the wrong result");
    expectEqual(qwordState.rcx, qwordTarget.value, "AND qword immediate changed its base");
    expectEqual(qwordState.rflags, std::uint64_t{0x6}, "AND qword immediate flags differ");

    constexpr rosa::guest::GuestAddress boundaryPage{0x9000};
    constexpr rosa::guest::GuestAddress boundaryTarget{0x9FFC};
    constexpr std::array<std::uint8_t, 4> boundaryBytes{0x07, 0x00, 0xFF, 0xEE};
    rosa::guest::AddressSpace boundaryAddressSpace;
    boundaryAddressSpace.mapAnonymous(boundaryPage, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    boundaryAddressSpace.writeBytes(boundaryTarget, boundaryBytes);
    rosa::x86::X86State boundaryState;
    boundaryState.rcx = boundaryTarget.value;
    boundaryState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(qwordBlock.execute(boundaryState, &boundaryAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page AND qword immediate did not fault");
    expect(boundaryAddressSpace.readBytes(boundaryTarget, 4) ==
               std::vector<std::uint8_t>(boundaryBytes.begin(), boundaryBytes.end()),
           "faulted cross-page AND qword immediate changed memory");
    expectEqual(boundaryState.rflags, std::uint64_t{0xAD7},
                "faulted cross-page AND qword immediate changed flags");

    // Observed in libsqlite3: AND dword [rsi+0x30], -17 (opcode 83 /4).
    constexpr std::array<std::uint8_t, 5> dwordCode{0x83, 0x66, 0x30, 0xEF, 0xC3};
    const auto dwordDecoded =
        decoder.decodeBlock(dwordCode, rosa::guest::GuestAddress{0x1000A3A54ULL});
    expect(dwordDecoded[0].opcode == rosa::x86::Opcode::AndMemImm && dwordDecoded[0].length == 4,
           "AND dword [memory], imm8 opcode or length differs");
    const auto dwordMemory = std::get<rosa::x86::MemoryOperand>(dwordDecoded[0].operands[0]);
    const auto dwordImmediate = std::get<rosa::x86::ImmediateOperand>(dwordDecoded[0].operands[1]);
    expect(dwordMemory.base == rosa::x86::Register::Rsi && dwordMemory.displacement == 0x30 &&
               dwordMemory.width == 32 && dwordImmediate.value == UINT64_MAX - 16 &&
               dwordImmediate.width == 8,
           "AND dword [rsi+0x30], -17 operands differ");
    expect(rosa::debug::dumpX86(dwordDecoded).find("and dword [rsi+0x30], 0xffffffffffffffef") !=
               std::string::npos,
           "AND dword [memory], imm8 dump differs");

    constexpr rosa::guest::GuestAddress dwordTarget{0x8230};
    addressSpace.writeU32(dwordTarget, 0xFFFFFFFFU);
    const auto dwordBlock =
        translator.translate(dwordCode, rosa::guest::GuestAddress{0x1000A3A54ULL});
    rosa::x86::X86State dwordState;
    dwordState.rsi = 0x8200;
    dwordState.rflags = 0x8D7;
    static_cast<void>(dwordBlock.execute(dwordState, &addressSpace));
    expectEqual(addressSpace.readU32(dwordTarget), std::uint32_t{0xFFFFFFEFU},
                "AND dword immediate stored the wrong result");
    expectEqual(dwordState.rsi, std::uint64_t{0x8200}, "AND dword immediate changed its base");
    expectEqual(dwordState.rflags, std::uint64_t{0x82}, "AND dword immediate flags differ");

    // Observed in libblocks: AND dword [rbx+0x8], 0xffff0000 (opcode 81 /4).
    constexpr std::array<std::uint8_t, 8> fullCode{0x81, 0x63, 0x08, 0x00,
                                                   0x00, 0xFF, 0xFF, 0xC3};
    const auto fullDecoded =
        decoder.decodeBlock(fullCode, rosa::guest::GuestAddress{0x7FF802B28D07ULL});
    expect(fullDecoded[0].opcode == rosa::x86::Opcode::AndMemImm &&
               fullDecoded[0].length == 7,
           "AND dword [memory], imm32 opcode or length differs");
    const auto fullMemory = std::get<rosa::x86::MemoryOperand>(fullDecoded[0].operands[0]);
    const auto fullImmediate = std::get<rosa::x86::ImmediateOperand>(fullDecoded[0].operands[1]);
    expect(fullMemory.base == rosa::x86::Register::Rbx && fullMemory.displacement == 0x08 &&
               fullMemory.width == 32 && fullImmediate.value == 0xFFFF0000 &&
               fullImmediate.width == 32,
           "AND dword [rbx+0x8], 0xffff0000 operands differ");
    expect(rosa::debug::dumpX86(fullDecoded).find("and dword [rbx+0x8], 0xffff0000") !=
               std::string::npos,
           "AND dword [memory], imm32 dump differs");

    constexpr rosa::guest::GuestAddress fullTarget{0x8208};
    addressSpace.writeU32(fullTarget, 0x12345678);
    const auto fullBlock =
        translator.translate(fullCode, rosa::guest::GuestAddress{0x7FF802B28D07ULL});
    rosa::x86::X86State fullState;
    fullState.rbx = 0x8200;
    fullState.rflags = 0x8D7;
    static_cast<void>(fullBlock.execute(fullState, &addressSpace));
    expectEqual(addressSpace.readU32(fullTarget), std::uint32_t{0x12340000U},
                "AND dword imm32 stored the wrong result");
    expectEqual(fullState.rflags, std::uint64_t{0x6}, "AND dword imm32 flags differ");
}

void testAndImmediateIntoGuestByte() {
    constexpr std::array<std::uint8_t, 5> code{0x80, 0x60, 0x48, 0xF0, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802D10E9BULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::AndMemImm,
           "AND byte [memory], imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "AND byte [memory], imm8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rax && memory.displacement == 0x48 &&
               memory.width == 8 && immediate.value == 0xF0 && immediate.width == 8,
           "AND byte [rax+0x48], 0xf0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("and byte [rax+0x48], 0xf0") != std::string::npos,
           "AND byte [memory], imm8 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8148};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 1>{0xAB});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.rax = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0xA0},
                "AND byte immediate stored the wrong result");
    expectEqual(state.rax, std::uint64_t{0x8100}, "AND byte immediate changed its base");
    expectEqual(state.rflags, std::uint64_t{0x86}, "AND byte immediate flags differ");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    std::array<std::uint8_t, 0x149>{},
                                    "read-only byte AND immediate target");
    rosa::x86::X86State faultState;
    faultState.rax = 0x8100;
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(faulted, "AND byte immediate accepted read-only memory");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1).front(), std::uint8_t{0},
                "faulted AND byte immediate changed memory");
    expectEqual(faultState.rax, std::uint64_t{0x8100},
                "faulted AND byte immediate changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted AND byte immediate changed flags");
}

void testBitScanForward32() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0xBC, 0xC6, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::BitScanForwardRegReg,
           "BSF r32, r32 opcode differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State nonzeroState;
    nonzeroState.rax = UINT64_MAX;
    nonzeroState.rsi = 0xAAAAAAAA0000C000ULL;
    nonzeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(nonzeroState));
    expectEqual(nonzeroState.rax, std::uint64_t{14}, "BSF r32 result or zero extension differs");
    expectEqual(nonzeroState.rsi, std::uint64_t{0xAAAAAAAA0000C000ULL}, "BSF changed source");
    expectEqual(nonzeroState.rflags, std::uint64_t{0x897}, "BSF nonzero ZF semantics differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0x12345678;
    zeroState.rsi = 0;
    zeroState.rflags = 0x897;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x12345678},
                "BSF zero-source deterministic destination differs");
    expectEqual(zeroState.rflags, std::uint64_t{0x8D7}, "BSF zero-source ZF semantics differ");

    constexpr std::array<std::uint8_t, 5> extendedCode{0x45, 0x0F, 0xBC, 0xE7, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x2000});
    const auto extendedDestination =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]);
    expect(extendedDestination.reg == rosa::x86::Register::R12 && extendedDestination.width == 32 &&
               extendedSource.reg == rosa::x86::Register::R15 && extendedSource.width == 32,
           "extended BSF r32 operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("bsf r12d, r15d") != std::string::npos,
           "extended BSF r32 dump differs");
    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State extendedState;
    extendedState.r12 = UINT64_MAX;
    extendedState.r15 = 0x100;
    extendedState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.r12, std::uint64_t{8},
                "extended BSF r32 result or zero extension differs");
    expectEqual(extendedState.r15, std::uint64_t{0x100}, "extended BSF r32 changed its source");
    expect((extendedState.rflags & (1U << 6U)) == 0,
           "extended BSF r32 did not clear ZF for a nonzero source");
}

void testBitTestMemoryImmediate32() {
    // Observed in libblocks under an Objective-C fixture: BT dword [r14+0x8], 0x1c.
    constexpr std::array<std::uint8_t, 7> code{0x41, 0x0F, 0xBA, 0x66,
                                               0x08, 0x1C, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802B28CC0ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::BitTestMemImm,
           "BT m32, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "BT m32, imm8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(!memory.ripRelative && memory.hasBase &&
               memory.base == rosa::x86::Register::R14 && !memory.index &&
               memory.displacement == 8 && memory.width == 32,
           "BT m32, imm8 memory operand differs");
    expectEqual(immediate.value, std::uint64_t{0x1C}, "BT m32, imm8 bit index differs");
    expect(rosa::debug::dumpX86(decoded).find("bt dword [r14+0x8], 0x1c") != std::string::npos,
           "BT m32, imm8 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8108};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    // Bit 28 (0x1C) set.
    addressSpace.writeU32(target, 0x10000000);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("update_bit_test_flags.i32") != std::string::npos,
           "BT m32, imm8 did not lower through typed flags IR");
    rosa::x86::X86State setState;
    setState.r14 = target.value - 8;
    setState.rflags = 0xAD6;
    static_cast<void>(block.execute(setState, &addressSpace));
    expectEqual(setState.r14, target.value - 8, "BT m32, imm8 changed its base");
    expectEqual(setState.rflags, std::uint64_t{0xAD7}, "BT m32, imm8 set-CF semantics differ");

    addressSpace.writeU32(target, 0xEFFFFFFF);
    rosa::x86::X86State clearState;
    clearState.r14 = target.value - 8;
    clearState.rflags = 0xAD7;
    static_cast<void>(block.execute(clearState, &addressSpace));
    expectEqual(clearState.rflags, std::uint64_t{0xAD6}, "BT m32, imm8 clear-CF semantics differ");

    // An out-of-range immediate is masked to five bits without striding:
    // bit 40 is bit 8 of the same dword, even when the next dword has bit 8 set.
    constexpr std::array<std::uint8_t, 7> maskedCode{0x41, 0x0F, 0xBA, 0x66,
                                                     0x08, 0x28, 0xC3};
    const auto maskedBlock = translator.translate(maskedCode, observedRip);
    addressSpace.writeU32(target, 0x00000000);
    addressSpace.writeU32(rosa::guest::GuestAddress{target.value + 4}, 0x00000100);
    rosa::x86::X86State maskedState;
    maskedState.r14 = target.value - 8;
    maskedState.rflags = 0xAD7;
    static_cast<void>(maskedBlock.execute(maskedState, &addressSpace));
    expectEqual(maskedState.rflags, std::uint64_t{0xAD6},
                "BT m32 strode into the neighboring unit");
}

void testBitTestRegisterImmediate32() {
    constexpr std::array<std::uint8_t, 5> code{0x0F, 0xBA, 0xE6, 0x09, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A8C8BCULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::BitTestRegImm, "BT r32, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "BT r32, imm8 length differs");
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(source.reg == rosa::x86::Register::Rsi && source.width == 32,
           "BT r32, imm8 source differs");
    expectEqual(immediate.value, std::uint64_t{9}, "BT r32, imm8 bit index differs");
    expectEqual(immediate.width, std::uint8_t{8}, "BT r32, imm8 immediate width differs");
    expect(rosa::debug::dumpX86(decoded).find("bt esi, 0x9") != std::string::npos,
           "BT r32, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A8C8BCULL});
    expect(
        rosa::debug::dumpIr(block.intermediateRepresentation()).find("update_bit_test_flags.i32") !=
            std::string::npos,
        "BT r32, imm8 did not lower through typed flags IR");

    rosa::x86::X86State setState;
    setState.rsi = 0xFFFFFFFF00000200ULL;
    setState.rflags = 0xAD6;
    static_cast<void>(block.execute(setState));
    expectEqual(setState.rsi, std::uint64_t{0xFFFFFFFF00000200ULL},
                "BT r32, imm8 changed its source");
    expectEqual(setState.rflags, std::uint64_t{0xAD7}, "BT r32, imm8 set-CF semantics differ");

    rosa::x86::X86State clearState;
    clearState.rsi = 0xFFFFFFFF00000000ULL;
    clearState.rflags = 0xAD7;
    static_cast<void>(block.execute(clearState));
    expectEqual(clearState.rsi, std::uint64_t{0xFFFFFFFF00000000ULL},
                "BT r32, imm8 changed its clear source");
    expectEqual(clearState.rflags, std::uint64_t{0xAD6}, "BT r32, imm8 clear-CF semantics differ");

    constexpr std::array<std::uint8_t, 5> maskedCode{0x0F, 0xBA, 0xE6, 0x29, 0xC3};
    const auto maskedBlock = translator.translate(maskedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State maskedState;
    maskedState.rsi = 0x200;
    maskedState.rflags = 0xAD6;
    static_cast<void>(maskedBlock.execute(maskedState));
    expectEqual(maskedState.rflags, std::uint64_t{0xAD7},
                "BT r32 did not mask the immediate index to five bits");

    constexpr std::array<std::uint8_t, 5> highBitCode{0x0F, 0xBA, 0xE6, 0x1F, 0xC3};
    const auto highBitBlock = translator.translate(highBitCode, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State highBitState;
    highBitState.rsi = 0xFFFFFFFF80000000ULL;
    highBitState.rflags = 0xAD6;
    static_cast<void>(highBitBlock.execute(highBitState));
    expectEqual(highBitState.rflags, std::uint64_t{0xAD7}, "BT r32 bit-31 semantics differ");

    constexpr std::array<std::uint8_t, 6> extendedCode{0x41, 0x0F, 0xBA, 0xE6, 0x09, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x4000});
    const auto extendedSource =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    expect(extendedSource.reg == rosa::x86::Register::R14 && extendedSource.width == 32,
           "REX.B BT r32 source differs");
    expect(rosa::debug::dumpX86(extendedDecoded).find("bt r14d, 0x9") != std::string::npos,
           "REX.B BT r32 dump differs");

    const auto expectRejected = [&decoder](std::span<const std::uint8_t> bytes,
                                           std::string_view message) {
        bool rejected = false;
        try {
            static_cast<void>(decoder.decodeBlock(bytes, rosa::guest::GuestAddress{0x5000}));
        } catch (const rosa::x86::DecodeError &) {
            rejected = true;
        }
        expect(rejected, message);
    };
    constexpr std::array<std::uint8_t, 4> wrongExtension{0x0F, 0xBA, 0xFE, 0x09};
    constexpr std::array<std::uint8_t, 5> rexW{0x48, 0x0F, 0xBA, 0xE6, 0x09};
    constexpr std::array<std::uint8_t, 5> rexR{0x44, 0x0F, 0xBA, 0xE6, 0x09};
    constexpr std::array<std::uint8_t, 5> rexX{0x42, 0x0F, 0xBA, 0xE6, 0x09};
    expectRejected(wrongExtension, "non-BT 0F BA extension was accepted");
    expectRejected(rexR, "REX.R BT extension was accepted");
    expectRejected(rexX, "REX.X BT form was accepted");
    const auto rexWDecoded = decoder.decodeBlock(rexW, rosa::guest::GuestAddress{0x6000}, 1);
    const auto rexWSource = std::get<rosa::x86::RegisterOperand>(rexWDecoded[0].operands[0]);
    expect(rexWDecoded[0].opcode == rosa::x86::Opcode::BitTestRegImm &&
               rexWSource.reg == rosa::x86::Register::Rsi && rexWSource.width == 64,
           "BT r64 operand differs");
}

void testBitSetResetRegisterImmediate64() {
    constexpr std::array<std::uint8_t, 6> setCode{0x48, 0x0F, 0xBA, 0xE8, 0x37, 0xC3};
    constexpr std::array<std::uint8_t, 6> resetCode{0x48, 0x0F, 0xBA, 0xF0, 0x37, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802AB3B68ULL};
    constexpr std::uint64_t bit = std::uint64_t{1} << 55U;
    const rosa::x86::Decoder decoder;
    const auto setDecoded = decoder.decodeBlock(setCode, observedRip);
    const auto resetDecoded =
        decoder.decodeBlock(resetCode, rosa::guest::GuestAddress{observedRip.value + 7});
    expect(setDecoded[0].opcode == rosa::x86::Opcode::BitSetRegImm, "BTS r64, imm8 opcode differs");
    expect(resetDecoded[0].opcode == rosa::x86::Opcode::BitResetRegImm,
           "BTR r64, imm8 opcode differs");
    const auto setDestination = std::get<rosa::x86::RegisterOperand>(setDecoded[0].operands[0]);
    expect(setDestination.reg == rosa::x86::Register::Rax && setDestination.width == 64,
           "BTS rax destination differs");
    expect(rosa::debug::dumpX86(setDecoded).find("bts rax, 0x37") != std::string::npos,
           "BTS rax dump differs");
    expect(rosa::debug::dumpX86(resetDecoded).find("btr rax, 0x37") != std::string::npos,
           "BTR rax dump differs");

    const rosa::dbt::Translator translator;
    const auto setBlock = translator.translate(setCode, observedRip);
    const auto resetBlock =
        translator.translate(resetCode, rosa::guest::GuestAddress{observedRip.value + 7});
    rosa::x86::X86State state;
    state.rax = 0;
    state.rflags = 0xAD7;
    static_cast<void>(setBlock.execute(state));
    expectEqual(state.rax, bit, "BTS did not set bit 55");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "BTS clear original bit did not clear CF");

    state.rax = bit | 0x1234;
    state.rflags = 0xAD6;
    static_cast<void>(setBlock.execute(state));
    expectEqual(state.rax, bit | 0x1234, "BTS changed bits outside its destination");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "BTS set original bit did not set CF");

    state.rax = bit | 0x1234;
    state.rflags = 0xAD6;
    static_cast<void>(resetBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1234}, "BTR did not clear bit 55");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "BTR set original bit did not set CF");

    state.rax = 0x1234;
    state.rflags = 0xAD7;
    static_cast<void>(resetBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1234}, "BTR changed a clear destination bit");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "BTR clear original bit did not clear CF");
}

void testBitTestRegisterIndex32() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0xA3, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AA0FE6ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::BitTestRegReg, "BT r32, r32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "BT r32, r32 length differs");
    const auto value = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto index = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(value.reg == rosa::x86::Register::Rcx && value.width == 32 &&
               index.reg == rosa::x86::Register::Rax && index.width == 32,
           "BT ecx, eax operands differ");
    expect(rosa::debug::dumpX86(decoded).find("bt ecx, eax") != std::string::npos,
           "BT ecx, eax dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AA0FE6ULL});
    rosa::x86::X86State setState;
    setState.rcx = 0xFFFFFFFF00000442ULL;
    setState.rax = 1;
    setState.rflags = 0xAD6;
    static_cast<void>(block.execute(setState));
    expectEqual(setState.rcx, std::uint64_t{0xFFFFFFFF00000442ULL},
                "BT r32, r32 changed its value operand");
    expectEqual(setState.rax, std::uint64_t{1}, "BT r32, r32 changed its index operand");
    expectEqual(setState.rflags, std::uint64_t{0xAD7}, "BT r32, r32 set-CF semantics differ");

    rosa::x86::X86State clearState;
    clearState.rcx = 0xFFFFFFFF00000442ULL;
    clearState.rax = 2;
    clearState.rflags = 0xAD7;
    static_cast<void>(block.execute(clearState));
    expectEqual(clearState.rflags, std::uint64_t{0xAD6}, "BT r32, r32 clear-CF semantics differ");

    rosa::x86::X86State maskedState;
    maskedState.rcx = 0x442;
    maskedState.rax = 33;
    maskedState.rflags = 0xAD6;
    static_cast<void>(block.execute(maskedState));
    expectEqual(maskedState.rflags, std::uint64_t{0xAD7},
                "BT r32, r32 did not mask its register index");

    constexpr std::array<std::uint8_t, 5> extendedCode{0x44, 0x0F, 0xA3, 0xE8, 0xC3};
    constexpr rosa::guest::GuestAddress extendedRip{0x7FF802C8F2F1ULL};
    const auto extendedDecoded = decoder.decodeBlock(extendedCode, extendedRip);
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::BitTestRegReg,
           "REX.R BT r32, r32 opcode differs");
    expectEqual(extendedDecoded[0].length, std::uint8_t{4}, "REX.R BT r32, r32 length differs");
    const auto extendedValue = std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedIndex = std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]);
    expect(extendedValue.reg == rosa::x86::Register::Rax && extendedValue.width == 32 &&
               extendedIndex.reg == rosa::x86::Register::R13 && extendedIndex.width == 32,
           "BT eax, r13d operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("bt eax, r13d") != std::string::npos,
           "BT eax, r13d dump differs");

    const auto extendedBlock = translator.translate(extendedCode, extendedRip);
    rosa::x86::X86State extendedSetState;
    extendedSetState.rax = 0xFFFFFFFF80000000ULL;
    extendedSetState.r13 = 0x123400000000003FULL;
    extendedSetState.rflags = 0xAD6;
    static_cast<void>(extendedBlock.execute(extendedSetState));
    expectEqual(extendedSetState.rax, std::uint64_t{0xFFFFFFFF80000000ULL},
                "REX.R BT changed its value operand");
    expectEqual(extendedSetState.r13, std::uint64_t{0x123400000000003FULL},
                "REX.R BT changed its index operand");
    expectEqual(extendedSetState.rflags, std::uint64_t{0xAD7}, "REX.R BT set-CF semantics differ");

    extendedSetState.rax = 0;
    extendedSetState.r13 = 0x3F;
    extendedSetState.rflags = 0xAD7;
    static_cast<void>(extendedBlock.execute(extendedSetState));
    expectEqual(extendedSetState.rflags, std::uint64_t{0xAD6},
                "REX.R BT clear-CF semantics differ");

    // Exact live corecrypto probe: the register index is masked modulo 64,
    // and BT preserves every flag except CF.
    constexpr std::array<std::uint8_t, 5> qwordCode{0x48, 0x0F, 0xA3, 0xD6, 0xC3};
    constexpr rosa::guest::GuestAddress qwordRip{0x7FF802C1402BULL};
    const auto qwordDecoded = decoder.decodeBlock(qwordCode, qwordRip);
    expect(qwordDecoded[0].opcode == rosa::x86::Opcode::BitTestRegReg,
           "BT r64, r64 opcode differs");
    const auto qwordValue = std::get<rosa::x86::RegisterOperand>(qwordDecoded[0].operands[0]);
    const auto qwordIndex = std::get<rosa::x86::RegisterOperand>(qwordDecoded[0].operands[1]);
    expect(qwordValue.reg == rosa::x86::Register::Rsi && qwordValue.width == 64 &&
               qwordIndex.reg == rosa::x86::Register::Rdx && qwordIndex.width == 64,
           "BT rsi, rdx operands differ");
    expect(rosa::debug::dumpX86(qwordDecoded).find("bt rsi, rdx") != std::string::npos,
           "BT rsi, rdx dump differs");
    const auto qwordBlock = translator.translate(qwordCode, qwordRip);
    rosa::x86::X86State qwordState;
    qwordState.rsi = UINT64_C(0x8000000100000000);
    qwordState.rdx = 96;
    qwordState.rflags = 0xAD6;
    static_cast<void>(qwordBlock.execute(qwordState));
    expectEqual(qwordState.rflags, std::uint64_t{0xAD7},
                "BT r64 did not mask its set-bit index modulo 64");
    expectEqual(qwordState.rsi, UINT64_C(0x8000000100000000), "BT r64 changed its value operand");
    expectEqual(qwordState.rdx, std::uint64_t{96}, "BT r64 changed its index operand");
    qwordState.rdx = 127;
    qwordState.rflags = 0xAD7;
    static_cast<void>(qwordBlock.execute(qwordState));
    expectEqual(qwordState.rflags, std::uint64_t{0xAD7}, "BT r64 did not test masked bit 63");
    qwordState.rsi = 0;
    qwordState.rflags = 0xAD7;
    static_cast<void>(qwordBlock.execute(qwordState));
    expectEqual(qwordState.rflags, std::uint64_t{0xAD6}, "BT r64 clear-bit semantics differ");
}

void testBitSetRegisterIndex64() {
    // Observed in libsqlite3: BTS R11, RAX with REX.WB.
    constexpr std::array<std::uint8_t, 5> code{0x49, 0x0F, 0xAB, 0xC3, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10011B46AULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::BitSetRegReg, "BTS r64, r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "BTS r64, r64 length differs");
    const auto value = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto index = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(value.reg == rosa::x86::Register::R11 && value.width == 64 &&
               index.reg == rosa::x86::Register::Rax && index.width == 64,
           "BTS r11, rax operands differ");
    expect(rosa::debug::dumpX86(decoded).find("bts r11, rax") != std::string::npos,
           "BTS r11, rax dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10011B46AULL});
    rosa::x86::X86State clearState;
    clearState.r11 = 0;
    clearState.rax = 5;
    clearState.rflags = 0xAD7;
    static_cast<void>(block.execute(clearState));
    expectEqual(clearState.r11, std::uint64_t{0x20}, "BTS r64 did not set the indexed bit");
    expectEqual(clearState.rax, std::uint64_t{5}, "BTS r64 changed its index operand");
    expectEqual(clearState.rflags, std::uint64_t{0xAD6}, "BTS r64 clear-CF semantics differ");

    rosa::x86::X86State setState;
    setState.r11 = 0x20;
    setState.rax = 5;
    setState.rflags = 0xAD6;
    static_cast<void>(block.execute(setState));
    expectEqual(setState.r11, std::uint64_t{0x20}, "BTS r64 changed an already-set bit");
    expectEqual(setState.rflags, std::uint64_t{0xAD7}, "BTS r64 set-CF semantics differ");

    rosa::x86::X86State maskedState;
    maskedState.r11 = 0;
    maskedState.rax = 69;
    maskedState.rflags = 0xAD7;
    static_cast<void>(block.execute(maskedState));
    expectEqual(maskedState.r11, std::uint64_t{0x20}, "BTS r64 did not mask its index modulo 64");
    expectEqual(maskedState.rflags, std::uint64_t{0xAD6}, "BTS r64 masked-CF semantics differ");
}

void testBitTestGuestDwordImmediate() {
    constexpr std::array<std::uint8_t, 9> observed{0x0F, 0xBA, 0xA3, 0x90, 0x00,
                                                   0x00, 0x00, 0x15, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded =
        decoder.decodeBlock(observed, rosa::guest::GuestAddress{0x7FF802AA05C0ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::BitTestMemImm, "BT dword memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "BT dword memory length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.width == 32 &&
               memory.displacement == 0x90 && immediate.width == 8 && immediate.value == 0x15,
           "BT dword [rbx+0x90], 0x15 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("bt dword [rbx+0x90], 0x15") != std::string::npos,
           "BT dword memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress operand{0x8090};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const std::array<std::uint8_t, 8> setValue{0x00, 0x00, 0x20, 0x00, 0xEF, 0xBE, 0xAD, 0xDE};
    addressSpace.writeBytes(operand, setValue);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observed, rosa::guest::GuestAddress{0x7FF802AA05C0ULL});
    rosa::x86::X86State state;
    state.rbx = page.value;
    state.rflags = 0xAD6;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "BT dword memory did not copy the selected bit to CF");
    expectEqual(state.rbx, page.value, "BT dword memory changed its base");
    expect(addressSpace.readBytes(operand, setValue.size()) ==
               std::vector<std::uint8_t>(setValue.begin(), setValue.end()),
           "BT dword memory changed its source or read beyond four bytes");

    const std::array<std::uint8_t, 4> clearValue{};
    addressSpace.writeBytes(operand, clearValue);
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "BT dword memory did not clear CF");

    constexpr std::array<std::uint8_t, 6> highOffset{0x0F, 0xBA, 0x63, 0x10, 0x25, 0xC3};
    const auto highBlock = translator.translate(highOffset, rosa::guest::GuestAddress{0x1000});
    const std::array<std::uint8_t, 8> bitString{0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8010}, bitString);
    state.rflags = 0xAD6;
    static_cast<void>(highBlock.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "BT dword memory did not mask the immediate to five bits");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbx = page.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "BT dword from unmapped guest memory did not fault");
    expectEqual(faultState.rbx, page.value, "faulted BT dword memory changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted BT dword memory changed flags");
}

void testBitScanForward64() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x0F, 0xBC, 0xD1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::BitScanForwardRegReg,
           "BSF r64, r64 opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 64,
           "BSF r64 destination differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 64, "BSF r64 source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State nonzeroState;
    nonzeroState.rdx = UINT64_MAX;
    nonzeroState.rcx = std::uint64_t{1} << 40U;
    nonzeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(nonzeroState));
    expectEqual(nonzeroState.rdx, std::uint64_t{40}, "BSF r64 result differs");
    expectEqual(nonzeroState.rcx, std::uint64_t{1} << 40U, "BSF r64 changed source");
    expectEqual(nonzeroState.rflags, std::uint64_t{0x897}, "BSF r64 nonzero ZF semantics differ");

    rosa::x86::X86State zeroState;
    zeroState.rdx = 0x123456789ABCDEF0ULL;
    zeroState.rcx = 0;
    zeroState.rflags = 0x897;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rdx, std::uint64_t{0x123456789ABCDEF0ULL},
                "BSF r64 zero-source destination policy differs");
    expectEqual(zeroState.rflags, std::uint64_t{0x8D7}, "BSF r64 zero-source ZF semantics differ");
}

void testByteSwap32() {
    constexpr std::array<std::uint8_t, 3> code{0x0F, 0xCE, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF700052E5CULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::BswapReg, "BSWAP r32 opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 32,
           "BSWAP esi operand differs");
    expect(rosa::debug::dumpX86(decoded).find("bswap esi") != std::string::npos,
           "BSWAP esi dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF700052E5CULL});
    rosa::x86::X86State state;
    state.rsi = 0xAABBCCDD12345678ULL;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rsi, std::uint64_t{0x78563412}, "BSWAP esi result or zero extension differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "BSWAP changed flags");

    state.rsi = 0xAABBCCDD00000000ULL;
    static_cast<void>(block.execute(state));
    expectEqual(state.rsi, std::uint64_t{0}, "BSWAP zero result differs");

    constexpr std::array<std::uint8_t, 4> wideCode{0x48, 0x0F, 0xCE, 0xC3};
    const auto wideDecoded =
        decoder.decodeBlock(wideCode, rosa::guest::GuestAddress{0x7FF700035631ULL});
    const auto wideDestination = std::get<rosa::x86::RegisterOperand>(wideDecoded[0].operands[0]);
    expect(wideDestination.reg == rosa::x86::Register::Rsi && wideDestination.width == 64,
           "BSWAP rsi operand differs");
    expect(rosa::debug::dumpX86(wideDecoded).find("bswap rsi") != std::string::npos,
           "BSWAP rsi dump differs");
    const auto wideBlock =
        translator.translate(wideCode, rosa::guest::GuestAddress{0x7FF700035631ULL});
    state.rsi = 0x0123456789ABCDEFULL;
    state.rflags = 0xAD7;
    static_cast<void>(wideBlock.execute(state));
    expectEqual(state.rsi, std::uint64_t{0xEFCDAB8967452301ULL}, "BSWAP rsi result differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "BSWAP rsi changed flags");
}

void testBitScanReverse64() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x0F, 0xBD, 0xC7, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF80005992DULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::BitScanReverseRegReg,
           "BSR r64, r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "BSR r64, r64 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64 &&
               source.reg == rosa::x86::Register::Rdi && source.width == 64,
           "BSR rax, rdi operands differ");
    expect(rosa::debug::dumpX86(decoded).find("bsr rax, rdi") != std::string::npos,
           "BSR r64 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF80005992DULL});
    rosa::x86::X86State nonzeroState;
    nonzeroState.rax = UINT64_MAX;
    nonzeroState.rdi = (std::uint64_t{1} << 40U) | 1U;
    nonzeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(nonzeroState));
    expectEqual(nonzeroState.rax, std::uint64_t{40}, "BSR r64 result differs");
    expectEqual(nonzeroState.rdi, (std::uint64_t{1} << 40U) | 1U, "BSR r64 changed its source");
    expectEqual(nonzeroState.rflags & zeroFlag, std::uint64_t{0}, "BSR r64 nonzero ZF differs");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0x7F;
    zeroState.rdi = 0;
    zeroState.rflags = 0x897;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rflags & zeroFlag, zeroFlag, "BSR r64 zero-source ZF differs");
    expectEqual(zeroState.rdi, std::uint64_t{0}, "BSR r64 zero-source changed its source");
    // The destination is architecturally undefined for a zero source.
}

void testBitScanReverse32() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0xBD, 0xF2, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A196CBULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::BitScanReverseRegReg,
           "BSR r32, r32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "BSR r32, r32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 32 &&
               source.reg == rosa::x86::Register::Rdx && source.width == 32,
           "BSR esi, edx operands differ");
    expect(rosa::debug::dumpX86(decoded).find("bsr esi, edx") != std::string::npos,
           "BSR r32 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A196CBULL});
    rosa::x86::X86State nonzeroState;
    nonzeroState.rsi = UINT64_MAX;
    nonzeroState.rdx = 0xAAAAAAAA80000100ULL;
    nonzeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(nonzeroState));
    expectEqual(nonzeroState.rsi, std::uint64_t{31}, "BSR r32 result or zero extension differs");
    expectEqual(nonzeroState.rdx, std::uint64_t{0xAAAAAAAA80000100ULL},
                "BSR r32 changed its source");
    expectEqual(nonzeroState.rflags, std::uint64_t{0x897}, "BSR r32 nonzero ZF semantics differ");

    rosa::x86::X86State zeroState;
    zeroState.rsi = 0x7FFF00000000ULL;
    zeroState.rdx = 0;
    zeroState.rflags = 0x897;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rsi, std::uint64_t{0x7FFF00000000ULL},
                "BSR r32 zero-source deterministic destination differs");
    expectEqual(zeroState.rflags, std::uint64_t{0x8D7}, "BSR r32 zero-source ZF semantics differ");

    constexpr std::array<std::uint8_t, 5> extendedCode{0x45, 0x0F, 0xBD, 0xE7, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x2000});
    const auto extendedDestination =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]);
    expect(extendedDestination.reg == rosa::x86::Register::R12 && extendedDestination.width == 32 &&
               extendedSource.reg == rosa::x86::Register::R15 && extendedSource.width == 32,
           "extended BSR r32 operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("bsr r12d, r15d") != std::string::npos,
           "extended BSR r32 dump differs");
}

void testLegacyAnd32Immediate() {
    constexpr std::array<std::uint8_t, 4> code{0x83, 0xE1, 0x1F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegImm,
           "legacy AND r32, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "legacy AND r32, imm8 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0xFFFFFFFF000000FFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x1F},
                "legacy AND r32, imm8 did not zero-extend the result");
    expectEqual(state.rflags, std::uint64_t{0x2}, "legacy AND r32, imm8 flags differ");
}

void testAnd8BitAccumulatorImmediate() {
    constexpr std::array<std::uint8_t, 3> code{0x24, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegImm, "AND AL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "AND AL, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8,
           "AND AL, imm8 destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{1}, "AND AL, imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("and al, 0x1") != std::string::npos,
           "AND AL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x11223344556677A5ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL},
                "AND AL, imm8 did not preserve upper RAX bytes");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0},
                "AND AL, imm8 nonzero defined flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0xFFEEDDCCBBAA5500ULL;
    zeroState.rflags = 0x810;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0xFFEEDDCCBBAA5500ULL},
                "AND AL, imm8 zero result changed upper RAX bytes");
    expectEqual(zeroState.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "AND AL, imm8 zero defined flags differ");
}

void testAnd16BitRegisterShortImmediate() {
    // Observed in libsqlite3: AND AX, 0xc (66 83 /4).
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x83, 0xE0, 0x0C, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10004D4E9ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegImm, "AND r16, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "AND r16, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 16 &&
               immediate.width == 8 && immediate.value == 0x0C,
           "AND AX, 0xc operands differ");
    expect(rosa::debug::dumpX86(decoded).find("and ax, 0xc") != std::string::npos,
           "AND AX, 0xc dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10004D4E9ULL});
    rosa::x86::X86State state;
    state.rax = 0x112233445566FF05ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455660004ULL},
                "AND AX, imm8 result differs");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0},
                "AND AX, imm8 nonzero defined flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0xFFEEDDCCBBAA5500ULL;
    zeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0xFFEEDDCCBBAA0000ULL},
                "AND AX, imm8 zero result changed upper RAX bytes");
    expectEqual(zeroState.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "AND AX, imm8 zero defined flags differ");
}

void testAndAccumulatorImmediate() {
    constexpr std::array<std::uint8_t, 6> code{0x25, 0x00, 0xF0, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AE7F6EULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegImm, "AND EAX, imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "AND EAX, imm32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               immediate.width == 32 && immediate.value == 0xF000,
           "AND EAX, imm32 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("and eax, 0xf000") != std::string::npos,
           "AND EAX, imm32 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AE7F6EULL});
    rosa::x86::X86State state;
    state.rax = 0xFFFFFFFF0000416DULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x4000}, "AND EAX, imm32 did not zero-extend the result");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "AND EAX, imm32 flags differ");

    constexpr std::array<std::uint8_t, 7> rexCode{0x48, 0x25, 0x00, 0xF0, 0xFF, 0xFF, 0xC3};
    const auto rexBlock = translator.translate(rexCode, rosa::guest::GuestAddress{0x2000});
    state.rax = 0xFEDCBA9876543210ULL;
    state.rflags = 0x8D7;
    static_cast<void>(rexBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFEDCBA9876543000ULL},
                "AND RAX, imm32 did not sign-extend the immediate");
}

void testAnd8BitRegisterImmediate() {
    constexpr std::array<std::uint8_t, 4> code{0x80, 0xE1, 0x7F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegImm, "AND r8, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "AND r8, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 8 &&
               immediate.width == 8 && immediate.value == 0x7F,
           "AND CL, imm8 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("and cl, 0x7f") != std::string::npos,
           "AND CL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0x1122334455667781ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x1122334455667701ULL},
                "AND CL immediate did not preserve upper RCX bytes");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0},
                "AND CL immediate nonzero defined flags differ");

    state.rcx = 0x1122334455667780ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x1122334455667700ULL},
                "AND CL immediate zero result differs");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "AND CL immediate zero defined flags differ");

    constexpr std::array<std::uint8_t, 3> legacyHighByte{0x80, 0xE4, 0x7F};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(legacyHighByte, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "AND silently treated legacy AH as a representable low byte");
}

void testAnd32BitRegisterImmediate() {
    constexpr std::array<std::uint8_t, 8> code{0x41, 0x81, 0xE7, 0xFF, 0x0F, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegImm, "AND r32, imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "AND r32, imm32 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R15 && destination.width == 32,
           "AND r32, imm32 destination differs");
    expectEqual(immediate.value, std::uint64_t{0xFFF}, "AND r32, imm32 immediate differs");
    expectEqual(immediate.width, std::uint8_t{32}, "AND r32, imm32 immediate width differs");
    expect(rosa::debug::dumpX86(decoded).find("and r15d, 0xfff") != std::string::npos,
           "AND r32, imm32 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r15 = 0xFFFFFFFF80000800ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r15, std::uint64_t{0x800}, "AND r32, imm32 result did not zero-extend");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "AND r32, imm32 nonzero defined flags differ");

    constexpr std::array<std::uint8_t, 7> zeroCode{0x81, 0xE0, 0x00, 0x00, 0x00, 0x00, 0xC3};
    const auto zeroBlock = translator.translate(zeroCode, rosa::guest::GuestAddress{0x2000});
    state.rax = UINT64_MAX;
    state.rflags = 0x811;
    static_cast<void>(zeroBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0}, "AND EAX, imm32 zero result did not clear upper bits");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "AND EAX, imm32 zero defined flags differ");

    constexpr std::array<std::uint8_t, 7> signCode{0x81, 0xE1, 0x00, 0x00, 0x00, 0x80, 0xC3};
    const auto signBlock = translator.translate(signCode, rosa::guest::GuestAddress{0x2800});
    state.rcx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(signBlock.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x80000000}, "AND ECX, imm32 sign-bit result differs");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 7U)},
                "AND ECX, imm32 sign defined flags differ");

    constexpr std::array<std::uint8_t, 8> observed{0x48, 0x81, 0xE1, 0x00, 0xC0, 0xFF, 0xFF, 0xC3};
    const auto observedDecoded = decoder.decodeBlock(observed, rosa::guest::GuestAddress{0x2C00});
    const auto observedDestination =
        std::get<rosa::x86::RegisterOperand>(observedDecoded[0].operands[0]);
    const auto observedImmediate =
        std::get<rosa::x86::ImmediateOperand>(observedDecoded[0].operands[1]);
    expect(observedDecoded[0].opcode == rosa::x86::Opcode::AndRegImm &&
               observedDecoded[0].length == 7,
           "AND r64, imm32 decode differs");
    expect(observedDestination.reg == rosa::x86::Register::Rcx && observedDestination.width == 64,
           "AND r64, imm32 destination differs");
    expect(observedImmediate.width == 32 && observedImmediate.value == 0xFFFFFFFFFFFFC000ULL,
           "AND r64, imm32 was not sign-extended");
    expect(rosa::debug::dumpX86(observedDecoded).find("and rcx, 0xffffffffffffc000") !=
               std::string::npos,
           "AND r64, imm32 dump differs");
    const auto observedBlock = translator.translate(observed, rosa::guest::GuestAddress{0x2C00});
    state.rcx = 0x123456789ABCDEF0ULL;
    state.rflags = 0x8D7;
    static_cast<void>(observedBlock.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x123456789ABCC000ULL}, "AND r64, imm32 result differs");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "AND r64, imm32 defined flags differ");

    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(std::span<const std::uint8_t>{code}.first(6),
                                              rosa::guest::GuestAddress{0x3000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "truncated AND r32, imm32 was not rejected");
}



} // namespace

std::span<const TestCase> integerSemanticsTests() {
    static const TestCase cases[]{
        {"R1 generated execution", testR1ExecutesGeneratedCode},
        {"add carry/zero flags", testAddFlagsCarryAndZero},
        {"add signed-overflow flags", testAddFlagsSignedOverflow},
        {"add register imm32", testAddRegisterImmediate32},
        {"add accumulator imm32", testAddRaxAccumulatorImmediate},
        {"add 32-bit register short immediate", testAdd32BitRegisterShortImmediate},
        {"and result/flags", testAndResultAndFlags},
        {"AND 32-bit registers", testAnd32BitRegisters},
        {"AND 8-bit registers", testAnd8BitRegisters},
        {"AND 8-bit register with RIP-relative guest memory", testAnd8BitRegisterWithRipRelativeGuestMemory},
        {"AND 8-bit register with SIB guest memory", testAnd8BitRegisterWithSibGuestMemory},
        {"AND 64-bit register with guest memory", testAnd64BitRegisterWithGuestMemory},
        {"AND 32-bit register with guest memory", testAnd32BitRegisterWithGuestMemory},
        {"AND 32-bit register with RSP SIB memory", testAnd32BitRegisterWithRspSibMemory},
        {"AND 32-bit register with indexed SIB memory", testAnd32BitRegisterWithIndexedSibMemory},
        {"AND 32-bit register into indexed guest memory", testAnd32BitRegisterIntoIndexedGuestMemory},
        {"AND 16-bit register into guest memory", testAnd16BitRegisterIntoGuestMemory},
        {"AND immediate into guest word", testAndImmediateIntoGuestWord},
        {"AND immediate into guest byte", testAndImmediateIntoGuestByte},
        {"BT 32-bit register with immediate", testBitTestRegisterImmediate32},
        {"BT 32-bit memory with immediate", testBitTestMemoryImmediate32},
        {"BTS/BTR 64-bit register with immediate", testBitSetResetRegisterImmediate64},
        {"BT 32-bit register with register index", testBitTestRegisterIndex32},
        {"BTS 64-bit register with register index", testBitSetRegisterIndex64},
        {"BT guest dword with immediate", testBitTestGuestDwordImmediate},
        {"BSF 32-bit registers", testBitScanForward32},
        {"BSF 64-bit registers", testBitScanForward64},
        {"BSWAP 32-bit register", testByteSwap32},
        {"BSR 32-bit registers", testBitScanReverse32},
        {"BSR 64-bit registers", testBitScanReverse64},
        {"legacy AND 32-bit immediate", testLegacyAnd32Immediate},
        {"AND 8-bit accumulator immediate", testAnd8BitAccumulatorImmediate},
        {"AND 16-bit register short immediate", testAnd16BitRegisterShortImmediate},
        {"AND accumulator immediate", testAndAccumulatorImmediate},
        {"AND 8-bit register immediate", testAnd8BitRegisterImmediate},
        {"AND 32-bit register immediate", testAnd32BitRegisterImmediate},
    };
    return cases;
}

} // namespace rosa::tests
