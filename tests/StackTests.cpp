#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {


void testDecoderR1() {
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(r1Code, rosa::guest::GuestAddress{0x1000});
    expectEqual(decoded.size(), std::size_t{3}, "decoder instruction count differs");
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegImm, "first opcode is not mov");
    expect(decoded[1].opcode == rosa::x86::Opcode::AddRegImm, "second opcode is not add");
    expect(decoded[2].opcode == rosa::x86::Opcode::Ret, "third opcode is not ret");
    expectEqual(decoded[0].length, std::uint8_t{10}, "mov length differs");
    expectEqual(decoded[1].length, std::uint8_t{4}, "add length differs");
    expectEqual(decoded[2].address.value, std::uint64_t{0x100E}, "ret RIP differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "mov destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{40}, "mov immediate differs");
}

void testDecoderExtendedRegisterAndSignedImmediate() {
    constexpr std::array<std::uint8_t, 15> code{
        0x49, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x83, 0xC0, 0xFF, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0});
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::R8,
           "REX.B mov register differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[1].operands[1]).value, UINT64_MAX,
                "imm8 was not sign-extended");
}

void testLegacyMov32ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0xBF, 0x34, 0x00, 0x07, 0x1F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegImm,
           "legacy MOV r32, imm32 opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rdi, "legacy MOV r32 destination differs");
    expectEqual(destination.width, std::uint8_t{32}, "legacy MOV r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x1F070034},
                "legacy MOV r32 did not clear the upper half");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "legacy MOV r32 changed flags");
}

void testLegacyMov16ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0xBA, 0x01, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AA5731ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegImm,
           "legacy MOV r16, imm16 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "legacy MOV r16, imm16 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 16,
           "legacy MOV DX destination differs");
    expect(immediate.width == 16 && immediate.value == 0x101, "legacy MOV DX immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("mov dx, 0x101") != std::string::npos,
           "legacy MOV DX dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AA5731ULL});
    rosa::x86::X86State state;
    state.rdx = 0xAABBCCDDEEFF7788ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0xAABBCCDDEEFF0101ULL},
                "legacy MOV DX did not preserve upper register bits");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "legacy MOV DX changed flags");

    constexpr std::array<std::uint8_t, 6> extendedCode{0x66, 0x41, 0xBC, 0xEF, 0xBE, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x2000});
    const auto extendedDestination =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    expect(extendedDestination.reg == rosa::x86::Register::R12 && extendedDestination.width == 16,
           "REX.B MOV R12W destination differs");
    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State extendedState;
    extendedState.r12 = 0x1122334455667788ULL;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.r12, std::uint64_t{0x112233445566BEEFULL},
                "REX.B MOV R12W did not preserve upper register bits");
}

void testLegacyMovLowByteImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0xB1, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegImm, "MOV low byte, imm8 opcode differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rcx, "MOV CL, imm8 register differs");
    expectEqual(operand.width, std::uint8_t{8}, "MOV CL, imm8 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0xAABBCCDDEEFF0080ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xAABBCCDDEEFF0001ULL},
                "MOV CL, imm8 did not preserve upper register bits");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV CL, imm8 changed flags");
}

void testRexExtendedMovLowByteImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x41, 0xB6, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegImm, "REX MOV r8, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "REX MOV r8, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R14, "REX MOV r8, imm8 destination differs");
    expectEqual(destination.width, std::uint8_t{8}, "REX MOV r8, imm8 destination width differs");
    expectEqual(immediate.value, std::uint64_t{1}, "REX MOV r8, imm8 immediate differs");
    expectEqual(immediate.width, std::uint8_t{8}, "REX MOV r8, imm8 immediate width differs");
    expect(rosa::debug::dumpX86(decoded).find("mov r14b, 0x1") != std::string::npos,
           "REX MOV r8, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0x11223344556677A5ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0x1122334455667701ULL},
                "REX MOV r8, imm8 did not replace only the low byte");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "REX MOV r8, imm8 changed flags");

    constexpr std::array<std::uint8_t, 3> highByteCode{0xB4, 0x01, 0xC3};
    bool rejectedHighByte = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejectedHighByte = true;
    }
    expect(rejectedHighByte, "legacy MOV AH, imm8 was silently decoded as a low-byte register");
}

void testRexExtendedMov32ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 7> code{
        0x41, 0xBD, 0x20, 0x00, 0x00, 0x00, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegImm, "REX MOV r32, imm32 opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::R13, "REX MOV r32 destination differs");
    expectEqual(destination.width, std::uint8_t{32}, "REX MOV r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r13 = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r13, std::uint64_t{0x20}, "REX MOV r32 did not clear the upper half");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "REX MOV r32 changed flags");
}

void testDecoderPushImm8() {
    constexpr std::array<std::uint8_t, 3> positive{0x6A, 0x7F, 0xC3};
    constexpr std::array<std::uint8_t, 3> negative{0x6A, 0x80, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto positiveDecoded = decoder.decodeBlock(positive, rosa::guest::GuestAddress{0x1000});
    const auto negativeDecoded = decoder.decodeBlock(negative, rosa::guest::GuestAddress{0x2000});
    expect(positiveDecoded[0].opcode == rosa::x86::Opcode::Push,
           "positive PUSH imm8 opcode differs");
    expectEqual(positiveDecoded[0].length, std::uint8_t{2}, "PUSH imm8 length differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(positiveDecoded[0].operands[0]).value,
                std::uint64_t{0x7F}, "positive PUSH imm8 value differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(negativeDecoded[0].operands[0]).value,
                std::uint64_t{0xFFFFFFFFFFFFFF80ULL},
                "negative PUSH imm8 was not sign-extended to 64 bits");
}

std::pair<rosa::x86::X86State, std::uint64_t> executePushImm8(std::uint8_t immediate) {
    const std::array<std::uint8_t, 3> code{0x6A, immediate, 0xC3};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rip = 0x1000;
    state.rsp = stackTop;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    return {state, addressSpace.readU64(rosa::guest::GuestAddress{stackTop - 8})};
}

void testPushImm8GeneratedExecution() {
    const auto [positiveState, positiveValue] = executePushImm8(0x7F);
    expectEqual(positiveState.rsp, std::uint64_t{0x700000000FF8ULL},
                "positive PUSH imm8 did not decrement RSP by 8");
    expectEqual(positiveValue, std::uint64_t{0x7F},
                "positive PUSH imm8 did not store a 64-bit guest value");
    expectEqual(positiveState.rflags, std::uint64_t{0xAD7},
                "positive PUSH imm8 changed guest flags");

    const auto [negativeState, negativeValue] = executePushImm8(0x80);
    expectEqual(negativeState.rsp, std::uint64_t{0x700000000FF8ULL},
                "negative PUSH imm8 did not decrement RSP by 8");
    expectEqual(negativeValue, std::uint64_t{0xFFFFFFFFFFFFFF80ULL},
                "negative PUSH imm8 did not store the sign-extended 64-bit value");
    expectEqual(negativeState.rflags, std::uint64_t{0xAD7},
                "negative PUSH imm8 changed guest flags");
}

void testPushImm8GuestStackFaults() {
    constexpr std::array<std::uint8_t, 3> code{0x6A, 0xFF, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State unmappedState;
    unmappedState.rip = 0x1000;
    unmappedState.rsp = 0x9000;
    unmappedState.rflags = 0x202;
    bool unmappedRejected = false;
    try {
        static_cast<void>(block.execute(unmappedState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        unmappedRejected =
            std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(unmappedRejected, "PUSH imm8 to an unmapped guest stack did not fail");
    expectEqual(unmappedState.rsp, std::uint64_t{0x9000}, "failed unmapped PUSH imm8 changed RSP");
    expectEqual(unmappedState.rflags, std::uint64_t{0x202},
                "failed unmapped PUSH imm8 changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    rosa::x86::X86State readOnlyState;
    readOnlyState.rip = 0x1000;
    readOnlyState.rsp = 0x9000;
    bool readOnlyRejected = false;
    try {
        static_cast<void>(block.execute(readOnlyState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        readOnlyRejected =
            std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(readOnlyRejected, "PUSH imm8 to a read-only guest stack did not fail");
    expectEqual(readOnlyState.rsp, std::uint64_t{0x9000}, "failed read-only PUSH imm8 changed RSP");
}

void testPushImm32GeneratedExecutionAndFault() {
    constexpr std::array<std::uint8_t, 6> observed{0x68, 0x40, 0x01, 0x00, 0x00, 0xC3};
    constexpr std::array<std::uint8_t, 6> negative{0x68, 0x00, 0x00, 0x00, 0x80, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto observedDecoded =
        decoder.decodeBlock(observed, rosa::guest::GuestAddress{0x7FF802A8F2A4ULL});
    const auto negativeDecoded = decoder.decodeBlock(negative, rosa::guest::GuestAddress{0x1000});
    expect(observedDecoded[0].opcode == rosa::x86::Opcode::Push, "PUSH imm32 opcode differs");
    expectEqual(observedDecoded[0].length, std::uint8_t{5}, "PUSH imm32 length differs");
    const auto observedImmediate =
        std::get<rosa::x86::ImmediateOperand>(observedDecoded[0].operands[0]);
    expect(observedImmediate.width == 32 && observedImmediate.value == 0x140,
           "positive PUSH imm32 value differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(negativeDecoded[0].operands[0]).value,
                std::uint64_t{0xFFFFFFFF80000000ULL}, "negative PUSH imm32 was not sign-extended");
    expect(rosa::debug::dumpX86(observedDecoded).find("push 0x140") != std::string::npos,
           "PUSH imm32 dump differs");

    constexpr rosa::guest::GuestAddress stackBase{0x8000};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(negative, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsp = stackTop;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rsp, stackTop - 8, "PUSH imm32 did not decrement RSP by 8");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{stackTop - 8}),
                std::uint64_t{0xFFFFFFFF80000000ULL},
                "PUSH imm32 did not store a sign-extended qword");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "PUSH imm32 changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rsp = 0x9000;
    faultState.rflags = 0x202;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "PUSH imm32 to unmapped guest stack did not fault");
    expectEqual(faultState.rsp, std::uint64_t{0x9000}, "faulted PUSH imm32 changed RSP");
    expectEqual(faultState.rflags, std::uint64_t{0x202}, "faulted PUSH imm32 changed flags");

    constexpr std::array<std::uint8_t, 4> truncated{0x68, 0x01, 0x02, 0x03};
    bool truncatedRejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(truncated, rosa::guest::GuestAddress{0x1000}));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated PUSH imm32 was accepted");
}

void testPushRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x55, 0x41, 0x57, 0xC3};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Push, "PUSH rbp opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rbp,
           "PUSH rbp register differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[1].operands[0]).reg ==
               rosa::x86::Register::R15,
           "REX PUSH r15 register differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto pushRbp = translator.translate(code, rosa::guest::GuestAddress{0x1000}, 1);
    const auto pushR15 =
        translator.translate(std::span(code).subspan(1), rosa::guest::GuestAddress{0x1001}, 1);
    rosa::x86::X86State state;
    state.rip = 0x1000;
    state.rsp = stackTop;
    state.rbp = 0x0123456789ABCDEFULL;
    state.r15 = 0xFEDCBA9876543210ULL;
    state.rflags = 0x8D7;
    static_cast<void>(pushRbp.execute(state, &addressSpace));
    static_cast<void>(pushR15.execute(state, &addressSpace));
    expectEqual(state.rsp, stackTop - 16, "two register PUSHes did not update RSP");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{stackTop - 8}), state.rbp,
                "PUSH rbp stored the wrong guest value");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{stackTop - 16}), state.r15,
                "PUSH r15 stored the wrong guest value");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "register PUSH changed guest flags");
}

void testPushGuestMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> observedCode{0x41, 0xFF, 0x74,
                                                       0x24, 0x10, 0xC3}; // push qword [r12+0x10]
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802AC0D22ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::Push, "PUSH guest memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "PUSH guest memory length differs");
    const auto source = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(source.base == rosa::x86::Register::R12 && source.displacement == 0x10 &&
               source.width == 64 && !source.index,
           "PUSH [r12+disp8] source differs");
    expect(rosa::debug::dumpX86(decoded).find("push [r12+0x10]") != std::string::npos,
           "PUSH guest memory dump differs");

    constexpr rosa::guest::GuestAddress dataBase{0x5000};
    constexpr rosa::guest::GuestAddress stackBase{0x8000};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(dataBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::uint64_t pushedValue = 0x0123456789ABCDEFULL;
    addressSpace.writeU64(rosa::guest::GuestAddress{dataBase.value + 0x10}, pushedValue);

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    rosa::x86::X86State state;
    state.rip = observedRip.value;
    state.r12 = dataBase.value;
    state.rsp = stackTop;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rsp, stackTop - 8, "PUSH guest memory did not decrement RSP");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{stackTop - 8}), pushedValue,
                "PUSH guest memory stored the wrong value");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PUSH guest memory changed flags");

    state.rip = observedRip.value;
    state.r12 = 0xA000;
    state.rsp = stackTop;
    state.rflags = 0x202;
    addressSpace.writeU64(rosa::guest::GuestAddress{stackTop - 8}, UINT64_MAX);
    bool sourceFaulted = false;
    try {
        static_cast<void>(block.execute(state, &addressSpace));
    } catch (const std::runtime_error &error) {
        sourceFaulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(sourceFaulted, "PUSH guest memory accepted an unmapped source");
    expectEqual(state.rsp, stackTop, "source-faulted PUSH guest memory changed RSP");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{stackTop - 8}), UINT64_MAX,
                "source-faulted PUSH guest memory changed the stack");
    expectEqual(state.rflags, std::uint64_t{0x202},
                "source-faulted PUSH guest memory changed flags");
}

void testPopRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 2> popRbpCode{0x5D, 0xC3};
    constexpr std::array<std::uint8_t, 2> popRspCode{0x5C, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(popRbpCode, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Pop, "POP r64 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rbp,
           "POP rbp destination differs");

    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackBase.value + 0x100},
                          0x0123456789ABCDEFULL);
    const rosa::dbt::Translator translator;
    const auto popRbp = translator.translate(popRbpCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsp = stackBase.value + 0x100;
    state.rbp = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(popRbp.execute(state, &addressSpace));
    expectEqual(state.rbp, std::uint64_t{0x0123456789ABCDEFULL}, "POP rbp loaded the wrong value");
    expectEqual(state.rsp, stackBase.value + 0x108, "POP rbp RSP update differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "POP rbp changed flags");

    addressSpace.writeU64(rosa::guest::GuestAddress{stackBase.value + 0x200}, 0x1234);
    const auto popRsp = translator.translate(popRspCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State rspState;
    rspState.rsp = stackBase.value + 0x200;
    static_cast<void>(popRsp.execute(rspState, &addressSpace));
    expectEqual(rspState.rsp, std::uint64_t{0x1234},
                "POP rsp did not apply the destination write last");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rsp = stackBase.value + 0x100;
    faultState.rbp = 0x55;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(popRbp.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "POP from unmapped guest stack did not fail");
    expectEqual(faultState.rsp, stackBase.value + 0x100, "failed POP changed RSP");
    expectEqual(faultState.rbp, std::uint64_t{0x55}, "failed POP changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "failed POP changed flags");
}

void testLeaveGeneratedExecution() {
    constexpr std::array<std::uint8_t, 2> code{0xC9, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802BEF23EULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::Leave, "LEAVE opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{1}, "LEAVE length differs");
    expect(rosa::debug::dumpX86(decoded).find("leave") != std::string::npos, "LEAVE dump differs");

    constexpr rosa::guest::GuestAddress stackPage{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress frame{stackPage.value + 0x180};
    constexpr std::uint64_t savedFrame = 0x0123456789ABCDEFULL;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(frame, savedFrame);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State state;
    state.rsp = stackPage.value + 0x80;
    state.rbp = frame.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rsp, frame.value + sizeof(std::uint64_t),
                "LEAVE produced the wrong stack pointer");
    expectEqual(state.rbp, savedFrame, "LEAVE popped the wrong frame pointer");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "LEAVE changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rsp = stackPage.value + 0x80;
    faultState.rbp = frame.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "LEAVE accepted an unmapped saved-frame address");
    expectEqual(faultState.rsp, frame.value, "faulted LEAVE did not commit RSP = RBP first");
    expectEqual(faultState.rbp, frame.value, "faulted LEAVE changed RBP");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted LEAVE changed flags");
}

} // namespace

std::span<const TestCase> stackTests() {
    static const TestCase cases[]{
        {"R1 decoder", testDecoderR1},
        {"extended register and signed immediate", testDecoderExtendedRegisterAndSignedImmediate},
        {"legacy MOV 32-bit immediate", testLegacyMov32ImmediateGeneratedExecution},
        {"legacy MOV 16-bit immediate", testLegacyMov16ImmediateGeneratedExecution},
        {"legacy MOV low-byte immediate", testLegacyMovLowByteImmediateGeneratedExecution},
        {"REX extended MOV low-byte immediate", testRexExtendedMovLowByteImmediateGeneratedExecution},
        {"REX extended MOV 32-bit immediate", testRexExtendedMov32ImmediateGeneratedExecution},
        {"PUSH imm8 decoder", testDecoderPushImm8},
        {"PUSH imm8 generated execution", testPushImm8GeneratedExecution},
        {"PUSH imm8 guest stack faults", testPushImm8GuestStackFaults},
        {"PUSH imm32 generated execution and fault", testPushImm32GeneratedExecutionAndFault},
        {"PUSH register generated execution", testPushRegisterGeneratedExecution},
        {"PUSH guest memory generated execution", testPushGuestMemoryGeneratedExecution},
        {"POP register generated execution", testPopRegisterGeneratedExecution},
        {"LEAVE generated execution", testLeaveGeneratedExecution},
    };
    return cases;
}

} // namespace rosa::tests
