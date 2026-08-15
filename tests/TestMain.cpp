#include "arm64/Assembler.h"
#include "arm64/CodeBuffer.h"
#include "dbt/Dispatcher.h"
#include "dbt/Translator.h"
#include "darwin/Commpage.h"
#include "debug/Dump.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "guest/StartupStack.h"
#include "ir/IR.h"
#include "macho/Loader.h"
#include "macho/MachOFile.h"
#include "x86/Decoder.h"
#include "x86/Instruction.h"
#include "x86/Registers.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

template <typename Actual, typename Expected>
void expectEqual(const Actual &actual, const Expected &expected, std::string_view message) {
    if (actual != expected) {
        throw std::runtime_error(std::string(message));
    }
}

void expect(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::uint64_t fixedTimestampCounter() { return 0x12345678ABCDEF01ULL; }

void testAssemblerEncodings() {
    rosa::arm64::Assembler assembler;
    assembler.movImmediate(rosa::arm64::x0, 42);
    assembler.add(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.lslImmediate(rosa::arm64::x10, rosa::arm64::x9, 32);
    assembler.lslVariable(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.multiplyLow(rosa::arm64::x11, rosa::arm64::x9, rosa::arm64::x10);
    assembler.multiplyHighUnsigned(rosa::arm64::x12, rosa::arm64::x9,
                                   rosa::arm64::x10);
    assembler.extract(rosa::arm64::x11, rosa::arm64::x10, rosa::arm64::x9, 32);
    assembler.bitAnd(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.bitOr(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.ldr(rosa::arm64::x9, rosa::arm64::x0, 0);
    assembler.ldr32(rosa::arm64::x9, rosa::arm64::x0, 0);
    assembler.str(rosa::arm64::x9, rosa::arm64::x0, 0);
    assembler.blr(rosa::arm64::x16);
    assembler.pushFrameRecord();
    assembler.popFrameRecord();
    assembler.dmbIsh();
    assembler.isb();
    assembler.ret();

    const std::array<std::uint32_t, 18> expected{
        0xD2800540U, 0x8B0B012AU, 0xD3607D2AU, 0x9ACB212AU, 0x9B0A7D2BU,
        0x9BCA7D2CU, 0x93C9814BU, 0x8A0B012AU, 0xAA0B012AU, 0xF9400009U,
        0xB9400009U, 0xF9000009U, 0xD63F0200U, 0xA9BF7BFDU, 0xA8C17BFDU,
        0xD5033BBFU, 0xD5033FDFU, 0xD65F03C0U,
    };
    expectEqual(assembler.words().size(), expected.size(), "assembler word count differs");
    for (std::size_t index = 0; index < expected.size(); ++index) {
        expectEqual(assembler.words()[index], expected[index], "ARM64 encoding differs");
    }
}

void testR0ExecutesGeneratedCode() {
    rosa::arm64::Assembler assembler;
    assembler.movImmediate(rosa::arm64::x0, 0x1234);
    assembler.ret();
    auto program = std::move(assembler).finish();
    rosa::arm64::ExecutableCode code(program.bytes);
    using Entry = std::uint64_t (*)();
    expectEqual(code.entry<Entry>()(), std::uint64_t{0x1234},
                "generated R0 function returned the wrong value");
}

void testAssemblerLabels() {
    rosa::arm64::Assembler assembler;
    const auto target = assembler.makeLabel();
    assembler.b(target);
    assembler.movImmediate(rosa::arm64::x0, 1);
    assembler.bind(target);
    assembler.ret();
    const auto program = std::move(assembler).finish();
    const auto firstWord = static_cast<std::uint32_t>(program.bytes[0]) |
                           (static_cast<std::uint32_t>(program.bytes[1]) << 8U) |
                           (static_cast<std::uint32_t>(program.bytes[2]) << 16U) |
                           (static_cast<std::uint32_t>(program.bytes[3]) << 24U);
    expectEqual(firstWord, 0x14000002U, "forward ARM64 label fixup differs");

    rosa::arm64::Assembler compareAssembler;
    const auto compareTarget = compareAssembler.makeLabel();
    compareAssembler.cbz(rosa::arm64::x0, compareTarget);
    compareAssembler.movImmediate(rosa::arm64::x0, 1);
    compareAssembler.bind(compareTarget);
    compareAssembler.ret();
    const auto compareProgram = std::move(compareAssembler).finish();
    const auto compareWord = static_cast<std::uint32_t>(compareProgram.bytes[0]) |
                             (static_cast<std::uint32_t>(compareProgram.bytes[1]) << 8U) |
                             (static_cast<std::uint32_t>(compareProgram.bytes[2]) << 16U) |
                             (static_cast<std::uint32_t>(compareProgram.bytes[3]) << 24U);
    expectEqual(compareWord, 0xB4000040U, "forward ARM64 CBZ label fixup differs");
}

constexpr std::array<std::uint8_t, 15> r1Code{
    0x48, 0xB8, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC0, 0x02, 0xC3,
};

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

void testDecoderPushImm8() {
    constexpr std::array<std::uint8_t, 3> positive{0x6A, 0x7F, 0xC3};
    constexpr std::array<std::uint8_t, 3> negative{0x6A, 0x80, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto positiveDecoded =
        decoder.decodeBlock(positive, rosa::guest::GuestAddress{0x1000});
    const auto negativeDecoded =
        decoder.decodeBlock(negative, rosa::guest::GuestAddress{0x2000});
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
        unmappedRejected = std::string_view(error.what()).find("unmapped") !=
                           std::string_view::npos;
    }
    expect(unmappedRejected, "PUSH imm8 to an unmapped guest stack did not fail");
    expectEqual(unmappedState.rsp, std::uint64_t{0x9000},
                "failed unmapped PUSH imm8 changed RSP");
    expectEqual(unmappedState.rflags, std::uint64_t{0x202},
                "failed unmapped PUSH imm8 changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                                      rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    rosa::x86::X86State readOnlyState;
    readOnlyState.rip = 0x1000;
    readOnlyState.rsp = 0x9000;
    bool readOnlyRejected = false;
    try {
        static_cast<void>(block.execute(readOnlyState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        readOnlyRejected = std::string_view(error.what()).find("permissions") !=
                           std::string_view::npos;
    }
    expect(readOnlyRejected, "PUSH imm8 to a read-only guest stack did not fail");
    expectEqual(readOnlyState.rsp, std::uint64_t{0x9000},
                "failed read-only PUSH imm8 changed RSP");
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
    const auto pushR15 = translator.translate(std::span(code).subspan(1),
                                              rosa::guest::GuestAddress{0x1001}, 1);
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

void testSubRegImm32GeneratedExecution() {
    constexpr std::array<std::uint8_t, 8> positive{
        0x48, 0x81, 0xEC, 0x58, 0x06, 0x00, 0x00, 0xC3,
    };
    constexpr std::array<std::uint8_t, 8> negative{
        0x49, 0x81, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(positive, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegImm,
           "SUB r64, imm32 opcode differs");
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
    expectEqual(positiveState.rsp, std::uint64_t{0x9A8},
                "SUB rsp, positive imm32 result differs");
    expectEqual(positiveState.rflags, std::uint64_t{0x12},
                "SUB rsp, positive imm32 flags differ");

    const auto negativeBlock = translator.translate(negative, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State negativeState;
    negativeState.r8 = 41;
    static_cast<void>(negativeBlock.execute(negativeState));
    expectEqual(negativeState.r8, std::uint64_t{42},
                "SUB r8, negative imm32 did not use sign extension");
    expectEqual(negativeState.rflags, std::uint64_t{0x13},
                "SUB r8, negative imm32 flags differ");
}

void testSubRegImm8GeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x83, 0xEC, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegImm,
           "SUB r64, imm8 opcode differs");
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

void testSubRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x2B, 0x06, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegMem,
           "SUB r64, [base] opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "SUB r64, [base] destination differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsi,
           "SUB r64, [base] base differs");

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
    expectEqual(state.rax, std::uint64_t{UINT64_MAX - 1},
                "SUB r64, [base] result differs");
    expectEqual(state.rsi, std::uint64_t{0x8100},
                "SUB r64, [base] changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x93},
                "SUB r64, [base] flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 5;
    faultState.rsi = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "SUB from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{5},
                "failed memory SUB changed its destination register");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed memory SUB changed flags");
}

void testAddRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x03, 0x46, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegMem,
           "ADD r64, [base+disp8] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsi,
           "ADD r64, [base+disp8] base differs");
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
    expectEqual(state.rflags, std::uint64_t{0x13},
                "ADD r64, [base+disp8] flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 9;
    faultState.rsi = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "ADD from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{9},
                "failed memory ADD changed its destination register");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed memory ADD changed flags");
}

void testCompare32BitRegisterWithGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x3B, 0x46, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegMem,
           "CMP r32, [base+disp8] opcode differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(lhs.reg == rosa::x86::Register::R8,
           "CMP r32, [base+disp8] register differs");
    expectEqual(lhs.width, std::uint8_t{32}, "CMP r32 width differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8118}, 1);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r8 = 0xFFFFFFFF00000001ULL;
    state.rsi = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r8, std::uint64_t{0xFFFFFFFF00000001ULL},
                "CMP r32 changed its register operand");
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP r32 equal flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r8 = 1;
    faultState.rsi = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "CMP from unmapped guest memory did not fail");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed memory CMP changed flags");
}

void testMovRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 12> code{
        0x48, 0x89, 0xBD, 0x58, 0xFF, 0xFF, 0xFF,
        0x48, 0x89, 0x4D, 0xC0,
        0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "MOV [base+disp32], r64 opcode differs");
    const auto firstMemory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(firstMemory.base == rosa::x86::Register::Rbp,
           "MOV [base+disp32], r64 base differs");
    expectEqual(firstMemory.displacement, std::int64_t{-0xA8},
                "MOV [base+disp32], r64 displacement differs");
    const auto secondMemory = std::get<rosa::x86::MemoryOperand>(decoded[1].operands[0]);
    expectEqual(secondMemory.displacement, std::int64_t{-0x40},
                "MOV [base+disp8], r64 displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto firstStore = translator.translate(code, rosa::guest::GuestAddress{0x1000}, 1);
    const auto secondStore = translator.translate(std::span(code).subspan(7),
                                                  rosa::guest::GuestAddress{0x1007}, 1);
    rosa::x86::X86State state;
    state.rip = 0x1000;
    state.rbp = 0x8800;
    state.rdi = 0x0123456789ABCDEFULL;
    state.rcx = 0xFEDCBA9876543210ULL;
    state.rflags = 0x8D7;
    static_cast<void>(firstStore.execute(state, &addressSpace));
    static_cast<void>(secondStore.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8758}), state.rdi,
                "MOV [base+disp32], r64 stored the wrong value");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x87C0}), state.rcx,
                "MOV [base+disp8], r64 stored the wrong value");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV register to guest memory changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    rosa::x86::X86State faultState;
    faultState.rbp = 0x8800;
    faultState.rdi = state.rdi;
    bool rejected = false;
    try {
        static_cast<void>(firstStore.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOV to read-only guest memory did not fail");
    expectEqual(faultState.rbp, std::uint64_t{0x8800},
                "failed guest-memory MOV changed the base register");
    expectEqual(faultState.rdi, state.rdi,
                "failed guest-memory MOV changed the source register");
}

void testMovGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x8B, 0x03, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV r64, [base] opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "MOV r64, [base] destination differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx,
           "MOV r64, [base] base register differs");
    expectEqual(memory.displacement, std::int64_t{0},
                "MOV r64, [base] displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::uint64_t value = 0x0123456789ABCDEFULL;
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8100}, value);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, value, "MOV r64, [base] loaded the wrong guest value");
    expectEqual(state.rbx, std::uint64_t{0x8100},
                "MOV r64, [base] changed the base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV r64, [base] changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x55;
    faultState.rbx = 0x8100;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOV from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{0x55},
                "failed guest-memory load changed the destination register");
}

void testMovGuestMemoryTo32BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x8B, 0x46, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV r32, [base+disp8] opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::R8,
           "MOV r32, [base+disp8] extended destination differs");
    expectEqual(destination.width, std::uint8_t{32},
                "MOV r32, [base+disp8] destination width differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8118}, 0xFEDCBA9876543210ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsi = 0x8100;
    state.r8 = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r8, std::uint64_t{0x76543210},
                "MOV r32, [base+disp8] did not zero-extend the guest value");
    expectEqual(state.rsi, std::uint64_t{0x8100},
                "MOV r32, [base+disp8] changed the base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV r32, [base+disp8] changed flags");
}

void testMovGuestMemoryToLegacy32BitRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x8B, 0x4E, 0x0C, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rcx,
           "legacy MOV r32, [base+disp8] destination differs");
    expectEqual(destination.width, std::uint8_t{32},
                "legacy MOV r32, [base+disp8] width differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x810C}, 0xFEDCBA9876543210ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsi = 0x8100;
    state.rcx = UINT64_MAX;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0x76543210},
                "legacy MOV r32, [base+disp8] did not zero-extend");
}

void testTestRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x85, 0xC9, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegReg,
           "TEST r64, r64 opcode differs");
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
    constexpr auto expectedZeroFlags =
        (UINT64_MAX & ~std::uint64_t{0x8D5}) | std::uint64_t{0x46};
    expectEqual(zeroState.rflags, expectedZeroFlags,
                "TEST zero-result flags differ");

    rosa::x86::X86State signState;
    signState.rcx = 0x8000000000000001ULL;
    static_cast<void>(block.execute(signState));
    expectEqual(signState.rcx, std::uint64_t{0x8000000000000001ULL},
                "TEST changed a nonzero guest register operand");
    expectEqual(signState.rflags, std::uint64_t{0x82},
                "TEST sign-result flags differ");
}

void testTest32BitRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x45, 0x85, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegReg,
           "TEST r32, r32 opcode differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::R8,
           "TEST r32, r32 extended register differs");
    expectEqual(operand.width, std::uint8_t{32}, "TEST r32, r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r8 = 0xFFFFFFFF80000000ULL;
    state.rflags = UINT64_MAX;
    static_cast<void>(block.execute(state));
    expectEqual(state.r8, std::uint64_t{0xFFFFFFFF80000000ULL},
                "TEST r32, r32 changed its guest operand");
    constexpr auto expectedFlags =
        (UINT64_MAX & ~std::uint64_t{0x8D5}) | std::uint64_t{0x86};
    expectEqual(state.rflags, expectedFlags, "TEST r32, r32 flags differ");
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
    expectEqual(state.rax, std::uint64_t{0x0123456789ABCDEFULL},
                "LFENCE changed a guest register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "LFENCE changed guest flags");
    expect(std::find(block.program().listing.begin(), block.program().listing.end(), "dmb ish") !=
               block.program().listing.end(),
           "LFENCE did not emit an ARM64 memory barrier");
    expect(std::find(block.program().listing.begin(), block.program().listing.end(), "isb") !=
               block.program().listing.end(),
           "LFENCE did not emit an ARM64 instruction barrier");
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
    expectEqual(state.rax, std::uint64_t{0xABCDEF01},
                "RDTSC did not zero-extend EAX");
    expectEqual(state.rdx, std::uint64_t{0x12345678},
                "RDTSC did not zero-extend EDX");
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
    expectEqual(missingSourceState.rax, std::uint64_t{0x55},
                "failed RDTSC changed guest EAX");
}

void testShiftLeftImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0xC1, 0xE2, 0x20, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShlRegImm,
           "SHL r64, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{32}, "SHL r64, imm8 count differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0x0000000180000001ULL;
    state.rflags = 0x812;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0x8000000100000000ULL},
                "SHL r64, 32 result differs");
    expectEqual(state.rflags, std::uint64_t{0x897},
                "SHL r64, 32 flags differ");

    constexpr std::array<std::uint8_t, 5> zeroCount{0x48, 0xC1, 0xE2, 0x40, 0xC3};
    const auto zeroBlock =
        translator.translate(zeroCount, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State zeroState;
    zeroState.rdx = 0x55;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rdx, std::uint64_t{0x55},
                "SHL with a masked zero count changed the value");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHL with a masked zero count changed flags");
}

void testShiftLeftClGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0xD3, 0xE0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShlRegCl,
           "SHL r64, CL opcode differs");
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
    expectEqual(state.rax, std::uint64_t{2},
                "SHL r64, CL did not mask the count to six bits");
    expectEqual(state.rcx, std::uint64_t{65}, "SHL r64, CL changed RCX");
    expectEqual(state.rflags, std::uint64_t{0x813},
                "SHL r64, CL flags differ");

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
    expectEqual(smallState.rflags, std::uint64_t{0xD6},
                "MUL zero-high defined flags differ");

    rosa::x86::X86State wideState;
    wideState.rax = UINT64_MAX;
    wideState.rcx = 2;
    wideState.rflags = 0x2;
    static_cast<void>(block.execute(wideState));
    expectEqual(wideState.rax, std::uint64_t{UINT64_MAX - 1},
                "MUL wide low result differs");
    expectEqual(wideState.rdx, std::uint64_t{1}, "MUL wide high result differs");
    expectEqual(wideState.rflags, std::uint64_t{0x803},
                "MUL nonzero-high defined flags differ");
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
    expectEqual(state.rax, std::uint64_t{0x7654321001234567ULL},
                "SHRD result differs");
    expectEqual(state.rdx, std::uint64_t{0xFEDCBA9876543210ULL},
                "SHRD changed its source");
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
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHRD masked-zero count changed flags");
}

void testOrRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x09, 0xD0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegReg,
           "OR r64, r64 opcode differs");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x00000000ABCDEF01ULL;
    state.rdx = 0x1234567800000000ULL;
    state.rflags = UINT64_MAX;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x12345678ABCDEF01ULL},
                "OR r64, r64 result differs");
    expectEqual(state.rdx, std::uint64_t{0x1234567800000000ULL},
                "OR r64, r64 changed its source");
    constexpr auto expectedFlags =
        (UINT64_MAX & ~std::uint64_t{0x8D5}) | std::uint64_t{0x2};
    expectEqual(state.rflags, expectedFlags, "OR r64, r64 flags differ");
}

void testRegisterMoveExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x89, 0xE7, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State state;
    state.rsp = 0x12345678;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, state.rsp, "generated register MOV result differs");
}

void testDecoderRejectsUnsupportedInstruction() {
    constexpr std::array<std::uint8_t, 2> code{0x0F, 0x0B};
    const rosa::x86::Decoder decoder;
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(code, rosa::guest::GuestAddress{0xCAFE}));
    } catch (const rosa::x86::DecodeError &error) {
        rejected =
            std::string_view(error.what()).find("guest RIP 0xcafe") != std::string_view::npos;
    }
    expect(rejected, "unsupported x86 instruction did not fail diagnostically");
}

void testDecoderRipRelativeLeaAndSyscall() {
    constexpr std::array<std::uint8_t, 9> code{
        0x48, 0x8D, 0x35, 0x04, 0x00, 0x00, 0x00, 0x0F, 0x05,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expectEqual(decoded.size(), std::size_t{2}, "LEA/syscall instruction count differs");
    expect(decoded[0].opcode == rosa::x86::Opcode::LeaRegRipRelative,
           "RIP-relative LEA opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0x100B}, "RIP-relative LEA target differs");
    expect(decoded[1].opcode == rosa::x86::Opcode::Syscall, "syscall opcode differs");
    expectEqual(decoded[1].fallthrough->value, std::uint64_t{0x1009},
                "syscall fallthrough differs");
}

void testIrVerification() {
    rosa::ir::Builder builder(rosa::guest::GuestAddress{0x1000});
    const auto lhs = builder.constant(40, rosa::ir::Width::I64, rosa::guest::GuestAddress{0x1000});
    const auto rhs = builder.constant(2, rosa::ir::Width::I64, rosa::guest::GuestAddress{0x100A});
    const auto result =
        builder.add(lhs, rhs, rosa::ir::Width::I64, rosa::guest::GuestAddress{0x100A});
    builder.writeGuestRegister(rosa::x86::Register::Rax, result, rosa::ir::Width::I64,
                               rosa::guest::GuestAddress{0x100A});
    builder.updateAddFlags(lhs, rhs, result, rosa::ir::Width::I64,
                           rosa::guest::GuestAddress{0x100A});
    builder.exitBlock(rosa::guest::GuestAddress{0x100E});
    const auto block = std::move(builder).finish();
    expect(rosa::ir::verify(block).empty(), "valid R1 IR failed verification");
}

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

void testAndResultAndFlags() {
    constexpr std::array<std::uint8_t, 15> code{
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x83, 0xE0, 0xF0, 0xC3,
    };
    const auto state = execute(code);
    expectEqual(state.rax, std::uint64_t{0xFFFFFFFFFFFFFFF0ULL}, "AND result differs");
    expectEqual(state.rflags, std::uint64_t{0x86}, "AND PF/SF flags differ");
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
    expectEqual(state.rflags, std::uint64_t{0x2},
                "legacy AND r32, imm8 flags differ");
}

void testGuestAddressSpace() {
    constexpr rosa::guest::GuestAddress base{0x4000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(base, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "test mapping");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x4FF8}, 0x0123456789ABCDEFULL);
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x4FF8}),
                std::uint64_t{0x0123456789ABCDEFULL}, "guest memory round trip differs");

    bool rejected = false;
    try {
        addressSpace.writeU64(rosa::guest::GuestAddress{0x4FFC}, 1);
    } catch (const std::runtime_error &) {
        rejected = true;
    }
    expect(rejected, "cross-mapping guest memory access was not rejected");
    const auto mappings = addressSpace.mappingInfos();
    expectEqual(mappings.size(), std::size_t{1}, "mapping summary count differs");
    expectEqual(mappings[0].base.value, base.value, "mapping summary base differs");
    expectEqual(mappings[0].size, rosa::guest::guestPageSize,
                "mapping summary size differs");
    expectEqual(mappings[0].label, std::string("test mapping"),
                "mapping summary label differs");
}

void testGuestFailureReport() {
    constexpr std::array<std::uint8_t, 12> code{
        0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x0B,
    };
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute,
                            code, "test-image:__TEXT");
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "test stack");
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize;
    state.rflags = 0x202;
    rosa::dbt::Dispatcher dispatcher(addressSpace, 1);
    std::string report;
    try {
        static_cast<void>(dispatcher.run(state, 8));
    } catch (const rosa::x86::DecodeError &error) {
        report = rosa::debug::dumpGuestFailure("fallback-image", error, state, addressSpace,
                                               dispatcher);
    }
    expect(!report.empty(), "unsupported instruction did not produce a guest failure report");
    expect(report.find("image=test-image:__TEXT") != std::string::npos,
           "guest failure report omitted the current image");
    expect(report.find("RIP=0x100a") != std::string::npos,
           "guest failure report omitted RIP");
    expect(report.find("RSP=0x9000") != std::string::npos,
           "guest failure report omitted RSP");
    expect(report.find("RFLAGS=0x202") != std::string::npos,
           "guest failure report omitted RFLAGS");
    expect(report.find("RAX=0x2a") != std::string::npos,
           "guest failure report omitted general registers");
    expect(report.find("0f 0b") != std::string::npos,
           "guest failure report omitted failing instruction bytes");
    expect(report.find("mov rax, 0x2a") != std::string::npos,
           "guest failure report omitted recent decoded history");
    expect(report.find("test stack") != std::string::npos,
           "guest failure report omitted the stack mapping");
    expect(report.find("executed=1 translations=1") != std::string::npos,
           "guest failure report omitted execution counters");
}

void testX86CommpageContinuousTimebase() {
    rosa::guest::AddressSpace addressSpace;
    constexpr std::uint64_t continuousTimebase = 0x0123456789ABCDEFULL;
    rosa::darwin::mapX86CommpageContinuousTimebase(addressSpace, continuousTimebase);
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageContinuousTimebaseOffset}),
                continuousTimebase, "x86 commpage continuous-time base differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeGenerationOffset}),
                std::uint32_t{1}, "x86 commpage nanotime generation differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeTscBaseOffset}),
                std::uint64_t{0}, "x86 commpage nanotime TSC base differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeScaleOffset}),
                rosa::darwin::x86CommpageNanotimeScale,
                "x86 commpage nanotime scale differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeShiftOffset}),
                std::uint32_t{0}, "x86 commpage nanotime shift differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeNanosecondsBaseOffset}),
                std::uint64_t{0}, "x86 commpage nanotime nanoseconds base differs");

    bool unsupportedReadRejected = false;
    try {
        static_cast<void>(addressSpace.readU64(rosa::darwin::x86CommpageBase));
    } catch (const std::runtime_error &error) {
        unsupportedReadRejected = std::string_view(error.what()).find("unsupported sparse") !=
                                  std::string_view::npos;
    }
    expect(unsupportedReadRejected,
           "unsupported x86 commpage data did not fail loudly");

    bool writeRejected = false;
    try {
        addressSpace.writeU64(
            rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                      rosa::darwin::x86CommpageContinuousTimebaseOffset},
            0);
    } catch (const std::runtime_error &error) {
        writeRejected = std::string_view(error.what()).find("permissions") !=
                        std::string_view::npos;
    }
    expect(writeRejected, "x86 commpage mapping was not read-only");
}

std::string readGuestString(const rosa::guest::AddressSpace &addressSpace,
                            rosa::guest::GuestAddress address) {
    std::string result;
    for (;;) {
        const auto byte = addressSpace.readBytes(address, 1).front();
        if (byte == 0) {
            return result;
        }
        result.push_back(static_cast<char>(byte));
        ++address.value;
    }
}

void testInitialDarwinStack() {
    constexpr rosa::guest::GuestAddress base{0x700000000000ULL};
    constexpr std::size_t size = 2 * rosa::guest::guestPageSize;
    const std::vector<std::string> arguments{"/guest/program", "argument"};
    const std::vector<std::string> environment{"A=B"};
    const std::vector<std::string> apple{"executable_path=/guest/program"};
    rosa::guest::AddressSpace addressSpace;
    const rosa::guest::StartupStackBuilder builder;
    const auto stack = builder.build(addressSpace, base, size, arguments, environment, apple);
    expectEqual(stack.stackPointer.value & 0xFU, std::uint64_t{0},
                "initial stack pointer is not 16-byte aligned");
    auto cursor = stack.stackPointer.value;
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{cursor}), std::uint64_t{2},
                "initial stack argc differs");
    cursor += 8;
    const auto argv0 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    cursor += 8;
    const auto argv1 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    cursor += 16; // Move past argv[1] and the argv null to envp[0].
    const auto env0 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    cursor += 16; // Move past envp[0] and the envp null to apple[0].
    const auto apple0 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{argv0}), arguments[0],
                "guest argv[0] differs");
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{argv1}), arguments[1],
                "guest argv[1] differs");
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{env0}), environment[0],
                "guest envp[0] differs");
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{apple0}), apple[0],
                "guest apple[0] differs");
}

constexpr std::array<std::uint8_t, 41> r2Code{
    0x48, 0xB8, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xF8, 0x28,
    0x75, 0x07, 0xE8, 0x0E, 0x00, 0x00, 0x00, 0xEB, 0x11, 0x48, 0xB8, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x05, 0x48, 0x83, 0xC0, 0x02, 0xC3, 0xC3,
};

std::pair<rosa::x86::X86State, rosa::dbt::DispatchResult>
executeR2(std::span<const std::uint8_t> code) {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackTop - sizeof(std::uint64_t);
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 64, sentinel);
    return {state, result};
}

void testR2MultiBlockControlFlow() {
    const auto [state, result] = executeR2(r2Code);
    expectEqual(state.rax, std::uint64_t{42}, "R2 call result differs");
    expectEqual(result.executedBlocks, std::size_t{5}, "R2 executed-block count differs");
    expectEqual(result.translatedBlocks, std::size_t{5}, "R2 translated-block count differs");
    expectEqual(state.rsp, std::uint64_t{0x700000001000ULL},
                "R2 call/return did not restore guest RSP");
}

void testR2TakenConditional() {
    auto code = r2Code;
    code[13] = 0x29; // cmp rax, 41 makes JNE take the failure path.
    const auto [state, result] = executeR2(code);
    expectEqual(state.rax, std::uint64_t{0}, "R2 taken JNE did not reach failure block");
    expectEqual(result.executedBlocks, std::size_t{3}, "taken-path block count differs");
}

void testControlledMachOParsing() {
    const auto file = rosa::macho::MachOFile::open(ROSA_TEST_MACHO_PATH);
    expectEqual(file.cpuType(), std::uint32_t{0x01000007U}, "Mach-O CPU type differs");
    expectEqual(file.fileType(), std::uint32_t{2}, "Mach-O file type differs");
    expect(!file.segments().empty(), "Mach-O has no parsed segments");
    bool sawMain = false;
    for (const auto &command : file.loadCommands()) {
        sawMain |= command.command == rosa::macho::lcMain;
    }
    expect(sawMain, "controlled Mach-O does not contain parsed LC_MAIN");

    rosa::guest::AddressSpace addressSpace;
    const rosa::macho::Loader loader;
    const auto image = loader.mapImage(file, addressSpace);
    expectEqual(image.mappedSegments, std::size_t{3}, "Mach-O mapped-segment count differs");
    expectEqual(addressSpace.mappingCount(), image.mappedSegments,
                "guest mapping count differs from loaded segment count");
    expectEqual(addressSpace.executableBytes(image.entryPoint).front(), std::uint8_t{0x48},
                "Mach-O entry does not point to controlled x86 code");
    bool pageZeroRejected = false;
    try {
        static_cast<void>(addressSpace.readBytes(rosa::guest::GuestAddress{0}, 1));
    } catch (const std::runtime_error &) {
        pageZeroRejected = true;
    }
    expect(pageZeroRejected, "sparse __PAGEZERO did not reject guest reads");
}

void writeBigU32(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 2] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 3] = static_cast<std::uint8_t>(value);
}

void testUniversalMachOX86Selection() {
    const auto thin = rosa::macho::MachOFile::open(ROSA_TEST_MACHO_PATH);
    constexpr std::size_t fatHeaderSize = 8 + 20;
    std::vector<std::uint8_t> fat(fatHeaderSize + thin.bytes().size());
    fat[0] = 0xCA;
    fat[1] = 0xFE;
    fat[2] = 0xBA;
    fat[3] = 0xBE;
    writeBigU32(fat, 4, 1);
    writeBigU32(fat, 8, 0x01000007U);
    writeBigU32(fat, 12, 3);
    writeBigU32(fat, 16, fatHeaderSize);
    writeBigU32(fat, 20, static_cast<std::uint32_t>(thin.bytes().size()));
    writeBigU32(fat, 24, 0);
    std::copy(thin.bytes().begin(), thin.bytes().end(),
              fat.begin() + static_cast<std::ptrdiff_t>(fatHeaderSize));
    const auto selected = rosa::macho::MachOFile::parse(std::move(fat));
    expectEqual(selected.entryPoint(), thin.entryPoint(), "universal Mach-O x86_64 entry differs");
}

void testMalformedMachORejection() {
    const auto valid = rosa::macho::MachOFile::open(ROSA_TEST_MACHO_PATH);
    std::vector<std::uint8_t> bytes(valid.bytes().begin(), valid.bytes().end());
    expect(bytes.size() > 40, "controlled Mach-O is unexpectedly short");
    bytes[36] = 0;
    bytes[37] = 0;
    bytes[38] = 0;
    bytes[39] = 0;
    bool rejected = false;
    try {
        static_cast<void>(rosa::macho::MachOFile::parse(std::move(bytes)));
    } catch (const std::runtime_error &) {
        rejected = true;
    }
    expect(rejected, "zero-sized Mach-O load command was not rejected");
}

void testR3ControlledMachOExecution() {
    const rosa::macho::Loader loader;
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    const auto image = loader.mapImage(ROSA_TEST_MACHO_PATH, addressSpace);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = image.entryPoint.value;
    state.rsp = stackTop - sizeof(std::uint64_t);
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 64, sentinel);
    expectEqual(state.rax, std::uint64_t{42}, "controlled Mach-O guest RAX differs");
    expectEqual(result.executedBlocks, std::size_t{5},
                "controlled Mach-O executed-block count differs");
}

} // namespace

int main() {
    const std::vector<std::pair<std::string_view, std::function<void()>>> tests{
        {"arm64 assembler encodings", testAssemblerEncodings},
        {"R0 generated execution", testR0ExecutesGeneratedCode},
        {"arm64 label fixups", testAssemblerLabels},
        {"R1 decoder", testDecoderR1},
        {"extended register and signed immediate", testDecoderExtendedRegisterAndSignedImmediate},
        {"PUSH imm8 decoder", testDecoderPushImm8},
        {"PUSH imm8 generated execution", testPushImm8GeneratedExecution},
        {"PUSH imm8 guest stack faults", testPushImm8GuestStackFaults},
        {"PUSH register generated execution", testPushRegisterGeneratedExecution},
        {"SUB register imm32 generated execution", testSubRegImm32GeneratedExecution},
        {"SUB register imm8 generated execution", testSubRegImm8GeneratedExecution},
        {"SUB register from guest memory", testSubRegisterFromGuestMemory},
        {"ADD register from guest memory", testAddRegisterFromGuestMemory},
        {"CMP 32-bit register with guest memory", testCompare32BitRegisterWithGuestMemory},
        {"MOV register to guest memory", testMovRegisterToGuestMemory},
        {"MOV guest memory to register", testMovGuestMemoryToRegister},
        {"MOV guest memory to 32-bit register", testMovGuestMemoryTo32BitRegister},
        {"legacy MOV guest memory to 32-bit register",
         testMovGuestMemoryToLegacy32BitRegister},
        {"TEST register generated execution", testTestRegisterGeneratedExecution},
        {"TEST 32-bit register generated execution", testTest32BitRegisterGeneratedExecution},
        {"LFENCE generated execution", testLfenceGeneratedExecution},
        {"RDTSC generated execution", testRdtscGeneratedExecution},
        {"SHL immediate generated execution", testShiftLeftImmediateGeneratedExecution},
        {"SHL CL generated execution", testShiftLeftClGeneratedExecution},
        {"unsigned MUL generated execution", testUnsignedMultiplyGeneratedExecution},
        {"SHRD generated execution", testShiftRightDoubleGeneratedExecution},
        {"OR register generated execution", testOrRegisterGeneratedExecution},
        {"register move execution", testRegisterMoveExecution},
        {"unsupported decoder diagnostic", testDecoderRejectsUnsupportedInstruction},
        {"RIP-relative LEA and syscall decoder", testDecoderRipRelativeLeaAndSyscall},
        {"IR verification", testIrVerification},
        {"R1 generated execution", testR1ExecutesGeneratedCode},
        {"add carry/zero flags", testAddFlagsCarryAndZero},
        {"add signed-overflow flags", testAddFlagsSignedOverflow},
        {"and result/flags", testAndResultAndFlags},
        {"legacy AND 32-bit immediate", testLegacyAnd32Immediate},
        {"guest address space", testGuestAddressSpace},
        {"guest failure report", testGuestFailureReport},
        {"x86 commpage continuous timebase", testX86CommpageContinuousTimebase},
        {"initial Darwin stack", testInitialDarwinStack},
        {"R2 multi-block control flow", testR2MultiBlockControlFlow},
        {"R2 taken conditional", testR2TakenConditional},
        {"controlled Mach-O parsing", testControlledMachOParsing},
        {"universal Mach-O x86 selection", testUniversalMachOX86Selection},
        {"malformed Mach-O rejection", testMalformedMachORejection},
        {"R3 controlled Mach-O execution", testR3ControlledMachOExecution},
    };

    std::size_t failures = 0;
    for (const auto &[name, test] : tests) {
        try {
            test();
            std::cout << "[pass] " << name << '\n';
        } catch (const std::exception &error) {
            ++failures;
            std::cerr << "[fail] " << name << ": " << error.what() << '\n';
        }
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << tests.size() << " tests passed\n";
    return 0;
}
