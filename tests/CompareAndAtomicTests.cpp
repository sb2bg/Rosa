#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testCompare32BitRegisterWithGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x3B, 0x46, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegMem,
           "CMP r32, [base+disp8] opcode differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(lhs.reg == rosa::x86::Register::R8, "CMP r32, [base+disp8] register differs");
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
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "CMP from unmapped guest memory did not fail");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "failed memory CMP changed flags");
}

void testCompare32BitRegisterWithGsAbsoluteMemory() {
    constexpr std::array<std::uint8_t, 9> observedCode{0x65, 0x3B, 0x04, 0x25, 0x18,
                                                       0x00, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802AEC84DULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegMem, "GS-absolute CMP opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "GS-absolute CMP length differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(lhs.reg == rosa::x86::Register::Rax && lhs.width == 32,
           "GS-absolute CMP register differs");
    expect(!memory.hasBase && !memory.index && !memory.ripRelative && memory.displacement == 0x18 &&
               memory.width == 32 && memory.segment == rosa::x86::Segment::Gs,
           "GS-absolute CMP memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp eax, [gs:0x18]") != std::string::npos,
           "GS-absolute CMP dump differs");

    constexpr rosa::guest::GuestAddress gsBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8018};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(gsBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 1);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("read_guest_gs_base.i64") !=
               std::string::npos,
           "GS-absolute CMP did not lower through guest GS base");
    rosa::x86::X86State state;
    state.rax = 1;
    state.gsBase = gsBase.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{1}, "GS-absolute CMP changed EAX");
    expectEqual(state.gsBase, gsBase.value, "GS-absolute CMP changed GS base");
    expectEqual(state.rflags, std::uint64_t{0x46}, "GS-absolute CMP equal flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 1;
    faultState.gsBase = gsBase.value;
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "GS-absolute CMP accepted unmapped memory");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted GS-absolute CMP changed flags");
}

// libdispatch clears and tests TSD slots through GS with the 83 group:
// and qword gs:[0x3c0], 0 and cmp qword gs:[0xe0], 0.
void testGsAbsoluteGroupOneImmediates() {
    constexpr std::array<std::uint8_t, 21> code{
        0x65, 0x48, 0x83, 0x24, 0x25, 0xC0, 0x03, 0x00, 0x00, 0x00, // and qword gs:[0x3c0], 0
        0x65, 0x48, 0x83, 0x3C, 0x25, 0xE0, 0x00, 0x00, 0x00, 0x00, // cmp qword gs:[0xe0], 0
        0xC3,
    };
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802CEBC95ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::AndMemImm &&
               decoded[1].opcode == rosa::x86::Opcode::CmpMemImm,
           "GS group-one immediate opcodes differ");
    for (std::size_t index = 0; index < 2; ++index) {
        const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[index].operands[0]);
        expect(!memory.hasBase && !memory.index && memory.width == 64 &&
                   memory.segment == rosa::x86::Segment::Gs,
               "GS group-one memory operand differs");
    }
    const auto dump = rosa::debug::dumpX86(decoded);
    expect(dump.find("and qword [gs:0x3c0], 0x0") != std::string::npos &&
               dump.find("cmp qword [gs:0xe0], 0x0") != std::string::npos,
           "GS group-one immediate dump differs");

    constexpr rosa::guest::GuestAddress gsBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(gsBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{gsBase.value + 0x3C0}, 0xFFFF);
    addressSpace.writeU64(rosa::guest::GuestAddress{gsBase.value + 0xE0}, 5);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.gsBase = gsBase.value;
    state.rflags = 0x2;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{gsBase.value + 0x3C0}),
                std::uint64_t{0}, "GS AND did not clear the TSD slot");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{gsBase.value + 0xE0}),
                std::uint64_t{5}, "GS CMP changed memory");
    // 5 - 0: not zero, no carry, positive.
    expectEqual(state.rflags & (zeroFlag | carryFlag | signFlag), std::uint64_t{0},
                "GS CMP flags differ");
}

void testTestByteGsAbsoluteMemory() {
    // Observed in libobjc under an Objective-C fixture: TEST byte gs:[0x160], 1.
    constexpr std::array<std::uint8_t, 10> observedCode{0x65, 0xF6, 0x04, 0x25, 0x60,
                                                        0x01, 0x00, 0x00, 0x01, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802A20BB1ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::TestMemImm,
           "GS-absolute TEST byte opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "GS-absolute TEST byte length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(!memory.hasBase && !memory.index && !memory.ripRelative &&
               memory.displacement == 0x160 && memory.width == 8 &&
               memory.segment == rosa::x86::Segment::Gs && immediate.value == 1,
           "GS-absolute TEST byte memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("test byte [gs:0x160], 0x1") != std::string::npos,
           "GS-absolute TEST byte dump differs");

    constexpr rosa::guest::GuestAddress gsBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8160};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(gsBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 1>{0x03});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("read_guest_gs_base.i64") !=
               std::string::npos,
           "GS-absolute TEST byte did not lower through guest GS base");
    rosa::x86::X86State state;
    state.gsBase = gsBase.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.gsBase, gsBase.value, "GS-absolute TEST byte changed GS base");
    // 0x03 & 0x01 == 0x01: nonzero, no sign, odd parity.
    expectEqual(state.rflags & ((1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U)),
                std::uint64_t{0}, "GS-absolute TEST byte flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.gsBase = gsBase.value;
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "GS-absolute TEST byte accepted unmapped memory");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted GS-absolute TEST byte changed flags");
}

void testCompareByteRegisterWithScaledGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0x3A, 0x14, 0x0E, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8000050A3ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegMem, "SIB byte CMP opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "SIB byte CMP length differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(lhs.reg == rosa::x86::Register::Rdx && lhs.width == 8,
           "SIB byte CMP register operand differs");
    expect(memory.base == rosa::x86::Register::R14 && memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 1 && memory.displacement == 0 && memory.width == 8,
           "SIB byte CMP memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp dl, [r14+rcx*1]") != std::string::npos,
           "SIB byte CMP dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> rhs{0x80};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8018}, rhs);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = memoryBase.value;
    state.rcx = 0x18;
    state.rdx = 0x1122334455667700ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdx, std::uint64_t{0x1122334455667700ULL},
                "SIB byte CMP changed its register operand");
    expectEqual(state.r14, memoryBase.value, "SIB byte CMP changed its base register");
    expectEqual(state.rcx, std::uint64_t{0x18}, "SIB byte CMP changed its index register");
    expectEqual(state.rflags, std::uint64_t{0x883},
                "SIB byte CMP did not compute 8-bit subtraction flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState = state;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "SIB byte CMP from unmapped memory did not fault");
    expectEqual(faultState.rdx, state.rdx, "failed SIB byte CMP changed its register operand");
    expectEqual(faultState.r14, state.r14, "failed SIB byte CMP changed its base register");
    expectEqual(faultState.rcx, state.rcx, "failed SIB byte CMP changed its index register");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed SIB byte CMP changed flags");
}

void testLegacyCompare32BitRegisterWithGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x3B, 0x47, 0x28, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegMem,
           "legacy CMP r32, [base+disp8] opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "legacy CMP r32 memory width differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8028}, 0x19);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xA5A5A5A500000019ULL;
    state.rdi = 0x8000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0xA5A5A5A500000019ULL}, "legacy CMP memory changed EAX");
    expectEqual(state.rflags, std::uint64_t{0x46}, "legacy CMP memory equal flags differ");
}

void testCompare64BitRegisterWithGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x3B, 0x45, 0xE0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegMem,
           "CMP r64, [base+disp8] opcode differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expectEqual(lhs.width, std::uint8_t{64}, "CMP r64 width differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expectEqual(memory.displacement, std::int64_t{-0x20}, "CMP r64 displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x80E0}, 7);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 5;
    state.rbp = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{5}, "CMP r64 changed its register operand");
    expectEqual(state.rflags, std::uint64_t{0x93}, "CMP r64 flags differ");

    constexpr std::array<std::uint8_t, 6> indexedCode{0x4B, 0x3B, 0x54, 0x25, 0x28, 0xC3};
    const auto indexedDecoded =
        decoder.decodeBlock(indexedCode, rosa::guest::GuestAddress{0x7FF802B0810FULL});
    const auto indexedLhs = std::get<rosa::x86::RegisterOperand>(indexedDecoded[0].operands[0]);
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[1]);
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::CmpRegMem &&
               indexedDecoded[0].length == 5 && indexedLhs.reg == rosa::x86::Register::Rdx &&
               indexedLhs.width == 64 && indexedMemory.base == rosa::x86::Register::R13 &&
               indexedMemory.index == rosa::x86::Register::R12 && indexedMemory.scale == 1 &&
               indexedMemory.displacement == 0x28,
           "indexed CMP r64, m64 operands differ");
    expect(rosa::debug::dumpX86(indexedDecoded).find("cmp rdx, [r13+r12*1+0x28]") !=
               std::string::npos,
           "indexed CMP r64, m64 dump differs");

    constexpr rosa::guest::GuestAddress indexedTarget{0x8148};
    addressSpace.writeU64(indexedTarget, 10);
    const auto indexedBlock =
        translator.translate(indexedCode, rosa::guest::GuestAddress{0x7FF802B0810FULL});
    state.rdx = 10;
    state.r13 = 0x8100;
    state.r12 = 0x20;
    state.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46}, "indexed CMP r64, m64 equal flags differ");
    expectEqual(state.r13, std::uint64_t{0x8100}, "indexed CMP changed its base");
    expectEqual(state.r12, std::uint64_t{0x20}, "indexed CMP changed its index");
}

void testCompare64BitRegisterWithRipRelativeGuestMemory() {
    constexpr std::array<std::uint8_t, 16> code{0x48, 0x3B, 0x0D, 0x01, 0x00, 0x00, 0x00, 0xC3,
                                                0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress target{0x1008};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeBase);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegMem,
           "RIP-relative CMP r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative CMP r64 length differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(lhs.reg == rosa::x86::Register::Rcx && lhs.width == 64,
           "RIP-relative CMP r64 register differs");
    expect(memory.ripRelative && !memory.hasBase && memory.displacement == 1 && memory.width == 64,
           "RIP-relative CMP r64 memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp rcx, [rip+0x1] ; 0x1008") != std::string::npos,
           "RIP-relative CMP r64 dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeBase);
    rosa::x86::X86State equalState;
    equalState.rcx = 5;
    equalState.rflags = 0x8D7;
    static_cast<void>(block.execute(equalState, &addressSpace));
    expectEqual(equalState.rcx, std::uint64_t{5}, "RIP-relative CMP changed its register");
    expectEqual(equalState.rflags, std::uint64_t{0x46}, "RIP-relative CMP equal flags differ");
    expectEqual(addressSpace.readU64(target), std::uint64_t{5},
                "RIP-relative CMP changed guest memory");

    constexpr std::array<std::uint8_t, 8> faultCode{0x48, 0x3B, 0x0D, 0xF9, 0x1F, 0x00, 0x00, 0xC3};
    rosa::guest::AddressSpace faultAddressSpace;
    faultAddressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                                 rosa::guest::Permission::Read | rosa::guest::Permission::Execute,
                                 faultCode);
    const auto faultBlock = translator.translate(faultCode, codeBase);
    rosa::x86::X86State faultState;
    faultState.rcx = 0x0123456789ABCDEFULL;
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        static_cast<void>(faultBlock.execute(faultState, &faultAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "RIP-relative CMP from unmapped guest memory did not fault");
    expectEqual(faultState.rcx, std::uint64_t{0x0123456789ABCDEFULL},
                "faulted RIP-relative CMP changed its register");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted RIP-relative CMP changed flags");
}

void testCompareWordRegisterWithGuestMemory() {
    // Observed in libsqlite3: CMP CX, word [R14+0x30] with an operand-size override.
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x41, 0x3B, 0x4E, 0x30, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000E7769ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegMem,
           "word CMP r16 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "word CMP r16 length differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(lhs.reg == rosa::x86::Register::Rcx && lhs.width == 16,
           "word CMP r16 register differs");
    expect(memory.base == rosa::x86::Register::R14 && memory.displacement == 0x30 &&
               memory.width == 16,
           "word CMP r16 memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp cx, [r14+0x30]") != std::string::npos,
           "word CMP r16 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8030};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 2>{0x05, 0x00});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000E7769ULL});
    rosa::x86::X86State equalState;
    equalState.rcx = 0xABCD0005ULL;
    equalState.r14 = page.value;
    equalState.rflags = 0x2;
    static_cast<void>(block.execute(equalState, &addressSpace));
    expectEqual(equalState.rcx, std::uint64_t{0xABCD0005ULL}, "word CMP changed its register");
    expectEqual(equalState.rflags, std::uint64_t{0x46}, "word CMP equal flags differ");

    rosa::x86::X86State belowState;
    belowState.rcx = 0xABCD0003ULL;
    belowState.r14 = page.value;
    belowState.rflags = 0x2;
    static_cast<void>(block.execute(belowState, &addressSpace));
    expectEqual(belowState.rflags, std::uint64_t{0x93}, "word CMP below flags differ");
}

void testCompareGuestByteWithRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x38, 0x4C, 0x13, 0x58, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemReg,
           "CMP byte [memory], r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "CMP byte [memory], r8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.index == rosa::x86::Register::Rdx &&
               memory.scale == 1 && memory.displacement == 0x58 && memory.width == 8,
           "CMP byte scaled-memory operand differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 8,
           "CMP byte memory source register differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp byte [rbx+rdx*1+0x58], cl") != std::string::npos,
           "CMP byte scaled-memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8078};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array memoryByte{std::uint8_t{0x80}};
    addressSpace.writeBytes(target, memoryByte);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = page.value;
    state.rdx = 0x20;
    state.rcx = 0x1122334455667701ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rbx, page.value, "CMP byte memory changed its base");
    expectEqual(state.rdx, std::uint64_t{0x20}, "CMP byte memory changed its index");
    expectEqual(state.rcx, std::uint64_t{0x1122334455667701ULL},
                "CMP byte memory changed its source");
    expectEqual(state.rflags, std::uint64_t{0x812}, "CMP byte memory overflow flags differ");
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0x80},
                "CMP byte memory changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbx = page.value;
    faultState.rdx = 0x20;
    faultState.rcx = 0x1122334455667701ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "CMP byte from unmapped guest memory did not fault");
    expectEqual(faultState.rbx, page.value, "faulted CMP byte memory changed its base");
    expectEqual(faultState.rdx, std::uint64_t{0x20}, "faulted CMP byte memory changed its index");
    expectEqual(faultState.rcx, std::uint64_t{0x1122334455667701ULL},
                "faulted CMP byte memory changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted CMP byte memory changed flags");
}

void testCompareRipRelativeGuestByteWithRegister() {
    constexpr std::array<std::uint8_t, 7> code{0x38, 0x05, 0xA3, 0xD8, 0xA2, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802E6F02BULL};
    constexpr rosa::guest::GuestAddress target{0x7FF84389C8D4ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF84389C000ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemReg,
           "RIP-relative CMP byte opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "RIP-relative CMP byte length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0x40A2D8A3,
           "RIP-relative CMP byte memory operand differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 8,
           "RIP-relative CMP byte source differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp byte [rip+0x40a2d8a3], al ; 0x7ff84389c8d4") !=
               std::string::npos,
           "RIP-relative CMP byte dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 1>{0});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rax = 0x0123456789ABCD00ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0x0123456789ABCD00ULL},
                "RIP-relative CMP byte changed its source");
    expectEqual(state.rflags, std::uint64_t{0x46}, "RIP-relative CMP byte equal flags differ");
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0},
                "RIP-relative CMP byte changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x0123456789ABCD00ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative CMP byte from unmapped memory did not fault");
    expectEqual(faultState.rax, std::uint64_t{0x0123456789ABCD00ULL},
                "faulted RIP-relative CMP byte changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative CMP byte changed flags");
}

void testCompareGuestWordWithExtendedRegister() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x44, 0x39, 0x63, 0x10, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C68D84ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemReg,
           "CMP word memory/register opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "CMP word memory/register length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.hasBase && !memory.ripRelative &&
               !memory.index && memory.displacement == 0x10 && memory.width == 16,
           "CMP word [rbx+0x10] memory operand differs");
    expect(source.reg == rosa::x86::Register::R12 && source.width == 16,
           "CMP word memory R12W source differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp word [rbx+0x10], r12w") != std::string::npos,
           "CMP word memory/register dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8010};
    constexpr std::array<std::uint8_t, 4> valueAndSentinel{0x03, 0x00, 0xAA, 0xBB};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, valueAndSentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    rosa::x86::X86State state;
    state.rbx = page.value;
    state.r12 = 0xAABBCCDDEEFF0003ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP word equal flags differ");
    expectEqual(state.rbx, page.value, "CMP word changed its memory base");
    expectEqual(state.r12, std::uint64_t{0xAABBCCDDEEFF0003ULL},
                "CMP word changed its source register");
    expect(addressSpace.readBytes(target, valueAndSentinel.size()) ==
               std::vector<std::uint8_t>(valueAndSentinel.begin(), valueAndSentinel.end()),
           "CMP word changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbx = page.value;
    faultState.r12 = 0x1122334455660003ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "CMP word from unmapped memory did not fault");
    expectEqual(faultState.r12, std::uint64_t{0x1122334455660003ULL},
                "faulted CMP word changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted CMP word changed flags");
}

void testCompareGuestMemoryWith64BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x39, 0x43, 0x30, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemReg, "CMP [memory], r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "CMP [memory], r64 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto rhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.displacement == 0x30 &&
               memory.width == 64,
           "CMP [rbx+0x30], rax memory operand differs");
    expect(rhs.reg == rosa::x86::Register::Rax && rhs.width == 64,
           "CMP [rbx+0x30], rax register operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp [rbx+0x30], rax") != std::string::npos,
           "CMP [rbx+0x30], rax dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8030}, 5);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8000;
    state.rax = 7;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rbx, std::uint64_t{0x8000}, "CMP [memory], r64 changed its base");
    expectEqual(state.rax, std::uint64_t{7}, "CMP [memory], r64 changed its source");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8030}), std::uint64_t{5},
                "CMP [memory], r64 changed memory");
    expectEqual(state.rflags, std::uint64_t{0x93}, "CMP qword 5, 7 subtraction flags differ");

    state.rax = 5;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP qword equal flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbx = 0x8000;
    faultState.rax = 7;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "CMP [unmapped], r64 did not fault");
    expectEqual(faultState.rbx, std::uint64_t{0x8000}, "failed CMP [memory], r64 changed its base");
    expectEqual(faultState.rax, std::uint64_t{7}, "failed CMP [memory], r64 changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed CMP [memory], r64 changed flags");

    constexpr std::array<std::uint8_t, 8> ripCode{0x48, 0x39, 0x15, 0x2D, 0x8A, 0xE4, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress ripCmpAddress{0x7FF802A17CFCULL};
    constexpr rosa::guest::GuestAddress ripTarget{0x7FF843860730ULL};
    constexpr rosa::guest::GuestAddress ripTargetPage{0x7FF843860000ULL};
    const auto ripDecoded = decoder.decodeBlock(ripCode, ripCmpAddress);
    expect(ripDecoded[0].opcode == rosa::x86::Opcode::CmpMemReg && ripDecoded[0].length == 7,
           "RIP-relative CMP [memory], r64 opcode or length differs");
    const auto ripMemory = std::get<rosa::x86::MemoryOperand>(ripDecoded[0].operands[0]);
    const auto ripSource = std::get<rosa::x86::RegisterOperand>(ripDecoded[0].operands[1]);
    expect(ripMemory.ripRelative && !ripMemory.hasBase && !ripMemory.index &&
               ripMemory.displacement == 0x40E48A2D && ripMemory.width == 64 &&
               ripSource.reg == rosa::x86::Register::Rdx && ripSource.width == 64,
           "RIP-relative CMP [memory], rdx operands differ");
    expect(rosa::debug::dumpX86(ripDecoded).find("cmp [rip+0x40e48a2d], rdx ; 0x7ff843860730") !=
               std::string::npos,
           "RIP-relative CMP [memory], rdx dump differs");

    constexpr std::uint64_t ripValue = 0x7FF82258A220ULL;
    addressSpace.mapAnonymous(ripTargetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(ripTarget, ripValue);
    const auto ripBlock = translator.translate(ripCode, ripCmpAddress);
    rosa::x86::X86State ripState;
    ripState.rdx = ripValue;
    ripState.rflags = 0x8D7;
    static_cast<void>(ripBlock.execute(ripState, &addressSpace));
    expectEqual(ripState.rdx, ripValue, "RIP-relative CMP [memory], rdx changed its source");
    expectEqual(ripState.rflags, std::uint64_t{0x46},
                "RIP-relative CMP [memory], rdx equal flags differ");
    expectEqual(addressSpace.readU64(ripTarget), ripValue,
                "RIP-relative CMP [memory], rdx changed memory");

    rosa::guest::AddressSpace ripFaultAddressSpace;
    rosa::x86::X86State ripFaultState;
    ripFaultState.rdx = ripValue;
    ripFaultState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(ripBlock.execute(ripFaultState, &ripFaultAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative CMP [unmapped], rdx did not fault");
    expectEqual(ripFaultState.rdx, ripValue, "faulted RIP-relative CMP changed its source");
    expectEqual(ripFaultState.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative CMP changed flags");

    constexpr std::array<std::uint8_t, 4> registerCode{0x48, 0x39, 0xD8, 0xC3};
    const auto registerDecoded =
        decoder.decodeBlock(registerCode, rosa::guest::GuestAddress{0x2000});
    expect(registerDecoded[0].opcode == rosa::x86::Opcode::CmpRegReg,
           "register-direct opcode 39 no longer decodes as CMP register");

    constexpr std::array<std::uint8_t, 6> sibCode{0x49, 0x39, 0x44, 0x24, 0x38, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802AA664AULL};
    const auto sibDecoded = decoder.decodeBlock(sibCode, observedRip);
    expect(sibDecoded[0].opcode == rosa::x86::Opcode::CmpMemReg,
           "CMP no-index SIB memory opcode differs");
    expectEqual(sibDecoded[0].length, std::uint8_t{5}, "CMP no-index SIB memory length differs");
    const auto sibMemory = std::get<rosa::x86::MemoryOperand>(sibDecoded[0].operands[0]);
    const auto sibSource = std::get<rosa::x86::RegisterOperand>(sibDecoded[0].operands[1]);
    expect(sibMemory.base == rosa::x86::Register::R12 && !sibMemory.index &&
               sibMemory.displacement == 0x38 && sibMemory.width == 64,
           "CMP [r12+0x38] memory operand differs");
    expect(sibSource.reg == rosa::x86::Register::Rax && sibSource.width == 64,
           "CMP [r12+0x38], rax source differs");
    expect(rosa::debug::dumpX86(sibDecoded).find("cmp [r12+0x38], rax") != std::string::npos,
           "CMP [r12+0x38], rax dump differs");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8038}, 0x55);
    const auto sibBlock = translator.translate(sibCode, observedRip);
    rosa::x86::X86State sibState;
    sibState.r12 = 0x8000;
    sibState.rax = 0x55;
    sibState.rflags = 0x8D7;
    static_cast<void>(sibBlock.execute(sibState, &addressSpace));
    expectEqual(sibState.rflags, std::uint64_t{0x46}, "CMP [r12+0x38], rax equal flags differ");
    expectEqual(sibState.r12, std::uint64_t{0x8000}, "CMP [r12+0x38], rax changed its base");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8038}), std::uint64_t{0x55},
                "CMP [r12+0x38], rax changed memory");

    constexpr std::array<std::uint8_t, 10> gsCode{0x65, 0x48, 0x39, 0x0C, 0x25,
                                                  0xD0, 0xFF, 0xFF, 0xFF, 0xC3};
    constexpr rosa::guest::GuestAddress gsRip{0x7FF802E6F83AULL};
    constexpr rosa::guest::GuestAddress gsBase{0x9000};
    constexpr rosa::guest::GuestAddress gsTarget{0x8FD0};
    const auto gsDecoded = decoder.decodeBlock(gsCode, gsRip);
    expect(gsDecoded[0].opcode == rosa::x86::Opcode::CmpMemReg,
           "GS-absolute CMP qword opcode differs");
    expectEqual(gsDecoded[0].length, std::uint8_t{9}, "GS-absolute CMP qword length differs");
    const auto gsMemory = std::get<rosa::x86::MemoryOperand>(gsDecoded[0].operands[0]);
    const auto gsSource = std::get<rosa::x86::RegisterOperand>(gsDecoded[0].operands[1]);
    expect(!gsMemory.hasBase && !gsMemory.index && !gsMemory.ripRelative &&
               gsMemory.displacement == -0x30 && gsMemory.width == 64 &&
               gsMemory.segment == rosa::x86::Segment::Gs,
           "GS-absolute CMP qword memory operand differs");
    expect(gsSource.reg == rosa::x86::Register::Rcx && gsSource.width == 64,
           "GS-absolute CMP qword source differs");
    expect(rosa::debug::dumpX86(gsDecoded).find("cmp [gs:0xffffffffffffffd0], rcx") !=
               std::string::npos,
           "GS-absolute CMP qword dump differs");
    constexpr std::uint64_t gsValue = 0x7000000FB678ULL;
    addressSpace.writeU64(gsTarget, gsValue);
    const auto gsBlock = translator.translate(gsCode, gsRip);
    expect(
        rosa::debug::dumpIr(gsBlock.intermediateRepresentation()).find("read_guest_gs_base.i64") !=
            std::string::npos,
        "GS-absolute CMP qword did not lower through GS base IR");
    rosa::x86::X86State gsState;
    gsState.gsBase = gsBase.value;
    gsState.rcx = gsValue;
    gsState.rflags = 0x8D7;
    static_cast<void>(gsBlock.execute(gsState, &addressSpace));
    expectEqual(gsState.rflags, std::uint64_t{0x46}, "GS-absolute CMP qword equal flags differ");
    expectEqual(gsState.gsBase, gsBase.value, "GS-absolute CMP qword changed GS base");
    expectEqual(gsState.rcx, gsValue, "GS-absolute CMP qword changed its source");
    expectEqual(addressSpace.readU64(gsTarget), gsValue, "GS-absolute CMP qword changed memory");

    rosa::guest::AddressSpace unmappedGsAddressSpace;
    gsState.rflags = 0xAD7;
    bool gsFaulted = false;
    try {
        static_cast<void>(gsBlock.execute(gsState, &unmappedGsAddressSpace));
    } catch (const std::runtime_error &error) {
        gsFaulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(gsFaulted, "GS-absolute CMP qword accepted unmapped memory");
    expectEqual(gsState.rflags, std::uint64_t{0xAD7},
                "faulted GS-absolute CMP qword changed flags");
}

void testLockedCompareExchangeGuestDword() {
    constexpr std::array<std::uint8_t, 5> code{0xF0, 0x0F, 0xB1, 0x0F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpxchgMemReg, "LOCK CMPXCHG opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "LOCK CMPXCHG length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdi && memory.width == 32 &&
               memory.displacement == 0,
           "LOCK CMPXCHG memory operand differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 32,
           "LOCK CMPXCHG source differs");
    expect(rosa::debug::dumpX86(decoded).find("lock cmpxchg dword [rdi], ecx") != std::string::npos,
           "LOCK CMPXCHG dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("compare_exchange_guest_memory.i32") != std::string::npos,
           "LOCK CMPXCHG did not lower through guest-memory IR");

    const std::array zeroBytes{std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{0}};
    addressSpace.writeBytes(memoryBase, zeroBytes);
    rosa::x86::X86State equalState;
    equalState.rdi = memoryBase.value;
    equalState.rax = 0xAAAAAAAA00000000ULL;
    equalState.rcx = 0xBBBBBBBB12345678ULL;
    equalState.rflags = 0x8D7;
    static_cast<void>(block.execute(equalState, &addressSpace));
    expectEqual(addressSpace.readU32(memoryBase), std::uint32_t{0x12345678},
                "successful LOCK CMPXCHG stored the wrong dword");
    expectEqual(equalState.rax, std::uint64_t{0},
                "successful LOCK CMPXCHG did not zero-extend EAX");
    expectEqual(equalState.rcx, std::uint64_t{0xBBBBBBBB12345678ULL},
                "successful LOCK CMPXCHG changed its source");
    expectEqual(equalState.rdi, memoryBase.value,
                "successful LOCK CMPXCHG changed its address base");
    expectEqual(equalState.rflags, std::uint64_t{0x46}, "successful LOCK CMPXCHG flags differ");

    constexpr std::array mismatchBytes{std::uint8_t{0x00}, std::uint8_t{0x00}, std::uint8_t{0x00},
                                       std::uint8_t{0x80}};
    addressSpace.writeBytes(memoryBase, mismatchBytes);
    rosa::x86::X86State mismatchState;
    mismatchState.rdi = memoryBase.value;
    mismatchState.rax = 0xAAAAAAAA00000000ULL;
    mismatchState.rcx = 0xBBBBBBBB12345678ULL;
    mismatchState.rflags = 0x8D7;
    static_cast<void>(block.execute(mismatchState, &addressSpace));
    expectEqual(addressSpace.readU32(memoryBase), std::uint32_t{0x80000000},
                "failed comparison changed LOCK CMPXCHG memory");
    expectEqual(mismatchState.rax, std::uint64_t{0x80000000},
                "failed comparison did not zero-extend memory into EAX");
    expectEqual(mismatchState.rcx, std::uint64_t{0xBBBBBBBB12345678ULL},
                "failed comparison changed LOCK CMPXCHG source");
    expectEqual(mismatchState.rflags, std::uint64_t{0x86}, "failed LOCK CMPXCHG flags differ");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    rosa::x86::X86State faultState;
    faultState.rdi = memoryBase.value;
    faultState.rax = 1;
    faultState.rcx = 2;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "LOCK CMPXCHG accepted a read-only guest destination");
    expectEqual(readOnlyAddressSpace.readU32(memoryBase), std::uint32_t{0},
                "faulted LOCK CMPXCHG changed guest memory");
    expectEqual(faultState.rax, std::uint64_t{1}, "faulted LOCK CMPXCHG changed RAX");
    expectEqual(faultState.rcx, std::uint64_t{2}, "faulted LOCK CMPXCHG changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted LOCK CMPXCHG changed flags");

    constexpr std::array<std::uint8_t, 7> sibCode{0xF0, 0x41, 0x0F, 0xB1, 0x0C, 0x24, 0xC3};
    constexpr rosa::guest::GuestAddress sibRip{0x7FF802C6819EULL};
    const auto sibDecoded = decoder.decodeBlock(sibCode, sibRip);
    expect(sibDecoded[0].opcode == rosa::x86::Opcode::CmpxchgMemReg,
           "LOCK CMPXCHG no-index SIB opcode differs");
    expectEqual(sibDecoded[0].length, std::uint8_t{6}, "LOCK CMPXCHG no-index SIB length differs");
    const auto sibMemory = std::get<rosa::x86::MemoryOperand>(sibDecoded[0].operands[0]);
    const auto sibSource = std::get<rosa::x86::RegisterOperand>(sibDecoded[0].operands[1]);
    expect(sibMemory.base == rosa::x86::Register::R12 && sibMemory.width == 32 &&
               sibMemory.displacement == 0 && !sibMemory.index &&
               sibSource.reg == rosa::x86::Register::Rcx && sibSource.width == 32,
           "LOCK CMPXCHG dword [r12], ecx operands differ");
    expect(rosa::debug::dumpX86(sibDecoded).find("lock cmpxchg dword [r12], ecx") !=
               std::string::npos,
           "LOCK CMPXCHG no-index SIB dump differs");

    addressSpace.writeBytes(memoryBase, zeroBytes);
    const auto sibBlock = translator.translate(sibCode, sibRip);
    rosa::x86::X86State sibState;
    sibState.r12 = memoryBase.value;
    sibState.rax = 0;
    sibState.rcx = 0x8007FFFB;
    sibState.rflags = 0x8D7;
    static_cast<void>(sibBlock.execute(sibState, &addressSpace));
    expectEqual(addressSpace.readU32(memoryBase), std::uint32_t{0x8007FFFB},
                "LOCK CMPXCHG no-index SIB stored the wrong dword");
    expectEqual(sibState.r12, memoryBase.value, "LOCK CMPXCHG no-index SIB changed R12");
    expectEqual(sibState.rcx, std::uint64_t{0x8007FFFB}, "LOCK CMPXCHG no-index SIB changed ECX");
    expectEqual(sibState.rflags, std::uint64_t{0x46}, "LOCK CMPXCHG no-index SIB flags differ");

    constexpr std::array<std::uint8_t, 7> indexedCode{0xF0, 0x41, 0x0F, 0xB1, 0x14, 0x0C, 0xC3};
    constexpr rosa::guest::GuestAddress indexedRip{0x7FF802C70673ULL};
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, indexedRip);
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::CmpxchgMemReg,
           "LOCK CMPXCHG indexed SIB opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{6},
                "LOCK CMPXCHG indexed SIB length differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[0]);
    const auto indexedSource = std::get<rosa::x86::RegisterOperand>(indexedDecoded[0].operands[1]);
    expect(indexedMemory.base == rosa::x86::Register::R12 &&
               indexedMemory.index == rosa::x86::Register::Rcx && indexedMemory.scale == 1 &&
               indexedMemory.width == 32 && indexedMemory.displacement == 0 &&
               indexedSource.reg == rosa::x86::Register::Rdx && indexedSource.width == 32,
           "LOCK CMPXCHG dword [r12+rcx], edx operands differ");
    expect(rosa::debug::dumpX86(indexedDecoded).find("lock cmpxchg dword [r12+rcx*1], edx") !=
               std::string::npos,
           "LOCK CMPXCHG indexed SIB dump differs");

    addressSpace.writeBytes(memoryBase, zeroBytes);
    const auto indexedBlock = translator.translate(indexedCode, indexedRip);
    rosa::x86::X86State indexedState;
    indexedState.r12 = memoryBase.value - 0x800;
    indexedState.rcx = 0x800;
    indexedState.rax = 0;
    indexedState.rdx = 0x803;
    indexedState.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(addressSpace.readU32(memoryBase), std::uint32_t{0x803},
                "LOCK CMPXCHG indexed SIB stored the wrong dword");
    expectEqual(indexedState.r12, memoryBase.value - 0x800, "LOCK CMPXCHG indexed SIB changed R12");
    expectEqual(indexedState.rcx, std::uint64_t{0x800}, "LOCK CMPXCHG indexed SIB changed RCX");
    expectEqual(indexedState.rdx, std::uint64_t{0x803}, "LOCK CMPXCHG indexed SIB changed EDX");
    expectEqual(indexedState.rflags, std::uint64_t{0x46}, "LOCK CMPXCHG indexed SIB flags differ");

    rosa::x86::X86State indexedFaultState;
    indexedFaultState.r12 = memoryBase.value - 0x800;
    indexedFaultState.rcx = 0x800;
    indexedFaultState.rax = 1;
    indexedFaultState.rdx = 2;
    indexedFaultState.rflags = 0xAD7;
    bool indexedRejected = false;
    try {
        static_cast<void>(indexedBlock.execute(indexedFaultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        indexedRejected =
            std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(indexedRejected, "LOCK CMPXCHG indexed SIB accepted a read-only destination");
    expectEqual(indexedFaultState.rax, std::uint64_t{1},
                "faulted LOCK CMPXCHG indexed SIB changed RAX");
    expectEqual(indexedFaultState.rdx, std::uint64_t{2},
                "faulted LOCK CMPXCHG indexed SIB changed EDX");
    expectEqual(indexedFaultState.rflags, std::uint64_t{0xAD7},
                "faulted LOCK CMPXCHG indexed SIB changed flags");
}

void testLockedCompareExchangeGuestQword() {
    constexpr std::array<std::uint8_t, 6> code{0xF0, 0x4C, 0x0F, 0xB1, 0x07, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802E7AF24ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpxchgMemReg,
           "LOCK CMPXCHG qword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "LOCK CMPXCHG qword length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdi && memory.width == 64 &&
               memory.displacement == 0 && source.reg == rosa::x86::Register::R8 &&
               source.width == 64,
           "LOCK CMPXCHG qword operands differ");
    expect(rosa::debug::dumpX86(decoded).find("lock cmpxchg qword [rdi], r8") != std::string::npos,
           "LOCK CMPXCHG qword dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802E7AF24ULL});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("compare_exchange_guest_memory.i64") != std::string::npos,
           "LOCK CMPXCHG qword IR differs");

    addressSpace.writeU64(memoryBase, 0);
    rosa::x86::X86State equalState;
    equalState.rdi = memoryBase.value;
    equalState.rax = 0;
    equalState.r8 = 0x1122334455667788ULL;
    equalState.rflags = 0x8D7;
    static_cast<void>(block.execute(equalState, &addressSpace));
    expectEqual(addressSpace.readU64(memoryBase), std::uint64_t{0x1122334455667788ULL},
                "successful LOCK CMPXCHG qword stored the wrong value");
    expectEqual(equalState.rax, std::uint64_t{0}, "successful LOCK CMPXCHG qword changed RAX");
    expectEqual(equalState.r8, std::uint64_t{0x1122334455667788ULL},
                "successful LOCK CMPXCHG qword changed its source");
    expectEqual(equalState.rflags, std::uint64_t{0x46},
                "successful LOCK CMPXCHG qword flags differ");

    addressSpace.writeU64(memoryBase, 0x8000000000000000ULL);
    rosa::x86::X86State mismatchState;
    mismatchState.rdi = memoryBase.value;
    mismatchState.rax = 0;
    mismatchState.r8 = 0x1122334455667788ULL;
    mismatchState.rflags = 0x8D7;
    static_cast<void>(block.execute(mismatchState, &addressSpace));
    expectEqual(addressSpace.readU64(memoryBase), std::uint64_t{0x8000000000000000ULL},
                "failed LOCK CMPXCHG qword comparison changed memory");
    expectEqual(mismatchState.rax, std::uint64_t{0x8000000000000000ULL},
                "failed LOCK CMPXCHG qword did not load RAX");
    expectEqual(mismatchState.rflags, std::uint64_t{0x86},
                "failed LOCK CMPXCHG qword flags differ");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    rosa::x86::X86State faultState;
    faultState.rdi = memoryBase.value;
    faultState.rax = 1;
    faultState.r8 = 2;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "LOCK CMPXCHG qword accepted a read-only guest destination");
    expectEqual(faultState.rax, std::uint64_t{1}, "faulted LOCK CMPXCHG qword changed RAX");
    expectEqual(faultState.r8, std::uint64_t{2}, "faulted LOCK CMPXCHG qword changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted LOCK CMPXCHG qword changed flags");

    constexpr std::array<std::uint8_t, 10> ripRelativeCode{0xF0, 0x48, 0x0F, 0xB1, 0x35,
                                                           0x38, 0x1E, 0x84, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress ripRelativeAddress{0x7FF802E7D1CFULL};
    constexpr rosa::guest::GuestAddress ripRelativeTarget{0x7FF8436BF010ULL};
    const auto ripRelativeDecoded = decoder.decodeBlock(ripRelativeCode, ripRelativeAddress);
    const auto ripRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(ripRelativeDecoded[0].operands[0]);
    expect(ripRelativeDecoded[0].opcode == rosa::x86::Opcode::CmpxchgMemReg &&
               ripRelativeMemory.ripRelative && !ripRelativeMemory.hasBase &&
               ripRelativeMemory.displacement == 0x40841E38 && ripRelativeMemory.width == 64,
           "RIP-relative LOCK CMPXCHG qword operand differs");
    expect(rosa::debug::dumpX86(ripRelativeDecoded)
                   .find("lock cmpxchg qword [rip+0x40841e38], rsi ; 0x7ff8436bf010") !=
               std::string::npos,
           "RIP-relative LOCK CMPXCHG qword dump differs");
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{ripRelativeTarget.value & ~UINT64_C(0xFFF)},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(ripRelativeTarget, 0);
    const auto ripRelativeBlock = translator.translate(ripRelativeCode, ripRelativeAddress);
    rosa::x86::X86State ripRelativeState;
    ripRelativeState.rax = 0;
    ripRelativeState.rsi = 0x8877665544332211ULL;
    ripRelativeState.rflags = 0x8D7;
    static_cast<void>(ripRelativeBlock.execute(ripRelativeState, &addressSpace));
    expectEqual(addressSpace.readU64(ripRelativeTarget), std::uint64_t{0x8877665544332211ULL},
                "RIP-relative LOCK CMPXCHG qword stored the wrong value");
    expectEqual(ripRelativeState.rflags, std::uint64_t{0x46},
                "RIP-relative LOCK CMPXCHG qword flags differ");
}

void testLockedCompareExchangeGuestPair() {
    constexpr std::array<std::uint8_t, 10> code{0xF0, 0x48, 0x0F, 0xC7, 0x8E,
                                                0x30, 0x01, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Cmpxchg16bMem, "LOCK CMPXCHG16B opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "LOCK CMPXCHG16B length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rsi && memory.displacement == 0x130 &&
               memory.width == 128,
           "LOCK CMPXCHG16B memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("lock cmpxchg16b [rsi+0x130]") != std::string::npos,
           "LOCK CMPXCHG16B dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8130};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("compare_exchange_guest_pair") != std::string::npos,
           "LOCK CMPXCHG16B IR differs");

    constexpr std::uint64_t memoryLow = 0x1111222233334444ULL;
    constexpr std::uint64_t memoryHigh = 0x5555666677778888ULL;
    addressSpace.writeU64(target, memoryLow);
    addressSpace.writeU64(rosa::guest::GuestAddress{target.value + 8}, memoryHigh);
    rosa::x86::X86State equalState;
    equalState.rsi = page.value;
    equalState.rax = memoryLow;
    equalState.rdx = memoryHigh;
    equalState.rbx = 0xAAAABBBBCCCCDDDDULL;
    equalState.rcx = 0xEEEEFFFF00001111ULL;
    equalState.rflags = 0x897;
    static_cast<void>(block.execute(equalState, &addressSpace));
    expectEqual(addressSpace.readU64(target), equalState.rbx,
                "successful CMPXCHG16B stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{target.value + 8}), equalState.rcx,
                "successful CMPXCHG16B stored the wrong high lane");
    expect((equalState.rflags & (1U << 6U)) != 0, "successful CMPXCHG16B did not set ZF");
    expectEqual(equalState.rax, memoryLow, "successful CMPXCHG16B changed RAX");
    expectEqual(equalState.rdx, memoryHigh, "successful CMPXCHG16B changed RDX");

    addressSpace.writeU64(target, memoryLow);
    addressSpace.writeU64(rosa::guest::GuestAddress{target.value + 8}, memoryHigh);
    rosa::x86::X86State mismatchState;
    mismatchState.rsi = page.value;
    mismatchState.rax = 1;
    mismatchState.rdx = 2;
    mismatchState.rbx = 3;
    mismatchState.rcx = 4;
    mismatchState.rflags = 0x8D7;
    static_cast<void>(block.execute(mismatchState, &addressSpace));
    expectEqual(mismatchState.rax, memoryLow, "failed CMPXCHG16B did not load RAX");
    expectEqual(mismatchState.rdx, memoryHigh, "failed CMPXCHG16B did not load RDX");
    expectEqual(mismatchState.rbx, std::uint64_t{3}, "failed CMPXCHG16B changed RBX");
    expectEqual(mismatchState.rcx, std::uint64_t{4}, "failed CMPXCHG16B changed RCX");
    expect((mismatchState.rflags & (1U << 6U)) == 0, "failed CMPXCHG16B did not clear ZF");
    expectEqual(addressSpace.readU64(target), memoryLow, "failed CMPXCHG16B changed memory");

    rosa::x86::X86State unalignedState;
    unalignedState.rsi = 0x8008;
    unalignedState.rax = 1;
    unalignedState.rdx = 2;
    unalignedState.rbx = 3;
    unalignedState.rcx = 4;
    unalignedState.rflags = 0xAD7;
    const auto before = addressSpace.readBytes(rosa::guest::GuestAddress{0x8138}, 16);
    bool rejected = false;
    try {
        static_cast<void>(block.execute(unalignedState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("16-byte aligned") != std::string_view::npos;
    }
    expect(rejected, "unaligned CMPXCHG16B did not fault");
    expect(addressSpace.readBytes(rosa::guest::GuestAddress{0x8138}, 16) == before,
           "unaligned CMPXCHG16B changed memory");
    expectEqual(unalignedState.rax, std::uint64_t{1}, "unaligned CMPXCHG16B changed RAX");
    expectEqual(unalignedState.rflags, std::uint64_t{0xAD7}, "unaligned CMPXCHG16B changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    std::memcpy(readOnlyBytes.data() + 0x130, &memoryLow, sizeof(memoryLow));
    std::memcpy(readOnlyBytes.data() + 0x138, &memoryHigh, sizeof(memoryHigh));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only CMPXCHG16B target");
    rosa::x86::X86State faultState;
    faultState.rsi = page.value;
    faultState.rax = memoryLow;
    faultState.rdx = memoryHigh;
    faultState.rbx = 3;
    faultState.rcx = 4;
    faultState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "CMPXCHG16B accepted read-only memory");
    expectEqual(faultState.rax, memoryLow, "faulted CMPXCHG16B changed RAX");
    expectEqual(faultState.rdx, memoryHigh, "faulted CMPXCHG16B changed RDX");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted CMPXCHG16B changed flags");
}

void testLockedCompareExchangeGuestPairRipRelative() {
    // Observed in libswiftCore under an Objective-C fixture.
    constexpr std::array<std::uint8_t, 10> code{0xF0, 0x48, 0x0F, 0xC7, 0x0D,
                                                0x29, 0x10, 0x66, 0x2C, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF81713FBBEULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::Cmpxchg16bMem,
           "RIP-relative LOCK CMPXCHG16B opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "RIP-relative LOCK CMPXCHG16B length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase && !memory.index &&
               memory.displacement == 0x2C661029 && memory.width == 128,
           "RIP-relative LOCK CMPXCHG16B memory operand differs");
    expectEqual(observedRip.value + decoded[0].length + memory.displacement,
                std::uint64_t{0x7FF8437A0BF0ULL}, "RIP-relative LOCK CMPXCHG16B target differs");
    expect(rosa::debug::dumpX86(decoded).find("lock cmpxchg16b [rip+0x2c661029]") !=
               std::string::npos,
           "RIP-relative LOCK CMPXCHG16B dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 10> executeCode{0xF0, 0x48, 0x0F, 0xC7, 0x0D,
                                                       0xF7, 0x70, 0x00, 0x00, 0xC3};
    const auto block = translator.translate(executeCode, rosa::guest::GuestAddress{0x1000});
    constexpr std::uint64_t memoryLow = 0x1111222233334444ULL;
    constexpr std::uint64_t memoryHigh = 0x5555666677778888ULL;
    addressSpace.writeU64(target, memoryLow);
    addressSpace.writeU64(rosa::guest::GuestAddress{target.value + 8}, memoryHigh);
    rosa::x86::X86State equalState;
    equalState.rax = memoryLow;
    equalState.rdx = memoryHigh;
    equalState.rbx = 0xAAAABBBBCCCCDDDDULL;
    equalState.rcx = 0xEEEEFFFF00001111ULL;
    equalState.rflags = 0x897;
    static_cast<void>(block.execute(equalState, &addressSpace));
    expectEqual(addressSpace.readU64(target), equalState.rbx,
                "RIP-relative CMPXCHG16B stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{target.value + 8}), equalState.rcx,
                "RIP-relative CMPXCHG16B stored the wrong high lane");
    expect((equalState.rflags & (1U << 6U)) != 0, "RIP-relative CMPXCHG16B did not set ZF");
}

void testExchangeGuestDwordWithRegister() {
    constexpr std::array<std::uint8_t, 3> code{0x87, 0x17, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XchgMemReg, "XCHG dword memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "XCHG dword memory length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdi && memory.displacement == 0 &&
               memory.width == 32,
           "XCHG dword memory operand differs");
    expect(source.reg == rosa::x86::Register::Rdx && source.width == 32,
           "XCHG dword source differs");
    expect(rosa::debug::dumpX86(decoded).find("xchg dword [rdi], edx") != std::string::npos,
           "XCHG dword dump differs");

    constexpr rosa::guest::GuestAddress target{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array oldBytes{std::uint8_t{0x44}, std::uint8_t{0x33}, std::uint8_t{0x22},
                                  std::uint8_t{0x11}};
    addressSpace.writeBytes(target, oldBytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(
        rosa::debug::dumpIr(block.intermediateRepresentation()).find("exchange_guest_memory.i32") !=
            std::string::npos,
        "XCHG did not lower through atomic guest-memory IR");
    rosa::x86::X86State state;
    state.rdi = target.value;
    state.rdx = 0xAAAAAAAAAABBCCDDULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0xAABBCCDDU},
                "XCHG stored the wrong guest dword");
    expectEqual(state.rdx, std::uint64_t{0x11223344},
                "XCHG did not zero-extend the old dword into EDX");
    expectEqual(state.rdi, target.value, "XCHG changed its address base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "XCHG changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0] = 0xDD;
    readOnlyBytes[1] = 0xCC;
    readOnlyBytes[2] = 0xBB;
    readOnlyBytes[3] = 0xAA;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(target, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only XCHG target");
    rosa::x86::X86State faultState;
    faultState.rdi = target.value;
    faultState.rdx = 0xBBBBBBBBAABBCCDDULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "same-value XCHG accepted a read-only target");
    expectEqual(readOnlyAddressSpace.readU32(target), std::uint32_t{0xAABBCCDDU},
                "faulted XCHG changed read-only memory");
    expectEqual(faultState.rdx, std::uint64_t{0xBBBBBBBBAABBCCDDULL}, "faulted XCHG changed EDX");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted XCHG changed flags");

    constexpr rosa::guest::GuestAddress page{0x9000};
    constexpr rosa::guest::GuestAddress crossPageTarget{0x9FFE};
    constexpr std::array crossPageBytes{std::uint8_t{0x55}, std::uint8_t{0xAA}};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, crossPageBytes);
    faultState.rdi = crossPageTarget.value;
    faultState.rdx = 0x12345678;
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page XCHG did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, 2) ==
               std::vector<std::uint8_t>(crossPageBytes.begin(), crossPageBytes.end()),
           "cross-page XCHG partially changed memory");
    expectEqual(faultState.rdx, std::uint64_t{0x12345678}, "cross-page XCHG changed EDX");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "cross-page XCHG changed flags");
}

void testExchangeGuestQwordWithRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x87, 0x48, 0x08, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XchgMemReg, "XCHG qword memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "XCHG qword memory length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rax && memory.displacement == 8 &&
               memory.width == 64,
           "XCHG qword memory operand differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 64,
           "XCHG qword source differs");
    expect(rosa::debug::dumpX86(decoded).find("xchg qword [rax+0x8], rcx") != std::string::npos,
           "XCHG qword dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8088};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0xFEDCBA9876543210ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(
        rosa::debug::dumpIr(block.intermediateRepresentation()).find("exchange_guest_memory.i64") !=
            std::string::npos,
        "XCHG qword did not lower through atomic guest-memory IR");
    rosa::x86::X86State state;
    state.rax = target.value - 8;
    state.rcx = 0x0123456789ABCDEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0x0123456789ABCDEFULL},
                "XCHG qword stored the wrong value");
    expectEqual(state.rcx, std::uint64_t{0xFEDCBA9876543210ULL},
                "XCHG qword returned the wrong old memory value");
    expectEqual(state.rax, target.value - 8, "XCHG qword changed its address base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "XCHG qword changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t readOnlySentinel = 0xAABBCCDDEEFF0011ULL;
    std::memcpy(readOnlyBytes.data() + 0x88, &readOnlySentinel, sizeof(readOnlySentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only qword XCHG target");
    rosa::x86::X86State faultState;
    faultState.rax = target.value - 8;
    faultState.rcx = 0x1122334455667788ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "XCHG qword accepted a read-only destination");
    expectEqual(readOnlyAddressSpace.readU64(target), readOnlySentinel,
                "faulted XCHG qword changed read-only memory");
    expectEqual(faultState.rcx, std::uint64_t{0x1122334455667788ULL},
                "faulted XCHG qword changed RCX");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted XCHG qword changed flags");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x9FFC};
    constexpr std::array crossPageBytes{std::uint8_t{0x11}, std::uint8_t{0x22}, std::uint8_t{0x33},
                                        std::uint8_t{0x44}};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(
        rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, crossPageBytes);
    faultState.rax = crossPageTarget.value - 8;
    faultState.rcx = 0x8877665544332211ULL;
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page XCHG qword did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, 4) ==
               std::vector<std::uint8_t>(crossPageBytes.begin(), crossPageBytes.end()),
           "cross-page XCHG qword partially changed memory");
    expectEqual(faultState.rcx, std::uint64_t{0x8877665544332211ULL},
                "cross-page XCHG qword changed RCX");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "cross-page XCHG qword changed flags");

    constexpr rosa::guest::GuestAddress rip{0x7FF802E18172ULL};
    constexpr rosa::guest::GuestAddress ripTarget{0x7FF8436BCF70ULL};
    constexpr rosa::guest::GuestAddress ripTargetPage{0x7FF8436BC000ULL};
    constexpr std::array<std::uint8_t, 8> ripCode{0x48, 0x87, 0x05, 0xF7, 0x4D, 0x8A, 0x40, 0xC3};
    const auto ripDecoded = decoder.decodeBlock(ripCode, rip);
    expect(ripDecoded[0].opcode == rosa::x86::Opcode::XchgMemReg,
           "RIP-relative XCHG qword opcode differs");
    expectEqual(ripDecoded[0].length, std::uint8_t{7}, "RIP-relative XCHG qword length differs");
    const auto ripMemory = std::get<rosa::x86::MemoryOperand>(ripDecoded[0].operands[0]);
    const auto ripSource = std::get<rosa::x86::RegisterOperand>(ripDecoded[0].operands[1]);
    expect(ripMemory.ripRelative && !ripMemory.hasBase && ripMemory.displacement == 0x408A4DF7 &&
               ripMemory.width == 64,
           "RIP-relative XCHG qword memory operand differs");
    expect(ripSource.reg == rosa::x86::Register::Rax && ripSource.width == 64,
           "RIP-relative XCHG qword source differs");
    expect(rosa::debug::dumpX86(ripDecoded)
                   .find("xchg qword [rip+0x408a4df7], rax ; 0x7ff8436bcf70") != std::string::npos,
           "RIP-relative XCHG qword dump differs");

    rosa::guest::AddressSpace ripAddressSpace;
    ripAddressSpace.mapAnonymous(ripTargetPage, rosa::guest::guestPageSize,
                                 rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::uint64_t ripOldValue = 0xFEDCBA9876543210ULL;
    constexpr std::uint64_t ripNewValue = 0x7FF802A31E99ULL;
    ripAddressSpace.writeU64(ripTarget, ripOldValue);
    const auto ripBlock = translator.translate(ripCode, rip);
    rosa::x86::X86State ripState;
    ripState.rax = ripNewValue;
    ripState.rflags = 0x9D7;
    static_cast<void>(ripBlock.execute(ripState, &ripAddressSpace));
    expectEqual(ripAddressSpace.readU64(ripTarget), ripNewValue,
                "RIP-relative XCHG qword stored the wrong value");
    expectEqual(ripState.rax, ripOldValue, "RIP-relative XCHG qword returned the wrong old value");
    expectEqual(ripState.rflags, std::uint64_t{0x9D7}, "RIP-relative XCHG qword changed flags");

    rosa::guest::AddressSpace unmappedRipAddressSpace;
    ripState.rax = ripNewValue;
    ripState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(ripBlock.execute(ripState, &unmappedRipAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative XCHG qword accepted an unmapped target");
    expectEqual(ripState.rax, ripNewValue, "faulted RIP-relative XCHG qword changed RAX");
    expectEqual(ripState.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative XCHG qword changed flags");
}

void testExchangeGuestQwordWithIndex() {
    // Observed in CoreFoundation under an Objective-C fixture: XCHG rcx, [rax+rdx].
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x87, 0x0C, 0x10, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802EB83A9ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::XchgMemReg,
           "indexed XCHG qword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "indexed XCHG qword length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(!memory.ripRelative && memory.hasBase &&
               memory.base == rosa::x86::Register::Rax && memory.index &&
               *memory.index == rosa::x86::Register::Rdx && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 64,
           "indexed XCHG qword memory operand differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 64,
           "indexed XCHG qword source differs");
    expect(rosa::debug::dumpX86(decoded).find("xchg qword [rax+rdx], rcx") != std::string::npos,
           "indexed XCHG qword dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0xFEDCBA9876543210ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = target.value - 0x40;
    state.rdx = 0x40;
    state.rcx = 0x0123456789ABCDEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0x0123456789ABCDEFULL},
                "indexed XCHG qword stored the wrong value");
    expectEqual(state.rcx, std::uint64_t{0xFEDCBA9876543210ULL},
                "indexed XCHG qword returned the wrong old memory value");
    expectEqual(state.rax, target.value - 0x40, "indexed XCHG qword changed its base");
    expectEqual(state.rdx, std::uint64_t{0x40}, "indexed XCHG qword changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "indexed XCHG qword changed flags");
}

void testExchangeGuestByteWithRegister() {
    // Observed in Foundation under an Objective-C fixture: XCHG byte [r14+0x37], al.
    constexpr std::array<std::uint8_t, 5> code{0x41, 0x86, 0x46, 0x37, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8040AC6FAULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::XchgMemReg,
           "XCHG byte memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "XCHG byte memory length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(!memory.ripRelative && memory.hasBase &&
               memory.base == rosa::x86::Register::R14 && !memory.index &&
               memory.displacement == 0x37 && memory.width == 8,
           "XCHG byte memory operand differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 8,
           "XCHG byte source differs");
    expect(rosa::debug::dumpX86(decoded).find("xchg byte [r14+0x37], al") != std::string::npos,
           "XCHG byte dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8137};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 1>{0x5A});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(
        rosa::debug::dumpIr(block.intermediateRepresentation()).find("exchange_guest_memory.i8") !=
            std::string::npos,
        "XCHG byte did not lower through byte guest-memory IR");
    rosa::x86::X86State state;
    state.r14 = target.value - 0x37;
    state.rax = 0x11223344556677A5ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0xA5},
                "XCHG byte stored the wrong value");
    expectEqual(state.rax, std::uint64_t{0x112233445566775AULL},
                "XCHG byte returned the wrong old memory value");
    expectEqual(state.r14, target.value - 0x37, "XCHG byte changed its address base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "XCHG byte changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r14 = target.value - 0x37;
    faultState.rax = 0xA5A5A5A5A5A5A5A5ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "XCHG byte accepted an unmapped target");
    expectEqual(faultState.rax, std::uint64_t{0xA5A5A5A5A5A5A5A5ULL},
                "faulted XCHG byte changed RAX");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted XCHG byte changed flags");

    // Observed in Foundation under an Objective-C fixture: XCHG byte [rax+0x37], cl.
    constexpr std::array<std::uint8_t, 4> plainCode{0x86, 0x48, 0x37, 0xC3};
    constexpr rosa::guest::GuestAddress plainRip{0x7FF804C60C7DULL};
    const auto plainDecoded = decoder.decodeBlock(plainCode, plainRip);
    expect(plainDecoded[0].opcode == rosa::x86::Opcode::XchgMemReg,
           "plain XCHG byte opcode differs");
    expectEqual(plainDecoded[0].length, std::uint8_t{3}, "plain XCHG byte length differs");
    const auto plainMemory = std::get<rosa::x86::MemoryOperand>(plainDecoded[0].operands[0]);
    const auto plainSource = std::get<rosa::x86::RegisterOperand>(plainDecoded[0].operands[1]);
    expect(!plainMemory.ripRelative && plainMemory.hasBase &&
               plainMemory.base == rosa::x86::Register::Rax && !plainMemory.index &&
               plainMemory.displacement == 0x37 && plainMemory.width == 8,
           "plain XCHG byte memory operand differs");
    expect(plainSource.reg == rosa::x86::Register::Rcx && plainSource.width == 8,
           "plain XCHG byte source differs");
    expect(rosa::debug::dumpX86(plainDecoded).find("xchg byte [rax+0x37], cl") !=
               std::string::npos,
           "plain XCHG byte dump differs");
    const auto plainBlock = translator.translate(plainCode, plainRip);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 1>{0x3C});
    rosa::x86::X86State plainState;
    plainState.rax = target.value - 0x37;
    plainState.rcx = 0x11223344556677C3ULL;
    plainState.rflags = 0x8D7;
    static_cast<void>(plainBlock.execute(plainState, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0xC3},
                "plain XCHG byte stored the wrong value");
    expectEqual(plainState.rcx, std::uint64_t{0x112233445566773CULL},
                "plain XCHG byte returned the wrong old memory value");
    expectEqual(plainState.rflags, std::uint64_t{0x8D7}, "plain XCHG byte changed flags");
}

void testLockedAddGuestQwordRegister() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF7000249E1ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF7000A5330ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF7000A5000ULL};
    constexpr std::array<std::uint8_t, 9> observed{0xF0, 0x48, 0x01, 0x05, 0x47,
                                                   0x09, 0x08, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockAddMemReg, "LOCK ADD qword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "LOCK ADD qword length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 64 &&
               memory.displacement == 0x80947,
           "LOCK ADD qword RIP-relative operand differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 64,
           "LOCK ADD qword source differs");
    expectEqual(instructionAddress.value + decoded[0].length +
                    static_cast<std::uint64_t>(memory.displacement),
                target.value, "LOCK ADD qword target differs");
    expect(rosa::debug::dumpX86(decoded).find("lock add qword [rip+0x80947], rax") !=
               std::string::npos,
           "LOCK ADD qword dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observed, instructionAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("locked_add_guest_memory.i64") != std::string::npos,
           "LOCK ADD did not lower through locked guest-memory IR");
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, UINT64_MAX);
    rosa::x86::X86State state;
    state.rax = 1;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0}, "LOCK ADD qword result differs");
    expectEqual(state.rax, std::uint64_t{1}, "LOCK ADD changed its source register");
    expectEqual(state.rflags, std::uint64_t{0x57}, "LOCK ADD carry/zero flags differ");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t readOnlySentinel = 0xAABBCCDDEEFF0011ULL;
    std::memcpy(readOnlyBytes.data() + (target.value - targetPage.value), &readOnlySentinel,
                sizeof(readOnlySentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(targetPage, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only LOCK ADD target");
    rosa::x86::X86State faultState;
    faultState.rax = 0x1122334455667788ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "LOCK ADD accepted a read-only guest qword");
    expectEqual(readOnlyAddressSpace.readU64(target), readOnlySentinel,
                "faulted LOCK ADD changed read-only guest memory");
    expectEqual(faultState.rax, std::uint64_t{0x1122334455667788ULL},
                "faulted LOCK ADD changed its source register");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted LOCK ADD changed flags");

    constexpr std::array<std::uint8_t, 6> based{0xF0, 0x48, 0x01, 0x47, 0x10, 0xC3};
    const auto basedBlock = translator.translate(based, rosa::guest::GuestAddress{0x1000});
    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FFC};
    constexpr std::array crossPageBytes{std::uint8_t{0x11}, std::uint8_t{0x22}, std::uint8_t{0x33},
                                        std::uint8_t{0x44}};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(
        rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, crossPageBytes);
    faultState.rdi = crossPageTarget.value - 0x10;
    faultState.rax = 1;
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(basedBlock.execute(faultState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page LOCK ADD did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, 4) ==
               std::vector<std::uint8_t>(crossPageBytes.begin(), crossPageBytes.end()),
           "cross-page LOCK ADD partially changed guest memory");
    expectEqual(faultState.rax, std::uint64_t{1},
                "cross-page LOCK ADD changed its source register");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "cross-page LOCK ADD changed flags");

    constexpr std::array<std::uint8_t, 8> rexBIgnored{0xF0, 0x4D, 0x01, 0x2D,
                                                      0x00, 0x00, 0x00, 0x00};
    const auto rexDecoded = decoder.decodeBlock(rexBIgnored, rosa::guest::GuestAddress{0x2000}, 1);
    const auto rexMemory = std::get<rosa::x86::MemoryOperand>(rexDecoded[0].operands[0]);
    const auto rexSource = std::get<rosa::x86::RegisterOperand>(rexDecoded[0].operands[1]);
    expect(rexMemory.ripRelative && rexSource.reg == rosa::x86::Register::R13,
           "REX.B incorrectly changed the RIP-relative LOCK ADD destination");
}

void testLockedExchangeAddGuestDwordRegister() {
    constexpr std::array<std::uint8_t, 5> code{0xF0, 0x0F, 0xC1, 0x07, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::LockXaddMemReg, "LOCK XADD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "LOCK XADD length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdi && memory.width == 32 &&
               memory.displacement == 0,
           "LOCK XADD memory operand differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 32,
           "LOCK XADD source operand differs");
    expect(rosa::debug::dumpX86(decoded).find("lock xadd dword [rdi], eax") != std::string::npos,
           "LOCK XADD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("locked_exchange_add_guest_memory.i32") != std::string::npos,
           "LOCK XADD did not lower through locked guest-memory IR");
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0xDEADBEEFFFFFFFFFULL);
    rosa::x86::X86State state;
    state.rax = 0xAAAAAAAA00000001ULL;
    state.rdi = target.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0xDEADBEEF00000000ULL},
                "LOCK XADD did not perform an exact dword write");
    expectEqual(state.rax, std::uint64_t{UINT32_MAX},
                "LOCK XADD did not return and zero-extend the old dword");
    expectEqual(state.rdi, target.value, "LOCK XADD changed its address register");
    expectEqual(state.rflags, std::uint64_t{0x57}, "LOCK XADD carry/zero flags differ");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t readOnlySentinel = 0xAABBCCDD7FFFFFFFULL;
    std::memcpy(readOnlyBytes.data() + 0x100, &readOnlySentinel, sizeof(readOnlySentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only LOCK XADD target");
    rosa::x86::X86State faultState;
    faultState.rax = 0xBBBBBBBB00000001ULL;
    faultState.rdi = target.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "LOCK XADD accepted a read-only guest dword");
    expectEqual(readOnlyAddressSpace.readU64(target), readOnlySentinel,
                "faulted LOCK XADD changed read-only memory");
    expectEqual(faultState.rax, std::uint64_t{0xBBBBBBBB00000001ULL},
                "faulted LOCK XADD changed its source register");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted LOCK XADD changed flags");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FFE};
    constexpr std::array crossPageBytes{std::uint8_t{0x55}, std::uint8_t{0xAA}};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, crossPageBytes);
    faultState.rax = 1;
    faultState.rdi = crossPageTarget.value;
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page LOCK XADD did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, 2) ==
               std::vector<std::uint8_t>(crossPageBytes.begin(), crossPageBytes.end()),
           "cross-page LOCK XADD partially changed memory");
    expectEqual(faultState.rax, std::uint64_t{1},
                "cross-page LOCK XADD changed its source register");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "cross-page LOCK XADD changed flags");
}

void testLockedExchangeAddRipRelativeGuestQword() {
    // Observed in libsystem_c: LOCK XADD qword [rip+disp32], r14.
    constexpr std::array<std::uint8_t, 10> code{0xF0, 0x4C, 0x0F, 0xC1, 0x35,
                                               0x51, 0x4D, 0x9A, 0x40, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802D15AB6ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::LockXaddMemReg,
           "RIP-relative LOCK XADD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "RIP-relative LOCK XADD length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 64 &&
               memory.displacement == 0x409A4D51 && source.reg == rosa::x86::Register::R14 &&
               source.width == 64,
           "LOCK XADD qword [rip+disp32], r14 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("lock xadd qword [rip+0x409a4d51], r14") !=
               std::string::npos,
           "LOCK XADD qword [rip+disp32], r14 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    constexpr rosa::guest::GuestAddress syntheticRip{0x7FFFULL};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x100);
    const rosa::dbt::Translator translator;
    // Execute at a synthetic RIP whose computed target stays in the page.
    constexpr std::array<std::uint8_t, 10> executableCode{0xF0, 0x4C, 0x0F, 0xC1, 0x35,
                                                          0xF8, 0x00, 0x00, 0x00, 0xC3};
    const auto block = translator.translate(executableCode, syntheticRip);
    rosa::x86::X86State state;
    state.r14 = 0x22;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0x122},
                "RIP-relative LOCK XADD memory result differs");
    expectEqual(state.r14, std::uint64_t{0x100},
                "RIP-relative LOCK XADD did not return the old value");
    expectEqual(state.rflags, std::uint64_t{0x6}, "RIP-relative LOCK XADD flags differ");
}

void testLockedExchangeAddGuestQwordRegister() {
    constexpr std::array<std::uint8_t, 6> code{0xF0, 0x49, 0x0F, 0xC1, 0x07, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802E7D202ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::LockXaddMemReg,
           "LOCK XADD qword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "LOCK XADD qword length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R15 && memory.width == 64 &&
               memory.displacement == 0 && source.reg == rosa::x86::Register::Rax &&
               source.width == 64,
           "LOCK XADD qword operands differ");
    expect(rosa::debug::dumpX86(decoded).find("lock xadd qword [r15], rax") != std::string::npos,
           "LOCK XADD qword dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802E7D202ULL});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("locked_exchange_add_guest_memory.i64") != std::string::npos,
           "LOCK XADD qword IR differs");
    constexpr rosa::guest::GuestAddress target{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x20);
    rosa::x86::X86State state;
    state.rax = 0x20;
    state.r15 = target.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0x40},
                "LOCK XADD qword stored the wrong sum");
    expectEqual(state.rax, std::uint64_t{0x20}, "LOCK XADD qword returned the wrong old value");
    expectEqual(state.r15, target.value, "LOCK XADD qword changed its address register");
    expectEqual(state.rflags, std::uint64_t{0x2}, "LOCK XADD qword flags differ");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    rosa::x86::X86State faultState;
    faultState.rax = 0x20;
    faultState.r15 = target.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "LOCK XADD qword accepted read-only guest memory");
    expectEqual(faultState.rax, std::uint64_t{0x20},
                "faulted LOCK XADD qword changed its source register");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted LOCK XADD qword changed flags");
}

void testLockedOrGuestDwordImmediate() {
    constexpr std::array<std::uint8_t, 7> zeroCode{0xF0, 0x83, 0x4C, 0x24, 0xC0, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(zeroCode, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::LockOrMemImm, "LOCK OR opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "LOCK OR length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsp && memory.width == 32 &&
               memory.displacement == -0x40,
           "LOCK OR stack operand differs");
    expect(immediate.width == 8 && immediate.value == 0, "LOCK OR immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("lock or dword [rsp-0x40], 0x0") != std::string::npos,
           "LOCK OR dump differs");

    constexpr rosa::guest::GuestAddress stackPage{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array zeroBytes{std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{0},
                                   std::uint8_t{0}};
    addressSpace.writeBytes(target, zeroBytes);
    const rosa::dbt::Translator translator;
    const auto zeroBlock = translator.translate(zeroCode, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(zeroBlock.intermediateRepresentation())
                   .find("locked_or_guest_memory.i32") != std::string::npos,
           "LOCK OR did not lower through atomic guest-memory IR");
    rosa::x86::X86State zeroState;
    zeroState.rsp = target.value + 0x40;
    zeroState.rflags = 0x8D7;
    static_cast<void>(zeroBlock.execute(zeroState, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0},
                "LOCK OR zero changed the guest dword");
    expectEqual(zeroState.rsp, target.value + 0x40, "LOCK OR changed RSP");
    constexpr std::uint64_t definedLogicFlags =
        (1ULL << 0U) | (1ULL << 2U) | (1ULL << 6U) | (1ULL << 7U) | (1ULL << 11U);
    expectEqual(zeroState.rflags & definedLogicFlags, std::uint64_t{0x44},
                "LOCK OR zero defined flags differ");

    constexpr std::array<std::uint8_t, 7> negativeCode{0xF0, 0x83, 0x4C, 0x24, 0xC0, 0x80, 0xC3};
    const auto negativeBlock =
        translator.translate(negativeCode, rosa::guest::GuestAddress{0x2000});
    constexpr std::array initialBytes{std::uint8_t{0x34}, std::uint8_t{0}, std::uint8_t{0},
                                      std::uint8_t{0}};
    addressSpace.writeBytes(target, initialBytes);
    rosa::x86::X86State negativeState;
    negativeState.rsp = target.value + 0x40;
    negativeState.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(negativeState, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0xFFFFFFB4U},
                "LOCK OR did not sign-extend imm8 to dword");
    expectEqual(negativeState.rflags & definedLogicFlags, std::uint64_t{0x84},
                "LOCK OR negative result defined flags differ");

    constexpr std::array<std::uint8_t, 8> fullImmediateCode{0xF0, 0x81, 0x08, 0x00,
                                                            0x00, 0x00, 0x10, 0xC3};
    const auto fullImmediateDecoded =
        decoder.decodeBlock(fullImmediateCode, rosa::guest::GuestAddress{0x3000});
    expect(fullImmediateDecoded[0].opcode == rosa::x86::Opcode::LockOrMemImm,
           "LOCK OR imm32 opcode differs");
    expectEqual(fullImmediateDecoded[0].length, std::uint8_t{7}, "LOCK OR imm32 length differs");
    const auto fullImmediateMemory =
        std::get<rosa::x86::MemoryOperand>(fullImmediateDecoded[0].operands[0]);
    const auto fullImmediate =
        std::get<rosa::x86::ImmediateOperand>(fullImmediateDecoded[0].operands[1]);
    expect(fullImmediateMemory.base == rosa::x86::Register::Rax &&
               fullImmediateMemory.width == 32 && fullImmediateMemory.displacement == 0 &&
               fullImmediate.width == 32 && fullImmediate.value == 0x10000000,
           "lock or dword [rax], 0x10000000 operands differ");
    expect(rosa::debug::dumpX86(fullImmediateDecoded).find("lock or dword [rax], 0x10000000") !=
               std::string::npos,
           "LOCK OR imm32 dump differs");
    const auto fullImmediateBlock =
        translator.translate(fullImmediateCode, rosa::guest::GuestAddress{0x3000});
    addressSpace.writeBytes(target, std::array<std::uint8_t, 4>{0x01, 0x00, 0x00, 0x00});
    rosa::x86::X86State fullImmediateState;
    fullImmediateState.rax = target.value;
    fullImmediateState.rflags = 0x8D7;
    static_cast<void>(fullImmediateBlock.execute(fullImmediateState, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x10000001},
                "LOCK OR imm32 result differs");
    expectEqual(fullImmediateState.rax, target.value, "LOCK OR imm32 changed RAX");
    expectEqual(fullImmediateState.rflags & definedLogicFlags, std::uint64_t{0},
                "LOCK OR imm32 defined flags differ");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0x100] = 0xA5;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(stackPage, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only LOCK OR stack");
    rosa::x86::X86State faultState;
    faultState.rsp = target.value + 0x40;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(zeroBlock.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "LOCK OR zero accepted a read-only guest dword");
    expectEqual(readOnlyAddressSpace.readU32(target), std::uint32_t{0xA5},
                "faulted LOCK OR changed read-only guest memory");
    expectEqual(faultState.rsp, target.value + 0x40, "faulted LOCK OR changed RSP");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted LOCK OR changed flags");

    rosa::x86::X86State fullImmediateFaultState;
    fullImmediateFaultState.rax = target.value;
    fullImmediateFaultState.rflags = 0xCD7;
    rejected = false;
    try {
        static_cast<void>(
            fullImmediateBlock.execute(fullImmediateFaultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "LOCK OR imm32 accepted a read-only guest dword");
    expectEqual(readOnlyAddressSpace.readU32(target), std::uint32_t{0xA5},
                "faulted LOCK OR imm32 changed read-only memory");
    expectEqual(fullImmediateFaultState.rax, target.value, "faulted LOCK OR imm32 changed RAX");
    expectEqual(fullImmediateFaultState.rflags, std::uint64_t{0xCD7},
                "faulted LOCK OR imm32 changed flags");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FFE};
    constexpr std::array crossPageBytes{std::uint8_t{0x55}, std::uint8_t{0xAA}};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(stackPage, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, crossPageBytes);
    faultState.rsp = crossPageTarget.value + 0x40;
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(negativeBlock.execute(faultState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page LOCK OR did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, 2) ==
               std::vector<std::uint8_t>(crossPageBytes.begin(), crossPageBytes.end()),
           "cross-page LOCK OR partially changed guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "cross-page LOCK OR changed flags");
}

void testLockedOrGuestWordImmediate() {
    constexpr std::array<std::uint8_t, 9> code{0x66, 0xF0, 0x41, 0x83, 0x4C,
                                               0x24, 0x1E, 0x01, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802A1A52AULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockOrMemImm, "word LOCK OR opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "word LOCK OR length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R12 && memory.width == 16 &&
               memory.displacement == 0x1E && immediate.width == 8 && immediate.value == 1,
           "lock or word [r12+0x1e], 1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("lock or word [r12+0x1e], 0x1") != std::string::npos,
           "word LOCK OR dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x811E};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> initial{0x00, 0x80};
    addressSpace.writeBytes(target, initial);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("locked_or_guest_memory.i16") != std::string::npos,
           "word LOCK OR did not lower through atomic guest-memory IR");
    rosa::x86::X86State state;
    state.r12 = 0x8100;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expect(addressSpace.readBytes(target, 2) == std::vector<std::uint8_t>({0x01, 0x80}),
           "word LOCK OR result differs");
    expectEqual(state.r12, std::uint64_t{0x8100}, "word LOCK OR changed its base");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "word LOCK OR defined flags differ");

    constexpr std::array<std::uint8_t, 10> imm16Code{0x66, 0xF0, 0x41, 0x81, 0x4C,
                                                     0x24, 0x1E, 0x00, 0x20, 0xC3};
    constexpr rosa::guest::GuestAddress imm16Address{0x7FF802A1A61AULL};
    const auto imm16Decoded = decoder.decodeBlock(imm16Code, imm16Address);
    expect(imm16Decoded[0].opcode == rosa::x86::Opcode::LockOrMemImm,
           "word LOCK OR imm16 opcode differs");
    expectEqual(imm16Decoded[0].length, std::uint8_t{9}, "word LOCK OR imm16 length differs");
    const auto imm16Memory = std::get<rosa::x86::MemoryOperand>(imm16Decoded[0].operands[0]);
    const auto imm16 = std::get<rosa::x86::ImmediateOperand>(imm16Decoded[0].operands[1]);
    expect(imm16Memory.base == rosa::x86::Register::R12 && imm16Memory.width == 16 &&
               imm16Memory.displacement == 0x1E && imm16.width == 16 && imm16.value == 0x2000,
           "lock or word [r12+0x1e], 0x2000 operands differ");
    expect(rosa::debug::dumpX86(imm16Decoded).find("lock or word [r12+0x1e], 0x2000") !=
               std::string::npos,
           "word LOCK OR imm16 dump differs");
    const auto imm16Block = translator.translate(imm16Code, imm16Address);
    rosa::x86::X86State imm16State;
    imm16State.r12 = 0x8100;
    imm16State.rflags = 0x8D7;
    static_cast<void>(imm16Block.execute(imm16State, &addressSpace));
    expect(addressSpace.readBytes(target, 2) == std::vector<std::uint8_t>({0x01, 0xA0}),
           "word LOCK OR imm16 result differs");
    expectEqual(imm16State.r12, std::uint64_t{0x8100}, "word LOCK OR imm16 changed its base");
    expectEqual(imm16State.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "word LOCK OR imm16 defined flags differ");

    constexpr std::array<std::uint8_t, 8> legacyImm16Code{0x66, 0xF0, 0x81, 0x4E,
                                                          0x1E, 0x00, 0x20, 0xC3};
    constexpr rosa::guest::GuestAddress legacyImm16Address{0x7FF802A1BC3CULL};
    const auto legacyImm16Decoded = decoder.decodeBlock(legacyImm16Code, legacyImm16Address);
    expect(legacyImm16Decoded[0].opcode == rosa::x86::Opcode::LockOrMemImm,
           "legacy word LOCK OR imm16 opcode differs");
    expectEqual(legacyImm16Decoded[0].length, std::uint8_t{7},
                "legacy word LOCK OR imm16 length differs");
    const auto legacyImm16Memory =
        std::get<rosa::x86::MemoryOperand>(legacyImm16Decoded[0].operands[0]);
    const auto legacyImm16 =
        std::get<rosa::x86::ImmediateOperand>(legacyImm16Decoded[0].operands[1]);
    expect(legacyImm16Memory.base == rosa::x86::Register::Rsi && legacyImm16Memory.width == 16 &&
               legacyImm16Memory.displacement == 0x1E && legacyImm16.width == 16 &&
               legacyImm16.value == 0x2000,
           "lock or word [rsi+0x1e], 0x2000 operands differ");
    expect(rosa::debug::dumpX86(legacyImm16Decoded).find("lock or word [rsi+0x1e], 0x2000") !=
               std::string::npos,
           "legacy word LOCK OR imm16 dump differs");
    addressSpace.writeBytes(target, std::array<std::uint8_t, 2>{0x01, 0x00});
    const auto legacyImm16Block = translator.translate(legacyImm16Code, legacyImm16Address);
    rosa::x86::X86State legacyImm16State;
    legacyImm16State.rsi = 0x8100;
    legacyImm16State.rflags = 0x8D7;
    static_cast<void>(legacyImm16Block.execute(legacyImm16State, &addressSpace));
    expect(addressSpace.readBytes(target, 2) == std::vector<std::uint8_t>({0x01, 0x20}),
           "legacy word LOCK OR imm16 result differs");
    expectEqual(legacyImm16State.rsi, std::uint64_t{0x8100},
                "legacy word LOCK OR imm16 changed its base");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FFF};
    constexpr std::array<std::uint8_t, 1> tail{0xA5};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, tail);
    rosa::x86::X86State faultState;
    faultState.r12 = crossPageTarget.value - 0x1E;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page word LOCK OR did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, 1) ==
               std::vector<std::uint8_t>(tail.begin(), tail.end()),
           "faulted word LOCK OR partially changed memory");
    expectEqual(faultState.r12, crossPageTarget.value - 0x1E,
                "faulted word LOCK OR changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "faulted word LOCK OR changed flags");
}

void testLockedAndGuestWordImmediate() {
    // Observed in libobjc under an Objective-C fixture: LOCK AND word [rbx+0x1e], 0xbfff.
    constexpr std::array<std::uint8_t, 8> code{0x66, 0xF0, 0x81, 0x63,
                                               0x1E, 0xFF, 0xBF, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802A3E69AULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockAndMemImm,
           "word LOCK AND opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "word LOCK AND length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.width == 16 &&
               memory.displacement == 0x1E && immediate.width == 16 &&
               immediate.value == 0xBFFF,
           "lock and word [rbx+0x1e], 0xbfff operands differ");
    expect(rosa::debug::dumpX86(decoded).find("lock and word [rbx+0x1e], 0xbfff") !=
               std::string::npos,
           "word LOCK AND dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x811E};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 2>{0xFF, 0xFF});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("locked_and_guest_memory.i16") != std::string::npos,
           "word LOCK AND did not lower through atomic guest-memory IR");
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    // 0xFFFF & 0xBFFF == 0xBFFF.
    expect(addressSpace.readBytes(target, 2) == std::vector<std::uint8_t>({0xFF, 0xBF}),
           "word LOCK AND result differs");
    expectEqual(state.rbx, std::uint64_t{0x8100}, "word LOCK AND changed its base");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    // 0xBFFF: sign set, parity even (low byte 0xFF has 8 bits set).
    expectEqual(state.rflags & definedLogicFlags,
                std::uint64_t{(1U << 2U) | (1U << 7U)},
                "word LOCK AND defined flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbx = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "word LOCK AND to unmapped guest memory did not fault");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "faulted word LOCK AND changed flags");
}

void testLockedIncrementGuestDword() {
    constexpr std::array<std::uint8_t, 4> code{0xF0, 0xFF, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::LockIncMem, "LOCK INC opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "LOCK INC length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rax && memory.width == 32 &&
               memory.displacement == 0,
           "LOCK INC memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("lock inc dword [rax]") != std::string::npos,
           "LOCK INC dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("locked_increment_guest_memory.i32") != std::string::npos,
           "LOCK INC did not lower through locked guest-memory IR");

    addressSpace.writeU64(target, 0xDEADBEEF7FFFFFFFULL);
    rosa::x86::X86State overflowState;
    overflowState.rax = target.value;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0xDEADBEEF80000000ULL},
                "LOCK INC did not perform an exact dword write");
    expectEqual(overflowState.rax, target.value, "LOCK INC changed its address base");
    expectEqual(overflowState.rflags, std::uint64_t{0x897}, "LOCK INC overflow flags differ");

    addressSpace.writeU64(target, 0xA5A5A5A5FFFFFFFFULL);
    rosa::x86::X86State wrapState;
    wrapState.rax = target.value;
    wrapState.rflags = 0x8D6;
    static_cast<void>(block.execute(wrapState, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0xA5A5A5A500000000ULL},
                "LOCK INC dword wrap result differs");
    expectEqual(wrapState.rflags, std::uint64_t{0x56}, "LOCK INC wrap flags differ or changed CF");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0x100] = 0xFF;
    readOnlyBytes[0x101] = 0xFF;
    readOnlyBytes[0x102] = 0xFF;
    readOnlyBytes[0x103] = 0x7F;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only LOCK INC memory");
    rosa::x86::X86State faultState;
    faultState.rax = target.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "LOCK INC accepted a read-only guest dword");
    expectEqual(readOnlyAddressSpace.readU32(target), std::uint32_t{0x7FFFFFFF},
                "faulted LOCK INC changed read-only memory");
    expectEqual(faultState.rax, target.value, "faulted LOCK INC changed its address base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted LOCK INC changed flags");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FFE};
    constexpr std::array crossPageBytes{std::uint8_t{0xFF}, std::uint8_t{0x7F}};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, crossPageBytes);
    faultState.rax = crossPageTarget.value;
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page LOCK INC did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, 2) ==
               std::vector<std::uint8_t>(crossPageBytes.begin(), crossPageBytes.end()),
           "cross-page LOCK INC partially changed guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "cross-page LOCK INC changed flags");
}

void testLockedIncrementRipRelativeGuestDword() {
    constexpr std::array<std::uint8_t, 8> observedCode{0xF0, 0xFF, 0x05, 0x31,
                                                       0x37, 0xA4, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C712B8ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8436B49F0ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockIncMem,
           "RIP-relative LOCK INC opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative LOCK INC length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && memory.width == 32 && !memory.index &&
               memory.displacement == 0x40A43731,
           "RIP-relative LOCK INC operand differs");
    expectEqual(observedRip.value + decoded[0].length + memory.displacement, target.value,
                "RIP-relative LOCK INC target differs");
    expect(rosa::debug::dumpX86(decoded).find("lock inc dword [rip+0x40a43731]") !=
               std::string::npos,
           "RIP-relative LOCK INC dump differs");

    constexpr rosa::guest::GuestAddress targetPage{target.value &
                                                   ~(rosa::guest::guestPageSize - 1)};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, UINT32_MAX);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    rosa::x86::X86State state;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0},
                "RIP-relative LOCK INC result differs");
    expectEqual(state.rflags, std::uint64_t{0x57}, "RIP-relative LOCK INC flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rflags = 0xBD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "RIP-relative LOCK INC accepted unmapped memory");
    expectEqual(state.rflags, std::uint64_t{0xBD7}, "faulted RIP-relative LOCK INC changed flags");
}

void testLockedIncrementGuestQword() {
    // Observed in libc++ under an Objective-C fixture: LOCK INC qword [rsi+0x8].
    constexpr std::array<std::uint8_t, 6> observedCode{0xF0, 0x48, 0xFF, 0x46, 0x08, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802D8E01AULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockIncMem, "LOCK INC opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "LOCK INC length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rsi && memory.width == 64 &&
               memory.displacement == 8 && !memory.ripRelative,
           "LOCK INC memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("lock inc qword [rsi+0x8]") != std::string::npos,
           "LOCK INC dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("locked_increment_guest_memory.i64") != std::string::npos,
           "LOCK INC did not lower through locked guest-memory IR");

    addressSpace.writeU64(target, 0x7FFFFFFFFFFFFFFFULL);
    rosa::x86::X86State overflowState;
    overflowState.rsi = target.value - 8;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0x8000000000000000ULL},
                "LOCK INC overflow result differs");
    expectEqual(overflowState.rsi, target.value - 8, "LOCK INC changed its address base");
    // ZF clears on the nonzero result; CF is preserved and PF/AF/SF/OF set here.
    expectEqual(overflowState.rflags, std::uint64_t{0x897},
                "LOCK INC overflow flags differ or changed CF");
}

void testLockedDecrementGuestDword() {
    constexpr std::array<std::uint8_t, 4> observedCode{0xF0, 0xFF, 0x08, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C7201FULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockDecMem, "LOCK DEC opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "LOCK DEC length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rax && memory.width == 32 &&
               memory.displacement == 0 && !memory.ripRelative,
           "LOCK DEC memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("lock dec dword [rax]") != std::string::npos,
           "LOCK DEC dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("locked_decrement_guest_memory.i32") != std::string::npos,
           "LOCK DEC did not lower through locked guest-memory IR");

    addressSpace.writeU64(target, 0xDEADBEEF80000000ULL);
    rosa::x86::X86State overflowState;
    overflowState.rax = target.value;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0xDEADBEEF7FFFFFFFULL},
                "LOCK DEC did not perform an exact dword write");
    expectEqual(overflowState.rax, target.value, "LOCK DEC changed its address base");
    expectEqual(overflowState.rflags, std::uint64_t{0x817},
                "LOCK DEC overflow flags differ or changed CF");

    addressSpace.writeU64(target, 0xA5A5A5A500000000ULL);
    rosa::x86::X86State wrapState;
    wrapState.rax = target.value;
    wrapState.rflags = 0x8D6;
    static_cast<void>(block.execute(wrapState, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0xA5A5A5A5FFFFFFFFULL},
                "LOCK DEC dword wrap result differs");
    expectEqual(wrapState.rflags, std::uint64_t{0x96}, "LOCK DEC wrap flags differ or changed CF");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0x100] = 0x00;
    readOnlyBytes[0x101] = 0x00;
    readOnlyBytes[0x102] = 0x00;
    readOnlyBytes[0x103] = 0x80;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only LOCK DEC memory");
    rosa::x86::X86State faultState;
    faultState.rax = target.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "LOCK DEC accepted a read-only guest dword");
    expectEqual(readOnlyAddressSpace.readU32(target), std::uint32_t{0x80000000U},
                "faulted LOCK DEC changed read-only memory");
    expectEqual(faultState.rax, target.value, "faulted LOCK DEC changed its address base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted LOCK DEC changed flags");
}

void testLockedDecrementRipRelativeGuestQword() {
    // Observed in libsystem_c: LOCK DEC qword [rip+disp32].
    constexpr std::array<std::uint8_t, 9> code{0xF0, 0x48, 0xFF, 0x0D, 0x99,
                                              0x4B, 0x9A, 0x40, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802D15C6FULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::LockDecMem,
           "RIP-relative LOCK DEC opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "RIP-relative LOCK DEC length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 64 &&
               memory.displacement == 0x409A4B99,
           "LOCK DEC qword [rip+disp32] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("lock dec qword [rip+0x409a4b99]") !=
               std::string::npos,
           "LOCK DEC qword [rip+disp32] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    constexpr rosa::guest::GuestAddress syntheticRip{0x7FF8ULL};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x8000000000000001ULL);
    const rosa::dbt::Translator translator;
    // Execute at a synthetic RIP whose computed target stays in the page.
    constexpr std::array<std::uint8_t, 9> executableCode{0xF0, 0x48, 0xFF, 0x0D, 0x00,
                                                         0x01, 0x00, 0x00, 0xC3};
    const auto block = translator.translate(executableCode, syntheticRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("locked_decrement_guest_memory.i64") != std::string::npos,
           "LOCK DEC qword did not lower through 64-bit locked guest-memory IR");
    rosa::x86::X86State state;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0x8000000000000000ULL},
                "LOCK DEC qword result differs");
    expectEqual(state.rflags, std::uint64_t{0x87}, "LOCK DEC qword flags differ or changed CF");
}

void testCompareGuestMemoryWith32BitImmediate() {
    constexpr std::array<std::uint8_t, 9> code{
        0x81, 0x7F, 0x04, 0x0C, 0x00, 0x00, 0x01, 0x75, 0x00,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm, "CMP [mem], imm32 opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rdi, "CMP [mem], imm32 base differs");
    expectEqual(memory.displacement, std::int64_t{4}, "CMP [mem], imm32 displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8100}, 0x0100000700000000ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000}, 1);
    rosa::x86::X86State state;
    state.rdi = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdi, std::uint64_t{0x8100}, "CMP [mem], imm32 changed its base");
    expectEqual(state.rflags, std::uint64_t{0x93}, "CMP [mem], imm32 flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rdi = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "CMP immediate from unmapped guest memory did not fail");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed memory-immediate CMP changed flags");
}

void testCompareRipMemoryWith64BitImmediate() {
    // Observed in libobjc under an Objective-C fixture: CMP qword [RIP+disp32], 0x8000.
    constexpr std::array<std::uint8_t, 12> code{0x48, 0x81, 0x3D, 0x53, 0xBF,
                                                0xC7, 0x40, 0x00, 0x80, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802A30F02ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "RIP CMP qword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{11}, "RIP CMP qword length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && !memory.index &&
               memory.displacement == 0x40C7BF53 && memory.width == 64,
           "RIP CMP qword memory operand differs");
    expectEqual(immediate.value, std::uint64_t{0x8000}, "RIP CMP qword immediate differs");
    expectEqual(observedRip.value + decoded[0].length + memory.displacement,
                std::uint64_t{0x7FF8436ACE60ULL}, "RIP CMP qword target differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp qword [rip+0x40c7bf53], 0x8000") !=
               std::string::npos,
           "RIP CMP qword dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x8000);
    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 12> executeCode{0x48, 0x81, 0x3D, 0xF5, 0x70,
                                                       0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0xC3};
    const auto block = translator.translate(executeCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46}, "RIP CMP qword equal flags differ");
}

void testCompareGuestSibMemoryWith32BitImmediate() {
    constexpr std::array<std::uint8_t, 10> code{
        0x41, 0x81, 0x7C, 0x24, 0x10, 0x05, 0x02, 0x00, 0x00, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AE2D78ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "SIB CMP dword [memory], imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "SIB CMP dword [memory], imm32 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R12 && !memory.index && memory.scale == 1 &&
               memory.displacement == 0x10 && memory.width == 32,
           "SIB CMP dword [r12+0x10], imm32 memory operand differs");
    expect(immediate.value == 0x205 && immediate.width == 32,
           "SIB CMP dword [memory], imm32 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp dword [r12+0x10], 0x205") != std::string::npos,
           "SIB CMP dword [memory], imm32 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress base{0x8100};
    constexpr rosa::guest::GuestAddress target{0x8110};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::uint64_t original = 0xDEADBEEF00000205ULL;
    addressSpace.writeU64(target, original);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AE2D78ULL}, 1);
    rosa::x86::X86State state;
    state.r12 = base.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r12, base.value, "SIB CMP dword [memory], imm32 changed its base");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "SIB CMP dword [memory], imm32 equal flags differ");
    expectEqual(addressSpace.readU64(target), original,
                "SIB CMP dword [memory], imm32 changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r12 = base.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "SIB CMP dword immediate accepted unmapped guest memory");
    expectEqual(faultState.r12, base.value, "faulted SIB CMP dword immediate changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted SIB CMP dword immediate changed flags");
}

void testCompareGuestQwordWith32BitImmediate() {
    constexpr std::array<std::uint8_t, 8> code{0x48, 0x81, 0x38, 0x00, 0x40, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF80004E0D8ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "CMP qword [memory], imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "CMP qword [memory], imm32 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rax && memory.displacement == 0 &&
               memory.width == 64,
           "CMP qword [rax], imm32 memory operand differs");
    expect(immediate.value == 0x4000 && immediate.width == 32,
           "CMP qword [rax], imm32 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp qword [rax], 0x4000") != std::string::npos,
           "CMP qword [rax], imm32 dump differs");

    constexpr rosa::guest::GuestAddress target{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF80004E0D8ULL});

    addressSpace.writeU64(target, 0x4000);
    rosa::x86::X86State equalState;
    equalState.rax = target.value;
    equalState.rflags = 0x8D7;
    static_cast<void>(block.execute(equalState, &addressSpace));
    expectEqual(equalState.rax, target.value, "CMP qword [rax], imm32 changed its base");
    expectEqual(equalState.rflags, std::uint64_t{0x46},
                "CMP qword [rax], imm32 equal flags differ");

    addressSpace.writeU64(target, 0x100004000ULL);
    rosa::x86::X86State widthState;
    widthState.rax = target.value;
    widthState.rflags = 0x8D7;
    static_cast<void>(block.execute(widthState, &addressSpace));
    expectEqual(widthState.rflags, std::uint64_t{0x6},
                "CMP qword [rax], imm32 did not read all eight bytes");

    constexpr std::array<std::uint8_t, 8> negativeCode{0x48, 0x81, 0x38, 0xFF,
                                                       0xFF, 0xFF, 0xFF, 0xC3};
    const auto negativeDecoded =
        decoder.decodeBlock(negativeCode, rosa::guest::GuestAddress{0x1000});
    const auto negativeImmediate =
        std::get<rosa::x86::ImmediateOperand>(negativeDecoded[0].operands[1]);
    expectEqual(negativeImmediate.value, UINT64_MAX, "CMP qword imm32 was not sign-extended");
    const auto negativeBlock =
        translator.translate(negativeCode, rosa::guest::GuestAddress{0x1000});
    addressSpace.writeU64(target, 0);
    rosa::x86::X86State negativeState;
    negativeState.rax = target.value;
    negativeState.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(negativeState, &addressSpace));
    expectEqual(negativeState.rflags, std::uint64_t{0x13}, "CMP qword negative imm32 flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = target.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "CMP qword immediate accepted unmapped guest memory");
    expectEqual(faultState.rax, target.value, "faulted CMP qword immediate changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted CMP qword immediate changed flags");
}

void testCompareGuestMemoryWithShortImmediate() {
    constexpr std::array<std::uint8_t, 6> code{0x41, 0x83, 0x7E, 0x04, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "CMP dword [memory], imm8 opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::R14,
           "CMP dword short immediate extended base differs");
    expectEqual(memory.displacement, std::int64_t{4},
                "CMP dword short immediate displacement differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8004}, 0x10);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0x8000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0x8000}, "CMP dword short immediate changed base");
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP dword short immediate flags differ");
}

void testCompareGuestSibMemoryWithShortImmediate() {
    constexpr std::array<std::uint8_t, 10> code{
        0x41, 0x83, 0xBC, 0x24, 0x04, 0x02, 0x00, 0x00, 0x00, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AE2D83ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "SIB CMP dword [memory], imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "SIB CMP dword [memory], imm8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R12 && !memory.index && memory.scale == 1 &&
               memory.displacement == 0x204 && memory.width == 32,
           "SIB CMP dword [r12+0x204], imm8 memory operand differs");
    expect(immediate.value == 0 && immediate.width == 8,
           "SIB CMP dword [memory], imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp dword [r12+0x204], 0x0") != std::string::npos,
           "SIB CMP dword [memory], imm8 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8204};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::uint64_t original = 0xDEADBEEF00000000ULL;
    addressSpace.writeU64(target, original);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AE2D83ULL}, 1);
    rosa::x86::X86State state;
    state.r12 = page.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r12, page.value, "SIB CMP dword [memory], imm8 changed its base");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "SIB CMP dword [memory], imm8 equal flags differ");
    expectEqual(addressSpace.readU64(target), original,
                "SIB CMP dword [memory], imm8 changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r12 = page.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "SIB CMP dword short immediate accepted unmapped memory");
    expectEqual(faultState.r12, page.value,
                "faulted SIB CMP dword short immediate changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted SIB CMP dword short immediate changed flags");
}

void testCompareRipRelativeGuestDwordWithShortImmediate() {
    constexpr std::array<std::uint8_t, 8> observed{0x83, 0x3D, 0x3D, 0x3F, 0x0C, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800004EC8ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "RIP-relative CMP dword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative CMP dword length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 32 &&
               memory.displacement == 0xC3F3D,
           "RIP-relative CMP dword memory operand differs");
    expect(immediate.value == 0 && immediate.width == 8,
           "RIP-relative CMP dword immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp dword [rip+0xc3f3d], 0x0 ; 0x7ff8000c8e0c") !=
               std::string::npos,
           "RIP-relative CMP dword dump differs");

    constexpr std::array<std::uint8_t, 8> code{0x83, 0x3D, 0xF9, 0x0F, 0x00, 0x00, 0x00, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    constexpr rosa::guest::GuestAddress target{0x2000};
    constexpr std::array<std::uint8_t, 8> data{0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(target, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                            data);
    rosa::x86::X86State state;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46}, "RIP-relative CMP dword equal flags differ");

    constexpr std::array<std::uint8_t, 8> negativeCode{0x83, 0x3D, 0xF9, 0x0F,
                                                       0x00, 0x00, 0xFF, 0xC3};
    const auto negativeBlock =
        translator.translate(negativeCode, rosa::guest::GuestAddress{0x1000});
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x13},
                "RIP-relative CMP dword did not sign-extend imm8");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative CMP dword from unmapped memory did not fault");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative CMP dword changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(
            decoder.decodeBlock(std::span<const std::uint8_t>{observed}.first(6), observedRip));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated RIP-relative CMP dword was accepted");
}

void testCompareGuestQwordWithShortImmediate() {
    constexpr std::array<std::uint8_t, 6> code{0x48, 0x83, 0x78, 0x10, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expectEqual(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]).width, std::uint8_t{64},
                "CMP qword short immediate width differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8010}, 0);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0x8000}, "CMP qword short immediate changed base");
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP qword short immediate flags differ");
}

void testCompareGuestWordWithShortImmediate() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x83, 0x7A, 0x14, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "CMP word [memory], imm8 opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rdx && memory.displacement == 0x14 &&
               memory.width == 16,
           "CMP word [rdx+0x14], imm8 memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp word [rdx+0x14]") != std::string::npos,
           "CMP word dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> zero{0, 0};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8114}, zero);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdx, std::uint64_t{0x8100}, "CMP word changed its base");
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP word equal flags differ");

    constexpr std::array<std::uint8_t, 7> observedCode{0x66, 0x41, 0x83, 0x3C, 0x24, 0x08, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C71AECULL};
    constexpr rosa::guest::GuestAddress observedPage{0x7FFFFFE00000ULL};
    constexpr rosa::guest::GuestAddress observedTarget{0x7FFFFFE0001EULL};
    const auto observedDecoded = decoder.decodeBlock(observedCode, observedRip);
    expect(observedDecoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "REX/SIB CMP word opcode differs");
    expectEqual(observedDecoded[0].length, std::uint8_t{6}, "REX/SIB CMP word length differs");
    const auto observedMemory = std::get<rosa::x86::MemoryOperand>(observedDecoded[0].operands[0]);
    expect(observedMemory.base == rosa::x86::Register::R12 && !observedMemory.index &&
               observedMemory.scale == 1 && observedMemory.displacement == 0 &&
               observedMemory.width == 16,
           "CMP word [r12], 8 operands differ");
    expect(rosa::debug::dumpX86(observedDecoded).find("cmp word [r12], 0x8") != std::string::npos,
           "REX/SIB CMP word dump differs");

    rosa::guest::AddressSpace observedAddressSpace;
    observedAddressSpace.mapAnonymous(observedPage, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> observedR12Value{8, 0};
    observedAddressSpace.writeBytes(observedTarget, observedR12Value);
    const auto observedBlock = translator.translate(observedCode, observedRip);
    rosa::x86::X86State observedState;
    observedState.r12 = observedTarget.value;
    observedState.rflags = 0x8D7;
    static_cast<void>(observedBlock.execute(observedState, &observedAddressSpace));
    expectEqual(observedState.r12, observedTarget.value, "CMP word [r12], 8 changed its base");
    expectEqual(observedState.rflags, std::uint64_t{0x46}, "CMP word [r12], 8 equal flags differ");

    constexpr std::array<std::uint8_t, 6> negativeCode{0x66, 0x83, 0x7A, 0x14, 0xFF, 0xC3};
    constexpr std::array<std::uint8_t, 2> minusOne{0xFF, 0xFF};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8114}, minusOne);
    const auto negativeBlock =
        translator.translate(negativeCode, rosa::guest::GuestAddress{0x2000});
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP word imm8 did not sign-extend -1");

    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8114}, zero);
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x13}, "CMP word negative imm8 flags differ");

    constexpr std::array<std::uint8_t, 10> wideImmediateCode{0x66, 0x81, 0xBD, 0x64, 0xFF,
                                                             0xFF, 0xFF, 0x00, 0x90, 0xC3};
    const auto wideImmediateDecoded =
        decoder.decodeBlock(wideImmediateCode, rosa::guest::GuestAddress{0x2800});
    expect(wideImmediateDecoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "CMP word [memory], imm16 opcode differs");
    const auto wideImmediateMemory =
        std::get<rosa::x86::MemoryOperand>(wideImmediateDecoded[0].operands[0]);
    expect(wideImmediateMemory.base == rosa::x86::Register::Rbp &&
               wideImmediateMemory.displacement == -0x9C && wideImmediateMemory.width == 16,
           "CMP word [rbp-0x9c], imm16 memory operand differs");
    expect(rosa::debug::dumpX86(wideImmediateDecoded).find("cmp word [rbp-0x9c], 0x9000") !=
               std::string::npos,
           "CMP word [memory], imm16 dump differs");
    constexpr std::array<std::uint8_t, 2> observedValue{0x00, 0x90};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8064}, observedValue);
    const auto wideImmediateBlock =
        translator.translate(wideImmediateCode, rosa::guest::GuestAddress{0x2800});
    state.rbp = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(wideImmediateBlock.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP word [memory], imm16 equal flags differ");

    constexpr std::array<std::uint8_t, 6> overflowCode{0x66, 0x83, 0x7A, 0x14, 0x01, 0xC3};
    constexpr std::array<std::uint8_t, 2> minimumSigned{0x00, 0x80};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8114}, minimumSigned);
    const auto overflowBlock =
        translator.translate(overflowCode, rosa::guest::GuestAddress{0x3000});
    state.rflags = 0x8D7;
    static_cast<void>(overflowBlock.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x816}, "CMP word signed-overflow flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "CMP word from unmapped guest memory did not fault");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "failed CMP word changed flags");

    // Observed in libsqlite3: CMP word [RBX+R12+0xc], 0 with a REX.X-indexed SIB.
    constexpr std::array<std::uint8_t, 8> indexedCode{0x66, 0x42, 0x83, 0x7C,
                                                      0x23, 0x0C, 0x00, 0xC3};
    const auto indexedDecoded =
        decoder.decodeBlock(indexedCode, rosa::guest::GuestAddress{0x1000E89B5ULL});
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "REX.X CMP word opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{7}, "REX.X CMP word length differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[0]);
    const auto indexedImmediate =
        std::get<rosa::x86::ImmediateOperand>(indexedDecoded[0].operands[1]);
    expect(indexedMemory.base == rosa::x86::Register::Rbx && indexedMemory.index &&
               *indexedMemory.index == rosa::x86::Register::R12 && indexedMemory.scale == 1 &&
               indexedMemory.displacement == 0x0C && indexedMemory.width == 16 &&
               indexedImmediate.value == 0 && indexedImmediate.width == 8,
           "CMP word [rbx+r12+0xc], 0 operands differ");
    expect(rosa::debug::dumpX86(indexedDecoded).find("cmp word [rbx+r12*1+0xc], 0x0") !=
               std::string::npos,
           "REX.X CMP word dump differs");
    const auto indexedBlock =
        translator.translate(indexedCode, rosa::guest::GuestAddress{0x1000E89B5ULL});
    constexpr rosa::guest::GuestAddress indexedTarget{0x820C};
    addressSpace.writeBytes(indexedTarget, zero);
    rosa::x86::X86State indexedState;
    indexedState.rbx = 0x8200;
    indexedState.r12 = 0;
    indexedState.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(indexedState.rflags, std::uint64_t{0x46}, "REX.X CMP word equal flags differ");
    expectEqual(indexedState.rbx, std::uint64_t{0x8200}, "REX.X CMP word changed its base");
    expectEqual(indexedState.r12, std::uint64_t{0}, "REX.X CMP word changed its index");

    // Observed in libobjc: CMP word [rax+rcx+0x8], 0x25ff (opcode 66 81 /7 SIB).
    constexpr std::array<std::uint8_t, 8> sibCode{0x66, 0x81, 0x7C, 0x08,
                                                  0x08, 0xFF, 0x25, 0xC3};
    const auto sibDecoded =
        decoder.decodeBlock(sibCode, rosa::guest::GuestAddress{0x7FF8040AC762ULL});
    expect(sibDecoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "SIB CMP word imm16 opcode differs");
    expectEqual(sibDecoded[0].length, std::uint8_t{7}, "SIB CMP word imm16 length differs");
    const auto sibMemory = std::get<rosa::x86::MemoryOperand>(sibDecoded[0].operands[0]);
    const auto sibImmediate = std::get<rosa::x86::ImmediateOperand>(sibDecoded[0].operands[1]);
    expect(sibMemory.base == rosa::x86::Register::Rax && sibMemory.index &&
               *sibMemory.index == rosa::x86::Register::Rcx && sibMemory.scale == 1 &&
               sibMemory.displacement == 0x08 && sibMemory.width == 16 &&
               sibImmediate.value == 0x25FF && sibImmediate.width == 16,
           "CMP word [rax+rcx+0x8], 0x25ff operands differ");
    expect(rosa::debug::dumpX86(sibDecoded).find("cmp word [rax+rcx*1+0x8], 0x25ff") !=
               std::string::npos,
           "SIB CMP word imm16 dump differs");
    constexpr rosa::guest::GuestAddress sibTarget{0x8208};
    addressSpace.writeBytes(sibTarget, std::array<std::uint8_t, 2>{0xFF, 0x25});
    const auto sibBlock =
        translator.translate(sibCode, rosa::guest::GuestAddress{0x7FF8040AC762ULL});
    rosa::x86::X86State sibState;
    sibState.rax = 0x8200;
    sibState.rcx = 0;
    sibState.rflags = 0x8D7;
    static_cast<void>(sibBlock.execute(sibState, &addressSpace));
    expectEqual(sibState.rflags, std::uint64_t{0x46}, "SIB CMP word imm16 equal flags differ");
    expectEqual(sibState.rax, std::uint64_t{0x8200}, "SIB CMP word imm16 changed its base");
    expectEqual(sibState.rcx, std::uint64_t{0}, "SIB CMP word imm16 changed its index");
}

void testCompare16BitRegisterWithShortImmediate() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x83, 0xFF, 0x0D, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegImm, "CMP r16, imm8 opcode differs");
    const auto reg = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(reg.reg == rosa::x86::Register::Rdi && reg.width == 16, "CMP DI, imm8 register differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp di, 0xd") != std::string::npos,
           "CMP DI, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0xA5A5A5A500000005ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0xA5A5A5A500000005ULL}, "CMP DI changed its register");
    expectEqual(state.rflags, std::uint64_t{0x93}, "CMP DI, positive imm8 flags differ");

    constexpr std::array<std::uint8_t, 5> negativeCode{0x66, 0x83, 0xFF, 0xFF, 0xC3};
    const auto negativeBlock =
        translator.translate(negativeCode, rosa::guest::GuestAddress{0x2000});
    state.rdi = 0x112233445566FFFFULL;
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP DI did not sign-extend negative imm8");
}

void testCompareGuestByteWithImmediate() {
    constexpr std::array<std::uint8_t, 5> code{0x80, 0x7D, 0xD7, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "CMP byte [memory], imm8 opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expectEqual(memory.width, std::uint8_t{8}, "CMP byte memory width differs");
    expectEqual(memory.displacement, std::int64_t{-0x29}, "CMP byte memory displacement differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> zero{0};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x80D7}, zero);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbp = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP byte [memory], imm8 equal flags differ");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0x80D7}, 1).front(),
                std::uint8_t{0}, "CMP byte [memory], imm8 changed memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbp = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "CMP byte from unmapped guest memory did not fail");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "failed CMP byte changed flags");
}

void testCompareIndexedGuestByteWithImmediate() {
    constexpr std::array<std::uint8_t, 6> code{0x42, 0x80, 0x3C, 0x20, 0x3D, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm, "indexed CMP byte opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "indexed CMP byte length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rax && memory.index &&
               *memory.index == rosa::x86::Register::R12 && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 8 && !memory.ripRelative,
           "indexed CMP byte memory operand differs");
    expect(immediate.value == 0x3D && immediate.width == 8, "indexed CMP byte immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp byte [rax+r12*1], 0x3d") != std::string::npos,
           "indexed CMP byte dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8020};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> equalValue{0x3D};
    addressSpace.writeBytes(target, equalValue);

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = page.value;
    state.r12 = 0x20;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, page.value, "indexed CMP byte changed RAX");
    expectEqual(state.r12, std::uint64_t{0x20}, "indexed CMP byte changed R12");
    expectEqual(state.rflags, std::uint64_t{0x46}, "indexed CMP byte equal flags differ");
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0x3D},
                "indexed CMP byte changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = page.value;
    faultState.r12 = 0x20;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed CMP byte from unmapped memory did not fault");
    expectEqual(faultState.rax, page.value, "failed indexed CMP byte changed RAX");
    expectEqual(faultState.r12, std::uint64_t{0x20}, "failed indexed CMP byte changed R12");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed indexed CMP byte changed flags");
}

void testCompareRipRelativeGuestByteWithImmediate() {
    constexpr std::array<std::uint8_t, 8> observed{0x80, 0x3D, 0x94, 0x3F, 0x0C, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800004E75ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "RIP-relative CMP byte opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative CMP byte length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0xC3F94,
           "RIP-relative CMP byte memory operand differs");
    expect(immediate.value == 0 && immediate.width == 8, "RIP-relative CMP byte immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp byte [rip+0xc3f94], 0x0 ; 0x7ff8000c8e10") !=
               std::string::npos,
           "RIP-relative CMP byte dump differs");

    constexpr std::array<std::uint8_t, 8> code{0x80, 0x3D, 0xF9, 0x0F, 0x00, 0x00, 0x00, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    constexpr rosa::guest::GuestAddress target{0x2000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const std::array<std::uint8_t, 1> zero{0};
    addressSpace.writeBytes(target, zero);
    rosa::x86::X86State state;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46}, "RIP-relative CMP byte equal flags differ");
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0},
                "RIP-relative CMP byte changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative CMP byte from unmapped memory did not fault");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative CMP byte changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(
            decoder.decodeBlock(std::span<const std::uint8_t>{observed}.first(6), observedRip));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated RIP-relative CMP byte was not rejected");
}

void testCompare8BitRegisterWithImmediate() {
    constexpr std::array<std::uint8_t, 4> code{0x80, 0xF9, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegImm, "CMP CL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "CMP CL, imm8 length differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rcx && operand.width == 8,
           "CMP CL, imm8 register differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{1}, "CMP CL, imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp cl, 0x1") != std::string::npos,
           "CMP CL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0x1122334455667700ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x1122334455667700ULL}, "CMP CL, imm8 changed RCX");
    expectEqual(state.rflags, std::uint64_t{0x97}, "CMP byte zero, one flags differ");

    state.rcx = 0xFFEEDDCCBBAA5501ULL;
    state.rflags = 0;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFFEEDDCCBBAA5501ULL}, "equal CMP CL, imm8 changed RCX");
    expectEqual(state.rflags, std::uint64_t{0x46}, "equal CMP CL, imm8 flags differ");

    state.rcx = 0x80;
    state.rflags = 0;
    static_cast<void>(block.execute(state));
    expectEqual(state.rflags, std::uint64_t{0x812}, "overflow CMP CL, imm8 flags differ");

    constexpr std::array<std::uint8_t, 4> highByteCode{0x80, 0xFC, 0x01, 0xC3};
    const auto highByteDecoded =
        decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x2000});
    const auto highByteReg =
        std::get<rosa::x86::RegisterOperand>(highByteDecoded[0].operands[0]);
    expect(highByteDecoded[0].opcode == rosa::x86::Opcode::CmpRegImm &&
               highByteReg.reg == rosa::x86::Register::Rax && highByteReg.width == 8 &&
               highByteReg.byteOffset == 1,
           "CMP AH, imm8 did not decode to the high-byte lane");

    constexpr std::array<std::uint8_t, 9> rexBMemoryCode{0x41, 0x80, 0x3D, 0x01, 0x00,
                                                         0x00, 0x00, 0x01, 0xC3};
    const auto rexBMemoryDecoded =
        decoder.decodeBlock(rexBMemoryCode, rosa::guest::GuestAddress{0x3000});
    const auto rexBMemory = std::get<rosa::x86::MemoryOperand>(rexBMemoryDecoded[0].operands[0]);
    expect(rexBMemoryDecoded[0].opcode == rosa::x86::Opcode::CmpMemImm && !rexBMemory.hasBase &&
               rexBMemory.ripRelative && rexBMemory.displacement == 1,
           "REX.B changed opcode-80 RIP-relative addressing");
}

void testCompare32BitRegisterWithImmediate() {
    constexpr std::array<std::uint8_t, 7> code{
        0x81, 0xFA, 0xCF, 0xFA, 0xED, 0xFE, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegImm, "CMP r32, imm32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "CMP r32, imm32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0xFFFFFFFFFEEDFACFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0xFFFFFFFFFEEDFACFULL},
                "CMP r32, imm32 changed its register");
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP r32, imm32 equal flags differ");

    constexpr std::array<std::uint8_t, 8> observed{
        0x49, 0x81, 0xFF, 0x01, 0x10, 0x00, 0x00, 0xC3,
    };
    const auto observedDecoded =
        decoder.decodeBlock(observed, rosa::guest::GuestAddress{0x7FF80004D317ULL});
    expect(observedDecoded[0].opcode == rosa::x86::Opcode::CmpRegImm,
           "CMP r15, imm32 opcode differs");
    expectEqual(observedDecoded[0].length, std::uint8_t{7}, "CMP r15, imm32 length differs");
    const auto observedRegister =
        std::get<rosa::x86::RegisterOperand>(observedDecoded[0].operands[0]);
    const auto observedImmediate =
        std::get<rosa::x86::ImmediateOperand>(observedDecoded[0].operands[1]);
    expect(observedRegister.reg == rosa::x86::Register::R15 && observedRegister.width == 64,
           "CMP r15, imm32 register differs");
    expect(observedImmediate.value == 0x1001 && observedImmediate.width == 32,
           "CMP r15, imm32 immediate differs");
    expect(rosa::debug::dumpX86(observedDecoded).find("cmp r15, 0x1001") != std::string::npos,
           "CMP r15, imm32 dump differs");

    const auto observedBlock =
        translator.translate(observed, rosa::guest::GuestAddress{0x7FF80004D317ULL});
    state.r15 = 0x1001;
    state.rflags = 0x8D7;
    static_cast<void>(observedBlock.execute(state));
    expectEqual(state.r15, std::uint64_t{0x1001}, "CMP r15, imm32 changed its register");
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP r15, imm32 equal flags differ");

    constexpr std::array<std::uint8_t, 8> negative{
        0x49, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3,
    };
    const auto negativeDecoded = decoder.decodeBlock(negative, rosa::guest::GuestAddress{0x2000});
    expectEqual(std::get<rosa::x86::ImmediateOperand>(negativeDecoded[0].operands[1]).value,
                UINT64_MAX, "CMP r64, imm32 did not sign-extend its immediate");
    const auto negativeBlock = translator.translate(negative, rosa::guest::GuestAddress{0x2000});
    state.r15 = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP r64, negative imm32 flags differ");
}

void testCompareAccumulatorImmediate() {
    constexpr std::array<std::uint8_t, 6> code{0x3D, 0x22, 0x00, 0x00, 0x80, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegImm, "CMP EAX, imm32 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "CMP accumulator destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0x80000022}, "CMP accumulator immediate differs");

    constexpr std::array<std::uint8_t, 3> byteCode{0x3C, 0x39, 0xC3};
    const auto byteDecoded =
        decoder.decodeBlock(byteCode, rosa::guest::GuestAddress{0x7FF800059948ULL});
    expect(byteDecoded[0].opcode == rosa::x86::Opcode::CmpRegImm, "CMP AL, imm8 opcode differs");
    expectEqual(byteDecoded[0].length, std::uint8_t{2}, "CMP AL, imm8 length differs");
    const auto byteDestination = std::get<rosa::x86::RegisterOperand>(byteDecoded[0].operands[0]);
    const auto byteImmediate = std::get<rosa::x86::ImmediateOperand>(byteDecoded[0].operands[1]);
    expect(byteDestination.reg == rosa::x86::Register::Rax && byteDestination.width == 8 &&
               byteImmediate.value == 0x39 && byteImmediate.width == 8,
           "CMP AL, imm8 operands differ");
    expect(rosa::debug::dumpX86(byteDecoded).find("cmp al, 0x39") != std::string::npos,
           "CMP AL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xAAAAAAAA80000022ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xAAAAAAAA80000022ULL}, "CMP EAX, imm32 changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP EAX, imm32 equal flags differ");

    const auto byteBlock =
        translator.translate(byteCode, rosa::guest::GuestAddress{0x7FF800059948ULL});
    state.rax = 0xAABBCCDDEEFF0039ULL;
    state.rflags = 0x8D7;
    static_cast<void>(byteBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0xAABBCCDDEEFF0039ULL}, "CMP AL, imm8 changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP AL, imm8 equal flags differ");

    state.rax = 0xAABBCCDDEEFF0000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(byteBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0xAABBCCDDEEFF0000ULL}, "CMP AL, imm8 borrow changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x93}, "CMP AL, imm8 borrow flags differ");

    constexpr std::array<std::uint8_t, 7> observed{0x48, 0x3D, 0x01, 0x00, 0x02, 0x00, 0xC3};
    const auto observedDecoded = decoder.decodeBlock(observed, rosa::guest::GuestAddress{0x2000});
    expect(observedDecoded[0].opcode == rosa::x86::Opcode::CmpRegImm,
           "CMP RAX, imm32 opcode differs");
    expectEqual(observedDecoded[0].length, std::uint8_t{6}, "CMP RAX, imm32 length differs");
    const auto observedDestination =
        std::get<rosa::x86::RegisterOperand>(observedDecoded[0].operands[0]);
    const auto observedImmediate =
        std::get<rosa::x86::ImmediateOperand>(observedDecoded[0].operands[1]);
    expect(observedDestination.reg == rosa::x86::Register::Rax && observedDestination.width == 64,
           "CMP RAX, imm32 destination differs");
    expect(observedImmediate.width == 32 && observedImmediate.value == 0x20001,
           "CMP RAX, imm32 immediate differs");
    expect(rosa::debug::dumpX86(observedDecoded).find("cmp rax, 0x20001") != std::string::npos,
           "CMP RAX, imm32 dump differs");
    const auto observedBlock = translator.translate(observed, rosa::guest::GuestAddress{0x2000});
    state.rax = 0x409F;
    state.rflags = 0x8D7;
    static_cast<void>(observedBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0x409F}, "CMP RAX, imm32 changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x83}, "CMP RAX, imm32 flags differ");

    constexpr std::array<std::uint8_t, 7> negative{0x48, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3};
    const auto negativeDecoded = decoder.decodeBlock(negative, rosa::guest::GuestAddress{0x3000});
    expectEqual(std::get<rosa::x86::ImmediateOperand>(negativeDecoded[0].operands[1]).value,
                UINT64_MAX, "CMP RAX, imm32 was not sign-extended");
    const auto negativeBlock = translator.translate(negative, rosa::guest::GuestAddress{0x3000});
    state.rax = 0;
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0}, "CMP RAX, negative imm32 changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x13}, "CMP RAX, negative imm32 flags differ");
}

void testCompare32BitRegisterWithShortImmediate() {
    constexpr std::array<std::uint8_t, 7> code{
        0x83, 0xFA, 0x0D, // cmp edx, 13
        0x83, 0xF9, 0xFF, // cmp ecx, -1
        0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegImm,
           "CMP r32, imm8 positive opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "CMP r32, imm8 positive width differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{13}, "CMP r32, imm8 positive immediate differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[1].operands[1]).value, UINT64_MAX,
                "CMP r32, imm8 negative sign extension differs");

    const rosa::dbt::Translator translator;
    const auto first = translator.translate(code, rosa::guest::GuestAddress{0x1000}, 1);
    rosa::x86::X86State positiveState;
    positiveState.rdx = 0xA5A5A5A500000007ULL;
    positiveState.rflags = 0x8D7;
    static_cast<void>(first.execute(positiveState));
    expectEqual(positiveState.rdx, std::uint64_t{0xA5A5A5A500000007ULL},
                "CMP r32, positive imm8 changed its register");
    expectEqual(positiveState.rflags, std::uint64_t{0x97}, "CMP r32, positive imm8 flags differ");

    const auto second = translator.translate(std::span<const std::uint8_t>{code}.subspan(3),
                                             rosa::guest::GuestAddress{0x1003}, 1);
    rosa::x86::X86State negativeState;
    negativeState.rcx = 0x12345678FFFFFFFFULL;
    negativeState.rflags = 0x8D7;
    static_cast<void>(second.execute(negativeState));
    expectEqual(negativeState.rcx, std::uint64_t{0x12345678FFFFFFFFULL},
                "CMP r32, negative imm8 changed its register");
    expectEqual(negativeState.rflags, std::uint64_t{0x46}, "CMP r32, negative imm8 flags differ");
}

void testCompare8BitRegisters() {
    constexpr std::array<std::uint8_t, 4> code{0x44, 0x38, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegReg, "CMP r8, r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "CMP r8, r8 length differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto rhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(lhs.reg == rosa::x86::Register::Rcx && lhs.width == 8 &&
               rhs.reg == rosa::x86::Register::R8 && rhs.width == 8,
           "CMP CL, R8B operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmp cl, r8b") != std::string::npos,
           "CMP CL, R8B dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State borrowState;
    borrowState.rcx = 0x1122334455667700ULL;
    borrowState.r8 = 0x887766554433221FULL;
    borrowState.rflags = 0x8D7;
    static_cast<void>(block.execute(borrowState));
    expectEqual(borrowState.rcx, std::uint64_t{0x1122334455667700ULL}, "CMP r8 changed its lhs");
    expectEqual(borrowState.r8, std::uint64_t{0x887766554433221FULL}, "CMP r8 changed its rhs");
    expectEqual(borrowState.rflags, std::uint64_t{0x97}, "CMP r8 borrow flags differ");

    rosa::x86::X86State overflowState;
    overflowState.rcx = 0x1122334455667780ULL;
    overflowState.r8 = 0x8877665544332201ULL;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.rcx, std::uint64_t{0x1122334455667780ULL},
                "overflowing CMP r8 changed its lhs");
    expectEqual(overflowState.r8, std::uint64_t{0x8877665544332201ULL},
                "overflowing CMP r8 changed its rhs");
    expectEqual(overflowState.rflags, std::uint64_t{0x812}, "CMP r8 overflow flags differ");

    constexpr std::array<std::uint8_t, 2> legacyHighByte{0x38, 0xE0};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(legacyHighByte, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "CMP silently treated legacy AH as a representable low byte");
}

void testCompare64BitRegisters() {
    constexpr std::array<std::uint8_t, 4> code{0x4D, 0x39, 0xEE, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegReg, "CMP r64, r64 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::R14,
           "CMP r64, r64 extended lhs differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::Register::R13,
           "CMP r64, r64 extended rhs differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 5;
    state.r13 = 7;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{5}, "CMP r64, r64 changed lhs");
    expectEqual(state.r13, std::uint64_t{7}, "CMP r64, r64 changed rhs");
    expectEqual(state.rflags, std::uint64_t{0x93}, "CMP r64, r64 flags differ");
}

void testCompare32BitRegisters() {
    constexpr std::array<std::uint8_t, 4> code{0x41, 0x39, 0xCF, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegReg, "CMP r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "CMP r32, r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r15 = 0xAAAAAAAA00000013ULL;
    state.rcx = 0xBBBBBBBB00000013ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r15, std::uint64_t{0xAAAAAAAA00000013ULL}, "CMP r32, r32 changed lhs");
    expectEqual(state.rcx, std::uint64_t{0xBBBBBBBB00000013ULL}, "CMP r32, r32 changed rhs");
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP r32, r32 flags differ");

    constexpr std::array<std::uint8_t, 3> legacyCode{0x39, 0xF2, 0xC3};
    const auto legacyDecoded = decoder.decodeBlock(legacyCode, rosa::guest::GuestAddress{0x2000});
    expect(legacyDecoded[0].opcode == rosa::x86::Opcode::CmpRegReg,
           "legacy CMP r32, r32 opcode differs");
    const auto legacyLhs = std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[0]);
    const auto legacyRhs = std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[1]);
    expect(legacyLhs.reg == rosa::x86::Register::Rdx && legacyLhs.width == 32 &&
               legacyRhs.reg == rosa::x86::Register::Rsi && legacyRhs.width == 32,
           "legacy CMP EDX, ESI operands differ");
    const auto legacyBlock = translator.translate(legacyCode, rosa::guest::GuestAddress{0x2000});
    state.rdx = 0xAAAAAAAA80000000ULL;
    state.rsi = 0xBBBBBBBB00000001ULL;
    state.rflags = 0x8D7;
    static_cast<void>(legacyBlock.execute(state));
    expectEqual(state.rdx, std::uint64_t{0xAAAAAAAA80000000ULL}, "legacy CMP changed EDX");
    expectEqual(state.rsi, std::uint64_t{0xBBBBBBBB00000001ULL}, "legacy CMP changed ESI");
    expectEqual(state.rflags, std::uint64_t{0x816}, "legacy CMP EDX, ESI flags differ");
}

void testCompare16BitRegisters() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x44, 0x39, 0xF9, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C6CCDCULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegReg, "CMP r16, r16 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "CMP r16, r16 length differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto rhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(lhs.reg == rosa::x86::Register::Rcx && lhs.width == 16 &&
               rhs.reg == rosa::x86::Register::R15 && rhs.width == 16,
           "CMP CX, R15W operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmp cx, r15w") != std::string::npos,
           "CMP CX, R15W dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    rosa::x86::X86State state;
    state.rcx = 0x112233445566003DULL;
    state.r15 = 0x8877665544330001ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x112233445566003DULL}, "CMP r16 changed its lhs");
    expectEqual(state.r15, std::uint64_t{0x8877665544330001ULL}, "CMP r16 changed its rhs");
    expectEqual(state.rflags, std::uint64_t{0x6}, "CMP r16 flags differ");
}

void testLockAddDwordMemoryRegister() {
    // Observed in libdispatch under an AppKit fixture: LOCK ADD [RBX+8], ECX.
    constexpr std::array<std::uint8_t, 5> code{0xF0, 0x01, 0x4B, 0x08, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802CD265BULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockAddMemReg,
           "LOCK ADD dword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "LOCK ADD dword length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.width == 32 &&
               memory.displacement == 8,
           "LOCK ADD [RBX+8] memory operand differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 32,
           "LOCK ADD source differs");
    expect(rosa::debug::dumpX86(decoded).find("lock add dword [rbx+0x8], ecx") !=
               std::string::npos,
           "LOCK ADD dword dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr rosa::guest::GuestAddress target{0x8100};
    addressSpace.writeU32(target, 100);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rbx = target.value - 8;
    state.rcx = 7;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{107},
                "LOCK ADD dword did not add");
}

void testLockIncSibMemory() {
    // Observed in libdispatch under an AppKit fixture: LOCK INC [R12+0x58].
    constexpr std::array<std::uint8_t, 7> code{0xF0, 0x41, 0xFF, 0x44, 0x24, 0x58, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802CD22AAULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockIncMem,
           "SIB LOCK INC opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "SIB LOCK INC length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::R12 && !memory.index &&
               memory.width == 32 && memory.displacement == 0x58,
           "SIB LOCK INC memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("lock inc dword [r12+0x58]") !=
               std::string::npos,
           "SIB LOCK INC dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr rosa::guest::GuestAddress target{0x8100};
    addressSpace.writeU32(target, 41);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.r12 = target.value - 0x58;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{42},
                "SIB LOCK INC did not increment");
}

void testLockBtsDwordMemoryImmediate() {
    // Observed in libdispatch under an AppKit fixture: LOCK BTS [RBX+0x50], 28.
    constexpr std::array<std::uint8_t, 7> code{0xF0, 0x0F, 0xBA, 0x6B, 0x50, 0x1C, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802CD36A1ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockBtsMemImm,
           "LOCK BTS opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "LOCK BTS length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto bitIndex = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.width == 32 &&
               memory.displacement == 0x50,
           "LOCK BTS memory operand differs");
    expectEqual(bitIndex.value, std::uint64_t{28}, "LOCK BTS bit index differs");
    expect(rosa::debug::dumpX86(decoded).find("lock bts dword [rbx+0x50], 0x1c") !=
               std::string::npos,
           "LOCK BTS dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr rosa::guest::GuestAddress target{0x8100};
    addressSpace.writeU32(target, 0);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("locked_bit_set_guest_memory.i32") != std::string::npos,
           "LOCK BTS did not lower through locked bit-set IR");
    rosa::x86::X86State state;
    state.rbx = target.value - 0x50;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    // Bit 28 was clear: CF stays clear and the bit is set.
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x10000000U},
                "LOCK BTS did not set the bit");
    expect((state.rflags & 0x1U) == 0, "LOCK BTS set CF for a clear bit");

    addressSpace.writeU32(target, 0xFFFFFFFFU);
    rosa::x86::X86State setState;
    setState.rbx = target.value - 0x50;
    setState.rflags = 0xAD6;
    static_cast<void>(block.execute(setState, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0xFFFFFFFFU},
                "LOCK BTS changed a set bit");
    expect((setState.rflags & 0x1U) != 0, "LOCK BTS missed CF for a set bit");
}

void testCmpxchgByteMemoryRegister() {
    // Observed in libdispatch under an AppKit fixture: LOCK CMPXCHG [RCX], DL.
    constexpr std::array<std::uint8_t, 5> code{0xF0, 0x0F, 0xB0, 0x11, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802CC710BULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpxchgMemReg,
           "byte CMPXCHG opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "byte CMPXCHG length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rcx && memory.width == 8 &&
               memory.displacement == 0,
           "byte CMPXCHG memory operand differs");
    expect(source.reg == rosa::x86::Register::Rdx && source.width == 8 &&
               source.byteOffset == 0,
           "byte CMPXCHG source differs");
    expect(rosa::debug::dumpX86(decoded).find("lock cmpxchg byte [rcx], dl") !=
               std::string::npos,
           "byte CMPXCHG dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr rosa::guest::GuestAddress target{0x8100};
    constexpr std::array<std::uint8_t, 1> initial{0x42};
    addressSpace.writeBytes(target, initial);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);

    // Equal path: memory takes DL, ZF set, AL unchanged.
    rosa::x86::X86State equalState;
    equalState.rcx = target.value;
    equalState.rdx = 0x99;
    equalState.rax = 0xFFFFFFFFFF000042ULL;
    equalState.rflags = 0xAD7;
    static_cast<void>(block.execute(equalState, &addressSpace));
    expectEqual(addressSpace.readU8(target), std::uint8_t{0x99},
                "byte CMPXCHG equal path did not store");
    expectEqual(equalState.rax, std::uint64_t{0xFFFFFFFFFF000042ULL},
                "byte CMPXCHG equal path changed AL");
    expect((equalState.rflags & 0x40U) != 0, "byte CMPXCHG equal path missed ZF");

    // Unequal path: AL takes memory, upper RAX preserved, ZF clear.
    addressSpace.writeBytes(target, initial);
    rosa::x86::X86State unequalState;
    unequalState.rcx = target.value;
    unequalState.rdx = 0x99;
    unequalState.rax = 0xFFFFFFFFFF000000ULL;
    unequalState.rflags = 0xAD7;
    static_cast<void>(block.execute(unequalState, &addressSpace));
    expectEqual(addressSpace.readU8(target), std::uint8_t{0x42},
                "byte CMPXCHG unequal path stored");
    expectEqual(unequalState.rax, std::uint64_t{0xFFFFFFFFFF000042ULL},
                "byte CMPXCHG unequal path clobbered upper RAX");
    expect((unequalState.rflags & 0x40U) == 0, "byte CMPXCHG unequal path set ZF");
}

void testLockOrByteMemoryImmediate() {
    // Observed in CoreFoundation under an AppKit fixture:
    // LOCK OR byte [RIP+0x407DEFE4], 0x02.
    constexpr std::array<std::uint8_t, 9> code{0xF0, 0x80, 0x0D, 0xE4,
                                               0xEF, 0x7D, 0x40, 0x02, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802EE39FEULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockOrMemImm,
           "LOCK OR byte opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "LOCK OR byte length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && memory.width == 8 &&
               memory.displacement == 0x407DEFE4,
           "LOCK OR byte RIP memory operand differs");
    expectEqual(immediate.value, std::uint64_t{2}, "LOCK OR byte immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("lock or byte [rip+0x407defe4], 0x2") !=
               std::string::npos,
           "LOCK OR byte dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr rosa::guest::GuestAddress target{0x8100};
    constexpr std::array<std::uint8_t, 1> initial{0xF0};
    addressSpace.writeBytes(target, initial);
    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 6> executeCode{0xF0, 0x80, 0x49, 0x08, 0x02, 0xC3};
    const auto block = translator.translate(executeCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = target.value - 8;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU8(target), std::uint8_t{0xF2},
                "LOCK OR byte did not set the bits");

    // The RIP-relative form addresses RIP+length+displacement, not the
    // placeholder base register.
    constexpr std::array<std::uint8_t, 9> ripCode{0xF0, 0x80, 0x0D, 0xF8,
                                                  0x70, 0x00, 0x00, 0x02, 0xC3};
    const auto ripBlock =
        translator.translate(ripCode, rosa::guest::GuestAddress{0x1000});
    constexpr std::array<std::uint8_t, 1> ripInitial{0xF0};
    addressSpace.writeBytes(target, ripInitial);
    rosa::x86::X86State ripState;
    ripState.rax = UINT64_C(0xDEADBEEF);
    ripState.rflags = 0xAD7;
    static_cast<void>(ripBlock.execute(ripState, &addressSpace));
    expectEqual(addressSpace.readU8(target), std::uint8_t{0xF2},
                "RIP-relative LOCK OR byte missed its target");
}

void testLockOrQwordMemoryImmediate() {
    // Observed in Foundation under an AppKit fixture: LOCK OR [RBX+8], 0x08.
    constexpr std::array<std::uint8_t, 7> code{0xF0, 0x48, 0x83, 0x4B, 0x08, 0x08, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8040AD459ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockOrMemImm,
           "LOCK OR qword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "LOCK OR qword length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.width == 64 &&
               memory.displacement == 8,
           "LOCK OR [RBX+8] memory operand differs");
    expectEqual(immediate.value, std::uint64_t{8}, "LOCK OR immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("lock or qword [rbx+0x8], 0x8") !=
               std::string::npos,
           "LOCK OR qword dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8100}, 0xF0);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rbx = 0x80F8;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8100}),
                std::uint64_t{0xF8}, "LOCK OR qword did not set the bits");
}

void testLockOrQwordMemoryRegister() {
    // Observed in Foundation under an AppKit fixture: LOCK OR [RBX+8], RCX.
    constexpr std::array<std::uint8_t, 6> code{0xF0, 0x48, 0x09, 0x4B, 0x08, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8040AD32FULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockOrMemReg,
           "LOCK OR opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "LOCK OR length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.width == 64 &&
               memory.displacement == 8,
           "LOCK OR [RBX+8] memory operand differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 64,
           "LOCK OR source differs");
    expect(rosa::debug::dumpX86(decoded).find("lock or qword [rbx+0x8], rcx") !=
               std::string::npos,
           "LOCK OR dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8100}, 0x0F0F0F0F0F0F0F0FULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rbx = 0x80F8;
    state.rcx = 0xF0F0F0F0F0F0F0F0ULL;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8100}),
                UINT64_MAX, "LOCK OR did not set the bits");
    expectEqual(state.rcx, std::uint64_t{0xF0F0F0F0F0F0F0F0ULL},
                "LOCK OR changed its source");
}

void testLockXaddWordMemory() {
    // Observed in libsystem_trace under an AppKit fixture:
    // LOCK XADD word [RIP+disp32], AX (66 F0 0F C1 /r).
    constexpr std::array<std::uint8_t, 6> code{0x66, 0xF0, 0x0F, 0xC1, 0x01, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802B83A40ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockXaddMemReg,
           "word LOCK XADD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "word LOCK XADD length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rcx && memory.width == 16 &&
               memory.displacement == 0,
           "word LOCK XADD memory operand differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 16,
           "word LOCK XADD source differs");
    expect(rosa::debug::dumpX86(decoded).find("lock xadd word [rcx], ax") !=
               std::string::npos,
           "word LOCK XADD dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> initialWord{0xE8, 0x03};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8100}, initialWord);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rcx = 0x8100;
    state.rax = 0xFFFF000000000007ULL;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    // AX takes the old contents; memory gains the sum; upper RAX is preserved.
    expectEqual(state.rax, std::uint64_t{0xFFFF0000000003E8ULL},
                "word LOCK XADD did not exchange AX");
    expectEqual(addressSpace.readU16(rosa::guest::GuestAddress{0x8100}),
                std::uint16_t{1007}, "word LOCK XADD did not add");
}

void testLockXaddIndexedMemory() {
    // Observed in libsystem_trace under an AppKit fixture:
    // LOCK XADD dword [R15+RAX], ECX.
    constexpr std::array<std::uint8_t, 7> code{0xF0, 0x41, 0x0F, 0xC1, 0x0C, 0x07, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802B8655EULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockXaddMemReg,
           "indexed LOCK XADD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "indexed LOCK XADD length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R15 && memory.index &&
               *memory.index == rosa::x86::Register::Rax && memory.scale == 1 &&
               memory.width == 32 && memory.displacement == 0,
           "indexed LOCK XADD memory operand differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 32,
           "indexed LOCK XADD source differs");
    expect(rosa::debug::dumpX86(decoded).find("lock xadd dword [r15+rax], ecx") !=
               std::string::npos,
           "indexed LOCK XADD dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(rosa::guest::GuestAddress{0x8100}, 100);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.r15 = 0x80F0;
    state.rax = 0x10;
    state.rcx = 7;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    // ECX takes the old contents; memory gains the sum.
    expectEqual(state.rcx, std::uint32_t{100}, "indexed LOCK XADD did not load the old value");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{0x8100}), std::uint32_t{107},
                "indexed LOCK XADD did not add");
}

void testLockAndDwordMemoryImmediate() {
    // Observed in libsystem_malloc under an AppKit fixture:
    // LOCK AND dword [RCX], 0x7FFFFFFF.
    constexpr std::array<std::uint8_t, 8> code{0xF0, 0x81, 0x21, 0xFF,
                                               0xFF, 0xFF, 0x7F, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C68442ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::LockAndMemImm,
           "LOCK AND opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "LOCK AND length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rcx && memory.width == 32 &&
               memory.displacement == 0,
           "LOCK AND [RCX] memory operand differs");
    expectEqual(immediate.value, std::uint64_t{0x7FFFFFFFULL},
                "LOCK AND immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("lock and dword [rcx], 0x7fffffff") !=
               std::string::npos,
           "LOCK AND dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(rosa::guest::GuestAddress{0x8100}, 0xFFFFFFFFU);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rcx = 0x8100;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{0x8100}),
                std::uint32_t{0x7FFFFFFFU}, "LOCK AND did not mask the dword");
    expect((state.rflags & 0x80U) == 0, "LOCK AND set SF for a positive result");
    expect((state.rflags & 0x40U) == 0, "LOCK AND set ZF for a nonzero result");
}

} // namespace

std::span<const TestCase> compareAndAtomicTests() {
    static const TestCase cases[]{
        {"LOCK ADD dword memory register", testLockAddDwordMemoryRegister},
        {"LOCK INC SIB memory", testLockIncSibMemory},
        {"LOCK BTS dword memory immediate", testLockBtsDwordMemoryImmediate},
        {"LOCK CMPXCHG byte memory register", testCmpxchgByteMemoryRegister},
        {"LOCK OR byte memory immediate", testLockOrByteMemoryImmediate},
        {"LOCK OR qword memory immediate", testLockOrQwordMemoryImmediate},
        {"LOCK OR qword memory register", testLockOrQwordMemoryRegister},
        {"LOCK XADD word memory", testLockXaddWordMemory},
        {"LOCK XADD indexed memory", testLockXaddIndexedMemory},
        {"LOCK AND dword memory immediate", testLockAndDwordMemoryImmediate},
        {"CMP 32-bit register with guest memory", testCompare32BitRegisterWithGuestMemory},
        {"CMP 32-bit register with GS-absolute guest memory", testCompare32BitRegisterWithGsAbsoluteMemory},
        {"TEST byte with GS-absolute guest memory", testTestByteGsAbsoluteMemory},
        {"AND/CMP qword with GS-absolute guest memory, imm8", testGsAbsoluteGroupOneImmediates},
        {"CMP byte register with scaled guest memory", testCompareByteRegisterWithScaledGuestMemory},
        {"legacy CMP 32-bit register with guest memory", testLegacyCompare32BitRegisterWithGuestMemory},
        {"CMP 64-bit register with guest memory", testCompare64BitRegisterWithGuestMemory},
        {"CMP 64-bit register with RIP-relative guest memory", testCompare64BitRegisterWithRipRelativeGuestMemory},
        {"CMP word register with guest memory", testCompareWordRegisterWithGuestMemory},
        {"CMP guest word with extended register", testCompareGuestWordWithExtendedRegister},
        {"CMP guest memory with 64-bit register", testCompareGuestMemoryWith64BitRegister},
        {"CMP guest byte with register", testCompareGuestByteWithRegister},
        {"CMP RIP-relative guest byte with register", testCompareRipRelativeGuestByteWithRegister},
        {"LOCK CMPXCHG guest dword", testLockedCompareExchangeGuestDword},
        {"LOCK CMPXCHG guest qword", testLockedCompareExchangeGuestQword},
        {"LOCK CMPXCHG16B guest pair", testLockedCompareExchangeGuestPair},
        {"LOCK CMPXCHG16B RIP-relative pair", testLockedCompareExchangeGuestPairRipRelative},
        {"XCHG guest dword with register", testExchangeGuestDwordWithRegister},
        {"XCHG guest qword with register", testExchangeGuestQwordWithRegister},
        {"XCHG guest qword with index", testExchangeGuestQwordWithIndex},
        {"XCHG guest byte with register", testExchangeGuestByteWithRegister},
        {"LOCK OR guest dword immediate", testLockedOrGuestDwordImmediate},
        {"LOCK OR guest word immediate", testLockedOrGuestWordImmediate},
        {"LOCK AND guest word immediate", testLockedAndGuestWordImmediate},
        {"LOCK ADD guest qword register", testLockedAddGuestQwordRegister},
        {"LOCK XADD guest dword register", testLockedExchangeAddGuestDwordRegister},
        {"LOCK XADD guest qword register", testLockedExchangeAddGuestQwordRegister},
        {"LOCK XADD RIP-relative guest qword", testLockedExchangeAddRipRelativeGuestQword},
        {"LOCK INC guest dword", testLockedIncrementGuestDword},
        {"LOCK INC RIP-relative guest dword", testLockedIncrementRipRelativeGuestDword},
        {"LOCK DEC guest dword", testLockedDecrementGuestDword},
        {"LOCK INC guest qword", testLockedIncrementGuestQword},
        {"LOCK DEC RIP-relative guest qword", testLockedDecrementRipRelativeGuestQword},
        {"CMP guest memory with 32-bit immediate", testCompareGuestMemoryWith32BitImmediate},
        {"CMP RIP memory with 64-bit immediate", testCompareRipMemoryWith64BitImmediate},
        {"CMP SIB guest memory with 32-bit immediate", testCompareGuestSibMemoryWith32BitImmediate},
        {"CMP guest qword with 32-bit immediate", testCompareGuestQwordWith32BitImmediate},
        {"CMP guest memory with short immediate", testCompareGuestMemoryWithShortImmediate},
        {"CMP SIB guest memory with short immediate", testCompareGuestSibMemoryWithShortImmediate},
        {"CMP RIP-relative guest dword with short immediate", testCompareRipRelativeGuestDwordWithShortImmediate},
        {"CMP guest qword with short immediate", testCompareGuestQwordWithShortImmediate},
        {"CMP guest word with short immediate", testCompareGuestWordWithShortImmediate},
        {"CMP 16-bit register with short immediate", testCompare16BitRegisterWithShortImmediate},
        {"CMP guest byte with immediate", testCompareGuestByteWithImmediate},
        {"CMP indexed guest byte with immediate", testCompareIndexedGuestByteWithImmediate},
        {"CMP RIP-relative guest byte with immediate", testCompareRipRelativeGuestByteWithImmediate},
        {"CMP 8-bit register with immediate", testCompare8BitRegisterWithImmediate},
        {"CMP 32-bit register with immediate", testCompare32BitRegisterWithImmediate},
        {"CMP accumulator immediate", testCompareAccumulatorImmediate},
        {"CMP 32-bit register with short immediate", testCompare32BitRegisterWithShortImmediate},
        {"CMP 8-bit registers", testCompare8BitRegisters},
        {"CMP 16-bit registers", testCompare16BitRegisters},
        {"CMP 64-bit registers", testCompare64BitRegisters},
        {"CMP 32-bit registers", testCompare32BitRegisters},
    };
    return cases;
}

} // namespace rosa::tests
