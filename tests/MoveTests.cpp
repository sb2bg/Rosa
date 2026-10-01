#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testMovRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 12> code{
        0x48, 0x89, 0xBD, 0x58, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x4D, 0xC0, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "MOV [base+disp32], r64 opcode differs");
    const auto firstMemory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(firstMemory.base == rosa::x86::Register::Rbp, "MOV [base+disp32], r64 base differs");
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
    const auto secondStore =
        translator.translate(std::span(code).subspan(7), rosa::guest::GuestAddress{0x1007}, 1);
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
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV register to guest memory changed flags");

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
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "MOV to read-only guest memory did not fail");
    expectEqual(faultState.rbp, std::uint64_t{0x8800},
                "failed guest-memory MOV changed the base register");
    expectEqual(faultState.rdi, state.rdi, "failed guest-memory MOV changed the source register");

    // Observed in libsqlite3: ADD byte [rcx+0x2], al (opcode 00).
    constexpr std::array<std::uint8_t, 4> byteCode{0x00, 0x41, 0x02, 0xC3};
    const auto byteDecoded =
        decoder.decodeBlock(byteCode, rosa::guest::GuestAddress{0x1000F2382ULL});
    expect(byteDecoded[0].opcode == rosa::x86::Opcode::AddMemReg,
           "ADD byte [memory], r8 opcode differs");
    expectEqual(byteDecoded[0].length, std::uint8_t{3}, "ADD byte [memory], r8 length differs");
    const auto byteMemory = std::get<rosa::x86::MemoryOperand>(byteDecoded[0].operands[0]);
    const auto byteSource = std::get<rosa::x86::RegisterOperand>(byteDecoded[0].operands[1]);
    expect(byteMemory.base == rosa::x86::Register::Rcx && byteMemory.displacement == 2 &&
               byteMemory.width == 8 && byteSource.reg == rosa::x86::Register::Rax &&
               byteSource.width == 8,
           "ADD byte [rcx+0x2], al operands differ");
    expect(rosa::debug::dumpX86(byteDecoded).find("add byte [rcx+0x2], al") != std::string::npos,
           "ADD byte [memory], r8 dump differs");
    constexpr rosa::guest::GuestAddress byteTarget{0x8202};
    addressSpace.writeBytes(byteTarget, std::array<std::uint8_t, 1>{0xFF});
    const auto byteBlock =
        translator.translate(byteCode, rosa::guest::GuestAddress{0x1000F2382ULL});
    rosa::x86::X86State byteState;
    byteState.rcx = 0x8200;
    byteState.rax = 0xAABBCCDD00000001ULL;
    byteState.rflags = 0x2;
    static_cast<void>(byteBlock.execute(byteState, &addressSpace));
    expectEqual(addressSpace.readBytes(byteTarget, 1).front(), std::uint8_t{0},
                "ADD byte [memory], r8 result differs");
    expectEqual(byteState.rcx, std::uint64_t{0x8200}, "ADD byte changed its base");
    expectEqual(byteState.rax, std::uint64_t{0xAABBCCDD00000001ULL},
                "ADD byte changed its source");
    expectEqual(byteState.rflags, std::uint64_t{0x57}, "ADD byte carry/zero flags differ");
}

void testMovHighByteRegisterToGuestMemory() {
    // Observed in libsqlite3: MOV [RSI+RDI+0x5], AH without a REX prefix.
    constexpr std::array<std::uint8_t, 5> code{0x88, 0x64, 0x3E, 0x05, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000ABB15ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "MOV [memory], high-byte-register opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "MOV [memory], AH length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsi && memory.index &&
               *memory.index == rosa::x86::Register::Rdi && memory.scale == 1 &&
               memory.displacement == 5 && memory.width == 8,
           "MOV [rsi+rdi+0x5], AH memory operand differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 8 &&
               source.byteOffset == 1,
           "MOV [memory], AH source differs");
    expect(rosa::debug::dumpX86(decoded).find("mov [rsi+rdi*1+0x5], ah") != std::string::npos,
           "MOV [memory], AH dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8105};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000ABB15ULL});
    rosa::x86::X86State state;
    state.rsi = 0x8100;
    state.rdi = 0;
    state.rax = 0x112233445566FF00ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0xFF},
                "MOV [memory], AH stored the wrong byte");
    expectEqual(state.rax, std::uint64_t{0x112233445566FF00ULL},
                "MOV [memory], AH changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV [memory], AH changed flags");
}

void testMovRegisterToRipRelativeGuestMemory() {
    constexpr std::array<std::uint8_t, 8> observed{0x4C, 0x89, 0x3D, 0x10, 0x33, 0x09, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800011FF9ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "RIP-relative MOV store opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative MOV store length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.displacement == 0x93310 &&
               memory.width == 64,
           "RIP-relative MOV store memory operand differs");
    expect(source.reg == rosa::x86::Register::R15 && source.width == 64,
           "RIP-relative MOV store source differs");
    expect(rosa::debug::dumpX86(decoded).find("mov [rip+0x93310], r15 ; 0x7ff8000a5310") !=
               std::string::npos,
           "RIP-relative MOV store dump differs");

    constexpr std::array<std::uint8_t, 8> code{0x4C, 0x89, 0x3D, 0xF9, 0x0F, 0x00, 0x00, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    constexpr rosa::guest::GuestAddress target{0x2000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.r15 = 0x0123456789ABCDEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), state.r15,
                "RIP-relative MOV stored at the wrong guest address");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative MOV changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    rosa::x86::X86State faultState;
    faultState.r15 = UINT64_MAX;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOV to read-only guest memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(target), std::uint64_t{0},
                "failed RIP-relative MOV changed guest memory");
    expectEqual(faultState.r15, UINT64_MAX, "failed RIP-relative MOV changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed RIP-relative MOV changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(
            decoder.decodeBlock(std::span<const std::uint8_t>{observed}.first(6), observedRip));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated RIP-relative MOV was not rejected");
}

void testMovRipRelativeGuestDwordToRegister() {
    constexpr std::array<std::uint8_t, 7> observed{0x8B, 0x0D, 0x66, 0x3F, 0x0C, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800004E9CULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "RIP-relative MOV load opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "RIP-relative MOV load length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32,
           "RIP-relative MOV load destination differs");
    expect(memory.ripRelative && !memory.hasBase && memory.displacement == 0xC3F66 &&
               memory.width == 32,
           "RIP-relative MOV load memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("mov ecx, [rip+0xc3f66] ; 0x7ff8000c8e08") !=
               std::string::npos,
           "RIP-relative MOV load dump differs");

    constexpr std::array<std::uint8_t, 7> code{0x8B, 0x0D, 0xFA, 0x0F, 0x00, 0x00, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    constexpr rosa::guest::GuestAddress target{0x2000};
    rosa::guest::AddressSpace addressSpace;
    constexpr std::array<std::uint8_t, 8> data{0xEF, 0xCD, 0xAB, 0x89, 0xEF, 0xBE, 0xAD, 0xDE};
    addressSpace.mapSegment(target, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                            data);
    rosa::x86::X86State state;
    state.rcx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0x89ABCDEF},
                "RIP-relative MOV load did not read exactly four bytes and zero-extend");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative MOV load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rcx = 0x0123456789ABCDEFULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOV from unmapped memory did not fault");
    expectEqual(faultState.rcx, std::uint64_t{0x0123456789ABCDEFULL},
                "failed RIP-relative MOV changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed RIP-relative MOV changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(
            decoder.decodeBlock(std::span<const std::uint8_t>{observed}.first(5), observedRip));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated RIP-relative MOV load was not rejected");

    bool overflowRejected = false;
    try {
        static_cast<void>(
            decoder.decodeBlock(observed, rosa::guest::GuestAddress{UINT64_MAX - 2U}));
    } catch (const std::runtime_error &) {
        overflowRejected = true;
    }
    expect(overflowRejected, "overflowing RIP-relative MOV target was accepted");
}

void testMov32BitRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x89, 0x72, 0x28, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg, "MOV [mem], r32 opcode differs");
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(source.reg == rosa::x86::Register::R14, "MOV [mem], r14d source differs");
    expectEqual(source.width, std::uint8_t{32}, "MOV [mem], r32 width differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8128}, UINT64_MAX);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0x8100;
    state.r14 = 0xFFFFFFFF12345678ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{0x8128}), std::uint32_t{0x12345678},
                "MOV [mem], r32 stored value differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{0x812C}), UINT32_MAX,
                "MOV [mem], r32 overwrote adjacent bytes");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV [mem], r32 changed flags");
}

void testMov64BitRegisterToScaledGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x89, 0x34, 0x17, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "scaled qword MOV store opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "scaled qword MOV store length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdi && memory.index &&
               *memory.index == rosa::x86::Register::Rdx && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 64,
           "scaled qword MOV store memory operand differs");
    expect(source.reg == rosa::x86::Register::Rsi && source.width == 64,
           "scaled qword MOV store source differs");
    expect(rosa::debug::dumpX86(decoded).find("mov [rdi+rdx*1], rsi") != std::string::npos,
           "scaled qword MOV store dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8020};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, UINT64_MAX);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = page.value;
    state.rdx = 0x20;
    state.rsi = 0x0123456789ABCDEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0x0123456789ABCDEFULL},
                "scaled qword MOV stored the wrong value");
    expectEqual(state.rdi, page.value, "scaled qword MOV changed its base");
    expectEqual(state.rdx, std::uint64_t{0x20}, "scaled qword MOV changed its index");
    expectEqual(state.rsi, std::uint64_t{0x0123456789ABCDEFULL},
                "scaled qword MOV changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "scaled qword MOV changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t readOnlySentinel = 0xA5A5A5A5A5A5A5A5ULL;
    std::memcpy(readOnlyBytes.data() + 0x20, &readOnlySentinel, sizeof(readOnlySentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only scaled MOV target");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "scaled qword MOV accepted read-only guest memory");
    expectEqual(readOnlyAddressSpace.readU64(target), readOnlySentinel,
                "faulted scaled qword MOV changed guest memory");
    expectEqual(state.rsi, std::uint64_t{0x0123456789ABCDEFULL},
                "faulted scaled qword MOV changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "faulted scaled qword MOV changed flags");
}

void testMovLowByteRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x88, 0x48, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "MOV byte [memory], low register opcode differs");
    expectEqual(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]).width, std::uint8_t{8},
                "MOV byte store memory width differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::Register::Rcx,
           "MOV byte store source differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8000;
    state.rcx = 0xAABBCCDDEEFF00A5ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0x8018}, 1).front(),
                std::uint8_t{0xA5}, "MOV byte store value differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV byte store changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x8000;
    faultState.rcx = 0xA5;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOV byte to unmapped guest memory did not fail");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "failed MOV byte store changed flags");
}

void testMovExtendedLowByteToScaledGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{0x45, 0x88, 0x5C, 0x08, 0x02, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "scaled byte MOV store opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "scaled byte MOV store length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R8 && memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 1 && memory.displacement == 2 && memory.width == 8,
           "scaled byte MOV store effective address differs");
    expect(source.reg == rosa::x86::Register::R11 && source.width == 8,
           "scaled byte MOV store source differs");
    expect(rosa::debug::dumpX86(decoded).find("mov [r8+rcx*1+0x2], r11b") != std::string::npos,
           "scaled byte MOV store dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8022};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array sentinel{std::uint8_t{0x11}, std::uint8_t{0}, std::uint8_t{0x22}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{target.value - 1}, sentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r8 = memoryBase.value;
    state.rcx = 0x20;
    state.r11 = 0x11223344556677A5ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    const auto stored = addressSpace.readBytes(rosa::guest::GuestAddress{target.value - 1}, 3);
    expect(stored[0] == 0x11 && stored[1] == 0xA5 && stored[2] == 0x22,
           "scaled byte MOV store changed the wrong guest bytes");
    expectEqual(state.r8, memoryBase.value, "scaled byte MOV store changed its base");
    expectEqual(state.rcx, std::uint64_t{0x20}, "scaled byte MOV store changed its index");
    expectEqual(state.r11, std::uint64_t{0x11223344556677A5ULL},
                "scaled byte MOV store changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "scaled byte MOV store changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "scaled byte MOV store accepted read-only memory");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1)[0], std::uint8_t{0},
                "faulted scaled byte MOV store changed memory");
    expectEqual(state.r11, std::uint64_t{0x11223344556677A5ULL},
                "faulted scaled byte MOV store changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "faulted scaled byte MOV store changed flags");
}

void testMovLowByteRegisterToRipRelativeGuestMemory() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF800058A51ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8000C8DAAULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF8000C8000ULL};
    constexpr std::array<std::uint8_t, 7> code{0x88, 0x05, 0x53, 0x03, 0x07, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "RIP-relative MOV byte register opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6},
                "RIP-relative MOV byte register length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8,
           "RIP-relative MOV byte register addressing differs");
    expectEqual(memory.displacement, std::int64_t{0x70353},
                "RIP-relative MOV byte register displacement differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 8,
           "RIP-relative MOV byte register source differs");
    expect(rosa::debug::dumpX86(decoded).find("mov [rip+0x70353], al ; 0x7ff8000c8daa") !=
               std::string::npos,
           "RIP-relative MOV byte register dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(rosa::guest::GuestAddress{target.value - 1},
                            std::array<std::uint8_t, 3>{0x11, 0x00, 0x22});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.rax = 0x11223344556677A5ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    const auto stored = addressSpace.readBytes(rosa::guest::GuestAddress{target.value - 1}, 3);
    expect(stored == std::vector<std::uint8_t>({0x11, 0xA5, 0x22}),
           "RIP-relative MOV byte register did not store exactly one byte");
    expectEqual(state.rax, std::uint64_t{0x11223344556677A5ULL},
                "RIP-relative MOV byte register changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative MOV byte register changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[static_cast<std::size_t>(target.value - targetPage.value)] = 0x5A;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(targetPage, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only RIP-relative byte MOV target");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOV byte register accepted read-only memory");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1).front(), std::uint8_t{0x5A},
                "failed RIP-relative MOV byte register changed memory");
    expectEqual(state.rax, std::uint64_t{0x11223344556677A5ULL},
                "failed RIP-relative MOV byte register changed RAX");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOV byte register changed flags");
}

void testMovLowByteRegisterToExtendedBase() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0x88, 0x40, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::R8, "MOV byte store REX.B base differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::Register::Rax,
           "MOV byte store legacy source under REX differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r8 = 0x8000;
    state.rax = 0xA5;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0x8018}, 1).front(),
                std::uint8_t{0xA5}, "MOV byte store through REX.B value differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV byte store through REX.B changed flags");
}

void testMov32BitImmediateToIndexedGuestMemory() {
    constexpr std::array<std::uint8_t, 8> code{0xC7, 0x04, 0x16, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AE9E8BULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "indexed MOV dword immediate opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "indexed MOV dword immediate length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsi && memory.index &&
               *memory.index == rosa::x86::Register::Rdx && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 32 && immediate.width == 32 &&
               immediate.value == UINT32_MAX,
           "indexed MOV dword immediate operands differ");
    expect(rosa::debug::dumpX86(decoded).find("mov dword [rsi+rdx*1], 0xffffffff") !=
               std::string::npos,
           "indexed MOV dword immediate dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8020};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 8> sentinel{0x11, 0x22, 0xA5, 0xA5, 0xA5, 0xA5, 0x77, 0x88};
    addressSpace.writeBytes(rosa::guest::GuestAddress{target.value - 2}, sentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AE9E8BULL});
    rosa::x86::X86State state;
    state.rsi = page.value;
    state.rdx = 0x20;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{target.value - 2}, 8),
                std::vector<std::uint8_t>{0x11, 0x22, 0xFF, 0xFF, 0xFF, 0xFF, 0x77, 0x88},
                "indexed MOV immediate did not store exactly four bytes");
    expectEqual(state.rsi, page.value, "indexed MOV immediate changed its base");
    expectEqual(state.rdx, std::uint64_t{0x20}, "indexed MOV immediate changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "indexed MOV immediate changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rsi = page.value;
    faultState.rdx = 0x20;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed MOV immediate accepted unmapped guest memory");
    expectEqual(faultState.rsi, page.value, "faulted indexed MOV immediate changed its base");
    expectEqual(faultState.rdx, std::uint64_t{0x20},
                "faulted indexed MOV immediate changed its index");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted indexed MOV immediate changed flags");
}

void testMovImmediateToGuestMemory() {
    constexpr std::array<std::uint8_t, 8> code{
        0x48, 0xC7, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm, "MOV [mem], imm32 opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value, UINT64_MAX,
                "MOV [mem], imm32 sign extension differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8100}), UINT64_MAX,
                "MOV [mem], imm32 stored value differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV [mem], imm32 changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOV immediate to unmapped guest memory did not fail");
}

void testMovImmediateToGuestStack() {
    constexpr std::array<std::uint8_t, 9> code{0x48, 0xC7, 0x04, 0x24, 0x00,
                                               0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "MOV qword [rsp], imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "MOV qword [rsp], imm32 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsp && !memory.index && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 64,
           "MOV qword [rsp], imm32 memory operand differs");
    expect(immediate.value == 0 && immediate.width == 32,
           "MOV qword [rsp], imm32 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("mov qword [rsp], 0x0") != std::string::npos,
           "MOV qword [rsp], imm32 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, UINT64_MAX);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsp = target.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0},
                "MOV qword [rsp], imm32 stored the wrong value");
    expectEqual(state.rsp, target.value, "MOV qword [rsp], imm32 changed RSP");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV qword [rsp], imm32 changed flags");

    constexpr std::array<std::uint8_t, 9> negativeCode{0x48, 0xC7, 0x04, 0x24, 0xFF,
                                                       0xFF, 0xFF, 0xFF, 0xC3};
    const auto negativeBlock =
        translator.translate(negativeCode, rosa::guest::GuestAddress{0x2000});
    addressSpace.writeU64(target, 0);
    state.rflags = 0xAD7;
    static_cast<void>(negativeBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), UINT64_MAX,
                "MOV qword [rsp], imm32 did not sign-extend");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "negative MOV qword [rsp], imm32 changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t sentinel = 0x0123456789ABCDEFULL;
    std::memcpy(readOnlyBytes.data() + 0x100, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only guest stack");
    state.rflags = 0xCD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "MOV qword immediate accepted a read-only guest stack");
    expectEqual(readOnlyAddressSpace.readU64(target), sentinel,
                "faulted MOV qword immediate changed guest stack memory");
    expectEqual(state.rsp, target.value, "faulted MOV qword immediate changed RSP");
    expectEqual(state.rflags, std::uint64_t{0xCD7}, "faulted MOV qword immediate changed flags");
}

void testMovImmediateToRipRelativeGuestMemory() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF800058A1AULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8000C8DD0ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF8000C8000ULL};
    constexpr std::array<std::uint8_t, 12> code{0x48, 0xC7, 0x05, 0xAB, 0x03, 0x07,
                                                0x00, 0x00, 0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "RIP-relative MOV qword immediate opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{11},
                "RIP-relative MOV qword immediate length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 64,
           "RIP-relative MOV qword immediate addressing differs");
    expectEqual(memory.displacement, std::int64_t{0x703AB},
                "RIP-relative MOV qword immediate displacement differs");
    expectEqual(immediate.value, std::uint64_t{0}, "RIP-relative MOV qword immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("mov qword [rip+0x703ab], 0x0 ; 0x7ff8000c8dd0") !=
               std::string::npos,
           "RIP-relative MOV qword immediate dump differs");

    auto rexBCode = code;
    rexBCode[0] = 0x49;
    const auto rexBDecoded = decoder.decodeBlock(rexBCode, instructionAddress);
    const auto rexBMemory = std::get<rosa::x86::MemoryOperand>(rexBDecoded[0].operands[0]);
    expect(rexBMemory.ripRelative && !rexBMemory.hasBase,
           "REX.B changed opcode-C7 RIP-relative addressing");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::uint64_t before = 0x1122334455667788ULL;
    constexpr std::uint64_t initial = 0xA5A5A5A5A5A5A5A5ULL;
    constexpr std::uint64_t after = 0x8877665544332211ULL;
    addressSpace.writeU64(rosa::guest::GuestAddress{target.value - 8}, before);
    addressSpace.writeU64(target, initial);
    addressSpace.writeU64(rosa::guest::GuestAddress{target.value + 8}, after);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.rax = 0xDEADBEEFCAFEBABEULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0},
                "RIP-relative MOV qword immediate stored the wrong value");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{target.value - 8}), before,
                "RIP-relative MOV qword immediate changed preceding bytes");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{target.value + 8}), after,
                "RIP-relative MOV qword immediate changed following bytes");
    expectEqual(state.rax, std::uint64_t{0xDEADBEEFCAFEBABEULL},
                "RIP-relative MOV qword immediate used a dummy base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOV qword immediate changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    const auto targetOffset = static_cast<std::size_t>(target.value - targetPage.value);
    std::memcpy(readOnlyBytes.data() + targetOffset, &initial, sizeof(initial));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(targetPage, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only RIP-relative MOV target");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOV qword immediate accepted a read-only target");
    expectEqual(readOnlyAddressSpace.readU64(target), initial,
                "failed RIP-relative MOV qword immediate changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOV qword immediate changed flags");
}

void testMovWordImmediateToRipRelativeGuestMemory() {
    // Observed in sqlite: mov word [rip+disp32], imm16.
    constexpr rosa::guest::GuestAddress instructionAddress{0x10005DB8AULL};
    constexpr rosa::guest::GuestAddress target{0x1001F0804ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x1001F0000ULL};
    constexpr std::array<std::uint8_t, 10> code{0x66, 0xC7, 0x05, 0x71, 0x2C,
                                               0x19, 0x00, 0x01, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "RIP-relative MOV word immediate opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9},
                "RIP-relative MOV word immediate length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 16,
           "RIP-relative MOV word immediate addressing differs");
    expectEqual(immediate.value, std::uint64_t{1}, "RIP-relative MOV word immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("mov word [rip+0x192c71], 0x1") !=
               std::string::npos,
           "RIP-relative MOV word immediate dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0xA5A5A5A5A5A5A5A5ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0xA5A5A5A5A5A50001ULL},
                "RIP-relative MOV word immediate stored the wrong value");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOV word immediate changed flags");
}

void testMov32BitImmediateToGuestMemory() {
    constexpr std::array<std::uint8_t, 8> code{0xC7, 0x45, 0x9F, 0x00, 0x00, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF80005899DULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "MOV dword [mem], imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "MOV dword [mem], imm32 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbp && memory.width == 32 &&
               memory.displacement == -0x61,
           "MOV dword [mem], imm32 memory operand differs");
    expect(immediate.value == 0 && immediate.width == 32,
           "MOV dword [mem], imm32 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("mov dword [rbp-0x61], 0x0") != std::string::npos,
           "MOV dword [mem], imm32 dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x809F};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x1122334455667788ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbp = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0x1122334400000000ULL},
                "MOV dword [mem], imm32 did not store exactly four bytes");
    expectEqual(state.rbp, std::uint64_t{0x8100},
                "MOV dword [mem], imm32 changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV dword [mem], imm32 changed flags");

    std::array<std::uint8_t, 0xA7> readOnlyBytes{};
    const auto sentinel = UINT64_C(0x8877665544332211);
    std::memcpy(readOnlyBytes.data() + 0x9F, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(memoryBase, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes);
    rosa::x86::X86State faultState;
    faultState.rbp = 0x8100;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "MOV dword immediate to read-only memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(target), sentinel,
                "failed MOV dword immediate changed guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed MOV dword immediate changed flags");
}

void testMovByteImmediateToGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0xC6, 0x43, 0x18, 0xA5, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "MOV byte [mem], imm8 opcode differs");
    expectEqual(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]).width, std::uint8_t{8},
                "MOV byte [mem], imm8 width differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    const auto byte = addressSpace.readBytes(rosa::guest::GuestAddress{0x8118}, 1);
    expectEqual(byte[0], std::uint8_t{0xA5}, "MOV byte [mem], imm8 stored value differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV byte [mem], imm8 changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "MOV byte immediate to read-only guest memory did not fail");
}

void testMovByteImmediateToScaledGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{0xC6, 0x44, 0x13, 0x58, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF8000500FBULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "MOV byte [scaled memory], imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5},
                "MOV byte [scaled memory], imm8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.index &&
               *memory.index == rosa::x86::Register::Rdx && memory.scale == 1 &&
               memory.displacement == 0x58 && memory.width == 8,
           "MOV byte [rbx+rdx+disp8], imm8 operand differs");
    expect(immediate.value == 0 && immediate.width == 8,
           "MOV byte [scaled memory], imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("mov byte [rbx+rdx*1+0x58], 0x0") !=
               std::string::npos,
           "MOV byte [scaled memory], imm8 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8078};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array sentinel{std::uint8_t{0x11}, std::uint8_t{0xA5}, std::uint8_t{0x22}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{target.value - 1}, sentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF8000500FBULL});
    rosa::x86::X86State state;
    state.rbx = page.value;
    state.rdx = 0x20;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    const auto result =
        addressSpace.readBytes(rosa::guest::GuestAddress{target.value - 1}, sentinel.size());
    expect(result == std::vector<std::uint8_t>({0x11, 0x00, 0x22}),
           "MOV byte [scaled memory], imm8 changed the wrong bytes");
    expectEqual(state.rbx, page.value, "MOV byte [scaled memory], imm8 changed its base");
    expectEqual(state.rdx, std::uint64_t{0x20}, "MOV byte [scaled memory], imm8 changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV byte [scaled memory], imm8 changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0x78] = 0xA5;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only scaled byte immediate target");
    rosa::x86::X86State faultState;
    faultState.rbx = page.value;
    faultState.rdx = 0x20;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "MOV byte immediate accepted read-only scaled guest memory");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1).front(), std::uint8_t{0xA5},
                "faulted scaled byte immediate MOV changed memory");
    expectEqual(faultState.rbx, page.value, "faulted scaled byte immediate MOV changed its base");
    expectEqual(faultState.rdx, std::uint64_t{0x20},
                "faulted scaled byte immediate MOV changed its index");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted scaled byte immediate MOV changed flags");
}

void testMovByteImmediateToRipRelativeGuestMemory() {
    constexpr std::array<std::uint8_t, 7> observed{0xC6, 0x05, 0xF5, 0x3E, 0x0C, 0x00, 0x01};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800004F14ULL};
    const rosa::x86::Decoder decoder;
    const auto observedDecoded = decoder.decodeBlock(observed, observedRip, 1);
    expectEqual(observedDecoded[0].length, std::uint8_t{7},
                "observed RIP-relative MOV byte immediate length differs");
    const auto observedMemory = std::get<rosa::x86::MemoryOperand>(observedDecoded[0].operands[0]);
    expect(observedMemory.ripRelative && !observedMemory.hasBase && observedMemory.width == 8 &&
               observedMemory.displacement == 0xC3EF5,
           "observed RIP-relative MOV byte immediate operand differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(observedDecoded[0].operands[1]).value,
                std::uint64_t{1}, "observed RIP-relative MOV byte immediate differs");
    expect(rosa::debug::dumpX86(observedDecoded)
                   .find("mov byte [rip+0xc3ef5], 0x1 ; 0x7ff8000c8e10") != std::string::npos,
           "observed RIP-relative MOV byte immediate dump differs");

    constexpr std::array<std::uint8_t, 8> code{0xC6, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0xA5, 0xC3};
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress target{0x2000};
    const auto decoded = decoder.decodeBlock(code, codeBase);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "RIP-relative MOV byte immediate opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7},
                "RIP-relative MOV byte immediate length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0xFF9,
           "RIP-relative MOV byte immediate memory operand differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0xA5}, "RIP-relative MOV byte immediate value differs");
    expect(rosa::debug::dumpX86(decoded).find("mov byte [rip+0xff9], 0xa5 ; 0x2000") !=
               std::string::npos,
           "RIP-relative MOV byte immediate dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 3>{0x11, 0x00, 0x22});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeBase);
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 3), std::vector<std::uint8_t>({0xA5, 0x00, 0x22}),
                "RIP-relative MOV byte immediate changed the wrong bytes");
    expectEqual(state.rax, UINT64_MAX,
                "RIP-relative MOV byte immediate read a dummy base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOV byte immediate changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    constexpr std::array<std::uint8_t, 1> sentinelByte{0x5A};
    readOnlyAddressSpace.mapSegment(target, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, sentinelByte);
    rosa::x86::X86State faultState;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOV byte immediate to read-only memory did not fault");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1).front(), std::uint8_t{0x5A},
                "failed RIP-relative MOV byte immediate changed memory");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOV byte immediate changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(
            decoder.decodeBlock(std::span<const std::uint8_t>{code}.first(6), codeBase));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated RIP-relative MOV byte immediate was accepted");
}

void testMovWordImmediateToGuestMemory() {
    constexpr std::array<std::uint8_t, 7> code{0x66, 0xC7, 0x43, 0x18, 0xEF, 0xBE, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "MOV word [mem], imm16 opcode differs");
    expectEqual(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]).width, std::uint8_t{16},
                "MOV word [mem], imm16 width differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0xBEEF}, "MOV word [mem], imm16 immediate differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8118}, 0x1122334455667788ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8118}),
                std::uint64_t{0x112233445566BEEFULL},
                "MOV word [mem], imm16 changed bytes outside the word");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV word [mem], imm16 changed flags");

    state.rbx = 0x8FE7;
    state.rflags = 0xAD7;
    const std::array marker{std::uint8_t{0x5A}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8FFF}, marker);
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("outside guest mapping") !=
                       std::string_view::npos ||
                   std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page MOV word guest store did not fault");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0x8FFF}, 1).front(),
                std::uint8_t{0x5A}, "failed MOV word guest store partially changed memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "failed MOV word guest store changed flags");

    constexpr std::array<std::uint8_t, 8> extendedCode{0x66, 0x41, 0xC7, 0x47,
                                                       0x50, 0x00, 0x00, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x2000});
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "REX MOV word [mem], imm16 opcode differs");
    expectEqual(extendedDecoded[0].length, std::uint8_t{7},
                "REX MOV word [mem], imm16 length differs");
    const auto extendedMemory = std::get<rosa::x86::MemoryOperand>(extendedDecoded[0].operands[0]);
    const auto extendedImmediate =
        std::get<rosa::x86::ImmediateOperand>(extendedDecoded[0].operands[1]);
    expect(extendedMemory.base == rosa::x86::Register::R15 && extendedMemory.displacement == 0x50 &&
               extendedMemory.width == 16 && !extendedMemory.ripRelative,
           "REX MOV word [r15+disp8], imm16 memory operand differs");
    expect(extendedImmediate.width == 16 && extendedImmediate.value == 0,
           "REX MOV word [mem], imm16 immediate differs");
    expect(rosa::debug::dumpX86(extendedDecoded).find("mov word [r15+0x50], 0x0") !=
               std::string::npos,
           "REX MOV word [mem], imm16 dump differs");

    constexpr rosa::guest::GuestAddress extendedTarget{0x8150};
    addressSpace.writeU64(extendedTarget, 0x1122334455667788ULL);
    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State extendedState;
    extendedState.r15 = extendedTarget.value - 0x50;
    extendedState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(extendedState, &addressSpace));
    expectEqual(addressSpace.readU64(extendedTarget), std::uint64_t{0x1122334455660000ULL},
                "REX MOV word immediate changed bytes outside the word");
    expectEqual(extendedState.r15, extendedTarget.value - 0x50,
                "REX MOV word immediate changed its extended base");
    expectEqual(extendedState.rflags, std::uint64_t{0x8D7}, "REX MOV word immediate changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0x150] = 0xA5;
    readOnlyBytes[0x151] = 0x5A;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(memoryBase, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only REX MOV word immediate memory");
    rosa::x86::X86State extendedFaultState;
    extendedFaultState.r15 = extendedTarget.value - 0x50;
    extendedFaultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(extendedBlock.execute(extendedFaultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "REX MOV word immediate accepted read-only memory");
    expectEqual(readOnlyAddressSpace.readBytes(extendedTarget, 2),
                std::vector<std::uint8_t>({0xA5, 0x5A}),
                "faulted REX MOV word immediate changed memory");
    expectEqual(extendedFaultState.r15, extendedTarget.value - 0x50,
                "faulted REX MOV word immediate changed its base");
    expectEqual(extendedFaultState.rflags, std::uint64_t{0xBD7},
                "faulted REX MOV word immediate changed flags");

    constexpr std::array<std::uint8_t, 7> indexedCode{0x66, 0xC7, 0x04, 0x88, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress indexedRip{0x7FF802C772B4ULL};
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, indexedRip);
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "indexed MOV word immediate opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{6},
                "indexed MOV word immediate length differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[0]);
    expect(indexedMemory.base == rosa::x86::Register::Rax &&
               indexedMemory.index == rosa::x86::Register::Rcx && indexedMemory.scale == 4 &&
               indexedMemory.width == 16 && indexedMemory.displacement == 0,
           "indexed MOV word immediate operand differs");
    expect(rosa::debug::dumpX86(indexedDecoded).find("mov word [rax+rcx*4], 0x0") !=
               std::string::npos,
           "indexed MOV word immediate dump differs");

    const auto indexedBlock = translator.translate(indexedCode, indexedRip);
    constexpr rosa::guest::GuestAddress indexedTarget{0x8010};
    addressSpace.writeU64(indexedTarget, 0x1122334455667788ULL);
    rosa::x86::X86State indexedState;
    indexedState.rax = memoryBase.value;
    indexedState.rcx = 4;
    indexedState.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(addressSpace.readU64(indexedTarget), std::uint64_t{0x1122334455660000ULL},
                "indexed MOV word immediate changed the wrong bytes");
    expectEqual(indexedState.rax, memoryBase.value, "indexed MOV word immediate changed its base");
    expectEqual(indexedState.rcx, std::uint64_t{4}, "indexed MOV word immediate changed its index");
    expectEqual(indexedState.rflags, std::uint64_t{0x8D7},
                "indexed MOV word immediate changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    indexedState.rflags = 0xAD7;
    bool indexedFaulted = false;
    try {
        static_cast<void>(indexedBlock.execute(indexedState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        indexedFaulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(indexedFaulted, "indexed MOV word immediate accepted unmapped memory");
    expectEqual(indexedState.rflags, std::uint64_t{0xAD7},
                "faulted indexed MOV word immediate changed flags");
}

void testMovWordRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x89, 0x46, 0x2C, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "MOV word [mem], register opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).width,
                std::uint8_t{16}, "MOV word source width differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x812C}, 0x1122334455667788ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsi = 0x8100;
    state.rax = 0xAABBCCDDEEFFBEEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x812C}),
                std::uint64_t{0x112233445566BEEFULL},
                "MOV word register store changed adjacent bytes");
    expectEqual(state.rax, std::uint64_t{0xAABBCCDDEEFFBEEFULL},
                "MOV word register store changed source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV word register store changed flags");

    constexpr std::array<std::uint8_t, 6> extendedBaseCode{0x66, 0x41, 0x89, 0x4E, 0x48, 0xC3};
    const auto extendedBaseDecoded =
        decoder.decodeBlock(extendedBaseCode, rosa::guest::GuestAddress{0x2000});
    expect(extendedBaseDecoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "REX MOV word store opcode differs");
    expectEqual(extendedBaseDecoded[0].length, std::uint8_t{5},
                "REX MOV word store length differs");
    const auto extendedMemory =
        std::get<rosa::x86::MemoryOperand>(extendedBaseDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::RegisterOperand>(extendedBaseDecoded[0].operands[1]);
    expect(extendedMemory.base == rosa::x86::Register::R14 && extendedMemory.displacement == 0x48 &&
               extendedMemory.width == 16,
           "REX MOV word store memory operand differs");
    expect(extendedSource.reg == rosa::x86::Register::Rcx && extendedSource.width == 16,
           "REX MOV word store source differs");
    expect(rosa::debug::dumpX86(extendedBaseDecoded).find("mov [r14+0x48], cx") !=
               std::string::npos,
           "REX MOV word store dump differs");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8148}, 0x1122334455667788ULL);
    const auto extendedBaseBlock =
        translator.translate(extendedBaseCode, rosa::guest::GuestAddress{0x2000});
    state.r14 = 0x8100;
    state.rcx = 0xAABBCCDDEEFFBEEFULL;
    state.rflags = 0xAD7;
    static_cast<void>(extendedBaseBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8148}),
                std::uint64_t{0x112233445566BEEFULL}, "REX MOV word store changed adjacent bytes");
    expectEqual(state.r14, std::uint64_t{0x8100}, "REX MOV word store changed its base");
    expectEqual(state.rcx, std::uint64_t{0xAABBCCDDEEFFBEEFULL},
                "REX MOV word store changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "REX MOV word store changed flags");

    constexpr std::array<std::uint8_t, 9> ripRelativeCode{0x66, 0x44, 0x89, 0x35, 0x72,
                                                          0x57, 0xC1, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress ripRelativeRip{0x7FF802C76986ULL};
    constexpr rosa::guest::GuestAddress ripRelativePage{0x7FF84388C000ULL};
    constexpr rosa::guest::GuestAddress ripRelativeTarget{0x7FF84388C100ULL};
    const auto ripRelativeDecoded = decoder.decodeBlock(ripRelativeCode, ripRelativeRip);
    expect(ripRelativeDecoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "RIP-relative MOV word store opcode differs");
    expectEqual(ripRelativeDecoded[0].length, std::uint8_t{8},
                "RIP-relative MOV word store length differs");
    const auto ripRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(ripRelativeDecoded[0].operands[0]);
    const auto ripRelativeSource =
        std::get<rosa::x86::RegisterOperand>(ripRelativeDecoded[0].operands[1]);
    expect(ripRelativeMemory.ripRelative && ripRelativeMemory.displacement == 0x40C15772 &&
               ripRelativeMemory.width == 16 && ripRelativeSource.reg == rosa::x86::Register::R14 &&
               ripRelativeSource.width == 16,
           "MOV word [rip+disp32], r14w operands differ");
    expect(rosa::debug::dumpX86(ripRelativeDecoded).find("mov [rip+0x40c15772], r14w") !=
               std::string::npos,
           "RIP-relative MOV word store dump differs");

    rosa::guest::AddressSpace ripRelativeAddressSpace;
    ripRelativeAddressSpace.mapAnonymous(ripRelativePage, rosa::guest::guestPageSize,
                                         rosa::guest::Permission::Read |
                                             rosa::guest::Permission::Write);
    ripRelativeAddressSpace.writeU64(ripRelativeTarget, 0x1122334455667788ULL);
    const auto ripRelativeBlock = translator.translate(ripRelativeCode, ripRelativeRip);
    rosa::x86::X86State ripRelativeState;
    ripRelativeState.r14 = 0xAABBCCDDEEFFBEEFULL;
    ripRelativeState.rflags = 0xBD7;
    static_cast<void>(ripRelativeBlock.execute(ripRelativeState, &ripRelativeAddressSpace));
    expectEqual(ripRelativeAddressSpace.readU64(ripRelativeTarget),
                std::uint64_t{0x112233445566BEEFULL},
                "RIP-relative MOV word store changed adjacent bytes");
    expectEqual(ripRelativeState.r14, std::uint64_t{0xAABBCCDDEEFFBEEFULL},
                "RIP-relative MOV word store changed its source");
    expectEqual(ripRelativeState.rflags, std::uint64_t{0xBD7},
                "RIP-relative MOV word store changed flags");

    constexpr std::array<std::uint8_t, 6> indexedCode{0x66, 0x89, 0x44, 0x51, 0x28, 0xC3};
    constexpr rosa::guest::GuestAddress indexedRip{0x7FF802C69351ULL};
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, indexedRip);
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "indexed MOV word store opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{5}, "indexed MOV word store length differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[0]);
    const auto indexedSource = std::get<rosa::x86::RegisterOperand>(indexedDecoded[0].operands[1]);
    expect(indexedMemory.base == rosa::x86::Register::Rcx &&
               indexedMemory.index == rosa::x86::Register::Rdx && indexedMemory.scale == 2 &&
               indexedMemory.displacement == 0x28 && indexedMemory.width == 16,
           "indexed MOV word memory operand differs");
    expect(indexedSource.reg == rosa::x86::Register::Rax && indexedSource.width == 16,
           "indexed MOV word source differs");
    expect(rosa::debug::dumpX86(indexedDecoded).find("mov [rcx+rdx*2+0x28], ax") !=
               std::string::npos,
           "indexed MOV word dump differs");

    constexpr rosa::guest::GuestAddress indexedTarget{0x8130};
    addressSpace.writeU64(indexedTarget, 0x1122334455667788ULL);
    const auto indexedBlock = translator.translate(indexedCode, indexedRip);
    rosa::x86::X86State indexedState;
    indexedState.rcx = 0x8100;
    indexedState.rdx = 4;
    indexedState.rax = 0xAABBCCDDEEFFBEEFULL;
    indexedState.rflags = 0xCD7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(addressSpace.readU64(indexedTarget), std::uint64_t{0x112233445566BEEFULL},
                "indexed MOV word changed adjacent bytes");
    expectEqual(indexedState.rcx, std::uint64_t{0x8100}, "indexed MOV word changed its base");
    expectEqual(indexedState.rdx, std::uint64_t{4}, "indexed MOV word changed its index");
    expectEqual(indexedState.rax, std::uint64_t{0xAABBCCDDEEFFBEEFULL},
                "indexed MOV word changed its source");
    expectEqual(indexedState.rflags, std::uint64_t{0xCD7}, "indexed MOV word changed flags");
}

void testMovGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x8B, 0x03, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem, "MOV r64, [base] opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "MOV r64, [base] destination differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx, "MOV r64, [base] base register differs");
    expectEqual(memory.displacement, std::int64_t{0}, "MOV r64, [base] displacement differs");
    constexpr std::array<std::uint8_t, 4> ignoredRexXCode{0x42, 0x8B, 0x03, 0xC3};
    const auto ignoredRexX =
        decoder.decodeBlock(ignoredRexXCode, rosa::guest::GuestAddress{0x2000});
    const auto ignoredRexXMemory = std::get<rosa::x86::MemoryOperand>(ignoredRexX[0].operands[1]);
    expect(ignoredRexXMemory.base == rosa::x86::Register::Rbx && !ignoredRexXMemory.index,
           "MOV treated REX.X as an index without a SIB");

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
    expectEqual(state.rbx, std::uint64_t{0x8100}, "MOV r64, [base] changed the base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV r64, [base] changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x55;
    faultState.rbx = 0x8100;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOV from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{0x55},
                "failed guest-memory load changed the destination register");
}

void testMovGuestGsMemoryTo32BitRegister() {
    constexpr std::array<std::uint8_t, 9> code{0x65, 0x8B, 0x0C, 0x25, 0x18,
                                               0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "GS MOV r32, [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "GS MOV instruction length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32,
           "GS MOV destination differs");
    expect(memory.segment == rosa::x86::Segment::Gs && !memory.hasBase && !memory.index &&
               !memory.ripRelative && memory.width == 32 && memory.displacement == 0x18,
           "GS MOV memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("mov ecx, [gs:0x18]") != std::string::npos,
           "GS MOV dump differs");

    constexpr rosa::guest::GuestAddress tsdBase{0x8000};
    constexpr std::array threadSelfBytes{std::uint8_t{0x78}, std::uint8_t{0x56}, std::uint8_t{0x34},
                                         std::uint8_t{0x12}};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(tsdBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(rosa::guest::GuestAddress{tsdBase.value + 0x18}, threadSelfBytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("read_guest_gs_base.i64") !=
               std::string::npos,
           "GS MOV did not lower the guest segment base through IR");
    rosa::x86::X86State state;
    state.gsBase = tsdBase.value;
    state.rcx = UINT64_MAX;
    state.rdi = 0x1111111111111111ULL;
    state.rsp = 0x2222222222222222ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0x12345678}, "GS MOV did not zero-extend the guest dword");
    expectEqual(state.gsBase, tsdBase.value, "GS MOV changed the guest GS base");
    expectEqual(state.rdi, std::uint64_t{0x1111111111111111ULL},
                "GS MOV used an unrelated GPR as its address base");
    expectEqual(state.rsp, std::uint64_t{0x2222222222222222ULL},
                "GS MOV used the host or guest stack");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "GS MOV changed flags");

    rosa::guest::AddressSpace nonReadableAddressSpace;
    nonReadableAddressSpace.mapAnonymous(tsdBase, rosa::guest::guestPageSize,
                                         rosa::guest::Permission::Write);
    rosa::x86::X86State faultState;
    faultState.gsBase = tsdBase.value;
    faultState.rcx = 0xAAAAAAAA55555555ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &nonReadableAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "GS MOV from non-readable guest memory did not fault");
    expectEqual(faultState.rcx, std::uint64_t{0xAAAAAAAA55555555ULL},
                "failed GS MOV changed the destination");
    expectEqual(faultState.gsBase, tsdBase.value, "failed GS MOV changed the guest GS base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed GS MOV changed flags");
}

void testMovGuestGsMemoryWithNoBaseScaledIndex() {
    constexpr std::array<std::uint8_t, 10> code{0x65, 0x48, 0x8B, 0x04, 0xC5,
                                                0x00, 0x00, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802D156DBULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "GS no-base indexed MOV opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "GS no-base indexed MOV length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64,
           "GS no-base indexed MOV destination differs");
    expect(memory.segment == rosa::x86::Segment::Gs && !memory.hasBase && !memory.ripRelative &&
               memory.index == rosa::x86::Register::Rax && memory.scale == 8 &&
               memory.displacement == 0 && memory.width == 64,
           "GS no-base indexed MOV memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("mov rax, [gs:rax*8]") != std::string::npos,
           "GS no-base indexed MOV dump differs");

    constexpr rosa::guest::GuestAddress gsBase{0x8000};
    constexpr std::uint64_t index = 4;
    constexpr std::uint64_t value = 0x0123456789ABCDEFULL;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(gsBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{gsBase.value + index * 8}, value);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.gsBase = gsBase.value;
    state.rax = index;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, value, "GS no-base indexed MOV loaded the wrong qword");
    expectEqual(state.gsBase, gsBase.value, "GS no-base indexed MOV changed GS base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "GS no-base indexed MOV changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.gsBase = gsBase.value;
    faultState.rax = index;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "GS no-base indexed MOV accepted unmapped memory");
    expectEqual(faultState.rax, index, "faulted GS no-base indexed MOV changed RAX");
    expectEqual(faultState.gsBase, gsBase.value, "faulted GS no-base indexed MOV changed GS base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted GS no-base indexed MOV changed flags");
}

void testMovImmediateToGuestGsMemory() {
    constexpr std::array<std::uint8_t, 14> code{0x65, 0x48, 0xC7, 0x04, 0x25, 0x50, 0x01,
                                                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802A4277AULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "MOV qword [GS:0x150], 1 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{13}, "MOV qword [GS:0x150], 1 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.segment == rosa::x86::Segment::Gs && !memory.hasBase && !memory.index &&
               !memory.ripRelative && memory.displacement == 0x150 && memory.width == 64 &&
               immediate.value == 1 && immediate.width == 32,
           "MOV qword [GS:0x150], 1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("mov qword [gs:0x150], 0x1") != std::string::npos,
           "MOV qword [GS:0x150], 1 dump differs");

    constexpr rosa::guest::GuestAddress gsBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8150};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(gsBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, UINT64_MAX);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("read_guest_gs_base.i64") !=
               std::string::npos,
           "MOV qword GS immediate did not read the guest GS base");
    rosa::x86::X86State state;
    state.gsBase = gsBase.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{1},
                "MOV qword [GS:0x150], 1 stored the wrong value");
    expectEqual(state.gsBase, gsBase.value, "MOV qword GS immediate changed GS base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV qword GS immediate changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t sentinel = 0x0123456789ABCDEFULL;
    std::memcpy(readOnlyBytes.data() + 0x150, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(gsBase, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only GS immediate target");
    rosa::x86::X86State faultState;
    faultState.gsBase = gsBase.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "MOV qword GS immediate accepted read-only memory");
    expectEqual(readOnlyAddressSpace.readU64(target), sentinel,
                "faulted MOV qword GS immediate changed memory");
    expectEqual(faultState.gsBase, gsBase.value, "faulted MOV qword GS immediate changed GS base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted MOV qword GS immediate changed flags");
}

void testMov64BitRegisterToGuestGsMemory() {
    constexpr std::array<std::uint8_t, 10> code{0x65, 0x48, 0x89, 0x04, 0x25,
                                                0x10, 0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "GS MOV [memory], r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "GS MOV store instruction length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.segment == rosa::x86::Segment::Gs && !memory.hasBase && !memory.index &&
               !memory.ripRelative && memory.width == 64 && memory.displacement == 0x10,
           "GS MOV store memory operand differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 64,
           "GS MOV store source differs");
    expect(rosa::debug::dumpX86(decoded).find("mov [gs:0x10], rax") != std::string::npos,
           "GS MOV store dump differs");

    constexpr rosa::guest::GuestAddress tsdBase{0x8000};
    constexpr std::uint64_t value = 0x0123456789ABCDEFULL;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(tsdBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("read_guest_gs_base.i64") !=
               std::string::npos,
           "GS MOV store did not lower guest GS base through IR");
    rosa::x86::X86State state;
    state.gsBase = tsdBase.value;
    state.rax = value;
    state.rsp = 0x2222222222222222ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{tsdBase.value + 0x10}), value,
                "GS MOV stored the wrong guest qword");
    expectEqual(state.rax, value, "GS MOV store changed its source register");
    expectEqual(state.gsBase, tsdBase.value, "GS MOV store changed the guest GS base");
    expectEqual(state.rsp, std::uint64_t{0x2222222222222222ULL},
                "GS MOV store used the guest or host stack");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "GS MOV store changed flags");

    std::array<std::uint8_t, 24> readOnlyBytes{};
    constexpr std::uint64_t sentinel = 0xAABBCCDDEEFF0011ULL;
    std::memcpy(readOnlyBytes.data() + 0x10, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(tsdBase, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes);
    rosa::x86::X86State faultState;
    faultState.gsBase = tsdBase.value;
    faultState.rax = value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "GS MOV store to read-only guest memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(rosa::guest::GuestAddress{tsdBase.value + 0x10}),
                sentinel, "failed GS MOV store changed guest memory");
    expectEqual(faultState.rax, value, "failed GS MOV store changed its source register");
    expectEqual(faultState.gsBase, tsdBase.value, "failed GS MOV store changed the guest GS base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed GS MOV store changed flags");
}

void testMovGuestMemoryToRegisterWithNoIndexSib() {
    constexpr std::array<std::uint8_t, 6> code{0x49, 0x8B, 0x74, 0x24, 0xE0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV r64, [SIB base+disp8] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R12, "MOV no-index SIB extended base differs");
    expectEqual(memory.displacement, std::int64_t{-0x20}, "MOV no-index SIB displacement differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8000}, 0x1122334455667788ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r12 = 0x8020;
    state.rsi = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rsi, std::uint64_t{0x1122334455667788ULL},
                "MOV no-index SIB loaded value differs");
    expectEqual(state.r12, std::uint64_t{0x8020}, "MOV no-index SIB changed base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV no-index SIB changed flags");
}

void testMovGuestMemoryTo32BitRegisterWithScaledIndex() {
    constexpr std::array<std::uint8_t, 6> code{0x41, 0x8B, 0x54, 0x9E, 0x04, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV r32, [base+index*scale+disp8] opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 32,
           "indexed MOV EDX destination differs");
    expect(memory.base == rosa::x86::Register::R14 && memory.index == rosa::x86::Register::Rbx &&
               memory.scale == 4 && memory.displacement == 4 && memory.width == 32,
           "indexed MOV memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("[r14+rbx*4+0x4]") != std::string::npos,
           "indexed MOV dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 8> sourceWithUpperSentinel{0x12, 0x34, 0x56, 0x78,
                                                                  0xEF, 0xBE, 0xAD, 0xDE};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8110}, sourceWithUpperSentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0x8100;
    state.rbx = 3;
    state.rdx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdx, std::uint64_t{0x78563412},
                "indexed MOV dword result or zero extension differs");
    expectEqual(state.r14, std::uint64_t{0x8100}, "indexed MOV changed its base");
    expectEqual(state.rbx, std::uint64_t{3}, "indexed MOV changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "indexed MOV changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rdx = UINT64_MAX;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed MOV from unmapped guest memory did not fault");
    expectEqual(state.rdx, UINT64_MAX, "failed indexed MOV changed its destination");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "failed indexed MOV changed flags");
}

void testMovGuestMemoryTo16BitRegisterWithIndex() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x8B, 0x3C, 0x3C, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C784CDULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV DI, word [RSP+RDI] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "MOV DI, word [RSP+RDI] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdi && destination.width == 16 &&
               memory.base == rosa::x86::Register::Rsp &&
               memory.index == rosa::x86::Register::Rdi && memory.scale == 1 &&
               memory.width == 16 && memory.displacement == 0,
           "MOV DI, word [RSP+RDI] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("mov di, [rsp+rdi*1]") != std::string::npos,
           "MOV DI, word [RSP+RDI] dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> word{0xC6, 0x85};
    addressSpace.writeBytes(memoryBase, word);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("load_guest.i16") !=
               std::string::npos,
           "MOV DI, word [RSP+RDI] did not use a 16-bit guest load");

    rosa::x86::X86State state;
    state.rdi = 0x1122334455660018ULL;
    state.rsp = memoryBase.value - state.rdi;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdi, std::uint64_t{0x11223344556685C6ULL},
                "MOV DI, word [RSP+RDI] did not preserve upper RDI bits");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV DI, word [RSP+RDI] changed flags");

    rosa::x86::X86State faultState;
    faultState.rdi = 0x1122334455660FFFULL;
    faultState.rsp = 0x8FFFULL - faultState.rdi;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page MOV DI, word [RSP+RDI] did not fault");
    expectEqual(faultState.rdi, std::uint64_t{0x1122334455660FFFULL},
                "faulted MOV DI, word [RSP+RDI] changed RDI");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted MOV DI, word [RSP+RDI] changed flags");
}

void testMovGuestMemoryTo32BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x8B, 0x46, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV r32, [base+disp8] opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
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
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV r32, [base+disp8] changed flags");
}

void testMovGuestMemoryToByteRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x8A, 0x70, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV byte register, [memory] opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::R14,
           "MOV byte load extended destination differs");
    expectEqual(destination.width, std::uint8_t{8}, "MOV byte load width differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> value{0xA5};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8018}, value);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8000;
    state.r14 = 0x1122334455667788ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0x11223344556677A5ULL},
                "MOV byte load did not preserve upper destination bits");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV byte load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x8000;
    faultState.r14 = 0x1122334455667788ULL;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOV byte from unmapped guest memory did not fail");
    expectEqual(faultState.r14, std::uint64_t{0x1122334455667788ULL},
                "failed MOV byte load changed destination");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "failed MOV byte load changed flags");
}

void testMovRipRelativeGuestByteToRegister() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x1000};
    constexpr rosa::guest::GuestAddress target{0x2000};
    constexpr std::array<std::uint8_t, 7> code{0x8A, 0x05, 0xFA, 0x0F, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "RIP-relative byte MOV load opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "RIP-relative byte MOV load length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8,
           "RIP-relative byte MOV load destination differs");
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0xFFA,
           "RIP-relative byte MOV load addressing differs");
    expect(rosa::debug::dumpX86(decoded).find("mov al, [rip+0xffa] ; 0x2000") != std::string::npos,
           "RIP-relative byte MOV load dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> value{0xA5};
    addressSpace.writeBytes(target, value);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0x11223344556677A5ULL},
                "RIP-relative byte MOV load changed upper RAX bits");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative byte MOV load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rax = 0x8877665544332211ULL;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative byte MOV load accepted unmapped memory");
    expectEqual(state.rax, std::uint64_t{0x8877665544332211ULL},
                "faulted RIP-relative byte MOV load changed RAX");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative byte MOV load changed flags");
}

void testMovGuestMemoryToByteRegisterWithScaledIndex() {
    constexpr std::array<std::uint8_t, 4> code{0x8A, 0x14, 0x08, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF8000050A0ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem, "SIB byte MOV load opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "SIB byte MOV load length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 8,
           "SIB byte MOV load destination differs");
    expect(memory.base == rosa::x86::Register::Rax && memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 1 && memory.displacement == 0 && memory.width == 8,
           "SIB byte MOV load effective address differs");
    expect(rosa::debug::dumpX86(decoded).find("mov dl, [rax+rcx*1]") != std::string::npos,
           "SIB byte MOV load dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> value{0xA5};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8018}, value);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8010;
    state.rcx = 8;
    state.rdx = 0x1122334455667788ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdx, std::uint64_t{0x11223344556677A5ULL},
                "SIB byte MOV load changed bytes above DL");
    expectEqual(state.rax, std::uint64_t{0x8010}, "SIB byte MOV load changed its base register");
    expectEqual(state.rcx, std::uint64_t{8}, "SIB byte MOV load changed its index register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "SIB byte MOV load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState = state;
    faultState.rdx = 0x8877665544332211ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "SIB byte MOV load from unmapped memory did not fault");
    expectEqual(faultState.rdx, std::uint64_t{0x8877665544332211ULL},
                "failed SIB byte MOV load changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed SIB byte MOV load changed flags");
}

void testMovzxLowByteRegisterTo32BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x0F, 0xB6, 0xE9, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegReg, "MOVZX r32, r8 opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R13 && destination.width == 32,
           "MOVZX r13d destination differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 8, "MOVZX CL source differs");
    expect(rosa::debug::dumpX86(decoded).find("movzx r13d, cl") != std::string::npos,
           "MOVZX r13d, cl dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r13 = UINT64_MAX;
    state.rcx = 0x11223344556677ABULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r13, std::uint64_t{0xAB}, "MOVZX r32, r8 result did not zero-extend");
    expectEqual(state.rcx, std::uint64_t{0x11223344556677ABULL},
                "MOVZX r32, r8 changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVZX r32, r8 changed flags");

    constexpr std::array<std::uint8_t, 4> highByteCode{0x0F, 0xB6, 0xDC, 0xC3};
    const auto highByteDecoded =
        decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x7FF802B05FE7ULL});
    const auto highByteDestination =
        std::get<rosa::x86::RegisterOperand>(highByteDecoded[0].operands[0]);
    const auto highByteSource =
        std::get<rosa::x86::RegisterOperand>(highByteDecoded[0].operands[1]);
    expect(highByteDestination.reg == rosa::x86::Register::Rbx && highByteDestination.width == 32 &&
               highByteSource.reg == rosa::x86::Register::Rax && highByteSource.width == 8 &&
               highByteSource.byteOffset == 1,
           "MOVZX EBX, AH operands differ");
    expect(rosa::debug::dumpX86(highByteDecoded).find("movzx ebx, ah") != std::string::npos,
           "MOVZX high-byte dump differs");

    const auto highByteBlock =
        translator.translate(highByteCode, rosa::guest::GuestAddress{0x7FF802B05FE7ULL});
    state.rax = 0x112233445566ABCDULL;
    state.rbx = UINT64_MAX;
    state.rflags = 0xAD7;
    static_cast<void>(highByteBlock.execute(state));
    expectEqual(state.rbx, std::uint64_t{0xAB}, "MOVZX EBX, AH selected the wrong byte lane");
    expectEqual(state.rax, std::uint64_t{0x112233445566ABCDULL},
                "MOVZX EBX, AH changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVZX EBX, AH changed flags");
}

void testMovsxLowByteRegisterTo32BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x40, 0x0F, 0xBE, 0xCE, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A8C850ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovsxRegReg, "MOVSX r32, r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "MOVSX r32, r8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32,
           "MOVSX ECX destination differs");
    expect(source.reg == rosa::x86::Register::Rsi && source.width == 8, "MOVSX SIL source differs");
    expect(rosa::debug::dumpX86(decoded).find("movsx ecx, sil") != std::string::npos,
           "MOVSX ECX, SIL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A8C850ULL});
    rosa::x86::X86State positiveState;
    positiveState.rcx = UINT64_MAX;
    positiveState.rsi = 0xAAAAAAAAAAAAAA2FULL;
    positiveState.rflags = 0x8D7;
    static_cast<void>(block.execute(positiveState));
    expectEqual(positiveState.rcx, std::uint64_t{0x2F}, "positive MOVSX r32, r8 result differs");
    expectEqual(positiveState.rsi, std::uint64_t{0xAAAAAAAAAAAAAA2FULL},
                "positive MOVSX changed its source");
    expectEqual(positiveState.rflags, std::uint64_t{0x8D7}, "positive MOVSX changed flags");

    rosa::x86::X86State negativeState;
    negativeState.rcx = UINT64_MAX;
    negativeState.rsi = 0xAAAAAAAAAAAAAA80ULL;
    negativeState.rflags = 0xAD7;
    static_cast<void>(block.execute(negativeState));
    expectEqual(negativeState.rcx, std::uint64_t{0xFFFFFF80},
                "negative MOVSX r32, r8 result or zero extension differs");
    expectEqual(negativeState.rsi, std::uint64_t{0xAAAAAAAAAAAAAA80ULL},
                "negative MOVSX changed its source");
    expectEqual(negativeState.rflags, std::uint64_t{0xAD7}, "negative MOVSX changed flags");

    constexpr std::array<std::uint8_t, 4> aliasedCode{0x0F, 0xBE, 0xC9, 0xC3};
    constexpr rosa::guest::GuestAddress aliasedRip{0x7FF802CBA133ULL};
    const auto aliasedDecoded = decoder.decodeBlock(aliasedCode, aliasedRip);
    expect(aliasedDecoded[0].opcode == rosa::x86::Opcode::MovsxRegReg,
           "legacy MOVSX r32, r8 opcode differs");
    expectEqual(aliasedDecoded[0].length, std::uint8_t{3}, "legacy MOVSX r32, r8 length differs");
    const auto aliasedDestination =
        std::get<rosa::x86::RegisterOperand>(aliasedDecoded[0].operands[0]);
    const auto aliasedSource = std::get<rosa::x86::RegisterOperand>(aliasedDecoded[0].operands[1]);
    expect(aliasedDestination.reg == rosa::x86::Register::Rcx && aliasedDestination.width == 32 &&
               aliasedSource.reg == rosa::x86::Register::Rcx && aliasedSource.width == 8,
           "MOVSX ECX, CL operands differ");
    expect(rosa::debug::dumpX86(aliasedDecoded).find("movsx ecx, cl") != std::string::npos,
           "MOVSX ECX, CL dump differs");
    const auto aliasedBlock = translator.translate(aliasedCode, aliasedRip);
    rosa::x86::X86State aliasedState;
    aliasedState.rcx = 0x1122334455667780ULL;
    aliasedState.rflags = 0x46;
    static_cast<void>(aliasedBlock.execute(aliasedState));
    expectEqual(aliasedState.rcx, std::uint64_t{0xFFFFFF80},
                "MOVSX ECX, CL result or zero extension differs");
    expectEqual(aliasedState.rflags, std::uint64_t{0x46}, "MOVSX ECX, CL changed flags");

    constexpr std::array<std::uint8_t, 5> extendedCode{0x45, 0x0F, 0xBE, 0xC8, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x2000});
    const auto extendedDestination =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]);
    expect(extendedDestination.reg == rosa::x86::Register::R9 && extendedDestination.width == 32 &&
               extendedSource.reg == rosa::x86::Register::R8 && extendedSource.width == 8,
           "extended MOVSX r32, r8 operands differ");

    const auto expectRejected = [&decoder](std::span<const std::uint8_t> bytes,
                                           std::string_view message) {
        bool rejected = false;
        try {
            static_cast<void>(decoder.decodeBlock(bytes, rosa::guest::GuestAddress{0x3000}));
        } catch (const rosa::x86::DecodeError &) {
            rejected = true;
        }
        expect(rejected, message);
    };
    constexpr std::array<std::uint8_t, 4> noRex{0x0F, 0xBE, 0xCE, 0xC3};
    expectRejected(noRex, "legacy high-byte MOVSX source was accepted");

    // Observed in libxpc: MOVSX RAX, AL with REX.W.
    constexpr std::array<std::uint8_t, 5> wideCode{0x48, 0x0F, 0xBE, 0xC0, 0xC3};
    const auto wideDecoded =
        decoder.decodeBlock(wideCode, rosa::guest::GuestAddress{0x7FF802B2DEB6ULL});
    expect(wideDecoded[0].opcode == rosa::x86::Opcode::MovsxRegReg,
           "MOVSX r64, r8 opcode differs");
    const auto wideDestination =
        std::get<rosa::x86::RegisterOperand>(wideDecoded[0].operands[0]);
    const auto wideSource = std::get<rosa::x86::RegisterOperand>(wideDecoded[0].operands[1]);
    expect(wideDestination.reg == rosa::x86::Register::Rax && wideDestination.width == 64 &&
               wideSource.reg == rosa::x86::Register::Rax && wideSource.width == 8,
           "MOVSX RAX, AL operands differ");
    expect(rosa::debug::dumpX86(wideDecoded).find("movsx rax, al") != std::string::npos,
           "MOVSX RAX, AL dump differs");
    const auto wideBlock =
        translator.translate(wideCode, rosa::guest::GuestAddress{0x7FF802B2DEB6ULL});
    rosa::x86::X86State wideState;
    wideState.rax = 0x1122334455667780ULL;
    wideState.rflags = 0x46;
    static_cast<void>(wideBlock.execute(wideState));
    expectEqual(wideState.rax, UINT64_C(0xFFFFFFFFFFFFFF80), "MOVSX RAX, AL result differs");
    expectEqual(wideState.rflags, std::uint64_t{0x46}, "MOVSX RAX, AL changed flags");
}

void testMovsxSibByteTo32BitRegister() {
    // Observed in sqlite: MOVSX EDX, byte [R12-8] with REX.B and a no-index SIB.
    constexpr std::array<std::uint8_t, 7> code{0x41, 0x0F, 0xBE, 0x54, 0x24, 0xF8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10014EE4AULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovsxRegMem,
           "SIB MOVSX opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "SIB MOVSX length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 32,
           "MOVSX EDX destination differs");
    expect(memory.base == rosa::x86::Register::R12 && !memory.index &&
               memory.displacement == -8 && memory.width == 8,
           "MOVSX byte [R12-8] source differs");
    expect(rosa::debug::dumpX86(decoded).find("movsx edx, byte [r12-0x8]") != std::string::npos,
           "MOVSX EDX, byte [R12-8] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress source{0x80F8};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> negative{0x80};
    addressSpace.writeBytes(source, negative);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10014EE4AULL});
    rosa::x86::X86State state;
    state.r12 = 0x8100;
    state.rdx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdx, std::uint64_t{0xFFFFFF80}, "SIB MOVSX result differs");
    expectEqual(state.r12, std::uint64_t{0x8100}, "SIB MOVSX changed its base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "SIB MOVSX changed flags");
}

void testMovsxGuestByteTo32BitRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0xBE, 0x17, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A8C856ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovsxRegMem,
           "MOVSX r32, byte [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "MOVSX r32, byte [memory] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 32,
           "MOVSX byte memory destination differs");
    expect(memory.base == rosa::x86::Register::Rdi && memory.width == 8 && memory.displacement == 0,
           "MOVSX byte memory source differs");
    expect(rosa::debug::dumpX86(decoded).find("movsx edx, byte [rdi]") != std::string::npos,
           "MOVSX byte memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress source{0x8120};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A8C856ULL});

    constexpr std::array<std::uint8_t, 1> positive{0x2F};
    addressSpace.writeBytes(source, positive);
    rosa::x86::X86State positiveState;
    positiveState.rdi = source.value;
    positiveState.rdx = UINT64_MAX;
    positiveState.rflags = 0x8D7;
    static_cast<void>(block.execute(positiveState, &addressSpace));
    expectEqual(positiveState.rdx, std::uint64_t{0x2F},
                "positive MOVSX byte memory result differs");
    expectEqual(positiveState.rdi, source.value, "positive MOVSX byte memory changed its base");
    expectEqual(positiveState.rflags, std::uint64_t{0x8D7},
                "positive MOVSX byte memory changed flags");

    constexpr std::array<std::uint8_t, 1> negative{0x80};
    addressSpace.writeBytes(source, negative);
    rosa::x86::X86State negativeState;
    negativeState.rdi = source.value;
    negativeState.rdx = UINT64_MAX;
    negativeState.rflags = 0xAD7;
    static_cast<void>(block.execute(negativeState, &addressSpace));
    expectEqual(negativeState.rdx, std::uint64_t{0xFFFFFF80},
                "negative MOVSX byte memory result differs");
    expectEqual(addressSpace.readBytes(source, 1).front(), std::uint8_t{0x80},
                "MOVSX byte memory changed its source");
    expectEqual(negativeState.rflags, std::uint64_t{0xAD7},
                "negative MOVSX byte memory changed flags");

    // Observed in sqlite: MOVSX ESI, byte [RDX+RSI] with a no-index SIB.
    constexpr std::array<std::uint8_t, 5> sibCode{0x0F, 0xBE, 0x34, 0x32, 0xC3};
    const auto sibDecoded =
        decoder.decodeBlock(sibCode, rosa::guest::GuestAddress{0x10004748FULL});
    expect(sibDecoded[0].opcode == rosa::x86::Opcode::MovsxRegMem,
           "SIB MOVSX opcode differs");
    expectEqual(sibDecoded[0].length, std::uint8_t{4}, "SIB MOVSX length differs");
    const auto sibDestination =
        std::get<rosa::x86::RegisterOperand>(sibDecoded[0].operands[0]);
    const auto sibMemory = std::get<rosa::x86::MemoryOperand>(sibDecoded[0].operands[1]);
    expect(sibDestination.reg == rosa::x86::Register::Rsi && sibDestination.width == 32 &&
               sibMemory.base == rosa::x86::Register::Rdx && sibMemory.index &&
               *sibMemory.index == rosa::x86::Register::Rsi && sibMemory.scale == 1 &&
               sibMemory.width == 8 && sibMemory.displacement == 0,
           "MOVSX ESI, byte [RDX+RSI] operands differ");
    expect(rosa::debug::dumpX86(sibDecoded).find("movsx esi, byte [rdx+rsi*1]") !=
               std::string::npos,
           "MOVSX ESI, byte [RDX+RSI] dump differs");
    const auto sibBlock =
        translator.translate(sibCode, rosa::guest::GuestAddress{0x10004748FULL});
    constexpr rosa::guest::GuestAddress sibSource{0x8140};
    constexpr std::array<std::uint8_t, 1> sibNegative{0x80};
    addressSpace.writeBytes(sibSource, sibNegative);
    rosa::x86::X86State sibState;
    sibState.rdx = 0x8100;
    sibState.rsi = 0x40;
    sibState.rflags = 0x8D7;
    static_cast<void>(sibBlock.execute(sibState, &addressSpace));
    expectEqual(sibState.rsi, std::uint64_t{0xFFFFFF80},
                "SIB MOVSX byte memory result differs");
    expectEqual(sibState.rdx, std::uint64_t{0x8100}, "SIB MOVSX changed its base");
    expectEqual(sibState.rflags, std::uint64_t{0x8D7}, "SIB MOVSX changed flags");

    constexpr std::array<std::uint8_t, 6> observedCode{0x49, 0x0F, 0xBE, 0x5D, 0x00, 0xC3};
    const auto observedDecoded =
        decoder.decodeBlock(observedCode, rosa::guest::GuestAddress{0x7FF802ACEDD0ULL});
    const auto observedDestination =
        std::get<rosa::x86::RegisterOperand>(observedDecoded[0].operands[0]);
    const auto observedMemory = std::get<rosa::x86::MemoryOperand>(observedDecoded[0].operands[1]);
    expect(observedDecoded[0].opcode == rosa::x86::Opcode::MovsxRegMem &&
               observedDecoded[0].length == 5,
           "MOVSX r64, byte [memory] decode differs");
    expect(observedDestination.reg == rosa::x86::Register::Rbx && observedDestination.width == 64 &&
               observedMemory.base == rosa::x86::Register::R13 && observedMemory.width == 8 &&
               observedMemory.displacement == 0,
           "MOVSX RBX, byte [R13] operands differ");
    expect(rosa::debug::dumpX86(observedDecoded).find("movsx rbx, byte [r13]") != std::string::npos,
           "MOVSX r64 byte memory dump differs");

    const auto observedBlock =
        translator.translate(observedCode, rosa::guest::GuestAddress{0x7FF802ACEDD0ULL});
    rosa::x86::X86State observedState;
    observedState.r13 = source.value;
    observedState.rbx = 0x0123456789ABCDEFULL;
    observedState.rflags = 0xBD7;
    static_cast<void>(observedBlock.execute(observedState, &addressSpace));
    expectEqual(observedState.rbx, std::uint64_t{0xFFFFFFFFFFFFFF80ULL},
                "MOVSX r64 byte memory did not sign-extend to 64 bits");
    expectEqual(observedState.r13, source.value, "MOVSX r64 byte memory changed its base");
    expectEqual(observedState.rflags, std::uint64_t{0xBD7}, "MOVSX r64 byte memory changed flags");

    constexpr std::array<std::uint8_t, 5> extendedMemoryCode{0x45, 0x0F, 0xBE, 0x2F, 0xC3};
    const auto extendedMemoryDecoded =
        decoder.decodeBlock(extendedMemoryCode, rosa::guest::GuestAddress{0x7FF802D058FCULL});
    const auto extendedMemoryDestination =
        std::get<rosa::x86::RegisterOperand>(extendedMemoryDecoded[0].operands[0]);
    const auto extendedMemory =
        std::get<rosa::x86::MemoryOperand>(extendedMemoryDecoded[0].operands[1]);
    expect(extendedMemoryDecoded[0].opcode == rosa::x86::Opcode::MovsxRegMem &&
               extendedMemoryDecoded[0].length == 4 &&
               extendedMemoryDestination.reg == rosa::x86::Register::R13 &&
               extendedMemoryDestination.width == 32 &&
               extendedMemory.base == rosa::x86::Register::R15 && extendedMemory.width == 8,
           "extended MOVSX r32 byte memory decode differs");
    expect(rosa::debug::dumpX86(extendedMemoryDecoded).find("movsx r13d, byte [r15]") !=
               std::string::npos,
           "extended MOVSX r32 byte memory dump differs");
    const auto extendedMemoryBlock =
        translator.translate(extendedMemoryCode, rosa::guest::GuestAddress{0x7FF802D058FCULL}, 1);
    rosa::x86::X86State extendedMemoryState;
    extendedMemoryState.r15 = source.value;
    extendedMemoryState.r13 = UINT64_MAX;
    extendedMemoryState.rflags = 0xAD7;
    static_cast<void>(extendedMemoryBlock.execute(extendedMemoryState, &addressSpace));
    expectEqual(extendedMemoryState.r13, std::uint64_t{0xFFFFFF80},
                "extended MOVSX r32 byte memory result differs");
    expectEqual(extendedMemoryState.r15, source.value,
                "extended MOVSX r32 byte memory changed its base");
    expectEqual(extendedMemoryState.rflags, std::uint64_t{0xAD7},
                "extended MOVSX r32 byte memory changed flags");

    // Observed in libsqlite3: MOVSX ESI, byte [RBX+R12] with a REX.X-indexed SIB.
    constexpr std::array<std::uint8_t, 6> indexedCode{0x42, 0x0F, 0xBE, 0x34, 0x23, 0xC3};
    const auto indexedDecoded =
        decoder.decodeBlock(indexedCode, rosa::guest::GuestAddress{0x1000480BEULL});
    const auto indexedDestination =
        std::get<rosa::x86::RegisterOperand>(indexedDecoded[0].operands[0]);
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[1]);
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovsxRegMem &&
               indexedDecoded[0].length == 5 &&
               indexedDestination.reg == rosa::x86::Register::Rsi &&
               indexedDestination.width == 32 && indexedMemory.base == rosa::x86::Register::Rbx &&
               indexedMemory.index && *indexedMemory.index == rosa::x86::Register::R12 &&
               indexedMemory.scale == 1 && indexedMemory.width == 8 &&
               indexedMemory.displacement == 0,
           "REX.X MOVSX ESI, byte [RBX+R12] decode differs");
    expect(rosa::debug::dumpX86(indexedDecoded).find("movsx esi, byte [rbx+r12*1]") !=
               std::string::npos,
           "REX.X MOVSX dump differs");
    const auto indexedBlock =
        translator.translate(indexedCode, rosa::guest::GuestAddress{0x1000480BEULL});
    constexpr rosa::guest::GuestAddress indexedSource{0x8180};
    constexpr std::array<std::uint8_t, 1> indexedNegative{0xFF};
    addressSpace.writeBytes(indexedSource, indexedNegative);
    rosa::x86::X86State indexedState;
    indexedState.rbx = 0x8100;
    indexedState.r12 = 0x80;
    indexedState.rsi = 0x0123456789ABCDEFULL;
    indexedState.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(indexedState.rsi, std::uint64_t{0xFFFFFFFFULL},
                "REX.X MOVSX byte memory result differs");
    expectEqual(indexedState.rbx, std::uint64_t{0x8100}, "REX.X MOVSX changed its base");
    expectEqual(indexedState.r12, std::uint64_t{0x80}, "REX.X MOVSX changed its index");
    expectEqual(indexedState.rflags, std::uint64_t{0x8D7}, "REX.X MOVSX changed flags");

    rosa::guest::AddressSpace unmapped;
    rosa::x86::X86State faultState;
    faultState.rdi = source.value;
    faultState.rdx = 0x0123456789ABCDEFULL;
    faultState.rflags = 0xBD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &unmapped));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "MOVSX byte from unmapped guest memory did not fault");
    expectEqual(faultState.rdx, std::uint64_t{0x0123456789ABCDEFULL},
                "faulted MOVSX byte memory changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "faulted MOVSX byte memory changed flags");
}

void testMovsxGuestWordWithScaledIndexTo32BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x0F, 0xBF, 0x0C, 0x4A, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802D0F967ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovsxRegMem,
           "indexed word MOVSX opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "indexed word MOVSX length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32,
           "indexed word MOVSX destination differs");
    expect(memory.base == rosa::x86::Register::Rdx && memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 2 && memory.displacement == 0 && memory.width == 16,
           "indexed word MOVSX address differs");
    expect(rosa::debug::dumpX86(decoded).find("movsx ecx, word [rdx+rcx*2]") != std::string::npos,
           "indexed word MOVSX dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::uint64_t index = 0x20;
    constexpr rosa::guest::GuestAddress source{page.value + index * 2};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);

    addressSpace.writeBytes(source, std::array<std::uint8_t, 2>{0x23, 0x81});
    rosa::x86::X86State negativeState;
    negativeState.rdx = page.value;
    negativeState.rcx = index;
    negativeState.rflags = 0x8D7;
    static_cast<void>(block.execute(negativeState, &addressSpace));
    expectEqual(negativeState.rcx, std::uint64_t{0xFFFF8123},
                "negative indexed word MOVSX result differs");
    expectEqual(negativeState.rdx, page.value, "indexed word MOVSX changed its base");
    expectEqual(negativeState.rflags, std::uint64_t{0x8D7}, "indexed word MOVSX changed flags");

    addressSpace.writeBytes(source, std::array<std::uint8_t, 2>{0x34, 0x12});
    rosa::x86::X86State positiveState;
    positiveState.rdx = page.value;
    positiveState.rcx = index;
    positiveState.rflags = 0xAD7;
    static_cast<void>(block.execute(positiveState, &addressSpace));
    expectEqual(positiveState.rcx, std::uint64_t{0x1234},
                "positive indexed word MOVSX result differs");
    expectEqual(positiveState.rflags, std::uint64_t{0xAD7},
                "positive indexed word MOVSX changed flags");

    rosa::x86::X86State faultState;
    faultState.rdx = page.value + 1;
    faultState.rcx = 0x7FF;
    faultState.rflags = 0xBD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "cross-page indexed word MOVSX did not fault");
    expectEqual(faultState.rcx, std::uint64_t{0x7FF},
                "faulted indexed word MOVSX changed its destination");
    expectEqual(faultState.rdx, page.value + 1, "faulted indexed word MOVSX changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7},
                "faulted indexed word MOVSX changed flags");
}

void testMovzxGuestByteTo32BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x0F, 0xB6, 0x48, 0x2F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegMem,
           "MOVZX r32, byte [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "MOVZX r32, byte [memory] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32,
           "MOVZX byte destination differs");
    expect(memory.base == rosa::x86::Register::Rax && memory.width == 8 &&
               memory.displacement == 0x2F,
           "MOVZX byte memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("movzx ecx, byte [rax+0x2f]") != std::string::npos,
           "MOVZX byte dump differs");

    std::array<std::uint8_t, 0x40> data{};
    data[0x2F] = 0xA5;
    data[0x30] = 0xDE;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read, data);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8000;
    state.rcx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0xA5}, "MOVZX byte result did not zero-extend");
    expectEqual(state.rax, std::uint64_t{0x8000}, "MOVZX byte changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVZX byte changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x8000;
    faultState.rcx = 0x0123456789ABCDEFULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOVZX byte from unmapped guest memory did not fault");
    expectEqual(faultState.rcx, std::uint64_t{0x0123456789ABCDEFULL},
                "failed MOVZX byte changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed MOVZX byte changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(std::span<const std::uint8_t>{code}.first(3),
                                              rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated MOVZX byte displacement was accepted");
}

void testMovzxRipRelativeGuestByteTo32BitRegister() {
    constexpr std::array<std::uint8_t, 8> code{0x0F, 0xB6, 0x05, 0x6B, 0x03, 0x85, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802E6EC26ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8436BEF98ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF8436BE000ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegMem,
           "RIP-relative MOVZX byte opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative MOVZX byte length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0x4085036B,
           "RIP-relative MOVZX byte operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movzx eax, byte [rip+0x4085036b]") !=
               std::string::npos,
           "RIP-relative MOVZX byte dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 1>{0xA5});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0xA5}, "RIP-relative MOVZX byte did not zero-extend");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative MOVZX byte changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x0123456789ABCDEFULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOVZX byte from unmapped memory did not fault");
    expectEqual(faultState.rax, std::uint64_t{0x0123456789ABCDEFULL},
                "faulted RIP-relative MOVZX byte changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative MOVZX byte changed flags");
}

void testMovzxGuestByteWithSibTo64BitRegister() {
    constexpr std::array<std::uint8_t, 6> code{0x48, 0x0F, 0xB6, 0x04, 0x0F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegMem,
           "MOVZX r64, byte SIB opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "MOVZX r64, byte SIB length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64,
           "MOVZX byte SIB destination differs");
    expect(memory.base == rosa::x86::Register::Rdi && memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 1 && memory.displacement == 0 && memory.width == 8,
           "MOVZX byte SIB memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("movzx rax, byte [rdi+rcx*1]") != std::string::npos,
           "MOVZX byte SIB dump differs");

    std::array<std::uint8_t, 0x40> data{};
    data[0x2F] = 0xA5;
    data[0x30] = 0xDE;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read, data);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rdi = 0x8000;
    state.rcx = 0x2F;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0xA5}, "MOVZX r64 byte SIB result did not zero-extend");
    expectEqual(state.rdi, std::uint64_t{0x8000}, "MOVZX byte SIB changed its base");
    expectEqual(state.rcx, std::uint64_t{0x2F}, "MOVZX byte SIB changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVZX byte SIB changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x0123456789ABCDEFULL;
    faultState.rdi = 0x8000;
    faultState.rcx = 0x2F;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOVZX r64 byte SIB from unmapped memory did not fault");
    expectEqual(faultState.rax, std::uint64_t{0x0123456789ABCDEFULL},
                "failed MOVZX r64 byte SIB changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "failed MOVZX r64 byte SIB changed flags");
}

void testMovzx16BitRegisterTo32BitRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0xB7, 0xC7, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegReg, "MOVZX r32, r16 opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               source.reg == rosa::x86::Register::Rdi && source.width == 16,
           "MOVZX EAX, DI operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movzx eax, di") != std::string::npos,
           "MOVZX EAX, DI dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rdi = 0x112233445566BEEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xBEEF}, "MOVZX EAX, DI result did not zero-extend");
    expectEqual(state.rdi, std::uint64_t{0x112233445566BEEFULL},
                "MOVZX EAX, DI changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVZX EAX, DI changed flags");
}

void testMovzxGuestWordTo32BitRegister() {
    constexpr std::array<std::uint8_t, 7> code{0x41, 0x0F, 0xB7, 0x4C, 0x24, 0x04, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegMem,
           "MOVZX r32, word [memory] opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rcx,
           "MOVZX destination differs");
    expect(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]).base ==
               rosa::x86::Register::R12,
           "MOVZX no-index SIB base differs");
    constexpr std::array<std::uint8_t, 5> ignoredRexXCode{0x42, 0x0F, 0xB7, 0x03, 0xC3};
    const auto ignoredRexX =
        decoder.decodeBlock(ignoredRexXCode, rosa::guest::GuestAddress{0x2000});
    const auto ignoredRexXMemory = std::get<rosa::x86::MemoryOperand>(ignoredRexX[0].operands[1]);
    expect(ignoredRexXMemory.base == rosa::x86::Register::Rbx && !ignoredRexXMemory.index,
           "MOVZX treated REX.X as an index without a SIB");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> word{0x58, 0x54};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8004}, word);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r12 = 0x8000;
    state.rcx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0x5458}, "MOVZX word result or zero extension differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVZX changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r12 = 0x8000;
    faultState.rcx = 0x1234;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOVZX from unmapped guest memory did not fail");
    expectEqual(faultState.rcx, std::uint64_t{0x1234}, "failed MOVZX changed destination");
}

void testMovzxGuestWordWithScaledIndex() {
    constexpr std::array<std::uint8_t, 7> code{0x46, 0x0F, 0xB7, 0x74, 0x6B, 0x16, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegMem, "indexed MOVZX opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R14 && destination.width == 32,
           "indexed MOVZX destination differs");
    expect(memory.base == rosa::x86::Register::Rbx && memory.index == rosa::x86::Register::R13 &&
               memory.scale == 2 && memory.displacement == 0x16 && memory.width == 16,
           "indexed MOVZX memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("[rbx+r13*2+0x16]") != std::string::npos,
           "indexed MOVZX dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 4> sourceWithUpperSentinel{0xEF, 0xBE, 0xAD, 0xDE};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x811C}, sourceWithUpperSentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.r13 = 3;
    state.r14 = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0xBEEF}, "indexed MOVZX result or zero extension differs");
    expectEqual(state.rbx, std::uint64_t{0x8100}, "indexed MOVZX changed its base");
    expectEqual(state.r13, std::uint64_t{3}, "indexed MOVZX changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "indexed MOVZX changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.r14 = UINT64_MAX;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed MOVZX from unmapped guest memory did not fault");
    expectEqual(state.r14, UINT64_MAX, "failed indexed MOVZX changed its destination");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "failed indexed MOVZX changed flags");
}

void testMovsxdScaledGuestDword() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x63, 0x0C, 0x88, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovsxdRegMem,
           "MOVSXD scaled memory opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rax, "MOVSXD scaled base differs");
    expect(memory.index == rosa::x86::Register::Rcx, "MOVSXD scaled index differs");
    expectEqual(memory.scale, std::uint8_t{4}, "MOVSXD scaled factor differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8008}, 0xFFFFFFFC);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8000;
    state.rcx = 2;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0xFFFFFFFFFFFFFFFCULL},
                "MOVSXD sign-extended result differs");
    expectEqual(state.rax, std::uint64_t{0x8000}, "MOVSXD changed base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVSXD changed flags");
}

void testMovsxdNoIndexSibGuestDword() {
    // Observed in libsqlite3: MOVSXD RAX, dword [R12] with a no-index SIB.
    constexpr std::array<std::uint8_t, 5> code{0x49, 0x63, 0x04, 0x24, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000CDC4EULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovsxdRegMem,
           "MOVSXD no-index SIB opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "MOVSXD no-index SIB length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64,
           "MOVSXD no-index SIB destination differs");
    expect(memory.base == rosa::x86::Register::R12 && !memory.index && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 32,
           "MOVSXD no-index SIB memory operand differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(rosa::guest::GuestAddress{0x8100}, 0xFFFFFFFFU);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000CDC4EULL});
    rosa::x86::X86State state;
    state.rax = 0x0123456789ABCDEFULL;
    state.r12 = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0xFFFFFFFFFFFFFFFFULL},
                "MOVSXD no-index SIB result differs");
    expectEqual(state.r12, std::uint64_t{0x8100}, "MOVSXD no-index SIB changed base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVSXD no-index SIB changed flags");
}

void testMovsxdRipRelativeGuestDword() {
    constexpr std::array<std::uint8_t, 8> observedCode{0x4C, 0x63, 0x3D, 0x98,
                                                       0x38, 0xA4, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C71151ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8436B49F0ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovsxdRegMem,
           "RIP-relative MOVSXD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative MOVSXD length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R15 && destination.width == 64,
           "RIP-relative MOVSXD destination differs");
    expect(memory.ripRelative && memory.width == 32 && !memory.index &&
               memory.displacement == 0x40A43898,
           "RIP-relative MOVSXD source differs");
    expectEqual(observedRip.value + decoded[0].length + memory.displacement, target.value,
                "RIP-relative MOVSXD target differs");
    expect(rosa::debug::dumpX86(decoded).find("movsxd r15, dword [rip+0x40a43898]") !=
               std::string::npos,
           "RIP-relative MOVSXD dump differs");

    constexpr rosa::guest::GuestAddress targetPage{target.value &
                                                   ~(rosa::guest::guestPageSize - 1)};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 0xFFFFFFFCU);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip);
    rosa::x86::X86State state;
    state.r15 = 0x1122334455667788ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r15, std::uint64_t{0xFFFFFFFFFFFFFFFCULL},
                "RIP-relative MOVSXD sign extension differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative MOVSXD changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.r15 = 0x8877665544332211ULL;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "RIP-relative MOVSXD accepted an unmapped source");
    expectEqual(state.r15, std::uint64_t{0x8877665544332211ULL},
                "faulted RIP-relative MOVSXD changed its destination");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "faulted RIP-relative MOVSXD changed flags");
}

void testMovsxdRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x49, 0x63, 0xC7, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AEE25A});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovsxdRegReg, "MOVSXD register opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "MOVSXD register length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64,
           "MOVSXD register destination differs");
    expect(source.reg == rosa::x86::Register::R15 && source.width == 32,
           "MOVSXD register source differs");
    expect(rosa::debug::dumpX86(decoded).find("movsxd rax, r15d") != std::string::npos,
           "MOVSXD register dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AEE25A});
    rosa::x86::X86State negative;
    negative.r15 = 0xAABBCCDD80000001ULL;
    negative.rax = 0x1122334455667788ULL;
    negative.rflags = 0x8D7;
    static_cast<void>(block.execute(negative));
    expectEqual(negative.rax, std::uint64_t{0xFFFFFFFF80000001ULL},
                "MOVSXD register negative result differs");
    expectEqual(negative.r15, std::uint64_t{0xAABBCCDD80000001ULL},
                "MOVSXD register changed its source");
    expectEqual(negative.rflags, std::uint64_t{0x8D7}, "MOVSXD register changed flags");

    rosa::x86::X86State positive;
    positive.r15 = 0xAABBCCDD7FFFFFFFULL;
    positive.rax = UINT64_MAX;
    positive.rflags = 0xAD7;
    static_cast<void>(block.execute(positive));
    expectEqual(positive.rax, std::uint64_t{0x7FFFFFFF}, "MOVSXD register positive result differs");
    expectEqual(positive.r15, std::uint64_t{0xAABBCCDD7FFFFFFFULL},
                "positive MOVSXD register changed its source");
    expectEqual(positive.rflags, std::uint64_t{0xAD7}, "positive MOVSXD register changed flags");

    constexpr std::array<std::uint8_t, 4> aliasCode{0x48, 0x63, 0xC0, 0xC3};
    const auto aliasBlock = translator.translate(aliasCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State alias;
    alias.rax = 0xAABBCCDD80000001ULL;
    alias.rflags = 0x8D7;
    static_cast<void>(aliasBlock.execute(alias));
    expectEqual(alias.rax, std::uint64_t{0xFFFFFFFF80000001ULL},
                "aliased MOVSXD register result differs");
    expectEqual(alias.rflags, std::uint64_t{0x8D7}, "aliased MOVSXD register changed flags");
}

void testCdqeGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x48, 0x98, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Cdqe, "CDQE opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "CDQE length differs");
    expect(decoded[0].operands.empty(), "CDQE unexpectedly has explicit operands");
    expect(rosa::debug::dumpX86(decoded).find("cdqe") != std::string::npos, "CDQE dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State negative;
    negative.rax = 0xAAAAAAAA80000001ULL;
    negative.rflags = 0x8D7;
    static_cast<void>(block.execute(negative));
    expectEqual(negative.rax, std::uint64_t{0xFFFFFFFF80000001ULL}, "CDQE negative result differs");
    expectEqual(negative.rflags, std::uint64_t{0x8D7}, "CDQE changed flags");

    rosa::x86::X86State positive;
    positive.rax = 0xFFFFFFFF7FFFFFFFULL;
    positive.rflags = 0xAD7;
    static_cast<void>(block.execute(positive));
    expectEqual(positive.rax, std::uint64_t{0x7FFFFFFF}, "CDQE positive result differs");
    expectEqual(positive.rflags, std::uint64_t{0xAD7}, "CDQE changed flags");
}

void testCwdeGeneratedExecution() {
    // Observed in libsqlite3: bare CWDE (opcode 98 without REX).
    constexpr std::array<std::uint8_t, 2> code{0x98, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x100119273ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::Cwde, "CWDE opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{1}, "CWDE length differs");
    expect(decoded[0].operands.empty(), "CWDE unexpectedly has explicit operands");
    expect(rosa::debug::dumpX86(decoded).find("cwde") != std::string::npos, "CWDE dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x100119273ULL});
    rosa::x86::X86State negative;
    negative.rax = 0xAAAAAAAAFFFF8001ULL;
    negative.rflags = 0x8D7;
    static_cast<void>(block.execute(negative));
    expectEqual(negative.rax, std::uint64_t{0xFFFF8001ULL}, "CWDE negative result differs");
    expectEqual(negative.rflags, std::uint64_t{0x8D7}, "CWDE changed flags");

    rosa::x86::X86State positive;
    positive.rax = 0xFFFFFFFFFFFF0080ULL;
    positive.rflags = 0xAD7;
    static_cast<void>(block.execute(positive));
    expectEqual(positive.rax, std::uint64_t{0x80}, "CWDE positive result differs");
    expectEqual(positive.rflags, std::uint64_t{0xAD7}, "CWDE changed flags");
}

void testMovGuestMemoryToLegacy32BitRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x8B, 0x4E, 0x0C, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rcx,
           "legacy MOV r32, [base+disp8] destination differs");
    expectEqual(destination.width, std::uint8_t{32}, "legacy MOV r32, [base+disp8] width differs");

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

} // namespace

std::span<const TestCase> moveTests() {
    static const TestCase cases[]{
        {"MOV register to guest memory", testMovRegisterToGuestMemory},
        {"MOV high-byte register to guest memory", testMovHighByteRegisterToGuestMemory},
        {"MOV register to RIP-relative guest memory", testMovRegisterToRipRelativeGuestMemory},
        {"MOV RIP-relative guest dword to register", testMovRipRelativeGuestDwordToRegister},
        {"MOV 32-bit register to guest memory", testMov32BitRegisterToGuestMemory},
        {"MOV 64-bit register to scaled guest memory", testMov64BitRegisterToScaledGuestMemory},
        {"MOV low-byte register to guest memory", testMovLowByteRegisterToGuestMemory},
        {"MOV extended low byte to scaled guest memory", testMovExtendedLowByteToScaledGuestMemory},
        {"MOV low-byte register to RIP-relative guest memory", testMovLowByteRegisterToRipRelativeGuestMemory},
        {"MOV low-byte register to extended base", testMovLowByteRegisterToExtendedBase},
        {"MOV immediate to guest memory", testMovImmediateToGuestMemory},
        {"MOV 32-bit immediate to indexed guest memory", testMov32BitImmediateToIndexedGuestMemory},
        {"MOV immediate to guest stack", testMovImmediateToGuestStack},
        {"MOV immediate to RIP-relative guest memory", testMovImmediateToRipRelativeGuestMemory},
        {"MOV word immediate to RIP-relative guest memory", testMovWordImmediateToRipRelativeGuestMemory},
        {"MOV 32-bit immediate to guest memory", testMov32BitImmediateToGuestMemory},
        {"MOV byte immediate to guest memory", testMovByteImmediateToGuestMemory},
        {"MOV byte immediate to scaled guest memory", testMovByteImmediateToScaledGuestMemory},
        {"MOV byte immediate to RIP-relative guest memory", testMovByteImmediateToRipRelativeGuestMemory},
        {"MOV word immediate to guest memory", testMovWordImmediateToGuestMemory},
        {"MOV word register to guest memory", testMovWordRegisterToGuestMemory},
        {"MOV guest memory to register", testMovGuestMemoryToRegister},
        {"MOV guest GS memory to 32-bit register", testMovGuestGsMemoryTo32BitRegister},
        {"MOV guest GS memory with no-base scaled index", testMovGuestGsMemoryWithNoBaseScaledIndex},
        {"MOV immediate to guest GS memory", testMovImmediateToGuestGsMemory},
        {"MOV 64-bit register to guest GS memory", testMov64BitRegisterToGuestGsMemory},
        {"MOV guest memory to register with no-index SIB", testMovGuestMemoryToRegisterWithNoIndexSib},
        {"MOV guest memory to 32-bit register with scaled index", testMovGuestMemoryTo32BitRegisterWithScaledIndex},
        {"MOV guest memory to 16-bit register with index", testMovGuestMemoryTo16BitRegisterWithIndex},
        {"MOV guest memory to 32-bit register", testMovGuestMemoryTo32BitRegister},
        {"MOV guest memory to byte register", testMovGuestMemoryToByteRegister},
        {"MOV RIP-relative guest byte to register", testMovRipRelativeGuestByteToRegister},
        {"MOV guest memory to byte register with scaled index", testMovGuestMemoryToByteRegisterWithScaledIndex},
        {"MOVZX low-byte register to 32-bit register", testMovzxLowByteRegisterTo32BitRegister},
        {"MOVSX low-byte register to 32-bit register", testMovsxLowByteRegisterTo32BitRegister},
        {"MOVSX SIB byte to 32-bit register", testMovsxSibByteTo32BitRegister},
        {"MOVSX guest byte to 32-bit register", testMovsxGuestByteTo32BitRegister},
        {"MOVSX guest word with scaled index to 32-bit register", testMovsxGuestWordWithScaledIndexTo32BitRegister},
        {"MOVZX guest byte to 32-bit register", testMovzxGuestByteTo32BitRegister},
        {"MOVZX RIP-relative guest byte to 32-bit register", testMovzxRipRelativeGuestByteTo32BitRegister},
        {"MOVZX guest byte with SIB to 64-bit register", testMovzxGuestByteWithSibTo64BitRegister},
        {"MOVZX 16-bit register to 32-bit register", testMovzx16BitRegisterTo32BitRegister},
        {"MOVZX guest word to 32-bit register", testMovzxGuestWordTo32BitRegister},
        {"MOVZX guest word with scaled index", testMovzxGuestWordWithScaledIndex},
        {"MOVSXD scaled guest dword", testMovsxdScaledGuestDword},
        {"MOVSXD no-index SIB guest dword", testMovsxdNoIndexSibGuestDword},
        {"MOVSXD RIP-relative guest dword", testMovsxdRipRelativeGuestDword},
        {"MOVSXD register", testMovsxdRegister},
        {"CDQE generated execution", testCdqeGeneratedExecution},
        {"CWDE generated execution", testCwdeGeneratedExecution},
        {"legacy MOV guest memory to 32-bit register", testMovGuestMemoryToLegacy32BitRegister},
    };
    return cases;
}

} // namespace rosa::tests
