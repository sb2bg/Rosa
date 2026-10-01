#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testOrRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x09, 0xD0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegReg, "OR r64, r64 opcode differs");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x00000000ABCDEF01ULL;
    state.rdx = 0x1234567800000000ULL;
    state.rflags = UINT64_MAX;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x12345678ABCDEF01ULL}, "OR r64, r64 result differs");
    expectEqual(state.rdx, std::uint64_t{0x1234567800000000ULL}, "OR r64, r64 changed its source");
    constexpr auto expectedFlags = (UINT64_MAX & ~std::uint64_t{0x8D5}) | std::uint64_t{0x2};
    expectEqual(state.rflags, expectedFlags, "OR r64, r64 flags differ");
}

void testOr8BitRegistersGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x08, 0xC8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegReg, "OR r8, r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "OR r8, r8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8 &&
               source.reg == rosa::x86::Register::Rcx && source.width == 8,
           "OR AL, CL operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or al, cl") != std::string::npos,
           "OR AL, CL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1122334455667780ULL;
    state.rcx = 0x8877665544332201ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667781ULL},
                "OR AL, CL did not preserve upper RAX bytes");
    expectEqual(state.rcx, std::uint64_t{0x8877665544332201ULL}, "OR AL, CL changed its source");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 7U)},
                "OR AL, CL defined flags differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0x08, 0xE0, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "OR AL, AH was silently treated as a low-byte register form");
}

void testOr8BitRegisterIntoIndexedGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x40, 0x08, 0x3C, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF70004DB43ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrMemReg, "OR byte [memory], r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "OR byte [memory], r8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rax && memory.index &&
               *memory.index == rosa::x86::Register::Rdx && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 8 &&
               source.reg == rosa::x86::Register::Rdi && source.width == 8,
           "OR byte [rax+rdx], dil operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or byte [rax+rdx], dil") != std::string::npos,
           "OR byte [rax+rdx], dil dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8128};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array initialByte{std::uint8_t{0x80}};
    addressSpace.writeBytes(target, initialByte);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF70004DB43ULL});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("or_guest_memory.i8") !=
               std::string::npos,
           "OR byte memory did not lower through guest-memory IR");
    rosa::x86::X86State state;
    state.rax = 0x8100;
    state.rdx = 0x28;
    state.rdi = 0x1122334455667701ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0x81},
                "OR byte memory result differs");
    expectEqual(state.rax, std::uint64_t{0x8100}, "OR byte memory changed its base");
    expectEqual(state.rdx, std::uint64_t{0x28}, "OR byte memory changed its index");
    expectEqual(state.rdi, std::uint64_t{0x1122334455667701ULL},
                "OR byte memory changed its source");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x84},
                "OR byte memory defined flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    auto faultState = state;
    faultState.rax = target.value - 8;
    faultState.rdx = 8;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "OR byte unmapped guest memory did not fault");
    expectEqual(faultState.rdi, state.rdi, "faulted OR byte memory changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted OR byte memory changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    readOnlyAddressSpace.writeBytes(target, initialByte);
    expectEqual(readOnlyAddressSpace.protect(page, rosa::guest::guestPageSize,
                                             rosa::guest::Permission::Read),
                rosa::guest::ProtectResult::Success,
                "could not make OR byte test memory read-only");
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "OR byte read-only guest memory did not fault");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1).front(), std::uint8_t{0x80},
                "faulted OR byte memory changed read-only memory");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "read-only OR byte memory changed flags");
}

void testOr32BitRegisterIntoIndexedGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x09, 0x7C, 0x82, 0x28, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C6AD29ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::OrMemReg,
           "dword memory-destination OR opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "dword memory-destination OR length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdx && memory.index == rosa::x86::Register::Rax &&
               memory.scale == 4 && memory.displacement == 0x28 && memory.width == 32 &&
               source.reg == rosa::x86::Register::Rdi && source.width == 32,
           "or dword [rdx+rax*4+0x28], edi operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or dword [rdx+rax*4+0x28], edi") !=
               std::string::npos,
           "dword memory-destination OR dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8050};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 0x80000000U);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("or_guest_memory.i32") !=
               std::string::npos,
           "dword memory-destination OR did not lower through guest-memory IR");
    rosa::x86::X86State state;
    state.rdx = page.value;
    state.rax = 10;
    state.rdi = 0xAABBCCDD00000101ULL;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x80000101U},
                "dword memory-destination OR result differs");
    expectEqual(state.rdx, page.value, "dword memory-destination OR changed its base");
    expectEqual(state.rax, std::uint64_t{10}, "dword memory-destination OR changed its index");
    expectEqual(state.rdi, std::uint64_t{0xAABBCCDD00000101ULL},
                "dword memory-destination OR changed its source");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "dword memory-destination OR defined flags differ");

    constexpr rosa::guest::GuestAddress crossPage{0x1000};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(crossPage, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> tailBytes{0xA5, 0x5A};
    crossPageAddressSpace.writeBytes(rosa::guest::GuestAddress{0x1FFE}, tailBytes);
    rosa::x86::X86State faultState;
    faultState.rdx = 0x1FAE;
    faultState.rax = 10;
    faultState.rdi = 0xAABBCCDD00000101ULL;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page dword memory OR did not fault");
    expect(crossPageAddressSpace.readBytes(rosa::guest::GuestAddress{0x1FFE}, tailBytes.size()) ==
               std::vector<std::uint8_t>(tailBytes.begin(), tailBytes.end()),
           "faulted dword memory OR partially changed memory");
    expectEqual(faultState.rdx, std::uint64_t{0x1FAE}, "faulted dword memory OR changed its base");
    expectEqual(faultState.rax, std::uint64_t{10}, "faulted dword memory OR changed its index");
    expectEqual(faultState.rdi, std::uint64_t{0xAABBCCDD00000101ULL},
                "faulted dword memory OR changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "faulted dword memory OR changed flags");
}

void testOr8BitRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x41, 0x0A, 0x06, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF700081988ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegMem, "OR r8, byte [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "OR r8, byte [memory] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8 &&
               memory.base == rosa::x86::Register::R14 && memory.width == 8 &&
               memory.displacement == 0 && !memory.index,
           "OR AL, byte [r14] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or al, byte [r14]") != std::string::npos,
           "OR AL, byte [r14] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    std::array<std::uint8_t, rosa::guest::guestPageSize> bytes{};
    bytes[0] = 1;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(page, bytes.size(), rosa::guest::Permission::Read, bytes,
                            "read-only byte OR source");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF700081988ULL});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("load_guest.i8") !=
               std::string::npos,
           "OR byte load did not lower through guest-memory IR");
    rosa::x86::X86State state;
    state.rax = 0x1122334455667780ULL;
    state.r14 = page.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0x1122334455667781ULL},
                "OR byte load did not preserve upper RAX bytes");
    expectEqual(state.r14, page.value, "OR byte load changed its base register");
    expectEqual(addressSpace.readBytes(page, 1).front(), std::uint8_t{1},
                "OR byte load changed guest memory");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x84},
                "OR byte load defined flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0xAABBCCDDEEFF0080ULL;
    faultState.r14 = page.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "OR byte load accepted unmapped guest memory");
    expectEqual(faultState.rax, std::uint64_t{0xAABBCCDDEEFF0080ULL},
                "faulted OR byte load changed its destination");
    expectEqual(faultState.r14, page.value, "faulted OR byte load changed its base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted OR byte load changed flags");

    rosa::guest::AddressSpace inaccessibleAddressSpace;
    inaccessibleAddressSpace.mapSegment(page, bytes.size(), rosa::guest::Permission::None, bytes,
                                        "inaccessible byte OR source");
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &inaccessibleAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "OR byte load accepted non-readable guest memory");
    expectEqual(faultState.rax, std::uint64_t{0xAABBCCDDEEFF0080ULL},
                "permission-faulted OR byte load changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7},
                "permission-faulted OR byte load changed flags");

    constexpr std::array<std::uint8_t, 8> ripRelativeCode{0x44, 0x0A, 0x3D, 0x21,
                                                          0x39, 0xC7, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress ripRelativeRip{0x7FF802A39288ULL};
    constexpr rosa::guest::GuestAddress ripRelativeTarget{0x7FF8436ACBB0ULL};
    constexpr rosa::guest::GuestAddress ripRelativePage{0x7FF8436AC000ULL};
    const auto ripRelativeDecoded = decoder.decodeBlock(ripRelativeCode, ripRelativeRip);
    expect(ripRelativeDecoded[0].opcode == rosa::x86::Opcode::OrRegMem,
           "RIP-relative byte OR opcode differs");
    expectEqual(ripRelativeDecoded[0].length, std::uint8_t{7},
                "RIP-relative byte OR length differs");
    const auto ripRelativeDestination =
        std::get<rosa::x86::RegisterOperand>(ripRelativeDecoded[0].operands[0]);
    const auto ripRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(ripRelativeDecoded[0].operands[1]);
    expect(ripRelativeDestination.reg == rosa::x86::Register::R15 &&
               ripRelativeDestination.width == 8 && ripRelativeMemory.ripRelative &&
               !ripRelativeMemory.hasBase && !ripRelativeMemory.index &&
               ripRelativeMemory.width == 8 && ripRelativeMemory.displacement == 0x40C73921,
           "RIP-relative byte OR operands differ");
    expect(rosa::debug::dumpX86(ripRelativeDecoded).find("or r15b, byte [rip+0x40c73921]") !=
               std::string::npos,
           "RIP-relative byte OR dump differs");

    std::array<std::uint8_t, rosa::guest::guestPageSize> ripRelativeBytes{};
    ripRelativeBytes[ripRelativeTarget.value - ripRelativePage.value] = 0x0F;
    rosa::guest::AddressSpace ripRelativeAddressSpace;
    ripRelativeAddressSpace.mapSegment(ripRelativePage, ripRelativeBytes.size(),
                                       rosa::guest::Permission::Read, ripRelativeBytes,
                                       "read-only RIP-relative byte OR source");
    const auto ripRelativeBlock = translator.translate(ripRelativeCode, ripRelativeRip);
    rosa::x86::X86State ripRelativeState;
    ripRelativeState.r15 = UINT64_C(0x11223344556677F0);
    ripRelativeState.rflags = 0x8D7;
    static_cast<void>(ripRelativeBlock.execute(ripRelativeState, &ripRelativeAddressSpace));
    expectEqual(ripRelativeState.r15, UINT64_C(0x11223344556677FF),
                "RIP-relative byte OR changed upper destination bytes");
    expectEqual(ripRelativeState.rflags & definedLogicFlags, std::uint64_t{0x84},
                "RIP-relative byte OR defined flags differ");

    rosa::guest::AddressSpace unmappedRipRelativeAddressSpace;
    rosa::x86::X86State ripRelativeFaultState;
    ripRelativeFaultState.r15 = UINT64_C(0x11223344556677F0);
    ripRelativeFaultState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(
            ripRelativeBlock.execute(ripRelativeFaultState, &unmappedRipRelativeAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative byte OR accepted unmapped memory");
    expectEqual(ripRelativeFaultState.r15, UINT64_C(0x11223344556677F0),
                "faulted RIP-relative byte OR changed its destination");
    expectEqual(ripRelativeFaultState.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative byte OR changed flags");
}

void testOr32BitRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x0B, 0x75, 0xD4, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AE2DA1ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegMem,
           "OR r32, dword [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "OR r32, dword [memory] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R14 && destination.width == 32 &&
               memory.base == rosa::x86::Register::Rbp && memory.width == 32 &&
               memory.displacement == -0x2C && !memory.index,
           "OR r14d, dword [rbp-0x2c] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or r14d, dword [rbp-0x2c]") != std::string::npos,
           "OR r14d, dword [rbp-0x2c] dump differs");

    constexpr std::array<std::uint8_t, 7> ripRelativeCode{0x0B, 0x05, 0x19, 0xDA, 0xC1, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress ripRelativeRip{0x7FF802C758C9ULL};
    constexpr rosa::guest::GuestAddress ripRelativePage{0x7FF843893000ULL};
    constexpr rosa::guest::GuestAddress ripRelativeTarget{0x7FF8438932E8ULL};
    const auto ripRelativeDecoded = decoder.decodeBlock(ripRelativeCode, ripRelativeRip);
    expect(ripRelativeDecoded[0].opcode == rosa::x86::Opcode::OrRegMem,
           "RIP-relative dword OR opcode differs");
    expectEqual(ripRelativeDecoded[0].length, std::uint8_t{6},
                "RIP-relative dword OR length differs");
    const auto ripRelativeDestination =
        std::get<rosa::x86::RegisterOperand>(ripRelativeDecoded[0].operands[0]);
    const auto ripRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(ripRelativeDecoded[0].operands[1]);
    expect(ripRelativeDestination.reg == rosa::x86::Register::Rax &&
               ripRelativeDestination.width == 32 && ripRelativeMemory.ripRelative &&
               ripRelativeMemory.displacement == 0x40C1DA19 && ripRelativeMemory.width == 32,
           "OR eax, dword [rip+disp32] operands differ");
    expect(rosa::debug::dumpX86(ripRelativeDecoded).find("or eax, dword [rip+0x40c1da19]") !=
               std::string::npos,
           "RIP-relative dword OR dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress base{0x8100};
    constexpr rosa::guest::GuestAddress target{0x80D4};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::uint64_t originalMemory = 0xDEADBEEF00000001ULL;
    addressSpace.writeU64(target, originalMemory);
    expectEqual(
        addressSpace.protect(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read),
        rosa::guest::ProtectResult::Success, "could not make dword OR source read-only");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AE2DA1ULL}, 1);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("load_guest.i32") !=
               std::string::npos,
           "OR dword load did not lower through guest-memory IR");
    rosa::x86::X86State state;
    state.r14 = 0xAAAAAAAA80000000ULL;
    state.rbp = base.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0x80000001}, "OR r32 memory result did not zero-extend");
    expectEqual(state.rbp, base.value, "OR r32 memory changed its base");
    expectEqual(addressSpace.readU64(target), originalMemory, "OR r32 memory changed guest memory");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x80},
                "OR r32 memory defined flags differ");

    rosa::guest::AddressSpace ripRelativeAddressSpace;
    ripRelativeAddressSpace.mapAnonymous(ripRelativePage, rosa::guest::guestPageSize,
                                         rosa::guest::Permission::Read |
                                             rosa::guest::Permission::Write);
    ripRelativeAddressSpace.writeU32(ripRelativeTarget, 0x4);
    expectEqual(ripRelativeAddressSpace.protect(ripRelativePage, rosa::guest::guestPageSize,
                                                rosa::guest::Permission::Read),
                rosa::guest::ProtectResult::Success,
                "could not make RIP-relative dword OR source read-only");
    const auto ripRelativeBlock = translator.translate(ripRelativeCode, ripRelativeRip);
    rosa::x86::X86State ripRelativeState;
    ripRelativeState.rax = 0xFFFFFFFF00000020ULL;
    ripRelativeState.rflags = 0x8D7;
    static_cast<void>(ripRelativeBlock.execute(ripRelativeState, &ripRelativeAddressSpace));
    expectEqual(ripRelativeState.rax, std::uint64_t{0x24},
                "RIP-relative dword OR result did not zero-extend");
    expectEqual(ripRelativeState.rflags, std::uint64_t{0x6}, "RIP-relative dword OR flags differ");
    expectEqual(ripRelativeAddressSpace.readU32(ripRelativeTarget), std::uint32_t{0x4},
                "RIP-relative dword OR changed its source memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r14 = 0xBBBBBBBB80000000ULL;
    faultState.rbp = base.value;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "OR r32 load accepted unmapped guest memory");
    expectEqual(faultState.r14, std::uint64_t{0xBBBBBBBB80000000ULL},
                "faulted OR r32 load changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted OR r32 load changed flags");
}

void testOr64BitRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x0B, 0x45, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A91850ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegMem,
           "OR r64, qword [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "OR r64, qword [memory] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 64 &&
               memory.base == rosa::x86::Register::Rbp && memory.width == 64 &&
               memory.displacement == 0x10 && !memory.index,
           "OR rax, qword [rbp+0x10] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or rax, qword [rbp+0x10]") != std::string::npos,
           "OR rax, qword [rbp+0x10] dump differs");

    constexpr std::array<std::uint8_t, 4> regCode{0x48, 0x0B, 0xC0, 0xC3};
    const auto regDecoded = decoder.decodeBlock(regCode, rosa::guest::GuestAddress{0x1000});
    expect(regDecoded[0].opcode == rosa::x86::Opcode::OrRegReg, "OR r64, r64 opcode differs");
    expectEqual(regDecoded[0].length, std::uint8_t{3}, "OR r64, r64 length differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress base{0x8100};
    constexpr rosa::guest::GuestAddress target{0x8110};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::uint64_t originalMemory = 0x0F0F0F0F00FF00FFULL;
    addressSpace.writeU64(target, originalMemory);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A91850ULL}, 1);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("load_guest.i64") !=
               std::string::npos,
           "OR qword load did not lower through guest-memory IR");
    rosa::x86::X86State state;
    state.rax = 0xF0F0F0F0FF00FF00ULL;
    state.rbp = base.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0xFFFFFFFFFFFFFFFFULL},
                "OR r64 memory result differs");
    expectEqual(state.rbp, base.value, "OR r64 memory changed its base");
    expectEqual(addressSpace.readU64(target), originalMemory, "OR r64 memory changed guest memory");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x84},
                "OR r64 memory defined flags differ");
}

void testOr16BitRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x44, 0x0B, 0x7B, 0x10, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802D1A234ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegMem,
           "OR r16, word [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "OR r16, word [memory] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R15 && destination.width == 16 &&
               memory.base == rosa::x86::Register::Rbx && memory.width == 16 &&
               memory.displacement == 0x10,
           "OR r15w, word [rbx+0x10] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or r15w, word [rbx+0x10]") != std::string::npos,
           "OR r15w, word [rbx+0x10] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress base{0x8100};
    constexpr std::array<std::uint8_t, 2> source{0x01, 0x80};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(rosa::guest::GuestAddress{base.value + 0x10}, source);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip, 1);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("load_guest.i16") !=
               std::string::npos,
           "OR word load did not lower through guest-memory IR");

    rosa::x86::X86State state;
    state.rbx = base.value;
    state.r15 = UINT64_C(0x1122334455660002);
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r15, UINT64_C(0x1122334455668003),
                "OR r16 memory result did not preserve upper bits");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x84},
                "OR r16 memory defined flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbx = base.value;
    faultState.r15 = UINT64_C(0xAABBCCDDEEFF0002);
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "OR r16 load accepted unmapped guest memory");
    expectEqual(faultState.r15, UINT64_C(0xAABBCCDDEEFF0002),
                "faulted OR r16 load changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted OR r16 load changed flags");
}

void testOrImmediateIntoGuestByteMemory() {
    constexpr std::array<std::uint8_t, 9> code{0x41, 0x80, 0x8E, 0xD8, 0x00,
                                               0x00, 0x00, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF70004E0F9ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrMemImm,
           "OR byte [memory], imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "OR byte [memory], imm8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R14 && memory.displacement == 0xD8 &&
               memory.width == 8 && immediate.value == 1 && immediate.width == 8,
           "OR byte [r14+0xd8], 1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or byte [r14+0xd8], 0x1") != std::string::npos,
           "OR byte [r14+0xd8], 1 dump differs");
    constexpr std::array<std::uint8_t, 6> negativeDisplacementCode{0x41, 0x80, 0x4E,
                                                                   0xF8, 0x01, 0xC3};
    const auto negativeDecoded =
        decoder.decodeBlock(negativeDisplacementCode, rosa::guest::GuestAddress{0x2000});
    expectEqual(std::get<rosa::x86::MemoryOperand>(negativeDecoded[0].operands[0]).displacement,
                std::int64_t{-8}, "OR byte immediate disp8 was not sign-extended");

    // Observed in libsystem_info: OR byte [r12+0x14], 1 with a no-index SIB.
    constexpr std::array<std::uint8_t, 7> sibCode{0x41, 0x80, 0x4C, 0x24,
                                                 0x14, 0x01, 0xC3};
    const auto sibDecoded =
        decoder.decodeBlock(sibCode, rosa::guest::GuestAddress{0x7FF802E86253ULL});
    expect(sibDecoded[0].opcode == rosa::x86::Opcode::OrMemImm,
           "SIB byte OR opcode differs");
    expectEqual(sibDecoded[0].length, std::uint8_t{6}, "SIB byte OR length differs");
    const auto sibMemory = std::get<rosa::x86::MemoryOperand>(sibDecoded[0].operands[0]);
    const auto sibImmediate = std::get<rosa::x86::ImmediateOperand>(sibDecoded[0].operands[1]);
    expect(sibMemory.base == rosa::x86::Register::R12 && sibMemory.displacement == 0x14 &&
               sibMemory.width == 8 && !sibMemory.index && sibImmediate.value == 1,
           "OR byte [r12+0x14], 1 operands differ");
    expect(rosa::debug::dumpX86(sibDecoded).find("or byte [r12+0x14], 0x1") != std::string::npos,
           "OR byte [r12+0x14], 1 dump differs");

    constexpr std::array<std::uint8_t, 8> ripRelativeCode{0x80, 0x0D, 0xEE, 0xEE,
                                                          0xA3, 0x40, 0x34, 0xC3};
    constexpr rosa::guest::GuestAddress ripRelativeRip{0x7FF802C75873ULL};
    constexpr rosa::guest::GuestAddress ripRelativePage{0x7FF8436B4000ULL};
    constexpr rosa::guest::GuestAddress ripRelativeTarget{0x7FF8436B4768ULL};
    const auto ripRelativeDecoded = decoder.decodeBlock(ripRelativeCode, ripRelativeRip);
    expect(ripRelativeDecoded[0].opcode == rosa::x86::Opcode::OrMemImm,
           "RIP-relative byte OR opcode differs");
    expectEqual(ripRelativeDecoded[0].length, std::uint8_t{7},
                "RIP-relative byte OR length differs");
    const auto ripRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(ripRelativeDecoded[0].operands[0]);
    expect(ripRelativeMemory.ripRelative && ripRelativeMemory.displacement == 0x40A3EEEE &&
               ripRelativeMemory.width == 8,
           "RIP-relative byte OR memory operand differs");
    expect(rosa::debug::dumpX86(ripRelativeDecoded).find("or byte [rip+0x40a3eeee], 0x34") !=
               std::string::npos,
           "RIP-relative byte OR dump differs");

    rosa::guest::AddressSpace ripRelativeAddressSpace;
    ripRelativeAddressSpace.mapAnonymous(ripRelativePage, rosa::guest::guestPageSize,
                                         rosa::guest::Permission::Read |
                                             rosa::guest::Permission::Write);
    constexpr std::array ripRelativeInitial{std::uint8_t{0x01}};
    ripRelativeAddressSpace.writeBytes(ripRelativeTarget, ripRelativeInitial);
    const rosa::dbt::Translator translator;
    const auto ripRelativeBlock = translator.translate(ripRelativeCode, ripRelativeRip);
    rosa::x86::X86State ripRelativeState;
    ripRelativeState.rflags = 0x8D7;
    static_cast<void>(ripRelativeBlock.execute(ripRelativeState, &ripRelativeAddressSpace));
    expectEqual(ripRelativeAddressSpace.readBytes(ripRelativeTarget, 1).front(), std::uint8_t{0x35},
                "RIP-relative byte OR result differs");
    expectEqual(ripRelativeState.rflags, std::uint64_t{0x6}, "RIP-relative byte OR flags differ");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x80D8};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array initialByte{std::uint8_t{0x40}};
    addressSpace.writeBytes(target, initialByte);
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF70004E0F9ULL});
    rosa::x86::X86State state;
    state.r14 = page.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0x41},
                "OR byte immediate memory result differs");
    expectEqual(state.r14, page.value, "OR byte immediate changed its base");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x4},
                "OR byte immediate defined flags differ");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    readOnlyAddressSpace.writeBytes(target, initialByte);
    expectEqual(readOnlyAddressSpace.protect(page, rosa::guest::guestPageSize,
                                             rosa::guest::Permission::Read),
                rosa::guest::ProtectResult::Success,
                "could not make immediate OR memory read-only");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "OR byte immediate read-only memory did not fault");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1).front(), std::uint8_t{0x40},
                "faulted immediate OR changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "faulted immediate OR changed flags");

    const auto sibBlock =
        translator.translate(sibCode, rosa::guest::GuestAddress{0x7FF802E86253ULL});
    constexpr std::array sibInitialByte{std::uint8_t{0x40}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8014}, sibInitialByte);
    rosa::x86::X86State sibState;
    sibState.r12 = page.value;
    sibState.rflags = 0x8D7;
    static_cast<void>(sibBlock.execute(sibState, &addressSpace));
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0x8014}, 1).front(),
                std::uint8_t{0x41}, "SIB byte OR result differs");
    expectEqual(sibState.r12, page.value, "SIB byte OR changed its base");
    expectEqual(sibState.rflags & definedLogicFlags, std::uint64_t{0x4},
                "SIB byte OR defined flags differ");

    // Observed in libsqlite3: OR dword [rbp-0x60], 0x4001 (opcode 81 /1).
    constexpr std::array<std::uint8_t, 8> fullCode{0x81, 0x4D, 0xA0, 0x01,
                                                  0x40, 0x00, 0x00, 0xC3};
    const auto fullDecoded =
        decoder.decodeBlock(fullCode, rosa::guest::GuestAddress{0x1000F3281ULL});
    expect(fullDecoded[0].opcode == rosa::x86::Opcode::OrMemImm,
           "dword OR opcode differs");
    expectEqual(fullDecoded[0].length, std::uint8_t{7}, "dword OR length differs");
    const auto fullMemory = std::get<rosa::x86::MemoryOperand>(fullDecoded[0].operands[0]);
    const auto fullImmediate = std::get<rosa::x86::ImmediateOperand>(fullDecoded[0].operands[1]);
    expect(fullMemory.base == rosa::x86::Register::Rbp && fullMemory.displacement == -96 &&
               fullMemory.width == 32 && !fullMemory.index &&
               fullImmediate.value == 0x4001 && fullImmediate.width == 32,
           "OR dword [rbp-0x60], 0x4001 operands differ");
    expect(rosa::debug::dumpX86(fullDecoded).find("or dword [rbp-0x60], 0x4001") !=
               std::string::npos,
           "OR dword [rbp-0x60], 0x4001 dump differs");
    const auto fullBlock =
        translator.translate(fullCode, rosa::guest::GuestAddress{0x1000F3281ULL});
    constexpr rosa::guest::GuestAddress fullTarget{0x8200};
    addressSpace.writeU32(fullTarget, 0x0001);
    rosa::x86::X86State fullState;
    fullState.rbp = fullTarget.value + 96;
    fullState.rflags = 0x8D7;
    static_cast<void>(fullBlock.execute(fullState, &addressSpace));
    expectEqual(addressSpace.readU32(fullTarget), std::uint32_t{0x4001},
                "OR dword immediate memory result differs");
    expectEqual(fullState.rbp, fullTarget.value + 96, "OR dword immediate changed its base");
    expectEqual(fullState.rflags & definedLogicFlags, std::uint64_t{0},
                "OR dword immediate defined flags differ");
}

void testOrShortImmediateIntoGuestWordMemory() {
    // Observed in libsqlite3: OR word [rax+0x72], 1 (66 83 /1).
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x83, 0x48, 0x72, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000A3509ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrMemImm, "word OR opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "word OR length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rax && memory.displacement == 0x72 &&
               memory.width == 16 && !memory.index && immediate.value == 1 &&
               immediate.width == 8,
           "OR word [rax+0x72], 1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or word [rax+0x72], 0x1") != std::string::npos,
           "OR word [rax+0x72], 1 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8072};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> initial{0x00, 0x00};
    addressSpace.writeBytes(target, initial);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000A3509ULL});
    rosa::x86::X86State state;
    state.rax = page.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expect(addressSpace.readBytes(target, 2) == std::vector<std::uint8_t>({0x01, 0x00}),
           "OR word immediate stored the wrong result");
    expectEqual(state.rax, page.value, "OR word immediate changed its base");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0},
                "OR word immediate defined flags differ");
}

void testOrFullImmediateIntoGuestWordMemory() {
    // Observed in libsqlite3: OR word [rbx+0x14], 0x202 (66 81 /1).
    constexpr std::array<std::uint8_t, 7> code{0x66, 0x81, 0x4B, 0x14,
                                               0x02, 0x02, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10008BF8BULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrMemImm, "word OR full opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "word OR full length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx && memory.displacement == 0x14 &&
               memory.width == 16 && !memory.index && immediate.value == 0x202 &&
               immediate.width == 16,
           "OR word [rbx+0x14], 0x202 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or word [rbx+0x14], 0x202") != std::string::npos,
           "OR word [rbx+0x14], 0x202 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8114};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> initial{0x00, 0x00};
    addressSpace.writeBytes(target, initial);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10008BF8BULL});
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expect(addressSpace.readBytes(target, 2) == std::vector<std::uint8_t>({0x02, 0x02}),
           "OR word full immediate stored the wrong result");
    expectEqual(state.rbx, std::uint64_t{0x8100}, "OR word full immediate changed its base");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0},
                "OR word full immediate defined flags differ");
}

void testAddDwordShortImmediateGuestMemory() {
    // Observed in libxpc: ADD dword [r15+0x1c], 0x10 with REX.B.
    constexpr std::array<std::uint8_t, 6> code{0x41, 0x83, 0x47, 0x1C, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802B4D50CULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddMemImm,
           "ADD dword [memory], imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "ADD dword [memory], imm8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R15 && memory.displacement == 0x1C &&
               memory.width == 32 && immediate.value == 0x10 && immediate.width == 8,
           "ADD dword [r15+0x1c], 0x10 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("add dword [r15+0x1c], 0x10") != std::string::npos,
           "ADD dword [r15+0x1c], 0x10 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x801C};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 0x7FFFFFF0);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802B4D50CULL});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("add_guest_memory.i32") !=
               std::string::npos,
           "ADD dword short did not lower through 32-bit guest-memory IR");
    rosa::x86::X86State state;
    state.r15 = page.value;
    state.rflags = 0x2;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x80000000},
                "ADD dword short memory result differs");
    expectEqual(state.r15, page.value, "ADD dword short changed its base");
    constexpr std::uint64_t definedFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedFlags,
                std::uint64_t{(1U << 2U) | (1U << 7U) | (1U << 11U)},
                "ADD dword short defined flags differ");
}

void testOrDwordShortImmediateGuestMemory() {
    // OR dword [r15+0x1c], 0x10 with REX.B.
    constexpr std::array<std::uint8_t, 6> code{0x41, 0x83, 0x4F, 0x1C, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10000});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrMemImm,
           "OR dword [memory], imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "OR dword [memory], imm8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R15 && memory.displacement == 0x1C &&
               memory.width == 32 && immediate.value == 0x10 && immediate.width == 8,
           "OR dword [r15+0x1c], 0x10 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or dword [r15+0x1c], 0x10") != std::string::npos,
           "OR dword [r15+0x1c], 0x10 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x801C};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 0x00FF00);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("or_guest_memory.i32") !=
               std::string::npos,
           "OR dword short did not lower through 32-bit guest-memory IR");
    rosa::x86::X86State state;
    state.r15 = page.value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x00FF10},
                "OR dword short memory result differs");
    expectEqual(state.r15, page.value, "OR dword short changed its base");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x0},
                "OR dword short defined flags differ");
}

void testOrShortImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x83, 0xC8, 0xFF, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegImm, "OR r64, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value, UINT64_MAX,
                "OR imm8 was not sign-extended");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1234;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, UINT64_MAX, "OR r64, imm8 result differs");
    expectEqual(state.rflags, std::uint64_t{0x86}, "OR r64, imm8 flags differ");

    constexpr std::array<std::uint8_t, 4> legacyCode{0x83, 0xC9, 0x04, 0xC3};
    const auto legacyDecoded = decoder.decodeBlock(legacyCode, rosa::guest::GuestAddress{0x2000});
    expectEqual(std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[0]).width,
                std::uint8_t{32}, "OR r32, imm8 width differs");
    const auto legacyBlock = translator.translate(legacyCode, rosa::guest::GuestAddress{0x2000});
    state.rcx = 0xAAAAAAAA00000002ULL;
    state.rflags = 0x8D7;
    static_cast<void>(legacyBlock.execute(state));
    expectEqual(state.rcx, std::uint64_t{6}, "OR r32, imm8 result did not zero-extend");
    expectEqual(state.rflags, std::uint64_t{0x6}, "OR r32, imm8 flags differ");

    constexpr std::array<std::uint8_t, 7> wideImmediateCode{0x81, 0xC9, 0x00, 0x00,
                                                            0x04, 0x00, 0xC3};
    const auto wideImmediateDecoded =
        decoder.decodeBlock(wideImmediateCode, rosa::guest::GuestAddress{0x2800});
    expect(wideImmediateDecoded[0].opcode == rosa::x86::Opcode::OrRegImm,
           "OR r32, imm32 opcode differs");
    expect(rosa::debug::dumpX86(wideImmediateDecoded).find("or ecx, 0x40000") != std::string::npos,
           "OR r32, imm32 dump differs");
    const auto wideImmediateBlock =
        translator.translate(wideImmediateCode, rosa::guest::GuestAddress{0x2800});
    state.rcx = 0xAAAAAAAA00000002ULL;
    state.rflags = 0x8D7;
    static_cast<void>(wideImmediateBlock.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x40002}, "OR r32, imm32 result did not zero-extend");
    expectEqual(state.rflags, std::uint64_t{0x2}, "OR r32, imm32 flags differ");

    constexpr std::array<std::uint8_t, 6> accumulatorCode{0x0D, 0x00, 0x00, 0x0F, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress accumulatorRip{0x7FF802CEA1DAULL};
    const auto accumulatorDecoded = decoder.decodeBlock(accumulatorCode, accumulatorRip);
    expect(accumulatorDecoded[0].opcode == rosa::x86::Opcode::OrRegImm,
           "OR EAX, imm32 opcode differs");
    expectEqual(accumulatorDecoded[0].length, std::uint8_t{5}, "OR EAX, imm32 length differs");
    const auto accumulatorDestination =
        std::get<rosa::x86::RegisterOperand>(accumulatorDecoded[0].operands[0]);
    const auto accumulatorImmediate =
        std::get<rosa::x86::ImmediateOperand>(accumulatorDecoded[0].operands[1]);
    expect(accumulatorDestination.reg == rosa::x86::Register::Rax &&
               accumulatorDestination.width == 32 && accumulatorImmediate.value == 0xF0000 &&
               accumulatorImmediate.width == 32,
           "OR EAX, 0xf0000 operands differ");
    expect(rosa::debug::dumpX86(accumulatorDecoded).find("or eax, 0xf0000") != std::string::npos,
           "OR EAX, 0xf0000 dump differs");
    const auto accumulatorBlock = translator.translate(accumulatorCode, accumulatorRip);
    rosa::x86::X86State accumulatorState;
    accumulatorState.rax = 0xFFFFFFFF00000000ULL;
    accumulatorState.rflags = 0x8D7;
    static_cast<void>(accumulatorBlock.execute(accumulatorState));
    expectEqual(accumulatorState.rax, std::uint64_t{0xF0000},
                "OR EAX, imm32 result did not zero-extend");
    expectEqual(accumulatorState.rflags, std::uint64_t{0x6}, "OR EAX, imm32 flags differ");

    constexpr std::array<std::uint8_t, 7> qwordAccumulatorCode{0x48, 0x0D, 0x80, 0x40,
                                                               0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress qwordAccumulatorRip{0x7FF802C7848BULL};
    const auto qwordAccumulatorDecoded =
        decoder.decodeBlock(qwordAccumulatorCode, qwordAccumulatorRip);
    expect(qwordAccumulatorDecoded[0].opcode == rosa::x86::Opcode::OrRegImm,
           "OR RAX, imm32 opcode differs");
    expectEqual(qwordAccumulatorDecoded[0].length, std::uint8_t{6}, "OR RAX, imm32 length differs");
    const auto qwordAccumulatorDestination =
        std::get<rosa::x86::RegisterOperand>(qwordAccumulatorDecoded[0].operands[0]);
    const auto qwordAccumulatorImmediate =
        std::get<rosa::x86::ImmediateOperand>(qwordAccumulatorDecoded[0].operands[1]);
    expect(qwordAccumulatorDestination.reg == rosa::x86::Register::Rax &&
               qwordAccumulatorDestination.width == 64 &&
               qwordAccumulatorImmediate.value == 0x4080 && qwordAccumulatorImmediate.width == 32,
           "OR RAX, 0x4080 operands differ");
    expect(rosa::debug::dumpX86(qwordAccumulatorDecoded).find("or rax, 0x4080") !=
               std::string::npos,
           "OR RAX, 0x4080 dump differs");
    const auto qwordAccumulatorBlock =
        translator.translate(qwordAccumulatorCode, qwordAccumulatorRip);
    rosa::x86::X86State qwordAccumulatorState;
    qwordAccumulatorState.rax = 0x100100000ULL;
    qwordAccumulatorState.rflags = 0x8D7;
    static_cast<void>(qwordAccumulatorBlock.execute(qwordAccumulatorState));
    expectEqual(qwordAccumulatorState.rax, std::uint64_t{0x100104080ULL},
                "OR RAX, 0x4080 result differs");
    expectEqual(qwordAccumulatorState.rflags, std::uint64_t{0x2}, "OR RAX, 0x4080 flags differ");

    constexpr std::array<std::uint8_t, 7> negativeAccumulatorCode{0x48, 0x0D, 0x00, 0x00,
                                                                  0x00, 0x80, 0xC3};
    const auto negativeAccumulatorDecoded =
        decoder.decodeBlock(negativeAccumulatorCode, qwordAccumulatorRip);
    expectEqual(
        std::get<rosa::x86::ImmediateOperand>(negativeAccumulatorDecoded[0].operands[1]).value,
        std::uint64_t{0xFFFFFFFF80000000ULL}, "OR RAX, imm32 did not sign-extend its immediate");
    const auto negativeAccumulatorBlock =
        translator.translate(negativeAccumulatorCode, qwordAccumulatorRip);
    rosa::x86::X86State negativeAccumulatorState;
    negativeAccumulatorState.rflags = 0x8D7;
    static_cast<void>(negativeAccumulatorBlock.execute(negativeAccumulatorState));
    expectEqual(negativeAccumulatorState.rax, std::uint64_t{0xFFFFFFFF80000000ULL},
                "OR RAX, negative imm32 result differs");
    expectEqual(negativeAccumulatorState.rflags, std::uint64_t{0x86},
                "OR RAX, negative imm32 flags differ");

    constexpr std::array<std::uint8_t, 5> extendedCode{0x41, 0x80, 0xC8, 0x0F, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x3000});
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::OrRegImm,
           "OR extended r8, imm8 opcode differs");
    expectEqual(extendedDecoded[0].length, std::uint8_t{4}, "OR extended r8, imm8 length differs");
    const auto extendedDestination =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedImmediate =
        std::get<rosa::x86::ImmediateOperand>(extendedDecoded[0].operands[1]);
    expect(extendedDestination.reg == rosa::x86::Register::R8 && extendedDestination.width == 8 &&
               extendedImmediate.width == 8 && extendedImmediate.value == 0x0F,
           "OR r8b, imm8 operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("or r8b, 0xf") != std::string::npos,
           "OR r8b, imm8 dump differs");

    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State extendedState;
    extendedState.r8 = 0x1122334455667780ULL;
    extendedState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.r8, std::uint64_t{0x112233445566778FULL},
                "OR r8b immediate did not preserve upper register bytes");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(extendedState.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "OR r8b immediate defined flags differ");

    constexpr std::array<std::uint8_t, 5> zeroCode{0x41, 0x80, 0xC8, 0x00, 0xC3};
    const auto zeroBlock = translator.translate(zeroCode, rosa::guest::GuestAddress{0x4000});
    extendedState.r8 = 0x1122334455667700ULL;
    extendedState.rflags = 0x8D7;
    static_cast<void>(zeroBlock.execute(extendedState));
    expectEqual(extendedState.r8, std::uint64_t{0x1122334455667700ULL},
                "OR r8b zero immediate changed the byte");
    expectEqual(extendedState.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "OR r8b zero defined flags differ");
}

void testOr32BitRegistersGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x09, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegReg, "OR r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "OR r32, r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0xAAAAAAAA000000F0ULL;
    state.rax = 0xBBBBBBBB0000000FULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFF}, "OR r32, r32 result or zero extension differs");
    expectEqual(state.rax, std::uint64_t{0xBBBBBBBB0000000FULL}, "OR r32, r32 changed source");
    expectEqual(state.rflags, std::uint64_t{0x6}, "OR r32, r32 flags differ");
}

void testOr16BitRegistersGeneratedExecution() {
    // Observed in libsqlite3: OR CX, AX with an operand-size override (66 09).
    constexpr std::array<std::uint8_t, 4> code{0x66, 0x09, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10007A042ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegReg, "OR r16, r16 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "OR r16, r16 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 16 &&
               source.reg == rosa::x86::Register::Rax && source.width == 16,
           "OR cx, ax operands differ");
    expect(rosa::debug::dumpX86(decoded).find("or cx, ax") != std::string::npos,
           "OR cx, ax dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10007A042ULL});
    rosa::x86::X86State state;
    state.rcx = 0xAAAAAAAA0000F0F0ULL;
    state.rax = 0xBBBBBBBB00000F0FULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xAAAAAAAA0000FFFFULL},
                "OR r16, r16 result or upper preservation differs");
    expectEqual(state.rax, std::uint64_t{0xBBBBBBBB00000F0FULL}, "OR r16, r16 changed source");
    expectEqual(state.rflags, std::uint64_t{0x86}, "OR r16, r16 flags differ");
}

void testXor32BitRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x31, 0xF6, 0x45, 0x31, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegReg, "legacy XOR r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "legacy XOR r32 width differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[1].operands[0]).reg ==
               rosa::x86::Register::R8,
           "REX XOR r8d destination differs");

    const rosa::dbt::Translator translator;
    const auto zeroEsi = translator.translate(code, rosa::guest::GuestAddress{0x1000}, 1);
    const auto zeroR8 =
        translator.translate(std::span(code).subspan(2), rosa::guest::GuestAddress{0x1002}, 1);
    rosa::x86::X86State state;
    state.rsi = UINT64_MAX;
    state.r8 = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(zeroEsi.execute(state));
    expectEqual(state.rsi, std::uint64_t{0}, "XOR esi, esi did not clear RSI");
    expectEqual(state.rflags, std::uint64_t{0x46}, "XOR esi, esi flags differ");
    static_cast<void>(zeroR8.execute(state));
    expectEqual(state.r8, std::uint64_t{0}, "XOR r8d, r8d did not clear R8");
    expectEqual(state.rflags, std::uint64_t{0x46}, "XOR r8d, r8d flags differ");

    constexpr std::array<std::uint8_t, 3> reverseEncodingCode{0x33, 0xC0, 0xC3};
    const auto reverseDecoded =
        decoder.decodeBlock(reverseEncodingCode, rosa::guest::GuestAddress{0x7FF802A18075ULL});
    expect(reverseDecoded[0].opcode == rosa::x86::Opcode::XorRegReg &&
               reverseDecoded[0].length == 2,
           "opcode 33 XOR r32, r32 opcode or length differs");
    const auto reverseDestination =
        std::get<rosa::x86::RegisterOperand>(reverseDecoded[0].operands[0]);
    const auto reverseSource = std::get<rosa::x86::RegisterOperand>(reverseDecoded[0].operands[1]);
    expect(reverseDestination.reg == rosa::x86::Register::Rax && reverseDestination.width == 32 &&
               reverseSource.reg == rosa::x86::Register::Rax && reverseSource.width == 32,
           "opcode 33 XOR eax, eax operands differ");
    expect(rosa::debug::dumpX86(reverseDecoded).find("xor eax, eax") != std::string::npos,
           "opcode 33 XOR eax, eax dump differs");

    const auto reverseBlock =
        translator.translate(reverseEncodingCode, rosa::guest::GuestAddress{0x7FF802A18075ULL});
    rosa::x86::X86State reverseState;
    reverseState.rax = UINT64_MAX;
    reverseState.rflags = 0x8D7;
    static_cast<void>(reverseBlock.execute(reverseState));
    expectEqual(reverseState.rax, std::uint64_t{0},
                "opcode 33 XOR eax, eax did not zero-extend its result");
    expectEqual(reverseState.rflags, std::uint64_t{0x46}, "opcode 33 XOR eax, eax flags differ");
}

void testXor8BitRegistersGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> observedCode{0x30, 0xC1, // xor cl, al
                                                       0x34, 0x01, // xor al, 1
                                                       0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802C751A6ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, observedRip);
    expectEqual(decoded.size(), std::size_t{3},
                "observed byte XOR sequence instruction count differs");
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegReg, "XOR CL, AL opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "XOR CL, AL length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 8 &&
               source.reg == rosa::x86::Register::Rax && source.width == 8,
           "XOR CL, AL operands differ");
    expect(rosa::debug::dumpX86(decoded).find("xor cl, al") != std::string::npos,
           "XOR CL, AL dump differs");

    const rosa::dbt::Translator translator;
    const auto first = translator.translate(observedCode, observedRip, 1);
    rosa::x86::X86State state;
    state.rax = 0x1122334455667701ULL;
    state.rcx = 0x8877665544332200ULL;
    state.rflags = 0x8D7;
    static_cast<void>(first.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL}, "XOR CL, AL changed its source");
    expectEqual(state.rcx, std::uint64_t{0x8877665544332201ULL},
                "XOR CL, AL changed bytes above CL");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0},
                "XOR CL, AL defined flags differ");

    const auto sequence = translator.translate(observedCode, observedRip);
    state.rax = 0x1122334455667701ULL;
    state.rcx = 0x8877665544332200ULL;
    state.rflags = 0x8D7;
    static_cast<void>(sequence.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667700ULL},
                "observed XOR sequence changed bytes above AL");
    expectEqual(state.rcx, std::uint64_t{0x8877665544332201ULL},
                "observed XOR sequence produced the wrong CL");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "observed XOR sequence final flags differ");

    constexpr std::array<std::uint8_t, 4> extendedCode{0x45, 0x30, 0xC8, 0xC3}; // xor r8b, r9b
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x2000});
    expect(std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]).reg ==
                   rosa::x86::Register::R8 &&
               std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]).reg ==
                   rosa::x86::Register::R9,
           "REX XOR r8b, r9b operands differ");
}

void testXor32BitRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0x33, 0x04, 0x24, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegMem, "XOR r32, [memory] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R12, "XOR no-index SIB base differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8000}, 0x45545F5F);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xAAAAAAAA45545F5FULL;
    state.r12 = 0x8000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0}, "XOR r32, [memory] result or zero extension differs");
    expectEqual(state.r12, std::uint64_t{0x8000}, "XOR changed memory base");
    expectEqual(state.rflags, std::uint64_t{0x46}, "XOR memory flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x45545F5F;
    faultState.r12 = 0x8000;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "XOR from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{0x45545F5F}, "failed XOR memory changed destination");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "failed XOR memory changed flags");

    constexpr std::array<std::uint8_t, 3> legacyCode{0x33, 0x08, 0xC3};
    const auto legacyDecoded = decoder.decodeBlock(legacyCode, rosa::guest::GuestAddress{0x2000});
    expect(legacyDecoded[0].opcode == rosa::x86::Opcode::XorRegMem,
           "legacy XOR r32, [memory] opcode differs");
    const auto legacyBlock = translator.translate(legacyCode, rosa::guest::GuestAddress{0x2000});
    state.rax = 0x8000;
    state.rcx = 0xAAAAAAAA45545F5FULL;
    state.rflags = 0x8D7;
    static_cast<void>(legacyBlock.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0}, "legacy XOR r32, [memory] result differs");
    expectEqual(state.rflags, std::uint64_t{0x46}, "legacy XOR r32, [memory] flags differ");

    constexpr std::array<std::uint8_t, 5> indexedCode{0x42, 0x33, 0x04, 0x8A, 0xC3};
    const auto indexedDecoded =
        decoder.decodeBlock(indexedCode, rosa::guest::GuestAddress{0x7FF800036668ULL});
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::XorRegMem,
           "indexed XOR r32, [memory] opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{4},
                "indexed XOR r32, [memory] length differs");
    const auto indexedDestination =
        std::get<rosa::x86::RegisterOperand>(indexedDecoded[0].operands[0]);
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[1]);
    expect(indexedDestination.reg == rosa::x86::Register::Rax && indexedDestination.width == 32 &&
               indexedMemory.base == rosa::x86::Register::Rdx &&
               indexedMemory.index == rosa::x86::Register::R9 && indexedMemory.scale == 4 &&
               indexedMemory.displacement == 0 && indexedMemory.width == 32,
           "XOR eax, dword [rdx+r9*4] operands differ");
    expect(rosa::debug::dumpX86(indexedDecoded).find("xor eax, [rdx+r9*4]") != std::string::npos,
           "indexed XOR r32 dump differs");

    constexpr std::array<std::uint8_t, 4> indexedValue{0x00, 0xFF, 0xFF, 0x00};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8100}, indexedValue);
    const auto indexedBlock =
        translator.translate(indexedCode, rosa::guest::GuestAddress{0x7FF800036668ULL});
    state.rax = 0xAABBCCDDFFFF0000ULL;
    state.rdx = 0x8000;
    state.r9 = 0x40;
    state.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0xFF00FF00},
                "indexed XOR r32 result or zero extension differs");
    expectEqual(state.rdx, std::uint64_t{0x8000}, "indexed XOR changed memory base");
    expectEqual(state.r9, std::uint64_t{0x40}, "indexed XOR changed memory index");
    constexpr std::uint64_t definedLogicFlags = 0x1U | 0x4U | 0x40U | 0x80U | 0x800U;
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x84},
                "indexed XOR r32 defined flags differ");

    rosa::x86::X86State indexedFaultState;
    indexedFaultState.rax = 0xAABBCCDDFFFF0000ULL;
    indexedFaultState.rdx = 0x9000;
    indexedFaultState.r9 = 0x40;
    indexedFaultState.rflags = 0x8D7;
    bool indexedRejected = false;
    try {
        static_cast<void>(indexedBlock.execute(indexedFaultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        indexedRejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(indexedRejected, "indexed XOR from unmapped guest memory did not fail");
    expectEqual(indexedFaultState.rax, std::uint64_t{0xAABBCCDDFFFF0000ULL},
                "failed indexed XOR changed destination");
    expectEqual(indexedFaultState.rflags, std::uint64_t{0x8D7}, "failed indexed XOR changed flags");
}

void testXorByteRegisterFromScaledGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x32, 0x04, 0x0F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF80003665EULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegMem,
           "XOR r8, byte [scaled memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "XOR r8, byte [scaled memory] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8 &&
               memory.base == rosa::x86::Register::Rdi &&
               memory.index == rosa::x86::Register::Rcx && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 8,
           "XOR AL, byte [RDI+RCX] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("xor al, [rdi+rcx]") != std::string::npos,
           "XOR AL, byte [RDI+RCX] dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> memoryValue{0x0F};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8030}, memoryValue);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF80003665EULL});
    rosa::x86::X86State state;
    state.rax = 0x11223344556677FFULL;
    state.rdi = 0x8000;
    state.rcx = 0x30;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0x11223344556677F0ULL},
                "XOR byte memory result or upper-register preservation differs");
    expectEqual(state.rdi, std::uint64_t{0x8000}, "XOR byte memory changed its base");
    expectEqual(state.rcx, std::uint64_t{0x30}, "XOR byte memory changed its index");
    constexpr std::uint64_t definedLogicFlags = 0x1U | 0x4U | 0x40U | 0x80U | 0x800U;
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x84},
                "XOR byte memory defined logic flags differ");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0x8030}, 1).front(),
                std::uint8_t{0x0F}, "XOR byte memory changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0xAABBCCDDEEFF00FFULL;
    faultState.rdi = 0x8000;
    faultState.rcx = 0x30;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "XOR byte from unmapped guest memory did not fault");
    expectEqual(faultState.rax, std::uint64_t{0xAABBCCDDEEFF00FFULL},
                "failed XOR byte memory changed destination");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "failed XOR byte memory changed flags");
}

void testXorByteRegisterFromDisplacedGuestMemory() {
    // Observed in libsqlite3: XOR DL, byte [RBP-0x88] (opcode 32 with disp32).
    constexpr std::array<std::uint8_t, 7> code{0x32, 0x95, 0x78, 0xFF,
                                               0xFF, 0xFF, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10011B4DEULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegMem,
           "XOR r8, byte [displaced memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6},
                "XOR r8, byte [displaced memory] length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 8 &&
               memory.base == rosa::x86::Register::Rbp && !memory.index &&
               memory.displacement == -136 && memory.width == 8,
           "XOR DL, byte [RBP-0x88] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("xor dl, [rbp-0x88]") != std::string::npos,
           "XOR DL, byte [RBP-0x88] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> memoryValue{0x0F};
    addressSpace.writeBytes(target, memoryValue);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10011B4DEULL});
    rosa::x86::X86State state;
    state.rdx = 0xAABBCCDD123456F0ULL;
    state.rbp = target.value + 136;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdx, std::uint64_t{0xAABBCCDD123456FFULL},
                "XOR byte displaced memory result differs");
    expectEqual(state.rbp, target.value + 136, "XOR byte displaced memory changed its base");
    constexpr std::uint64_t definedLogicFlags = 0x1U | 0x4U | 0x40U | 0x80U | 0x800U;
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x84},
                "XOR byte displaced memory flags differ");
}

void testXor64BitRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x33, 0x08, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegMem, "XOR r64, [memory] opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{64}, "XOR r64, [memory] width differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8100}, 0x44454B4E494C5F5FULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8100;
    state.rcx = 0x44454B4E494C5F5FULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0}, "XOR r64, [memory] result differs");
    expectEqual(state.rflags, std::uint64_t{0x46}, "XOR r64, [memory] flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rcx = 0x1122334455667788ULL;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "XOR r64 from unmapped guest memory did not fault");
    expectEqual(state.rcx, std::uint64_t{0x1122334455667788ULL},
                "failed XOR r64 changed destination");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "failed XOR r64 changed flags");
}

void testXor64BitRegisterFromRipGuestMemory() {
    // Observed in CoreFoundation under an Objective-C fixture: XOR r14, [RIP+disp32].
    constexpr std::array<std::uint8_t, 8> code{0x4C, 0x33, 0x35, 0x41, 0xC6,
                                               0x1D, 0x3D, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802EB7758ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegMem,
           "RIP-relative XOR r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative XOR r64 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R14 && destination.width == 64,
           "RIP-relative XOR r14 destination differs");
    expect(memory.ripRelative && !memory.hasBase && !memory.index &&
               memory.displacement == 0x3D1DC641 && memory.width == 64,
           "RIP-relative XOR r64 memory operand differs");
    expectEqual(observedRip.value + decoded[0].length + memory.displacement,
                std::uint64_t{0x7FF840093DA0ULL}, "RIP-relative XOR r64 target differs");
    expect(rosa::debug::dumpX86(decoded).find("xor r14, [rip+0x3d1dc641]") != std::string::npos,
           "RIP-relative XOR r64 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0xFFFFFFFFFFFFFFFFULL);
    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 8> executeCode{0x4C, 0x33, 0x35, 0xF9, 0x70,
                                                      0x00, 0x00, 0xC3};
    const auto block = translator.translate(executeCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0xFFFFFFFFFFFFFFFFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0}, "RIP-relative XOR r64 result differs");
    expectEqual(state.rflags, std::uint64_t{0x46}, "RIP-relative XOR r64 flags differ");
}

void testXor64BitRegisterFromIndexedGuestMemoryWithDisplacement() {
    constexpr std::array<std::uint8_t, 6> code{0x48, 0x33, 0x74, 0x07, 0x06, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AC2457ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegMem, "indexed XOR r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "indexed XOR r64 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 64 &&
               memory.base == rosa::x86::Register::Rdi &&
               memory.index == rosa::x86::Register::Rax && memory.scale == 1 &&
               memory.displacement == 6 && memory.width == 64,
           "XOR rsi, [rdi+rax+6] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("xor rsi, [rdi+rax+0x6]") != std::string::npos,
           "indexed XOR r64 dump differs");

    constexpr rosa::guest::GuestAddress memoryPage{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8106};
    constexpr std::uint64_t value = 0x0123456789ABCDEFULL;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, value);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AC2457ULL});
    rosa::x86::X86State state;
    state.rdi = memoryPage.value;
    state.rax = 0x100;
    state.rsi = value;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rsi, std::uint64_t{0}, "indexed XOR r64 result differs");
    expectEqual(state.rdi, memoryPage.value, "indexed XOR r64 changed its base");
    expectEqual(state.rax, std::uint64_t{0x100}, "indexed XOR r64 changed its index");
    constexpr std::uint64_t definedLogicFlags = 0x1U | 0x4U | 0x40U | 0x80U | 0x800U;
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0x44},
                "indexed XOR r64 defined flags differ");
    expectEqual(addressSpace.readU64(target), value, "indexed XOR r64 changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rsi = 0x1122334455667788ULL;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed XOR r64 from unmapped memory did not fault");
    expectEqual(state.rsi, std::uint64_t{0x1122334455667788ULL},
                "failed indexed XOR r64 changed its destination");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "failed indexed XOR r64 changed flags");
}

void testXor32BitRegisterImmediate() {
    constexpr std::array<std::uint8_t, 7> code{0x81, 0xF1, 0x58, 0x54, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegImm, "XOR r32, imm32 opcode differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0xAAAAAAAA00005458ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0}, "XOR r32, imm32 result or zero extension differs");
    expectEqual(state.rflags, std::uint64_t{0x46}, "XOR r32, imm32 flags differ");

    constexpr std::array<std::uint8_t, 6> accumulatorCode{0x35, 0x58, 0x54, 0x00, 0x00, 0xC3};
    const auto accumulatorDecoded =
        decoder.decodeBlock(accumulatorCode, rosa::guest::GuestAddress{0x2000});
    expect(accumulatorDecoded[0].opcode == rosa::x86::Opcode::XorRegImm,
           "XOR EAX, imm32 opcode differs");
    const auto accumulatorBlock =
        translator.translate(accumulatorCode, rosa::guest::GuestAddress{0x2000});
    state.rax = 0xAAAAAAAA00005458ULL;
    state.rflags = 0x8D7;
    static_cast<void>(accumulatorBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0}, "XOR EAX, imm32 did not zero-extend result");
    expectEqual(state.rflags, std::uint64_t{0x46}, "XOR EAX, imm32 flags differ");

    constexpr std::array<std::uint8_t, 4> shortCode{0x83, 0xF0, 0x07, 0xC3};
    const auto shortDecoded = decoder.decodeBlock(shortCode, rosa::guest::GuestAddress{0x3000});
    expect(shortDecoded[0].opcode == rosa::x86::Opcode::XorRegImm, "XOR r32, imm8 opcode differs");
    expectEqual(shortDecoded[0].length, std::uint8_t{3}, "XOR r32, imm8 length differs");
    const auto shortDestination = std::get<rosa::x86::RegisterOperand>(shortDecoded[0].operands[0]);
    const auto shortImmediate = std::get<rosa::x86::ImmediateOperand>(shortDecoded[0].operands[1]);
    expect(shortDestination.reg == rosa::x86::Register::Rax && shortDestination.width == 32,
           "XOR r32, imm8 destination differs");
    expect(shortImmediate.width == 8 && shortImmediate.value == 7,
           "XOR r32, imm8 immediate differs");
    expect(rosa::debug::dumpX86(shortDecoded).find("xor eax, 0x7") != std::string::npos,
           "XOR r32, imm8 dump differs");
    const auto shortBlock = translator.translate(shortCode, rosa::guest::GuestAddress{0x3000});
    state.rax = 0xAAAAAAAA00000007ULL;
    state.rflags = 0x8D7;
    static_cast<void>(shortBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0}, "XOR r32, imm8 did not zero-extend its result");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "XOR r32, imm8 defined flags differ");

    constexpr std::array<std::uint8_t, 4> negativeShortCode{0x83, 0xF0, 0xFF, 0xC3};
    const auto negativeShortDecoded =
        decoder.decodeBlock(negativeShortCode, rosa::guest::GuestAddress{0x4000});
    expectEqual(std::get<rosa::x86::ImmediateOperand>(negativeShortDecoded[0].operands[1]).value,
                UINT64_MAX, "XOR r32, imm8 was not sign-extended");
}

void testXor64BitAccumulatorImmediate() {
    constexpr std::array<std::uint8_t, 7> observedCode{0x48, 0x35, 0x49, 0x54, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observedCode, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegImm, "XOR RAX, imm32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{64}, "XOR RAX, imm32 width differs");

    const rosa::dbt::Translator translator;
    const auto observedBlock =
        translator.translate(observedCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x5449;
    state.rflags = 0x8D7;
    static_cast<void>(observedBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0}, "XOR RAX, positive imm32 result differs");
    expectEqual(state.rflags, std::uint64_t{0x46}, "XOR RAX, positive imm32 flags differ");

    constexpr std::array<std::uint8_t, 7> negativeCode{0x48, 0x35, 0x00, 0x00, 0x00, 0x80, 0xC3};
    const auto negativeBlock =
        translator.translate(negativeCode, rosa::guest::GuestAddress{0x2000});
    state.rax = 0;
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFFFFFFF80000000ULL},
                "XOR RAX, imm32 did not sign-extend its immediate");
    expectEqual(state.rflags, std::uint64_t{0x86}, "XOR RAX, negative imm32 flags differ");
}

void testXor8BitAccumulatorImmediate() {
    constexpr std::array<std::uint8_t, 3> code{0x34, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegImm, "XOR AL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "XOR AL, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8,
           "XOR AL, imm8 destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{1}, "XOR AL, imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("xor al, 0x1") != std::string::npos,
           "XOR AL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1122334455667700ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL},
                "XOR AL, imm8 did not preserve upper RAX bytes");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0},
                "XOR AL, imm8 nonzero defined flags differ");

    state.rax = 0xFFEEDDCCBBAA5581ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFEEDDCCBBAA5580ULL},
                "XOR AL, imm8 sign result changed upper RAX bytes");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "XOR AL, imm8 sign defined flags differ");
}

void testOr8BitAccumulatorImmediate() {
    // Observed in libsqlite3: OR AL, 0x2 (opcode 0C).
    constexpr std::array<std::uint8_t, 3> code{0x0C, 0x02, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10011ADE6ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegImm, "OR AL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "OR AL, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8,
           "OR AL, imm8 destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{2}, "OR AL, imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("or al, 0x2") != std::string::npos,
           "OR AL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x10011ADE6ULL});
    rosa::x86::X86State state;
    state.rax = 0x1122334455667701ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667703ULL},
                "OR AL, imm8 did not preserve upper RAX bytes");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "OR AL, imm8 nonzero defined flags differ");

    state.rax = 0xFFEEDDCCBBAA5580ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFEEDDCCBBAA5582ULL},
                "OR AL, imm8 sign result changed upper RAX bytes");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 7U)},
                "OR AL, imm8 sign defined flags differ");
}

void testXor8BitRegisterImmediate() {
    constexpr std::array<std::uint8_t, 4> code{0x80, 0xF1, 0x01, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802AB6BFDULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegImm, "XOR CL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "XOR CL, imm8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 8,
           "XOR CL, imm8 destination differs");
    expect(immediate.width == 8 && immediate.value == 1, "XOR CL, imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("xor cl, 0x1") != std::string::npos,
           "XOR CL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rcx = 0x1122334455667700ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x1122334455667701ULL},
                "XOR CL, imm8 changed upper RCX bytes");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0},
                "XOR CL, imm8 defined flags differ");

    constexpr std::array<std::uint8_t, 4> extendedCode{0x41, 0x80, 0xF4, 0xFF};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x2000}, 1);
    const auto extendedDestination =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    expect(extendedDestination.reg == rosa::x86::Register::R12 && extendedDestination.width == 8,
           "XOR R12B, imm8 destination differs");
}

} // namespace

std::span<const TestCase> logicTests() {
    static const TestCase cases[]{
        {"OR register generated execution", testOrRegisterGeneratedExecution},
        {"OR 8-bit registers generated execution", testOr8BitRegistersGeneratedExecution},
        {"OR 8-bit register from guest memory", testOr8BitRegisterFromGuestMemory},
        {"OR 32-bit register from guest memory", testOr32BitRegisterFromGuestMemory},
        {"OR 64-bit register from guest memory", testOr64BitRegisterFromGuestMemory},
        {"OR 16-bit register from guest memory", testOr16BitRegisterFromGuestMemory},
        {"OR 8-bit register into indexed guest memory", testOr8BitRegisterIntoIndexedGuestMemory},
        {"OR 32-bit register into indexed guest memory", testOr32BitRegisterIntoIndexedGuestMemory},
        {"OR immediate into guest byte memory", testOrImmediateIntoGuestByteMemory},
        {"OR short immediate into guest word memory", testOrShortImmediateIntoGuestWordMemory},
        {"OR full immediate into guest word memory", testOrFullImmediateIntoGuestWordMemory},
        {"OR short immediate generated execution", testOrShortImmediateGeneratedExecution},
        {"OR dword short immediate guest memory", testOrDwordShortImmediateGuestMemory},
        {"ADD dword short immediate guest memory", testAddDwordShortImmediateGuestMemory},
        {"OR 32-bit registers generated execution", testOr32BitRegistersGeneratedExecution},
        {"OR 16-bit registers generated execution", testOr16BitRegistersGeneratedExecution},
        {"XOR 32-bit register generated execution", testXor32BitRegisterGeneratedExecution},
        {"XOR 8-bit registers generated execution", testXor8BitRegistersGeneratedExecution},
        {"XOR 32-bit register from guest memory", testXor32BitRegisterFromGuestMemory},
        {"XOR byte register from scaled guest memory", testXorByteRegisterFromScaledGuestMemory},
        {"XOR byte register from displaced guest memory", testXorByteRegisterFromDisplacedGuestMemory},
        {"XOR 64-bit register from guest memory", testXor64BitRegisterFromGuestMemory},
        {"XOR 64-bit register from RIP memory", testXor64BitRegisterFromRipGuestMemory},
        {"XOR 64-bit register from indexed guest memory with displacement", testXor64BitRegisterFromIndexedGuestMemoryWithDisplacement},
        {"XOR 32-bit register immediate", testXor32BitRegisterImmediate},
        {"XOR 64-bit accumulator immediate", testXor64BitAccumulatorImmediate},
        {"XOR 8-bit accumulator immediate", testXor8BitAccumulatorImmediate},
        {"OR 8-bit accumulator immediate", testOr8BitAccumulatorImmediate},
        {"XOR 8-bit register immediate", testXor8BitRegisterImmediate},
    };
    return cases;
}

} // namespace rosa::tests
