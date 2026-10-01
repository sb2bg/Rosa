#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testXorpsRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x57, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorpsRegReg, "XORPS xmm, xmm opcode differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::XmmRegister::Xmm0,
           "XORPS destination differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::XmmRegister::Xmm1,
           "XORPS source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.xmm[1] = {.low = 0x1111111111111111ULL, .high = 0x2222222222222222ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x1032547698BADCFEULL}, "XORPS low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0xDCFE98BA54761032ULL}, "XORPS high lane differs");
    expectEqual(state.xmm[1].low, std::uint64_t{0x1111111111111111ULL}, "XORPS changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "XORPS changed flags");
}

void testXorpsGuestMemoryGeneratedExecution() {
    // Observed in sqlite: XORPS xmm0, [RIP+disp32].
    constexpr std::array<std::uint8_t, 8> code{0x0F, 0x57, 0x05, 0x75, 0x2A,
                                              0x07, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x10014E804ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorpsRegMem, "XORPS memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "XORPS memory length differs");
    const auto destination =
        std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0, "XORPS memory destination differs");
    expect(memory.ripRelative && !memory.hasBase && memory.width == 128 &&
               memory.displacement == 0x072A75,
           "XORPS memory source differs");
    expect(rosa::debug::dumpX86(decoded).find("xorps xmm0, [rip+0x72a75]") != std::string::npos,
           "XORPS memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    constexpr rosa::guest::GuestAddress syntheticRip{0x7F00};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x0123456789ABCDEFULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{target.value + 8}, 0xFEDCBA9876543210ULL);
    const rosa::dbt::Translator translator;
    // Execute at a synthetic RIP whose computed target stays in the page.
    constexpr std::array<std::uint8_t, 8> executableCode{0x0F, 0x57, 0x05, 0xF9,
                                                         0x01, 0x00, 0x00, 0xC3};
    const auto block = translator.translate(executableCode, syntheticRip);
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x1111111111111111ULL, .high = 0x2222222222222222ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x1032547698BADCFEULL},
                "XORPS memory low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0xDCFE98BA54761032ULL},
                "XORPS memory high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "XORPS memory changed flags");
}

void testXorpdRegisterGeneratedExecution() {
    // Observed in sqlite: XORPD xmm2, xmm2.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x57, 0xD2, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x100046E60ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorpdRegReg, "XORPD xmm, xmm opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "XORPD length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::XmmRegister::Xmm2,
           "XORPD destination differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::XmmRegister::Xmm2,
           "XORPD source differs");
    expect(rosa::debug::dumpX86(decoded).find("xorpd xmm2, xmm2") != std::string::npos,
           "XORPD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x100046E60ULL});
    rosa::x86::X86State state;
    state.xmm[2] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[2].low, std::uint64_t{0}, "XORPD low lane differs");
    expectEqual(state.xmm[2].high, std::uint64_t{0}, "XORPD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "XORPD changed flags");
}

void testPxorRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0xEF, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PxorRegReg, "PXOR xmm, xmm opcode differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.xmm[0] = {.low = UINT64_MAX, .high = 0x0123456789ABCDEFULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0}, "PXOR low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0}, "PXOR high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PXOR changed flags");
}

void testPxorExtendedRegisterGeneratedExecution() {
    // Observed in libsqlite3: PXOR XMM8, XMM8 with REX.RB (66 45 0F EF C0).
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x45, 0x0F, 0xEF, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000FE0F6ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::PxorRegReg,
           "extended PXOR xmm, xmm opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "extended PXOR length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::XmmRegister::Xmm8,
           "extended PXOR destination differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::XmmRegister::Xmm8,
           "extended PXOR source differs");
    expect(rosa::debug::dumpX86(decoded).find("pxor xmm8, xmm8") != std::string::npos,
           "extended PXOR dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000FE0F6ULL});
    rosa::x86::X86State state;
    state.xmm[8] = {.low = UINT64_MAX, .high = 0x0123456789ABCDEFULL};
    state.xmm[0] = {.low = UINT64_MAX, .high = UINT64_MAX};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[8].low, std::uint64_t{0}, "extended PXOR low lane differs");
    expectEqual(state.xmm[8].high, std::uint64_t{0}, "extended PXOR high lane differs");
    expectEqual(state.xmm[0].low, UINT64_MAX, "extended PXOR clobbered xmm0");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "extended PXOR changed flags");
}

void testPxorGuestMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 9> code{0x66, 0x0F, 0xEF, 0x85, 0x70,
                                               0xFF, 0xFF, 0xFF, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PxorRegMem, "PXOR xmm, [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "PXOR xmm, [memory] length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::XmmRegister::Xmm0,
           "PXOR memory destination differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbp && memory.displacement == -0x90 &&
               memory.width == 128,
           "PXOR memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("pxor xmm0, [rbp-0x90]") != std::string::npos,
           "PXOR memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress alignedTarget{0x8100};
    constexpr std::array<std::uint8_t, 16> sourceBytes{0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                                       0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
                                                       0xCC, 0xDD, 0xEE, 0xFF};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(alignedTarget, sourceBytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(
        rosa::debug::dumpIr(block.intermediateRepresentation()).find("xor_guest_memory_xmm.i128") !=
            std::string::npos,
        "PXOR memory did not lower through its guest-memory IR");
    rosa::x86::X86State state;
    state.rbp = alignedTarget.value + 0x90;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x76451023BA89DCEF},
                "PXOR memory low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x01326754CDFEAB98},
                "PXOR memory high lane differs");
    expect(addressSpace.readBytes(alignedTarget, sourceBytes.size()) ==
               std::vector<std::uint8_t>(sourceBytes.begin(), sourceBytes.end()),
           "PXOR changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PXOR memory changed flags");

    constexpr rosa::guest::GuestAddress unalignedTarget{0x8111};
    addressSpace.writeBytes(unalignedTarget, sourceBytes);
    state.rbp = unalignedTarget.value + 0x90;
    state.xmm[0] = {};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x7766554433221100ULL},
                "unaligned PXOR memory low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFFEEDDCCBBAA9988ULL},
                "unaligned PXOR memory high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "unaligned PXOR changed flags");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FF8};
    state.rbp = crossPageTarget.value + 0x90;
    state.xmm[0] = {.low = 0x1111111111111111ULL, .high = 0x2222222222222222ULL};
    state.rflags = 0xBD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page PXOR memory did not fault");
    expectEqual(state.xmm[0].low, std::uint64_t{0x1111111111111111ULL},
                "faulted PXOR changed its low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0x2222222222222222ULL},
                "faulted PXOR changed its high lane");
    expectEqual(state.rflags, std::uint64_t{0xBD7}, "faulted PXOR changed flags");

    constexpr std::array<std::uint8_t, 9> ripCode{0x66, 0x0F, 0xEF, 0x05, 0xB9,
                                                  0xEB, 0x05, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress ripAddress{0x7FF802AB443FULL};
    constexpr rosa::guest::GuestAddress ripTarget{0x7FF802B13000ULL};
    const auto ripDecoded = decoder.decodeBlock(ripCode, ripAddress);
    expect(ripDecoded[0].opcode == rosa::x86::Opcode::PxorRegMem && ripDecoded[0].length == 8,
           "RIP-relative PXOR opcode or length differs");
    const auto ripMemory = std::get<rosa::x86::MemoryOperand>(ripDecoded[0].operands[1]);
    expect(ripMemory.ripRelative && !ripMemory.hasBase && !ripMemory.index &&
               ripMemory.displacement == 0x5EBB9 && ripMemory.width == 128,
           "RIP-relative PXOR memory operand differs");
    expect(rosa::debug::dumpX86(ripDecoded).find("pxor xmm0, [rip+0x5ebb9] ; 0x7ff802b13000") !=
               std::string::npos,
           "RIP-relative PXOR dump differs");

    constexpr std::uint64_t ripSourceLow = 0xFFFF0000FFFF0000ULL;
    constexpr std::uint64_t ripSourceHigh = 0x00FF00FF00FF00FFULL;
    addressSpace.mapAnonymous(ripTarget, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(ripTarget, ripSourceLow);
    addressSpace.writeU64(rosa::guest::GuestAddress{ripTarget.value + 8}, ripSourceHigh);
    const auto ripBlock = translator.translate(ripCode, ripAddress);
    rosa::x86::X86State ripState;
    ripState.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    ripState.rflags = 0x82;
    static_cast<void>(ripBlock.execute(ripState, &addressSpace));
    expectEqual(ripState.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL ^ ripSourceLow},
                "RIP-relative PXOR low lane differs");
    expectEqual(ripState.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL ^ ripSourceHigh},
                "RIP-relative PXOR high lane differs");
    expectEqual(ripState.rflags, std::uint64_t{0x82}, "RIP-relative PXOR changed flags");

    rosa::guest::AddressSpace ripFaultAddressSpace;
    rosa::x86::X86State ripFaultState;
    ripFaultState.xmm[0] = {.low = 0x1122334455667788ULL, .high = 0x8877665544332211ULL};
    ripFaultState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(ripBlock.execute(ripFaultState, &ripFaultAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "unmapped RIP-relative PXOR did not fault");
    expectEqual(ripFaultState.xmm[0].low, std::uint64_t{0x1122334455667788ULL},
                "faulted RIP-relative PXOR changed its low lane");
    expectEqual(ripFaultState.xmm[0].high, std::uint64_t{0x8877665544332211ULL},
                "faulted RIP-relative PXOR changed its high lane");
    expectEqual(ripFaultState.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative PXOR changed flags");
}

void testPandRipGuestMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 9> code{0x66, 0x0F, 0xDB, 0x05, 0xED,
                                               0x13, 0x07, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802AA0F3BULL};
    constexpr rosa::guest::GuestAddress target{0x7FF802B12330ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PandRegMem,
           "PAND xmm, [RIP+disp32] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "PAND xmm, [RIP+disp32] length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 && memory.ripRelative &&
               !memory.hasBase && memory.displacement == 0x713ED && memory.width == 128,
           "PAND RIP-relative operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pand xmm0, [rip+0x713ed]") != std::string::npos,
           "PAND RIP-relative dump differs");

    constexpr auto pageBase =
        rosa::guest::GuestAddress{target.value & ~(rosa::guest::guestPageSize - 1)};
    constexpr std::array<std::uint64_t, 2> source{0xFF00FF00FF00FF00ULL, 0x0F0F0F0F0F0F0F0FULL};
    std::array<std::uint8_t, rosa::guest::guestPageSize> pageBytes{};
    std::memcpy(pageBytes.data() + (target.value - pageBase.value), source.data(), sizeof(source));
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(pageBase, pageBytes.size(), rosa::guest::Permission::Read, pageBytes,
                            "read-only PAND source");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    expect(
        rosa::debug::dumpIr(block.intermediateRepresentation()).find("and_guest_memory_xmm.i128") !=
            std::string::npos,
        "PAND memory did not lower through guest-memory IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL} & source[0],
                "PAND memory low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL} & source[1],
                "PAND memory high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PAND memory changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.xmm[0] = {.low = 0x1111111111111111ULL, .high = 0x2222222222222222ULL};
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "PAND accepted unmapped guest memory");
    expectEqual(faultState.xmm[0].low, std::uint64_t{0x1111111111111111ULL},
                "faulted PAND changed its low lane");
    expectEqual(faultState.xmm[0].high, std::uint64_t{0x2222222222222222ULL},
                "faulted PAND changed its high lane");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted PAND changed flags");
}

void testPandRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0xDB, 0xC8, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802C6ACDFULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PandRegReg, "register PAND opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "register PAND length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
                   rosa::x86::XmmRegister::Xmm1 &&
               std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
                   rosa::x86::XmmRegister::Xmm0,
           "pand xmm1, xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pand xmm1, xmm0") != std::string::npos,
           "pand xmm1, xmm0 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0xFF00FF00FF00FF00ULL, .high = 0x0F0F0F0F0F0F0F0FULL};
    state.xmm[1] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[1].low, std::uint64_t{0x010045008900CD00ULL},
                "register PAND low lane differs");
    expectEqual(state.xmm[1].high, std::uint64_t{0x0E0C0A0806040200ULL},
                "register PAND high lane differs");
    expectEqual(state.xmm[0].low, std::uint64_t{0xFF00FF00FF00FF00ULL},
                "register PAND changed source low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0x0F0F0F0F0F0F0F0FULL},
                "register PAND changed source high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "register PAND changed flags");

    constexpr std::array<std::uint8_t, 5> aliasedCode{0x66, 0x0F, 0xDB, 0xC0, 0xC3};
    const auto aliasedBlock = translator.translate(aliasedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State aliasedState;
    aliasedState.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    static_cast<void>(aliasedBlock.execute(aliasedState));
    expectEqual(aliasedState.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "aliased PAND low lane differs");
    expectEqual(aliasedState.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "aliased PAND high lane differs");
}

void testPtestRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> selfCode{0x66, 0x0F, 0x38, 0x17, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(selfCode, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PtestRegReg, "PTEST opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "PTEST length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
                   rosa::x86::XmmRegister::Xmm0 &&
               std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
                   rosa::x86::XmmRegister::Xmm0,
           "PTEST operands differ");
    expect(rosa::debug::dumpX86(decoded).find("ptest xmm0, xmm0") != std::string::npos,
           "PTEST x86 dump differs");

    const rosa::dbt::Translator translator;
    const auto selfBlock = translator.translate(selfCode, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(selfBlock.intermediateRepresentation())
                   .find("test_xmm_bits xmm0, xmm0") != std::string::npos,
           "PTEST IR dump differs");

    rosa::x86::X86State state;
    state.rflags = 0xCD7;
    static_cast<void>(selfBlock.execute(state));
    expectEqual(state.rflags, std::uint64_t{0x443}, "zero self-PTEST flags differ");
    expectEqual(state.xmm[0].low, std::uint64_t{0}, "zero self-PTEST changed low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0}, "zero self-PTEST changed high lane");

    state.xmm[0] = {.low = 1, .high = 0x8000000000000000ULL};
    const auto original = state.xmm[0];
    state.rflags = 0xCD7;
    static_cast<void>(selfBlock.execute(state));
    expectEqual(state.rflags, std::uint64_t{0x403}, "nonzero self-PTEST flags differ");
    expectEqual(state.xmm[0].low, original.low, "nonzero self-PTEST changed low lane");
    expectEqual(state.xmm[0].high, original.high, "nonzero self-PTEST changed high lane");

    constexpr std::array<std::uint8_t, 6> distinctCode{0x66, 0x0F, 0x38, 0x17, 0xC1, 0xC3};
    const auto distinctBlock =
        translator.translate(distinctCode, rosa::guest::GuestAddress{0x2000});
    state.xmm[0] = {.low = 0x0FULL, .high = 0};
    state.xmm[1] = {.low = 0xF0ULL, .high = 0};
    state.rflags = 0xCD7;
    static_cast<void>(distinctBlock.execute(state));
    expectEqual(state.rflags, std::uint64_t{0x442},
                "distinct PTEST operand ordering or flags differ");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0F}, "distinct PTEST changed destination");
    expectEqual(state.xmm[1].low, std::uint64_t{0xF0}, "distinct PTEST changed source");
}

void testPcmpeqbGuestMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x74, 0x07, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PcmpeqbRegMem,
           "PCMPEQB xmm, [memory] opcode differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 16> bytes{1, 0, 2, 0,  3,  4,  5,  6,
                                                 7, 8, 9, 10, 11, 12, 13, 14};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8000}, bytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0x8000;
    state.xmm[0] = {};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x00000000FF00FF00ULL}, "PCMPEQB low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0}, "PCMPEQB high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PCMPEQB changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rdi = 0x8000;
    faultState.xmm[0] = {.low = 1, .high = 2};
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "PCMPEQB from unmapped guest memory did not fail");
    expectEqual(faultState.xmm[0].low, std::uint64_t{1}, "failed PCMPEQB changed low lane");
    expectEqual(faultState.xmm[0].high, std::uint64_t{2}, "failed PCMPEQB changed high lane");
}

void testPcmpeqbRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x74, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PcmpeqbRegReg,
           "PCMPEQB xmm, xmm opcode differs");
    expect(rosa::debug::dumpX86(decoded).find("pcmpeqb xmm0, xmm1") != std::string::npos,
           "PCMPEQB xmm, xmm dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0102030405060708ULL, .high = 0xFEDCBA9876543210ULL};
    state.xmm[1] = {.low = 0x0102030405060709ULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0xFFFFFFFFFFFFFF00ULL},
                "PCMPEQB register low lane differs");
    expectEqual(state.xmm[0].high, UINT64_MAX, "PCMPEQB register high lane differs");
    expectEqual(state.xmm[1].low, std::uint64_t{0x0102030405060709ULL},
                "PCMPEQB changed its source low lane");
    expectEqual(state.xmm[1].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "PCMPEQB changed its source high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PCMPEQB register changed flags");

    constexpr std::array<std::uint8_t, 5> aliasCode{0x66, 0x0F, 0x74, 0xC0, 0xC3};
    const auto aliasBlock = translator.translate(aliasCode, rosa::guest::GuestAddress{0x2000});
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    static_cast<void>(aliasBlock.execute(state));
    expectEqual(state.xmm[0].low, UINT64_MAX, "aliased PCMPEQB low lane differs");
    expectEqual(state.xmm[0].high, UINT64_MAX, "aliased PCMPEQB high lane differs");
}

void testPcmpeqdRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> observed{0x66, 0x0F, 0x76, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded =
        decoder.decodeBlock(observed, rosa::guest::GuestAddress{0x7FF802AA15C4ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::PcmpeqdRegReg,
           "PCMPEQD xmm, xmm opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "PCMPEQD xmm, xmm length differs");
    expect(rosa::debug::dumpX86(decoded).find("pcmpeqd xmm0, xmm0") != std::string::npos,
           "PCMPEQD dump differs");

    const rosa::dbt::Translator translator;
    const auto observedBlock =
        translator.translate(observed, rosa::guest::GuestAddress{0x7FF802AA15C4ULL});
    expect(rosa::debug::dumpIr(observedBlock.intermediateRepresentation())
                   .find("compare_equal_xmm_dwords.i32") != std::string::npos,
           "PCMPEQD did not lower through dword-compare IR");
    rosa::x86::X86State selfState;
    selfState.xmm[0] = {.low = 0x2222222211111111ULL, .high = 0x4444444433333333ULL};
    selfState.rflags = 0x8D7;
    static_cast<void>(observedBlock.execute(selfState));
    expectEqual(selfState.xmm[0].low, UINT64_MAX, "self-PCMPEQD low lane differs");
    expectEqual(selfState.xmm[0].high, UINT64_MAX, "self-PCMPEQD high lane differs");
    expectEqual(selfState.rflags, std::uint64_t{0x8D7}, "self-PCMPEQD changed flags");

    constexpr std::array<std::uint8_t, 5> distinct{0x66, 0x0F, 0x76, 0xC1, 0xC3};
    const auto distinctBlock = translator.translate(distinct, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State distinctState;
    distinctState.xmm[0] = {.low = 0x2222222211111111ULL, .high = 0x4444444433333333ULL};
    distinctState.xmm[1] = {.low = 0x9999999911111111ULL, .high = 0x8888888833333333ULL};
    distinctState.rflags = 0xAD7;
    static_cast<void>(distinctBlock.execute(distinctState));
    expectEqual(distinctState.xmm[0].low, std::uint64_t{0x00000000FFFFFFFFULL},
                "distinct PCMPEQD low lane differs");
    expectEqual(distinctState.xmm[0].high, std::uint64_t{0x00000000FFFFFFFFULL},
                "distinct PCMPEQD high lane differs");
    expectEqual(distinctState.xmm[1].low, std::uint64_t{0x9999999911111111ULL},
                "PCMPEQD changed its source");
    expectEqual(distinctState.rflags, std::uint64_t{0xAD7}, "distinct PCMPEQD changed flags");

    // Observed in sqlite: REX.R+B pcmpeqd xmm13, xmm13.
    constexpr std::array<std::uint8_t, 6> extended{0x66, 0x45, 0x0F, 0x76, 0xED, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extended, rosa::guest::GuestAddress{0x100046E3DULL});
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::PcmpeqdRegReg,
           "extended PCMPEQD opcode differs");
    expectEqual(extendedDecoded[0].length, std::uint8_t{5}, "extended PCMPEQD length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(extendedDecoded[0].operands[0]).reg ==
                   rosa::x86::XmmRegister::Xmm13 &&
               std::get<rosa::x86::XmmRegisterOperand>(extendedDecoded[0].operands[1]).reg ==
                   rosa::x86::XmmRegister::Xmm13,
           "extended PCMPEQD operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("pcmpeqd xmm13, xmm13") !=
               std::string::npos,
           "extended PCMPEQD dump differs");
    const auto extendedBlock =
        translator.translate(extended, rosa::guest::GuestAddress{0x100046E3DULL});
    rosa::x86::X86State extendedState;
    extendedState.xmm[13] = {.low = 0x2222222211111111ULL, .high = 0x4444444433333333ULL};
    extendedState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.xmm[13].low, UINT64_MAX, "extended PCMPEQD low lane differs");
    expectEqual(extendedState.xmm[13].high, UINT64_MAX, "extended PCMPEQD high lane differs");
    expectEqual(extendedState.rflags, std::uint64_t{0x8D7}, "extended PCMPEQD changed flags");
}

void testPackedDwordLogicalRightShiftImmediate() {
    // Observed in libswiftCore under an Objective-C fixture: PSRLD xmm0, 16.
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x72, 0xD0, 0x10, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8171A33AAULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PsrldRegImm, "PSRLD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "PSRLD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto count = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 && count.value == 16,
           "PSRLD xmm0, 16 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("psrld xmm0, 16") != std::string::npos,
           "PSRLD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x12345678ABCDEF00ULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x000012340000ABCDULL},
                "PSRLD low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x0000FEDC00007654ULL},
                "PSRLD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "PSRLD changed flags");

    // Counts of 32 or more zero every dword.
    constexpr std::array<std::uint8_t, 6> zeroCode{0x66, 0x0F, 0x72, 0xD0, 0x21, 0xC3};
    const auto zeroBlock = translator.translate(zeroCode, observedRip);
    rosa::x86::X86State zeroState;
    zeroState.xmm[0] = {.low = UINT64_MAX, .high = UINT64_MAX};
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.xmm[0].low, std::uint64_t{0}, "PSRLD count 33 did not zero low dwords");
    expectEqual(zeroState.xmm[0].high, std::uint64_t{0}, "PSRLD count 33 did not zero high dwords");
}

void testPackedWordAddGeneratedExecution() {
    // Observed in libswiftCore under an Objective-C fixture: PADDW xmm0, xmm1.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0xFD, 0xC1, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8171A33AFULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PaddwRegReg, "PADDW opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "PADDW length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "PADDW xmm0, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("paddw xmm0, xmm1") != std::string::npos,
           "PADDW dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("add_xmm_words.i16 xmm0, xmm1") != std::string::npos,
           "PADDW did not lower through packed-word IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x00020003FFFE0004ULL, .high = 0x80007FFF00010000ULL};
    state.xmm[1] = {.low = 0x0004000500060007ULL, .high = 0x8000800000010000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // Low words: B+7, 4+6, 3+5 (mod 2^16), 2+4; high words likewise.
    expectEqual(state.xmm[0].low, std::uint64_t{0x000600080004000BULL},
                "PADDW low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x0000FFFF00020000ULL},
                "PADDW high lane differs");
    expectEqual(state.xmm[1].low, std::uint64_t{0x0004000500060007ULL},
                "PADDW changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "PADDW changed flags");
}

void testPackedDoubleCompareGeneratedExecution() {
    // Observed in ColorSync under an Objective-C fixture: CMPPD xmm4, xmm2, 0.
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0xC2, 0xE2, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4EB0ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmppdRegRegImm, "CMPPD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "CMPPD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    const auto predicate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm4 &&
               source.reg == rosa::x86::XmmRegister::Xmm2 && predicate.value == 0,
           "CMPPD xmm4, xmm2, 0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cmppd xmm4, xmm2, 0x0") != std::string::npos,
           "CMPPD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("compare_packed_double_xmm") != std::string::npos,
           "CMPPD did not lower through packed-double IR");
    rosa::x86::X86State state;
    state.xmm[4] = {.low = 0x3FF0000000000000ULL, .high = 0x7FF8000000000000ULL};
    state.xmm[2] = {.low = 0x3FF0000000000000ULL, .high = 0x4000000000000000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // Low lane equal (mask set); high lane NaN unordered (mask clear for EQ).
    expectEqual(state.xmm[4].low, UINT64_MAX, "CMPPD equal lane differs");
    expectEqual(state.xmm[4].high, std::uint64_t{0}, "CMPPD unordered lane differs");
    expectEqual(state.xmm[2].low, std::uint64_t{0x3FF0000000000000ULL},
                "CMPPD changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "CMPPD changed flags");

    // Less-than predicate over distinct lanes.
    constexpr std::array<std::uint8_t, 6> lessCode{0x66, 0x0F, 0xC2, 0xE2, 0x01, 0xC3};
    const auto lessBlock = translator.translate(lessCode, observedRip);
    rosa::x86::X86State lessState;
    lessState.xmm[4] = {.low = 0x4008000000000000ULL, .high = 0x3FF0000000000000ULL};
    lessState.xmm[2] = {.low = 0x4004000000000000ULL, .high = 0x4000000000000000ULL};
    static_cast<void>(lessBlock.execute(lessState));
    // 3.0 < 2.5 is false; 1.0 < 2.0 is true.
    expectEqual(lessState.xmm[4].low, std::uint64_t{0}, "CMPPD less-than low lane differs");
    expectEqual(lessState.xmm[4].high, UINT64_MAX, "CMPPD less-than high lane differs");
}

void testPackedDwordShiftAndAddGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> shiftCode{0x66, 0x0F, 0x72, 0xF1, 0x06, 0xC3};
    constexpr rosa::guest::GuestAddress shiftRip{0x7FF802C76FB0ULL};
    const rosa::x86::Decoder decoder;
    const auto shiftDecoded = decoder.decodeBlock(shiftCode, shiftRip);
    expect(shiftDecoded[0].opcode == rosa::x86::Opcode::PslldRegImm, "PSLLD opcode differs");
    expectEqual(shiftDecoded[0].length, std::uint8_t{5}, "PSLLD length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(shiftDecoded[0].operands[0]).reg ==
               rosa::x86::XmmRegister::Xmm1,
           "PSLLD destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(shiftDecoded[0].operands[1]).value,
                std::uint64_t{6}, "PSLLD count differs");
    expect(rosa::debug::dumpX86(shiftDecoded).find("pslld xmm1, 6") != std::string::npos,
           "PSLLD dump differs");

    const rosa::dbt::Translator translator;
    const auto shiftBlock = translator.translate(shiftCode, shiftRip);
    expect(rosa::debug::dumpIr(shiftBlock.intermediateRepresentation())
                   .find("shift_left_xmm_dwords.i32 xmm1, 6") != std::string::npos,
           "PSLLD did not lower through packed-dword IR");
    rosa::x86::X86State shiftState;
    shiftState.xmm[1] = {.low = 0x0000000200000001ULL, .high = 0x0400000080000000ULL};
    shiftState.ymmUpper[1] = {.low = 0x1122334455667788ULL, .high = 0x8877665544332211ULL};
    shiftState.rflags = 0x8D7;
    static_cast<void>(shiftBlock.execute(shiftState));
    expectEqual(shiftState.xmm[1].low, std::uint64_t{0x0000008000000040ULL},
                "PSLLD low lane differs");
    expectEqual(shiftState.xmm[1].high, std::uint64_t{0},
                "PSLLD did not truncate overflowing dwords");
    expectEqual(shiftState.ymmUpper[1].low, std::uint64_t{0x1122334455667788ULL},
                "legacy PSLLD changed the upper YMM state");
    expectEqual(shiftState.rflags, std::uint64_t{0x8D7}, "PSLLD changed flags");

    constexpr std::array<std::uint8_t, 6> largeShiftCode{0x66, 0x0F, 0x72, 0xF1, 0x20, 0xC3};
    const auto largeShiftBlock =
        translator.translate(largeShiftCode, rosa::guest::GuestAddress{0x1000});
    shiftState.xmm[1] = {.low = UINT64_MAX, .high = UINT64_MAX};
    static_cast<void>(largeShiftBlock.execute(shiftState));
    expectEqual(shiftState.xmm[1].low, std::uint64_t{0}, "PSLLD count 32 did not zero low dwords");
    expectEqual(shiftState.xmm[1].high, std::uint64_t{0},
                "PSLLD count 32 did not zero high dwords");

    constexpr std::array<std::uint8_t, 5> addCode{0x66, 0x0F, 0xFE, 0xC1, 0xC3};
    constexpr rosa::guest::GuestAddress addRip{0x7FF802C76FB5ULL};
    const auto addDecoded = decoder.decodeBlock(addCode, addRip);
    expect(addDecoded[0].opcode == rosa::x86::Opcode::PadddRegReg, "PADDD opcode differs");
    expectEqual(addDecoded[0].length, std::uint8_t{4}, "PADDD length differs");
    expect(rosa::debug::dumpX86(addDecoded).find("paddd xmm0, xmm1") != std::string::npos,
           "PADDD dump differs");

    const auto addBlock = translator.translate(addCode, addRip);
    expect(rosa::debug::dumpIr(addBlock.intermediateRepresentation())
                   .find("add_xmm_dwords.i32 xmm0, xmm1") != std::string::npos,
           "PADDD did not lower through packed-dword IR");
    rosa::x86::X86State addState;
    addState.xmm[0] = {.low = 0x00000002FFFFFFFFULL, .high = 0xFFFFFFFF80000000ULL};
    addState.xmm[1] = {.low = 0xFFFFFFFF00000002ULL, .high = 0xFFFFFFFF80000000ULL};
    addState.ymmUpper[0] = {.low = 0xA5A5A5A5A5A5A5A5ULL, .high = 0x5A5A5A5A5A5A5A5AULL};
    addState.rflags = 0xAD7;
    static_cast<void>(addBlock.execute(addState));
    expectEqual(addState.xmm[0].low, std::uint64_t{0x0000000100000001ULL},
                "PADDD low lane differs");
    expectEqual(addState.xmm[0].high, std::uint64_t{0xFFFFFFFE00000000ULL},
                "PADDD high lane differs");
    expectEqual(addState.xmm[1].low, std::uint64_t{0xFFFFFFFF00000002ULL},
                "PADDD changed its source");
    expectEqual(addState.ymmUpper[0].low, std::uint64_t{0xA5A5A5A5A5A5A5A5ULL},
                "legacy PADDD changed the upper YMM state");
    expectEqual(addState.rflags, std::uint64_t{0xAD7}, "PADDD changed flags");
}

void testPackedDwordAddRipMemory() {
    // Observed in libobjc under an Objective-C fixture: PADDD xmm0, [RIP+disp32].
    constexpr std::array<std::uint8_t, 9> code{0x66, 0x0F, 0xFE, 0x05,
                                               0x12, 0xFA, 0x02, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802A1BAF6ULL};
    constexpr rosa::guest::GuestAddress sourceAddress{0x7FF802A4B510ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PadddRegMem, "PADDD m128 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8}, "PADDD m128 length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0,
           "PADDD m128 destination differs");
    expect(memory.ripRelative && !memory.hasBase && !memory.index && memory.width == 128 &&
               memory.displacement == 0x2FA12,
           "PADDD m128 memory operand differs");
    expectEqual(observedRip.value + decoded[0].length + memory.displacement,
                sourceAddress.value, "PADDD m128 target differs");
    expect(rosa::debug::dumpX86(decoded).find("paddd xmm0, xmmword [rip+0x2fa12]") !=
               std::string::npos,
           "PADDD m128 dump differs");

    constexpr rosa::guest::GuestAddress sourcePage{sourceAddress.value &
                                                   ~(rosa::guest::guestPageSize - 1)};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(sourcePage, rosa::guest::guestPageSize * 2,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(sourceAddress, 0xFFFFFFFF00000002ULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{sourceAddress.value + 8},
                          0xFFFFFFFF80000000ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x00000002FFFFFFFFULL, .high = 0xFFFFFFFF80000000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0000000100000001ULL},
                "PADDD m128 low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFFFFFFFE00000000ULL},
                "PADDD m128 high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "PADDD m128 changed flags");
}

void testPackedQwordLogicalRightShiftImmediate() {
    constexpr std::array<std::uint8_t, 6> observed{0x66, 0x0F, 0x73, 0xD2, 0x20, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF80681D31DULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PsrlqRegImm, "PSRLQ opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "PSRLQ length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::XmmRegister::Xmm2,
           "PSRLQ destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{32}, "PSRLQ count differs");
    expect(rosa::debug::dumpX86(decoded).find("psrlq xmm2, 32") != std::string::npos,
           "PSRLQ dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observed, rip);
    expect(
        rosa::debug::dumpIr(block.intermediateRepresentation()).find("shift_right_logical.i64") !=
            std::string::npos,
        "PSRLQ did not lower through logical-right-shift IR");
    rosa::x86::X86State state;
    state.xmm[2] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.ymmUpper[2] = {.low = 0x1122334455667788ULL, .high = 0x8877665544332211ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[2].low, std::uint64_t{0x01234567}, "PSRLQ count 32 low qword differs");
    expectEqual(state.xmm[2].high, std::uint64_t{0xFEDCBA98}, "PSRLQ count 32 high qword differs");
    expectEqual(state.ymmUpper[2].low, std::uint64_t{0x1122334455667788ULL},
                "legacy PSRLQ changed upper YMM state");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PSRLQ changed flags");

    constexpr std::array<std::uint8_t, 6> count33{0x66, 0x0F, 0x73, 0xD3, 0x21, 0xC3};
    const auto count33Block =
        translator.translate(count33, rosa::guest::GuestAddress{rip.value + 12});
    state.xmm[3] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    static_cast<void>(count33Block.execute(state));
    expectEqual(state.xmm[3].low, std::uint64_t{0x0091A2B3}, "PSRLQ count 33 low qword differs");
    expectEqual(state.xmm[3].high, std::uint64_t{0x7F6E5D4C}, "PSRLQ count 33 high qword differs");

    constexpr std::array<std::uint8_t, 6> count64{0x66, 0x0F, 0x73, 0xD2, 0x40, 0xC3};
    const auto count64Block = translator.translate(count64, rosa::guest::GuestAddress{0x1000});
    state.xmm[2] = {.low = UINT64_MAX, .high = UINT64_MAX};
    static_cast<void>(count64Block.execute(state));
    expectEqual(state.xmm[2].low, std::uint64_t{0}, "PSRLQ count 64 did not zero low qword");
    expectEqual(state.xmm[2].high, std::uint64_t{0}, "PSRLQ count 64 did not zero high qword");

    constexpr std::array<std::uint8_t, 7> extended{0x66, 0x41, 0x0F, 0x73, 0xD2, 0x01, 0xC3};
    const auto extendedDecoded = decoder.decodeBlock(extended, rosa::guest::GuestAddress{0x2000});
    expect(std::get<rosa::x86::XmmRegisterOperand>(extendedDecoded[0].operands[0]).reg ==
               rosa::x86::XmmRegister::Xmm10,
           "REX.B PSRLQ destination differs");
}

void testPackedHorizontalAddAndMovdExtract() {
    constexpr std::array<std::uint8_t, 6> horizontalCode{0x66, 0x0F, 0x38, 0x02, 0xC0, 0xC3};
    constexpr rosa::guest::GuestAddress horizontalRip{0x7FF802C76FC3ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(horizontalCode, horizontalRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PhadddRegReg, "PHADDD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "PHADDD length differs");
    expect(rosa::debug::dumpX86(decoded).find("phaddd xmm0, xmm0") != std::string::npos,
           "PHADDD dump differs");

    const rosa::dbt::Translator translator;
    const auto horizontalBlock = translator.translate(horizontalCode, horizontalRip);
    expect(rosa::debug::dumpIr(horizontalBlock.intermediateRepresentation())
                   .find("horizontal_add_xmm_dwords.i32 xmm0, xmm0") != std::string::npos,
           "PHADDD did not lower through horizontal-add IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0000000200000001ULL, .high = 0x00000002FFFFFFFFULL};
    state.ymmUpper[0] = {.low = 0x1122334455667788ULL, .high = 0x8877665544332211ULL};
    state.rflags = 0x8D7;
    static_cast<void>(horizontalBlock.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0000000100000003ULL},
                "first aliased PHADDD low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x0000000100000003ULL},
                "first aliased PHADDD high lane differs");
    static_cast<void>(horizontalBlock.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0000000400000004ULL},
                "second aliased PHADDD low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x0000000400000004ULL},
                "second aliased PHADDD high lane differs");
    expectEqual(state.ymmUpper[0].low, std::uint64_t{0x1122334455667788ULL},
                "legacy PHADDD changed upper YMM state");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PHADDD changed flags");

    constexpr std::array<std::uint8_t, 5> extractCode{0x66, 0x0F, 0x7E, 0xC1, 0xC3};
    constexpr rosa::guest::GuestAddress extractRip{0x7FF802C76FCDULL};
    const auto extractDecoded = decoder.decodeBlock(extractCode, extractRip);
    expect(extractDecoded[0].opcode == rosa::x86::Opcode::MovdRegXmm,
           "MOVD XMM-to-register opcode differs");
    expectEqual(extractDecoded[0].length, std::uint8_t{4}, "MOVD XMM-to-register length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(extractDecoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32,
           "MOVD ECX destination differs");
    expect(rosa::debug::dumpX86(extractDecoded).find("movd ecx, xmm0") != std::string::npos,
           "MOVD XMM-to-register dump differs");

    const auto extractBlock = translator.translate(extractCode, extractRip);
    state.rcx = UINT64_MAX;
    state.rflags = 0xAD7;
    static_cast<void>(extractBlock.execute(state));
    expectEqual(state.rcx, std::uint64_t{4}, "MOVD XMM-to-register did not zero-extend ECX");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0000000400000004ULL},
                "MOVD XMM-to-register changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVD XMM-to-register changed flags");
}

void testPmovzxbdRegisterToRegister() {
    // Observed in libsqlite3: PMOVZXBD XMM2, XMM2 (in-place widening).
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x38, 0x31, 0xD2, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x100082DCEULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::PmovzxbdXmmReg, "PMOVZXBD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "PMOVZXBD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm2 &&
               source.reg == rosa::x86::XmmRegister::Xmm2,
           "PMOVZXBD xmm2, xmm2 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pmovzxbd xmm2, xmm2") != std::string::npos,
           "PMOVZXBD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x100082DCEULL});
    rosa::x86::X86State state;
    state.xmm[2] = {.low = 0xDDCCBBAA04030201ULL, .high = 0xFFFFFFFFFFFFFFFFULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[2].low, std::uint64_t{0x0000000200000001ULL},
                "PMOVZXBD low lane differs");
    expectEqual(state.xmm[2].high, std::uint64_t{0x0000000400000003ULL},
                "PMOVZXBD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PMOVZXBD changed flags");
}

void testPandnRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0xDF, 0xC8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PandnRegReg, "PANDN xmm, xmm opcode differs");
    expect(rosa::debug::dumpX86(decoded).find("pandn xmm1, xmm0") != std::string::npos,
           "PANDN dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x00FF00FF00FF00FFULL, .high = 0xFFFF0000FFFF0000ULL};
    state.xmm[1] = {.low = 0x0F0F0F0F0F0F0F0FULL, .high = 0xAAAAAAAA55555555ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[1].low, std::uint64_t{0x00F000F000F000F0ULL}, "PANDN low lane differs");
    expectEqual(state.xmm[1].high, std::uint64_t{0x55550000AAAA0000ULL}, "PANDN high lane differs");
    expectEqual(state.xmm[0].low, std::uint64_t{0x00FF00FF00FF00FFULL},
                "PANDN changed its source low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFFFF0000FFFF0000ULL},
                "PANDN changed its source high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PANDN changed flags");

    constexpr std::array<std::uint8_t, 5> aliasCode{0x66, 0x0F, 0xDF, 0xC9, 0xC3};
    const auto aliasBlock = translator.translate(aliasCode, rosa::guest::GuestAddress{0x2000});
    state.xmm[1] = {.low = UINT64_MAX, .high = 0x0123456789ABCDEFULL};
    static_cast<void>(aliasBlock.execute(state));
    expectEqual(state.xmm[1].low, std::uint64_t{0}, "aliased PANDN low lane differs");
    expectEqual(state.xmm[1].high, std::uint64_t{0}, "aliased PANDN high lane differs");
}

void testPmovmskbGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0xD7, 0xF0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PmovmskbRegXmm,
           "PMOVMSKB r32, xmm opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rsi,
           "PMOVMSKB destination differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsi = UINT64_MAX;
    state.xmm[0] = {
        .low = 0x8000000000000080ULL,
        .high = 0x0000000000008000ULL,
    };
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rsi, std::uint64_t{0x281}, "PMOVMSKB mask or 32-bit zero extension differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PMOVMSKB changed flags");
}

void testPmovsxbqRipMemoryGeneratedExecution() {
    // Observed in liblzma under grep -X: pmovsxbq xmm1, word [rip+0xd4a7].
    constexpr std::array<std::uint8_t, 10> code{0x66, 0x0F, 0x38, 0x22, 0x0D,
                                                0xA7, 0xD4, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF814A80BB4ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF814A8E064ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::PmovsxbqRegMem && decoded[0].length == 9,
           "PMOVSXBQ decode differs");
    expect(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]).width == 16,
           "PMOVSXBQ memory width differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "pmovsxbq xmm1, word [rip+0xd4a7] ; 0x7ff814a8e064") != std::string::npos,
           "PMOVSXBQ disassembly differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x7FF814A8E000ULL},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> source{0x80, 0x7F};
    addressSpace.writeBytes(target, source);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    rosa::x86::X86State state;
    state.xmm[1] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[1].low, std::uint64_t{0xFFFFFFFFFFFFFF80ULL},
                "PMOVSXBQ low lane differs");
    expectEqual(state.xmm[1].high, std::uint64_t{0x7F}, "PMOVSXBQ high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PMOVSXBQ changed flags");

    // A source straddling an unmapped page faults without a partial write.
    constexpr std::array<std::uint8_t, 10> crossingCode{0x66, 0x0F, 0x38, 0x22, 0x0D,
                                                        0xF6, 0x0F, 0x00, 0x00, 0xC3};
    const auto crossingBlock =
        translator.translate(crossingCode, rosa::guest::GuestAddress{0x1000});
    rosa::guest::AddressSpace crossingAddressSpace;
    crossingAddressSpace.mapAnonymous(rosa::guest::GuestAddress{0x1000},
                                      rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    rosa::x86::X86State crossing;
    crossing.xmm[1] = {.low = 0x1111111111111111ULL, .high = 0x2222222222222222ULL};
    bool faulted = false;
    try {
        static_cast<void>(crossingBlock.execute(crossing, &crossingAddressSpace));
    } catch (const std::runtime_error &) {
        faulted = true;
    }
    expect(faulted, "PMOVSXBQ across an unmapped page did not fault");
    expectEqual(crossing.xmm[1].low, std::uint64_t{0x1111111111111111ULL},
                "faulted PMOVSXBQ wrote its low lane");
}

void testPmovsxbdRipMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 10> code{0x66, 0x0F, 0x38, 0x21, 0x0D,
                                                0x57, 0xE2, 0x03, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C6AA48ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF802CA8CA8ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF802CA8000ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::PmovsxbdRegMem,
           "PMOVSXBD RIP-relative opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "PMOVSXBD RIP-relative length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1, "PMOVSXBD destination differs");
    expect(memory.ripRelative && !memory.hasBase && !memory.index && memory.width == 32 &&
               memory.displacement == 0x3E257,
           "PMOVSXBD RIP-relative memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "pmovsxbd xmm1, dword [rip+0x3e257] ; 0x7ff802ca8ca8") != std::string::npos,
           "PMOVSXBD disassembly differs");

    constexpr std::array<std::uint8_t, 4> source{0x80, 0xFF, 0x00, 0x7F};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "PMOVSXBD source");
    addressSpace.writeBytes(target, source);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("load_guest_sign_extended_bytes_xmm") != std::string::npos,
           "PMOVSXBD IR differs");
    rosa::x86::X86State state;
    state.xmm[0] = {
        .low = 0x0123456789ABCDEFULL,
        .high = 0xFEDCBA9876543210ULL,
    };
    state.xmm[1] = {
        .low = 0xAAAAAAAAAAAAAAAAULL,
        .high = 0xBBBBBBBBBBBBBBBBULL,
    };
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[1].low, std::uint64_t{0xFFFFFFFFFFFFFF80ULL},
                "PMOVSXBD low sign extensions differ");
    expectEqual(state.xmm[1].high, std::uint64_t{0x0000007F00000000ULL},
                "PMOVSXBD high sign extensions differ");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "PMOVSXBD changed an unrelated XMM lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PMOVSXBD changed flags");

    constexpr std::array<std::uint8_t, 10> crossingCode{0x66, 0x0F, 0x38, 0x21, 0x0D,
                                                        0xF5, 0x3F, 0x00, 0x00, 0xC3};
    const auto crossingBlock =
        translator.translate(crossingCode, rosa::guest::GuestAddress{0x1000});
    rosa::guest::AddressSpace crossingAddressSpace;
    crossingAddressSpace.mapAnonymous(
        rosa::guest::GuestAddress{0x4000}, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read | rosa::guest::Permission::Write, "partial PMOVSXBD source");
    crossingAddressSpace.writeBytes(rosa::guest::GuestAddress{0x4FFE},
                                    std::array<std::uint8_t, 2>{0x80, 0xFF});
    rosa::x86::X86State faultState;
    faultState.xmm[1] = {
        .low = 0x1122334455667788ULL,
        .high = 0x8877665544332211ULL,
    };
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(crossingBlock.execute(faultState, &crossingAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page PMOVSXBD did not fault");
    expectEqual(faultState.xmm[1].low, std::uint64_t{0x1122334455667788ULL},
                "faulted PMOVSXBD changed its low lane");
    expectEqual(faultState.xmm[1].high, std::uint64_t{0x8877665544332211ULL},
                "faulted PMOVSXBD changed its high lane");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted PMOVSXBD changed flags");
}

void testPmovsxdqRipMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 10> code{0x66, 0x0F, 0x38, 0x25, 0x0D,
                                                0x09, 0xF1, 0x03, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C6932EULL};
    constexpr rosa::guest::GuestAddress target{0x7FF802CA8440ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF802CA8000ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::PmovsxdqRegMem,
           "PMOVSXDQ RIP-relative opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "PMOVSXDQ RIP-relative length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1, "PMOVSXDQ destination differs");
    expect(memory.ripRelative && !memory.hasBase && !memory.index && memory.width == 64 &&
               memory.displacement == 0x3F109,
           "PMOVSXDQ RIP-relative memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "pmovsxdq xmm1, qword [rip+0x3f109] ; 0x7ff802ca8440") != std::string::npos,
           "PMOVSXDQ disassembly differs");

    constexpr std::array<std::uint8_t, 8> source{0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x80};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "PMOVSXDQ source");
    addressSpace.writeBytes(target, source);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("load_guest_sign_extended_dwords_xmm") != std::string::npos,
           "PMOVSXDQ IR differs");
    rosa::x86::X86State state;
    state.xmm[0] = {
        .low = 0x0123456789ABCDEFULL,
        .high = 0xFEDCBA9876543210ULL,
    };
    state.xmm[1] = {
        .low = 0xAAAAAAAAAAAAAAAAULL,
        .high = 0xBBBBBBBBBBBBBBBBULL,
    };
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[1].low, std::uint64_t{0xFFFFFFFFFFFFFFFEULL},
                "PMOVSXDQ low sign extension differs");
    expectEqual(state.xmm[1].high, std::uint64_t{0xFFFFFFFF80000000ULL},
                "PMOVSXDQ high sign extension differs");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "PMOVSXDQ changed an unrelated XMM lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PMOVSXDQ changed flags");
    expect(addressSpace.readBytes(target, source.size()) ==
               std::vector<std::uint8_t>(source.begin(), source.end()),
           "PMOVSXDQ changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.xmm[1] = {
        .low = 0x1122334455667788ULL,
        .high = 0x8877665544332211ULL,
    };
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "unmapped PMOVSXDQ did not fault");
    expectEqual(faultState.xmm[1].low, std::uint64_t{0x1122334455667788ULL},
                "faulted PMOVSXDQ changed its low lane");
    expectEqual(faultState.xmm[1].high, std::uint64_t{0x8877665544332211ULL},
                "faulted PMOVSXDQ changed its high lane");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted PMOVSXDQ changed flags");
}

void testPaddqRegisterExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0xD4, 0xC8, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C6933EULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::PaddqRegReg, "PADDQ opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "PADDQ length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               source.reg == rosa::x86::XmmRegister::Xmm0,
           "PADDQ xmm1, xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("paddq xmm1, xmm0") != std::string::npos,
           "PADDQ dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    rosa::x86::X86State state;
    state.xmm[0] = {
        .low = 2,
        .high = UINT64_MAX,
    };
    state.xmm[1] = {
        .low = UINT64_MAX,
        .high = 1,
    };
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[1].low, std::uint64_t{1}, "PADDQ low wrapping sum differs");
    expectEqual(state.xmm[1].high, std::uint64_t{0}, "PADDQ high wrapping sum differs");
    expectEqual(state.xmm[0].low, std::uint64_t{2}, "PADDQ changed its source low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{UINT64_MAX}, "PADDQ changed its source high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PADDQ changed flags");
}

void testPshufdRegisterExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x70, 0xC0, 0xE8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PshufdRegRegImm, "PSHUFD opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]).value,
                std::uint64_t{0xE8}, "PSHUFD control differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.xmm[0] = {
        .low = 0x2222222211111111ULL,
        .high = 0x4444444433333333ULL,
    };
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x3333333311111111ULL},
                "in-place PSHUFD low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x4444444433333333ULL},
                "in-place PSHUFD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PSHUFD changed flags");
}

void testShufpsRegisterExecution() {
    // Observed in ColorSync under an Objective-C fixture: SHUFPS xmm2, xmm4, 0x88.
    constexpr std::array<std::uint8_t, 5> code{0x0F, 0xC6, 0xD4, 0x88, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4EBAULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::ShufpsRegRegImm, "SHUFPS opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "SHUFPS length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    const auto control = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm2 &&
               source.reg == rosa::x86::XmmRegister::Xmm4 && control.value == 0x88,
           "SHUFPS xmm2, xmm4, 0x88 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("shufps xmm2, xmm4, 0x88") != std::string::npos,
           "SHUFPS dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.xmm[2] = {.low = 0x0000222200001111ULL, .high = 0x0000444400003333ULL};
    state.xmm[4] = {.low = 0x0000666600005555ULL, .high = 0x0000888800007777ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // Control 0x88 selects dest[0], dest[2], src[0], src[2].
    expectEqual(state.xmm[2].low, std::uint64_t{0x0000333300001111ULL},
                "SHUFPS low lane differs");
    expectEqual(state.xmm[2].high, std::uint64_t{0x0000777700005555ULL},
                "SHUFPS high lane differs");
    expectEqual(state.xmm[4].low, std::uint64_t{0x0000666600005555ULL},
                "SHUFPS changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "SHUFPS changed flags");
}

void testShufpdRegisterExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0xC6, 0xC1, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A8C43CULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShufpdRegRegImm, "SHUFPD opcode differs");
    expect(rosa::debug::dumpX86(decoded).find("shufpd xmm0, xmm1, 0x1") != std::string::npos,
           "SHUFPD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A8C43CULL});
    rosa::x86::X86State state;
    state.xmm[0] = {
        .low = 0x1111111111111111ULL,
        .high = 0x2222222222222222ULL,
    };
    state.xmm[1] = {
        .low = 0x3333333333333333ULL,
        .high = 0x4444444444444444ULL,
    };
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x2222222222222222ULL},
                "SHUFPD selected the wrong destination lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0x3333333333333333ULL},
                "SHUFPD selected the wrong source lane");
    expectEqual(state.xmm[1].low, std::uint64_t{0x3333333333333333ULL},
                "SHUFPD changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "SHUFPD changed flags");

    constexpr std::array<std::uint8_t, 6> inPlaceCode{0x66, 0x0F, 0xC6, 0xC0, 0x01, 0xC3};
    const auto inPlaceBlock = translator.translate(inPlaceCode, rosa::guest::GuestAddress{0x2000});
    state.xmm[0] = {
        .low = 0x1111111111111111ULL,
        .high = 0x2222222222222222ULL,
    };
    static_cast<void>(inPlaceBlock.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x2222222222222222ULL},
                "in-place SHUFPD low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x1111111111111111ULL},
                "in-place SHUFPD did not preserve its old low lane");
}

void testPalignrRegisterExecution() {
    constexpr std::array<std::uint8_t, 7> code{0x66, 0x0F, 0x3A, 0x0F, 0xE3, 0x06, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PalignrRegRegImm, "PALIGNR opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "PALIGNR length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm4 &&
               source.reg == rosa::x86::XmmRegister::Xmm3 && immediate.value == 6,
           "PALIGNR operands differ");
    expect(rosa::debug::dumpX86(decoded).find("palignr xmm4, xmm3, 0x6") != std::string::npos,
           "PALIGNR x86 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("align_right_xmm_bytes xmm4, xmm3, 6") != std::string::npos,
           "PALIGNR IR dump differs");
    rosa::x86::X86State state;
    state.xmm[3] = {.low = 0x0706050403020100ULL, .high = 0x0F0E0D0C0B0A0908ULL};
    state.xmm[4] = {.low = 0x1716151413121110ULL, .high = 0x1F1E1D1C1B1A1918ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[4].low, std::uint64_t{0x0D0C0B0A09080706ULL}, "PALIGNR low lane differs");
    expectEqual(state.xmm[4].high, std::uint64_t{0x1514131211100F0EULL},
                "PALIGNR high lane differs");
    expectEqual(state.xmm[3].low, std::uint64_t{0x0706050403020100ULL},
                "PALIGNR changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PALIGNR changed flags");
}

void testMovapsRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 8> code{
        0x0F, 0x29, 0x85, 0xE0, 0xFF, 0xFF, 0xFF, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovapsMemReg,
           "MOVAPS [mem], xmm opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rbp, "MOVAPS base differs");
    expectEqual(memory.displacement, std::int64_t{-0x20}, "MOVAPS displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbp = 0x8100;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x80E0}), state.xmm[0].low,
                "MOVAPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x80E8}), state.xmm[0].high,
                "MOVAPS stored the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVAPS changed flags");

    constexpr std::array<std::uint8_t, 6> movapdCode{0x66, 0x0F, 0x29, 0x04, 0x0F, 0xC3};
    const auto movapdDecoded =
        decoder.decodeBlock(movapdCode, rosa::guest::GuestAddress{0x7FF802A8C457ULL});
    expect(movapdDecoded[0].opcode == rosa::x86::Opcode::MovapdMemReg,
           "MOVAPD [indexed memory], xmm opcode differs");
    const auto movapdMemory = std::get<rosa::x86::MemoryOperand>(movapdDecoded[0].operands[0]);
    expect(movapdMemory.base == rosa::x86::Register::Rdi &&
               movapdMemory.index == rosa::x86::Register::Rcx && movapdMemory.scale == 1 &&
               movapdMemory.displacement == 0,
           "MOVAPD [rdi+rcx], xmm0 operands differ");
    expect(rosa::debug::dumpX86(movapdDecoded).find("movapd [rdi+rcx*1], xmm0") !=
               std::string::npos,
           "MOVAPD indexed store dump differs");
    const auto movapdBlock =
        translator.translate(movapdCode, rosa::guest::GuestAddress{0x7FF802A8C457ULL});
    state.rdi = 0x8100;
    state.rcx = 0x10;
    state.xmm[0] = {
        .low = 0x8877665544332211ULL,
        .high = 0x1020304050607080ULL,
    };
    state.rflags = 0xAD7;
    static_cast<void>(movapdBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8110}), state.xmm[0].low,
                "MOVAPD indexed store low lane differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8118}), state.xmm[0].high,
                "MOVAPD indexed store high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVAPD indexed store changed flags");

    constexpr std::array<std::uint8_t, 5> extendedBaseCode{0x41, 0x0F, 0x29, 0x07, 0xC3};
    const auto extendedBaseDecoded =
        decoder.decodeBlock(extendedBaseCode, rosa::guest::GuestAddress{0x1800});
    expect(extendedBaseDecoded[0].opcode == rosa::x86::Opcode::MovapsMemReg,
           "REX MOVAPS store opcode differs");
    expectEqual(extendedBaseDecoded[0].length, std::uint8_t{4}, "REX MOVAPS store length differs");
    const auto extendedMemory =
        std::get<rosa::x86::MemoryOperand>(extendedBaseDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::XmmRegisterOperand>(extendedBaseDecoded[0].operands[1]);
    expect(extendedMemory.base == rosa::x86::Register::R15 && extendedMemory.displacement == 0 &&
               extendedMemory.width == 128 && !extendedMemory.ripRelative,
           "REX MOVAPS store memory operand differs");
    expect(extendedSource.reg == rosa::x86::XmmRegister::Xmm0, "REX MOVAPS store source differs");
    expect(rosa::debug::dumpX86(extendedBaseDecoded).find("movaps [r15], xmm0") !=
               std::string::npos,
           "REX MOVAPS store dump differs");
    const auto extendedBaseBlock =
        translator.translate(extendedBaseCode, rosa::guest::GuestAddress{0x1800});
    state.r15 = 0x8080;
    state.xmm[0] = {.low = 0x8877665544332211ULL, .high = 0x1020304050607080ULL};
    state.rflags = 0xAD7;
    static_cast<void>(extendedBaseBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8080}), state.xmm[0].low,
                "REX MOVAPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8088}), state.xmm[0].high,
                "REX MOVAPS stored the wrong high lane");
    expectEqual(state.r15, std::uint64_t{0x8080}, "REX MOVAPS changed its base register");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "REX MOVAPS changed flags");

    rosa::x86::X86State unalignedState;
    unalignedState.rbp = 0x8108;
    unalignedState.xmm[0] = state.xmm[0];
    bool rejected = false;
    try {
        static_cast<void>(block.execute(unalignedState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("16-byte aligned") != std::string_view::npos;
    }
    expect(rejected, "unaligned MOVAPS guest store did not fail");
    expectEqual(unalignedState.rbp, std::uint64_t{0x8108},
                "failed MOVAPS changed its base register");
}

void testMovapsRegisterToRipRelativeGuestMemory() {
    constexpr std::array<std::uint8_t, 8> code{0x0F, 0x29, 0x05, 0x27, 0xD6, 0x06, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800058AB2ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8000C60E0ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF8000C6000ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovapsMemReg,
           "RIP-relative MOVAPS store opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative MOVAPS store length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 128 &&
               memory.displacement == 0x6D627,
           "RIP-relative MOVAPS memory operand differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::XmmRegister::Xmm0,
           "RIP-relative MOVAPS source differs");
    expect(rosa::debug::dumpX86(decoded).find("movaps [rip+0x6d627], xmm0") != std::string::npos,
           "RIP-relative MOVAPS dump differs");

    constexpr std::array<std::uint8_t, 9> rexBIgnoredCode{0x41, 0x0F, 0x29, 0x05, 0xF8,
                                                          0x0F, 0x00, 0x00, 0xC3};
    const auto rexBIgnoredDecoded =
        decoder.decodeBlock(rexBIgnoredCode, rosa::guest::GuestAddress{0x1000});
    const auto rexBIgnoredMemory =
        std::get<rosa::x86::MemoryOperand>(rexBIgnoredDecoded[0].operands[0]);
    expect(rexBIgnoredMemory.ripRelative && !rexBIgnoredMemory.hasBase &&
               rexBIgnoredMemory.displacement == 0xFF8 && rexBIgnoredDecoded[0].length == 8,
           "REX.B incorrectly changed MOVAPS mod=00 r/m=5 RIP-relative addressing");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), state.xmm[0].low,
                "RIP-relative MOVAPS stored the wrong low lane");
    expectEqual(
        addressSpace.readU64(rosa::guest::GuestAddress{target.value + sizeof(std::uint64_t)}),
        state.xmm[0].high, "RIP-relative MOVAPS stored the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative MOVAPS changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t lowSentinel = 0xAAAAAAAAAAAAAAAAULL;
    constexpr std::uint64_t highSentinel = 0xBBBBBBBBBBBBBBBBULL;
    std::memcpy(readOnlyBytes.data() + 0xE0, &lowSentinel, sizeof(lowSentinel));
    std::memcpy(readOnlyBytes.data() + 0xE8, &highSentinel, sizeof(highSentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(targetPage, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only RIP-relative MOVAPS target");
    rosa::x86::X86State faultState = state;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOVAPS to read-only memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(target), lowSentinel,
                "failed RIP-relative MOVAPS changed its low target lane");
    expectEqual(readOnlyAddressSpace.readU64(
                    rosa::guest::GuestAddress{target.value + sizeof(std::uint64_t)}),
                highSentinel, "failed RIP-relative MOVAPS changed its high target lane");
    expectEqual(faultState.xmm[0].low, state.xmm[0].low,
                "failed RIP-relative MOVAPS changed source low lane");
    expectEqual(faultState.xmm[0].high, state.xmm[0].high,
                "failed RIP-relative MOVAPS changed source high lane");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOVAPS changed flags");
}

void testMovapsGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x0F, 0x28, 0x45, 0xE0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovapsRegMem,
           "MOVAPS xmm, [mem] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbp && memory.displacement == -0x20 &&
               memory.width == 128,
           "MOVAPS xmm, [rbp-0x20] memory operand differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x80E0}, 0x0123456789ABCDEFULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x80E8}, 0xFEDCBA9876543210ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbp = 0x8100;
    state.xmm[0] = {.low = 1, .high = 2};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVAPS load low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVAPS load high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVAPS load changed flags");

    constexpr std::array<std::uint8_t, 7> movapdCode{0x66, 0x0F, 0x28, 0x44, 0x0E, 0xF8, 0xC3};
    const auto movapdDecoded =
        decoder.decodeBlock(movapdCode, rosa::guest::GuestAddress{0x7FF802A8C425ULL});
    expect(movapdDecoded[0].opcode == rosa::x86::Opcode::MovapdRegMem,
           "MOVAPD xmm, [indexed memory] opcode differs");
    const auto movapdMemory = std::get<rosa::x86::MemoryOperand>(movapdDecoded[0].operands[1]);
    expect(movapdMemory.base == rosa::x86::Register::Rsi &&
               movapdMemory.index == rosa::x86::Register::Rcx && movapdMemory.scale == 1 &&
               movapdMemory.displacement == -8 && movapdMemory.width == 128,
           "MOVAPD xmm0, [rsi+rcx-8] operands differ");
    expect(rosa::debug::dumpX86(movapdDecoded).find("movapd xmm0, [rsi+rcx*1-0x8]") !=
               std::string::npos,
           "MOVAPD indexed load dump differs");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8110}, 0x8877665544332211ULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8118}, 0x1020304050607080ULL);
    const auto movapdBlock =
        translator.translate(movapdCode, rosa::guest::GuestAddress{0x7FF802A8C425ULL});
    state.rsi = 0x8108;
    state.rcx = 0x10;
    state.xmm[0] = {};
    state.rflags = 0xAD7;
    static_cast<void>(movapdBlock.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "MOVAPD indexed load low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x1020304050607080ULL},
                "MOVAPD indexed load high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVAPD indexed load changed flags");

    constexpr std::array<std::uint8_t, 5> movapdRegisterCode{0x66, 0x0F, 0x28, 0xC4, 0xC3};
    const auto movapdRegisterDecoded =
        decoder.decodeBlock(movapdRegisterCode, rosa::guest::GuestAddress{0x7FF802A8C46DULL});
    expect(movapdRegisterDecoded[0].opcode == rosa::x86::Opcode::MovapdRegReg,
           "MOVAPD xmm, xmm opcode differs");
    expect(rosa::debug::dumpX86(movapdRegisterDecoded).find("movapd xmm0, xmm4") !=
               std::string::npos,
           "MOVAPD xmm, xmm dump differs");
    const auto movapdRegisterBlock =
        translator.translate(movapdRegisterCode, rosa::guest::GuestAddress{0x7FF802A8C46DULL});
    state.xmm[0] = {};
    state.xmm[4] = {
        .low = 0x0123456789ABCDEFULL,
        .high = 0xFEDCBA9876543210ULL,
    };
    state.rflags = 0xBD7;
    static_cast<void>(movapdRegisterBlock.execute(state));
    expectEqual(state.xmm[0].low, state.xmm[4].low, "MOVAPD register move low lane differs");
    expectEqual(state.xmm[0].high, state.xmm[4].high, "MOVAPD register move high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xBD7}, "MOVAPD register move changed flags");

    state.rbp = 0x8108;
    state.xmm[0] = {.low = 3, .high = 4};
    state.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("16-byte aligned") != std::string_view::npos;
    }
    expect(rejected, "unaligned MOVAPS guest load did not fault");
    expectEqual(state.rbp, std::uint64_t{0x8108}, "failed MOVAPS changed its base register");
    expectEqual(state.xmm[0].low, std::uint64_t{3}, "failed MOVAPS changed low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{4}, "failed MOVAPS changed high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "failed MOVAPS changed flags");
}

void testMovapsRipRelativeGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 8> code{0x0F, 0x28, 0x05, 0x19, 0xD0, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF70007CEE0ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF700089F00ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF700089000ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovapsRegMem,
           "RIP-relative MOVAPS load opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative MOVAPS load length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 128 &&
               memory.displacement == 0xD019,
           "RIP-relative MOVAPS load memory operand differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::XmmRegister::Xmm0,
           "RIP-relative MOVAPS load destination differs");
    expect(rosa::debug::dumpX86(decoded).find("movaps xmm0, [rip+0xd019]") != std::string::npos,
           "RIP-relative MOVAPS load dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x0123456789ABCDEFULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{target.value + sizeof(std::uint64_t)},
                          0xFEDCBA9876543210ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 1, .high = 2};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "RIP-relative MOVAPS loaded the wrong low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "RIP-relative MOVAPS loaded the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative MOVAPS load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.xmm[0] = {.low = 3, .high = 4};
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "unmapped RIP-relative MOVAPS load did not fault");
    expectEqual(faultState.xmm[0].low, std::uint64_t{3},
                "failed RIP-relative MOVAPS changed low lane");
    expectEqual(faultState.xmm[0].high, std::uint64_t{4},
                "failed RIP-relative MOVAPS changed high lane");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOVAPS changed flags");
}

void testMovupsRegisterToGuestMemoryWithSib() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x11, 0x44, 0x24, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovupsMemReg,
           "MOVUPS [mem], xmm opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rsp, "MOVUPS SIB base differs");
    expectEqual(memory.displacement, std::int64_t{0x10}, "MOVUPS SIB displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsp = 0x8103;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8113}), state.xmm[0].low,
                "MOVUPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x811B}), state.xmm[0].high,
                "MOVUPS stored the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVUPS changed flags");

    constexpr std::array<std::uint8_t, 6> extendedBaseCode{0x41, 0x0F, 0x11, 0x46, 0x50, 0xC3};
    const auto extendedBaseDecoded =
        decoder.decodeBlock(extendedBaseCode, rosa::guest::GuestAddress{0x1800});
    expect(extendedBaseDecoded[0].opcode == rosa::x86::Opcode::MovupsMemReg,
           "REX MOVUPS store opcode differs");
    expectEqual(extendedBaseDecoded[0].length, std::uint8_t{5}, "REX MOVUPS store length differs");
    const auto extendedMemory =
        std::get<rosa::x86::MemoryOperand>(extendedBaseDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::XmmRegisterOperand>(extendedBaseDecoded[0].operands[1]);
    expect(extendedMemory.base == rosa::x86::Register::R14 && extendedMemory.displacement == 0x50 &&
               extendedMemory.width == 128 && !extendedMemory.ripRelative,
           "REX MOVUPS store memory operand differs");
    expect(extendedSource.reg == rosa::x86::XmmRegister::Xmm0, "REX MOVUPS store source differs");
    expect(rosa::debug::dumpX86(extendedBaseDecoded).find("movups [r14+0x50], xmm0") !=
               std::string::npos,
           "REX MOVUPS store dump differs");
    const auto extendedBaseBlock =
        translator.translate(extendedBaseCode, rosa::guest::GuestAddress{0x1800});
    state.r14 = 0x8083;
    state.xmm[0] = {.low = 0x8877665544332211ULL, .high = 0x1020304050607080ULL};
    state.rflags = 0xAD7;
    static_cast<void>(extendedBaseBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x80D3}), state.xmm[0].low,
                "REX MOVUPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x80DB}), state.xmm[0].high,
                "REX MOVUPS stored the wrong high lane");
    expectEqual(state.r14, std::uint64_t{0x8083}, "REX MOVUPS changed its base register");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "REX MOVUPS changed flags");

    constexpr std::array<std::uint8_t, 5> indexedCode{0x0F, 0x11, 0x04, 0x17, 0xC3};
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, rosa::guest::GuestAddress{0x2000});
    expectEqual(indexedDecoded[0].length, std::uint8_t{4}, "indexed MOVUPS store length differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[0]);
    expect(indexedMemory.base == rosa::x86::Register::Rdi &&
               indexedMemory.index == rosa::x86::Register::Rdx && indexedMemory.scale == 1 &&
               indexedMemory.displacement == 0 && indexedMemory.width == 128,
           "indexed MOVUPS store effective address differs");
    expect(rosa::debug::dumpX86(indexedDecoded).find("movups [rdi+rdx*1], xmm0") !=
               std::string::npos,
           "indexed MOVUPS store dump differs");
    const auto indexedBlock = translator.translate(indexedCode, rosa::guest::GuestAddress{0x2000});
    state.rdi = memoryBase.value;
    state.rdx = 0x23;
    state.xmm[0] = {.low = 0x8877665544332211ULL, .high = 0x1020304050607080ULL};
    state.rflags = 0xAD7;
    static_cast<void>(indexedBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8023}), state.xmm[0].low,
                "indexed MOVUPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x802B}), state.xmm[0].high,
                "indexed MOVUPS stored the wrong high lane");
    expectEqual(state.rdi, memoryBase.value, "indexed MOVUPS changed its base");
    expectEqual(state.rdx, std::uint64_t{0x23}, "indexed MOVUPS changed its index");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "indexed MOVUPS changed flags");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FF8};
    constexpr std::array<std::uint8_t, 8> sentinel{1, 2, 3, 4, 5, 6, 7, 8};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, sentinel);
    state.rdi = memoryBase.value;
    state.rdx = crossPageTarget.value - memoryBase.value;
    state.rflags = 0xBD7;
    bool rejected = false;
    try {
        static_cast<void>(indexedBlock.execute(state, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page indexed MOVUPS did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, sentinel.size()) ==
               std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
           "cross-page indexed MOVUPS partially changed memory");
    expectEqual(state.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "faulted indexed MOVUPS changed low XMM lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0x1020304050607080ULL},
                "faulted indexed MOVUPS changed high XMM lane");
    expectEqual(state.rflags, std::uint64_t{0xBD7}, "faulted indexed MOVUPS changed flags");

    // Observed in libsqlite3: MOVUPD [RBP-0x180], XMM0 (66 0F 11 stores like MOVUPS).
    constexpr std::array<std::uint8_t, 9> unalignedDoubleCode{0x66, 0x0F, 0x11, 0x85,
                                                              0x80, 0xFE, 0xFF, 0xFF, 0xC3};
    const auto unalignedDoubleDecoded =
        decoder.decodeBlock(unalignedDoubleCode, rosa::guest::GuestAddress{0x100002D1DULL});
    expect(unalignedDoubleDecoded[0].opcode == rosa::x86::Opcode::MovupsMemReg,
           "MOVUPD [mem], xmm opcode differs");
    expectEqual(unalignedDoubleDecoded[0].length, std::uint8_t{8},
                "MOVUPD [mem], xmm length differs");
    const auto unalignedDoubleMemory =
        std::get<rosa::x86::MemoryOperand>(unalignedDoubleDecoded[0].operands[0]);
    expect(unalignedDoubleMemory.base == rosa::x86::Register::Rbp &&
               unalignedDoubleMemory.displacement == -0x180 &&
               unalignedDoubleMemory.width == 128,
           "MOVUPD [rbp-0x180], xmm0 memory operand differs");
    expect(rosa::debug::dumpX86(unalignedDoubleDecoded).find("movups [rbp-0x180], xmm0") !=
               std::string::npos,
           "MOVUPD [mem], xmm dump differs");
    const auto unalignedDoubleBlock =
        translator.translate(unalignedDoubleCode, rosa::guest::GuestAddress{0x100002D1DULL});
    constexpr rosa::guest::GuestAddress unalignedDoubleTarget{0x8100};
    rosa::x86::X86State unalignedDoubleState;
    unalignedDoubleState.rbp = unalignedDoubleTarget.value + 0x180;
    unalignedDoubleState.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    unalignedDoubleState.rflags = 0x8D7;
    static_cast<void>(unalignedDoubleBlock.execute(unalignedDoubleState, &addressSpace));
    expectEqual(addressSpace.readU64(unalignedDoubleTarget), unalignedDoubleState.xmm[0].low,
                "MOVUPD stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8108}),
                unalignedDoubleState.xmm[0].high, "MOVUPD stored the wrong high lane");
    expectEqual(unalignedDoubleState.rflags, std::uint64_t{0x8D7}, "MOVUPD store changed flags");
}

void testMovupsRegisterToRipRelativeGuestMemory() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF800058A0CULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8000C8DC0ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF8000C8000ULL};
    constexpr std::array<std::uint8_t, 8> code{0x0F, 0x11, 0x05, 0xAD, 0x03, 0x07, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovupsMemReg,
           "RIP-relative MOVUPS store opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "RIP-relative MOVUPS store length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase,
           "RIP-relative MOVUPS store addressing kind differs");
    expectEqual(memory.displacement, std::int64_t{0x703AD},
                "RIP-relative MOVUPS store displacement differs");
    expectEqual(memory.width, std::uint8_t{128}, "RIP-relative MOVUPS store width differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::XmmRegister::Xmm0,
           "RIP-relative MOVUPS store source differs");
    expect(rosa::debug::dumpX86(decoded).find("movups [rip+0x703ad], xmm0") != std::string::npos,
           "RIP-relative MOVUPS store dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.xmm[0] = {
        .low = 0x0123456789ABCDEFULL,
        .high = 0xFEDCBA9876543210ULL,
    };
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), state.xmm[0].low,
                "RIP-relative MOVUPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{target.value + 8}),
                state.xmm[0].high, "RIP-relative MOVUPS stored the wrong high lane");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "RIP-relative MOVUPS changed its low source lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "RIP-relative MOVUPS changed its high source lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative MOVUPS changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    std::fill_n(readOnlyBytes.begin() +
                    static_cast<std::ptrdiff_t>(target.value - targetPage.value),
                16, std::uint8_t{0xA5});
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(targetPage, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, readOnlyBytes,
                                    "read-only RIP-relative MOVUPS target");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOVUPS accepted a read-only target");
    const auto unchanged = readOnlyAddressSpace.readBytes(target, 16);
    expect(std::ranges::all_of(unchanged, [](std::uint8_t byte) { return byte == 0xA5; }),
           "failed RIP-relative MOVUPS partially changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "failed RIP-relative MOVUPS changed flags");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "failed RIP-relative MOVUPS changed its source");
}

void testMovupsGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 6> code{0x41, 0x0F, 0x10, 0x47, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovupsRegMem,
           "MOVUPS xmm, [mem] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R15, "MOVUPS load REX.B base differs");
    expectEqual(memory.displacement, std::int64_t{0x18}, "MOVUPS load displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x811B}, 0x0123456789ABCDEFULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8123}, 0xFEDCBA9876543210ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r15 = 0x8103;
    state.xmm[0] = {.low = 1, .high = 2};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVUPS load low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVUPS load high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVUPS load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.xmm[0] = {.low = 3, .high = 4};
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOVUPS load from unmapped guest memory did not fault");
    expectEqual(state.xmm[0].low, std::uint64_t{3}, "failed MOVUPS load changed low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{4}, "failed MOVUPS load changed high lane");

    constexpr std::array<std::uint8_t, 6> indexedCode{0x43, 0x0F, 0x10, 0x04, 0x2C, 0xC3};
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, rosa::guest::GuestAddress{0x2000});
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovupsRegMem,
           "indexed MOVUPS opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{5}, "indexed MOVUPS length differs");
    const auto indexedDestination =
        std::get<rosa::x86::XmmRegisterOperand>(indexedDecoded[0].operands[0]);
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[1]);
    expect(indexedDestination.reg == rosa::x86::XmmRegister::Xmm0,
           "indexed MOVUPS destination differs");
    expect(indexedMemory.base == rosa::x86::Register::R12 &&
               indexedMemory.index == rosa::x86::Register::R13 && indexedMemory.scale == 1 &&
               indexedMemory.displacement == 0,
           "indexed MOVUPS effective-address operands differ");
    expect(rosa::debug::dumpX86(indexedDecoded).find("movups xmm0, [r12+r13*1]") !=
               std::string::npos,
           "indexed MOVUPS dump differs");

    addressSpace.writeU64(rosa::guest::GuestAddress{0x8023}, 0x8877665544332211ULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x802B}, 0x0123456789ABCDEFULL);
    const auto indexedBlock = translator.translate(indexedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State indexedState;
    indexedState.r12 = 0x8003;
    indexedState.r13 = 0x20;
    indexedState.xmm[0] = {.low = UINT64_MAX, .high = UINT64_MAX};
    indexedState.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(indexedState.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "indexed MOVUPS loaded the wrong low lane");
    expectEqual(indexedState.xmm[0].high, std::uint64_t{0x0123456789ABCDEFULL},
                "indexed MOVUPS loaded the wrong high lane");
    expectEqual(indexedState.r12, std::uint64_t{0x8003}, "indexed MOVUPS changed its base");
    expectEqual(indexedState.r13, std::uint64_t{0x20}, "indexed MOVUPS changed its index");
    expectEqual(indexedState.rflags, std::uint64_t{0x8D7}, "indexed MOVUPS changed flags");

    rosa::x86::X86State indexedFaultState;
    indexedFaultState.r12 = 0xA003;
    indexedFaultState.r13 = 0x20;
    indexedFaultState.xmm[0] = {.low = 0x55, .high = 0xAA};
    indexedFaultState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(indexedBlock.execute(indexedFaultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed MOVUPS from unmapped guest memory did not fault");
    expectEqual(indexedFaultState.xmm[0].low, std::uint64_t{0x55},
                "failed indexed MOVUPS changed the low lane");
    expectEqual(indexedFaultState.xmm[0].high, std::uint64_t{0xAA},
                "failed indexed MOVUPS changed the high lane");
    expectEqual(indexedFaultState.rflags, std::uint64_t{0xAD7},
                "failed indexed MOVUPS changed flags");

    // Observed in libsqlite3: MOVUPD XMM0, [RBX+0x70] (66 0F 10 loads like MOVUPS).
    constexpr std::array<std::uint8_t, 6> unalignedDoubleCode{0x66, 0x0F, 0x10, 0x43, 0x70, 0xC3};
    const auto unalignedDoubleDecoded =
        decoder.decodeBlock(unalignedDoubleCode, rosa::guest::GuestAddress{0x100002993ULL});
    expect(unalignedDoubleDecoded[0].opcode == rosa::x86::Opcode::MovupsRegMem,
           "MOVUPD xmm, [mem] opcode differs");
    expectEqual(unalignedDoubleDecoded[0].length, std::uint8_t{5},
                "MOVUPD xmm, [mem] length differs");
    const auto unalignedDoubleMemory =
        std::get<rosa::x86::MemoryOperand>(unalignedDoubleDecoded[0].operands[1]);
    expect(unalignedDoubleMemory.base == rosa::x86::Register::Rbx &&
               unalignedDoubleMemory.displacement == 0x70,
           "MOVUPD [rbx+0x70] memory operand differs");
    const auto unalignedDoubleBlock =
        translator.translate(unalignedDoubleCode, rosa::guest::GuestAddress{0x100002993ULL});
    // Deliberately unaligned: MOVUPD must not fault on alignment.
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8071}, 0xAAAAAAAAAAAAAAAAULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8079}, 0x5555555555555555ULL);
    rosa::x86::X86State unalignedDoubleState;
    unalignedDoubleState.rbx = 0x8001;
    unalignedDoubleState.xmm[0] = {.low = 1, .high = 2};
    unalignedDoubleState.rflags = 0x8D7;
    static_cast<void>(unalignedDoubleBlock.execute(unalignedDoubleState, &addressSpace));
    expectEqual(unalignedDoubleState.xmm[0].low, std::uint64_t{0xAAAAAAAAAAAAAAAAULL},
                "MOVUPD loaded the wrong low lane");
    expectEqual(unalignedDoubleState.xmm[0].high, std::uint64_t{0x5555555555555555ULL},
                "MOVUPD loaded the wrong high lane");
    expectEqual(unalignedDoubleState.rflags, std::uint64_t{0x8D7}, "MOVUPD changed flags");
}

void testVexXmmShortCopyInstructions() {
    constexpr rosa::guest::GuestAddress codeAddress{0x1000};
    constexpr rosa::guest::GuestAddress memoryPage{0x8000};
    const rosa::x86::Decoder decoder;
    const rosa::dbt::Translator translator;

    constexpr std::array<std::uint8_t, 7> loadCode{0xC5, 0xF8, 0x10, 0x4C, 0x16, 0xF0, 0xC3};
    const auto loadDecoded = decoder.decodeBlock(loadCode, codeAddress);
    expect(loadDecoded[0].opcode == rosa::x86::Opcode::VmovupsRegMem,
           "VMOVUPS load opcode differs");
    expectEqual(loadDecoded[0].length, std::uint8_t{6}, "VMOVUPS load length differs");
    const auto loadDestination =
        std::get<rosa::x86::XmmRegisterOperand>(loadDecoded[0].operands[0]);
    const auto loadMemory = std::get<rosa::x86::MemoryOperand>(loadDecoded[0].operands[1]);
    expect(loadDestination.reg == rosa::x86::XmmRegister::Xmm1 &&
               loadMemory.base == rosa::x86::Register::Rsi &&
               loadMemory.index == rosa::x86::Register::Rdx && loadMemory.scale == 1 &&
               loadMemory.displacement == -0x10 && loadMemory.width == 128,
           "VMOVUPS load operands differ");
    expect(rosa::debug::dumpX86(loadDecoded).find("vmovups xmm1, [rsi+rdx*1-0x10]") !=
               std::string::npos,
           "VMOVUPS load dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8030}, 0x0123456789ABCDEFULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8038}, 0xFEDCBA9876543210ULL);
    rosa::x86::X86State state;
    state.rsi = memoryPage.value;
    state.rdx = 0x40;
    state.xmm[1] = {.low = 1, .high = 2};
    state.ymmUpper[1] = {.low = 3, .high = 4};
    state.rflags = 0x8D7;
    const auto loadBlock = translator.translate(loadCode, codeAddress);
    static_cast<void>(loadBlock.execute(state, &addressSpace));
    expectEqual(state.xmm[1].low, std::uint64_t{0x0123456789ABCDEFULL},
                "VMOVUPS loaded the wrong low lane");
    expectEqual(state.xmm[1].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "VMOVUPS loaded the wrong high lane");
    expectEqual(state.ymmUpper[1].low, std::uint64_t{0},
                "128-bit VMOVUPS did not clear the low upper-YMM lane");
    expectEqual(state.ymmUpper[1].high, std::uint64_t{0},
                "128-bit VMOVUPS did not clear the high upper-YMM lane");
    expectEqual(state.rsi, memoryPage.value, "VMOVUPS load changed its base");
    expectEqual(state.rdx, std::uint64_t{0x40}, "VMOVUPS load changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "VMOVUPS load changed flags");

    constexpr std::array<std::uint8_t, 6> storeCode{0xC5, 0xF8, 0x11, 0x0C, 0x17, 0xC3};
    const auto storeDecoded = decoder.decodeBlock(storeCode, codeAddress);
    expect(storeDecoded[0].opcode == rosa::x86::Opcode::VmovupsMemReg,
           "VMOVUPS store opcode differs");
    expectEqual(storeDecoded[0].length, std::uint8_t{5}, "VMOVUPS store length differs");
    const auto storeMemory = std::get<rosa::x86::MemoryOperand>(storeDecoded[0].operands[0]);
    const auto storeSource = std::get<rosa::x86::XmmRegisterOperand>(storeDecoded[0].operands[1]);
    expect(storeMemory.base == rosa::x86::Register::Rdi &&
               storeMemory.index == rosa::x86::Register::Rdx && storeMemory.scale == 1 &&
               storeMemory.displacement == 0 && storeSource.reg == rosa::x86::XmmRegister::Xmm1,
           "VMOVUPS store operands differ");
    expect(rosa::debug::dumpX86(storeDecoded).find("vmovups [rdi+rdx*1], xmm1") !=
               std::string::npos,
           "VMOVUPS store dump differs");
    state.rdi = memoryPage.value;
    state.rdx = 0x50;
    state.xmm[1] = {.low = 0x8877665544332211ULL, .high = 0x1020304050607080ULL};
    state.rflags = 0xAD7;
    const auto storeBlock = translator.translate(storeCode, codeAddress);
    static_cast<void>(storeBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8050}),
                std::uint64_t{0x8877665544332211ULL}, "VMOVUPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8058}),
                std::uint64_t{0x1020304050607080ULL}, "VMOVUPS stored the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "VMOVUPS store changed flags");

    constexpr std::array<std::uint8_t, 5> xorCode{0xC5, 0xF0, 0x57, 0xC9, 0xC3};
    const auto xorDecoded = decoder.decodeBlock(xorCode, codeAddress);
    expect(xorDecoded[0].opcode == rosa::x86::Opcode::VxorpsRegRegReg, "VXORPS opcode differs");
    expect(rosa::debug::dumpX86(xorDecoded).find("vxorps xmm1, xmm1, xmm1") != std::string::npos,
           "VXORPS dump differs");
    state.xmm[1] = {.low = UINT64_MAX, .high = 0x123456789ABCDEF0ULL};
    state.ymmUpper[1] = {.low = UINT64_MAX, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0xBD7;
    const auto xorBlock = translator.translate(xorCode, codeAddress);
    static_cast<void>(xorBlock.execute(state, &addressSpace));
    expectEqual(state.xmm[1].low, std::uint64_t{0}, "VXORPS did not clear its low lane");
    expectEqual(state.xmm[1].high, std::uint64_t{0}, "VXORPS did not clear its high lane");
    expectEqual(state.ymmUpper[1].low, std::uint64_t{0},
                "128-bit VXORPS did not clear the low upper-YMM lane");
    expectEqual(state.ymmUpper[1].high, std::uint64_t{0},
                "128-bit VXORPS did not clear the high upper-YMM lane");
    expectEqual(state.rflags, std::uint64_t{0xBD7}, "VXORPS changed flags");

    constexpr std::array<std::uint8_t, 4> zeroUpperCode{0xC5, 0xF8, 0x77, 0xC3};
    const auto zeroUpperDecoded = decoder.decodeBlock(zeroUpperCode, codeAddress);
    expect(zeroUpperDecoded[0].opcode == rosa::x86::Opcode::Vzeroupper,
           "VZEROUPPER opcode differs");
    expect(rosa::debug::dumpX86(zeroUpperDecoded).find("vzeroupper") != std::string::npos,
           "VZEROUPPER dump differs");
    state.xmm[1] = {.low = 0x55, .high = 0xAA};
    state.ymmUpper[1] = {.low = UINT64_MAX, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0xCD7;
    const auto zeroUpperBlock = translator.translate(zeroUpperCode, codeAddress);
    static_cast<void>(zeroUpperBlock.execute(state, &addressSpace));
    expectEqual(state.xmm[1].low, std::uint64_t{0x55}, "VZEROUPPER changed modeled low XMM state");
    expectEqual(state.xmm[1].high, std::uint64_t{0xAA},
                "VZEROUPPER changed modeled high XMM state");
    expectEqual(state.ymmUpper[1].low, std::uint64_t{0},
                "VZEROUPPER did not clear the low upper-YMM lane");
    expectEqual(state.ymmUpper[1].high, std::uint64_t{0},
                "VZEROUPPER did not clear the high upper-YMM lane");
    expectEqual(state.rflags, std::uint64_t{0xCD7}, "VZEROUPPER changed flags");
}

void testVexYmmBroadcastAndStore() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802E7AE50ULL};
    constexpr rosa::guest::GuestAddress memoryPage{0x8000};
    constexpr std::array<std::uint8_t, 11> code{0xC4, 0xE2, 0x7D, 0x18, 0xC0, 0xC5,
                                                0xFC, 0x11, 0x07, 0xEB, 0x00};

    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expectEqual(decoded.size(), std::size_t{3},
                "YMM broadcast/store test block instruction count differs");
    expect(decoded[0].opcode == rosa::x86::Opcode::VbroadcastssYmmReg && decoded[0].length == 5,
           "VBROADCASTSS YMM opcode or length differs");
    const auto broadcastDestination =
        std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto broadcastSource = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(broadcastDestination.reg == rosa::x86::XmmRegister::Xmm0 &&
               broadcastSource.reg == rosa::x86::XmmRegister::Xmm0,
           "VBROADCASTSS ymm0, xmm0 operands differ");
    expect(decoded[1].opcode == rosa::x86::Opcode::VmovupsYmmMemReg && decoded[1].length == 4,
           "256-bit VMOVUPS opcode or length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[1].operands[0]);
    const auto storeSource = std::get<rosa::x86::XmmRegisterOperand>(decoded[1].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdi && !memory.index && memory.displacement == 0 &&
               memory.width == 256 && storeSource.reg == rosa::x86::XmmRegister::Xmm0,
           "VMOVUPS [rdi], ymm0 operands differ");
    const auto dump = rosa::debug::dumpX86(decoded);
    expect(dump.find("vbroadcastss ymm0, xmm0") != std::string::npos &&
               dump.find("vmovups [rdi], ymm0") != std::string::npos,
           "YMM broadcast/store dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("store_guest_ymm.i256") !=
               std::string::npos,
           "256-bit VMOVUPS did not lower through YMM store IR");
    rosa::x86::X86State state;
    state.rip = instructionAddress.value;
    state.rdi = 0x8043;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.ymmUpper[0] = {.low = 1, .high = 2};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    constexpr std::uint64_t packed = 0x89ABCDEF89ABCDEFULL;
    expectEqual(state.xmm[0].low, packed, "VBROADCASTSS produced the wrong first qword");
    expectEqual(state.xmm[0].high, packed, "VBROADCASTSS produced the wrong second qword");
    expectEqual(state.ymmUpper[0].low, packed, "VBROADCASTSS produced the wrong third qword");
    expectEqual(state.ymmUpper[0].high, packed, "VBROADCASTSS produced the wrong fourth qword");
    for (std::uint64_t offset = 0; offset < 32; offset += 8) {
        expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{state.rdi + offset}), packed,
                    "256-bit VMOVUPS stored the wrong qword");
    }
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "YMM broadcast/store changed flags");

    constexpr std::array<std::uint8_t, 11> alignedStoreCode{0xC5, 0xFC, 0x29, 0x07, 0xC5, 0xFC,
                                                            0x29, 0x47, 0x20, 0xEB, 0x00};
    const auto alignedDecoded = decoder.decodeBlock(alignedStoreCode, instructionAddress);
    expect(alignedDecoded[0].opcode == rosa::x86::Opcode::VmovapsYmmMemReg &&
               alignedDecoded[1].opcode == rosa::x86::Opcode::VmovapsYmmMemReg,
           "256-bit VMOVAPS store opcodes differ");
    const auto secondAlignedMemory =
        std::get<rosa::x86::MemoryOperand>(alignedDecoded[1].operands[0]);
    expect(secondAlignedMemory.base == rosa::x86::Register::Rdi &&
               secondAlignedMemory.displacement == 0x20 && secondAlignedMemory.width == 256,
           "second 256-bit VMOVAPS store operand differs");
    expect(rosa::debug::dumpX86(alignedDecoded).find("vmovaps [rdi+0x20], ymm0") !=
               std::string::npos,
           "256-bit VMOVAPS dump differs");
    const auto alignedStore = translator.translate(alignedStoreCode, instructionAddress);
    state.rdi = 0x8080;
    state.xmm[0] = {.low = 1, .high = 2};
    state.ymmUpper[0] = {.low = 3, .high = 4};
    state.rflags = 0xAD7;
    static_cast<void>(alignedStore.execute(state, &addressSpace));
    for (const auto base : {std::uint64_t{0x8080}, std::uint64_t{0x80A0}}) {
        expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{base}), std::uint64_t{1},
                    "256-bit VMOVAPS stored the wrong first qword");
        expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{base + 8}), std::uint64_t{2},
                    "256-bit VMOVAPS stored the wrong second qword");
        expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{base + 16}), std::uint64_t{3},
                    "256-bit VMOVAPS stored the wrong third qword");
        expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{base + 24}), std::uint64_t{4},
                    "256-bit VMOVAPS stored the wrong fourth qword");
    }
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "256-bit VMOVAPS changed flags");

    rosa::guest::AddressSpace misalignedAddressSpace;
    misalignedAddressSpace.mapAnonymous(memoryPage, rosa::guest::guestPageSize,
                                        rosa::guest::Permission::Read |
                                            rosa::guest::Permission::Write);
    const std::vector<std::uint8_t> alignmentSentinel(64, 0xA5);
    misalignedAddressSpace.writeBytes(rosa::guest::GuestAddress{0x8081}, alignmentSentinel);
    rosa::x86::X86State misalignedState = state;
    misalignedState.rdi = 0x8081;
    bool misaligned = false;
    try {
        static_cast<void>(alignedStore.execute(misalignedState, &misalignedAddressSpace));
    } catch (const std::runtime_error &error) {
        misaligned =
            std::string_view(error.what()).find("32-byte aligned") != std::string_view::npos;
    }
    expect(misaligned, "256-bit VMOVAPS accepted a misaligned target");
    expectEqual(misalignedAddressSpace.readBytes(rosa::guest::GuestAddress{0x8081}, 64),
                alignmentSentinel, "misaligned 256-bit VMOVAPS changed guest memory");

    constexpr std::array<std::uint8_t, 6> storeOnlyCode{0xC5, 0xFC, 0x11, 0x07, 0xEB, 0x00};
    const auto storeOnly = translator.translate(storeOnlyCode, instructionAddress);
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(memoryPage, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FF0};
    const std::vector<std::uint8_t> sentinel(16, 0xA5);
    crossPageAddressSpace.writeBytes(crossPageTarget, sentinel);
    rosa::x86::X86State faultState;
    faultState.rip = instructionAddress.value;
    faultState.rdi = crossPageTarget.value;
    faultState.xmm[0] = {.low = 1, .high = 2};
    faultState.ymmUpper[0] = {.low = 3, .high = 4};
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        static_cast<void>(storeOnly.execute(faultState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "cross-page 256-bit VMOVUPS did not fault");
    expectEqual(crossPageAddressSpace.readBytes(crossPageTarget, 16), sentinel,
                "faulted 256-bit VMOVUPS partially changed guest memory");
    expectEqual(faultState.xmm[0].low, std::uint64_t{1},
                "faulted 256-bit VMOVUPS changed lower YMM state");
    expectEqual(faultState.ymmUpper[0].high, std::uint64_t{4},
                "faulted 256-bit VMOVUPS changed upper YMM state");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted 256-bit VMOVUPS changed flags");
}

} // namespace

std::span<const TestCase> simdIntegerTests() {
    static const TestCase cases[]{
        {"XORPS register generated execution", testXorpsRegisterGeneratedExecution},
        {"XORPS guest memory generated execution", testXorpsGuestMemoryGeneratedExecution},
        {"XORPD register generated execution", testXorpdRegisterGeneratedExecution},
        {"PXOR register generated execution", testPxorRegisterGeneratedExecution},
        {"PXOR extended register generated execution", testPxorExtendedRegisterGeneratedExecution},
        {"PXOR guest memory generated execution", testPxorGuestMemoryGeneratedExecution},
        {"PAND RIP-relative guest memory generated execution", testPandRipGuestMemoryGeneratedExecution},
        {"PAND register generated execution", testPandRegisterGeneratedExecution},
        {"PTEST register generated execution", testPtestRegisterGeneratedExecution},
        {"PCMPEQB guest memory generated execution", testPcmpeqbGuestMemoryGeneratedExecution},
        {"PCMPEQB register generated execution", testPcmpeqbRegisterGeneratedExecution},
        {"PCMPEQD register generated execution", testPcmpeqdRegisterGeneratedExecution},
        {"packed dword shift and add generated execution", testPackedDwordShiftAndAddGeneratedExecution},
        {"packed word add generated execution", testPackedWordAddGeneratedExecution},
        {"packed double compare generated execution", testPackedDoubleCompareGeneratedExecution},
        {"packed dword logical right shift immediate", testPackedDwordLogicalRightShiftImmediate},
        {"packed qword logical right shift immediate", testPackedQwordLogicalRightShiftImmediate},
        {"packed dword add RIP-relative memory", testPackedDwordAddRipMemory},
        {"packed horizontal add and MOVD extract", testPackedHorizontalAddAndMovdExtract},
        {"PMOVZXBD register to register", testPmovzxbdRegisterToRegister},
        {"PANDN register generated execution", testPandnRegisterGeneratedExecution},
        {"PMOVMSKB generated execution", testPmovmskbGeneratedExecution},
        {"PMOVSXBD RIP-relative memory generated execution", testPmovsxbdRipMemoryGeneratedExecution},
        {"PMOVSXBQ RIP-relative memory execution", testPmovsxbqRipMemoryGeneratedExecution},
        {"PMOVSXDQ RIP-relative memory generated execution", testPmovsxdqRipMemoryGeneratedExecution},
        {"PADDQ register execution", testPaddqRegisterExecution},
        {"PSHUFD register execution", testPshufdRegisterExecution},
        {"SHUFPD register execution", testShufpdRegisterExecution},
        {"SHUFPS register execution", testShufpsRegisterExecution},
        {"PALIGNR register execution", testPalignrRegisterExecution},
        {"MOVAPS register to guest memory", testMovapsRegisterToGuestMemory},
        {"MOVAPS register to RIP-relative guest memory", testMovapsRegisterToRipRelativeGuestMemory},
        {"MOVAPS guest memory to register", testMovapsGuestMemoryToRegister},
        {"MOVAPS RIP-relative guest memory to register", testMovapsRipRelativeGuestMemoryToRegister},
        {"MOVUPS register to guest memory with SIB", testMovupsRegisterToGuestMemoryWithSib},
        {"MOVUPS register to RIP-relative guest memory", testMovupsRegisterToRipRelativeGuestMemory},
        {"MOVUPS guest memory to register", testMovupsGuestMemoryToRegister},
        {"VEX XMM short-copy instructions", testVexXmmShortCopyInstructions},
        {"VEX YMM broadcast and store", testVexYmmBroadcastAndStore},
    };
    return cases;
}

} // namespace rosa::tests
