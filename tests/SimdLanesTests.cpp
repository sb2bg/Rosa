#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testPshufbRegisters() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x38, 0x00, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A8CCEDULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::PshufbRegReg, "PSHUFB opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "PSHUFB length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "PSHUFB xmm0, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pshufb xmm0, xmm1") != std::string::npos,
           "PSHUFB dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A8CCEDULL});
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0706050403020100ULL, .high = 0x0F0E0D0C0B0A0908ULL};
    state.xmm[1] = {.low = 0x0807820100800E0FULL, .high = 0xFF0F0E0D0C0B0A09ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0807000100000E0FULL},
                "PSHUFB produced the wrong low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0x000F0E0D0C0B0A09ULL},
                "PSHUFB produced the wrong high lane");
    expectEqual(state.xmm[1].low, std::uint64_t{0x0807820100800E0FULL},
                "PSHUFB changed its control source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PSHUFB changed flags");
}

void testPshufbRipRelativeGuestMemory() {
    constexpr std::array<std::uint8_t, 10> code{0x66, 0x0F, 0x38, 0x00, 0x05,
                                                0xB3, 0xCF, 0x03, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802B2E6F4ULL};
    constexpr rosa::guest::GuestAddress controlAddress{0x7FF802B6B6B0ULL};
    constexpr rosa::guest::GuestAddress controlPage{0x7FF802B6B000ULL};
    constexpr std::array<std::uint8_t, 16> control{0x0F, 0x0E, 0x80, 0x00, 0x01, 0x82, 0x07, 0x08,
                                                   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF};

    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PshufbRegMem,
           "RIP-relative PSHUFB opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{9}, "RIP-relative PSHUFB length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::XmmRegister::Xmm0,
           "RIP-relative PSHUFB destination differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && !memory.index && memory.width == 128 &&
               memory.displacement == 0x3CFB3,
           "RIP-relative PSHUFB memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("pshufb xmm0, [rip+0x3cfb3]") != std::string::npos,
           "RIP-relative PSHUFB dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(controlPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "PSHUFB control table");
    addressSpace.writeBytes(controlAddress, control);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0706050403020100ULL, .high = 0x0F0E0D0C0B0A0908ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0807000100000E0FULL},
                "memory PSHUFB produced the wrong low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0x000F0E0D0C0B0A09ULL},
                "memory PSHUFB produced the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "memory PSHUFB changed flags");
    expectEqual(addressSpace.readBytes(controlAddress, control.size()),
                std::vector<std::uint8_t>(control.begin(), control.end()),
                "memory PSHUFB changed its control table");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.xmm[0] = {.low = 0x1111222233334444ULL, .high = 0x5555666677778888ULL};
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "unmapped RIP-relative PSHUFB did not fault");
    expectEqual(faultState.xmm[0].low, std::uint64_t{0x1111222233334444ULL},
                "faulted PSHUFB changed its low lane");
    expectEqual(faultState.xmm[0].high, std::uint64_t{0x5555666677778888ULL},
                "faulted PSHUFB changed its high lane");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted PSHUFB changed flags");
}

void testPunpcklwdRegisters() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x61, 0xD9, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF80681D353ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PunpcklwdRegReg, "PUNPCKLWD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "PUNPCKLWD length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
                   rosa::x86::XmmRegister::Xmm3 &&
               std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
                   rosa::x86::XmmRegister::Xmm1,
           "PUNPCKLWD operands differ");
    expect(rosa::debug::dumpX86(decoded).find("punpcklwd xmm3, xmm1") != std::string::npos,
           "PUNPCKLWD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("unpack_low_xmm_words.i16 xmm3, xmm1") != std::string::npos,
           "PUNPCKLWD IR differs");
    rosa::x86::X86State state;
    state.xmm[3] = {.low = UINT64_C(0x4444333322221111), .high = UINT64_C(0x8888777766665555)};
    state.xmm[1] = {.low = UINT64_C(0xDDDDCCCCBBBBAAAA), .high = UINT64_C(0x9999888877776666)};
    state.ymmUpper[3] = {.low = UINT64_C(0x1122334455667788), .high = UINT64_C(0x8877665544332211)};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[3].low, UINT64_C(0xBBBB2222AAAA1111), "PUNPCKLWD low lane differs");
    expectEqual(state.xmm[3].high, UINT64_C(0xDDDD4444CCCC3333), "PUNPCKLWD high lane differs");
    expectEqual(state.xmm[1].low, UINT64_C(0xDDDDCCCCBBBBAAAA), "PUNPCKLWD changed its source");
    expectEqual(state.ymmUpper[3].low, UINT64_C(0x1122334455667788),
                "legacy PUNPCKLWD changed upper YMM state");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PUNPCKLWD changed flags");

    constexpr std::array<std::uint8_t, 5> aliasCode{0x66, 0x0F, 0x61, 0xC0, 0xC3};
    const auto aliasBlock = translator.translate(aliasCode, rosa::guest::GuestAddress{0x1000});
    state.xmm[0] = {.low = UINT64_C(0x0004000300020001), .high = UINT64_MAX};
    static_cast<void>(aliasBlock.execute(state));
    expectEqual(state.xmm[0].low, UINT64_C(0x0002000200010001),
                "aliased PUNPCKLWD low lane differs");
    expectEqual(state.xmm[0].high, UINT64_C(0x0004000400030003),
                "aliased PUNPCKLWD high lane differs");

    constexpr std::array<std::uint8_t, 6> extendedCode{0x66, 0x45, 0x0F, 0x61, 0xE8, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x2000});
    expect(std::get<rosa::x86::XmmRegisterOperand>(extendedDecoded[0].operands[0]).reg ==
                   rosa::x86::XmmRegister::Xmm13 &&
               std::get<rosa::x86::XmmRegisterOperand>(extendedDecoded[0].operands[1]).reg ==
                   rosa::x86::XmmRegister::Xmm8,
           "REX PUNPCKLWD operands differ");
}

void testPunpcklqdqRegisters() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x6C, 0xD1, 0xC3};
    constexpr rosa::guest::GuestAddress rip{0x7FF802AB965FULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PunpcklqdqRegReg, "PUNPCKLQDQ opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "PUNPCKLQDQ length differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]).reg ==
                   rosa::x86::XmmRegister::Xmm2 &&
               std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
                   rosa::x86::XmmRegister::Xmm1,
           "PUNPCKLQDQ operands differ");
    expect(rosa::debug::dumpX86(decoded).find("punpcklqdq xmm2, xmm1") != std::string::npos,
           "PUNPCKLQDQ dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State state;
    state.xmm[2] = {.low = UINT64_C(0x2222222222222222), .high = UINT64_C(0xAAAAAAAAAAAAAAAA)};
    state.xmm[1] = {.low = UINT64_C(0x1111111111111111), .high = UINT64_C(0xBBBBBBBBBBBBBBBB)};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[2].low, UINT64_C(0x2222222222222222), "PUNPCKLQDQ low lane differs");
    expectEqual(state.xmm[2].high, UINT64_C(0x1111111111111111), "PUNPCKLQDQ high lane differs");
    expectEqual(state.xmm[1].low, UINT64_C(0x1111111111111111), "PUNPCKLQDQ changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PUNPCKLQDQ changed flags");

    constexpr std::array<std::uint8_t, 5> aliasCode{0x66, 0x0F, 0x6C, 0xC0, 0xC3};
    const auto aliasBlock = translator.translate(aliasCode, rosa::guest::GuestAddress{0x1000});
    state.xmm[0] = {.low = UINT64_C(0xDEADBEEFCAFEBABE), .high = UINT64_MAX};
    static_cast<void>(aliasBlock.execute(state));
    expectEqual(state.xmm[0].low, UINT64_C(0xDEADBEEFCAFEBABE),
                "aliased PUNPCKLQDQ low lane differs");
    expectEqual(state.xmm[0].high, UINT64_C(0xDEADBEEFCAFEBABE),
                "aliased PUNPCKLQDQ high lane differs");
}

void testPorRegisters() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0xEB, 0xD1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A8CD08ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::PorRegReg, "POR opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "POR length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm2 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "POR xmm2, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("por xmm2, xmm1") != std::string::npos,
           "POR dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A8CD08ULL});
    rosa::x86::X86State state;
    state.xmm[2] = {.low = 0x00FF00FF00FF00FFULL, .high = 0xAAAAAAAA55555555ULL};
    state.xmm[1] = {.low = 0xFF00FF000F0F0F0FULL, .high = 0x55555555AAAAAAAAULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[2].low, std::uint64_t{0xFFFFFFFF0FFF0FFFULL},
                "POR produced the wrong low lane");
    expectEqual(state.xmm[2].high, UINT64_MAX, "POR produced the wrong high lane");
    expectEqual(state.xmm[1].low, std::uint64_t{0xFF00FF000F0F0F0FULL}, "POR changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "POR changed flags");
}

void testMovdRegisterToXmm() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x6E, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AA0F1BULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovdXmmReg, "MOVD xmm, r32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "MOVD xmm, r32 length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               source.reg == rosa::x86::Register::Rax && source.width == 32,
           "MOVD xmm0, eax operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movd xmm0, eax") != std::string::npos,
           "MOVD xmm0, eax dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AA0F1BULL});
    rosa::x86::X86State state;
    state.rax = 0xAABBCCDD89ABCDEFULL;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x89ABCDEFULL},
                "MOVD did not zero-extend EAX into the low XMM lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0}, "MOVD did not clear the high XMM lane");
    expectEqual(state.rax, std::uint64_t{0xAABBCCDD89ABCDEFULL}, "MOVD changed its GPR source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVD changed flags");

    constexpr std::array<std::uint8_t, 6> extendedCode{0x66, 0x45, 0x0F, 0x6E, 0xE8, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x1000});
    const auto extendedDestination =
        std::get<rosa::x86::XmmRegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]);
    expect(extendedDestination.reg == rosa::x86::XmmRegister::Xmm13 &&
               extendedSource.reg == rosa::x86::Register::R8 && extendedSource.width == 32,
           "extended MOVD operands differ");
    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State extendedState;
    extendedState.r8 = 0xDEADBEEFCAFEBABEULL;
    extendedState.xmm[13] = {.low = UINT64_MAX, .high = UINT64_MAX};
    extendedState.rflags = 0xAD7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.xmm[13].low, std::uint64_t{0xCAFEBABEULL},
                "extended MOVD produced the wrong low lane");
    expectEqual(extendedState.xmm[13].high, std::uint64_t{0},
                "extended MOVD did not clear the high lane");
    expectEqual(extendedState.r8, std::uint64_t{0xDEADBEEFCAFEBABEULL},
                "extended MOVD changed its source");
    expectEqual(extendedState.rflags, std::uint64_t{0xAD7}, "extended MOVD changed flags");

    constexpr std::array<std::uint8_t, 6> movq{0x66, 0x48, 0x0F, 0x6E, 0xC6, 0xC3};
    const auto movqDecoded =
        decoder.decodeBlock(movq, rosa::guest::GuestAddress{0x7FF802A8BE13ULL});
    expect(movqDecoded[0].opcode == rosa::x86::Opcode::MovqXmmReg, "MOVQ xmm, r64 opcode differs");
    const auto movqDestination =
        std::get<rosa::x86::XmmRegisterOperand>(movqDecoded[0].operands[0]);
    const auto movqSource = std::get<rosa::x86::RegisterOperand>(movqDecoded[0].operands[1]);
    expectEqual(movqDecoded[0].length, std::uint8_t{5}, "MOVQ xmm, r64 length differs");
    expect(movqDestination.reg == rosa::x86::XmmRegister::Xmm0 &&
               movqSource.reg == rosa::x86::Register::Rsi && movqSource.width == 64,
           "MOVQ xmm0, rsi operands differ");
    expect(rosa::debug::dumpX86(movqDecoded).find("movq xmm0, rsi") != std::string::npos,
           "MOVQ xmm0, rsi dump differs");
    const auto movqBlock = translator.translate(movq, rosa::guest::GuestAddress{0x7FF802A8BE13ULL});
    rosa::x86::X86State movqState;
    movqState.rsi = 0xFEDCBA9876543210ULL;
    movqState.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = UINT64_MAX};
    movqState.rflags = 0xAD7;
    static_cast<void>(movqBlock.execute(movqState));
    expectEqual(movqState.xmm[0].low, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVQ copied the wrong low XMM lane");
    expectEqual(movqState.xmm[0].high, std::uint64_t{0}, "MOVQ did not clear the high XMM lane");
    expectEqual(movqState.rsi, std::uint64_t{0xFEDCBA9876543210ULL}, "MOVQ changed its source GPR");
    expectEqual(movqState.rflags, std::uint64_t{0xAD7}, "MOVQ changed flags");
}

void testMovqRegisterFromXmm() {
    // Observed in CoreFoundation under an Objective-C fixture: MOVQ rsi, xmm0.
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x48, 0x0F, 0x7E, 0xC6, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802EB5515ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovqRegXmm, "MOVQ r64, xmm opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "MOVQ r64, xmm length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi && destination.width == 64 &&
               source.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVQ rsi, xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movq rsi, xmm0") != std::string::npos,
           "MOVQ rsi, xmm0 dump differs");

    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 6> executeCode{0x66, 0x48, 0x0F, 0x7E, 0xC6, 0xC3};
    const auto block = translator.translate(executeCode, observedRip);
    rosa::x86::X86State state;
    state.rsi = 0xAAAAAAAAAAAAAAAAULL;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rsi, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVQ r64, xmm copied the wrong lane");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVQ r64, xmm changed its low source lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVQ r64, xmm changed its high source lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVQ r64, xmm changed flags");
}

void testMovdGuestMemoryToXmm() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802A90439ULL};
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr std::array<std::uint8_t, 7> code{0x66, 0x0F, 0x6E, 0x40, 0x58, 0xEB, 0x00};
    constexpr std::uint32_t sourceValue = 0x89ABCDEFU;

    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expectEqual(decoded.size(), std::size_t{2},
                "MOVD memory load test block instruction count differs");
    expect(decoded[0].opcode == rosa::x86::Opcode::MovdXmmMem, "MOVD xmm, [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "MOVD xmm, [memory] length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               memory.base == rosa::x86::Register::Rax && memory.displacement == 0x58 &&
               memory.width == 32,
           "MOVD xmm0, dword [rax+0x58] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movd xmm0, dword [rax+0x58]") != std::string::npos,
           "MOVD xmm, [memory] dump differs");

    std::array<std::uint8_t, rosa::guest::guestPageSize> bytes{};
    std::memcpy(bytes.data() + 0x58, &sourceValue, sizeof(sourceValue));
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(page, bytes.size(), rosa::guest::Permission::Read, bytes,
                            "read-only MOVD source");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.rip = instructionAddress.value;
    state.rax = page.value;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{sourceValue},
                "MOVD memory load did not zero-extend its dword");
    expectEqual(state.xmm[0].high, std::uint64_t{0},
                "MOVD memory load did not clear the high XMM lane");
    expectEqual(state.rax, page.value, "MOVD memory load changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVD memory load changed flags");

    rosa::x86::X86State faultState;
    faultState.rip = instructionAddress.value;
    faultState.rax = 0x9000;
    faultState.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "MOVD memory load accepted an unmapped source");
    expectEqual(faultState.rip, instructionAddress.value, "faulted MOVD memory load changed RIP");
    expectEqual(faultState.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "faulted MOVD memory load changed the low XMM lane");
    expectEqual(faultState.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "faulted MOVD memory load changed the high XMM lane");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted MOVD memory load changed flags");

    // Exact paired corecrypto load using the REX.X-extended SIB index.
    constexpr std::array<std::uint8_t, 7> indexedCode{0x66, 0x42, 0x0F, 0x6E, 0x04, 0x1E, 0xC3};
    constexpr rosa::guest::GuestAddress indexedRip{0x7FF802C09C42ULL};
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, indexedRip);
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovdXmmMem,
           "indexed MOVD xmm, [memory] opcode differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[1]);
    expect(indexedMemory.base == rosa::x86::Register::Rsi &&
               indexedMemory.index == rosa::x86::Register::R11 && indexedMemory.scale == 1 &&
               indexedMemory.displacement == 0,
           "MOVD xmm0, dword [rsi+r11] operands differ");
    expect(rosa::debug::dumpX86(indexedDecoded).find("movd xmm0, dword [rsi+r11]") !=
               std::string::npos,
           "indexed MOVD load dump differs");
    const auto indexedBlock = translator.translate(indexedCode, indexedRip);
    rosa::x86::X86State indexedState;
    indexedState.r11 = 0x20;
    indexedState.rsi = page.value + 0x58 - indexedState.r11;
    indexedState.xmm[0] = {.low = UINT64_C(0x0123456789ABCDEF),
                           .high = UINT64_C(0xFEDCBA9876543210)};
    indexedState.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(indexedState.xmm[0].low, std::uint64_t{sourceValue},
                "indexed MOVD load read the wrong dword");
    expectEqual(indexedState.xmm[0].high, std::uint64_t{0},
                "indexed MOVD load did not clear its high XMM lane");
    expectEqual(indexedState.rflags, std::uint64_t{0x8D7}, "indexed MOVD load changed flags");

    indexedState.rsi = page.value + rosa::guest::guestPageSize - 2 - indexedState.r11;
    indexedState.xmm[0] = {.low = UINT64_C(0x0123456789ABCDEF),
                           .high = UINT64_C(0xFEDCBA9876543210)};
    indexedState.rflags = 0xAD7;
    faulted = false;
    try {
        static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "cross-page indexed MOVD accepted an unmapped tail");
    expectEqual(indexedState.xmm[0].low, UINT64_C(0x0123456789ABCDEF),
                "faulted indexed MOVD changed its low XMM lane");
    expectEqual(indexedState.xmm[0].high, UINT64_C(0xFEDCBA9876543210),
                "faulted indexed MOVD changed its high XMM lane");
    expectEqual(indexedState.rflags, std::uint64_t{0xAD7}, "faulted indexed MOVD changed flags");

    constexpr std::array<std::uint8_t, 9> ripRelativeCode{0x66, 0x0F, 0x6E, 0x05, 0x57,
                                                          0x59, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress ripRelativeRip{0x7FF80681D341ULL};
    constexpr rosa::guest::GuestAddress ripRelativeTarget{0x7FF806822CA0ULL};
    constexpr rosa::guest::GuestAddress ripRelativePage{0x7FF806822000ULL};
    constexpr std::uint32_t ripRelativeValue = 0xF3A55A3CU;
    const auto ripRelativeDecoded = decoder.decodeBlock(ripRelativeCode, ripRelativeRip);
    expect(ripRelativeDecoded[0].opcode == rosa::x86::Opcode::MovdXmmMem,
           "RIP-relative MOVD opcode differs");
    expectEqual(ripRelativeDecoded[0].length, std::uint8_t{8}, "RIP-relative MOVD length differs");
    const auto ripRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(ripRelativeDecoded[0].operands[1]);
    expect(ripRelativeMemory.ripRelative && !ripRelativeMemory.hasBase &&
               !ripRelativeMemory.index && ripRelativeMemory.width == 32 &&
               ripRelativeMemory.displacement == 0x5957,
           "RIP-relative MOVD memory operand differs");
    expect(rosa::debug::dumpX86(ripRelativeDecoded).find("movd xmm0, dword [rip+0x5957]") !=
               std::string::npos,
           "RIP-relative MOVD dump differs");

    rosa::guest::AddressSpace ripRelativeAddressSpace;
    ripRelativeAddressSpace.mapAnonymous(
        ripRelativePage, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read | rosa::guest::Permission::Write, "RIP-relative MOVD source");
    ripRelativeAddressSpace.writeBytes(
        ripRelativeTarget,
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t *>(&ripRelativeValue),
                                      sizeof(ripRelativeValue)});
    const auto ripRelativeBlock = translator.translate(ripRelativeCode, ripRelativeRip);
    rosa::x86::X86State ripRelativeState;
    ripRelativeState.xmm[0] = {.low = UINT64_C(0x0123456789ABCDEF),
                               .high = UINT64_C(0xFEDCBA9876543210)};
    ripRelativeState.rflags = 0x8D7;
    static_cast<void>(ripRelativeBlock.execute(ripRelativeState, &ripRelativeAddressSpace));
    expectEqual(ripRelativeState.xmm[0].low, std::uint64_t{ripRelativeValue},
                "RIP-relative MOVD loaded the wrong dword");
    expectEqual(ripRelativeState.xmm[0].high, std::uint64_t{0},
                "RIP-relative MOVD did not clear its high XMM lane");
    expectEqual(ripRelativeState.rflags, std::uint64_t{0x8D7}, "RIP-relative MOVD changed flags");

    rosa::guest::AddressSpace unmappedRipRelativeAddressSpace;
    rosa::x86::X86State ripRelativeFaultState;
    ripRelativeFaultState.xmm[0] = {.low = UINT64_C(0x0123456789ABCDEF),
                                    .high = UINT64_C(0xFEDCBA9876543210)};
    ripRelativeFaultState.rflags = 0xAD7;
    faulted = false;
    try {
        static_cast<void>(
            ripRelativeBlock.execute(ripRelativeFaultState, &unmappedRipRelativeAddressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "unmapped RIP-relative MOVD did not fault");
    expectEqual(ripRelativeFaultState.xmm[0].low, UINT64_C(0x0123456789ABCDEF),
                "faulted RIP-relative MOVD changed its low XMM lane");
    expectEqual(ripRelativeFaultState.xmm[0].high, UINT64_C(0xFEDCBA9876543210),
                "faulted RIP-relative MOVD changed its high XMM lane");
    expectEqual(ripRelativeFaultState.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative MOVD changed flags");
}

void testMovdXmmToGuestMemory() {
    constexpr std::array<std::uint8_t, 7> code{0x66, 0x41, 0x0F, 0x7E, 0x46, 0x11, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AA0F43ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovdMemXmm, "MOVD [memory], xmm opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "MOVD [memory], xmm length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R14 && memory.displacement == 0x11 &&
               memory.width == 32 && source.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVD dword [r14+0x11], xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movd dword [r14+0x11], xmm0") != std::string::npos,
           "MOVD [memory], xmm dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8111};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 8> sentinel{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    addressSpace.writeBytes(rosa::guest::GuestAddress{target.value - 2}, sentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AA0F43ULL});
    rosa::x86::X86State state;
    state.r14 = target.value - 0x11;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    const auto stored =
        addressSpace.readBytes(rosa::guest::GuestAddress{target.value - 2}, sentinel.size());
    constexpr std::array<std::uint8_t, 8> expected{0x11, 0x22, 0xEF, 0xCD, 0xAB, 0x89, 0x77, 0x88};
    expect(stored == std::vector<std::uint8_t>(expected.begin(), expected.end()),
           "MOVD did not store exactly the low XMM dword");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVD store changed its low XMM source lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVD store changed its high XMM source lane");
    expectEqual(state.r14, target.value - 0x11, "MOVD store changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVD store changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    std::array<std::uint8_t, rosa::guest::guestPageSize> pageBytes{};
    std::memcpy(pageBytes.data() + (target.value - page.value), sentinel.data(),
                sizeof(std::uint32_t));
    readOnlyAddressSpace.mapSegment(page, pageBytes.size(), rosa::guest::Permission::Read,
                                    pageBytes, "read-only MOVD destination");
    const auto readOnlyBefore = readOnlyAddressSpace.readU32(target);
    rosa::x86::X86State faultState = state;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected =
            std::string_view(error.what()).find("mapping permissions") != std::string_view::npos;
    }
    expect(rejected, "MOVD store accepted read-only guest memory");
    expectEqual(faultState.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "faulted MOVD store changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted MOVD store changed flags");
    expectEqual(readOnlyAddressSpace.readU32(target), readOnlyBefore,
                "faulted MOVD store changed guest memory");

    // Exact live corecrypto form with a REX.X-extended SIB index.
    constexpr std::array<std::uint8_t, 8> indexedCode{0x66, 0x42, 0x0F, 0x7E,
                                                      0x44, 0x1E, 0x10, 0xC3};
    constexpr rosa::guest::GuestAddress indexedRip{0x7FF802C09B86ULL};
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, indexedRip);
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovdMemXmm,
           "indexed MOVD [memory], xmm opcode differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[0]);
    expect(indexedMemory.base == rosa::x86::Register::Rsi &&
               indexedMemory.index == rosa::x86::Register::R11 && indexedMemory.scale == 1 &&
               indexedMemory.displacement == 0x10,
           "MOVD dword [rsi+r11+0x10], xmm0 operands differ");
    expect(rosa::debug::dumpX86(indexedDecoded).find("movd dword [rsi+r11+0x10], xmm0") !=
               std::string::npos,
           "indexed MOVD store dump differs");
    const auto indexedBlock = translator.translate(indexedCode, indexedRip);
    constexpr rosa::guest::GuestAddress indexedTarget{0x8200};
    state.r11 = 0x20;
    state.rsi = indexedTarget.value - state.r11 - 0x10;
    state.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(indexedTarget), std::uint32_t{0x89ABCDEF},
                "indexed MOVD stored the wrong low XMM dword");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "indexed MOVD store changed flags");

    constexpr rosa::guest::GuestAddress crossPage{0xA000};
    constexpr rosa::guest::GuestAddress crossTarget{crossPage.value + rosa::guest::guestPageSize -
                                                    2};
    rosa::guest::AddressSpace crossAddressSpace;
    crossAddressSpace.mapAnonymous(crossPage, rosa::guest::guestPageSize,
                                   rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> firstHalf{0x11, 0x22};
    crossAddressSpace.writeBytes(crossTarget, firstHalf);
    std::array<std::uint8_t, rosa::guest::guestPageSize> secondPage{};
    secondPage[0] = 0x33;
    secondPage[1] = 0x44;
    crossAddressSpace.mapSegment(
        rosa::guest::GuestAddress{crossPage.value + rosa::guest::guestPageSize}, secondPage.size(),
        rosa::guest::Permission::Read, secondPage, "read-only second half of MOVD destination");
    rosa::x86::X86State crossState = state;
    crossState.r11 = 0x20;
    crossState.rsi = crossTarget.value - crossState.r11 - 0x10;
    crossState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(indexedBlock.execute(crossState, &crossAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "cross-page MOVD store accepted a read-only second page");
    expectEqual(crossAddressSpace.readBytes(crossTarget, 2),
                std::vector<std::uint8_t>(firstHalf.begin(), firstHalf.end()),
                "faulted cross-page MOVD partially changed its first page");
    expectEqual(crossAddressSpace.readBytes(
                    rosa::guest::GuestAddress{crossPage.value + rosa::guest::guestPageSize}, 2),
                std::vector<std::uint8_t>{0x33, 0x44},
                "faulted cross-page MOVD changed its second page");
    expectEqual(crossState.rflags, std::uint64_t{0xAD7}, "faulted indexed MOVD changed flags");

    constexpr std::array<std::uint8_t, 9> ripRelativeCode{0x66, 0x0F, 0x7E, 0x1D, 0x95,
                                                          0x62, 0xEC, 0x3C, 0xC3};
    constexpr rosa::guest::GuestAddress ripRelativeRip{0x7FF80681D35FULL};
    constexpr rosa::guest::GuestAddress ripRelativeTarget{0x7FF8436E35FCULL};
    constexpr rosa::guest::GuestAddress ripRelativePage{0x7FF8436E3000ULL};
    const auto ripRelativeDecoded = decoder.decodeBlock(ripRelativeCode, ripRelativeRip);
    expect(ripRelativeDecoded[0].opcode == rosa::x86::Opcode::MovdMemXmm,
           "RIP-relative MOVD store opcode differs");
    expectEqual(ripRelativeDecoded[0].length, std::uint8_t{8},
                "RIP-relative MOVD store length differs");
    const auto ripRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(ripRelativeDecoded[0].operands[0]);
    expect(ripRelativeMemory.ripRelative && !ripRelativeMemory.hasBase &&
               !ripRelativeMemory.index && ripRelativeMemory.width == 32 &&
               ripRelativeMemory.displacement == 0x3CEC6295,
           "RIP-relative MOVD store memory operand differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(ripRelativeDecoded[0].operands[1]).reg ==
               rosa::x86::XmmRegister::Xmm3,
           "RIP-relative MOVD store source differs");
    expect(rosa::debug::dumpX86(ripRelativeDecoded).find("movd dword [rip+0x3cec6295], xmm3") !=
               std::string::npos,
           "RIP-relative MOVD store dump differs");

    rosa::guest::AddressSpace ripRelativeAddressSpace;
    ripRelativeAddressSpace.mapAnonymous(ripRelativePage, rosa::guest::guestPageSize,
                                         rosa::guest::Permission::Read |
                                             rosa::guest::Permission::Write,
                                         "RIP-relative MOVD destination");
    ripRelativeAddressSpace.writeU64(rosa::guest::GuestAddress{ripRelativeTarget.value - 2},
                                     UINT64_C(0x8877665544332211));
    const auto ripRelativeBlock = translator.translate(ripRelativeCode, ripRelativeRip);
    rosa::x86::X86State ripRelativeState;
    ripRelativeState.xmm[3] = {.low = UINT64_C(0x0123456789ABCDEF),
                               .high = UINT64_C(0xFEDCBA9876543210)};
    ripRelativeState.rflags = 0x8D7;
    static_cast<void>(ripRelativeBlock.execute(ripRelativeState, &ripRelativeAddressSpace));
    expectEqual(
        ripRelativeAddressSpace.readU64(rosa::guest::GuestAddress{ripRelativeTarget.value - 2}),
        UINT64_C(0x887789ABCDEF2211), "RIP-relative MOVD did not store exactly one dword");
    expectEqual(ripRelativeState.xmm[3].low, UINT64_C(0x0123456789ABCDEF),
                "RIP-relative MOVD store changed its source");
    expectEqual(ripRelativeState.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOVD store changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> ripRelativePageBytes{};
    std::memcpy(ripRelativePageBytes.data() + (ripRelativeTarget.value - ripRelativePage.value),
                sentinel.data(), sizeof(std::uint32_t));
    rosa::guest::AddressSpace readOnlyRipRelativeAddressSpace;
    readOnlyRipRelativeAddressSpace.mapSegment(ripRelativePage, ripRelativePageBytes.size(),
                                               rosa::guest::Permission::Read, ripRelativePageBytes,
                                               "read-only RIP-relative MOVD destination");
    const auto ripRelativeBefore = readOnlyRipRelativeAddressSpace.readU32(ripRelativeTarget);
    auto ripRelativeFaultState = ripRelativeState;
    ripRelativeFaultState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(
            ripRelativeBlock.execute(ripRelativeFaultState, &readOnlyRipRelativeAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOVD store accepted read-only memory");
    expectEqual(readOnlyRipRelativeAddressSpace.readU32(ripRelativeTarget), ripRelativeBefore,
                "faulted RIP-relative MOVD store changed memory");
    expectEqual(ripRelativeFaultState.xmm[3].low, UINT64_C(0x0123456789ABCDEF),
                "faulted RIP-relative MOVD store changed its source");
    expectEqual(ripRelativeFaultState.rflags, std::uint64_t{0xAD7},
                "faulted RIP-relative MOVD store changed flags");
}

void testMovssXmmFromGuestMemory() {
    // Observed in CoreGraphics under an Objective-C fixture: MOVSS xmm0, [rbp-0x2c].
    constexpr std::array<std::uint8_t, 6> code{0xF3, 0x0F, 0x10, 0x45, 0xD4, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF80968BE24ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovssRegMem,
           "MOVSS xmm, [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "MOVSS xmm, [memory] length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVSS xmm0, [memory] destination differs");
    expect(!memory.ripRelative && memory.hasBase &&
               memory.base == rosa::x86::Register::Rbp && !memory.index &&
               memory.displacement == -0x2C && memory.width == 32,
           "MOVSS xmm0, dword [rbp-0x2c] memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("movss xmm0, dword [rbp-0x2c]") !=
               std::string::npos,
           "MOVSS xmm, [memory] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress sourceAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(sourceAddress, 0x4048F5C3);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rbp = sourceAddress.value + 0x2C;
    state.xmm[0] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x4048F5C3ULL},
                "MOVSS load low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0}, "MOVSS load did not zero the high lane");
    expectEqual(state.rbp, sourceAddress.value + 0x2C, "MOVSS load changed its base");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVSS load changed flags");

    // REX-extended store: MOVSS [r15+0x8], xmm0.
    constexpr std::array<std::uint8_t, 7> storeCode{0xF3, 0x41, 0x0F, 0x11,
                                                    0x47, 0x08, 0xC3};
    const auto storeDecoded = decoder.decodeBlock(storeCode, observedRip);
    expect(storeDecoded[0].opcode == rosa::x86::Opcode::MovssMemXmm,
           "REX MOVSS store opcode differs");
    expectEqual(storeDecoded[0].length, std::uint8_t{6}, "REX MOVSS store length differs");
    const auto storeMemory = std::get<rosa::x86::MemoryOperand>(storeDecoded[0].operands[0]);
    const auto storeSource =
        std::get<rosa::x86::XmmRegisterOperand>(storeDecoded[0].operands[1]);
    expect(storeMemory.base == rosa::x86::Register::R15 &&
               storeMemory.displacement == 8 && storeSource.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVSS [r15+0x8], xmm0 operands differ");
    expect(rosa::debug::dumpX86(storeDecoded).find("movss dword [r15+0x8], xmm0") !=
               std::string::npos,
           "REX MOVSS store dump differs");
}

void testMovssXmmToGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{0xF3, 0x0F, 0x11, 0x45, 0xD0, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802C67F31ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovssMemXmm,
           "MOVSS [memory], xmm opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "MOVSS [memory], xmm length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbp && memory.displacement == -0x30 &&
               memory.width == 32 && source.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVSS dword [rbp-0x30], xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movss dword [rbp-0x30], xmm0") != std::string::npos,
           "MOVSS [memory], xmm dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 8> sentinel{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    addressSpace.writeBytes(rosa::guest::GuestAddress{target.value - 2}, sentinel);

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.rbp = target.value + 0x30;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    constexpr std::array<std::uint8_t, 8> expected{0x10, 0x20, 0xEF, 0xCD, 0xAB, 0x89, 0x70, 0x80};
    expect(addressSpace.readBytes(rosa::guest::GuestAddress{target.value - 2}, expected.size()) ==
               std::vector<std::uint8_t>(expected.begin(), expected.end()),
           "MOVSS did not store exactly the low XMM dword");
    expectEqual(state.rbp, target.value + 0x30, "MOVSS store changed its base register");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVSS store changed its low XMM source lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVSS store changed its high XMM source lane");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVSS store changed flags");

    constexpr rosa::guest::GuestAddress faultTarget{page.value + rosa::guest::guestPageSize - 2};
    constexpr std::array<std::uint8_t, 2> faultSentinel{0xA5, 0x5A};
    addressSpace.writeBytes(faultTarget, faultSentinel);
    rosa::x86::X86State faultState = state;
    faultState.rbp = faultTarget.value + 0x30;
    faultState.rflags = 0xBD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page MOVSS store did not fault");
    expect(addressSpace.readBytes(faultTarget, faultSentinel.size()) ==
               std::vector<std::uint8_t>(faultSentinel.begin(), faultSentinel.end()),
           "faulted MOVSS store partially changed guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "faulted MOVSS store changed flags");
}

void testMovsdXmmMemoryMoves() {
    // Observed in libsystem_c (strtod) under grep: MOVSD xmm0, qword [rbx].
    constexpr std::array<std::uint8_t, 5> loadBlockCode{0xF2, 0x0F, 0x10, 0x03, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802D7BAAF};
    const rosa::x86::Decoder decoder;
    const auto loadDecoded = decoder.decodeBlock(loadBlockCode, instructionAddress);
    expect(loadDecoded[0].opcode == rosa::x86::Opcode::MovsdRegMem,
           "MOVSD xmm, [memory] opcode differs");
    expectEqual(loadDecoded[0].length, std::uint8_t{4}, "MOVSD xmm, [memory] length differs");
    const auto loadDestination =
        std::get<rosa::x86::XmmRegisterOperand>(loadDecoded[0].operands[0]);
    const auto loadMemory = std::get<rosa::x86::MemoryOperand>(loadDecoded[0].operands[1]);
    expect(loadDestination.reg == rosa::x86::XmmRegister::Xmm0 &&
               loadMemory.base == rosa::x86::Register::Rbx && loadMemory.displacement == 0 &&
               loadMemory.width == 64,
           "MOVSD xmm0, qword [rbx] operands differ");
    expect(rosa::debug::dumpX86(loadDecoded).find("movsd xmm0, qword [rbx]") !=
               std::string::npos,
           "MOVSD xmm, [memory] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 8>{0xEF, 0xCD, 0xAB, 0x89,
                                                                0x67, 0x45, 0x23, 0x01});

    const rosa::dbt::Translator translator;
    const auto loadBlock = translator.translate(loadBlockCode, instructionAddress);
    rosa::x86::X86State loadState;
    loadState.rbx = target.value;
    loadState.xmm[0] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    loadState.rflags = 0xAD7;
    static_cast<void>(loadBlock.execute(loadState, &addressSpace));
    expectEqual(loadState.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVSD load did not copy the guest qword into the low lane");
    expectEqual(loadState.xmm[0].high, std::uint64_t{0},
                "MOVSD load did not zero the high lane");
    expectEqual(loadState.rbx, target.value, "MOVSD load changed its base register");
    expectEqual(loadState.rflags, std::uint64_t{0xAD7}, "MOVSD load changed flags");

    constexpr std::array<std::uint8_t, 6> storeCode{0xF2, 0x0F, 0x11, 0x45, 0xD0, 0xC3};
    const auto storeDecoded = decoder.decodeBlock(storeCode, instructionAddress);
    expect(storeDecoded[0].opcode == rosa::x86::Opcode::MovsdMemXmm,
           "MOVSD [memory], xmm opcode differs");
    expectEqual(storeDecoded[0].length, std::uint8_t{5}, "MOVSD [memory], xmm length differs");
    const auto storeMemory = std::get<rosa::x86::MemoryOperand>(storeDecoded[0].operands[0]);
    const auto storeSource =
        std::get<rosa::x86::XmmRegisterOperand>(storeDecoded[0].operands[1]);
    expect(storeMemory.base == rosa::x86::Register::Rbp && storeMemory.displacement == -0x30 &&
               storeMemory.width == 64 && storeSource.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVSD qword [rbp-0x30], xmm0 operands differ");
    expect(rosa::debug::dumpX86(storeDecoded).find("movsd qword [rbp-0x30], xmm0") !=
               std::string::npos,
           "MOVSD [memory], xmm dump differs");

    const auto storeBlock = translator.translate(storeCode, instructionAddress);
    rosa::x86::X86State storeState;
    storeState.rbp = target.value + 0x30;
    storeState.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    storeState.rflags = 0xAD7;
    static_cast<void>(storeBlock.execute(storeState, &addressSpace));
    expectEqual(storeState.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVSD store changed its low XMM source lane");
    expectEqual(storeState.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVSD store changed its high XMM source lane");
    expectEqual(storeState.rflags, std::uint64_t{0xAD7}, "MOVSD store changed flags");
}

void testMovlpsXmmMemoryMoves() {
    // Observed in libsystem_c under grep: MOVLPS qword [rax+0x4], xmm0.
    constexpr std::array<std::uint8_t, 5> storeCode{0x0F, 0x13, 0x40, 0x04, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802D7BADE};
    const rosa::x86::Decoder decoder;
    const auto storeDecoded = decoder.decodeBlock(storeCode, instructionAddress);
    expect(storeDecoded[0].opcode == rosa::x86::Opcode::MovlpsMemXmm,
           "MOVLPS [memory], xmm opcode differs");
    expectEqual(storeDecoded[0].length, std::uint8_t{4}, "MOVLPS [memory], xmm length differs");
    const auto storeMemory = std::get<rosa::x86::MemoryOperand>(storeDecoded[0].operands[0]);
    const auto storeSource =
        std::get<rosa::x86::XmmRegisterOperand>(storeDecoded[0].operands[1]);
    expect(storeMemory.base == rosa::x86::Register::Rax && storeMemory.displacement == 4 &&
               storeMemory.width == 64 && storeSource.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVLPS qword [rax+0x4], xmm0 operands differ");
    expect(rosa::debug::dumpX86(storeDecoded).find("movlps qword [rax+0x4], xmm0") !=
               std::string::npos,
           "MOVLPS [memory], xmm dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);

    const rosa::dbt::Translator translator;
    const auto storeBlock = translator.translate(storeCode, instructionAddress);
    rosa::x86::X86State storeState;
    storeState.rax = target.value - 4;
    storeState.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    storeState.rflags = 0xAD7;
    static_cast<void>(storeBlock.execute(storeState, &addressSpace));
    expectEqual(addressSpace.readU64(target), std::uint64_t{0x0123456789ABCDEFULL},
                "MOVLPS did not store the low XMM qword");
    expectEqual(storeState.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVLPS store changed its high XMM source lane");
    expectEqual(storeState.rflags, std::uint64_t{0xAD7}, "MOVLPS store changed flags");

    constexpr std::array<std::uint8_t, 5> loadCode{0x0F, 0x12, 0x45, 0xE0, 0xC3};
    const auto loadDecoded = decoder.decodeBlock(loadCode, instructionAddress);
    expect(loadDecoded[0].opcode == rosa::x86::Opcode::MovlpsRegMem,
           "MOVLPS xmm, [memory] opcode differs");
    expectEqual(loadDecoded[0].length, std::uint8_t{4}, "MOVLPS xmm, [memory] length differs");
    const auto loadDestination =
        std::get<rosa::x86::XmmRegisterOperand>(loadDecoded[0].operands[0]);
    const auto loadMemory = std::get<rosa::x86::MemoryOperand>(loadDecoded[0].operands[1]);
    expect(loadDestination.reg == rosa::x86::XmmRegister::Xmm0 &&
               loadMemory.base == rosa::x86::Register::Rbp && loadMemory.displacement == -0x20 &&
               loadMemory.width == 64,
           "MOVLPS xmm0, qword [rbp-0x20] operands differ");
    expect(rosa::debug::dumpX86(loadDecoded).find("movlps xmm0, qword [rbp-0x20]") !=
               std::string::npos,
           "MOVLPS xmm, [memory] dump differs");

    const auto loadBlock = translator.translate(loadCode, instructionAddress);
    rosa::x86::X86State loadState;
    loadState.rbp = target.value + 0x20;
    loadState.xmm[0] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    loadState.rflags = 0xAD7;
    static_cast<void>(loadBlock.execute(loadState, &addressSpace));
    expectEqual(loadState.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVLPS load did not copy the guest qword into the low lane");
    expectEqual(loadState.xmm[0].high, std::uint64_t{0xBBBBBBBBBBBBBBBBULL},
                "MOVLPS load did not preserve the high lane");
    expectEqual(loadState.rflags, std::uint64_t{0xAD7}, "MOVLPS load changed flags");
}

void testExtractpsXmmToGuestMemory() {
    constexpr std::array<std::uint8_t, 8> laneThreeCode{0x66, 0x0F, 0x3A, 0x17,
                                                        0x45, 0xCC, 0x03, 0xC3};
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802C67F36ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(laneThreeCode, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::ExtractpsMemXmmImm,
           "EXTRACTPS [memory], xmm, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "EXTRACTPS [memory], xmm, imm8 length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(memory.base == rosa::x86::Register::Rbp && memory.displacement == -0x34 &&
               memory.width == 32 && source.reg == rosa::x86::XmmRegister::Xmm0 &&
               immediate.value == 3 && immediate.width == 8,
           "EXTRACTPS dword [rbp-0x34], xmm0, 3 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("extractps dword [rbp-0x34], xmm0, 0x3") !=
               std::string::npos,
           "EXTRACTPS lane-three dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto laneThreeBlock = translator.translate(laneThreeCode, instructionAddress);
    rosa::x86::X86State state;
    state.rbp = target.value + 0x34;
    state.xmm[0] = {.low = 0x1122334455667788ULL, .high = 0x99AABBCCDDEEFF00ULL};
    state.rflags = 0xAD7;
    static_cast<void>(laneThreeBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0x99AABBCC},
                "EXTRACTPS lane three stored the wrong dword");
    expectEqual(state.xmm[0].low, std::uint64_t{0x1122334455667788ULL},
                "EXTRACTPS changed its low XMM source lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0x99AABBCCDDEEFF00ULL},
                "EXTRACTPS changed its high XMM source lane");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "EXTRACTPS changed flags");

    constexpr std::array<std::uint8_t, 8> laneOneCode{0x66, 0x0F, 0x3A, 0x17,
                                                      0x45, 0x98, 0x01, 0xC3};
    const auto laneOneBlock =
        translator.translate(laneOneCode, rosa::guest::GuestAddress{0x7FF802C67F3DULL});
    constexpr rosa::guest::GuestAddress laneOneTarget{0x8200};
    state.rbp = laneOneTarget.value + 0x68;
    static_cast<void>(laneOneBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU32(laneOneTarget), std::uint32_t{0x11223344},
                "EXTRACTPS lane one stored the wrong dword");

    constexpr rosa::guest::GuestAddress faultTarget{page.value + rosa::guest::guestPageSize - 2};
    constexpr std::array<std::uint8_t, 2> sentinel{0xA5, 0x5A};
    addressSpace.writeBytes(faultTarget, sentinel);
    rosa::x86::X86State faultState = state;
    faultState.rbp = faultTarget.value + 0x34;
    faultState.rflags = 0xBD7;
    bool rejected = false;
    try {
        static_cast<void>(laneThreeBlock.execute(faultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page EXTRACTPS did not fault");
    expect(addressSpace.readBytes(faultTarget, sentinel.size()) ==
               std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
           "faulted EXTRACTPS partially changed guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "faulted EXTRACTPS changed flags");
}

void testPinsrwGuestMemoryToXmm() {
    // Observed in CoreGraphics under an Objective-C fixture: PINSRW xmm1, [rbp-0x4b], 2.
    constexpr std::array<std::uint8_t, 7> code{0x66, 0x0F, 0xC4, 0x4D, 0xB5, 0x02, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8099AB173ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PinsrwXmmMem,
           "PINSRW xmm, [mem], imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "PINSRW xmm, [mem], imm8 length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               memory.base == rosa::x86::Register::Rbp && memory.displacement == -0x4B &&
               memory.width == 16 && immediate.value == 2,
           "PINSRW xmm1, word [rbp-0x4b], 2 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pinsrw xmm1, word [rbp-0x4b], 0x2") !=
               std::string::npos,
           "PINSRW xmm, [mem], imm8 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress sourceAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(sourceAddress, std::array<std::uint8_t, 2>{0xCD, 0xAB});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rbp = sourceAddress.value + 0x4B;
    state.xmm[1] = {.low = 0x1111222233334444ULL, .high = 0x5555666677778888ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[1].low, std::uint64_t{0x1111ABCD33334444ULL},
                "PINSRW inserted the wrong word");
    expectEqual(state.xmm[1].high, std::uint64_t{0x5555666677778888ULL},
                "PINSRW changed the high lane");
    expectEqual(state.rbp, sourceAddress.value + 0x4B, "PINSRW changed its base");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "PINSRW changed flags");
}

void testPinsrdGuestMemoryToXmm() {
    constexpr std::array<std::uint8_t, 8> code{0x66, 0x0F, 0x3A, 0x22, 0x4B, 0xF0, 0x02, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF700081A49ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::PinsrdXmmMem,
           "PINSRD xmm, [mem], imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "PINSRD xmm, [mem], imm8 length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               memory.base == rosa::x86::Register::Rbx && memory.displacement == -0x10 &&
               memory.width == 32 && immediate.value == 2 && immediate.width == 8,
           "PINSRD xmm1, [rbx-0x10], 2 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pinsrd xmm1, dword [rbx-0x10], 0x2") !=
               std::string::npos,
           "PINSRD dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr std::uint32_t value = 0xAABBCCDDU;
    std::array<std::uint8_t, rosa::guest::guestPageSize> bytes{};
    std::memcpy(bytes.data() + 0xF0, &value, sizeof(value));
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(page, bytes.size(), rosa::guest::Permission::Read, bytes,
                            "read-only PINSRD source");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF700081A49ULL});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("write_guest_xmm_dword.i32 xmm1.2") != std::string::npos,
           "PINSRD did not lower through partial-XMM-write IR");
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.xmm[1] = {.low = 0x2222222211111111ULL, .high = 0x4444444433333333ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[1].low, std::uint64_t{0x2222222211111111ULL},
                "PINSRD changed an unselected XMM lane");
    expectEqual(state.xmm[1].high, std::uint64_t{0x44444444AABBCCDDULL},
                "PINSRD inserted the dword into the wrong lane");
    expectEqual(state.rbx, std::uint64_t{0x8100}, "PINSRD changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PINSRD changed flags");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{0x80F0}), value,
                "PINSRD changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbx = 0x8100;
    faultState.xmm[1] = {.low = 0x8877665544332211ULL, .high = 0x1020304050607080ULL};
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "PINSRD accepted unmapped guest memory");
    expectEqual(faultState.xmm[1].low, std::uint64_t{0x8877665544332211ULL},
                "faulted PINSRD changed its low XMM lane");
    expectEqual(faultState.xmm[1].high, std::uint64_t{0x1020304050607080ULL},
                "faulted PINSRD changed its high XMM lane");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted PINSRD changed flags");
}

void testUnorderedCompareScalarFloat() {
    // Observed in CoreGraphics under an Objective-C fixture: UCOMISS xmm0, xmm1.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x2E, 0xC1, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF80968BF2DULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::UcomissRegReg,
           "UCOMISS opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "UCOMISS length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "UCOMISS xmm0, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("ucomiss xmm0, xmm1") != std::string::npos,
           "UCOMISS dump differs");

    struct FloatCase {
        std::uint32_t destinationBits;
        std::uint32_t sourceBits;
        std::uint64_t expectedFlags;
        const char *name;
    };
    constexpr FloatCase cases[] = {
        {0x3F800000U, 0x40000000U, 0x3ULL, "less"},
        {0x40000000U, 0x40000000U, 0x42ULL, "equal"},
        {0x40400000U, 0x40000000U, 0x2ULL, "greater"},
        {0x7FC00000U, 0x3F800000U, 0x47ULL, "unordered"},
        {0x80000000U, 0x00000000U, 0x42ULL, "signed-zero"},
    };
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("update_unordered_float_flags.i32") != std::string::npos,
           "UCOMISS did not lower through unordered-compare IR");
    for (const auto &testCase : cases) {
        rosa::x86::X86State state;
        state.xmm[0] = {.low = testCase.destinationBits, .high = 0};
        state.xmm[1] = {.low = testCase.sourceBits, .high = 0};
        state.rflags = 0x8D7;
        static_cast<void>(block.execute(state));
        expectEqual(state.rflags, testCase.expectedFlags,
                    std::string("UCOMISS ") + testCase.name + " flags differ");
    }

    // REX.X-indexed form: UCOMISS xmm0, dword [rbx+r12*8].
    constexpr std::array<std::uint8_t, 7> indexedCode{0x66, 0x42, 0x0F, 0x2E,
                                                      0x04, 0xE3, 0xC3};
    constexpr rosa::guest::GuestAddress indexedRip{0x7FF80968BF49ULL};
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, indexedRip);
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::UcomissRegMem,
           "indexed UCOMISS xmm, m32 opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{6},
                "indexed UCOMISS xmm, m32 length differs");
    const auto indexedDestination =
        std::get<rosa::x86::XmmRegisterOperand>(indexedDecoded[0].operands[0]);
    const auto indexedMemory =
        std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[1]);
    expect(indexedDestination.reg == rosa::x86::XmmRegister::Xmm0,
           "indexed UCOMISS destination differs");
    expect(!indexedMemory.ripRelative && indexedMemory.hasBase &&
               indexedMemory.base == rosa::x86::Register::Rbx && indexedMemory.index &&
               *indexedMemory.index == rosa::x86::Register::R12 &&
               indexedMemory.scale == 8 && indexedMemory.displacement == 0,
           "UCOMISS xmm0, dword [rbx+r12*8] memory operand differs");
    expect(rosa::debug::dumpX86(indexedDecoded).find("ucomiss xmm0, dword [rbx+r12*8]") !=
               std::string::npos,
           "indexed UCOMISS xmm, m32 dump differs");
    const auto indexedBlock = translator.translate(indexedCode, indexedRip);
    constexpr rosa::guest::GuestAddress indexedPage{0x9000};
    constexpr rosa::guest::GuestAddress indexedTarget{0x9100};
    rosa::guest::AddressSpace indexedAddressSpace;
    indexedAddressSpace.mapAnonymous(indexedPage, rosa::guest::guestPageSize,
                                     rosa::guest::Permission::Read |
                                         rosa::guest::Permission::Write);
    indexedAddressSpace.writeU32(indexedTarget, 0x40000000);
    rosa::x86::X86State indexedState;
    indexedState.rbx = indexedTarget.value;
    indexedState.r12 = 0;
    indexedState.xmm[0] = {.low = 0x3F800000ULL, .high = 0};
    indexedState.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(indexedState, &indexedAddressSpace));
    // 1.0f < 2.0f sets CF only.
    expectEqual(indexedState.rflags, std::uint64_t{0x3ULL},
                "indexed UCOMISS xmm, m32 flags differ");

    // Memory form: UCOMISS xmm1, dword [RIP+disp32].
    constexpr std::array<std::uint8_t, 9> memCode{0x66, 0x0F, 0x2E, 0x0D, 0x25,
                                                  0x1B, 0x8B, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress memRip{0x7FF80968BF33ULL};
    const auto memDecoded = decoder.decodeBlock(memCode, memRip);
    expect(memDecoded[0].opcode == rosa::x86::Opcode::UcomissRegMem,
           "UCOMISS xmm, m32 opcode differs");
    expectEqual(memDecoded[0].length, std::uint8_t{8}, "UCOMISS xmm, m32 length differs");
    const auto memDestination =
        std::get<rosa::x86::XmmRegisterOperand>(memDecoded[0].operands[0]);
    const auto memMemory = std::get<rosa::x86::MemoryOperand>(memDecoded[0].operands[1]);
    expect(memDestination.reg == rosa::x86::XmmRegister::Xmm1,
           "UCOMISS xmm1, m32 destination differs");
    expect(memMemory.ripRelative && !memMemory.hasBase && !memMemory.index &&
               memMemory.displacement == 0x8B1B25 && memMemory.width == 32,
           "UCOMISS xmm1, dword [RIP+disp32] memory operand differs");
    expectEqual(memRip.value + memDecoded[0].length + memMemory.displacement,
                std::uint64_t{0x7FF809F3DA60ULL}, "UCOMISS xmm, m32 target differs");
    expect(rosa::debug::dumpX86(memDecoded).find("ucomiss xmm1, dword [rip+0x8b1b25]") !=
               std::string::npos,
           "UCOMISS xmm, m32 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 0x40000000);
    constexpr std::array<std::uint8_t, 9> memExecuteCode{0x66, 0x0F, 0x2E, 0x0D, 0xF9,
                                                         0x70, 0x00, 0x00, 0xC3};
    const auto memBlock = translator.translate(memExecuteCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State memState;
    memState.xmm[1] = {.low = 0x40800000ULL, .high = 0};
    memState.rflags = 0x8D7;
    static_cast<void>(memBlock.execute(memState, &addressSpace));
    // 4.0 == 2.0 is false; 4.0 > 2.0 leaves only the reserved bit.
    expectEqual(memState.rflags, std::uint64_t{0x2ULL}, "UCOMISS xmm, m32 flags differ");
}

void testUnorderedCompareScalarDouble() {
    // Observed in CoreGraphics under an Objective-C fixture: UCOMISD xmm1, xmm0.
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x2E, 0xC8, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809C4ADD9ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::UcomisdRegReg,
           "UCOMISD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "UCOMISD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               source.reg == rosa::x86::XmmRegister::Xmm0,
           "UCOMISD xmm1, xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("ucomisd xmm1, xmm0") != std::string::npos,
           "UCOMISD dump differs");

    struct UnorderedCase {
        std::uint64_t destinationBits;
        std::uint64_t sourceBits;
        std::uint64_t expectedFlags;
        const char *name;
    };
    constexpr UnorderedCase cases[] = {
        {0x3FF0000000000000ULL, 0x4000000000000000ULL, 0x3ULL, "less"},
        {0x4000000000000000ULL, 0x4000000000000000ULL, 0x42ULL, "equal"},
        {0x4008000000000000ULL, 0x4000000000000000ULL, 0x2ULL, "greater"},
        {0x7FF8000000000000ULL, 0x3FF0000000000000ULL, 0x47ULL, "unordered"},
        {0x8000000000000000ULL, 0x0000000000000000ULL, 0x42ULL, "signed-zero"},
    };
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("update_unordered_double_flags.i64") != std::string::npos,
           "UCOMISD did not lower through unordered-compare IR");
    for (const auto &testCase : cases) {
        rosa::x86::X86State state;
        state.xmm[1] = {.low = testCase.destinationBits, .high = 0};
        state.xmm[0] = {.low = testCase.sourceBits, .high = 0};
        state.rflags = 0x8D7;
        static_cast<void>(block.execute(state));
        expectEqual(state.rflags, testCase.expectedFlags,
                    std::string("UCOMISD ") + testCase.name + " flags differ");
    }
}

void testMovmskpsRegisterFromXmm() {
    // Observed in ColorSync under an Objective-C fixture: MOVMSKPS ecx, xmm2.
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x50, 0xCA, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4EBEULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovmskpsRegXmm,
           "MOVMSKPS opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "MOVMSKPS length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32 &&
               source.reg == rosa::x86::XmmRegister::Xmm2,
           "MOVMSKPS ecx, xmm2 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movmskps ecx, xmm2") != std::string::npos,
           "MOVMSKPS dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rcx = 0xFFFFFFFFFFFFFFFFULL;
    state.xmm[2] = {.low = 0x8000000000000000ULL, .high = 0x0000000080000000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // Sign bits set in dwords 1 and 2 only.
    expectEqual(state.rcx, std::uint64_t{0x6ULL}, "MOVMSKPS produced the wrong mask");
    expectEqual(state.xmm[2].low, std::uint64_t{0x8000000000000000ULL},
                "MOVMSKPS changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVMSKPS changed flags");
}

void testPextrdRegisterFromXmm() {
    // Observed in CoreGraphics under an Objective-C fixture: PEXTRD eax, xmm0, 2.
    constexpr std::array<std::uint8_t, 7> code{0x66, 0x0F, 0x3A, 0x16, 0xC0, 0x02, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8099AB146ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PextrdRegXmmImm,
           "PEXTRD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "PEXTRD length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    const auto count = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               source.reg == rosa::x86::XmmRegister::Xmm0 && count.value == 2,
           "PEXTRD eax, xmm0, 2 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pextrd eax, xmm0, 0x2") != std::string::npos,
           "PEXTRD dump differs");

    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 7> executeCode{0x66, 0x0F, 0x3A, 0x16, 0xC0, 0x02, 0xC3};
    const auto block = translator.translate(executeCode, observedRip);
    rosa::x86::X86State state;
    state.rax = 0xFFFFFFFFFFFFFFFFULL;
    state.xmm[0] = {.low = 0xDDDDBBBBCCCCAAAAULL, .high = 0x1111333322224444ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x22224444ULL}, "PEXTRD extracted the wrong dword");
    expectEqual(state.xmm[0].low, std::uint64_t{0xDDDDBBBBCCCCAAAAULL},
                "PEXTRD changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "PEXTRD changed flags");
}

void testPextrwRegisterFromXmm() {
    // Observed in libswiftCore under an Objective-C fixture: PEXTRW edi, xmm0, 3.
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0xC5, 0xF8, 0x03, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF817193A81ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PextrwRegXmmImm,
           "PEXTRW opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "PEXTRW length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    const auto count = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::Register::Rdi && destination.width == 32 &&
               source.reg == rosa::x86::XmmRegister::Xmm0 && count.value == 3 &&
               count.width == 8,
           "PEXTRW edi, xmm0, 3 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pextrw edi, xmm0, 0x3") != std::string::npos,
           "PEXTRW dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rdi = 0xFFFFFFFFFFFFFFFFULL;
    state.xmm[0] = {.low = 0xABCD1234DEADBEEFULL, .high = 0x0123456789ABCDEFULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // Word 3 of the low lane is 0xABCD, zero-extended.
    expectEqual(state.rdi, std::uint64_t{0xABCDULL}, "PEXTRW extracted the wrong word");
    expectEqual(state.xmm[0].low, std::uint64_t{0xABCD1234DEADBEEFULL},
                "PEXTRW changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "PEXTRW changed flags");

    // Word 0 needs no shift: low word of the low lane.
    constexpr std::array<std::uint8_t, 6> lowCode{0x66, 0x0F, 0xC5, 0xF8, 0x00, 0xC3};
    const auto lowBlock = translator.translate(lowCode, observedRip);
    rosa::x86::X86State lowState;
    lowState.rdi = 0;
    lowState.xmm[0] = {.low = 0xABCD1234DEADBEEFULL, .high = 0};
    static_cast<void>(lowBlock.execute(lowState));
    expectEqual(lowState.rdi, std::uint64_t{0xBEEFULL}, "PEXTRW word 0 differs");
}

void testPinsrdRegisterToXmm() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802A9044AULL};
    constexpr std::array<std::uint8_t, 14> code{0x66, 0x0F, 0x3A, 0x22, 0xC0, 0x02, 0x66,
                                                0x0F, 0x3A, 0x22, 0xC0, 0x03, 0xEB, 0x00};

    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expectEqual(decoded.size(), std::size_t{3},
                "register PINSRD test block instruction count differs");
    for (std::size_t index = 0; index < 2; ++index) {
        expect(decoded[index].opcode == rosa::x86::Opcode::PinsrdXmmReg,
               "register PINSRD opcode differs");
        expectEqual(decoded[index].length, std::uint8_t{6}, "register PINSRD length differs");
        const auto destination =
            std::get<rosa::x86::XmmRegisterOperand>(decoded[index].operands[0]);
        const auto source = std::get<rosa::x86::RegisterOperand>(decoded[index].operands[1]);
        const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[index].operands[2]);
        expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
                   source.reg == rosa::x86::Register::Rax && source.width == 32 &&
                   immediate.value == index + 2 && immediate.width == 8,
               "register PINSRD operands differ");
    }
    const auto dump = rosa::debug::dumpX86(decoded);
    expect(dump.find("pinsrd xmm0, eax, 0x2") != std::string::npos &&
               dump.find("pinsrd xmm0, eax, 0x3") != std::string::npos,
           "register PINSRD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    const auto ir = rosa::debug::dumpIr(block.intermediateRepresentation());
    expect(ir.find("write_guest_xmm_dword.i32 xmm0.2") != std::string::npos &&
               ir.find("write_guest_xmm_dword.i32 xmm0.3") != std::string::npos,
           "register PINSRD did not lower through partial-XMM-write IR");
    rosa::x86::X86State state;
    state.rip = instructionAddress.value;
    state.rax = 0xAABBCCDD00010000ULL;
    state.xmm[0] = {.low = 0x2222222211111111ULL, .high = 0x4444444433333333ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x2222222211111111ULL},
                "register PINSRD changed unselected low dwords");
    expectEqual(state.xmm[0].high, std::uint64_t{0x0001000000010000ULL},
                "register PINSRD inserted the wrong high dwords");
    expectEqual(state.rax, std::uint64_t{0xAABBCCDD00010000ULL},
                "register PINSRD changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "register PINSRD changed flags");

    constexpr std::array<std::uint8_t, 8> extendedCode{0x66, 0x41, 0x0F, 0x3A,
                                                       0x22, 0xC8, 0x01, 0xC3};
    constexpr rosa::guest::GuestAddress extendedAddress{0x7FF802C6ACD8ULL};
    const auto extendedDecoded = decoder.decodeBlock(extendedCode, extendedAddress);
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::PinsrdXmmReg,
           "extended-source PINSRD opcode differs");
    expectEqual(extendedDecoded[0].length, std::uint8_t{7},
                "extended-source PINSRD length differs");
    const auto extendedDestination =
        std::get<rosa::x86::XmmRegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]);
    const auto extendedLane = std::get<rosa::x86::ImmediateOperand>(extendedDecoded[0].operands[2]);
    expect(extendedDestination.reg == rosa::x86::XmmRegister::Xmm1 &&
               extendedSource.reg == rosa::x86::Register::R8 && extendedSource.width == 32 &&
               extendedLane.value == 1,
           "pinsrd xmm1, r8d, 1 operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("pinsrd xmm1, r8d, 0x1") != std::string::npos,
           "pinsrd xmm1, r8d, 1 dump differs");

    const auto extendedBlock = translator.translate(extendedCode, extendedAddress);
    rosa::x86::X86State extendedState;
    extendedState.r8 = 0xAABBCCDDEEFF0011ULL;
    extendedState.xmm[1] = {.low = 0x1122334455667788ULL, .high = 0x8877665544332211ULL};
    extendedState.rflags = 0xAD7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.xmm[1].low, std::uint64_t{0xEEFF001155667788ULL},
                "extended-source PINSRD inserted the wrong dword");
    expectEqual(extendedState.xmm[1].high, std::uint64_t{0x8877665544332211ULL},
                "extended-source PINSRD changed unselected dwords");
    expectEqual(extendedState.r8, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "extended-source PINSRD changed its source");
    expectEqual(extendedState.rflags, std::uint64_t{0xAD7}, "extended-source PINSRD changed flags");
}

void testPinsrqRegisterToXmm() {
    constexpr std::array<std::uint8_t, 8> code{0x66, 0x48, 0x0F, 0x3A, 0x22, 0xC8, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress codeAddress{0x7FF802C69337ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::PinsrdXmmReg, "PINSRQ register opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "PINSRQ register length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    const auto lane = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               source.reg == rosa::x86::Register::Rax && source.width == 64 && lane.value == 0,
           "PINSRQ xmm1, rax, 0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pinsrq xmm1, rax, 0x0") != std::string::npos,
           "PINSRQ register dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("write_guest_xmm_lane.i64 xmm1.low") != std::string::npos,
           "PINSRQ did not lower through a qword XMM lane write");
    rosa::x86::X86State state;
    state.rax = 0x0123456789ABCDEFULL;
    state.xmm[1] = {
        .low = 0xAAAAAAAAAAAAAAAAULL,
        .high = 0xFEDCBA9876543210ULL,
    };
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[1].low, std::uint64_t{0x0123456789ABCDEFULL},
                "PINSRQ inserted the wrong low qword");
    expectEqual(state.xmm[1].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "PINSRQ changed the unselected high qword");
    expectEqual(state.rax, std::uint64_t{0x0123456789ABCDEFULL},
                "PINSRQ changed its source register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PINSRQ changed flags");
}

void testPinsrbRegisterToXmm() {
    constexpr std::array<std::uint8_t, 7> code{0x66, 0x0F, 0x3A, 0x20, 0xC1, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802AA0F22ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::PinsrbXmmReg, "PINSRB xmm, r32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "PINSRB xmm, r32 length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               source.reg == rosa::x86::Register::Rcx && source.width == 32 && immediate.value == 1,
           "PINSRB xmm0, ecx, 1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pinsrb xmm0, ecx, 0x1") != std::string::npos,
           "PINSRB dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802AA0F22ULL});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("write_guest_xmm_byte.i8 xmm0.1") != std::string::npos,
           "PINSRB IR does not contain a typed XMM-byte write");
    rosa::x86::X86State state;
    state.rcx = 0xAABBCCDDEEFF00A5ULL;
    state.xmm[0] = {.low = 0x0706050403020100ULL, .high = 0x0F0E0D0C0B0A0908ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x070605040302A500ULL},
                "PINSRB wrote the wrong low-lane byte");
    expectEqual(state.xmm[0].high, std::uint64_t{0x0F0E0D0C0B0A0908ULL},
                "PINSRB changed the other XMM lane");
    expectEqual(state.rcx, std::uint64_t{0xAABBCCDDEEFF00A5ULL},
                "PINSRB changed its source register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PINSRB changed flags");

    constexpr std::array<std::uint8_t, 8> extendedCode{0x66, 0x45, 0x0F, 0x3A,
                                                       0x20, 0xE8, 0x19, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x1000});
    const auto extendedDestination =
        std::get<rosa::x86::XmmRegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[1]);
    expect(extendedDestination.reg == rosa::x86::XmmRegister::Xmm13 &&
               extendedSource.reg == rosa::x86::Register::R8,
           "extended PINSRB operands differ");
    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State extendedState;
    extendedState.r8 = 0xDEADBEEFCAFEBABEULL;
    extendedState.xmm[13] = {.low = 0x0706050403020100ULL, .high = 0x0F0E0D0C0B0A0908ULL};
    extendedState.rflags = 0xAD7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.xmm[13].low, std::uint64_t{0x0706050403020100ULL},
                "extended PINSRB changed the wrong XMM lane");
    expectEqual(extendedState.xmm[13].high, std::uint64_t{0x0F0E0D0C0B0ABE08ULL},
                "extended PINSRB did not mask its lane immediate");
    expectEqual(extendedState.r8, std::uint64_t{0xDEADBEEFCAFEBABEULL},
                "extended PINSRB changed its source register");
    expectEqual(extendedState.rflags, std::uint64_t{0xAD7}, "extended PINSRB changed flags");
}

void testPinsrbGuestMemoryToXmm() {
    // Observed in libsqlite3: PINSRB XMM2, byte [RBX-0xc8], 1.
    constexpr std::array<std::uint8_t, 11> code{0x66, 0x0F, 0x3A, 0x20, 0x93, 0x38,
                                                0xFF, 0xFF, 0xFF, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x100082D87ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::PinsrbXmmMem,
           "PINSRB xmm, byte [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{10}, "PINSRB xmm, byte [memory] length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm2, "PINSRB memory destination differs");
    expect(memory.base == rosa::x86::Register::Rbx && memory.displacement == -200 &&
               memory.width == 8,
           "PINSRB byte [rbx-0xc8] memory operand differs");
    expect(immediate.value == 1, "PINSRB memory lane differs");
    expect(rosa::debug::dumpX86(decoded).find("pinsrb xmm2, byte [rbx-0xc8], 0x1") !=
               std::string::npos,
           "PINSRB memory dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> sourceByte{0xAB};
    addressSpace.writeBytes(target, sourceByte);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x100082D87ULL});
    rosa::x86::X86State state;
    state.rbx = target.value + 200;
    state.xmm[2] = {.low = 0x0706050403020100ULL, .high = 0x0F0E0D0C0B0A0908ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[2].low, std::uint64_t{0x070605040302AB00ULL},
                "PINSRB memory wrote the wrong low-lane byte");
    expectEqual(state.xmm[2].high, std::uint64_t{0x0F0E0D0C0B0A0908ULL},
                "PINSRB memory changed the other XMM lane");
    expectEqual(state.rbx, target.value + 200, "PINSRB memory changed its base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PINSRB memory changed flags");
}

void testPblendwRegisters() {
    constexpr std::array<std::uint8_t, 7> code{0x66, 0x0F, 0x3A, 0x0E, 0xC8, 0x0F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF700081A57ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::PblendwRegRegImm, "PBLENDW opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "PBLENDW length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    const auto immediate = std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[2]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               source.reg == rosa::x86::XmmRegister::Xmm0 && immediate.value == 0x0F &&
               immediate.width == 8,
           "PBLENDW xmm1, xmm0, 0x0f operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pblendw xmm1, xmm0, 0xf") != std::string::npos,
           "PBLENDW dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF700081A57ULL});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("blend_xmm_words.i16 xmm1, xmm0, 0xf") != std::string::npos,
           "PBLENDW did not lower through word-blend IR");
    rosa::x86::X86State state;
    state.rax = 0x0123456789ABCDEFULL;
    state.xmm[0] = {.low = 0x4444333322221111ULL, .high = 0x8888777766665555ULL};
    state.xmm[1] = {.low = 0xDDDDCCCCBBBBAAAAULL, .high = 0x11110000FFFFEEEEULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[1].low, std::uint64_t{0x4444333322221111ULL},
                "PBLENDW did not select source words 0-3");
    expectEqual(state.xmm[1].high, std::uint64_t{0x11110000FFFFEEEEULL},
                "PBLENDW did not preserve destination words 4-7");
    expectEqual(state.xmm[0].low, std::uint64_t{0x4444333322221111ULL},
                "PBLENDW changed its source");
    expectEqual(state.rax, std::uint64_t{0x0123456789ABCDEFULL}, "PBLENDW changed a GPR");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "PBLENDW changed flags");

    constexpr std::array<std::uint8_t, 7> aliasCode{0x66, 0x0F, 0x3A, 0x0E, 0xC0, 0x5A, 0xC3};
    const auto aliasBlock = translator.translate(aliasCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State aliasState;
    aliasState.xmm[0] = {.low = 0x8877665544332211ULL, .high = 0x1020304050607080ULL};
    aliasState.rflags = 0x8D7;
    static_cast<void>(aliasBlock.execute(aliasState));
    expectEqual(aliasState.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "aliased PBLENDW changed its low lane");
    expectEqual(aliasState.xmm[0].high, std::uint64_t{0x1020304050607080ULL},
                "aliased PBLENDW changed its high lane");
    expectEqual(aliasState.rflags, std::uint64_t{0x8D7}, "aliased PBLENDW changed flags");
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

void testLeaBaseDisplacementExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x8D, 0x5D, 0xB0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::LeaRegMem, "LEA base+disp opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbp, "LEA base differs");
    expectEqual(memory.displacement, std::int64_t{-0x50}, "LEA displacement differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbp = 0x1000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rbx, std::uint64_t{0xFB0}, "LEA base+disp result differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "LEA changed flags");
}

void testLea32BitBaseDisplacementExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x8D, 0x48, 0xE5, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::LeaRegMem,
           "LEA r32, [base+disp8] opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "LEA r32 destination width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 25;
    state.rcx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFFFFFFFE}, "LEA r32 result or zero extension differs");
    expectEqual(state.rax, std::uint64_t{25}, "LEA r32 changed base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "LEA r32 changed flags");
}

void testLeaBaseIndexExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x4A, 0x8D, 0x14, 0x28, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::LeaRegMem, "LEA base+index opcode differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx, "LEA base+index destination differs");
    expect(memory.base == rosa::x86::Register::Rax, "LEA SIB base differs");
    expect(memory.index == rosa::x86::Register::R13, "LEA SIB extended index differs");
    expectEqual(memory.scale, std::uint8_t{1}, "LEA SIB scale differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1000;
    state.r13 = 0x234;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0x1234}, "LEA base+index result differs");
    expectEqual(state.rax, std::uint64_t{0x1000}, "LEA changed its base register");
    expectEqual(state.r13, std::uint64_t{0x234}, "LEA changed its index register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "LEA changed guest flags");
}

void testLeaNoBaseScaledIndexExecution() {
    constexpr std::array<std::uint8_t, 9> code{0x48, 0x8D, 0x0C, 0xCD, 0x18,
                                               0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::LeaRegMem, "no-base scaled LEA opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(!memory.hasBase, "no-base scaled LEA acquired a base");
    expect(memory.index == rosa::x86::Register::Rcx, "no-base scaled LEA index differs");
    expectEqual(memory.scale, std::uint8_t{8}, "no-base scaled LEA scale differs");
    expectEqual(memory.displacement, std::int64_t{0x18}, "no-base scaled LEA displacement differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 5;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x40}, "no-base scaled LEA result differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "no-base scaled LEA changed guest flags");

    constexpr std::array<std::uint8_t, 9> negativeDisplacement{0x48, 0x8D, 0x04, 0x8D, 0xF8,
                                                               0xFF, 0xFF, 0xFF, 0xC3};
    const auto negativeBlock =
        translator.translate(negativeDisplacement, rosa::guest::GuestAddress{0x2000});
    state.rcx = 3;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{4}, "no-base scaled LEA did not sign-extend disp32");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "no-base scaled LEA with negative displacement changed flags");

    constexpr std::array<std::uint8_t, 9> noBaseOrIndex{0x48, 0x8D, 0x14, 0x25, 0x78,
                                                        0x56, 0x34, 0x12, 0xC3};
    const auto displacementBlock =
        translator.translate(noBaseOrIndex, rosa::guest::GuestAddress{0x3000});
    state.rdx = UINT64_MAX;
    state.rsp = 0xDEADBEEF;
    static_cast<void>(displacementBlock.execute(state));
    expectEqual(state.rdx, std::uint64_t{0x12345678},
                "no-base no-index LEA read a dummy base register");
    expectEqual(state.rsp, std::uint64_t{0xDEADBEEF},
                "no-base no-index LEA changed an unrelated register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "no-base no-index LEA changed flags");
}

void testLegacyRegisterMove32Execution() {
    constexpr std::array<std::uint8_t, 3> code{0x89, 0xFB, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegReg, "legacy MOV r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "legacy MOV r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0xFFFFFFFF12345678ULL;
    state.rbx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rbx, std::uint64_t{0x12345678},
                "legacy MOV ebx, edi did not clear the upper half");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "legacy MOV r32 changed flags");
}

void testByteRegisterMoveExecution() {
    // Observed in libsqlite3: MOV DL, R8B with REX.R (opcode 88, register-direct).
    constexpr std::array<std::uint8_t, 4> code{0x44, 0x88, 0xC2, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000480B3ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegReg, "MOV r8, r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "MOV r8, r8 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 8 &&
               source.reg == rosa::x86::Register::R8 && source.width == 8,
           "MOV DL, R8B operands differ");
    expect(rosa::debug::dumpX86(decoded).find("mov dl, r8b") != std::string::npos,
           "MOV DL, R8B dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000480B3ULL});
    rosa::x86::X86State state;
    state.rdx = 0xAABBCCDD12345600ULL;
    state.r8 = 0x11223344556677FFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0xAABBCCDD123456FFULL},
                "MOV DL, R8B result differs");
    expectEqual(state.r8, std::uint64_t{0x11223344556677FFULL}, "MOV DL, R8B changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV r8, r8 changed flags");
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

} // namespace

std::span<const TestCase> simdLanesTests() {
    static const TestCase cases[]{
        {"PSHUFB register execution", testPshufbRegisters},
        {"PSHUFB RIP-relative guest memory", testPshufbRipRelativeGuestMemory},
        {"PUNPCKLWD register execution", testPunpcklwdRegisters},
        {"PUNPCKLQDQ register execution", testPunpcklqdqRegisters},
        {"POR register execution", testPorRegisters},
        {"MOVD register to XMM", testMovdRegisterToXmm},
        {"MOVQ register from XMM", testMovqRegisterFromXmm},
        {"MOVD guest memory to XMM", testMovdGuestMemoryToXmm},
        {"MOVD XMM to guest memory", testMovdXmmToGuestMemory},
        {"MOVSS XMM to guest memory", testMovssXmmToGuestMemory},
        {"MOVSS XMM from guest memory", testMovssXmmFromGuestMemory},
        {"MOVSD XMM memory moves", testMovsdXmmMemoryMoves},
        {"MOVLPS XMM memory moves", testMovlpsXmmMemoryMoves},
        {"EXTRACTPS XMM to guest memory", testExtractpsXmmToGuestMemory},
        {"PINSRD guest memory to XMM", testPinsrdGuestMemoryToXmm},
        {"PINSRW guest memory to XMM", testPinsrwGuestMemoryToXmm},
        {"PINSRD register to XMM", testPinsrdRegisterToXmm},
        {"PEXTRW register from XMM", testPextrwRegisterFromXmm},
        {"PEXTRD register from XMM", testPextrdRegisterFromXmm},
        {"MOVMSKPS register from XMM", testMovmskpsRegisterFromXmm},
        {"UCOMISD registers unordered compare", testUnorderedCompareScalarDouble},
        {"UCOMISS registers unordered compare", testUnorderedCompareScalarFloat},
        {"PINSRQ register to XMM", testPinsrqRegisterToXmm},
        {"PINSRB register to XMM", testPinsrbRegisterToXmm},
        {"PINSRB guest memory to XMM", testPinsrbGuestMemoryToXmm},
        {"PBLENDW registers", testPblendwRegisters},
        {"register move execution", testRegisterMoveExecution},
        {"LEA base displacement execution", testLeaBaseDisplacementExecution},
        {"LEA 32-bit base displacement execution", testLea32BitBaseDisplacementExecution},
        {"LEA base index execution", testLeaBaseIndexExecution},
        {"LEA no-base scaled index execution", testLeaNoBaseScaledIndexExecution},
        {"legacy 32-bit register move execution", testLegacyRegisterMove32Execution},
        {"byte register move execution", testByteRegisterMoveExecution},
        {"unsupported decoder diagnostic", testDecoderRejectsUnsupportedInstruction},
        {"RIP-relative LEA and syscall decoder", testDecoderRipRelativeLeaAndSyscall},
    };
    return cases;
}

} // namespace rosa::tests
