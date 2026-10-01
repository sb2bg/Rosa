#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testVexYmmMemoryLoad() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802E7AA70ULL};
    constexpr std::array<std::uint8_t, 5> code{0xC5, 0xFC, 0x10, 0x06, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::VmovupsYmmRegMem,
           "256-bit VMOVUPS load opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "256-bit VMOVUPS load length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               memory.base == rosa::x86::Register::Rsi && memory.hasBase && !memory.ripRelative &&
               !memory.index && memory.displacement == 0 && memory.width == 256,
           "VMOVUPS ymm0, [rsi] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("vmovups ymm0, [rsi]") != std::string::npos,
           "256-bit VMOVUPS load dump differs");

    constexpr rosa::guest::GuestAddress memoryPage{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8080};
    constexpr std::array<std::uint64_t, 4> lanes{
        0x0123456789ABCDEFULL,
        0xFEDCBA9876543210ULL,
        0x8877665544332211ULL,
        0x1020304050607080ULL,
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    for (std::size_t lane = 0; lane < lanes.size(); ++lane) {
        addressSpace.writeU64(
            rosa::guest::GuestAddress{target.value + lane * sizeof(std::uint64_t)}, lanes[lane]);
    }
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("load_guest_ymm.i256") !=
               std::string::npos,
           "256-bit VMOVUPS did not lower through YMM load IR");
    rosa::x86::X86State state;
    state.rsi = target.value;
    state.xmm[0] = {.low = 1, .high = 2};
    state.ymmUpper[0] = {.low = 3, .high = 4};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, lanes[0], "256-bit VMOVUPS loaded the wrong first qword");
    expectEqual(state.xmm[0].high, lanes[1], "256-bit VMOVUPS loaded the wrong second qword");
    expectEqual(state.ymmUpper[0].low, lanes[2], "256-bit VMOVUPS loaded the wrong third qword");
    expectEqual(state.ymmUpper[0].high, lanes[3], "256-bit VMOVUPS loaded the wrong fourth qword");
    expectEqual(state.rsi, target.value, "256-bit VMOVUPS changed its address base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "256-bit VMOVUPS changed flags");

    constexpr std::array<std::uint8_t, 5> alignedCode{0xC5, 0xFC, 0x28, 0x0E, 0xC3};
    const auto alignedDecoded = decoder.decodeBlock(alignedCode, instructionAddress);
    expect(alignedDecoded[0].opcode == rosa::x86::Opcode::VmovapsYmmRegMem &&
               alignedDecoded[0].length == 4,
           "256-bit VMOVAPS load opcode or length differs");
    expect(rosa::debug::dumpX86(alignedDecoded).find("vmovaps ymm1, [rsi]") != std::string::npos,
           "256-bit VMOVAPS load dump differs");
    const auto alignedBlock = translator.translate(alignedCode, instructionAddress);
    state.rsi = target.value;
    state.xmm[1] = {.low = 1, .high = 2};
    state.ymmUpper[1] = {.low = 3, .high = 4};
    state.rflags = 0x8D7;
    static_cast<void>(alignedBlock.execute(state, &addressSpace));
    expectEqual(state.xmm[1].low, lanes[0], "256-bit VMOVAPS loaded the wrong first qword");
    expectEqual(state.xmm[1].high, lanes[1], "256-bit VMOVAPS loaded the wrong second qword");
    expectEqual(state.ymmUpper[1].low, lanes[2], "256-bit VMOVAPS loaded the wrong third qword");
    expectEqual(state.ymmUpper[1].high, lanes[3], "256-bit VMOVAPS loaded the wrong fourth qword");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "256-bit VMOVAPS changed flags");

    state.rsi = target.value + 1;
    state.xmm[1] = {.low = 0x11, .high = 0x22};
    state.ymmUpper[1] = {.low = 0x33, .high = 0x44};
    bool misaligned = false;
    try {
        static_cast<void>(alignedBlock.execute(state, &addressSpace));
    } catch (const std::runtime_error &error) {
        misaligned =
            std::string_view(error.what()).find("32-byte aligned") != std::string_view::npos;
    }
    expect(misaligned, "256-bit VMOVAPS accepted a misaligned source");
    expectEqual(state.xmm[1].low, std::uint64_t{0x11},
                "misaligned VMOVAPS changed lower YMM state");
    expectEqual(state.ymmUpper[1].high, std::uint64_t{0x44},
                "misaligned VMOVAPS changed upper YMM state");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x9FF0};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(
        rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    state.rsi = crossPageTarget.value;
    state.xmm[0] = {.low = 0x11, .high = 0x22};
    state.ymmUpper[0] = {.low = 0x33, .high = 0x44};
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page 256-bit VMOVUPS load did not fault");
    expectEqual(state.xmm[0].low, std::uint64_t{0x11},
                "faulted 256-bit VMOVUPS changed its first qword");
    expectEqual(state.xmm[0].high, std::uint64_t{0x22},
                "faulted 256-bit VMOVUPS changed its second qword");
    expectEqual(state.ymmUpper[0].low, std::uint64_t{0x33},
                "faulted 256-bit VMOVUPS changed its third qword");
    expectEqual(state.ymmUpper[0].high, std::uint64_t{0x44},
                "faulted 256-bit VMOVUPS changed its fourth qword");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "faulted 256-bit VMOVUPS changed flags");

    constexpr std::array<std::uint8_t, 5> zeroCode{0xC5, 0xFC, 0x57, 0xC0, 0xC3};
    const auto zeroDecoded = decoder.decodeBlock(zeroCode, instructionAddress);
    expect(zeroDecoded[0].opcode == rosa::x86::Opcode::VxorpsYmmRegRegReg &&
               zeroDecoded[0].length == 4,
           "256-bit VXORPS zero-idiom opcode or length differs");
    expect(rosa::debug::dumpX86(zeroDecoded).find("vxorps ymm0, ymm0, ymm0") != std::string::npos,
           "256-bit VXORPS zero-idiom dump differs");
    const auto zeroBlock = translator.translate(zeroCode, instructionAddress);
    state.xmm[0] = {.low = UINT64_MAX, .high = 0x0123456789ABCDEFULL};
    state.ymmUpper[0] = {.low = 0xFEDCBA9876543210ULL, .high = UINT64_MAX};
    state.rflags = 0xBD7;
    static_cast<void>(zeroBlock.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0}, "256-bit VXORPS did not clear its first qword");
    expectEqual(state.xmm[0].high, std::uint64_t{0},
                "256-bit VXORPS did not clear its second qword");
    expectEqual(state.ymmUpper[0].low, std::uint64_t{0},
                "256-bit VXORPS did not clear its third qword");
    expectEqual(state.ymmUpper[0].high, std::uint64_t{0},
                "256-bit VXORPS did not clear its fourth qword");
    expectEqual(state.rflags, std::uint64_t{0xBD7}, "256-bit VXORPS zero idiom changed flags");

    constexpr std::array<std::uint8_t, 5> xorCode{0xC5, 0xF4, 0x57, 0xC2, 0xC3};
    const auto xorDecoded = decoder.decodeBlock(xorCode, instructionAddress);
    expect(rosa::debug::dumpX86(xorDecoded).find("vxorps ymm0, ymm1, ymm2") != std::string::npos,
           "256-bit three-register VXORPS dump differs");
    const auto xorBlock = translator.translate(xorCode, instructionAddress);
    expect(rosa::debug::dumpIr(xorBlock.intermediateRepresentation())
                   .find("read_guest_ymm_upper_lane.i64") != std::string::npos,
           "256-bit VXORPS did not lower upper-lane reads");
    state.xmm[1] = {.low = 0xFFFF0000FFFF0000ULL, .high = 0xAAAAAAAAAAAAAAAAULL};
    state.ymmUpper[1] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.xmm[2] = {.low = 0x00FF00FF00FF00FFULL, .high = 0x5555555555555555ULL};
    state.ymmUpper[2] = {.low = 0x1111111111111111ULL, .high = 0x2222222222222222ULL};
    state.rflags = 0xCD7;
    static_cast<void>(xorBlock.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, state.xmm[1].low ^ state.xmm[2].low,
                "256-bit VXORPS produced the wrong first qword");
    expectEqual(state.xmm[0].high, state.xmm[1].high ^ state.xmm[2].high,
                "256-bit VXORPS produced the wrong second qword");
    expectEqual(state.ymmUpper[0].low, state.ymmUpper[1].low ^ state.ymmUpper[2].low,
                "256-bit VXORPS produced the wrong third qword");
    expectEqual(state.ymmUpper[0].high, state.ymmUpper[1].high ^ state.ymmUpper[2].high,
                "256-bit VXORPS produced the wrong fourth qword");
    expectEqual(state.rflags, std::uint64_t{0xCD7}, "256-bit VXORPS changed flags");
}

void testMovdqaRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x7F, 0x0C, 0x0F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovdqaMemReg,
           "MOVDQA [memory], xmm opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "MOVDQA [memory], xmm length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdi && memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 1 && memory.displacement == 0 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "MOVDQA [memory], xmm operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movdqa [rdi+rcx*1], xmm1") != std::string::npos,
           "MOVDQA [memory], xmm dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = page.value;
    state.rcx = 0x20;
    state.xmm[1] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8020}),
                std::uint64_t{0x0123456789ABCDEFULL}, "MOVDQA store low lane differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8028}),
                std::uint64_t{0xFEDCBA9876543210ULL}, "MOVDQA store high lane differs");
    expectEqual(state.rdi, page.value, "MOVDQA store changed its base");
    expectEqual(state.rcx, std::uint64_t{0x20}, "MOVDQA store changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVDQA store changed flags");

    const auto before = addressSpace.readBytes(rosa::guest::GuestAddress{0x8023}, 16);
    state.rdi = 0x8003;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("16-byte aligned") != std::string_view::npos;
    }
    expect(rejected, "unaligned MOVDQA store did not fault");
    expect(addressSpace.readBytes(rosa::guest::GuestAddress{0x8023}, 16) == before,
           "unaligned MOVDQA store partially changed memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "unaligned MOVDQA store changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only MOVDQA target");
    state.rdi = page.value;
    state.rflags = 0x8D7;
    rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "MOVDQA store accepted read-only memory");
    expectEqual(readOnlyAddressSpace.readU64(rosa::guest::GuestAddress{0x8020}), std::uint64_t{0},
                "faulted MOVDQA store changed read-only memory");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "faulted MOVDQA store changed flags");
}

void testMovdqaGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 9> code{
        0x66, 0x0F, 0x6F, 0x85, 0xE0, 0xFF, 0xFF, 0xFF, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovdqaRegMem,
           "MOVDQA xmm, [mem] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbp, "MOVDQA base differs");
    expectEqual(memory.displacement, std::int64_t{-0x20}, "MOVDQA displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x80E0}, 0x0123456789ABCDEFULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x80E8}, 0xFEDCBA9876543210ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbp = 0x8100;
    state.xmm[0] = {.low = UINT64_MAX, .high = UINT64_MAX};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVDQA loaded the wrong low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVDQA loaded the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVDQA changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbp = 0x8100;
    faultState.xmm[0] = {.low = 0x55, .high = 0xAA};
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOVDQA from unmapped guest memory did not fail");
    expectEqual(faultState.xmm[0].low, std::uint64_t{0x55}, "failed MOVDQA changed the low lane");
    expectEqual(faultState.xmm[0].high, std::uint64_t{0xAA}, "failed MOVDQA changed the high lane");

    constexpr std::array<std::uint8_t, 6> indexedCode{
        0x66, 0x0F, 0x6F, 0x04, 0x0F, 0xC3,
    };
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, rosa::guest::GuestAddress{0x2000});
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovdqaRegMem,
           "indexed MOVDQA opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{5}, "indexed MOVDQA length differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[1]);
    expect(indexedMemory.base == rosa::x86::Register::Rdi, "indexed MOVDQA base differs");
    expect(indexedMemory.index == rosa::x86::Register::Rcx, "indexed MOVDQA index differs");
    expectEqual(indexedMemory.scale, std::uint8_t{1}, "indexed MOVDQA scale differs");
    expectEqual(indexedMemory.displacement, std::int64_t{0}, "indexed MOVDQA displacement differs");
    expect(rosa::debug::dumpX86(indexedDecoded).find("movdqa xmm0, [rdi+rcx*1]") !=
               std::string::npos,
           "indexed MOVDQA dump differs");

    addressSpace.writeU64(rosa::guest::GuestAddress{0x8020}, 0x8877665544332211ULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8028}, 0x0123456789ABCDEFULL);
    const auto indexedBlock = translator.translate(indexedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State indexedState;
    indexedState.rdi = memoryBase.value;
    indexedState.rcx = 0x20;
    indexedState.xmm[0] = {.low = UINT64_MAX, .high = UINT64_MAX};
    indexedState.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(indexedState.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "indexed MOVDQA loaded the wrong low lane");
    expectEqual(indexedState.xmm[0].high, std::uint64_t{0x0123456789ABCDEFULL},
                "indexed MOVDQA loaded the wrong high lane");
    expectEqual(indexedState.rdi, memoryBase.value, "indexed MOVDQA changed its base register");
    expectEqual(indexedState.rcx, std::uint64_t{0x20}, "indexed MOVDQA changed its index register");
    expectEqual(indexedState.rflags, std::uint64_t{0x8D7}, "indexed MOVDQA changed flags");

    rosa::x86::X86State indexedFaultState;
    indexedFaultState.rdi = 0xA000;
    indexedFaultState.rcx = 0x20;
    indexedFaultState.xmm[0] = {.low = 0x55, .high = 0xAA};
    indexedFaultState.rflags = 0x8D7;
    rejected = false;
    try {
        static_cast<void>(indexedBlock.execute(indexedFaultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed MOVDQA from unmapped guest memory did not fail");
    expectEqual(indexedFaultState.xmm[0].low, std::uint64_t{0x55},
                "failed indexed MOVDQA changed the low lane");
    expectEqual(indexedFaultState.xmm[0].high, std::uint64_t{0xAA},
                "failed indexed MOVDQA changed the high lane");
    expectEqual(indexedFaultState.rflags, std::uint64_t{0x8D7},
                "failed indexed MOVDQA changed flags");

    // Observed in sqlite: movdqa xmm7, [rip+disp32].
    constexpr std::array<std::uint8_t, 9> ripRelativeCode{
        0x66, 0x0F, 0x6F, 0x3D, 0x10, 0xA0, 0x17, 0x00, 0xC3,
    };
    const auto ripRelativeDecoded = decoder.decodeBlock(
        ripRelativeCode, rosa::guest::GuestAddress{0x100046E08ULL});
    expect(ripRelativeDecoded[0].opcode == rosa::x86::Opcode::MovdqaRegMem,
           "RIP-relative MOVDQA opcode differs");
    expectEqual(ripRelativeDecoded[0].length, std::uint8_t{8},
                "RIP-relative MOVDQA length differs");
    const auto ripRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(ripRelativeDecoded[0].operands[1]);
    const auto ripRelativeDestination =
        std::get<rosa::x86::XmmRegisterOperand>(ripRelativeDecoded[0].operands[0]);
    expect(ripRelativeDestination.reg == rosa::x86::XmmRegister::Xmm7,
           "RIP-relative MOVDQA destination differs");
    expect(ripRelativeMemory.ripRelative && !ripRelativeMemory.hasBase,
           "RIP-relative MOVDQA addressing differs");
    expectEqual(ripRelativeMemory.displacement, std::int64_t{0x17A010},
                "RIP-relative MOVDQA displacement differs");
    expect(rosa::debug::dumpX86(ripRelativeDecoded).find("movdqa xmm7, [rip+0x17a010]") !=
               std::string::npos,
           "RIP-relative MOVDQA dump differs");

    // Execute the same bytes at a synthetic RIP whose target is aligned.
    constexpr rosa::guest::GuestAddress alignedRip{0x10008};
    constexpr rosa::guest::GuestAddress alignedPage{0x18A000ULL};
    constexpr rosa::guest::GuestAddress alignedTarget{0x18A020ULL};
    rosa::guest::AddressSpace ripRelativeAddressSpace;
    ripRelativeAddressSpace.mapAnonymous(alignedPage, rosa::guest::guestPageSize,
                                         rosa::guest::Permission::Read |
                                             rosa::guest::Permission::Write);
    ripRelativeAddressSpace.writeU64(alignedTarget, 0x0123456789ABCDEFULL);
    ripRelativeAddressSpace.writeU64(
        rosa::guest::GuestAddress{alignedTarget.value + 8}, 0xFEDCBA9876543210ULL);
    const auto ripRelativeBlock = translator.translate(ripRelativeCode, alignedRip);
    rosa::x86::X86State ripRelativeState;
    ripRelativeState.xmm[7] = {.low = UINT64_MAX, .high = UINT64_MAX};
    ripRelativeState.rflags = 0x8D7;
    static_cast<void>(ripRelativeBlock.execute(ripRelativeState, &ripRelativeAddressSpace));
    expectEqual(ripRelativeState.xmm[7].low, std::uint64_t{0x0123456789ABCDEFULL},
                "RIP-relative MOVDQA loaded the wrong low lane");
    expectEqual(ripRelativeState.xmm[7].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "RIP-relative MOVDQA loaded the wrong high lane");
    expectEqual(ripRelativeState.rflags, std::uint64_t{0x8D7}, "RIP-relative MOVDQA changed flags");

    // REX.R extended destination observed in sqlite: movdqa xmm8, [rip+disp32].
    constexpr std::array<std::uint8_t, 10> rexRipRelativeCode{
        0x66, 0x44, 0x0F, 0x6F, 0x05, 0x17, 0xA0, 0x17, 0x00, 0xC3,
    };
    const auto rexRipRelativeDecoded = decoder.decodeBlock(
        rexRipRelativeCode, rosa::guest::GuestAddress{0x100046E10ULL});
    expect(rexRipRelativeDecoded[0].opcode == rosa::x86::Opcode::MovdqaRegMem,
           "REX RIP-relative MOVDQA opcode differs");
    expectEqual(rexRipRelativeDecoded[0].length, std::uint8_t{9},
                "REX RIP-relative MOVDQA length differs");
    const auto rexRipRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(rexRipRelativeDecoded[0].operands[1]);
    const auto rexRipRelativeDestination =
        std::get<rosa::x86::XmmRegisterOperand>(rexRipRelativeDecoded[0].operands[0]);
    expect(rexRipRelativeDestination.reg == rosa::x86::XmmRegister::Xmm8,
           "REX RIP-relative MOVDQA destination differs");
    expect(rexRipRelativeMemory.ripRelative && !rexRipRelativeMemory.hasBase,
           "REX RIP-relative MOVDQA addressing differs");
    expect(rosa::debug::dumpX86(rexRipRelativeDecoded).find("movdqa xmm8, [rip+0x17a017]") !=
               std::string::npos,
           "REX RIP-relative MOVDQA dump differs");
    const auto rexRipRelativeBlock =
        translator.translate(rexRipRelativeCode, rosa::guest::GuestAddress{0x10000});
    rosa::x86::X86State rexRipRelativeState;
    rexRipRelativeState.xmm[8] = {.low = UINT64_MAX, .high = UINT64_MAX};
    rexRipRelativeState.rflags = 0x8D7;
    static_cast<void>(
        rexRipRelativeBlock.execute(rexRipRelativeState, &ripRelativeAddressSpace));
    expectEqual(rexRipRelativeState.xmm[8].low, std::uint64_t{0x0123456789ABCDEFULL},
                "REX RIP-relative MOVDQA loaded the wrong low lane");
    expectEqual(rexRipRelativeState.xmm[8].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "REX RIP-relative MOVDQA loaded the wrong high lane");

    constexpr std::array<std::uint8_t, 5> registerCode{0x66, 0x0F, 0x6F, 0xE8, 0xC3};
    const auto registerDecoded =
        decoder.decodeBlock(registerCode, rosa::guest::GuestAddress{0x3000});
    expect(registerDecoded[0].opcode == rosa::x86::Opcode::MovdqaRegReg,
           "register MOVDQA opcode differs");
    expectEqual(registerDecoded[0].length, std::uint8_t{4}, "register MOVDQA length differs");
    const auto registerDestination =
        std::get<rosa::x86::XmmRegisterOperand>(registerDecoded[0].operands[0]);
    const auto registerSource =
        std::get<rosa::x86::XmmRegisterOperand>(registerDecoded[0].operands[1]);
    expect(registerDestination.reg == rosa::x86::XmmRegister::Xmm5 &&
               registerSource.reg == rosa::x86::XmmRegister::Xmm0,
           "register MOVDQA operands differ");
    expect(rosa::debug::dumpX86(registerDecoded).find("movdqa xmm5, xmm0") != std::string::npos,
           "register MOVDQA dump differs");

    const auto registerBlock =
        translator.translate(registerCode, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State registerState;
    registerState.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    registerState.xmm[5] = {.low = 1, .high = 2};
    registerState.rflags = 0x8D7;
    static_cast<void>(registerBlock.execute(registerState));
    expectEqual(registerState.xmm[5].low, std::uint64_t{0x0123456789ABCDEFULL},
                "register MOVDQA low lane differs");
    expectEqual(registerState.xmm[5].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "register MOVDQA high lane differs");
    expectEqual(registerState.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "register MOVDQA changed its source");
    expectEqual(registerState.rflags, std::uint64_t{0x8D7}, "register MOVDQA changed flags");

    constexpr std::array<std::uint8_t, 10> extendedCode{0x66, 0x41, 0x0F, 0x6F, 0x86,
                                                        0xA0, 0x00, 0x00, 0x00, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x7FF802AA1634ULL});
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::MovdqaRegMem,
           "REX MOVDQA load opcode differs");
    expectEqual(extendedDecoded[0].length, std::uint8_t{9}, "REX MOVDQA load length differs");
    const auto extendedDestination =
        std::get<rosa::x86::XmmRegisterOperand>(extendedDecoded[0].operands[0]);
    const auto extendedMemory = std::get<rosa::x86::MemoryOperand>(extendedDecoded[0].operands[1]);
    expect(extendedDestination.reg == rosa::x86::XmmRegister::Xmm0 &&
               extendedMemory.base == rosa::x86::Register::R14 &&
               extendedMemory.displacement == 0xA0 && extendedMemory.width == 128,
           "MOVDQA xmm0, [r14+0xa0] operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("movdqa xmm0, [r14+0xa0]") !=
               std::string::npos,
           "REX MOVDQA load dump differs");

    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x7FF802AA1634ULL});
    addressSpace.writeU64(rosa::guest::GuestAddress{0x80A0}, 0x8877665544332211ULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x80A8}, 0x1020304050607080ULL);
    rosa::x86::X86State extendedState;
    extendedState.r14 = memoryBase.value;
    extendedState.xmm[0] = {.low = UINT64_MAX, .high = UINT64_MAX};
    extendedState.rflags = 0xAD7;
    static_cast<void>(extendedBlock.execute(extendedState, &addressSpace));
    expectEqual(extendedState.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "REX MOVDQA loaded the wrong low lane");
    expectEqual(extendedState.xmm[0].high, std::uint64_t{0x1020304050607080ULL},
                "REX MOVDQA loaded the wrong high lane");
    expectEqual(extendedState.r14, memoryBase.value, "REX MOVDQA changed its base register");
    expectEqual(extendedState.rflags, std::uint64_t{0xAD7}, "REX MOVDQA changed flags");

    rosa::x86::X86State unalignedState;
    unalignedState.r14 = memoryBase.value + 1;
    unalignedState.xmm[0] = {.low = 0x55, .high = 0xAA};
    unalignedState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(extendedBlock.execute(unalignedState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("aligned") != std::string_view::npos;
    }
    expect(rejected, "REX MOVDQA accepted an unaligned guest address");
    expectEqual(unalignedState.xmm[0].low, std::uint64_t{0x55},
                "faulted REX MOVDQA changed the low lane");
    expectEqual(unalignedState.xmm[0].high, std::uint64_t{0xAA},
                "faulted REX MOVDQA changed the high lane");
    expectEqual(unalignedState.rflags, std::uint64_t{0xBD7}, "faulted REX MOVDQA changed flags");
}

void testMovdquRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{0xF3, 0x0F, 0x7F, 0x04, 0x24, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovdquMemReg,
           "MOVDQU [mem], xmm opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rsp, "MOVDQU SIB base differs");
    expectEqual(memory.displacement, std::int64_t{0}, "MOVDQU displacement differs");

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
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8103}), state.xmm[0].low,
                "MOVDQU stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x810B}), state.xmm[0].high,
                "MOVDQU stored the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVDQU changed flags");

    constexpr std::array<std::uint8_t, 6> indexedCode{0xF3, 0x0F, 0x7F, 0x04, 0xC8, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802AA9366ULL};
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, observedRip);
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovdquMemReg,
           "indexed MOVDQU store opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{5}, "indexed MOVDQU store length differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[0]);
    expect(indexedMemory.base == rosa::x86::Register::Rax &&
               indexedMemory.index == rosa::x86::Register::Rcx && indexedMemory.scale == 8 &&
               indexedMemory.displacement == 0,
           "MOVDQU [rax+rcx*8] memory operand differs");
    expect(rosa::debug::dumpX86(indexedDecoded).find("movdqu [rax+rcx*8], xmm0") !=
               std::string::npos,
           "MOVDQU [rax+rcx*8], xmm0 dump differs");
    const auto indexedBlock = translator.translate(indexedCode, observedRip);
    rosa::x86::X86State indexedState;
    indexedState.rax = 0x8101;
    indexedState.rcx = 2;
    indexedState.xmm[0] = {.low = 0x1122334455667788ULL, .high = 0x99AABBCCDDEEFF00ULL};
    indexedState.rflags = 0xAD7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8111}),
                std::uint64_t{0x1122334455667788ULL}, "indexed MOVDQU stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8119}),
                std::uint64_t{0x99AABBCCDDEEFF00ULL}, "indexed MOVDQU stored the wrong high lane");
    expectEqual(indexedState.rax, std::uint64_t{0x8101}, "indexed MOVDQU changed its base");
    expectEqual(indexedState.rcx, std::uint64_t{2}, "indexed MOVDQU changed its index");
    expectEqual(indexedState.rflags, std::uint64_t{0xAD7}, "indexed MOVDQU changed flags");

    constexpr std::array<std::uint8_t, 7> extendedCode{0xF3, 0x41, 0x0F, 0x7F, 0x47, 0x08, 0xC3};
    const auto extendedDecoded =
        decoder.decodeBlock(extendedCode, rosa::guest::GuestAddress{0x7FF802AA163DULL});
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::MovdquMemReg,
           "REX MOVDQU store opcode differs");
    expectEqual(extendedDecoded[0].length, std::uint8_t{6}, "REX MOVDQU store length differs");
    const auto extendedMemory = std::get<rosa::x86::MemoryOperand>(extendedDecoded[0].operands[0]);
    const auto extendedSource =
        std::get<rosa::x86::XmmRegisterOperand>(extendedDecoded[0].operands[1]);
    expect(extendedMemory.base == rosa::x86::Register::R15 && extendedMemory.displacement == 8 &&
               extendedSource.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVDQU [r15+8], xmm0 operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find("movdqu [r15+0x8], xmm0") !=
               std::string::npos,
           "REX MOVDQU store dump differs");
    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x7FF802AA163DULL});
    rosa::x86::X86State extendedState;
    extendedState.r15 = 0x8103;
    extendedState.xmm[0] = {.low = 0x8877665544332211ULL, .high = 0x1020304050607080ULL};
    extendedState.rflags = 0xAD7;
    static_cast<void>(extendedBlock.execute(extendedState, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x810B}),
                std::uint64_t{0x8877665544332211ULL}, "REX MOVDQU stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8113}),
                std::uint64_t{0x1020304050607080ULL}, "REX MOVDQU stored the wrong high lane");
    expectEqual(extendedState.r15, std::uint64_t{0x8103}, "REX MOVDQU changed its base register");
    expectEqual(extendedState.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "REX MOVDQU changed its source");
    expectEqual(extendedState.rflags, std::uint64_t{0xAD7}, "REX MOVDQU changed flags");

    constexpr std::array<std::uint8_t, 7> extendedSibCode{0xF3, 0x41, 0x0F, 0x7F, 0x04, 0x24, 0xC3};
    constexpr rosa::guest::GuestAddress extendedSibRip{0x7FF802C6CC03ULL};
    const auto extendedSibDecoded = decoder.decodeBlock(extendedSibCode, extendedSibRip);
    expect(extendedSibDecoded[0].opcode == rosa::x86::Opcode::MovdquMemReg,
           "REX SIB MOVDQU store opcode differs");
    expectEqual(extendedSibDecoded[0].length, std::uint8_t{6},
                "REX SIB MOVDQU store length differs");
    const auto extendedSibMemory =
        std::get<rosa::x86::MemoryOperand>(extendedSibDecoded[0].operands[0]);
    const auto extendedSibSource =
        std::get<rosa::x86::XmmRegisterOperand>(extendedSibDecoded[0].operands[1]);
    expect(extendedSibMemory.base == rosa::x86::Register::R12 && !extendedSibMemory.index &&
               extendedSibMemory.displacement == 0 &&
               extendedSibSource.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVDQU [r12], xmm0 operands differ");
    expect(rosa::debug::dumpX86(extendedSibDecoded).find("movdqu [r12], xmm0") != std::string::npos,
           "REX SIB MOVDQU store dump differs");
    const auto extendedSibBlock = translator.translate(extendedSibCode, extendedSibRip);
    rosa::x86::X86State extendedSibState;
    extendedSibState.r12 = 0x8120;
    extendedSibState.xmm[0] = {.low = 0xA1A2A3A4A5A6A7A8ULL, .high = 0xB1B2B3B4B5B6B7B8ULL};
    extendedSibState.rflags = 0x46;
    static_cast<void>(extendedSibBlock.execute(extendedSibState, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8120}),
                extendedSibState.xmm[0].low, "REX SIB MOVDQU stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8128}),
                extendedSibState.xmm[0].high, "REX SIB MOVDQU stored the wrong high lane");
    expectEqual(extendedSibState.r12, std::uint64_t{0x8120}, "REX SIB MOVDQU changed R12");
    expectEqual(extendedSibState.rflags, std::uint64_t{0x46}, "REX SIB MOVDQU changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    std::fill_n(readOnlyBytes.begin() + 0x10B, 16, 0xA5);
    readOnlyAddressSpace.mapSegment(memoryBase, readOnlyBytes.size(), rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only REX MOVDQU target");
    auto faultState = extendedState;
    faultState.rflags = 0xBD7;
    bool rejected = false;
    try {
        static_cast<void>(extendedBlock.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "REX MOVDQU accepted read-only guest memory");
    const auto unchanged = readOnlyAddressSpace.readBytes(rosa::guest::GuestAddress{0x810B}, 16);
    expect(std::ranges::all_of(unchanged, [](std::uint8_t byte) { return byte == 0xA5; }),
           "faulted REX MOVDQU partially changed guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7}, "faulted REX MOVDQU changed flags");

    auto extendedSibFaultState = extendedSibState;
    extendedSibFaultState.r12 = 0x810B;
    extendedSibFaultState.rflags = 0xCD7;
    rejected = false;
    try {
        static_cast<void>(extendedSibBlock.execute(extendedSibFaultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(rejected, "REX SIB MOVDQU accepted read-only guest memory");
    expect(
        std::ranges::all_of(readOnlyAddressSpace.readBytes(rosa::guest::GuestAddress{0x810B}, 16),
                            [](std::uint8_t byte) { return byte == 0xA5; }),
        "faulted REX SIB MOVDQU partially changed guest memory");
    expectEqual(extendedSibFaultState.r12, std::uint64_t{0x810B},
                "faulted REX SIB MOVDQU changed R12");
    expectEqual(extendedSibFaultState.rflags, std::uint64_t{0xCD7},
                "faulted REX SIB MOVDQU changed flags");

    constexpr std::array<std::uint8_t, 9> ripCode{0xF3, 0x0F, 0x7F, 0x05, 0x2B,
                                                  0x47, 0xC9, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress ripStoreAddress{0x7FF802A18245ULL};
    constexpr rosa::guest::GuestAddress ripTarget{0x7FF8436AC978ULL};
    constexpr rosa::guest::GuestAddress ripTargetPage{0x7FF8436AC000ULL};
    const auto ripDecoded = decoder.decodeBlock(ripCode, ripStoreAddress);
    expect(ripDecoded[0].opcode == rosa::x86::Opcode::MovdquMemReg && ripDecoded[0].length == 8,
           "RIP-relative MOVDQU store opcode or length differs");
    const auto ripMemory = std::get<rosa::x86::MemoryOperand>(ripDecoded[0].operands[0]);
    const auto ripSource = std::get<rosa::x86::XmmRegisterOperand>(ripDecoded[0].operands[1]);
    expect(ripMemory.ripRelative && !ripMemory.hasBase && !ripMemory.index &&
               ripMemory.displacement == 0x40C9472B && ripMemory.width == 128 &&
               ripSource.reg == rosa::x86::XmmRegister::Xmm0,
           "RIP-relative MOVDQU store operands differ");
    expect(
        rosa::debug::dumpX86(ripDecoded).find("movdqu [rip+0x40c9472b], xmm0 ; 0x7ff8436ac978") !=
            std::string::npos,
        "RIP-relative MOVDQU store dump differs");

    addressSpace.mapAnonymous(ripTargetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const auto ripBlock = translator.translate(ripCode, ripStoreAddress);
    rosa::x86::X86State ripState;
    ripState.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    ripState.rflags = 0x46;
    static_cast<void>(ripBlock.execute(ripState, &addressSpace));
    expectEqual(addressSpace.readU64(ripTarget), ripState.xmm[0].low,
                "RIP-relative MOVDQU stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{ripTarget.value + 8}),
                ripState.xmm[0].high, "RIP-relative MOVDQU stored the wrong high lane");
    expectEqual(ripState.rflags, std::uint64_t{0x46}, "RIP-relative MOVDQU changed flags");

    constexpr std::array<std::uint8_t, 9> crossPageCode{0xF3, 0x0F, 0x7F, 0x05, 0xF0,
                                                        0x0F, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress crossPageAddress{0x1000};
    constexpr rosa::guest::GuestAddress crossPageTarget{0x1FF8};
    constexpr std::array<std::uint8_t, 8> crossPageBytes{0xA5, 0xA5, 0xA5, 0xA5,
                                                         0xA5, 0xA5, 0xA5, 0xA5};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(crossPageAddress, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, crossPageBytes);
    const auto crossPageBlock = translator.translate(crossPageCode, crossPageAddress);
    rosa::x86::X86State crossPageState;
    crossPageState.xmm[0] = {.low = 0x1122334455667788ULL, .high = 0x99AABBCCDDEEFF00ULL};
    crossPageState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(crossPageBlock.execute(crossPageState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page RIP-relative MOVDQU did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, 8) ==
               std::vector<std::uint8_t>(crossPageBytes.begin(), crossPageBytes.end()),
           "faulted cross-page RIP-relative MOVDQU partially changed memory");
    expectEqual(crossPageState.rflags, std::uint64_t{0xAD7},
                "faulted cross-page RIP-relative MOVDQU changed flags");
}

void testMovdquGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 7> code{0xF3, 0x41, 0x0F, 0x6F, 0x47, 0x28, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovdquRegMem,
           "MOVDQU xmm, [mem] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R15, "MOVDQU load REX.B base differs");
    expectEqual(memory.displacement, std::int64_t{0x28}, "MOVDQU load displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x812B}, 0x0123456789ABCDEFULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8133}, 0xFEDCBA9876543210ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r15 = 0x8103;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVDQU load low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVDQU load high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVDQU load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.xmm[0] = {.low = 5, .high = 6};
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOVDQU load from unmapped guest memory did not fault");
    expectEqual(state.xmm[0].low, std::uint64_t{5}, "failed MOVDQU load changed low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{6}, "failed MOVDQU load changed high lane");

    constexpr std::array<std::uint8_t, 6> indexedCode{
        0xF3, 0x0F, 0x6F, 0x0C, 0x0E, 0xC3,
    };
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, rosa::guest::GuestAddress{0x2000});
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovdquRegMem,
           "indexed MOVDQU opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{5}, "indexed MOVDQU length differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[1]);
    expect(indexedMemory.base == rosa::x86::Register::Rsi, "indexed MOVDQU base differs");
    expect(indexedMemory.index == rosa::x86::Register::Rcx, "indexed MOVDQU index differs");
    expectEqual(indexedMemory.scale, std::uint8_t{1}, "indexed MOVDQU scale differs");
    expect(rosa::debug::dumpX86(indexedDecoded).find("movdqu xmm1, [rsi+rcx*1]") !=
               std::string::npos,
           "indexed MOVDQU dump differs");

    addressSpace.writeU64(rosa::guest::GuestAddress{0x8023}, 0x8877665544332211ULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x802B}, 0x0123456789ABCDEFULL);
    const auto indexedBlock = translator.translate(indexedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State indexedState;
    indexedState.rsi = 0x8003;
    indexedState.rcx = 0x20;
    indexedState.xmm[1] = {.low = UINT64_MAX, .high = UINT64_MAX};
    indexedState.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(indexedState.xmm[1].low, std::uint64_t{0x8877665544332211ULL},
                "indexed MOVDQU loaded the wrong low lane");
    expectEqual(indexedState.xmm[1].high, std::uint64_t{0x0123456789ABCDEFULL},
                "indexed MOVDQU loaded the wrong high lane");
    expectEqual(indexedState.rsi, std::uint64_t{0x8003},
                "indexed MOVDQU changed its base register");
    expectEqual(indexedState.rcx, std::uint64_t{0x20}, "indexed MOVDQU changed its index register");
    expectEqual(indexedState.rflags, std::uint64_t{0x8D7}, "indexed MOVDQU changed flags");

    constexpr std::array<std::uint8_t, 9> ripCode{0xF3, 0x0F, 0x6F, 0x05, 0xA1,
                                                  0xDB, 0x63, 0x3D, 0xC3};
    constexpr rosa::guest::GuestAddress ripAddress{0x7FF802A186FFULL};
    constexpr rosa::guest::GuestAddress ripSource{0x7FF8400562A8ULL};
    constexpr rosa::guest::GuestAddress ripSourcePage{0x7FF840056000ULL};
    const auto ripDecoded = decoder.decodeBlock(ripCode, ripAddress);
    expect(ripDecoded[0].opcode == rosa::x86::Opcode::MovdquRegMem && ripDecoded[0].length == 8,
           "RIP-relative MOVDQU load opcode or length differs");
    const auto ripMemory = std::get<rosa::x86::MemoryOperand>(ripDecoded[0].operands[1]);
    expect(ripMemory.ripRelative && !ripMemory.hasBase && !ripMemory.index &&
               ripMemory.width == 128 && ripMemory.displacement == 0x3D63DBA1,
           "RIP-relative MOVDQU load operand differs");
    expect(
        rosa::debug::dumpX86(ripDecoded).find("movdqu xmm0, [rip+0x3d63dba1] ; 0x7ff8400562a8") !=
            std::string::npos,
        "RIP-relative MOVDQU load dump differs");
    rosa::guest::AddressSpace ripAddressSpace;
    ripAddressSpace.mapAnonymous(ripSourcePage, rosa::guest::guestPageSize,
                                 rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    ripAddressSpace.writeU64(ripSource, 0x1122334455667788ULL);
    ripAddressSpace.writeU64(rosa::guest::GuestAddress{ripSource.value + 8}, 0x99AABBCCDDEEFF00ULL);
    const auto ripBlock = translator.translate(ripCode, ripAddress);
    rosa::x86::X86State ripState;
    ripState.xmm[0] = {.low = 5, .high = 6};
    ripState.rflags = 0xAD7;
    static_cast<void>(ripBlock.execute(ripState, &ripAddressSpace));
    expectEqual(ripState.xmm[0].low, std::uint64_t{0x1122334455667788ULL},
                "RIP-relative MOVDQU loaded the wrong low lane");
    expectEqual(ripState.xmm[0].high, std::uint64_t{0x99AABBCCDDEEFF00ULL},
                "RIP-relative MOVDQU loaded the wrong high lane");
    expectEqual(ripState.rflags, std::uint64_t{0xAD7}, "RIP-relative MOVDQU load changed flags");

    constexpr std::array<std::uint8_t, 9> crossPageCode{0xF3, 0x0F, 0x6F, 0x05, 0xF0,
                                                        0x0F, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress crossPageRip{0x1000};
    constexpr rosa::guest::GuestAddress crossPageSource{0x1FF8};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(crossPageRip, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    crossPageAddressSpace.writeU64(crossPageSource, 0x0123456789ABCDEFULL);
    const auto crossPageBlock = translator.translate(crossPageCode, crossPageRip);
    rosa::x86::X86State crossPageState;
    crossPageState.xmm[0] = {.low = 0x8877665544332211ULL, .high = 0x1020304050607080ULL};
    crossPageState.rflags = 0x8D7;
    rejected = false;
    try {
        static_cast<void>(crossPageBlock.execute(crossPageState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page RIP-relative MOVDQU load did not fault");
    expectEqual(crossPageState.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "faulted MOVDQU load changed the low lane");
    expectEqual(crossPageState.xmm[0].high, std::uint64_t{0x1020304050607080ULL},
                "faulted MOVDQU load changed the high lane");
    expectEqual(crossPageState.rflags, std::uint64_t{0x8D7}, "faulted MOVDQU load changed flags");
}

void testMovqXmmToGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0xD6, 0x46, 0x20, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovqMemXmm, "MOVQ [mem], xmm opcode differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsi = 0x8103;
    state.xmm[0] = {
        .low = 0x0123456789ABCDEFULL,
        .high = 0xFEDCBA9876543210ULL,
    };
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8123}),
                std::uint64_t{0x0123456789ABCDEFULL}, "MOVQ stored the wrong XMM lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVQ changed its XMM source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVQ changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOVQ to unmapped guest memory did not fault");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "failed MOVQ changed its XMM source");

    constexpr std::array<std::uint8_t, 7> indexedCode{0x66, 0x0F, 0xD6, 0x44, 0xC2, 0x20, 0xC3};
    const auto indexedDecoded =
        decoder.decodeBlock(indexedCode, rosa::guest::GuestAddress{0x7FF802A18008ULL});
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovqMemXmm &&
               indexedDecoded[0].length == 6,
           "indexed MOVQ [memory], xmm opcode or length differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[0]);
    const auto indexedSource =
        std::get<rosa::x86::XmmRegisterOperand>(indexedDecoded[0].operands[1]);
    expect(indexedMemory.base == rosa::x86::Register::Rdx &&
               indexedMemory.index == rosa::x86::Register::Rax && indexedMemory.scale == 8 &&
               indexedMemory.displacement == 0x20 && indexedMemory.width == 64 &&
               indexedSource.reg == rosa::x86::XmmRegister::Xmm0,
           "indexed MOVQ [rdx+rax*8+0x20], xmm0 operands differ");
    expect(rosa::debug::dumpX86(indexedDecoded).find("movq [rdx+rax*8+0x20], xmm0") !=
               std::string::npos,
           "indexed MOVQ [memory], xmm dump differs");

    const auto indexedBlock =
        translator.translate(indexedCode, rosa::guest::GuestAddress{0x7FF802A18008ULL});
    rosa::x86::X86State indexedState;
    indexedState.rdx = memoryBase.value;
    indexedState.rax = 4;
    indexedState.xmm[0] = {
        .low = 0x8877665544332211ULL,
        .high = 0x1020304050607080ULL,
    };
    indexedState.rflags = 0xAD7;
    static_cast<void>(indexedBlock.execute(indexedState, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8040}),
                std::uint64_t{0x8877665544332211ULL}, "indexed MOVQ stored the wrong XMM lane");
    expectEqual(indexedState.rdx, memoryBase.value, "indexed MOVQ changed its base");
    expectEqual(indexedState.rax, std::uint64_t{4}, "indexed MOVQ changed its index");
    expectEqual(indexedState.xmm[0].high, std::uint64_t{0x1020304050607080ULL},
                "indexed MOVQ changed its XMM source");
    expectEqual(indexedState.rflags, std::uint64_t{0xAD7}, "indexed MOVQ changed flags");

    rosa::x86::X86State indexedFaultState = indexedState;
    indexedFaultState.rflags = 0x8D7;
    rejected = false;
    try {
        static_cast<void>(indexedBlock.execute(indexedFaultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed MOVQ to unmapped guest memory did not fault");
    expectEqual(indexedFaultState.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "faulted indexed MOVQ changed its XMM source");
    expectEqual(indexedFaultState.rflags, std::uint64_t{0x8D7},
                "faulted indexed MOVQ changed flags");

    constexpr std::array<std::uint8_t, 8> extendedIndexedCode{0x66, 0x42, 0x0F, 0xD6,
                                                              0x4C, 0x92, 0x2C, 0xC3};
    constexpr rosa::guest::GuestAddress extendedIndexedRip{0x7FF802C6ACE3ULL};
    const auto extendedIndexedDecoded =
        decoder.decodeBlock(extendedIndexedCode, extendedIndexedRip);
    expect(extendedIndexedDecoded[0].opcode == rosa::x86::Opcode::MovqMemXmm,
           "extended-index MOVQ [memory], xmm opcode differs");
    expectEqual(extendedIndexedDecoded[0].length, std::uint8_t{7},
                "extended-index MOVQ [memory], xmm length differs");
    const auto extendedIndexedMemory =
        std::get<rosa::x86::MemoryOperand>(extendedIndexedDecoded[0].operands[0]);
    const auto extendedIndexedSource =
        std::get<rosa::x86::XmmRegisterOperand>(extendedIndexedDecoded[0].operands[1]);
    expect(extendedIndexedMemory.base == rosa::x86::Register::Rdx &&
               extendedIndexedMemory.index == rosa::x86::Register::R10 &&
               extendedIndexedMemory.scale == 4 && extendedIndexedMemory.displacement == 0x2C &&
               extendedIndexedSource.reg == rosa::x86::XmmRegister::Xmm1,
           "movq [rdx+r10*4+0x2c], xmm1 operands differ");
    expect(rosa::debug::dumpX86(extendedIndexedDecoded).find("movq [rdx+r10*4+0x2c], xmm1") !=
               std::string::npos,
           "movq [rdx+r10*4+0x2c], xmm1 dump differs");

    const auto extendedIndexedBlock = translator.translate(extendedIndexedCode, extendedIndexedRip);
    rosa::x86::X86State extendedIndexedState;
    extendedIndexedState.rdx = memoryBase.value;
    extendedIndexedState.r10 = 7;
    extendedIndexedState.xmm[1] = {.low = 0xD0C0B0A090807060ULL, .high = 0x1020304050607080ULL};
    extendedIndexedState.rflags = 0xAD7;
    static_cast<void>(extendedIndexedBlock.execute(extendedIndexedState, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{memoryBase.value + 0x48}),
                std::uint64_t{0xD0C0B0A090807060ULL},
                "extended-index MOVQ stored the wrong XMM lane");
    expectEqual(extendedIndexedState.rdx, memoryBase.value, "extended-index MOVQ changed its base");
    expectEqual(extendedIndexedState.r10, std::uint64_t{7},
                "extended-index MOVQ changed its index");
    expectEqual(extendedIndexedState.xmm[1].high, std::uint64_t{0x1020304050607080ULL},
                "extended-index MOVQ changed its XMM source");
    expectEqual(extendedIndexedState.rflags, std::uint64_t{0xAD7},
                "extended-index MOVQ changed flags");

    constexpr rosa::guest::GuestAddress crossPage{0x1000};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(crossPage, rosa::guest::guestPageSize,
                                       rosa::guest::Permission::Read |
                                           rosa::guest::Permission::Write);
    crossPageAddressSpace.writeU32(rosa::guest::GuestAddress{0x1FFC}, 0xA5A5A5A5U);
    rosa::x86::X86State crossPageState = extendedIndexedState;
    crossPageState.rdx = 0x1FB4;
    rejected = false;
    try {
        static_cast<void>(extendedIndexedBlock.execute(crossPageState, &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "cross-page extended-index MOVQ did not fault");
    expectEqual(crossPageAddressSpace.readU32(rosa::guest::GuestAddress{0x1FFC}),
                std::uint32_t{0xA5A5A5A5U}, "faulted extended-index MOVQ partially changed memory");
    expectEqual(crossPageState.xmm[1].low, std::uint64_t{0xD0C0B0A090807060ULL},
                "faulted extended-index MOVQ changed its XMM source");

    // Observed in libobjc under an Objective-C fixture: MOVQ [RIP+disp32], xmm0.
    constexpr std::array<std::uint8_t, 9> ripRelativeCode{0x66, 0x0F, 0xD6, 0x05,
                                                          0xDA, 0x0E, 0xC9, 0x40, 0xC3};
    constexpr rosa::guest::GuestAddress ripRelativeRip{0x7FF802A1BAFEULL};
    const auto ripRelativeDecoded = decoder.decodeBlock(ripRelativeCode, ripRelativeRip);
    expect(ripRelativeDecoded[0].opcode == rosa::x86::Opcode::MovqMemXmm,
           "RIP-relative MOVQ [memory], xmm opcode differs");
    expectEqual(ripRelativeDecoded[0].length, std::uint8_t{8},
                "RIP-relative MOVQ [memory], xmm length differs");
    const auto ripRelativeMemory =
        std::get<rosa::x86::MemoryOperand>(ripRelativeDecoded[0].operands[0]);
    const auto ripRelativeSource =
        std::get<rosa::x86::XmmRegisterOperand>(ripRelativeDecoded[0].operands[1]);
    expect(ripRelativeMemory.ripRelative && !ripRelativeMemory.hasBase &&
               !ripRelativeMemory.index && ripRelativeMemory.width == 64 &&
               ripRelativeMemory.displacement == 0x40C90EDA &&
               ripRelativeSource.reg == rosa::x86::XmmRegister::Xmm0,
           "movq [rip+0x40c90eda], xmm0 operands differ");
    expectEqual(ripRelativeRip.value + ripRelativeDecoded[0].length +
                    ripRelativeMemory.displacement,
                std::uint64_t{0x7FF8436AC9E0ULL}, "RIP-relative MOVQ target differs");
    expect(rosa::debug::dumpX86(ripRelativeDecoded).find("movq [rip+0x40c90eda], xmm0") !=
               std::string::npos,
           "RIP-relative MOVQ [memory], xmm dump differs");

    constexpr rosa::guest::GuestAddress ripTarget{0x8200};
    constexpr std::array<std::uint8_t, 9> ripExecuteCode{0x66, 0x0F, 0xD6, 0x05,
                                                        0xF8, 0x71, 0x00, 0x00, 0xC3};
    const auto ripBlock =
        translator.translate(ripExecuteCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State ripState;
    ripState.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    ripState.rflags = 0x8D7;
    static_cast<void>(ripBlock.execute(ripState, &addressSpace));
    expectEqual(addressSpace.readU64(ripTarget), std::uint64_t{0x0123456789ABCDEFULL},
                "RIP-relative MOVQ stored the wrong XMM lane");
    expectEqual(ripState.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "RIP-relative MOVQ changed its XMM source");
    expectEqual(ripState.rflags, std::uint64_t{0x8D7}, "RIP-relative MOVQ changed flags");
}

void testConvertInt32x2ToDoubleXmm() {
    // Observed in CoreGraphics under an Objective-C fixture: CVTDQ2PD xmm0, xmm0.
    constexpr std::array<std::uint8_t, 5> code{0xF3, 0x0F, 0xE6, 0xC0, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4E28ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::Cvtdq2pdXmmReg,
           "CVTDQ2PD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "CVTDQ2PD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               source.reg == rosa::x86::XmmRegister::Xmm0,
           "CVTDQ2PD xmm0, xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("cvtdq2pd xmm0, xmm0") != std::string::npos,
           "CVTDQ2PD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("convert_int32x2_to_double_xmm.i64") != std::string::npos,
           "CVTDQ2PD did not lower through conversion IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0000002AFFFFFFFFULL, .high = 0xAAAAAAAAAAAAAAAAULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // d0 -1 becomes -1.0, d1 42 becomes 42.0.
    expectEqual(state.xmm[0].low, std::uint64_t{0xBFF0000000000000ULL},
                "CVTDQ2PD low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x4045000000000000ULL},
                "CVTDQ2PD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "CVTDQ2PD changed flags");
}

void testConvertFloat32ToDoubleXmm() {
    // Observed in CoreGraphics under an Objective-C fixture:
    // CVTSS2SD xmm0, dword [rax+r15*8].
    constexpr std::array<std::uint8_t, 7> code{0xF2, 0x42, 0x0F, 0x5A, 0x04, 0xF8, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8099AB301ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::Cvtss2sdXmmMem,
           "CVTSS2SD xmm, m32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6}, "CVTSS2SD xmm, m32 length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0,
           "CVTSS2SD xmm, m32 destination differs");
    expect(!memory.ripRelative && memory.hasBase &&
               memory.base == rosa::x86::Register::Rax && memory.index &&
               *memory.index == rosa::x86::Register::R15 && memory.scale == 8 &&
               memory.displacement == 0 && memory.width == 32,
           "CVTSS2SD xmm0, dword [rax+r15*8] memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cvtss2sd xmm0, dword [rax+r15*8]") !=
               std::string::npos,
           "CVTSS2SD xmm, m32 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress sourceAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    // 3.14f.
    addressSpace.writeU32(sourceAddress, 0x4048F5C3);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("convert_float_to_double_xmm.i32") != std::string::npos,
           "CVTSS2SD did not lower through conversion IR");
    rosa::x86::X86State state;
    state.rax = sourceAddress.value - 0x20;
    state.r15 = 4;
    state.xmm[0] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x40091EB860000000ULL},
                "CVTSS2SD converted the wrong double bits");
    // Legacy SSE leaves the upper quadword unchanged (checked against Rosetta).
    expectEqual(state.xmm[0].high, std::uint64_t{0xBBBBBBBBBBBBBBBBULL},
                "CVTSS2SD changed the high lane");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "CVTSS2SD changed flags");

    // Register form: CVTSS2SD xmm0, xmm1 with -0.5f.
    constexpr std::array<std::uint8_t, 5> regCode{0xF2, 0x0F, 0x5A, 0xC1, 0xC3};
    const auto regDecoded = decoder.decodeBlock(regCode, observedRip);
    expect(regDecoded[0].opcode == rosa::x86::Opcode::Cvtss2sdXmmReg,
           "CVTSS2SD xmm, xmm opcode differs");
    expect(rosa::debug::dumpX86(regDecoded).find("cvtss2sd xmm0, xmm1") != std::string::npos,
           "CVTSS2SD xmm, xmm dump differs");
    const auto regBlock = translator.translate(regCode, observedRip);
    rosa::x86::X86State regState;
    regState.xmm[0] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    regState.xmm[1] = {.low = 0x12345678BF000000ULL, .high = 0};
    regState.rflags = 0xAD7;
    static_cast<void>(regBlock.execute(regState));
    expectEqual(regState.xmm[0].low, std::uint64_t{0xBFE0000000000000ULL},
                "CVTSS2SD register form converted the wrong double bits");
    expectEqual(regState.xmm[0].high, std::uint64_t{0xBBBBBBBBBBBBBBBBULL},
                "CVTSS2SD register form changed the high lane");
}

void testConvertInt32ToDoubleXmm() {
    // Observed in Foundation under an Objective-C fixture: CVTSI2SD xmm0, [rbp-0x30].
    constexpr std::array<std::uint8_t, 6> code{0xF2, 0x0F, 0x2A, 0x45, 0xD0, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8040AC765ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::Cvtsi2sdXmmMem,
           "CVTSI2SD xmm, m32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "CVTSI2SD xmm, m32 length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0,
           "CVTSI2SD xmm, m32 destination differs");
    expect(!memory.ripRelative && memory.hasBase &&
               memory.base == rosa::x86::Register::Rbp && !memory.index &&
               memory.displacement == -0x30 && memory.width == 32,
           "CVTSI2SD xmm, m32 memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cvtsi2sd xmm0, dword [rbp-0x30]") !=
               std::string::npos,
           "CVTSI2SD xmm, m32 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress sourceAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    // -123456789.
    addressSpace.writeU32(sourceAddress, 0xF8A432EB);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("convert_int_to_double_xmm.i32") != std::string::npos,
           "CVTSI2SD did not lower through conversion IR");
    rosa::x86::X86State state;
    state.rbp = sourceAddress.value + 0x30;
    state.xmm[0] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0xC19D6F3454000000ULL},
                "CVTSI2SD converted the wrong double bits");
    // Legacy SSE leaves the upper quadword unchanged (checked against Rosetta).
    expectEqual(state.xmm[0].high, std::uint64_t{0xBBBBBBBBBBBBBBBBULL},
                "CVTSI2SD changed the high lane");
    expectEqual(state.rbp, sourceAddress.value + 0x30, "CVTSI2SD changed its base register");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "CVTSI2SD changed flags");

    // Register form: CVTSI2SD xmm0, ecx.
    constexpr std::array<std::uint8_t, 5> regCode{0xF2, 0x0F, 0x2A, 0xC1, 0xC3};
    const auto regDecoded = decoder.decodeBlock(regCode, observedRip);
    expect(regDecoded[0].opcode == rosa::x86::Opcode::Cvtsi2sdXmmReg,
           "CVTSI2SD xmm, r32 opcode differs");
    const auto regSource = std::get<rosa::x86::RegisterOperand>(regDecoded[0].operands[1]);
    expect(regSource.reg == rosa::x86::Register::Rcx && regSource.width == 32,
           "CVTSI2SD xmm0, ecx operands differ");
    expect(rosa::debug::dumpX86(regDecoded).find("cvtsi2sd xmm0, ecx") != std::string::npos,
           "CVTSI2SD xmm, r32 dump differs");
    const auto regBlock = translator.translate(regCode, observedRip);
    rosa::x86::X86State regState;
    regState.rcx = 42;
    regState.xmm[0] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    regState.rflags = 0xAD7;
    static_cast<void>(regBlock.execute(regState));
    expectEqual(regState.xmm[0].low, std::uint64_t{0x4045000000000000ULL},
                "CVTSI2SD register form converted the wrong double bits");
    expectEqual(regState.xmm[0].high, std::uint64_t{0xBBBBBBBBBBBBBBBBULL},
                "CVTSI2SD register form changed the high lane");
    expectEqual(regState.rflags, std::uint64_t{0xAD7}, "CVTSI2SD register form changed flags");
}

void testScalarDoubleArithmeticXmm() {
    // Observed in Foundation under an Objective-C fixture: DIVSD xmm0, [RIP+disp32].
    constexpr std::array<std::uint8_t, 9> divCode{0xF2, 0x0F, 0x5E, 0x05,
                                                  0xF6, 0x55, 0xED, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress divRip{0x7FF8040AC76AULL};
    const rosa::x86::Decoder decoder;
    const auto divDecoded = decoder.decodeBlock(divCode, divRip);
    expect(divDecoded[0].opcode == rosa::x86::Opcode::DivsdXmmMem,
           "DIVSD xmm, m64 opcode differs");
    expectEqual(divDecoded[0].length, std::uint8_t{8}, "DIVSD xmm, m64 length differs");
    const auto divDestination =
        std::get<rosa::x86::XmmRegisterOperand>(divDecoded[0].operands[0]);
    const auto divMemory = std::get<rosa::x86::MemoryOperand>(divDecoded[0].operands[1]);
    expect(divDestination.reg == rosa::x86::XmmRegister::Xmm0,
           "DIVSD xmm, m64 destination differs");
    expect(divMemory.ripRelative && !divMemory.hasBase && !divMemory.index &&
               divMemory.width == 64 && divMemory.displacement == 0xED55F6,
           "DIVSD xmm, m64 memory operand differs");
    expect(rosa::debug::dumpX86(divDecoded).find("divsd xmm0, qword [rip+0xed55f6]") !=
               std::string::npos,
           "DIVSD xmm, m64 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress sourceAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(sourceAddress, 0x4004000000000000ULL); // 2.5.
    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 9> divExecuteCode{0xF2, 0x0F, 0x5E, 0x05,
                                                         0xF8, 0x70, 0x00, 0x00, 0xC3};
    const auto divBlock =
        translator.translate(divExecuteCode, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(divBlock.intermediateRepresentation())
                   .find("scalar_divide_double_xmm") != std::string::npos,
           "DIVSD did not lower through scalar-double IR");
    rosa::x86::X86State divState;
    // 7.5 / 2.5 == 3.0; the high lane is preserved, unlike CVTSI2SD.
    divState.xmm[0] = {.low = 0x401E000000000000ULL, .high = 0xAAAAAAAAAAAAAAAAULL};
    divState.rflags = 0xAD7;
    static_cast<void>(divBlock.execute(divState, &addressSpace));
    expectEqual(divState.xmm[0].low, std::uint64_t{0x4008000000000000ULL},
                "DIVSD produced the wrong quotient");
    expectEqual(divState.xmm[0].high, std::uint64_t{0xAAAAAAAAAAAAAAAAULL},
                "DIVSD did not preserve the high lane");
    expectEqual(divState.rflags, std::uint64_t{0xAD7}, "DIVSD changed flags");

    struct ScalarDoubleCase {
        std::uint8_t opcode;
        rosa::x86::Opcode expected;
        std::string_view name;
        std::uint64_t destinationBits;
        std::uint64_t sourceBits;
        std::uint64_t expectedBits;
    };
    constexpr ScalarDoubleCase cases[] = {
        {0x58, rosa::x86::Opcode::AddsdXmmReg, "addsd", 0x3FF8000000000000ULL,
         0x4002000000000000ULL, 0x400E000000000000ULL}, // 1.5 + 2.25 == 3.75.
        {0x5C, rosa::x86::Opcode::SubsdXmmReg, "subsd", 0x4014000000000000ULL,
         0x4020000000000000ULL, 0xC008000000000000ULL}, // 5.0 - 8.0 == -3.0.
        {0x59, rosa::x86::Opcode::MulsdXmmReg, "mulsd", 0x4004000000000000ULL,
         0x4010000000000000ULL, 0x4024000000000000ULL}, // 2.5 * 4.0 == 10.0.
        {0x5E, rosa::x86::Opcode::DivsdXmmReg, "divsd", 0x401E000000000000ULL,
         0x4004000000000000ULL, 0x4008000000000000ULL}, // 7.5 / 2.5 == 3.0.
    };
    for (const auto &doubleCase : cases) {
        const std::array<std::uint8_t, 5> code{0xF2, 0x0F, doubleCase.opcode, 0xC1, 0xC3};
        const auto decoded = decoder.decodeBlock(code, divRip);
        expect(decoded[0].opcode == doubleCase.expected,
               std::string(doubleCase.name) + " xmm, xmm opcode differs");
        expectEqual(decoded[0].length, std::uint8_t{4},
                    std::string(doubleCase.name) + " xmm, xmm length differs");
        expect(rosa::debug::dumpX86(decoded).find(
                   std::string(doubleCase.name) + " xmm0, xmm1") != std::string::npos,
               std::string(doubleCase.name) + " xmm, xmm dump differs");

        const auto block = translator.translate(code, divRip);
        rosa::x86::X86State state;
        state.xmm[0] = {.low = doubleCase.destinationBits, .high = 0xBBBBBBBBBBBBBBBBULL};
        state.xmm[1] = {.low = doubleCase.sourceBits, .high = 0xCCCCCCCCCCCCCCCCULL};
        state.rflags = 0xAD7;
        static_cast<void>(block.execute(state));
        expectEqual(state.xmm[0].low, doubleCase.expectedBits,
                    std::string(doubleCase.name) + " produced the wrong result");
        expectEqual(state.xmm[0].high, std::uint64_t{0xBBBBBBBBBBBBBBBBULL},
                    std::string(doubleCase.name) + " did not preserve the high lane");
        expectEqual(state.xmm[1].low, doubleCase.sourceBits,
                    std::string(doubleCase.name) + " changed its source");
        expectEqual(state.rflags, std::uint64_t{0xAD7},
                    std::string(doubleCase.name) + " changed flags");
    }
}

void testMovqGuestMemoryToXmm() {
    constexpr std::array<std::uint8_t, 6> code{0xF3, 0x0F, 0x7E, 0x40, 0x38, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF700081A44ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovqXmmMem, "MOVQ xmm, [mem] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "MOVQ xmm, [mem] length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               memory.base == rosa::x86::Register::Rax && memory.displacement == 0x38 &&
               memory.width == 64,
           "MOVQ xmm0, [rax+0x38] operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movq xmm0, qword [rax+0x38]") != std::string::npos,
           "MOVQ xmm0, [rax+0x38] dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr auto value = std::uint64_t{0x0123456789ABCDEFULL};
    std::array<std::uint8_t, rosa::guest::guestPageSize> bytes{};
    std::memcpy(bytes.data() + 0x38, &value, sizeof(value));
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(page, bytes.size(), rosa::guest::Permission::Read, bytes,
                            "read-only MOVQ source");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF700081A44ULL});
    rosa::x86::X86State state;
    state.rax = page.value;
    state.xmm[0] = {.low = UINT64_MAX, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, value, "MOVQ loaded the wrong low XMM lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0}, "MOVQ did not zero the high XMM lane");
    expectEqual(state.rax, page.value, "MOVQ changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVQ load changed flags");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{page.value + 0x38}), value,
                "MOVQ load changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = page.value;
    faultState.xmm[0] = {.low = 0x8877665544332211ULL, .high = 0x1020304050607080ULL};
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "MOVQ load accepted unmapped guest memory");
    expectEqual(faultState.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "faulted MOVQ load changed its low lane");
    expectEqual(faultState.xmm[0].high, std::uint64_t{0x1020304050607080ULL},
                "faulted MOVQ load changed its high lane");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7}, "faulted MOVQ load changed flags");

    constexpr std::array<std::uint8_t, 7> indexedCode{0xF3, 0x0F, 0x7E, 0x44, 0x3A, 0x28, 0xC3};
    constexpr rosa::guest::GuestAddress indexedRip{0x7FF802C6AC09ULL};
    const auto indexedDecoded = decoder.decodeBlock(indexedCode, indexedRip);
    expect(indexedDecoded[0].opcode == rosa::x86::Opcode::MovqXmmMem,
           "indexed MOVQ xmm, [mem] opcode differs");
    expectEqual(indexedDecoded[0].length, std::uint8_t{6},
                "indexed MOVQ xmm, [mem] length differs");
    const auto indexedMemory = std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[1]);
    expect(indexedMemory.base == rosa::x86::Register::Rdx &&
               indexedMemory.index == rosa::x86::Register::Rdi && indexedMemory.scale == 1 &&
               indexedMemory.displacement == 0x28 && indexedMemory.width == 64,
           "MOVQ xmm0, [rdx+rdi+0x28] operands differ");
    expect(rosa::debug::dumpX86(indexedDecoded).find("movq xmm0, qword [rdx+rdi+0x28]") !=
               std::string::npos,
           "MOVQ xmm0, [rdx+rdi+0x28] dump differs");

    constexpr auto indexedValue = std::uint64_t{0xD0C0B0A090807060ULL};
    std::array<std::uint8_t, rosa::guest::guestPageSize> indexedBytes{};
    std::memcpy(indexedBytes.data() + 0x48, &indexedValue, sizeof(indexedValue));
    rosa::guest::AddressSpace indexedAddressSpace;
    indexedAddressSpace.mapSegment(page, indexedBytes.size(), rosa::guest::Permission::Read,
                                   indexedBytes, "read-only indexed MOVQ source");
    const auto indexedBlock = translator.translate(indexedCode, indexedRip);
    rosa::x86::X86State indexedState;
    indexedState.rdx = page.value;
    indexedState.rdi = 0x20;
    indexedState.xmm[0] = {.low = 0x1122334455667788ULL, .high = 0x8877665544332211ULL};
    indexedState.rflags = 0x8D7;
    static_cast<void>(indexedBlock.execute(indexedState, &indexedAddressSpace));
    expectEqual(indexedState.xmm[0].low, indexedValue, "indexed MOVQ loaded the wrong low lane");
    expectEqual(indexedState.xmm[0].high, std::uint64_t{0},
                "indexed MOVQ did not zero the high lane");
    expectEqual(indexedState.rdx, page.value, "indexed MOVQ changed its base register");
    expectEqual(indexedState.rdi, std::uint64_t{0x20}, "indexed MOVQ changed its index register");
    expectEqual(indexedState.rflags, std::uint64_t{0x8D7}, "indexed MOVQ changed flags");

    rosa::x86::X86State indexedFaultState;
    indexedFaultState.rdx = page.value;
    indexedFaultState.rdi = 0x20;
    indexedFaultState.xmm[0] = {.low = 0x1122334455667788ULL, .high = 0x8877665544332211ULL};
    indexedFaultState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(indexedBlock.execute(indexedFaultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indexed MOVQ load accepted unmapped guest memory");
    expectEqual(indexedFaultState.xmm[0].low, std::uint64_t{0x1122334455667788ULL},
                "faulted indexed MOVQ changed its low lane");
    expectEqual(indexedFaultState.xmm[0].high, std::uint64_t{0x8877665544332211ULL},
                "faulted indexed MOVQ changed its high lane");
    expectEqual(indexedFaultState.rflags, std::uint64_t{0xAD7},
                "faulted indexed MOVQ changed flags");

    constexpr std::array<std::uint8_t, 8> extendedIndexedCode{0xF3, 0x42, 0x0F, 0x7E,
                                                              0x44, 0x92, 0x2C, 0xC3};
    constexpr rosa::guest::GuestAddress extendedIndexedRip{0x7FF802C6ACCCULL};
    const auto extendedIndexedDecoded =
        decoder.decodeBlock(extendedIndexedCode, extendedIndexedRip);
    expect(extendedIndexedDecoded[0].opcode == rosa::x86::Opcode::MovqXmmMem,
           "extended-index MOVQ xmm, [mem] opcode differs");
    expectEqual(extendedIndexedDecoded[0].length, std::uint8_t{7},
                "extended-index MOVQ xmm, [mem] length differs");
    const auto extendedIndexedMemory =
        std::get<rosa::x86::MemoryOperand>(extendedIndexedDecoded[0].operands[1]);
    expect(extendedIndexedMemory.base == rosa::x86::Register::Rdx &&
               extendedIndexedMemory.index == rosa::x86::Register::R10 &&
               extendedIndexedMemory.scale == 4 && extendedIndexedMemory.displacement == 0x2C,
           "MOVQ xmm0, [rdx+r10*4+0x2c] operands differ");
    expect(rosa::debug::dumpX86(extendedIndexedDecoded).find("movq xmm0, qword [rdx+r10*4+0x2c]") !=
               std::string::npos,
           "MOVQ xmm0, [rdx+r10*4+0x2c] dump differs");

    const auto extendedIndexedBlock = translator.translate(extendedIndexedCode, extendedIndexedRip);
    rosa::x86::X86State extendedIndexedState;
    extendedIndexedState.rdx = page.value;
    extendedIndexedState.r10 = 7;
    extendedIndexedState.xmm[0] = {.low = 0x1122334455667788ULL, .high = 0x8877665544332211ULL};
    extendedIndexedState.rflags = 0x8D7;
    static_cast<void>(extendedIndexedBlock.execute(extendedIndexedState, &indexedAddressSpace));
    expectEqual(extendedIndexedState.xmm[0].low, indexedValue,
                "extended-index MOVQ loaded the wrong low lane");
    expectEqual(extendedIndexedState.xmm[0].high, std::uint64_t{0},
                "extended-index MOVQ did not zero the high lane");
    expectEqual(extendedIndexedState.rdx, page.value,
                "extended-index MOVQ changed its base register");
    expectEqual(extendedIndexedState.r10, std::uint64_t{7},
                "extended-index MOVQ changed its index register");
    expectEqual(extendedIndexedState.rflags, std::uint64_t{0x8D7},
                "extended-index MOVQ changed flags");

    rosa::x86::X86State extendedIndexedFaultState = extendedIndexedState;
    extendedIndexedFaultState.xmm[0] = {.low = 0x1122334455667788ULL,
                                        .high = 0x8877665544332211ULL};
    extendedIndexedFaultState.rflags = 0xAD7;
    rejected = false;
    try {
        static_cast<void>(
            extendedIndexedBlock.execute(extendedIndexedFaultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "extended-index MOVQ load accepted unmapped guest memory");
    expectEqual(extendedIndexedFaultState.xmm[0].low, std::uint64_t{0x1122334455667788ULL},
                "faulted extended-index MOVQ changed its low lane");
    expectEqual(extendedIndexedFaultState.xmm[0].high, std::uint64_t{0x8877665544332211ULL},
                "faulted extended-index MOVQ changed its high lane");
    expectEqual(extendedIndexedFaultState.rflags, std::uint64_t{0xAD7},
                "faulted extended-index MOVQ changed flags");
}

void testMovlhpsRipMemory() {
    // Observed in CoreGraphics under an Objective-C fixture: MOVLHPS xmm1, [RIP+disp32].
    constexpr std::array<std::uint8_t, 8> code{0x0F, 0x16, 0x0D, 0x71, 0x08,
                                               0x8B, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF80968D1E8ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovlhpsRegMem,
           "MOVLHPS xmm, m64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "MOVLHPS xmm, m64 length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1,
           "MOVLHPS xmm1, m64 destination differs");
    expect(memory.ripRelative && !memory.hasBase && !memory.index &&
               memory.displacement == 0x8B0871 && memory.width == 64,
           "MOVLHPS xmm, m64 memory operand differs");
    expectEqual(observedRip.value + decoded[0].length + memory.displacement,
                std::uint64_t{0x7FF809F3DA60ULL}, "MOVLHPS xmm, m64 target differs");
    expect(rosa::debug::dumpX86(decoded).find("movlhps xmm1, qword [rip+0x8b0871]") !=
               std::string::npos,
           "MOVLHPS xmm, m64 dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x0123456789ABCDEFULL);
    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 8> executeCode{0x0F, 0x16, 0x0D, 0xF9, 0x70,
                                                      0x00, 0x00, 0xC3};
    const auto block = translator.translate(executeCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.xmm[1] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[1].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVLHPS m64 did not replace the low lane");
    expectEqual(state.xmm[1].high, std::uint64_t{0xBBBBBBBBBBBBBBBBULL},
                "MOVLHPS m64 did not preserve the high lane");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVLHPS m64 changed flags");
}

void testBlendvpdRegisters() {
    // Observed in CoreGraphics under an Objective-C fixture: BLENDVPD xmm1, xmm3.
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x38, 0x15, 0xCB, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF80968A84DULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::BlendvpdRegReg,
           "BLENDVPD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "BLENDVPD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               source.reg == rosa::x86::XmmRegister::Xmm3,
           "BLENDVPD xmm1, xmm3 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("blendvpd xmm1, xmm3") != std::string::npos,
           "BLENDVPD dump differs");

    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 6> executeCode{0x66, 0x0F, 0x38, 0x15, 0xCB, 0xC3};
    const auto block = translator.translate(executeCode, observedRip);
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x8000000000000000ULL, .high = 0x0000000000000000ULL};
    state.xmm[1] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.xmm[3] = {.low = 0xCCCCCCCCCCCCCCCCULL, .high = 0xDDDDDDDDDDDDDDDDULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // Mask MSB set low (take source), clear high (keep destination).
    expectEqual(state.xmm[1].low, std::uint64_t{0xCCCCCCCCCCCCCCCCULL},
                "BLENDVPD low lane differs");
    expectEqual(state.xmm[1].high, std::uint64_t{0xBBBBBBBBBBBBBBBBULL},
                "BLENDVPD high lane differs");
    expectEqual(state.xmm[0].low, std::uint64_t{0x8000000000000000ULL},
                "BLENDVPD changed its mask");
    expectEqual(state.xmm[3].low, std::uint64_t{0xCCCCCCCCCCCCCCCCULL},
                "BLENDVPD changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "BLENDVPD changed flags");
}






void testMinsdRegisters() {
    // Observed in CoreFoundation under an AppKit fixture: MINSD xmm1, xmm0.
    constexpr std::array<std::uint8_t, 5> code{0xF2, 0x0F, 0x5D, 0xC8, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802ED113FULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MinsdXmmReg,
           "MINSD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "MINSD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               source.reg == rosa::x86::XmmRegister::Xmm0,
           "MINSD xmm1, xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("minsd xmm1, xmm0") != std::string::npos,
           "MINSD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("scalar_minimum_double_xmm") != std::string::npos,
           "MINSD did not lower through scalar-double IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x4008000000000000ULL, .high = 0xAAAAAAAAAAAAAAAAULL}; // 3.0.
    state.xmm[1] = {.low = 0x4014000000000000ULL, .high = 0xBBBBBBBBBBBBBBBBULL}; // 5.0.
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // min(5.0, 3.0) == 3.0; the high lane is preserved, unlike CVTSI2SD.
    expectEqual(state.xmm[1].low, std::uint64_t{0x4008000000000000ULL},
                "MINSD produced the wrong minimum");
    expectEqual(state.xmm[1].high, std::uint64_t{0xBBBBBBBBBBBBBBBBULL},
                "MINSD did not preserve the high lane");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MINSD changed flags");

    // NaN inputs select the source lane.
    rosa::x86::X86State nanState;
    nanState.xmm[0] = {.low = 0x4008000000000000ULL, .high = 0};
    nanState.xmm[1] = {.low = 0x7FF8000000000000ULL, .high = 0};
    static_cast<void>(block.execute(nanState));
    expectEqual(nanState.xmm[1].low, std::uint64_t{0x4008000000000000ULL},
                "MINSD NaN destination missed the source");
}

void testMaxsdRegisters() {
    constexpr std::array<std::uint8_t, 5> code{0xF2, 0x0F, 0x5F, 0xC8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MaxsdXmmReg,
           "MAXSD opcode differs");
    expect(rosa::debug::dumpX86(decoded).find("maxsd xmm1, xmm0") != std::string::npos,
           "MAXSD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("scalar_maximum_double_xmm") != std::string::npos,
           "MAXSD did not lower through scalar-double IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x4008000000000000ULL, .high = 0};
    state.xmm[1] = {.low = 0x4014000000000000ULL, .high = 0};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[1].low, std::uint64_t{0x4014000000000000ULL},
                "MAXSD produced the wrong maximum");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MAXSD changed flags");
}

void testCvttsd2siRegisters() {
    // Observed in CoreFoundation under an AppKit fixture: CVTTSD2SI r12, xmm0.
    constexpr std::array<std::uint8_t, 6> code{0xF2, 0x4C, 0x0F, 0x2C, 0xE0, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802EBB41BULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::Cvttsd2siRegXmm,
           "CVTTSD2SI opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "CVTTSD2SI length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R12 && destination.width == 64,
           "CVTTSD2SI r12 operand differs");
    expect(source.reg == rosa::x86::XmmRegister::Xmm0, "CVTTSD2SI xmm0 operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cvttsd2si r12, xmm0") != std::string::npos,
           "CVTTSD2SI dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("convert_double_to_int.i64") != std::string::npos,
           "CVTTSD2SI did not lower through conversion IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x402B59B3C0FE98E0ULL, .high = 0}; // ~13.726.
    state.r12 = UINT64_MAX;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r12, std::uint64_t{13}, "CVTTSD2SI truncation differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "CVTTSD2SI changed flags");

    // Negative truncation and 32-bit indefinite saturation.
    constexpr std::array<std::uint8_t, 5> code32{0xF2, 0x0F, 0x2C, 0xC1, 0xC3};
    const auto block32 = translator.translate(code32, observedRip);
    rosa::x86::X86State state32;
    state32.xmm[1] = {.low = 0xC0253CA3C8B43958ULL, .high = 0}; // ~-10.9.
    state32.rflags = 0xAD7;
    static_cast<void>(block32.execute(state32));
    expectEqual(state32.rax, std::uint64_t{0xFFFFFFF6ULL},
                "CVTTSD2SI negative truncation differs");
    rosa::x86::X86State nanState;
    nanState.xmm[1] = {.low = 0x7FF8000000000000ULL, .high = 0};
    const auto nanBlock = translator.translate(
        std::array<std::uint8_t, 5>{0xF2, 0x0F, 0x2C, 0xC9, 0xC3}, observedRip);
    static_cast<void>(nanBlock.execute(nanState));
    expectEqual(nanState.rcx, std::uint64_t{0x80000000ULL},
                "CVTTSD2SI NaN did not saturate");
}






void testSubScaledIndexMemory() {
    // Observed in CoreFoundation under an AppKit fixture: SUB EBX, [RDX+RCX*4].
    constexpr std::array<std::uint8_t, 4> code{0x2B, 0x1C, 0x8A, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802ED7E70ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegMem,
           "scaled SUB opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "scaled SUB length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rbx && destination.width == 32,
           "scaled SUB destination differs");
    expect(memory.base == rosa::x86::Register::Rdx && memory.index &&
               *memory.index == rosa::x86::Register::Rcx && memory.scale == 4 &&
               memory.width == 32 && memory.displacement == 0,
           "scaled SUB memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("sub rbx, [rdx+rcx*4]") != std::string::npos,
           "scaled SUB dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(rosa::guest::GuestAddress{0x8100}, 0x2F);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rdx = 0x80F0;
    state.rcx = 0x4;
    state.rbx = 0x100;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    // 0x100 - 0x2F == 0xD1.
    expectEqual(state.rbx, std::uint64_t{0xD1}, "scaled SUB result differs");
}



void testMovmskpdRegisters() {
    // Observed in libsystem_kernel under an AppKit fixture: MOVMSKPD eax, xmm1.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x50, 0xC1, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802E2FE7AULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovmskpdRegXmm,
           "MOVMSKPD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "MOVMSKPD length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "MOVMSKPD eax, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movmskpd eax, xmm1") != std::string::npos,
           "MOVMSKPD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.xmm[1] = {.low = 0xBFF0000000000000ULL, .high = 0x3FF0000000000000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // Low double negative, high double positive: mask 0b01.
    expectEqual(state.rax, std::uint64_t{1}, "MOVMSKPD mask differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVMSKPD changed flags");
}

void testPmovsxdqRegisters() {
    // Observed in libsystem_kernel under an AppKit fixture: PMOVSXDQ xmm1, xmm1.
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x38, 0x25, 0xC9, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802E2FE75ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PmovsxdqRegReg,
           "PMOVSXDQ opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "PMOVSXDQ length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "PMOVSXDQ xmm1, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pmovsxdq xmm1, xmm1") != std::string::npos,
           "PMOVSXDQ dump differs");

    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 6> executeCode{0x66, 0x0F, 0x38, 0x25, 0xC9, 0xC3};
    const auto block = translator.translate(executeCode, observedRip);
    rosa::x86::X86State state;
    state.xmm[1] = {.low = 0x80000001FFFFFFFFULL, .high = 0xAAAAAAAAAAAAAAAAULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // d0 -1 sign-extends to all-ones; d1 0x80000001 sign-extends to 0xFFFFFFFF80000001.
    expectEqual(state.xmm[1].low, UINT64_MAX, "PMOVSXDQ low lane differs");
    expectEqual(state.xmm[1].high, std::uint64_t{0xFFFFFFFF80000001ULL},
                "PMOVSXDQ high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "PMOVSXDQ changed flags");
}


void testAdcRegMem() {
    // Observed in CoreFoundation under an Objective-C fixture: ADC RDI, [RBP-0x460].
    constexpr std::array<std::uint8_t, 8> code{0x48, 0x13, 0xBD, 0xA0,
                                               0xFB, 0xFF, 0xFF, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802EE1F04ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::AdcRegMem,
           "ADC r64, m64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7}, "ADC r64, m64 length differs");
    const auto destination = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdi && destination.width == 64,
           "ADC RDI destination differs");
    expect(!memory.ripRelative && memory.base == rosa::x86::Register::Rbp &&
               memory.width == 64 && memory.displacement == -0x460,
           "ADC [RBP-0x460] memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("adc rdi, qword [rbp-0x460]") !=
               std::string::npos,
           "ADC r64, m64 dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8100}, 5);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rbp = 0x8560;
    state.rdi = 10;
    state.rflags = 0xAD7;  // CF set.
    static_cast<void>(block.execute(state, &addressSpace));
    // 10 + 5 + CF(1) == 16.
    expectEqual(state.rdi, std::uint64_t{16}, "ADC r64, m64 result differs");
    expect((state.rflags & 0x1U) == 0, "ADC r64, m64 left CF set");
}

void testCmpHighByteRegisterImmediate() {
    // Observed in libcrypto under an Objective-C fixture: CMP AH, 0x0F.
    constexpr std::array<std::uint8_t, 4> code{0x80, 0xFC, 0x0F, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FFE06E5ED69ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegImm,
           "CMP AH opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "CMP AH length differs");
    const auto reg = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(reg.reg == rosa::x86::Register::Rax && reg.width == 8 && reg.byteOffset == 1,
           "CMP AH operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp ah, 0xf") != std::string::npos,
           "CMP AH dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rax = 0x106A5;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // AH == 0x06: 0x06 - 0x0F borrows and goes negative.
    expectEqual(state.rax, std::uint64_t{0x106A5}, "CMP AH changed its operand");
    expect((state.rflags & 0x1U) != 0, "CMP AH missed the borrow");
    expect((state.rflags & 0x40U) == 0, "CMP AH set ZF for a nonzero difference");
    expect((state.rflags & 0x80U) != 0, "CMP AH missed the negative difference");
}

void testAndHighByteRegisterImmediate() {
    // Observed in libcrypto under an Objective-C fixture: AND AH, 0x0F.
    constexpr std::array<std::uint8_t, 4> code{0x80, 0xE4, 0x0F, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FFE06E5ED66ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegImm,
           "AND AH opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "AND AH length differs");
    const auto reg = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(reg.reg == rosa::x86::Register::Rax && reg.width == 8 && reg.byteOffset == 1,
           "AND AH operand differs");
    expect(rosa::debug::dumpX86(decoded).find("and ah, 0xf") != std::string::npos,
           "AND AH dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.rax = 0x123456789ABCDEF0ULL;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // Only bits[15:8] combine: 0xDE & 0x0F == 0x0E.
    expectEqual(state.rax, std::uint64_t{0x123456789ABC0EF0ULL},
                "AND AH merged the wrong lane");
    expect((state.rflags & 0x40U) == 0, "AND AH set ZF for a nonzero result");
    expect((state.rflags & 0x80U) == 0, "AND AH set SF for a positive result");
}

void testCpuidLeaves() {
    // Observed in libcrypto under an Objective-C fixture: CPUID vendor/feature dispatch.
    constexpr std::array<std::uint8_t, 3> code{0x0F, 0xA2, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FFE06E5EC75ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::Cpuid, "CPUID opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "CPUID length differs");
    expect(rosa::debug::dumpX86(decoded).find("cpuid") != std::string::npos,
           "CPUID dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation()).find("cpuid") !=
               std::string::npos,
           "CPUID did not lower through cpuid IR");

    // Leaf 0 reports the vendor string and maximum basic leaf.
    rosa::x86::X86State vendorState;
    vendorState.rax = 0;
    vendorState.rcx = 0;
    vendorState.rflags = 0xAD7;
    static_cast<void>(block.execute(vendorState));
    expectEqual(vendorState.rax, std::uint64_t{7}, "CPUID leaf 0 max leaf differs");
    expectEqual(vendorState.rbx, std::uint64_t{0x756E6547ULL}, "CPUID vendor EBX differs");
    expectEqual(vendorState.rdx, std::uint64_t{0x49656E69ULL}, "CPUID vendor EDX differs");
    expectEqual(vendorState.rcx, std::uint64_t{0x6C65746EULL}, "CPUID vendor ECX differs");
    expectEqual(vendorState.rflags, std::uint64_t{0xAD7}, "CPUID changed flags");

    // Leaf 1 reports version info and the SSE-through-SSE4.2 feature set.
    rosa::x86::X86State featureState;
    featureState.rax = 1;
    featureState.rcx = 0;
    static_cast<void>(block.execute(featureState));
    expectEqual(featureState.rax, std::uint64_t{0x106A5ULL}, "CPUID leaf 1 version differs");
    expect((featureState.rcx & ((1ULL << 0U) | (1ULL << 9U) | (1ULL << 19U) | (1ULL << 20U))) ==
               ((1ULL << 0U) | (1ULL << 9U) | (1ULL << 19U) | (1ULL << 20U)),
           "CPUID leaf 1 misses SSE4-era features");
    expect((featureState.rcx & (1ULL << 28U)) == 0, "CPUID advertises unimplemented AVX");
    expect((featureState.rdx & ((1ULL << 25U) | (1ULL << 26U))) ==
               ((1ULL << 25U) | (1ULL << 26U)),
           "CPUID leaf 1 misses SSE/SSE2");
}

void testMovapsRegisters() {
    // Observed in SkyLight under an Objective-C fixture: MOVAPS xmm1, xmm0.
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x28, 0xC8, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8095B0C0AULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovapsRegReg,
           "MOVAPS opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "MOVAPS length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               source.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVAPS xmm1, xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movaps xmm1, xmm0") != std::string::npos,
           "MOVAPS dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.xmm[1] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[1].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVAPS did not copy the low lane");
    expectEqual(state.xmm[1].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVAPS did not copy the high lane");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVAPS changed flags");
}

void testSqrtpdRegisters() {
    // Observed in ColorSync under an Objective-C fixture: SQRTPD xmm0, xmm1.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x51, 0xC1, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4F2BULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::SqrtpdRegReg,
           "SQRTPD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "SQRTPD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "SQRTPD xmm0, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("sqrtpd xmm0, xmm1") != std::string::npos,
           "SQRTPD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("packed_sqrt_double_xmm") != std::string::npos,
           "SQRTPD did not lower through packed-arithmetic IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0xAAAAAAAAAAAAAAAAULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.xmm[1] = {.low = 0x4019000000000000ULL, .high = 0x4030000000000000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // sqrt(6.25) == 2.5, sqrt(16.0) == 4.0.
    expectEqual(state.xmm[0].low, std::uint64_t{0x4004000000000000ULL},
                "SQRTPD low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x4010000000000000ULL},
                "SQRTPD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "SQRTPD changed flags");
}

void testUnpcklpsRegisters() {
    // Observed in ColorSync under an Objective-C fixture: UNPCKLPS xmm5, xmm0.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x14, 0xE8, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4F0BULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::UnpcklpsRegReg,
           "UNPCKLPS opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "UNPCKLPS length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm5 &&
               source.reg == rosa::x86::XmmRegister::Xmm0,
           "UNPCKLPS xmm5, xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("unpcklps xmm5, xmm0") != std::string::npos,
           "UNPCKLPS dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("unpack_low_packed_single_xmm.i64") != std::string::npos,
           "UNPCKLPS did not lower through unpack IR");
    rosa::x86::X86State state;
    state.xmm[5] = {.low = 0x2222222211111111ULL, .high = 0xAAAAAAAAAAAAAAAAULL};
    state.xmm[0] = {.low = 0x6666666655555555ULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // Low dwords interleave: {d0, e0, d1, e1}.
    expectEqual(state.xmm[5].low, std::uint64_t{0x5555555511111111ULL},
                "UNPCKLPS low lane differs");
    expectEqual(state.xmm[5].high, std::uint64_t{0x6666666622222222ULL},
                "UNPCKLPS high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "UNPCKLPS changed flags");
}

void testUnpcklpsGuestMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x14, 0x07, 0xC3, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::UnpcklpsRegMem,
           "UNPCKLPS xmm, [memory] opcode differs");
    expect(rosa::debug::dumpX86(decoded).find("unpcklps xmm0, xmmword [rdi]") !=
               std::string::npos,
           "UNPCKLPS xmm, [memory] dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 16> bytes{0x55, 0x55, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66,
                                                 0x77, 0x77, 0x77, 0x77, 0x88, 0x88, 0x88, 0x88};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8000}, bytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0x8000;
    state.xmm[0] = {.low = 0x2222222211111111ULL, .high = 0xAAAAAAAAAAAAAAAAULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x5555555511111111ULL},
                "UNPCKLPS memory low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x6666666622222222ULL},
                "UNPCKLPS memory high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "UNPCKLPS changed flags");

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
    expect(rejected, "UNPCKLPS from unmapped guest memory did not fail");
}

void testSqrtsdRegisters() {
    // Observed in ColorSync under an Objective-C fixture: SQRTSD xmm4, xmm4.
    constexpr std::array<std::uint8_t, 5> code{0xF2, 0x0F, 0x51, 0xE4, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4F03ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::SqrtsdXmmReg,
           "SQRTSD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "SQRTSD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm4 &&
               source.reg == rosa::x86::XmmRegister::Xmm4,
           "SQRTSD xmm4, xmm4 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("sqrtsd xmm4, xmm4") != std::string::npos,
           "SQRTSD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("scalar_sqrt_double_xmm") != std::string::npos,
           "SQRTSD did not lower through scalar-double IR");
    rosa::x86::X86State state;
    state.xmm[4] = {.low = 0x4019000000000000ULL, .high = 0xAAAAAAAAAAAAAAAAULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // sqrt(6.25) == 2.5; the high lane is preserved.
    expectEqual(state.xmm[4].low, std::uint64_t{0x4004000000000000ULL},
                "SQRTSD produced the wrong root");
    expectEqual(state.xmm[4].high, std::uint64_t{0xAAAAAAAAAAAAAAAAULL},
                "SQRTSD did not preserve the high lane");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "SQRTSD changed flags");
}

void testHaddpdRegisters() {
    // Observed in ColorSync under an Objective-C fixture: HADDPD xmm4, xmm4.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x7C, 0xE4, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4EFFULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::HaddpdRegReg,
           "HADDPD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "HADDPD length differs");
    expect(rosa::debug::dumpX86(decoded).find("haddpd xmm4, xmm4") != std::string::npos,
           "HADDPD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("horizontal_add_packed_double_xmm.i64") != std::string::npos,
           "HADDPD did not lower through horizontal-add IR");
    rosa::x86::X86State state;
    state.xmm[4] = {.low = 0x3FF8000000000000ULL, .high = 0x4002000000000000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // 1.5 + 2.25 = 3.75 in both lanes.
    expectEqual(state.xmm[4].low, std::uint64_t{0x400E000000000000ULL},
                "HADDPD low lane differs");
    expectEqual(state.xmm[4].high, std::uint64_t{0x400E000000000000ULL},
                "HADDPD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "HADDPD changed flags");
}

void testHaddpdGuestMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x7C, 0x07, 0xC3, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::HaddpdRegMem,
           "HADDPD xmm, [memory] opcode differs");
    expect(rosa::debug::dumpX86(decoded).find("haddpd xmm0, xmmword [rdi]") !=
               std::string::npos,
           "HADDPD xmm, [memory] dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 16> bytes{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8000}, bytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0x8000;
    state.xmm[0] = {.low = 0x3FF8000000000000ULL, .high = 0x4002000000000000ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    // Dest: 1.5 + 2.25 = 3.75; source mem: 1.0 + 2.0 = 3.0.
    expectEqual(state.xmm[0].low, std::uint64_t{0x400E000000000000ULL},
                "HADDPD memory low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x4008000000000000ULL},
                "HADDPD memory high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "HADDPD changed flags");

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
    expect(rejected, "HADDPD from unmapped guest memory did not fail");
}

void testUnpckhpsRegisters() {
    // Observed in ColorSync under an Objective-C fixture: UNPCKHPS xmm2, xmm3.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x15, 0xD3, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4EDFULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::UnpckhpsRegReg,
           "UNPCKHPS opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "UNPCKHPS length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm2 &&
               source.reg == rosa::x86::XmmRegister::Xmm3,
           "UNPCKHPS xmm2, xmm3 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("unpckhps xmm2, xmm3") != std::string::npos,
           "UNPCKHPS dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("unpack_high_packed_single_xmm.i64") != std::string::npos,
           "UNPCKHPS did not lower through unpack IR");
    rosa::x86::X86State state;
    state.xmm[2] = {.low = 0x2222222211111111ULL, .high = 0x4444444433333333ULL};
    state.xmm[3] = {.low = 0x6666666655555555ULL, .high = 0x8888888877777777ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // High dwords interleave: {d2, e2, d3, e3}.
    expectEqual(state.xmm[2].low, std::uint64_t{0x7777777733333333ULL},
                "UNPCKHPS low lane differs");
    expectEqual(state.xmm[2].high, std::uint64_t{0x8888888844444444ULL},
                "UNPCKHPS high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "UNPCKHPS changed flags");
}

void testUnpckhpsGuestMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x15, 0x07, 0xC3, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::UnpckhpsRegMem,
           "UNPCKHPS xmm, [memory] opcode differs");
    expect(rosa::debug::dumpX86(decoded).find("unpckhps xmm0, xmmword [rdi]") !=
               std::string::npos,
           "UNPCKHPS xmm, [memory] dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 16> bytes{0x55, 0x55, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66,
                                                 0x77, 0x77, 0x77, 0x77, 0x88, 0x88, 0x88, 0x88};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8000}, bytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0x8000;
    state.xmm[0] = {.low = 0x2222222211111111ULL, .high = 0x4444444433333333ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x7777777733333333ULL},
                "UNPCKHPS memory low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x8888888844444444ULL},
                "UNPCKHPS memory high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "UNPCKHPS changed flags");

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
    expect(rejected, "UNPCKHPS from unmapped guest memory did not fail");
}

void testSubpdRegisters() {
    // Observed in ColorSync under an Objective-C fixture: SUBPD xmm4, xmm1.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x5C, 0xE1, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4EF7ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::SubpdRegReg,
           "SUBPD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "SUBPD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm4 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "SUBPD xmm4, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("subpd xmm4, xmm1") != std::string::npos,
           "SUBPD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("packed_subtract_double_xmm") != std::string::npos,
           "SUBPD did not lower through packed-arithmetic IR");
    rosa::x86::X86State state;
    state.xmm[4] = {.low = 0x4014000000000000ULL, .high = 0x4008000000000000ULL};
    state.xmm[1] = {.low = 0x4020000000000000ULL, .high = 0x3FF0000000000000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // 5.0 - 8.0 = -3.0, 3.0 - 1.0 = 2.0.
    expectEqual(state.xmm[4].low, std::uint64_t{0xC008000000000000ULL},
                "SUBPD low lane differs");
    expectEqual(state.xmm[4].high, std::uint64_t{0x4000000000000000ULL},
                "SUBPD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "SUBPD changed flags");
}

void testMulpdRegisters() {
    // Observed in ColorSync under an Objective-C fixture: MULPD xmm4, xmm4.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x59, 0xE4, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4EFBULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MulpdRegReg,
           "MULPD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "MULPD length differs");
    expect(rosa::debug::dumpX86(decoded).find("mulpd xmm4, xmm4") != std::string::npos,
           "MULPD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("packed_multiply_double_xmm") != std::string::npos,
           "MULPD did not lower through packed-arithmetic IR");
    rosa::x86::X86State state;
    state.xmm[4] = {.low = 0x4004000000000000ULL, .high = 0x4010000000000000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // 2.5 * 2.5 = 6.25, 4.0 * 4.0 = 16.0.
    expectEqual(state.xmm[4].low, std::uint64_t{0x4019000000000000ULL},
                "MULPD low lane differs");
    expectEqual(state.xmm[4].high, std::uint64_t{0x4030000000000000ULL},
                "MULPD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MULPD changed flags");
}

void testAddpdRegisters() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x58, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddpdRegReg,
           "ADDPD opcode differs");
    expect(rosa::debug::dumpX86(decoded).find("addpd xmm0, xmm1") != std::string::npos,
           "ADDPD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("packed_add_double_xmm") != std::string::npos,
           "ADDPD did not lower through packed-arithmetic IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x3FF8000000000000ULL, .high = 0x4008000000000000ULL};
    state.xmm[1] = {.low = 0x4002000000000000ULL, .high = 0x4010000000000000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // 1.5 + 2.25 = 3.75, 3.0 + 4.0 = 7.0.
    expectEqual(state.xmm[0].low, std::uint64_t{0x400E000000000000ULL},
                "ADDPD low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x401C000000000000ULL},
                "ADDPD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "ADDPD changed flags");
}


void testDivpdRegisters() {
    // Observed in ColorSync under an Objective-C fixture: DIVPD xmm0, xmm1.
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x5E, 0xC1, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4E30ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::DivpdRegReg,
           "DIVPD opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "DIVPD length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "DIVPD xmm0, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("divpd xmm0, xmm1") != std::string::npos,
           "DIVPD dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("packed_divide_double_xmm") != std::string::npos,
           "DIVPD did not lower through packed-divide IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x3FF0000000000000ULL, .high = 0x401C000000000000ULL};
    state.xmm[1] = {.low = 0x4000000000000000ULL, .high = 0x4000000000000000ULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    // 1.0 / 2.0 = 0.5, 7.0 / 2.0 = 3.5.
    expectEqual(state.xmm[0].low, std::uint64_t{0x3FE0000000000000ULL},
                "DIVPD low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x400C000000000000ULL},
                "DIVPD high lane differs");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "DIVPD changed flags");
}

void testDivpdGuestMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x5E, 0x07, 0xC3, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::DivpdRegMem,
           "DIVPD xmm, [memory] opcode differs");
    expect(rosa::debug::dumpX86(decoded).find("divpd xmm0, xmmword [rdi]") !=
               std::string::npos,
           "DIVPD xmm, [memory] dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 16> bytes{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8000}, bytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0x8000;
    state.xmm[0] = {.low = 0x3FF0000000000000ULL, .high = 0x4020000000000000ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    // 1.0 / 2.0 = 0.5, 8.0 / 4.0 = 2.0.
    expectEqual(state.xmm[0].low, std::uint64_t{0x3FE0000000000000ULL},
                "DIVPD memory low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0x4000000000000000ULL},
                "DIVPD memory high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "DIVPD changed flags");

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
    expect(rejected, "DIVPD from unmapped guest memory did not fail");
}

void testMovddupRegisters() {
    // Observed in ColorSync under an Objective-C fixture: MOVDDUP xmm1, xmm1 (F2 0F 12 /r).
    constexpr std::array<std::uint8_t, 5> code{0xF2, 0x0F, 0x12, 0xC9, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF809FA4E2CULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovddupRegReg,
           "MOVDDUP opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "MOVDDUP length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm1 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "MOVDDUP xmm1, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movddup xmm1, xmm1") != std::string::npos,
           "MOVDDUP dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.xmm[1] = {.low = 0x0123456789ABCDEFULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[1].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVDDUP changed the low lane");
    expectEqual(state.xmm[1].high, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVDDUP did not duplicate into the high lane");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "MOVDDUP changed flags");
}

void testPcmpeqqRegisterGeneratedExecution() {
    // Observed in CoreGraphics under an Objective-C fixture: PCMPEQQ xmm0, xmm1
    // (66 0F 38 29 /r; previously mislabeled as MOVDDUP).
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x38, 0x29, 0xC1, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF80968A84DULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::PcmpeqqRegReg,
           "PCMPEQQ opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5}, "PCMPEQQ length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               source.reg == rosa::x86::XmmRegister::Xmm1,
           "PCMPEQQ xmm0, xmm1 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("pcmpeqq xmm0, xmm1") != std::string::npos,
           "PCMPEQQ dump differs");

    const rosa::dbt::Translator translator;
    constexpr std::array<std::uint8_t, 6> executeCode{0x66, 0x0F, 0x38, 0x29, 0xC1, 0xC3};
    const auto block = translator.translate(executeCode, observedRip);
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("compare_equal_xmm_qwords.i64") != std::string::npos,
           "PCMPEQQ did not lower through qword-compare IR");
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xAAAAAAAAAAAAAAAAULL};
    state.xmm[1] = {.low = 0x0123456789ABCDEFULL, .high = 0xBBBBBBBBBBBBBBBBULL};
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, UINT64_MAX, "PCMPEQQ equal low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0}, "PCMPEQQ unequal high lane differs");
    expectEqual(state.xmm[1].low, std::uint64_t{0x0123456789ABCDEFULL},
                "PCMPEQQ changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "PCMPEQQ changed flags");
}

void testPcmpeqqGuestMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x66, 0x0F, 0x38, 0x29, 0x07, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PcmpeqqRegMem,
           "PCMPEQQ xmm, [memory] opcode differs");
    expect(rosa::debug::dumpX86(decoded).find("pcmpeqq xmm0, xmmword [rdi]") !=
               std::string::npos,
           "PCMPEQQ xmm, [memory] dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 16> bytes{0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
                                                 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8000}, bytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0x8000;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xAAAAAAAAAAAAAAAAULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, UINT64_MAX, "PCMPEQQ memory low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0}, "PCMPEQQ memory high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PCMPEQQ changed flags");

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
    expect(rejected, "PCMPEQQ from unmapped guest memory did not fail");
    expectEqual(faultState.xmm[0].low, std::uint64_t{1}, "failed PCMPEQQ changed low lane");
    expectEqual(faultState.xmm[0].high, std::uint64_t{2}, "failed PCMPEQQ changed high lane");
}

void testMovlhpsRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x16, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x7FF802A8BE18ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovlhpsRegReg, "MOVLHPS opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "MOVLHPS length differs");
    const auto destination = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[0]);
    const auto source = std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::XmmRegister::Xmm0 &&
               source.reg == rosa::x86::XmmRegister::Xmm0,
           "MOVLHPS xmm0, xmm0 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movlhps xmm0, xmm0") != std::string::npos,
           "MOVLHPS dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x7FF802A8BE18ULL});
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVLHPS changed the destination low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0x0123456789ABCDEFULL},
                "MOVLHPS copied the wrong source low lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVLHPS changed flags");

    constexpr std::array<std::uint8_t, 5> extendedCode{0x45, 0x0F, 0x16, 0xE8, 0xC3};
    const auto extendedBlock =
        translator.translate(extendedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State extendedState;
    extendedState.xmm[13] = {.low = 0x1111222233334444ULL, .high = 0x5555666677778888ULL};
    extendedState.xmm[8] = {.low = 0xAABBCCDDEEFF0011ULL, .high = 0x2233445566778899ULL};
    extendedState.rflags = 0xAD7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.xmm[13].low, std::uint64_t{0x1111222233334444ULL},
                "extended MOVLHPS changed the destination low lane");
    expectEqual(extendedState.xmm[13].high, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "extended MOVLHPS copied the wrong source lane");
    expectEqual(extendedState.rflags, std::uint64_t{0xAD7}, "extended MOVLHPS changed flags");
}

} // namespace

std::span<const TestCase> simdExtendedTests() {
    static const TestCase cases[]{
        {"VEX YMM memory load", testVexYmmMemoryLoad},
        {"MOVDQA register to guest memory", testMovdqaRegisterToGuestMemory},
        {"MOVDQA guest memory to register", testMovdqaGuestMemoryToRegister},
        {"MOVDQU register to guest memory", testMovdquRegisterToGuestMemory},
        {"MOVDQU guest memory to register", testMovdquGuestMemoryToRegister},
        {"MOVQ XMM to guest memory", testMovqXmmToGuestMemory},
        {"MOVQ guest memory to XMM", testMovqGuestMemoryToXmm},
        {"CVTSI2SD int32 to XMM", testConvertInt32ToDoubleXmm},
        {"CVTDQ2PD int32x2 to XMM", testConvertInt32x2ToDoubleXmm},
        {"CVTSS2SD float32 to XMM", testConvertFloat32ToDoubleXmm},
        {"scalar double arithmetic XMM", testScalarDoubleArithmeticXmm},
        {"MOVLHPS register execution", testMovlhpsRegister},
        {"MINSD registers execution", testMinsdRegisters},
        {"MAXSD registers execution", testMaxsdRegisters},
        {"CVTTSD2SI registers execution", testCvttsd2siRegisters},
        {"SUB scaled-index memory", testSubScaledIndexMemory},
        {"MOVMSKPD registers execution", testMovmskpdRegisters},
        {"PMOVSXDQ registers execution", testPmovsxdqRegisters},
        {"ADC r64 m64", testAdcRegMem},
        {"CMP AH register immediate", testCmpHighByteRegisterImmediate},
        {"AND AH register immediate", testAndHighByteRegisterImmediate},
        {"CPUID leaves", testCpuidLeaves},
        {"MOVAPS registers execution", testMovapsRegisters},
        {"SQRTPD registers execution", testSqrtpdRegisters},
        {"UNPCKLPS registers execution", testUnpcklpsRegisters},
        {"UNPCKLPS guest memory execution", testUnpcklpsGuestMemoryGeneratedExecution},
        {"SQRTSD registers execution", testSqrtsdRegisters},
        {"HADDPD registers execution", testHaddpdRegisters},
        {"HADDPD guest memory execution", testHaddpdGuestMemoryGeneratedExecution},
        {"UNPCKHPS registers execution", testUnpckhpsRegisters},
        {"UNPCKHPS guest memory execution", testUnpckhpsGuestMemoryGeneratedExecution},
        {"SUBPD registers execution", testSubpdRegisters},
        {"MULPD registers execution", testMulpdRegisters},
        {"ADDPD registers execution", testAddpdRegisters},
        {"DIVPD registers execution", testDivpdRegisters},
        {"DIVPD guest memory execution", testDivpdGuestMemoryGeneratedExecution},
        {"MOVDDUP registers execution", testMovddupRegisters},
        {"PCMPEQQ registers execution", testPcmpeqqRegisterGeneratedExecution},
        {"PCMPEQQ guest memory execution", testPcmpeqqGuestMemoryGeneratedExecution},
        {"BLENDVPD registers execution", testBlendvpdRegisters},
        {"MOVLHPS RIP memory execution", testMovlhpsRipMemory},
    };
    return cases;
}

} // namespace rosa::tests
