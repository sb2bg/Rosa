#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

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

void testIndirectGuestMemoryCall() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress dataBase{0x8000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 32> code{
        0x41, 0xFF, 0x54, 0x24, 0x10, 0xC3, 0, 0, 0, 0, 0,    0, 0, 0, 0, 0,
        0x48, 0xB8, 0x2A, 0,    0,    0,    0, 0, 0, 0, 0xC3, 0, 0, 0, 0, 0,
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(dataBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8010}, 0x1010);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.r12 = dataBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expectEqual(state.rax, std::uint64_t{42}, "indirect guest call result differs");
    expectEqual(state.rsp, stackBase.value + rosa::guest::guestPageSize,
                "indirect guest call did not restore RSP");
    expectEqual(result.executedBlocks, std::size_t{3}, "indirect guest call block count differs");
}

void testIndirectGuestMemoryCallFault() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0xFF, 0x54, 0x24, 0x10};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rip = 0x1000;
    state.r12 = 0x8000;
    state.rsp = 0x9000;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "indirect call through unmapped guest memory did not fail");
    expectEqual(state.rip, std::uint64_t{0x1000}, "failed indirect call changed RIP");
    expectEqual(state.rsp, std::uint64_t{0x9000}, "failed indirect call changed RSP");
}

void testIndexedIndirectGuestMemoryCall() {
    // Observed in libobjc under an Objective-C fixture: CALL qword [rax+rcx].
    constexpr std::array<std::uint8_t, 3> code{0xFF, 0x14, 0x08};
    constexpr rosa::guest::GuestAddress rip{0x7FF802A17E62ULL};
    constexpr rosa::guest::GuestAddress pointerAddress{0x7000000F7680ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF802A17D9AULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expectEqual(decoded.size(), std::size_t{1},
                "indexed indirect CALL did not terminate its block");
    expect(decoded[0].opcode == rosa::x86::Opcode::CallMem,
           "indexed indirect CALL opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(!memory.ripRelative && memory.hasBase &&
               memory.base == rosa::x86::Register::Rax && memory.index &&
               *memory.index == rosa::x86::Register::Rcx && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 64,
           "indexed indirect CALL operand differs");
    expectEqual(decoded[0].fallthrough->value, rip.value + code.size(),
                "indexed indirect CALL fallthrough differs");
    expect(rosa::debug::dumpX86(decoded).find("call qword [rax+rcx]") != std::string::npos,
           "indexed indirect CALL dump differs");

    // REX.X-extended scaled index: CALL qword [r8+r9*8].
    constexpr std::array<std::uint8_t, 4> extendedCode{0x43, 0xFF, 0x14, 0xC8};
    const auto extendedDecoded = decoder.decodeBlock(extendedCode, rip);
    expect(extendedDecoded[0].opcode == rosa::x86::Opcode::CallMem,
           "extended indexed indirect CALL opcode differs");
    const auto extendedMemory =
        std::get<rosa::x86::MemoryOperand>(extendedDecoded[0].operands[0]);
    expect(extendedMemory.base == rosa::x86::Register::R8 && extendedMemory.index &&
               *extendedMemory.index == rosa::x86::Register::R9 &&
               extendedMemory.scale == 8 && extendedMemory.displacement == 0,
           "extended indexed indirect CALL operand differs");
    expect(rosa::debug::dumpX86(extendedDecoded).find("call qword [r8+r9*8]") !=
               std::string::npos,
           "extended indexed indirect CALL dump differs");

    constexpr rosa::guest::GuestAddress pointerPage{pointerAddress.value &
                                                    ~(rosa::guest::guestPageSize - 1)};
    constexpr rosa::guest::GuestAddress stackPage{0x700000000000ULL};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(pointerPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(pointerAddress, target.value);
    addressSpace.mapAnonymous(stackPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State state;
    state.rip = rip.value;
    state.rax = pointerAddress.value - 0x80;
    state.rcx = 0x80;
    state.rsp = stackPage.value + 0x100;
    state.rflags = 0x8D7;
    const auto exit = block.execute(state, &addressSpace);
    expect(exit == rosa::dbt::BlockExit::Call,
           "indexed indirect CALL produced the wrong block exit");
    expectEqual(state.rip, target.value, "indexed indirect CALL selected the wrong target");
    expectEqual(state.rax, pointerAddress.value - 0x80,
                "indexed indirect CALL changed its base register");
    expectEqual(state.rcx, std::uint64_t{0x80},
                "indexed indirect CALL changed its index register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "indexed indirect CALL changed flags");
}

void testRipRelativeIndirectGuestMemoryCall() {
    constexpr std::array<std::uint8_t, 6> code{0xFF, 0x15, 0xA0, 0x23, 0xB1, 0x40};
    constexpr rosa::guest::GuestAddress rip{0x7FF802BA1A6AULL};
    constexpr rosa::guest::GuestAddress pointerAddress{0x7FF8436B3E10ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF802C4FA30ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rip);
    expectEqual(decoded.size(), std::size_t{1},
                "RIP-relative indirect CALL did not terminate its block");
    expect(decoded[0].opcode == rosa::x86::Opcode::CallMem,
           "RIP-relative indirect CALL opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase && !memory.index && memory.width == 64 &&
               memory.displacement == 0x40B123A0,
           "RIP-relative indirect CALL operand differs");
    expectEqual(decoded[0].fallthrough->value, rip.value + code.size(),
                "RIP-relative indirect CALL fallthrough differs");
    expect(rosa::debug::dumpX86(decoded).find("call qword [rip+0x40b123a0] ; 0x7ff8436b3e10") !=
               std::string::npos,
           "RIP-relative indirect CALL dump differs");

    constexpr rosa::guest::GuestAddress pointerPage{pointerAddress.value &
                                                    ~(rosa::guest::guestPageSize - 1)};
    constexpr rosa::guest::GuestAddress stackPage{0x700000000000ULL};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(pointerPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(pointerAddress, target.value);
    addressSpace.mapAnonymous(stackPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rip);
    rosa::x86::X86State state;
    state.rip = rip.value;
    state.rsp = stackPage.value + 0x100;
    state.rflags = 0x8D7;
    const auto exit = block.execute(state, &addressSpace);
    expect(exit == rosa::dbt::BlockExit::Call,
           "RIP-relative indirect CALL produced the wrong block exit");
    expectEqual(state.rip, target.value, "RIP-relative indirect CALL selected the wrong target");
    expectEqual(state.rsp, stackPage.value + 0x100,
                "RIP-relative indirect CALL block changed RSP before dispatch");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative indirect CALL changed flags");

    constexpr rosa::guest::GuestAddress codePage{rip.value & ~(rosa::guest::guestPageSize - 1)};
    constexpr rosa::guest::GuestAddress targetPage{target.value &
                                                   ~(rosa::guest::guestPageSize - 1)};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    std::array<std::uint8_t, rosa::guest::guestPageSize> codeBytes{};
    const auto codeOffset = static_cast<std::size_t>(rip.value - codePage.value);
    std::copy(code.begin(), code.end(), codeBytes.begin() + codeOffset);
    codeBytes[codeOffset + code.size()] = 0xC3;
    std::array<std::uint8_t, rosa::guest::guestPageSize> targetBytes{};
    targetBytes[static_cast<std::size_t>(target.value - targetPage.value)] = 0xC3;
    rosa::guest::AddressSpace dispatchAddressSpace;
    dispatchAddressSpace.mapSegment(
        codePage, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read | rosa::guest::Permission::Execute, codeBytes);
    dispatchAddressSpace.mapSegment(
        targetPage, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read | rosa::guest::Permission::Execute, targetBytes);
    dispatchAddressSpace.mapAnonymous(pointerPage, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    dispatchAddressSpace.writeU64(pointerAddress, target.value);
    dispatchAddressSpace.mapAnonymous(stackPage, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    rosa::x86::X86State dispatchState;
    dispatchState.rip = rip.value;
    dispatchState.rsp = stackPage.value + 0x100;
    dispatchState.rflags = 0x8D7;
    dispatchAddressSpace.writeU64(rosa::guest::GuestAddress{dispatchState.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(dispatchAddressSpace);
    const auto result = dispatcher.run(dispatchState, 8, sentinel);
    expectEqual(result.executedBlocks, std::size_t{3},
                "RIP-relative indirect CALL block count differs");
    expectEqual(dispatchState.rsp, stackPage.value + 0x108,
                "RIP-relative indirect CALL/return did not restore RSP");
    expectEqual(dispatchAddressSpace.readU64(rosa::guest::GuestAddress{stackPage.value + 0xF8}),
                rip.value + code.size(),
                "RIP-relative indirect CALL pushed the wrong return address");
    expectEqual(dispatchState.rflags, std::uint64_t{0x8D7},
                "dispatched RIP-relative indirect CALL changed flags");

    rosa::guest::AddressSpace faultAddressSpace;
    faultAddressSpace.mapAnonymous(stackPage, rosa::guest::guestPageSize,
                                   rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State faultState;
    faultState.rip = rip.value;
    faultState.rsp = stackPage.value + 0x100;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &faultAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(rejected, "RIP-relative indirect CALL accepted an unmapped target pointer");
    expectEqual(faultState.rip, rip.value, "target-faulted indirect CALL changed RIP");
    expectEqual(faultState.rsp, stackPage.value + 0x100,
                "target-faulted indirect CALL changed RSP");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "target-faulted indirect CALL changed flags");
}

void testIndirectGuestRegisterCall() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 9> code{
        0xFF, 0xD0,       // call rax
        0xEB, 0x04,       // skip the target after it returns
        0x83, 0xC3, 0x01, // add ebx, 1
        0xC3,             // return from target
        0xC3,             // return to dispatcher sentinel
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, codeBase);
    expectEqual(decoded.size(), std::size_t{1},
                "register-indirect CALL did not terminate its block");
    expect(decoded[0].opcode == rosa::x86::Opcode::CallReg,
           "register-indirect CALL opcode differs");
    const auto target = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(target.reg == rosa::x86::Register::Rax && target.width == 64,
           "register-indirect CALL target differs");
    expectEqual(decoded[0].fallthrough->value, std::uint64_t{0x1002},
                "register-indirect CALL fallthrough differs");
    expect(rosa::debug::dumpX86(decoded).find("call rax") != std::string::npos,
           "register-indirect CALL dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rax = codeBase.value + 4;
    state.rbx = 0xAAAAAAAA00000029ULL;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    const auto initialRsp = state.rsp;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expectEqual(state.rbx, std::uint64_t{42}, "register-indirect CALL did not execute its target");
    expectEqual(state.rax, codeBase.value + 4,
                "register-indirect CALL changed its target register");
    expectEqual(state.rsp, initialRsp + 8,
                "register-indirect CALL did not restore the guest stack");
    expectEqual(result.executedBlocks, std::size_t{4},
                "register-indirect CALL block count differs");
}

void testUnsignedBelowConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x72, 0x02}; // jb 0x1004
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::JccRelative, "JB rel8 opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Below, "JB rel8 condition differs");
    expectEqual(decoded[0].branchTarget->value, std::uint64_t{0x1004}, "JB rel8 target differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x8D7 | 1U;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1004}, "JB did not take when CF was set");
    expectEqual(taken.rflags, std::uint64_t{0x8D7 | 1U}, "JB changed guest flags");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x8D6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1002}, "JB took when CF was clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D6 & ~std::uint64_t{1}},
                "not-taken JB changed guest flags");
}

void testOverflowParityShortConditionals() {
    // Observed in libobjc under an Objective-C fixture: JO rel8.
    const rosa::x86::Decoder decoder;
    const rosa::dbt::Translator translator;
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802A34D62ULL};
    constexpr std::array<std::uint8_t, 2> observedCode{0x70, 0x7A};
    const auto observedDecoded = decoder.decodeBlock(observedCode, observedRip);
    expect(observedDecoded[0].opcode == rosa::x86::Opcode::JccRelative,
           "observed JO rel8 opcode differs");
    expect(observedDecoded[0].condition == rosa::x86::Condition::Overflow,
           "observed JO rel8 condition differs");
    expectEqual(observedDecoded[0].branchTarget->value, observedRip.value + 2 + 0x7A,
                "observed JO rel8 target differs");

    struct ShortJumpCase {
        std::uint8_t opcode;
        rosa::x86::Condition condition;
        std::string_view name;
        std::uint64_t takenFlags;
        std::uint64_t notTakenFlags;
    };
    constexpr std::uint64_t overflowSet = 0x8D7;
    constexpr std::uint64_t overflowClear = 0x8D7 & ~std::uint64_t{1U << 11U};
    constexpr std::uint64_t parityClear = 0x8D7 & ~std::uint64_t{1U << 2U};
    constexpr ShortJumpCase cases[] = {
        {0x70, rosa::x86::Condition::Overflow, "jo", overflowSet, overflowClear},
        {0x71, rosa::x86::Condition::NotOverflow, "jno", overflowClear, overflowSet},
        {0x7A, rosa::x86::Condition::ParityEven, "jp", overflowSet, parityClear},
        {0x7B, rosa::x86::Condition::ParityOdd, "jnp", parityClear, overflowSet},
    };
    for (const auto &jump : cases) {
        const std::array<std::uint8_t, 2> code{jump.opcode, 0x02};
        const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
        expect(decoded[0].opcode == rosa::x86::Opcode::JccRelative,
               std::string(jump.name) + " rel8 opcode differs");
        expect(decoded[0].condition == jump.condition,
               std::string(jump.name) + " rel8 condition differs");
        expectEqual(decoded[0].branchTarget->value, std::uint64_t{0x1004},
                    std::string(jump.name) + " rel8 target differs");
        expect(rosa::debug::dumpX86(decoded).find(std::string(jump.name) + " 0x1004") !=
                   std::string::npos,
               std::string(jump.name) + " rel8 dump differs");

        const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
        rosa::x86::X86State taken;
        taken.rflags = jump.takenFlags;
        static_cast<void>(block.execute(taken));
        expectEqual(taken.rip, std::uint64_t{0x1004},
                    std::string(jump.name) + " did not take its branch");
        expectEqual(taken.rflags, jump.takenFlags,
                    std::string(jump.name) + " changed guest flags");

        rosa::x86::X86State notTaken;
        notTaken.rflags = jump.notTakenFlags;
        static_cast<void>(block.execute(notTaken));
        expectEqual(notTaken.rip, std::uint64_t{0x1002},
                    std::string(jump.name) + " took its branch");
        expectEqual(notTaken.rflags, jump.notTakenFlags,
                    std::string(jump.name) + " changed guest flags when not taken");
    }
}

void testOverflowParityLongConditionals() {
    // Observed in Foundation under an Objective-C fixture: JNO rel32.
    struct LongJumpCase {
        std::uint8_t opcode;
        rosa::x86::Condition condition;
        std::string_view name;
        std::uint64_t takenFlags;
        std::uint64_t notTakenFlags;
    };
    constexpr std::uint64_t overflowSet = 0x8D7;
    constexpr std::uint64_t overflowClear = 0x8D7 & ~std::uint64_t{1U << 11U};
    constexpr std::uint64_t parityClear = 0x8D7 & ~std::uint64_t{1U << 2U};
    constexpr LongJumpCase cases[] = {
        {0x81, rosa::x86::Condition::NotOverflow, "jno", overflowClear, overflowSet},
        {0x8A, rosa::x86::Condition::ParityEven, "jp", overflowSet, parityClear},
        {0x8B, rosa::x86::Condition::ParityOdd, "jnp", parityClear, overflowSet},
    };
    const rosa::x86::Decoder decoder;
    const rosa::dbt::Translator translator;
    for (const auto &jump : cases) {
        const std::array<std::uint8_t, 6> code{0x0F, jump.opcode, 0xAB, 0xFC, 0xFF, 0xFF};
        const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
        expect(decoded[0].opcode == rosa::x86::Opcode::JccRelative,
               std::string(jump.name) + " rel32 opcode differs");
        expect(decoded[0].condition == jump.condition,
               std::string(jump.name) + " rel32 condition differs");
        // 0x1006 - 853 == 0xCB1.
        expectEqual(decoded[0].branchTarget->value, std::uint64_t{0xCB1},
                    std::string(jump.name) + " rel32 target differs");
        expect(rosa::debug::dumpX86(decoded).find(std::string(jump.name) + " 0xcb1") !=
                   std::string::npos,
               std::string(jump.name) + " rel32 dump differs");

        const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
        rosa::x86::X86State taken;
        taken.rflags = jump.takenFlags;
        static_cast<void>(block.execute(taken));
        expectEqual(taken.rip, std::uint64_t{0xCB1},
                    std::string(jump.name) + " rel32 did not take its branch");
        expectEqual(taken.rflags, jump.takenFlags,
                    std::string(jump.name) + " rel32 changed guest flags");

        rosa::x86::X86State notTaken;
        notTaken.rflags = jump.notTakenFlags;
        static_cast<void>(block.execute(notTaken));
        expectEqual(notTaken.rip, std::uint64_t{0x1006},
                    std::string(jump.name) + " rel32 took its branch");
    }

    constexpr std::array<std::uint8_t, 6> observed{0x0F, 0x81, 0xAB, 0xFC, 0xFF, 0xFF};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF80493763FULL};
    const auto observedDecoded = decoder.decodeBlock(observed, observedRip);
    expect(observedDecoded[0].condition == rosa::x86::Condition::NotOverflow,
           "observed JNO rel32 condition differs");
    expectEqual(observedDecoded[0].branchTarget->value, std::uint64_t{0x7FF8049372F0ULL},
                "observed JNO rel32 target differs");
}

void testUnsignedBelowLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x82, 0x02, 0, 0, 0};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::Below, "JB rel32 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x3;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1008}, "JB rel32 did not take with CF set");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1006}, "JB rel32 took with CF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x2}, "JB rel32 changed flags");
}

void testRegisterIndirectJump() {
    constexpr std::array<std::uint8_t, 2> code{0xFF, 0xE1};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::JmpReg, "JMP register opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rcx,
           "JMP register target differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0x123456789ABCDEF0ULL;
    state.rsp = 0x8000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rip, std::uint64_t{0x123456789ABCDEF0ULL},
                "JMP register selected target differs");
    expectEqual(state.rsp, std::uint64_t{0x8000}, "JMP register changed RSP");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "JMP register changed flags");
}

void testRipRelativeMemoryIndirectJump() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 48> code{
        0xFF, 0x25, 0x0A, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0,    0, 0, 0, 0, 0,
        0x20, 0x10, 0,    0,    0,    0,    0, 0, 0, 0, 0,    0, 0, 0, 0, 0,
        0x48, 0xB8, 0x2A, 0,    0,    0,    0, 0, 0, 0, 0xC3, 0, 0, 0, 0, 0,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded =
        decoder.decodeBlock(std::span<const std::uint8_t>{code}.first(6), codeBase);
    expect(decoded[0].opcode == rosa::x86::Opcode::JmpMem,
           "RIP-relative memory JMP opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase && !memory.index && memory.displacement == 0xA &&
               memory.width == 64,
           "RIP-relative memory JMP operand differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 4, sentinel);
    expectEqual(state.rax, std::uint64_t{42}, "RIP-relative memory JMP selected target differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RIP-relative memory JMP changed flags");
    expectEqual(result.executedBlocks, std::size_t{2},
                "RIP-relative memory JMP block count differs");
}

void testBasedMemoryIndirectJump() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF802A5BD7AULL};
    constexpr rosa::guest::GuestAddress tableBase{0x8000};
    constexpr std::uint64_t target = 0x7FF802A5BF90ULL;
    constexpr std::array<std::uint8_t, 6> code{0xFF, 0xA0, 0x10, 0x02, 0x00, 0x00};

    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expectEqual(decoded.size(), std::size_t{1}, "based memory JMP did not terminate its block");
    expect(decoded[0].opcode == rosa::x86::Opcode::JmpMem, "based memory JMP opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.hasBase && !memory.ripRelative && !memory.index &&
               memory.base == rosa::x86::Register::Rax && memory.displacement == 0x210 &&
               memory.width == 64,
           "based memory JMP operand differs");
    expect(rosa::debug::dumpX86(decoded).find("jmp qword [rax+0x210]") != std::string::npos,
           "based memory JMP dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(tableBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "indirect JMP table");
    addressSpace.writeU64(rosa::guest::GuestAddress{tableBase.value + 0x210}, target);
    rosa::x86::X86State state;
    state.rip = instructionAddress.value;
    state.rax = tableBase.value;
    state.rsp = 0x7000000FF000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rip, target, "based memory JMP selected target differs");
    expectEqual(state.rax, tableBase.value, "based memory JMP changed its base register");
    expectEqual(state.rsp, std::uint64_t{0x7000000FF000ULL}, "based memory JMP changed RSP");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "based memory JMP changed flags");

    rosa::x86::X86State faultState;
    faultState.rip = instructionAddress.value;
    faultState.rax = 0x9000;
    faultState.rsp = 0x7000000FF000ULL;
    faultState.rflags = 0x8D7;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(faultState, &addressSpace));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "based memory JMP accepted an unmapped target slot");
    expectEqual(faultState.rip, instructionAddress.value, "faulted based memory JMP changed RIP");
    expectEqual(faultState.rax, std::uint64_t{0x9000},
                "faulted based memory JMP changed its base register");
    expectEqual(faultState.rsp, std::uint64_t{0x7000000FF000ULL},
                "faulted based memory JMP changed RSP");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7}, "faulted based memory JMP changed flags");
}

} // namespace

std::span<const TestCase> controlFlowTests() {
    static const TestCase cases[]{
        {"R2 multi-block control flow", testR2MultiBlockControlFlow},
        {"R2 taken conditional", testR2TakenConditional},
        {"indirect guest-memory call", testIndirectGuestMemoryCall},
        {"indirect guest-memory call fault", testIndirectGuestMemoryCallFault},
        {"RIP-relative indirect guest-memory call", testRipRelativeIndirectGuestMemoryCall},
        {"indexed indirect guest-memory call", testIndexedIndirectGuestMemoryCall},
        {"indirect guest-register call", testIndirectGuestRegisterCall},
        {"unsigned-below conditional", testUnsignedBelowConditional},
        {"overflow/parity short conditionals", testOverflowParityShortConditionals},
        {"overflow/parity long conditionals", testOverflowParityLongConditionals},
        {"unsigned-below long conditional", testUnsignedBelowLongConditional},
        {"register-indirect jump", testRegisterIndirectJump},
        {"RIP-relative memory-indirect jump", testRipRelativeMemoryIndirectJump},
        {"based memory-indirect jump", testBasedMemoryIndirectJump},
    };
    return cases;
}

} // namespace rosa::tests
