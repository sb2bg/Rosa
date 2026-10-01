#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testHotGuestBlockDiagnostics() {
    constexpr std::array<std::uint8_t, 2> code{0xEB, 0xFE};
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code,
                            "hot-loop:__TEXT");
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    rosa::dbt::Dispatcher dispatcher(addressSpace, 1);
    std::string report;
    try {
        static_cast<void>(dispatcher.run(state, 40));
    } catch (const std::runtime_error &error) {
        report = rosa::debug::dumpGuestFailure("hot-loop", error, state, addressSpace, dispatcher);
    }
    expect(!report.empty(), "hot guest loop did not hit its diagnostic limit");
    const auto hot = dispatcher.hotBlocks();
    expectEqual(hot.size(), std::size_t{1}, "hot guest block count differs");
    expectEqual(hot[0].address.value, codeBase.value, "hot guest block address differs");
    expectEqual(hot[0].count, std::size_t{40}, "hot guest block execution count differs");
    expect(report.find("hot guest blocks:") != std::string::npos &&
               report.find("0x1000 count=40") != std::string::npos,
           "guest failure report omitted hot-block diagnostics");
}

void testGuestStoreSelfEdgeBatching() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress dataBase{0x8000};
    constexpr std::array<std::uint8_t, 12> code{
        0x40, 0x88, 0x38,       // mov byte [rax], dil
        0x48, 0x83, 0xC0, 0x01, // add rax, 1
        0x48, 0x39, 0xC8,       // cmp rax, rcx
        0x72, 0xF4,             // jb back to mov
    };

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeBase);
    expect(block.hasInternalSelfEdge(),
           "guest-store self edge was not eligible for generated batching");
    expect(rosa::debug::dumpArm64(block.program()).find("strb") != std::string::npos,
           "guest-store self edge omitted its direct-memory fast path");
    expectEqual(block.program().pointerRelocations.size(), std::size_t{1},
                "guest-store self edge retained dead flag helpers");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(dataBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rax = dataBase.value + 0x20;
    state.rcx = state.rax + 5;
    state.rdi = 0xA5;
    state.rip = codeBase.value;
    state.rflags = 0x202;
    const auto result = block.executeRepeated(state, addressSpace, nullptr, 10);
    expectEqual(result.exit, rosa::dbt::BlockExit::Continue,
                "guest-store self edge returned the wrong exit");
    expectEqual(result.executionCount, std::size_t{5},
                "guest-store self edge executed the wrong batch size");
    expectEqual(state.rax, dataBase.value + 0x25,
                "guest-store self edge produced the wrong cursor");
    expectEqual(state.rip, codeBase.value + code.size(),
                "guest-store self edge produced the wrong fallthrough");
    expectEqual(state.rflags & UINT64_C(0x8D5), UINT64_C(0x44),
                "guest-store self edge produced incorrect compare flags");
    const auto stored = addressSpace.readBytes(rosa::guest::GuestAddress{dataBase.value + 0x20}, 5);
    expect(std::ranges::all_of(stored, [](std::uint8_t byte) { return byte == 0xA5; }),
           "guest-store self edge wrote incorrect bytes");

    constexpr std::array<std::uint8_t, 15> constantLimitCode{
        0x40, 0x88, 0x3C, 0x08,             // mov byte [rax+rcx], dil
        0x4C, 0x01, 0xC8,                   // add rax, r9
        0x48, 0x3D, 0x25, 0x00, 0x00, 0x00, // cmp rax, 0x25
        0x72, 0xF1,                         // jb back to mov
    };
    auto constantLimitBlock = translator.translate(constantLimitCode, codeBase);
    expect(constantLimitBlock.hasInternalSelfEdge(),
           "constant-limit guest-store loop was not eligible for generated batching");
    state = {};
    state.rax = 0x20;
    state.rcx = dataBase.value;
    state.r9 = 1;
    state.rdi = 0x3C;
    state.rip = codeBase.value;
    const auto constantLimitResult =
        constantLimitBlock.executeRepeated(state, addressSpace, nullptr, 10);
    expectEqual(constantLimitResult.executionCount, std::size_t{5},
                "constant-limit guest-store span executed the wrong batch size");
    expectEqual(state.rax, std::uint64_t{0x25},
                "constant-limit guest-store span produced the wrong cursor");
    const auto constantLimitStored =
        addressSpace.readBytes(rosa::guest::GuestAddress{dataBase.value + 0x20}, 5);
    expect(std::ranges::all_of(constantLimitStored, [](std::uint8_t byte) { return byte == 0x3C; }),
           "constant-limit guest-store span wrote incorrect bytes");

    expectEqual(constantLimitBlock.isOptimizationCandidate(), rosa::dbt::llvmBackendAvailable(),
                "constant-limit guest-store trace candidacy differs");
    constantLimitBlock.recordExecutions(rosa::dbt::TranslatedBlock::optimizedLoopWarmupExecutions);
    constantLimitBlock.promoteOptimizedLoopIfHot(
        rosa::dbt::TranslatedBlock::optimizedLoopMinimumRemainingExecutions);
    expect(!constantLimitBlock.usesOptimizedLoop(),
           "guest-store trace ignored its memory amortization threshold");
    constantLimitBlock.recordExecutions(
        rosa::dbt::TranslatedBlock::optimizedMemoryLoopWarmupExecutions -
        rosa::dbt::TranslatedBlock::optimizedLoopWarmupExecutions);
    constantLimitBlock.promoteOptimizedLoopIfHot(
        rosa::dbt::TranslatedBlock::optimizedLoopMinimumRemainingExecutions);
    expectEqual(constantLimitBlock.usesOptimizedLoop(), rosa::dbt::llvmBackendAvailable(),
                "constant-limit guest-store trace promotion differs");
    state = {};
    state.rax = 0x20;
    state.rcx = dataBase.value;
    state.r9 = 1;
    state.rdi = 0x6D;
    state.rip = codeBase.value;
    const auto optimizedStoreResult =
        constantLimitBlock.executeRepeated(state, addressSpace, nullptr, 10);
    expectEqual(optimizedStoreResult.executionCount, std::size_t{5},
                "optimized guest-store trace executed the wrong batch size");
    expectEqual(state.rax, std::uint64_t{0x25},
                "optimized guest-store trace produced the wrong cursor");
    const auto optimizedStored =
        addressSpace.readBytes(rosa::guest::GuestAddress{dataBase.value + 0x20}, 5);
    expect(std::ranges::all_of(optimizedStored, [](std::uint8_t byte) { return byte == 0x6D; }),
           "optimized guest-store trace wrote incorrect bytes");

    state = {};
    state.rax = 0x20;
    state.rcx = dataBase.value + rosa::guest::guestPageSize - 0x22;
    state.r9 = 1;
    state.rdi = 0x7E;
    state.rip = codeBase.value;
    bool optimizedStoreFaulted = false;
    try {
        static_cast<void>(constantLimitBlock.executeRepeated(state, addressSpace, nullptr, 10));
    } catch (const std::runtime_error &error) {
        optimizedStoreFaulted =
            std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(optimizedStoreFaulted,
           "optimized guest-store trace crossed its rejected mapping boundary");
    expectEqual(state.rax, std::uint64_t{0x22},
                "optimized guest-store fallback advanced past its faulting iteration");

    state = {};
    state.rax = dataBase.value + rosa::guest::guestPageSize - 1;
    state.rcx = dataBase.value + rosa::guest::guestPageSize + 1;
    state.rdi = 0x5A;
    state.rip = codeBase.value;
    bool faulted = false;
    try {
        static_cast<void>(block.executeRepeated(state, addressSpace, nullptr, 3));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "batched guest store did not stop at a memory fault");
    expectEqual(state.rax, dataBase.value + rosa::guest::guestPageSize,
                "batched guest store advanced past its faulting iteration");
    expectEqual(addressSpace.readU8(
                    rosa::guest::GuestAddress{dataBase.value + rosa::guest::guestPageSize - 1}),
                std::uint8_t{0x5A}, "batched guest store lost its completed iteration");

    rosa::guest::AddressSpace executableAddressSpace;
    executableAddressSpace.mapAnonymous(dataBase, rosa::guest::guestPageSize,
                                        rosa::guest::Permission::Read |
                                            rosa::guest::Permission::Write |
                                            rosa::guest::Permission::Execute);
    state = {};
    state.rax = dataBase.value + 0x40;
    state.rcx = state.rax + 5;
    state.rdi = 0xCC;
    state.rip = codeBase.value;
    const auto executableResult = block.executeRepeated(state, executableAddressSpace, nullptr, 10);
    expectEqual(executableResult.executionCount, std::size_t{1},
                "self-modifying guest store did not stop its batch");
    expectEqual(state.rax, dataBase.value + 0x41,
                "self-modifying guest store executed more than once");
    expectEqual(state.rip, codeBase.value, "self-modifying guest store lost its self edge");
}

void testGuestLoadSelfEdgeBatching() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress dataBase{0x8000};
    constexpr std::array<std::uint8_t, 12> code{
        0x40, 0x38, 0x38,       // cmp byte [rax], dil
        0x48, 0x83, 0xC0, 0x01, // add rax, 1
        0x48, 0x39, 0xC8,       // cmp rax, rcx
        0x72, 0xF4,             // jb back to cmp byte
    };

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeBase);
    expect(block.hasInternalSelfEdge(),
           "guest-load self edge was not eligible for generated batching");
    expect(rosa::debug::dumpArm64(block.program()).find("ldrb") != std::string::npos,
           "guest-load self edge omitted its direct-memory fast path");
    expectEqual(block.program().pointerRelocations.size(), std::size_t{1},
                "guest-load self edge retained dead flag helpers");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(dataBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array bytes{
        std::uint8_t{1}, std::uint8_t{2}, std::uint8_t{3}, std::uint8_t{4}, std::uint8_t{5},
    };
    addressSpace.writeBytes(rosa::guest::GuestAddress{dataBase.value + 0x20}, bytes);
    rosa::x86::X86State state;
    state.rax = dataBase.value + 0x20;
    state.rcx = state.rax + bytes.size();
    state.rdi = 3;
    state.rip = codeBase.value;
    state.rflags = 0x202;
    const auto result = block.executeRepeated(state, addressSpace, nullptr, 10);
    expectEqual(result.executionCount, bytes.size(),
                "guest-load self edge executed the wrong batch size");
    expectEqual(state.rax, dataBase.value + 0x25, "guest-load self edge produced the wrong cursor");
    expectEqual(state.rip, codeBase.value + code.size(),
                "guest-load self edge produced the wrong fallthrough");
    expectEqual(state.rflags & UINT64_C(0x8D5), UINT64_C(0x44),
                "guest-load self edge produced incorrect compare flags");

    constexpr std::array<std::uint8_t, 92> constantStrideCode{
        0x45, 0x31, 0xD2,                         // xor r10d, r10d
        0x41, 0x38, 0x3C, 0x08,                   // cmp byte [r8+rcx], dil
        0x41, 0x0F, 0x95, 0xC2,                   // setne r10b
        0x41, 0xBB, 0x00, 0x00, 0x00, 0x00,       // mov r11d, 0
        0x4D, 0x0F, 0x45, 0xD8,                   // cmovne r11, r8
        0x45, 0x01, 0xCA,                         // add r10d, r9d
        0x49, 0x01, 0xC3,                         // add r11, rax
        0x49, 0x8D, 0x58, 0x01,                   // lea rbx, [r8+1]
        0x45, 0x31, 0xF6,                         // xor r14d, r14d
        0x41, 0x38, 0x7C, 0x08, 0x01,             // cmp byte [r8+rcx+1], dil
        0x41, 0x0F, 0x95, 0xC6,                   // setne r14b
        0x48, 0x0F, 0x44, 0xDA,                   // cmove rbx, rdx
        0x49, 0x8D, 0x40, 0x02,                   // lea rax, [r8+2]
        0x45, 0x31, 0xC9,                         // xor r9d, r9d
        0x41, 0x38, 0x7C, 0x08, 0x02,             // cmp byte [r8+rcx+2], dil
        0x41, 0x0F, 0x95, 0xC1,                   // setne r9b
        0x48, 0x0F, 0x44, 0xC2,                   // cmove rax, rdx
        0x45, 0x01, 0xF1,                         // add r9d, r14d
        0x45, 0x01, 0xD1,                         // add r9d, r10d
        0x48, 0x01, 0xD8,                         // add rax, rbx
        0x4C, 0x01, 0xD8,                         // add rax, r11
        0x49, 0x83, 0xC0, 0x03,                   // add r8, 3
        0x49, 0x81, 0xF8, 0x26, 0x00, 0x00, 0x00, // cmp r8, 0x26
        0x75, 0xA4,                               // jne back to xor
    };
    auto constantStrideBlock = translator.translate(constantStrideCode, codeBase);
    expect(constantStrideBlock.hasInternalSelfEdge(),
           "constant-stride guest-load loop was not eligible for generated batching");
    expect(constantStrideBlock.program().pointerRelocations.size() >= 2,
           "constant-stride guest-load loop omitted its span guard (relocations=" +
               std::to_string(constantStrideBlock.program().pointerRelocations.size()) + ")");
    expect(rosa::debug::dumpArm64(constantStrideBlock.program()).find("add x3, x3, #3") !=
               std::string::npos,
           "constant-stride guest-load loop omitted its host-pointer stride");
    state = {};
    state.r8 = 0x20;
    state.rcx = dataBase.value;
    state.rip = codeBase.value;
    const auto constantStrideResult =
        constantStrideBlock.executeRepeated(state, addressSpace, nullptr, 10);
    expectEqual(constantStrideResult.executionCount, std::size_t{2},
                "constant-stride guest-load span executed the wrong batch size");
    expectEqual(state.r8, std::uint64_t{0x26},
                "constant-stride guest-load span produced the wrong cursor");
    expectEqual(state.rip, codeBase.value + constantStrideCode.size(),
                "constant-stride guest-load span produced the wrong fallthrough");

    state = {};
    state.r8 = 0x20;
    state.rcx = dataBase.value + rosa::guest::guestPageSize - 0x23;
    state.rip = codeBase.value;
    bool spanFaulted = false;
    try {
        static_cast<void>(constantStrideBlock.executeRepeated(state, addressSpace, nullptr, 10));
    } catch (const std::runtime_error &error) {
        spanFaulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(spanFaulted, "constant-stride guest-load span crossed its mapping boundary");
    expectEqual(state.r8, std::uint64_t{0x23},
                "constant-stride guest-load span advanced past its faulting iteration");

    expectEqual(constantStrideBlock.isOptimizationCandidate(), rosa::dbt::llvmBackendAvailable(),
                "constant-stride guest-load trace candidacy differs");
    constantStrideBlock.recordExecutions(
        rosa::dbt::TranslatedBlock::optimizedMemoryLoopWarmupExecutions);
    constantStrideBlock.promoteOptimizedLoopIfHot(
        rosa::dbt::TranslatedBlock::optimizedLoopMinimumRemainingExecutions);
    expectEqual(constantStrideBlock.usesOptimizedLoop(), rosa::dbt::llvmBackendAvailable(),
                "constant-stride guest-load trace promotion differs");

    state = {};
    state.r8 = 0x20;
    state.rcx = dataBase.value;
    state.rip = codeBase.value;
    const auto optimizedStrideResult =
        constantStrideBlock.executeRepeated(state, addressSpace, nullptr, 10);
    expectEqual(optimizedStrideResult.executionCount, std::size_t{2},
                "optimized guest-load trace executed the wrong batch size");
    expectEqual(state.r8, std::uint64_t{0x26},
                "optimized guest-load trace produced the wrong cursor");
    expectEqual(state.rip, codeBase.value + constantStrideCode.size(),
                "optimized guest-load trace produced the wrong fallthrough");

    state = {};
    state.r8 = 0x20;
    state.rcx = dataBase.value + rosa::guest::guestPageSize - 0x23;
    state.rip = codeBase.value;
    bool optimizedSpanFaulted = false;
    try {
        static_cast<void>(constantStrideBlock.executeRepeated(state, addressSpace, nullptr, 10));
    } catch (const std::runtime_error &error) {
        optimizedSpanFaulted =
            std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(optimizedSpanFaulted,
           "optimized guest-load trace crossed its rejected mapping boundary");
    expectEqual(state.r8, std::uint64_t{0x23},
                "optimized guest-load fallback advanced past its faulting iteration");

    state = {};
    state.rax = dataBase.value + rosa::guest::guestPageSize - 1;
    state.rcx = dataBase.value + rosa::guest::guestPageSize + 1;
    state.rip = codeBase.value;
    bool faulted = false;
    try {
        static_cast<void>(block.executeRepeated(state, addressSpace, nullptr, 3));
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(faulted, "batched guest load did not stop at a memory fault");
    expectEqual(state.rax, dataBase.value + rosa::guest::guestPageSize,
                "batched guest load advanced past its faulting iteration");
}

void testConditionalSelfEdgeBatching() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x8000};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 16> code{
        0x48, 0xB9, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 5
        0x48, 0xFF, 0xC9,                                           // dec rcx
        0x75, 0xFB,                                                 // jne back to dec
        0xC3,                                                       // ret
    };

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code,
                            "conditional-self-edge:__TEXT");
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "conditional-self-edge stack");
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - sizeof(std::uint64_t);
    state.rflags = 0x203;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 16, sentinel);
    expectEqual(result.executedBlocks, std::size_t{6}, "conditional self-edge block count differs");
    expectEqual(result.translatedBlocks, std::size_t{3},
                "conditional self-edge translation count differs");
    expectEqual(state.rcx, std::uint64_t{0},
                "conditional self-edge loop produced the wrong counter");
    expectEqual(state.rflags & std::uint64_t{0x8D5}, std::uint64_t{0x45},
                "inlined DEC flags differ after conditional self-edge loop");
    const auto hot = dispatcher.hotBlocks(1, 8);
    const auto loop = std::ranges::find_if(
        hot, [](const auto &block) { return block.address.value == codeBase.value + 10; });
    expect(loop != hot.end() && loop->count == 4,
           "conditional self-edge diagnostics lost batched executions");
    if (rosa::dbt::llvmBackendAvailable()) {
        const auto translatedLoop = dispatcher.cache().blocks().find(codeBase.value + 10);
        expect(translatedLoop != dispatcher.cache().blocks().end() &&
                   translatedLoop->second->isOptimizationCandidate() &&
                   !translatedLoop->second->usesOptimizedLoop(),
               "cold conditional self-edge paid the LLVM compilation cost");
    }
}

void testOptimizedDecrementLoopEdges() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr std::array<std::uint8_t, 5> code{
        0x48, 0xFF, 0xC9, // dec rcx
        0x75, 0xFB,       // jne back to dec
    };
    const rosa::dbt::Translator translator;
    auto block = translator.translate(code, codeBase);
    expectEqual(block.isOptimizationCandidate(), rosa::dbt::llvmBackendAvailable(),
                "optimized decrement-loop candidacy differs");
    expect(!block.usesOptimizedLoop(), "decrement loop compiled before reaching the hot threshold");
    expectEqual(block.executionBatchLimit(10000),
                rosa::dbt::llvmBackendAvailable()
                    ? rosa::dbt::TranslatedBlock::optimizedLoopWarmupExecutions
                    : std::size_t{10000},
                "decrement-loop warmup batch limit differs");
    block.recordExecutions(rosa::dbt::TranslatedBlock::optimizedLoopWarmupExecutions - 1);
    block.promoteOptimizedLoopIfHot(
        rosa::dbt::TranslatedBlock::optimizedLoopMinimumRemainingExecutions);
    expect(!block.usesOptimizedLoop(), "decrement loop promoted before reaching the hot threshold");
    expectEqual(block.executionBatchLimit(10000),
                rosa::dbt::llvmBackendAvailable() ? std::size_t{1} : std::size_t{10000},
                "decrement-loop final warmup batch limit differs");
    block.recordExecutions(1);
    block.promoteOptimizedLoopIfHot(
        rosa::dbt::TranslatedBlock::optimizedLoopMinimumRemainingExecutions - 1);
    expect(!block.usesOptimizedLoop(), "decrement loop promoted without enough remaining work");
    block.promoteOptimizedLoopIfHot(
        rosa::dbt::TranslatedBlock::optimizedLoopMinimumRemainingExecutions);
    expectEqual(block.usesOptimizedLoop(), rosa::dbt::llvmBackendAvailable(),
                "optimized decrement-loop promotion differs");

    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rcx = 5;
    state.rflags = 0x203;
    auto result = block.executeRepeated(state, addressSpace, nullptr, 3);
    expectEqual(result.exit, rosa::dbt::BlockExit::Continue,
                "budgeted optimized loop returned the wrong exit");
    expectEqual(result.executionCount, std::size_t{3},
                "budgeted optimized loop executed the wrong block count");
    expectEqual(state.rcx, std::uint64_t{2}, "budgeted optimized loop produced the wrong counter");
    expectEqual(state.rip, codeBase.value, "budgeted optimized loop produced the wrong self edge");
    expectEqual(state.rflags & UINT64_C(0x8D5), UINT64_C(0x1),
                "budgeted optimized loop produced the wrong DEC flags");

    state = {};
    state.rcx = 2;
    state.rflags = 0x203;
    result = block.executeRepeated(state, addressSpace, nullptr, 10);
    expectEqual(result.executionCount, std::size_t{2},
                "terminating optimized loop executed the wrong block count");
    expectEqual(state.rcx, std::uint64_t{0},
                "terminating optimized loop produced the wrong counter");
    expectEqual(state.rip, codeBase.value + code.size(),
                "terminating optimized loop produced the wrong fallthrough");
    expectEqual(state.rflags & UINT64_C(0x8D5), UINT64_C(0x45),
                "terminating optimized loop produced the wrong DEC flags");

    state = {};
    state.rcx = UINT64_C(1) << 63U;
    state.rflags = 0x202;
    result = block.executeRepeated(state, addressSpace, nullptr, 1);
    expectEqual(result.executionCount, std::size_t{1},
                "overflow optimized loop executed the wrong block count");
    expectEqual(state.rcx, (UINT64_C(1) << 63U) - 1U,
                "overflow optimized loop produced the wrong counter");
    expectEqual(state.rflags & UINT64_C(0x8D5), UINT64_C(0x814),
                "overflow optimized loop produced the wrong DEC flags");

    state = {};
    state.rcx = 0;
    state.rflags = 0x203;
    result = block.executeRepeated(state, addressSpace, nullptr, 1);
    expectEqual(result.executionCount, std::size_t{1},
                "wrapping optimized loop executed the wrong block count");
    expectEqual(state.rcx, UINT64_MAX, "wrapping optimized loop produced the wrong counter");
    expectEqual(state.rflags & UINT64_C(0x8D5), UINT64_C(0x95),
                "wrapping optimized loop produced the wrong DEC flags");
}

void testOptimizedAddCompareLoop() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x8000};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 24> code{
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0
        0x48, 0x83, 0xC1, 0x02,                                     // add rcx, 2
        0x48, 0x81, 0xF9, 0xB8, 0x0B, 0x00, 0x00,                   // cmp rcx, 3000
        0x75, 0xF3,                                                 // jne back to add
        0xC3,                                                       // ret
    };

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code,
                            "optimized-add-compare:__TEXT");
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "optimized-add-compare stack");
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - sizeof(std::uint64_t);
    state.rflags = 0x203;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 2000, sentinel);
    expectEqual(result.executedBlocks, std::size_t{1501}, "add/compare loop block count differs");
    expectEqual(result.translatedBlocks, std::size_t{3},
                "add/compare loop translation count differs");
    expectEqual(state.rcx, std::uint64_t{3000}, "add/compare loop produced the wrong counter");
    expectEqual(state.rflags & UINT64_C(0x8D5), UINT64_C(0x44),
                "add/compare loop produced the wrong CMP flags");

    const auto translatedLoop = dispatcher.cache().blocks().find(codeBase.value + 10);
    expect(translatedLoop != dispatcher.cache().blocks().end(),
           "add/compare loop block was not cached");
    expectEqual(translatedLoop->second->executionCount(), std::size_t{1499},
                "add/compare loop execution count differs");
    expectEqual(translatedLoop->second->isOptimizationCandidate(),
                rosa::dbt::llvmBackendAvailable(), "generic add/compare loop candidacy differs");
    expect(!translatedLoop->second->usesOptimizedLoop(),
           "short generic add/compare loop paid the LLVM compilation cost");
}

void testTranslatedBlockInvalidationAfterExecutableWrite() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x8000};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 11> firstCode{
        0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3,
    };

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Write |
                                rosa::guest::Permission::Execute,
                            firstCode, "mutable-code:__TEXT");
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "mutable-code stack");

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    rosa::x86::X86State state;
    const auto resetState = [&] {
        state = {};
        state.rip = codeBase.value;
        state.rsp = stackBase.value + rosa::guest::guestPageSize - sizeof(std::uint64_t);
        addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    };

    resetState();
    static_cast<void>(dispatcher.run(state, 2, sentinel));
    expectEqual(state.rax, std::uint64_t{1}, "initial mutable block produced the wrong value");

    constexpr std::array replacementImmediate{std::uint8_t{2}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{codeBase.value + 2}, replacementImmediate);
    resetState();
    static_cast<void>(dispatcher.run(state, 2, sentinel));
    expectEqual(state.rax, std::uint64_t{2}, "dispatcher reused stale translated executable bytes");
    expectEqual(dispatcher.translatedBlocks(), std::size_t{1},
                "mutable block replacement grew the translation cache");
}

void testRepeatedFaultRip() {
    const std::array<std::uint8_t, 8> code{
        0x90, 0x0F, 0xB6, 0x03, // nop; movzx eax, byte [rbx]
        0xFF, 0xC9, 0x75, 0xF8, // dec ecx; jne back to nop
    };
    const auto block = rosa::dbt::Translator{}.translate(code, rosa::guest::GuestAddress{0x2000});
    expect(block.hasInternalSelfEdge(), "fault regression loop was not batchable");
    rosa::guest::AddressSpace memory;
    rosa::x86::X86State state;
    state.rip = 0x2000;
    state.rbx = 0x8000;
    state.rcx = 3;
    bool faulted = false;
    try {
        static_cast<void>(block.executeRepeated(state, memory, nullptr, 8));
    } catch (const std::runtime_error &) {
        faulted = true;
    }
    expect(faulted, "repeated load did not fault");
    expectEqual(state.rip, std::uint64_t{0x2001}, "repeated fault lost the instruction RIP");
    expectEqual(state.rcx, std::uint64_t{3}, "repeated fault committed a later instruction");
}

void testExecutionFaultRip() {
    const std::array<std::uint8_t, 5> code{0x90, 0x41, 0xF7, 0xF3, 0xC3};
    const auto block = rosa::dbt::Translator{}.translate(code, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State state;
    state.rip = 0x3000;
    state.rax = 100;
    state.r11 = 0;
    bool faulted = false;
    try {
        static_cast<void>(block.execute(state));
    } catch (const std::runtime_error &) {
        faulted = true;
    }
    expect(faulted, "division by zero did not fault");
    expectEqual(state.rip, std::uint64_t{0x3001}, "execution fault lost the instruction RIP");
    expectEqual(state.rax, std::uint64_t{100}, "faulting division changed the dividend");
}

} // namespace

std::span<const TestCase> optimizationTests() {
    static const TestCase cases[]{
        {"repeated memory fault RIP", testRepeatedFaultRip},
        {"execution fault RIP", testExecutionFaultRip},
        {"hot guest block diagnostics", testHotGuestBlockDiagnostics},
        {"guest-store self-edge batching", testGuestStoreSelfEdgeBatching},
        {"guest-load self-edge batching", testGuestLoadSelfEdgeBatching},
        {"conditional self-edge batching", testConditionalSelfEdgeBatching},
        {"optimized decrement-loop edges", testOptimizedDecrementLoopEdges},
        {"optimized add/compare loop", testOptimizedAddCompareLoop},
        {"translated block invalidation after executable write", testTranslatedBlockInvalidationAfterExecutableWrite},
    };
    return cases;
}

} // namespace rosa::tests
