#include "TestSupport.h"
#include "TestSuite.h"
#include "arm64/Backend.h"
#include "ir/Optimization.h"
#include "x86/Lowering.h"

namespace rosa::tests {
namespace {

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

void testLocalRegisterAllocatorReusesDeadValues() {
    constexpr std::array<std::uint8_t, 5> observedCode{0x44, 0x33, 0x64, 0x8B, 0x20};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF802AE1635ULL};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(observedCode, observedRip, 1);
    expectEqual(block.decoded().size(), std::size_t{1},
                "allocator regression block instruction count differs");
    expect(block.intermediateRepresentation().valueCount > 8,
           "allocator regression block no longer exceeds the physical temporary set");
    expect(!block.program().bytes.empty(), "allocator regression block produced no ARM64 code");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8028};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(target, 0x0F0F0F0F);
    rosa::x86::X86State state;
    state.rbx = page.value;
    state.rcx = 2;
    state.r12 = 0xAAAAAAAAFF00FF00ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r12, std::uint64_t{0xF00FF00F}, "register-reused indexed XOR result differs");
    expectEqual(state.rbx, page.value, "register-reused indexed XOR changed its base");
    expectEqual(state.rcx, std::uint64_t{2}, "register-reused indexed XOR changed its index");
    expectEqual(state.rflags, std::uint64_t{0x86}, "register-reused indexed XOR flags differ");
}

void testPreparedIrExecution() {
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(r1Code, rosa::guest::GuestAddress{0x1000});
    auto unoptimized = rosa::x86::lowerToIr(decoded);
    auto optimized = unoptimized;
    rosa::ir::optimizeBlock(optimized);
    expect(rosa::ir::verify(optimized).empty(), "optimization produced invalid IR");
    const auto executeIr = [&](const rosa::ir::Block &ir) {
        auto program = rosa::arm64::compile(ir, false);
        rosa::dbt::TranslatedBlock block(decoded, ir, std::move(program),
            std::make_shared<rosa::arm64::ExecutableArena>(), decoded.size());
        rosa::x86::X86State state;
        state.rip = 0x1000;
        expectEqual(block.execute(state), rosa::dbt::BlockExit::Return,
                    "prepared IR returned the wrong exit");
        return state;
    };
    const auto baseline = executeIr(unoptimized);
    const auto prepared = executeIr(optimized);
    expectEqual(prepared.rax, std::uint64_t{42}, "prepared IR arithmetic result differs");
    expectEqual(prepared.rax, baseline.rax, "optimization changed the arithmetic result");
    expectEqual(prepared.rflags, baseline.rflags, "optimization changed architectural flags");
    expectEqual(prepared.rip, baseline.rip, "optimization changed the exit RIP");
}

void testPreparedIrFaultOrdering() {
    // Commit one register before a faulting load, and never commit the later ADD.
    const std::array<std::uint8_t, 13> bytes{
        0x48, 0xC7, 0xC0, 0x29, 0, 0, 0, // mov rax, 41
        0x48, 0x8B, 0x0B,                // mov rcx, [rbx]
        0x04, 0x01,                      // add al, 1
        0xC3,
    };
    const auto decoded = rosa::x86::Decoder{}.decodeBlock(bytes, rosa::guest::GuestAddress{0x1000});
    for (const bool optimize : {false, true}) {
        auto ir = rosa::x86::lowerToIr(decoded);
        if (optimize) {
            rosa::ir::optimizeBlock(ir);
        }
        auto program = rosa::arm64::compile(ir, false);
        rosa::dbt::TranslatedBlock block(decoded, ir, std::move(program),
            std::make_shared<rosa::arm64::ExecutableArena>(), decoded.size());
        rosa::guest::AddressSpace memory;
        rosa::x86::X86State state;
        state.rip = 0x1000;
        state.rbx = 0x8000;
        state.rcx = 99;
        bool faulted = false;
        try {
            static_cast<void>(block.execute(state, &memory));
        } catch (const std::runtime_error &) {
            faulted = true;
        }
        expect(faulted, "prepared IR did not fault on unmapped memory");
        expectEqual(state.rax, std::uint64_t{41}, "fault crossed a register commit boundary");
        expectEqual(state.rcx, std::uint64_t{99}, "faulting load modified its destination");
        expectEqual(state.rip, std::uint64_t{0x1007}, "prepared IR lost the faulting RIP");
    }
}

} // namespace

std::span<const TestCase> irTests() {
    static const TestCase cases[]{
        {"prepared IR execution", testPreparedIrExecution},
        {"prepared IR fault ordering", testPreparedIrFaultOrdering},
        {"IR verification", testIrVerification},
        {"local register allocator reuses dead values", testLocalRegisterAllocatorReusesDeadValues},
    };
    return cases;
}

} // namespace rosa::tests
