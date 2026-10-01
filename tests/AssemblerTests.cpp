#include "TestSupport.h"
#include "TestSuite.h"
#include "TemporaryFile.h"

namespace rosa::tests {
namespace {

void testAssemblerEncodings() {
    rosa::arm64::Assembler assembler;
    assembler.movImmediate(rosa::arm64::x0, 42);
    assembler.add(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.lslImmediate(rosa::arm64::x10, rosa::arm64::x9, 32);
    assembler.lsrImmediate(rosa::arm64::x10, rosa::arm64::x9, 31);
    assembler.asrImmediate(rosa::arm64::x10, rosa::arm64::x9, 3);
    assembler.asrImmediate32(rosa::arm64::x10, rosa::arm64::x9, 3);
    assembler.lslVariable(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.lsrVariable(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.asrVariable(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.asrVariable32(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.multiplyLow(rosa::arm64::x11, rosa::arm64::x9, rosa::arm64::x10);
    assembler.multiplyHighUnsigned(rosa::arm64::x12, rosa::arm64::x9, rosa::arm64::x10);
    assembler.extract(rosa::arm64::x11, rosa::arm64::x10, rosa::arm64::x9, 32);
    assembler.bitAnd(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.bitOr(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.bitXor(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.reverseBytes32(rosa::arm64::x10, rosa::arm64::x9);
    assembler.reverseBytes64(rosa::arm64::x10, rosa::arm64::x9);
    assembler.signExtend32(rosa::arm64::x10, rosa::arm64::x9);
    assembler.ldr(rosa::arm64::x9, rosa::arm64::x0, 0);
    assembler.ldr32(rosa::arm64::x9, rosa::arm64::x0, 0);
    assembler.str(rosa::arm64::x9, rosa::arm64::x0, 0);
    assembler.blr(rosa::arm64::x16);
    assembler.pushFrameRecord();
    assembler.popFrameRecord();
    assembler.dmbIsh();
    assembler.isb();
    assembler.ret();

    const std::array<std::uint32_t, 28> expected{
        0xD2800540U, 0x8B0B012AU, 0xD3607D2AU, 0xD35FFD2AU, 0x9343FD2AU, 0x13037D2AU, 0x9ACB212AU, 0x9ACB252AU,
        0x9ACB292AU, 0x1ACB292AU,
        0x9B0A7D2BU, 0x9BCA7D2CU, 0x93C9814BU, 0x8A0B012AU, 0xAA0B012AU, 0xCA0B012AU, 0x5AC0092AU,
        0xDAC00D2AU, 0x93407D2AU, 0xF9400009U, 0xB9400009U, 0xF9000009U, 0xD63F0200U, 0xA9BF7BFDU,
        0xA8C17BFDU, 0xD5033BBFU, 0xD5033FDFU, 0xD65F03C0U,
    };
    expectEqual(assembler.words().size(), expected.size(), "assembler word count differs");
    for (std::size_t index = 0; index < expected.size(); ++index) {
        expectEqual(assembler.words()[index], expected[index], "ARM64 encoding differs");
    }

    rosa::arm64::Assembler complementAssembler;
    complementAssembler.movImmediate(rosa::arm64::x0, ~std::uint64_t{0x8D4});
    expectEqual(complementAssembler.words().size(), std::size_t{1},
                "MOVN immediate was not encoded compactly");
    expectEqual(complementAssembler.words().front(), std::uint32_t{0x92811A80},
                "MOVN immediate encoding differs");

    rosa::arm64::Assembler noListingAssembler(false);
    noListingAssembler.movImmediate(rosa::arm64::x0, 42);
    noListingAssembler.ret();
    const auto noListingProgram = std::move(noListingAssembler).finish();
    expect(noListingProgram.listing.empty(),
           "disabled ARM64 diagnostics retained a program listing");
    expect(!noListingProgram.bytes.empty(), "disabled ARM64 diagnostics discarded generated code");

    rosa::arm64::Assembler byteAccessAssembler;
    const auto outside = byteAccessAssembler.makeLabel();
    byteAccessAssembler.ldr8(rosa::arm64::x9, rosa::arm64::x10, 3);
    byteAccessAssembler.str8(rosa::arm64::x11, rosa::arm64::x12, 5);
    byteAccessAssembler.compare(rosa::arm64::x9, rosa::arm64::x10);
    byteAccessAssembler.bUnsignedHigherOrSame(outside);
    byteAccessAssembler.bConditional(rosa::arm64::BranchCondition::SignedLess, outside);
    byteAccessAssembler.subImmediate(rosa::arm64::x23, rosa::arm64::x23, 1);
    byteAccessAssembler.mov(rosa::arm64::x0, rosa::arm64::x0);
    byteAccessAssembler.bind(outside);
    const auto byteAccessProgram = std::move(byteAccessAssembler).finish();
    constexpr std::array<std::uint8_t, 28> byteAccessExpected{
        0x49, 0x0D, 0x40, 0x39, // ldrb w9, [x10, #3]
        0x8B, 0x15, 0x00, 0x39, // strb w11, [x12, #5]
        0x3F, 0x01, 0x0A, 0xEB, // cmp x9, x10
        0x82, 0x00, 0x00, 0x54, // b.hs +16
        0x6B, 0x00, 0x00, 0x54, // b.lt +12
        0xF7, 0x06, 0x00, 0xD1, // sub x23, x23, #1
        0xE0, 0x03, 0x00, 0xAA, // mov x0, x0
    };
    expect(std::ranges::equal(byteAccessProgram.bytes, byteAccessExpected),
           "ARM64 byte-access or conditional-branch encoding differs");

    rosa::arm64::Assembler word32Assembler;
    word32Assembler.add32(rosa::arm64::x8, rosa::arm64::x9, rosa::arm64::x10);
    word32Assembler.sub32(rosa::arm64::x11, rosa::arm64::x12, rosa::arm64::x13);
    word32Assembler.bitAnd32(rosa::arm64::x14, rosa::arm64::x15, rosa::arm64::x8);
    word32Assembler.bitOr32(rosa::arm64::x9, rosa::arm64::x10, rosa::arm64::x11);
    word32Assembler.bitXor32(rosa::arm64::x12, rosa::arm64::x13, rosa::arm64::x14);
    word32Assembler.addImmediate(rosa::arm64::x8, rosa::arm64::x9, 3);
    word32Assembler.addImmediate32(rosa::arm64::x10, rosa::arm64::x11, 4);
    word32Assembler.subImmediate32(rosa::arm64::x12, rosa::arm64::x13, 5);
    word32Assembler.mov32(rosa::arm64::x8, rosa::arm64::x9);
    word32Assembler.compareZero(rosa::arm64::x10);
    word32Assembler.conditionalSet(rosa::arm64::x8, rosa::arm64::BranchCondition::Equal);
    word32Assembler.conditionalSet(rosa::arm64::x9, rosa::arm64::BranchCondition::NotEqual);
    word32Assembler.conditionalSelect(rosa::arm64::x8, rosa::arm64::x9, rosa::arm64::x10,
                                      rosa::arm64::BranchCondition::NotEqual);
    word32Assembler.conditionalSelect32(rosa::arm64::x11, rosa::arm64::x12, rosa::arm64::x13,
                                        rosa::arm64::BranchCondition::Equal);
    constexpr std::array<std::uint32_t, 14> word32Expected{
        0x0B0A0128U, 0x4B0D018BU, 0x0A0801EEU, 0x2A0B0149U, 0x4A0E01ACU, 0x91000D28U, 0x1100116AU,
        0x510015ACU, 0x2A0903E8U, 0xF100015FU, 0x9A9F17E8U, 0x9A9F07E9U, 0x9A8A1128U, 0x1A8D018BU,
    };
    expect(std::ranges::equal(word32Assembler.words(), word32Expected),
           "ARM64 32-bit data-processing encodings differ");

    rosa::arm64::Assembler calleeSavedAssembler;
    calleeSavedAssembler.pushCalleeSaved19Through24();
    calleeSavedAssembler.popCalleeSaved19Through24();
    constexpr std::array<std::uint32_t, 6> calleeSavedExpected{
        0xA9BF53F3U, 0xA9BF5BF5U, 0xA9BF63F7U, 0xA8C163F7U, 0xA8C15BF5U, 0xA8C153F3U,
    };
    expect(std::ranges::equal(calleeSavedAssembler.words(), calleeSavedExpected),
           "ARM64 x19...x24 save/restore encoding differs");

    rosa::arm64::Assembler callerSavedAssembler;
    callerSavedAssembler.pushCallerSaved8Through15();
    callerSavedAssembler.popCallerSaved8Through15();
    constexpr std::array<std::uint32_t, 8> callerSavedExpected{
        0xA9BF27E8U, 0xA9BF2FEAU, 0xA9BF37ECU, 0xA9BF3FEEU,
        0xA8C13FEEU, 0xA8C137ECU, 0xA8C12FEAU, 0xA8C127E8U,
    };
    expect(std::ranges::equal(callerSavedAssembler.words(), callerSavedExpected),
           "ARM64 x8...x15 save/restore encoding differs");

    rosa::arm64::Assembler extendedCallerSavedAssembler;
    extendedCallerSavedAssembler.pushCallerSaved5Through15();
    extendedCallerSavedAssembler.popCallerSaved5Through15();
    constexpr std::array<std::uint32_t, 12> extendedCallerSavedExpected{
        0xA9BF1BE5U, 0xA9BF7BE7U, 0xA9BF27E8U, 0xA9BF2FEAU, 0xA9BF37ECU, 0xA9BF3FEEU,
        0xA8C13FEEU, 0xA8C137ECU, 0xA8C12FEAU, 0xA8C127E8U, 0xA8C17BE7U, 0xA8C11BE5U,
    };
    expect(std::ranges::equal(extendedCallerSavedAssembler.words(), extendedCallerSavedExpected),
           "ARM64 x5...x15/x30 save/restore encoding differs");

    rosa::arm64::Assembler highCalleeSavedAssembler;
    highCalleeSavedAssembler.pushCalleeSaved25Through28();
    highCalleeSavedAssembler.popCalleeSaved25Through28();
    constexpr std::array<std::uint32_t, 4> highCalleeSavedExpected{
        0xA9BF6BF9U,
        0xA9BF73FBU,
        0xA8C173FBU,
        0xA8C16BF9U,
    };
    expect(std::ranges::equal(highCalleeSavedAssembler.words(), highCalleeSavedExpected),
           "ARM64 x25...x28 save/restore encoding differs");
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

void testExecutableArenaReusesMappings() {
    auto arena = std::make_shared<rosa::arm64::ExecutableArena>(64U * 1024U);

    rosa::arm64::Assembler firstAssembler;
    firstAssembler.movImmediate(rosa::arm64::x0, 0x1234);
    firstAssembler.ret();
    const auto firstProgram = std::move(firstAssembler).finish();
    rosa::arm64::ExecutableCode first(arena, firstProgram.bytes);

    rosa::arm64::Assembler secondAssembler;
    secondAssembler.movImmediate(rosa::arm64::x0, 0x5678);
    secondAssembler.ret();
    const auto secondProgram = std::move(secondAssembler).finish();
    rosa::arm64::ExecutableCode second(arena, secondProgram.bytes);

    expectEqual(arena->mappingCount(), std::size_t{1},
                "small generated functions did not share one JIT mapping");
    expectEqual(arena->allocatedBytes(), std::size_t{64U * 1024U},
                "executable arena allocation size differs");
    expect(arena->usedBytes() >= first.size() + second.size(),
           "executable arena did not account for published code");

    using Entry = std::uint64_t (*)();
    expectEqual(first.entry<Entry>()(), std::uint64_t{0x1234},
                "first arena function returned the wrong value");
    expectEqual(second.entry<Entry>()(), std::uint64_t{0x5678},
                "second arena function returned the wrong value");
}

void testPersistentTranslationCacheRoundTrip() {
    std::array<char, 39> pathTemplate{};
    constexpr std::string_view pattern = "/tmp/rosa-translation-cache-XXXXXX";
    std::copy(pattern.begin(), pattern.end(), pathTemplate.begin());
    const auto descriptor = ::mkstemp(pathTemplate.data());
    expect(descriptor >= 0, "could not create persistent translation-cache fixture");
    ::close(descriptor);
    const std::filesystem::path path(pathTemplate.data());
    constexpr rosa::guest::GuestAddress start{0x1000};
    constexpr std::array<std::uint8_t, 4> code{
        0x48, 0xFF,
        0xC0, // inc rax
        0xC3, // ret
    };
    constexpr rosa::guest::GuestAddress loopStart{0x2000};
    constexpr std::array<std::uint8_t, 5> loopCode{
        0x48, 0xFF, 0xC9, // dec rcx
        0x75, 0xFB,       // jne back to dec
    };
    try {
        {
            rosa::dbt::BlockCache cache(false, path);
            auto &block = cache.getOrTranslate(start, code, 16, 1);
            expectEqual(cache.persistentHitCount(), std::size_t{0},
                        "cold translation unexpectedly hit persistent cache");
            expect(!block.program().pointerRelocations.empty(),
                   "helper-bearing block omitted pointer relocations");
            rosa::x86::X86State state;
            state.rax = 41;
            expect(block.execute(state) == rosa::dbt::BlockExit::Return,
                   "cold cached block returned the wrong exit kind");
            expectEqual(state.rax, std::uint64_t{42},
                        "cold cached block produced the wrong result");
            auto &loop = cache.getOrTranslate(loopStart, loopCode, 16, 1);
            expectEqual(loop.isOptimizationCandidate(), rosa::dbt::llvmBackendAvailable(),
                        "cold persistent self loop candidacy differs");
        }
        {
            rosa::dbt::BlockCache cache(false, path);
            auto &block = cache.getOrTranslate(start, code, 16, 1);
            expectEqual(cache.persistentHitCount(), std::size_t{1},
                        "warm translation missed persistent cache");
            rosa::x86::X86State state;
            state.rax = 41;
            expect(block.execute(state) == rosa::dbt::BlockExit::Return,
                   "warm cached block returned the wrong exit kind");
            expectEqual(state.rax, std::uint64_t{42},
                        "warm cached block produced the wrong result");
            expectEqual(block.decoded().size(), std::size_t{2},
                        "warm cached block could not reconstruct diagnostics");
            auto &loop = cache.getOrTranslate(loopStart, loopCode, 16, 1);
            expectEqual(cache.persistentHitCount(), std::size_t{2},
                        "warm persistent self loop missed its cache entry");
            expectEqual(loop.isOptimizationCandidate(), rosa::dbt::llvmBackendAvailable(),
                        "warm persistent self loop lost lazy optimization candidacy");
            loop.recordExecutions(rosa::dbt::TranslatedBlock::optimizedLoopWarmupExecutions);
            loop.promoteOptimizedLoopIfHot(
                rosa::dbt::TranslatedBlock::optimizedLoopMinimumRemainingExecutions);
            expectEqual(loop.usesOptimizedLoop(), rosa::dbt::llvmBackendAvailable(),
                        "warm persistent self loop did not reconstruct IR for promotion");
        }
    } catch (...) {
        ::unlink(path.c_str());
        throw;
    }
    ::unlink(path.c_str());
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

void testPersistentCacheRejectsDifferentBuild() {
    const TemporaryFile fixture(std::filesystem::temp_directory_path());
    const std::array<std::uint8_t, 4> code{0x48, 0xFF, 0xC0, 0xC3};
    constexpr rosa::guest::GuestAddress start{0x1000};
    {
        rosa::dbt::BlockCache cache(false, fixture.path());
        static_cast<void>(cache.getOrTranslate(start, code, 16, 1));
    }
    // Cache v2: eight magic bytes and a four-byte version precede the identity.
    {
        std::fstream file(fixture.path(), std::ios::binary | std::ios::in | std::ios::out);
        expect(bool(file), "cannot open the persistent cache fixture");
        file.seekg(12);
        char byte{};
        file.read(&byte, 1);
        expect(bool(file), "cache fixture has no build identity");
        byte ^= 1;
        file.seekp(12);
        file.write(&byte, 1);
        expect(bool(file), "cannot alter the cache fixture build identity");
    }
    rosa::dbt::BlockCache cache(false, fixture.path());
    const auto &block = cache.getOrTranslate(start, code, 16, 1);
    expectEqual(cache.persistentHitCount(), std::size_t{0}, "cache accepted a different build");
    rosa::x86::X86State state;
    state.rax = 41;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{42}, "cache miss did not recompile correctly");
}

} // namespace

std::span<const TestCase> assemblerTests() {
    static const TestCase cases[]{
        {"persistent cache rejects different builds", testPersistentCacheRejectsDifferentBuild},
        {"arm64 assembler encodings", testAssemblerEncodings},
        {"R0 generated execution", testR0ExecutesGeneratedCode},
        {"executable arena mapping reuse", testExecutableArenaReusesMappings},
        {"persistent translation cache round trip", testPersistentTranslationCacheRoundTrip},
        {"arm64 label fixups", testAssemblerLabels},
    };
    return cases;
}

} // namespace rosa::tests
