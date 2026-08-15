#include "arm64/Assembler.h"
#include "arm64/CodeBuffer.h"
#include "dbt/Dispatcher.h"
#include "dbt/Translator.h"
#include "darwin/Commpage.h"
#include "darwin/Mach.h"
#include "darwin/Syscall.h"
#include "debug/Dump.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "guest/StartupStack.h"
#include "ir/IR.h"
#include "macho/Loader.h"
#include "macho/MachOFile.h"
#include "x86/Decoder.h"
#include "x86/Instruction.h"
#include "x86/Registers.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#if ROSA_HAS_X86_ORACLE
#include "differential/Protocol.h"
#endif

namespace {

template <typename Actual, typename Expected>
void expectEqual(const Actual &actual, const Expected &expected, std::string_view message) {
    if (actual != expected) {
        throw std::runtime_error(std::string(message));
    }
}

void expect(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::uint64_t fixedTimestampCounter() { return 0x12345678ABCDEF01ULL; }

#if ROSA_HAS_X86_ORACLE

#define ROSA_DIFFERENTIAL_CASE(name, ...)                                          \
    constexpr auto differentialBytes_##name =                                     \
        std::to_array<std::uint8_t>({__VA_ARGS__, 0xC3});
#include "differential/Cases.def"
#undef ROSA_DIFFERENTIAL_CASE

constexpr std::uint64_t carryFlag = 1U << 0U;
constexpr std::uint64_t parityFlag = 1U << 2U;
constexpr std::uint64_t auxiliaryFlag = 1U << 4U;
constexpr std::uint64_t zeroFlag = 1U << 6U;
constexpr std::uint64_t signFlag = 1U << 7U;
constexpr std::uint64_t overflowFlag = 1U << 11U;
constexpr std::uint64_t arithmeticFlags =
    carryFlag | parityFlag | auxiliaryFlag | zeroFlag | signFlag | overflowFlag;
constexpr std::uint64_t logicDefinedFlags =
    carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
constexpr std::uint16_t allGprsExceptRsp =
    static_cast<std::uint16_t>(UINT16_MAX &
                               ~(1U << static_cast<unsigned>(rosa::x86::Register::Rsp)));

struct DifferentialCase {
    std::string_view name;
    rosa::differential::Request request;
    std::span<const std::uint8_t> code;
    std::uint16_t gprMask{allGprsExceptRsp};
    std::uint64_t flagMask{arithmeticFlags};
    std::uint16_t xmmMask{UINT16_MAX};
    std::size_t memoryCompareOffset{};
    std::size_t memoryCompareSize{};
    std::size_t stackCompareOffset{};
    std::size_t stackCompareSize{};
};

std::uint64_t registerValue(const rosa::x86::X86State &state,
                            rosa::x86::Register reg) {
    std::uint64_t result = 0;
    const auto *bytes = reinterpret_cast<const std::uint8_t *>(&state);
    std::memcpy(&result, bytes + rosa::x86::registerOffset(reg), sizeof(result));
    return result;
}

void setRegisterValue(rosa::x86::X86State &state, rosa::x86::Register reg,
                      std::uint64_t value) {
    auto *bytes = reinterpret_cast<std::uint8_t *>(&state);
    std::memcpy(bytes + rosa::x86::registerOffset(reg), &value, sizeof(value));
}

bool writeFully(int descriptor, std::span<const std::byte> bytes) {
    while (!bytes.empty()) {
        const auto count = ::write(descriptor, bytes.data(), bytes.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
    return true;
}

bool readFully(int descriptor, std::span<std::byte> bytes) {
    while (!bytes.empty()) {
        const auto count = ::read(descriptor, bytes.data(), bytes.size());
        if (count == 0) {
            return false;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
    return true;
}

rosa::differential::Result
runX86Oracle(const rosa::differential::Request &request) {
    int requestPipe[2]{};
    int resultPipe[2]{};
    if (::pipe(requestPipe) != 0 || ::pipe(resultPipe) != 0) {
        throw std::runtime_error("failed to create x86 oracle pipes");
    }
    const auto child = ::fork();
    if (child < 0) {
        throw std::runtime_error("failed to fork x86 oracle");
    }
    if (child == 0) {
        static_cast<void>(::dup2(requestPipe[0], STDIN_FILENO));
        static_cast<void>(::dup2(resultPipe[1], STDOUT_FILENO));
        ::close(requestPipe[0]);
        ::close(requestPipe[1]);
        ::close(resultPipe[0]);
        ::close(resultPipe[1]);
        ::execl("/usr/bin/arch", "arch", "-x86_64", ROSA_TEST_X86_ORACLE_PATH,
                static_cast<char *>(nullptr));
        _exit(127);
    }

    ::close(requestPipe[0]);
    ::close(resultPipe[1]);
    const auto wrote = writeFully(
        requestPipe[1], std::as_bytes(std::span(&request, std::size_t{1})));
    ::close(requestPipe[1]);
    rosa::differential::Result result;
    const auto read = readFully(
        resultPipe[0], std::as_writable_bytes(std::span(&result, std::size_t{1})));
    ::close(resultPipe[0]);
    int status = 0;
    static_cast<void>(::waitpid(child, &status, 0));
    if (!wrote || !read || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        result.magic != rosa::differential::protocolMagic || result.status != 0) {
        throw std::runtime_error("x86 Rosetta oracle did not return a valid result");
    }
    return result;
}

rosa::differential::Result runRosaDifferential(const DifferentialCase &testCase) {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read |
                                rosa::guest::Permission::Execute,
                            testCase.code, "differential:__TEXT");
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write,
                              "differential memory");
    addressSpace.writeBytes(memoryBase, testCase.request.memory);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write,
                              "differential stack");

    auto state = testCase.request.state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::differential::stackSize - 8;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    if (testCase.request.memoryBaseRegister != rosa::differential::noRegister) {
        setRegisterValue(
            state,
            static_cast<rosa::x86::Register>(testCase.request.memoryBaseRegister),
            memoryBase.value + testCase.request.memoryBaseOffset);
    }
    if (testCase.request.codePointerMemoryOffset != rosa::differential::noOffset) {
        addressSpace.writeU64(
            rosa::guest::GuestAddress{memoryBase.value +
                                      testCase.request.codePointerMemoryOffset},
            codeBase.value + testCase.request.codePointerTargetOffset);
    }

    rosa::differential::Result result;
    result.initial = state;
    rosa::dbt::Dispatcher dispatcher(addressSpace, 1);
    static_cast<void>(dispatcher.run(state, 128, sentinel));
    result.final = state;
    const auto memory = addressSpace.readBytes(memoryBase, result.memory.size());
    std::ranges::copy(memory, result.memory.begin());
    const auto stack = addressSpace.readBytes(stackBase, result.stack.size());
    std::ranges::copy(stack, result.stack.begin());
    return result;
}

std::string hexadecimal(std::uint64_t value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}

void compareDifferentialResult(const DifferentialCase &testCase,
                               const rosa::differential::Result &oracle,
                               const rosa::differential::Result &rosaResult) {
    for (unsigned encoded = 0; encoded < 16; ++encoded) {
        if ((testCase.gprMask & (1U << encoded)) == 0) {
            continue;
        }
        const auto reg = static_cast<rosa::x86::Register>(encoded);
        const auto expected = registerValue(oracle.final, reg);
        const auto actual = registerValue(rosaResult.final, reg);
        if (actual != expected) {
            throw std::runtime_error(
                std::string(testCase.name) + ": " +
                std::string(rosa::x86::registerName(reg)) + " expected " +
                hexadecimal(expected) + " but Rosa produced " + hexadecimal(actual));
        }
    }

    const auto expectedFlags = oracle.final.rflags & testCase.flagMask;
    const auto actualFlags = rosaResult.final.rflags & testCase.flagMask;
    if (actualFlags != expectedFlags) {
        throw std::runtime_error(std::string(testCase.name) +
                                 ": defined RFLAGS expected " +
                                 hexadecimal(expectedFlags) + " but Rosa produced " +
                                 hexadecimal(actualFlags) + " (mask " +
                                 hexadecimal(testCase.flagMask) + ")");
    }

    const auto oracleStackDelta = oracle.final.rsp - oracle.initial.rsp;
    const auto rosaStackDelta = rosaResult.final.rsp - rosaResult.initial.rsp;
    if (rosaStackDelta != oracleStackDelta) {
        throw std::runtime_error(std::string(testCase.name) +
                                 ": normalized RSP delta differs");
    }

    for (unsigned encoded = 0; encoded < 16; ++encoded) {
        if ((testCase.xmmMask & (1U << encoded)) == 0) {
            continue;
        }
        const auto &expected = oracle.final.xmm[encoded];
        const auto &actual = rosaResult.final.xmm[encoded];
        if (actual.low != expected.low || actual.high != expected.high) {
            throw std::runtime_error(std::string(testCase.name) + ": xmm" +
                                     std::to_string(encoded) + " differs");
        }
    }

    const auto memoryEnd = testCase.memoryCompareOffset + testCase.memoryCompareSize;
    if (memoryEnd > oracle.memory.size() ||
        !std::equal(oracle.memory.begin() +
                        static_cast<std::ptrdiff_t>(testCase.memoryCompareOffset),
                    oracle.memory.begin() + static_cast<std::ptrdiff_t>(memoryEnd),
                    rosaResult.memory.begin() +
                        static_cast<std::ptrdiff_t>(testCase.memoryCompareOffset))) {
        throw std::runtime_error(std::string(testCase.name) +
                                 ": selected guest memory differs");
    }
    const auto stackEnd = testCase.stackCompareOffset + testCase.stackCompareSize;
    if (stackEnd > oracle.stack.size() ||
        !std::equal(oracle.stack.begin() +
                        static_cast<std::ptrdiff_t>(testCase.stackCompareOffset),
                    oracle.stack.begin() + static_cast<std::ptrdiff_t>(stackEnd),
                    rosaResult.stack.begin() +
                        static_cast<std::ptrdiff_t>(testCase.stackCompareOffset))) {
        throw std::runtime_error(std::string(testCase.name) +
                                 ": selected guest stack memory differs");
    }
}

#endif

#if ROSA_HAS_X86_ORACLE

void testRosettaDifferentialSemantics() {
    using rosa::differential::CaseId;
    std::size_t compared = 0;
    const auto run = [&compared](DifferentialCase testCase) {
        const auto oracle = runX86Oracle(testCase.request);
        const auto rosaResult = runRosaDifferential(testCase);
        compareDifferentialResult(testCase, oracle, rosaResult);
        ++compared;
    };
    const auto make = [](std::string_view name, CaseId id,
                         std::span<const std::uint8_t> code) {
        DifferentialCase result;
        result.name = name;
        result.request.caseId = id;
        result.request.state.rflags = 0x8D7;
        result.code = code;
        return result;
    };
    const auto bindMemory = [](DifferentialCase &testCase, rosa::x86::Register reg,
                               std::uint32_t offset) {
        testCase.request.memoryBaseRegister = static_cast<std::uint8_t>(reg);
        testCase.request.memoryBaseOffset = offset;
        testCase.gprMask = static_cast<std::uint16_t>(
            testCase.gprMask & ~(1U << static_cast<unsigned>(reg)));
    };

    {
        auto testCase = make("add64_overflow", CaseId::add64_overflow,
                             differentialBytes_add64_overflow);
        testCase.request.state.rax = INT64_MAX;
        run(testCase);
    }
    {
        auto testCase = make("add8_register_overflow",
                             CaseId::add8_register_overflow,
                             differentialBytes_add8_register_overflow);
        testCase.request.state.rsi = 0x112233445566777FULL;
        testCase.request.state.r9 = 0x8877665544332201ULL;
        run(testCase);
    }
    {
        auto testCase = make("add8_scaled_memory",
                             CaseId::add8_scaled_memory,
                             differentialBytes_add8_scaled_memory);
        bindMemory(testCase, rosa::x86::Register::R10, 0);
        testCase.request.state.rdi = 0x20;
        testCase.request.state.rsi = 0x112233445566777FULL;
        testCase.request.memory[0x20] = 1;
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("add8_immediate", CaseId::add8_immediate,
                             differentialBytes_add8_immediate);
        testCase.request.state.rdx = 0x112233445566777CULL;
        run(testCase);
    }
    {
        auto testCase = make("add32_sign_extended_immediate",
                             CaseId::add32_sign_extended_immediate,
                             differentialBytes_add32_sign_extended_immediate);
        testCase.request.state.rax = 0xAAAAAAAA80000003ULL;
        run(testCase);
    }
    {
        auto testCase = make("sub64_borrow", CaseId::sub64_borrow,
                             differentialBytes_sub64_borrow);
        testCase.request.state.rdi = 5;
        testCase.request.state.rdx = 7;
        run(testCase);
    }
    {
        auto testCase = make("inc32_overflow", CaseId::inc32_overflow,
                             differentialBytes_inc32_overflow);
        testCase.request.state.r15 = 0xAAAAAAAA7FFFFFFFULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("inc8_overflow", CaseId::inc8_overflow,
                             differentialBytes_inc8_overflow);
        testCase.request.state.r8 = 0x112233445566777FULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("dec32_overflow", CaseId::dec32_overflow,
                             differentialBytes_dec32_overflow);
        testCase.request.state.rdi = 0xBBBBBBBB80000000ULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("dec8_overflow", CaseId::dec8_overflow,
                             differentialBytes_dec8_overflow);
        testCase.request.state.rax = 0x1122334455667780ULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("dec64_memory", CaseId::dec64_memory,
                             differentialBytes_dec64_memory);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        const std::uint64_t value = std::uint64_t{1} << 63U;
        std::memcpy(testCase.request.memory.data() + 0x18, &value,
                    sizeof(value));
        testCase.memoryCompareOffset = 0x18;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("and32_mask", CaseId::and32_mask,
                             differentialBytes_and32_mask);
        testCase.request.state.r15 = 0xFFFFFFFF80000800ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("and8_accumulator", CaseId::and8_accumulator,
                             differentialBytes_and8_accumulator);
        testCase.request.state.rax = 0x11223344556677A5ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("and8_register", CaseId::and8_register,
                             differentialBytes_and8_register);
        testCase.request.state.rax = 0x1122334455667780ULL;
        testCase.request.state.rcx = 0x88776655443322FFULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("and8_rip_memory", CaseId::and8_rip_memory,
                             differentialBytes_and8_rip_memory);
        testCase.request.state.r14 = 0x11223344556677F3ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or64_register", CaseId::or64_register,
                             differentialBytes_or64_register);
        testCase.request.state.rax = 0x00000000ABCDEF01ULL;
        testCase.request.state.rdx = 0x1234567800000000ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or8_register", CaseId::or8_register,
                             differentialBytes_or8_register);
        testCase.request.state.rax = 0x1122334455667780ULL;
        testCase.request.state.rcx = 0x8877665544332201ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("xor32_register", CaseId::xor32_register,
                             differentialBytes_xor32_register);
        testCase.request.state.rsi = UINT64_MAX;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("xor8_accumulator", CaseId::xor8_accumulator,
                             differentialBytes_xor8_accumulator);
        testCase.request.state.rax = 0x1122334455667701ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("test16_register", CaseId::test16_register,
                             differentialBytes_test16_register);
        testCase.request.state.r14 = 0xA5A5A5A500008000ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("test8_register_immediate",
                             CaseId::test8_register_immediate,
                             differentialBytes_test8_register_immediate);
        testCase.request.state.rdx = 0x1122334455667782ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("test8_extended_register_immediate",
                             CaseId::test8_extended_register_immediate,
                             differentialBytes_test8_extended_register_immediate);
        testCase.request.state.r14 = 0x8877665544332202ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("test8_extended_registers",
                             CaseId::test8_extended_registers,
                             differentialBytes_test8_extended_registers);
        testCase.request.state.r14 = 0x1122334455667780ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("cmp64_register", CaseId::cmp64_register,
                             differentialBytes_cmp64_register);
        testCase.request.state.r14 = 5;
        testCase.request.state.r13 = 7;
        run(testCase);
    }
    {
        auto testCase = make("cmp32_register_legacy",
                             CaseId::cmp32_register_legacy,
                             differentialBytes_cmp32_register_legacy);
        testCase.request.state.rdx = 0xAAAAAAAA80000000ULL;
        testCase.request.state.rsi = 0xBBBBBBBB00000001ULL;
        run(testCase);
    }
    {
        auto testCase = make("cmp8_register_immediate",
                             CaseId::cmp8_register_immediate,
                             differentialBytes_cmp8_register_immediate);
        testCase.request.state.rcx = 0x1122334455667700ULL;
        run(testCase);
    }
    {
        auto testCase = make("cmp64_memory_register",
                             CaseId::cmp64_memory_register,
                             differentialBytes_cmp64_memory_register);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.rax = 7;
        const std::uint64_t value = 5;
        std::memcpy(testCase.request.memory.data() + 0x30, &value,
                    sizeof(value));
        testCase.memoryCompareOffset = 0x30;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("lock_cmpxchg32_equal",
                             CaseId::lock_cmpxchg32_equal,
                             differentialBytes_lock_cmpxchg32_equal);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0x40);
        testCase.request.state.rax = 0xAAAAAAAA00000000ULL;
        testCase.request.state.rcx = 0xBBBBBBBB12345678ULL;
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = sizeof(std::uint32_t);
        run(testCase);
    }
    {
        auto testCase = make("lock_cmpxchg32_mismatch",
                             CaseId::lock_cmpxchg32_mismatch,
                             differentialBytes_lock_cmpxchg32_mismatch);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0x40);
        testCase.request.state.rax = 0xAAAAAAAA00000000ULL;
        testCase.request.state.rcx = 0xBBBBBBBB12345678ULL;
        constexpr std::uint32_t memoryValue = 0x80000000U;
        std::memcpy(testCase.request.memory.data() + 0x40, &memoryValue,
                    sizeof(memoryValue));
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = sizeof(memoryValue);
        run(testCase);
    }
    {
        auto testCase = make("xchg32_memory", CaseId::xchg32_memory,
                             differentialBytes_xchg32_memory);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0x40);
        testCase.request.state.rdx = 0xAAAAAAAAAABBCCDDULL;
        constexpr std::uint32_t memoryValue = 0x11223344U;
        std::memcpy(testCase.request.memory.data() + 0x40, &memoryValue,
                    sizeof(memoryValue));
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = sizeof(memoryValue);
        run(testCase);
    }
    {
        auto testCase = make("lock_or32_stack_zero",
                             CaseId::lock_or32_stack_zero,
                             differentialBytes_lock_or32_stack_zero);
        testCase.flagMask = logicDefinedFlags;
        testCase.stackCompareOffset = rosa::differential::stackSize - 72;
        testCase.stackCompareSize = sizeof(std::uint32_t);
        run(testCase);
    }
    {
        auto testCase = make("cmp8_scaled_memory", CaseId::cmp8_scaled_memory,
                             differentialBytes_cmp8_scaled_memory);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.rcx = 0x18;
        testCase.request.state.rdx = 0;
        testCase.request.memory[0x18] = 0x80;
        run(testCase);
    }
    {
        auto testCase = make("cmp8_scaled_memory_immediate",
                             CaseId::cmp8_scaled_memory_immediate,
                             differentialBytes_cmp8_scaled_memory_immediate);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.r12 = 0x20;
        testCase.request.memory[0x20] = 0x80;
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("cmp32_rip_memory", CaseId::cmp32_rip_memory,
                             differentialBytes_cmp32_rip_memory);
        run(testCase);
    }
    {
        auto testCase = make("shl64_one", CaseId::shl64_one,
                             differentialBytes_shl64_one);
        testCase.request.state.rax = 0x8000000000000001ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("shl64_masked_zero", CaseId::shl64_masked_zero,
                             differentialBytes_shl64_masked_zero);
        testCase.request.state.rax = 0x55;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("shl32_immediate", CaseId::shl32_immediate,
                             differentialBytes_shl32_immediate);
        testCase.request.state.rdx = 0xAAAAAAAA08000001ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("shl32_immediate_masked_zero",
                             CaseId::shl32_immediate_masked_zero,
                             differentialBytes_shl32_immediate_masked_zero);
        testCase.request.state.rdx = 0xAAAAAAAA12345678ULL;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("shl32_cl_one", CaseId::shl32_cl_one,
                             differentialBytes_shl32_cl_one);
        testCase.request.state.rax = 0xFFFFFFFF80000001ULL;
        testCase.request.state.rcx = 1;
        testCase.flagMask =
            carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("shl32_cl_masked_zero",
                             CaseId::shl32_cl_masked_zero,
                             differentialBytes_shl32_cl_masked_zero);
        testCase.request.state.rax = 0xAAAAAAAA12345678ULL;
        testCase.request.state.rcx = 32;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("shr32_many", CaseId::shr32_many,
                             differentialBytes_shr32_many);
        testCase.request.state.rax = 0xFFFFFFFF80000001ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr64_many", CaseId::shr64_many,
                             differentialBytes_shr64_many);
        testCase.request.state.rax = 0xE000000000000200ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr64_masked_zero", CaseId::shr64_masked_zero,
                             differentialBytes_shr64_masked_zero);
        testCase.request.state.rax = 0xE000000000000200ULL;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("neg64_zero", CaseId::neg64_zero,
                             differentialBytes_neg64_zero);
        testCase.request.state.r13 = 0;
        run(testCase);
    }
    {
        auto testCase = make("neg64_overflow", CaseId::neg64_overflow,
                             differentialBytes_neg64_overflow);
        testCase.request.state.r13 = std::uint64_t{1} << 63U;
        run(testCase);
    }
    {
        auto testCase = make("shrd64_many", CaseId::shrd64_many,
                             differentialBytes_shrd64_many);
        testCase.request.state.rax = 0x0123456789ABCDEFULL;
        testCase.request.state.rdx = 0xFEDCBA9876543210ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("mul64_wide", CaseId::mul64_wide,
                             differentialBytes_mul64_wide);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.rcx = 2;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("imul64_overflow", CaseId::imul64_overflow,
                             differentialBytes_imul64_overflow);
        testCase.request.state.rcx = INT64_MAX;
        testCase.request.state.r13 = 2;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("bsf64_nonzero", CaseId::bsf64_nonzero,
                             differentialBytes_bsf64_nonzero);
        testCase.request.state.rdx = UINT64_MAX;
        testCase.request.state.rcx = std::uint64_t{1} << 40U;
        testCase.flagMask = zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("movzx8_register", CaseId::movzx8_register,
                             differentialBytes_movzx8_register);
        testCase.request.state.rcx = 0xAABBCCDDEEFF00A5ULL;
        testCase.request.state.r13 = UINT64_MAX;
        run(testCase);
    }
    {
        auto testCase = make("movzx8_memory", CaseId::movzx8_memory,
                             differentialBytes_movzx8_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.rcx = UINT64_MAX;
        testCase.request.memory[0x2F] = 0xA5;
        testCase.memoryCompareOffset = 0x2F;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("movzx8_memory64_sib",
                             CaseId::movzx8_memory64_sib,
                             differentialBytes_movzx8_memory64_sib);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.rcx = 0x2F;
        testCase.request.memory[0x2F] = 0xA5;
        testCase.memoryCompareOffset = 0x2F;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("movzx16_register", CaseId::movzx16_register,
                             differentialBytes_movzx16_register);
        testCase.request.state.rdi = 0xAABBCCDDEEFF80A5ULL;
        testCase.request.state.rax = UINT64_MAX;
        run(testCase);
    }
    {
        auto testCase = make("movsxd_scaled_memory", CaseId::movsxd_scaled_memory,
                             differentialBytes_movsxd_scaled_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 16);
        testCase.request.state.rcx = 3;
        const std::int32_t value = -2;
        std::memcpy(testCase.request.memory.data() + 28, &value, sizeof(value));
        testCase.memoryCompareOffset = 28;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("cdqe_negative", CaseId::cdqe_negative,
                             differentialBytes_cdqe_negative);
        testCase.request.state.rax = 0xAAAAAAAA80000001ULL;
        run(testCase);
    }
    {
        auto testCase = make("lea_scaled", CaseId::lea_scaled,
                             differentialBytes_lea_scaled);
        testCase.request.state.rax = 0x1000;
        testCase.request.state.r13 = 0x234;
        run(testCase);
    }
    {
        auto testCase = make("sete_low_byte", CaseId::sete_low_byte,
                             differentialBytes_sete_low_byte);
        testCase.request.state.rax = 0x1122334455667788ULL;
        testCase.request.state.rflags |= zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("setg_extended_taken",
                             CaseId::setg_extended_taken,
                             differentialBytes_setg_extended_taken);
        testCase.request.state.r14 = 0x1122334455667788ULL;
        testCase.request.state.rflags = 0x882;
        run(testCase);
    }
    {
        auto testCase = make("setg_extended_not_taken",
                             CaseId::setg_extended_not_taken,
                             differentialBytes_setg_extended_not_taken);
        testCase.request.state.r14 = 0x1122334455667788ULL;
        testCase.request.state.rflags = 0x802;
        run(testCase);
    }
    {
        auto testCase = make("cmovb64_taken", CaseId::cmovb64_taken,
                             differentialBytes_cmovb64_taken);
        testCase.request.state.rax = 0x1122334455667788ULL;
        testCase.request.state.r13 = UINT64_MAX;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("cmove64_taken", CaseId::cmove64_taken,
                             differentialBytes_cmove64_taken);
        testCase.request.state.rax = 0x1122334455667788ULL;
        testCase.request.state.rcx = UINT64_MAX;
        testCase.request.state.rflags |= zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("cmove64_not_taken", CaseId::cmove64_not_taken,
                             differentialBytes_cmove64_not_taken);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.rcx = 0xAABBCCDDEEFF0011ULL;
        testCase.request.state.rflags &= ~zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("branch_equal_taken", CaseId::branch_equal_taken,
                             differentialBytes_branch_equal_taken);
        testCase.request.state.rax = 42;
        run(testCase);
    }
    {
        auto testCase = make("branch_not_equal_taken", CaseId::branch_not_equal_taken,
                             differentialBytes_branch_not_equal_taken);
        testCase.request.state.rax = 41;
        run(testCase);
    }
    {
        auto testCase = make("branch_below_taken", CaseId::branch_below_taken,
                             differentialBytes_branch_below_taken);
        testCase.request.state.rflags = carryFlag | 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_above_equal_taken",
                             CaseId::branch_above_equal_taken,
                             differentialBytes_branch_above_equal_taken);
        testCase.request.state.rflags = 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_above_not_taken", CaseId::branch_above_not_taken,
                             differentialBytes_branch_above_not_taken);
        testCase.request.state.rflags = zeroFlag | 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_below_equal_taken",
                             CaseId::branch_below_equal_taken,
                             differentialBytes_branch_below_equal_taken);
        testCase.request.state.rflags = zeroFlag | 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_sign_taken", CaseId::branch_sign_taken,
                             differentialBytes_branch_sign_taken);
        testCase.request.state.rflags = signFlag | 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_less_equal_taken",
                             CaseId::branch_less_equal_taken,
                             differentialBytes_branch_less_equal_taken);
        testCase.request.state.rflags = zeroFlag | 0x2;
        run(testCase);
    }
    {
        auto testCase = make("relative_call_stack", CaseId::relative_call_stack,
                             differentialBytes_relative_call_stack);
        testCase.request.state.rcx = 41;
        run(testCase);
    }
    {
        auto testCase = make("indirect_call_memory", CaseId::indirect_call_memory,
                             differentialBytes_indirect_call_memory);
        testCase.request.state.rcx = 41;
        bindMemory(testCase, rosa::x86::Register::R12, 0);
        testCase.request.codePointerMemoryOffset = 0x10;
        testCase.request.codePointerTargetOffset = 6;
        run(testCase);
    }
    {
        auto testCase = make("push_sign_extend", CaseId::push_sign_extend,
                             differentialBytes_push_sign_extend);
        testCase.request.state.rax = 0;
        testCase.stackCompareOffset = rosa::differential::stackSize - 16;
        testCase.stackCompareSize = 8;
        run(testCase);
    }
    {
        auto testCase = make("xorps_register", CaseId::xorps_register,
                             differentialBytes_xorps_register);
        testCase.request.state.xmm[0] = {
            .low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
        testCase.request.state.xmm[1] = {
            .low = 0x1111111111111111ULL, .high = 0x2222222222222222ULL};
        run(testCase);
    }
    {
        auto testCase = make("pxor_register", CaseId::pxor_register,
                             differentialBytes_pxor_register);
        testCase.request.state.xmm[0] = {
            .low = UINT64_MAX, .high = 0x0123456789ABCDEFULL};
        run(testCase);
    }
    {
        auto testCase = make("pmovmskb", CaseId::pmovmskb,
                             differentialBytes_pmovmskb);
        testCase.request.state.rsi = UINT64_MAX;
        testCase.request.state.xmm[0] = {
            .low = 0x8000000000000080ULL, .high = 0x0000000000008000ULL};
        run(testCase);
    }
    {
        auto testCase = make("pshufd", CaseId::pshufd,
                             differentialBytes_pshufd);
        testCase.request.state.xmm[0] = {
            .low = 0x2222222211111111ULL, .high = 0x4444444433333333ULL};
        run(testCase);
    }
    {
        auto testCase = make("mov32_scaled_memory", CaseId::mov32_scaled_memory,
                             differentialBytes_mov32_scaled_memory);
        bindMemory(testCase, rosa::x86::Register::R14, 16);
        testCase.request.state.rbx = 3;
        testCase.request.state.rdx = UINT64_MAX;
        const std::uint32_t value = 0xA5B6C7D8U;
        std::memcpy(testCase.request.memory.data() + 32, &value, sizeof(value));
        testCase.memoryCompareOffset = 32;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("mov8_immediate_memory",
                             CaseId::mov8_immediate_memory,
                             differentialBytes_mov8_immediate_memory);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.memory[0x17] = 0x11;
        testCase.request.memory[0x18] = 0x00;
        testCase.request.memory[0x19] = 0x22;
        testCase.memoryCompareOffset = 0x17;
        testCase.memoryCompareSize = 3;
        run(testCase);
    }
    {
        auto testCase = make("mov8_scaled_memory", CaseId::mov8_scaled_memory,
                             differentialBytes_mov8_scaled_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.rcx = 0x18;
        testCase.request.state.rdx = 0x1122334455667788ULL;
        testCase.request.memory[0x18] = 0xA5;
        testCase.memoryCompareOffset = 0x18;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("mov8_rip_memory", CaseId::mov8_rip_memory,
                             differentialBytes_mov8_rip_memory);
        testCase.request.state.rax = 0x1122334455667788ULL;
        run(testCase);
    }
    {
        auto testCase = make("mov8_register_memory",
                             CaseId::mov8_register_memory,
                             differentialBytes_mov8_register_memory);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.rax = 0x11223344556677A5ULL;
        testCase.request.memory[0x17] = 0x11;
        testCase.request.memory[0x18] = 0x00;
        testCase.request.memory[0x19] = 0x22;
        testCase.memoryCompareOffset = 0x17;
        testCase.memoryCompareSize = 3;
        run(testCase);
    }
    {
        auto testCase = make("mov8_extended_scaled_store",
                             CaseId::mov8_extended_scaled_store,
                             differentialBytes_mov8_extended_scaled_store);
        bindMemory(testCase, rosa::x86::Register::R8, 0);
        testCase.request.state.rcx = 0x20;
        testCase.request.state.r11 = 0x11223344556677A5ULL;
        testCase.request.memory[0x21] = 0x11;
        testCase.request.memory[0x22] = 0;
        testCase.request.memory[0x23] = 0x22;
        testCase.memoryCompareOffset = 0x21;
        testCase.memoryCompareSize = 3;
        run(testCase);
    }
    {
        auto testCase = make("mov64_scaled_store",
                             CaseId::mov64_scaled_store,
                             differentialBytes_mov64_scaled_store);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rdx = 0x20;
        testCase.request.state.rsi = 0x0123456789ABCDEFULL;
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = sizeof(std::uint64_t);
        run(testCase);
    }
    {
        auto testCase = make("mov32_immediate_memory",
                             CaseId::mov32_immediate_memory,
                             differentialBytes_mov32_immediate_memory);
        bindMemory(testCase, rosa::x86::Register::Rbp, 0x80);
        const std::array sentinel{
            std::uint8_t{0x88}, std::uint8_t{0x77}, std::uint8_t{0x66},
            std::uint8_t{0x55}, std::uint8_t{0x44}, std::uint8_t{0x33},
            std::uint8_t{0x22}, std::uint8_t{0x11}};
        std::ranges::copy(sentinel, testCase.request.memory.begin() + 0x1F);
        testCase.memoryCompareOffset = 0x1F;
        testCase.memoryCompareSize = sentinel.size();
        run(testCase);
    }
    {
        auto testCase = make("mov64_immediate_memory",
                             CaseId::mov64_immediate_memory,
                             differentialBytes_mov64_immediate_memory);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        const std::array sentinel{
            std::uint8_t{0x88}, std::uint8_t{0x77}, std::uint8_t{0x66},
            std::uint8_t{0x55}, std::uint8_t{0x44}, std::uint8_t{0x33},
            std::uint8_t{0x22}, std::uint8_t{0x11}};
        std::ranges::copy(sentinel, testCase.request.memory.begin() + 0x18);
        testCase.memoryCompareOffset = 0x18;
        testCase.memoryCompareSize = sentinel.size();
        run(testCase);
    }
    {
        auto testCase = make("add64_memory", CaseId::add64_memory,
                             differentialBytes_add64_memory);
        bindMemory(testCase, rosa::x86::Register::Rsi, 0);
        testCase.request.state.rax = UINT64_MAX - 2;
        const std::uint64_t value = 7;
        std::memcpy(testCase.request.memory.data() + 16, &value, sizeof(value));
        testCase.memoryCompareOffset = 16;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("inc16_memory", CaseId::inc16_memory,
                             differentialBytes_inc16_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.rflags |= carryFlag;
        const std::uint16_t value = 0x7FFF;
        std::memcpy(testCase.request.memory.data() + 24, &value, sizeof(value));
        testCase.memoryCompareOffset = 24;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("inc64_memory", CaseId::inc64_memory,
                             differentialBytes_inc64_memory);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.rflags |= carryFlag;
        const std::uint64_t value = INT64_MAX;
        std::memcpy(testCase.request.memory.data() + 24, &value, sizeof(value));
        testCase.memoryCompareOffset = 24;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("xor64_memory", CaseId::xor64_memory,
                             differentialBytes_xor64_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.rcx = 0x44454B4E494C5F5FULL;
        const std::uint64_t value = 0x44454B4E494C5F5FULL;
        std::memcpy(testCase.request.memory.data(), &value, sizeof(value));
        testCase.flagMask = logicDefinedFlags;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("hot_pointer_transform", CaseId::hot_pointer_transform,
                             differentialBytes_hot_pointer_transform);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        const std::uint64_t value = 0x123456789ABCDEF0ULL;
        std::memcpy(testCase.request.memory.data(), &value, sizeof(value));
        testCase.flagMask = logicDefinedFlags;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movaps_load", CaseId::movaps_load,
                             differentialBytes_movaps_load);
        bindMemory(testCase, rosa::x86::Register::Rbp, 32);
        const std::array<std::uint64_t, 2> value{
            0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
        std::memcpy(testCase.request.memory.data(), value.data(), sizeof(value));
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movaps_store", CaseId::movaps_store,
                             differentialBytes_movaps_store);
        bindMemory(testCase, rosa::x86::Register::Rbp, 32);
        testCase.request.state.xmm[0] = {
            .low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
        testCase.memoryCompareSize = 16;
        run(testCase);
    }
    {
        auto testCase = make("movups_scaled_store",
                             CaseId::movups_scaled_store,
                             differentialBytes_movups_scaled_store);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rdx = 0x20;
        testCase.request.state.xmm[0] = {
            .low = 0x0123456789ABCDEFULL,
            .high = 0xFEDCBA9876543210ULL};
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = 16;
        run(testCase);
    }
    {
        auto testCase = make("movups_load", CaseId::movups_load,
                             differentialBytes_movups_load);
        bindMemory(testCase, rosa::x86::Register::R15, 3);
        const std::array<std::uint64_t, 2> value{
            0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
        std::memcpy(testCase.request.memory.data() + 27, value.data(), sizeof(value));
        testCase.memoryCompareOffset = 27;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("pcmpeqb_memory", CaseId::pcmpeqb_memory,
                             differentialBytes_pcmpeqb_memory);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        constexpr std::array<std::uint8_t, 16> value{
            1, 0, 2, 0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
        std::ranges::copy(value, testCase.request.memory.begin());
        testCase.memoryCompareSize = value.size();
        run(testCase);
    }
    {
        auto testCase = make("movdqa_load", CaseId::movdqa_load,
                             differentialBytes_movdqa_load);
        bindMemory(testCase, rosa::x86::Register::Rbp, 32);
        const std::array<std::uint64_t, 2> value{
            0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
        std::memcpy(testCase.request.memory.data(), value.data(), sizeof(value));
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movdqu_load", CaseId::movdqu_load,
                             differentialBytes_movdqu_load);
        bindMemory(testCase, rosa::x86::Register::R15, 3);
        const std::array<std::uint64_t, 2> value{
            0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
        std::memcpy(testCase.request.memory.data() + 43, value.data(), sizeof(value));
        testCase.memoryCompareOffset = 43;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movq_store", CaseId::movq_store,
                             differentialBytes_movq_store);
        bindMemory(testCase, rosa::x86::Register::Rsi, 3);
        testCase.request.state.xmm[0] = {
            .low = 0x0123456789ABCDEFULL, .high = 0xFEDCBA9876543210ULL};
        testCase.memoryCompareOffset = 35;
        testCase.memoryCompareSize = 8;
        run(testCase);
    }

    expectEqual(compared, static_cast<std::size_t>(CaseId::Count),
                "not every differential case was executed");
}

#endif

void testAssemblerEncodings() {
    rosa::arm64::Assembler assembler;
    assembler.movImmediate(rosa::arm64::x0, 42);
    assembler.add(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.lslImmediate(rosa::arm64::x10, rosa::arm64::x9, 32);
    assembler.lsrImmediate(rosa::arm64::x10, rosa::arm64::x9, 31);
    assembler.lslVariable(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.multiplyLow(rosa::arm64::x11, rosa::arm64::x9, rosa::arm64::x10);
    assembler.multiplyHighUnsigned(rosa::arm64::x12, rosa::arm64::x9,
                                   rosa::arm64::x10);
    assembler.extract(rosa::arm64::x11, rosa::arm64::x10, rosa::arm64::x9, 32);
    assembler.bitAnd(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.bitOr(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
    assembler.bitXor(rosa::arm64::x10, rosa::arm64::x9, rosa::arm64::x11);
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

    const std::array<std::uint32_t, 21> expected{
        0xD2800540U, 0x8B0B012AU, 0xD3607D2AU, 0xD35FFD2AU, 0x9ACB212AU,
        0x9B0A7D2BU, 0x9BCA7D2CU, 0x93C9814BU, 0x8A0B012AU, 0xAA0B012AU,
        0xCA0B012AU, 0x93407D2AU, 0xF9400009U, 0xB9400009U, 0xF9000009U, 0xD63F0200U,
        0xA9BF7BFDU, 0xA8C17BFDU, 0xD5033BBFU, 0xD5033FDFU, 0xD65F03C0U,
    };
    expectEqual(assembler.words().size(), expected.size(), "assembler word count differs");
    for (std::size_t index = 0; index < expected.size(); ++index) {
        expectEqual(assembler.words()[index], expected[index], "ARM64 encoding differs");
    }
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

constexpr std::array<std::uint8_t, 15> r1Code{
    0x48, 0xB8, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC0, 0x02, 0xC3,
};

void testDecoderR1() {
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(r1Code, rosa::guest::GuestAddress{0x1000});
    expectEqual(decoded.size(), std::size_t{3}, "decoder instruction count differs");
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegImm, "first opcode is not mov");
    expect(decoded[1].opcode == rosa::x86::Opcode::AddRegImm, "second opcode is not add");
    expect(decoded[2].opcode == rosa::x86::Opcode::Ret, "third opcode is not ret");
    expectEqual(decoded[0].length, std::uint8_t{10}, "mov length differs");
    expectEqual(decoded[1].length, std::uint8_t{4}, "add length differs");
    expectEqual(decoded[2].address.value, std::uint64_t{0x100E}, "ret RIP differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "mov destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{40}, "mov immediate differs");
}

void testDecoderExtendedRegisterAndSignedImmediate() {
    constexpr std::array<std::uint8_t, 15> code{
        0x49, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x83, 0xC0, 0xFF, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0});
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::R8,
           "REX.B mov register differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[1].operands[1]).value, UINT64_MAX,
                "imm8 was not sign-extended");
}

void testLegacyMov32ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0xBF, 0x34, 0x00, 0x07, 0x1F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegImm,
           "legacy MOV r32, imm32 opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rdi,
           "legacy MOV r32 destination differs");
    expectEqual(destination.width, std::uint8_t{32}, "legacy MOV r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x1F070034},
                "legacy MOV r32 did not clear the upper half");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "legacy MOV r32 changed flags");
}

void testLegacyMovLowByteImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0xB1, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegImm,
           "MOV low byte, imm8 opcode differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rcx,
           "MOV CL, imm8 register differs");
    expectEqual(operand.width, std::uint8_t{8}, "MOV CL, imm8 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0xAABBCCDDEEFF0080ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xAABBCCDDEEFF0001ULL},
                "MOV CL, imm8 did not preserve upper register bits");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV CL, imm8 changed flags");
}

void testRexExtendedMov32ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 7> code{
        0x41, 0xBD, 0x20, 0x00, 0x00, 0x00, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegImm,
           "REX MOV r32, imm32 opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::R13,
           "REX MOV r32 destination differs");
    expectEqual(destination.width, std::uint8_t{32}, "REX MOV r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r13 = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r13, std::uint64_t{0x20},
                "REX MOV r32 did not clear the upper half");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "REX MOV r32 changed flags");
}

void testDecoderPushImm8() {
    constexpr std::array<std::uint8_t, 3> positive{0x6A, 0x7F, 0xC3};
    constexpr std::array<std::uint8_t, 3> negative{0x6A, 0x80, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto positiveDecoded =
        decoder.decodeBlock(positive, rosa::guest::GuestAddress{0x1000});
    const auto negativeDecoded =
        decoder.decodeBlock(negative, rosa::guest::GuestAddress{0x2000});
    expect(positiveDecoded[0].opcode == rosa::x86::Opcode::Push,
           "positive PUSH imm8 opcode differs");
    expectEqual(positiveDecoded[0].length, std::uint8_t{2}, "PUSH imm8 length differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(positiveDecoded[0].operands[0]).value,
                std::uint64_t{0x7F}, "positive PUSH imm8 value differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(negativeDecoded[0].operands[0]).value,
                std::uint64_t{0xFFFFFFFFFFFFFF80ULL},
                "negative PUSH imm8 was not sign-extended to 64 bits");
}

std::pair<rosa::x86::X86State, std::uint64_t> executePushImm8(std::uint8_t immediate) {
    const std::array<std::uint8_t, 3> code{0x6A, immediate, 0xC3};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rip = 0x1000;
    state.rsp = stackTop;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    return {state, addressSpace.readU64(rosa::guest::GuestAddress{stackTop - 8})};
}

void testPushImm8GeneratedExecution() {
    const auto [positiveState, positiveValue] = executePushImm8(0x7F);
    expectEqual(positiveState.rsp, std::uint64_t{0x700000000FF8ULL},
                "positive PUSH imm8 did not decrement RSP by 8");
    expectEqual(positiveValue, std::uint64_t{0x7F},
                "positive PUSH imm8 did not store a 64-bit guest value");
    expectEqual(positiveState.rflags, std::uint64_t{0xAD7},
                "positive PUSH imm8 changed guest flags");

    const auto [negativeState, negativeValue] = executePushImm8(0x80);
    expectEqual(negativeState.rsp, std::uint64_t{0x700000000FF8ULL},
                "negative PUSH imm8 did not decrement RSP by 8");
    expectEqual(negativeValue, std::uint64_t{0xFFFFFFFFFFFFFF80ULL},
                "negative PUSH imm8 did not store the sign-extended 64-bit value");
    expectEqual(negativeState.rflags, std::uint64_t{0xAD7},
                "negative PUSH imm8 changed guest flags");
}

void testPushImm8GuestStackFaults() {
    constexpr std::array<std::uint8_t, 3> code{0x6A, 0xFF, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State unmappedState;
    unmappedState.rip = 0x1000;
    unmappedState.rsp = 0x9000;
    unmappedState.rflags = 0x202;
    bool unmappedRejected = false;
    try {
        static_cast<void>(block.execute(unmappedState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        unmappedRejected = std::string_view(error.what()).find("unmapped") !=
                           std::string_view::npos;
    }
    expect(unmappedRejected, "PUSH imm8 to an unmapped guest stack did not fail");
    expectEqual(unmappedState.rsp, std::uint64_t{0x9000},
                "failed unmapped PUSH imm8 changed RSP");
    expectEqual(unmappedState.rflags, std::uint64_t{0x202},
                "failed unmapped PUSH imm8 changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                                      rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    rosa::x86::X86State readOnlyState;
    readOnlyState.rip = 0x1000;
    readOnlyState.rsp = 0x9000;
    bool readOnlyRejected = false;
    try {
        static_cast<void>(block.execute(readOnlyState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        readOnlyRejected = std::string_view(error.what()).find("permissions") !=
                           std::string_view::npos;
    }
    expect(readOnlyRejected, "PUSH imm8 to a read-only guest stack did not fail");
    expectEqual(readOnlyState.rsp, std::uint64_t{0x9000},
                "failed read-only PUSH imm8 changed RSP");
}

void testPushRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x55, 0x41, 0x57, 0xC3};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Push, "PUSH rbp opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rbp,
           "PUSH rbp register differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[1].operands[0]).reg ==
               rosa::x86::Register::R15,
           "REX PUSH r15 register differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto pushRbp = translator.translate(code, rosa::guest::GuestAddress{0x1000}, 1);
    const auto pushR15 = translator.translate(std::span(code).subspan(1),
                                              rosa::guest::GuestAddress{0x1001}, 1);
    rosa::x86::X86State state;
    state.rip = 0x1000;
    state.rsp = stackTop;
    state.rbp = 0x0123456789ABCDEFULL;
    state.r15 = 0xFEDCBA9876543210ULL;
    state.rflags = 0x8D7;
    static_cast<void>(pushRbp.execute(state, &addressSpace));
    static_cast<void>(pushR15.execute(state, &addressSpace));
    expectEqual(state.rsp, stackTop - 16, "two register PUSHes did not update RSP");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{stackTop - 8}), state.rbp,
                "PUSH rbp stored the wrong guest value");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{stackTop - 16}), state.r15,
                "PUSH r15 stored the wrong guest value");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "register PUSH changed guest flags");
}

void testPopRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 2> popRbpCode{0x5D, 0xC3};
    constexpr std::array<std::uint8_t, 2> popRspCode{0x5C, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(popRbpCode, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Pop, "POP r64 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rbp,
           "POP rbp destination differs");

    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackBase.value + 0x100},
                          0x0123456789ABCDEFULL);
    const rosa::dbt::Translator translator;
    const auto popRbp = translator.translate(popRbpCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsp = stackBase.value + 0x100;
    state.rbp = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(popRbp.execute(state, &addressSpace));
    expectEqual(state.rbp, std::uint64_t{0x0123456789ABCDEFULL},
                "POP rbp loaded the wrong value");
    expectEqual(state.rsp, stackBase.value + 0x108, "POP rbp RSP update differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "POP rbp changed flags");

    addressSpace.writeU64(rosa::guest::GuestAddress{stackBase.value + 0x200}, 0x1234);
    const auto popRsp = translator.translate(popRspCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State rspState;
    rspState.rsp = stackBase.value + 0x200;
    static_cast<void>(popRsp.execute(rspState, &addressSpace));
    expectEqual(rspState.rsp, std::uint64_t{0x1234},
                "POP rsp did not apply the destination write last");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rsp = stackBase.value + 0x100;
    faultState.rbp = 0x55;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(popRbp.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "POP from unmapped guest stack did not fail");
    expectEqual(faultState.rsp, stackBase.value + 0x100,
                "failed POP changed RSP");
    expectEqual(faultState.rbp, std::uint64_t{0x55},
                "failed POP changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed POP changed flags");
}

void testSubRegImm32GeneratedExecution() {
    constexpr std::array<std::uint8_t, 8> positive{
        0x48, 0x81, 0xEC, 0x58, 0x06, 0x00, 0x00, 0xC3,
    };
    constexpr std::array<std::uint8_t, 8> negative{
        0x49, 0x81, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(positive, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegImm,
           "SUB r64, imm32 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rsp,
           "SUB r64, imm32 destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0x658}, "SUB r64, imm32 immediate differs");

    const rosa::dbt::Translator translator;
    const auto positiveBlock = translator.translate(positive, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State positiveState;
    positiveState.rsp = 0x1000;
    static_cast<void>(positiveBlock.execute(positiveState));
    expectEqual(positiveState.rsp, std::uint64_t{0x9A8},
                "SUB rsp, positive imm32 result differs");
    expectEqual(positiveState.rflags, std::uint64_t{0x12},
                "SUB rsp, positive imm32 flags differ");

    const auto negativeBlock = translator.translate(negative, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State negativeState;
    negativeState.r8 = 41;
    static_cast<void>(negativeBlock.execute(negativeState));
    expectEqual(negativeState.r8, std::uint64_t{42},
                "SUB r8, negative imm32 did not use sign extension");
    expectEqual(negativeState.rflags, std::uint64_t{0x13},
                "SUB r8, negative imm32 flags differ");
}

void testSubRegImm8GeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x83, 0xEC, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegImm,
           "SUB r64, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0x18}, "SUB r64, imm8 immediate differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsp = 0x100;
    static_cast<void>(block.execute(state));
    expectEqual(state.rsp, std::uint64_t{0xE8}, "SUB rsp, imm8 result differs");
    expectEqual(state.rflags, std::uint64_t{0x16}, "SUB rsp, imm8 flags differ");
}

void testSubRegisterFromRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x29, 0xD7, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegReg,
           "SUB r64, r64 opcode differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0x1028;
    state.rdx = 0x1000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x28}, "SUB r64, r64 result differs");
    expectEqual(state.rdx, std::uint64_t{0x1000}, "SUB r64, r64 changed source");
    expectEqual(state.rflags, std::uint64_t{0x6}, "SUB r64, r64 flags differ");
}

void testSubRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x2B, 0x06, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegMem,
           "SUB r64, [base] opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "SUB r64, [base] destination differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsi,
           "SUB r64, [base] base differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8100}, 7);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 5;
    state.rsi = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{UINT64_MAX - 1},
                "SUB r64, [base] result differs");
    expectEqual(state.rsi, std::uint64_t{0x8100},
                "SUB r64, [base] changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x93},
                "SUB r64, [base] flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 5;
    faultState.rsi = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "SUB from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{5},
                "failed memory SUB changed its destination register");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed memory SUB changed flags");
}

void testSub32BitRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x2B, 0x56, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SubRegMem,
           "SUB r32, [base+disp8] opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 32,
           "SUB EDX, [base+disp8] destination differs");
    expect(memory.base == rosa::x86::Register::Rsi &&
               memory.displacement == 0x18 && memory.width == 32,
           "SUB EDX, [RSI+disp8] memory operand differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 8> sourceWithUpperSentinel{
        7, 0, 0, 0, 0xEF, 0xBE, 0xAD, 0xDE};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8118},
                            sourceWithUpperSentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0xA5A5A5A500000005ULL;
    state.rsi = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdx, std::uint64_t{0xFFFFFFFE},
                "SUB r32, [memory] result did not zero-extend");
    expectEqual(state.rflags, std::uint64_t{0x93},
                "SUB r32, [memory] flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rdx = 0xA5A5A5A500000005ULL;
    state.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "SUB r32 from unmapped guest memory did not fail");
    expectEqual(state.rdx, std::uint64_t{0xA5A5A5A500000005ULL},
                "failed SUB r32 changed its destination");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "failed SUB r32 changed flags");
}

void testAddRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x03, 0x46, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegMem,
           "ADD r64, [base+disp8] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsi,
           "ADD r64, [base+disp8] base differs");
    expectEqual(memory.displacement, std::int64_t{0x10},
                "ADD r64, [base+disp8] displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8110}, 7);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = UINT64_MAX - 2;
    state.rsi = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{4}, "ADD r64, [base+disp8] result differs");
    expectEqual(state.rflags, std::uint64_t{0x13},
                "ADD r64, [base+disp8] flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 9;
    faultState.rsi = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "ADD from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{9},
                "failed memory ADD changed its destination register");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed memory ADD changed flags");
}

void testAddRegisterToRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x49, 0x01, 0xDD, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegReg,
           "ADD r64, r64 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::R13,
           "ADD r64, r64 extended destination differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::Register::Rbx,
           "ADD r64, r64 source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r13 = UINT64_MAX;
    state.rbx = 2;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r13, std::uint64_t{1}, "ADD r64, r64 result differs");
    expectEqual(state.rbx, std::uint64_t{2}, "ADD r64, r64 changed its source");
    expectEqual(state.rflags, std::uint64_t{0x13}, "ADD r64, r64 flags differ");
}

void testAddLowByteRegisters() {
    constexpr std::array<std::uint8_t, 4> code{0x44, 0x00, 0xCE, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegReg,
           "ADD r8, r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3},
                "ADD r8, r8 length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi &&
               destination.width == 8,
           "ADD r8, r8 destination differs");
    expect(source.reg == rosa::x86::Register::R9 && source.width == 8,
           "ADD r8, r8 source differs");
    expect(rosa::debug::dumpX86(decoded).find("add sil, r9b") !=
               std::string::npos,
           "ADD r8, r8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.rsi = 0x112233445566777FULL;
    overflowState.r9 = 0x8877665544332201ULL;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.rsi, std::uint64_t{0x1122334455667780ULL},
                "ADD r8, r8 did not preserve upper destination bits");
    expectEqual(overflowState.r9, std::uint64_t{0x8877665544332201ULL},
                "ADD r8, r8 changed its source");
    expectEqual(overflowState.rflags, std::uint64_t{0x892},
                "ADD r8 signed-overflow flags differ");

    rosa::x86::X86State carryState;
    carryState.rsi = 0xAABBCCDDEEFF00FFULL;
    carryState.r9 = 0x1020304050607001ULL;
    carryState.rflags = 0x802;
    static_cast<void>(block.execute(carryState));
    expectEqual(carryState.rsi, std::uint64_t{0xAABBCCDDEEFF0000ULL},
                "ADD r8 carry result differs");
    expectEqual(carryState.rflags, std::uint64_t{0x57},
                "ADD r8 carry flags differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0x00, 0xCE, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "ADD silently represented legacy DH as SIL");
}

void testAddGuestByteToLowRegister() {
    constexpr std::array<std::uint8_t, 5> code{
        0x41, 0x02, 0x34, 0x3A, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegMem,
           "ADD r8, byte [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4},
                "ADD r8, byte [memory] length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rsi &&
               destination.width == 8,
           "ADD r8, byte [memory] destination differs");
    expect(memory.base == rosa::x86::Register::R10 &&
               memory.index == rosa::x86::Register::Rdi &&
               memory.scale == 1 && memory.displacement == 0 &&
               memory.width == 8,
           "ADD r8, byte [memory] effective address differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "add sil, [r10+rdi*1]") != std::string::npos,
           "ADD r8, byte [memory] dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> value{1};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8018}, value);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r10 = memoryBase.value;
    state.rdi = 0x18;
    state.rsi = 0x112233445566777FULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rsi, std::uint64_t{0x1122334455667780ULL},
                "ADD guest byte did not preserve upper RSI bits");
    expectEqual(state.r10, memoryBase.value,
                "ADD guest byte changed its base register");
    expectEqual(state.rdi, std::uint64_t{0x18},
                "ADD guest byte changed its index register");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0x8018}, 1)[0],
                std::uint8_t{1}, "ADD guest byte changed memory");
    expectEqual(state.rflags, std::uint64_t{0x892},
                "ADD guest byte flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r10 = memoryBase.value;
    faultState.rdi = 0x18;
    faultState.rsi = 0x887766554433227FULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "ADD from unmapped guest byte did not fault");
    expectEqual(faultState.rsi, std::uint64_t{0x887766554433227FULL},
                "faulted ADD guest byte changed destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted ADD guest byte changed flags");
}

void testAddImmediateToLowByte() {
    constexpr std::array<std::uint8_t, 4> code{0x80, 0xC2, 0x04, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegImm,
           "ADD r8, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3},
                "ADD r8, imm8 length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate =
        std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx &&
               destination.width == 8,
           "ADD DL, imm8 destination differs");
    expect(immediate.width == 8 && immediate.value == 4,
           "ADD DL, imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("add dl, 0x4") !=
               std::string::npos,
           "ADD DL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.rdx = 0x112233445566777CULL;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.rdx, std::uint64_t{0x1122334455667780ULL},
                "ADD DL, imm8 did not preserve upper RDX bits");
    expectEqual(overflowState.rflags, std::uint64_t{0x892},
                "ADD DL, imm8 overflow flags differ");

    rosa::x86::X86State carryState;
    carryState.rdx = 0x88776655443322FDULL;
    carryState.rflags = 0x8D7;
    static_cast<void>(block.execute(carryState));
    expectEqual(carryState.rdx, std::uint64_t{0x8877665544332201ULL},
                "ADD DL, imm8 carry result differs");
    expectEqual(carryState.rflags, std::uint64_t{0x13},
                "ADD DL, imm8 carry flags differ");

    constexpr std::array<std::uint8_t, 4> highByteCode{
        0x80, 0xC4, 0x01, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "ADD silently represented legacy AH as SPL");
}

void testIncrement32BitRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x41, 0xFF, 0xC7, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::IncReg,
           "INC r32 opcode differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::R15,
           "INC extended register differs");
    expectEqual(operand.width, std::uint8_t{32}, "INC r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.r15 = 0xAAAAAAAA7FFFFFFFULL;
    overflowState.rflags = 0x8D7 | 1U;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.r15, std::uint64_t{0x80000000},
                "INC r32 did not zero-extend its result");
    expectEqual(overflowState.rflags, std::uint64_t{0x897},
                "INC r32 overflow flags differ or CF was not preserved");

    rosa::x86::X86State zeroState;
    zeroState.r15 = UINT64_MAX;
    zeroState.rflags = 0x8D6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.r15, std::uint64_t{0}, "INC r32 wrapped result differs");
    expectEqual(zeroState.rflags, std::uint64_t{0x56},
                "INC r32 zero flags differ or CF was not preserved");
}

void testIncrementLowByteRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x41, 0xFE, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::IncReg,
           "INC r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3},
                "INC r8 length differs");
    const auto operand =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::R8 && operand.width == 8,
           "INC r8 operand differs");
    expect(rosa::debug::dumpX86(decoded).find("inc r8b") !=
               std::string::npos,
           "INC r8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.r8 = 0x112233445566777FULL;
    overflowState.rflags = 0x203;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.r8, std::uint64_t{0x1122334455667780ULL},
                "INC r8 did not preserve upper register bits");
    expectEqual(overflowState.rflags, std::uint64_t{0xA93},
                "INC r8 overflow flags or preserved CF differ");

    rosa::x86::X86State wrapState;
    wrapState.r8 = 0x88776655443322FFULL;
    wrapState.rflags = 0x202;
    static_cast<void>(block.execute(wrapState));
    expectEqual(wrapState.r8, std::uint64_t{0x8877665544332200ULL},
                "INC r8 wrap result differs");
    expectEqual(wrapState.rflags, std::uint64_t{0x256},
                "INC r8 wrap flags or preserved CF differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0xFE, 0xC4, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "INC silently represented legacy AH as SPL");
}

void testDecrement32BitRegister() {
    constexpr std::array<std::uint8_t, 3> code{0xFF, 0xCF, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::DecReg,
           "DEC r32 opcode differs");
    const auto operand =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rdi && operand.width == 32,
           "DEC EDI operand differs");
    expect(rosa::debug::dumpX86(decoded).find("dec edi") != std::string::npos,
           "DEC EDI dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 6;
    state.rflags = 1;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{5}, "DEC EDI result differs");
    expectEqual(state.rflags, std::uint64_t{0x7},
                "DEC EDI flags differ or CF was not preserved");

    state.rdi = 0xAAAAAAAA00000001ULL;
    state.rflags = 0;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0},
                "DEC EDI zero result did not clear upper bits");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "DEC EDI zero flags differ");

    state.rdi = 0xBBBBBBBB80000000ULL;
    state.rflags = 1;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0x7FFFFFFF},
                "DEC EDI overflow result differs");
    expectEqual(state.rflags, std::uint64_t{0x817},
                "DEC EDI overflow flags differ or CF was not preserved");
}

void testDecrementLowByteRegister() {
    constexpr std::array<std::uint8_t, 3> code{0xFE, 0xC8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::DecReg,
           "DEC r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2},
                "DEC r8 length differs");
    const auto operand =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rax && operand.width == 8,
           "DEC AL operand differs");
    expect(rosa::debug::dumpX86(decoded).find("dec al") !=
               std::string::npos,
           "DEC AL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.rax = 0x1122334455667780ULL;
    overflowState.rflags = 0x203;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.rax, std::uint64_t{0x112233445566777FULL},
                "DEC AL did not preserve upper RAX bits");
    expectEqual(overflowState.rflags, std::uint64_t{0xA13},
                "DEC AL overflow flags or preserved CF differ");

    rosa::x86::X86State wrapState;
    wrapState.rax = 0x8877665544332200ULL;
    wrapState.rflags = 0x203;
    static_cast<void>(block.execute(wrapState));
    expectEqual(wrapState.rax, std::uint64_t{0x88776655443322FFULL},
                "DEC AL wrap result differs");
    expectEqual(wrapState.rflags, std::uint64_t{0x297},
                "DEC AL wrap flags or preserved CF differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0xFE, 0xCC, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "DEC silently represented legacy AH as SPL");
}

void testIncrement16BitGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{
        0x66, 0xFF, 0x40, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::IncMem,
           "INC word [memory] opcode differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8100;
    state.rflags = 0x3;
    const std::array overflowValue{std::uint8_t{0xFF}, std::uint8_t{0x7F}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8118}, overflowValue);
    static_cast<void>(block.execute(state, &addressSpace));
    const auto overflowResult =
        addressSpace.readBytes(rosa::guest::GuestAddress{0x8118}, 2);
    expectEqual(overflowResult[0], std::uint8_t{0x00},
                "INC word overflow low byte differs");
    expectEqual(overflowResult[1], std::uint8_t{0x80},
                "INC word overflow high byte differs");
    expectEqual(state.rflags, std::uint64_t{0x897},
                "INC word overflow flags differ or CF changed");

    const std::array wrapValue{std::uint8_t{0xFF}, std::uint8_t{0xFF}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8118}, wrapValue);
    state.rflags = 0x2;
    static_cast<void>(block.execute(state, &addressSpace));
    const auto wrapResult =
        addressSpace.readBytes(rosa::guest::GuestAddress{0x8118}, 2);
    expectEqual(wrapResult[0], std::uint8_t{0}, "INC word wrap low byte differs");
    expectEqual(wrapResult[1], std::uint8_t{0}, "INC word wrap high byte differs");
    expectEqual(state.rflags, std::uint64_t{0x56},
                "INC word wrap flags differ or CF changed");

    std::array<std::uint8_t, 0x1A> readOnlyBytes{};
    readOnlyBytes[0x18] = 0x34;
    readOnlyBytes[0x19] = 0x12;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(
        rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read, readOnlyBytes, "read-only increment test");
    state.rax = 0x9000;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "INC word on read-only guest memory did not fault");
    const auto unchanged =
        readOnlyAddressSpace.readBytes(rosa::guest::GuestAddress{0x9018}, 2);
    expectEqual(unchanged[0], std::uint8_t{0x34},
                "failed INC word changed low memory byte");
    expectEqual(unchanged[1], std::uint8_t{0x12},
                "failed INC word changed high memory byte");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "failed INC word changed flags");
}

void testIncrement64BitGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{
        0x49, 0xFF, 0x46, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::IncMem,
           "INC qword [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4},
                "INC qword [memory] length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::R14,
           "INC qword [memory] base differs");
    expectEqual(memory.displacement, std::int64_t{0x18},
                "INC qword [memory] displacement differs");
    expectEqual(memory.width, std::uint8_t{64},
                "INC qword [memory] width differs");
    expect(rosa::debug::dumpX86(decoded).find("inc qword [r14+0x18]") !=
               std::string::npos,
           "INC qword [memory] dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0x8100;
    state.rflags = 0x3;
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8118}, INT64_MAX);
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8118}),
                std::uint64_t{0x8000000000000000ULL},
                "INC qword overflow result differs");
    expectEqual(state.r14, std::uint64_t{0x8100},
                "INC qword changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x897},
                "INC qword overflow flags differ or CF changed");

    addressSpace.writeU64(rosa::guest::GuestAddress{0x8118}, UINT64_MAX);
    state.rflags = 0x2;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8118}),
                std::uint64_t{0}, "INC qword wrap result differs");
    expectEqual(state.rflags, std::uint64_t{0x56},
                "INC qword wrap flags differ or CF changed");

    std::array<std::uint8_t, 0x20> readOnlyBytes{};
    const std::uint64_t sentinel = 0x0123456789ABCDEFULL;
    std::memcpy(readOnlyBytes.data() + 0x18, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(
        rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read, readOnlyBytes,
        "read-only qword increment test");
    state.r14 = 0x9000;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "INC qword on read-only guest memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(rosa::guest::GuestAddress{0x9018}),
                sentinel, "failed INC qword changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "failed INC qword changed flags");
}

void testDecrement64BitGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0xFF, 0x4B, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::DecMem,
           "DEC qword memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4},
                "DEC qword memory length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rbx &&
               memory.displacement == 0x18 && memory.width == 64,
           "DEC qword [rbx+0x18] operand differs");
    expect(rosa::debug::dumpX86(decoded).find("dec qword [rbx+0x18]") !=
               std::string::npos,
           "DEC qword memory dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8000;
    state.rflags = 0x3;
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8018},
                          std::uint64_t{1} << 63U);
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8018}),
                std::uint64_t{0x7FFFFFFFFFFFFFFFULL},
                "DEC qword overflow result differs");
    expectEqual(state.rbx, std::uint64_t{0x8000},
                "DEC qword changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x817},
                "DEC qword overflow flags differ or CF changed");

    addressSpace.writeU64(rosa::guest::GuestAddress{0x8018}, 0);
    state.rflags = 0x2;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8018}),
                UINT64_MAX, "DEC qword wrap result differs");
    expectEqual(state.rflags, std::uint64_t{0x96},
                "DEC qword wrap flags differ or CF changed");

    std::array<std::uint8_t, 0x20> readOnlyBytes{};
    constexpr std::uint64_t sentinel = 7;
    std::memcpy(readOnlyBytes.data() + 0x18, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(
        rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read, readOnlyBytes,
        "read-only qword decrement test");
    rosa::x86::X86State faultState;
    faultState.rbx = 0x9000;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "DEC qword on read-only guest memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(rosa::guest::GuestAddress{0x9018}),
                sentinel, "failed DEC qword changed guest memory");
    expectEqual(faultState.rbx, std::uint64_t{0x9000},
                "failed DEC qword changed its base register");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed DEC qword changed flags");
}

void testCompare32BitRegisterWithGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x3B, 0x46, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegMem,
           "CMP r32, [base+disp8] opcode differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(lhs.reg == rosa::x86::Register::R8,
           "CMP r32, [base+disp8] register differs");
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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "CMP from unmapped guest memory did not fail");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed memory CMP changed flags");
}

void testCompareByteRegisterWithScaledGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{
        0x41, 0x3A, 0x14, 0x0E, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF8000050A3ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegMem,
           "SIB byte CMP opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4},
                "SIB byte CMP length differs");
    const auto lhs =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(lhs.reg == rosa::x86::Register::Rdx && lhs.width == 8,
           "SIB byte CMP register operand differs");
    expect(memory.base == rosa::x86::Register::R14 &&
               memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 1 && memory.displacement == 0 &&
               memory.width == 8,
           "SIB byte CMP memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp dl, [r14+rcx*1]") !=
               std::string::npos,
           "SIB byte CMP dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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
    expectEqual(state.r14, memoryBase.value,
                "SIB byte CMP changed its base register");
    expectEqual(state.rcx, std::uint64_t{0x18},
                "SIB byte CMP changed its index register");
    expectEqual(state.rflags, std::uint64_t{0x883},
                "SIB byte CMP did not compute 8-bit subtraction flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState = state;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "SIB byte CMP from unmapped memory did not fault");
    expectEqual(faultState.rdx, state.rdx,
                "failed SIB byte CMP changed its register operand");
    expectEqual(faultState.r14, state.r14,
                "failed SIB byte CMP changed its base register");
    expectEqual(faultState.rcx, state.rcx,
                "failed SIB byte CMP changed its index register");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed SIB byte CMP changed flags");
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
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8028}, 0x19);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xA5A5A5A500000019ULL;
    state.rdi = 0x8000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0xA5A5A5A500000019ULL},
                "legacy CMP memory changed EAX");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "legacy CMP memory equal flags differ");
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
    expectEqual(memory.displacement, std::int64_t{-0x20},
                "CMP r64 displacement differs");

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
}

void testCompareGuestMemoryWith64BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x39, 0x43, 0x30, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemReg,
           "CMP [memory], r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4},
                "CMP [memory], r64 length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto rhs =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx &&
               memory.displacement == 0x30 && memory.width == 64,
           "CMP [rbx+0x30], rax memory operand differs");
    expect(rhs.reg == rosa::x86::Register::Rax && rhs.width == 64,
           "CMP [rbx+0x30], rax register operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp [rbx+0x30], rax") !=
               std::string::npos,
           "CMP [rbx+0x30], rax dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8030}, 5);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8000;
    state.rax = 7;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rbx, std::uint64_t{0x8000},
                "CMP [memory], r64 changed its base");
    expectEqual(state.rax, std::uint64_t{7},
                "CMP [memory], r64 changed its source");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8030}),
                std::uint64_t{5}, "CMP [memory], r64 changed memory");
    expectEqual(state.rflags, std::uint64_t{0x93},
                "CMP qword 5, 7 subtraction flags differ");

    state.rax = 5;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46},
                "CMP qword equal flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rbx = 0x8000;
    faultState.rax = 7;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "CMP [unmapped], r64 did not fault");
    expectEqual(faultState.rbx, std::uint64_t{0x8000},
                "failed CMP [memory], r64 changed its base");
    expectEqual(faultState.rax, std::uint64_t{7},
                "failed CMP [memory], r64 changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed CMP [memory], r64 changed flags");

    constexpr std::array<std::uint8_t, 4> registerCode{0x48, 0x39, 0xD8, 0xC3};
    const auto registerDecoded = decoder.decodeBlock(
        registerCode, rosa::guest::GuestAddress{0x2000});
    expect(registerDecoded[0].opcode == rosa::x86::Opcode::CmpRegReg,
           "register-direct opcode 39 no longer decodes as CMP register");
}

void testLockedCompareExchangeGuestDword() {
    constexpr std::array<std::uint8_t, 5> code{
        0xF0, 0x0F, 0xB1, 0x0F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpxchgMemReg,
           "LOCK CMPXCHG opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4},
                "LOCK CMPXCHG length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdi && memory.width == 32 &&
               memory.displacement == 0,
           "LOCK CMPXCHG memory operand differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 32,
           "LOCK CMPXCHG source differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "lock cmpxchg dword [rdi], ecx") != std::string::npos,
           "LOCK CMPXCHG dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("compare_exchange_guest_memory.i32") !=
               std::string::npos,
           "LOCK CMPXCHG did not lower through guest-memory IR");

    const std::array zeroBytes{
        std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{0}};
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
    expectEqual(equalState.rflags, std::uint64_t{0x46},
                "successful LOCK CMPXCHG flags differ");

    constexpr std::array mismatchBytes{
        std::uint8_t{0x00}, std::uint8_t{0x00}, std::uint8_t{0x00},
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
    expectEqual(mismatchState.rflags, std::uint64_t{0x86},
                "failed LOCK CMPXCHG flags differ");

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
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "LOCK CMPXCHG accepted a read-only guest destination");
    expectEqual(readOnlyAddressSpace.readU32(memoryBase), std::uint32_t{0},
                "faulted LOCK CMPXCHG changed guest memory");
    expectEqual(faultState.rax, std::uint64_t{1},
                "faulted LOCK CMPXCHG changed RAX");
    expectEqual(faultState.rcx, std::uint64_t{2},
                "faulted LOCK CMPXCHG changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted LOCK CMPXCHG changed flags");
}

void testExchangeGuestDwordWithRegister() {
    constexpr std::array<std::uint8_t, 3> code{0x87, 0x17, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XchgMemReg,
           "XCHG dword memory opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2},
                "XCHG dword memory length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdi &&
               memory.displacement == 0 && memory.width == 32,
           "XCHG dword memory operand differs");
    expect(source.reg == rosa::x86::Register::Rdx && source.width == 32,
           "XCHG dword source differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "xchg dword [rdi], edx") != std::string::npos,
           "XCHG dword dump differs");

    constexpr rosa::guest::GuestAddress target{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array oldBytes{
        std::uint8_t{0x44}, std::uint8_t{0x33}, std::uint8_t{0x22},
        std::uint8_t{0x11}};
    addressSpace.writeBytes(target, oldBytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("exchange_guest_memory.i32") != std::string::npos,
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
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "XCHG changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0] = 0xDD;
    readOnlyBytes[1] = 0xCC;
    readOnlyBytes[2] = 0xBB;
    readOnlyBytes[3] = 0xAA;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(
        target, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
        readOnlyBytes, "read-only XCHG target");
    rosa::x86::X86State faultState;
    faultState.rdi = target.value;
    faultState.rdx = 0xBBBBBBBBAABBCCDDULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "same-value XCHG accepted a read-only target");
    expectEqual(readOnlyAddressSpace.readU32(target),
                std::uint32_t{0xAABBCCDDU},
                "faulted XCHG changed read-only memory");
    expectEqual(faultState.rdx, std::uint64_t{0xBBBBBBBBAABBCCDDULL},
                "faulted XCHG changed EDX");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted XCHG changed flags");

    constexpr rosa::guest::GuestAddress page{0x9000};
    constexpr rosa::guest::GuestAddress crossPageTarget{0x9FFE};
    constexpr std::array crossPageBytes{
        std::uint8_t{0x55}, std::uint8_t{0xAA}};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(
        page, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, crossPageBytes);
    faultState.rdi = crossPageTarget.value;
    faultState.rdx = 0x12345678;
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(block.execute(faultState,
                                        &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "cross-page XCHG did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, 2) ==
               std::vector<std::uint8_t>(crossPageBytes.begin(),
                                         crossPageBytes.end()),
           "cross-page XCHG partially changed memory");
    expectEqual(faultState.rdx, std::uint64_t{0x12345678},
                "cross-page XCHG changed EDX");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7},
                "cross-page XCHG changed flags");
}

void testLockedOrGuestDwordImmediate() {
    constexpr std::array<std::uint8_t, 7> zeroCode{
        0xF0, 0x83, 0x4C, 0x24, 0xC0, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        zeroCode, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::LockOrMemImm,
           "LOCK OR opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6},
                "LOCK OR length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate =
        std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rsp && memory.width == 32 &&
               memory.displacement == -0x40,
           "LOCK OR stack operand differs");
    expect(immediate.width == 8 && immediate.value == 0,
           "LOCK OR immediate differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "lock or dword [rsp-0x40], 0x0") != std::string::npos,
           "LOCK OR dump differs");

    constexpr rosa::guest::GuestAddress stackPage{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(stackPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array zeroBytes{
        std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{0}};
    addressSpace.writeBytes(target, zeroBytes);
    const rosa::dbt::Translator translator;
    const auto zeroBlock = translator.translate(
        zeroCode, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(zeroBlock.intermediateRepresentation())
                   .find("locked_or_guest_memory.i32") != std::string::npos,
           "LOCK OR did not lower through atomic guest-memory IR");
    rosa::x86::X86State zeroState;
    zeroState.rsp = target.value + 0x40;
    zeroState.rflags = 0x8D7;
    static_cast<void>(zeroBlock.execute(zeroState, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0},
                "LOCK OR zero changed the guest dword");
    expectEqual(zeroState.rsp, target.value + 0x40,
                "LOCK OR changed RSP");
    constexpr std::uint64_t definedLogicFlags =
        (1ULL << 0U) | (1ULL << 2U) | (1ULL << 6U) | (1ULL << 7U) |
        (1ULL << 11U);
    expectEqual(zeroState.rflags & definedLogicFlags, std::uint64_t{0x44},
                "LOCK OR zero defined flags differ");

    constexpr std::array<std::uint8_t, 7> negativeCode{
        0xF0, 0x83, 0x4C, 0x24, 0xC0, 0x80, 0xC3};
    const auto negativeBlock = translator.translate(
        negativeCode, rosa::guest::GuestAddress{0x2000});
    constexpr std::array initialBytes{
        std::uint8_t{0x34}, std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{0}};
    addressSpace.writeBytes(target, initialBytes);
    rosa::x86::X86State negativeState;
    negativeState.rsp = target.value + 0x40;
    negativeState.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(negativeState, &addressSpace));
    expectEqual(addressSpace.readU32(target), std::uint32_t{0xFFFFFFB4U},
                "LOCK OR did not sign-extend imm8 to dword");
    expectEqual(negativeState.rflags & definedLogicFlags, std::uint64_t{0x84},
                "LOCK OR negative result defined flags differ");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[0x100] = 0xA5;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(stackPage, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only LOCK OR stack");
    rosa::x86::X86State faultState;
    faultState.rsp = target.value + 0x40;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(zeroBlock.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "LOCK OR zero accepted a read-only guest dword");
    expectEqual(readOnlyAddressSpace.readU32(target), std::uint32_t{0xA5},
                "faulted LOCK OR changed read-only guest memory");
    expectEqual(faultState.rsp, target.value + 0x40,
                "faulted LOCK OR changed RSP");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted LOCK OR changed flags");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FFE};
    constexpr std::array crossPageBytes{
        std::uint8_t{0x55}, std::uint8_t{0xAA}};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(
        stackPage, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, crossPageBytes);
    faultState.rsp = crossPageTarget.value + 0x40;
    faultState.rflags = 0xBD7;
    rejected = false;
    try {
        static_cast<void>(negativeBlock.execute(faultState,
                                                &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "cross-page LOCK OR did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, 2) ==
               std::vector<std::uint8_t>(crossPageBytes.begin(),
                                         crossPageBytes.end()),
           "cross-page LOCK OR partially changed guest memory");
    expectEqual(faultState.rflags, std::uint64_t{0xBD7},
                "cross-page LOCK OR changed flags");
}

void testCompareGuestMemoryWith32BitImmediate() {
    constexpr std::array<std::uint8_t, 9> code{
        0x81, 0x7F, 0x04, 0x0C, 0x00, 0x00, 0x01, 0x75, 0x00,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "CMP [mem], imm32 opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rdi, "CMP [mem], imm32 base differs");
    expectEqual(memory.displacement, std::int64_t{4},
                "CMP [mem], imm32 displacement differs");

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
    expectEqual(state.rflags, std::uint64_t{0x93},
                "CMP [mem], imm32 flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rdi = 0x8100;
    faultState.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "CMP immediate from unmapped guest memory did not fail");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed memory-immediate CMP changed flags");
}

void testCompareGuestMemoryWithShortImmediate() {
    constexpr std::array<std::uint8_t, 6> code{
        0x41, 0x83, 0x7E, 0x04, 0x10, 0xC3};
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
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8004}, 0x10);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0x8000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0x8000},
                "CMP dword short immediate changed base");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "CMP dword short immediate flags differ");
}

void testCompareRipRelativeGuestDwordWithShortImmediate() {
    constexpr std::array<std::uint8_t, 8> observed{
        0x83, 0x3D, 0x3D, 0x3F, 0x0C, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800004EC8ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "RIP-relative CMP dword opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7},
                "RIP-relative CMP dword length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate =
        std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 32 &&
               memory.displacement == 0xC3F3D,
           "RIP-relative CMP dword memory operand differs");
    expect(immediate.value == 0 && immediate.width == 8,
           "RIP-relative CMP dword immediate differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "cmp dword [rip+0xc3f3d], 0x0 ; 0x7ff8000c8e0c") !=
               std::string::npos,
           "RIP-relative CMP dword dump differs");

    constexpr std::array<std::uint8_t, 8> code{
        0x83, 0x3D, 0xF9, 0x0F, 0x00, 0x00, 0x00, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    constexpr rosa::guest::GuestAddress target{0x2000};
    constexpr std::array<std::uint8_t, 8> data{
        0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(target, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read, data);
    rosa::x86::X86State state;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46},
                "RIP-relative CMP dword equal flags differ");

    constexpr std::array<std::uint8_t, 8> negativeCode{
        0x83, 0x3D, 0xF9, 0x0F, 0x00, 0x00, 0xFF, 0xC3};
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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "RIP-relative CMP dword from unmapped memory did not fault");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative CMP dword changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            std::span<const std::uint8_t>{observed}.first(6), observedRip));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated RIP-relative CMP dword was accepted");
}

void testCompareGuestQwordWithShortImmediate() {
    constexpr std::array<std::uint8_t, 6> code{
        0x48, 0x83, 0x78, 0x10, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expectEqual(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]).width,
                std::uint8_t{64}, "CMP qword short immediate width differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8010}, 0);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0x8000},
                "CMP qword short immediate changed base");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "CMP qword short immediate flags differ");
}

void testCompareGuestWordWithShortImmediate() {
    constexpr std::array<std::uint8_t, 6> code{
        0x66, 0x83, 0x7A, 0x14, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "CMP word [memory], imm8 opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rdx &&
               memory.displacement == 0x14 && memory.width == 16,
           "CMP word [rdx+0x14], imm8 memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp word [rdx+0x14]") !=
               std::string::npos,
           "CMP word dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> zero{0, 0};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8114}, zero);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rdx, std::uint64_t{0x8100},
                "CMP word changed its base");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "CMP word equal flags differ");

    constexpr std::array<std::uint8_t, 6> negativeCode{
        0x66, 0x83, 0x7A, 0x14, 0xFF, 0xC3};
    constexpr std::array<std::uint8_t, 2> minusOne{0xFF, 0xFF};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8114}, minusOne);
    const auto negativeBlock = translator.translate(
        negativeCode, rosa::guest::GuestAddress{0x2000});
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46},
                "CMP word imm8 did not sign-extend -1");

    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8114}, zero);
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x13},
                "CMP word negative imm8 flags differ");

    constexpr std::array<std::uint8_t, 6> overflowCode{
        0x66, 0x83, 0x7A, 0x14, 0x01, 0xC3};
    constexpr std::array<std::uint8_t, 2> minimumSigned{0x00, 0x80};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8114}, minimumSigned);
    const auto overflowBlock = translator.translate(
        overflowCode, rosa::guest::GuestAddress{0x3000});
    state.rflags = 0x8D7;
    static_cast<void>(overflowBlock.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x816},
                "CMP word signed-overflow flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rflags = 0x8D7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "CMP word from unmapped guest memory did not fault");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "failed CMP word changed flags");
}

void testCompare16BitRegisterWithShortImmediate() {
    constexpr std::array<std::uint8_t, 5> code{
        0x66, 0x83, 0xFF, 0x0D, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegImm,
           "CMP r16, imm8 opcode differs");
    const auto reg = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(reg.reg == rosa::x86::Register::Rdi && reg.width == 16,
           "CMP DI, imm8 register differs");
    expect(rosa::debug::dumpX86(decoded).find("cmp di, 0xd") !=
               std::string::npos,
           "CMP DI, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0xA5A5A5A500000005ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdi, std::uint64_t{0xA5A5A5A500000005ULL},
                "CMP DI changed its register");
    expectEqual(state.rflags, std::uint64_t{0x93},
                "CMP DI, positive imm8 flags differ");

    constexpr std::array<std::uint8_t, 5> negativeCode{
        0x66, 0x83, 0xFF, 0xFF, 0xC3};
    const auto negativeBlock = translator.translate(
        negativeCode, rosa::guest::GuestAddress{0x2000});
    state.rdi = 0x112233445566FFFFULL;
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rflags, std::uint64_t{0x46},
                "CMP DI did not sign-extend negative imm8");
}

void testCompareGuestByteWithImmediate() {
    constexpr std::array<std::uint8_t, 5> code{0x80, 0x7D, 0xD7, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "CMP byte [memory], imm8 opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expectEqual(memory.width, std::uint8_t{8}, "CMP byte memory width differs");
    expectEqual(memory.displacement, std::int64_t{-0x29},
                "CMP byte memory displacement differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 1> zero{0};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x80D7}, zero);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbp = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46},
                "CMP byte [memory], imm8 equal flags differ");
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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "CMP byte from unmapped guest memory did not fail");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed CMP byte changed flags");
}

void testCompareIndexedGuestByteWithImmediate() {
    constexpr std::array<std::uint8_t, 6> code{
        0x42, 0x80, 0x3C, 0x20, 0x3D, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "indexed CMP byte opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5},
                "indexed CMP byte length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate =
        std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rax && memory.index &&
               *memory.index == rosa::x86::Register::R12 && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 8 &&
               !memory.ripRelative,
           "indexed CMP byte memory operand differs");
    expect(immediate.value == 0x3D && immediate.width == 8,
           "indexed CMP byte immediate differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "cmp byte [rax+r12*1], 0x3d") != std::string::npos,
           "indexed CMP byte dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8020};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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
    expectEqual(state.rflags, std::uint64_t{0x46},
                "indexed CMP byte equal flags differ");
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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "indexed CMP byte from unmapped memory did not fault");
    expectEqual(faultState.rax, page.value,
                "failed indexed CMP byte changed RAX");
    expectEqual(faultState.r12, std::uint64_t{0x20},
                "failed indexed CMP byte changed R12");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed indexed CMP byte changed flags");
}

void testCompareRipRelativeGuestByteWithImmediate() {
    constexpr std::array<std::uint8_t, 8> observed{
        0x80, 0x3D, 0x94, 0x3F, 0x0C, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800004E75ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpMemImm,
           "RIP-relative CMP byte opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7},
                "RIP-relative CMP byte length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate =
        std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0xC3F94,
           "RIP-relative CMP byte memory operand differs");
    expect(immediate.value == 0 && immediate.width == 8,
           "RIP-relative CMP byte immediate differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "cmp byte [rip+0xc3f94], 0x0 ; 0x7ff8000c8e10") !=
               std::string::npos,
           "RIP-relative CMP byte dump differs");

    constexpr std::array<std::uint8_t, 8> code{
        0x80, 0x3D, 0xF9, 0x0F, 0x00, 0x00, 0x00, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    constexpr rosa::guest::GuestAddress target{0x2000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    const std::array<std::uint8_t, 1> zero{0};
    addressSpace.writeBytes(target, zero);
    rosa::x86::X86State state;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rflags, std::uint64_t{0x46},
                "RIP-relative CMP byte equal flags differ");
    expectEqual(addressSpace.readBytes(target, 1).front(), std::uint8_t{0},
                "RIP-relative CMP byte changed guest memory");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "RIP-relative CMP byte from unmapped memory did not fault");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative CMP byte changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            std::span<const std::uint8_t>{observed}.first(6), observedRip));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated RIP-relative CMP byte was not rejected");
}

void testCompare8BitRegisterWithImmediate() {
    constexpr std::array<std::uint8_t, 4> code{0x80, 0xF9, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegImm,
           "CMP CL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3},
                "CMP CL, imm8 length differs");
    const auto operand =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
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
    expectEqual(state.rcx, std::uint64_t{0x1122334455667700ULL},
                "CMP CL, imm8 changed RCX");
    expectEqual(state.rflags, std::uint64_t{0x97},
                "CMP byte zero, one flags differ");

    state.rcx = 0xFFEEDDCCBBAA5501ULL;
    state.rflags = 0;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFFEEDDCCBBAA5501ULL},
                "equal CMP CL, imm8 changed RCX");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "equal CMP CL, imm8 flags differ");

    state.rcx = 0x80;
    state.rflags = 0;
    static_cast<void>(block.execute(state));
    expectEqual(state.rflags, std::uint64_t{0x812},
                "overflow CMP CL, imm8 flags differ");

    constexpr std::array<std::uint8_t, 4> highByteCode{0x80, 0xFC, 0x01, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "CMP AH, imm8 was silently treated as a low-byte register");

    constexpr std::array<std::uint8_t, 9> rexBMemoryCode{
        0x41, 0x80, 0x3D, 0x01, 0x00, 0x00, 0x00, 0x01, 0xC3};
    const auto rexBMemoryDecoded = decoder.decodeBlock(
        rexBMemoryCode, rosa::guest::GuestAddress{0x3000});
    const auto rexBMemory =
        std::get<rosa::x86::MemoryOperand>(rexBMemoryDecoded[0].operands[0]);
    expect(rexBMemoryDecoded[0].opcode == rosa::x86::Opcode::CmpMemImm &&
               !rexBMemory.hasBase && rexBMemory.ripRelative &&
               rexBMemory.displacement == 1,
           "REX.B changed opcode-80 RIP-relative addressing");
}

void testCompare32BitRegisterWithImmediate() {
    constexpr std::array<std::uint8_t, 7> code{
        0x81, 0xFA, 0xCF, 0xFA, 0xED, 0xFE, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegImm,
           "CMP r32, imm32 opcode differs");
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
    expectEqual(state.rflags, std::uint64_t{0x46},
                "CMP r32, imm32 equal flags differ");
}

void testCompareEaxAccumulatorImmediate() {
    constexpr std::array<std::uint8_t, 6> code{
        0x3D, 0x22, 0x00, 0x00, 0x80, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegImm,
           "CMP EAX, imm32 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "CMP accumulator destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0x80000022}, "CMP accumulator immediate differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xAAAAAAAA80000022ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xAAAAAAAA80000022ULL},
                "CMP EAX, imm32 changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "CMP EAX, imm32 equal flags differ");
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
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[1].operands[1]).value,
                UINT64_MAX, "CMP r32, imm8 negative sign extension differs");

    const rosa::dbt::Translator translator;
    const auto first = translator.translate(code, rosa::guest::GuestAddress{0x1000}, 1);
    rosa::x86::X86State positiveState;
    positiveState.rdx = 0xA5A5A5A500000007ULL;
    positiveState.rflags = 0x8D7;
    static_cast<void>(first.execute(positiveState));
    expectEqual(positiveState.rdx, std::uint64_t{0xA5A5A5A500000007ULL},
                "CMP r32, positive imm8 changed its register");
    expectEqual(positiveState.rflags, std::uint64_t{0x97},
                "CMP r32, positive imm8 flags differ");

    const auto second = translator.translate(
        std::span<const std::uint8_t>{code}.subspan(3),
        rosa::guest::GuestAddress{0x1003}, 1);
    rosa::x86::X86State negativeState;
    negativeState.rcx = 0x12345678FFFFFFFFULL;
    negativeState.rflags = 0x8D7;
    static_cast<void>(second.execute(negativeState));
    expectEqual(negativeState.rcx, std::uint64_t{0x12345678FFFFFFFFULL},
                "CMP r32, negative imm8 changed its register");
    expectEqual(negativeState.rflags, std::uint64_t{0x46},
                "CMP r32, negative imm8 flags differ");
}

void testCompare64BitRegisters() {
    constexpr std::array<std::uint8_t, 4> code{0x4D, 0x39, 0xEE, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegReg,
           "CMP r64, r64 opcode differs");
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
    expect(decoded[0].opcode == rosa::x86::Opcode::CmpRegReg,
           "CMP r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "CMP r32, r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r15 = 0xAAAAAAAA00000013ULL;
    state.rcx = 0xBBBBBBBB00000013ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r15, std::uint64_t{0xAAAAAAAA00000013ULL},
                "CMP r32, r32 changed lhs");
    expectEqual(state.rcx, std::uint64_t{0xBBBBBBBB00000013ULL},
                "CMP r32, r32 changed rhs");
    expectEqual(state.rflags, std::uint64_t{0x46}, "CMP r32, r32 flags differ");

    constexpr std::array<std::uint8_t, 3> legacyCode{0x39, 0xF2, 0xC3};
    const auto legacyDecoded = decoder.decodeBlock(
        legacyCode, rosa::guest::GuestAddress{0x2000});
    expect(legacyDecoded[0].opcode == rosa::x86::Opcode::CmpRegReg,
           "legacy CMP r32, r32 opcode differs");
    const auto legacyLhs =
        std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[0]);
    const auto legacyRhs =
        std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[1]);
    expect(legacyLhs.reg == rosa::x86::Register::Rdx &&
               legacyLhs.width == 32 &&
               legacyRhs.reg == rosa::x86::Register::Rsi &&
               legacyRhs.width == 32,
           "legacy CMP EDX, ESI operands differ");
    const auto legacyBlock = translator.translate(
        legacyCode, rosa::guest::GuestAddress{0x2000});
    state.rdx = 0xAAAAAAAA80000000ULL;
    state.rsi = 0xBBBBBBBB00000001ULL;
    state.rflags = 0x8D7;
    static_cast<void>(legacyBlock.execute(state));
    expectEqual(state.rdx, std::uint64_t{0xAAAAAAAA80000000ULL},
                "legacy CMP changed EDX");
    expectEqual(state.rsi, std::uint64_t{0xBBBBBBBB00000001ULL},
                "legacy CMP changed ESI");
    expectEqual(state.rflags, std::uint64_t{0x816},
                "legacy CMP EDX, ESI flags differ");
}

void testMovRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 12> code{
        0x48, 0x89, 0xBD, 0x58, 0xFF, 0xFF, 0xFF,
        0x48, 0x89, 0x4D, 0xC0,
        0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "MOV [base+disp32], r64 opcode differs");
    const auto firstMemory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(firstMemory.base == rosa::x86::Register::Rbp,
           "MOV [base+disp32], r64 base differs");
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
    const auto secondStore = translator.translate(std::span(code).subspan(7),
                                                  rosa::guest::GuestAddress{0x1007}, 1);
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
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV register to guest memory changed flags");

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
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOV to read-only guest memory did not fail");
    expectEqual(faultState.rbp, std::uint64_t{0x8800},
                "failed guest-memory MOV changed the base register");
    expectEqual(faultState.rdi, state.rdi,
                "failed guest-memory MOV changed the source register");
}

void testMovRegisterToRipRelativeGuestMemory() {
    constexpr std::array<std::uint8_t, 8> observed{
        0x4C, 0x89, 0x3D, 0x10, 0x33, 0x09, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800011FF9ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "RIP-relative MOV store opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7},
                "RIP-relative MOV store length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.displacement == 0x93310 &&
               memory.width == 64,
           "RIP-relative MOV store memory operand differs");
    expect(source.reg == rosa::x86::Register::R15 && source.width == 64,
           "RIP-relative MOV store source differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "mov [rip+0x93310], r15 ; 0x7ff8000a5310") != std::string::npos,
           "RIP-relative MOV store dump differs");

    constexpr std::array<std::uint8_t, 8> code{
        0x4C, 0x89, 0x3D, 0xF9, 0x0F, 0x00, 0x00, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    constexpr rosa::guest::GuestAddress target{0x2000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.r15 = 0x0123456789ABCDEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), state.r15,
                "RIP-relative MOV stored at the wrong guest address");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOV changed flags");

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
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOV to read-only guest memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(target), std::uint64_t{0},
                "failed RIP-relative MOV changed guest memory");
    expectEqual(faultState.r15, UINT64_MAX,
                "failed RIP-relative MOV changed its source");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOV changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            std::span<const std::uint8_t>{observed}.first(6), observedRip));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated RIP-relative MOV was not rejected");
}

void testMovRipRelativeGuestDwordToRegister() {
    constexpr std::array<std::uint8_t, 7> observed{
        0x8B, 0x0D, 0x66, 0x3F, 0x0C, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800004E9CULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "RIP-relative MOV load opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6},
                "RIP-relative MOV load length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32,
           "RIP-relative MOV load destination differs");
    expect(memory.ripRelative && !memory.hasBase && memory.displacement == 0xC3F66 &&
               memory.width == 32,
           "RIP-relative MOV load memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "mov ecx, [rip+0xc3f66] ; 0x7ff8000c8e08") != std::string::npos,
           "RIP-relative MOV load dump differs");

    constexpr std::array<std::uint8_t, 7> code{
        0x8B, 0x0D, 0xFA, 0x0F, 0x00, 0x00, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    constexpr rosa::guest::GuestAddress target{0x2000};
    rosa::guest::AddressSpace addressSpace;
    constexpr std::array<std::uint8_t, 8> data{
        0xEF, 0xCD, 0xAB, 0x89, 0xEF, 0xBE, 0xAD, 0xDE};
    addressSpace.mapSegment(target, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read, data);
    rosa::x86::X86State state;
    state.rcx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0x89ABCDEF},
                "RIP-relative MOV load did not read exactly four bytes and zero-extend");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOV load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rcx = 0x0123456789ABCDEFULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOV from unmapped memory did not fault");
    expectEqual(faultState.rcx, std::uint64_t{0x0123456789ABCDEFULL},
                "failed RIP-relative MOV changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOV changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            std::span<const std::uint8_t>{observed}.first(5), observedRip));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated RIP-relative MOV load was not rejected");

    bool overflowRejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            observed, rosa::guest::GuestAddress{UINT64_MAX - 2U}));
    } catch (const std::runtime_error &) {
        overflowRejected = true;
    }
    expect(overflowRejected, "overflowing RIP-relative MOV target was accepted");
}

void testMov32BitRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x89, 0x72, 0x28, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "MOV [mem], r32 opcode differs");
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
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{0x8128}),
                std::uint32_t{0x12345678}, "MOV [mem], r32 stored value differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{0x812C}),
                UINT32_MAX, "MOV [mem], r32 overwrote adjacent bytes");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOV [mem], r32 changed flags");
}

void testMov64BitRegisterToScaledGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{
        0x48, 0x89, 0x34, 0x17, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "scaled qword MOV store opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4},
                "scaled qword MOV store length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rdi && memory.index &&
               *memory.index == rosa::x86::Register::Rdx && memory.scale == 1 &&
               memory.displacement == 0 && memory.width == 64,
           "scaled qword MOV store memory operand differs");
    expect(source.reg == rosa::x86::Register::Rsi && source.width == 64,
           "scaled qword MOV store source differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "mov [rdi+rdx*1], rsi") != std::string::npos,
           "scaled qword MOV store dump differs");

    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8020};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(target, UINT64_MAX);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = page.value;
    state.rdx = 0x20;
    state.rsi = 0x0123456789ABCDEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target),
                std::uint64_t{0x0123456789ABCDEFULL},
                "scaled qword MOV stored the wrong value");
    expectEqual(state.rdi, page.value, "scaled qword MOV changed its base");
    expectEqual(state.rdx, std::uint64_t{0x20},
                "scaled qword MOV changed its index");
    expectEqual(state.rsi, std::uint64_t{0x0123456789ABCDEFULL},
                "scaled qword MOV changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "scaled qword MOV changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t readOnlySentinel = 0xA5A5A5A5A5A5A5A5ULL;
    std::memcpy(readOnlyBytes.data() + 0x20, &readOnlySentinel,
                sizeof(readOnlySentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(page, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read,
                                    readOnlyBytes, "read-only scaled MOV target");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "scaled qword MOV accepted read-only guest memory");
    expectEqual(readOnlyAddressSpace.readU64(target), readOnlySentinel,
                "faulted scaled qword MOV changed guest memory");
    expectEqual(state.rsi, std::uint64_t{0x0123456789ABCDEFULL},
                "faulted scaled qword MOV changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "faulted scaled qword MOV changed flags");
}

void testMovLowByteRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x88, 0x48, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "MOV byte [memory], low register opcode differs");
    expectEqual(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]).width,
                std::uint8_t{8}, "MOV byte store memory width differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::Register::Rcx,
           "MOV byte store source differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOV byte to unmapped guest memory did not fail");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed MOV byte store changed flags");
}

void testMovExtendedLowByteToScaledGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{
        0x45, 0x88, 0x5C, 0x08, 0x02, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "scaled byte MOV store opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5},
                "scaled byte MOV store length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R8 &&
               memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 1 && memory.displacement == 2 &&
               memory.width == 8,
           "scaled byte MOV store effective address differs");
    expect(source.reg == rosa::x86::Register::R11 && source.width == 8,
           "scaled byte MOV store source differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "mov [r8+rcx*1+0x2], r11b") != std::string::npos,
           "scaled byte MOV store dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x8022};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array sentinel{
        std::uint8_t{0x11}, std::uint8_t{0}, std::uint8_t{0x22}};
    addressSpace.writeBytes(rosa::guest::GuestAddress{target.value - 1},
                            sentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r8 = memoryBase.value;
    state.rcx = 0x20;
    state.r11 = 0x11223344556677A5ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    const auto stored = addressSpace.readBytes(
        rosa::guest::GuestAddress{target.value - 1}, 3);
    expect(stored[0] == 0x11 && stored[1] == 0xA5 && stored[2] == 0x22,
           "scaled byte MOV store changed the wrong guest bytes");
    expectEqual(state.r8, memoryBase.value,
                "scaled byte MOV store changed its base");
    expectEqual(state.rcx, std::uint64_t{0x20},
                "scaled byte MOV store changed its index");
    expectEqual(state.r11, std::uint64_t{0x11223344556677A5ULL},
                "scaled byte MOV store changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "scaled byte MOV store changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "scaled byte MOV store accepted read-only memory");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1)[0], std::uint8_t{0},
                "faulted scaled byte MOV store changed memory");
    expectEqual(state.r11, std::uint64_t{0x11223344556677A5ULL},
                "faulted scaled byte MOV store changed its source");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "faulted scaled byte MOV store changed flags");
}

void testMovLowByteRegisterToRipRelativeGuestMemory() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF800058A51ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8000C8DAAULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF8000C8000ULL};
    constexpr std::array<std::uint8_t, 7> code{
        0x88, 0x05, 0x53, 0x03, 0x07, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "RIP-relative MOV byte register opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6},
                "RIP-relative MOV byte register length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8,
           "RIP-relative MOV byte register addressing differs");
    expectEqual(memory.displacement, std::int64_t{0x70353},
                "RIP-relative MOV byte register displacement differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 8,
           "RIP-relative MOV byte register source differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "mov [rip+0x70353], al ; 0x7ff8000c8daa") !=
               std::string::npos,
           "RIP-relative MOV byte register dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeBytes(rosa::guest::GuestAddress{target.value - 1},
                            std::array<std::uint8_t, 3>{0x11, 0x00, 0x22});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, instructionAddress);
    rosa::x86::X86State state;
    state.rax = 0x11223344556677A5ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    const auto stored =
        addressSpace.readBytes(rosa::guest::GuestAddress{target.value - 1}, 3);
    expect(stored == std::vector<std::uint8_t>({0x11, 0xA5, 0x22}),
           "RIP-relative MOV byte register did not store exactly one byte");
    expectEqual(state.rax, std::uint64_t{0x11223344556677A5ULL},
                "RIP-relative MOV byte register changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOV byte register changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    readOnlyBytes[static_cast<std::size_t>(target.value - targetPage.value)] =
        0x5A;
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(targetPage, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read,
                                    readOnlyBytes,
                                    "read-only RIP-relative byte MOV target");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOV byte register accepted read-only memory");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1).front(),
                std::uint8_t{0x5A},
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
    expect(memory.base == rosa::x86::Register::R8,
           "MOV byte store REX.B base differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::Register::Rax,
           "MOV byte store legacy source under REX differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r8 = 0x8000;
    state.rax = 0xA5;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0x8018}, 1).front(),
                std::uint8_t{0xA5}, "MOV byte store through REX.B value differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV byte store through REX.B changed flags");
}

void testMovImmediateToGuestMemory() {
    constexpr std::array<std::uint8_t, 8> code{
        0x48, 0xC7, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3,
    };
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "MOV [mem], imm32 opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                UINT64_MAX, "MOV [mem], imm32 sign extension differs");

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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOV immediate to unmapped guest memory did not fail");
}

void testMovImmediateToRipRelativeGuestMemory() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF800058A1AULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8000C8DD0ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF8000C8000ULL};
    constexpr std::array<std::uint8_t, 12> code{
        0x48, 0xC7, 0x05, 0xAB, 0x03, 0x07, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "RIP-relative MOV qword immediate opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{11},
                "RIP-relative MOV qword immediate length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate =
        std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 64,
           "RIP-relative MOV qword immediate addressing differs");
    expectEqual(memory.displacement, std::int64_t{0x703AB},
                "RIP-relative MOV qword immediate displacement differs");
    expectEqual(immediate.value, std::uint64_t{0},
                "RIP-relative MOV qword immediate differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "mov qword [rip+0x703ab], 0x0 ; 0x7ff8000c8dd0") !=
               std::string::npos,
           "RIP-relative MOV qword immediate dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{target.value - 8}),
                before,
                "RIP-relative MOV qword immediate changed preceding bytes");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{target.value + 8}),
                after,
                "RIP-relative MOV qword immediate changed following bytes");
    expectEqual(state.rax, std::uint64_t{0xDEADBEEFCAFEBABEULL},
                "RIP-relative MOV qword immediate used a dummy base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOV qword immediate changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    const auto targetOffset =
        static_cast<std::size_t>(target.value - targetPage.value);
    std::memcpy(readOnlyBytes.data() + targetOffset, &initial, sizeof(initial));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(targetPage, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read,
                                    readOnlyBytes,
                                    "read-only RIP-relative MOV target");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected,
           "RIP-relative MOV qword immediate accepted a read-only target");
    expectEqual(readOnlyAddressSpace.readU64(target), initial,
                "failed RIP-relative MOV qword immediate changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOV qword immediate changed flags");
}

void testMov32BitImmediateToGuestMemory() {
    constexpr std::array<std::uint8_t, 8> code{
        0xC7, 0x45, 0x9F, 0x00, 0x00, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF80005899DULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "MOV dword [mem], imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7},
                "MOV dword [mem], imm32 length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    const auto immediate =
        std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbp && memory.width == 32 &&
               memory.displacement == -0x61,
           "MOV dword [mem], imm32 memory operand differs");
    expect(immediate.value == 0 && immediate.width == 32,
           "MOV dword [mem], imm32 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "mov dword [rbp-0x61], 0x0") != std::string::npos,
           "MOV dword [mem], imm32 dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    constexpr rosa::guest::GuestAddress target{0x809F};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(target, 0x1122334455667788ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbp = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target),
                std::uint64_t{0x1122334400000000ULL},
                "MOV dword [mem], imm32 did not store exactly four bytes");
    expectEqual(state.rbp, std::uint64_t{0x8100},
                "MOV dword [mem], imm32 changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV dword [mem], imm32 changed flags");

    std::array<std::uint8_t, 0xA7> readOnlyBytes{};
    const auto sentinel = UINT64_C(0x8877665544332211);
    std::memcpy(readOnlyBytes.data() + 0x9F, &sentinel, sizeof(sentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(memoryBase, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read,
                                    readOnlyBytes);
    rosa::x86::X86State faultState;
    faultState.rbp = 0x8100;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
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
    expectEqual(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]).width,
                std::uint8_t{8}, "MOV byte [mem], imm8 width differs");

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
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV byte [mem], imm8 changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOV byte immediate to read-only guest memory did not fail");
}

void testMovByteImmediateToRipRelativeGuestMemory() {
    constexpr std::array<std::uint8_t, 7> observed{
        0xC6, 0x05, 0xF5, 0x3E, 0x0C, 0x00, 0x01};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800004F14ULL};
    const rosa::x86::Decoder decoder;
    const auto observedDecoded = decoder.decodeBlock(observed, observedRip, 1);
    expectEqual(observedDecoded[0].length, std::uint8_t{7},
                "observed RIP-relative MOV byte immediate length differs");
    const auto observedMemory =
        std::get<rosa::x86::MemoryOperand>(observedDecoded[0].operands[0]);
    expect(observedMemory.ripRelative && !observedMemory.hasBase &&
               observedMemory.width == 8 &&
               observedMemory.displacement == 0xC3EF5,
           "observed RIP-relative MOV byte immediate operand differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(
                    observedDecoded[0].operands[1]).value,
                std::uint64_t{1},
                "observed RIP-relative MOV byte immediate differs");
    expect(rosa::debug::dumpX86(observedDecoded).find(
               "mov byte [rip+0xc3ef5], 0x1 ; 0x7ff8000c8e10") !=
               std::string::npos,
           "observed RIP-relative MOV byte immediate dump differs");

    constexpr std::array<std::uint8_t, 8> code{
        0xC6, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0xA5, 0xC3};
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress target{0x2000};
    const auto decoded = decoder.decodeBlock(code, codeBase);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "RIP-relative MOV byte immediate opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7},
                "RIP-relative MOV byte immediate length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0xFF9,
           "RIP-relative MOV byte immediate memory operand differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0xA5},
                "RIP-relative MOV byte immediate value differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "mov byte [rip+0xff9], 0xa5 ; 0x2000") != std::string::npos,
           "RIP-relative MOV byte immediate dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeBytes(target, std::array<std::uint8_t, 3>{0x11, 0x00, 0x22});
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, codeBase);
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readBytes(target, 3),
                std::vector<std::uint8_t>({0xA5, 0x00, 0x22}),
                "RIP-relative MOV byte immediate changed the wrong bytes");
    expectEqual(state.rax, UINT64_MAX,
                "RIP-relative MOV byte immediate read a dummy base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOV byte immediate changed flags");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    constexpr std::array<std::uint8_t, 1> sentinelByte{0x5A};
    readOnlyAddressSpace.mapSegment(target, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read,
                                    sentinelByte);
    rosa::x86::X86State faultState;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected,
           "RIP-relative MOV byte immediate to read-only memory did not fault");
    expectEqual(readOnlyAddressSpace.readBytes(target, 1).front(),
                std::uint8_t{0x5A},
                "failed RIP-relative MOV byte immediate changed memory");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOV byte immediate changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            std::span<const std::uint8_t>{code}.first(6), codeBase));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected,
           "truncated RIP-relative MOV byte immediate was accepted");
}

void testMovWordImmediateToGuestMemory() {
    constexpr std::array<std::uint8_t, 7> code{
        0x66, 0xC7, 0x43, 0x18, 0xEF, 0xBE, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemImm,
           "MOV word [mem], imm16 opcode differs");
    expectEqual(std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]).width,
                std::uint8_t{16}, "MOV word [mem], imm16 width differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0xBEEF}, "MOV word [mem], imm16 immediate differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8118},
                          0x1122334455667788ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8118}),
                std::uint64_t{0x112233445566BEEFULL},
                "MOV word [mem], imm16 changed bytes outside the word");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV word [mem], imm16 changed flags");

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
                   std::string_view(error.what()).find("unmapped") !=
                       std::string_view::npos;
    }
    expect(rejected, "cross-page MOV word guest store did not fault");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{0x8FFF}, 1).front(),
                std::uint8_t{0x5A},
                "failed MOV word guest store partially changed memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "failed MOV word guest store changed flags");
}

void testMovWordRegisterToGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{
        0x66, 0x89, 0x46, 0x2C, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovMemReg,
           "MOV word [mem], register opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).width,
                std::uint8_t{16}, "MOV word source width differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x812C},
                          0x1122334455667788ULL);
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
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV word register store changed flags");
}

void testMovGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x8B, 0x03, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV r64, [base] opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "MOV r64, [base] destination differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbx,
           "MOV r64, [base] base register differs");
    expectEqual(memory.displacement, std::int64_t{0},
                "MOV r64, [base] displacement differs");
    constexpr std::array<std::uint8_t, 4> ignoredRexXCode{
        0x42, 0x8B, 0x03, 0xC3};
    const auto ignoredRexX = decoder.decodeBlock(
        ignoredRexXCode, rosa::guest::GuestAddress{0x2000});
    const auto ignoredRexXMemory =
        std::get<rosa::x86::MemoryOperand>(ignoredRexX[0].operands[1]);
    expect(ignoredRexXMemory.base == rosa::x86::Register::Rbx &&
               !ignoredRexXMemory.index,
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
    expectEqual(state.rbx, std::uint64_t{0x8100},
                "MOV r64, [base] changed the base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV r64, [base] changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x55;
    faultState.rbx = 0x8100;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOV from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{0x55},
                "failed guest-memory load changed the destination register");
}

void testMovGuestGsMemoryTo32BitRegister() {
    constexpr std::array<std::uint8_t, 9> code{
        0x65, 0x8B, 0x0C, 0x25, 0x18, 0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "GS MOV r32, [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{8},
                "GS MOV instruction length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx &&
               destination.width == 32,
           "GS MOV destination differs");
    expect(memory.segment == rosa::x86::Segment::Gs && !memory.hasBase &&
               !memory.index && !memory.ripRelative && memory.width == 32 &&
               memory.displacement == 0x18,
           "GS MOV memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("mov ecx, [gs:0x18]") !=
               std::string::npos,
           "GS MOV dump differs");

    constexpr rosa::guest::GuestAddress tsdBase{0x8000};
    constexpr std::array threadSelfBytes{
        std::uint8_t{0x78}, std::uint8_t{0x56}, std::uint8_t{0x34},
        std::uint8_t{0x12}};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(tsdBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeBytes(rosa::guest::GuestAddress{tsdBase.value + 0x18},
                            threadSelfBytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    expect(rosa::debug::dumpIr(block.intermediateRepresentation())
                   .find("read_guest_gs_base.i64") !=
               std::string::npos,
           "GS MOV did not lower the guest segment base through IR");
    rosa::x86::X86State state;
    state.gsBase = tsdBase.value;
    state.rcx = UINT64_MAX;
    state.rdi = 0x1111111111111111ULL;
    state.rsp = 0x2222222222222222ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0x12345678},
                "GS MOV did not zero-extend the guest dword");
    expectEqual(state.gsBase, tsdBase.value, "GS MOV changed the guest GS base");
    expectEqual(state.rdi, std::uint64_t{0x1111111111111111ULL},
                "GS MOV used an unrelated GPR as its address base");
    expectEqual(state.rsp, std::uint64_t{0x2222222222222222ULL},
                "GS MOV used the host or guest stack");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "GS MOV changed flags");

    rosa::guest::AddressSpace nonReadableAddressSpace;
    nonReadableAddressSpace.mapAnonymous(
        tsdBase, rosa::guest::guestPageSize, rosa::guest::Permission::Write);
    rosa::x86::X86State faultState;
    faultState.gsBase = tsdBase.value;
    faultState.rcx = 0xAAAAAAAA55555555ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &nonReadableAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "GS MOV from non-readable guest memory did not fault");
    expectEqual(faultState.rcx, std::uint64_t{0xAAAAAAAA55555555ULL},
                "failed GS MOV changed the destination");
    expectEqual(faultState.gsBase, tsdBase.value,
                "failed GS MOV changed the guest GS base");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed GS MOV changed flags");
}

void testMovGuestMemoryToRegisterWithNoIndexSib() {
    constexpr std::array<std::uint8_t, 6> code{
        0x49, 0x8B, 0x74, 0x24, 0xE0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV r64, [SIB base+disp8] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R12,
           "MOV no-index SIB extended base differs");
    expectEqual(memory.displacement, std::int64_t{-0x20},
                "MOV no-index SIB displacement differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8000},
                          0x1122334455667788ULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r12 = 0x8020;
    state.rsi = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rsi, std::uint64_t{0x1122334455667788ULL},
                "MOV no-index SIB loaded value differs");
    expectEqual(state.r12, std::uint64_t{0x8020},
                "MOV no-index SIB changed base");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV no-index SIB changed flags");
}

void testMovGuestMemoryTo32BitRegisterWithScaledIndex() {
    constexpr std::array<std::uint8_t, 6> code{
        0x41, 0x8B, 0x54, 0x9E, 0x04, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV r32, [base+index*scale+disp8] opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx &&
               destination.width == 32,
           "indexed MOV EDX destination differs");
    expect(memory.base == rosa::x86::Register::R14 &&
               memory.index == rosa::x86::Register::Rbx &&
               memory.scale == 4 && memory.displacement == 4 &&
               memory.width == 32,
           "indexed MOV memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("[r14+rbx*4+0x4]") !=
               std::string::npos,
           "indexed MOV dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 8> sourceWithUpperSentinel{
        0x12, 0x34, 0x56, 0x78, 0xEF, 0xBE, 0xAD, 0xDE};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8110},
                            sourceWithUpperSentinel);
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
    expectEqual(state.r14, std::uint64_t{0x8100},
                "indexed MOV changed its base");
    expectEqual(state.rbx, std::uint64_t{3},
                "indexed MOV changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "indexed MOV changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rdx = UINT64_MAX;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "indexed MOV from unmapped guest memory did not fault");
    expectEqual(state.rdx, UINT64_MAX,
                "failed indexed MOV changed its destination");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "failed indexed MOV changed flags");
}

void testMovGuestMemoryTo32BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x8B, 0x46, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV r32, [base+disp8] opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
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
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOV r32, [base+disp8] changed flags");
}

void testMovGuestMemoryToByteRegister() {
    constexpr std::array<std::uint8_t, 5> code{0x44, 0x8A, 0x70, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "MOV byte register, [memory] opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::R14,
           "MOV byte load extended destination differs");
    expectEqual(destination.width, std::uint8_t{8}, "MOV byte load width differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOV byte from unmapped guest memory did not fail");
    expectEqual(faultState.r14, std::uint64_t{0x1122334455667788ULL},
                "failed MOV byte load changed destination");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed MOV byte load changed flags");
}

void testMovRipRelativeGuestByteToRegister() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x1000};
    constexpr rosa::guest::GuestAddress target{0x2000};
    constexpr std::array<std::uint8_t, 7> code{
        0x8A, 0x05, 0xFA, 0x0F, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "RIP-relative byte MOV load opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{6},
                "RIP-relative byte MOV load length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax &&
               destination.width == 8,
           "RIP-relative byte MOV load destination differs");
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0xFFA,
           "RIP-relative byte MOV load addressing differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "mov al, [rip+0xffa] ; 0x2000") != std::string::npos,
           "RIP-relative byte MOV load dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative byte MOV load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rax = 0x8877665544332211ULL;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
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
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x7FF8000050A0ULL});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegMem,
           "SIB byte MOV load opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3},
                "SIB byte MOV load length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx &&
               destination.width == 8,
           "SIB byte MOV load destination differs");
    expect(memory.base == rosa::x86::Register::Rax &&
               memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 1 && memory.displacement == 0 &&
               memory.width == 8,
           "SIB byte MOV load effective address differs");
    expect(rosa::debug::dumpX86(decoded).find("mov dl, [rax+rcx*1]") !=
               std::string::npos,
           "SIB byte MOV load dump differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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
    expectEqual(state.rax, std::uint64_t{0x8010},
                "SIB byte MOV load changed its base register");
    expectEqual(state.rcx, std::uint64_t{8},
                "SIB byte MOV load changed its index register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "SIB byte MOV load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState = state;
    faultState.rdx = 0x8877665544332211ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "SIB byte MOV load from unmapped memory did not fault");
    expectEqual(faultState.rdx, std::uint64_t{0x8877665544332211ULL},
                "failed SIB byte MOV load changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed SIB byte MOV load changed flags");
}

void testMovzxLowByteRegisterTo32BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{
        0x44, 0x0F, 0xB6, 0xE9, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegReg,
           "MOVZX r32, r8 opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R13 &&
               destination.width == 32,
           "MOVZX r13d destination differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 8,
           "MOVZX CL source differs");
    expect(rosa::debug::dumpX86(decoded).find("movzx r13d, cl") !=
               std::string::npos,
           "MOVZX r13d, cl dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r13 = UINT64_MAX;
    state.rcx = 0x11223344556677ABULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r13, std::uint64_t{0xAB},
                "MOVZX r32, r8 result did not zero-extend");
    expectEqual(state.rcx, std::uint64_t{0x11223344556677ABULL},
                "MOVZX r32, r8 changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOVZX r32, r8 changed flags");

    constexpr std::array<std::uint8_t, 3> highByteCode{0x0F, 0xB6, 0xE4};
    bool rejectedHighByte = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejectedHighByte = true;
    }
    expect(rejectedHighByte, "MOVZX from AH was not rejected explicitly");
}

void testMovzxGuestByteTo32BitRegister() {
    constexpr std::array<std::uint8_t, 5> code{
        0x0F, 0xB6, 0x48, 0x2F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegMem,
           "MOVZX r32, byte [memory] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4},
                "MOVZX r32, byte [memory] length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 32,
           "MOVZX byte destination differs");
    expect(memory.base == rosa::x86::Register::Rax && memory.width == 8 &&
               memory.displacement == 0x2F,
           "MOVZX byte memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "movzx ecx, byte [rax+0x2f]") != std::string::npos,
           "MOVZX byte dump differs");

    std::array<std::uint8_t, 0x40> data{};
    data[0x2F] = 0xA5;
    data[0x30] = 0xDE;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(rosa::guest::GuestAddress{0x8000},
                            rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read, data);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8000;
    state.rcx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0xA5},
                "MOVZX byte result did not zero-extend");
    expectEqual(state.rax, std::uint64_t{0x8000},
                "MOVZX byte changed its base register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOVZX byte changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rax = 0x8000;
    faultState.rcx = 0x0123456789ABCDEFULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOVZX byte from unmapped guest memory did not fault");
    expectEqual(faultState.rcx, std::uint64_t{0x0123456789ABCDEFULL},
                "failed MOVZX byte changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed MOVZX byte changed flags");

    bool truncatedRejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            std::span<const std::uint8_t>{code}.first(3),
            rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        truncatedRejected = true;
    }
    expect(truncatedRejected, "truncated MOVZX byte displacement was accepted");
}

void testMovzxGuestByteWithSibTo64BitRegister() {
    constexpr std::array<std::uint8_t, 6> code{
        0x48, 0x0F, 0xB6, 0x04, 0x0F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegMem,
           "MOVZX r64, byte SIB opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{5},
                "MOVZX r64, byte SIB length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax &&
               destination.width == 64,
           "MOVZX byte SIB destination differs");
    expect(memory.base == rosa::x86::Register::Rdi &&
               memory.index == rosa::x86::Register::Rcx &&
               memory.scale == 1 && memory.displacement == 0 &&
               memory.width == 8,
           "MOVZX byte SIB memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "movzx rax, byte [rdi+rcx*1]") != std::string::npos,
           "MOVZX byte SIB dump differs");

    std::array<std::uint8_t, 0x40> data{};
    data[0x2F] = 0xA5;
    data[0x30] = 0xDE;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(rosa::guest::GuestAddress{0x8000},
                            rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read, data);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rdi = 0x8000;
    state.rcx = 0x2F;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0xA5},
                "MOVZX r64 byte SIB result did not zero-extend");
    expectEqual(state.rdi, std::uint64_t{0x8000},
                "MOVZX byte SIB changed its base");
    expectEqual(state.rcx, std::uint64_t{0x2F},
                "MOVZX byte SIB changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOVZX byte SIB changed flags");

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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOVZX r64 byte SIB from unmapped memory did not fault");
    expectEqual(faultState.rax, std::uint64_t{0x0123456789ABCDEFULL},
                "failed MOVZX r64 byte SIB changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed MOVZX r64 byte SIB changed flags");
}

void testMovzx16BitRegisterTo32BitRegister() {
    constexpr std::array<std::uint8_t, 4> code{
        0x0F, 0xB7, 0xC7, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegReg,
           "MOVZX r32, r16 opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax &&
               destination.width == 32 &&
               source.reg == rosa::x86::Register::Rdi && source.width == 16,
           "MOVZX EAX, DI operands differ");
    expect(rosa::debug::dumpX86(decoded).find("movzx eax, di") !=
               std::string::npos,
           "MOVZX EAX, DI dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rdi = 0x112233445566BEEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xBEEF},
                "MOVZX EAX, DI result did not zero-extend");
    expectEqual(state.rdi, std::uint64_t{0x112233445566BEEFULL},
                "MOVZX EAX, DI changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOVZX EAX, DI changed flags");
}

void testMovzxGuestWordTo32BitRegister() {
    constexpr std::array<std::uint8_t, 7> code{
        0x41, 0x0F, 0xB7, 0x4C, 0x24, 0x04, 0xC3};
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
    constexpr std::array<std::uint8_t, 5> ignoredRexXCode{
        0x42, 0x0F, 0xB7, 0x03, 0xC3};
    const auto ignoredRexX = decoder.decodeBlock(
        ignoredRexXCode, rosa::guest::GuestAddress{0x2000});
    const auto ignoredRexXMemory =
        std::get<rosa::x86::MemoryOperand>(ignoredRexX[0].operands[1]);
    expect(ignoredRexXMemory.base == rosa::x86::Register::Rbx &&
               !ignoredRexXMemory.index,
           "MOVZX treated REX.X as an index without a SIB");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 2> word{0x58, 0x54};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8004}, word);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r12 = 0x8000;
    state.rcx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0x5458},
                "MOVZX word result or zero extension differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVZX changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r12 = 0x8000;
    faultState.rcx = 0x1234;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOVZX from unmapped guest memory did not fail");
    expectEqual(faultState.rcx, std::uint64_t{0x1234},
                "failed MOVZX changed destination");
}

void testMovzxGuestWordWithScaledIndex() {
    constexpr std::array<std::uint8_t, 7> code{
        0x46, 0x0F, 0xB7, 0x74, 0x6B, 0x16, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovzxRegMem,
           "indexed MOVZX opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R14 &&
               destination.width == 32,
           "indexed MOVZX destination differs");
    expect(memory.base == rosa::x86::Register::Rbx &&
               memory.index == rosa::x86::Register::R13 &&
               memory.scale == 2 && memory.displacement == 0x16 &&
               memory.width == 16,
           "indexed MOVZX memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find("[rbx+r13*2+0x16]") !=
               std::string::npos,
           "indexed MOVZX dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 4> sourceWithUpperSentinel{
        0xEF, 0xBE, 0xAD, 0xDE};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x811C},
                            sourceWithUpperSentinel);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rbx = 0x8100;
    state.r13 = 3;
    state.r14 = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0xBEEF},
                "indexed MOVZX result or zero extension differs");
    expectEqual(state.rbx, std::uint64_t{0x8100},
                "indexed MOVZX changed its base");
    expectEqual(state.r13, std::uint64_t{3},
                "indexed MOVZX changed its index");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "indexed MOVZX changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.r14 = UINT64_MAX;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "indexed MOVZX from unmapped guest memory did not fault");
    expectEqual(state.r14, UINT64_MAX,
                "failed indexed MOVZX changed its destination");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "failed indexed MOVZX changed flags");
}

void testMovsxdScaledGuestDword() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x63, 0x0C, 0x88, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovsxdRegMem,
           "MOVSXD scaled memory opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rax,
           "MOVSXD scaled base differs");
    expect(memory.index == rosa::x86::Register::Rcx,
           "MOVSXD scaled index differs");
    expectEqual(memory.scale, std::uint8_t{4}, "MOVSXD scaled factor differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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

void testCdqeGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x48, 0x98, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Cdqe,
           "CDQE opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "CDQE length differs");
    expect(decoded[0].operands.empty(), "CDQE unexpectedly has explicit operands");
    expect(rosa::debug::dumpX86(decoded).find("cdqe") != std::string::npos,
           "CDQE dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State negative;
    negative.rax = 0xAAAAAAAA80000001ULL;
    negative.rflags = 0x8D7;
    static_cast<void>(block.execute(negative));
    expectEqual(negative.rax, std::uint64_t{0xFFFFFFFF80000001ULL},
                "CDQE negative result differs");
    expectEqual(negative.rflags, std::uint64_t{0x8D7}, "CDQE changed flags");

    rosa::x86::X86State positive;
    positive.rax = 0xFFFFFFFF7FFFFFFFULL;
    positive.rflags = 0xAD7;
    static_cast<void>(block.execute(positive));
    expectEqual(positive.rax, std::uint64_t{0x7FFFFFFF},
                "CDQE positive result differs");
    expectEqual(positive.rflags, std::uint64_t{0xAD7}, "CDQE changed flags");
}

void testMovGuestMemoryToLegacy32BitRegister() {
    constexpr std::array<std::uint8_t, 4> code{0x8B, 0x4E, 0x0C, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rcx,
           "legacy MOV r32, [base+disp8] destination differs");
    expectEqual(destination.width, std::uint8_t{32},
                "legacy MOV r32, [base+disp8] width differs");

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

void testTestRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x85, 0xC9, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegReg,
           "TEST r64, r64 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rcx,
           "TEST r64, r64 left operand differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State zeroState;
    zeroState.rcx = 0;
    zeroState.rflags = UINT64_MAX;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rcx, std::uint64_t{0}, "TEST changed its guest register operand");
    constexpr auto expectedZeroFlags =
        (UINT64_MAX & ~std::uint64_t{0x8D5}) | std::uint64_t{0x46};
    expectEqual(zeroState.rflags, expectedZeroFlags,
                "TEST zero-result flags differ");

    rosa::x86::X86State signState;
    signState.rcx = 0x8000000000000001ULL;
    static_cast<void>(block.execute(signState));
    expectEqual(signState.rcx, std::uint64_t{0x8000000000000001ULL},
                "TEST changed a nonzero guest register operand");
    expectEqual(signState.rflags, std::uint64_t{0x82},
                "TEST sign-result flags differ");
}

void testTest16BitRegistersGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{
        0x66, 0x45, 0x85, 0xF6, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegReg,
           "TEST r16, r16 opcode differs");
    const auto lhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto rhs = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(lhs.reg == rosa::x86::Register::R14 && lhs.width == 16 &&
               rhs.reg == rosa::x86::Register::R14 && rhs.width == 16,
           "TEST r14w operands differ");
    expect(rosa::debug::dumpX86(decoded).find("test r14w, r14w") !=
               std::string::npos,
           "TEST r14w dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0xA5A5A5A500000000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0xA5A5A5A500000000ULL},
                "TEST r16 changed its operand");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "TEST r16 zero flags differ");

    state.r14 = 0x1122334455668000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0x1122334455668000ULL},
                "TEST r16 sign case changed its operand");
    expectEqual(state.rflags, std::uint64_t{0x86},
                "TEST r16 sign flags differ");
}

void testTest32BitRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x45, 0x85, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegReg,
           "TEST r32, r32 opcode differs");
    const auto operand = std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::R8,
           "TEST r32, r32 extended register differs");
    expectEqual(operand.width, std::uint8_t{32}, "TEST r32, r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r8 = 0xFFFFFFFF80000000ULL;
    state.rflags = UINT64_MAX;
    static_cast<void>(block.execute(state));
    expectEqual(state.r8, std::uint64_t{0xFFFFFFFF80000000ULL},
                "TEST r32, r32 changed its guest operand");
    constexpr auto expectedFlags =
        (UINT64_MAX & ~std::uint64_t{0x8D5}) | std::uint64_t{0x86};
    expectEqual(state.rflags, expectedFlags, "TEST r32, r32 flags differ");
}

void testLegacyTest32BitRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x85, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegReg,
           "legacy TEST r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "legacy TEST r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xFFFFFFFF00000000ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFFFFFFF00000000ULL},
                "legacy TEST changed EAX");
    expectEqual(state.rflags, std::uint64_t{0x46}, "legacy TEST flags differ");
}

void testLegacyTestLowByteGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x84, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestReg8Reg8,
           "legacy TEST r8, r8 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{8}, "legacy TEST r8 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0xFFFFFFFFFFFFFF00ULL;
    zeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0xFFFFFFFFFFFFFF00ULL},
                "TEST al, al changed RAX");
    expectEqual(zeroState.rflags, std::uint64_t{0x46},
                "TEST zero AL flags differ");

    rosa::x86::X86State signState;
    signState.rax = 0x80;
    static_cast<void>(block.execute(signState));
    expectEqual(signState.rflags, std::uint64_t{0x82},
                "TEST signed AL flags differ");

    constexpr std::array<std::uint8_t, 4> extendedCode{
        0x45, 0x84, 0xF6, 0xC3};
    const auto extendedDecoded = decoder.decodeBlock(
        extendedCode, rosa::guest::GuestAddress{0x2000});
    const auto extendedLhs =
        std::get<rosa::x86::RegisterOperand>(
            extendedDecoded[0].operands[0]);
    const auto extendedRhs =
        std::get<rosa::x86::RegisterOperand>(
            extendedDecoded[0].operands[1]);
    expect(extendedLhs.reg == rosa::x86::Register::R14 &&
               extendedLhs.width == 8 &&
               extendedRhs.reg == rosa::x86::Register::R14 &&
               extendedRhs.width == 8,
           "TEST R14B, R14B operands differ");
    expect(rosa::debug::dumpX86(extendedDecoded).find(
               "test r14b, r14b") != std::string::npos,
           "TEST R14B dump differs");
    const auto extendedBlock = translator.translate(
        extendedCode, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State extendedState;
    extendedState.r14 = 0x1122334455667780ULL;
    extendedState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.r14, std::uint64_t{0x1122334455667780ULL},
                "TEST R14B changed R14");
    expectEqual(extendedState.rflags, std::uint64_t{0x82},
                "TEST R14B flags differ");
}

void testTestAccumulatorImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0xA8, 0x03, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegImm,
           "TEST AL, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{8}, "TEST AL, imm8 register width differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{3}, "TEST AL, imm8 immediate differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xABCDEF1234567806ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xABCDEF1234567806ULL},
                "TEST AL, imm8 changed RAX");
    expectEqual(state.rflags, std::uint64_t{0x2}, "TEST AL, imm8 flags differ");
}

void testTestLowByteRegisterImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0xF6, 0xC2, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::TestRegImm,
           "TEST DL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3},
                "TEST DL, imm8 length differs");
    const auto operand =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::Rdx && operand.width == 8,
           "TEST DL, imm8 register differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{1}, "TEST DL, imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("test dl, 0x1") != std::string::npos,
           "TEST DL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0x1122334455667782ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0x1122334455667782ULL},
                "TEST DL, imm8 changed RDX");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags,
                std::uint64_t{(1U << 2U) | (1U << 6U)},
                "TEST DL, imm8 zero-result flags differ");

    constexpr std::array<std::uint8_t, 4> signCode{0xF6, 0xC2, 0x80, 0xC3};
    const auto signBlock = translator.translate(
        signCode, rosa::guest::GuestAddress{0x2000});
    state.rdx = 0x80;
    state.rflags = 0x8D7;
    static_cast<void>(signBlock.execute(state));
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "TEST DL, imm8 sign-result flags differ");

    constexpr std::array<std::uint8_t, 5> extendedCode{
        0x41, 0xF6, 0xC6, 0x02, 0xC3};
    const auto extendedDecoded = decoder.decodeBlock(
        extendedCode, rosa::guest::GuestAddress{0x3000});
    expectEqual(extendedDecoded[0].length, std::uint8_t{4},
                "TEST r14b, imm8 length differs");
    const auto extendedOperand =
        std::get<rosa::x86::RegisterOperand>(extendedDecoded[0].operands[0]);
    expect(extendedOperand.reg == rosa::x86::Register::R14 &&
               extendedOperand.width == 8,
           "TEST r14b, imm8 register differs");
    expect(rosa::debug::dumpX86(extendedDecoded).find("test r14b, 0x2") !=
               std::string::npos,
           "TEST r14b, imm8 dump differs");
    const auto extendedBlock = translator.translate(
        extendedCode, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State extendedState;
    extendedState.r14 = 0x8877665544332202ULL;
    extendedState.rflags = 0x8D7;
    static_cast<void>(extendedBlock.execute(extendedState));
    expectEqual(extendedState.r14, std::uint64_t{0x8877665544332202ULL},
                "TEST r14b, imm8 changed R14");
    expectEqual(extendedState.rflags & definedLogicFlags, std::uint64_t{0},
                "TEST r14b, imm8 defined flags differ");

    constexpr std::array<std::uint8_t, 4> highByteCode{0xF6, 0xE6, 0x01, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            highByteCode, rosa::guest::GuestAddress{0x4000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "TEST DH, imm8 was silently treated as a low-byte register form");
}

void testLfenceGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0xAE, 0xE8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Lfence, "LFENCE opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "LFENCE length differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x0123456789ABCDEFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x0123456789ABCDEFULL},
                "LFENCE changed a guest register");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "LFENCE changed guest flags");
    expect(std::find(block.program().listing.begin(), block.program().listing.end(), "dmb ish") !=
               block.program().listing.end(),
           "LFENCE did not emit an ARM64 memory barrier");
    expect(std::find(block.program().listing.begin(), block.program().listing.end(), "isb") !=
               block.program().listing.end(),
           "LFENCE did not emit an ARM64 instruction barrier");
}

void testRdtscGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x0F, 0x31, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::Rdtsc, "RDTSC opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "RDTSC length differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = UINT64_MAX;
    state.rdx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, nullptr, &fixedTimestampCounter));
    expectEqual(state.rax, std::uint64_t{0xABCDEF01},
                "RDTSC did not zero-extend EAX");
    expectEqual(state.rdx, std::uint64_t{0x12345678},
                "RDTSC did not zero-extend EDX");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "RDTSC changed guest flags");

    rosa::x86::X86State missingSourceState;
    missingSourceState.rax = 0x55;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(missingSourceState));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("timestamp-counter source") !=
                   std::string_view::npos;
    }
    expect(rejected, "RDTSC without a virtual counter source did not fail");
    expectEqual(missingSourceState.rax, std::uint64_t{0x55},
                "failed RDTSC changed guest EAX");
}

void testShiftLeftImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0xC1, 0xE2, 0x20, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShlRegImm,
           "SHL r64, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{32}, "SHL r64, imm8 count differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdx = 0x0000000180000001ULL;
    state.rflags = 0x812;
    static_cast<void>(block.execute(state));
    expectEqual(state.rdx, std::uint64_t{0x8000000100000000ULL},
                "SHL r64, 32 result differs");
    expectEqual(state.rflags, std::uint64_t{0x897},
                "SHL r64, 32 flags differ");

    constexpr std::array<std::uint8_t, 5> zeroCount{0x48, 0xC1, 0xE2, 0x40, 0xC3};
    const auto zeroBlock =
        translator.translate(zeroCount, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State zeroState;
    zeroState.rdx = 0x55;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rdx, std::uint64_t{0x55},
                "SHL with a masked zero count changed the value");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHL with a masked zero count changed flags");

    constexpr std::array<std::uint8_t, 4> code32{0xC1, 0xE2, 0x04, 0xC3};
    const auto decoded32 = decoder.decodeBlock(
        code32, rosa::guest::GuestAddress{0x3000});
    expect(decoded32[0].opcode == rosa::x86::Opcode::ShlRegImm,
           "SHL r32, imm8 opcode differs");
    const auto destination32 =
        std::get<rosa::x86::RegisterOperand>(decoded32[0].operands[0]);
    expect(destination32.reg == rosa::x86::Register::Rdx &&
               destination32.width == 32,
           "SHL EDX, imm8 destination differs");
    expectEqual(decoded32[0].length, std::uint8_t{3},
                "SHL EDX, imm8 length differs");
    expect(rosa::debug::dumpX86(decoded32).find("shl edx, 0x4") !=
               std::string::npos,
           "SHL EDX, imm8 dump differs");
    const auto block32 = translator.translate(
        code32, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State state32;
    state32.rdx = 0xAAAAAAAA08000001ULL;
    state32.rflags = 0x8D7;
    static_cast<void>(block32.execute(state32));
    expectEqual(state32.rdx, std::uint64_t{0x80000010},
                "SHL EDX, 4 result did not zero-extend");
    constexpr std::uint64_t definedManyFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state32.rflags & definedManyFlags,
                std::uint64_t{1U << 7U},
                "SHL EDX, 4 defined flags differ");

    constexpr std::array<std::uint8_t, 4> one32{0xC1, 0xE2, 0x01, 0xC3};
    const auto one32Block = translator.translate(
        one32, rosa::guest::GuestAddress{0x4000});
    state32.rdx = 0xFFFFFFFF40000000ULL;
    state32.rflags = 0;
    static_cast<void>(one32Block.execute(state32));
    expectEqual(state32.rdx, std::uint64_t{0x80000000},
                "SHL EDX, 1 result differs");
    constexpr std::uint64_t definedOneFlags =
        definedManyFlags | (std::uint64_t{1} << 11U);
    expectEqual(state32.rflags & definedOneFlags,
                std::uint64_t{(1U << 2U) | (1U << 7U) | (1U << 11U)},
                "SHL EDX, 1 defined flags differ");

    constexpr std::array<std::uint8_t, 4> zero32{0xC1, 0xE2, 0x20, 0xC3};
    const auto zero32Block = translator.translate(
        zero32, rosa::guest::GuestAddress{0x5000});
    state32.rdx = 0xAAAAAAAA12345678ULL;
    state32.rflags = 0xAD7;
    static_cast<void>(zero32Block.execute(state32));
    expectEqual(state32.rdx, std::uint64_t{0x12345678},
                "SHL EDX masked-zero result did not zero-extend");
    expectEqual(state32.rflags, std::uint64_t{0xAD7},
                "SHL EDX masked-zero count changed flags");
}

void testShiftLeftClGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0xD3, 0xE0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShlRegCl,
           "SHL r64, CL opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "SHL r64, CL destination differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8000000000000001ULL;
    state.rcx = 65;
    state.rflags = 0x10;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{2},
                "SHL r64, CL did not mask the count to six bits");
    expectEqual(state.rcx, std::uint64_t{65}, "SHL r64, CL changed RCX");
    expectEqual(state.rflags, std::uint64_t{0x813},
                "SHL r64, CL flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0x55;
    zeroState.rcx = 64;
    zeroState.rflags = 0xAD7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x55},
                "SHL r64, CL with a masked zero count changed the value");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHL r64, CL with a masked zero count changed flags");
}

void testShiftLeft32ClGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0xD3, 0xE0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShlRegCl,
           "SHL r32, CL opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 32,
           "SHL EAX, CL destination differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "SHL EAX, CL length differs");
    expect(rosa::debug::dumpX86(decoded).find("shl eax, cl") !=
               std::string::npos,
           "SHL EAX, CL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xFFFFFFFF80000001ULL;
    state.rcx = 1;
    state.rflags = 0x10;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{2},
                "SHL EAX, CL result did not zero-extend");
    expectEqual(state.rcx, std::uint64_t{1}, "SHL EAX, CL changed RCX");
    expectEqual(state.rflags, std::uint64_t{0x813},
                "SHL EAX, CL count-one flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0xAAAAAAAA12345678ULL;
    zeroState.rcx = 32;
    zeroState.rflags = 0xAD7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x12345678},
                "SHL EAX, CL masked-zero result did not zero-extend");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHL EAX, CL masked-zero count changed flags");

    rosa::x86::X86State manyState;
    manyState.rax = 0xFFFFFFFF80000001ULL;
    manyState.rcx = 31;
    manyState.rflags = 0x810;
    static_cast<void>(block.execute(manyState));
    expectEqual(manyState.rax, std::uint64_t{0x80000000},
                "SHL EAX, CL count-31 result differs");
    constexpr std::uint64_t definedManyFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(manyState.rflags & definedManyFlags,
                std::uint64_t{(1U << 2U) | (1U << 7U)},
                "SHL EAX, CL count-31 defined flags differ");
}

void testShiftRight32ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0xC1, 0xE8, 0x1F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShrRegImm,
           "SHR r32, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "SHR r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xFFFFFFFF80000001ULL;
    state.rflags = 0x812;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{1},
                "SHR eax, 31 result or zero-extension differs");
    expectEqual(state.rflags, std::uint64_t{0x812}, "SHR eax, 31 flags differ");

    constexpr std::array<std::uint8_t, 4> countOne{0xC1, 0xE8, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.rax = 0x80000001;
    oneState.rflags = 0x10;
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.rax, std::uint64_t{0x40000000}, "SHR eax, 1 result differs");
    expectEqual(oneState.rflags, std::uint64_t{0x817}, "SHR eax, 1 flags differ");

    constexpr std::array<std::uint8_t, 4> zeroCount{0xC1, 0xE8, 0x20, 0xC3};
    const auto zeroBlock = translator.translate(zeroCount, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0x55;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x55}, "SHR masked-zero changed EAX");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHR masked-zero changed flags");
}

void testShiftRight64ImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0xC1, 0xE8, 0x3E, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShrRegImm,
           "SHR r64, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{4}, "SHR r64 length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax,
           "SHR r64 destination differs");
    expectEqual(destination.width, std::uint8_t{64}, "SHR r64 width differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{62}, "SHR r64 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("shr rax, 0x3e") != std::string::npos,
           "SHR r64 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xE000000000000200ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{3}, "SHR r64 count-62 result differs");
    constexpr std::uint64_t definedManyFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U);
    expectEqual(state.rflags & definedManyFlags,
                std::uint64_t{(1U << 0U) | (1U << 2U)},
                "SHR r64 count-62 defined flags differ");

    constexpr std::array<std::uint8_t, 5> countOne{0x48, 0xC1, 0xE8, 0x01, 0xC3};
    const auto oneBlock = translator.translate(countOne, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State oneState;
    oneState.rax = 0x8000000000000001ULL;
    oneState.rflags = 0x10;
    static_cast<void>(oneBlock.execute(oneState));
    expectEqual(oneState.rax, std::uint64_t{0x4000000000000000ULL},
                "SHR r64 count-one result differs");
    constexpr std::uint64_t definedOneFlags =
        definedManyFlags | (std::uint64_t{1} << 11U);
    expectEqual(oneState.rflags & definedOneFlags,
                std::uint64_t{(1U << 0U) | (1U << 2U) | (1U << 11U)},
                "SHR r64 count-one defined flags differ");

    constexpr std::array<std::uint8_t, 5> zeroCount{0x48, 0xC1, 0xE8, 0x40, 0xC3};
    const auto zeroBlock = translator.translate(zeroCount, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0xE000000000000200ULL;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0xE000000000000200ULL},
                "SHR r64 masked-zero changed RAX");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHR r64 masked-zero changed flags");
}

void testNeg64GeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x49, 0xF7, 0xDD, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::NegReg,
           "NEG r64 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3}, "NEG r64 length differs");
    const auto operand =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(operand.reg == rosa::x86::Register::R13 && operand.width == 64,
           "NEG r13 operand differs");
    expect(rosa::debug::dumpX86(decoded).find("neg r13") != std::string::npos,
           "NEG r13 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});

    rosa::x86::X86State zero;
    zero.r13 = 0;
    zero.rflags = 0x8D7;
    static_cast<void>(block.execute(zero));
    expectEqual(zero.r13, std::uint64_t{0}, "NEG zero result differs");
    expectEqual(zero.rflags, std::uint64_t{0x46}, "NEG zero flags differ");

    rosa::x86::X86State one;
    one.r13 = 1;
    one.rflags = 0;
    static_cast<void>(block.execute(one));
    expectEqual(one.r13, UINT64_MAX, "NEG one result differs");
    expectEqual(one.rflags, std::uint64_t{0x97}, "NEG one flags differ");

    rosa::x86::X86State overflow;
    overflow.r13 = std::uint64_t{1} << 63U;
    overflow.rflags = 0;
    static_cast<void>(block.execute(overflow));
    expectEqual(overflow.r13, std::uint64_t{1} << 63U,
                "NEG minimum result differs");
    expectEqual(overflow.rflags, std::uint64_t{0x887},
                "NEG minimum flags differ");
}

void testUnsignedMultiplyGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0xF7, 0xE1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MulReg, "MUL r64 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rcx,
           "MUL r64 source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State smallState;
    smallState.rax = 3;
    smallState.rcx = 4;
    smallState.rdx = UINT64_MAX;
    smallState.rflags = 0x8D7;
    static_cast<void>(block.execute(smallState));
    expectEqual(smallState.rax, std::uint64_t{12}, "MUL low result differs");
    expectEqual(smallState.rdx, std::uint64_t{0}, "MUL high result differs");
    expectEqual(smallState.rcx, std::uint64_t{4}, "MUL changed its source register");
    expectEqual(smallState.rflags, std::uint64_t{0xD6},
                "MUL zero-high defined flags differ");

    rosa::x86::X86State wideState;
    wideState.rax = UINT64_MAX;
    wideState.rcx = 2;
    wideState.rflags = 0x2;
    static_cast<void>(block.execute(wideState));
    expectEqual(wideState.rax, std::uint64_t{UINT64_MAX - 1},
                "MUL wide low result differs");
    expectEqual(wideState.rdx, std::uint64_t{1}, "MUL wide high result differs");
    expectEqual(wideState.rflags, std::uint64_t{0x803},
                "MUL nonzero-high defined flags differ");
}

void testSignedMultiply64GeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{
        0x49, 0x0F, 0xAF, 0xCD, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ImulRegReg,
           "IMUL r64, r64 opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx &&
               destination.width == 64 &&
               source.reg == rosa::x86::Register::R13 && source.width == 64,
           "IMUL rcx, r13 operands differ");
    expect(rosa::debug::dumpX86(decoded).find("imul rcx, r13") !=
               std::string::npos,
           "IMUL rcx, r13 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 2;
    state.r13 = static_cast<std::uint64_t>(-3);
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFFFFFFFFFFFFFFFAULL},
                "non-overflowing signed IMUL result differs");
    expectEqual(state.r13, static_cast<std::uint64_t>(-3),
                "signed IMUL changed its source");
    expectEqual(state.rflags, std::uint64_t{0xD6},
                "non-overflowing signed IMUL defined flags differ");

    state.rcx = static_cast<std::uint64_t>(INT64_MAX);
    state.r13 = 2;
    state.rflags = 0xD6;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFFFFFFFFFFFFFFFEULL},
                "overflowing signed IMUL low result differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "overflowing signed IMUL did not set CF and OF");

    state.rcx = std::uint64_t{1} << 63U;
    state.r13 = UINT64_MAX;
    state.rflags = 0;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{1} << 63U,
                "minimum-times-negative-one IMUL low result differs");
    expectEqual(state.rflags, std::uint64_t{0x803},
                "minimum-times-negative-one IMUL flags differ");
}

void testShiftRightDoubleGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x48, 0x0F, 0xAC, 0xD0, 0x20, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::ShrdRegRegImm,
           "SHRD r64, r64, imm8 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rax,
           "SHRD destination differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::Register::Rdx,
           "SHRD source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x0123456789ABCDEFULL;
    state.rdx = 0xFEDCBA9876543210ULL;
    state.rflags = 0x812;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x7654321001234567ULL},
                "SHRD result differs");
    expectEqual(state.rdx, std::uint64_t{0xFEDCBA9876543210ULL},
                "SHRD changed its source");
    expectEqual(state.rflags, std::uint64_t{0x813}, "SHRD flags differ");

    constexpr std::array<std::uint8_t, 6> zeroCount{
        0x48, 0x0F, 0xAC, 0xD0, 0x40, 0xC3,
    };
    const auto zeroBlock = translator.translate(zeroCount, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State zeroState;
    zeroState.rax = 0x55;
    zeroState.rdx = UINT64_MAX;
    zeroState.rflags = 0xAD7;
    static_cast<void>(zeroBlock.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x55},
                "SHRD masked-zero count changed its destination");
    expectEqual(zeroState.rflags, std::uint64_t{0xAD7},
                "SHRD masked-zero count changed flags");
}

void testOrRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x09, 0xD0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegReg,
           "OR r64, r64 opcode differs");
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x00000000ABCDEF01ULL;
    state.rdx = 0x1234567800000000ULL;
    state.rflags = UINT64_MAX;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x12345678ABCDEF01ULL},
                "OR r64, r64 result differs");
    expectEqual(state.rdx, std::uint64_t{0x1234567800000000ULL},
                "OR r64, r64 changed its source");
    constexpr auto expectedFlags =
        (UINT64_MAX & ~std::uint64_t{0x8D5}) | std::uint64_t{0x2};
    expectEqual(state.rflags, expectedFlags, "OR r64, r64 flags differ");
}

void testOr8BitRegistersGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x08, 0xC8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegReg,
           "OR r8, r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "OR r8, r8 length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax &&
               destination.width == 8 && source.reg == rosa::x86::Register::Rcx &&
               source.width == 8,
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
    expectEqual(state.rcx, std::uint64_t{0x8877665544332201ULL},
                "OR AL, CL changed its source");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags,
                std::uint64_t{(1U << 2U) | (1U << 7U)},
                "OR AL, CL defined flags differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0x08, 0xE0, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "OR AL, AH was silently treated as a low-byte register form");
}

void testOrShortImmediateGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x83, 0xC8, 0xFF, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegImm,
           "OR r64, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                UINT64_MAX, "OR imm8 was not sign-extended");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1234;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, UINT64_MAX, "OR r64, imm8 result differs");
    expectEqual(state.rflags, std::uint64_t{0x86}, "OR r64, imm8 flags differ");

    constexpr std::array<std::uint8_t, 4> legacyCode{
        0x83, 0xC9, 0x04, 0xC3};
    const auto legacyDecoded = decoder.decodeBlock(
        legacyCode, rosa::guest::GuestAddress{0x2000});
    expectEqual(
        std::get<rosa::x86::RegisterOperand>(legacyDecoded[0].operands[0]).width,
        std::uint8_t{32}, "OR r32, imm8 width differs");
    const auto legacyBlock = translator.translate(
        legacyCode, rosa::guest::GuestAddress{0x2000});
    state.rcx = 0xAAAAAAAA00000002ULL;
    state.rflags = 0x8D7;
    static_cast<void>(legacyBlock.execute(state));
    expectEqual(state.rcx, std::uint64_t{6},
                "OR r32, imm8 result did not zero-extend");
    expectEqual(state.rflags, std::uint64_t{0x6},
                "OR r32, imm8 flags differ");
}

void testOr32BitRegistersGeneratedExecution() {
    constexpr std::array<std::uint8_t, 3> code{0x09, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::OrRegReg,
           "OR r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "OR r32, r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0xAAAAAAAA000000F0ULL;
    state.rax = 0xBBBBBBBB0000000FULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0xFF},
                "OR r32, r32 result or zero extension differs");
    expectEqual(state.rax, std::uint64_t{0xBBBBBBBB0000000FULL},
                "OR r32, r32 changed source");
    expectEqual(state.rflags, std::uint64_t{0x6}, "OR r32, r32 flags differ");
}

void testXor32BitRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 6> code{0x31, 0xF6, 0x45, 0x31, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegReg,
           "legacy XOR r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "legacy XOR r32 width differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[1].operands[0]).reg ==
               rosa::x86::Register::R8,
           "REX XOR r8d destination differs");

    const rosa::dbt::Translator translator;
    const auto zeroEsi = translator.translate(code, rosa::guest::GuestAddress{0x1000}, 1);
    const auto zeroR8 = translator.translate(std::span(code).subspan(2),
                                             rosa::guest::GuestAddress{0x1002}, 1);
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
}

void testXor32BitRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 5> code{0x41, 0x33, 0x04, 0x24, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegMem,
           "XOR r32, [memory] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R12,
           "XOR no-index SIB base differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8000}, 0x45545F5F);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0xAAAAAAAA45545F5FULL;
    state.r12 = 0x8000;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rax, std::uint64_t{0},
                "XOR r32, [memory] result or zero extension differs");
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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "XOR from unmapped guest memory did not fail");
    expectEqual(faultState.rax, std::uint64_t{0x45545F5F},
                "failed XOR memory changed destination");
    expectEqual(faultState.rflags, std::uint64_t{0x8D7},
                "failed XOR memory changed flags");

    constexpr std::array<std::uint8_t, 3> legacyCode{0x33, 0x08, 0xC3};
    const auto legacyDecoded = decoder.decodeBlock(
        legacyCode, rosa::guest::GuestAddress{0x2000});
    expect(legacyDecoded[0].opcode == rosa::x86::Opcode::XorRegMem,
           "legacy XOR r32, [memory] opcode differs");
    const auto legacyBlock = translator.translate(
        legacyCode, rosa::guest::GuestAddress{0x2000});
    state.rax = 0x8000;
    state.rcx = 0xAAAAAAAA45545F5FULL;
    state.rflags = 0x8D7;
    static_cast<void>(legacyBlock.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0},
                "legacy XOR r32, [memory] result differs");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "legacy XOR r32, [memory] flags differ");
}

void testXor64BitRegisterFromGuestMemory() {
    constexpr std::array<std::uint8_t, 4> code{0x48, 0x33, 0x08, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegMem,
           "XOR r64, [memory] opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{64}, "XOR r64, [memory] width differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8100},
                          0x44454B4E494C5F5FULL);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x8100;
    state.rcx = 0x44454B4E494C5F5FULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.rcx, std::uint64_t{0}, "XOR r64, [memory] result differs");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "XOR r64, [memory] flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.rcx = 0x1122334455667788ULL;
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "XOR r64 from unmapped guest memory did not fault");
    expectEqual(state.rcx, std::uint64_t{0x1122334455667788ULL},
                "failed XOR r64 changed destination");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "failed XOR r64 changed flags");
}

void testXor32BitRegisterImmediate() {
    constexpr std::array<std::uint8_t, 7> code{
        0x81, 0xF1, 0x58, 0x54, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegImm,
           "XOR r32, imm32 opcode differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0xAAAAAAAA00005458ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0},
                "XOR r32, imm32 result or zero extension differs");
    expectEqual(state.rflags, std::uint64_t{0x46}, "XOR r32, imm32 flags differ");

    constexpr std::array<std::uint8_t, 6> accumulatorCode{
        0x35, 0x58, 0x54, 0x00, 0x00, 0xC3};
    const auto accumulatorDecoded = decoder.decodeBlock(
        accumulatorCode, rosa::guest::GuestAddress{0x2000});
    expect(accumulatorDecoded[0].opcode == rosa::x86::Opcode::XorRegImm,
           "XOR EAX, imm32 opcode differs");
    const auto accumulatorBlock = translator.translate(
        accumulatorCode, rosa::guest::GuestAddress{0x2000});
    state.rax = 0xAAAAAAAA00005458ULL;
    state.rflags = 0x8D7;
    static_cast<void>(accumulatorBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0},
                "XOR EAX, imm32 did not zero-extend result");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "XOR EAX, imm32 flags differ");
}

void testXor64BitAccumulatorImmediate() {
    constexpr std::array<std::uint8_t, 7> observedCode{
        0x48, 0x35, 0x49, 0x54, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        observedCode, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegImm,
           "XOR RAX, imm32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{64}, "XOR RAX, imm32 width differs");

    const rosa::dbt::Translator translator;
    const auto observedBlock = translator.translate(
        observedCode, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x5449;
    state.rflags = 0x8D7;
    static_cast<void>(observedBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0},
                "XOR RAX, positive imm32 result differs");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "XOR RAX, positive imm32 flags differ");

    constexpr std::array<std::uint8_t, 7> negativeCode{
        0x48, 0x35, 0x00, 0x00, 0x00, 0x80, 0xC3};
    const auto negativeBlock = translator.translate(
        negativeCode, rosa::guest::GuestAddress{0x2000});
    state.rax = 0;
    state.rflags = 0x8D7;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFFFFFFF80000000ULL},
                "XOR RAX, imm32 did not sign-extend its immediate");
    expectEqual(state.rflags, std::uint64_t{0x86},
                "XOR RAX, negative imm32 flags differ");
}

void testXor8BitAccumulatorImmediate() {
    constexpr std::array<std::uint8_t, 3> code{0x34, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorRegImm,
           "XOR AL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2},
                "XOR AL, imm8 length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
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

void testXorpsRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x57, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::XorpsRegReg,
           "XORPS xmm, xmm opcode differs");
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
    expectEqual(state.xmm[0].low, std::uint64_t{0x1032547698BADCFEULL},
                "XORPS low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0xDCFE98BA54761032ULL},
                "XORPS high lane differs");
    expectEqual(state.xmm[1].low, std::uint64_t{0x1111111111111111ULL},
                "XORPS changed its source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "XORPS changed flags");
}

void testPxorRegisterGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0xEF, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PxorRegReg,
           "PXOR xmm, xmm opcode differs");

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

void testPcmpeqbGuestMemoryGeneratedExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x66, 0x0F, 0x74, 0x07, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PcmpeqbRegMem,
           "PCMPEQB xmm, [memory] opcode differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 16> bytes{
        1, 0, 2, 0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    addressSpace.writeBytes(rosa::guest::GuestAddress{0x8000}, bytes);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rdi = 0x8000;
    state.xmm[0] = {};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.xmm[0].low, std::uint64_t{0x00000000FF00FF00ULL},
                "PCMPEQB low lane differs");
    expectEqual(state.xmm[0].high, std::uint64_t{0},
                "PCMPEQB high lane differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PCMPEQB changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.rdi = 0x8000;
    faultState.xmm[0] = {.low = 1, .high = 2};
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "PCMPEQB from unmapped guest memory did not fail");
    expectEqual(faultState.xmm[0].low, std::uint64_t{1},
                "failed PCMPEQB changed low lane");
    expectEqual(faultState.xmm[0].high, std::uint64_t{2},
                "failed PCMPEQB changed high lane");
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
    expectEqual(state.rsi, std::uint64_t{0x281},
                "PMOVMSKB mask or 32-bit zero extension differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "PMOVMSKB changed flags");
}

void testPshufdRegisterExecution() {
    constexpr std::array<std::uint8_t, 6> code{
        0x66, 0x0F, 0x70, 0xC0, 0xE8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::PshufdRegRegImm,
           "PSHUFD opcode differs");
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
    expectEqual(memory.displacement, std::int64_t{-0x20},
                "MOVAPS displacement differs");

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
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x80E0}),
                state.xmm[0].low, "MOVAPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x80E8}),
                state.xmm[0].high, "MOVAPS stored the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVAPS changed flags");

    rosa::x86::X86State unalignedState;
    unalignedState.rbp = 0x8108;
    unalignedState.xmm[0] = state.xmm[0];
    bool rejected = false;
    try {
        static_cast<void>(block.execute(unalignedState, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("16-byte aligned") !=
                   std::string_view::npos;
    }
    expect(rejected, "unaligned MOVAPS guest store did not fail");
    expectEqual(unalignedState.rbp, std::uint64_t{0x8108},
                "failed MOVAPS changed its base register");
}

void testMovapsRegisterToRipRelativeGuestMemory() {
    constexpr std::array<std::uint8_t, 8> code{
        0x0F, 0x29, 0x05, 0x27, 0xD6, 0x06, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF800058AB2ULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8000C60E0ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF8000C6000ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovapsMemReg,
           "RIP-relative MOVAPS store opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7},
                "RIP-relative MOVAPS store length differs");
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase && memory.width == 128 &&
               memory.displacement == 0x6D627,
           "RIP-relative MOVAPS memory operand differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::XmmRegister::Xmm0,
           "RIP-relative MOVAPS source differs");
    expect(rosa::debug::dumpX86(decoded).find("movaps [rip+0x6d627], xmm0") !=
               std::string::npos,
           "RIP-relative MOVAPS dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, observedRip);
    rosa::x86::X86State state;
    state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                    .high = 0xFEDCBA9876543210ULL};
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(target), state.xmm[0].low,
                "RIP-relative MOVAPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(
                    rosa::guest::GuestAddress{target.value + sizeof(std::uint64_t)}),
                state.xmm[0].high,
                "RIP-relative MOVAPS stored the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOVAPS changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    constexpr std::uint64_t lowSentinel = 0xAAAAAAAAAAAAAAAAULL;
    constexpr std::uint64_t highSentinel = 0xBBBBBBBBBBBBBBBBULL;
    std::memcpy(readOnlyBytes.data() + 0xE0, &lowSentinel,
                sizeof(lowSentinel));
    std::memcpy(readOnlyBytes.data() + 0xE8, &highSentinel,
                sizeof(highSentinel));
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(
        targetPage, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
        readOnlyBytes, "read-only RIP-relative MOVAPS target");
    rosa::x86::X86State faultState = state;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOVAPS to read-only memory did not fault");
    expectEqual(readOnlyAddressSpace.readU64(target), lowSentinel,
                "failed RIP-relative MOVAPS changed its low target lane");
    expectEqual(readOnlyAddressSpace.readU64(
                    rosa::guest::GuestAddress{target.value + sizeof(std::uint64_t)}),
                highSentinel,
                "failed RIP-relative MOVAPS changed its high target lane");
    expectEqual(faultState.xmm[0].low, state.xmm[0].low,
                "failed RIP-relative MOVAPS changed source low lane");
    expectEqual(faultState.xmm[0].high, state.xmm[0].high,
                "failed RIP-relative MOVAPS changed source high lane");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOVAPS changed flags");
}

void testMovapsGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 5> code{
        0x0F, 0x28, 0x45, 0xE0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovapsRegMem,
           "MOVAPS xmm, [mem] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::Rbp &&
               memory.displacement == -0x20 && memory.width == 128,
           "MOVAPS xmm, [rbp-0x20] memory operand differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x80E0},
                          0x0123456789ABCDEFULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x80E8},
                          0xFEDCBA9876543210ULL);
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
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOVAPS load changed flags");

    state.rbp = 0x8108;
    state.xmm[0] = {.low = 3, .high = 4};
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &addressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("16-byte aligned") !=
                   std::string_view::npos;
    }
    expect(rejected, "unaligned MOVAPS guest load did not fault");
    expectEqual(state.rbp, std::uint64_t{0x8108},
                "failed MOVAPS changed its base register");
    expectEqual(state.xmm[0].low, std::uint64_t{3},
                "failed MOVAPS changed low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{4},
                "failed MOVAPS changed high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "failed MOVAPS changed flags");
}

void testMovupsRegisterToGuestMemoryWithSib() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x11, 0x44, 0x24, 0x10, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovupsMemReg,
           "MOVUPS [mem], xmm opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.base == rosa::x86::Register::Rsp, "MOVUPS SIB base differs");
    expectEqual(memory.displacement, std::int64_t{0x10},
                "MOVUPS SIB displacement differs");

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
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8113}),
                state.xmm[0].low, "MOVUPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x811B}),
                state.xmm[0].high, "MOVUPS stored the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVUPS changed flags");

    constexpr std::array<std::uint8_t, 5> indexedCode{
        0x0F, 0x11, 0x04, 0x17, 0xC3};
    const auto indexedDecoded = decoder.decodeBlock(
        indexedCode, rosa::guest::GuestAddress{0x2000});
    expectEqual(indexedDecoded[0].length, std::uint8_t{4},
                "indexed MOVUPS store length differs");
    const auto indexedMemory =
        std::get<rosa::x86::MemoryOperand>(indexedDecoded[0].operands[0]);
    expect(indexedMemory.base == rosa::x86::Register::Rdi &&
               indexedMemory.index == rosa::x86::Register::Rdx &&
               indexedMemory.scale == 1 &&
               indexedMemory.displacement == 0 &&
               indexedMemory.width == 128,
           "indexed MOVUPS store effective address differs");
    expect(rosa::debug::dumpX86(indexedDecoded).find(
               "movups [rdi+rdx*1], xmm0") != std::string::npos,
           "indexed MOVUPS store dump differs");
    const auto indexedBlock = translator.translate(
        indexedCode, rosa::guest::GuestAddress{0x2000});
    state.rdi = memoryBase.value;
    state.rdx = 0x23;
    state.xmm[0] = {
        .low = 0x8877665544332211ULL,
        .high = 0x1020304050607080ULL};
    state.rflags = 0xAD7;
    static_cast<void>(indexedBlock.execute(state, &addressSpace));
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8023}),
                state.xmm[0].low,
                "indexed MOVUPS stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x802B}),
                state.xmm[0].high,
                "indexed MOVUPS stored the wrong high lane");
    expectEqual(state.rdi, memoryBase.value,
                "indexed MOVUPS changed its base");
    expectEqual(state.rdx, std::uint64_t{0x23},
                "indexed MOVUPS changed its index");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "indexed MOVUPS changed flags");

    constexpr rosa::guest::GuestAddress crossPageTarget{0x8FF8};
    constexpr std::array<std::uint8_t, 8> sentinel{
        1, 2, 3, 4, 5, 6, 7, 8};
    rosa::guest::AddressSpace crossPageAddressSpace;
    crossPageAddressSpace.mapAnonymous(
        memoryBase, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    crossPageAddressSpace.writeBytes(crossPageTarget, sentinel);
    state.rdi = memoryBase.value;
    state.rdx = crossPageTarget.value - memoryBase.value;
    state.rflags = 0xBD7;
    bool rejected = false;
    try {
        static_cast<void>(indexedBlock.execute(state,
                                               &crossPageAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "cross-page indexed MOVUPS did not fault");
    expect(crossPageAddressSpace.readBytes(crossPageTarget, sentinel.size()) ==
               std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
           "cross-page indexed MOVUPS partially changed memory");
    expectEqual(state.xmm[0].low, std::uint64_t{0x8877665544332211ULL},
                "faulted indexed MOVUPS changed low XMM lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0x1020304050607080ULL},
                "faulted indexed MOVUPS changed high XMM lane");
    expectEqual(state.rflags, std::uint64_t{0xBD7},
                "faulted indexed MOVUPS changed flags");
}

void testMovupsRegisterToRipRelativeGuestMemory() {
    constexpr rosa::guest::GuestAddress instructionAddress{0x7FF800058A0CULL};
    constexpr rosa::guest::GuestAddress target{0x7FF8000C8DC0ULL};
    constexpr rosa::guest::GuestAddress targetPage{0x7FF8000C8000ULL};
    constexpr std::array<std::uint8_t, 8> code{
        0x0F, 0x11, 0x05, 0xAD, 0x03, 0x07, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, instructionAddress);
    expect(decoded[0].opcode == rosa::x86::Opcode::MovupsMemReg,
           "RIP-relative MOVUPS store opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7},
                "RIP-relative MOVUPS store length differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[0]);
    expect(memory.ripRelative && !memory.hasBase,
           "RIP-relative MOVUPS store addressing kind differs");
    expectEqual(memory.displacement, std::int64_t{0x703AD},
                "RIP-relative MOVUPS store displacement differs");
    expectEqual(memory.width, std::uint8_t{128},
                "RIP-relative MOVUPS store width differs");
    expect(std::get<rosa::x86::XmmRegisterOperand>(decoded[0].operands[1]).reg ==
               rosa::x86::XmmRegister::Xmm0,
           "RIP-relative MOVUPS store source differs");
    expect(rosa::debug::dumpX86(decoded).find("movups [rip+0x703ad], xmm0") !=
               std::string::npos,
           "RIP-relative MOVUPS store dump differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(targetPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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
                state.xmm[0].high,
                "RIP-relative MOVUPS stored the wrong high lane");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "RIP-relative MOVUPS changed its low source lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "RIP-relative MOVUPS changed its high source lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "RIP-relative MOVUPS changed flags");

    std::array<std::uint8_t, rosa::guest::guestPageSize> readOnlyBytes{};
    std::fill_n(readOnlyBytes.begin() +
                    static_cast<std::ptrdiff_t>(target.value - targetPage.value),
                16, std::uint8_t{0xA5});
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(targetPage, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read,
                                    readOnlyBytes,
                                    "read-only RIP-relative MOVUPS target");
    state.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &readOnlyAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("permissions") !=
                   std::string_view::npos;
    }
    expect(rejected, "RIP-relative MOVUPS accepted a read-only target");
    const auto unchanged = readOnlyAddressSpace.readBytes(target, 16);
    expect(std::ranges::all_of(unchanged,
                               [](std::uint8_t byte) { return byte == 0xA5; }),
           "failed RIP-relative MOVUPS partially changed guest memory");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "failed RIP-relative MOVUPS changed flags");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "failed RIP-relative MOVUPS changed its source");
}

void testMovupsGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 6> code{
        0x41, 0x0F, 0x10, 0x47, 0x18, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovupsRegMem,
           "MOVUPS xmm, [mem] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R15,
           "MOVUPS load REX.B base differs");
    expectEqual(memory.displacement, std::int64_t{0x18},
                "MOVUPS load displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x811B},
                          0x0123456789ABCDEFULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8123},
                          0xFEDCBA9876543210ULL);
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
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOVUPS load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.xmm[0] = {.low = 3, .high = 4};
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOVUPS load from unmapped guest memory did not fault");
    expectEqual(state.xmm[0].low, std::uint64_t{3},
                "failed MOVUPS load changed low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{4},
                "failed MOVUPS load changed high lane");
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
    expectEqual(memory.displacement, std::int64_t{-0x20},
                "MOVDQA displacement differs");

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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOVDQA from unmapped guest memory did not fail");
    expectEqual(faultState.xmm[0].low, std::uint64_t{0x55},
                "failed MOVDQA changed the low lane");
    expectEqual(faultState.xmm[0].high, std::uint64_t{0xAA},
                "failed MOVDQA changed the high lane");
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
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x8103}),
                state.xmm[0].low, "MOVDQU stored the wrong low lane");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x810B}),
                state.xmm[0].high, "MOVDQU stored the wrong high lane");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVDQU changed flags");
}

void testMovdquGuestMemoryToRegister() {
    constexpr std::array<std::uint8_t, 7> code{
        0xF3, 0x41, 0x0F, 0x6F, 0x47, 0x28, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovdquRegMem,
           "MOVDQU xmm, [mem] opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(memory.base == rosa::x86::Register::R15,
           "MOVDQU load REX.B base differs");
    expectEqual(memory.displacement, std::int64_t{0x28},
                "MOVDQU load displacement differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x812B},
                          0x0123456789ABCDEFULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8133},
                          0xFEDCBA9876543210ULL);
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
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "MOVDQU load changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    state.xmm[0] = {.low = 5, .high = 6};
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOVDQU load from unmapped guest memory did not fault");
    expectEqual(state.xmm[0].low, std::uint64_t{5},
                "failed MOVDQU load changed low lane");
    expectEqual(state.xmm[0].high, std::uint64_t{6},
                "failed MOVDQU load changed high lane");
}

void testMovqXmmToGuestMemory() {
    constexpr std::array<std::uint8_t, 6> code{
        0x66, 0x0F, 0xD6, 0x46, 0x20, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovqMemXmm,
           "MOVQ [mem], xmm opcode differs");

    constexpr rosa::guest::GuestAddress memoryBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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
                std::uint64_t{0x0123456789ABCDEFULL},
                "MOVQ stored the wrong XMM lane");
    expectEqual(state.xmm[0].high, std::uint64_t{0xFEDCBA9876543210ULL},
                "MOVQ changed its XMM source");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "MOVQ changed flags");

    rosa::guest::AddressSpace unmappedAddressSpace;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(state, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "MOVQ to unmapped guest memory did not fault");
    expectEqual(state.xmm[0].low, std::uint64_t{0x0123456789ABCDEFULL},
                "failed MOVQ changed its XMM source");
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
    expect(decoded[0].opcode == rosa::x86::Opcode::LeaRegMem,
           "LEA base+disp opcode differs");
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
    expectEqual(state.rcx, std::uint64_t{0xFFFFFFFE},
                "LEA r32 result or zero extension differs");
    expectEqual(state.rax, std::uint64_t{25}, "LEA r32 changed base");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "LEA r32 changed flags");
}

void testLeaBaseIndexExecution() {
    constexpr std::array<std::uint8_t, 5> code{0x4A, 0x8D, 0x14, 0x28, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::LeaRegMem,
           "LEA base+index opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx,
           "LEA base+index destination differs");
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
    constexpr std::array<std::uint8_t, 9> code{
        0x48, 0x8D, 0x0C, 0xCD, 0x18, 0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::LeaRegMem,
           "no-base scaled LEA opcode differs");
    const auto memory = std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(!memory.hasBase, "no-base scaled LEA acquired a base");
    expect(memory.index == rosa::x86::Register::Rcx,
           "no-base scaled LEA index differs");
    expectEqual(memory.scale, std::uint8_t{8}, "no-base scaled LEA scale differs");
    expectEqual(memory.displacement, std::int64_t{0x18},
                "no-base scaled LEA displacement differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 5;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x40},
                "no-base scaled LEA result differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "no-base scaled LEA changed guest flags");

    constexpr std::array<std::uint8_t, 9> negativeDisplacement{
        0x48, 0x8D, 0x04, 0x8D, 0xF8, 0xFF, 0xFF, 0xFF, 0xC3};
    const auto negativeBlock = translator.translate(
        negativeDisplacement, rosa::guest::GuestAddress{0x2000});
    state.rcx = 3;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{4},
                "no-base scaled LEA did not sign-extend disp32");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "no-base scaled LEA with negative displacement changed flags");

    constexpr std::array<std::uint8_t, 9> noBaseOrIndex{
        0x48, 0x8D, 0x14, 0x25, 0x78, 0x56, 0x34, 0x12, 0xC3};
    const auto displacementBlock = translator.translate(
        noBaseOrIndex, rosa::guest::GuestAddress{0x3000});
    state.rdx = UINT64_MAX;
    state.rsp = 0xDEADBEEF;
    static_cast<void>(displacementBlock.execute(state));
    expectEqual(state.rdx, std::uint64_t{0x12345678},
                "no-base no-index LEA read a dummy base register");
    expectEqual(state.rsp, std::uint64_t{0xDEADBEEF},
                "no-base no-index LEA changed an unrelated register");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "no-base no-index LEA changed flags");
}

void testLegacyRegisterMove32Execution() {
    constexpr std::array<std::uint8_t, 3> code{0x89, 0xFB, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::MovRegReg,
           "legacy MOV r32, r32 opcode differs");
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

void testDarwinThreadSelfid() {
    constexpr auto threadSelfidNumber = UINT64_C(0x02000174);
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = threadSelfidNumber;
    state.rdi = UINT64_MAX;
    state.r9 = 0x123456789ABCDEF0ULL;
    state.rflags = 0x8D7;

    const auto outcome = dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x7FF800004F84ULL});
    expect(!outcome.exited, "thread_selfid terminated the guest");
    expectEqual(state.rax, std::uint64_t{1},
                "thread_selfid returned the wrong guest-local identity");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "thread_selfid did not apply successful BSD carry semantics");
    expectEqual(state.rdi, UINT64_MAX,
                "thread_selfid changed an ignored argument register");
    expectEqual(state.r9, std::uint64_t{0x123456789ABCDEF0ULL},
                "thread_selfid changed an ignored argument register");

    state.rax = threadSelfidNumber;
    static_cast<void>(dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{1},
                "repeated thread_selfid changed guest identity");
}

void testGeneratedDarwinThreadSelfid() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x74, 0x01, 0x00, 0x02, // mov eax, 0x2000174
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read |
                                rosa::guest::Permission::Execute,
                            code);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated thread_selfid terminated the guest");
    expectEqual(state.rax, std::uint64_t{1},
                "generated thread_selfid returned the wrong guest identity");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated thread_selfid did not preserve SYSCALL fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated thread_selfid did not save input flags in R11");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "generated thread_selfid did not clear the BSD error flag");
}

void testDarwinGetentropy() {
    constexpr auto callNumber = UINT64_C(0x020001F4);
    constexpr rosa::guest::GuestAddress buffer{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    std::array<std::uint8_t, 144> sentinel{};
    sentinel.fill(0xA5);
    addressSpace.writeBytes(buffer, sentinel);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = callNumber;
    state.rdi = buffer.value;
    state.rsi = 128;
    state.rflags = 0xAD7;
    const auto outcome = dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x7FF800064C50ULL});
    expect(!outcome.exited, "getentropy terminated the guest");
    expectEqual(state.rax, std::uint64_t{0},
                "getentropy did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "getentropy did not apply BSD success flags");
    const auto entropy = addressSpace.readBytes(buffer, 128);
    expect(std::ranges::any_of(entropy,
                               [](std::uint8_t byte) { return byte != 0xA5; }),
           "getentropy left the entire guest buffer unchanged");
    const auto tail = addressSpace.readBytes(
        rosa::guest::GuestAddress{buffer.value + 128}, 16);
    expect(std::ranges::all_of(tail,
                               [](std::uint8_t byte) { return byte == 0xA5; }),
           "getentropy wrote beyond the requested guest range");

    const std::array marker{std::uint8_t{0x5A}};
    constexpr rosa::guest::GuestAddress oversizedBuffer{0x8200};
    addressSpace.writeBytes(oversizedBuffer, marker);
    state.rax = callNumber;
    state.rdi = oversizedBuffer.value;
    state.rsi = 257;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "oversized getentropy returned the wrong guest errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "oversized getentropy did not set BSD carry");
    expectEqual(addressSpace.readBytes(oversizedBuffer, 1).front(),
                std::uint8_t{0x5A},
                "oversized getentropy changed guest memory");

    state.rax = callNumber;
    state.rdi = 0x8300;
    state.rsi = 256;
    state.rflags = 0x3;
    static_cast<void>(dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0},
                "maximum-sized getentropy request failed");
    expectEqual(state.rflags, std::uint64_t{0x2},
                "maximum-sized getentropy did not clear BSD carry");

    constexpr rosa::guest::GuestAddress crossPageBuffer{0x8FF0};
    std::array<std::uint8_t, 16> crossPageSentinel{};
    crossPageSentinel.fill(0x3C);
    addressSpace.writeBytes(crossPageBuffer, crossPageSentinel);
    state.rax = callNumber;
    state.rdi = crossPageBuffer.value;
    state.rsi = 32;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "cross-page getentropy returned the wrong guest errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "cross-page getentropy did not set BSD carry");
    expectEqual(addressSpace.readBytes(crossPageBuffer, 16),
                std::vector<std::uint8_t>(16, 0x3C),
                "cross-page getentropy partially changed guest memory");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(
        rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
        rosa::guest::Permission::Read);
    state.rax = callNumber;
    state.rdi = 0x9000;
    state.rsi = 16;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(
        readOnlyAddressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "getentropy read-only target returned the wrong guest errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "getentropy read-only target did not set BSD carry");

    rosa::guest::AddressSpace emptyAddressSpace;
    state.rax = callNumber;
    state.rdi = UINT64_MAX;
    state.rsi = 0;
    state.rflags = 0x3;
    static_cast<void>(dispatcher.dispatch(
        emptyAddressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0},
                "zero-length getentropy rejected an unused guest pointer");
    expectEqual(state.rflags, std::uint64_t{0x2},
                "zero-length getentropy did not clear BSD carry");
}

void testDarwinFsgetpath() {
    constexpr auto callNumber = UINT64_C(0x020001AB);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress guestFsidAddress{0x8100};
    constexpr rosa::guest::GuestAddress output{0x8200};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 8> guestFsidBytes{};
    addressSpace.writeBytes(guestFsidAddress, guestFsidBytes);
    std::array<std::uint8_t, 64> sentinel{};
    sentinel.fill(0xA5);
    addressSpace.writeBytes(output, sentinel);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = callNumber;
    state.rdi = output.value;
    state.rsi = 0x400;
    state.rdx = guestFsidAddress.value;
    state.r10 = 0;
    state.rflags = 0xAD7;
    const auto outcome = dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x7FF800064BC0ULL});
    expect(!outcome.exited, "empty-tuple fsgetpath terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOTSUP),
                "empty-tuple fsgetpath returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "empty-tuple fsgetpath did not set BSD carry");
    expectEqual(addressSpace.readBytes(output, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "failed empty-tuple fsgetpath changed its output buffer");

    state.rax = callNumber;
    state.rdi = output.value;
    state.rsi = 0x400;
    state.rdx = 0x9000;
    state.r10 = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "fsgetpath invalid guest fsid returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "fsgetpath invalid guest fsid did not set BSD carry");

    state.rax = callNumber;
    state.rdi = output.value;
    state.rsi = 8193;
    state.rdx = guestFsidAddress.value;
    state.r10 = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "oversized fsgetpath returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "oversized fsgetpath did not set BSD carry");

    constexpr std::array<std::uint8_t, 8> nonemptyFsidBytes{1};
    addressSpace.writeBytes(guestFsidAddress, nonemptyFsidBytes);
    state.rax = callNumber;
    state.rdi = output.value;
    state.rsi = 0x400;
    state.rdx = guestFsidAddress.value;
    state.r10 = 2;
    state.rflags = 0x2;
    bool unsupportedIdentity = false;
    try {
        static_cast<void>(dispatcher.dispatch(
            addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedIdentity = std::string_view(error.what()).find(
                                  "guest VFS identity resolver") !=
                              std::string_view::npos;
    }
    expect(unsupportedIdentity,
           "nonempty fsgetpath identity did not stop at the guest VFS boundary");
}

void testDarwinSharedRegionCheck() {
    constexpr auto callNumber = UINT64_C(0x02000126);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress output{0x8100};
    constexpr std::uint64_t sentinel = 0x0123456789ABCDEFULL;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.writeU64(output, sentinel);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = callNumber;
    state.rdi = output.value;
    state.rflags = 0xAD6;
    const auto outcome = dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x7FF800064A40ULL});
    expect(!outcome.exited, "shared-region check terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "missing shared region returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "missing shared region did not set BSD carry");
    expectEqual(addressSpace.readU64(output), sentinel,
                "missing shared region changed its output pointer");

    rosa::guest::AddressSpace emptyAddressSpace;
    state.rax = callNumber;
    state.rdi = UINT64_MAX - 8;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(
        emptyAddressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "missing shared region inspected an invalid guest pointer");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "invalid-pointer shared-region check did not set BSD carry");
}

void testGeneratedDarwinGetentropy() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress buffer{0x8000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0xF4, 0x01, 0x00, 0x02, // mov eax, 0x20001f4
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read |
                                rosa::guest::Permission::Execute,
                            code);
    addressSpace.mapAnonymous(buffer, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rdi = buffer.value;
    state.rsi = 32;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated getentropy terminated the guest");
    expectEqual(state.rax, std::uint64_t{0},
                "generated getentropy did not return success");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated getentropy lost SYSCALL fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated getentropy did not save input flags");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "generated getentropy did not clear BSD carry");
}

void testDarwinThreadFastSetCthreadSelf() {
    constexpr auto callNumber = UINT64_C(0x03000003);
    constexpr std::uint64_t guestTsdBase = 0x00007FF8000C8F20ULL;
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = callNumber;
    state.rdi = guestTsdBase;
    state.rflags = 0x8D7;

    const auto outcome = dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x7FF800064E32ULL});
    expect(!outcome.exited, "thread_fast_set_cthread_self terminated the guest");
    expectEqual(state.gsBase, guestTsdBase,
                "thread_fast_set_cthread_self stored the wrong guest GS base");
    expectEqual(state.rax, std::uint64_t{0x0F},
                "thread_fast_set_cthread_self returned the wrong selector");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "thread_fast_set_cthread_self applied BSD flag semantics");

    state.rax = callNumber;
    state.rdi = 0xFFFF800000000000ULL;
    static_cast<void>(dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.gsBase, std::uint64_t{0},
                "thread_fast_set_cthread_self retained a non-user GS base");
    expectEqual(state.rax, std::uint64_t{0x0F},
                "invalid thread_fast_set_cthread_self changed its selector return");
}

void testGeneratedDarwinThreadFastSetCthreadSelf() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x03, 0x00, 0x00, 0x03, // mov eax, 0x3000003
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read |
                                rosa::guest::Permission::Execute,
                            code);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rdi = 0x00007FF8000C8F20ULL;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited,
           "generated thread_fast_set_cthread_self terminated the guest");
    expectEqual(state.rax, std::uint64_t{0x0F},
                "generated thread_fast_set_cthread_self returned the wrong selector");
    expectEqual(state.gsBase, std::uint64_t{0x00007FF8000C8F20ULL},
                "generated thread_fast_set_cthread_self lost the guest GS base");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated machdep call did not preserve SYSCALL fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated machdep call did not save input flags in R11");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "generated machdep call changed guest flags");
}

void testMachTaskSelfTrap() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    const rosa::darwin::MachDispatcher mach;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    state.rdi = 0x1111111111111111ULL;
    state.rsi = 0x2222222222222222ULL;
    state.rdx = 0x3333333333333333ULL;
    state.r10 = 0x4444444444444444ULL;
    state.r8 = 0x5555555555555555ULL;
    state.r9 = 0x6666666666666666ULL;
    state.rflags = 0x8D7;

    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF80000158CULL});
    expect(!outcome.exited, "task_self_trap terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(mach.taskSelfPortName().value),
                "task_self_trap returned the wrong guest port name");
    expect(state.rax != 0 && state.rax <= UINT32_MAX,
           "task_self_trap did not return a valid 32-bit guest port name");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "task_self_trap applied BSD carry-flag semantics");
    expectEqual(state.rdi, std::uint64_t{0x1111111111111111ULL},
                "task_self_trap changed an argument register");
    expectEqual(state.r9, std::uint64_t{0x6666666666666666ULL},
                "task_self_trap changed an argument register");

    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(mach.taskSelfPortName().value),
                "repeated task_self_trap returned a different guest name");
}

void testGeneratedMachTaskSelfTrap() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x1C, 0x00, 0x00, 0x01, // mov eax, 0x100001c
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read |
                                rosa::guest::Permission::Execute,
                            code);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated task_self_trap terminated the guest");
    expectEqual(state.rax, std::uint64_t{0x103},
                "generated task_self_trap returned the wrong guest port");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated syscall did not save its fallthrough in RCX");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated syscall did not save the input flags in R11");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "generated task_self_trap changed guest flags");
}

void testMachReplyPortTrap() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::MachDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    state.rdi = 0x1111111111111111ULL;
    state.r9 = 0x9999999999999999ULL;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state,
                        rosa::guest::GuestAddress{0x7FF800001574ULL});
    const rosa::darwin::GuestMachPortName first{static_cast<std::uint32_t>(state.rax)};
    expect(first.value != 0, "mach_reply_port returned MACH_PORT_NULL");
    expect(dispatcher.ownsReceiveRight(first),
           "mach_reply_port did not allocate a guest receive right");
    expect(first != dispatcher.taskSelfPortName(),
           "mach_reply_port collided with the guest task-self port");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mach_reply_port applied BSD carry-flag semantics");
    expectEqual(state.rdi, std::uint64_t{0x1111111111111111ULL},
                "mach_reply_port changed an ignored argument register");
    expectEqual(state.r9, std::uint64_t{0x9999999999999999ULL},
                "mach_reply_port changed an ignored argument register");

    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state,
                        rosa::guest::GuestAddress{0x7FF800001574ULL});
    const rosa::darwin::GuestMachPortName second{static_cast<std::uint32_t>(state.rax)};
    expect(second != first, "repeated mach_reply_port reused a receive-right name");
    expect(dispatcher.ownsReceiveRight(first) && dispatcher.ownsReceiveRight(second),
           "mach_reply_port lost a previously allocated receive right");
}

void testMachVmProtectTrap() {
    constexpr rosa::guest::GuestAddress mappingBase{0x4000};
    constexpr auto pageSize = rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(
        mappingBase, pageSize * 3,
        rosa::guest::Permission::Read | rosa::guest::Permission::Write,
        "mach protect test");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x5000},
                          0x0123456789ABCDEFULL);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.rdi = 0x103;
    state.rsi = 0x5000;
    state.rdx = 8;
    state.r10 = 0;
    state.r8 = 1; // VM_PROT_READ
    state.r9 = 0x9999999999999999ULL;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "mach_vm_protect did not return KERN_SUCCESS");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mach_vm_protect applied BSD carry-flag semantics");
    expectEqual(state.r9, std::uint64_t{0x9999999999999999ULL},
                "mach_vm_protect consumed a nonexistent sixth argument");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x5000}),
                std::uint64_t{0x0123456789ABCDEFULL},
                "mach_vm_protect changed guest bytes");

    const auto mappings = addressSpace.mappingInfos();
    expectEqual(mappings.size(), std::size_t{3},
                "mach_vm_protect did not split the mapping at guest-page boundaries");
    expectEqual(mappings[0].base.value, std::uint64_t{0x4000},
                "mach_vm_protect prefix mapping differs");
    expectEqual(mappings[1].base.value, std::uint64_t{0x5000},
                "mach_vm_protect protected mapping base differs");
    expectEqual(mappings[1].size, pageSize,
                "mach_vm_protect did not round an 8-byte range to one guest page");
    expect(mappings[1].permissions == rosa::guest::Permission::Read,
           "mach_vm_protect middle-page permissions differ");

    bool writeRejected = false;
    try {
        addressSpace.writeU64(rosa::guest::GuestAddress{0x5000}, 0);
    } catch (const std::runtime_error &) {
        writeRejected = true;
    }
    expect(writeRejected, "mach_vm_protect did not remove guest write permission");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x4000}, 1);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x6000}, 2);

    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.r8 = 3; // VM_PROT_READ | VM_PROT_WRITE
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0},
                "mach_vm_protect could not restore a maximum guest permission");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x5000},
                          0xFEDCBA9876543210ULL);

    const auto beforeFailure = addressSpace.mappingInfos();
    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.rsi = 0x7000;
    state.rdx = pageSize;
    state.r8 = 1;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{1},
                "mach_vm_protect unmapped range did not return KERN_INVALID_ADDRESS");
    const auto afterFailure = addressSpace.mappingInfos();
    expectEqual(afterFailure.size(), beforeFailure.size(),
                "failed mach_vm_protect changed the mapping count");
    for (std::size_t index = 0; index < beforeFailure.size(); ++index) {
        expect(afterFailure[index].permissions == beforeFailure[index].permissions,
               "failed mach_vm_protect changed guest permissions");
    }

    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.rdi = 0xDEAD;
    state.rsi = 0x5000;
    state.rdx = 8;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0x10000003},
                "mach_vm_protect invalid task did not return MACH_SEND_INVALID_DEST");

    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, pageSize,
                              rosa::guest::Permission::Read,
                              "mach protect maximum test");
    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.rdi = 0x103;
    state.rsi = 0x8000;
    state.rdx = 8;
    state.r10 = 0;
    state.r8 = 3;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{2},
                "mach_vm_protect maximum violation did not return KERN_PROTECTION_FAILURE");

    for (const auto [setMaximum, protection] :
         std::array<std::pair<std::uint64_t, std::uint64_t>, 2>{
             std::pair{std::uint64_t{1}, std::uint64_t{1}},
             std::pair{std::uint64_t{0}, std::uint64_t{8}}}) {
        state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
        state.rsi = 0x5000;
        state.r10 = setMaximum;
        state.r8 = protection;
        bool rejected = false;
        try {
            static_cast<void>(dispatcher.dispatch(
                addressSpace, state, rosa::guest::GuestAddress{0x1000}));
        } catch (const std::runtime_error &error) {
            rejected = std::string_view(error.what()).find("Mach trap") !=
                       std::string_view::npos;
        }
        expect(rejected,
               "unsupported mach_vm_protect behavior did not fail diagnostically");
    }
}

void testGeneratedMachVmProtectTrap() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress dataBase{0x4000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x0E, 0x00, 0x00, 0x01, // mov eax, 0x100000e
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read |
                                rosa::guest::Permission::Execute,
                            code);
    addressSpace.mapAnonymous(dataBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rdi = 0x103;
    state.rsi = dataBase.value;
    state.rdx = 8;
    state.r10 = 0;
    state.r8 = 3;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated mach_vm_protect terminated the guest");
    expectEqual(state.rax, std::uint64_t{0},
                "generated mach_vm_protect did not return KERN_SUCCESS");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated mach_vm_protect did not preserve SYSCALL fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated mach_vm_protect did not save input flags in R11");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "generated mach_vm_protect changed guest flags");
}

void testUnsupportedMachTrapDiagnostic() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::syscallClass | 31U;

    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1234}));
        throw std::runtime_error("unsupported Mach trap was accepted");
    } catch (const std::runtime_error &error) {
        const std::string_view message{error.what()};
        expect(message.find("unsupported Darwin guest Mach trap") != std::string_view::npos,
               "unsupported Mach trap diagnostic lacks its boundary class");
        expect(message.find("trap: 31") != std::string_view::npos,
               "unsupported Mach trap diagnostic lacks the trap number");
        expect(message.find("RIP: 0x1234") != std::string_view::npos,
               "unsupported Mach trap diagnostic lacks guest RIP");
    }
}

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

rosa::x86::X86State execute(std::span<const std::uint8_t> code) {
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rip = 0x1000;
    static_cast<void>(block.execute(state));
    return state;
}

void testR1ExecutesGeneratedCode() {
    const auto state = execute(r1Code);
    expectEqual(state.rax, std::uint64_t{42}, "R1 guest RAX differs");
    expectEqual(state.rip, std::uint64_t{0x100E}, "R1 exit RIP is not precise");
    expectEqual(state.rflags, std::uint64_t{0x2}, "R1 flags differ for 40 + 2");
}

void testAddFlagsCarryAndZero() {
    constexpr std::array<std::uint8_t, 15> code{
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x83, 0xC0, 0x01, 0xC3,
    };
    const auto state = execute(code);
    constexpr std::uint64_t expectedFlags = 0x2 | 0x1 | 0x4 | 0x10 | 0x40;
    expectEqual(state.rax, std::uint64_t{0}, "wrapping add result differs");
    expectEqual(state.rflags, expectedFlags, "CF/PF/AF/ZF flags differ");
}

void testAddFlagsSignedOverflow() {
    constexpr std::array<std::uint8_t, 15> code{
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x48, 0x83, 0xC0, 0x01, 0xC3,
    };
    const auto state = execute(code);
    constexpr std::uint64_t expectedFlags = 0x2 | 0x4 | 0x10 | 0x80 | 0x800;
    expectEqual(state.rax, std::uint64_t{0x8000000000000000ULL},
                "signed-overflow add result differs");
    expectEqual(state.rflags, expectedFlags, "PF/AF/SF/OF flags differ");
}

void testAddRegisterImmediate32() {
    constexpr std::array<std::uint8_t, 8> positive{
        0x48, 0x81, 0xC4, 0xB0, 0x00, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(positive,
                                             rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegImm,
           "ADD r64, imm32 opcode differs");
    expect(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).reg ==
               rosa::x86::Register::Rsp,
           "ADD r64, imm32 destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{0xB0}, "ADD r64, imm32 immediate differs");

    const rosa::dbt::Translator translator;
    const auto positiveBlock = translator.translate(
        positive, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsp = 0x1000;
    static_cast<void>(positiveBlock.execute(state));
    expectEqual(state.rsp, std::uint64_t{0x10B0},
                "ADD r64, positive imm32 result differs");

    constexpr std::array<std::uint8_t, 8> negative{
        0x48, 0x81, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3};
    const auto negativeDecoded = decoder.decodeBlock(
        negative, rosa::guest::GuestAddress{0x2000});
    expectEqual(
        std::get<rosa::x86::ImmediateOperand>(negativeDecoded[0].operands[1]).value,
        UINT64_MAX, "ADD r64, imm32 did not sign-extend its immediate");
    const auto negativeBlock = translator.translate(
        negative, rosa::guest::GuestAddress{0x2000});
    state.rax = 0;
    static_cast<void>(negativeBlock.execute(state));
    expectEqual(state.rax, UINT64_MAX, "ADD r64, negative imm32 result differs");
    expectEqual(state.rflags, std::uint64_t{0x86},
                "ADD r64, negative imm32 flags differ");
}

void testAdd32BitRegisterShortImmediate() {
    constexpr std::array<std::uint8_t, 4> code{0x83, 0xC0, 0xFC, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AddRegImm,
           "ADD r32, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{3},
                "ADD r32, imm8 length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate =
        std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rax &&
               destination.width == 32,
           "ADD EAX, imm8 destination differs");
    expect(immediate.width == 8 && immediate.value == UINT64_MAX - 3,
           "ADD EAX, imm8 was not sign-extended");
    expect(rosa::debug::dumpX86(decoded).find(
               "add eax, 0xfffffffffffffffc") != std::string::npos,
           "ADD EAX, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State overflowState;
    overflowState.rax = 0xAAAAAAAA80000003ULL;
    overflowState.rflags = 0x8D7;
    static_cast<void>(block.execute(overflowState));
    expectEqual(overflowState.rax, std::uint64_t{0x7FFFFFFF},
                "ADD EAX, imm8 did not zero-extend its result");
    expectEqual(overflowState.rflags, std::uint64_t{0x807},
                "ADD EAX, negative imm8 overflow flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0xBBBBBBBB00000004ULL;
    zeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0},
                "ADD EAX, negative imm8 zero result differs");
    expectEqual(zeroState.rflags, std::uint64_t{0x57},
                "ADD EAX, negative imm8 zero flags differ");
}

void testAndResultAndFlags() {
    constexpr std::array<std::uint8_t, 15> code{
        0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x83, 0xE0, 0xF0, 0xC3,
    };
    const auto state = execute(code);
    expectEqual(state.rax, std::uint64_t{0xFFFFFFFFFFFFFFF0ULL}, "AND result differs");
    expectEqual(state.rflags, std::uint64_t{0x86}, "AND PF/SF flags differ");
}

void testAnd32BitRegisters() {
    constexpr std::array<std::uint8_t, 3> code{0x21, 0xC6, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegReg,
           "AND r32, r32 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "AND r32, r32 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rsi = 0xAAAAAAAA0000C0CEULL;
    state.rax = 0xBBBBBBBBFFFFFF00ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rsi, std::uint64_t{0xC000},
                "AND r32, r32 result or zero extension differs");
    expectEqual(state.rax, std::uint64_t{0xBBBBBBBBFFFFFF00ULL},
                "AND r32, r32 changed source");
    expectEqual(state.rflags, std::uint64_t{0x6}, "AND r32, r32 flags differ");
}

void testAnd8BitRegisters() {
    constexpr std::array<std::uint8_t, 3> code{0x20, 0xC1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegReg,
           "AND r8, r8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "AND r8, r8 length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx &&
               destination.width == 8 && source.reg == rosa::x86::Register::Rax &&
               source.width == 8,
           "AND CL, AL operands differ");
    expect(rosa::debug::dumpX86(decoded).find("and cl, al") != std::string::npos,
           "AND CL, AL dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1122334455667780ULL;
    state.rcx = 0x88776655443322FFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x8877665544332280ULL},
                "AND CL, AL did not preserve upper RCX bytes");
    expectEqual(state.rax, std::uint64_t{0x1122334455667780ULL},
                "AND CL, AL changed its source");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "AND CL, AL defined flags differ");

    constexpr std::array<std::uint8_t, 3> highByteCode{0x20, 0xE0, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            highByteCode, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "AND AL, AH was silently treated as a low-byte register form");
}

void testAnd8BitRegisterWithRipRelativeGuestMemory() {
    constexpr std::array<std::uint8_t, 8> observed{
        0x44, 0x22, 0x35, 0xE0, 0x9E, 0x06, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress observedRip{0x7FF80005C225ULL};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(observed, observedRip);
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegMem,
           "AND r8, byte [RIP] opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7},
                "AND r8, byte [RIP] length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto memory =
        std::get<rosa::x86::MemoryOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R14 &&
               destination.width == 8,
           "AND r8, byte [RIP] destination differs");
    expect(memory.ripRelative && !memory.hasBase && memory.width == 8 &&
               memory.displacement == 0x69EE0,
           "AND r8, byte [RIP] memory operand differs");
    expect(rosa::debug::dumpX86(decoded).find(
               "and r14b, byte [rip+0x69ee0] ; 0x7ff8000c610c") !=
               std::string::npos,
           "AND r8, byte [RIP] dump differs");

    constexpr std::array<std::uint8_t, 8> code{
        0x44, 0x22, 0x35, 0xF9, 0x0F, 0x00, 0x00, 0xC3};
    constexpr rosa::guest::GuestAddress sourceAddress{0x2000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(sourceAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) |
        (1U << 11U);

    const std::array sourceParity{std::uint8_t{0x0F}};
    addressSpace.writeBytes(sourceAddress, sourceParity);
    rosa::x86::X86State state;
    state.r14 = 0x11223344556677F3ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0x1122334455667703ULL},
                "AND byte memory did not preserve upper R14 bytes");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "AND byte memory parity flags differ");
    expectEqual(addressSpace.readBytes(sourceAddress, 1).front(),
                std::uint8_t{0x0F}, "AND byte memory changed its source");

    const std::array sourceZero{std::uint8_t{0}};
    addressSpace.writeBytes(sourceAddress, sourceZero);
    state.r14 = UINT64_MAX;
    state.rflags = 0xAD7;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0xFFFFFFFFFFFFFF00ULL},
                "zero AND byte memory result differs");
    expectEqual(state.rflags & definedLogicFlags,
                std::uint64_t{(1U << 2U) | (1U << 6U)},
                "zero AND byte memory flags differ");

    const std::array sourceSign{std::uint8_t{0x80}};
    addressSpace.writeBytes(sourceAddress, sourceSign);
    state.r14 = UINT64_MAX;
    state.rflags = 0;
    static_cast<void>(block.execute(state, &addressSpace));
    expectEqual(state.r14, std::uint64_t{0xFFFFFFFFFFFFFF80ULL},
                "signed AND byte memory result differs");
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 7U},
                "signed AND byte memory flags differ");

    rosa::guest::AddressSpace unmappedAddressSpace;
    rosa::x86::X86State faultState;
    faultState.r14 = 0xAAAAAAAA55555555ULL;
    faultState.rflags = 0xAD7;
    bool rejected = false;
    try {
        static_cast<void>(block.execute(faultState, &unmappedAddressSpace));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "AND byte from unmapped guest memory did not fault");
    expectEqual(faultState.r14, std::uint64_t{0xAAAAAAAA55555555ULL},
                "faulted AND byte memory changed its destination");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted AND byte memory changed flags");
}

void testBitScanForward32() {
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0xBC, 0xC6, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::BitScanForwardRegReg,
           "BSF r32, r32 opcode differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State nonzeroState;
    nonzeroState.rax = UINT64_MAX;
    nonzeroState.rsi = 0xAAAAAAAA0000C000ULL;
    nonzeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(nonzeroState));
    expectEqual(nonzeroState.rax, std::uint64_t{14},
                "BSF r32 result or zero extension differs");
    expectEqual(nonzeroState.rsi, std::uint64_t{0xAAAAAAAA0000C000ULL},
                "BSF changed source");
    expectEqual(nonzeroState.rflags, std::uint64_t{0x897},
                "BSF nonzero ZF semantics differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0x12345678;
    zeroState.rsi = 0;
    zeroState.rflags = 0x897;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0x12345678},
                "BSF zero-source deterministic destination differs");
    expectEqual(zeroState.rflags, std::uint64_t{0x8D7},
                "BSF zero-source ZF semantics differ");
}

void testBitScanForward64() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x0F, 0xBC, 0xD1, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::BitScanForwardRegReg,
           "BSF r64, r64 opcode differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rdx && destination.width == 64,
           "BSF r64 destination differs");
    expect(source.reg == rosa::x86::Register::Rcx && source.width == 64,
           "BSF r64 source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State nonzeroState;
    nonzeroState.rdx = UINT64_MAX;
    nonzeroState.rcx = std::uint64_t{1} << 40U;
    nonzeroState.rflags = 0x8D7;
    static_cast<void>(block.execute(nonzeroState));
    expectEqual(nonzeroState.rdx, std::uint64_t{40}, "BSF r64 result differs");
    expectEqual(nonzeroState.rcx, std::uint64_t{1} << 40U,
                "BSF r64 changed source");
    expectEqual(nonzeroState.rflags, std::uint64_t{0x897},
                "BSF r64 nonzero ZF semantics differ");

    rosa::x86::X86State zeroState;
    zeroState.rdx = 0x123456789ABCDEF0ULL;
    zeroState.rcx = 0;
    zeroState.rflags = 0x897;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rdx, std::uint64_t{0x123456789ABCDEF0ULL},
                "BSF r64 zero-source destination policy differs");
    expectEqual(zeroState.rflags, std::uint64_t{0x8D7},
                "BSF r64 zero-source ZF semantics differ");
}

void testLegacyAnd32Immediate() {
    constexpr std::array<std::uint8_t, 4> code{0x83, 0xE1, 0x1F, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegImm,
           "legacy AND r32, imm8 opcode differs");
    expectEqual(std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]).width,
                std::uint8_t{32}, "legacy AND r32, imm8 width differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rcx = 0xFFFFFFFF000000FFULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x1F},
                "legacy AND r32, imm8 did not zero-extend the result");
    expectEqual(state.rflags, std::uint64_t{0x2},
                "legacy AND r32, imm8 flags differ");
}

void testAnd8BitAccumulatorImmediate() {
    constexpr std::array<std::uint8_t, 3> code{0x24, 0x01, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegImm,
           "AND AL, imm8 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{2}, "AND AL, imm8 length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8,
           "AND AL, imm8 destination differs");
    expectEqual(std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]).value,
                std::uint64_t{1}, "AND AL, imm8 immediate differs");
    expect(rosa::debug::dumpX86(decoded).find("and al, 0x1") != std::string::npos,
           "AND AL, imm8 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x11223344556677A5ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL},
                "AND AL, imm8 did not preserve upper RAX bytes");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{0},
                "AND AL, imm8 nonzero defined flags differ");

    rosa::x86::X86State zeroState;
    zeroState.rax = 0xFFEEDDCCBBAA5500ULL;
    zeroState.rflags = 0x810;
    static_cast<void>(block.execute(zeroState));
    expectEqual(zeroState.rax, std::uint64_t{0xFFEEDDCCBBAA5500ULL},
                "AND AL, imm8 zero result changed upper RAX bytes");
    expectEqual(zeroState.rflags & definedLogicFlags,
                std::uint64_t{(1U << 2U) | (1U << 6U)},
                "AND AL, imm8 zero defined flags differ");
}

void testAnd32BitRegisterImmediate() {
    constexpr std::array<std::uint8_t, 8> code{
        0x41, 0x81, 0xE7, 0xFF, 0x0F, 0x00, 0x00, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::AndRegImm,
           "AND r32, imm32 opcode differs");
    expectEqual(decoded[0].length, std::uint8_t{7},
                "AND r32, imm32 length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto immediate =
        std::get<rosa::x86::ImmediateOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R15 && destination.width == 32,
           "AND r32, imm32 destination differs");
    expectEqual(immediate.value, std::uint64_t{0xFFF},
                "AND r32, imm32 immediate differs");
    expectEqual(immediate.width, std::uint8_t{32},
                "AND r32, imm32 immediate width differs");
    expect(rosa::debug::dumpX86(decoded).find("and r15d, 0xfff") !=
               std::string::npos,
           "AND r32, imm32 dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r15 = 0xFFFFFFFF80000800ULL;
    state.rflags = 0x8D7;
    static_cast<void>(block.execute(state));
    expectEqual(state.r15, std::uint64_t{0x800},
                "AND r32, imm32 result did not zero-extend");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(state.rflags & definedLogicFlags, std::uint64_t{1U << 2U},
                "AND r32, imm32 nonzero defined flags differ");

    constexpr std::array<std::uint8_t, 7> zeroCode{
        0x81, 0xE0, 0x00, 0x00, 0x00, 0x00, 0xC3};
    const auto zeroBlock =
        translator.translate(zeroCode, rosa::guest::GuestAddress{0x2000});
    state.rax = UINT64_MAX;
    state.rflags = 0x811;
    static_cast<void>(zeroBlock.execute(state));
    expectEqual(state.rax, std::uint64_t{0},
                "AND EAX, imm32 zero result did not clear upper bits");
    expectEqual(state.rflags & definedLogicFlags,
                std::uint64_t{(1U << 2U) | (1U << 6U)},
                "AND EAX, imm32 zero defined flags differ");

    constexpr std::array<std::uint8_t, 7> signCode{
        0x81, 0xE1, 0x00, 0x00, 0x00, 0x80, 0xC3};
    const auto signBlock =
        translator.translate(signCode, rosa::guest::GuestAddress{0x2800});
    state.rcx = UINT64_MAX;
    state.rflags = 0x8D7;
    static_cast<void>(signBlock.execute(state));
    expectEqual(state.rcx, std::uint64_t{0x80000000},
                "AND ECX, imm32 sign-bit result differs");
    expectEqual(state.rflags & definedLogicFlags,
                std::uint64_t{(1U << 2U) | (1U << 7U)},
                "AND ECX, imm32 sign defined flags differ");

    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            std::span<const std::uint8_t>{code}.first(6),
            rosa::guest::GuestAddress{0x3000}));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "truncated AND r32, imm32 was not rejected");
}

void testGuestAddressSpace() {
    constexpr rosa::guest::GuestAddress base{0x4000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(base, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "test mapping");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x4FF8}, 0x0123456789ABCDEFULL);
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x4FF8}),
                std::uint64_t{0x0123456789ABCDEFULL}, "guest memory round trip differs");

    bool rejected = false;
    try {
        addressSpace.writeU64(rosa::guest::GuestAddress{0x4FFC}, 1);
    } catch (const std::runtime_error &) {
        rejected = true;
    }
    expect(rejected, "cross-mapping guest memory access was not rejected");
    const auto mappings = addressSpace.mappingInfos();
    expectEqual(mappings.size(), std::size_t{1}, "mapping summary count differs");
    expectEqual(mappings[0].base.value, base.value, "mapping summary base differs");
    expectEqual(mappings[0].size, rosa::guest::guestPageSize,
                "mapping summary size differs");
    expectEqual(mappings[0].label, std::string("test mapping"),
                "mapping summary label differs");
}

void testGuestFailureReport() {
    constexpr std::array<std::uint8_t, 12> code{
        0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x0B,
    };
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute,
                            code, "test-image:__TEXT");
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "test stack");
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize;
    state.rflags = 0x202;
    rosa::dbt::Dispatcher dispatcher(addressSpace, 1);
    std::string report;
    try {
        static_cast<void>(dispatcher.run(state, 8));
    } catch (const rosa::x86::DecodeError &error) {
        report = rosa::debug::dumpGuestFailure("fallback-image", error, state, addressSpace,
                                               dispatcher);
    }
    expect(!report.empty(), "unsupported instruction did not produce a guest failure report");
    expect(report.find("image=test-image:__TEXT") != std::string::npos,
           "guest failure report omitted the current image");
    expect(report.find("RIP=0x100a") != std::string::npos,
           "guest failure report omitted RIP");
    expect(report.find("RSP=0x9000") != std::string::npos,
           "guest failure report omitted RSP");
    expect(report.find("RFLAGS=0x202") != std::string::npos,
           "guest failure report omitted RFLAGS");
    expect(report.find("RAX=0x2a") != std::string::npos,
           "guest failure report omitted general registers");
    expect(report.find("0f 0b") != std::string::npos,
           "guest failure report omitted failing instruction bytes");
    expect(report.find("mov rax, 0x2a") != std::string::npos,
           "guest failure report omitted recent decoded history");
    expect(report.find("test stack") != std::string::npos,
           "guest failure report omitted the stack mapping");
    expect(report.find("executed=1 translations=1") != std::string::npos,
           "guest failure report omitted execution counters");
}

void testHotGuestBlockDiagnostics() {
    constexpr std::array<std::uint8_t, 2> code{0xEB, 0xFE};
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read |
                                rosa::guest::Permission::Execute,
                            code, "hot-loop:__TEXT");
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    rosa::dbt::Dispatcher dispatcher(addressSpace, 1);
    std::string report;
    try {
        static_cast<void>(dispatcher.run(state, 40));
    } catch (const std::runtime_error &error) {
        report = rosa::debug::dumpGuestFailure("hot-loop", error, state,
                                               addressSpace, dispatcher);
    }
    expect(!report.empty(), "hot guest loop did not hit its diagnostic limit");
    const auto hot = dispatcher.hotBlocks();
    expectEqual(hot.size(), std::size_t{1}, "hot guest block count differs");
    expectEqual(hot[0].address.value, codeBase.value,
                "hot guest block address differs");
    expectEqual(hot[0].count, std::size_t{40},
                "hot guest block execution count differs");
    expect(report.find("hot guest blocks:") != std::string::npos &&
               report.find("0x1000 count=40") != std::string::npos,
           "guest failure report omitted hot-block diagnostics");
}

void testX86Commpage() {
    rosa::guest::AddressSpace addressSpace;
    constexpr std::uint64_t continuousTimebase = 0x0123456789ABCDEFULL;
    rosa::darwin::mapX86Commpage(addressSpace, continuousTimebase);
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageCpuCapabilities64Offset}),
                rosa::darwin::x86CommpageCpuCapabilities64,
                "x86 commpage CPU capabilities differ");
    constexpr auto translatedCapability = UINT64_C(0x4000000000000000);
    expect((rosa::darwin::x86CommpageCpuCapabilities64 &
            translatedCapability) == 0,
           "x86 commpage falsely advertises Apple's translated-process bit");

    constexpr std::array<std::uint8_t, 14> loadCapabilities{
        0x48, 0xB8, 0x10, 0x00, 0xE0, 0xFF, 0xFF,
        0x7F, 0x00, 0x00, 0x48, 0x8B, 0x00, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(loadCapabilities,
                                            rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State loadState;
    loadState.rflags = 0x8D7;
    static_cast<void>(block.execute(loadState, &addressSpace));
    expectEqual(loadState.rax, rosa::darwin::x86CommpageCpuCapabilities64,
                "generated x86 load read the wrong CPU capabilities");
    expectEqual(loadState.rflags, std::uint64_t{0x8D7},
                "x86 commpage capability load changed flags");

    const auto version = addressSpace.readBytes(
        rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                  rosa::darwin::x86CommpageVersionOffset},
        sizeof(rosa::darwin::x86CommpageVersion));
    expectEqual(version,
                std::vector<std::uint8_t>{
                    static_cast<std::uint8_t>(rosa::darwin::x86CommpageVersion), 0},
                "x86 commpage version differs");
    expectEqual(addressSpace.readBytes(
                    rosa::guest::GuestAddress{
                        rosa::darwin::x86CommpageBase.value +
                        rosa::darwin::x86CommpageKernelPageShiftOffset},
                    1)
                    .front(),
                rosa::darwin::x86CommpageKernelPageShift,
                "x86 commpage kernel page shift differs");
    expectEqual(addressSpace.readBytes(
                    rosa::guest::GuestAddress{
                        rosa::darwin::x86CommpageBase.value +
                        rosa::darwin::x86CommpageUserPageShiftOffset},
                    1)
                    .front(),
                rosa::darwin::x86CommpageUserPageShift,
                "x86 commpage user page shift differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageKdebugEnableOffset}),
                std::uint32_t{0}, "x86 commpage kdebug state is not disabled");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageContinuousTimebaseOffset}),
                continuousTimebase, "x86 commpage continuous-time base differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeGenerationOffset}),
                std::uint32_t{1}, "x86 commpage nanotime generation differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeTscBaseOffset}),
                std::uint64_t{0}, "x86 commpage nanotime TSC base differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeScaleOffset}),
                rosa::darwin::x86CommpageNanotimeScale,
                "x86 commpage nanotime scale differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeShiftOffset}),
                std::uint32_t{0}, "x86 commpage nanotime shift differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeNanosecondsBaseOffset}),
                std::uint64_t{0}, "x86 commpage nanotime nanoseconds base differs");

    bool unsupportedReadRejected = false;
    try {
        static_cast<void>(addressSpace.readU64(rosa::darwin::x86CommpageBase));
    } catch (const std::runtime_error &error) {
        unsupportedReadRejected = std::string_view(error.what()).find("unsupported sparse") !=
                                  std::string_view::npos;
    }
    expect(unsupportedReadRejected,
           "unsupported x86 commpage data did not fail loudly");

    bool writeRejected = false;
    try {
        addressSpace.writeU64(
            rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                      rosa::darwin::x86CommpageContinuousTimebaseOffset},
            0);
    } catch (const std::runtime_error &error) {
        writeRejected = std::string_view(error.what()).find("permissions") !=
                        std::string_view::npos;
    }
    expect(writeRejected, "x86 commpage mapping was not read-only");
}

std::string readGuestString(const rosa::guest::AddressSpace &addressSpace,
                            rosa::guest::GuestAddress address) {
    std::string result;
    for (;;) {
        const auto byte = addressSpace.readBytes(address, 1).front();
        if (byte == 0) {
            return result;
        }
        result.push_back(static_cast<char>(byte));
        ++address.value;
    }
}

void testInitialDarwinStack() {
    constexpr rosa::guest::GuestAddress base{0x700000000000ULL};
    constexpr std::size_t size = 2 * rosa::guest::guestPageSize;
    const std::vector<std::string> arguments{"/guest/program", "argument"};
    const std::vector<std::string> environment{"A=B"};
    const std::vector<std::string> apple{"executable_path=/guest/program"};
    rosa::guest::AddressSpace addressSpace;
    const rosa::guest::StartupStackBuilder builder;
    const auto stack = builder.build(addressSpace, base, size, arguments, environment, apple);
    expectEqual(stack.stackPointer.value & 0xFU, std::uint64_t{0},
                "initial stack pointer is not 16-byte aligned");
    auto cursor = stack.stackPointer.value;
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{cursor}), std::uint64_t{2},
                "initial stack argc differs");
    cursor += 8;
    const auto argv0 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    cursor += 8;
    const auto argv1 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    cursor += 16; // Move past argv[1] and the argv null to envp[0].
    const auto env0 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    cursor += 16; // Move past envp[0] and the envp null to apple[0].
    const auto apple0 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{argv0}), arguments[0],
                "guest argv[0] differs");
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{argv1}), arguments[1],
                "guest argv[1] differs");
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{env0}), environment[0],
                "guest envp[0] differs");
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{apple0}), apple[0],
                "guest apple[0] differs");
}

void testInitialDyldStack() {
    constexpr rosa::guest::GuestAddress base{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress executableHeader{0x100000000ULL};
    constexpr std::size_t size = 2 * rosa::guest::guestPageSize;
    const std::vector<std::string> arguments{"/guest/program"};
    const std::vector<std::string> environment;
    const std::vector<std::string> apple{"executable_path=/guest/program"};
    rosa::guest::AddressSpace addressSpace;
    const rosa::guest::StartupStackBuilder builder;
    const auto stack = builder.build(addressSpace, base, size, arguments,
                                     environment, apple, executableHeader);
    expectEqual(stack.stackPointer.value & 0xFU, std::uint64_t{0},
                "initial dyld stack pointer is not 16-byte aligned");
    expectEqual(addressSpace.readU64(stack.stackPointer), executableHeader.value,
                "initial dyld stack lacks the main Mach-O header");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{
                    stack.stackPointer.value + sizeof(std::uint64_t)}),
                std::uint64_t{1}, "initial dyld stack argc differs");
    const auto argv0 = addressSpace.readU64(rosa::guest::GuestAddress{
        stack.stackPointer.value + (2 * sizeof(std::uint64_t))});
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{argv0}),
                arguments[0], "initial dyld stack argv[0] differs");
}

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
        0x41, 0xFF, 0x54, 0x24, 0x10, 0xC3, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0xB8, 0x2A, 0, 0, 0, 0, 0,
        0, 0, 0xC3, 0, 0, 0, 0, 0,
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read |
                                rosa::guest::Permission::Execute,
                            code);
    addressSpace.mapAnonymous(dataBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read |
                                  rosa::guest::Permission::Write);
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
    expectEqual(result.executedBlocks, std::size_t{3},
                "indirect guest call block count differs");
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
        rejected = std::string_view(error.what()).find("unmapped") !=
                   std::string_view::npos;
    }
    expect(rejected, "indirect call through unmapped guest memory did not fail");
    expectEqual(state.rip, std::uint64_t{0x1000},
                "failed indirect call changed RIP");
    expectEqual(state.rsp, std::uint64_t{0x9000},
                "failed indirect call changed RSP");
}

void testUnsignedBelowConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x72, 0x02}; // jb 0x1004
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::JccRelative,
           "JB rel8 opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Below,
           "JB rel8 condition differs");
    expectEqual(decoded[0].branchTarget->value, std::uint64_t{0x1004},
                "JB rel8 target differs");

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

void testUnsignedBelowLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x82, 0x02, 0, 0, 0};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::Below,
           "JB rel32 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x3;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1008},
                "JB rel32 did not take with CF set");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1006},
                "JB rel32 took with CF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x2},
                "JB rel32 changed flags");
}

void testRegisterIndirectJump() {
    constexpr std::array<std::uint8_t, 2> code{0xFF, 0xE1};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::JmpReg,
           "JMP register opcode differs");
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

void testSetEqualLowByteRegister() {
    constexpr std::uint64_t zeroFlag = std::uint64_t{1} << 6U;
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x94, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg,
           "SETE opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Equal,
           "SETE condition differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::Rax && destination.width == 8,
           "SETE AL destination differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x897 | zeroFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL},
                "taken SETE did not merge one into AL");
    expectEqual(state.rflags, std::uint64_t{0x897 | zeroFlag},
                "taken SETE changed flags");

    state.rax = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x891 & ~zeroFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "not-taken SETE did not merge zero into AL");
    expectEqual(state.rflags, std::uint64_t{0x891 & ~zeroFlag},
                "not-taken SETE changed flags");

    constexpr std::array<std::uint8_t, 3> highByte{0x0F, 0x94, 0xE0};
    bool rejectedHighByte = false;
    try {
        static_cast<void>(decoder.decodeBlock(highByte,
                                              rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejectedHighByte = true;
    }
    expect(rejectedHighByte, "SETE AH was not rejected explicitly");
}

void testSetNotEqualLowByteRegister() {
    constexpr std::uint64_t zeroFlag = std::uint64_t{1} << 6U;
    constexpr std::array<std::uint8_t, 4> code{0x0F, 0x95, 0xC0, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg,
           "SETNE opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::NotEqual,
           "SETNE condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.rax = 0x1122334455667788ULL;
    state.rflags = 0x897 & ~zeroFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0x1122334455667701ULL},
                "taken SETNE did not merge one into AL");
    expectEqual(state.rflags, std::uint64_t{0x897 & ~zeroFlag},
                "taken SETNE changed flags");

    state.rax = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x891 | zeroFlag;
    static_cast<void>(block.execute(state));
    expectEqual(state.rax, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "not-taken SETNE did not merge zero into AL");
    expectEqual(state.rflags, std::uint64_t{0x891 | zeroFlag},
                "not-taken SETNE changed flags");
}

void testSetGreaterExtendedLowByteRegister() {
    constexpr std::array<std::uint8_t, 5> code{
        0x41, 0x0F, 0x9F, 0xC6, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(
        code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::SetccReg,
           "SETG opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Greater,
           "SETG condition differs");
    expectEqual(decoded[0].length, std::uint8_t{4},
                "SETG length differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    expect(destination.reg == rosa::x86::Register::R14 &&
               destination.width == 8,
           "SETG extended low-byte destination differs");
    expect(rosa::debug::dumpX86(decoded).find("setg r14b") !=
               std::string::npos,
           "SETG dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(
        code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State state;
    state.r14 = 0x1122334455667788ULL;
    state.rflags = 0x882; // ZF=0, SF=OF=1.
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0x1122334455667701ULL},
                "taken SETG did not merge one into R14B");
    expectEqual(state.rflags, std::uint64_t{0x882},
                "taken SETG changed flags");

    state.r14 = 0xFFEEDDCCBBAA9988ULL;
    state.rflags = 0x802; // ZF=0, SF=0, OF=1.
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0xFFEEDDCCBBAA9900ULL},
                "SETG accepted unequal SF and OF");
    expectEqual(state.rflags, std::uint64_t{0x802},
                "not-taken SETG changed flags");

    state.r14 = UINT64_MAX;
    state.rflags = 0x42; // ZF=1, SF=OF=0.
    static_cast<void>(block.execute(state));
    expectEqual(state.r14, std::uint64_t{0xFFFFFFFFFFFFFF00ULL},
                "SETG ignored ZF");
    expectEqual(state.rflags, std::uint64_t{0x42},
                "zero SETG changed flags");

    constexpr std::array<std::uint8_t, 3> highByte{
        0x0F, 0x9F, 0xC6};
    bool rejectedHighByte = false;
    try {
        static_cast<void>(decoder.decodeBlock(
            highByte, rosa::guest::GuestAddress{0x2000}));
    } catch (const rosa::x86::DecodeError &) {
        rejectedHighByte = true;
    }
    expect(rejectedHighByte,
           "SETG DH was silently treated as a low-byte register");
}

void testConditionalMoveBelow64() {
    constexpr std::array<std::uint8_t, 5> code{0x4C, 0x0F, 0x42, 0xE8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg,
           "CMOVB opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Below,
           "CMOVB condition differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::R13 && destination.width == 64,
           "CMOVB destination differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 64,
           "CMOVB source differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rax = 0x1122334455667788ULL;
    taken.r13 = UINT64_MAX;
    taken.rflags = 0x8D7 | 1U;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.r13, std::uint64_t{0x1122334455667788ULL},
                "taken CMOVB result differs");
    expectEqual(taken.rax, std::uint64_t{0x1122334455667788ULL},
                "CMOVB changed its source");
    expectEqual(taken.rflags, std::uint64_t{0x8D7 | 1U},
                "taken CMOVB changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rax = UINT64_MAX;
    notTaken.r13 = 0xAABBCCDDEEFF0011ULL;
    notTaken.rflags = 0x8D6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.r13, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "untaken CMOVB changed destination");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D6 & ~std::uint64_t{1}},
                "untaken CMOVB changed flags");
}

void testConditionalMoveEqual64() {
    constexpr std::array<std::uint8_t, 5> code{0x48, 0x0F, 0x44, 0xC8, 0xC3};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].opcode == rosa::x86::Opcode::CmovccReg,
           "CMOVE opcode differs");
    expect(decoded[0].condition == rosa::x86::Condition::Equal,
           "CMOVE condition differs");
    const auto destination =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[0]);
    const auto source =
        std::get<rosa::x86::RegisterOperand>(decoded[0].operands[1]);
    expect(destination.reg == rosa::x86::Register::Rcx && destination.width == 64,
           "CMOVE destination differs");
    expect(source.reg == rosa::x86::Register::Rax && source.width == 64,
           "CMOVE source differs");
    expect(rosa::debug::dumpX86(decoded).find("cmove rcx, rax") !=
               std::string::npos,
           "CMOVE dump differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rax = 0x1122334455667788ULL;
    taken.rcx = UINT64_MAX;
    taken.rflags = 0x8D7 | zeroFlag;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rcx, std::uint64_t{0x1122334455667788ULL},
                "taken CMOVE result differs");
    expectEqual(taken.rax, std::uint64_t{0x1122334455667788ULL},
                "CMOVE changed its source");
    expectEqual(taken.rflags, std::uint64_t{0x8D7 | zeroFlag},
                "taken CMOVE changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rax = UINT64_MAX;
    notTaken.rcx = 0xAABBCCDDEEFF0011ULL;
    notTaken.rflags = 0x8D7 & ~zeroFlag;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rcx, std::uint64_t{0xAABBCCDDEEFF0011ULL},
                "untaken CMOVE changed destination");
    expectEqual(notTaken.rax, UINT64_MAX, "untaken CMOVE changed source");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D7 & ~zeroFlag},
                "untaken CMOVE changed flags");
}

void testUnsignedAboveConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x77, 0x02}; // ja 0x1004
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::Above,
           "JA rel8 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x2;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1004},
                "JA did not take with CF and ZF clear");
    expectEqual(taken.rflags, std::uint64_t{0x2}, "JA changed guest flags");

    rosa::x86::X86State carrySet;
    carrySet.rflags = 0x3;
    static_cast<void>(block.execute(carrySet));
    expectEqual(carrySet.rip, std::uint64_t{0x1002}, "JA took with CF set");

    rosa::x86::X86State zeroSet;
    zeroSet.rflags = 0x42;
    static_cast<void>(block.execute(zeroSet));
    expectEqual(zeroSet.rip, std::uint64_t{0x1002}, "JA took with ZF set");
}

void testUnsignedAboveLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x87, 0x02, 0, 0, 0};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::Above,
           "JA rel32 condition differs");
    expectEqual(decoded[0].branchTarget->value, std::uint64_t{0x1008},
                "JA rel32 target differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x2;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1008}, "JA rel32 did not take");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x3;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1006},
                "JA rel32 took with CF set");
}

void testUnsignedAboveOrEqualLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x83, 0x02, 0, 0, 0};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::AboveOrEqual,
           "JAE rel32 condition differs");
    expectEqual(decoded[0].branchTarget->value, std::uint64_t{0x1008},
                "JAE rel32 target differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x8D6 & ~std::uint64_t{1};
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1008},
                "JAE did not take with CF clear");
    expectEqual(taken.rflags, std::uint64_t{0x8D6 & ~std::uint64_t{1}},
                "taken JAE changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x8D7 | 1U;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1006},
                "JAE took with CF set");
    expectEqual(notTaken.rflags, std::uint64_t{0x8D7 | 1U},
                "not-taken JAE changed flags");
}

void testUnsignedBelowOrEqualConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x76, 0x02}; // jbe 0x1004
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::BelowOrEqual,
           "JBE rel8 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State carrySet;
    carrySet.rflags = 0x3;
    static_cast<void>(block.execute(carrySet));
    expectEqual(carrySet.rip, std::uint64_t{0x1004}, "JBE did not take with CF set");

    rosa::x86::X86State zeroSet;
    zeroSet.rflags = 0x42;
    static_cast<void>(block.execute(zeroSet));
    expectEqual(zeroSet.rip, std::uint64_t{0x1004}, "JBE did not take with ZF set");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1002},
                "JBE took with CF and ZF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x2}, "JBE changed guest flags");
}

void testUnsignedBelowOrEqualLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x86, 0x02, 0, 0, 0};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::BelowOrEqual,
           "JBE rel32 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State carryTaken;
    carryTaken.rflags = 0x3;
    static_cast<void>(block.execute(carryTaken));
    expectEqual(carryTaken.rip, std::uint64_t{0x1008},
                "JBE rel32 did not take with CF set");

    rosa::x86::X86State zeroTaken;
    zeroTaken.rflags = 0x42;
    static_cast<void>(block.execute(zeroTaken));
    expectEqual(zeroTaken.rip, std::uint64_t{0x1008},
                "JBE rel32 did not take with ZF set");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1006},
                "JBE rel32 took with CF and ZF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x2},
                "JBE rel32 changed flags");
}

void testSignedLessOrEqualConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x7E, 0x02}; // jle 0x1004
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::LessOrEqual,
           "JLE rel8 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State equal;
    equal.rflags = 0x42;
    static_cast<void>(block.execute(equal));
    expectEqual(equal.rip, std::uint64_t{0x1004}, "JLE did not take with ZF set");

    rosa::x86::X86State less;
    less.rflags = 0x82;
    static_cast<void>(block.execute(less));
    expectEqual(less.rip, std::uint64_t{0x1004},
                "JLE did not take with SF different from OF");

    rosa::x86::X86State greater;
    greater.rflags = 0x2;
    static_cast<void>(block.execute(greater));
    expectEqual(greater.rip, std::uint64_t{0x1002},
                "JLE took with ZF clear and SF equal to OF");
    expectEqual(greater.rflags, std::uint64_t{0x2}, "JLE changed flags");
}

void testSignLongConditional() {
    constexpr std::array<std::uint8_t, 6> code{0x0F, 0x88, 0x02, 0, 0, 0};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::Sign,
           "JS rel32 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x82;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1008},
                "JS did not take with SF set");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1006},
                "JS took with SF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x2}, "JS changed flags");
}

void testSignShortConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x78, 0x02};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::Sign,
           "JS rel8 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x82;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1004},
                "short JS did not take with SF set");
    expectEqual(taken.rflags, std::uint64_t{0x82},
                "taken short JS changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x2;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1002},
                "short JS took with SF clear");
    expectEqual(notTaken.rflags, std::uint64_t{0x2},
                "not-taken short JS changed flags");
}

void testUnsignedAboveOrEqualShortConditional() {
    constexpr std::array<std::uint8_t, 2> code{0x73, 0x02};
    const rosa::x86::Decoder decoder;
    const auto decoded = decoder.decodeBlock(code, rosa::guest::GuestAddress{0x1000});
    expect(decoded[0].condition == rosa::x86::Condition::AboveOrEqual,
           "JAE rel8 condition differs");

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(code, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State taken;
    taken.rflags = 0x2;
    static_cast<void>(block.execute(taken));
    expectEqual(taken.rip, std::uint64_t{0x1004},
                "short JAE did not take with CF clear");
    expectEqual(taken.rflags, std::uint64_t{0x2},
                "taken short JAE changed flags");

    rosa::x86::X86State notTaken;
    notTaken.rflags = 0x3;
    static_cast<void>(block.execute(notTaken));
    expectEqual(notTaken.rip, std::uint64_t{0x1002},
                "short JAE took with CF set");
    expectEqual(notTaken.rflags, std::uint64_t{0x3},
                "not-taken short JAE changed flags");
}

void testControlledMachOParsing() {
    const auto file = rosa::macho::MachOFile::open(ROSA_TEST_MACHO_PATH);
    expectEqual(file.cpuType(), std::uint32_t{0x01000007U}, "Mach-O CPU type differs");
    expectEqual(file.fileType(), std::uint32_t{2}, "Mach-O file type differs");
    expect(!file.segments().empty(), "Mach-O has no parsed segments");
    bool sawMain = false;
    for (const auto &command : file.loadCommands()) {
        sawMain |= command.command == rosa::macho::lcMain;
    }
    expect(sawMain, "controlled Mach-O does not contain parsed LC_MAIN");

    rosa::guest::AddressSpace addressSpace;
    const rosa::macho::Loader loader;
    const auto image = loader.mapImage(file, addressSpace);
    expectEqual(image.mappedSegments, std::size_t{3}, "Mach-O mapped-segment count differs");
    expectEqual(image.loadAddress.value, std::uint64_t{0x100000000ULL},
                "Mach-O load address differs");
    expectEqual(addressSpace.readU32(image.loadAddress),
                std::uint32_t{0xFEEDFACFU},
                "Mach-O load address does not point at its header");
    expectEqual(addressSpace.mappingCount(), image.mappedSegments,
                "guest mapping count differs from loaded segment count");
    expectEqual(addressSpace.executableBytes(image.entryPoint).front(), std::uint8_t{0x48},
                "Mach-O entry does not point to controlled x86 code");
    bool pageZeroRejected = false;
    try {
        static_cast<void>(addressSpace.readBytes(rosa::guest::GuestAddress{0}, 1));
    } catch (const std::runtime_error &) {
        pageZeroRejected = true;
    }
    expect(pageZeroRejected, "sparse __PAGEZERO did not reject guest reads");
}

void writeBigU32(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 2] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 3] = static_cast<std::uint8_t>(value);
}

void testUniversalMachOX86Selection() {
    const auto thin = rosa::macho::MachOFile::open(ROSA_TEST_MACHO_PATH);
    constexpr std::size_t fatHeaderSize = 8 + 20;
    std::vector<std::uint8_t> fat(fatHeaderSize + thin.bytes().size());
    fat[0] = 0xCA;
    fat[1] = 0xFE;
    fat[2] = 0xBA;
    fat[3] = 0xBE;
    writeBigU32(fat, 4, 1);
    writeBigU32(fat, 8, 0x01000007U);
    writeBigU32(fat, 12, 3);
    writeBigU32(fat, 16, fatHeaderSize);
    writeBigU32(fat, 20, static_cast<std::uint32_t>(thin.bytes().size()));
    writeBigU32(fat, 24, 0);
    std::copy(thin.bytes().begin(), thin.bytes().end(),
              fat.begin() + static_cast<std::ptrdiff_t>(fatHeaderSize));
    const auto selected = rosa::macho::MachOFile::parse(std::move(fat));
    expectEqual(selected.entryPoint(), thin.entryPoint(), "universal Mach-O x86_64 entry differs");
}

void testMalformedMachORejection() {
    const auto valid = rosa::macho::MachOFile::open(ROSA_TEST_MACHO_PATH);
    std::vector<std::uint8_t> bytes(valid.bytes().begin(), valid.bytes().end());
    expect(bytes.size() > 40, "controlled Mach-O is unexpectedly short");
    bytes[36] = 0;
    bytes[37] = 0;
    bytes[38] = 0;
    bytes[39] = 0;
    bool rejected = false;
    try {
        static_cast<void>(rosa::macho::MachOFile::parse(std::move(bytes)));
    } catch (const std::runtime_error &) {
        rejected = true;
    }
    expect(rejected, "zero-sized Mach-O load command was not rejected");
}

void testR3ControlledMachOExecution() {
    const rosa::macho::Loader loader;
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    const auto image = loader.mapImage(ROSA_TEST_MACHO_PATH, addressSpace);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = image.entryPoint.value;
    state.rsp = stackTop - sizeof(std::uint64_t);
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 64, sentinel);
    expectEqual(state.rax, std::uint64_t{42}, "controlled Mach-O guest RAX differs");
    expectEqual(result.executedBlocks, std::size_t{5},
                "controlled Mach-O executed-block count differs");
}

} // namespace

int main() {
    const std::vector<std::pair<std::string_view, std::function<void()>>> tests{
#if ROSA_HAS_X86_ORACLE
        {"Rosetta semantic differential corpus", testRosettaDifferentialSemantics},
#endif
        {"arm64 assembler encodings", testAssemblerEncodings},
        {"R0 generated execution", testR0ExecutesGeneratedCode},
        {"arm64 label fixups", testAssemblerLabels},
        {"R1 decoder", testDecoderR1},
        {"extended register and signed immediate", testDecoderExtendedRegisterAndSignedImmediate},
        {"legacy MOV 32-bit immediate", testLegacyMov32ImmediateGeneratedExecution},
        {"legacy MOV low-byte immediate",
         testLegacyMovLowByteImmediateGeneratedExecution},
        {"REX extended MOV 32-bit immediate", testRexExtendedMov32ImmediateGeneratedExecution},
        {"PUSH imm8 decoder", testDecoderPushImm8},
        {"PUSH imm8 generated execution", testPushImm8GeneratedExecution},
        {"PUSH imm8 guest stack faults", testPushImm8GuestStackFaults},
        {"PUSH register generated execution", testPushRegisterGeneratedExecution},
        {"POP register generated execution", testPopRegisterGeneratedExecution},
        {"SUB register imm32 generated execution", testSubRegImm32GeneratedExecution},
        {"SUB register imm8 generated execution", testSubRegImm8GeneratedExecution},
        {"SUB register from register", testSubRegisterFromRegister},
        {"SUB register from guest memory", testSubRegisterFromGuestMemory},
        {"SUB 32-bit register from guest memory", testSub32BitRegisterFromGuestMemory},
        {"ADD register from guest memory", testAddRegisterFromGuestMemory},
        {"ADD register to register", testAddRegisterToRegister},
        {"ADD low-byte registers", testAddLowByteRegisters},
        {"ADD guest byte to low register", testAddGuestByteToLowRegister},
        {"ADD immediate to low byte", testAddImmediateToLowByte},
        {"INC 32-bit register", testIncrement32BitRegister},
        {"INC low-byte register", testIncrementLowByteRegister},
        {"DEC 32-bit register", testDecrement32BitRegister},
        {"DEC low-byte register", testDecrementLowByteRegister},
        {"INC 16-bit guest memory", testIncrement16BitGuestMemory},
        {"INC 64-bit guest memory", testIncrement64BitGuestMemory},
        {"DEC 64-bit guest memory", testDecrement64BitGuestMemory},
        {"CMP 32-bit register with guest memory", testCompare32BitRegisterWithGuestMemory},
        {"CMP byte register with scaled guest memory",
         testCompareByteRegisterWithScaledGuestMemory},
        {"legacy CMP 32-bit register with guest memory",
         testLegacyCompare32BitRegisterWithGuestMemory},
        {"CMP 64-bit register with guest memory", testCompare64BitRegisterWithGuestMemory},
        {"CMP guest memory with 64-bit register",
         testCompareGuestMemoryWith64BitRegister},
        {"LOCK CMPXCHG guest dword", testLockedCompareExchangeGuestDword},
        {"XCHG guest dword with register", testExchangeGuestDwordWithRegister},
        {"LOCK OR guest dword immediate", testLockedOrGuestDwordImmediate},
        {"CMP guest memory with 32-bit immediate", testCompareGuestMemoryWith32BitImmediate},
        {"CMP guest memory with short immediate", testCompareGuestMemoryWithShortImmediate},
        {"CMP RIP-relative guest dword with short immediate",
         testCompareRipRelativeGuestDwordWithShortImmediate},
        {"CMP guest qword with short immediate", testCompareGuestQwordWithShortImmediate},
        {"CMP guest word with short immediate", testCompareGuestWordWithShortImmediate},
        {"CMP 16-bit register with short immediate",
         testCompare16BitRegisterWithShortImmediate},
        {"CMP guest byte with immediate", testCompareGuestByteWithImmediate},
        {"CMP indexed guest byte with immediate",
         testCompareIndexedGuestByteWithImmediate},
        {"CMP RIP-relative guest byte with immediate",
         testCompareRipRelativeGuestByteWithImmediate},
        {"CMP 8-bit register with immediate", testCompare8BitRegisterWithImmediate},
        {"CMP 32-bit register with immediate", testCompare32BitRegisterWithImmediate},
        {"CMP EAX accumulator immediate", testCompareEaxAccumulatorImmediate},
        {"CMP 32-bit register with short immediate",
         testCompare32BitRegisterWithShortImmediate},
        {"CMP 64-bit registers", testCompare64BitRegisters},
        {"CMP 32-bit registers", testCompare32BitRegisters},
        {"MOV register to guest memory", testMovRegisterToGuestMemory},
        {"MOV register to RIP-relative guest memory",
         testMovRegisterToRipRelativeGuestMemory},
        {"MOV RIP-relative guest dword to register",
         testMovRipRelativeGuestDwordToRegister},
        {"MOV 32-bit register to guest memory", testMov32BitRegisterToGuestMemory},
        {"MOV 64-bit register to scaled guest memory",
         testMov64BitRegisterToScaledGuestMemory},
        {"MOV low-byte register to guest memory", testMovLowByteRegisterToGuestMemory},
        {"MOV extended low byte to scaled guest memory",
         testMovExtendedLowByteToScaledGuestMemory},
        {"MOV low-byte register to RIP-relative guest memory",
         testMovLowByteRegisterToRipRelativeGuestMemory},
        {"MOV low-byte register to extended base", testMovLowByteRegisterToExtendedBase},
        {"MOV immediate to guest memory", testMovImmediateToGuestMemory},
        {"MOV immediate to RIP-relative guest memory",
         testMovImmediateToRipRelativeGuestMemory},
        {"MOV 32-bit immediate to guest memory",
         testMov32BitImmediateToGuestMemory},
        {"MOV byte immediate to guest memory", testMovByteImmediateToGuestMemory},
        {"MOV byte immediate to RIP-relative guest memory",
         testMovByteImmediateToRipRelativeGuestMemory},
        {"MOV word immediate to guest memory", testMovWordImmediateToGuestMemory},
        {"MOV word register to guest memory", testMovWordRegisterToGuestMemory},
        {"MOV guest memory to register", testMovGuestMemoryToRegister},
        {"MOV guest GS memory to 32-bit register",
         testMovGuestGsMemoryTo32BitRegister},
        {"MOV guest memory to register with no-index SIB",
         testMovGuestMemoryToRegisterWithNoIndexSib},
        {"MOV guest memory to 32-bit register with scaled index",
         testMovGuestMemoryTo32BitRegisterWithScaledIndex},
        {"MOV guest memory to 32-bit register", testMovGuestMemoryTo32BitRegister},
        {"MOV guest memory to byte register", testMovGuestMemoryToByteRegister},
        {"MOV RIP-relative guest byte to register",
         testMovRipRelativeGuestByteToRegister},
        {"MOV guest memory to byte register with scaled index",
         testMovGuestMemoryToByteRegisterWithScaledIndex},
        {"MOVZX low-byte register to 32-bit register",
         testMovzxLowByteRegisterTo32BitRegister},
        {"MOVZX guest byte to 32-bit register",
         testMovzxGuestByteTo32BitRegister},
        {"MOVZX guest byte with SIB to 64-bit register",
         testMovzxGuestByteWithSibTo64BitRegister},
        {"MOVZX 16-bit register to 32-bit register",
         testMovzx16BitRegisterTo32BitRegister},
        {"MOVZX guest word to 32-bit register", testMovzxGuestWordTo32BitRegister},
        {"MOVZX guest word with scaled index", testMovzxGuestWordWithScaledIndex},
        {"MOVSXD scaled guest dword", testMovsxdScaledGuestDword},
        {"CDQE generated execution", testCdqeGeneratedExecution},
        {"legacy MOV guest memory to 32-bit register",
         testMovGuestMemoryToLegacy32BitRegister},
        {"TEST register generated execution", testTestRegisterGeneratedExecution},
        {"TEST 16-bit registers generated execution",
         testTest16BitRegistersGeneratedExecution},
        {"TEST 32-bit register generated execution", testTest32BitRegisterGeneratedExecution},
        {"legacy TEST 32-bit register generated execution",
         testLegacyTest32BitRegisterGeneratedExecution},
        {"legacy TEST low-byte generated execution", testLegacyTestLowByteGeneratedExecution},
        {"TEST accumulator immediate generated execution",
         testTestAccumulatorImmediateGeneratedExecution},
        {"TEST low-byte register immediate generated execution",
         testTestLowByteRegisterImmediateGeneratedExecution},
        {"LFENCE generated execution", testLfenceGeneratedExecution},
        {"RDTSC generated execution", testRdtscGeneratedExecution},
        {"SHL immediate generated execution", testShiftLeftImmediateGeneratedExecution},
        {"SHL CL generated execution", testShiftLeftClGeneratedExecution},
        {"SHL 32-bit CL generated execution", testShiftLeft32ClGeneratedExecution},
        {"SHR 32-bit immediate generated execution", testShiftRight32ImmediateGeneratedExecution},
        {"SHR 64-bit immediate generated execution", testShiftRight64ImmediateGeneratedExecution},
        {"NEG 64-bit generated execution", testNeg64GeneratedExecution},
        {"unsigned MUL generated execution", testUnsignedMultiplyGeneratedExecution},
        {"signed IMUL 64-bit generated execution", testSignedMultiply64GeneratedExecution},
        {"SHRD generated execution", testShiftRightDoubleGeneratedExecution},
        {"OR register generated execution", testOrRegisterGeneratedExecution},
        {"OR 8-bit registers generated execution", testOr8BitRegistersGeneratedExecution},
        {"OR short immediate generated execution", testOrShortImmediateGeneratedExecution},
        {"OR 32-bit registers generated execution", testOr32BitRegistersGeneratedExecution},
        {"XOR 32-bit register generated execution", testXor32BitRegisterGeneratedExecution},
        {"XOR 32-bit register from guest memory",
         testXor32BitRegisterFromGuestMemory},
        {"XOR 64-bit register from guest memory",
         testXor64BitRegisterFromGuestMemory},
        {"XOR 32-bit register immediate", testXor32BitRegisterImmediate},
        {"XOR 64-bit accumulator immediate", testXor64BitAccumulatorImmediate},
        {"XOR 8-bit accumulator immediate", testXor8BitAccumulatorImmediate},
        {"XORPS register generated execution", testXorpsRegisterGeneratedExecution},
        {"PXOR register generated execution", testPxorRegisterGeneratedExecution},
        {"PCMPEQB guest memory generated execution",
         testPcmpeqbGuestMemoryGeneratedExecution},
        {"PMOVMSKB generated execution", testPmovmskbGeneratedExecution},
        {"PSHUFD register execution", testPshufdRegisterExecution},
        {"MOVAPS register to guest memory", testMovapsRegisterToGuestMemory},
        {"MOVAPS register to RIP-relative guest memory",
         testMovapsRegisterToRipRelativeGuestMemory},
        {"MOVAPS guest memory to register", testMovapsGuestMemoryToRegister},
        {"MOVUPS register to guest memory with SIB", testMovupsRegisterToGuestMemoryWithSib},
        {"MOVUPS register to RIP-relative guest memory",
         testMovupsRegisterToRipRelativeGuestMemory},
        {"MOVUPS guest memory to register", testMovupsGuestMemoryToRegister},
        {"MOVDQA guest memory to register", testMovdqaGuestMemoryToRegister},
        {"MOVDQU register to guest memory", testMovdquRegisterToGuestMemory},
        {"MOVDQU guest memory to register", testMovdquGuestMemoryToRegister},
        {"MOVQ XMM to guest memory", testMovqXmmToGuestMemory},
        {"register move execution", testRegisterMoveExecution},
        {"LEA base displacement execution", testLeaBaseDisplacementExecution},
        {"LEA 32-bit base displacement execution", testLea32BitBaseDisplacementExecution},
        {"LEA base index execution", testLeaBaseIndexExecution},
        {"LEA no-base scaled index execution", testLeaNoBaseScaledIndexExecution},
        {"legacy 32-bit register move execution", testLegacyRegisterMove32Execution},
        {"unsupported decoder diagnostic", testDecoderRejectsUnsupportedInstruction},
        {"RIP-relative LEA and syscall decoder", testDecoderRipRelativeLeaAndSyscall},
        {"Darwin thread_selfid", testDarwinThreadSelfid},
        {"generated Darwin thread_selfid", testGeneratedDarwinThreadSelfid},
        {"Darwin getentropy", testDarwinGetentropy},
        {"Darwin fsgetpath", testDarwinFsgetpath},
        {"Darwin shared-region check", testDarwinSharedRegionCheck},
        {"generated Darwin getentropy", testGeneratedDarwinGetentropy},
        {"Darwin thread_fast_set_cthread_self",
         testDarwinThreadFastSetCthreadSelf},
        {"generated Darwin thread_fast_set_cthread_self",
         testGeneratedDarwinThreadFastSetCthreadSelf},
        {"Mach task-self trap", testMachTaskSelfTrap},
        {"generated Mach task-self trap", testGeneratedMachTaskSelfTrap},
        {"Mach reply-port trap", testMachReplyPortTrap},
        {"Mach VM protect trap", testMachVmProtectTrap},
        {"generated Mach VM protect trap", testGeneratedMachVmProtectTrap},
        {"unsupported Mach trap diagnostic", testUnsupportedMachTrapDiagnostic},
        {"IR verification", testIrVerification},
        {"R1 generated execution", testR1ExecutesGeneratedCode},
        {"add carry/zero flags", testAddFlagsCarryAndZero},
        {"add signed-overflow flags", testAddFlagsSignedOverflow},
        {"add register imm32", testAddRegisterImmediate32},
        {"add 32-bit register short immediate",
         testAdd32BitRegisterShortImmediate},
        {"and result/flags", testAndResultAndFlags},
        {"AND 32-bit registers", testAnd32BitRegisters},
        {"AND 8-bit registers", testAnd8BitRegisters},
        {"AND 8-bit register with RIP-relative guest memory",
         testAnd8BitRegisterWithRipRelativeGuestMemory},
        {"BSF 32-bit registers", testBitScanForward32},
        {"BSF 64-bit registers", testBitScanForward64},
        {"legacy AND 32-bit immediate", testLegacyAnd32Immediate},
        {"AND 8-bit accumulator immediate", testAnd8BitAccumulatorImmediate},
        {"AND 32-bit register immediate", testAnd32BitRegisterImmediate},
        {"guest address space", testGuestAddressSpace},
        {"guest failure report", testGuestFailureReport},
        {"hot guest block diagnostics", testHotGuestBlockDiagnostics},
        {"x86 commpage", testX86Commpage},
        {"initial Darwin stack", testInitialDarwinStack},
        {"initial dyld stack", testInitialDyldStack},
        {"R2 multi-block control flow", testR2MultiBlockControlFlow},
        {"R2 taken conditional", testR2TakenConditional},
        {"indirect guest-memory call", testIndirectGuestMemoryCall},
        {"indirect guest-memory call fault", testIndirectGuestMemoryCallFault},
        {"unsigned-below conditional", testUnsignedBelowConditional},
        {"unsigned-below long conditional", testUnsignedBelowLongConditional},
        {"register-indirect jump", testRegisterIndirectJump},
        {"set equal low-byte register", testSetEqualLowByteRegister},
        {"set not-equal low-byte register", testSetNotEqualLowByteRegister},
        {"set greater extended low-byte register",
         testSetGreaterExtendedLowByteRegister},
        {"conditional move below 64-bit", testConditionalMoveBelow64},
        {"conditional move equal 64-bit", testConditionalMoveEqual64},
        {"unsigned-above conditional", testUnsignedAboveConditional},
        {"unsigned-above long conditional", testUnsignedAboveLongConditional},
        {"unsigned-above-or-equal long conditional",
         testUnsignedAboveOrEqualLongConditional},
        {"unsigned-below-or-equal conditional", testUnsignedBelowOrEqualConditional},
        {"unsigned-below-or-equal long conditional",
         testUnsignedBelowOrEqualLongConditional},
        {"signed-less-or-equal conditional", testSignedLessOrEqualConditional},
        {"sign long conditional", testSignLongConditional},
        {"sign short conditional", testSignShortConditional},
        {"unsigned-above-or-equal short conditional",
         testUnsignedAboveOrEqualShortConditional},
        {"controlled Mach-O parsing", testControlledMachOParsing},
        {"universal Mach-O x86 selection", testUniversalMachOX86Selection},
        {"malformed Mach-O rejection", testMalformedMachORejection},
        {"R3 controlled Mach-O execution", testR3ControlledMachOExecution},
    };

    std::size_t failures = 0;
    for (const auto &[name, test] : tests) {
        try {
            test();
            std::cout << "[pass] " << name << '\n';
        } catch (const std::exception &error) {
            ++failures;
            std::cerr << "[fail] " << name << ": " << error.what() << '\n';
        }
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << tests.size() << " tests passed\n";
    return 0;
}
