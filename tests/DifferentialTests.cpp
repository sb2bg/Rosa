#include "TestSupport.h"
#include "TestSuite.h"

#if ROSA_HAS_X86_ORACLE
#include "differential/Protocol.h"
#endif

namespace rosa::tests {
namespace {

#if ROSA_HAS_X86_ORACLE

#define ROSA_DIFFERENTIAL_CASE(name, ...)                                                          \
    constexpr auto differentialBytes_##name = std::to_array<std::uint8_t>({__VA_ARGS__, 0xC3});
#include "differential/Cases.def"
#undef ROSA_DIFFERENTIAL_CASE

constexpr std::uint16_t allGprsExceptRsp = static_cast<std::uint16_t>(
    UINT16_MAX & ~(1U << static_cast<unsigned>(rosa::x86::Register::Rsp)));

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

std::uint64_t registerValue(const rosa::x86::X86State &state, rosa::x86::Register reg) {
    std::uint64_t result = 0;
    const auto *bytes = reinterpret_cast<const std::uint8_t *>(&state);
    std::memcpy(&result, bytes + rosa::x86::registerOffset(reg), sizeof(result));
    return result;
}

void setRegisterValue(rosa::x86::X86State &state, rosa::x86::Register reg, std::uint64_t value) {
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

rosa::differential::Result runX86Oracle(const rosa::differential::Request &request) {
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
    const auto wrote =
        writeFully(requestPipe[1], std::as_bytes(std::span(&request, std::size_t{1})));
    ::close(requestPipe[1]);
    rosa::differential::Result result;
    const auto read =
        readFully(resultPipe[0], std::as_writable_bytes(std::span(&result, std::size_t{1})));
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
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute,
                            testCase.code, "differential:__TEXT");
    addressSpace.mapAnonymous(memoryBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "differential memory");
    addressSpace.writeBytes(memoryBase, testCase.request.memory);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "differential stack");

    auto state = testCase.request.state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::differential::stackSize - 8;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    if (testCase.request.memoryBaseRegister != rosa::differential::noRegister) {
        setRegisterValue(state,
                         static_cast<rosa::x86::Register>(testCase.request.memoryBaseRegister),
                         memoryBase.value + testCase.request.memoryBaseOffset);
    }
    if (testCase.request.memorySecondBaseRegister != rosa::differential::noRegister) {
        setRegisterValue(
            state, static_cast<rosa::x86::Register>(testCase.request.memorySecondBaseRegister),
            memoryBase.value + testCase.request.memorySecondBaseOffset);
    }
    if (testCase.request.codePointerMemoryOffset != rosa::differential::noOffset) {
        addressSpace.writeU64(
            rosa::guest::GuestAddress{memoryBase.value + testCase.request.codePointerMemoryOffset},
            codeBase.value + testCase.request.codePointerTargetOffset);
    }
    if (testCase.request.codePointerRegister != rosa::differential::noRegister) {
        setRegisterValue(state,
                         static_cast<rosa::x86::Register>(testCase.request.codePointerRegister),
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
                std::string(testCase.name) + ": " + std::string(rosa::x86::registerName(reg)) +
                " expected " + hexadecimal(expected) + " but Rosa produced " + hexadecimal(actual));
        }
    }

    const auto compareBoundRegisterDelta = [&](std::uint8_t encoded, std::string_view role) {
        if (encoded == rosa::differential::noRegister) {
            return;
        }
        const auto reg = static_cast<rosa::x86::Register>(encoded);
        const auto expected = registerValue(oracle.final, reg) - registerValue(oracle.initial, reg);
        const auto actual =
            registerValue(rosaResult.final, reg) - registerValue(rosaResult.initial, reg);
        if (actual != expected) {
            throw std::runtime_error(
                std::string(testCase.name) + ": normalized " + std::string(role) + " delta for " +
                std::string(rosa::x86::registerName(reg)) + " expected " + hexadecimal(expected) +
                " but Rosa produced " + hexadecimal(actual));
        }
    };
    compareBoundRegisterDelta(testCase.request.memoryBaseRegister, "memory base");
    compareBoundRegisterDelta(testCase.request.memorySecondBaseRegister, "second memory base");
    compareBoundRegisterDelta(testCase.request.codePointerRegister, "code pointer");

    const auto expectedFlags = oracle.final.rflags & testCase.flagMask;
    const auto actualFlags = rosaResult.final.rflags & testCase.flagMask;
    if (actualFlags != expectedFlags) {
        throw std::runtime_error(std::string(testCase.name) + ": defined RFLAGS expected " +
                                 hexadecimal(expectedFlags) + " but Rosa produced " +
                                 hexadecimal(actualFlags) + " (mask " +
                                 hexadecimal(testCase.flagMask) + ")");
    }

    const auto oracleStackDelta = oracle.final.rsp - oracle.initial.rsp;
    const auto rosaStackDelta = rosaResult.final.rsp - rosaResult.initial.rsp;
    if (rosaStackDelta != oracleStackDelta) {
        throw std::runtime_error(std::string(testCase.name) + ": normalized RSP delta differs");
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
        throw std::runtime_error(std::string(testCase.name) + ": selected guest memory differs");
    }
    const auto stackEnd = testCase.stackCompareOffset + testCase.stackCompareSize;
    if (stackEnd > oracle.stack.size() ||
        !std::equal(oracle.stack.begin() + static_cast<std::ptrdiff_t>(testCase.stackCompareOffset),
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
    const auto make = [](std::string_view name, CaseId id, std::span<const std::uint8_t> code) {
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
        testCase.gprMask =
            static_cast<std::uint16_t>(testCase.gprMask & ~(1U << static_cast<unsigned>(reg)));
    };
    const auto bindSecondMemory = [](DifferentialCase &testCase, rosa::x86::Register reg,
                                     std::uint16_t offset) {
        testCase.request.memorySecondBaseRegister = static_cast<std::uint8_t>(reg);
        testCase.request.memorySecondBaseOffset = offset;
        testCase.gprMask =
            static_cast<std::uint16_t>(testCase.gprMask & ~(1U << static_cast<unsigned>(reg)));
    };

    {
        auto testCase =
            make("add64_overflow", CaseId::add64_overflow, differentialBytes_add64_overflow);
        testCase.request.state.rax = INT64_MAX;
        run(testCase);
    }
    {
        auto testCase = make("add64_accumulator_immediate", CaseId::add64_accumulator_immediate,
                             differentialBytes_add64_accumulator_immediate);
        testCase.request.state.rax = 0x40;
        run(testCase);
    }
    {
        auto testCase =
            make("add64_accumulator_sign_extended", CaseId::add64_accumulator_sign_extended,
                 differentialBytes_add64_accumulator_sign_extended);
        testCase.request.state.rax = 0;
        run(testCase);
    }
    {
        auto testCase = make("add32_accumulator_zero_extend", CaseId::add32_accumulator_zero_extend,
                             differentialBytes_add32_accumulator_zero_extend);
        testCase.request.state.rax = UINT64_MAX;
        run(testCase);
    }
    {
        auto testCase = make("add32_register_zero_extend", CaseId::add32_register_zero_extend,
                             differentialBytes_add32_register_zero_extend);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.rcx = 1;
        run(testCase);
    }
    {
        auto testCase = make("add32_register_overflow", CaseId::add32_register_overflow,
                             differentialBytes_add32_register_overflow);
        testCase.request.state.rax = 0xAAAAAAAA7FFFFFFFULL;
        testCase.request.state.rcx = 1;
        run(testCase);
    }
    {
        auto testCase = make("add64_memory_destination", CaseId::add64_memory_destination,
                             differentialBytes_add64_memory_destination);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.r14 = 1;
        const std::uint64_t value = UINT64_MAX;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("add64_indexed_memory_carry", CaseId::add64_indexed_memory_carry,
                             differentialBytes_add64_indexed_memory_carry);
        bindMemory(testCase, rosa::x86::Register::R15, 0x20);
        testCase.request.state.r14 = 0x20;
        testCase.request.state.r13 = UINT64_MAX - 2;
        constexpr std::uint64_t value = 7;
        std::memcpy(testCase.request.memory.data() + 0x30, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x30;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("add64_indexed_memory_overflow", CaseId::add64_indexed_memory_overflow,
                             differentialBytes_add64_indexed_memory_overflow);
        bindMemory(testCase, rosa::x86::Register::R15, 0x20);
        testCase.request.state.r14 = 0x20;
        testCase.request.state.r13 = 1;
        constexpr std::uint64_t value = INT64_MAX;
        std::memcpy(testCase.request.memory.data() + 0x30, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x30;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("lock_add64_memory_carry", CaseId::lock_add64_memory_carry,
                             differentialBytes_lock_add64_memory_carry);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = 1;
        const std::uint64_t value = UINT64_MAX;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("lock_add64_memory_overflow", CaseId::lock_add64_memory_overflow,
                             differentialBytes_lock_add64_memory_overflow);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = 1;
        const std::uint64_t value = INT64_MAX;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("lock_xadd32_memory_carry", CaseId::lock_xadd32_memory_carry,
                             differentialBytes_lock_xadd32_memory_carry);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = 0xAAAAAAAA00000001ULL;
        const std::uint64_t value = 0xDEADBEEFFFFFFFFFULL;
        std::memcpy(testCase.request.memory.data(), &value, sizeof(value));
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("lock_xadd32_memory_overflow", CaseId::lock_xadd32_memory_overflow,
                             differentialBytes_lock_xadd32_memory_overflow);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = 0xBBBBBBBB00000001ULL;
        const std::uint64_t value = 0xCAFEBABE7FFFFFFFULL;
        std::memcpy(testCase.request.memory.data(), &value, sizeof(value));
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("add8_register_overflow", CaseId::add8_register_overflow,
                             differentialBytes_add8_register_overflow);
        testCase.request.state.rsi = 0x112233445566777FULL;
        testCase.request.state.r9 = 0x8877665544332201ULL;
        run(testCase);
    }
    {
        auto testCase = make("add8_scaled_memory", CaseId::add8_scaled_memory,
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
        auto testCase =
            make("add8_immediate", CaseId::add8_immediate, differentialBytes_add8_immediate);
        testCase.request.state.rdx = 0x112233445566777CULL;
        run(testCase);
    }
    {
        auto testCase = make("add8_accumulator_immediate", CaseId::add8_accumulator_immediate,
                             differentialBytes_add8_accumulator_immediate);
        testCase.request.state.rax = 0xAABBCCDDEEFF0001ULL;
        run(testCase);
    }
    {
        auto testCase =
            make("add8_accumulator_immediate_overflow", CaseId::add8_accumulator_immediate_overflow,
                 differentialBytes_add8_accumulator_immediate_overflow);
        testCase.request.state.rax = 0xAABBCCDDEEFF007AULL;
        run(testCase);
    }
    {
        auto testCase = make("add32_sign_extended_immediate", CaseId::add32_sign_extended_immediate,
                             differentialBytes_add32_sign_extended_immediate);
        testCase.request.state.rax = 0xAAAAAAAA80000003ULL;
        run(testCase);
    }
    {
        auto testCase =
            make("add32_extended_immediate_carry", CaseId::add32_extended_immediate_carry,
                 differentialBytes_add32_extended_immediate_carry);
        testCase.request.state.r13 = 0xAAAAAAAAFFFF0020ULL;
        run(testCase);
    }
    {
        auto testCase =
            make("add32_extended_immediate_overflow", CaseId::add32_extended_immediate_overflow,
                 differentialBytes_add32_extended_immediate_overflow);
        testCase.request.state.r13 = 0xAAAAAAAA7FFF0020ULL;
        run(testCase);
    }
    {
        auto testCase = make("sub64_borrow", CaseId::sub64_borrow, differentialBytes_sub64_borrow);
        testCase.request.state.rdi = 5;
        testCase.request.state.rdx = 7;
        run(testCase);
    }
    {
        auto testCase = make("sub64_indexed_memory_borrow", CaseId::sub64_indexed_memory_borrow,
                             differentialBytes_sub64_indexed_memory_borrow);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = 5;
        testCase.request.state.rcx = 0x20;
        const std::uint64_t value = 7;
        std::memcpy(testCase.request.memory.data() + 0x20, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("sub64_indexed_memory_overflow", CaseId::sub64_indexed_memory_overflow,
                             differentialBytes_sub64_indexed_memory_overflow);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = 0x8000000000000000ULL;
        testCase.request.state.rcx = 0x20;
        const std::uint64_t value = 1;
        std::memcpy(testCase.request.memory.data() + 0x20, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("sub32_extended_borrow", CaseId::sub32_extended_borrow,
                             differentialBytes_sub32_extended_borrow);
        testCase.request.state.r13 = 0xAAAAAAAA00000005ULL;
        testCase.request.state.r12 = 0xBBBBBBBB00000007ULL;
        run(testCase);
    }
    {
        auto testCase = make("sub32_extended_overflow", CaseId::sub32_extended_overflow,
                             differentialBytes_sub32_extended_overflow);
        testCase.request.state.r13 = 0xAAAAAAAA80000000ULL;
        testCase.request.state.r12 = 0xBBBBBBBB00000001ULL;
        run(testCase);
    }
    {
        auto testCase = make("sub8_register_borrow", CaseId::sub8_register_borrow,
                             differentialBytes_sub8_register_borrow);
        testCase.request.state.rcx = 0x1122334455667700ULL;
        testCase.request.state.rax = 0x8877665544332201ULL;
        run(testCase);
    }
    {
        auto testCase = make("sub8_register_overflow", CaseId::sub8_register_overflow,
                             differentialBytes_sub8_register_overflow);
        testCase.request.state.rcx = 0x1122334455667780ULL;
        testCase.request.state.rax = 0x8877665544332201ULL;
        run(testCase);
    }
    {
        auto testCase =
            make("inc32_overflow", CaseId::inc32_overflow, differentialBytes_inc32_overflow);
        testCase.request.state.r15 = 0xAAAAAAAA7FFFFFFFULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("inc32_extended_memory_overflow", CaseId::inc32_extended_memory_overflow,
                 differentialBytes_inc32_extended_memory_overflow);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.rflags |= carryFlag;
        constexpr std::uint32_t memoryValue = 0x7FFFFFFFU;
        std::memcpy(testCase.request.memory.data() + 0xD0, &memoryValue, sizeof(memoryValue));
        testCase.memoryCompareOffset = 0xD0;
        testCase.memoryCompareSize = sizeof(memoryValue);
        run(testCase);
    }
    {
        auto testCase = make("inc32_extended_memory_wrap", CaseId::inc32_extended_memory_wrap,
                             differentialBytes_inc32_extended_memory_wrap);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.rflags &= ~carryFlag;
        constexpr std::uint32_t memoryValue = UINT32_MAX;
        std::memcpy(testCase.request.memory.data() + 0xD0, &memoryValue, sizeof(memoryValue));
        testCase.memoryCompareOffset = 0xD0;
        testCase.memoryCompareSize = sizeof(memoryValue);
        run(testCase);
    }
    {
        auto testCase =
            make("inc8_overflow", CaseId::inc8_overflow, differentialBytes_inc8_overflow);
        testCase.request.state.r8 = 0x112233445566777FULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("inc8_scaled_memory_overflow", CaseId::inc8_scaled_memory_overflow,
                             differentialBytes_inc8_scaled_memory_overflow);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.rsi = 0x20;
        testCase.request.state.rflags |= carryFlag;
        testCase.request.memory[0x78] = 0x7F;
        testCase.memoryCompareOffset = 0x78;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("inc8_scaled_memory_wrap", CaseId::inc8_scaled_memory_wrap,
                             differentialBytes_inc8_scaled_memory_wrap);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.rsi = 0x20;
        testCase.request.state.rflags &= ~carryFlag;
        testCase.request.memory[0x78] = 0xFF;
        testCase.memoryCompareOffset = 0x78;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase =
            make("dec32_overflow", CaseId::dec32_overflow, differentialBytes_dec32_overflow);
        testCase.request.state.rdi = 0xBBBBBBBB80000000ULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("dec8_overflow", CaseId::dec8_overflow, differentialBytes_dec8_overflow);
        testCase.request.state.rax = 0x1122334455667780ULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("dec8_scaled_memory_overflow", CaseId::dec8_scaled_memory_overflow,
                             differentialBytes_dec8_scaled_memory_overflow);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.rax = 0x20;
        testCase.request.state.rflags |= carryFlag;
        testCase.request.memory[0x78] = 0x80;
        testCase.memoryCompareOffset = 0x78;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("dec8_scaled_memory_zero", CaseId::dec8_scaled_memory_zero,
                             differentialBytes_dec8_scaled_memory_zero);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.rax = 0x20;
        testCase.request.state.rflags &= ~carryFlag;
        testCase.request.memory[0x78] = 1;
        testCase.memoryCompareOffset = 0x78;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("dec64_memory", CaseId::dec64_memory, differentialBytes_dec64_memory);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        const std::uint64_t value = std::uint64_t{1} << 63U;
        std::memcpy(testCase.request.memory.data() + 0x18, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x18;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("nop_multi_byte_disp32", CaseId::nop_multi_byte_disp32,
                             differentialBytes_nop_multi_byte_disp32);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("and32_mask", CaseId::and32_mask, differentialBytes_and32_mask);
        testCase.request.state.r15 = 0xFFFFFFFF80000800ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("and64_sign_extended_mask", CaseId::and64_sign_extended_mask,
                             differentialBytes_and64_sign_extended_mask);
        testCase.request.state.rcx = 0x123456789ABCDEF0ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase =
            make("and8_accumulator", CaseId::and8_accumulator, differentialBytes_and8_accumulator);
        testCase.request.state.rax = 0x11223344556677A5ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("and8_register_immediate", CaseId::and8_register_immediate,
                             differentialBytes_and8_register_immediate);
        testCase.request.state.rcx = 0x1122334455667781ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("and8_register_immediate_zero", CaseId::and8_register_immediate_zero,
                             differentialBytes_and8_register_immediate_zero);
        testCase.request.state.rcx = 0x1122334455667780ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase =
            make("and8_register", CaseId::and8_register, differentialBytes_and8_register);
        testCase.request.state.rax = 0x1122334455667780ULL;
        testCase.request.state.rcx = 0x88776655443322FFULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase =
            make("and8_rip_memory", CaseId::and8_rip_memory, differentialBytes_and8_rip_memory);
        testCase.request.state.r14 = 0x11223344556677F3ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("and32_memory", CaseId::and32_memory, differentialBytes_and32_memory);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = 0xFFFFFFFFF0F0F0F0ULL;
        const std::uint32_t value = 0x0FF00FF0U;
        std::memcpy(testCase.request.memory.data() + 4, &value, sizeof(value));
        testCase.memoryCompareOffset = 4;
        testCase.memoryCompareSize = sizeof(value);
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("and32_memory_zero", CaseId::and32_memory_zero,
                             differentialBytes_and32_memory_zero);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = UINT64_MAX;
        const std::uint32_t value = 0;
        std::memcpy(testCase.request.memory.data() + 4, &value, sizeof(value));
        testCase.memoryCompareOffset = 4;
        testCase.memoryCompareSize = sizeof(value);
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("and64_memory", CaseId::and64_memory, differentialBytes_and64_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.rsi = 0xF0F0F0F0F0F0F0F0ULL;
        const std::uint64_t value = 0x0FF00FF00FF00FF0ULL;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("and64_memory_zero", CaseId::and64_memory_zero,
                             differentialBytes_and64_memory_zero);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.rsi = 0xF0F0F0F0F0F0F0F0ULL;
        const std::uint64_t value = 0x0F0F0F0F0F0F0F0FULL;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase =
            make("or64_register", CaseId::or64_register, differentialBytes_or64_register);
        testCase.request.state.rax = 0x00000000ABCDEF01ULL;
        testCase.request.state.rdx = 0x1234567800000000ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or8_register", CaseId::or8_register, differentialBytes_or8_register);
        testCase.request.state.rax = 0x1122334455667780ULL;
        testCase.request.state.rcx = 0x8877665544332201ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or8_extended_memory", CaseId::or8_extended_memory,
                             differentialBytes_or8_extended_memory);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.rax = 0x1122334455667780ULL;
        testCase.request.memory[0] = 1;
        testCase.memoryCompareSize = 1;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or8_extended_memory_zero", CaseId::or8_extended_memory_zero,
                             differentialBytes_or8_extended_memory_zero);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.rax = 0x1122334455667700ULL;
        testCase.request.memory[0] = 0;
        testCase.memoryCompareSize = 1;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or32_extended_memory", CaseId::or32_extended_memory,
                             differentialBytes_or32_extended_memory);
        bindMemory(testCase, rosa::x86::Register::Rbp, 0x40);
        testCase.request.state.r14 = 0xAAAAAAAA80000000ULL;
        constexpr std::uint32_t value = 1;
        std::memcpy(testCase.request.memory.data() + 0x14, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x14;
        testCase.memoryCompareSize = sizeof(value);
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or32_extended_memory_zero", CaseId::or32_extended_memory_zero,
                             differentialBytes_or32_extended_memory_zero);
        bindMemory(testCase, rosa::x86::Register::Rbp, 0x40);
        testCase.request.state.r14 = UINT64_MAX << 32U;
        testCase.memoryCompareOffset = 0x14;
        testCase.memoryCompareSize = sizeof(std::uint32_t);
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or8_extended_immediate", CaseId::or8_extended_immediate,
                             differentialBytes_or8_extended_immediate);
        testCase.request.state.r8 = 0x1122334455667780ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or8_extended_immediate_zero", CaseId::or8_extended_immediate_zero,
                             differentialBytes_or8_extended_immediate_zero);
        testCase.request.state.r8 = 0x1122334455667700ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or8_indexed_memory", CaseId::or8_indexed_memory,
                             differentialBytes_or8_indexed_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 0x20);
        testCase.request.state.rdx = 8;
        testCase.request.state.rdi = 0x1122334455667701ULL;
        testCase.request.memory[0x28] = 0x80;
        testCase.memoryCompareOffset = 0x28;
        testCase.memoryCompareSize = 1;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("or8_memory_immediate", CaseId::or8_memory_immediate,
                             differentialBytes_or8_memory_immediate);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.memory[0xD8] = 0x80;
        testCase.memoryCompareOffset = 0xD8;
        testCase.memoryCompareSize = 1;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase =
            make("xor32_register", CaseId::xor32_register, differentialBytes_xor32_register);
        testCase.request.state.rsi = UINT64_MAX;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("xor32_scaled_memory", CaseId::xor32_scaled_memory,
                             differentialBytes_xor32_scaled_memory);
        bindMemory(testCase, rosa::x86::Register::Rdx, 0);
        testCase.request.state.rax = 0xAABBCCDDFFFF0000ULL;
        testCase.request.state.r9 = 0x10;
        constexpr std::uint32_t value = 0x00FFFF00;
        std::memcpy(testCase.request.memory.data() + 0x40, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = sizeof(value);
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("xor32_short_immediate", CaseId::xor32_short_immediate,
                             differentialBytes_xor32_short_immediate);
        testCase.request.state.rax = 0xAAAAAAAA00000007ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase =
            make("xor32_negative_short_immediate", CaseId::xor32_negative_short_immediate,
                 differentialBytes_xor32_negative_short_immediate);
        testCase.request.state.rax = 0xAAAAAAAA12345678ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase =
            make("xor8_accumulator", CaseId::xor8_accumulator, differentialBytes_xor8_accumulator);
        testCase.request.state.rax = 0x1122334455667701ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("xor8_scaled_memory", CaseId::xor8_scaled_memory,
                             differentialBytes_xor8_scaled_memory);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = 0x11223344556677FFULL;
        testCase.request.state.rcx = 0x30;
        testCase.request.memory[0x30] = 0x0F;
        testCase.memoryCompareOffset = 0x30;
        testCase.memoryCompareSize = 1;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase =
            make("test16_register", CaseId::test16_register, differentialBytes_test16_register);
        testCase.request.state.r14 = 0xA5A5A5A500008000ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("test8_register_immediate", CaseId::test8_register_immediate,
                             differentialBytes_test8_register_immediate);
        testCase.request.state.rdx = 0x1122334455667782ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase =
            make("test8_extended_register_immediate", CaseId::test8_extended_register_immediate,
                 differentialBytes_test8_extended_register_immediate);
        testCase.request.state.r14 = 0x8877665544332202ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("test64_register_immediate", CaseId::test64_register_immediate,
                             differentialBytes_test64_register_immediate);
        testCase.request.state.rdi = 0x100002990ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("test64_register_sign_extended_immediate",
                             CaseId::test64_register_sign_extended_immediate,
                             differentialBytes_test64_register_sign_extended_immediate);
        testCase.request.state.rdi = 0x8000000000000000ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("test8_memory_immediate_zero", CaseId::test8_memory_immediate_zero,
                             differentialBytes_test8_memory_immediate_zero);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.memory[8] = 0;
        testCase.memoryCompareOffset = 8;
        testCase.memoryCompareSize = 1;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("test8_memory_immediate_sign", CaseId::test8_memory_immediate_sign,
                             differentialBytes_test8_memory_immediate_sign);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.memory[8] = 0x80;
        testCase.memoryCompareOffset = 8;
        testCase.memoryCompareSize = 1;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("test8_extended_registers", CaseId::test8_extended_registers,
                             differentialBytes_test8_extended_registers);
        testCase.request.state.r14 = 0x1122334455667780ULL;
        testCase.flagMask = logicDefinedFlags;
        run(testCase);
    }
    {
        auto testCase = make("cmp8_extended_registers", CaseId::cmp8_extended_registers,
                             differentialBytes_cmp8_extended_registers);
        testCase.request.state.rcx = 0x1122334455667700ULL;
        testCase.request.state.r8 = 0x887766554433221FULL;
        run(testCase);
    }
    {
        auto testCase =
            make("cmp8_extended_registers_overflow", CaseId::cmp8_extended_registers_overflow,
                 differentialBytes_cmp8_extended_registers_overflow);
        testCase.request.state.rcx = 0x1122334455667780ULL;
        testCase.request.state.r8 = 0x8877665544332201ULL;
        run(testCase);
    }
    {
        auto testCase =
            make("cmp64_register", CaseId::cmp64_register, differentialBytes_cmp64_register);
        testCase.request.state.r14 = 5;
        testCase.request.state.r13 = 7;
        run(testCase);
    }
    {
        auto testCase = make("cmp64_accumulator_immediate", CaseId::cmp64_accumulator_immediate,
                             differentialBytes_cmp64_accumulator_immediate);
        testCase.request.state.rax = 0x409F;
        run(testCase);
    }
    {
        auto testCase =
            make("cmp64_accumulator_sign_extended", CaseId::cmp64_accumulator_sign_extended,
                 differentialBytes_cmp64_accumulator_sign_extended);
        testCase.request.state.rax = 0;
        run(testCase);
    }
    {
        auto testCase =
            make("cmp64_extended_immediate_equal", CaseId::cmp64_extended_immediate_equal,
                 differentialBytes_cmp64_extended_immediate_equal);
        testCase.request.state.r15 = 0x1001;
        run(testCase);
    }
    {
        auto testCase = make("cmp64_extended_immediate_sign_extended",
                             CaseId::cmp64_extended_immediate_sign_extended,
                             differentialBytes_cmp64_extended_immediate_sign_extended);
        testCase.request.state.r15 = 0;
        run(testCase);
    }
    {
        auto testCase = make("cmp32_register_legacy", CaseId::cmp32_register_legacy,
                             differentialBytes_cmp32_register_legacy);
        testCase.request.state.rdx = 0xAAAAAAAA80000000ULL;
        testCase.request.state.rsi = 0xBBBBBBBB00000001ULL;
        run(testCase);
    }
    {
        auto testCase = make("cmp8_register_immediate", CaseId::cmp8_register_immediate,
                             differentialBytes_cmp8_register_immediate);
        testCase.request.state.rcx = 0x1122334455667700ULL;
        run(testCase);
    }
    {
        auto testCase = make("cmp8_accumulator_equal", CaseId::cmp8_accumulator_equal,
                             differentialBytes_cmp8_accumulator_equal);
        testCase.request.state.rax = 0xAABBCCDDEEFF0039ULL;
        run(testCase);
    }
    {
        auto testCase = make("cmp8_accumulator_borrow", CaseId::cmp8_accumulator_borrow,
                             differentialBytes_cmp8_accumulator_borrow);
        testCase.request.state.rax = 0xAABBCCDDEEFF0000ULL;
        run(testCase);
    }
    {
        auto testCase = make("cmp64_memory_register", CaseId::cmp64_memory_register,
                             differentialBytes_cmp64_memory_register);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.rax = 7;
        const std::uint64_t value = 5;
        std::memcpy(testCase.request.memory.data() + 0x30, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x30;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("cmp64_rip_memory_equal", CaseId::cmp64_rip_memory_equal,
                             differentialBytes_cmp64_rip_memory_equal);
        testCase.request.state.rcx = 5;
        testCase.flagMask = arithmeticFlags;
        run(testCase);
    }
    {
        auto testCase = make("cmp64_rip_memory_below", CaseId::cmp64_rip_memory_below,
                             differentialBytes_cmp64_rip_memory_below);
        testCase.request.state.rcx = 4;
        testCase.flagMask = arithmeticFlags;
        run(testCase);
    }
    {
        auto testCase = make("cmp64_memory_immediate_equal", CaseId::cmp64_memory_immediate_equal,
                             differentialBytes_cmp64_memory_immediate_equal);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        constexpr std::uint64_t value = 0x4000;
        std::memcpy(testCase.request.memory.data(), &value, sizeof(value));
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("cmp64_memory_immediate_sign_extended",
                             CaseId::cmp64_memory_immediate_sign_extended,
                             differentialBytes_cmp64_memory_immediate_sign_extended);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        constexpr std::uint64_t value = 0;
        std::memcpy(testCase.request.memory.data(), &value, sizeof(value));
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase =
            make("cmp32_sib_memory_immediate_equal", CaseId::cmp32_sib_memory_immediate_equal,
                 differentialBytes_cmp32_sib_memory_immediate_equal);
        bindMemory(testCase, rosa::x86::Register::R12, 0);
        constexpr std::uint32_t value = 0x205;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase =
            make("cmp32_sib_memory_immediate_borrow", CaseId::cmp32_sib_memory_immediate_borrow,
                 differentialBytes_cmp32_sib_memory_immediate_borrow);
        bindMemory(testCase, rosa::x86::Register::R12, 0);
        constexpr std::uint32_t value = 0x204;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("cmp32_sib_memory_short_equal", CaseId::cmp32_sib_memory_short_equal,
                             differentialBytes_cmp32_sib_memory_short_equal);
        bindMemory(testCase, rosa::x86::Register::R12, 0);
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = sizeof(std::uint32_t);
        run(testCase);
    }
    {
        auto testCase = make("cmp8_scaled_memory_register", CaseId::cmp8_scaled_memory_register,
                             differentialBytes_cmp8_scaled_memory_register);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.rdx = 0x20;
        testCase.request.state.rcx = 0x1122334455667701ULL;
        testCase.request.memory[0x78] = 0x80;
        testCase.memoryCompareOffset = 0x78;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("lock_cmpxchg32_equal", CaseId::lock_cmpxchg32_equal,
                             differentialBytes_lock_cmpxchg32_equal);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0x40);
        testCase.request.state.rax = 0xAAAAAAAA00000000ULL;
        testCase.request.state.rcx = 0xBBBBBBBB12345678ULL;
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = sizeof(std::uint32_t);
        run(testCase);
    }
    {
        auto testCase = make("lock_cmpxchg32_mismatch", CaseId::lock_cmpxchg32_mismatch,
                             differentialBytes_lock_cmpxchg32_mismatch);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0x40);
        testCase.request.state.rax = 0xAAAAAAAA00000000ULL;
        testCase.request.state.rcx = 0xBBBBBBBB12345678ULL;
        constexpr std::uint32_t memoryValue = 0x80000000U;
        std::memcpy(testCase.request.memory.data() + 0x40, &memoryValue, sizeof(memoryValue));
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = sizeof(memoryValue);
        run(testCase);
    }
    {
        auto testCase = make("lock_cmpxchg16b_equal", CaseId::lock_cmpxchg16b_equal,
                             differentialBytes_lock_cmpxchg16b_equal);
        bindMemory(testCase, rosa::x86::Register::Rsi, 0);
        constexpr std::array<std::uint64_t, 2> memoryValue{0x1111222233334444ULL,
                                                           0x5555666677778888ULL};
        std::memcpy(testCase.request.memory.data() + 0x30, memoryValue.data(), sizeof(memoryValue));
        testCase.request.state.rax = memoryValue[0];
        testCase.request.state.rdx = memoryValue[1];
        testCase.request.state.rbx = 0xAAAABBBBCCCCDDDDULL;
        testCase.request.state.rcx = 0xEEEEFFFF00001111ULL;
        testCase.memoryCompareOffset = 0x30;
        testCase.memoryCompareSize = sizeof(memoryValue);
        testCase.flagMask = zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("lock_cmpxchg16b_mismatch", CaseId::lock_cmpxchg16b_mismatch,
                             differentialBytes_lock_cmpxchg16b_mismatch);
        bindMemory(testCase, rosa::x86::Register::Rsi, 0);
        constexpr std::array<std::uint64_t, 2> memoryValue{0x1111222233334444ULL,
                                                           0x5555666677778888ULL};
        std::memcpy(testCase.request.memory.data() + 0x30, memoryValue.data(), sizeof(memoryValue));
        testCase.request.state.rax = 1;
        testCase.request.state.rdx = 2;
        testCase.request.state.rbx = 3;
        testCase.request.state.rcx = 4;
        testCase.memoryCompareOffset = 0x30;
        testCase.memoryCompareSize = sizeof(memoryValue);
        testCase.flagMask = zeroFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("xchg32_memory", CaseId::xchg32_memory, differentialBytes_xchg32_memory);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0x40);
        testCase.request.state.rdx = 0xAAAAAAAAAABBCCDDULL;
        constexpr std::uint32_t memoryValue = 0x11223344U;
        std::memcpy(testCase.request.memory.data() + 0x40, &memoryValue, sizeof(memoryValue));
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = sizeof(memoryValue);
        run(testCase);
    }
    {
        auto testCase =
            make("xchg64_memory", CaseId::xchg64_memory, differentialBytes_xchg64_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 0x38);
        testCase.request.state.rcx = 0x0123456789ABCDEFULL;
        constexpr std::uint64_t memoryValue = 0xFEDCBA9876543210ULL;
        std::memcpy(testCase.request.memory.data() + 0x40, &memoryValue, sizeof(memoryValue));
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = sizeof(memoryValue);
        run(testCase);
    }
    {
        auto testCase = make("lock_or32_stack_zero", CaseId::lock_or32_stack_zero,
                             differentialBytes_lock_or32_stack_zero);
        testCase.flagMask = logicDefinedFlags;
        testCase.stackCompareOffset = rosa::differential::stackSize - 72;
        testCase.stackCompareSize = sizeof(std::uint32_t);
        run(testCase);
    }
    {
        auto testCase = make("lock_inc32_overflow", CaseId::lock_inc32_overflow,
                             differentialBytes_lock_inc32_overflow);
        bindMemory(testCase, rosa::x86::Register::Rax, 0x40);
        constexpr std::uint32_t memoryValue = 0x7FFFFFFFU;
        std::memcpy(testCase.request.memory.data() + 0x40, &memoryValue, sizeof(memoryValue));
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = sizeof(memoryValue);
        run(testCase);
    }
    {
        auto testCase =
            make("lock_inc32_wrap", CaseId::lock_inc32_wrap, differentialBytes_lock_inc32_wrap);
        bindMemory(testCase, rosa::x86::Register::Rax, 0x40);
        testCase.request.state.rflags = 0x8D6;
        constexpr std::uint32_t memoryValue = UINT32_MAX;
        std::memcpy(testCase.request.memory.data() + 0x40, &memoryValue, sizeof(memoryValue));
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = sizeof(memoryValue);
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
        auto testCase = make("cmp8_scaled_memory_immediate", CaseId::cmp8_scaled_memory_immediate,
                             differentialBytes_cmp8_scaled_memory_immediate);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.r12 = 0x20;
        testCase.request.memory[0x20] = 0x80;
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase =
            make("cmp32_rip_memory", CaseId::cmp32_rip_memory, differentialBytes_cmp32_rip_memory);
        run(testCase);
    }
    {
        auto testCase = make("shl64_one", CaseId::shl64_one, differentialBytes_shl64_one);
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
        auto testCase =
            make("shl32_immediate", CaseId::shl32_immediate, differentialBytes_shl32_immediate);
        testCase.request.state.rdx = 0xAAAAAAAA08000001ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("shl64_memory_three", CaseId::shl64_memory_three,
                             differentialBytes_shl64_memory_three);
        bindMemory(testCase, rosa::x86::Register::Rbp, 0x80);
        const std::uint64_t value = 0x2000000000000001ULL;
        std::memcpy(testCase.request.memory.data() + 0x48, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x48;
        testCase.memoryCompareSize = sizeof(value);
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("shl64_memory_one", CaseId::shl64_memory_one, differentialBytes_shl64_memory_one);
        bindMemory(testCase, rosa::x86::Register::Rbp, 0x80);
        const std::uint64_t value = 0x4000000000000001ULL;
        std::memcpy(testCase.request.memory.data() + 0x48, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x48;
        testCase.memoryCompareSize = sizeof(value);
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("shl32_immediate_masked_zero", CaseId::shl32_immediate_masked_zero,
                             differentialBytes_shl32_immediate_masked_zero);
        testCase.request.state.rdx = 0xAAAAAAAA12345678ULL;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("shl32_cl_one", CaseId::shl32_cl_one, differentialBytes_shl32_cl_one);
        testCase.request.state.rax = 0xFFFFFFFF80000001ULL;
        testCase.request.state.rcx = 1;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("shl32_cl_masked_zero", CaseId::shl32_cl_masked_zero,
                             differentialBytes_shl32_cl_masked_zero);
        testCase.request.state.rax = 0xAAAAAAAA12345678ULL;
        testCase.request.state.rcx = 32;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("shl8_cl_one", CaseId::shl8_cl_one, differentialBytes_shl8_cl_one);
        testCase.request.state.rdi = 0x1122334455667781ULL;
        testCase.request.state.rcx = 1;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("shl8_cl_many", CaseId::shl8_cl_many, differentialBytes_shl8_cl_many);
        testCase.request.state.rdi = 0x1122334455667781ULL;
        testCase.request.state.rcx = 7;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("shl8_cl_operand_width", CaseId::shl8_cl_operand_width,
                             differentialBytes_shl8_cl_operand_width);
        testCase.request.state.rdi = 0x1122334455667781ULL;
        testCase.request.state.rcx = 8;
        testCase.flagMask = parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("shl8_cl_masked_zero", CaseId::shl8_cl_masked_zero,
                             differentialBytes_shl8_cl_masked_zero);
        testCase.request.state.rdi = 0x1122334455667781ULL;
        testCase.request.state.rcx = 0xABCDEF0000000020ULL;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("shr32_many", CaseId::shr32_many, differentialBytes_shr32_many);
        testCase.request.state.rax = 0xFFFFFFFF80000001ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr8_extended_many", CaseId::shr8_extended_many,
                             differentialBytes_shr8_extended_many);
        testCase.request.state.r8 = 0x1122334455667780ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr8_extended_one", CaseId::shr8_extended_one,
                             differentialBytes_shr8_extended_one);
        testCase.request.state.r8 = 0x1122334455667781ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr8_accumulator_implicit_one", CaseId::shr8_accumulator_implicit_one,
                             differentialBytes_shr8_accumulator_implicit_one);
        testCase.request.state.rax = 0xAABBCCDDEEFF0006ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr8_accumulator_implicit_one_high_bit",
                             CaseId::shr8_accumulator_implicit_one_high_bit,
                             differentialBytes_shr8_accumulator_implicit_one_high_bit);
        testCase.request.state.rax = 0xAABBCCDDEEFF0081ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr64_many", CaseId::shr64_many, differentialBytes_shr64_many);
        testCase.request.state.rax = 0xE000000000000200ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr64_implicit_one", CaseId::shr64_implicit_one,
                             differentialBytes_shr64_implicit_one);
        testCase.request.state.rsi = 0x8000000000000001ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr32_implicit_one", CaseId::shr32_implicit_one,
                             differentialBytes_shr32_implicit_one);
        testCase.request.state.rdx = 0xAABBCCDD80000001ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr64_cl_one", CaseId::shr64_cl_one, differentialBytes_shr64_cl_one);
        testCase.request.state.r12 = 0x8000000000000001ULL;
        testCase.request.state.rcx = 1;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("shr64_cl_many", CaseId::shr64_cl_many, differentialBytes_shr64_cl_many);
        testCase.request.state.r12 = 0xE000000000000200ULL;
        testCase.request.state.rcx = 62;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("shr64_cl_masked_zero", CaseId::shr64_cl_masked_zero,
                             differentialBytes_shr64_cl_masked_zero);
        testCase.request.state.r12 = 0xE000000000000200ULL;
        testCase.request.state.rcx = 64;
        testCase.request.state.rflags = 0xAD7;
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
        auto testCase = make("sar64_many", CaseId::sar64_many, differentialBytes_sar64_many);
        testCase.request.state.rcx = 0x8000000000000007ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("sar64_one", CaseId::sar64_one, differentialBytes_sar64_one);
        testCase.request.state.rcx = 0x8000000000000000ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("sar64_masked_zero", CaseId::sar64_masked_zero,
                             differentialBytes_sar64_masked_zero);
        testCase.request.state.rcx = 0x8000000000000007ULL;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("rol16_eight", CaseId::rol16_eight, differentialBytes_rol16_eight);
        testCase.request.state.rsi = 0x11223344556612A5ULL;
        testCase.request.state.rflags = 0xAD7;
        testCase.flagMask = carryFlag | parityFlag | auxiliaryFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("rol16_one", CaseId::rol16_one, differentialBytes_rol16_one);
        testCase.request.state.rsi = 0x1122334455668000ULL;
        testCase.request.state.rflags = 0x2;
        testCase.flagMask = arithmeticFlags;
        run(testCase);
    }
    {
        auto testCase = make("rol16_zero_effective", CaseId::rol16_zero_effective,
                             differentialBytes_rol16_zero_effective);
        testCase.request.state.rsi = 0x11223344556612A5ULL;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("not32_accumulator", CaseId::not32_accumulator,
                             differentialBytes_not32_accumulator);
        testCase.request.state.rax = 0xAABBCCDD10203040ULL;
        testCase.request.state.rflags = 0x8D7;
        run(testCase);
    }
    {
        auto testCase = make("neg64_zero", CaseId::neg64_zero, differentialBytes_neg64_zero);
        testCase.request.state.r13 = 0;
        run(testCase);
    }
    {
        auto testCase =
            make("neg64_overflow", CaseId::neg64_overflow, differentialBytes_neg64_overflow);
        testCase.request.state.r13 = std::uint64_t{1} << 63U;
        run(testCase);
    }
    {
        auto testCase = make("neg32_zero_extend", CaseId::neg32_zero_extend,
                             differentialBytes_neg32_zero_extend);
        testCase.request.state.rcx = 0xAAAAAAAA00000001ULL;
        run(testCase);
    }
    {
        auto testCase =
            make("neg32_overflow", CaseId::neg32_overflow, differentialBytes_neg32_overflow);
        testCase.request.state.rcx = 0xBBBBBBBB80000000ULL;
        run(testCase);
    }
    {
        auto testCase = make("rep_movsb_forward", CaseId::rep_movsb_forward,
                             differentialBytes_rep_movsb_forward);
        bindMemory(testCase, rosa::x86::Register::Rsi, 0x10);
        bindSecondMemory(testCase, rosa::x86::Register::Rdi, 0x40);
        testCase.request.state.rcx = 6;
        constexpr std::array<std::uint8_t, 6> value{1, 2, 3, 4, 5, 6};
        std::ranges::copy(value, testCase.request.memory.begin() + 0x10);
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = value.size();
        testCase.flagMask = arithmeticFlags | directionFlag;
        run(testCase);
    }
    {
        // Observed in libsystem_c: sbb ax, 0 propagating a borrow.
        auto testCase = make("sbb16_immediate_borrow_wraps", CaseId::sbb16_immediate_borrow_wraps,
                             differentialBytes_sbb16_immediate_borrow_wraps);
        testCase.request.state.rax = 0x1234567890AB0000ULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        // sbb r9w, 1 crossing the signed boundary, with REX.B.
        auto testCase = make("sbb16_immediate_overflow", CaseId::sbb16_immediate_overflow,
                             differentialBytes_sbb16_immediate_overflow);
        testCase.request.state.r9 = 0xFFFFFFFFFFFF8000ULL;
        testCase.request.state.rflags &= ~carryFlag;
        run(testCase);
    }
    {
        // Observed in libbz2: rol eax, 1 defines OF as MSB(result) XOR CF.
        auto testCase = make("rol32_by_one_overflow", CaseId::rol32_by_one_overflow,
                             differentialBytes_rol32_by_one_overflow);
        testCase.request.state.rax = 0xFFFFFFFF40000001ULL;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("rol64_by_one", CaseId::rol64_by_one, differentialBytes_rol64_by_one);
        testCase.request.state.r8 = 0x8000000000000001ULL;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        // Observed in liblzma under grep -X: xor dx, word [rcx+4].
        auto testCase = make("xor16_register_memory", CaseId::xor16_register_memory,
                             differentialBytes_xor16_register_memory);
        bindMemory(testCase, rosa::x86::Register::Rcx, 0x20);
        testCase.request.state.rdx = 0x1122334455668001ULL;
        constexpr std::uint16_t value = 0x0F0F;
        std::memcpy(testCase.request.memory.data() + 0x24, &value, sizeof(value));
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;
        run(testCase);
    }
    {
        // Observed in corecrypto's SHA-256 rounds: ror eax, 14.
        auto testCase =
            make("ror32_immediate", CaseId::ror32_immediate, differentialBytes_ror32_immediate);
        testCase.request.state.rax = 0xFFFFFFFF12345679ULL;
        testCase.flagMask = carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("ror32_by_one_overflow", CaseId::ror32_by_one_overflow,
                             differentialBytes_ror32_by_one_overflow);
        testCase.request.state.r9 = 0xAAAAAAAA00000001ULL;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        // A count that masks to zero: do the upper 32 bits survive?
        auto testCase = make("ror32_masked_zero_count", CaseId::ror32_masked_zero_count,
                             differentialBytes_ror32_masked_zero_count);
        testCase.request.state.rax = 0xFFFFFFFF12345679ULL;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("rol32_masked_zero_count", CaseId::rol32_masked_zero_count,
                             differentialBytes_rol32_masked_zero_count);
        testCase.request.state.rax = 0xFFFFFFFF12345679ULL;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        // corecrypto: pshufb xmm0, [rbx+0x40] with a byte-reversing mask.
        auto testCase = make("pshufb_based_memory", CaseId::pshufb_based_memory,
                             differentialBytes_pshufb_based_memory);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.xmm[0] = {.low = 0x0706050403020100ULL,
                                         .high = 0x0F0E0D0C0B0A0908ULL};
        constexpr std::array<std::uint8_t, 16> mask{3, 2, 1, 0, 7, 6, 5, 4,
                                                    0x80, 10, 9, 8, 15, 14, 13, 12};
        std::ranges::copy(mask, testCase.request.memory.begin() + 0x40);
        run(testCase);
    }
    {
        // corecrypto's block loop counter: sub qword [mem], 1 crossing zero.
        auto testCase = make("sub64_memory_immediate_borrow",
                             CaseId::sub64_memory_immediate_borrow,
                             differentialBytes_sub64_memory_immediate_borrow);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        constexpr std::uint64_t value = 0;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("sub32_memory_immediate_overflow",
                             CaseId::sub32_memory_immediate_overflow,
                             differentialBytes_sub32_memory_immediate_overflow);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        constexpr std::uint32_t value = 0x80000000U;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("std_sets_direction", CaseId::std_sets_direction,
                             differentialBytes_std_sets_direction);
        testCase.flagMask = arithmeticFlags | directionFlag;
        run(testCase);
    }
    {
        // memmove's backward path: STD, copy, then CLD restores the ABI's DF=0.
        auto testCase = make("std_rep_movsb_cld", CaseId::std_rep_movsb_cld,
                             differentialBytes_std_rep_movsb_cld);
        bindMemory(testCase, rosa::x86::Register::Rsi, 0x15);
        bindSecondMemory(testCase, rosa::x86::Register::Rdi, 0x45);
        testCase.request.state.rcx = 6;
        constexpr std::array<std::uint8_t, 6> value{7, 8, 9, 10, 11, 12};
        std::ranges::copy(value, testCase.request.memory.begin() + 0x10);
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = value.size();
        testCase.flagMask = arithmeticFlags | directionFlag;
        run(testCase);
    }
    {
        auto testCase = make("rep_movsb_backward", CaseId::rep_movsb_backward,
                             differentialBytes_rep_movsb_backward);
        bindMemory(testCase, rosa::x86::Register::Rsi, 0x15);
        bindSecondMemory(testCase, rosa::x86::Register::Rdi, 0x45);
        testCase.request.state.rcx = 6;
        testCase.request.state.rflags |= directionFlag;
        constexpr std::array<std::uint8_t, 6> value{7, 8, 9, 10, 11, 12};
        std::ranges::copy(value, testCase.request.memory.begin() + 0x10);
        testCase.memoryCompareOffset = 0x40;
        testCase.memoryCompareSize = value.size();
        testCase.flagMask = arithmeticFlags | directionFlag;
        run(testCase);
    }
    {
        auto testCase = make("rep_movsb_overlap", CaseId::rep_movsb_overlap,
                             differentialBytes_rep_movsb_overlap);
        bindMemory(testCase, rosa::x86::Register::Rsi, 0x10);
        bindSecondMemory(testCase, rosa::x86::Register::Rdi, 0x12);
        testCase.request.state.rcx = 6;
        constexpr std::array<std::uint8_t, 8> value{1, 2, 3, 4, 5, 6, 7, 8};
        std::ranges::copy(value, testCase.request.memory.begin() + 0x10);
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = value.size();
        testCase.flagMask = arithmeticFlags | directionFlag;
        run(testCase);
    }
    {
        auto testCase = make("shrd64_many", CaseId::shrd64_many, differentialBytes_shrd64_many);
        testCase.request.state.rax = 0x0123456789ABCDEFULL;
        testCase.request.state.rdx = 0xFEDCBA9876543210ULL;
        testCase.flagMask = carryFlag | parityFlag | zeroFlag | signFlag;
        run(testCase);
    }
    {
        auto testCase = make("mul64_wide", CaseId::mul64_wide, differentialBytes_mul64_wide);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.rcx = 2;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("imul64_overflow", CaseId::imul64_overflow, differentialBytes_imul64_overflow);
        testCase.request.state.rcx = INT64_MAX;
        testCase.request.state.r13 = 2;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("imul64_rip_memory_fit", CaseId::imul64_rip_memory_fit,
                             differentialBytes_imul64_rip_memory_fit);
        testCase.request.state.rsi = 7;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("imul64_rip_memory_overflow", CaseId::imul64_rip_memory_overflow,
                             differentialBytes_imul64_rip_memory_overflow);
        testCase.request.state.rsi = INT64_MAX;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("imul64_imm8_positive", CaseId::imul64_imm8_positive,
                             differentialBytes_imul64_imm8_positive);
        testCase.request.state.rcx = 6;
        testCase.request.state.rbx = UINT64_MAX;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("imul64_imm8_negative", CaseId::imul64_imm8_negative,
                             differentialBytes_imul64_imm8_negative);
        testCase.request.state.rcx = 7;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("imul64_imm8_overflow", CaseId::imul64_imm8_overflow,
                             differentialBytes_imul64_imm8_overflow);
        testCase.request.state.rcx = INT64_MAX;
        testCase.flagMask = carryFlag | overflowFlag;
        run(testCase);
    }
    {
        auto testCase = make("bt32_register_set", CaseId::bt32_register_set,
                             differentialBytes_bt32_register_set);
        testCase.request.state.rsi = 0xFFFFFFFF00000200ULL;
        testCase.flagMask = carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("bt32_register_clear", CaseId::bt32_register_clear,
                             differentialBytes_bt32_register_clear);
        testCase.request.state.rsi = 0xFFFFFFFF00000000ULL;
        testCase.flagMask = carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("bt32_register_masked_index", CaseId::bt32_register_masked_index,
                             differentialBytes_bt32_register_masked_index);
        testCase.request.state.rsi = 0xFFFFFFFF00000200ULL;
        testCase.flagMask = carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("bt32_register_index_set", CaseId::bt32_register_index_set,
                             differentialBytes_bt32_register_index_set);
        testCase.request.state.rcx = 0xFFFFFFFF00000442ULL;
        testCase.request.state.rax = 1;
        testCase.flagMask = carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("bt32_register_index_clear", CaseId::bt32_register_index_clear,
                             differentialBytes_bt32_register_index_clear);
        testCase.request.state.rcx = 0xFFFFFFFF00000442ULL;
        testCase.request.state.rax = 2;
        testCase.flagMask = carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("bt32_register_index_masked", CaseId::bt32_register_index_masked,
                             differentialBytes_bt32_register_index_masked);
        testCase.request.state.rcx = 0xFFFFFFFF00000442ULL;
        testCase.request.state.rax = 33;
        testCase.flagMask = carryFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("bsf64_nonzero", CaseId::bsf64_nonzero, differentialBytes_bsf64_nonzero);
        testCase.request.state.rdx = UINT64_MAX;
        testCase.request.state.rcx = std::uint64_t{1} << 40U;
        testCase.flagMask = zeroFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("bsf32_extended", CaseId::bsf32_extended, differentialBytes_bsf32_extended);
        testCase.request.state.r12 = UINT64_MAX;
        testCase.request.state.r15 = 0x100;
        testCase.flagMask = zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("bsf32_extended_zero", CaseId::bsf32_extended_zero,
                             differentialBytes_bsf32_extended_zero);
        testCase.request.state.r12 = 0x1122334455667788ULL;
        testCase.request.state.r15 = 0;
        testCase.gprMask = static_cast<std::uint16_t>(
            testCase.gprMask & ~(1U << static_cast<unsigned>(rosa::x86::Register::R12)));
        testCase.flagMask = zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("bswap32", CaseId::bswap32, differentialBytes_bswap32);
        testCase.request.state.rsi = 0xAABBCCDD12345678ULL;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("bswap32_zero", CaseId::bswap32_zero, differentialBytes_bswap32_zero);
        testCase.request.state.rsi = 0xAABBCCDD00000000ULL;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("bswap64", CaseId::bswap64, differentialBytes_bswap64);
        testCase.request.state.rsi = 0x0123456789ABCDEFULL;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase = make("bswap64_zero", CaseId::bswap64_zero, differentialBytes_bswap64_zero);
        testCase.request.state.rsi = 0;
        testCase.request.state.rflags = 0xAD7;
        run(testCase);
    }
    {
        auto testCase =
            make("bsr64_nonzero", CaseId::bsr64_nonzero, differentialBytes_bsr64_nonzero);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.rdi = (std::uint64_t{1} << 40U) | 1U;
        testCase.flagMask = zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("bsr64_zero", CaseId::bsr64_zero, differentialBytes_bsr64_zero);
        testCase.request.state.rax = 0x7F;
        testCase.request.state.rdi = 0;
        testCase.gprMask = static_cast<std::uint16_t>(
            testCase.gprMask & ~(1U << static_cast<unsigned>(rosa::x86::Register::Rax)));
        testCase.flagMask = zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("movsx8_register_positive", CaseId::movsx8_register_positive,
                             differentialBytes_movsx8_register_positive);
        testCase.request.state.rcx = UINT64_MAX;
        testCase.request.state.rsi = 0xAAAAAAAAAAAAAA2FULL;
        testCase.flagMask = arithmeticFlags | directionFlag;
        run(testCase);
    }
    {
        auto testCase = make("movsx8_register_negative", CaseId::movsx8_register_negative,
                             differentialBytes_movsx8_register_negative);
        testCase.request.state.rcx = UINT64_MAX;
        testCase.request.state.rsi = 0xAAAAAAAAAAAAAA80ULL;
        testCase.flagMask = arithmeticFlags | directionFlag;
        run(testCase);
    }
    {
        auto testCase = make("movsx8_memory_positive", CaseId::movsx8_memory_positive,
                             differentialBytes_movsx8_memory_positive);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rdx = UINT64_MAX;
        testCase.request.memory[0] = 0x2F;
        testCase.memoryCompareSize = 1;
        testCase.flagMask = arithmeticFlags | directionFlag;
        run(testCase);
    }
    {
        auto testCase = make("movsx8_memory_negative", CaseId::movsx8_memory_negative,
                             differentialBytes_movsx8_memory_negative);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rdx = UINT64_MAX;
        testCase.request.memory[0] = 0x80;
        testCase.memoryCompareSize = 1;
        testCase.flagMask = arithmeticFlags | directionFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("movzx8_register", CaseId::movzx8_register, differentialBytes_movzx8_register);
        testCase.request.state.rcx = 0xAABBCCDDEEFF00A5ULL;
        testCase.request.state.r13 = UINT64_MAX;
        run(testCase);
    }
    {
        auto testCase =
            make("movzx8_memory", CaseId::movzx8_memory, differentialBytes_movzx8_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.rcx = UINT64_MAX;
        testCase.request.memory[0x2F] = 0xA5;
        testCase.memoryCompareOffset = 0x2F;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("movzx8_memory64_sib", CaseId::movzx8_memory64_sib,
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
        auto testCase =
            make("movzx16_register", CaseId::movzx16_register, differentialBytes_movzx16_register);
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
        auto testCase = make("movsxd_register_negative", CaseId::movsxd_register_negative,
                             differentialBytes_movsxd_register_negative);
        testCase.request.state.r15 = 0xAABBCCDD80000001ULL;
        testCase.request.state.rax = 0x1122334455667788ULL;
        run(testCase);
    }
    {
        auto testCase = make("movsxd_register_positive", CaseId::movsxd_register_positive,
                             differentialBytes_movsxd_register_positive);
        testCase.request.state.r15 = 0xAABBCCDD7FFFFFFFULL;
        testCase.request.state.rax = UINT64_MAX;
        run(testCase);
    }
    {
        auto testCase = make("movsxd_register_alias", CaseId::movsxd_register_alias,
                             differentialBytes_movsxd_register_alias);
        testCase.request.state.rax = 0xAABBCCDD80000001ULL;
        run(testCase);
    }
    {
        auto testCase =
            make("cdqe_negative", CaseId::cdqe_negative, differentialBytes_cdqe_negative);
        testCase.request.state.rax = 0xAAAAAAAA80000001ULL;
        run(testCase);
    }
    {
        auto testCase = make("lea_scaled", CaseId::lea_scaled, differentialBytes_lea_scaled);
        testCase.request.state.rax = 0x1000;
        testCase.request.state.r13 = 0x234;
        run(testCase);
    }
    {
        auto testCase =
            make("sete_low_byte", CaseId::sete_low_byte, differentialBytes_sete_low_byte);
        testCase.request.state.rax = 0x1122334455667788ULL;
        testCase.request.state.rflags |= zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("setb_low_byte_taken", CaseId::setb_low_byte_taken,
                             differentialBytes_setb_low_byte_taken);
        testCase.request.state.rbx = 0x1122334455667788ULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("setb_low_byte_not_taken", CaseId::setb_low_byte_not_taken,
                             differentialBytes_setb_low_byte_not_taken);
        testCase.request.state.rbx = 0xFFEEDDCCBBAA9988ULL;
        testCase.request.state.rflags &= ~carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("setg_extended_taken", CaseId::setg_extended_taken,
                             differentialBytes_setg_extended_taken);
        testCase.request.state.r14 = 0x1122334455667788ULL;
        testCase.request.state.rflags = 0x882;
        run(testCase);
    }
    {
        auto testCase = make("setg_extended_not_taken", CaseId::setg_extended_not_taken,
                             differentialBytes_setg_extended_not_taken);
        testCase.request.state.r14 = 0x1122334455667788ULL;
        testCase.request.state.rflags = 0x802;
        run(testCase);
    }
    {
        auto testCase = make("setae8_memory_taken", CaseId::setae8_memory_taken,
                             differentialBytes_setae8_memory_taken);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.memory[0xCE] = 0xA5;
        testCase.request.state.rflags &= ~carryFlag;
        testCase.memoryCompareOffset = 0xCE;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("setae8_memory_not_taken", CaseId::setae8_memory_not_taken,
                             differentialBytes_setae8_memory_not_taken);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.memory[0xCE] = 0xA5;
        testCase.request.state.rflags |= carryFlag;
        testCase.memoryCompareOffset = 0xCE;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("setne8_memory_taken", CaseId::setne8_memory_taken,
                             differentialBytes_setne8_memory_taken);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.memory[0xCF] = 0xA5;
        testCase.request.state.rflags &= ~zeroFlag;
        testCase.memoryCompareOffset = 0xCF;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase = make("setne8_memory_not_taken", CaseId::setne8_memory_not_taken,
                             differentialBytes_setne8_memory_not_taken);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.memory[0xCF] = 0xA5;
        testCase.request.state.rflags |= zeroFlag;
        testCase.memoryCompareOffset = 0xCF;
        testCase.memoryCompareSize = 1;
        run(testCase);
    }
    {
        auto testCase =
            make("cmovb64_taken", CaseId::cmovb64_taken, differentialBytes_cmovb64_taken);
        testCase.request.state.rax = 0x1122334455667788ULL;
        testCase.request.state.r13 = UINT64_MAX;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("cmovb32_taken", CaseId::cmovb32_taken, differentialBytes_cmovb32_taken);
        testCase.request.state.rax = 0xAABBCCDD11223344ULL;
        testCase.request.state.rcx = UINT64_MAX;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("cmovb32_not_taken", CaseId::cmovb32_not_taken,
                             differentialBytes_cmovb32_not_taken);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.rcx = 0xAABBCCDD55667788ULL;
        testCase.request.state.rflags &= ~carryFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("bt32_memory_set", CaseId::bt32_memory_set, differentialBytes_bt32_memory_set);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        const std::uint32_t value = 1U << 21U;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.request.state.rflags &= ~carryFlag;
        testCase.flagMask = carryFlag;
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("bt32_memory_clear", CaseId::bt32_memory_clear,
                             differentialBytes_bt32_memory_clear);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        const std::uint32_t value = 0;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.request.state.rflags |= carryFlag;
        testCase.flagMask = carryFlag;
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("bt32_memory_masked_immediate", CaseId::bt32_memory_masked_immediate,
                             differentialBytes_bt32_memory_masked_immediate);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        const std::uint32_t first = 0;
        const std::uint32_t second = 1U << 5U;
        std::memcpy(testCase.request.memory.data() + 0x10, &first, sizeof(first));
        std::memcpy(testCase.request.memory.data() + 0x14, &second, sizeof(second));
        testCase.request.state.rflags &= ~carryFlag;
        testCase.flagMask = carryFlag;
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(first) + sizeof(second);
        run(testCase);
    }
    {
        auto testCase =
            make("cmovae64_taken", CaseId::cmovae64_taken, differentialBytes_cmovae64_taken);
        testCase.request.state.rsi = 0x0123456789ABCDEFULL;
        testCase.request.state.r15 = UINT64_MAX;
        testCase.request.state.rflags &= ~carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("cmovae64_not_taken", CaseId::cmovae64_not_taken,
                             differentialBytes_cmovae64_not_taken);
        testCase.request.state.rsi = UINT64_MAX;
        testCase.request.state.r15 = 0xAABBCCDDEEFF0011ULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("cmovae32_taken", CaseId::cmovae32_taken, differentialBytes_cmovae32_taken);
        testCase.request.state.rcx = 0xAABBCCDD01234567ULL;
        testCase.request.state.rsi = UINT64_MAX;
        testCase.request.state.rflags &= ~carryFlag;
        run(testCase);
    }
    {
        auto testCase = make("cmovae32_not_taken", CaseId::cmovae32_not_taken,
                             differentialBytes_cmovae32_not_taken);
        testCase.request.state.rcx = UINT64_MAX;
        testCase.request.state.rsi = 0xAABBCCDD01234567ULL;
        testCase.request.state.rflags |= carryFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("cmove64_taken", CaseId::cmove64_taken, differentialBytes_cmove64_taken);
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
        auto testCase = make("cmovne64_extended_taken", CaseId::cmovne64_extended_taken,
                             differentialBytes_cmovne64_extended_taken);
        testCase.request.state.rcx = 0x1122334455667788ULL;
        testCase.request.state.r12 = UINT64_MAX;
        testCase.request.state.rflags &= ~zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("cmovne64_extended_not_taken", CaseId::cmovne64_extended_not_taken,
                             differentialBytes_cmovne64_extended_not_taken);
        testCase.request.state.rcx = UINT64_MAX;
        testCase.request.state.r12 = 0xAABBCCDDEEFF0011ULL;
        testCase.request.state.rflags |= zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("amfi_input_flags_unrestricted", CaseId::amfi_input_flags_unrestricted,
                             differentialBytes_amfi_input_flags_unrestricted);
        testCase.request.state.rdi = 0x00000001000002A8ULL;
        testCase.request.state.rsi = 0;
        testCase.request.state.rdx = 0;
        run(testCase);
    }
    {
        auto testCase = make("cmove32_extended_taken", CaseId::cmove32_extended_taken,
                             differentialBytes_cmove32_extended_taken);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.r8 = 0xAABBCCDD01234567ULL;
        testCase.request.state.rflags |= zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("cmove32_extended_not_taken", CaseId::cmove32_extended_not_taken,
                             differentialBytes_cmove32_extended_not_taken);
        testCase.request.state.rax = 0xAABBCCDD55667788ULL;
        testCase.request.state.r8 = UINT64_MAX;
        testCase.request.state.rflags &= ~zeroFlag;
        run(testCase);
    }
    {
        auto testCase =
            make("cmova64_taken", CaseId::cmova64_taken, differentialBytes_cmova64_taken);
        testCase.request.state.rax = 0x0123456789ABCDEFULL;
        testCase.request.state.rdx = UINT64_MAX;
        testCase.request.state.rflags &= ~(carryFlag | zeroFlag);
        run(testCase);
    }
    {
        auto testCase = make("cmova64_carry_not_taken", CaseId::cmova64_carry_not_taken,
                             differentialBytes_cmova64_carry_not_taken);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.rdx = 0xAABBCCDDEEFF0011ULL;
        testCase.request.state.rflags = (testCase.request.state.rflags | carryFlag) & ~zeroFlag;
        run(testCase);
    }
    {
        auto testCase = make("cmova64_zero_not_taken", CaseId::cmova64_zero_not_taken,
                             differentialBytes_cmova64_zero_not_taken);
        testCase.request.state.rax = UINT64_MAX;
        testCase.request.state.rdx = 0xAABBCCDDEEFF0011ULL;
        testCase.request.state.rflags = (testCase.request.state.rflags | zeroFlag) & ~carryFlag;
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
        auto testCase = make("branch_above_equal_taken", CaseId::branch_above_equal_taken,
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
        auto testCase = make("branch_below_equal_taken", CaseId::branch_below_equal_taken,
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
        auto testCase = make("branch_not_sign_taken", CaseId::branch_not_sign_taken,
                             differentialBytes_branch_not_sign_taken);
        testCase.request.state.rflags = 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_not_sign_not_taken", CaseId::branch_not_sign_not_taken,
                             differentialBytes_branch_not_sign_not_taken);
        testCase.request.state.rflags = signFlag | 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_less_taken", CaseId::branch_less_taken,
                             differentialBytes_branch_less_taken);
        testCase.request.state.rflags = signFlag | 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_less_not_taken", CaseId::branch_less_not_taken,
                             differentialBytes_branch_less_not_taken);
        testCase.request.state.rflags = 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_greater_equal_taken", CaseId::branch_greater_equal_taken,
                             differentialBytes_branch_greater_equal_taken);
        testCase.request.state.rflags = 0x2;
        run(testCase);
    }
    {
        auto testCase =
            make("branch_greater_equal_not_taken", CaseId::branch_greater_equal_not_taken,
                 differentialBytes_branch_greater_equal_not_taken);
        testCase.request.state.rflags = signFlag | 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_less_equal_taken", CaseId::branch_less_equal_taken,
                             differentialBytes_branch_less_equal_taken);
        testCase.request.state.rflags = zeroFlag | 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_greater_taken", CaseId::branch_greater_taken,
                             differentialBytes_branch_greater_taken);
        testCase.request.state.rflags = 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_greater_not_taken", CaseId::branch_greater_not_taken,
                             differentialBytes_branch_greater_not_taken);
        testCase.request.state.rflags = zeroFlag | 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_greater_long_taken", CaseId::branch_greater_long_taken,
                             differentialBytes_branch_greater_long_taken);
        testCase.request.state.rflags = 0x2;
        run(testCase);
    }
    {
        auto testCase = make("branch_greater_long_not_taken", CaseId::branch_greater_long_not_taken,
                             differentialBytes_branch_greater_long_not_taken);
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
        auto testCase = make("indirect_call_register", CaseId::indirect_call_register,
                             differentialBytes_indirect_call_register);
        testCase.request.state.rbx = 41;
        testCase.request.codePointerRegister = static_cast<std::uint8_t>(rosa::x86::Register::Rax);
        testCase.request.codePointerTargetOffset = 4;
        testCase.gprMask &=
            static_cast<std::uint16_t>(~(1U << static_cast<unsigned>(rosa::x86::Register::Rax)));
        run(testCase);
    }
    {
        auto testCase =
            make("push_sign_extend", CaseId::push_sign_extend, differentialBytes_push_sign_extend);
        testCase.request.state.rax = 0;
        testCase.stackCompareOffset = rosa::differential::stackSize - 16;
        testCase.stackCompareSize = 8;
        run(testCase);
    }
    {
        auto testCase = make("push_imm32_positive", CaseId::push_imm32_positive,
                             differentialBytes_push_imm32_positive);
        testCase.request.state.rax = 0;
        testCase.stackCompareOffset = rosa::differential::stackSize - 16;
        testCase.stackCompareSize = 8;
        run(testCase);
    }
    {
        auto testCase = make("push_imm32_negative", CaseId::push_imm32_negative,
                             differentialBytes_push_imm32_negative);
        testCase.request.state.rax = 0;
        testCase.stackCompareOffset = rosa::differential::stackSize - 16;
        testCase.stackCompareSize = 8;
        run(testCase);
    }
    {
        auto testCase =
            make("xorps_register", CaseId::xorps_register, differentialBytes_xorps_register);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.request.state.xmm[1] = {.low = 0x1111111111111111ULL,
                                         .high = 0x2222222222222222ULL};
        run(testCase);
    }
    {
        // Observed in dyld's memmove: register MOVSS keeps the upper dwords.
        auto testCase = make("movss_register_load_form", CaseId::movss_register_load_form,
                             differentialBytes_movss_register_load_form);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.request.state.xmm[1] = {.low = 0x1111111122222222ULL,
                                         .high = 0x3333333344444444ULL};
        run(testCase);
    }
    {
        // movss xmm8, xmm9 through the 0F 11 encoding with REX.R and REX.B.
        auto testCase = make("movss_register_store_form", CaseId::movss_register_store_form,
                             differentialBytes_movss_register_store_form);
        testCase.request.state.xmm[8] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.request.state.xmm[9] = {.low = 0x1111111122222222ULL,
                                         .high = 0x3333333344444444ULL};
        run(testCase);
    }
    {
        auto testCase =
            make("pxor_register", CaseId::pxor_register, differentialBytes_pxor_register);
        testCase.request.state.xmm[0] = {.low = UINT64_MAX, .high = 0x0123456789ABCDEFULL};
        run(testCase);
    }
    {
        auto testCase = make("pxor_memory_aligned", CaseId::pxor_memory_aligned,
                             differentialBytes_pxor_memory_aligned);
        bindMemory(testCase, rosa::x86::Register::Rbp, 0xA0);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        constexpr std::array<std::uint8_t, 16> value{0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                                     0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
                                                     0xCC, 0xDD, 0xEE, 0xFF};
        std::ranges::copy(value, testCase.request.memory.begin() + 0x10);
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = value.size();
        run(testCase);
    }
    {
        auto testCase = make("pxor_memory_unaligned", CaseId::pxor_memory_unaligned,
                             differentialBytes_pxor_memory_unaligned);
        bindMemory(testCase, rosa::x86::Register::Rbp, 0xA1);
        testCase.request.state.xmm[0] = {.low = UINT64_MAX, .high = 0x0123456789ABCDEFULL};
        constexpr std::array<std::uint8_t, 16> value{0x10, 0x21, 0x32, 0x43, 0x54, 0x65,
                                                     0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB,
                                                     0xDC, 0xED, 0xFE, 0x0F};
        std::ranges::copy(value, testCase.request.memory.begin() + 0x11);
        testCase.memoryCompareOffset = 0x11;
        testCase.memoryCompareSize = value.size();
        run(testCase);
    }
    {
        auto testCase = make("pand_memory", CaseId::pand_memory, differentialBytes_pand_memory);
        bindMemory(testCase, rosa::x86::Register::Rdi, 3);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        const std::array<std::uint64_t, 2> value{0xFF00FF00FF00FF00ULL, 0x0F0F0F0F0F0F0F0FULL};
        std::memcpy(testCase.request.memory.data() + 3, value.data(), sizeof(value));
        testCase.memoryCompareOffset = 3;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase =
            make("pand_memory_zero", CaseId::pand_memory_zero, differentialBytes_pand_memory_zero);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.xmm[0] = {.low = UINT64_MAX, .high = UINT64_MAX};
        testCase.memoryCompareSize = 16;
        run(testCase);
    }
    {
        auto testCase = make("ptest_xmm_self_zero", CaseId::ptest_xmm_self_zero,
                             differentialBytes_ptest_xmm_self_zero);
        testCase.request.state.rflags = arithmeticFlags | directionFlag | 0x2;
        // Apple Rosetta currently leaves PTEST's defined arithmetic flags
        // unchanged. Keep it as an operand/non-mutation oracle while the
        // generated-execution test below checks architectural flag semantics.
        testCase.flagMask = 0;
        run(testCase);
    }
    {
        auto testCase = make("ptest_xmm_self_nonzero", CaseId::ptest_xmm_self_nonzero,
                             differentialBytes_ptest_xmm_self_nonzero);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.request.state.rflags = arithmeticFlags | directionFlag | 0x2;
        testCase.flagMask = 0;
        run(testCase);
    }
    {
        auto testCase = make("ptest_xmm_distinct", CaseId::ptest_xmm_distinct,
                             differentialBytes_ptest_xmm_distinct);
        testCase.request.state.xmm[0] = {.low = 0x0FULL, .high = 0};
        testCase.request.state.xmm[1] = {.low = 0xF0ULL, .high = 0};
        testCase.request.state.rflags = arithmeticFlags | directionFlag | 0x2;
        testCase.flagMask = 0;
        run(testCase);
    }
    {
        auto testCase = make("pcmpeqd_self", CaseId::pcmpeqd_self, differentialBytes_pcmpeqd_self);
        testCase.request.state.xmm[0] = {.low = 0x2222222211111111ULL,
                                         .high = 0x4444444433333333ULL};
        run(testCase);
    }
    {
        auto testCase =
            make("pcmpeqd_distinct", CaseId::pcmpeqd_distinct, differentialBytes_pcmpeqd_distinct);
        testCase.request.state.xmm[0] = {.low = 0x2222222211111111ULL,
                                         .high = 0x4444444433333333ULL};
        testCase.request.state.xmm[1] = {.low = 0x9999999911111111ULL,
                                         .high = 0x8888888833333333ULL};
        run(testCase);
    }
    {
        auto testCase = make("pmovmskb", CaseId::pmovmskb, differentialBytes_pmovmskb);
        testCase.request.state.rsi = UINT64_MAX;
        testCase.request.state.xmm[0] = {.low = 0x8000000000000080ULL,
                                         .high = 0x0000000000008000ULL};
        run(testCase);
    }
    {
        auto testCase = make("pshufd", CaseId::pshufd, differentialBytes_pshufd);
        testCase.request.state.xmm[0] = {.low = 0x2222222211111111ULL,
                                         .high = 0x4444444433333333ULL};
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
        auto testCase = make("mov8_extended_immediate", CaseId::mov8_extended_immediate,
                             differentialBytes_mov8_extended_immediate);
        testCase.request.state.r14 = 0x11223344556677A5ULL;
        run(testCase);
    }
    {
        auto testCase = make("mov8_immediate_memory", CaseId::mov8_immediate_memory,
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
        auto testCase = make("mov8_immediate_scaled_memory", CaseId::mov8_immediate_scaled_memory,
                             differentialBytes_mov8_immediate_scaled_memory);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        testCase.request.state.rdx = 0x20;
        testCase.request.memory[0x77] = 0x11;
        testCase.request.memory[0x78] = 0xA5;
        testCase.request.memory[0x79] = 0x22;
        testCase.memoryCompareOffset = 0x77;
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
        auto testCase =
            make("mov8_rip_memory", CaseId::mov8_rip_memory, differentialBytes_mov8_rip_memory);
        testCase.request.state.rax = 0x1122334455667788ULL;
        run(testCase);
    }
    {
        auto testCase = make("mov8_register_memory", CaseId::mov8_register_memory,
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
        auto testCase = make("mov8_extended_scaled_store", CaseId::mov8_extended_scaled_store,
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
        auto testCase = make("mov64_scaled_store", CaseId::mov64_scaled_store,
                             differentialBytes_mov64_scaled_store);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rdx = 0x20;
        testCase.request.state.rsi = 0x0123456789ABCDEFULL;
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = sizeof(std::uint64_t);
        run(testCase);
    }
    {
        auto testCase = make("mov32_immediate_memory", CaseId::mov32_immediate_memory,
                             differentialBytes_mov32_immediate_memory);
        bindMemory(testCase, rosa::x86::Register::Rbp, 0x80);
        const std::array sentinel{std::uint8_t{0x88}, std::uint8_t{0x77}, std::uint8_t{0x66},
                                  std::uint8_t{0x55}, std::uint8_t{0x44}, std::uint8_t{0x33},
                                  std::uint8_t{0x22}, std::uint8_t{0x11}};
        std::ranges::copy(sentinel, testCase.request.memory.begin() + 0x1F);
        testCase.memoryCompareOffset = 0x1F;
        testCase.memoryCompareSize = sentinel.size();
        run(testCase);
    }
    {
        auto testCase = make("mov16_extended_base_store", CaseId::mov16_extended_base_store,
                             differentialBytes_mov16_extended_base_store);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.rcx = 0xAABBCCDDEEFFBEEFULL;
        testCase.memoryCompareOffset = 0x48;
        testCase.memoryCompareSize = sizeof(std::uint16_t);
        run(testCase);
    }
    {
        auto testCase = make("mov16_immediate_extended_base", CaseId::mov16_immediate_extended_base,
                             differentialBytes_mov16_immediate_extended_base);
        bindMemory(testCase, rosa::x86::Register::R15, 0);
        const std::array sentinel{std::uint8_t{0x88}, std::uint8_t{0x77}, std::uint8_t{0x66},
                                  std::uint8_t{0x55}, std::uint8_t{0x44}, std::uint8_t{0x33},
                                  std::uint8_t{0x22}, std::uint8_t{0x11}};
        std::ranges::copy(sentinel, testCase.request.memory.begin() + 0x50);
        testCase.memoryCompareOffset = 0x50;
        testCase.memoryCompareSize = sentinel.size();
        run(testCase);
    }
    {
        auto testCase = make("mov64_immediate_memory", CaseId::mov64_immediate_memory,
                             differentialBytes_mov64_immediate_memory);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0);
        const std::array sentinel{std::uint8_t{0x88}, std::uint8_t{0x77}, std::uint8_t{0x66},
                                  std::uint8_t{0x55}, std::uint8_t{0x44}, std::uint8_t{0x33},
                                  std::uint8_t{0x22}, std::uint8_t{0x11}};
        std::ranges::copy(sentinel, testCase.request.memory.begin() + 0x18);
        testCase.memoryCompareOffset = 0x18;
        testCase.memoryCompareSize = sentinel.size();
        run(testCase);
    }
    {
        auto testCase = make("mov64_immediate_stack", CaseId::mov64_immediate_stack,
                             differentialBytes_mov64_immediate_stack);
        testCase.stackCompareOffset = rosa::differential::stackSize - 16;
        testCase.stackCompareSize = sizeof(std::uint64_t);
        run(testCase);
    }
    {
        auto testCase = make("add64_memory", CaseId::add64_memory, differentialBytes_add64_memory);
        bindMemory(testCase, rosa::x86::Register::Rsi, 0);
        testCase.request.state.rax = UINT64_MAX - 2;
        const std::uint64_t value = 7;
        std::memcpy(testCase.request.memory.data() + 16, &value, sizeof(value));
        testCase.memoryCompareOffset = 16;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("inc16_memory", CaseId::inc16_memory, differentialBytes_inc16_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.rflags |= carryFlag;
        const std::uint16_t value = 0x7FFF;
        std::memcpy(testCase.request.memory.data() + 24, &value, sizeof(value));
        testCase.memoryCompareOffset = 24;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("inc64_memory", CaseId::inc64_memory, differentialBytes_inc64_memory);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.rflags |= carryFlag;
        const std::uint64_t value = INT64_MAX;
        std::memcpy(testCase.request.memory.data() + 24, &value, sizeof(value));
        testCase.memoryCompareOffset = 24;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("xor64_memory", CaseId::xor64_memory, differentialBytes_xor64_memory);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        testCase.request.state.rcx = 0x44454B4E494C5F5FULL;
        const std::uint64_t value = 0x44454B4E494C5F5FULL;
        std::memcpy(testCase.request.memory.data(), &value, sizeof(value));
        testCase.flagMask = logicDefinedFlags;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("xor64_indexed_disp8", CaseId::xor64_indexed_disp8,
                             differentialBytes_xor64_indexed_disp8);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rax = 0x20;
        testCase.request.state.rsi = 0x0123456789ABCDEFULL;
        const std::uint64_t value = 0xFEDCBA9876543210ULL;
        std::memcpy(testCase.request.memory.data() + 0x26, &value, sizeof(value));
        testCase.flagMask = logicDefinedFlags;
        testCase.memoryCompareOffset = 0x26;
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
        auto testCase = make("movaps_load", CaseId::movaps_load, differentialBytes_movaps_load);
        bindMemory(testCase, rosa::x86::Register::Rbp, 32);
        const std::array<std::uint64_t, 2> value{0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
        std::memcpy(testCase.request.memory.data(), value.data(), sizeof(value));
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase =
            make("movaps_rip_load", CaseId::movaps_rip_load, differentialBytes_movaps_rip_load);
        testCase.request.state.xmm[0] = {.low = 0x1111111111111111ULL,
                                         .high = 0x2222222222222222ULL};
        run(testCase);
    }
    {
        auto testCase = make("movaps_store", CaseId::movaps_store, differentialBytes_movaps_store);
        bindMemory(testCase, rosa::x86::Register::Rbp, 32);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.memoryCompareSize = 16;
        run(testCase);
    }
    {
        auto testCase = make("movaps_extended_base_store", CaseId::movaps_extended_base_store,
                             differentialBytes_movaps_extended_base_store);
        bindMemory(testCase, rosa::x86::Register::R15, 0);
        testCase.request.state.xmm[0] = {.low = 0x8877665544332211ULL,
                                         .high = 0x1020304050607080ULL};
        testCase.memoryCompareSize = 16;
        run(testCase);
    }
    {
        auto testCase = make("movups_scaled_store", CaseId::movups_scaled_store,
                             differentialBytes_movups_scaled_store);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rdx = 0x20;
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = 16;
        run(testCase);
    }
    {
        auto testCase = make("movups_extended_base_store", CaseId::movups_extended_base_store,
                             differentialBytes_movups_extended_base_store);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.xmm[0] = {.low = 0x8877665544332211ULL,
                                         .high = 0x1020304050607080ULL};
        testCase.memoryCompareOffset = 0x50;
        testCase.memoryCompareSize = 16;
        run(testCase);
    }
    {
        auto testCase = make("movups_load", CaseId::movups_load, differentialBytes_movups_load);
        bindMemory(testCase, rosa::x86::Register::R15, 3);
        const std::array<std::uint64_t, 2> value{0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
        std::memcpy(testCase.request.memory.data() + 27, value.data(), sizeof(value));
        testCase.memoryCompareOffset = 27;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movups_indexed_load", CaseId::movups_indexed_load,
                             differentialBytes_movups_indexed_load);
        bindMemory(testCase, rosa::x86::Register::R12, 0);
        testCase.request.state.r13 = 0x20;
        const std::array<std::uint64_t, 2> value{0x8877665544332211ULL, 0x0123456789ABCDEFULL};
        std::memcpy(testCase.request.memory.data() + 0x20, value.data(), sizeof(value));
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase =
            make("pcmpeqb_memory", CaseId::pcmpeqb_memory, differentialBytes_pcmpeqb_memory);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        constexpr std::array<std::uint8_t, 16> value{1, 0, 2, 0,  3,  4,  5,  6,
                                                     7, 8, 9, 10, 11, 12, 13, 14};
        std::ranges::copy(value, testCase.request.memory.begin());
        testCase.memoryCompareSize = value.size();
        run(testCase);
    }
    {
        auto testCase =
            make("pcmpeqb_register", CaseId::pcmpeqb_register, differentialBytes_pcmpeqb_register);
        testCase.request.state.xmm[0] = {.low = 0x0102030405060708ULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.request.state.xmm[1] = {.low = 0x0102030405060709ULL,
                                         .high = 0xFEDCBA9876543210ULL};
        run(testCase);
    }
    {
        auto testCase =
            make("pandn_register", CaseId::pandn_register, differentialBytes_pandn_register);
        testCase.request.state.xmm[0] = {.low = 0x00FF00FF00FF00FFULL,
                                         .high = 0xFFFF0000FFFF0000ULL};
        testCase.request.state.xmm[1] = {.low = 0x0F0F0F0F0F0F0F0FULL,
                                         .high = 0xAAAAAAAA55555555ULL};
        run(testCase);
    }
    const auto runPalignr = [&](std::string_view name, CaseId id,
                                std::span<const std::uint8_t> bytes) {
        auto testCase = make(name, id, bytes);
        testCase.request.state.xmm[3] = {.low = 0x0706050403020100ULL,
                                         .high = 0x0F0E0D0C0B0A0908ULL};
        testCase.request.state.xmm[4] = {.low = 0x1716151413121110ULL,
                                         .high = 0x1F1E1D1C1B1A1918ULL};
        run(testCase);
    };
    runPalignr("palignr_count_0", CaseId::palignr_count_0, differentialBytes_palignr_count_0);
    runPalignr("palignr_count_6", CaseId::palignr_count_6, differentialBytes_palignr_count_6);
    runPalignr("palignr_count_16", CaseId::palignr_count_16, differentialBytes_palignr_count_16);
    runPalignr("palignr_count_31", CaseId::palignr_count_31, differentialBytes_palignr_count_31);
    runPalignr("palignr_count_32", CaseId::palignr_count_32, differentialBytes_palignr_count_32);
    const auto runPinsrd = [&](std::string_view name, CaseId id,
                               std::span<const std::uint8_t> code) {
        auto testCase = make(name, id, code);
        bindMemory(testCase, rosa::x86::Register::Rbx, 0x20);
        constexpr std::uint32_t value = 0xAABBCCDDU;
        std::memcpy(testCase.request.memory.data() + 0x10, &value, sizeof(value));
        testCase.request.state.xmm[1] = {.low = 0x2222222211111111ULL,
                                         .high = 0x4444444433333333ULL};
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    };
    runPinsrd("pinsrd_lane0", CaseId::pinsrd_lane0, differentialBytes_pinsrd_lane0);
    runPinsrd("pinsrd_lane1", CaseId::pinsrd_lane1, differentialBytes_pinsrd_lane1);
    runPinsrd("pinsrd_lane2", CaseId::pinsrd_lane2, differentialBytes_pinsrd_lane2);
    runPinsrd("pinsrd_lane3", CaseId::pinsrd_lane3, differentialBytes_pinsrd_lane3);
    const auto runPinsrb = [&](std::string_view name, CaseId id, std::span<const std::uint8_t> code,
                               std::uint64_t source) {
        auto testCase = make(name, id, code);
        testCase.request.state.rcx = source;
        testCase.request.state.xmm[0] = {.low = 0x0706050403020100ULL,
                                         .high = 0x0F0E0D0C0B0A0908ULL};
        run(testCase);
    };
    runPinsrb("pinsrb_lane1", CaseId::pinsrb_lane1, differentialBytes_pinsrb_lane1,
              0xAABBCCDDEEFF00A5ULL);
    runPinsrb("pinsrb_lane15", CaseId::pinsrb_lane15, differentialBytes_pinsrb_lane15,
              0x1122334455667780ULL);
    runPinsrb("pinsrb_lane_mask", CaseId::pinsrb_lane_mask, differentialBytes_pinsrb_lane_mask,
              0xFFEEDDCCBBAA995AULL);
    {
        auto testCase =
            make("pinsrb_extended", CaseId::pinsrb_extended, differentialBytes_pinsrb_extended);
        testCase.request.state.r8 = 0xDEADBEEFCAFEBABEULL;
        testCase.request.state.xmm[13] = {.low = 0x0706050403020100ULL,
                                          .high = 0x0F0E0D0C0B0A0908ULL};
        run(testCase);
    }
    const auto runPblendw = [&](std::string_view name, CaseId id,
                                std::span<const std::uint8_t> code) {
        auto testCase = make(name, id, code);
        testCase.request.state.xmm[0] = {.low = 0x4444333322221111ULL,
                                         .high = 0x8888777766665555ULL};
        testCase.request.state.xmm[1] = {.low = 0xDDDDCCCCBBBBAAAAULL,
                                         .high = 0x11110000FFFFEEEEULL};
        run(testCase);
    };
    runPblendw("pblendw_mask00", CaseId::pblendw_mask00, differentialBytes_pblendw_mask00);
    runPblendw("pblendw_mask0f", CaseId::pblendw_mask0f, differentialBytes_pblendw_mask0f);
    runPblendw("pblendw_maskaa", CaseId::pblendw_maskaa, differentialBytes_pblendw_maskaa);
    runPblendw("pblendw_maskff", CaseId::pblendw_maskff, differentialBytes_pblendw_maskff);
    runPblendw("pblendw_alias", CaseId::pblendw_alias, differentialBytes_pblendw_alias);
    {
        auto testCase = make("movdqa_load", CaseId::movdqa_load, differentialBytes_movdqa_load);
        bindMemory(testCase, rosa::x86::Register::Rbp, 32);
        const std::array<std::uint64_t, 2> value{0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
        std::memcpy(testCase.request.memory.data(), value.data(), sizeof(value));
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase =
            make("movdqa_register", CaseId::movdqa_register, differentialBytes_movdqa_register);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.request.state.xmm[5] = {.low = 1, .high = 2};
        run(testCase);
    }
    {
        auto testCase = make("movdqa_register_alias", CaseId::movdqa_register_alias,
                             differentialBytes_movdqa_register_alias);
        testCase.request.state.xmm[0] = {.low = 0x8877665544332211ULL,
                                         .high = 0x1020304050607080ULL};
        run(testCase);
    }
    {
        auto testCase = make("movdqa_indexed_store", CaseId::movdqa_indexed_store,
                             differentialBytes_movdqa_indexed_store);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rcx = 0x20;
        testCase.request.state.xmm[1] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = 16;
        run(testCase);
    }
    {
        auto testCase = make("movdqa_indexed_load", CaseId::movdqa_indexed_load,
                             differentialBytes_movdqa_indexed_load);
        bindMemory(testCase, rosa::x86::Register::Rdi, 0);
        testCase.request.state.rcx = 0x20;
        const std::array<std::uint64_t, 2> value{0x8877665544332211ULL, 0x0123456789ABCDEFULL};
        std::memcpy(testCase.request.memory.data() + 0x20, value.data(), sizeof(value));
        testCase.memoryCompareOffset = 0x20;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movdqa_extended_base_load", CaseId::movdqa_extended_base_load,
                             differentialBytes_movdqa_extended_base_load);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        const std::array<std::uint64_t, 2> value{0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
        std::memcpy(testCase.request.memory.data() + 0x10, value.data(), sizeof(value));
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movdqa_extended_register_load", CaseId::movdqa_extended_register_load,
                             differentialBytes_movdqa_extended_register_load);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        const std::array<std::uint64_t, 2> value{0x8877665544332211ULL, 0x1020304050607080ULL};
        std::memcpy(testCase.request.memory.data() + 0x10, value.data(), sizeof(value));
        testCase.request.state.xmm[13] = {.low = UINT64_MAX, .high = UINT64_MAX};
        testCase.memoryCompareOffset = 0x10;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movdqu_load", CaseId::movdqu_load, differentialBytes_movdqu_load);
        bindMemory(testCase, rosa::x86::Register::R15, 3);
        const std::array<std::uint64_t, 2> value{0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
        std::memcpy(testCase.request.memory.data() + 43, value.data(), sizeof(value));
        testCase.memoryCompareOffset = 43;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movdqu_extended_base_store", CaseId::movdqu_extended_base_store,
                             differentialBytes_movdqu_extended_base_store);
        bindMemory(testCase, rosa::x86::Register::R15, 3);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.memoryCompareOffset = 0x0B;
        testCase.memoryCompareSize = 16;
        run(testCase);
    }
    {
        auto testCase =
            make("movdqu_extended_register_store", CaseId::movdqu_extended_register_store,
                 differentialBytes_movdqu_extended_register_store);
        bindMemory(testCase, rosa::x86::Register::R15, 3);
        testCase.request.state.xmm[13] = {.low = 0x8877665544332211ULL,
                                          .high = 0x1020304050607080ULL};
        testCase.memoryCompareOffset = 0x0B;
        testCase.memoryCompareSize = 16;
        run(testCase);
    }
    {
        auto testCase = make("movdqu_indexed_load", CaseId::movdqu_indexed_load,
                             differentialBytes_movdqu_indexed_load);
        bindMemory(testCase, rosa::x86::Register::Rsi, 3);
        testCase.request.state.rcx = 0x20;
        const std::array<std::uint64_t, 2> value{0x8877665544332211ULL, 0x0123456789ABCDEFULL};
        std::memcpy(testCase.request.memory.data() + 0x23, value.data(), sizeof(value));
        testCase.memoryCompareOffset = 0x23;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movq_store", CaseId::movq_store, differentialBytes_movq_store);
        bindMemory(testCase, rosa::x86::Register::Rsi, 3);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        testCase.memoryCompareOffset = 35;
        testCase.memoryCompareSize = 8;
        run(testCase);
    }
    {
        auto testCase = make("movq_load", CaseId::movq_load, differentialBytes_movq_load);
        bindMemory(testCase, rosa::x86::Register::Rax, 0);
        constexpr std::uint64_t value = 0x0123456789ABCDEFULL;
        std::memcpy(testCase.request.memory.data() + 0x38, &value, sizeof(value));
        testCase.request.state.xmm[0] = {.low = UINT64_MAX, .high = 0xFEDCBA9876543210ULL};
        testCase.memoryCompareOffset = 0x38;
        testCase.memoryCompareSize = sizeof(value);
        run(testCase);
    }
    {
        auto testCase = make("movd_xmm_register", CaseId::movd_xmm_register,
                             differentialBytes_movd_xmm_register);
        testCase.request.state.rax = 0xAABBCCDD12345678ULL;
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        run(testCase);
    }
    {
        auto testCase = make("movd_xmm_register_high_bit", CaseId::movd_xmm_register_high_bit,
                             differentialBytes_movd_xmm_register_high_bit);
        testCase.request.state.rax = 0xAABBCCDD80000001ULL;
        testCase.request.state.xmm[0] = {.low = UINT64_MAX, .high = UINT64_MAX};
        run(testCase);
    }
    {
        auto testCase = make("movd_xmm_extended_register", CaseId::movd_xmm_extended_register,
                             differentialBytes_movd_xmm_extended_register);
        testCase.request.state.r8 = 0xDEADBEEFCAFEBABEULL;
        testCase.request.state.xmm[13] = {.low = 0x0123456789ABCDEFULL,
                                          .high = 0xFEDCBA9876543210ULL};
        run(testCase);
    }
    {
        auto testCase = make("movq_xmm_register", CaseId::movq_xmm_register,
                             differentialBytes_movq_xmm_register);
        testCase.request.state.rsi = 0xFEDCBA9876543210ULL;
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL, .high = UINT64_MAX};
        run(testCase);
    }
    {
        auto testCase = make("movq_xmm_extended_register", CaseId::movq_xmm_extended_register,
                             differentialBytes_movq_xmm_extended_register);
        testCase.request.state.r8 = 0x8000000000000001ULL;
        testCase.request.state.xmm[13] = {.low = 0x0123456789ABCDEFULL, .high = UINT64_MAX};
        run(testCase);
    }
    {
        auto testCase =
            make("movlhps_alias", CaseId::movlhps_alias, differentialBytes_movlhps_alias);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        run(testCase);
    }
    {
        auto testCase =
            make("movlhps_distinct", CaseId::movlhps_distinct, differentialBytes_movlhps_distinct);
        testCase.request.state.xmm[1] = {.low = 0x1111222233334444ULL,
                                         .high = 0x5555666677778888ULL};
        testCase.request.state.xmm[2] = {.low = 0xAABBCCDDEEFF0011ULL,
                                         .high = 0x2233445566778899ULL};
        run(testCase);
    }
    {
        auto testCase = make("pshufb_mixed", CaseId::pshufb_mixed, differentialBytes_pshufb_mixed);
        testCase.request.state.xmm[0] = {.low = 0x0706050403020100ULL,
                                         .high = 0x0F0E0D0C0B0A0908ULL};
        testCase.request.state.xmm[1] = {.low = 0x0807820100800E0FULL,
                                         .high = 0xFF0F0E0D0C0B0A09ULL};
        run(testCase);
    }
    {
        auto testCase = make("pshufb_alias", CaseId::pshufb_alias, differentialBytes_pshufb_alias);
        testCase.request.state.xmm[0] = {.low = 0x070605040302800FULL,
                                         .high = 0xFF0E0D0C0B0A0908ULL};
        run(testCase);
    }
    {
        auto testCase = make("por_distinct", CaseId::por_distinct, differentialBytes_por_distinct);
        testCase.request.state.xmm[2] = {.low = 0x00FF00FF00FF00FFULL,
                                         .high = 0xAAAAAAAA55555555ULL};
        testCase.request.state.xmm[1] = {.low = 0xFF00FF000F0F0F0FULL,
                                         .high = 0x55555555AAAAAAAAULL};
        run(testCase);
    }
    {
        auto testCase = make("por_alias", CaseId::por_alias, differentialBytes_por_alias);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        run(testCase);
    }
    {
        auto testCase = make("movd_memory", CaseId::movd_memory, differentialBytes_movd_memory);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.xmm[0] = {.low = 0x0123456789ABCDEFULL,
                                         .high = 0xFEDCBA9876543210ULL};
        std::fill_n(testCase.request.memory.begin() + 0x0F, 8, 0xA5);
        testCase.memoryCompareOffset = 0x0F;
        testCase.memoryCompareSize = 8;
        run(testCase);
    }
    {
        auto testCase = make("movd_memory_extended_xmm", CaseId::movd_memory_extended_xmm,
                             differentialBytes_movd_memory_extended_xmm);
        bindMemory(testCase, rosa::x86::Register::R14, 0);
        testCase.request.state.xmm[13] = {.low = 0xAABBCCDD80000001ULL,
                                          .high = 0x1020304050607080ULL};
        std::fill_n(testCase.request.memory.begin() + 0x0F, 8, 0x5A);
        testCase.memoryCompareOffset = 0x0F;
        testCase.memoryCompareSize = 8;
        run(testCase);
    }
    {
        auto testCase = make("mov32_immediate_indexed", CaseId::mov32_immediate_indexed,
                             differentialBytes_mov32_immediate_indexed);
        bindMemory(testCase, rosa::x86::Register::Rsi, 0);
        testCase.request.state.rdx = 0x20;
        std::fill_n(testCase.request.memory.begin() + 0x1E, 8, 0xA5);
        testCase.memoryCompareOffset = 0x1E;
        testCase.memoryCompareSize = 8;
        run(testCase);
    }

    expectEqual(compared, static_cast<std::size_t>(CaseId::Count),
                "not every differential case was executed");
}

#endif

} // namespace

std::span<const TestCase> differentialTests() {
#if ROSA_HAS_X86_ORACLE
    static const TestCase cases[]{
#if ROSA_HAS_X86_ORACLE
        {"Rosetta semantic differential corpus", testRosettaDifferentialSemantics},
#endif
    };
    return cases;
#else
    return {};
#endif
}

} // namespace rosa::tests
