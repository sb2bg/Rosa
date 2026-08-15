#include "Protocol.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <unistd.h>

using rosa::differential::CaseId;

extern "C" {
alignas(16) rosa::x86::X86State rosa_oracle_input;
alignas(16) rosa::x86::X86State rosa_oracle_output;
std::uint64_t rosa_oracle_host_rsp;
std::uint64_t rosa_oracle_function;

void rosa_oracle_run(void (*function)());
#define ROSA_DIFFERENTIAL_CASE(name, ...) void rosa_oracle_case_##name();
#include "Cases.def"
#undef ROSA_DIFFERENTIAL_CASE
}

namespace {

alignas(16) std::array<std::uint8_t, rosa::differential::memorySize> oracleMemory;
alignas(16) std::array<std::uint8_t, rosa::differential::stackSize> oracleStack;

constexpr std::array oracleCases{
#define ROSA_DIFFERENTIAL_CASE(name, ...) &rosa_oracle_case_##name,
#include "Cases.def"
#undef ROSA_DIFFERENTIAL_CASE
};

static_assert(oracleCases.size() == static_cast<std::size_t>(CaseId::Count));
static_assert(offsetof(rosa::x86::X86State, rflags) == 136);
static_assert(offsetof(rosa::x86::X86State, xmm) == 144);
static_assert(sizeof(rosa::x86::X86State) == 400);

bool readFully(int descriptor, std::span<std::byte> bytes) {
    while (!bytes.empty()) {
        const auto count = read(descriptor, bytes.data(), bytes.size());
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

bool writeFully(int descriptor, std::span<const std::byte> bytes) {
    while (!bytes.empty()) {
        const auto count = write(descriptor, bytes.data(), bytes.size());
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

std::uint64_t &registerValue(rosa::x86::X86State &state, std::uint8_t encoded) {
    const auto reg = static_cast<rosa::x86::Register>(encoded);
    auto *bytes = reinterpret_cast<std::uint8_t *>(&state);
    return *reinterpret_cast<std::uint64_t *>(bytes + rosa::x86::registerOffset(reg));
}

} // namespace

int main() {
    rosa::differential::Request request;
    if (!readFully(STDIN_FILENO, std::as_writable_bytes(std::span(&request, 1))) ||
        request.magic != rosa::differential::protocolMagic ||
        static_cast<std::size_t>(request.caseId) >= oracleCases.size()) {
        return 2;
    }

    oracleMemory = request.memory;
    oracleStack.fill(0);
    rosa_oracle_input = request.state;
    rosa_oracle_input.rsp =
        reinterpret_cast<std::uint64_t>(oracleStack.data() + oracleStack.size() - 8);
    if (request.memoryBaseRegister != rosa::differential::noRegister) {
        if (request.memoryBaseRegister >
            static_cast<std::uint8_t>(rosa::x86::Register::R15) ||
            request.memoryBaseOffset >= oracleMemory.size()) {
            return 3;
        }
        registerValue(rosa_oracle_input, request.memoryBaseRegister) =
            reinterpret_cast<std::uint64_t>(oracleMemory.data() + request.memoryBaseOffset);
    }
    const auto function = oracleCases[static_cast<std::size_t>(request.caseId)];
    if (request.codePointerMemoryOffset != rosa::differential::noOffset) {
        if (request.codePointerMemoryOffset > oracleMemory.size() - sizeof(std::uint64_t)) {
            return 3;
        }
        const auto target = reinterpret_cast<std::uint64_t>(function) +
                            request.codePointerTargetOffset;
        std::memcpy(oracleMemory.data() + request.codePointerMemoryOffset, &target,
                    sizeof(target));
    }
    const auto initial = rosa_oracle_input;
    rosa_oracle_run(function);

    rosa::differential::Result result;
    result.initial = initial;
    result.final = rosa_oracle_output;
    result.memory = oracleMemory;
    result.stack = oracleStack;
    return writeFully(STDOUT_FILENO, std::as_bytes(std::span(&result, 1))) ? 0 : 4;
}
