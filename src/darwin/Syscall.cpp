#include "darwin/Syscall.h"

#include <unistd.h>

#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace rosa::darwin {
namespace {

constexpr std::uint64_t unixSyscallClass = 2U << 24U;
constexpr std::uint64_t syscallExit = unixSyscallClass | 1U;
constexpr std::uint64_t syscallWrite = unixSyscallClass | 4U;
constexpr std::uint64_t carryFlag = 1U << 0U;
constexpr std::uint64_t reservedOneFlag = 1U << 1U;
constexpr std::size_t maximumControlledWrite = 16U * 1024U * 1024U;

void setSuccess(x86::X86State &state, std::uint64_t result) {
    state.rax = result;
    state.rflags = (state.rflags & ~carryFlag) | reservedOneFlag;
}

void setError(x86::X86State &state, int error) {
    state.rax = static_cast<std::uint64_t>(error);
    state.rflags = state.rflags | carryFlag | reservedOneFlag;
}

std::runtime_error unsupported(const x86::X86State &state, guest::GuestAddress rip,
                               const std::string &reason) {
    std::ostringstream stream;
    stream << "unsupported Darwin guest syscall\n"
           << "  number: 0x" << std::hex << state.rax << '\n'
           << "  RIP: 0x" << rip.value << '\n'
           << "  args: 0x" << state.rdi << " 0x" << state.rsi << " 0x" << state.rdx << " 0x"
           << state.r10 << " 0x" << state.r8 << " 0x" << state.r9 << '\n'
           << "  reason: " << reason;
    return std::runtime_error(stream.str());
}

} // namespace

SyscallOutcome SyscallDispatcher::dispatch(guest::AddressSpace &addressSpace, x86::X86State &state,
                                           guest::GuestAddress syscallRip) const {
    const auto number = state.rax;
    if (number == syscallExit) {
        const auto rawStatus = static_cast<std::uint32_t>(state.rdi);
        return SyscallOutcome{
            .exited = true,
            .exitStatus = static_cast<int>(std::bit_cast<std::int32_t>(rawStatus)),
        };
    }
    if (number != syscallWrite) {
        throw unsupported(state, syscallRip, "only BSD write(2) and exit(2) are implemented");
    }
    if (state.rdi != STDOUT_FILENO && state.rdi != STDERR_FILENO) {
        throw unsupported(state, syscallRip,
                          "controlled write currently accepts only stdout or stderr");
    }
    if (state.rdx > maximumControlledWrite) {
        throw unsupported(state, syscallRip, "controlled write exceeds the 16 MiB limit");
    }

    const auto bytes =
        addressSpace.readBytes(guest::GuestAddress{state.rsi}, static_cast<std::size_t>(state.rdx));
    const auto result = ::write(static_cast<int>(state.rdi), bytes.data(), bytes.size());
    if (result < 0) {
        setError(state, errno);
    } else {
        setSuccess(state, static_cast<std::uint64_t>(result));
    }
    return {};
}

} // namespace rosa::darwin
