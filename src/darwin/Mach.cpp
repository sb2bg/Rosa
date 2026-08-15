#include "darwin/Mach.h"

#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace rosa::darwin {
namespace {

std::runtime_error unsupported(const x86::X86State &state, guest::GuestAddress rip) {
    std::ostringstream stream;
    stream << "unsupported Darwin guest Mach trap\n"
           << "  number: 0x" << std::hex << state.rax << '\n'
           << "  trap: " << std::dec << MachDispatcher::trapNumber(state.rax) << '\n'
           << "  RIP: 0x" << std::hex << rip.value << '\n'
           << "  args: 0x" << state.rdi << " 0x" << state.rsi << " 0x" << state.rdx << " 0x"
           << state.r10 << " 0x" << state.r8 << " 0x" << state.r9;
    return std::runtime_error(stream.str());
}

} // namespace

void MachDispatcher::dispatch(x86::X86State &state, guest::GuestAddress syscallRip) const {
    if (!isMachTrap(state.rax) || trapNumber(state.rax) != 28U) {
        throw unsupported(state, syscallRip);
    }

    // XNU's x86_64 mach_call_munger64 writes only the trap result to saved RAX. In particular,
    // Mach traps do not use the BSD carry-flag error convention.
    state.rax = taskSelfPortName_.value;
}

} // namespace rosa::darwin
