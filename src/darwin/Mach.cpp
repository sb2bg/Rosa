#include "darwin/Mach.h"

#include <algorithm>
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

bool MachDispatcher::ownsReceiveRight(GuestMachPortName name) const {
    return std::ranges::find(receiveRights_, name) != receiveRights_.end();
}

void MachDispatcher::dispatch(x86::X86State &state, guest::GuestAddress syscallRip) {
    if (!isMachTrap(state.rax)) {
        throw unsupported(state, syscallRip);
    }

    // XNU's x86_64 mach_call_munger64 writes only the trap result to saved RAX. In particular,
    // Mach traps do not use the BSD carry-flag error convention.
    switch (trapNumber(state.rax)) {
    case 26U: {
        // mach_reply_port allocates a fresh receive right in the calling task on every call.
        const auto name = nextReplyPortName_;
        if (name.value > UINT32_MAX - 0x100U) {
            state.rax = 0; // MACH_PORT_NULL models allocation exhaustion.
            return;
        }
        nextReplyPortName_.value += 0x100U;
        receiveRights_.push_back(name);
        state.rax = name.value;
        return;
    }
    case 28U:
        state.rax = taskSelfPortName_.value;
        return;
    default:
        throw unsupported(state, syscallRip);
    }
}

} // namespace rosa::darwin
