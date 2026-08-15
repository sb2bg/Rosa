#include "darwin/Mach.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace rosa::darwin {
namespace {

constexpr std::uint64_t kernSuccess = 0;
constexpr std::uint64_t kernInvalidAddress = 1;
constexpr std::uint64_t kernProtectionFailure = 2;
constexpr std::uint64_t kernInvalidArgument = 4;
constexpr std::uint64_t machSendInvalidDestination = 0x10000003U;
constexpr std::uint64_t vmProtectionMask = 0x7U;

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

void MachDispatcher::dispatch(guest::AddressSpace &addressSpace, x86::X86State &state,
                              guest::GuestAddress syscallRip) {
    if (!isMachTrap(state.rax)) {
        throw unsupported(state, syscallRip);
    }

    // XNU's x86_64 mach_call_munger64 writes only the trap result to saved RAX. In particular,
    // Mach traps do not use the BSD carry-flag error convention.
    switch (trapNumber(state.rax)) {
    case 14U: {
        // XNU trap 14 is _kernelrpc_mach_vm_protect_trap. Its five x86_64
        // arguments are target, address, size, set_maximum, and new_protection.
        if (state.rdi != taskSelfPortName_.value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        if (state.r10 != 0) {
            throw unsupported(state, syscallRip);
        }
        if ((state.r8 & ~vmProtectionMask) != 0) {
            throw unsupported(state, syscallRip);
        }
        auto permissions = guest::Permission::None;
        if ((state.r8 & 0x1U) != 0) {
            permissions = permissions | guest::Permission::Read;
        }
        if ((state.r8 & 0x2U) != 0) {
            permissions = permissions | guest::Permission::Write;
        }
        if ((state.r8 & 0x4U) != 0) {
            permissions = permissions | guest::Permission::Execute;
        }
        switch (addressSpace.protect(guest::GuestAddress{state.rsi}, state.rdx,
                                     permissions)) {
        case guest::ProtectResult::Success:
            state.rax = kernSuccess;
            return;
        case guest::ProtectResult::InvalidAddress:
            state.rax = kernInvalidAddress;
            return;
        case guest::ProtectResult::ProtectionFailure:
            state.rax = kernProtectionFailure;
            return;
        case guest::ProtectResult::InvalidArgument:
            state.rax = kernInvalidArgument;
            return;
        }
        throw std::runtime_error("unreachable guest protection result");
    }
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
