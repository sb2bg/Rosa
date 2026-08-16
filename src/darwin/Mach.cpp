#include "darwin/Mach.h"

#include <algorithm>
#include <bit>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>

namespace rosa::darwin {
namespace {

constexpr std::uint64_t kernSuccess = 0;
constexpr std::uint64_t kernInvalidAddress = 1;
constexpr std::uint64_t kernProtectionFailure = 2;
constexpr std::uint64_t kernNoSpace = 3;
constexpr std::uint64_t kernInvalidArgument = 4;
constexpr std::uint64_t kernInvalidName = 15;
constexpr std::uint64_t kernInvalidRight = 17;
constexpr std::uint64_t kernInvalidValue = 18;
constexpr std::uint64_t kernUrefsOverflow = 19;
constexpr std::uint64_t machSendInvalidDestination = 0x10000003U;
constexpr std::uint64_t vmProtectionMask = 0x7U;
constexpr std::uint64_t vmFlagsAnywhere = 0x1U;
constexpr std::uint64_t vmFlagsAliasMask = 0xFF000000U;
constexpr std::uint64_t minimumAnywhereAddress = 0x0000000100000000ULL;
constexpr std::uint64_t maximumUserMapEnd = 0x00007FFFFFFFF000ULL;
constexpr std::uint32_t machPortRightSend = 0;
constexpr std::uint32_t machPortRightCount = 6;
constexpr std::uint32_t machPortUrefsMaximum = 0xFFFF;

guest::Permission permissionsFromProtection(std::uint64_t protection) {
    auto permissions = guest::Permission::None;
    if ((protection & 0x1U) != 0) {
        permissions = permissions | guest::Permission::Read;
    }
    if ((protection & 0x2U) != 0) {
        permissions = permissions | guest::Permission::Write;
    }
    if ((protection & 0x4U) != 0) {
        permissions = permissions | guest::Permission::Execute;
    }
    return permissions;
}

std::optional<std::uint64_t> alignUp(std::uint64_t value,
                                     std::uint64_t mask) {
    if (value > std::numeric_limits<std::uint64_t>::max() - mask) {
        return std::nullopt;
    }
    return (value + mask) & ~mask;
}

std::optional<guest::GuestAddress>
findAnywhereRange(const guest::AddressSpace &addressSpace,
                  std::uint64_t hint, std::uint64_t size,
                  std::uint64_t alignmentMask) {
    const auto aligned =
        alignUp(std::max(hint, minimumAnywhereAddress), alignmentMask);
    if (!aligned) {
        return std::nullopt;
    }
    auto candidate = *aligned;
    auto mappings = addressSpace.mappingInfos();
    std::ranges::sort(mappings, {},
                      [](const guest::MappingInfo &mapping) {
                          return mapping.base.value;
                      });
    for (const auto &mapping : mappings) {
        const auto mappingEnd = mapping.base.value + mapping.size;
        if (mappingEnd <= candidate) {
            continue;
        }
        if (candidate <= mapping.base.value &&
            size <= mapping.base.value - candidate) {
            return guest::GuestAddress{candidate};
        }
        const auto next = alignUp(mappingEnd, alignmentMask);
        if (!next) {
            return std::nullopt;
        }
        candidate = *next;
    }
    if (candidate <= maximumUserMapEnd &&
        size <= maximumUserMapEnd - candidate) {
        return guest::GuestAddress{candidate};
    }
    return std::nullopt;
}

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
        const auto permissions = permissionsFromProtection(state.r8);
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
    case 15U: {
        // XNU's _kernelrpc_mach_vm_map_trap is the six-argument anonymous
        // fast path used when object is null, maximum protection is ALL, and
        // inheritance is DEFAULT. The second argument points to an in/out
        // guest mach_vm_address_t.
        if (state.rdi != taskSelfPortName_.value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        if ((state.r8 & ~vmFlagsAliasMask) != vmFlagsAnywhere ||
            state.r10 != guest::guestPageSize - 1U) {
            throw unsupported(state, syscallRip);
        }
        if ((state.r9 & ~vmProtectionMask) != 0 || state.rdx == 0 ||
            state.rdx > std::numeric_limits<std::size_t>::max() ||
            state.rdx > std::numeric_limits<std::uint64_t>::max() -
                            (guest::guestPageSize - 1U)) {
            state.rax = kernInvalidArgument;
            return;
        }
        std::uint64_t hint = 0;
        try {
            hint = addressSpace.readU64(guest::GuestAddress{state.rsi});
        } catch (const std::runtime_error &) {
            state.rax = kernInvalidAddress;
            return;
        }
        const auto roundedSize =
            (state.rdx + guest::guestPageSize - 1U) &
            ~(static_cast<std::uint64_t>(guest::guestPageSize) - 1U);
        const auto mappedAddress = findAnywhereRange(
            addressSpace, hint, roundedSize, state.r10);
        if (!mappedAddress) {
            state.rax = kernNoSpace;
            return;
        }
        const auto currentPermissions = permissionsFromProtection(state.r9);
        constexpr auto maximumPermissions =
            guest::Permission::Read | guest::Permission::Write |
            guest::Permission::Execute;
        addressSpace.mapAnonymous(
            *mappedAddress, static_cast<std::size_t>(roundedSize),
            currentPermissions, maximumPermissions,
            "mach_vm_map anonymous");
        try {
            addressSpace.writeU64(guest::GuestAddress{state.rsi},
                                  mappedAddress->value);
        } catch (const std::runtime_error &) {
            // XNU performs mach_copyout after creating the mapping; a failed
            // copyout returns KERN_INVALID_ADDRESS but does not undo it.
            state.rax = kernInvalidAddress;
            return;
        }
        state.rax = kernSuccess;
        return;
    }
    case 19U: {
        // XNU trap 19 is _kernelrpc_mach_port_mod_refs_trap. Model the
        // task-self send right currently exposed by Rosa's guest namespace.
        if (state.rdi != taskSelfPortName_.value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        const auto right = static_cast<std::uint32_t>(state.rdx);
        if (right >= machPortRightCount) {
            state.rax = kernInvalidValue;
            return;
        }
        const auto name = static_cast<std::uint32_t>(state.rsi);
        if (name != taskSelfPortName_.value || taskSelfSendReferences_ == 0) {
            state.rax = kernInvalidName;
            return;
        }
        if (right != machPortRightSend) {
            state.rax = kernInvalidRight;
            return;
        }
        const auto delta = std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.r10));
        const auto updated = static_cast<std::int64_t>(taskSelfSendReferences_) +
                             static_cast<std::int64_t>(delta);
        if (updated < 0) {
            state.rax = kernInvalidValue;
            return;
        }
        if (updated > machPortUrefsMaximum) {
            state.rax = kernUrefsOverflow;
            return;
        }
        taskSelfSendReferences_ = static_cast<std::uint32_t>(updated);
        state.rax = kernSuccess;
        return;
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
        if (taskSelfSendReferences_ == machPortUrefsMaximum) {
            state.rax = 0;
            return;
        }
        ++taskSelfSendReferences_;
        state.rax = taskSelfPortName_.value;
        return;
    default:
        throw unsupported(state, syscallRip);
    }
}

} // namespace rosa::darwin
