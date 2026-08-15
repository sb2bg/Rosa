#pragma once

#include "guest/Address.h"
#include "x86/Registers.h"

#include <cstdint>
#include <vector>

namespace rosa::darwin {

struct GuestMachPortName {
    std::uint32_t value{};

    auto operator<=>(const GuestMachPortName &) const = default;
};

class MachDispatcher {
  public:
    static constexpr std::uint64_t syscallClass = 1U << 24U;
    static constexpr std::uint64_t syscallClassMask = 0xFF000000U;
    static constexpr std::uint64_t syscallNumberMask = 0x00FFFFFFU;
    static constexpr std::uint64_t replyPortTrapNumber = syscallClass | 26U;
    static constexpr std::uint64_t taskSelfTrapNumber = syscallClass | 28U;

    [[nodiscard]] static constexpr bool isMachTrap(std::uint64_t number) {
        return (number & syscallClassMask) == syscallClass;
    }

    [[nodiscard]] static constexpr std::uint64_t trapNumber(std::uint64_t number) {
        return number & syscallNumberMask;
    }

    [[nodiscard]] constexpr GuestMachPortName taskSelfPortName() const {
        return taskSelfPortName_;
    }

    [[nodiscard]] bool ownsReceiveRight(GuestMachPortName name) const;

    void dispatch(x86::X86State &state, guest::GuestAddress syscallRip);

  private:
    // Mach port names are opaque identifiers in the guest task's namespace. This value is never
    // passed to the host Mach APIs or confused with a native mach_port_t.
    GuestMachPortName taskSelfPortName_{0x103U};
    GuestMachPortName nextReplyPortName_{0x203U};
    std::vector<GuestMachPortName> receiveRights_;
};

} // namespace rosa::darwin
