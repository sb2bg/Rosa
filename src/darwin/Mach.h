#pragma once

#include "darwin/PortSpace.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "x86/Registers.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace rosa::darwin {

struct GuestPortConstructObservation {
    GuestMachPortName target;
    guest::GuestAddress optionsPointer;
    std::uint32_t flags{};
    std::uint32_t queueLimit{};
    std::array<std::uint64_t, 2> specialFields{};
    std::uint64_t context{};
    guest::GuestAddress outputPointer;
};

class MachDispatcher {
  public:
    static constexpr std::uint64_t syscallClass = 1U << 24U;
    static constexpr std::uint64_t syscallClassMask = 0xFF000000U;
    static constexpr std::uint64_t syscallNumberMask = 0x00FFFFFFU;
    static constexpr std::uint64_t vmAllocateTrapNumber = syscallClass | 10U;
    static constexpr std::uint64_t vmDeallocateTrapNumber = syscallClass | 12U;
    static constexpr std::uint64_t vmProtectTrapNumber = syscallClass | 14U;
    static constexpr std::uint64_t vmMapTrapNumber = syscallClass | 15U;
    static constexpr std::uint64_t portDeallocateTrapNumber = syscallClass | 18U;
    static constexpr std::uint64_t portModRefsTrapNumber = syscallClass | 19U;
    static constexpr std::uint64_t portConstructTrapNumber = syscallClass | 24U;
    static constexpr std::uint64_t replyPortTrapNumber = syscallClass | 26U;
    static constexpr std::uint64_t threadSelfTrapNumber = syscallClass | 27U;
    static constexpr std::uint64_t taskSelfTrapNumber = syscallClass | 28U;
    static constexpr std::uint64_t hostSelfTrapNumber = syscallClass | 29U;
    static constexpr std::uint64_t machMessage2TrapNumber = syscallClass | 47U;

    [[nodiscard]] static constexpr bool isMachTrap(std::uint64_t number) {
        return (number & syscallClassMask) == syscallClass;
    }

    [[nodiscard]] static constexpr std::uint64_t trapNumber(std::uint64_t number) {
        return number & syscallNumberMask;
    }

    [[nodiscard]] constexpr GuestMachPortName taskSelfPortName() const {
        return GuestPortSpace::taskSelfName;
    }

    [[nodiscard]] bool ownsReceiveRight(GuestMachPortName name) const;
    [[nodiscard]] const GuestPortSpace &portSpace() const noexcept {
        return portSpace_;
    }
    [[nodiscard]] const std::optional<GuestPortConstructObservation> &
    lastPortConstruct() const noexcept {
        return lastPortConstruct_;
    }
    [[nodiscard]] const std::optional<GuestMachPortName> &
    taskDebugControlPort() const noexcept {
        return taskDebugControlPort_;
    }
    [[nodiscard]] std::string portSpaceSummary() const;

    void dispatch(guest::AddressSpace &addressSpace, x86::X86State &state,
                  guest::GuestAddress syscallRip);

  private:
    // This namespace contains guest-only names and rights. None of its values
    // are ever passed to host Mach APIs or confused with mach_port_t.
    GuestPortSpace portSpace_;
    std::optional<GuestPortConstructObservation> lastPortConstruct_;
    std::optional<GuestMachPortName> taskDebugControlPort_;
};

} // namespace rosa::darwin
