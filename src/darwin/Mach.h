#pragma once

#include "darwin/PortSpace.h"
#include "darwin/Threads.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "x86/Registers.h"

#include <array>
#include <chrono>
#include <functional>
#include <cstdint>
#include <optional>
#include <set>
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

// The lowest free guest range of `size` at or above `hint`, aligned to
// `alignmentMask + 1`, as XNU's VM_FLAGS_ANYWHERE placement chooses.
[[nodiscard]] std::optional<guest::GuestAddress>
findGuestAnywhereRange(const guest::AddressSpace &addressSpace, std::uint64_t hint,
                       std::uint64_t size, std::uint64_t alignmentMask);

class MachDispatcher {
  public:
    static constexpr std::uint64_t syscallClass = 1U << 24U;
    static constexpr std::uint64_t syscallClassMask = 0xFF000000U;
    static constexpr std::uint64_t syscallNumberMask = 0x00FFFFFFU;
    static constexpr std::uint64_t vmAllocateTrapNumber = syscallClass | 10U;
    static constexpr std::uint64_t vmDeallocateTrapNumber = syscallClass | 12U;
    static constexpr std::uint64_t vmProtectTrapNumber = syscallClass | 14U;
    static constexpr std::uint64_t vmMapTrapNumber = syscallClass | 15U;
    static constexpr std::uint64_t portAllocateTrapNumber = syscallClass | 16U;
    static constexpr std::uint64_t portInsertMemberTrapNumber = syscallClass | 22U;
    static constexpr std::uint64_t timerCreateTrapNumber = syscallClass | 91U;
    static constexpr std::uint64_t portDeallocateTrapNumber = syscallClass | 18U;
    static constexpr std::uint64_t portModRefsTrapNumber = syscallClass | 19U;
    static constexpr std::uint64_t portConstructTrapNumber = syscallClass | 24U;
    static constexpr std::uint64_t portDestructTrapNumber = syscallClass | 25U;
    static constexpr std::uint64_t replyPortTrapNumber = syscallClass | 26U;
    static constexpr std::uint64_t threadSelfTrapNumber = syscallClass | 27U;
    static constexpr std::uint64_t taskSelfTrapNumber = syscallClass | 28U;
    static constexpr std::uint64_t hostSelfTrapNumber = syscallClass | 29U;
    static constexpr std::uint64_t machMessage2TrapNumber = syscallClass | 47U;
    static constexpr std::uint64_t specialReplyPortTrapNumber = syscallClass | 50U;
    static constexpr std::uint64_t hostCreateMachVoucherTrapNumber = syscallClass | 70U;
    static constexpr std::uint64_t timebaseInfoTrapNumber = syscallClass | 89U;

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
    [[nodiscard]] GuestPortSpace &portSpace() noexcept { return portSpace_; }
    // The task's guest threads. Without one, every trap runs as the main
    // thread and nothing can block.
    void setScheduler(GuestScheduler *scheduler) noexcept { scheduler_ = scheduler; }
    // Told whenever a guest port or port set gains or loses its last queued
    // message, so kqueue EVFILT_MACHPORT knotes can follow.
    using PortReadinessHandler =
        std::function<void(guest::AddressSpace &, GuestMachPortName, bool ready)>;
    void setPortReadinessHandler(PortReadinessHandler handler) {
        portReadiness_ = std::move(handler);
    }
    // Queues the expiration message of every armed mk_timer due at `now`
    // (guest mach_absolute_time); returns the next armed deadline.
    std::optional<std::uint64_t> fireDueTimers(guest::AddressSpace &addressSpace,
                                               std::uint64_t now);
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
    struct GuestReceive {
        GuestMachPortName name;
        std::uint64_t buffer{};
        std::uint32_t size{};
        std::uint64_t options{};
        std::uint32_t timeout{};
    };

    // MachIpc.cpp: messages between guest ports. Returns false when the
    // destination is a kernel object for the MIG paths in Mach.cpp.
    [[nodiscard]] bool dispatchGuestMessage(guest::AddressSpace &addressSpace,
                                            x86::X86State &state);
    [[nodiscard]] static bool isGuestQueue(const GuestPort &port) noexcept;
    [[nodiscard]] static bool holdsRight(const GuestPort &port, std::uint32_t disposition) noexcept;
    static void transferRight(GuestPort &port, std::uint32_t disposition) noexcept;
    [[nodiscard]] std::uint64_t sendGuestMessage(guest::AddressSpace &addressSpace,
                                                 const x86::X86State &state,
                                                 GuestPort &destination, std::uint64_t timeout);
    void receiveGuestMessage(guest::AddressSpace &addressSpace, x86::X86State &state,
                             const GuestReceive &receive);
    [[nodiscard]] std::optional<std::uint64_t>
    tryReceiveGuestMessage(guest::AddressSpace &addressSpace, const GuestReceive &receive);
    [[nodiscard]] GuestPort *nextMessagePort(GuestMachPortName receiveName);
    void messageQueued(guest::AddressSpace &addressSpace, GuestMachPortName port);
    void updateReadiness(guest::AddressSpace &addressSpace, GuestMachPortName port);
    void destroyReceiveRight(guest::AddressSpace &addressSpace, GuestPort &port);
    void queueTimerExpiration(guest::AddressSpace &addressSpace, GuestPort &timer);
    // Resolves an mk_timer receive right for the timer traps.
    [[nodiscard]] GuestPort *timerPort(std::uint64_t name, std::uint64_t &error);

    [[nodiscard]] GuestPort *semaphorePort(std::uint64_t name);
    void signalSemaphore(GuestPort &semaphore, bool all);
    void waitSemaphore(GuestPort &semaphore, x86::X86State &state,
                       std::optional<std::chrono::nanoseconds> timeout);

    // This namespace contains guest-only names and rights. None of its values
    // are ever passed to host Mach APIs or confused with mach_port_t.
    GuestPortSpace portSpace_;
    GuestScheduler *scheduler_{};
    PortReadinessHandler portReadiness_;
    std::uint64_t nextMessageArrival_{};
    std::uint64_t nextActivityId_{1};
    std::optional<GuestPortConstructObservation> lastPortConstruct_;
    std::optional<GuestMachPortName> taskDebugControlPort_;
    std::set<std::uint64_t> vouchers_;
    std::uint64_t nextVoucher_{1};
};

} // namespace rosa::darwin
