#pragma once

#include "darwin/Files.h"
#include "darwin/Mach.h"
#include "darwin/Threads.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "x86/Registers.h"

#include <array>
#include <cstdint>
#include <map>
#include <iosfwd>
#include <optional>

namespace rosa::darwin {

class GuestSharedCache;

struct SyscallOutcome {
    bool exited{};
    int exitStatus{};
};

struct GuestDyldInfo {
    guest::GuestAddress address;
    std::uint64_t size{};
};

struct GuestPthreadRegistration {
    guest::GuestAddress threadStart;
    guest::GuestAddress workqueueThreadStart;
    std::uint32_t pthreadSize{};
    guest::GuestAddress dataAddress;
    std::uint64_t dataSize{};
    std::uint64_t dispatchQueueOffset{};
    std::uint32_t tsdOffset{};
    std::uint32_t returnToKernelOffset{};
    std::uint32_t machThreadSelfOffset{};
    std::uint32_t joinableOffsetBits{};
    std::uint32_t workqueueQuantumExpiryOffset{};
};

// Task-local x86_64 struct sigaction without any host signal delivery.
struct GuestSignalDisposition {
    std::uint64_t handlerAddress{};
    std::uint32_t mask{};
    std::int32_t flags{};
};

// Task-wide Darwin state shared by every syscall handler.
struct GuestTask {
    const GuestSharedCache *sharedCache{};
    std::array<std::uint8_t, 16> executableUuid{};
    GuestFileSpace fileSpace;
    GuestScheduler scheduler;
    GuestWorkqueue workqueue;
    MachDispatcher machDispatcher;
    std::optional<GuestDyldInfo> dyldInfo;
    std::optional<GuestPthreadRegistration> pthreadRegistration;
    std::map<std::int32_t, GuestSignalDisposition> signalDispositions;
    bool dyldInfoFinal{};
};

// Routes Mach traps, machdep calls, and table-driven BSD syscalls. Handlers
// live in Syscall{Process,Sysctl,Files,Memory}.cpp.
class SyscallDispatcher {
  public:
    explicit SyscallDispatcher(
        const GuestSharedCache *sharedCache = nullptr,
        const std::array<std::uint8_t, 16> &executableUuid = {})
        : task_{.sharedCache = sharedCache, .executableUuid = executableUuid} {
        task_.machDispatcher.setScheduler(&task_.scheduler);
        task_.machDispatcher.setPortReadinessHandler(
            [this](guest::AddressSpace &addressSpace, GuestMachPortName port, bool ready) {
                portReadinessChanged(addressSpace, port, ready);
            });
    }
    SyscallDispatcher(const SyscallDispatcher &) = delete;
    SyscallDispatcher &operator=(const SyscallDispatcher &) = delete;

    [[nodiscard]] SyscallOutcome dispatch(guest::AddressSpace &addressSpace, x86::X86State &state,
                                          guest::GuestAddress syscallRip);
    [[nodiscard]] const std::optional<GuestDyldInfo> &dyldInfo() const noexcept {
        return task_.dyldInfo;
    }
    [[nodiscard]] const MachDispatcher &machDispatcher() const noexcept {
        return task_.machDispatcher;
    }
    [[nodiscard]] GuestScheduler &scheduler() noexcept { return task_.scheduler; }
    [[nodiscard]] const GuestScheduler &scheduler() const noexcept { return task_.scheduler; }
    [[nodiscard]] const GuestFileSpace &fileSpace() const noexcept {
        return task_.fileSpace;
    }
    [[nodiscard]] const std::optional<GuestPthreadRegistration> &
    pthreadRegistration() const noexcept {
        return task_.pthreadRegistration;
    }
    [[nodiscard]] GuestSignalDisposition
    signalDisposition(std::int32_t signum) const noexcept {
        const auto found = task_.signalDispositions.find(signum);
        return found == task_.signalDispositions.end() ? GuestSignalDisposition{}
                                                       : found->second;
    }
    void setHostAccess(GuestHostAccess access) noexcept {
        task_.fileSpace.setHostAccess(access);
    }
    // Fires due workqueue-kqueue timers and hands ready work to workqueue
    // threads; returns when it next needs to run.
    [[nodiscard]] std::optional<GuestClock::time_point>
    serviceEvents(guest::AddressSpace &addressSpace);
    // Logs each BSD syscall with its arguments and result; null disables.
    void setTrace(std::ostream *trace) noexcept { trace_ = trace; }

  private:
    // EVFILT_MACHPORT knotes follow their port's queue; a newly ready port
    // may need a workqueue thread.
    void portReadinessChanged(guest::AddressSpace &addressSpace, GuestMachPortName port,
                              bool ready);

    GuestTask task_;
    std::ostream *trace_{};
};

} // namespace rosa::darwin
