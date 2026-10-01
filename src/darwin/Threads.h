#pragma once

#include "darwin/Kqueue.h"
#include "darwin/PortSpace.h"
#include "x86/Registers.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace rosa::darwin {

using GuestClock = std::chrono::steady_clock;

enum class GuestThreadStatus : std::uint8_t {
    Runnable,
    Blocked,
    Exited,
};

enum class GuestWakeReason : std::uint8_t {
    Signaled,
    TimedOut,
    // The waited-on object was destroyed (a port's receive right died).
    Destroyed,
};

// What a parked syscall waits on. Wakers find waiters by kind and channel.
enum class GuestWaitKind : std::uint8_t {
    Ulock,
    Sleep,
    // A dispatch_sync waiter parked on a workloop NOTE_WL_SYNC_WAIT knote.
    WorkloopSync,
    // semaphore_wait on a guest semaphore port.
    Semaphore,
    // mach_msg receive on a guest port or port set.
    MachReceive,
    // An idle workqueue thread parked until a thread request rebinds it.
    WorkqueueIdle,
};

// A guest syscall parked until another guest thread signals its channel or
// its deadline passes. `complete` writes the call's result into the waiting
// thread's registers when the wait ends.
struct GuestWait {
    GuestWaitKind kind{GuestWaitKind::Sleep};
    std::uint64_t channel{};
    std::optional<GuestClock::time_point> deadline;
    std::function<void(x86::X86State &, GuestWakeReason)> complete;
    std::string description;
};

struct GuestThread {
    std::uint64_t id{};
    // The main thread runs on the caller's state; created threads own theirs.
    x86::X86State *state{};
    std::unique_ptr<x86::X86State> ownedState;
    std::optional<GuestMachPortName> port;
    GuestThreadStatus status{GuestThreadStatus::Runnable};
    std::optional<GuestWait> wait;
    // Signal state recorded for the guest; Rosa delivers no signals.
    std::uint32_t signalMask{};
    bool signalsDisabled{};
    // A workqueue thread's kernel-allocated region: guard page, stack, then
    // its pthread_t at `workqueueSelf`.
    bool workqueue{};
    std::uint64_t workqueueStackAddress{};
    std::uint64_t workqueueSelf{};
    // The workqueue-kqueue bucket whose events this thread is processing.
    std::optional<std::uint32_t> keventBucket;
    // The workloop this thread services.
    std::optional<std::uint64_t> workloop;
};

// One outstanding workq_kernreturn(WQOPS_QUEUE_REQTHREADS) thread request.
struct GuestThreadRequest {
    std::uint32_t qos{};
    bool overcommit{};
};

// Task-wide pthread workqueue state (XNU's struct workqueue).
struct GuestWorkqueue {
    bool open{};
    std::uint64_t serialNumberOffset{};
    std::uint64_t labelOffset{};
    std::uint32_t eventManagerPriority{};
    std::vector<GuestThreadRequest> pending;
    // The process's workqueue kqueue (KEVENT_FLAG_WORKQ). Like XNU's
    // kqworkq, each QoS bucket is served by at most one thread at a time.
    GuestKqueue kqueue{true};
    std::array<std::optional<std::uint64_t>, kqueueManagerBucket + 1> keventBucketThreads;
    std::map<std::uint64_t, GuestWorkloop> workloops;
};

// Guest threads multiplexed onto the one host thread that runs translated
// code. Threads switch only at block boundaries and syscalls, so guest memory,
// the translation cache, and every task-wide table stay single-threaded.
class GuestScheduler {
  public:
    static constexpr std::uint64_t mainThreadId = 1;

    GuestScheduler() = default;
    GuestScheduler(const GuestScheduler &) = delete;
    GuestScheduler &operator=(const GuestScheduler &) = delete;

    // Binds the main thread to `state`, the state the dispatcher was asked to
    // run. Rebinding replaces the pointer; the thread keeps its identity.
    void bindMainThread(x86::X86State &state);

    // Adds a runnable thread with its own copy of `initial`.
    GuestThread &create(const x86::X86State &initial);

    // The thread whose syscall is being handled or whose blocks are running.
    // Without a bound main thread this is a detached main-thread record, so
    // single-threaded callers see the main thread's identity.
    [[nodiscard]] GuestThread &current() noexcept;
    [[nodiscard]] const GuestThread &current() const noexcept;
    [[nodiscard]] GuestThread *find(std::uint64_t id) noexcept;
    [[nodiscard]] GuestThread *findByPort(GuestMachPortName port) noexcept;

    // Parks the current thread. The dispatcher switches away after the
    // syscall that called this returns.
    void block(GuestWait wait);
    // Ends the current wait of every matching waiter, oldest first, up to
    // `maximum`; returns how many were woken.
    std::size_t wake(GuestWaitKind kind, std::uint64_t channel,
                     std::size_t maximum = static_cast<std::size_t>(-1),
                     GuestWakeReason reason = GuestWakeReason::Signaled);
    // Wakes `thread` if it waits on the channel; returns whether it did.
    bool wakeThread(GuestThread &thread, GuestWaitKind kind, std::uint64_t channel);
    [[nodiscard]] std::size_t waiters(GuestWaitKind kind, std::uint64_t channel) const noexcept;

    void exitCurrent() noexcept;
    // Asks the dispatcher to give other runnable threads a turn after the
    // current syscall (thread_switch, swtch_pri, and friends).
    void requestYield() noexcept { yieldRequested_ = true; }
    [[nodiscard]] bool takeYieldRequest() noexcept { return std::exchange(yieldRequested_, false); }

    // Runs task-wide work that can wake threads, such as due kqueue timers,
    // and returns when it next needs to run.
    using ServiceEvents = std::function<std::optional<GuestClock::time_point>()>;

    // Selects the thread to run next: the current one unless it blocked,
    // exited, or `rotate` asks for round-robin. Sleeps until the earliest
    // deadline when every live thread is blocked. Returns null once every
    // thread has exited and throws when the remaining threads can never wake.
    GuestThread *schedule(bool rotate, const ServiceEvents &service = {});

    [[nodiscard]] bool hasOtherRunnable() const noexcept;
    [[nodiscard]] std::size_t liveThreadCount() const noexcept;
    [[nodiscard]] const std::vector<std::unique_ptr<GuestThread>> &threads() const noexcept {
        return threads_;
    }
    [[nodiscard]] std::string summary() const;

  private:
    // The main thread is always threads_[0], created on first use.
    void ensureMainThread();
    void expireDeadlines(GuestClock::time_point now);
    void finishWait(GuestThread &thread, GuestWakeReason reason);
    [[nodiscard]] GuestThread *nextRunnable(bool rotate) noexcept;

    std::vector<std::unique_ptr<GuestThread>> threads_;
    std::size_t current_{};
    std::uint64_t nextId_{mainThreadId + 1};
    bool yieldRequested_{};
    GuestThread detachedMain_{.id = mainThreadId};
};

} // namespace rosa::darwin
