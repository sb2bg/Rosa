#include "darwin/SyscallInternal.h"

// Guest thread lifecycle and user-space lock waits. Every guest thread runs on
// the one host thread through GuestScheduler; a call that would block in XNU
// parks the calling guest thread instead.

namespace rosa::darwin::detail {
namespace {

// libpthread's bsdthread_create flags (kern_support.c).
constexpr std::uint64_t pthreadStartCustom = 0x01000000;
constexpr std::uint64_t pthreadStartTsdBaseSet = 0x10000000;
constexpr std::uint64_t pthreadStartSuspended = 0x20000000;

// XNU's ulock ABI (bsd/sys/ulock.h).
constexpr std::uint32_t ulockOpcodeMask = 0xFF;
constexpr std::uint32_t ulockCompareAndWait = 1;
constexpr std::uint32_t ulockUnfairLock = 2;
constexpr std::uint32_t ulockCompareAndWait64 = 5;
constexpr std::uint32_t ulockWakeAll = 0x00000100;
constexpr std::uint32_t ulockWakeThread = 0x00000200;
constexpr std::uint32_t ulockWakeAllowNonOwner = 0x00000400;
constexpr std::uint32_t ulockWaitWorkqDataContention = 0x00010000;
constexpr std::uint32_t ulockWaitCancelPoint = 0x00020000;
constexpr std::uint32_t ulockWaitAdaptiveSpin = 0x00040000;
constexpr std::uint32_t ulockNoErrno = 0x01000000;
constexpr std::uint32_t ulockDeadline = 0x02000000;
constexpr std::uint32_t ulockWaitFlags = ulockNoErrno | ulockDeadline |
                                         ulockWaitWorkqDataContention | ulockWaitCancelPoint |
                                         ulockWaitAdaptiveSpin;
constexpr std::uint32_t ulockWakeFlags =
    ulockNoErrno | ulockWakeAll | ulockWakeThread | ulockWakeAllowNonOwner;
constexpr std::uint32_t machPortDead = 0xFFFFFFFF;
constexpr std::uint32_t portNameFlagBits = 0x3;
constexpr std::uint32_t machPortUrefsMaximum = 0xFFFF;

// An int-returning BSD call stores its result sign-extended in RAX.
void setIntResult(x86::X86State &state, std::int32_t result) {
    setSuccess(state, static_cast<std::uint64_t>(static_cast<std::int64_t>(result)));
}

// XNU's munge_retval: with ULF_NO_ERRNO an error becomes a negative result.
void setUlockResult(x86::X86State &state, std::uint32_t flags, int error, std::int32_t value) {
    if (error == 0) {
        setIntResult(state, value);
    } else if ((flags & ulockNoErrno) != 0) {
        setIntResult(state, -error);
    } else {
        setError(state, error);
    }
}

SyscallOutcome ulockWait(SyscallCall &call, std::uint64_t timeoutNanoseconds) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto operation = static_cast<std::uint32_t>(state.rdi);
    const auto opcode = operation & ulockOpcodeMask;
    const auto flags = operation & ~ulockOpcodeMask;
    const auto address = state.rsi;
    const auto expected = state.rdx;
    if ((flags & ~ulockWaitFlags) != 0) {
        setUlockResult(state, flags, EINVAL, 0);
        return {};
    }
    if ((flags & ulockDeadline) != 0) {
        throw unsupported(state, syscallRip, "ulock_wait2 with an absolute ULF_DEADLINE");
    }
    std::size_t width = 0;
    switch (opcode) {
    case ulockCompareAndWait:
    case ulockUnfairLock:
        width = sizeof(std::uint32_t);
        break;
    case ulockCompareAndWait64:
        width = sizeof(std::uint64_t);
        break;
    default:
        // The shared opcodes key on a VM object; no guest memory is shared
        // with another process.
        setUlockResult(state, flags, EINVAL, 0);
        return {};
    }
    if (address == 0 || (address & (width - 1)) != 0) {
        setUlockResult(state, flags, EINVAL, 0);
        return {};
    }

    auto &scheduler = task.scheduler;
    const auto otherWaiters =
        static_cast<std::int32_t>(scheduler.waiters(GuestWaitKind::Ulock, address));
    std::uint64_t value{};
    try {
        value = width == sizeof(std::uint32_t)
                    ? addressSpace.readU32(guest::GuestAddress{address})
                    : addressSpace.readU64(guest::GuestAddress{address});
    } catch (const std::runtime_error &) {
        setUlockResult(state, flags, EFAULT, otherWaiters);
        return {};
    }
    if (value != expected) {
        setUlockResult(state, flags, 0, otherWaiters);
        return {};
    }
    if (opcode == ulockUnfairLock) {
        // The lock word names its owner's thread port; the low bits are
        // userland flags. A dead name waits ownerless, as in XNU.
        const auto ownerName = static_cast<std::uint32_t>(value) | portNameFlagBits;
        if (ownerName != machPortDead) {
            const auto *owner = scheduler.findByPort(GuestMachPortName{ownerName});
            if (owner == nullptr || owner == &scheduler.current()) {
                setUlockResult(state, flags, EOWNERDEAD, otherWaiters);
                return {};
            }
        }
    }
    GuestWait wait{
        .kind = GuestWaitKind::Ulock,
        .channel = address,
        .complete =
            [&scheduler, flags, address](x86::X86State &waiter, GuestWakeReason reason) {
                const auto remaining =
                    static_cast<std::int32_t>(scheduler.waiters(GuestWaitKind::Ulock, address));
                setUlockResult(waiter, flags, reason == GuestWakeReason::TimedOut ? ETIMEDOUT : 0,
                               remaining);
            },
    };
    if (timeoutNanoseconds != 0) {
        wait.deadline = GuestClock::now() + std::chrono::nanoseconds{timeoutNanoseconds};
    }
    std::ostringstream description;
    description << "ulock_wait 0x" << std::hex << address << " value=0x" << expected;
    wait.description = description.str();
    scheduler.block(std::move(wait));
    return {};
}

} // namespace

SyscallOutcome handleBsdthreadCreate(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto function = state.rdi;
    const auto argument = state.rsi;
    const auto stack = state.rdx;
    const auto pthread = state.r10;
    auto flags = static_cast<std::uint32_t>(state.r8);
    if (!task.pthreadRegistration || (flags & pthreadStartCustom) == 0) {
        setError(state, EINVAL);
        return {};
    }
    if ((flags & pthreadStartSuspended) != 0) {
        throw unsupported(state, syscallRip, "bsdthread_create with PTHREAD_START_SUSPENDED");
    }
    const auto &registration = *task.pthreadRegistration;

    // A new guest thread starts at libpthread's thread_start with the
    // registers XNU's _bsdthread_create sets, its stack pointer at the
    // caller's stack top, and its TSD base inside the caller's pthread_t.
    x86::X86State initial;
    const auto tsdBase = pthread + registration.tsdOffset;
    initial.gsBase = tsdBase;
    flags |= pthreadStartTsdBaseSet;
    initial.rip = registration.threadStart.value;
    initial.rdi = pthread;
    initial.rdx = function;
    initial.rcx = argument;
    initial.r8 = stack;
    initial.r9 = flags;
    initial.rsp = stack;

    auto &thread = task.scheduler.create(initial);
    auto &ports = task.machDispatcher.portSpace();
    const auto port = ports.copyoutThreadSendRight(thread.id, machPortUrefsMaximum);
    if (!port) {
        thread.status = GuestThreadStatus::Exited;
        throw unsupported(state, syscallRip, "guest port namespace exhausted creating a thread");
    }
    thread.port = port;
    thread.state->rsi = port->value;
    if (registration.machThreadSelfOffset != 0) {
        try {
            addressSpace.writeU64(guest::GuestAddress{tsdBase + registration.machThreadSelfOffset},
                                  port->value);
        } catch (const std::runtime_error &) {
            thread.status = GuestThreadStatus::Exited;
            static_cast<void>(ports.deallocateUref(*port));
            setError(state, EFAULT);
            return {};
        }
    }
    setSuccess(state, pthread);
    return {};
}

SyscallOutcome handleBsdthreadTerminate(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    const auto stackAddress = state.rdi;
    const auto freeSize = state.rsi;
    const auto port = static_cast<std::uint32_t>(state.rdx);
    const auto semaphore = static_cast<std::uint32_t>(state.r10);
    if (semaphore != 0) {
        throw unsupported(state, syscallRip,
                          "bsdthread_terminate signaling a custom-stack semaphore");
    }
    if (task.scheduler.current().id == GuestScheduler::mainThreadId) {
        throw unsupported(state, syscallRip, "bsdthread_terminate on the main thread");
    }
    if (stackAddress != 0 && freeSize != 0) {
        // XNU ignores a failed deallocation here; the thread exits anyway.
        static_cast<void>(addressSpace.deallocate(guest::GuestAddress{stackAddress}, freeSize));
    }
    if (port != 0) {
        static_cast<void>(
            task.machDispatcher.portSpace().deallocateUref(GuestMachPortName{port}));
    }
    task.scheduler.exitCurrent();
    return {};
}

SyscallOutcome handleDisableThreadsignal(SyscallCall &call) {
    // XNU marks the thread so no further signals are delivered to it.
    call.task.scheduler.current().signalsDisabled = true;
    setSuccess(call.state, 0);
    return {};
}

// __pthread_sigmask and sigprocmask both act on the calling thread's mask.
SyscallOutcome handlePthreadSigmask(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    constexpr std::uint64_t signalBlock = 1;
    constexpr std::uint64_t signalUnblock = 2;
    constexpr std::uint64_t signalSetMask = 3;
    // SIGKILL and SIGSTOP can never be masked.
    constexpr std::uint32_t unmaskable = (1U << (9 - 1)) | (1U << (17 - 1));
    auto &thread = task.scheduler.current();
    const auto previous = thread.signalMask;
    std::optional<std::uint32_t> requested;
    if (state.rsi != 0) {
        if (state.rdi != signalBlock && state.rdi != signalUnblock && state.rdi != signalSetMask) {
            setError(state, EINVAL);
            return {};
        }
        try {
            requested = addressSpace.readU32(guest::GuestAddress{state.rsi});
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
    }
    if (state.rdx != 0) {
        try {
            addressSpace.writeU32(guest::GuestAddress{state.rdx}, previous);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
    }
    if (requested) {
        auto next = state.rdi == signalBlock     ? previous | *requested
                    : state.rdi == signalUnblock ? previous & ~*requested
                                                 : *requested;
        thread.signalMask = next & ~unmaskable;
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleUlockWait(SyscallCall &call) {
    // ulock_wait's timeout is in microseconds; zero waits forever.
    const auto microseconds = static_cast<std::uint32_t>(call.state.r10);
    return ulockWait(call, std::uint64_t{microseconds} * 1000U);
}

SyscallOutcome handleUlockWait2(SyscallCall &call) { return ulockWait(call, call.state.r10); }

SyscallOutcome handleUlockWake(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    const auto operation = static_cast<std::uint32_t>(state.rdi);
    const auto opcode = operation & ulockOpcodeMask;
    const auto flags = operation & ~ulockOpcodeMask;
    const auto address = state.rsi;
    if (opcode != ulockCompareAndWait && opcode != ulockUnfairLock &&
        opcode != ulockCompareAndWait64) {
        setUlockResult(state, flags, EINVAL, 0);
        return {};
    }
    if ((flags & ~ulockWakeFlags) != 0 ||
        ((flags & ulockWakeThread) != 0 &&
         ((flags & ulockWakeAll) != 0 || opcode == ulockUnfairLock)) ||
        ((flags & ulockWakeAllowNonOwner) != 0 && opcode != ulockUnfairLock) || address == 0) {
        setUlockResult(state, flags, EINVAL, 0);
        return {};
    }

    auto &scheduler = task.scheduler;
    GuestThread *target = nullptr;
    if ((flags & ulockWakeThread) != 0) {
        target = scheduler.findByPort(GuestMachPortName{static_cast<std::uint32_t>(state.rdx)});
        if (target == nullptr || target == &scheduler.current()) {
            setUlockResult(state, flags, ESRCH, 0);
            return {};
        }
    }
    if (scheduler.waiters(GuestWaitKind::Ulock, address) == 0) {
        setUlockResult(state, flags, ENOENT, 0);
        return {};
    }
    // An unfair-lock wake from a thread other than the recorded owner is
    // dropped by XNU; waking anyway is safe because every ulock caller
    // re-checks its lock word after waking.
    int error = 0;
    if (target != nullptr) {
        error = scheduler.wakeThread(*target, GuestWaitKind::Ulock, address) ? 0 : EALREADY;
    } else {
        static_cast<void>(scheduler.wake(GuestWaitKind::Ulock, address,
                                         (flags & ulockWakeAll) != 0 ? SIZE_MAX : 1U));
    }
    setUlockResult(state, flags, error, 0);
    return {};
}

} // namespace rosa::darwin::detail
