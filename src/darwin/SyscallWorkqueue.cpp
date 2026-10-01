#include "darwin/SyscallInternal.h"

// The pthread workqueue (XNU bsd/pthread/pthread_workqueue.c). libdispatch
// asks for threads at a QoS; each request becomes an upcall into libpthread's
// _pthread_wqthread on a workqueue thread with a kernel-allocated stack. A
// thread that returns either takes the next pending request or parks idle.

namespace rosa::darwin::detail {
namespace {

// workq_kernreturn operations (workqueue_syscalls.h).
constexpr std::uint64_t wqopsThreadReturn = 0x004;
constexpr std::uint64_t wqopsQueueNewSpiSupport = 0x010;
constexpr std::uint64_t wqopsQueueRequestThreads = 0x020;
constexpr std::uint64_t wqopsThreadKeventReturn = 0x040;
constexpr std::uint64_t wqopsSetEventManagerPriority = 0x080;
constexpr std::uint64_t wqopsThreadWorkloopReturn = 0x100;
constexpr std::uint64_t wqopsShouldNarrow = 0x200;
constexpr std::uint64_t wqopsSetupDispatch = 0x400;

// Upcall flags passed to _pthread_wqthread.
constexpr std::uint32_t wqFlagThreadPriorityQos = 0x00004000;
constexpr std::uint32_t wqFlagThreadOvercommit = 0x00010000;
constexpr std::uint32_t wqFlagThreadReuse = 0x00020000;
constexpr std::uint32_t wqFlagThreadNewSpi = 0x00040000;
constexpr std::uint32_t wqFlagThreadKevent = 0x00080000;
constexpr std::uint32_t wqFlagThreadEventManager = 0x00100000;
constexpr std::uint32_t wqFlagThreadTsdBaseSet = 0x00200000;
constexpr std::uint32_t wqFlagThreadWorkloop = 0x00400000;
// THREAD_QOS_LEGACY, reported alongside the event-manager flag.
constexpr std::uint32_t threadQosLegacy = 4;

// pthread_priority_t layout (priority_private.h).
constexpr std::uint64_t pthreadPriorityOvercommit = 0x80000000;
constexpr std::uint64_t pthreadPrioritySchedulingPriority = 0x20000000;
constexpr std::uint64_t pthreadPriorityValidQosMask = 0x00003F00;
constexpr unsigned pthreadPriorityQosShift = 8;
constexpr std::uint64_t pthreadPriorityPriorityMask = 0xFF;

// struct workq_dispatch_config: version, flags, serial-number offset, then
// (version 2) the label offset.
constexpr std::size_t dispatchConfigSize = 24;

// PTH_DEFAULT_STACKSIZE below an x86_64 pthread_t (PTHREAD_T_OFFSET is zero).
constexpr std::uint64_t workqueueStackSize = 512U * 1024U;
constexpr std::uint64_t workqueueGuardSize = guest::guestPageSize;
constexpr std::uint64_t workqueueStackAlignment = 16;
// WQ_KEVENT_LIST_LEN events sit just below the pthread_t, above the stack.
constexpr std::size_t workqueueKeventListLength = 16;
// More concurrency buys nothing on one host thread; requests beyond this wait
// for a worker to return.
constexpr std::size_t maximumWorkqueueThreads = 64;
constexpr std::uint32_t machPortUrefsMaximum = 0xFFFF;

// _pthread_priority_thread_qos: zero for a scheduling priority or no QoS.
std::uint32_t threadQos(std::uint64_t priority) {
    if ((priority & pthreadPrioritySchedulingPriority) != 0) {
        return 0;
    }
    const auto bits = (priority & pthreadPriorityValidQosMask) >> pthreadPriorityQosShift;
    return bits == 0 ? 0 : static_cast<std::uint32_t>(std::countr_zero(bits)) + 1;
}

// _pthread_priority_relpri: the encoded relative priority, at most zero.
std::int32_t relativePriority(std::uint64_t priority) {
    return static_cast<std::int8_t>(static_cast<std::uint8_t>(
               (priority & pthreadPriorityPriorityMask))) +
           1;
}

std::size_t liveWorkqueueThreads(const GuestScheduler &scheduler) {
    return static_cast<std::size_t>(
        std::ranges::count_if(scheduler.threads(), [](const auto &thread) {
            return thread->workqueue && thread->status != GuestThreadStatus::Exited;
        }));
}

GuestThread *idleWorkqueueThread(GuestScheduler &scheduler) {
    for (const auto &thread : scheduler.threads()) {
        if (thread->workqueue && thread->status == GuestThreadStatus::Blocked && thread->wait &&
            thread->wait->kind == GuestWaitKind::WorkqueueIdle) {
            return thread.get();
        }
    }
    return nullptr;
}

// XNU's workq_create_threadstack: guard page lowest, then the stack, then
// the pthread_t, with the stack pointer just below the pthread_t.
GuestThread *createWorkqueueThread(guest::AddressSpace &addressSpace, GuestTask &task) {
    constexpr auto pageMask = static_cast<std::uint64_t>(guest::guestPageSize - 1U);
    const auto pthreadSize = (task.pthreadRegistration->pthreadSize + pageMask) & ~pageMask;
    const auto size = workqueueGuardSize + workqueueStackSize + pthreadSize;
    const auto base = findMmapRange(addressSpace, size);
    if (!base) {
        throw std::runtime_error("guest address space exhausted for a workqueue stack");
    }
    constexpr auto readWrite = guest::Permission::Read | guest::Permission::Write;
    addressSpace.mapAnonymous(*base, static_cast<std::size_t>(size), readWrite,
                              readWrite | guest::Permission::Execute, "workqueue thread stack");
    if (addressSpace.protect(*base, workqueueGuardSize, guest::Permission::None) !=
        guest::ProtectResult::Success) {
        throw std::runtime_error("cannot protect a workqueue stack guard page");
    }

    auto &thread = task.scheduler.create(x86::X86State{});
    const auto port =
        task.machDispatcher.portSpace().copyoutThreadSendRight(thread.id, machPortUrefsMaximum);
    if (!port) {
        thread.status = GuestThreadStatus::Exited;
        throw std::runtime_error("guest port namespace exhausted creating a workqueue thread");
    }
    thread.port = port;
    thread.workqueue = true;
    thread.workqueueStackAddress = base->value;
    thread.workqueueSelf = base->value + workqueueGuardSize + workqueueStackSize;
    return &thread;
}

// XNU's workq_set_register_state for an x86_64 upcall into _pthread_wqthread.
// Kevents are copied into the list just below the pthread_t and the stack
// starts beneath them (workq_kevent with no stack data used).
// A workloop servicer also finds the workloop id just below its kevent list.
void setWorkqueueUpcall(guest::AddressSpace &addressSpace, GuestThread &thread,
                        const GuestPthreadRegistration &registration, std::uint32_t flags,
                        std::span<const GuestKevent> events,
                        std::optional<std::uint64_t> workloopId = std::nullopt) {
    auto &state = *thread.state;
    state = x86::X86State{};
    std::uint64_t keventList = 0;
    auto stackTop = thread.workqueueSelf;
    if (!events.empty() || workloopId) {
        keventList = thread.workqueueSelf - workqueueKeventListLength * GuestKevent::size;
        std::vector<std::uint8_t> bytes(events.size() * GuestKevent::size);
        for (std::size_t index = 0; index < events.size(); ++index) {
            events[index].encode(std::span{bytes}.subspan(index * GuestKevent::size));
        }
        if (!bytes.empty()) {
            addressSpace.writeBytes(guest::GuestAddress{keventList}, bytes);
        }
        stackTop = keventList;
        if (workloopId) {
            stackTop -= sizeof(std::uint64_t);
            addressSpace.writeU64(guest::GuestAddress{stackTop}, *workloopId);
        }
    }
    state.rip = registration.workqueueThreadStart.value;
    state.rdi = thread.workqueueSelf;
    state.rsi = thread.port->value;
    state.rdx = thread.workqueueStackAddress + workqueueGuardSize;
    state.rcx = keventList;
    state.r8 = flags;
    state.r9 = events.size();
    state.rsp = stackTop & ~(workqueueStackAlignment - 1U);
    state.gsBase = thread.workqueueSelf + registration.tsdOffset;
}

std::uint32_t keventUpcallFlags(std::uint32_t bucket) {
    auto flags = wqFlagThreadNewSpi | wqFlagThreadKevent;
    return bucket == kqueueManagerBucket
               ? flags | wqFlagThreadEventManager | wqFlagThreadPriorityQos | threadQosLegacy
               : flags | wqFlagThreadPriorityQos | bucket;
}

std::uint32_t workloopUpcallFlags(const GuestWorkloop &workloop) {
    const auto priority = workloopRequestPriority(workloop);
    auto qos = threadQos(priority);
    if (qos == 0) {
        qos = threadQosLegacy;
    }
    auto flags = wqFlagThreadNewSpi | wqFlagThreadKevent | wqFlagThreadWorkloop |
                 wqFlagThreadPriorityQos | qos;
    if ((priority & pthreadPriorityOvercommit) != 0) {
        flags |= wqFlagThreadOvercommit;
    }
    return flags;
}

GuestWorkloop *unservicedWorkloop(GuestWorkqueue &workqueue) {
    for (auto &[id, workloop] : workqueue.workloops) {
        if (workloopDeliverable(workloop)) {
            return &workloop;
        }
    }
    return nullptr;
}

std::optional<std::uint32_t> unservedKeventBucket(const GuestWorkqueue &workqueue) {
    for (auto bucket = kqueueManagerBucket; bucket >= 1; --bucket) {
        if (!workqueue.keventBucketThreads[bucket] && workqueue.kqueue.hasReadyEvents(bucket)) {
            return bucket;
        }
    }
    return std::nullopt;
}

} // namespace

std::uint64_t guestMachAbsoluteTime() { return sampleX86TimestampCounter(); }

// Fires due workqueue-kqueue timers, then hands work to threads: ready kevent
// buckets first, then plain thread requests. Threads come from `returning`,
// then idle workers, then new ones up to the cap; a returning thread with
// nothing to do parks idle.
void serviceWorkqueue(guest::AddressSpace &addressSpace, GuestTask &task, GuestThread *returning) {
    auto &workqueue = task.workqueue;
    if (!task.pthreadRegistration) {
        return;
    }
    const auto &registration = *task.pthreadRegistration;
    const auto now = guestMachAbsoluteTime();
    workqueue.kqueue.expireTimers(now);
    for (;;) {
        const auto bucket = unservedKeventBucket(workqueue);
        auto *workloop = bucket ? nullptr : unservicedWorkloop(workqueue);
        if (!bucket && workloop == nullptr && workqueue.pending.empty()) {
            break;
        }
        GuestThread *thread = std::exchange(returning, nullptr);
        auto firstUse = false;
        if (thread == nullptr) {
            thread = idleWorkqueueThread(task.scheduler);
        }
        if (thread == nullptr && liveWorkqueueThreads(task.scheduler) < maximumWorkqueueThreads) {
            thread = createWorkqueueThread(addressSpace, task);
            firstUse = true;
        }
        if (thread == nullptr) {
            break;
        }
        thread->wait.reset();
        thread->status = GuestThreadStatus::Runnable;
        const auto reuse = firstUse ? wqFlagThreadTsdBaseSet : wqFlagThreadReuse;
        if (bucket) {
            const auto events =
                workqueue.kqueue.process(*bucket, workqueueKeventListLength, now, thread->id);
            workqueue.keventBucketThreads[*bucket] = thread->id;
            thread->keventBucket = *bucket;
            setWorkqueueUpcall(addressSpace, *thread, registration,
                               keventUpcallFlags(*bucket) | reuse, events);
            continue;
        }
        if (workloop != nullptr) {
            const auto events =
                collectWorkloopEvents(*workloop, workqueueKeventListLength, now, thread->id);
            workloop->servicer = thread->id;
            thread->workloop = workloop->id;
            setWorkqueueUpcall(addressSpace, *thread, registration,
                               workloopUpcallFlags(*workloop) | reuse, events, workloop->id);
            continue;
        }
        const auto request = workqueue.pending.front();
        workqueue.pending.erase(workqueue.pending.begin());
        auto flags = wqFlagThreadNewSpi | wqFlagThreadPriorityQos | request.qos | reuse;
        if (request.overcommit) {
            flags |= wqFlagThreadOvercommit;
        }
        setWorkqueueUpcall(addressSpace, *thread, registration, flags, {});
    }
    if (returning != nullptr) {
        task.scheduler.block(GuestWait{
            .kind = GuestWaitKind::WorkqueueIdle,
            .description = "workqueue idle",
        });
    }
}

SyscallOutcome handleWorkqOpen(SyscallCall &call) {
    call.task.workqueue.open = true;
    setSuccess(call.state, 0);
    return {};
}

SyscallOutcome handleWorkqKernreturn(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    if (!task.pthreadRegistration) {
        setError(state, EINVAL);
        return {};
    }
    const auto options = state.rdi;
    const auto item = state.rsi;
    const auto argument2 = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdx));
    const auto argument3 = static_cast<std::uint32_t>(state.r10);
    auto &workqueue = task.workqueue;
    auto &current = task.scheduler.current();
    switch (options) {
    case wqopsQueueNewSpiSupport:
        workqueue.serialNumberOffset = static_cast<std::uint64_t>(argument2);
        setSuccess(state, 0);
        return {};
    case wqopsSetupDispatch: {
        std::array<std::uint8_t, dispatchConfigSize> config{};
        const auto copied = std::min<std::size_t>(config.size(), static_cast<std::uint32_t>(argument2));
        try {
            const auto bytes = addressSpace.readBytes(guest::GuestAddress{item}, copied);
            std::ranges::copy(bytes, config.begin());
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        std::uint32_t version{};
        std::uint32_t flags{};
        std::memcpy(&version, config.data(), sizeof(version));
        std::memcpy(&flags, config.data() + 4, sizeof(flags));
        if (flags != 0 || version < 1) {
            setError(state, ENOTSUP);
            return {};
        }
        std::memcpy(&workqueue.serialNumberOffset, config.data() + 8, sizeof(std::uint64_t));
        if (version >= 2) {
            std::memcpy(&workqueue.labelOffset, config.data() + 16, sizeof(std::uint64_t));
        }
        setSuccess(state, 0);
        return {};
    }
    case wqopsQueueRequestThreads: {
        const auto qos = threadQos(argument3);
        if (argument2 <= 0 || argument2 > 0xFFFF || qos == 0) {
            setError(state, EINVAL);
            return {};
        }
        const GuestThreadRequest request{
            .qos = qos,
            .overcommit = (argument3 & pthreadPriorityOvercommit) != 0,
        };
        workqueue.pending.insert(workqueue.pending.end(), static_cast<std::size_t>(argument2),
                                 request);
        setSuccess(state, 0);
        serviceWorkqueue(addressSpace, task, nullptr);
        return {};
    }
    case wqopsSetEventManagerPriority: {
        const auto priority = static_cast<std::uint32_t>(argument2);
        if ((priority & pthreadPrioritySchedulingPriority) == 0) {
            const auto relative = relativePriority(priority);
            if (relative > 0 || threadQos(priority) == 0) {
                setError(state, EINVAL);
                return {};
            }
        }
        workqueue.eventManagerPriority = std::max(workqueue.eventManagerPriority, priority);
        setSuccess(state, 0);
        return {};
    }
    case wqopsShouldNarrow:
        if (!current.workqueue || threadQos(static_cast<std::uint32_t>(argument2)) == 0) {
            setError(state, EINVAL);
            return {};
        }
        // One host thread runs every guest thread; there is no CPU pressure
        // for narrowing to relieve.
        setSuccess(state, 0);
        return {};
    case wqopsThreadWorkloopReturn: {
        if (!current.workqueue || !current.workloop) {
            setError(state, EINVAL);
            return {};
        }
        std::vector<GuestKevent> changes;
        try {
            const auto bytes = addressSpace.readBytes(
                guest::GuestAddress{item},
                item == 0 || argument2 <= 0 ? 0
                                            : static_cast<std::size_t>(argument2) * GuestKevent::size);
            for (std::size_t offset = 0; offset < bytes.size(); offset += GuestKevent::size) {
                changes.push_back(GuestKevent::decode(std::span{bytes}.subspan(offset)));
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        std::vector<GuestKevent> events;
        try {
            events = returnWorkloopServicer(addressSpace, task, current, changes,
                                            workqueueKeventListLength);
        } catch (const std::runtime_error &error) {
            throw unsupported(state, syscallRip, error.what());
        }
        const auto id = *current.workloop;
        if (!events.empty()) {
            setWorkqueueUpcall(addressSpace, current, *task.pthreadRegistration,
                               workloopUpcallFlags(workqueue.workloops.at(id)) | wqFlagThreadReuse,
                               events, id);
            return {};
        }
        releaseWorkloopServicer(workqueue, current);
        serviceWorkqueue(addressSpace, task, &current);
        return {};
    }
    case wqopsThreadReturn:
        if (!current.workqueue || current.keventBucket || current.workloop) {
            setError(state, EINVAL);
            return {};
        }
        if (item != 0 && argument2 != 0) {
            setError(state, EINVAL);
            return {};
        }
        // The call never returns to its caller: the thread either starts a
        // fresh upcall or parks until a request rebinds it.
        serviceWorkqueue(addressSpace, task, &current);
        return {};
    case wqopsThreadKeventReturn: {
        if (!current.workqueue || !current.keventBucket) {
            setError(state, EINVAL);
            return {};
        }
        // workq_handle_stack_events: apply the thread's changes, then keep it
        // on its bucket while events remain, else release it.
        const auto bucket = *current.keventBucket;
        const auto now = guestMachAbsoluteTime();
        if (item != 0 && argument2 > 0) {
            std::vector<std::uint8_t> changes;
            try {
                changes = addressSpace.readBytes(
                    guest::GuestAddress{item},
                    static_cast<std::size_t>(argument2) * GuestKevent::size);
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
            for (std::size_t index = 0; index < static_cast<std::size_t>(argument2); ++index) {
                const auto change = GuestKevent::decode(
                    std::span{changes}.subspan(index * GuestKevent::size));
                try {
                    static_cast<void>(workqueue.kqueue.registerChange(change, now));
                } catch (const std::runtime_error &error) {
                    throw unsupported(state, syscallRip, error.what());
                }
            }
        }
        workqueue.kqueue.unsuppress(current.id);
        workqueue.kqueue.expireTimers(now);
        const auto events =
            workqueue.kqueue.process(bucket, workqueueKeventListLength, now, current.id);
        if (!events.empty()) {
            setWorkqueueUpcall(addressSpace, current, *task.pthreadRegistration,
                               keventUpcallFlags(bucket) | wqFlagThreadReuse, events);
            return {};
        }
        workqueue.keventBucketThreads[bucket].reset();
        current.keventBucket.reset();
        serviceWorkqueue(addressSpace, task, &current);
        return {};
    }
    default: {
        std::ostringstream reason;
        reason << "workq_kernreturn operation 0x" << std::hex << options;
        throw unsupported(state, syscallRip, reason.str());
    }
    }
}

} // namespace rosa::darwin::detail
