#include "darwin/SyscallInternal.h"

// kevent_qos on the workqueue kqueue and kevent_id on dispatch workloops (XNU
// kevent_internal and the EVFILT_WORKLOOP filter). libdispatch registers its
// sources and serial-queue thread requests here; ready work reaches the guest
// on workqueue threads through serviceWorkqueue.

namespace rosa::darwin::detail {
namespace {

constexpr std::uint32_t keventFlagImmediate = 0x000001;
constexpr std::uint32_t keventFlagErrorEvents = 0x000002;
constexpr std::uint32_t keventFlagStackData = 0x000008;
constexpr std::uint32_t keventFlagWorkqueue = 0x000020;
constexpr std::uint32_t keventFlagWorkloop = 0x000400;
constexpr std::uint32_t keventFlagDynamicKqueueMustExist = 0x020000;
constexpr std::uint32_t keventFlagDynamicKqueueMustNotExist = 0x040000;
constexpr std::uint32_t keventQosFlagsModeled =
    keventFlagImmediate | keventFlagErrorEvents | keventFlagStackData | keventFlagWorkqueue;
constexpr std::uint32_t keventIdFlagsModeled =
    keventFlagImmediate | keventFlagErrorEvents | keventFlagStackData | keventFlagWorkloop |
    keventFlagDynamicKqueueMustExist | keventFlagDynamicKqueueMustNotExist;

// EVFILT_WORKLOOP fflags (event_private.h).
constexpr std::uint32_t noteWorkloopThreadRequest = 0x00000001;
constexpr std::uint32_t noteWorkloopSyncWait = 0x00000004;
constexpr std::uint32_t noteWorkloopSyncWake = 0x00000008;
constexpr std::uint32_t noteWorkloopSyncIpc = 0x80000000;
constexpr std::uint32_t noteWorkloopCommandsMask = 0x8000000F;
constexpr std::uint32_t noteWorkloopUpdateQos = 0x00000010;
constexpr std::uint32_t noteWorkloopEndOwnership = 0x00000020;
constexpr std::uint32_t noteWorkloopDiscoverOwner = 0x00000080;
constexpr std::uint32_t noteWorkloopIgnoreStale = 0x00000100;
constexpr std::uint32_t noteWorkloopUpdatesMask = 0x000001F0;
// kevent ext[] slots of a workloop debounce (EV_EXTIDX_WL_*).
constexpr std::size_t workloopDebounceAddress = 1;
constexpr std::size_t workloopDebounceMask = 2;
constexpr std::size_t workloopDebounceValue = 3;

constexpr std::uint32_t pthreadPrioritySchedulingPriority = 0x20000000;
constexpr std::uint32_t pthreadPriorityValidQosMask = 0x00003F00;
constexpr std::uint32_t portNameFlagBits = 0x3;

std::uint32_t threadQos(std::int32_t priority) {
    const auto value = static_cast<std::uint32_t>(priority);
    if ((value & pthreadPrioritySchedulingPriority) != 0) {
        return 0;
    }
    const auto bits = (value & pthreadPriorityValidQosMask) >> 8U;
    return bits == 0 ? 0 : static_cast<std::uint32_t>(std::countr_zero(bits)) + 1;
}

struct WorkloopContext {
    guest::AddressSpace &addressSpace;
    GuestScheduler &scheduler;
    GuestThread &current;
};

// XNU's filt_wlupdate: the debounce against the queue's state word and the
// workloop owner it may discover or end.
int updateWorkloop(WorkloopContext &context, GuestWorkloop &workloop, GuestKevent &change) {
    auto owner = workloop.owner;
    const auto address = change.ext[workloopDebounceAddress];
    if (address != 0) {
        std::uint64_t current{};
        try {
            current = context.addressSpace.readU64(guest::GuestAddress{address});
        } catch (const std::runtime_error &) {
            return EFAULT;
        }
        const auto expected = change.ext[workloopDebounceValue];
        const auto mask = change.ext[workloopDebounceMask];
        change.ext[workloopDebounceValue] = current;
        if ((current & mask) != (expected & mask)) {
            return ESTALE;
        }
        if ((change.fflags & noteWorkloopDiscoverOwner) != 0) {
            const auto name = static_cast<std::uint32_t>(current) & ~portNameFlagBits;
            if (name != 0) {
                const auto *thread =
                    context.scheduler.findByPort(GuestMachPortName{name | portNameFlagBits});
                if (thread == nullptr) {
                    return EOWNERDEAD;
                }
                owner = thread->id;
            }
        }
    }
    if ((change.fflags & noteWorkloopEndOwnership) != 0 && owner == context.current.id) {
        owner.reset();
    }
    workloop.owner = owner;
    return 0;
}

int staleUnlessIgnored(int error, const GuestKevent &change) {
    return error == ESTALE && (change.fflags & noteWorkloopIgnoreStale) != 0 ? 0 : error;
}

void wakeSyncWaiter(WorkloopContext &context, GuestWorkloop::SyncKnote &knote,
                    std::uint64_t ident) {
    if (!knote.waiter) {
        return;
    }
    if (auto *thread = context.scheduler.find(*knote.waiter)) {
        static_cast<void>(
            context.scheduler.wakeThread(*thread, GuestWaitKind::WorkloopSync, ident));
    }
    knote.waiter.reset();
}

// One EVFILT_WORKLOOP change (filt_wlattach, filt_wltouch, filt_wlallow_drop).
// Sets `wait` when the calling thread must park as a dispatch_sync waiter.
// Like XNU's kevent_register, it updates `change` in place, so an error
// event reports the normalized flags and the debounce's current value.
int applyWorkloopChange(WorkloopContext &context, GuestWorkloop &workloop, GuestKevent &change,
                        bool &wait) {
    if ((change.flags & evDelete) != 0) {
        change.flags &= static_cast<std::uint16_t>(~evAdd);
    }
    if ((change.flags & evDisable) != 0) {
        change.flags &= static_cast<std::uint16_t>(~evEnable);
    }
    const auto command = change.fflags & noteWorkloopCommandsMask;
    const auto deleting = (change.flags & evDelete) != 0;
    if ((change.fflags & noteWorkloopDiscoverOwner) != 0 && deleting) {
        return EINVAL;
    }
    if (command == noteWorkloopThreadRequest) {
        if (!workloop.threadRequest) {
            if ((change.flags & evAdd) == 0) {
                return ENOENT;
            }
            if (change.ident != workloop.id) {
                return EINVAL;
            }
            if (threadQos(change.qos) == 0) {
                return ERANGE;
            }
            if (const auto error = updateWorkloop(context, workloop, change); error != 0) {
                return staleUnlessIgnored(error, change);
            }
            change.flags |= evClear;
            workloop.threadRequest = change;
            workloop.threadRequestDelivered = false;
            return 0;
        }
        if ((change.fflags & noteWorkloopUpdateQos) != 0 && (deleting || threadQos(change.qos) == 0)) {
            return deleting ? EINVAL : ERANGE;
        }
        if (const auto error = updateWorkloop(context, workloop, change); error != 0) {
            return staleUnlessIgnored(error, change);
        }
        if (deleting) {
            workloop.threadRequest.reset();
            workloop.threadRequestDelivered = false;
            return 0;
        }
        auto &request = *workloop.threadRequest;
        request.fflags = (request.fflags & ~noteWorkloopUpdatesMask) | change.fflags;
        if ((change.fflags & noteWorkloopUpdateQos) != 0) {
            request.qos = change.qos;
        }
        request.udata = change.udata;
        request.ext = change.ext;
        return 0;
    }
    if (command == noteWorkloopSyncWait || command == noteWorkloopSyncWake) {
        auto found = workloop.syncKnotes.find(change.ident);
        if (found == workloop.syncKnotes.end()) {
            if ((change.flags & evAdd) == 0) {
                return ENOENT;
            }
            if (change.ident == workloop.id || (change.flags & evDisable) == 0 ||
                (change.fflags & noteWorkloopEndOwnership) != 0) {
                return EINVAL;
            }
            if (const auto error = updateWorkloop(context, workloop, change); error != 0) {
                return staleUnlessIgnored(error, change);
            }
            auto &knote = workloop.syncKnotes[change.ident];
            knote.registration = change;
            knote.savedFilterFlags = change.fflags;
            if (command == noteWorkloopSyncWait) {
                knote.waiter = context.current.id;
                wait = true;
            }
            return 0;
        }
        auto &knote = found->second;
        if ((knote.savedFilterFlags & (noteWorkloopSyncWait | noteWorkloopSyncWake)) == 0 ||
            (!deleting && (change.flags & (evEnable | evDelete)) == evEnable)) {
            return EINVAL;
        }
        if (const auto error = updateWorkloop(context, workloop, change); error != 0) {
            return staleUnlessIgnored(error, change);
        }
        if (deleting) {
            wakeSyncWaiter(context, knote, change.ident);
            workloop.syncKnotes.erase(found);
            return 0;
        }
        knote.savedFilterFlags = (knote.savedFilterFlags & ~noteWorkloopUpdatesMask) | change.fflags;
        if ((change.fflags & noteWorkloopSyncWake) != 0) {
            wakeSyncWaiter(context, knote, change.ident);
        }
        if (command == noteWorkloopSyncWait &&
            (knote.savedFilterFlags & noteWorkloopSyncWake) == 0) {
            knote.waiter = context.current.id;
            wait = true;
        }
        return 0;
    }
    if (command == noteWorkloopSyncIpc) {
        throw std::runtime_error("EVFILT_WORKLOOP NOTE_WL_SYNC_IPC is not modeled");
    }
    return EINVAL;
}

bool workloopEmpty(const GuestWorkloop &workloop) {
    return !workloop.threadRequest && workloop.syncKnotes.empty() && workloop.sources.size() == 0 &&
           !workloop.servicer;
}

// Applies a change list to a workloop as kevent_internal does, writing
// EV_ERROR/EV_RECEIPT results to `errors` while room remains. Returns the
// errno that fails the whole call, if any.
int applyWorkloopChanges(WorkloopContext &context, GuestWorkloop &workloop,
                         std::span<const GuestKevent> changes, std::size_t room,
                         std::vector<GuestKevent> &errors, bool &wait, std::uint64_t now) {
    for (auto change : changes) {
        int result = 0;
        if (change.filter == evfiltWorkloop) {
            result = applyWorkloopChange(context, workloop, change, wait);
        } else {
            result = workloop.sources.registerChange(change, now);
        }
        if (result != 0) {
            change.flags |= evError;
            change.data = result;
        }
        if (errors.size() < room && (change.flags & (evError | evReceipt)) != 0) {
            if ((change.flags & evError) == 0) {
                change.flags |= evError;
                change.data = 0;
            }
            errors.push_back(change);
        } else if ((change.flags & evError) != 0) {
            return static_cast<int>(change.data);
        }
    }
    return 0;
}

std::vector<GuestKevent> readKevents(const guest::AddressSpace &addressSpace,
                                     std::uint64_t address, std::size_t count) {
    std::vector<GuestKevent> events;
    if (count == 0) {
        return events;
    }
    const auto bytes = addressSpace.readBytes(guest::GuestAddress{address}, count * GuestKevent::size);
    for (std::size_t index = 0; index < count; ++index) {
        events.push_back(GuestKevent::decode(std::span{bytes}.subspan(index * GuestKevent::size)));
    }
    return events;
}

void writeKevents(guest::AddressSpace &addressSpace, std::uint64_t address,
                  std::span<const GuestKevent> events) {
    std::vector<std::uint8_t> bytes(events.size() * GuestKevent::size);
    for (std::size_t index = 0; index < events.size(); ++index) {
        events[index].encode(std::span{bytes}.subspan(index * GuestKevent::size));
    }
    if (!bytes.empty()) {
        addressSpace.writeBytes(guest::GuestAddress{address}, bytes);
    }
}

} // namespace

bool workloopDeliverable(const GuestWorkloop &workloop) {
    return !workloop.servicer &&
           ((workloop.threadRequest && !workloop.threadRequestDelivered && !workloop.owner) ||
            workloop.sources.hasReadyEvents(0));
}

std::vector<GuestKevent> collectWorkloopEvents(GuestWorkloop &workloop, std::size_t maximum,
                                               std::uint64_t now, std::uint64_t thread) {
    std::vector<GuestKevent> events;
    // filt_wlprocess: an owned workloop's thread request waits for the owner.
    if (workloop.threadRequest && !workloop.threadRequestDelivered && !workloop.owner &&
        maximum > 0) {
        auto event = *workloop.threadRequest;
        event.data = 0;
        events.push_back(event);
        workloop.threadRequestDelivered = true;
    }
    workloop.sources.expireTimers(now);
    auto sources = workloop.sources.process(std::nullopt, maximum - events.size(), now, thread);
    events.insert(events.end(), sources.begin(), sources.end());
    return events;
}

std::uint32_t workloopRequestPriority(const GuestWorkloop &workloop) {
    return workloop.threadRequest ? static_cast<std::uint32_t>(workloop.threadRequest->qos) : 0;
}

void releaseWorkloopServicer(GuestWorkqueue &workqueue, GuestThread &thread) {
    if (!thread.workloop) {
        return;
    }
    if (const auto found = workqueue.workloops.find(*thread.workloop);
        found != workqueue.workloops.end()) {
        found->second.servicer.reset();
        found->second.threadRequestDelivered = false;
        found->second.sources.unsuppress(thread.id);
        if (workloopEmpty(found->second)) {
            workqueue.workloops.erase(found);
        }
    }
    thread.workloop.reset();
}

// WQOPS_THREAD_WORKLOOP_RETURN: applies the servicer's changes and returns
// the events it must handle next, errors first, or none to release it.
std::vector<GuestKevent> returnWorkloopServicer(guest::AddressSpace &addressSpace, GuestTask &task,
                                                GuestThread &thread,
                                                std::span<const GuestKevent> changes,
                                                std::size_t room) {
    auto &workloop = task.workqueue.workloops.at(*thread.workloop);
    WorkloopContext context{addressSpace, task.scheduler, thread};
    const auto now = guestMachAbsoluteTime();
    std::vector<GuestKevent> events;
    bool wait = false;
    static_cast<void>(applyWorkloopChanges(context, workloop, changes, room, events, wait, now));
    if (wait) {
        throw std::runtime_error("a workloop servicer parked in NOTE_WL_SYNC_WAIT while returning");
    }
    workloop.threadRequestDelivered = false;
    workloop.sources.unsuppress(thread.id);
    if (events.size() < room) {
        auto more = collectWorkloopEvents(workloop, room - events.size(), now, thread.id);
        events.insert(events.end(), more.begin(), more.end());
    }
    return events;
}

SyscallOutcome handleKeventQos(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto changelist = state.rsi;
    const auto changeCount = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdx));
    const auto eventlist = state.r10;
    const auto eventCount = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.r8));
    // x86_64 passes arguments beyond the sixth on the user stack, above the
    // stub's return address.
    std::uint32_t flags{};
    try {
        flags = addressSpace.readU32(guest::GuestAddress{state.rsp + 16U});
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    if ((flags & ~keventQosFlagsModeled) != 0 || (flags & keventFlagWorkqueue) == 0) {
        std::ostringstream reason;
        reason << "kevent_qos with flags 0x" << std::hex << flags
               << " (only the workqueue kqueue is modeled)";
        throw unsupported(state, syscallRip, reason.str());
    }
    if (changeCount < 0 || eventCount < 0) {
        setError(state, EINVAL);
        return {};
    }

    auto &kqueue = task.workqueue.kqueue;
    const auto now = guestMachAbsoluteTime();
    int error = 0;
    std::vector<GuestKevent> outputs;
    std::vector<GuestKevent> changes;
    try {
        changes = readKevents(addressSpace, changelist, static_cast<std::size_t>(changeCount));
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    for (auto change : changes) {
        int result = 0;
        try {
            result = kqueue.registerChange(change, now);
        } catch (const std::runtime_error &modelError) {
            throw unsupported(state, syscallRip, modelError.what());
        }
        if (result != 0) {
            change.flags |= evError;
            change.data = result;
        }
        // A change reports through the event list when there is room and it
        // failed or asked for a receipt; otherwise a failure fails the call.
        if (outputs.size() < static_cast<std::size_t>(eventCount) &&
            (change.flags & (evError | evReceipt)) != 0) {
            if ((change.flags & evError) == 0) {
                change.flags |= evError;
                change.data = 0;
            }
            outputs.push_back(change);
        } else if ((change.flags & evError) != 0) {
            error = static_cast<int>(change.data);
            break;
        }
    }

    if (error == 0 && (flags & keventFlagErrorEvents) == 0 && eventCount > 0 && outputs.empty()) {
        auto &current = task.scheduler.current();
        if (!current.keventBucket) {
            throw unsupported(state, syscallRip,
                              "kevent_qos collecting workqueue events outside a kevent thread");
        }
        kqueue.expireTimers(now);
        outputs = kqueue.process(*current.keventBucket, static_cast<std::size_t>(eventCount), now,
                                 current.id);
    }
    try {
        writeKevents(addressSpace, eventlist, outputs);
    } catch (const std::runtime_error &) {
        error = EFAULT;
    }
    if (error != 0) {
        setError(state, error);
    } else {
        setSuccess(state, outputs.size());
    }
    // Registration may have triggered events that need a thread.
    serviceWorkqueue(addressSpace, task, nullptr);
    return {};
}

SyscallOutcome handleKeventId(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto id = state.rdi;
    const auto changelist = state.rsi;
    const auto changeCount = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.rdx));
    const auto eventlist = state.r10;
    const auto eventCount = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.r8));
    std::uint32_t flags{};
    try {
        flags = addressSpace.readU32(guest::GuestAddress{state.rsp + 16U});
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    if ((flags & ~keventIdFlagsModeled) != 0) {
        std::ostringstream reason;
        reason << "kevent_id with flags 0x" << std::hex << flags;
        throw unsupported(state, syscallRip, reason.str());
    }
    if (changeCount < 0 || eventCount < 0 || id == 0) {
        setError(state, EINVAL);
        return {};
    }
    auto &workloops = task.workqueue.workloops;
    auto found = workloops.find(id);
    if (found == workloops.end() && (flags & keventFlagDynamicKqueueMustExist) != 0) {
        setError(state, ENOENT);
        return {};
    }
    if (found != workloops.end() && (flags & keventFlagDynamicKqueueMustNotExist) != 0) {
        setError(state, EEXIST);
        return {};
    }
    if (found == workloops.end()) {
        found = workloops.emplace(id, GuestWorkloop{.id = id}).first;
    }
    auto &workloop = found->second;

    std::vector<GuestKevent> changes;
    try {
        changes = readKevents(addressSpace, changelist, static_cast<std::size_t>(changeCount));
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    auto &current = task.scheduler.current();
    WorkloopContext context{addressSpace, task.scheduler, current};
    const auto now = guestMachAbsoluteTime();
    std::vector<GuestKevent> outputs;
    bool wait = false;
    int error = 0;
    try {
        error = applyWorkloopChanges(context, workloop, changes,
                                     static_cast<std::size_t>(eventCount), outputs, wait, now);
    } catch (const std::runtime_error &modelError) {
        throw unsupported(state, syscallRip, modelError.what());
    }
    if (error == 0 && !wait && (flags & keventFlagErrorEvents) == 0 && eventCount > 0 &&
        outputs.empty()) {
        if (workloop.servicer != current.id) {
            throw unsupported(state, syscallRip,
                              "kevent_id collecting workloop events outside its servicer");
        }
        outputs = collectWorkloopEvents(workloop, static_cast<std::size_t>(eventCount), now,
                                        current.id);
    }
    try {
        writeKevents(addressSpace, eventlist, outputs);
    } catch (const std::runtime_error &) {
        error = EFAULT;
    }
    if (error != 0) {
        setError(state, error);
    } else {
        setSuccess(state, outputs.size());
    }
    if (wait) {
        // A dispatch_sync waiter parks until a NOTE_WL_SYNC_WAKE or the
        // knote's deletion wakes it; the call then returns its outputs.
        const auto ident = changes.back().ident;
        const auto count = outputs.size();
        std::ostringstream description;
        description << "workloop 0x" << std::hex << id << " sync wait 0x" << ident;
        task.scheduler.block(GuestWait{
            .kind = GuestWaitKind::WorkloopSync,
            .channel = ident,
            .complete =
                [count](x86::X86State &waiter, GuestWakeReason) { setSuccess(waiter, count); },
            .description = description.str(),
        });
    }
    if (workloopEmpty(workloop)) {
        workloops.erase(found);
    }
    serviceWorkqueue(addressSpace, task, nullptr);
    return {};
}

} // namespace rosa::darwin::detail
