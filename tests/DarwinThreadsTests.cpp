#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

constexpr std::uint64_t bsdthreadCreate = 0x02000168;
constexpr std::uint64_t ulockWait = 0x02000203;
constexpr std::uint64_t ulockWake = 0x02000204;
constexpr std::uint64_t ulockCompareAndWait = 1;
constexpr std::uint64_t ulockUnfairLock = 2;
constexpr std::uint64_t ulockNoErrno = 0x01000000;
constexpr std::uint64_t ulockWakeAll = 0x00000100;

std::int32_t intResult(const rosa::x86::X86State &state) {
    return static_cast<std::int32_t>(static_cast<std::uint32_t>(state.rax));
}

// A bsdthread_register handshake with the observed x86_64 libpthread record.
void registerPthread(rosa::darwin::SyscallDispatcher &dispatcher,
                     rosa::guest::AddressSpace &addressSpace) {
    constexpr rosa::guest::GuestAddress codePage{0x7000};
    constexpr rosa::guest::GuestAddress dataPage{0x8000};
    std::array<std::uint8_t, 56> data{};
    const auto put64 = [&](std::size_t offset, std::uint64_t value) {
        std::memcpy(data.data() + offset, &value, sizeof(value));
    };
    const auto put32 = [&](std::size_t offset, std::uint32_t value) {
        std::memcpy(data.data() + offset, &value, sizeof(value));
    };
    put64(0, data.size());
    put64(8, 0xA0);
    put32(24, 0xE0);
    put32(28, 0x28);
    put32(32, 0x18);
    put32(48, 0x188);
    put32(52, 0x3C0);
    addressSpace.mapSegment(codePage, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute,
                            std::array<std::uint8_t, 1>{0xC3});
    addressSpace.mapAnonymous(dataPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(dataPage, data);
    rosa::x86::X86State state;
    state.rax = 0x0200016E;
    state.rdi = 0x7020;
    state.rsi = 0x7040;
    state.rdx = 0x2000;
    state.r10 = dataPage.value;
    state.r8 = data.size();
    state.r9 = 0xA0;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expect((state.rflags & carryFlag) == 0, "test bsdthread_register failed");
}

void testSchedulerRoundRobinAndWake() {
    rosa::darwin::GuestScheduler scheduler;
    rosa::x86::X86State mainState;
    scheduler.bindMainThread(mainState);
    rosa::x86::X86State initial;
    initial.rip = 0x2000;
    auto &worker = scheduler.create(initial);
    expectEqual(worker.id, std::uint64_t{2}, "second guest thread has the wrong id");
    expect(scheduler.schedule(false)->id == rosa::darwin::GuestScheduler::mainThreadId,
           "scheduler did not keep running the main thread");
    expect(scheduler.schedule(true) == &worker, "scheduler did not rotate to the new thread");
    expect(scheduler.schedule(true)->id == rosa::darwin::GuestScheduler::mainThreadId,
           "scheduler did not rotate back to the main thread");

    bool completed = false;
    scheduler.block(rosa::darwin::GuestWait{
        .kind = rosa::darwin::GuestWaitKind::Ulock,
        .channel = 0x9000,
        .complete =
            [&](rosa::x86::X86State &state, rosa::darwin::GuestWakeReason reason) {
                completed = reason == rosa::darwin::GuestWakeReason::Signaled;
                state.rax = 0x55;
            },
        .description = "test wait",
    });
    expectEqual(scheduler.waiters(rosa::darwin::GuestWaitKind::Ulock, 0x9000), std::size_t{1},
                "blocked thread is not counted as a waiter");
    expect(scheduler.schedule(false) == &worker, "scheduler ran a blocked thread");
    expectEqual(scheduler.wake(rosa::darwin::GuestWaitKind::Ulock, 0x9001), std::size_t{0},
                "a wake on another channel ended the wait");
    expectEqual(scheduler.wake(rosa::darwin::GuestWaitKind::Ulock, 0x9000), std::size_t{1},
                "wake did not end the matching wait");
    expect(completed && mainState.rax == 0x55, "wake did not complete the parked syscall");

    scheduler.exitCurrent();
    expect(scheduler.schedule(false)->id == rosa::darwin::GuestScheduler::mainThreadId,
           "scheduler kept an exited thread");
    expectEqual(scheduler.liveThreadCount(), std::size_t{1}, "exited thread is still live");
}

void testSchedulerDeadlineAndDeadlock() {
    rosa::darwin::GuestScheduler scheduler;
    rosa::x86::X86State mainState;
    scheduler.bindMainThread(mainState);
    scheduler.block(rosa::darwin::GuestWait{
        .kind = rosa::darwin::GuestWaitKind::Sleep,
        .deadline = rosa::darwin::GuestClock::now() + std::chrono::milliseconds{2},
        .complete =
            [](rosa::x86::X86State &state, rosa::darwin::GuestWakeReason reason) {
                state.rax = reason == rosa::darwin::GuestWakeReason::TimedOut ? 1 : 2;
            },
        .description = "timed sleep",
    });
    expect(scheduler.schedule(false)->id == rosa::darwin::GuestScheduler::mainThreadId,
           "scheduler did not wait for the only thread's deadline");
    expectEqual(mainState.rax, std::uint64_t{1}, "deadline did not time the wait out");

    scheduler.block(rosa::darwin::GuestWait{
        .kind = rosa::darwin::GuestWaitKind::Ulock,
        .channel = 0x9000,
        .description = "ulock_wait 0x9000",
    });
    bool threw = false;
    try {
        static_cast<void>(scheduler.schedule(false));
    } catch (const std::runtime_error &error) {
        threw = std::string_view{error.what()}.find("ulock_wait 0x9000") != std::string_view::npos;
    }
    expect(threw, "a permanently blocked process was not reported with its waits");
}

void testBsdthreadCreateRegisters() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    registerPthread(dispatcher, addressSpace);
    constexpr rosa::guest::GuestAddress pthreadPage{0x20000};
    addressSpace.mapAnonymous(pthreadPage, 0x2000,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);

    rosa::x86::X86State state;
    state.rax = bsdthreadCreate;
    state.rdi = 0x1234;           // start routine
    state.rsi = 0x5678;           // argument
    state.rdx = pthreadPage.value; // stack top
    state.r10 = pthreadPage.value; // pthread_t
    state.r8 = 0x090008FF;        // QOSCLASS | CUSTOM | legacy QoS
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expect((state.rflags & carryFlag) == 0, "bsdthread_create failed");
    expectEqual(state.rax, pthreadPage.value, "bsdthread_create did not return the pthread_t");

    const auto &threads = dispatcher.scheduler().threads();
    expectEqual(threads.size(), std::size_t{2}, "bsdthread_create did not add one thread");
    const auto &thread = *threads.back();
    const auto &created = *thread.state;
    expect(thread.port.has_value(), "new thread has no thread port");
    // XNU's _bsdthread_create register contract for x86_64.
    expectEqual(created.rip, std::uint64_t{0x7020}, "new thread does not start at thread_start");
    expectEqual(created.rdi, pthreadPage.value, "thread_start pthread_t argument differs");
    expectEqual(created.rsi, std::uint64_t{thread.port->value}, "thread port argument differs");
    expectEqual(created.rdx, std::uint64_t{0x1234}, "start routine argument differs");
    expectEqual(created.rcx, std::uint64_t{0x5678}, "start argument differs");
    expectEqual(created.r8, pthreadPage.value, "stack argument differs");
    expectEqual(created.r9, std::uint64_t{0x190008FF}, "flags lack PTHREAD_START_TSD_BASE_SET");
    expectEqual(created.rsp, pthreadPage.value, "new thread stack pointer differs");
    expectEqual(created.gsBase, pthreadPage.value + 0xE0, "TSD base differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{pthreadPage.value + 0xE0 + 0x18}),
                std::uint64_t{thread.port->value},
                "kernel did not store the thread port in the TSD slot");

    // Without PTHREAD_START_CUSTOM XNU rejects the call.
    state.rax = bsdthreadCreate;
    state.r8 = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expect((state.rflags & carryFlag) != 0 && state.rax == EINVAL,
           "bsdthread_create without PTHREAD_START_CUSTOM did not fail with EINVAL");
}

void testUlockWaitAndWake() {
    rosa::guest::AddressSpace addressSpace;
    constexpr rosa::guest::GuestAddress lockPage{0x9000};
    addressSpace.mapAnonymous(lockPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    auto &scheduler = dispatcher.scheduler();
    rosa::x86::X86State mainState;
    scheduler.bindMainThread(mainState);
    rosa::x86::X86State workerInitial;
    auto &worker = scheduler.create(workerInitial);

    // A changed value returns at once with the number of other waiters.
    addressSpace.writeU32(lockPage, 1);
    mainState.rax = ulockWait;
    mainState.rdi = ulockCompareAndWait | ulockNoErrno;
    mainState.rsi = lockPage.value;
    mainState.rdx = 0;
    mainState.r10 = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, mainState, rosa::guest::GuestAddress{0x1000}));
    expect(scheduler.current().status == rosa::darwin::GuestThreadStatus::Runnable &&
               mainState.rax == 0,
           "ulock_wait on a changed value blocked or failed");

    // A matching value parks the caller.
    addressSpace.writeU32(lockPage, 0);
    mainState.rax = ulockWait;
    static_cast<void>(dispatcher.dispatch(addressSpace, mainState, rosa::guest::GuestAddress{0x1000}));
    expect(scheduler.current().status == rosa::darwin::GuestThreadStatus::Blocked,
           "ulock_wait on a matching value did not park the thread");

    expect(scheduler.schedule(false) == &worker, "scheduler did not switch to the waker");
    auto &workerState = *worker.state;
    workerState.rax = ulockWake;
    workerState.rdi = ulockCompareAndWait | ulockNoErrno | ulockWakeAll;
    workerState.rsi = lockPage.value;
    workerState.rdx = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, workerState, rosa::guest::GuestAddress{0x1000}));
    expectEqual(intResult(workerState), 0, "ulock_wake with a waiter failed");
    expect(scheduler.threads().front()->status == rosa::darwin::GuestThreadStatus::Runnable,
           "ulock_wake did not wake the waiter");
    expectEqual(intResult(mainState), 0, "woken ulock_wait did not report zero remaining waiters");

    // No waiters: ENOENT, negated under ULF_NO_ERRNO and with carry otherwise.
    workerState.rax = ulockWake;
    static_cast<void>(dispatcher.dispatch(addressSpace, workerState, rosa::guest::GuestAddress{0x1000}));
    expectEqual(intResult(workerState), -ENOENT, "ulock_wake without waiters did not return -ENOENT");
    workerState.rax = ulockWake;
    workerState.rdi = ulockCompareAndWait;
    static_cast<void>(dispatcher.dispatch(addressSpace, workerState, rosa::guest::GuestAddress{0x1000}));
    expect((workerState.rflags & carryFlag) != 0 && workerState.rax == ENOENT,
           "ulock_wake without waiters did not fail with ENOENT");

}

void testUlockWaitTimesOut() {
    rosa::guest::AddressSpace addressSpace;
    constexpr rosa::guest::GuestAddress lockPage{0x9000};
    addressSpace.mapAnonymous(lockPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    auto &scheduler = dispatcher.scheduler();
    rosa::x86::X86State mainState;
    scheduler.bindMainThread(mainState);
    mainState.rax = ulockWait;
    mainState.rdi = ulockCompareAndWait | ulockNoErrno;
    mainState.rsi = lockPage.value;
    mainState.rdx = 0;
    mainState.r10 = 1000;
    static_cast<void>(dispatcher.dispatch(addressSpace, mainState, rosa::guest::GuestAddress{0x1000}));
    expect(scheduler.schedule(false)->id == rosa::darwin::GuestScheduler::mainThreadId,
           "timed ulock_wait never resumed");
    expectEqual(intResult(mainState), -ETIMEDOUT, "timed ulock_wait did not return -ETIMEDOUT");
}

void testUlockUnfairLockOwner() {
    rosa::guest::AddressSpace addressSpace;
    constexpr rosa::guest::GuestAddress lockPage{0x9000};
    addressSpace.mapAnonymous(lockPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    auto &scheduler = dispatcher.scheduler();
    rosa::x86::X86State mainState;
    scheduler.bindMainThread(mainState);
    // A lock word naming no guest thread is EOWNERDEAD, as XNU reports for an
    // owner name that does not translate.
    addressSpace.writeU32(lockPage, 0x7703);
    mainState.rax = ulockWait;
    mainState.rdi = ulockUnfairLock | ulockNoErrno;
    mainState.rsi = lockPage.value;
    mainState.rdx = 0x7703;
    mainState.r10 = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, mainState, rosa::guest::GuestAddress{0x1000}));
    expectEqual(intResult(mainState), -EOWNERDEAD,
                "unfair-lock wait on an unknown owner did not return -EOWNERDEAD");
    // Misaligned addresses are EINVAL.
    mainState.rax = ulockWait;
    mainState.rsi = lockPage.value + 1;
    static_cast<void>(dispatcher.dispatch(addressSpace, mainState, rosa::guest::GuestAddress{0x1000}));
    expectEqual(intResult(mainState), -EINVAL, "misaligned ulock_wait did not return -EINVAL");
}

// Two guest threads through the dispatcher: main parks in ulock_wait until a
// second thread stores a value, wakes it, and terminates.
void testGeneratedThreadsHandOff() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress workerCode{0x1100};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 28> mainCode{
        0xB8, 0x03, 0x02, 0x00, 0x02, // mov eax, ulock_wait
        0xBF, 0x01, 0x00, 0x00, 0x01, // mov edi, UL_COMPARE_AND_WAIT | ULF_NO_ERRNO
        0xBE, 0x00, 0x90, 0x00, 0x00, // mov esi, 0x9000
        0x31, 0xD2,                   // xor edx, edx
        0x45, 0x31, 0xD2,             // xor r10d, r10d
        0x0F, 0x05,                   // syscall
        0x8B, 0x1E,                   // mov ebx, [rsi]
        0xC3,                         // ret
        0x90, 0x90, 0x90,
    };
    constexpr std::array<std::uint8_t, 42> threadCode{
        0xBE, 0x00, 0x90, 0x00, 0x00,       // mov esi, 0x9000
        0xC7, 0x06, 0x07, 0x00, 0x00, 0x00, // mov dword [rsi], 7
        0xB8, 0x04, 0x02, 0x00, 0x02,       // mov eax, ulock_wake
        0xBF, 0x01, 0x00, 0x00, 0x01,       // mov edi, UL_COMPARE_AND_WAIT | ULF_NO_ERRNO
        0x31, 0xD2,                         // xor edx, edx
        0x0F, 0x05,                         // syscall
        0xB8, 0x69, 0x01, 0x00, 0x02,       // mov eax, bsdthread_terminate
        0x31, 0xFF,                         // xor edi, edi
        0x31, 0xF6,                         // xor esi, esi
        0x31, 0xD2,                         // xor edx, edx
        0x45, 0x31, 0xD2,                   // xor r10d, r10d
        0x0F, 0x05,                         // syscall
        0xC3,
    };
    std::array<std::uint8_t, 0x200> code{};
    std::ranges::copy(mainCode, code.begin());
    std::ranges::copy(threadCode, code.begin() + (workerCode.value - codeBase.value));
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    rosa::x86::X86State worker;
    worker.rip = workerCode.value;
    auto &thread = dispatcher.syscalls().scheduler().create(worker);
    const auto result = dispatcher.run(state, 64, sentinel);
    expect(!result.exited, "two-thread guest exited instead of returning");
    expectEqual(state.rbx, std::uint64_t{7}, "main thread did not observe the second thread's store");
    expectEqual(state.rax, std::uint64_t{0}, "woken ulock_wait did not return zero");
    expect(thread.status == rosa::darwin::GuestThreadStatus::Exited,
           "second thread did not terminate");
}


// --- kqueue model -----------------------------------------------------------

rosa::darwin::GuestKevent userEvent(std::uint16_t flags, std::uint32_t fflags = 0) {
    return rosa::darwin::GuestKevent{.ident = 1,
                                     .filter = rosa::darwin::evfiltUser,
                                     .flags = flags,
                                     .udata = 0xABCD,
                                     .fflags = fflags};
}

void testKqueueUserEvents() {
    constexpr std::uint32_t noteTrigger = 0x01000000;
    rosa::darwin::GuestKqueue kqueue(true);
    expectEqual(kqueue.registerChange(userEvent(rosa::darwin::evAdd | rosa::darwin::evClear), 0), 0,
                "EVFILT_USER add failed");
    expect(!kqueue.readyBucket(), "an untriggered EVFILT_USER is ready");
    expectEqual(kqueue.registerChange(userEvent(0, noteTrigger), 0), 0, "NOTE_TRIGGER touch failed");
    // No QoS on the workqueue kqueue means the event manager.
    expect(kqueue.readyBucket() == rosa::darwin::kqueueManagerBucket,
           "untagged workqueue knote is not in the manager bucket");
    auto events = kqueue.process(std::nullopt, 16, 0, std::nullopt);
    expect(events.size() == 1 && events[0].udata == 0xABCD && events[0].filter == rosa::darwin::evfiltUser,
           "triggered EVFILT_USER was not delivered");
    expect(!kqueue.readyBucket(), "EV_CLEAR did not reset the EVFILT_USER trigger");

    // EV_DISPATCH disables after delivery until EV_ENABLE.
    kqueue = rosa::darwin::GuestKqueue(true);
    static_cast<void>(kqueue.registerChange(
        userEvent(rosa::darwin::evAdd | rosa::darwin::evDispatch, noteTrigger), 0));
    expectEqual(kqueue.process(std::nullopt, 16, 0, std::nullopt).size(), std::size_t{1},
                "EV_DISPATCH knote was not delivered");
    expect(!kqueue.readyBucket(), "EV_DISPATCH knote stayed enabled");
    static_cast<void>(kqueue.registerChange(userEvent(rosa::darwin::evEnable), 0));
    expect(kqueue.readyBucket().has_value(), "EV_ENABLE did not re-enable a level-triggered knote");

    // EV_ONESHOT deletes after delivery; a second delete is ENOENT.
    kqueue = rosa::darwin::GuestKqueue(true);
    static_cast<void>(kqueue.registerChange(
        userEvent(rosa::darwin::evAdd | rosa::darwin::evOneshot, noteTrigger), 0));
    static_cast<void>(kqueue.process(std::nullopt, 16, 0, std::nullopt));
    expectEqual(kqueue.size(), std::size_t{0}, "EV_ONESHOT knote survived delivery");
    expectEqual(kqueue.registerChange(userEvent(rosa::darwin::evDelete), 0), ENOENT,
                "deleting a missing knote was not ENOENT");
    expectEqual(kqueue.registerChange(rosa::darwin::GuestKevent{.filter = 3, .flags = 1}, 0), EINVAL,
                "an invalid filter was not EINVAL");
}

void testKqueueSuppressionAndBuckets() {
    constexpr std::uint32_t noteTrigger = 0x01000000;
    rosa::darwin::GuestKqueue kqueue(true);
    auto change = userEvent(rosa::darwin::evAdd, noteTrigger);
    change.qos = 0x1000; // QOS_CLASS_USER_INITIATED: thread QoS 5
    static_cast<void>(kqueue.registerChange(change, 0));
    expect(kqueue.readyBucket() == 5U, "a QoS knote landed in the wrong bucket");
    // Level-triggered: still active after delivery, but suppressed while the
    // delivering thread processes it.
    expectEqual(kqueue.process(5U, 16, 0, std::uint64_t{9}).size(), std::size_t{1},
                "bucket delivery missed the knote");
    expect(!kqueue.hasReadyEvents(5), "a delivered knote was not suppressed");
    kqueue.unsuppress(9);
    expect(kqueue.hasReadyEvents(5), "unsuppress did not restore a level-triggered knote");
}

void testKqueueTimers() {
    constexpr std::uint32_t noteAbsolute = 0x8;
    constexpr std::uint32_t noteMachTime = 0x100;
    rosa::darwin::GuestKqueue kqueue(true);
    // A 5 ms interval timer, in guest mach units (two per nanosecond).
    rosa::darwin::GuestKevent timer{.ident = 7, .filter = rosa::darwin::evfiltTimer,
                                    .flags = rosa::darwin::evAdd, .data = 5};
    constexpr std::uint64_t start = 1'000'000;
    constexpr std::uint64_t interval = 5'000'000 * rosa::darwin::guestMachTicksPerNanosecond;
    static_cast<void>(kqueue.registerChange(timer, start));
    expect(kqueue.nextTimerDeadline() == start + interval, "interval timer deadline differs");
    expect(!kqueue.expireTimers(start + interval - 1) && !kqueue.readyBucket(),
           "timer fired before its deadline");
    // Three whole intervals later it reports three expirations and re-arms.
    expect(kqueue.expireTimers(start + 3 * interval + 1), "timer did not fire at its deadline");
    auto events = kqueue.process(std::nullopt, 16, start + 3 * interval + 1, std::nullopt);
    expect(events.size() == 1 && events[0].data == 3 && (events[0].flags & rosa::darwin::evClear) != 0,
           "interval timer expiration count or EV_CLEAR differs");
    expect(kqueue.nextTimerDeadline() == start + 4 * interval, "interval timer did not re-arm");

    // NOTE_ABSOLUTE with NOTE_MACHTIME is a one-shot at a mach deadline.
    rosa::darwin::GuestKqueue oneshot(true);
    rosa::darwin::GuestKevent absolute{.ident = 8, .filter = rosa::darwin::evfiltTimer,
                                       .flags = rosa::darwin::evAdd,
                                       .fflags = noteAbsolute | noteMachTime, .data = 500};
    static_cast<void>(oneshot.registerChange(absolute, 1000));
    expect(oneshot.readyBucket().has_value(), "a past absolute deadline did not fire at once");
    static_cast<void>(oneshot.process(std::nullopt, 16, 1000, std::nullopt));
    expectEqual(oneshot.size(), std::size_t{0}, "absolute timer was not one-shot");
}

// --- workqueue and workloops --------------------------------------------------

constexpr std::uint64_t workqKernreturn = 0x02000170;
constexpr std::uint64_t keventQos = 0x02000176;
constexpr std::uint64_t keventId = 0x02000177;
constexpr std::uint32_t wqFlagPriorityQos = 0x00004000;
constexpr std::uint32_t wqFlagReuse = 0x00020000;
constexpr std::uint32_t wqFlagNewSpi = 0x00040000;
constexpr std::uint32_t wqFlagKevent = 0x00080000;
constexpr std::uint32_t wqFlagEventManager = 0x00100000;
constexpr std::uint32_t wqFlagTsdBaseSet = 0x00200000;
constexpr std::uint32_t wqFlagWorkloop = 0x00400000;
constexpr std::uint64_t guestStack = 0x700000000000ULL;

struct WorkqueueFixture {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State mainState;

    WorkqueueFixture() {
        registerPthread(dispatcher, addressSpace);
        addressSpace.mapAnonymous(rosa::guest::GuestAddress{guestStack}, 0x4000,
                                  rosa::guest::Permission::Read | rosa::guest::Permission::Write);
        addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
                                  rosa::guest::Permission::Read | rosa::guest::Permission::Write);
        dispatcher.scheduler().bindMainThread(mainState);
        mainState.rsp = guestStack + 0x2000;
    }

    void syscall(rosa::x86::X86State &state, std::uint64_t number) {
        state.rax = number;
        static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    }

    // kevent_qos/kevent_id take their 7th and 8th arguments from the stack.
    void setStackFlags(rosa::x86::X86State &state, std::uint32_t flags) {
        addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp + 8}, 0);
        addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp + 16}, flags);
    }

    void writeChange(std::uint64_t address, const rosa::darwin::GuestKevent &change) {
        std::array<std::uint8_t, rosa::darwin::GuestKevent::size> bytes{};
        change.encode(bytes);
        addressSpace.writeBytes(rosa::guest::GuestAddress{address}, bytes);
    }

    rosa::darwin::GuestThread &thread(std::size_t index) {
        return *dispatcher.scheduler().threads().at(index);
    }

    // Syscall handlers act for the scheduler's current thread.
    void makeCurrent(const rosa::darwin::GuestThread &target) {
        auto &scheduler = dispatcher.scheduler();
        for (std::size_t attempt = 0; attempt < scheduler.threads().size() &&
                                      &scheduler.current() != &target;
             ++attempt) {
            static_cast<void>(scheduler.schedule(true));
        }
        expect(&scheduler.current() == &target, "test could not switch to a guest thread");
    }
};

void testWorkqueueThreadRequests() {
    WorkqueueFixture fixture;
    auto &state = fixture.mainState;
    state.rdi = 0x020; // WQOPS_QUEUE_REQTHREADS
    state.rsi = 0;
    state.rdx = 2;
    state.r10 = 0x8FF; // QOS_CLASS_DEFAULT (thread QoS 4), not overcommit
    fixture.syscall(state, workqKernreturn);
    expect((state.rflags & carryFlag) == 0, "WQOPS_QUEUE_REQTHREADS failed");
    expectEqual(fixture.dispatcher.scheduler().threads().size(), std::size_t{3},
                "two thread requests did not create two workqueue threads");
    auto &worker = fixture.thread(1);
    const auto &upcall = *worker.state;
    expect(worker.workqueue, "requested thread is not a workqueue thread");
    expectEqual(upcall.rip, std::uint64_t{0x7040}, "worker does not start at start_wqthread");
    expectEqual(upcall.rdi, worker.workqueueSelf, "worker pthread_t argument differs");
    expectEqual(upcall.rsi, std::uint64_t{worker.port->value}, "worker thread port differs");
    expectEqual(upcall.rdx, worker.workqueueStackAddress + rosa::guest::guestPageSize,
                "worker stack bottom is not above the guard page");
    expectEqual(upcall.r8, std::uint64_t{wqFlagNewSpi | wqFlagPriorityQos | wqFlagTsdBaseSet | 4},
                "first-use upcall flags differ");
    expectEqual(upcall.rsp, worker.workqueueSelf & ~std::uint64_t{15}, "worker stack top differs");
    expectEqual(upcall.gsBase, worker.workqueueSelf + 0xE0, "worker TSD base differs");
    bool guarded = false;
    try {
        static_cast<void>(fixture.addressSpace.readU8(
            rosa::guest::GuestAddress{worker.workqueueStackAddress}));
    } catch (const std::runtime_error &) {
        guarded = true;
    }
    expect(guarded, "workqueue stack guard page is accessible");

    // A worker returning with nothing pending parks; a new request reuses it.
    auto &workerState = *worker.state;
    fixture.makeCurrent(worker);
    workerState.rdi = 0x004; // WQOPS_THREAD_RETURN
    workerState.rsi = 0;
    workerState.rdx = 0;
    fixture.syscall(workerState, workqKernreturn);
    expect(worker.status == rosa::darwin::GuestThreadStatus::Blocked,
           "a returning worker with no work did not park");
    state.rdi = 0x020;
    state.rdx = 1;
    state.r10 = 0x8FF;
    fixture.syscall(state, workqKernreturn);
    expectEqual(fixture.dispatcher.scheduler().threads().size(), std::size_t{3},
                "a request created a thread while one was idle");
    expect(worker.status == rosa::darwin::GuestThreadStatus::Runnable &&
               (worker.state->r8 & wqFlagReuse) != 0 && (worker.state->r8 & wqFlagTsdBaseSet) == 0,
           "an idle worker was not reused with WQ_FLAG_THREAD_REUSE");
}

void testWorkqueueKeventDelivery() {
    WorkqueueFixture fixture;
    auto &state = fixture.mainState;
    constexpr std::uint64_t changes = 0x9000;
    // The manager EVFILT_USER libdispatch registers, already triggered.
    fixture.writeChange(changes, rosa::darwin::GuestKevent{
                                     .ident = 1,
                                     .filter = rosa::darwin::evfiltUser,
                                     .flags = rosa::darwin::evAdd | rosa::darwin::evClear,
                                     .qos = 0x02000000,
                                     .udata = 0x55,
                                     .fflags = 0x01000000});
    state.rdi = 0xFFFFFFFF;
    state.rsi = changes;
    state.rdx = 1;
    state.r10 = 0;
    state.r8 = 0;
    state.r9 = 0;
    fixture.setStackFlags(state, 0x20 | 0x1 | 0x2); // WORKQ | IMMEDIATE | ERROR_EVENTS
    fixture.syscall(state, keventQos);
    expect((state.rflags & carryFlag) == 0 && state.rax == 0, "workqueue kevent_qos failed");
    expectEqual(fixture.dispatcher.scheduler().threads().size(), std::size_t{2},
                "a ready manager event did not create a kevent thread");
    auto &thread = fixture.thread(1);
    const auto &upcall = *thread.state;
    expectEqual(upcall.r8 & (wqFlagKevent | wqFlagEventManager),
                std::uint64_t{wqFlagKevent | wqFlagEventManager},
                "manager kevent thread flags differ");
    expectEqual(upcall.r9, std::uint64_t{1}, "kevent thread event count differs");
    expectEqual(upcall.rcx, thread.workqueueSelf - 16 * rosa::darwin::GuestKevent::size,
                "kevent list is not below the pthread_t");
    const auto delivered = rosa::darwin::GuestKevent::decode(fixture.addressSpace.readBytes(
        rosa::guest::GuestAddress{upcall.rcx}, rosa::darwin::GuestKevent::size));
    expect(delivered.udata == 0x55 && delivered.filter == rosa::darwin::evfiltUser,
           "delivered kevent differs");
    expectEqual(upcall.rsp, upcall.rcx & ~std::uint64_t{15}, "kevent thread stack is not below its list");
}

void testWorkloopThreadRequest() {
    WorkqueueFixture fixture;
    auto &state = fixture.mainState;
    constexpr std::uint64_t queue = 0x9800;    // the dispatch queue (workloop id)
    constexpr std::uint64_t stateWord = 0x9810; // its dq_state
    constexpr std::uint64_t changes = 0x9000;
    constexpr std::uint32_t threadRequest = 0x1;
    constexpr std::uint32_t ignoreStale = 0x100;
    fixture.addressSpace.writeU64(rosa::guest::GuestAddress{stateWord}, 0x10);
    const auto request = [&](std::uint16_t flags, std::uint32_t extra, std::uint64_t expected) {
        return rosa::darwin::GuestKevent{
            .ident = queue,
            .filter = rosa::darwin::evfiltWorkloop,
            .flags = flags,
            .qos = 0x8FF,
            .udata = queue,
            .fflags = threadRequest | extra,
            .ext = {0, stateWord, 0xFF, expected},
        };
    };
    const auto keventIdCall = [&](rosa::x86::X86State &caller, const rosa::darwin::GuestKevent &change,
                                  std::int32_t eventCount) {
        fixture.writeChange(changes, change);
        caller.rdi = queue;
        caller.rsi = changes;
        caller.rdx = 1;
        caller.r10 = changes + 0x100;
        caller.r8 = static_cast<std::uint64_t>(eventCount);
        caller.r9 = 0;
        fixture.setStackFlags(caller, 0x400 | 0x1 | 0x2); // WORKLOOP | IMMEDIATE | ERROR_EVENTS
        fixture.syscall(caller, keventId);
    };

    // A stale debounce reports ESTALE through the event list and requests nothing.
    keventIdCall(state, request(rosa::darwin::evAdd | rosa::darwin::evEnable, 0, 0x11), 1);
    expectEqual(state.rax, std::uint64_t{1}, "stale workloop request did not report one error event");
    const auto error = rosa::darwin::GuestKevent::decode(fixture.addressSpace.readBytes(
        rosa::guest::GuestAddress{changes + 0x100}, rosa::darwin::GuestKevent::size));
    expect((error.flags & rosa::darwin::evError) != 0 && error.data == ESTALE &&
               error.ext[3] == 0x10,
           "stale workloop request error differs");
    expectEqual(fixture.dispatcher.scheduler().threads().size(), std::size_t{1},
                "a stale thread request created a servicer");
    // NOTE_WL_IGNORE_ESTALE swallows the same failure.
    keventIdCall(state, request(rosa::darwin::evAdd | rosa::darwin::evEnable, ignoreStale, 0x11), 1);
    expectEqual(state.rax, std::uint64_t{0}, "NOTE_WL_IGNORE_ESTALE still reported ESTALE");

    // A current debounce requests a servicer bound to the workloop.
    keventIdCall(state, request(rosa::darwin::evAdd | rosa::darwin::evEnable, 0, 0x10), 1);
    expectEqual(state.rax, std::uint64_t{0}, "valid workloop thread request failed");
    expectEqual(fixture.dispatcher.scheduler().threads().size(), std::size_t{2},
                "a workloop thread request did not create a servicer");
    auto &servicer = fixture.thread(1);
    const auto upcall = *servicer.state;
    expect((upcall.r8 & (wqFlagWorkloop | wqFlagKevent)) == (wqFlagWorkloop | wqFlagKevent) &&
               upcall.r9 == 1,
           "workloop servicer upcall differs");
    expectEqual(fixture.addressSpace.readU64(rosa::guest::GuestAddress{upcall.rcx - 8}), queue,
                "the workloop id is not below the kevent list");
    expect(servicer.workloop == queue, "servicer is not bound to its workloop");

    // Returning with the request deleted releases and parks the servicer.
    auto &servicerState = *servicer.state;
    fixture.writeChange(changes, request(rosa::darwin::evAdd | rosa::darwin::evDelete |
                                             rosa::darwin::evEnable,
                                         0, 0x10));
    fixture.makeCurrent(servicer);
    servicerState.rdi = 0x100; // WQOPS_THREAD_WORKLOOP_RETURN
    servicerState.rsi = changes;
    servicerState.rdx = 1;
    fixture.syscall(servicerState, workqKernreturn);
    expect(servicer.status == rosa::darwin::GuestThreadStatus::Blocked && !servicer.workloop,
           "a servicer whose request was deleted was not released");
}

void testSemaphoreTraps() {
    WorkqueueFixture fixture;
    auto &ports = fixture.dispatcher.machDispatcher();
    static_cast<void>(ports);
    // Create a semaphore through the port space as semaphore_create would.
    auto &space = const_cast<rosa::darwin::GuestPortSpace &>(ports.portSpace());
    const auto semaphore = space.allocateSemaphoreSendRight(0, 0);
    expect(semaphore.has_value(), "semaphore allocation failed");
    auto &state = fixture.mainState;
    // semaphore_timedwait with a zero timeout times out at once.
    state.rdi = semaphore->value;
    state.rsi = 0;
    state.rdx = 0;
    fixture.syscall(state, 0x01000026);
    expectEqual(state.rax, std::uint64_t{49}, "zero-timeout semaphore wait did not time out");
    // A signal with no waiter is banked; the next wait consumes it.
    state.rdi = semaphore->value;
    fixture.syscall(state, 0x01000021);
    expectEqual(state.rax, std::uint64_t{0}, "semaphore_signal failed");
    state.rdi = semaphore->value;
    fixture.syscall(state, 0x01000024);
    expect(state.rax == 0 && fixture.dispatcher.scheduler().current().status ==
                                 rosa::darwin::GuestThreadStatus::Runnable,
           "a banked signal did not satisfy semaphore_wait");
    // An empty wait parks; a signal from another thread wakes it.
    rosa::x86::X86State otherInitial;
    auto &other = fixture.dispatcher.scheduler().create(otherInitial);
    state.rdi = semaphore->value;
    fixture.syscall(state, 0x01000024);
    expect(fixture.thread(0).status == rosa::darwin::GuestThreadStatus::Blocked,
           "an empty semaphore_wait did not park");
    expect(fixture.dispatcher.scheduler().schedule(false) == &other, "scheduler did not switch");
    other.state->rdi = semaphore->value;
    fixture.syscall(*other.state, 0x01000021);
    expect(fixture.thread(0).status == rosa::darwin::GuestThreadStatus::Runnable &&
               fixture.mainState.rax == 0,
           "semaphore_signal did not wake the waiter");
    // An invalid name is KERN_INVALID_ARGUMENT.
    state.rdi = 0x7777;
    fixture.syscall(state, 0x01000021);
    expectEqual(state.rax, std::uint64_t{4}, "signaling a non-semaphore was not KERN_INVALID_ARGUMENT");
}

} // namespace

std::span<const TestCase> darwinThreadsTests() {
    static const std::array cases{
        TestCase{"scheduler round robin and wake", testSchedulerRoundRobinAndWake},
        TestCase{"scheduler deadline and deadlock", testSchedulerDeadlineAndDeadlock},
        TestCase{"Darwin bsdthread_create registers", testBsdthreadCreateRegisters},
        TestCase{"Darwin ulock wait and wake", testUlockWaitAndWake},
        TestCase{"Darwin ulock wait timeout", testUlockWaitTimesOut},
        TestCase{"Darwin ulock unfair-lock owner", testUlockUnfairLockOwner},
        TestCase{"generated two-thread hand-off", testGeneratedThreadsHandOff},
        TestCase{"kqueue EVFILT_USER registration and delivery", testKqueueUserEvents},
        TestCase{"kqueue suppression and QoS buckets", testKqueueSuppressionAndBuckets},
        TestCase{"kqueue EVFILT_TIMER interval and absolute", testKqueueTimers},
        TestCase{"Darwin workqueue thread requests", testWorkqueueThreadRequests},
        TestCase{"Darwin workqueue kevent delivery", testWorkqueueKeventDelivery},
        TestCase{"Darwin workloop thread request", testWorkloopThreadRequest},
        TestCase{"Darwin semaphore traps", testSemaphoreTraps},
    };
    return cases;
}

} // namespace rosa::tests
