#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testDarwinBsdthreadRegister() {
    constexpr auto syscallNumber = UINT64_C(0x0200016E);
    constexpr rosa::guest::GuestAddress codePage{0x7000};
    constexpr rosa::guest::GuestAddress threadStart{0x7020};
    constexpr rosa::guest::GuestAddress workqueueStart{0x7040};
    constexpr rosa::guest::GuestAddress dataPage{0x8000};
    constexpr rosa::guest::GuestAddress dataAddress{0x8100};
    constexpr std::size_t dataSize = 56;

    std::array<std::uint8_t, dataSize> data{};
    const auto put64 = [&](std::size_t offset, std::uint64_t value) {
        std::memcpy(data.data() + offset, &value, sizeof(value));
    };
    const auto put32 = [&](std::size_t offset, std::uint32_t value) {
        std::memcpy(data.data() + offset, &value, sizeof(value));
    };
    put64(0, dataSize);
    put64(8, 0xA0);
    put32(24, 0xE0);
    put32(28, 0x28);
    put32(32, 0x18);
    put32(48, 0x188);
    put32(52, 0x3C0);

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codePage, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute,
                            std::array<std::uint8_t, 1>{0xC3});
    addressSpace.mapAnonymous(dataPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(dataAddress, data);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = syscallNumber;
    state.rdi = threadStart.value;
    state.rsi = workqueueStart.value;
    state.rdx = 0x2000;
    state.r10 = dataAddress.value;
    state.r8 = dataSize;
    state.r9 = 0xA0;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E345DCULL}));
    expectEqual(state.rax, std::uint64_t{0},
                "bsdthread_register did not return legacy feature success");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "bsdthread_register did not clear BSD carry");
    expectEqual(addressSpace.readBytes(dataAddress, data.size()),
                std::vector<std::uint8_t>(data.begin(), data.end()),
                "bsdthread_register changed unsupported outgoing fields");
    const auto &registration = dispatcher.pthreadRegistration();
    expect(registration.has_value(), "bsdthread_register did not record the guest handshake");
    expectEqual(registration->threadStart, threadStart,
                "bsdthread_register recorded the wrong thread entry");
    expectEqual(registration->workqueueThreadStart, workqueueStart,
                "bsdthread_register recorded the wrong workqueue entry");
    expectEqual(registration->pthreadSize, std::uint32_t{0x2000},
                "bsdthread_register recorded the wrong pthread size");
    expectEqual(registration->tsdOffset, std::uint32_t{0xE0},
                "bsdthread_register recorded the wrong TSD offset");
    expectEqual(registration->machThreadSelfOffset, std::uint32_t{0x18},
                "bsdthread_register recorded the wrong thread-port offset");

    state.rax = syscallNumber;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "repeated bsdthread_register returned the wrong errno");
    expect((state.rflags & 1U) != 0, "repeated bsdthread_register did not set BSD carry");

    rosa::darwin::SyscallDispatcher faultDispatcher;
    state.rax = syscallNumber;
    state.r10 = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(
        faultDispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid bsdthread_register record returned the wrong errno");
    expect(!faultDispatcher.pthreadRegistration(),
           "faulted bsdthread_register recorded a partial handshake");
}

void testDarwinThreadSelfid() {
    constexpr auto threadSelfidNumber = UINT64_C(0x02000174);
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = threadSelfidNumber;
    state.rdi = UINT64_MAX;
    state.r9 = 0x123456789ABCDEF0ULL;
    state.rflags = 0x8D7;

    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF800004F84ULL});
    expect(!outcome.exited, "thread_selfid terminated the guest");
    expectEqual(state.rax, std::uint64_t{1},
                "thread_selfid returned the wrong guest-local identity");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "thread_selfid did not apply successful BSD carry semantics");
    expectEqual(state.rdi, UINT64_MAX, "thread_selfid changed an ignored argument register");
    expectEqual(state.r9, std::uint64_t{0x123456789ABCDEF0ULL},
                "thread_selfid changed an ignored argument register");

    state.rax = threadSelfidNumber;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{1}, "repeated thread_selfid changed guest identity");
}

void testDarwinGetpid() {
    constexpr auto getpidNumber = UINT64_C(0x02000014);
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = getpidNumber;
    state.rdi = 0x0123456789ABCDEFULL;
    state.r9 = 0xFEDCBA9876543210ULL;
    state.rflags = 0x8D7;

    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF700005487ULL});
    expect(!outcome.exited, "getpid terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(::getpid()),
                "getpid returned the wrong process identity");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "getpid did not apply successful BSD carry semantics");
    expectEqual(state.rdi, std::uint64_t{0x0123456789ABCDEFULL},
                "getpid changed an ignored argument register");
    expectEqual(state.r9, std::uint64_t{0xFEDCBA9876543210ULL},
                "getpid changed an ignored argument register");
}

void testDarwinGetuid() {
    constexpr auto getuidNumber = UINT64_C(0x02000018);
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = getuidNumber;
    state.rdi = 0x0123456789ABCDEFULL;
    state.rsi = 0x803;
    state.rflags = 0x8D7;

    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E31180ULL});
    expect(!outcome.exited, "getuid terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(::getuid()),
                "getuid returned the wrong user identity");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "getuid did not apply successful BSD carry semantics");
    expectEqual(state.rdi, std::uint64_t{0x0123456789ABCDEFULL},
                "getuid changed an ignored argument register");
}

void testDarwinGeteuid() {
    constexpr auto geteuidNumber = UINT64_C(0x02000019);
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = geteuidNumber;
    state.rdi = 0x0123456789ABCDEFULL;
    state.rsi = 0x803;
    state.rflags = 0x8D7;

    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30BA0ULL});
    expect(!outcome.exited, "geteuid terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(::geteuid()),
                "geteuid returned the wrong user identity");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "geteuid did not apply successful BSD carry semantics");
}

void testDarwinGettidReportsNoOverrideIdentity() {
    // Observed under an Objective-C fixture: CoreFoundation probes the
    // per-thread override identity and falls back on ESRCH.
    constexpr auto gettidNumber = UINT64_C(0x0200011E);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress uidAddress{0x8100};
    constexpr rosa::guest::GuestAddress gidAddress{0x8108};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 16> sentinel{0xA5, 0x5A, 0xA5, 0x5A, 0xA5, 0x5A, 0xA5, 0x5A,
                                                    0x5A, 0xA5, 0x5A, 0xA5, 0x5A, 0xA5, 0x5A, 0xA5};
    addressSpace.writeBytes(uidAddress, sentinel);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = gettidNumber;
    state.rdi = uidAddress.value;
    state.rsi = gidAddress.value;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E31190ULL});
    expect(!outcome.exited, "gettid terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(ESRCH),
                "gettid without an override identity returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "gettid did not set BSD carry");
    // XNU checks for an active override before touching the out-pointers.
    expect(addressSpace.readBytes(uidAddress, sentinel.size()) ==
               std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
           "gettid without an override identity touched its out-pointers");

    // Even unmapped out-pointers report ESRCH rather than EFAULT.
    state.rax = gettidNumber;
    state.rdi = 0x700000000000ULL;
    state.rsi = 0x700000000008ULL;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ESRCH),
                "gettid with unmapped out-pointers returned the wrong errno");
}

void testDarwinGetegid() {
    constexpr auto getegidNumber = UINT64_C(0x0200002B);
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = getegidNumber;
    state.rdi = 0x3;
    state.rsi = 0x7000000FAB04ULL;
    state.rdx = 0xFFFFFFFFFFFFFFFFULL;
    state.rflags = 0x86;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E311B0ULL});
    expect(!outcome.exited, "getegid terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(::getegid()),
                "getegid returned the wrong group identity");
    expectEqual(state.rflags, std::uint64_t{0x86},
                "getegid did not apply successful BSD carry semantics");
}

void testDarwinGetrlimit() {
    constexpr auto getrlimitNumber = UINT64_C(0x020000C2);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;

    // RLIMIT_NOFILE with the libc POSIX flag bit, as observed from libsystem_c.
    state.rax = getrlimitNumber;
    state.rdi = 8 | 0x1000;
    state.rsi = outputAddress.value;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E317A0ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "getrlimit did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "getrlimit did not clear BSD carry");
    struct rlimit expected{};
    expect(::getrlimit(8, &expected) == 0, "could not query host RLIMIT_NOFILE");
    std::array<std::uint8_t, 16> expectedBytes{};
    std::memcpy(expectedBytes.data(), &expected, sizeof(expected));
    expectEqual(addressSpace.readBytes(outputAddress, expectedBytes.size()),
                std::vector<std::uint8_t>(expectedBytes.begin(), expectedBytes.end()),
                "getrlimit did not copy out the host limits");

    // Past RLIM_NLIMITS fails even with the flag bit set.
    state.rax = getrlimitNumber;
    state.rdi = 9 | 0x1000;
    state.rsi = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "out-of-range getrlimit returned the wrong errno");

    // Unmapped output reports EFAULT.
    state.rax = getrlimitNumber;
    state.rdi = 8;
    state.rsi = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "getrlimit with an unmapped output returned the wrong errno");
}

void testDarwinSigaction() {
    constexpr auto sigactionNumber = UINT64_C(0x0200002E);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress newActionAddress{0x8100};
    constexpr rosa::guest::GuestAddress oldActionAddress{0x8200};
    constexpr auto readWrite = rosa::guest::Permission::Read | rosa::guest::Permission::Write;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize, readWrite);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;

    // Install a SIGINT disposition and read back the previous default.
    std::array<std::uint8_t, 16> newAction{};
    const std::uint64_t handler = 0x7FF802D07632ULL;
    const std::uint32_t mask = 0xFF;
    const std::int32_t flags = 0x40;
    std::memcpy(newAction.data(), &handler, 8);
    std::memcpy(newAction.data() + 8, &mask, 4);
    std::memcpy(newAction.data() + 12, &flags, 4);
    addressSpace.writeBytes(newActionAddress, newAction);
    state.rax = sigactionNumber;
    state.rdi = 2;
    state.rsi = newActionAddress.value;
    state.rdx = oldActionAddress.value;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E34B1CULL}));
    expectEqual(state.rax, std::uint64_t{0}, "sigaction install did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "sigaction install did not clear BSD carry");
    expectEqual(addressSpace.readU64(oldActionAddress), std::uint64_t{0},
                "sigaction did not report the default previous handler");
    const auto installed = dispatcher.signalDisposition(2);
    expectEqual(installed.handlerAddress, handler, "sigaction stored the wrong handler");
    expectEqual(installed.mask, mask, "sigaction stored the wrong mask");
    expectEqual(installed.flags, flags, "sigaction stored the wrong flags");

    // Query-only round trip returns the installed disposition.
    state.rax = sigactionNumber;
    state.rsi = 0;
    state.rdx = oldActionAddress.value;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "sigaction query did not succeed");
    expectEqual(addressSpace.readBytes(oldActionAddress, newAction.size()),
                std::vector<std::uint8_t>(newAction.begin(), newAction.end()),
                "sigaction query did not copy out the installed disposition");

    // Invalid signal numbers fail without touching dispositions.
    state.rax = sigactionNumber;
    state.rdi = 0;
    state.rsi = newActionAddress.value;
    state.rdx = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "sigaction with signal 0 returned the wrong errno");
    expectEqual(dispatcher.signalDisposition(2).handlerAddress, handler,
                "rejected sigaction changed the installed disposition");

    // Faulting action pointers report EFAULT.
    state.rax = sigactionNumber;
    state.rdi = 2;
    state.rsi = 0x9000;
    state.rdx = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "sigaction with an unmapped action returned the wrong errno");
}

void testDarwinGettimeofday() {
    constexpr auto gettimeofdayNumber = UINT64_C(0x02000074);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress timevalAddress{0x8100};
    constexpr rosa::guest::GuestAddress timezoneAddress{0x8120};
    constexpr rosa::guest::GuestAddress absoluteTimeAddress{0x8130};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = gettimeofdayNumber;
    state.rdi = timevalAddress.value;
    state.rsi = timezoneAddress.value;
    state.rdx = absoluteTimeAddress.value;
    state.rflags = 0x8D7;

    timeval hostBefore{};
    expect(::gettimeofday(&hostBefore, nullptr) == 0,
           "could not sample host time before guest gettimeofday");
    const auto absoluteBefore = rosa::darwin::sampleX86TimestampCounter() / 2U;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E32BACULL});
    const auto absoluteAfter = rosa::darwin::sampleX86TimestampCounter() / 2U;
    timeval hostAfter{};
    expect(::gettimeofday(&hostAfter, nullptr) == 0,
           "could not sample host time after guest gettimeofday");

    expect(!outcome.exited, "gettimeofday terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "gettimeofday did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "gettimeofday did not apply successful BSD carry semantics");
    const auto guestSeconds = addressSpace.readU64(timevalAddress);
    const auto guestMicroseconds =
        addressSpace.readU32(rosa::guest::GuestAddress{timevalAddress.value + 8});
    expect(guestSeconds >= static_cast<std::uint32_t>(hostBefore.tv_sec) &&
               guestSeconds <= static_cast<std::uint32_t>(hostAfter.tv_sec),
           "gettimeofday returned seconds outside its host sample interval");
    expect(guestMicroseconds < 1'000'000, "gettimeofday returned an invalid microsecond field");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{timevalAddress.value + 12}),
                std::uint32_t{0}, "gettimeofday did not clear timeval padding");
    expectEqual(addressSpace.readU64(timezoneAddress), std::uint64_t{0},
                "gettimeofday did not return the UTC timezone default");
    const auto guestAbsoluteTime = addressSpace.readU64(absoluteTimeAddress);
    expect(guestAbsoluteTime >= absoluteBefore && guestAbsoluteTime <= absoluteAfter,
           "gettimeofday returned an unsynchronized Mach absolute time");

    const auto originalTimeval = addressSpace.readBytes(timevalAddress, 16);
    const auto originalTimezone = addressSpace.readBytes(timezoneAddress, 8);
    state = {};
    state.rax = gettimeofdayNumber;
    state.rdi = timevalAddress.value;
    state.rsi = timezoneAddress.value;
    state.rdx = page.value + rosa::guest::guestPageSize;
    state.rflags = 0x46;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "gettimeofday invalid output returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x47}, "gettimeofday invalid output did not set carry");
    expectEqual(addressSpace.readBytes(timevalAddress, 16), originalTimeval,
                "failed gettimeofday partially changed the timeval");
    expectEqual(addressSpace.readBytes(timezoneAddress, 8), originalTimezone,
                "failed gettimeofday partially changed the timezone");
}

void testDarwinIssetugid() {
    constexpr auto issetugidNumber = UINT64_C(0x02000147);
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = issetugidNumber;
    state.rdi = 0x7FF8436BD774ULL;
    state.rsi = 0x1FFE1000000800ULL;
    state.rdx = 0x1FFE1000000000ULL;
    state.r10 = UINT32_MAX;
    state.r8 = 1;
    state.r9 = 0x3E0;
    state.rflags = 0x47;

    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2F89CULL});
    expect(!outcome.exited, "issetugid terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "issetugid reported a credential transition");
    expectEqual(state.rflags, std::uint64_t{0x46},
                "issetugid did not apply successful BSD carry semantics");
    expectEqual(state.rdi, std::uint64_t{0x7FF8436BD774ULL},
                "issetugid changed an ignored argument register");
    expectEqual(state.rsi, std::uint64_t{0x1FFE1000000800ULL},
                "issetugid changed an ignored argument register");
    expectEqual(state.rdx, std::uint64_t{0x1FFE1000000000ULL},
                "issetugid changed an ignored argument register");
    expectEqual(state.r10, std::uint64_t{UINT32_MAX},
                "issetugid changed an ignored argument register");
}

void testDarwinIoctlStandardDescriptorType() {
    constexpr auto ioctlNumber = UINT64_C(0x02000036);
    constexpr auto fileDescriptorTypeRequest = UINT64_C(0x4004667A);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress typeAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(typeAddress, UINT32_MAX);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = ioctlNumber;
    state.rdi = STDERR_FILENO;
    state.rsi = fileDescriptorTypeRequest;
    state.rdx = typeAddress.value;
    state.r10 = 0x18;
    state.rflags = 0x7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E33228ULL});
    expect(!outcome.exited, "ioctl(FIODTYPE) terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "ioctl(FIODTYPE) did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x6}, "ioctl(FIODTYPE) did not clear BSD carry");
    expectEqual(addressSpace.readU32(typeAddress), std::uint32_t{3},
                "stderr was not reported as a Darwin tty");
    expectEqual(state.r10, std::uint64_t{0x18},
                "ioctl(FIODTYPE) changed an ignored argument register");

    addressSpace.writeU32(typeAddress, UINT32_MAX);
    state.rax = ioctlNumber;
    state.rdi = STDERR_FILENO;
    state.rsi = fileDescriptorTypeRequest;
    state.rdx = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "ioctl(FIODTYPE) invalid output returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3}, "faulted ioctl(FIODTYPE) did not set BSD carry");
    expectEqual(addressSpace.readU32(typeAddress), UINT32_MAX,
                "faulted ioctl(FIODTYPE) changed a valid output buffer");

    // The synthetic console reports a conventional 80x24 window.
    constexpr auto windowSizeRequest = UINT64_C(0x40087468);
    state.rax = ioctlNumber;
    state.rdi = STDIN_FILENO;
    state.rsi = windowSizeRequest;
    state.rdx = typeAddress.value;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "ioctl(TIOCGWINSZ) did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "ioctl(TIOCGWINSZ) did not clear BSD carry");
    expectEqual(addressSpace.readBytes(typeAddress, 8),
                std::vector<std::uint8_t>({24, 0, 80, 0, 0, 0, 0, 0}),
                "synthetic console window size differs");

    state.rax = ioctlNumber;
    state.rdi = 3;
    state.rsi = windowSizeRequest;
    state.rdx = typeAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "ioctl(TIOCGWINSZ) on a nonstandard descriptor returned the wrong errno");

    state.rax = ioctlNumber;
    state.rdi = STDERR_FILENO;
    state.rsi = 0;
    state.rdx = typeAddress.value;
    bool unsupportedRequest = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedRequest =
            std::string_view(error.what()).find("FIODTYPE") != std::string_view::npos;
    }
    expect(unsupportedRequest, "unobserved guest ioctl request did not fail loudly");
}

void testDarwinSysctlOsversion() {
    // Observed under an AppKit fixture: sysctl({CTL_KERN, 65}) reads the
    // kernel build string; stale newp/newlen registers are ignored.
    constexpr auto sysctlNumber = UINT64_C(0x020000CA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress nameAddress{0x8100};
    constexpr rosa::guest::GuestAddress outputAddress{0x8200};
    constexpr rosa::guest::GuestAddress sizeAddress{0x8300};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    const std::array<std::uint32_t, 2> name{1, 65};
    std::array<std::uint8_t, sizeof(name)> nameBytes{};
    std::memcpy(nameBytes.data(), name.data(), sizeof(nameBytes));
    addressSpace.writeBytes(nameAddress, nameBytes);
    addressSpace.writeU64(sizeAddress, 256);

    char hostBuild[256]{};
    std::size_t hostBuildSize = sizeof(hostBuild);
    expect(::sysctlbyname("kern.osversion", hostBuild, &hostBuildSize, nullptr, 0) == 0,
           "could not sample the host build string");

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = sysctlNumber;
    state.rdi = nameAddress.value;
    state.rsi = name.size();
    state.rdx = outputAddress.value;
    state.r10 = sizeAddress.value;
    state.r8 = 0x69; // Stale caller registers, not a set payload.
    state.r9 = 0x7FF8438A6268ULL;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E310B4ULL});
    expect(!outcome.exited, "kern.osversion sysctl terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "kern.osversion sysctl did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "kern.osversion sysctl did not clear BSD carry");
    expectEqual(addressSpace.readU64(sizeAddress), hostBuildSize,
                "kern.osversion sysctl reported the wrong size");
    const auto reported = addressSpace.readBytes(outputAddress, hostBuildSize);
    expectEqual(reported,
                std::vector<std::uint8_t>(hostBuild, hostBuild + hostBuildSize),
                "kern.osversion sysctl reported the wrong build");

    // A short buffer reports ENOMEM and the required size.
    addressSpace.writeU64(sizeAddress, 2);
    state.rax = sysctlNumber;
    state.rdi = nameAddress.value;
    state.rsi = name.size();
    state.rdx = outputAddress.value;
    state.r10 = sizeAddress.value;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short kern.osversion read returned the wrong errno");
    expectEqual(addressSpace.readU64(sizeAddress), hostBuildSize,
                "short kern.osversion read did not report its size");
}

void testDarwinSandboxMachLookupCheck() {
    // Observed under an AppKit fixture: Sandbox mach-lookup for a bootstrap
    // service name. No profile is installed, so well-formed self lookups
    // are allowed.
    constexpr auto macSyscallNumber = UINT64_C(0x0200017D);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress policyAddress{0x8000};
    constexpr rosa::guest::GuestAddress operationAddress{0x8020};
    constexpr rosa::guest::GuestAddress serviceAddress{0x8040};
    constexpr rosa::guest::GuestAddress requestAddress{0x8100};
    constexpr rosa::guest::GuestAddress outputAddress{0x8180};
    constexpr std::array<std::uint8_t, 8> policy{'S', 'a', 'n', 'd', 'b', 'o', 'x', 0};
    constexpr std::array<std::uint8_t, 12> operation{'m', 'a', 'c', 'h', '-', 'l', 'o', 'o',
                                                     'k', 'u', 'p', 0};
    constexpr std::array<std::uint8_t, 26> service{'c', 'o', 'm', '.', 'a', 'p', 'p', 'l', 'e',
                                                   '.', 'w', 'i', 'n', 'd', 'o', 'w', 's', 'e',
                                                   'r', 'v', 'e', 'r', '.', 'x', 'p', 0};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(policyAddress, policy);
    addressSpace.writeBytes(operationAddress, operation);
    addressSpace.writeBytes(serviceAddress, service);
    const std::array<std::uint64_t, 6> fields{
        outputAddress.value, static_cast<std::uint64_t>(::getpid()), operationAddress.value,
        0x6, serviceAddress.value, 1,
    };
    std::array<std::uint8_t, sizeof(fields)> bytes{};
    std::memcpy(bytes.data(), fields.data(), sizeof(fields));
    addressSpace.writeBytes(requestAddress, bytes);
    addressSpace.writeU64(outputAddress, UINT64_MAX);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 2;
    state.rdx = requestAddress.value;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E310B4ULL});
    expect(!outcome.exited, "Sandbox mach-lookup terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "unsandboxed mach-lookup did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "Sandbox mach-lookup did not clear BSD carry");
    expectEqual(addressSpace.readU64(outputAddress), std::uint64_t{0},
                "Sandbox mach-lookup did not report allowed");

    // A foreign pid stays loud.
    std::array<std::uint8_t, sizeof(fields)> foreignBytes{};
    const std::array<std::uint64_t, 6> foreignFields{
        outputAddress.value, static_cast<std::uint64_t>(::getpid()) + 1, operationAddress.value,
        0x6, serviceAddress.value, 1,
    };
    std::memcpy(foreignBytes.data(), foreignFields.data(), sizeof(foreignBytes));
    addressSpace.writeBytes(requestAddress, foreignBytes);
    addressSpace.writeU64(outputAddress, UINT64_MAX);
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 2;
    state.rdx = requestAddress.value;
    bool rejectedPid = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        rejectedPid =
            std::string_view(error.what()).find("mach-lookup") != std::string_view::npos;
    }
    expect(rejectedPid, "foreign-pid mach-lookup did not fail diagnostically");
    expectEqual(addressSpace.readU64(outputAddress), UINT64_MAX,
                "unsupported Sandbox check changed its output");
}

void testDarwinSandboxSyscallCheck() {
    constexpr auto macSyscallNumber = UINT64_C(0x0200017D);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress policyAddress{0x8000};
    constexpr rosa::guest::GuestAddress operationAddress{0x8020};
    constexpr rosa::guest::GuestAddress requestAddress{0x8100};
    constexpr rosa::guest::GuestAddress outputAddress{0x8180};
    constexpr std::array<std::uint8_t, 8> policy{'S', 'a', 'n', 'd', 'b', 'o', 'x', 0};
    constexpr std::array<std::uint8_t, 13> operation{'s', 'y', 's', 'c', 'a', 'l', 'l',
                                                     '-', 'u', 'n', 'i', 'x', 0};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(policyAddress, policy);
    addressSpace.writeBytes(operationAddress, operation);

    const auto writeRequest = [&](std::uint64_t resultAddress, std::uint64_t operationPointer,
                                  std::uint64_t flags) {
        const std::array<std::uint64_t, 6> fields{
            resultAddress, static_cast<std::uint64_t>(::getpid()), operationPointer, 0x41, 550,
            flags,
        };
        std::array<std::uint8_t, sizeof(fields)> bytes{};
        std::memcpy(bytes.data(), fields.data(), sizeof(fields));
        addressSpace.writeBytes(requestAddress, bytes);
        return bytes;
    };

    const auto requestBytes = writeRequest(outputAddress.value, operationAddress.value, 1);
    addressSpace.writeU64(outputAddress, UINT64_MAX);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 2;
    state.rdx = requestAddress.value;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEE7FCULL});
    expect(!outcome.exited, "Sandbox check terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "unsandboxed syscall check did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "Sandbox check did not clear BSD carry");
    expectEqual(addressSpace.readU64(outputAddress), std::uint64_t{0},
                "Sandbox check did not report the syscall allowed");
    expectEqual(addressSpace.readBytes(requestAddress, requestBytes.size()),
                std::vector<std::uint8_t>(requestBytes.begin(), requestBytes.end()),
                "Sandbox check changed its input request");

    addressSpace.writeU64(outputAddress, UINT64_MAX);
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 2;
    state.rdx = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid Sandbox argument pointer returned the wrong errno");
    expectEqual(addressSpace.readU64(outputAddress), UINT64_MAX,
                "faulted Sandbox argument read changed its output");

    static_cast<void>(writeRequest(outputAddress.value, 0x9000, 1));
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 2;
    state.rdx = requestAddress.value;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid Sandbox operation pointer returned the wrong errno");
    expectEqual(addressSpace.readU64(outputAddress), UINT64_MAX,
                "faulted Sandbox operation read changed its output");

    static_cast<void>(writeRequest(0x9000, operationAddress.value, 1));
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 2;
    state.rdx = requestAddress.value;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid Sandbox result pointer returned the wrong errno");

    static_cast<void>(writeRequest(outputAddress.value, operationAddress.value, 0));
    addressSpace.writeU64(outputAddress, UINT64_MAX);
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 2;
    state.rdx = requestAddress.value;
    bool unsupportedFlags = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedFlags =
            std::string_view(error.what()).find("flags=0x0") != std::string_view::npos;
    }
    expect(unsupportedFlags, "unobserved Sandbox flags did not fail diagnostically");
    expectEqual(addressSpace.readU64(outputAddress), UINT64_MAX,
                "unsupported Sandbox check changed its output");
}

void testDarwinAmfiDyldPolicy() {
    constexpr auto macSyscallNumber = UINT64_C(0x0200017D);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress policyAddress{0x8000};
    constexpr rosa::guest::GuestAddress requestAddress{0x8100};
    constexpr rosa::guest::GuestAddress outputAddress{0x8180};
    constexpr std::array<std::uint8_t, 5> policy{'A', 'M', 'F', 'I', 0};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(policyAddress, policy);
    const auto writeRequest = [&](std::uint64_t inputFlags, std::uint64_t outputPointer) {
        const std::array<std::uint64_t, 2> fields{inputFlags, outputPointer};
        std::array<std::uint8_t, sizeof(fields)> bytes{};
        std::memcpy(bytes.data(), fields.data(), sizeof(fields));
        addressSpace.writeBytes(requestAddress, bytes);
        return bytes;
    };

    const auto requestBytes = writeRequest(0, outputAddress.value);
    addressSpace.writeU64(outputAddress, 0xAAAAAAAAAAAAAAAAULL);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 90;
    state.rdx = requestAddress.value;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEE7FCULL});
    expect(!outcome.exited, "AMFI dyld-policy check terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "AMFI dyld-policy check did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "AMFI dyld-policy check did not clear BSD carry");
    expectEqual(addressSpace.readU64(outputAddress), std::uint64_t{0x1DF},
                "unrestricted guest AMFI dyld policy differs");
    expectEqual(addressSpace.readBytes(requestAddress, requestBytes.size()),
                std::vector<std::uint8_t>(requestBytes.begin(), requestBytes.end()),
                "AMFI dyld-policy check changed its input request");

    addressSpace.writeU64(outputAddress, UINT64_MAX);
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 90;
    state.rdx = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid AMFI request returned the wrong errno");
    expectEqual(addressSpace.readU64(outputAddress), UINT64_MAX,
                "faulted AMFI request changed its output");

    static_cast<void>(writeRequest(0, 0x9000));
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 90;
    state.rdx = requestAddress.value;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid AMFI output returned the wrong errno");

    static_cast<void>(writeRequest(2, outputAddress.value));
    addressSpace.writeU64(outputAddress, UINT64_MAX);
    state.rax = macSyscallNumber;
    state.rdi = policyAddress.value;
    state.rsi = 90;
    state.rdx = requestAddress.value;
    bool unsupportedInput = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedInput =
            std::string_view(error.what()).find("input flags 0x2") != std::string_view::npos;
    }
    expect(unsupportedInput, "restricted AMFI input flags did not fail diagnostically");
    expectEqual(addressSpace.readU64(outputAddress), UINT64_MAX,
                "unsupported AMFI policy changed its output");
}

void testDarwinLockdownModeSysctl() {
    constexpr auto sysctlNumber = UINT64_C(0x020000CA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress mibAddress{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    constexpr rosa::guest::GuestAddress lengthAddress{0x8180};
    constexpr rosa::guest::GuestAddress nameAddress{0x8200};
    constexpr std::string_view lockdownName = "security.mac.lockdown_mode_state";

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint32_t, 2> nameToOidMib{0, 3};
    std::array<std::uint8_t, sizeof(nameToOidMib)> nameToOidBytes{};
    std::memcpy(nameToOidBytes.data(), nameToOidMib.data(), sizeof(nameToOidMib));
    addressSpace.writeBytes(mibAddress, nameToOidBytes);
    addressSpace.writeBytes(
        nameAddress,
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t *>(lockdownName.data()),
                                      lockdownName.size()});
    addressSpace.writeU64(lengthAddress, 48);
    constexpr std::array<std::uint8_t, 16> outputSentinel{0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
                                                          0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
                                                          0xA5, 0xA5, 0xA5, 0xA5};
    addressSpace.writeBytes(outputAddress, outputSentinel);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = nameToOidMib.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = nameAddress.value;
    state.r9 = lockdownName.size();
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEEA88ULL});
    expect(!outcome.exited, "name-to-OID sysctl terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "lockdown name-to-OID sysctl did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "name-to-OID sysctl did not clear BSD carry");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{12},
                "name-to-OID sysctl returned the wrong byte length");
    constexpr std::array<std::uint32_t, 3> expectedOid{103, 101, 101};
    const auto oidBytes = addressSpace.readBytes(outputAddress, sizeof(expectedOid));
    std::array<std::uint32_t, 3> actualOid{};
    std::memcpy(actualOid.data(), oidBytes.data(), sizeof(actualOid));
    expectEqual(actualOid, expectedOid, "name-to-OID sysctl returned the wrong guest MIB");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{outputAddress.value + 12}, 4),
                std::vector<std::uint8_t>(4, 0xA5), "name-to-OID sysctl wrote beyond its result");

    addressSpace.writeBytes(mibAddress, oidBytes);
    addressSpace.writeU64(lengthAddress, sizeof(std::uint32_t));
    constexpr std::array<std::uint8_t, 4> dwordSentinel{0xFF, 0xFF, 0xFF, 0xFF};
    addressSpace.writeBytes(outputAddress, dwordSentinel);
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = expectedOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "lockdown-mode sysctl read did not succeed");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "lockdown-mode sysctl read did not clear BSD carry");
    expectEqual(addressSpace.readU32(outputAddress), std::uint32_t{0},
                "guest lockdown-mode state differs");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{4},
                "lockdown-mode sysctl returned the wrong value size");

    addressSpace.writeBytes(mibAddress, nameToOidBytes);
    addressSpace.writeU64(lengthAddress, 48);
    addressSpace.writeBytes(outputAddress, outputSentinel);
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = nameToOidMib.size();
    state.rdx = 0x9000;
    state.r10 = lengthAddress.value;
    state.r8 = nameAddress.value;
    state.r9 = lockdownName.size();
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid name-to-OID output returned the wrong errno");
    expectEqual(addressSpace.readBytes(outputAddress, outputSentinel.size()),
                std::vector<std::uint8_t>(outputSentinel.begin(), outputSentinel.end()),
                "faulted name-to-OID sysctl changed guest output");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{48},
                "faulted name-to-OID sysctl changed guest length");

    state.rax = sysctlNumber;
    state.rdi = 0x9000;
    state.rsi = nameToOidMib.size();
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid sysctl MIB returned the wrong errno");
}

void testDarwinUserStack64Sysctl() {
    constexpr auto sysctlNumber = UINT64_C(0x020000CA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress mibAddress{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    constexpr rosa::guest::GuestAddress lengthAddress{0x8180};
    constexpr std::array<std::uint32_t, 2> userStackOid{1, 59};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    std::array<std::uint8_t, sizeof(userStackOid)> mibBytes{};
    std::memcpy(mibBytes.data(), userStackOid.data(), mibBytes.size());
    addressSpace.writeBytes(mibAddress, mibBytes);
    addressSpace.writeU64(lengthAddress, sizeof(std::uint64_t));
    addressSpace.writeU64(outputAddress, UINT64_MAX);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = userStackOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30EECULL}));
    expectEqual(state.rax, std::uint64_t{0}, "kern.usrstack64 read did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "kern.usrstack64 read did not clear BSD carry");
    expectEqual(addressSpace.readU64(outputAddress), std::uint64_t{0x700000100000ULL},
                "kern.usrstack64 returned the wrong guest stack ceiling");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{8},
                "kern.usrstack64 returned the wrong size");

    addressSpace.writeU64(lengthAddress, 0);
    state.rax = sysctlNumber;
    state.rdx = 0;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "kern.usrstack64 size query did not succeed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{8},
                "kern.usrstack64 size query returned the wrong size");

    addressSpace.writeU64(lengthAddress, 4);
    addressSpace.writeU64(outputAddress, UINT64_MAX);
    state.rax = sysctlNumber;
    state.rdx = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short kern.usrstack64 buffer returned the wrong errno");
    expectEqual(addressSpace.readU64(outputAddress), UINT64_MAX,
                "short kern.usrstack64 buffer was partially changed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{4},
                "short kern.usrstack64 buffer changed its length");

    addressSpace.writeU64(lengthAddress, 8);
    state.rax = sysctlNumber;
    state.rdx = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid kern.usrstack64 output returned the wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{8},
                "faulted kern.usrstack64 read changed its length");
}

void testDarwinBootArgsSysctl() {
    constexpr auto sysctlNumber = UINT64_C(0x020000CA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress mibAddress{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    constexpr rosa::guest::GuestAddress lengthAddress{0x8180};
    constexpr rosa::guest::GuestAddress nameAddress{0x8200};
    constexpr std::string_view bootArgsName = "kern.bootargs";
    constexpr std::array<std::uint32_t, 2> nameToOidMib{0, 3};
    constexpr std::array<std::uint32_t, 2> bootArgsOid{1, 143};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    std::array<std::uint8_t, sizeof(nameToOidMib)> mibBytes{};
    std::memcpy(mibBytes.data(), nameToOidMib.data(), mibBytes.size());
    addressSpace.writeBytes(mibAddress, mibBytes);
    addressSpace.writeBytes(
        nameAddress,
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t *>(bootArgsName.data()),
                                      bootArgsName.size()});
    addressSpace.writeU64(lengthAddress, 48);
    addressSpace.writeBytes(
        outputAddress, std::array<std::uint8_t, 8>{0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5});

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = nameToOidMib.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = nameAddress.value;
    state.r9 = bootArgsName.size();
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEEA88ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "kern.bootargs name-to-OID did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "kern.bootargs name-to-OID did not clear BSD carry");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{8},
                "kern.bootargs name-to-OID returned the wrong size");
    const auto oidBytes = addressSpace.readBytes(outputAddress, sizeof(bootArgsOid));
    std::array<std::uint32_t, 2> actualOid{};
    std::memcpy(actualOid.data(), oidBytes.data(), sizeof(actualOid));
    expectEqual(actualOid, bootArgsOid, "kern.bootargs name-to-OID returned the wrong guest MIB");

    addressSpace.writeBytes(mibAddress, oidBytes);
    addressSpace.writeU64(lengthAddress, 4);
    addressSpace.writeBytes(outputAddress, std::array<std::uint8_t, 4>{0xA5, 0xA5, 0xA5, 0xA5});
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = bootArgsOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest kern.bootargs read did not succeed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{1},
                "guest kern.bootargs returned the wrong length");
    expectEqual(addressSpace.readBytes(outputAddress, 4),
                std::vector<std::uint8_t>{0, 0xA5, 0xA5, 0xA5},
                "guest kern.bootargs did not return exactly one NUL byte");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "guest kern.bootargs read did not clear BSD carry");

    addressSpace.writeU64(lengthAddress, 0);
    state.rax = sysctlNumber;
    state.rdx = 0;
    state.rflags = 0xBD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest kern.bootargs size query did not succeed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{1},
                "guest kern.bootargs size query returned the wrong length");

    addressSpace.writeU64(lengthAddress, 0);
    addressSpace.writeBytes(outputAddress, std::array<std::uint8_t, 1>{0xA5});
    state.rax = sysctlNumber;
    state.rdx = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short kern.bootargs buffer returned the wrong errno");
    expectEqual(addressSpace.readBytes(outputAddress, 1), std::vector<std::uint8_t>{0xA5},
                "short kern.bootargs buffer was partially changed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{0},
                "short kern.bootargs buffer changed its length");

    addressSpace.writeU64(lengthAddress, 4);
    state.rax = sysctlNumber;
    state.rdx = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid kern.bootargs output returned the wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{4},
                "faulted kern.bootargs read changed its length");
}

void testDarwinKernelVersionSysctl() {
    constexpr auto sysctlNumber = UINT64_C(0x020000CA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress mibAddress{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    constexpr rosa::guest::GuestAddress lengthAddress{0x8180};
    constexpr rosa::guest::GuestAddress nameAddress{0x8200};
    constexpr std::string_view name = "kern.version";
    constexpr std::array<std::uint32_t, 2> nameToOid{0, 3};
    constexpr std::array<std::uint32_t, 2> versionOid{1, 4};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    std::array<std::uint8_t, sizeof(nameToOid)> mibBytes{};
    std::memcpy(mibBytes.data(), nameToOid.data(), mibBytes.size());
    addressSpace.writeBytes(mibAddress, mibBytes);
    addressSpace.writeBytes(nameAddress,
                            std::span<const std::uint8_t>{
                                reinterpret_cast<const std::uint8_t *>(name.data()), name.size()});
    addressSpace.writeU64(lengthAddress, 16);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = nameToOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = nameAddress.value;
    state.r9 = name.size();
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEEA88ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "kern.version name-to-OID did not succeed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{8},
                "kern.version name-to-OID returned the wrong size");
    const auto oidBytes = addressSpace.readBytes(outputAddress, sizeof(versionOid));
    std::array<std::uint32_t, 2> actualOid{};
    std::memcpy(actualOid.data(), oidBytes.data(), sizeof(actualOid));
    expectEqual(actualOid, versionOid, "kern.version returned the wrong guest MIB");

    addressSpace.writeBytes(mibAddress, oidBytes);
    addressSpace.writeU64(lengthAddress, 512);
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = versionOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest kern.version read did not succeed");
    const auto versionSize = addressSpace.readU64(lengthAddress);
    expect(versionSize > 32 && versionSize < 512, "guest kern.version length is implausible");
    const auto version =
        addressSpace.readBytes(outputAddress, static_cast<std::size_t>(versionSize));
    constexpr std::string_view prefix = "Darwin Kernel Version ";
    expect(version.size() > prefix.size() && version.back() == 0 &&
               std::equal(prefix.begin(), prefix.end(), version.begin()),
           "guest kern.version bytes differ from Darwin kernel metadata");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "guest kern.version read did not clear BSD carry");

    addressSpace.writeU64(lengthAddress, 0);
    state.rax = sysctlNumber;
    state.rdx = 0;
    state.rflags = 0xBD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest kern.version size query failed");
    expectEqual(addressSpace.readU64(lengthAddress), versionSize,
                "guest kern.version size query returned a different size");

    addressSpace.writeU64(lengthAddress, 4);
    addressSpace.writeBytes(outputAddress, std::array<std::uint8_t, 4>{0xA5, 0xA5, 0xA5, 0xA5});
    state.rax = sysctlNumber;
    state.rdx = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short kern.version buffer returned the wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{0},
                "short kern.version buffer did not report zero copied bytes");
    expectEqual(addressSpace.readBytes(outputAddress, 4),
                std::vector<std::uint8_t>{0xA5, 0xA5, 0xA5, 0xA5},
                "short kern.version buffer was partially changed");

    addressSpace.writeU64(lengthAddress, 512);
    state.rax = sysctlNumber;
    state.rdx = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid kern.version output returned the wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{512},
                "faulted kern.version read changed its length");
}

void testDarwinHwNcpuSysctl() {
    constexpr auto sysctlNumber = UINT64_C(0x020000CA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress mibAddress{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    constexpr rosa::guest::GuestAddress lengthAddress{0x8180};
    constexpr rosa::guest::GuestAddress nameAddress{0x8200};
    constexpr std::string_view name = "hw.ncpu";
    constexpr std::array<std::uint32_t, 2> nameToOid{0, 3};
    constexpr std::array<std::uint32_t, 2> ncpuOid{6, 3};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    std::array<std::uint8_t, sizeof(nameToOid)> mibBytes{};
    std::memcpy(mibBytes.data(), nameToOid.data(), mibBytes.size());
    addressSpace.writeBytes(mibAddress, mibBytes);
    addressSpace.writeBytes(nameAddress,
                            std::span<const std::uint8_t>{
                                reinterpret_cast<const std::uint8_t *>(name.data()), name.size()});
    addressSpace.writeU64(lengthAddress, 16);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = nameToOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = nameAddress.value;
    state.r9 = name.size();
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30EECULL}));
    expectEqual(state.rax, std::uint64_t{0}, "hw.ncpu name-to-OID did not succeed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{8},
                "hw.ncpu name-to-OID returned the wrong size");
    const auto oidBytes = addressSpace.readBytes(outputAddress, sizeof(ncpuOid));
    std::array<std::uint32_t, 2> actualOid{};
    std::memcpy(actualOid.data(), oidBytes.data(), sizeof(actualOid));
    expectEqual(actualOid, ncpuOid, "hw.ncpu returned the wrong guest MIB");

    addressSpace.writeBytes(mibAddress, oidBytes);
    addressSpace.writeU64(lengthAddress, 4);
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = ncpuOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest hw.ncpu read did not succeed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{4},
                "guest hw.ncpu read returned the wrong size");
    std::int32_t count = 0;
    const auto countBytes = addressSpace.readBytes(outputAddress, sizeof(count));
    std::memcpy(&count, countBytes.data(), sizeof(count));
    expect(count > 0 && count < 1024, "guest hw.ncpu count is implausible");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "guest hw.ncpu read did not clear BSD carry");

    addressSpace.writeU64(lengthAddress, 0);
    state.rax = sysctlNumber;
    state.rdx = 0;
    state.rflags = 0xBD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest hw.ncpu size query failed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{4},
                "guest hw.ncpu size query returned the wrong size");

    addressSpace.writeU64(lengthAddress, 2);
    state.rax = sysctlNumber;
    state.rdx = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short hw.ncpu buffer returned the wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{0},
                "short hw.ncpu buffer did not report zero copied bytes");
}

void testDarwinProductVersionSysctl() {
    constexpr auto sysctlNumber = UINT64_C(0x020000CA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress mibAddress{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    constexpr rosa::guest::GuestAddress lengthAddress{0x8180};
    constexpr rosa::guest::GuestAddress nameAddress{0x8200};
    constexpr std::string_view name = "kern.osproductversion";
    constexpr std::array<std::uint32_t, 2> nameToOid{0, 3};
    constexpr std::array<std::uint32_t, 2> productVersionOid{1, 138};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    std::array<std::uint8_t, sizeof(nameToOid)> mibBytes{};
    std::memcpy(mibBytes.data(), nameToOid.data(), mibBytes.size());
    addressSpace.writeBytes(mibAddress, mibBytes);
    addressSpace.writeBytes(nameAddress,
                            std::span<const std::uint8_t>{
                                reinterpret_cast<const std::uint8_t *>(name.data()), name.size()});
    addressSpace.writeU64(lengthAddress, 16);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = nameToOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = nameAddress.value;
    state.r9 = name.size();
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30EECULL}));
    expectEqual(state.rax, std::uint64_t{0}, "kern.osproductversion name-to-OID did not succeed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{8},
                "kern.osproductversion name-to-OID returned the wrong size");
    const auto oidBytes = addressSpace.readBytes(outputAddress, sizeof(productVersionOid));
    std::array<std::uint32_t, 2> actualOid{};
    std::memcpy(actualOid.data(), oidBytes.data(), sizeof(actualOid));
    expectEqual(actualOid, productVersionOid, "kern.osproductversion returned the wrong guest MIB");

    addressSpace.writeBytes(mibAddress, oidBytes);
    addressSpace.writeU64(lengthAddress, 64);
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = productVersionOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest kern.osproductversion read did not succeed");
    const auto versionSize = addressSpace.readU64(lengthAddress);
    expect(versionSize >= 4 && versionSize < 64,
           "guest kern.osproductversion length is implausible");
    const auto version =
        addressSpace.readBytes(outputAddress, static_cast<std::size_t>(versionSize));
    expect(version.back() == 0 && std::count(version.begin(), version.end() - 1, '.') >= 1 &&
               std::all_of(version.begin(), version.end() - 1,
                           [](std::uint8_t character) {
                               return (character >= '0' && character <= '9') || character == '.';
                           }),
           "guest kern.osproductversion is not a dotted version string");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "guest kern.osproductversion did not clear BSD carry");

    addressSpace.writeU64(lengthAddress, 0);
    state.rax = sysctlNumber;
    state.rdx = 0;
    state.rflags = 0xBD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest kern.osproductversion size query failed");
    expectEqual(addressSpace.readU64(lengthAddress), versionSize,
                "guest kern.osproductversion size query changed size");

    addressSpace.writeU64(lengthAddress, 1);
    addressSpace.writeBytes(outputAddress, std::array<std::uint8_t, 1>{0xA5});
    state.rax = sysctlNumber;
    state.rdx = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short kern.osproductversion buffer returned wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{0},
                "short kern.osproductversion did not report zero bytes");
    expectEqual(addressSpace.readBytes(outputAddress, 1), std::vector<std::uint8_t>{0xA5},
                "short kern.osproductversion partially changed output");

    addressSpace.writeU64(lengthAddress, 64);
    state.rax = sysctlNumber;
    state.rdx = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid kern.osproductversion output returned wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{64},
                "faulted kern.osproductversion changed its length");
}

void testDarwinIosSupportVersionSysctl() {
    constexpr auto sysctlNumber = UINT64_C(0x020000CA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress mibAddress{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    constexpr rosa::guest::GuestAddress lengthAddress{0x8180};
    constexpr rosa::guest::GuestAddress nameAddress{0x8200};
    constexpr std::string_view name = "kern.iossupportversion";
    constexpr std::array<std::uint32_t, 2> nameToOid{0, 3};
    constexpr std::array<std::uint32_t, 2> supportVersionOid{1, 140};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    std::array<std::uint8_t, sizeof(nameToOid)> mibBytes{};
    std::memcpy(mibBytes.data(), nameToOid.data(), mibBytes.size());
    addressSpace.writeBytes(mibAddress, mibBytes);
    addressSpace.writeBytes(nameAddress,
                            std::span<const std::uint8_t>{
                                reinterpret_cast<const std::uint8_t *>(name.data()), name.size()});
    addressSpace.writeU64(lengthAddress, 16);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = nameToOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = nameAddress.value;
    state.r9 = name.size();
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30EECULL}));
    expectEqual(state.rax, std::uint64_t{0}, "kern.iossupportversion name-to-OID did not succeed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{8},
                "kern.iossupportversion name-to-OID returned wrong size");
    const auto oidBytes = addressSpace.readBytes(outputAddress, sizeof(supportVersionOid));
    std::array<std::uint32_t, 2> actualOid{};
    std::memcpy(actualOid.data(), oidBytes.data(), sizeof(actualOid));
    expectEqual(actualOid, supportVersionOid,
                "kern.iossupportversion returned the wrong guest MIB");

    addressSpace.writeBytes(mibAddress, oidBytes);
    addressSpace.writeU64(lengthAddress, 64);
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = supportVersionOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest kern.iossupportversion read did not succeed");
    const auto versionSize = addressSpace.readU64(lengthAddress);
    expect(versionSize >= 4 && versionSize < 64,
           "guest kern.iossupportversion length is implausible");
    const auto version =
        addressSpace.readBytes(outputAddress, static_cast<std::size_t>(versionSize));
    expect(version.back() == 0 && std::count(version.begin(), version.end() - 1, '.') >= 1 &&
               std::all_of(version.begin(), version.end() - 1,
                           [](std::uint8_t character) {
                               return (character >= '0' && character <= '9') || character == '.';
                           }),
           "guest kern.iossupportversion is not a dotted version string");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "guest kern.iossupportversion did not clear BSD carry");

    addressSpace.writeU64(lengthAddress, 0);
    state.rax = sysctlNumber;
    state.rdx = 0;
    state.rflags = 0xBD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest kern.iossupportversion size query failed");
    expectEqual(addressSpace.readU64(lengthAddress), versionSize,
                "guest kern.iossupportversion size query changed size");

    addressSpace.writeU64(lengthAddress, 1);
    addressSpace.writeBytes(outputAddress, std::array<std::uint8_t, 1>{0xA5});
    state.rax = sysctlNumber;
    state.rdx = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short kern.iossupportversion buffer returned wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{0},
                "short kern.iossupportversion did not report zero bytes");
    expectEqual(addressSpace.readBytes(outputAddress, 1), std::vector<std::uint8_t>{0xA5},
                "short kern.iossupportversion partially changed output");

    addressSpace.writeU64(lengthAddress, 64);
    state.rax = sysctlNumber;
    state.rdx = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid kern.iossupportversion output returned wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{64},
                "faulted kern.iossupportversion changed its length");
}

void testDarwinSysctlKernProcPid() {
    // Observed under an Objective-C fixture: CoreFoundation reads its own
    // kinfo_proc during process-name resolution.
    constexpr auto sysctlNumber = UINT64_C(0x020000CA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress mibAddress{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    constexpr rosa::guest::GuestAddress lengthAddress{0x8400};
    const std::array<std::uint32_t, 4> procPidOid{
        1, 14, 1, static_cast<std::uint32_t>(::getpid())};

    int hostMib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID,
                      static_cast<int>(procPidOid[3])};
    struct kinfo_proc hostInfo {};
    std::size_t hostSize = sizeof(hostInfo);
    expect(::sysctl(hostMib, 4, &hostInfo, &hostSize, nullptr, 0) == 0,
           "could not sysctl the host kinfo_proc fixture");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    std::array<std::uint8_t, sizeof(procPidOid)> mibBytes{};
    std::memcpy(mibBytes.data(), procPidOid.data(), mibBytes.size());
    addressSpace.writeBytes(mibAddress, mibBytes);
    addressSpace.writeU64(lengthAddress, hostSize);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = procPidOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30EECULL}));
    expectEqual(state.rax, std::uint64_t{0}, "kern.proc.pid read did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "kern.proc.pid read did not clear BSD carry");
    expectEqual(addressSpace.readU64(lengthAddress), hostSize,
                "kern.proc.pid returned the wrong size");
    expect(addressSpace.readBytes(outputAddress, hostSize) ==
               std::vector<std::uint8_t>(
                   reinterpret_cast<const std::uint8_t *>(&hostInfo),
                   reinterpret_cast<const std::uint8_t *>(&hostInfo) + hostSize),
           "kern.proc.pid returned the wrong bytes");

    // A foreign PID is outside the single-process model.
    const std::array<std::uint32_t, 4> foreignOid{1, 14, 1, 0x42424242};
    std::array<std::uint8_t, sizeof(foreignOid)> foreignBytes{};
    std::memcpy(foreignBytes.data(), foreignOid.data(), foreignBytes.size());
    addressSpace.writeBytes(mibAddress, foreignBytes);
    state.rax = sysctlNumber;
    state.rdx = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ESRCH),
                "foreign kern.proc.pid returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "foreign kern.proc.pid did not set BSD carry");

    // A short buffer reports ENOMEM with the required length.
    addressSpace.writeBytes(mibAddress, mibBytes);
    addressSpace.writeU64(lengthAddress, hostSize - 1);
    state.rax = sysctlNumber;
    state.rdx = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short kern.proc.pid buffer returned the wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), hostSize,
                "short kern.proc.pid buffer did not report its required length");
}

void testDarwinOsVariantStatusSysctl() {
    constexpr auto sysctlNumber = UINT64_C(0x020000CA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress mibAddress{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    constexpr rosa::guest::GuestAddress lengthAddress{0x8180};
    constexpr rosa::guest::GuestAddress nameAddress{0x8200};
    constexpr std::string_view name = "kern.osvariant_status";
    constexpr std::array<std::uint32_t, 2> nameToOid{0, 3};
    constexpr std::array<std::uint32_t, 2> statusOid{1, 141};

    std::uint64_t expectedStatus = 0;
    std::size_t expectedSize = sizeof(expectedStatus);
    expect(::sysctlbyname(name.data(), &expectedStatus, &expectedSize, nullptr, 0) == 0 &&
               expectedSize == sizeof(expectedStatus),
           "host kern.osvariant_status query failed");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    std::array<std::uint8_t, sizeof(nameToOid)> mibBytes{};
    std::memcpy(mibBytes.data(), nameToOid.data(), mibBytes.size());
    addressSpace.writeBytes(mibAddress, mibBytes);
    addressSpace.writeBytes(nameAddress,
                            std::span<const std::uint8_t>{
                                reinterpret_cast<const std::uint8_t *>(name.data()), name.size()});
    addressSpace.writeU64(lengthAddress, 16);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = nameToOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = nameAddress.value;
    state.r9 = name.size();
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30EECULL}));
    expectEqual(state.rax, std::uint64_t{0}, "kern.osvariant_status name-to-OID did not succeed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{8},
                "kern.osvariant_status name-to-OID returned wrong size");
    const auto oidBytes = addressSpace.readBytes(outputAddress, sizeof(statusOid));
    std::array<std::uint32_t, 2> actualOid{};
    std::memcpy(actualOid.data(), oidBytes.data(), sizeof(actualOid));
    expectEqual(actualOid, statusOid, "kern.osvariant_status returned the wrong guest MIB");

    addressSpace.writeBytes(mibAddress, oidBytes);
    addressSpace.writeU64(lengthAddress, sizeof(expectedStatus));
    state.rax = sysctlNumber;
    state.rdi = mibAddress.value;
    state.rsi = statusOid.size();
    state.rdx = outputAddress.value;
    state.r10 = lengthAddress.value;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest kern.osvariant_status read did not succeed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{sizeof(expectedStatus)},
                "guest kern.osvariant_status returned wrong size");
    expectEqual(addressSpace.readU64(outputAddress), expectedStatus,
                "guest kern.osvariant_status did not mirror the host");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "guest kern.osvariant_status did not clear BSD carry");

    addressSpace.writeU64(lengthAddress, 0);
    state.rax = sysctlNumber;
    state.rdx = 0;
    state.rflags = 0xBD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "guest kern.osvariant_status size query failed");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{sizeof(expectedStatus)},
                "guest kern.osvariant_status size query returned wrong size");

    addressSpace.writeU64(lengthAddress, 1);
    addressSpace.writeBytes(outputAddress, std::array<std::uint8_t, 1>{0xA5});
    state.rax = sysctlNumber;
    state.rdx = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short kern.osvariant_status buffer returned wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{0},
                "short kern.osvariant_status did not report zero bytes");
    expectEqual(addressSpace.readBytes(outputAddress, 1), std::vector<std::uint8_t>{0xA5},
                "short kern.osvariant_status changed output");

    addressSpace.writeU64(lengthAddress, sizeof(expectedStatus));
    state.rax = sysctlNumber;
    state.rdx = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid kern.osvariant_status output returned wrong errno");
    expectEqual(addressSpace.readU64(lengthAddress), std::uint64_t{sizeof(expectedStatus)},
                "faulted kern.osvariant_status changed its length");
}

} // namespace

std::span<const TestCase> darwinProcessTests() {
    static const TestCase cases[]{
        {"Darwin bsdthread_register", testDarwinBsdthreadRegister},
        {"Darwin getpid", testDarwinGetpid},
        {"Darwin getuid", testDarwinGetuid},
        {"Darwin geteuid", testDarwinGeteuid},
        {"Darwin gettid without override identity", testDarwinGettidReportsNoOverrideIdentity},
        {"Darwin getegid", testDarwinGetegid},
        {"Darwin getrlimit", testDarwinGetrlimit},
        {"Darwin sigaction", testDarwinSigaction},
        {"Darwin gettimeofday", testDarwinGettimeofday},
        {"Darwin issetugid", testDarwinIssetugid},
        {"Darwin ioctl standard descriptor type", testDarwinIoctlStandardDescriptorType},
        {"Darwin sysctl kern.osversion", testDarwinSysctlOsversion},
        {"Darwin Sandbox mach-lookup check", testDarwinSandboxMachLookupCheck},
        {"Darwin Sandbox syscall check", testDarwinSandboxSyscallCheck},
        {"Darwin AMFI dyld policy", testDarwinAmfiDyldPolicy},
        {"Darwin lockdown-mode sysctl", testDarwinLockdownModeSysctl},
        {"Darwin 64-bit user-stack sysctl", testDarwinUserStack64Sysctl},
        {"Darwin boot-arguments sysctl", testDarwinBootArgsSysctl},
        {"Darwin kernel-version sysctl", testDarwinKernelVersionSysctl},
        {"Darwin hw.ncpu sysctl", testDarwinHwNcpuSysctl},
        {"Darwin product-version sysctl", testDarwinProductVersionSysctl},
        {"Darwin iOS-support-version sysctl", testDarwinIosSupportVersionSysctl},
        {"Darwin OS-variant-status sysctl", testDarwinOsVariantStatusSysctl},
        {"Darwin kern.proc.pid sysctl", testDarwinSysctlKernProcPid},
        {"Darwin thread_selfid", testDarwinThreadSelfid},
    };
    return cases;
}

} // namespace rosa::tests
