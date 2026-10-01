#include "darwin/SyscallInternal.h"

namespace rosa::darwin::detail {
namespace {

template <typename T>
T decodeGuestPthreadField(std::span<const std::uint8_t> bytes,
                          std::size_t offset) {
    static_assert(std::is_integral_v<T>);
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        throw std::runtime_error(
            "guest pthread registration field exceeds its record");
    }
    T value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}

audit_token_t currentProcessAuditToken() {
    audit_token_t token{};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    const auto result = task_info(
        mach_task_self(), TASK_AUDIT_TOKEN,
        reinterpret_cast<task_info_t>(&token), &count);
    if (result != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT) {
        std::ostringstream stream;
        stream << "task_info(TASK_AUDIT_TOKEN) failed for guest syscall: "
               << result << " count=" << count;
        throw std::runtime_error(stream.str());
    }
    return token;
}

struct GuestProcUniqueIdentifierInfo {
    std::array<std::uint8_t, 16> uuid{};
    std::uint64_t uniqueId{};
    std::uint64_t parentUniqueId{};
    std::int32_t idVersion{};
    std::uint32_t reserved2{};
    std::uint64_t reserved3{};
    std::uint64_t reserved4{};
};

static_assert(sizeof(GuestProcUniqueIdentifierInfo) == 56);
static_assert(offsetof(GuestProcUniqueIdentifierInfo, uniqueId) == 16);
static_assert(offsetof(GuestProcUniqueIdentifierInfo, idVersion) == 32);

struct GuestProcBsdShortInfo {
    std::uint32_t pid{};
    std::uint32_t parentPid{};
    std::uint32_t processGroupId{};
    std::uint32_t status{};
    std::array<char, 16> command{};
    std::uint32_t flags{};
    std::uint32_t uid{};
    std::uint32_t gid{};
    std::uint32_t realUid{};
    std::uint32_t realGid{};
    std::uint32_t savedUid{};
    std::uint32_t savedGid{};
    std::uint32_t reserved{};
};

static_assert(sizeof(GuestProcBsdShortInfo) == 64);
static_assert(offsetof(GuestProcBsdShortInfo, command) == 16);
static_assert(offsetof(GuestProcBsdShortInfo, flags) == 32);

GuestProcBsdShortInfo guestProcBsdShortInfo(std::uint64_t argument) {
    GuestProcBsdShortInfo result{};
    const auto returned = ::proc_pidinfo(
        ::getpid(), procPidShortBsdInfo, argument, &result,
        static_cast<int>(sizeof(result)));
    if (returned != sizeof(result)) {
        std::ostringstream reason;
        reason << "cannot query host short BSD process information: returned="
               << returned << " errno=" << errno;
        throw std::runtime_error(reason.str());
    }
    return result;
}

GuestProcUniqueIdentifierInfo guestProcUniqueIdentifierInfo(
    const std::array<std::uint8_t, 16> &executableUuid) {
    GuestProcUniqueIdentifierInfo result{};
    const auto returned = ::proc_pidinfo(
        ::getpid(), procPidUniqueIdentifierInfo, 0, &result,
        static_cast<int>(sizeof(result)));
    if (returned != sizeof(result)) {
        std::ostringstream reason;
        reason << "cannot query host process-generation identifiers: returned="
               << returned << " errno=" << errno;
        throw std::runtime_error(reason.str());
    }
    result.uuid = executableUuid;
    return result;
}

// Private x86_64 Sandbox policy call-2 ABI observed in the guest dyld cache.
// Every address remains a guest integer until copied through AddressSpace.
struct GuestSandboxCheckRequest {
    std::uint64_t resultAddress;
    std::uint64_t pid;
    std::uint64_t operationAddress;
    std::uint64_t filterType;
    std::uint64_t value;
    std::uint64_t flags;
};

static_assert(sizeof(GuestSandboxCheckRequest) == 48);

struct GuestAmfiDyldPolicyRequest {
    std::uint64_t inputFlags;
    std::uint64_t outputAddress;
};

static_assert(sizeof(GuestAmfiDyldPolicyRequest) == 16);

struct GuestTimeval64 {
    std::int64_t seconds;
    std::int32_t microseconds;
    std::int32_t padding;
};

static_assert(sizeof(GuestTimeval64) == 16);

struct GuestTimezone {
    std::int32_t minutesWest;
    std::int32_t daylightSavingsTime;
};

static_assert(sizeof(GuestTimezone) == 8);

} // namespace

SyscallOutcome handleExit(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    const auto rawStatus = static_cast<std::uint32_t>(state.rdi);
    return SyscallOutcome{
        .exited = true,
        .exitStatus = static_cast<int>(std::bit_cast<std::int32_t>(rawStatus)),
    };
}

SyscallOutcome handleBsdthreadRegister(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    if (task.pthreadRegistration) {
        setError(state, EINVAL);
        return {};
    }
    if (state.r8 != guestPthreadRegistrationDataSize) {
        std::ostringstream reason;
        reason << "unsupported bsdthread_register data size 0x"
               << std::hex << state.r8;
        throw unsupported(state, syscallRip, reason.str());
    }
    std::vector<std::uint8_t> data;
    try {
        addressSpace.validateAccess(guest::GuestAddress{state.rdi}, 1,
                                    guest::Permission::Execute);
        addressSpace.validateAccess(guest::GuestAddress{state.rsi}, 1,
                                    guest::Permission::Execute);
        data = addressSpace.readBytes(
            guest::GuestAddress{state.r10},
            guestPthreadRegistrationDataSize);
        addressSpace.validateAccess(
            guest::GuestAddress{state.r10},
            guestPthreadRegistrationDataSize,
            guest::Permission::Write);
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }

    const auto version =
        decodeGuestPthreadField<std::uint64_t>(data, 0);
    const auto dispatchQueueOffset =
        decodeGuestPthreadField<std::uint64_t>(data, 8);
    const auto mainQos =
        decodeGuestPthreadField<std::uint64_t>(data, 16);
    const auto tsdOffset =
        decodeGuestPthreadField<std::uint32_t>(data, 24);
    const auto returnToKernelOffset =
        decodeGuestPthreadField<std::uint32_t>(data, 28);
    const auto machThreadSelfOffset =
        decodeGuestPthreadField<std::uint32_t>(data, 32);
    const auto stackAddressHint =
        decodeGuestPthreadField<std::uint64_t>(data, 36);
    const auto mutexDefaultPolicy =
        decodeGuestPthreadField<std::uint32_t>(data, 44);
    const auto joinableOffsetBits =
        decodeGuestPthreadField<std::uint32_t>(data, 48);
    const auto workqueueQuantumExpiryOffset =
        decodeGuestPthreadField<std::uint32_t>(data, 52);
    if (state.rdx != observedGuestPthreadSize ||
        version != guestPthreadRegistrationDataSize ||
        state.r9 != observedDispatchQueueOffset ||
        dispatchQueueOffset != observedDispatchQueueOffset ||
        mainQos != 0 || tsdOffset != 0xE0 ||
        returnToKernelOffset != 0x28 ||
        machThreadSelfOffset != 0x18 || stackAddressHint != 0 ||
        mutexDefaultPolicy != 0 || joinableOffsetBits != 0x188 ||
        workqueueQuantumExpiryOffset != 0x3C0) {
        std::ostringstream reason;
        reason << "unsupported bsdthread_register record: pthread-size=0x"
               << std::hex << state.rdx << " version=0x" << version
               << " dq-offset=0x" << dispatchQueueOffset
               << " tsd-offset=0x" << tsdOffset
               << " return-offset=0x" << returnToKernelOffset
               << " thread-port-offset=0x" << machThreadSelfOffset
               << " joinable-bits=0x" << joinableOffsetBits
               << " quantum-offset=0x"
               << workqueueQuantumExpiryOffset;
        throw unsupported(state, syscallRip, reason.str());
    }

    // The kernel ABI copies this packed record back even when outgoing
    // values are zero. Preserve those zeros: Rosa has no child-thread
    // stack allocator or QoS/mutex policy to advertise yet.
    addressSpace.writeBytes(guest::GuestAddress{state.r10}, data);
    task.pthreadRegistration = GuestPthreadRegistration{
        .threadStart = guest::GuestAddress{state.rdi},
        .workqueueThreadStart = guest::GuestAddress{state.rsi},
        .pthreadSize = static_cast<std::uint32_t>(state.rdx),
        .dataAddress = guest::GuestAddress{state.r10},
        .dataSize = state.r8,
        .dispatchQueueOffset = dispatchQueueOffset,
        .tsdOffset = tsdOffset,
        .returnToKernelOffset = returnToKernelOffset,
        .machThreadSelfOffset = machThreadSelfOffset,
        .joinableOffsetBits = joinableOffsetBits,
        .workqueueQuantumExpiryOffset = workqueueQuantumExpiryOffset,
    };
    // A zero return is the ABI's documented old-kernel compatibility
    // value. It avoids advertising workqueue/kevent/QoS features Rosa
    // cannot yet provide while allowing single-thread pthread startup.
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleThreadSelfid(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    setSuccess(state, initialGuestThreadId);
    return {};
}

SyscallOutcome handleGettimeofday(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    const auto timevalAddress = guest::GuestAddress{state.rdi};
    const auto timezoneAddress = guest::GuestAddress{state.rsi};
    const auto absoluteTimeAddress = guest::GuestAddress{state.rdx};
    try {
        if (state.rdi != 0) {
            addressSpace.validateAccess(timevalAddress,
                                        sizeof(GuestTimeval64),
                                        guest::Permission::Write);
        }
        if (state.rsi != 0) {
            addressSpace.validateAccess(timezoneAddress,
                                        sizeof(GuestTimezone),
                                        guest::Permission::Write);
        }
        if (state.rdx != 0) {
            addressSpace.validateAccess(absoluteTimeAddress,
                                        sizeof(std::uint64_t),
                                        guest::Permission::Write);
        }
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }

    GuestTimeval64 guestTime{};
    std::uint64_t absoluteTime = 0;
    if (state.rdi != 0 || state.rdx != 0) {
        const auto absoluteBefore = sampleX86TimestampCounter() / 2U;
        timeval hostTime{};
        if (::gettimeofday(&hostTime, nullptr) != 0 ||
            hostTime.tv_sec < 0 || hostTime.tv_usec < 0 ||
            hostTime.tv_usec >= 1'000'000) {
            throw std::runtime_error("cannot sample the host wall clock");
        }
        const auto absoluteAfter = sampleX86TimestampCounter() / 2U;
        absoluteTime =
            absoluteBefore + ((absoluteAfter - absoluteBefore) / 2U);
        // XNU deliberately narrows seconds through uint32_t so x86 and
        // arm64 observe the same 64-bit user timeval representation.
        guestTime.seconds = static_cast<std::uint32_t>(hostTime.tv_sec);
        guestTime.microseconds =
            static_cast<std::int32_t>(hostTime.tv_usec);
    }

    if (state.rdi != 0) {
        std::array<std::uint8_t, sizeof(guestTime)> bytes{};
        std::memcpy(bytes.data(), &guestTime, sizeof(guestTime));
        addressSpace.writeBytes(timevalAddress, bytes);
    }
    if (state.rsi != 0) {
        // Darwin's kernel timezone is obsolete process-global state. Rosa
        // exposes the normal UTC/no-DST default without borrowing host
        // kernel policy.
        constexpr std::array<std::uint8_t, sizeof(GuestTimezone)>
            utcTimezone{};
        addressSpace.writeBytes(timezoneAddress, utcTimezone);
    }
    if (state.rdx != 0) {
        addressSpace.writeU64(absoluteTimeAddress, absoluteTime);
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleIssetugid(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    // The controlled guest image is launched directly by Rosa without a
    // set-user-ID or set-group-ID transition. Keep this guest process
    // policy independent of the credentials of Rosa's host process.
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleGetpid(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    // Rosa currently has one guest process hosted by one Rosa process, so
    // the host PID is also its externally observable guest process ID.
    setSuccess(state, static_cast<std::uint64_t>(::getpid()));
    return {};
}

SyscallOutcome handleGetuid(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    // Same one-process model as getpid: the host user ID is the guest's
    // externally observable real user ID.
    setSuccess(state, static_cast<std::uint64_t>(::getuid()));
    return {};
}

SyscallOutcome handleGeteuid(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    // Same one-process model: the host effective user ID is the guest's.
    setSuccess(state, static_cast<std::uint64_t>(::geteuid()));
    return {};
}

SyscallOutcome handleGettid(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    // XNU's gettid reports the per-thread UID/GID override identity and
    // returns ESRCH when none is active. Rosa never activates one, so
    // report ESRCH exactly like XNU does for ordinary threads (checked
    // before touching the out-pointers). CoreFoundation expects this and
    // falls back to its default identity.
    setError(state, ESRCH);
    return {};
}

SyscallOutcome handleGetegid(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    // Same one-process model as getuid/geteuid: the host effective group
    // ID is the guest's. Reached as CoreFoundation's gettid fallback.
    setSuccess(state, static_cast<std::uint64_t>(::getegid()));
    return {};
}

SyscallOutcome handleGetrlimit(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    // The libc wrapper ORs in _RLIMIT_POSIX_FLAG (0x1000); XNU masks it
    // out and rejects resources past RLIM_NLIMITS. Answer from the host
    // process limits, which launchd provisions identically for the
    // translated guest. struct rlimit is two little-endian u64s.
    const auto resource =
        static_cast<std::uint32_t>(state.rdi) & ~guestRlimitPosixFlag;
    if (resource >= guestRlimitCount) {
        setError(state, EINVAL);
        return {};
    }
    struct rlimit limits{};
    if (::getrlimit(resource, &limits) != 0) {
        setError(state, errno);
        return {};
    }
    std::array<std::uint8_t, sizeof(limits)> limitBytes{};
    static_assert(sizeof(limitBytes) == 16);
    std::memcpy(limitBytes.data(), &limits, sizeof(limits));
    try {
        addressSpace.writeBytes(guest::GuestAddress{state.rsi}, limitBytes);
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleSigaction(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    // Rosa has no signal delivery: the single guest thread never receives
    // a host signal. Keep dispositions as task-local guest state so
    // library initialization can install and query handlers and proceed.
    // Arguments are the signal number in RDI, the new 16-byte struct
    // sigaction in RSI (or null to query), and the old-action copyout in
    // RDX (or null to skip it).
    if (state.rdi < 1 || state.rdi > 31) {
        setError(state, EINVAL);
        return {};
    }
    const auto signum = static_cast<std::int32_t>(state.rdi);
    const auto previous = task.signalDispositions.contains(signum)
                              ? task.signalDispositions.at(signum)
                              : GuestSignalDisposition{};
    if (state.rsi != 0) {
        GuestSignalDisposition next{};
        try {
            const auto bytes =
                addressSpace.readBytes(guest::GuestAddress{state.rsi}, 16);
            std::memcpy(&next.handlerAddress, bytes.data(), 8);
            std::memcpy(&next.mask, bytes.data() + 8, 4);
            std::memcpy(&next.flags, bytes.data() + 12, 4);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        task.signalDispositions[signum] = next;
    }
    if (state.rdx != 0) {
        std::array<std::uint8_t, 16> previousBytes{};
        std::memcpy(previousBytes.data(), &previous.handlerAddress, 8);
        std::memcpy(previousBytes.data() + 8, &previous.mask, 4);
        std::memcpy(previousBytes.data() + 12, &previous.flags, 4);
        try {
            addressSpace.writeBytes(guest::GuestAddress{state.rdx}, previousBytes);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleCsops(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(task);
    const auto pid = static_cast<std::uint32_t>(state.rdi);
    const auto operation = static_cast<std::uint32_t>(state.rsi);
    if (pid == static_cast<std::uint32_t>(::getpid()) &&
        operation == guestCsOpsDerEntitlementsBlob) {
        // Same unsigned-guest reasoning as the audit-token DER
        // entitlements path below: no code signing blob exists, so the
        // query fails with EINVAL without touching the output buffer.
        setError(state, EINVAL);
        return {};
    }
    if (pid != static_cast<std::uint32_t>(::getpid()) ||
        operation != guestCsOpsStatus || state.r10 != sizeof(std::uint32_t)) {
        std::ostringstream reason;
        reason << "only CS_OPS_STATUS and unsigned CS_OPS_DER_ENTITLEMENTS_BLOB for the current guest process are implemented; got pid="
               << std::dec << pid << " operation=" << operation
               << " size=" << state.r10;
        throw unsupported(state, syscallRip, reason.str());
    }
    try {
        addressSpace.writeU32(guest::GuestAddress{state.rdx},
                              guestUnsignedCodeSigningStatus);
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleCsopsAuditToken(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(task);
    const auto pid = static_cast<std::uint32_t>(state.rdi);
    const auto operation = static_cast<std::uint32_t>(state.rsi);
    if (pid != static_cast<std::uint32_t>(::getpid()) ||
        operation != guestCsOpsDerEntitlementsBlob ||
        state.r10 != observedGuestDerEntitlementsBufferSize ||
        state.r8 == 0) {
        std::ostringstream reason;
        reason << "only CS_OPS_DER_ENTITLEMENTS_BLOB with an audit token for the current unsigned guest process is implemented; got pid="
               << std::dec << pid << " operation=" << operation
               << " size=" << state.r10 << " token=0x" << std::hex
               << state.r8;
        throw unsupported(state, syscallRip, reason.str());
    }

    audit_token_t guestToken{};
    try {
        const auto bytes = addressSpace.readBytes(
            guest::GuestAddress{state.r8}, sizeof(guestToken));
        std::memcpy(&guestToken, bytes.data(), sizeof(guestToken));
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    const auto expectedToken = currentProcessAuditToken();
    if (guestToken.val[5] != expectedToken.val[5] ||
        guestToken.val[7] != expectedToken.val[7]) {
        setError(state, ESRCH);
        return {};
    }

    // XNU validates the supplied audit token before consulting the code
    // signing blob. Rosa's controlled guest image is unsigned (matching
    // CS_OPS_STATUS above), so DER entitlements fail with EINVAL without
    // reading or writing the caller's output buffer.
    setError(state, EINVAL);
    return {};
}

SyscallOutcome handleProcInfo(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto callNumber = std::bit_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.rdi));
    if (callNumber == procInfoCallPidInfo) {
        const auto pid = std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.rsi));
        const auto flavor = static_cast<std::uint32_t>(state.rdx);
        if (pid != static_cast<std::int32_t>(::getpid())) {
            setError(state, ESRCH);
            return {};
        }
        if (flavor != procPidUniqueIdentifierInfo &&
            flavor != procPidShortBsdInfo) {
            throw unsupported(
                state, syscallRip,
                "only PROC_PIDT_SHORTBSDINFO and PROC_PIDUNIQIDENTIFIERINFO for the current guest process are implemented");
        }
        const auto signedSize = std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.r9));
        const auto requiredSize =
            flavor == procPidShortBsdInfo
                ? sizeof(GuestProcBsdShortInfo)
                : sizeof(GuestProcUniqueIdentifierInfo);
        if (signedSize < static_cast<std::int32_t>(requiredSize)) {
            setError(state, ENOMEM);
            return {};
        }
        if (flavor == procPidUniqueIdentifierInfo && state.r10 != 0 && state.r10 != 1) {
            throw unsupported(
                state, syscallRip,
                "only active-process PROC_PIDUNIQIDENTIFIERINFO is implemented");
        }
        // XNU fills the same unique-identifier record for arg 0 and 1;
        // AppKit startup probes with arg 1. Other arguments stay loud.
        const auto writeResult = [&](const auto &result) {
            addressSpace.validateAccess(
                guest::GuestAddress{state.r8}, sizeof(result),
                guest::Permission::Write);
            addressSpace.writeBytes(
                guest::GuestAddress{state.r8},
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t *>(&result),
                    sizeof(result)});
        };
        if (flavor == procPidShortBsdInfo) {
            const auto result = guestProcBsdShortInfo(state.r10);
            try {
                writeResult(result);
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
        } else {
            const auto result =
                guestProcUniqueIdentifierInfo(task.executableUuid);
            try {
                writeResult(result);
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
        }
        setSuccess(state, requiredSize);
        return {};
    }
    if (callNumber != procInfoCallSetDyldImages) {
        throw unsupported(
            state, syscallRip,
            "only the observed PROC_INFO_CALL_SET_DYLD_IMAGES operation is implemented");
    }

    const auto pid = std::bit_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.rsi));
    const auto hostPid = static_cast<std::int32_t>(::getpid());
    if (pid != hostPid || state.r8 == 0) {
        setError(state, EINVAL);
        return {};
    }

    // XNU registers this userspace address range as TASK_DYLD_INFO. It
    // neither copies the buffer nor passes it to another kernel API. Keep
    // the same metadata in the guest task namespace. The address need not
    // currently be mapped, but the range must not wrap.
    const auto signedSize = std::bit_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.r9));
    const auto size = static_cast<std::uint64_t>(signedSize);
    std::uint64_t end = 0;
    if (__builtin_add_overflow(state.r8, size, &end) || task.dyldInfoFinal) {
        setError(state, EINVAL);
        return {};
    }
    task.dyldInfo = GuestDyldInfo{
        .address = guest::GuestAddress{state.r8},
        .size = size,
    };
    // In a real dynamic process, the kernel loader has already installed
    // dyld's initial __all_image_info range. This dyld-issued update is the
    // one permitted nonzero-to-nonzero transition, which finalizes it.
    task.dyldInfoFinal = true;
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleGetentropy(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    constexpr std::size_t maximumEntropySize = 256;
    if (state.rsi > maximumEntropySize) {
        // XNU randomdev.c rejects requests larger than its 256-byte
        // kernel buffer before touching userspace.
        setError(state, EINVAL);
        return {};
    }
    const auto size = static_cast<std::size_t>(state.rsi);
    try {
        addressSpace.validateAccess(guest::GuestAddress{state.rdi}, size,
                                    guest::Permission::Write);
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    std::array<std::uint8_t, maximumEntropySize> bytes{};
    if (::getentropy(bytes.data(), size) != 0) {
        setError(state, errno);
        return {};
    }
    try {
        addressSpace.writeBytes(
            guest::GuestAddress{state.rdi},
            std::span<const std::uint8_t>(bytes).first(size));
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleCsrctl(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(task);
    if (state.rdi != csrSyscallCheck) {
        throw unsupported(
            state, syscallRip,
            "only the observed csrctl CSR_SYSCALL_CHECK operation is implemented");
    }
    if (state.rsi == 0 || state.rdx != sizeof(std::uint32_t)) {
        setError(state, EINVAL);
        return {};
    }
    std::uint32_t requestedMask = 0;
    try {
        requestedMask = addressSpace.readU32(
            guest::GuestAddress{state.rsi});
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    if ((guestCsrActiveConfig & requestedMask) == requestedMask) {
        setSuccess(state, 0);
    } else {
        setError(state, EPERM);
    }
    return {};
}

SyscallOutcome handleMac(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(task);
    std::optional<std::string> policy;
    try {
        policy = readGuestCString(
            addressSpace, guest::GuestAddress{state.rdi},
            guestPathMaximum);
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    if (!policy) {
        setError(state, ENAMETOOLONG);
        return {};
    }
    const auto policyCall = static_cast<std::uint32_t>(state.rsi);
    if (*policy == "AMFI" && policyCall == guestAmfiDyldPolicyCall) {
        GuestAmfiDyldPolicyRequest request{};
        try {
            const auto requestBytes = addressSpace.readBytes(
                guest::GuestAddress{state.rdx}, sizeof(request));
            std::memcpy(&request, requestBytes.data(), sizeof(request));
            addressSpace.validateAccess(
                guest::GuestAddress{request.outputAddress},
                sizeof(std::uint64_t), guest::Permission::Write);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (request.inputFlags != 0) {
            std::ostringstream reason;
            reason << "unsupported AMFI dyld-policy input flags 0x"
                   << std::hex << request.inputFlags;
            throw unsupported(state, syscallRip, reason.str());
        }

        // This initial guest process is an unsigned, unrestricted,
        // unencrypted development executable. A matching x86_64 process
        // reports these dyld policy bits: @ paths, path variables, custom
        // cache, fallback paths, print variables, interposing, embedded
        // variables, and development variables. Restricted/encrypted
        // process policy remains unsupported above.
        addressSpace.writeU64(
            guest::GuestAddress{request.outputAddress},
            guestAmfiUnrestrictedDyldPolicy);
        setSuccess(state, 0);
        return {};
    }
    if (*policy != "Sandbox" || policyCall != guestSandboxCheckCall) {
        std::ostringstream reason;
        reason << "only Sandbox policy call 2 is implemented; got policy=\""
               << *policy << "\" call=" << std::dec << policyCall;
        throw unsupported(state, syscallRip, reason.str());
    }

    GuestSandboxCheckRequest request{};
    std::optional<std::string> operation;
    try {
        const auto requestBytes = addressSpace.readBytes(
            guest::GuestAddress{state.rdx}, sizeof(request));
        std::memcpy(&request, requestBytes.data(), sizeof(request));
        operation = readGuestCString(
            addressSpace,
            guest::GuestAddress{request.operationAddress},
            guestPathMaximum);
        addressSpace.validateAccess(
            guest::GuestAddress{request.resultAddress},
            sizeof(std::uint64_t), guest::Permission::Write);
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    if (!operation) {
        setError(state, ENAMETOOLONG);
        return {};
    }

    const auto guestPid = static_cast<std::uint64_t>(::getpid());
    const bool syscallUnixCheck =
        request.pid == guestPid && *operation == "syscall-unix" &&
        request.filterType == guestSandboxSyscallFilterType &&
        request.value == guestMapWithLinkingSyscall &&
        request.flags == guestSandboxObservedFlags;
    // Mach-lookup checks name a bootstrap service through the value
    // pointer. Rosa installs no sandbox profile, so any well-formed
    // self lookup is allowed; the subsequent bootstrap send still goes
    // through the (unprovisioned) guest port namespace.
    bool machLookupCheck = false;
    if (request.pid == guestPid && *operation == "mach-lookup" &&
        request.filterType == guestSandboxMachLookupFilterType &&
        request.flags == guestSandboxObservedFlags) {
        try {
            static_cast<void>(readGuestCString(
                addressSpace, guest::GuestAddress{request.value},
                guestPathMaximum));
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        machLookupCheck = true;
    }
    if (!syscallUnixCheck && !machLookupCheck) {
        std::ostringstream reason;
        reason << "unsupported Sandbox check: pid=0x" << std::hex
               << request.pid << " operation=\"" << *operation
               << "\" filter-type=0x" << request.filterType
               << " value=0x" << request.value << " flags=0x"
               << request.flags;
        throw unsupported(state, syscallRip, reason.str());
    }

    // Rosa has not installed a sandbox profile for this controlled guest,
    // so the observed checks are allowed. The x86 policy ABI writes a
    // 64-bit zero decision and returns success.
    addressSpace.writeU64(guest::GuestAddress{request.resultAddress}, 0);
    setSuccess(state, 0);
    return {};
}

} // namespace rosa::darwin::detail
