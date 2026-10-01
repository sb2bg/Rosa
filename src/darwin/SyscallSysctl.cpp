#include "darwin/SyscallInternal.h"

namespace rosa::darwin::detail {
namespace {

std::vector<std::uint8_t> hostKernelVersion() {
    std::size_t size = 0;
    if (::sysctlbyname("kern.version", nullptr, &size, nullptr, 0) != 0 ||
        size == 0) {
        throw std::runtime_error("failed to query host kern.version size");
    }
    std::vector<std::uint8_t> bytes(size);
    if (::sysctlbyname("kern.version", bytes.data(), &size, nullptr, 0) != 0) {
        throw std::runtime_error("failed to query host kern.version");
    }
    bytes.resize(size);
    return bytes;
}

std::int32_t hostLogicalCpuCount() {
    std::int32_t count = 0;
    std::size_t size = sizeof(count);
    if (::sysctlbyname(guestHwNcpuName.data(), &count, &size, nullptr, 0) != 0 ||
        size != sizeof(count) || count <= 0) {
        throw std::runtime_error("failed to query host hw.ncpu");
    }
    return count;
}

std::vector<std::uint8_t> hostProductVersion() {
    std::size_t size = 0;
    if (::sysctlbyname(guestProductVersionName.data(), nullptr, &size,
                       nullptr, 0) != 0 ||
        size == 0) {
        throw std::runtime_error(
            "failed to query host kern.osproductversion size");
    }
    std::vector<std::uint8_t> bytes(size);
    if (::sysctlbyname(guestProductVersionName.data(), bytes.data(), &size,
                       nullptr, 0) != 0) {
        throw std::runtime_error(
            "failed to query host kern.osproductversion");
    }
    bytes.resize(size);
    return bytes;
}

std::vector<std::uint8_t> hostIosSupportVersion() {
    std::size_t size = 0;
    if (::sysctlbyname(guestIosSupportVersionName.data(), nullptr, &size,
                       nullptr, 0) != 0 ||
        size == 0) {
        throw std::runtime_error(
            "failed to query host kern.iossupportversion size");
    }
    std::vector<std::uint8_t> bytes(size);
    if (::sysctlbyname(guestIosSupportVersionName.data(), bytes.data(), &size,
                       nullptr, 0) != 0) {
        throw std::runtime_error(
            "failed to query host kern.iossupportversion");
    }
    bytes.resize(size);
    return bytes;
}

std::vector<std::uint8_t> hostOsVariantStatus() {
    std::size_t size = 0;
    if (::sysctlbyname(guestOsVariantStatusName.data(), nullptr, &size,
                       nullptr, 0) != 0 ||
        size != sizeof(std::uint64_t)) {
        throw std::runtime_error(
            "failed to query host kern.osvariant_status size");
    }
    std::vector<std::uint8_t> bytes(size);
    if (::sysctlbyname(guestOsVariantStatusName.data(), bytes.data(), &size,
                       nullptr, 0) != 0 ||
        size != bytes.size()) {
        throw std::runtime_error(
            "failed to query host kern.osvariant_status");
    }
    return bytes;
}

} // namespace

SyscallOutcome handleSysctl(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(task);
    if (state.rsi > 12) {
        setError(state, EINVAL);
        return {};
    }
    std::vector<std::uint32_t> name;
    name.reserve(static_cast<std::size_t>(state.rsi));
    try {
        for (std::size_t index = 0; index < state.rsi; ++index) {
            name.push_back(addressSpace.readU32(guest::GuestAddress{
                state.rdi + index * sizeof(std::uint32_t)}));
        }
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }

    if (std::ranges::equal(name, guestSysctlNameToOid)) {
        if (state.r8 == 0 || state.r9 == 0 ||
            state.r9 > guestPathMaximum || state.rdx == 0 ||
            state.r10 == 0) {
            throw unsupported(
                state, syscallRip,
                "malformed CTL_SYSCTL/CTL_SYSCTL_NAME2OID request");
        }
        std::string requestedName;
        std::uint64_t outputCapacity = 0;
        try {
            const auto bytes = addressSpace.readBytes(
                guest::GuestAddress{state.r8},
                static_cast<std::size_t>(state.r9));
            requestedName.assign(bytes.begin(), bytes.end());
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        std::span<const std::uint32_t> resultOid;
        if (requestedName == guestLockdownModeName) {
            resultOid = guestLockdownModeOid;
        } else if (requestedName == guestBootArgsName) {
            resultOid = guestBootArgsOid;
        } else if (requestedName == guestKernelVersionName) {
            resultOid = guestKernelVersionOid;
        } else if (requestedName == guestProductVersionName) {
            resultOid = guestProductVersionOid;
        } else if (requestedName == guestIosSupportVersionName) {
            resultOid = guestIosSupportVersionOid;
        } else if (requestedName == guestOsVariantStatusName) {
            resultOid = guestOsVariantStatusOid;
        } else if (requestedName == guestHwNcpuName) {
            resultOid = guestHwNcpuOid;
        } else {
            std::ostringstream reason;
            reason << "unsupported guest sysctl name \"" << requestedName
                   << '"';
            throw unsupported(state, syscallRip, reason.str());
        }
        const auto resultSize =
            resultOid.size() * sizeof(std::uint32_t);
        if (outputCapacity < resultSize) {
            setError(state, ENOMEM);
            return {};
        }
        try {
            addressSpace.validateAccess(
                guest::GuestAddress{state.rdx}, resultSize,
                guest::Permission::Write);
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        std::vector<std::uint8_t> oidBytes(resultSize);
        std::memcpy(oidBytes.data(), resultOid.data(), resultSize);
        addressSpace.writeBytes(guest::GuestAddress{state.rdx}, oidBytes);
        addressSpace.writeU64(guest::GuestAddress{state.r10}, resultSize);
        setSuccess(state, 0);
        return {};
    }

    if (std::ranges::equal(name, guestKernelVersionOid)) {
        if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
            throw unsupported(
                state, syscallRip,
                "only a read or size query of guest kern.version is implemented");
        }
        const auto version = hostKernelVersion();
        std::uint64_t outputCapacity = 0;
        try {
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
            if (state.rdx != 0 && outputCapacity >= version.size()) {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx}, version.size(),
                    guest::Permission::Write);
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (state.rdx != 0 && outputCapacity < version.size()) {
            // The x86_64 Darwin kernel returns ENOMEM, leaves the short
            // output untouched, and reports zero bytes copied.
            addressSpace.writeU64(guest::GuestAddress{state.r10}, 0);
            setError(state, ENOMEM);
            return {};
        }
        if (state.rdx != 0) {
            addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                    version);
        }
        addressSpace.writeU64(guest::GuestAddress{state.r10},
                              version.size());
        setSuccess(state, 0);
        return {};
    }

    if (std::ranges::equal(name, guestHwNcpuOid)) {
        if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
            throw unsupported(
                state, syscallRip,
                "only a read or size query of guest hw.ncpu is implemented");
        }
        // Native and Rosetta x86 callers observe the same host CPU
        // count, so report it from a host-owned value like kern.version.
        const auto count = hostLogicalCpuCount();
        std::uint64_t outputCapacity = 0;
        try {
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
            if (state.rdx != 0) {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx}, sizeof(count),
                    guest::Permission::Write);
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (state.rdx != 0 && outputCapacity < sizeof(count)) {
            addressSpace.writeU64(guest::GuestAddress{state.r10}, 0);
            setError(state, ENOMEM);
            return {};
        }
        if (state.rdx != 0) {
            std::array<std::uint8_t, sizeof(count)> countBytes{};
            std::memcpy(countBytes.data(), &count, sizeof(count));
            addressSpace.writeBytes(guest::GuestAddress{state.rdx}, countBytes);
        }
        addressSpace.writeU64(guest::GuestAddress{state.r10}, sizeof(count));
        setSuccess(state, 0);
        return {};
    }

    if (std::ranges::equal(name, guestProductVersionOid)) {
        if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
            throw unsupported(
                state, syscallRip,
                "only a read or size query of guest kern.osproductversion is implemented");
        }
        const auto version = hostProductVersion();
        std::uint64_t outputCapacity = 0;
        try {
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
            if (state.rdx != 0 && outputCapacity >= version.size()) {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx}, version.size(),
                    guest::Permission::Write);
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (state.rdx != 0 && outputCapacity < version.size()) {
            addressSpace.writeU64(guest::GuestAddress{state.r10}, 0);
            setError(state, ENOMEM);
            return {};
        }
        if (state.rdx != 0) {
            addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                    version);
        }
        addressSpace.writeU64(guest::GuestAddress{state.r10},
                              version.size());
        setSuccess(state, 0);
        return {};
    }

    if (std::ranges::equal(name, guestIosSupportVersionOid)) {
        if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
            throw unsupported(
                state, syscallRip,
                "only a read or size query of guest kern.iossupportversion is implemented");
        }
        const auto version = hostIosSupportVersion();
        std::uint64_t outputCapacity = 0;
        try {
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
            if (state.rdx != 0 && outputCapacity >= version.size()) {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx}, version.size(),
                    guest::Permission::Write);
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (state.rdx != 0 && outputCapacity < version.size()) {
            addressSpace.writeU64(guest::GuestAddress{state.r10}, 0);
            setError(state, ENOMEM);
            return {};
        }
        if (state.rdx != 0) {
            addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                    version);
        }
        addressSpace.writeU64(guest::GuestAddress{state.r10},
                              version.size());
        setSuccess(state, 0);
        return {};
    }

    if (std::ranges::equal(name, guestOsVariantStatusOid)) {
        if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
            throw unsupported(
                state, syscallRip,
                "only a read or size query of guest kern.osvariant_status is implemented");
        }
        const auto status = hostOsVariantStatus();
        std::uint64_t outputCapacity = 0;
        try {
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
            if (state.rdx != 0 && outputCapacity >= status.size()) {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx}, status.size(),
                    guest::Permission::Write);
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (state.rdx != 0 && outputCapacity < status.size()) {
            addressSpace.writeU64(guest::GuestAddress{state.r10}, 0);
            setError(state, ENOMEM);
            return {};
        }
        if (state.rdx != 0) {
            addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                    status);
        }
        addressSpace.writeU64(guest::GuestAddress{state.r10},
                              status.size());
        setSuccess(state, 0);
        return {};
    }

    if (std::ranges::equal(name, guestUserStack64Oid)) {
        if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
            throw unsupported(
                state, syscallRip,
                "only a read or size query of guest kern.usrstack64 is implemented");
        }
        std::uint64_t outputCapacity = 0;
        try {
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
            if (state.rdx != 0 &&
                outputCapacity >= sizeof(initialUserStackTop)) {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx},
                    sizeof(initialUserStackTop), guest::Permission::Write);
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (state.rdx != 0 &&
            outputCapacity < sizeof(initialUserStackTop)) {
            setError(state, ENOMEM);
            return {};
        }
        if (state.rdx != 0) {
            addressSpace.writeU64(guest::GuestAddress{state.rdx},
                                  initialUserStackTop);
        }
        addressSpace.writeU64(guest::GuestAddress{state.r10},
                              sizeof(initialUserStackTop));
        setSuccess(state, 0);
        return {};
    }

    if (std::ranges::equal(name, guestBootArgsOid)) {
        if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
            throw unsupported(
                state, syscallRip,
                "only a read or size query of guest kern.bootargs is implemented");
        }
        std::uint64_t outputCapacity = 0;
        try {
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
            if (state.rdx != 0) {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx}, guestBootArgs.size(),
                    guest::Permission::Write);
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (state.rdx != 0 && outputCapacity < guestBootArgs.size()) {
            setError(state, ENOMEM);
            return {};
        }
        if (state.rdx != 0) {
            addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                    guestBootArgs);
        }
        addressSpace.writeU64(guest::GuestAddress{state.r10},
                              guestBootArgs.size());
        setSuccess(state, 0);
        return {};
    }

    if (std::ranges::equal(name, guestLockdownModeOid)) {
        if (state.rdx == 0 || state.r10 == 0 || state.r8 != 0 ||
            state.r9 != 0) {
            throw unsupported(
                state, syscallRip,
                "only a read of the guest lockdown-mode sysctl is implemented");
        }
        std::uint64_t outputCapacity = 0;
        try {
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (outputCapacity < sizeof(guestLockdownModeState)) {
            setError(state, ENOMEM);
            return {};
        }
        try {
            addressSpace.validateAccess(
                guest::GuestAddress{state.rdx},
                sizeof(guestLockdownModeState), guest::Permission::Write);
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        std::array<std::uint8_t, sizeof(guestLockdownModeState)>
            valueBytes{};
        std::memcpy(valueBytes.data(), &guestLockdownModeState,
                    sizeof(guestLockdownModeState));
        addressSpace.writeBytes(guest::GuestAddress{state.rdx},
                                valueBytes);
        addressSpace.writeU64(guest::GuestAddress{state.r10},
                              sizeof(guestLockdownModeState));
        setSuccess(state, 0);
        return {};
    }

    if (std::ranges::equal(name, guestOsversionOid)) {
        // kern.osversion: the human-facing build string. Answer the
        // host build verbatim: the guest runs on this macOS release,
        // and version gates compare against it. The trailing registers
        // are stale caller values, not a set payload: read-only nodes
        // ignore newp/newlen.
        if (state.r10 == 0) {
            throw unsupported(
                state, syscallRip,
                "only a read or size query of guest kern.osversion is implemented");
        }
        std::array<char, 256> hostBuild{};
        std::size_t hostBuildSize = hostBuild.size();
        if (::sysctlbyname("kern.osversion", hostBuild.data(), &hostBuildSize, nullptr,
                           0) != 0) {
            setError(state, errno);
            return {};
        }
        std::uint64_t outputCapacity = 0;
        try {
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
            if (state.rdx != 0) {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx}, hostBuildSize,
                    guest::Permission::Write);
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (state.rdx != 0 && outputCapacity < hostBuildSize) {
            addressSpace.writeU64(guest::GuestAddress{state.r10}, hostBuildSize);
            setError(state, ENOMEM);
            return {};
        }
        if (state.rdx != 0) {
            addressSpace.writeBytes(
                guest::GuestAddress{state.rdx},
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t *>(hostBuild.data()),
                    hostBuildSize});
        }
        addressSpace.writeU64(guest::GuestAddress{state.r10}, hostBuildSize);
        setSuccess(state, 0);
        return {};
    }

    if (name.size() == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID) {
        // kern.proc.pid.<pid>: CoreFoundation reads its own kinfo_proc
        // during process-name resolution. Rosa hosts a single guest
        // process, so only its own PID is visible; serve the host
        // kernel's record for that PID verbatim (same ABI).
        if (state.r10 == 0 || state.r8 != 0 || state.r9 != 0) {
            throw unsupported(
                state, syscallRip,
                "only a read or size query of guest kern.proc.pid is implemented");
        }
        if (name[3] != static_cast<std::uint32_t>(::getpid())) {
            setError(state, ESRCH);
            return {};
        }
        int hostMib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID,
                          static_cast<int>(name[3])};
        struct kinfo_proc info {};
        std::size_t infoSize = sizeof(info);
        if (::sysctl(hostMib, 4, &info, &infoSize, nullptr, 0) != 0) {
            setError(state, errno);
            return {};
        }
        std::uint64_t outputCapacity = 0;
        try {
            outputCapacity = addressSpace.readU64(
                guest::GuestAddress{state.r10});
            addressSpace.validateAccess(
                guest::GuestAddress{state.r10}, sizeof(std::uint64_t),
                guest::Permission::Write);
            if (state.rdx != 0 && outputCapacity >= infoSize) {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdx}, infoSize,
                    guest::Permission::Write);
            }
        } catch (const std::runtime_error &) {
            setError(state, EFAULT);
            return {};
        }
        if (state.rdx != 0 && outputCapacity < infoSize) {
            addressSpace.writeU64(guest::GuestAddress{state.r10}, infoSize);
            setError(state, ENOMEM);
            return {};
        }
        if (state.rdx != 0) {
            addressSpace.writeBytes(
                guest::GuestAddress{state.rdx},
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t *>(&info),
                    infoSize});
        }
        addressSpace.writeU64(guest::GuestAddress{state.r10}, infoSize);
        setSuccess(state, 0);
        return {};
    }

    std::ostringstream reason;
    reason << "unsupported guest sysctl MIB";
    for (const auto component : name) {
        reason << ' ' << std::dec << component;
    }
    throw unsupported(state, syscallRip, reason.str());
}

} // namespace rosa::darwin::detail
