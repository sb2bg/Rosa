#include "darwin/Syscall.h"
#include "darwin/SyscallInternal.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <ostream>

namespace rosa::darwin {
namespace {

using detail::SyscallHandler;

struct SyscallEntry {
    std::uint64_t number;
    std::string_view name;
    SyscallHandler handler;
};

// Every modeled BSD syscall. A number missing here stops the guest with a
// diagnostic instead of guessing at kernel behavior.
constexpr std::array syscallTable = std::to_array<SyscallEntry>({
    {detail::syscallExit, "exit", detail::handleExit},
    {detail::syscallBsdthreadRegister, "bsdthread_register", detail::handleBsdthreadRegister},
    {detail::syscallThreadSelfid, "thread_selfid", detail::handleThreadSelfid},
    {detail::syscallBsdthreadCreate, "bsdthread_create", detail::handleBsdthreadCreate},
    {detail::syscallBsdthreadTerminate, "bsdthread_terminate", detail::handleBsdthreadTerminate},
    {detail::syscallSigprocmask, "sigprocmask", detail::handlePthreadSigmask},
    {detail::syscallPthreadSigmask, "__pthread_sigmask", detail::handlePthreadSigmask},
    {detail::syscallDisableThreadsignal, "__disable_threadsignal",
     detail::handleDisableThreadsignal},
    {detail::syscallWorkqOpen, "workq_open", detail::handleWorkqOpen},
    {detail::syscallKeventQos, "kevent_qos", detail::handleKeventQos},
    {detail::syscallKeventId, "kevent_id", detail::handleKeventId},
    {detail::syscallWorkqKernreturn, "workq_kernreturn", detail::handleWorkqKernreturn},
    {detail::syscallUlockWait, "ulock_wait", detail::handleUlockWait},
    {detail::syscallUlockWait2, "ulock_wait2", detail::handleUlockWait2},
    {detail::syscallUlockWake, "ulock_wake", detail::handleUlockWake},
    {detail::syscallGettimeofday, "gettimeofday", detail::handleGettimeofday},
    {detail::syscallIssetugid, "issetugid", detail::handleIssetugid},
    {detail::syscallDup, "dup", detail::handleDup},
    {detail::syscallIoctl, "ioctl", detail::handleIoctl},
    {detail::syscallMac, "__mac_syscall", detail::handleMac},
    {detail::syscallSysctl, "sysctl", detail::handleSysctl},
    {detail::syscallGetpid, "getpid", detail::handleGetpid},
    {detail::syscallGetuid, "getuid", detail::handleGetuid},
    {detail::syscallGeteuid, "geteuid", detail::handleGeteuid},
    {detail::syscallGettid, "gettid", detail::handleGettid},
    {detail::syscallGetegid, "getegid", detail::handleGetegid},
    {detail::syscallGetrlimit, "getrlimit", detail::handleGetrlimit},
    {detail::syscallSigaction, "sigaction", detail::handleSigaction},
    {detail::syscallCsops, "csops", detail::handleCsops},
    {detail::syscallCsopsAuditToken, "csops_audittoken", detail::handleCsopsAuditToken},
    {detail::syscallAccess, "access", detail::handleAccess},
    {detail::syscallShmOpen, "shm_open", detail::handleShmOpen},
    {detail::syscallOpen, "open", detail::handleOpen},
    {detail::syscallOpenNoCancel, "open_nocancel", detail::handleOpen},
    {detail::syscallOpenat, "openat", detail::handleOpenat},
    {detail::syscallStat64, "stat64", detail::handleStat64},
    {detail::syscallLstat64, "lstat64", detail::handleStat64},
    {detail::syscallLseek, "lseek", detail::handleLseek},
    {detail::syscallFstat64, "fstat64", detail::handleFstat64},
    {detail::syscallGetattrlist, "getattrlist", detail::handleGetattrlist},
    {detail::syscallFgetattrlist, "fgetattrlist", detail::handleFgetattrlist},
    {detail::syscallGetattrlistbulk, "getattrlistbulk", detail::handleGetattrlistbulk},
    {detail::syscallGetfsstat64, "getfsstat64", detail::handleGetfsstat64},
    {detail::syscallFstatfs64, "fstatfs64", detail::handleFstatfs64},
    {detail::syscallGetdirentries64, "getdirentries64", detail::handleGetdirentries64},
    {detail::syscallFstatat64, "fstatat64", detail::handleFstatat64},
    {detail::syscallSocket, "socket", detail::handleSocket},
    {detail::syscallConnect, "connect", detail::handleConnect},
    {detail::syscallClose, "close", detail::handleClose},
    {detail::syscallCloseNoCancel, "close_nocancel", detail::handleClose},
    {detail::syscallRead, "read", detail::handleRead},
    {detail::syscallReadNoCancel, "read_nocancel", detail::handleRead},
    {detail::syscallFcntl, "fcntl", detail::handleFcntl},
    {detail::syscallFcntlNoCancel, "fcntl_nocancel", detail::handleFcntl},
    {detail::syscallMprotect, "mprotect", detail::handleMprotect},
    {detail::syscallMadvise, "madvise", detail::handleMadvise},
    {detail::syscallMunmap, "munmap", detail::handleMunmap},
    {detail::syscallMmap, "mmap", detail::handleMmap},
    {detail::syscallMapWithLinking, "map_with_linking_np", detail::handleMapWithLinking},
    {detail::syscallSharedRegionCheck, "shared_region_check_np", detail::handleSharedRegionCheck},
    {detail::syscallProcInfo, "proc_info", detail::handleProcInfo},
    {detail::syscallGetentropy, "getentropy", detail::handleGetentropy},
    {detail::syscallFsgetpath, "fsgetpath", detail::handleFsgetpath},
    {detail::syscallCsrctl, "csrctl", detail::handleCsrctl},
    {detail::syscallWrite, "write", detail::handleWrite},
    {detail::syscallWriteNoCancel, "write_nocancel", detail::handleWrite},
});

const SyscallEntry *findSyscall(std::uint64_t number) {
    const auto found = std::ranges::find(syscallTable, number, &SyscallEntry::number);
    return found == syscallTable.end() ? nullptr : &*found;
}

} // namespace

void SyscallDispatcher::portReadinessChanged(guest::AddressSpace &addressSpace,
                                             GuestMachPortName port, bool ready) {
    task_.workqueue.kqueue.setMachPortReady(port.value, ready);
    for (auto &[id, workloop] : task_.workqueue.workloops) {
        workloop.sources.setMachPortReady(port.value, ready);
    }
    if (ready) {
        detail::serviceWorkqueue(addressSpace, task_, nullptr);
    }
}

std::optional<GuestClock::time_point>
SyscallDispatcher::serviceEvents(guest::AddressSpace &addressSpace) {
    const auto now = detail::guestMachAbsoluteTime();
    const auto nextTimer = task_.machDispatcher.fireDueTimers(addressSpace, now);
    detail::serviceWorkqueue(addressSpace, task_, nullptr);
    auto next = task_.workqueue.kqueue.nextTimerDeadline();
    if (nextTimer) {
        next = next ? std::min(*next, *nextTimer) : *nextTimer;
    }
    if (!next) {
        return std::nullopt;
    }
    const auto remaining = *next > now ? (*next - now) / guestMachTicksPerNanosecond : 0;
    return GuestClock::now() + std::chrono::nanoseconds{remaining};
}

SyscallOutcome SyscallDispatcher::dispatch(guest::AddressSpace &addressSpace,
                                           x86::X86State &state,
                                           guest::GuestAddress syscallRip) {
    using namespace detail;
    const auto number = state.rax;
    if (MachDispatcher::isMachTrap(number)) {
        if (trace_ == nullptr) {
            task_.machDispatcher.dispatch(addressSpace, state, syscallRip);
            return {};
        }
        const std::array arguments{state.rdi, state.rsi, state.rdx, state.r10, state.r8, state.r9};
        const auto thread = task_.scheduler.current().id;
        task_.machDispatcher.dispatch(addressSpace, state, syscallRip);
        *trace_ << "[mach] thread=" << std::dec << thread << " trap "
                << MachDispatcher::trapNumber(number) << "(" << std::hex;
        for (std::size_t index = 0; index < arguments.size(); ++index) {
            *trace_ << (index == 0 ? "0x" : ", 0x") << arguments[index];
        }
        *trace_ << ") = ";
        if (task_.scheduler.current().status == GuestThreadStatus::Blocked) {
            *trace_ << "blocked";
        } else {
            *trace_ << "0x" << state.rax;
        }
        *trace_ << std::dec << '\n';
        return {};
    }
    if ((number & syscallClassMask) == machdepSyscallClass) {
        const auto call = number & syscallNumberMask;
        if (call != machdepThreadFastSetCthreadSelf) {
            throw unsupportedMachdep(state, syscallRip);
        }
        // XNU's 64-bit call stores a canonical user pointer as the thread's GS
        // base, clears an invalid pointer to zero, and returns USER_CTHREAD.
        state.gsBase = state.rdi < x86MaximumUserPageAddress ? state.rdi : 0;
        state.rax = x86UserCthreadSelector;
        return {};
    }
    const auto *entry = findSyscall(number);
    if (entry == nullptr) {
        throw unsupported(state, syscallRip,
                          "only the currently provisioned Darwin bootstrap syscalls are implemented; this call is outside that set");
    }
    SyscallCall call{addressSpace, state, syscallRip, task_};
    if (trace_ == nullptr) {
        return entry->handler(call);
    }
    const std::array arguments{state.rdi, state.rsi, state.rdx, state.r10, state.r8, state.r9};
    const auto outcome = entry->handler(call);
    *trace_ << "[syscall] thread=" << std::dec << task_.scheduler.current().id << ' '
            << entry->name << "(" << std::hex;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        *trace_ << (index == 0 ? "0x" : ", 0x") << arguments[index];
    }
    *trace_ << ") = ";
    if (outcome.exited) {
        *trace_ << "exit " << std::dec << outcome.exitStatus;
    } else if ((state.rflags & 1U) != 0) {
        *trace_ << "errno " << std::dec << state.rax;
    } else {
        *trace_ << "0x" << state.rax << std::dec;
    }
    *trace_ << '\n';
    return outcome;
}

} // namespace rosa::darwin
