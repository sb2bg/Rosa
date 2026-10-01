# Darwin boundary

Rosa implements the x86_64 Darwin calls that dyld, `libSystem` startup, and the tested programs actually make. Anything else stops the guest with a diagnostic. There is no generic syscall passthrough, and no assumption that arm64 host syscall numbers or structures match x86_64 Darwin.

The authoritative list of BSD calls is the table in `src/darwin/Syscall.cpp`. Handlers are grouped by domain in `SyscallProcess.cpp`, `SyscallSysctl.cpp`, `SyscallFiles.cpp`, and `SyscallMemory.cpp`, and reach per-process state (descriptors, ports, signal dispositions, dyld registration) through `GuestTask`. `--trace-syscalls` logs every BSD call a guest makes, with its arguments and result.

## Calling convention

The x86 `syscall` instruction exits generated code to `darwin::SyscallDispatcher`; it is never converted to an ARM `svc`. Generated code stores the next RIP in guest `RIP`/`RCX` and the input flags in `R11`. The class in the top byte of `RAX` selects BSD (`0x2000000`), Mach (`0x1000000`), or machdep (`0x3000000`) handling. Arguments come from `RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9`.

BSD calls clear `CF` on success; on error they put `errno` in `RAX` and set `CF`. Mach traps return a `kern_return_t` in `RAX` and leave the carry flag alone. Guest buffers are always copied through the guest address space; no guest pointer reaches the host kernel.

## BSD calls

| Area | Calls | Notes |
| ---- | ----- | ----- |
| Process identity | `getpid`, `getuid`, `geteuid`, `getegid`, `issetugid`, `thread_selfid`, `gettid` | One guest process sharing the host's uid/gid. `issetugid` is 0. `thread_selfid` is 1. `gettid` returns `ESRCH`, as XNU does for a thread without a per-thread identity override |
| Process setup | `exit`, `bsdthread_register`, `sigaction`, `getrlimit`, `gettimeofday` | `bsdthread_register` returns the compatibility value that advertises no workqueue or QoS features. `sigaction` records dispositions without host signal delivery. `getrlimit` reports host limits. `gettimeofday` reports UTC |
| Code signing and policy | `csops`, `csops_audittoken`, `__mac_syscall`, `csrctl` | The guest is unsigned: `CS_OPS_STATUS` reports no flags and entitlement queries fail with `EINVAL`. `__mac_syscall` covers the Sandbox map-with-linking check and a permissive development AMFI dyld policy. `csrctl` applies a restrictive SIP policy |
| `sysctl` | `sysctl` | Name-to-OID lookup plus reads of `kern.version`, `kern.bootargs`, `kern.osproductversion`, `kern.iossupportversion`, `kern.osvariant_status`, `kern.usrstack64`, `hw.ncpu`, `hw.pagesize` (4096, matching Rosetta), and `security.mac.lockdown_mode_state` |
| Descriptors | `open`, `open_nocancel`, `openat`, `close`, `close_nocancel`, `dup`, `fcntl`, `fcntl_nocancel` | Opens are read-only and go through the [path policy](#descriptors-and-paths). `fcntl` supports `F_DUPFD`, `F_DUPFD_CLOEXEC`, `F_GETFD`, `F_SETFD`, `F_GETFL`, `F_GETLK`, `F_SETLK`, `F_SETLKW`, and `F_GETPATH` |
| I/O | `read`, `read_nocancel`, `write`, `write_nocancel`, `lseek`, `ioctl` | Reads and writes are capped at 16 MiB per call. `ioctl` covers `FIODTYPE`, `TIOCGWINSZ`, and `TIOCGETA` |
| File metadata | `stat64`, `lstat64`, `fstat64`, `fstatat64`, `access`, `getattrlist`, `fgetattrlist`, `getdirentries64`, `fstatfs64`, `getfsstat64`, `fsgetpath` | `stat` results are rewritten into the 144-byte x86_64 layout rather than copied from the arm64 host structure. `getdirentries64` works on host-backed directories, and its resume index doubles as the `lseek` offset. `fsgetpath` covers only dyld's empty-tuple probe (`ENOTSUP`) |
| Memory | `mmap`, `munmap`, `mprotect`, `madvise` | All operate on guest mappings. `mmap` covers only the read-only private file mapping dyld makes. `madvise` accepts every defined behavior as a no-op |
| dyld and shared cache | `shared_region_check_np`, `map_with_linking_np`, `proc_info` | `shared_region_check_np` returns the guest cache base, or `EINVAL` with no cache. `map_with_linking_np` maps file ranges into guest mappings and applies `DYLD_CHAINED_PTR_64` fixups. `proc_info` covers `PROC_INFO_CALL_SET_DYLD_IMAGES` |
| IPC and misc | `socket`, `connect`, `shm_open`, `getentropy` | `socket` creates only `AF_UNIX` datagram sockets, and `connect` reports the missing ASL daemon. `shm_open` reports the FeatureFlags snapshot as absent. `getentropy` fills at most 256 bytes from host entropy |

The system user and group databases are not provisioned. `open` and `stat` on them return `ENOENT`.

## Descriptors and paths

`GuestFileSpace` is the descriptor table. Descriptors are allocated lowest-free, and a new task inherits duplicates of Rosa's standard streams as 0, 1, and 2. Descriptors point at shared open file descriptions, so `dup` and `F_DUPFD` share the offset and status flags while close-on-exec stays per descriptor. A host-backed description owns a host fd that closes with its last descriptor. Root, cryptex, urandom, and socket descriptions are synthetic. Guest root and cryptex descriptors never open or traverse the host root.

Every path goes through one policy, `GuestFileSpace::permitsHostPath`, chosen per task:

- `GuestHostAccess::Controlled` (`rosa run`): opens are confined to the working directory, and the standard streams answer terminal ioctls as an 80×24 synthetic console.
- `GuestHostAccess::HostReadOnly` (`rosa exec`): the guest can read the host filesystem like an ordinary process, and terminal ioctls go to the inherited streams.

A path outside the policy stops the guest with a diagnostic rather than returning an invented errno.

## Mach traps

| Trap | Behavior |
| ---: | -------- |
| 10 | task-self `mach_vm_allocate`: anonymous read/write memory with `VM_PROT_ALL` as the maximum protection |
| 12 | task-self `mach_vm_deallocate`, including page rounding and ranges containing holes |
| 14 | task-self `mach_vm_protect`, including `VM_PROT_COPY` |
| 15 | task-self anonymous `mach_vm_map` with `VM_FLAGS_ANYWHERE`, separate current and maximum protections |
| 16 | allocate a receive right or port set |
| 18 | drop one send or send-once uref |
| 19 | update task-self send-right references |
| 22 | move a receive right into a port set |
| 24 | construct an `MPO_REPLY_PORT` receive right (see below) |
| 26 | allocate a reply-port receive right |
| 27 | `thread_self`: a send right to the single guest thread |
| 28 | `task_self`: the guest task port name |
| 29 | `host_self`: a synthetic host send right |
| 47 | `mach_msg2` for the host-basic-info, host special-port, and task `mach_vm_map` MIG exchanges. Sends to the serverless bootstrap port fail with `MACH_SEND_INVALID_DEST` instead of blocking |
| 50 | the guest thread's special reply port, allocated on first use |
| 70 | mint a process voucher token; banks and attributes are not modeled |
| 89 | `mach_timebase_info`: 1/2, matching the virtual 2 GHz `RDTSC` |
| 91 | create a Mach timer port; timers never fire, and arming one is not implemented |

All ports and mappings live in the guest namespace. Host task and port identities are never passed through.

Trap 24's observed form targets task-self `0x103` with flags `0x1000` (`MPO_REPLY_PORT`), zero special fields and context, and a default queue limit of 5. If the output copy faults, the new right is rolled back. Successive constructions get deterministic names (`0x203`, `0x303`, `0x403`, …).

## Machdep and commpage

The machdep class implements only `thread_fast_set_cthread_self` (call 3). It validates the guest cthread pointer, stores it in guest `GSBASE`, and returns the x86 `USER_CTHREAD` selector. Host segment registers are never touched.

Rosa maps a sparse read-only x86 commpage at `0x7fffffe00000` with these fields: ABI version, page size, maximum user address, a minimal CPU-capability mask, the kdebug-enable word (zero), a nanotime tuple consistent with Rosa's virtual 2 GHz `RDTSC`, and the continuous-time offset.

## Not implemented

Opening files for writing, general `mmap` (including the private writable mapping libc uses to load UTF-8 locale data), signal delivery, `fork`/`exec`, threads, most Mach messages, and most Darwin structures. Each stops the guest with a diagnostic naming the call and its arguments.
