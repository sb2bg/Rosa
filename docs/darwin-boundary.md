# Darwin boundary

Rosa implements only the x86_64 Darwin operations reached by the controlled fixture and current dyld probe.

| Guest operation | Guest `RAX` | Guest arguments | Host action |
| --- | ---: | --- | --- |
| `exit` | `0x02000001` | status in `RDI` | terminate the guest dispatch loop |
| `write` / `write_nocancel` | `0x02000004` / `0x0200018d` | fd in `RDI`, address in `RSI`, count in `RDX` | copy guest bytes, then call host `write` |
| `access` | `0x02000021` | guest path/mode | resolve relative paths against the guest working directory and answer F_OK/R_OK/W_OK/X_OK from host metadata inside it; report ENOENT/EINVAL without a VFS mapping outside it |
| `open` | `0x02000005` | guest path/flags/mode | open controlled user files or allocate synthetic guest directory descriptors for the observed root operations |
| `close` | `0x02000006` | guest fd | remove a task-local guest descriptor |
| `getpid` | `0x02000014` | none | return the single Rosa process identity used by the current one-process model |
| `sigaction` | `0x0200002e` | signal number, new 16-byte action, old-action copyout | record task-local signal dispositions without host delivery; report EINVAL/EFAULT for bad numbers and pointers |
| `dup` | `0x02000029` | guest fd | allocate a unique guest fd sharing the same guest open-description identity |
| `munmap` | `0x02000049` | guest address/size | validate BSD alignment/size semantics and deallocate only guest mappings |
| `fcntl(F_GETPATH)` | `0x0200005c` | guest fd/cmd/output | copy the controlled guest path through guest memory |
| `sysctl` | `0x020000ca` | x86 Darwin MIB and guest buffers | implement name-to-OID plus observed lockdown, boot-argument, kernel-version, and CPU-count reads |
| `shared_region_check_np` | `0x02000126` | guest address-pointer in `RDI` | copy out the installed Intel cache base, or return `EINVAL` when no compatible cache exists |
| `proc_info` | `0x02000150` | observed `PROC_INFO_CALL_SET_DYLD_IMAGES` arguments | register/finalize guest TASK_DYLD_INFO metadata without copying or forwarding its pointer |
| `stat64` / `fstat64` / `fstatat64` | `0x02000152` / `0x02000153` / `0x020001d6` | controlled guest path or descriptor plus output | translate metadata into the explicit 144-byte x86_64 Darwin stat layout |
| `thread_selfid` | `0x02000174` | none | return guest thread ID 1 |
| `__mac_syscall` | `0x0200017d` | guest policy/call/request | implement the observed Sandbox map-with-linking check and unrestricted development AMFI dyld policy |
| `fsgetpath` | `0x020001ab` | guest output buffer/size and guest fsid/object ID | implement only dyld's empty identity-tuple probe, returning `ENOTSUP` without touching output |
| `openat` | `0x020001cf` | guest dirfd/path/flags/mode | open the provisioned synthetic `System/Cryptexes/OS` directory relative to guest root |
| `csrctl` | `0x020001e3` | observed `CSR_SYSCALL_CHECK` arguments | apply Rosa's explicit restrictive guest SIP policy |
| `getentropy` | `0x020001f4` | guest buffer in `RDI`, size in `RSI` | validate at most 256 writable guest bytes, obtain host entropy, then copy into guest memory |
| `map_with_linking_np` | `0x02000226` | guest regions/count/blob/size | over-map read-only file ranges into existing guest mappings and apply `DYLD_CHAINED_PTR_64` chained fixups through the blob's pre-resolved bind table |

The x86 `syscall` instruction exits generated ARM64 to `darwin::SyscallDispatcher`. It is never converted to an ARM `svc`. Generated code records the next RIP in guest `RIP`/`RCX` and the input flags in guest `R11`. Successful writes clear x86 `CF`; host errors place `errno` in guest `RAX` and set `CF`.

The controlled write implementation accepts stdout and stderr and rejects writes over 16 MiB. Guest root/cryptex descriptors never open or traverse the host root. `kern.version` is obtained with a host-owned buffer because native and Rosetta x86 callers observe the same current kernel string; only copied bytes enter guest memory. Every unsupported number reports its guest RIP and six ABI arguments. There is no generic syscall-number passthrough and no assumption that arm64 host numbers or structures match x86 Darwin.

The x86 machdep class currently implements only `thread_fast_set_cthread_self` (call 3). It validates/canonicalizes the guest cthread pointer into explicit guest `GSBASE` state and returns the x86 `USER_CTHREAD` selector. It never changes a host segment register.

The Mach trap class currently implements these narrow semantic forms:

| Trap | Implemented behavior |
| ---: | --- |
| 12 | task-self `mach_vm_deallocate`, including page rounding and ranges containing holes |
| 14 | task-self `mach_vm_protect`, including observed `VM_PROT_COPY` private guest mappings |
| 15 | task-self anonymous `mach_vm_map` with `VM_FLAGS_ANYWHERE`, 4 KiB mask, null object fast-path assumptions, guest address copyout, and separate current/maximum permissions |
| 18 | drop one explicit guest send/send-once uref |
| 19 | observed task-self send-right reference updates in the guest port namespace |
| 24 | construct the observed `MPO_REPLY_PORT` receive right after decoding the 24-byte guest options structure and validating copyout atomically |
| 26 | allocate a synthetic guest reply-port receive right |
| 28 | return the synthetic guest task-self port name |
| 29 | copy out a synthetic guest host send right |
| 47 | decode only the observed `mach_msg2` host-basic-info and task `mach_vm_map` MIG exchanges |

Mach traps return Mach result values in guest `RAX`; they do not use the BSD carry-flag convention. These are guest-namespace ports and mappings, not host task/port identity passthrough.

For dyld bring-up Rosa also maps a sparse, read-only x86 commpage at `0x7fffffe00000`. The implemented fields are the ABI version, guest page size, maximum user-page address, a minimal guest CPU-capability mask, the kdebug-enable word (zero because Rosa does not forward guest kdebug), a coherent nanotime tuple driven by Rosa's virtual 2 GHz `RDTSC`, and the continuous-time offset. This is a userspace ABI mapping, not a syscall passthrough.

For trap 24 the observed target is guest task-self `0x103`; options flags are `0x1000` (`MPO_REPLY_PORT`), the queue-limit field and both special fields are zero, context is zero, and the queue limit defaults to 5. Output faults roll the new right back. Repeated constructions allocate deterministic task-local names (`0x203`, `0x303`, `0x403`, ...).

The current frontier enters dyld-in-cache, unmaps standalone dyld, initializes
the required shared-cache libraries, transfers to an ordinary C `main`, and
prints through libc's `write_nocancel` path before exiting successfully.
General filesystem metadata, directory enumeration, signals, most Mach
messages, and most Darwin structures remain unsupported and fail
diagnostically.
