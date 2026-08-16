# Darwin boundary

Rosa implements only the x86_64 Darwin operations reached by the controlled fixture and current dyld probe.

| Guest operation | Guest `RAX` | Guest arguments | Host action |
| --- | ---: | --- | --- |
| `exit` | `0x02000001` | status in `RDI` | terminate the guest dispatch loop |
| `write` | `0x02000004` | fd in `RDI`, address in `RSI`, count in `RDX` | copy guest bytes, then call host `write` |
| `getpid` | `0x02000014` | none | return the single Rosa process identity used by the current one-process model |
| `munmap` | `0x02000049` | guest address/size | validate BSD alignment/size semantics and deallocate only guest mappings |
| `shared_region_check_np` | `0x02000126` | guest address-pointer in `RDI` | copy out the installed Intel cache base, or return `EINVAL` when no compatible cache exists |
| `proc_info` | `0x02000150` | observed `PROC_INFO_CALL_SET_DYLD_IMAGES` arguments | register/finalize guest TASK_DYLD_INFO metadata without copying or forwarding its pointer |
| `thread_selfid` | `0x02000174` | none | return guest thread ID 1 |
| `fsgetpath` | `0x020001ab` | guest output buffer/size and guest fsid/object ID | implement only dyld's empty identity-tuple probe, returning `ENOTSUP` without touching output |
| `csrctl` | `0x020001e3` | observed `CSR_SYSCALL_CHECK` arguments | apply Rosa's explicit restrictive guest SIP policy |
| `getentropy` | `0x020001f4` | guest buffer in `RDI`, size in `RSI` | validate at most 256 writable guest bytes, obtain host entropy, then copy into guest memory |

The x86 `syscall` instruction exits generated ARM64 to `darwin::SyscallDispatcher`. It is never converted to an ARM `svc`. Generated code records the next RIP in guest `RIP`/`RCX` and the input flags in guest `R11`. Successful writes clear x86 `CF`; host errors place `errno` in guest `RAX` and set `CF`.

The controlled write implementation accepts stdout and stderr and rejects writes over 16 MiB. Every unsupported number reports its guest RIP and six ABI arguments. There is no generic syscall-number passthrough and no assumption that arm64 host numbers or structures match x86 Darwin.

The x86 machdep class currently implements only `thread_fast_set_cthread_self` (call 3). It validates/canonicalizes the guest cthread pointer into explicit guest `GSBASE` state and returns the x86 `USER_CTHREAD` selector. It never changes a host segment register.

The Mach trap class currently implements these narrow semantic forms:

| Trap | Implemented behavior |
| ---: | --- |
| 12 | task-self `mach_vm_deallocate`, including page rounding and ranges containing holes |
| 14 | task-self `mach_vm_protect`, including observed `VM_PROT_COPY` private guest mappings |
| 15 | task-self anonymous `mach_vm_map` with `VM_FLAGS_ANYWHERE`, 4 KiB mask, null object fast-path assumptions, guest address copyout, and separate current/maximum permissions |
| 19 | observed task-self send-right reference updates in the guest port namespace |
| 26 | allocate a synthetic guest reply-port receive right |
| 28 | return the synthetic guest task-self port name |

Mach traps return Mach result values in guest `RAX`; they do not use the BSD carry-flag convention. These are guest-namespace ports and mappings, not host task/port identity passthrough.

For dyld bring-up Rosa also maps a sparse, read-only x86 commpage at `0x7fffffe00000`. The implemented fields are the ABI version, guest page size, maximum user-page address, a minimal guest CPU-capability mask, the kdebug-enable word (zero because Rosa does not forward guest kdebug), a coherent nanotime tuple driven by Rosa's virtual 2 GHz `RDTSC`, and the continuous-time offset. This is a userspace ABI mapping, not a syscall passthrough.

The current trace has entered dyld-in-cache and unmapped standalone dyld. Its first unsupported Darwin boundary is `_kernelrpc_mach_port_construct_trap` (trap 24). General file operations, Mach messages, signals, and most Darwin structures remain unsupported and fail diagnostically.
