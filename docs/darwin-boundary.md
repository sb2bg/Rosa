# Darwin boundary

Rosa implements only the x86_64 Darwin operations reached by the controlled fixture and current dyld probe.

| Guest operation | Guest `RAX` | Guest arguments | Host action |
| --- | ---: | --- | --- |
| `exit` | `0x02000001` | status in `RDI` | terminate the guest dispatch loop |
| `write` | `0x02000004` | fd in `RDI`, address in `RSI`, count in `RDX` | copy guest bytes, then call host `write` |
| `shared_region_check_np` | `0x02000126` | guest address-pointer in `RDI` | return `EINVAL` without dereferencing it because no Intel shared region is provisioned |
| `thread_selfid` | `0x02000174` | none | return guest thread ID 1 |
| `fsgetpath` | `0x020001ab` | guest output buffer/size and guest fsid/object ID | implement only dyld's empty identity-tuple probe, returning `ENOTSUP` without touching output |
| `getentropy` | `0x020001f4` | guest buffer in `RDI`, size in `RSI` | validate at most 256 writable guest bytes, obtain host entropy, then copy into guest memory |

The x86 `syscall` instruction exits generated ARM64 to `darwin::SyscallDispatcher`. It is never converted to an ARM `svc`. Generated code records the next RIP in guest `RIP`/`RCX` and the input flags in guest `R11`. Successful writes clear x86 `CF`; host errors place `errno` in guest `RAX` and set `CF`.

The controlled write implementation accepts stdout and stderr and rejects writes over 16 MiB. Every unsupported number reports its guest RIP and six ABI arguments. There is no generic syscall-number passthrough and no assumption that arm64 host numbers or structures match x86 Darwin.

The x86 machdep class currently implements only `thread_fast_set_cthread_self` (call 3). It validates/canonicalizes the guest cthread pointer into explicit guest `GSBASE` state and returns the x86 `USER_CTHREAD` selector. It never changes a host segment register.

The Mach trap class currently implements these narrow semantic forms:

| Trap | Implemented behavior |
| ---: | --- |
| 14 | task-self `mach_vm_protect` over existing guest mappings, including guest protection/result translation |
| 15 | task-self anonymous `mach_vm_map` with `VM_FLAGS_ANYWHERE`, 4 KiB mask, null object fast-path assumptions, guest address copyout, and separate current/maximum permissions |
| 26 | allocate a synthetic guest reply-port receive right |
| 28 | return the synthetic guest task-self port name |

Mach traps return Mach result values in guest `RAX`; they do not use the BSD carry-flag convention. These are guest-namespace ports and mappings, not host task/port identity passthrough.

For dyld bring-up Rosa also maps a sparse, read-only x86 commpage at `0x7fffffe00000`. The implemented fields are the ABI version, guest page size, maximum user-page address, a minimal guest CPU-capability mask, the kdebug-enable word (zero because Rosa does not forward guest kdebug), a coherent nanotime tuple driven by Rosa's virtual 2 GHz `RDTSC`, and the continuous-time offset. This is a userspace ABI mapping, not a syscall passthrough.

The current dyld trace has reached all operations listed above and has successfully created an anonymous mapping labeled `mach_vm_map anonymous` for dyld. The `shared_region_check_np` call is the first shared-cache-related interaction, but no x86 shared-cache image has been mapped or resolved. General file operations, Mach messages, signals, shared-cache provisioning, and most Darwin structures remain unsupported and fail diagnostically.
