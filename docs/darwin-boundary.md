# Darwin boundary

Rosa currently implements exactly two x86_64 Darwin BSD syscalls.

| Guest operation | Guest `RAX` | Guest arguments | Host action |
| --- | ---: | --- | --- |
| `exit` | `0x02000001` | status in `RDI` | terminate the guest dispatch loop |
| `write` | `0x02000004` | fd in `RDI`, address in `RSI`, count in `RDX` | copy guest bytes, then call host `write` |

The x86 `syscall` instruction exits generated ARM64 to `darwin::SyscallDispatcher`. It is never converted to an ARM `svc`. Generated code records the next RIP in guest `RIP`/`RCX` and the input flags in guest `R11`. Successful writes clear x86 `CF`; host errors place `errno` in guest `RAX` and set `CF`.

The controlled implementation accepts stdout and stderr and rejects writes over 16 MiB. Every unsupported number reports its guest RIP and six ABI arguments. There is no generic syscall-number passthrough and no assumption that arm64 host numbers or structures match x86 Darwin.

For dyld bring-up Rosa also maps a sparse, read-only x86 commpage at `0x7fffffe00000`. The implemented fields are the kdebug-enable word (zero because Rosa does not forward guest kdebug), a coherent nanotime tuple driven by Rosa's virtual 2 GHz `RDTSC`, and the continuous-time offset. This is a userspace ABI mapping, not a syscall passthrough.

Mach traps, file operations, memory syscalls, process/thread calls, signals, shared-region operations, and structure translations are not implemented. The current dyld trace has not reached a Darwin syscall or Mach trap.
