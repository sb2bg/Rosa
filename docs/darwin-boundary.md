# Darwin boundary

Rosa currently implements exactly two x86_64 Darwin BSD syscalls.

| Guest operation | Guest `RAX` | Guest arguments | Host action |
| --- | ---: | --- | --- |
| `exit` | `0x02000001` | status in `RDI` | terminate the guest dispatch loop |
| `write` | `0x02000004` | fd in `RDI`, address in `RSI`, count in `RDX` | copy guest bytes, then call host `write` |

The x86 `syscall` instruction exits generated ARM64 to `darwin::SyscallDispatcher`. It is never converted to an ARM `svc`. Generated code records the next RIP in guest `RIP`/`RCX` and the input flags in guest `R11`. Successful writes clear x86 `CF`; host errors place `errno` in guest `RAX` and set `CF`.

The controlled implementation accepts stdout and stderr and rejects writes over 16 MiB. Every unsupported number reports its guest RIP and six ABI arguments. There is no generic syscall-number passthrough and no assumption that arm64 host numbers or structures match x86 Darwin.

Mach traps, file operations, memory syscalls, process/thread calls, signals, and structure translations are not implemented.
