# Milestones

Each milestone is a vertical slice with tests. "Implemented" means implemented for the stated fixtures, not in general.

## R0 — bootstrap: implemented

- C++23 CMake/Ninja project with arm64 macOS host validation.
- Test executable with CTest integration.
- Custom AArch64 instruction encoder.
- `MAP_JIT` ownership and write-protection transitions.
- A generated function returns a known value.

## R1 — one x86 block: implemented

- Decoder for `mov r64, imm64`, `add r64, imm8`, and `ret`.
- Explicit-width IR with a verifier.
- Generated AArch64 updates explicit guest state, including eagerly computed arithmetic flags.
- x86, IR, and AArch64 dumps.
- A test proves the block leaves `RAX == 42`.

## R2 — control flow: implemented

- `cmp`, `je`/`jne`, direct `jmp`, relative `call`, and `ret`.
- AArch64 labels and branch fixups.
- Conditional exits on guest `ZF`.
- Translated-block cache and a bounded dispatcher.
- 4 KiB guest address-space mappings and a guest stack for `call`/`ret`.
- Tests for taken and not-taken paths across multiple blocks.

## R3 — controlled Mach-O: implemented

- The build cross-compiles x86_64 Mach-O fixtures, including a C `main`, with the native Apple toolchain.
- Bounded parsing of 64-bit x86 headers, load commands, segments, `LC_MAIN`, and `LC_UNIXTHREAD`.
- `rosa inspect` with segment and load-command views.
- `rosa run` maps every segment with file data, zero-filled tails, and translated permissions, builds a Darwin startup stack, and starts at the real `LC_MAIN` entry.
- Instructions are fetched only from executable guest mappings.
- The x86 file is never passed to `exec`, so Rosetta never runs it.

Dynamic-library load commands are parsed but not acted on at this stage.

## R4 — Darwin calls: implemented

- `0F 05` ends a generated block and is never lowered to `svc`.
- Syscall numbers and arguments follow the x86_64 Darwin ABI.
- BSD `write` and `exit`, with guest buffers copied through guest memory.
- The hello fixture prints `hello from Intel Darwin` and exits with status zero.
- A minimal entry stub passes `argc`/`argv` to a Clang-compiled `main(int, char **)`, which checks its arguments, runs a hot loop promoted by the LLVM tier, and returns 42.

## R5 — ordinary dynamically linked C program: implemented on the tested userspace

A normal Clang-linked x86_64 executable with `LC_MAIN` and a dependency on `/usr/lib/libSystem.B.dylib` runs through the unmodified Intel dyld and shared cache: dyld and library initialization complete, libc formats `printf` output and writes it with `write_nocancel`, `main` returns, and the process exits with status zero. No custom `_start`, static linking, binary patching, interpreter, or Rosetta is involved.

What it took:

- x86_64 slice selection from a universal dyld, mapped alongside the application; execution starts at dyld's `LC_UNIXTHREAD` entry.
- The shared cache and its six subcaches validated and mapped intact as 28 guest mappings at slide zero, with lazy per-page chained fixups.
- dyld switches to dyld-in-cache and unmaps the standalone dyld image.
- Guest Mach ports, starting with trap 24 `MPO_REPLY_PORT` construction and the `mach_msg2` exchanges dyld makes.
- `proc_info` image registration, `munmap`, `VM_PROT_COPY`, sysctl, AMFI and Sandbox policy, and a synthetic root and cryptex filesystem.
- x86_64 `stat64` family layouts built explicitly rather than copied from arm64 structures.
- Execution in 21 cache images, including libSystem, libsystem_kernel, libsystem_pthread, libsystem_platform, libc, malloc, libdispatch, libobjc, libc++abi, libxpc, and libsystem_darwin.

The first bring-up used single-instruction blocks and took over 4.1 million blocks and 65,000 translations. With 32-instruction blocks the same startup takes about 750,000 blocks and 12,300 translations in a single JIT arena mapping.

An `-O2` scalar prime sieve (ten passes to one million, verifying 78,498 primes and their sum) runs through the same path. It added register-direct unsigned 32-bit `DIV`.

### R5 performance

All measurements are on one M1 Pro host with warm process launches; medians over alternating Rosa and Rosetta trials.

**Cold start (`ordinary-c-x86_64`).** The uncached release path dropped from 1.23 s to about 0.09 s, and peak resident size from 956 MB to about 96 MB. The changes: pooled executable allocation, not retaining runtime listings, lazy shared-cache rebasing, allocation-free scalar memory accesses, release IPO, and multi-instruction dyld blocks. With the persistent translation cache, eleven trials measured 46.4 ms for Rosa and 10.5 ms for Rosetta, a 4.4× gap (down from 37×).

**Steady state (`prime-sieve-x86_64`).** The first measurement was 598.1 ms for Rosa and 28.5 ms for Rosetta, 21.0×. Sixty-one trials now measure 65.0 ms and 24.4 ms, 2.7×. The changes: self-loop batching inside generated code, checked anonymous byte windows, native and deferred flags, native 32-bit arithmetic with immediate folding, guest-register forwarding and pinning, branchless `SET`/`CMOV`, shared range checks for adjacent loads, and guarded monotonic read/write spans.

Forcing the sieve's memory loops into the LLVM tier saves about 8 ms of execution but costs about 29 ms of ORC compilation, so memory loops wait for 100 million executions and this benchmark stays on the baseline tier.

The next structural improvements are linking translated blocks into direct traces and persisting optimized code.

## Current work: host command-line tools

Running unmodified x86_64 slices of the host's own tools, starting with `/usr/bin/grep`:

- `rosa exec` launches a program the way a shell would, with read-only host filesystem access, the host environment, and the guest's exit status.
- `GuestFileSpace` provides a host-backed descriptor table with one path policy per task.
- `--trace-syscalls` logs every BSD call.
- `tests/compat/compat.py` compares stdout, stderr, and exit status byte for byte against the same universal binary's native arm64e slice, for `grep`, `cat`, `head`, `echo`, and `basename`.

Known gap: under a UTF-8 locale, libc maps locale data with a private writable `mmap`, which Rosa does not yet implement. `LC_ALL=C` avoids it.

## Verification notes

The debug, release, and UndefinedBehaviorSanitizer configurations pass the full suite. On macOS 26.5.1 with Apple Clang 17, AddressSanitizer builds hang in the sanitizer runtime's dynamic-shadow initialization before `main`; even `rosa` with no arguments hangs before any JIT allocation. The `asan` preset is kept for retesting on other hosts and toolchains but does not count as a passing run.
