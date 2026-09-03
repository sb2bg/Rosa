# Milestones

## R0 — bootstrap: implemented

- C++23, CMake and Ninja project;
- arm64 macOS host validation;
- focused test executable and CTest integration;
- custom AArch64 instruction encoder;
- `MAP_JIT` executable-memory ownership and write-protection transitions;
- generated function returns a known value.

## R1 — x86 basic block: implemented for the stated probe

- Rosa-owned decoder for `mov r64, imm64`, `add r64, imm8`, and the `ret` terminator;
- explicit-width IR with verification;
- generated ARM64 updates explicit guest state;
- eager arithmetic flag calculation;
- decoded x86, IR and ARM64 byte/listing dumps;
- automated proof that the requested block produces guest `RAX == 42`.

This is not a general x86 executor.

## R2 — control flow: implemented for a controlled program

- `cmp`, `je`/`jne`, direct `jmp`, relative `call`, and `ret`;
- AArch64 label and branch fixups;
- generated conditional exits based on guest `ZF`;
- translated-block cache and bounded dispatcher;
- explicit 4 KiB guest address-space mappings;
- guest stack push/pop for `call`/`ret`;
- taken and not-taken multi-block tests.

## R3 — controlled Mach-O: implemented for controlled fixtures

- the build produces x86_64 Mach-O assembly fixtures and a controlled C `main` fixture using the native arm64 Apple toolchain as a cross-target compiler and linker;
- robust parsing of 64-bit x86 executable headers, load commands, segments, `LC_MAIN`, and x86_64 `LC_UNIXTHREAD` entry state;
- `rosa inspect`, including segment and load-command views;
- `rosa run` starts at the Mach-O's real `LC_MAIN` entry;
- all segments are mapped with file data, zero-filled tails, and translated permissions;
- an initial 16-byte-aligned Darwin stack contains `argc`/`argv`/`envp`/`apple[]`;
- instruction fetches come from executable guest mappings;
- the Rosa process and tests are arm64 Mach-O files; the x86 file is never passed to `exec`, so Rosetta does not execute it.

Dynamic-library commands are parsed but not acted upon.

## R4 — Darwin calls: implemented for controlled write/exit

- `0F 05` is a generated-block terminator, never a host `svc`;
- syscall numbers and arguments follow the x86_64 Darwin ABI;
- only BSD-class `write` and `exit` are implemented;
- guest buffers are copied through guest memory;
- the fixture prints `hello from Intel Darwin` and exits with status zero;
- a minimal checked-in entry stub passes the direct-entry Darwin `argc`/`argv` stack to a real Clang-compiled `main(int, char **)`, which validates guest arguments, exercises LLVM hot-loop promotion, returns 42, and exits cleanly;
- no output helper or interpreter fallback exists.

## R5 — ordinary dynamically linked C `main`: implemented for the tested userspace

- universal Mach-O x86_64 slice selection works for a manually supplied dyld;
- the controlled app and all six dyld segments map together at explicit guest addresses;
- Rosa enters dyld's x86_64 `LC_UNIXTHREAD` entry with the initial stack;
- a manually supplied x86_64 dyld cache plus six subcaches is validated and mapped intact as 28 guest mappings at slide zero;
- `shared_region_check_np` succeeds and dyld recognizes/accesses the cache metadata;
- the original single-instruction diagnostic path advanced through more than 4.1 million executed blocks and 65,000 unique translations of the tested unmodified dyld and shared-cache userspace;
- the normal bounded-block path executes the same startup in roughly 784,000 blocks and 12,847 translations, consuming about 3.97 MiB in one pooled `MAP_JIT` arena mapping;
- dyld has parsed and repeatedly traversed application Mach-O structures, dispatched internal callbacks and jump tables, used vector string operations, consulted the x86 commpage, and entered deeper load-command/address-calculation paths;
- the trace has reached BSD `proc_info(PROC_INFO_CALL_SET_DYLD_IMAGES)`, `munmap`, sysctl/AMFI/Sandbox policy, and synthetic root/cryptex VFS operations, plus guest `VM_PROT_COPY`;
- dyld enters dyld-in-cache and successfully unmaps the standalone dyld image;
- trap 24 constructs explicit guest-only `MPO_REPLY_PORT` receive rights with fault-atomic copyout; subsequent deallocation/refcount and observed `mach_msg2` operations use the same namespace;
- x86_64 `stat64`, `fstat64`, `fstatat64`, `getfsstat64`, and controlled descriptor/path operations use explicit guest layouts rather than copying arm64 host structures;
- cache-PC provenance records execution in 21 images, including libSystem, libsystem_kernel, libsystem_pthread, libsystem_platform, libc, malloc, dispatch, Objective-C, libc++abi, XPC, trace, secinit, container management, and libsystem_darwin;
- a normal Clang-driver-linked x86_64 Mach-O with `LC_MAIN` and an `LC_LOAD_DYLIB` dependency on `/usr/lib/libSystem.B.dylib` completes dyld and library initialization;
- libc formats the program's `printf`, crosses Darwin `write_nocancel`, returns from the ordinary `main`, and exits with status zero;
- an `-O2` scalar prime-sieve application completes ten passes to one million through the same ordinary dynamic path, verifies 78,498 primes and their sum, and exercises about 25.3 million guest blocks with 32-instruction application blocks;
- that application-driven frontier added register-direct unsigned 32-bit `DIV`, with focused decode, IR, execution, and fault-semantics coverage;
- no custom `_start`, static link, binary patch, interpreter fallback, or Rosetta runtime execution is involved in that frontier run.

This proves deliberately small ordinary applications, not general macOS
compatibility. The next compatibility frontier is a richer C program that
exercises heap allocation, file I/O, environment access, and additional libc
paths. The next performance frontier is persisting optimized memory traces or
linking translated blocks into broader direct traces.

### R5 performance snapshot

On the current M1 Pro host, the uncached release path is roughly 0.09 seconds,
down from 1.23 seconds before pooled executable allocation, non-retained
runtime listings, lazy shared-cache page rebasing, allocation-free scalar
guest memory, release IPO, and bounded multi-instruction dyld blocks. Peak resident size
is about 96 MB rather than 956 MB. The opt-in persistent translation cache
stores relocatable AArch64 and publishes a warm 4 MiB cache image as one JIT
batch. Across eleven alternating warm-cache process trials, the baseline-only
Rosa median was 46.4 ms while Rosetta's median was 10.5 ms, leaving about a
4.4x gap rather than 37x. The next structural speed work is broader direct
block/trace linking; process-persistent compilation has removed most repeated
frontend and publication cost.

The scalar prime sieve exposes the steady-state gap more clearly. Its first
baseline measurement was a 28.5 ms Rosetta median and a 598.1 ms Rosa median,
or 21.0x. After generated self-edge batching, checked anonymous byte windows,
native and deferred flags, guest-register forwarding and pinning, adjacent-load
guard coalescing, and guarded monotonic read/write spans, 61 alternating warm
process trials measured 24.4 ms through Rosetta and 65.0 ms through baseline
Rosa: a 2.7x gap and a 9.2x Rosa speedup. The LLVM tier now accepts the sieve's
proven anonymous read and write loops, reconstructing IR lazily even from a
persistent baseline entry. Forced promotion saved about 8 ms of trace execution
but cost about 29 ms of ORC compilation, so memory traces use a measured
100-million-execution threshold and this short process remains on the faster
baseline path.

## Verification notes

The debug, release, and UndefinedBehaviorSanitizer presets pass the complete suite. On the current macOS 26.5.1 / Apple Clang 17 host, binaries built with AddressSanitizer hang in the sanitizer runtime during dynamic-shadow initialization before `main`; even `rosa` with no command reaches that hang before any JIT allocation. The `asan` preset is retained for toolchain/host retesting, but it is not counted as a passing verification run.
