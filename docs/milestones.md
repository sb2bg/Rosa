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

- the build produces an x86_64 Mach-O using the native arm64 Apple toolchain as a cross-target linker;
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
- no output helper or interpreter fallback exists.

## R5 — x86 dyld startup: shared-cache transition and guest policy/VFS reached

- universal Mach-O x86_64 slice selection works for a manually supplied dyld;
- the controlled app and all six dyld segments map together at explicit guest addresses;
- Rosa enters dyld's x86_64 `LC_UNIXTHREAD` entry with the initial stack;
- a manually supplied x86_64 dyld cache plus six subcaches is validated and mapped intact as 28 guest mappings at slide zero;
- `shared_region_check_np` succeeds and dyld recognizes/accesses the cache metadata;
- diagnostic one-instruction translations have advanced through 1,079,752 executed blocks and 24,954 unique translations of the tested unmodified dyld;
- dyld has parsed and repeatedly traversed application Mach-O structures, dispatched internal callbacks and jump tables, used vector string operations, consulted the x86 commpage, and entered deeper load-command/address-calculation paths;
- the trace has reached BSD `proc_info(PROC_INFO_CALL_SET_DYLD_IMAGES)`, `munmap`, sysctl/AMFI/Sandbox policy, and synthetic root/cryptex VFS operations, plus guest `VM_PROT_COPY`;
- dyld enters dyld-in-cache and successfully unmaps the standalone dyld image;
- trap 24 constructs explicit guest-only `MPO_REPLY_PORT` receive rights with fault-atomic copyout; subsequent deallocation/refcount and observed `mach_msg2` operations use the same namespace;
- cache-PC provenance still records only `/usr/lib/dyld` (image index 2) as executed;
- the next loud failure is guest `fstatat64` for `System/Library/dyld/` relative to the synthetic `/System/Cryptexes/OS` descriptor.

No non-dyld cached system image resolution or execution is yet verified. `libSystem` initialization, application initialization, and transfer to guest `main` have not begun. The next slice must define the x86_64 Darwin `stat64` ABI and synthetic VFS metadata; copying an arm64 host `stat` is explicitly not acceptable.

## Verification notes

The debug, release, and UndefinedBehaviorSanitizer presets pass the complete suite. On the current macOS 26.5.1 / Apple Clang 17 host, binaries built with AddressSanitizer hang in the sanitizer runtime during dynamic-shadow initialization before `main`; even `rosa` with no command reaches that hang before any JIT allocation. The `asan` preset is retained for toolchain/host retesting, but it is not counted as a passing verification run.
