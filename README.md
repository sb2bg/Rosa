# Rosa

Run Intel Mac software on Apple Silicon.

Rosa is an experimental open-source x86_64 macOS compatibility runtime for arm64 macOS. It dynamically translates Intel code to ARM64 and aims to execute legacy Intel macOS applications against a provisioned Intel macOS userspace without depending on Apple's Rosetta 2.

Status: very early experimental development. R0–R4 work for deliberately controlled programs: Rosa maps a complete x86_64 Mach-O image, constructs an initial Darwin guest stack, and can print and exit through the x86 Darwin syscall ABI. It does **not** run ordinary dynamically linked executables or initialize `libSystem` yet.

```text
x86_64 Mac app
      ↓
Intel macOS userspace
      ↓
Rosa DBT + Darwin compatibility
      ↓
arm64 macOS
```

## Build and verify

Rosa's current backend requires an arm64 macOS host, CMake, and Ninja.

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug

./build/debug/rosa selftest r0 --dump-arm64
./build/debug/rosa selftest r1 --dump-x86 --dump-ir --dump-arm64
./build/debug/rosa selftest r2 --dump-x86 --dump-ir --dump-arm64

./build/debug/rosa inspect --segments --load-commands \
  ./build/debug/test-fixtures/hello-darwin-x86_64
./build/debug/rosa run ./build/debug/test-fixtures/hello-darwin-x86_64

# Manually supplied dyld experiment; failure is currently expected and diagnostic.
./build/debug/rosa run --dyld /usr/lib/dyld \
  ./build/debug/test-fixtures/hello-darwin-x86_64 --dump-x86 --dump-ir
```

The R1 self-test decodes and lowers this exact block:

```asm
mov rax, 40
add rax, 2
ret
```

The emitted ARM64 receives a pointer to an explicit guest `X86State`, calculates `RAX = 42`, eagerly updates the arithmetic x86 flags, records the guest exit RIP, and returns to the dispatcher.

The build creates `hello-darwin-x86_64` from checked-in assembly source. `rosa run` maps all of its Mach-O segments, finds its actual `LC_MAIN` entry, constructs `argc`/`argv`/`envp`/`apple[]`, and executes generated ARM64 for its x86 instructions. The guest executes `syscall` with Darwin BSD numbers `0x02000004` (`write`) and `0x02000001` (`exit`):

```text
hello from Intel Darwin
guest exited: status=0, blocks=2, translations=2
```

There is no output helper or interpreter fallback. macOS never launches the guest Mach-O, so Apple Rosetta is not part of this execution path. The fixture is linked with `libSystem` only to obtain a normal `LC_MAIN`; it makes no library calls and dynamic loading remains unimplemented.

## Current instruction subset

Coverage is encoding-specific and failure-driven. The generated ARM64 path currently supports the forms exercised by the controlled fixtures and dyld probe:

- integer movement: selected 8/16/32/64-bit `mov`, `lea`, `push`, `pop`, `movzx`, and `movsxd` register, immediate, base/displacement, RIP-relative, and scaled-SIB forms;
- integer/flags: selected 8/16/32/64-bit `add`, `sub`, `inc`, `dec`, `not`, `neg`, `and`, `or`, `xor`, `test`, `cmp`, `shl`, `shr`, `shrd`, unsigned `mul`, signed two-register `imul`, `bsf`, and `bsr` forms;
- control: relative `jmp`/`call`, register `jmp`, indirect guest-memory `call`, `ret`, selected register `cmovcc` and `setcc` forms, and the observed short/long unsigned and signed conditional branches;
- SIMD used by dyld: register `xorps`/`pxor`, memory `pcmpeqb`, `pmovmskb`, `pshufd`, aligned/unaligned `movaps`/`movups`/`movdqa`/`movdqu`, and low-qword `movq` store;
- ordering/time/system: `lfence`, `rdtsc`, and semantic x86_64 Darwin `syscall` exits to the compatibility dispatcher.

Guest loads and stores are permission-checked at 8, 16, 32, 64, and 128 bits. Unsupported encodings still fail with the guest RIP, bytes, register state, nearby mappings, recent instruction history, and translation counters rather than falling back to interpretation.

The semantic differential corpus currently runs 176 controlled instruction cases both through Rosa and through a standalone x86_64 oracle under Apple Rosetta, comparing only architecturally defined registers, flags, and memory. Rosetta is used only by that test oracle; it is never used to execute the dyld probe.

Mach-O inspection accepts thin x86_64 files and selects x86_64 slices from universal binaries. Loading maps every segment with its initial permissions, copies the file-backed portion, zero-fills the virtual tail, and represents inaccessible segments such as `__PAGEZERO` without allocating their full size. Rosa does not yet apply rebases, bindings, chained fixups, or shared-cache mappings.

The manual dyld experiment maps the app and all six x86_64 dyld segments, enters the slid `LC_UNIXTHREAD` RIP, and runs unmodified dyld in diagnostic one-instruction translations. The current probe reaches 179,745 executed blocks and 5,745 unique translations. Its first failure is `test byte [r14+0x8], 1` (`41 f6 46 08 01`) at guest RIP `0x7ff8000598aa`.

The trace has crossed real environment boundaries: BSD `thread_selfid`, `getentropy`, the empty-tuple `fsgetpath` probe, and `shared_region_check_np`; the x86 machdep thread-self setup call; Mach task-self, reply-port, `mach_vm_protect`, and anonymous `mach_vm_map` traps; and an anonymous `VM_MEMORY_DYLD` allocation. `shared_region_check_np` currently reports `EINVAL` because Rosa has no provisioned Intel shared region. No x86 shared-cache image has been mapped or resolved, no x86 system library has loaded, and `libSystem`, application initialization, and guest `main` have not begun.

The diagnostic mode changes translation granularity only; every supported guest instruction still executes as generated ARM64. Apple binaries are never modified or launched with `exec`, and there is no interpreter fallback.

See [docs/architecture.md](docs/architecture.md), [docs/guest-memory.md](docs/guest-memory.md), [docs/darwin-boundary.md](docs/darwin-boundary.md), and [docs/milestones.md](docs/milestones.md) for the implemented architecture and exact milestone status.
