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
- integer/flags: selected 16/32/64-bit `add`, `sub`, `inc`, `dec`, `and`, `or`, `xor`, `test`, `cmp`, `shl`, `shr`, `shrd`, unsigned `mul`, signed two-register `imul`, and `bsf` forms;
- control: relative `jmp`/`call`, register `jmp`, indirect guest-memory `call`, `ret`, `cmovb`, `sete`, `setne`, and the observed short/long unsigned, equality, sign, and signed-less-or-equal branches;
- SIMD used by dyld: register `xorps`/`pxor`, memory `pcmpeqb`, `pmovmskb`, `pshufd`, aligned/unaligned `movaps`/`movups`/`movdqa`/`movdqu`, and low-qword `movq` store;
- ordering/time/system: `lfence`, `rdtsc`, and semantic x86_64 Darwin `syscall` exit.

Guest loads and stores are permission-checked at 8, 16, 32, 64, and 128 bits. Unsupported encodings still fail with the guest RIP, bytes, register state, nearby mappings, recent instruction history, and translation counters rather than falling back to interpretation.

Mach-O inspection accepts thin x86_64 files and selects x86_64 slices from universal binaries. Loading maps every segment with its initial permissions, copies the file-backed portion, zero-fills the virtual tail, and represents inaccessible segments such as `__PAGEZERO` without allocating their full size. Rosa does not yet apply rebases, bindings, chained fixups, or shared-cache mappings.

The manual dyld experiment maps the app and all six x86_64 dyld segments, enters the slid `LC_UNIXTHREAD` RIP, and runs unmodified dyld in diagnostic one-instruction translations. The current probe reaches 3,413 executed blocks and 1,147 unique translations. Its first failure is `and r15d, 0xfff` (`41 81 e7 ff 0f 00 00`) at guest RIP `0x7ff80004469e`. No Darwin syscall, Mach operation, shared-cache mapping, system-library resolution, or `libSystem` initialization has been observed yet.

The diagnostic mode changes translation granularity only; every supported guest instruction still executes as generated ARM64. Apple binaries are never modified or launched with `exec`, and there is no interpreter fallback.

See [docs/architecture.md](docs/architecture.md), [docs/guest-memory.md](docs/guest-memory.md), [docs/darwin-boundary.md](docs/darwin-boundary.md), and [docs/milestones.md](docs/milestones.md) for the implemented architecture and exact milestone status.
