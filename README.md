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

# Apple binaries remain outside the repository. This uses a local Intel cache.
./build/debug/rosa cache inspect /path/to/dyld_shared_cache_x86_64
./build/debug/rosa run --max-blocks 5000000 \
  --dyld /usr/lib/dyld \
  --shared-cache /path/to/dyld_shared_cache_x86_64 \
  ./build/debug/test-fixtures/hello-darwin-x86_64
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
- SIMD used by dyld: selected register/memory `xorps`/`pxor`, `pcmpeqb`, `pmovmskb`, `pshufd`, `pblendw`, `pinsrd`, aligned/unaligned `movaps`/`movups`/`movdqa`/`movdqu`, and low-qword `movq` load/store forms;
- ordering/time/system: `lfence`, `rdtsc`, and semantic x86_64 Darwin `syscall` exits to the compatibility dispatcher.

Guest loads and stores are permission-checked at 8, 16, 32, 64, and 128 bits. Unsupported encodings still fail with the guest RIP, bytes, register state, nearby mappings, recent instruction history, and translation counters rather than falling back to interpretation.

The semantic differential corpus currently runs 265 controlled instruction cases both through Rosa and through a standalone x86_64 oracle under Apple Rosetta, comparing only architecturally defined registers, flags, XMM lanes, and memory. Rosetta is used only by that test oracle; it is never used to execute the dyld probe.

Mach-O inspection accepts thin x86_64 files and selects x86_64 slices from universal binaries. Loading maps every segment with its initial permissions, copies the file-backed portion, zero-fills the virtual tail, and represents inaccessible segments such as `__PAGEZERO` without allocating their full size.

`GuestSharedCache` validates a manually supplied x86_64/x86_64h cache and its subcaches, maps file-backed regions at the preferred unslid guest addresses, applies mapping permissions and version-2 slide fixups, and constructs the cache dynamic-data page. `rosa cache inspect` reports its identity, preferred region, dyld entry, files, mappings, protections, and slide metadata. No Apple cache file is copied into the repository.

The current unmodified-dyld probe uses a local seven-file x86_64 cache with 28 mappings at guest slide zero. `shared_region_check_np` succeeds, dyld recognizes and accesses the cache, registers its all-image-info range with `proc_info`, enters dyld-in-cache, applies `VM_PROT_COPY` to guest cache data, and unmaps the standalone dyld image. It reaches 1,058,265 executed blocks and 21,776 translations before the next loud boundary: `_kernelrpc_mach_port_construct_trap` (Mach trap 24).

No non-dyld cached system image resolution has yet been verified. `libSystem` initialization, application initialization, and guest `main` have not begun.

The diagnostic mode changes translation granularity only; every supported guest instruction still executes as generated ARM64. Apple binaries are never modified or launched with `exec`, and there is no interpreter fallback.

See [docs/architecture.md](docs/architecture.md), [docs/guest-memory.md](docs/guest-memory.md), [docs/darwin-boundary.md](docs/darwin-boundary.md), and [docs/milestones.md](docs/milestones.md) for the implemented architecture and exact milestone status.
