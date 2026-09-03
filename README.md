<div align="center">
  <img src="assets/rosa-mark.svg" width="144" alt="Rosa logo">

  <h1>Rosa</h1>

  <p><strong>x86_64 macOS compatibility runtime for Apple Silicon.</strong></p>

  <p>
    <a href="#quick-start"><img alt="Host: macOS arm64" src="https://img.shields.io/badge/host-macOS%20arm64-111827?style=flat-square&logo=apple&logoColor=white"></a>
    <a href="CMakeLists.txt"><img alt="C++23" src="https://img.shields.io/badge/C%2B%2B-23-00599C?style=flat-square&logo=cplusplus&logoColor=white"></a>
    <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-D22128?style=flat-square"></a>
    <a href="#project-status"><img alt="Status: experimental" src="https://img.shields.io/badge/status-experimental-E11D48?style=flat-square"></a>
  </p>
</div>

Rosa dynamically translates Intel machine code to AArch64 and recreates the Darwin userspace boundary that translated programs need. Its goal is to run legacy Intel Mac software against a locally provisioned Intel macOS userspace without relying on Rosetta 2 at runtime.

> [!IMPORTANT]
> Rosa is a research project, not a Rosetta replacement you can use for everyday applications today. It can run a small ordinary x86_64 C executable through a locally supplied Intel dyld and matching shared cache, including `libSystem` startup and `printf`, but its instruction and Darwin ABI coverage remains deliberately narrow.

## Why Rosa?

Rosa is built to make the whole compatibility path observable. It owns the x86 decoder, intermediate representation, AArch64 emitter, guest address space, Mach-O loader, and Darwin ABI translation instead of hiding those boundaries behind an interpreter or the host kernel.

- **Real dynamic binary translation.** Supported x86 instructions execute as generated AArch64 in pooled `MAP_JIT` mappings; there is no interpreter fallback.
- **Explicit guest isolation.** Guest addresses, permissions, registers, ports, and syscalls are modeled separately from their host counterparts.
- **Useful failure modes.** An unsupported instruction or Darwin operation stops with its guest RIP, bytes, registers, mappings, recent history, and translation counters.
- **No bundled Apple binaries.** dyld and shared-cache experiments use files supplied locally by the developer. Rosa never patches or launches the guest Mach-O with `exec`.

## Project status

| Layer        | Current capability                                                                                                           |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| Translation  | Decodes an encoding-specific x86_64 subset, lowers it through a typed SSA-like IR, and emits AArch64 with a custom assembler; an optional LLVM tier optimizes supported hot loops |
| Execution    | Caches translated blocks in pooled executable arenas, maintains explicit x86 register/flag/XMM state, and dispatches guest control flow |
| Memory       | Enforces a 4 KiB guest-page model with sparse, anonymous, Mach-O, commpage, and shared-cache mappings                        |
| Mach-O       | Selects x86_64 universal slices, validates load commands, maps complete segments, and builds the initial Darwin stack        |
| Darwin       | Implements the BSD, Mach, and machdep subset needed by the fixtures and the first ordinary dynamically linked C program       |
| Verification | Runs 324 semantic cases against an independent x86_64 oracle when Rosetta is installed                                       |

The [checked-in example](tests/fixtures/hello-darwin-x86_64.s) currently completes end to end:

```text
x86_64 Mach-O
    → x86 decode → Rosa IR → AArch64 emission
    → translated Darwin write(2)
    → translated Darwin exit(2)

hello from Intel Darwin
guest exited: status=0, blocks=2, translations=2
```

The test suite also cross-compiles
[a C `main`](tests/fixtures/c-main-x86_64.c). A minimal x86_64 entry stub
passes the Darwin startup stack's `argc` and `argv`, calls compiler-generated
code, and verifies that `main` returns 42. Its hot `INC`/`CMP` loop is promoted
through the LLVM tier.

Not yet implemented:

- general-purpose x86_64 instruction coverage
- the complete Darwin syscall and Mach interfaces
- broad compatibility across ordinary macOS applications and framework stacks
- general filesystem, signal, process, thread, and Mach IPC behavior
- multiple guest processes or threads

See the [milestone ledger](docs/milestones.md) for the exact implemented scope and verification notes.

## Quick start

### Requirements

- an Apple Silicon Mac;
- CMake 3.25 or newer;
- Ninja;
- Apple Clang from Xcode or the Command Line Tools;
- optionally, Homebrew LLVM for the optimizing JIT tier;
- optionally, Rosetta 2 for the independent differential-test oracle only.

Configure, build, and run the test suite:

```bash
git clone https://github.com/sb2bg/Rosa.git
cd Rosa

cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

The build cross-links a small x86_64 Mach-O fixture from checked-in assembly. Run it through Rosa:

```bash
./build/debug/rosa run \
  ./build/debug/test-fixtures/hello-darwin-x86_64
```

Expected output:

```text
hello from Intel Darwin
guest exited: status=0, blocks=2, translations=2
```

macOS does not launch this fixture, so Rosetta is not part of the execution path. The fixture links against `libSystem` to obtain a conventional `LC_MAIN`, but makes no library calls.

Run the controlled C program with two guest arguments:

```bash
./build/debug/rosa run --max-blocks 21000000 \
  ./build/debug/test-fixtures/c-main-x86_64 -- rosa jit
```

Expected output:

```text
C main returned 42
guest exited: status=0, blocks=20000011, translations=13
```

This is a real Clang-compiled `main(int, char **)`, but it uses Rosa's minimal
checked-in entry stub and makes no C-library calls. The separate frontier
fixture below exercises the ordinary dynamic path.

Builds also produce a normal compiler-driver-linked x86_64 executable that
calls `printf`. With a compatible Intel dyld and shared cache installed on the
host, run it without a custom entry stub:

```bash
./build/debug/rosa run \
  --dyld /usr/lib/dyld \
  --shared-cache /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64 \
  --max-blocks 5000000 \
  ./build/debug/frontier-fixtures/ordinary-c-x86_64
```

Expected output (the `argv[0]` path follows the invocation):

```text
ordinary x86_64 C main: argc=1 argv[0]=./build/debug/frontier-fixtures/ordinary-c-x86_64
dyld experiment exited: status=0, blocks=..., translations=..., cache-hits=..., jit-mappings=1, jit-used=...
```

For repeated launches, opt into the relocatable persistent translation cache.
The first run fills the file; later runs validate the cached x86 source bytes,
relocate helper calls for the current process ASLR slide, and batch-publish the
cached AArch64 with one JIT write/instruction-cache transaction:

```bash
./build/release/rosa run \
  --translation-cache /tmp/rosa-ordinary.translation-cache \
  --dyld /usr/lib/dyld \
  --shared-cache /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64 \
  --max-blocks 5000000 \
  ./build/release/frontier-fixtures/ordinary-c-x86_64
```

`--timings` prints phase and translation-cache timing. Dump requests bypass the
persistent cache so x86, IR, and AArch64 diagnostics always describe a freshly
lowered block.

The build also produces an ordinary dynamically linked, CPU-bound x86_64 prime
sieve. It runs ten scalar Eratosthenes passes to one million and verifies an
exact count, sum, and cross-round checksum:

```bash
./build/release/rosa run \
  --translation-cache /tmp/rosa-sieve.translation-cache \
  --dyld /usr/lib/dyld \
  --shared-cache /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64 \
  --max-blocks 1000000000 \
  ./build/release/benchmarks/prime-sieve-x86_64
```

```text
sieve limit=1000000 rounds=10 primes=78498 sum=37550402023 checksum=1876165121666630888
```

The reduction loop explicitly disables Clang vectorization while retaining
`-O2`; the otherwise generated SSE4.1 reduction is beyond Rosa's current SIMD
surface. Both Rosa and Rosetta measurements execute this same scalar binary.

## Explore the translator

Rosa can dump each stage of a translation. The R1 probe executes this block and verifies that the resulting guest `RAX` is 42:

```asm
mov rax, 40
add rax, 2
ret
```

```bash
./build/debug/rosa selftest r1 \
  --dump-x86 \
  --dump-ir \
  --dump-arm64
```

Inspect the generated fixture without running it:

```bash
./build/debug/rosa inspect \
  --segments \
  --load-commands \
  ./build/debug/test-fixtures/hello-darwin-x86_64
```

### Command reference

| Command                      | Purpose                                                            |
| ---------------------------- | ------------------------------------------------------------------ |
| `rosa selftest r0`           | Verify executable AArch64 emission                                 |
| `rosa selftest r1`           | Decode, lower, emit, and execute one x86 basic block               |
| `rosa selftest r2`           | Exercise multi-block control flow and the translation cache        |
| `rosa inspect <mach-o>`      | Inspect an x86_64 thin or universal Mach-O                         |
| `rosa cache inspect <cache>` | Validate and describe an Intel dyld shared cache and its subcaches |
| `rosa run <mach-o>`          | Run a controlled x86_64 Mach-O through the DBT                     |

The self-tests and `run` command accept `--dump-x86`, `--dump-ir`, and `--dump-arm64` where applicable. `run` also accepts `--max-blocks <count>` to bound guest execution.

## dyld research probe

Apple binaries are kept outside the repository. With a locally obtained compatible x86_64 dyld shared cache, inspect the cache first:

```bash
./build/debug/rosa cache inspect \
  /path/to/dyld_shared_cache_x86_64
```

Then run the ordinary C frontier fixture through the unmodified x86_64 dyld
path:

```bash
./build/debug/rosa run \
  --dyld /usr/lib/dyld \
  --shared-cache /path/to/dyld_shared_cache_x86_64 \
  --max-blocks 5000000 \
  ./build/debug/frontier-fixtures/ordinary-c-x86_64
```

This remains a version-sensitive research path: dyld and cache compatibility
matter, and a larger program will still stop loudly at its first unsupported
instruction or Darwin operation. On the tested macOS userspace, the fixture
enters the intact cache at slide zero, executes code in 21 cached images,
completes dyld and `libSystem` initialization, calls its normal `main`, prints
through libc, and exits with status zero.

## Architecture

```text
 x86_64 app ───────┐
                   ▼
        Mach-O loader + Darwin startup stack
                   │
                   ▼
 x86 decoder → typed IR ─┬→ baseline AArch64 emitter → pooled MAP_JIT cache
                         └→ LLVM O2 hot-loop tier ────→ ORC JIT
                   │                                  │
                   └──────── explicit X86State ◀──────┘
                                │
                                ▼
             guest memory + Darwin compatibility
                                │
                                ▼
                         arm64 macOS host
```

Generated blocks receive an explicit `X86State*`, update architectural state, and return the next guest action to the dispatcher. Guest virtual addresses are never reinterpreted as host pointers; repeated-loop byte fast paths first resolve a permission-checked anonymous mapping, coalesce bounds checks for adjacent loads, and permit unchecked monotonic spans only after proving exact loop termination and complete containment of the remaining range. Syscalls leave generated code and cross a semantic compatibility boundary. An x86 `syscall` is never rewritten as an ARM `svc`.

Instruction support is deliberately encoding-specific and failure-driven. The current surface covers the integer, control-flow, flag, memory, atomic, string, and SIMD forms needed by the controlled fixtures and dyld probe. Unsupported encodings fail rather than silently changing execution strategy.

## Testing

The default test suite covers the assembler, decoder, IR, translator, dispatcher, guest memory, Mach-O loader, Darwin boundary, shared-cache handling, and end-to-end fixture. When Rosetta 2 is available, it also builds a standalone x86_64 oracle and compares only architecturally defined registers, flags, XMM lanes, and memory.

Rosetta is a test dependency only. Rosa never uses it to execute a guest in the runtime path.

```bash
# Standard debug suite
ctest --preset debug

# UndefinedBehaviorSanitizer build
cmake --preset ubsan
cmake --build --preset ubsan
ctest --preset ubsan
```

An AddressSanitizer preset is also provided. See the [verification notes](docs/milestones.md#verification-notes) for the current host-runtime caveat.

For a repeatable dispatcher benchmark, configure a release build and run the
200-million-iteration x86 entrypoint fixture:

```bash
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --target benchmark_entrypoint
```

When Homebrew LLVM is installed, CMake reports `Rosa LLVM optimizing JIT` and
eligible 64-bit, register-only conditional self-loops become hot after 1,024
executions. A narrow memory tier also accepts proven anonymous byte read/write
loops, including exact constant-stride reductions and unsigned dynamic-stride
stores. It validates the complete invocation range before passing a host span
to LLVM; rejected, executable, file-backed, wrapping, and faulting cases remain
on the checked baseline. Because ORC compilation costs about 29 ms for the two
sieve traces on the development host, memory loops require 100 million observed
executions before promotion. Rosa also requires at least ten million dispatcher
executions left in the current budget. The tier keeps guest registers in LLVM
SSA, materializes lazy x86 flags only at the side exit, and optimizes at `-O2`.
Persistent baseline blocks lazily reconstruct IR only after a self-loop becomes
hot. Pass `-DROSA_ENABLE_LLVM_JIT=OFF` to measure or test the fallback path
explicitly.

The ordinary dynamic fixture is also a cold-start benchmark. On the current
M1 Pro development host, the uncached release path is roughly 0.09 seconds,
down from 1.23 seconds before pooled executable allocation, lazy shared-cache
rebasing, bounded multi-instruction blocks, allocation-free scalar memory
accesses, and release IPO. Eleven alternating warm-cache process trials put the
baseline-only Rosa median at 46.4 milliseconds and the same x86_64 fixture
through Rosetta at 10.5 milliseconds: a remaining gap of about 4.4x, down from
37x at the start of this optimization pass. This is a host- and
userspace-specific frontier measurement, not a general application-performance
claim.

The prime sieve separates steady-state execution from launch overhead. With
32-instruction dynamic blocks it executes about 25.3 million guest blocks per
process. In 61 alternating warm process trials on the same M1 Pro host, the
scalar x86_64 binary had a 24.4 ms Rosetta median and a 65.0 ms baseline Rosa
median, a 2.7x gap. That is a 9.2x Rosa improvement over the earlier 598.1 ms
baseline. Generated self-edge batching, anonymous byte-window fast paths,
native and deferred flag lowering, native 32-bit arithmetic and immediate
folding, guest-register forwarding and pinning, branchless `SET`/`CMOV`,
adjacent-load guard coalescing, and guarded monotonic read/write spans account
for the gain. A memory-loop LLVM experiment reduced trace execution by about
8 ms but cost about 29 ms to compile, so this short benchmark deliberately
remains on the faster baseline tier. Persisting optimized code or broader
direct trace formation is the next structural performance step.

## Documentation

| Document                                   | Contents                                                                   |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| [Architecture](docs/architecture.md)       | Translation pipeline, state boundaries, executable memory, and constraints |
| [Guest memory](docs/guest-memory.md)       | Address-space model, permissions, mapping behavior, and safety invariants  |
| [Darwin boundary](docs/darwin-boundary.md) | Implemented BSD calls, Mach traps, machdep behavior, and commpage fields   |
| [Milestones](docs/milestones.md)           | R0–R5 progress, known boundaries, and verification status                  |

## Development philosophy

Rosa advances through narrow, tested vertical slices. New behavior should be justified by a controlled fixture or a captured real-world failure, preserve the guest/host boundary, and fail diagnostically when semantics are not yet implemented. That keeps partial compatibility measurable and avoids hiding correctness gaps behind permissive fallbacks.

## License

Copyright © 2026 Sullivan Bognar.

Rosa is licensed under the [Apache License 2.0](LICENSE).
