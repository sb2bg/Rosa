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
> Rosa is a research project, not a Rosetta replacement you can use for everyday applications today. It runs controlled x86_64 Mach-O fixtures, ordinary dynamically linked applications do not yet reach `main`.

## Why Rosa?

Rosa is built to make the whole compatibility path observable. It owns the x86 decoder, intermediate representation, AArch64 emitter, guest address space, Mach-O loader, and Darwin ABI translation instead of hiding those boundaries behind an interpreter or the host kernel.

- **Real dynamic binary translation.** Supported x86 instructions execute as generated AArch64 in `MAP_JIT` mappings; there is no interpreter fallback.
- **Explicit guest isolation.** Guest addresses, permissions, registers, ports, and syscalls are modeled separately from their host counterparts.
- **Useful failure modes.** An unsupported instruction or Darwin operation stops with its guest RIP, bytes, registers, mappings, recent history, and translation counters.
- **No bundled Apple binaries.** dyld and shared-cache experiments use files supplied locally by the developer. Rosa never patches or launches the guest Mach-O with `exec`.

## Project status

| Layer        | Current capability                                                                                                           |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| Translation  | Decodes an encoding-specific x86_64 subset, lowers it through a typed SSA-like IR, and emits AArch64 with a custom assembler; an optional LLVM tier optimizes supported hot loops |
| Execution    | Caches translated blocks, maintains explicit x86 register/flag/XMM state, and dispatches guest control flow                  |
| Memory       | Enforces a 4 KiB guest-page model with sparse, anonymous, Mach-O, commpage, and shared-cache mappings                        |
| Mach-O       | Selects x86_64 universal slices, validates load commands, maps complete segments, and builds the initial Darwin stack        |
| Darwin       | Implements the small BSD, Mach, and machdep surface reached by the fixture and current dyld probe                            |
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

Not yet implemented:

- general-purpose x86_64 instruction coverage
- the complete Darwin syscall and Mach interfaces
- general Mach-O rebasing, binding, or library loading outside dyld
- `libSystem` initialization, application initialization, or transfer to guest `main`
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

Then run the fixture through the unmodified x86_64 dyld path:

```bash
./build/debug/rosa run \
  --dyld /usr/lib/dyld \
  --shared-cache /path/to/dyld_shared_cache_x86_64 \
  --max-blocks 5000000 \
  ./build/debug/test-fixtures/hello-darwin-x86_64
```

This is a diagnostic bring-up path. Cache compatibility matters, the supported instruction and ABI surfaces are intentionally incomplete, and the run is expected to stop loudly at the first unimplemented boundary.

The current probe recognizes and enters the intact cache at slide zero, executes cached `/usr/lib/dyld`, and advances through guest Mach-port, policy, kernel-metadata, and synthetic cryptex-directory operations. It currently stops at the first unimplemented x86_64 `fstatat64` structure copyout. No non-dyld cached image execution or `libSystem` initialization is claimed.

## Architecture

```text
 x86_64 app ───────┐
                   ▼
        Mach-O loader + Darwin startup stack
                   │
                   ▼
 x86 decoder → typed IR ─┬→ baseline AArch64 emitter → MAP_JIT block cache
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

Generated blocks receive an explicit `X86State*`, update architectural state, and return the next guest action to the dispatcher. Guest virtual addresses are never treated as host pointers. Syscalls leave generated code and cross a semantic compatibility boundary. An x86 `syscall` is never rewritten as an ARM `svc`.

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
the benchmark's 64-bit `DEC`/`JNE` self-loop is lowered from Rosa IR into LLVM
SSA, optimized at `-O2`, and executed through ORC. All other IR shapes continue
through the baseline emitter. Pass `-DROSA_ENABLE_LLVM_JIT=OFF` to measure or
test the fallback path explicitly.

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
