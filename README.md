<div align="center">
  <img src="assets/rosa-mark.svg" width="144" alt="Rosa logo">

  <h1>Rosa</h1>

  <p><strong>x86_64 macOS compatibility runtime for Apple Silicon.</strong></p>

  <p>
    <a href="#quick-start"><img alt="Host: macOS arm64" src="https://img.shields.io/badge/host-macOS%20arm64-111827?style=flat-square&logo=apple&logoColor=white"></a>
    <a href="CMakeLists.txt"><img alt="C++23" src="https://img.shields.io/badge/C%2B%2B-23-00599C?style=flat-square&logo=cplusplus&logoColor=white"></a>
    <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-D22128?style=flat-square"></a>
    <a href="#status"><img alt="Status: experimental" src="https://img.shields.io/badge/status-experimental-E11D48?style=flat-square"></a>
  </p>
</div>

Rosa translates Intel machine code to AArch64 at run time and reimplements the Darwin userspace boundary that translated programs call into. The goal is to run Intel Mac software against an Intel macOS userspace (dyld and the x86_64 shared cache) without Rosetta 2 in the execution path.

> [!IMPORTANT]
> Rosa is a research project. It runs ordinary dynamically linked x86_64 C programs and small host command-line tools such as `grep` through the unmodified Intel dyld and shared cache, but instruction and Darwin ABI coverage is deliberately narrow. Most applications stop at their first unsupported instruction or system call.

## Why Rosa?

Rosa owns every layer of the compatibility path (x86 decoder, IR, AArch64 emitter, guest address space, Mach-O loader, and Darwin ABI) so each boundary can be inspected and tested.

- **Dynamic binary translation, no interpreter.** Supported instructions run as generated AArch64 in pooled `MAP_JIT` memory. Anything else stops translation.
- **Explicit guest isolation.** Guest addresses, permissions, registers, file descriptors, Mach ports, and syscalls are modeled separately from the host's.
- **Loud failures.** An unsupported instruction or Darwin operation stops with its guest RIP, bytes, registers, mappings, recent history, and translation counters.
- **No bundled Apple binaries.** dyld and the shared cache come from the local machine. Rosa never patches the guest Mach-O or launches it with `exec`.

## Status

| Layer        | Current capability |
| ------------ | ------------------ |
| Translation  | Encoding-specific x86_64 subset → typed SSA-like IR → AArch64 via a custom assembler; optional LLVM tier for hot loops |
| Execution    | Block cache in pooled executable arenas, explicit x86 register/flag/XMM state, optional persistent translation cache |
| Memory       | 4 KiB guest pages over anonymous, file-backed, Mach-O, commpage, and shared-cache mappings |
| Mach-O       | Universal-slice selection, validated load commands, segment mapping, Darwin startup stack |
| Darwin       | The BSD, Mach, and machdep calls reached by dyld, `libSystem` startup, and the tested programs ([list](docs/darwin-boundary.md)) |
| Verification | Unit suites per subsystem, a differential corpus against an x86_64 oracle, byte-exact comparison against host tools |

Not yet implemented:

- general x86_64 instruction coverage;
- the complete BSD syscall and Mach interfaces;
- signals, `fork`/`exec`, and multiple guest threads or processes;
- guest filesystem writes;
- Objective-C and framework-heavy applications.

The [milestone ledger](docs/milestones.md) records exactly what is implemented and how it was verified.

## Quick start

Requirements:

- an Apple Silicon Mac;
- CMake 3.25+, Ninja, and Apple Clang (Xcode or the Command Line Tools);
- optionally, Homebrew LLVM for the optimizing JIT tier;
- optionally, Rosetta 2, used only as the oracle for differential tests.

Build and test:

```bash
git clone https://github.com/sb2bg/Rosa.git
cd Rosa
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

The build cross-compiles its x86_64 test fixtures with the host toolchain. The simplest one is a hand-written Mach-O that calls `write` and `exit` directly:

```console
$ ./build/debug/rosa run ./build/debug/test-fixtures/hello-darwin-x86_64
hello from Intel Darwin
guest exited: status=0, blocks=2, translations=2
```

### Dynamically linked programs

A program linked against `libSystem` needs an Intel dyld and shared cache. A Mac with Rosetta installed already has both, and `rosa exec` uses them by default:

```bash
lipo /usr/bin/grep -thin x86_64 -output /tmp/grep-x86_64
LC_ALL=C ./build/debug/rosa exec /tmp/grep-x86_64 -n --color=always beta README.md
```

`LC_ALL=C` is currently required: under a UTF-8 locale, libc maps the locale data with a private writable `mmap` that Rosa does not implement yet.

`rosa exec` behaves like a shell launching the program: it passes every argument after the executable to the guest, passes the host environment minus `DYLD_*`, gives the guest read-only access to the host filesystem, and has no block limit. The guest's exit status becomes Rosa's; a Rosa failure exits with 125 and writes its diagnostic to stderr. `--argv0 <name>` overrides the guest's `argv[0]`.

`rosa run` is the lower-level entry point used for fixtures. It confines file access to the working directory, prints a status line on exit, takes guest arguments after `--`, and stops after a block limit (1,000,000 by default with `--dyld`):

```bash
CACHE=/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64

./build/debug/rosa run --dyld /usr/lib/dyld --shared-cache "$CACHE" \
  ./build/debug/frontier-fixtures/ordinary-c-x86_64
```

```text
ordinary x86_64 C main: argc=1 argv[0]=./build/debug/frontier-fixtures/ordinary-c-x86_64
dyld experiment exited: status=0, blocks=..., translations=..., cache-hits=..., jit-mappings=1, jit-used=...
```

That run goes through dyld, `libSystem` initialization, and libc `printf`. Compatibility depends on the dyld and cache versions; inspect a cache with `rosa cache inspect <path>`.

### Persistent translation cache

`--translation-cache <path>` stores translated blocks on disk. The first run fills the file. Later runs check the cached x86 bytes against the guest, relocate helper calls for the current ASLR slide, and publish all cached code in one JIT transaction. `--timings` reports where launch time goes. Dump options bypass the cache so their output always comes from a fresh translation.

## Command reference

| Command | Purpose |
| ------- | ------- |
| `rosa exec <mach-o> [args...]` | Run a dynamically linked x86_64 program like a shell would |
| `rosa run <mach-o> [-- args...]` | Run a fixture, controlled or through dyld, with a status line and block limit |
| `rosa inspect <mach-o>` | Describe an x86_64 thin or universal Mach-O (`--segments`, `--load-commands`) |
| `rosa cache inspect <cache>` | Validate and describe an Intel dyld shared cache and its subcaches |
| `rosa selftest r0` / `r1` / `r2` | Self-tests for AArch64 emission, one translated block, and multi-block control flow |

| Option | Applies to | Effect |
| ------ | ---------- | ------ |
| `--dyld <path>`, `--shared-cache <path>` | `run`, `exec` | Intel dyld and shared cache (`exec` defaults to the host's) |
| `--max-blocks <n>` | `run`, `exec` | Stop after `n` dispatched blocks |
| `--translation-cache <path>` | `run`, `exec` | Use a persistent translation cache |
| `--trace-syscalls` | `run`, `exec` | Log each BSD call, its arguments, and its result to stderr |
| `--argv0 <name>` | `exec` | Guest `argv[0]` (defaults to the executable path) |
| `--timings` | `run` | Print phase and translation-cache timing |
| `--dump-x86`, `--dump-ir`, `--dump-arm64` | `run`, `selftest` | Print each translation stage |

## Explore the translator

The R1 self-test translates and runs this block, then checks that guest `RAX` is 42:

```asm
mov rax, 40
add rax, 2
ret
```

```bash
./build/debug/rosa selftest r1 --dump-x86 --dump-ir --dump-arm64
```

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

Generated blocks take an explicit `X86State*`, update guest state, and return the next guest RIP to the dispatcher. Guest addresses are never used as host pointers; every access goes through the guest address space, with narrow fast paths only where a runtime check has proven the range safe. An x86 `syscall` leaves generated code and is handled by Rosa's Darwin layer. It is never rewritten as an ARM `svc`.

See [docs/architecture.md](docs/architecture.md) for details.

## Testing

```bash
ctest --preset debug                  # full debug suite
ctest --preset debug -L Optimization  # one subsystem
./build/debug/rosa_tests --list       # list suites

# Without LLVM or the Rosetta oracle
cmake --preset baseline && cmake --build --preset baseline && ctest --preset baseline

# UndefinedBehaviorSanitizer
cmake --preset ubsan && cmake --build --preset ubsan && ctest --preset ubsan
```

When Rosetta is installed, the differential suite builds a standalone x86_64 oracle and compares architecturally defined registers, flags, XMM lanes, and memory against Rosa for every case in [`tests/differential/Cases.def`](tests/differential/Cases.def). Rosetta is a test dependency only.

The compatibility harness runs host tools under Rosa and compares stdout, stderr, and exit status byte for byte against the same universal binary run natively:

```bash
tests/compat/compat.py --rosa build/debug/rosa
tests/compat/compat.py --rosa build/debug/rosa grep -v
```

An AddressSanitizer preset exists but currently hangs on the development host; see the [verification notes](docs/milestones.md#verification-notes).

## Performance

Measured on an M1 Pro with warm process launches, using release builds (`cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release`). These numbers describe two small fixtures on one host, not application performance in general.

| Fixture | Rosetta median | Rosa median (baseline tier) | Gap |
| ------- | -------------: | --------------------------: | --: |
| `ordinary-c-x86_64` (dyld startup + `printf`, persistent cache) | 10.5 ms | 46.4 ms | 4.4× |
| `prime-sieve-x86_64` (10 scalar sieve passes to 1,000,000) | 24.4 ms | 65.0 ms | 2.7× |

The sieve is built at `-O2` with vectorization disabled because the SSE4.1 reduction Clang would otherwise emit is outside Rosa's SIMD coverage. Both runtimes execute the same binary:

```bash
./build/release/rosa run --dyld /usr/lib/dyld --shared-cache "$CACHE" \
  --translation-cache /tmp/rosa-sieve.translation-cache --max-blocks 1000000000 \
  ./build/release/benchmarks/prime-sieve-x86_64
```

```text
sieve limit=1000000 rounds=10 primes=78498 sum=37550402023 checksum=1876165121666630888
```

The [milestone ledger](docs/milestones.md#r5-performance) has the measurement history and what each optimization contributed.

## Documentation

| Document | Contents |
| -------- | -------- |
| [Architecture](docs/architecture.md) | Translation pipeline, state boundaries, caches, executable memory |
| [Guest memory](docs/guest-memory.md) | Address-space model, permissions, fast paths, invariants |
| [Darwin boundary](docs/darwin-boundary.md) | Implemented BSD calls, Mach traps, machdep calls, commpage, path policy |
| [Backend contract](docs/backend-contract.md) | What a host backend owns and must preserve |
| [Milestones](docs/milestones.md) | R0–R5 scope, current work, performance history, verification status |
| [Contributing](CONTRIBUTING.md) | Invariants, workflow, and how to add instructions and syscalls |

## Development approach

Rosa grows in narrow, tested vertical slices. New behavior should be motivated by a fixture or a captured real-program failure, keep guest and host state separate, and fail with a diagnostic where semantics are not yet implemented. Partial compatibility stays measurable because nothing falls back silently.

## License

Copyright © 2026 Sullivan Bognar.

Rosa is licensed under the [Apache License 2.0](LICENSE).
