# From `--version` to `SELECT 1` in 55 Minutes: What SQLite Forced a New DBT to Learn

*September 3, 2026*

Today an unmodified x86_64 macOS build of SQLite executed a real SQL query on
Apple Silicon through Rosa:

```text
-- warning: cannot find home directory; cannot read ~/.sqliterc
╭───╮
│ 1 │
╞═══╡
│ 1 │
╰───╯
dyld experiment exited: status=0, blocks=2355619, translations=18524,
  cache-hits=0, jit-mappings=1, jit-used=6715512
```

The command was deliberately ordinary:

```text
sqlite3 :memory: "SELECT 1;"
```

The executable was not recompiled for Rosa. It entered the real Intel dyld,
used an intact x86_64 dyld shared cache, initialized macOS system libraries,
entered SQLite's command-line shell and database engine, prepared and executed
the statement, formatted the row, printed it, and exited zero.

There was no interpreter fallback. Rosa decoded the x86_64 instructions,
lowered them through its own IR, emitted AArch64, and handled the Darwin
boundary through explicit guest state.

The final 55 minutes were fast. Getting to those 55 minutes was not.

## `--version` was not a small program

The first target was `sqlite3 --version`. From the outside, this sounds like a
string-printing test. SQLite's public version API ultimately does return a
constant string. But an ordinary dynamically linked macOS program does not
begin at that function.

Before SQLite could inspect its arguments, Rosa had to carry the process
through:

```text
x86_64 Mach-O
    → standalone dyld
    → dyld in the shared cache
    → libSystem and dependent initializers
    → the SQLite CLI's main()
```

That path had already been proven with smaller C fixtures. SQLite widened it
again. The runtime encountered new integer and SIMD encodings, process queries,
Mach traps, code-signing policy, feature flags, bootstrap-port behavior, and
the edges of the guest filesystem model.

Then the supposed version command went looking for a user.

## The surprising detour through identity and XPC

On Unix-like systems, the SQLite shell normally looks for a per-user
initialization file. Its startup code tries to locate the home directory using
`getuid()` and `getpwuid()` before falling back to the `HOME` environment
variable.

Rosa intentionally started the guest with an empty environment. The home
lookup therefore entered macOS's `libsystem_info` implementation, which
explored user and group databases and XPC-backed system services. That pulled
the trace through machinery that seemed wildly disproportionate to printing a
version number:

- effective and real user IDs;
- system user/group database probes;
- special reply ports;
- host special-port demotion;
- Mach vouchers;
- bootstrap messages;
- XPC failure behavior; and
- additional atomic and SIMD instruction forms in the supporting libraries.

This was not SQLite database work. It was normal macOS process behavior exposed
by a very small CLI feature.

The detour raised an important project-management question: should a
compatibility runtime complete every newly observed path, or should it change
the experiment to reach the intended subsystem sooner?

## The shortcut that clarified the architecture

SQLite accepts `-init FILENAME`, which overrides its normal search for
`~/.sqliterc`. Running the native x86_64 binary under a debugger confirmed
that these commands never called `getpwuid()`:

```text
sqlite3 -init /dev/null -batch --version
sqlite3 -init /dev/null -batch :memory: "SELECT 1;"
```

The same override under Rosa jumped past the identity/XPC frontier and exposed
an ordinary locked decrement in libc. This proved that the security-looking
work was a startup-policy branch, not a prerequisite imposed by the SQLite
engine.

That discovery did not make the work worthless. The new Mach-port, voucher,
identity, process-limit, and bootstrap behavior is reusable runtime substrate.
Other macOS programs will ask similar questions. It did, however, separate two
goals that had accidentally become entangled:

1. broaden Rosa's normal macOS process compatibility; and
2. reach actual SQLite execution.

Rosa could use the override for the second goal while retaining the default
startup path as a separate compatibility target.

In the event, the normal path was close enough to finish. At commit `45503db`,
plain `sqlite3 --version` succeeded without `-init`:

```text
-- warning: cannot find home directory; cannot read ~/.sqliterc
3.53.4 2026-07-24 19:02:57 \
  bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b-experimental (64-bit)
dyld experiment exited: status=0, blocks=2282831, translations=14067,
  cache-hits=0, jit-mappings=1, jit-used=5063432
```

The warning is accurate: Rosa presents no guest home directory. More
importantly, the unmodified program handled that condition, printed its version,
and exited successfully.

The shortcut was still valuable. It explained which work belonged to SQLite
and which work belonged to general macOS compatibility.

## `SELECT 1` moved the frontier into SQLite

The next command used the special database name `:memory:`:

```text
sqlite3 :memory: "SELECT 1;"
```

This choice was structural, not cosmetic. An exact `:memory:` database does not
open a database file. It lets the parser, code generator, virtual machine,
allocator, and result formatter execute without first requiring Rosa to
support SQLite's full filesystem and locking behavior.

The first run made that separation visible. It completed the same macOS startup
path as `--version`, entered the SQLite executable, executed 2,317,673 guest
blocks, created 14,803 translations, and stopped here:

```asm
48 f7 ea    imul rdx
```

This is the single-operand signed 64-bit multiply. x86 writes the low half of
the product to `RAX`, the high half to `RDX`, and defines overflow and carry
according to whether the high half is a sign extension of the low half.

It was an ideal frontier failure: attributable, local, testable, and plainly in
application code rather than another system service.

## Twenty-six small doors

The first multiply fix landed at 14:35. The successful query landed at 15:30.
Between them, the trace exposed roughly two dozen additional gaps.

They were not twenty-six unrelated features. They clustered around patterns
that optimized C code uses constantly.

### Widths and flags

SQLite exercised operations that look redundant at the source level but are
distinct architectural contracts:

- 8-bit subtract-with-borrow and XOR;
- 16-bit ADD, CMP, AND, and OR;
- 32- and 64-bit shifts with immediate or implicit counts;
- signed multiplication with high-half results;
- bit-test-and-set; and
- signed conditional moves and byte results.

Each width changes truncation, zero extension, sign extension, carry,
overflow, parity, and undefined-flag behavior. Treating a 16-bit operation as a
masked 64-bit operation is tempting, but wrong unless the untouched register
bits and exact flags are preserved.

### Addressing forms

Several existing operations needed new ways to name memory:

- no-index SIB encodings;
- REX.X-extended indexes;
- based memory with displacement;
- RIP-relative constants; and
- memory sources for conditional moves.

This is why instruction counts alone are misleading. “Support MOVSX” is not a
binary property. Real code asks for a particular source width, destination
width, register extension, base/index/scale combination, displacement, and
fault behavior.

### SIMD forms

The trace also reached:

- REX-extended `PXOR` using high XMM registers; and
- unaligned `MOVUPD` loads and stores.

The scalar source program did not explicitly request SIMD. The compiler and
SQLite implementation chose it. Rosa still had to preserve the x86 distinction
between legacy XMM operations and wider YMM state while validating guest-memory
access before committing architectural changes.

### One Darwin operation

Almost the entire post-version stretch was CPU coverage. The one new operating
system request was `madvise(MADV_CAN_REUSE)` over a malloc region. Rosa modeled
it as a successful advisory no-op: the guest may offer a reuse hint, but the
runtime does not need to expose or reproduce the host allocator's internal
policy.

That ratio mattered. Before `--version`, the frontier alternated between x86
and Darwin work. After entering the in-memory query, the remaining gap was
overwhelmingly instruction vocabulary.

## Failure-driven development only works with tests

The speed of the final stretch did not come from skipping validation. Each
newly observed form received a focused regression test covering the behavior
that justified it.

Those tests checked more than a happy-path value. Depending on the operation,
they covered:

- extended registers and address calculation;
- count masking for shifts;
- count-zero flag preservation;
- signed high-half multiplication;
- partial-register writes;
- aliasing between sources and destinations;
- memory faults before state commitment; and
- the exact subset of architecturally defined flags.

Rosa also has an independent x86_64 execution oracle when Rosetta is available.
The oracle compares defined registers, flags, SIMD lanes, and memory rather than
requiring undefined state to match by accident.

The result is a useful inversion of the usual whack-a-mole criticism. A loud
failure identifies a missing contract. A narrow implementation satisfies that
contract. A regression test keeps it satisfied. Then the real program chooses
the next contract.

## What `SELECT 1` proves

The successful run closes a larger loop than `--version`:

```text
Mach-O executable
    → Intel dyld and shared cache
    → macOS system-library initialization
    → SQLite CLI
    → SQLite parser and virtual machine
    → one result row
    → libc output
    → clean process exit
```

It proves that Rosa can carry one real, unmodified x86_64 macOS application
through both substantial system userspace and substantial application code.
The application did not merely reach `main()`. It performed the operation it
was built to perform.

It also validates the architectural boundaries under a much wider workload:

- x86 integer, flags, SIMD, and addressing semantics;
- typed IR and AArch64 emission;
- sparse guest memory and fault handling;
- x86_64 Mach-O and dyld startup state;
- shared-cache system libraries;
- BSD syscalls and Mach messages; and
- normal process output and exit.

## What it does not prove

`SELECT 1` is real SQLite, but it is not yet a general SQLite environment.

The database was in memory. Rosa has not demonstrated the complete writable
file path: opening a database in an explicitly permitted directory, positional
reads and writes, metadata, truncation, synchronization, advisory locks,
journals, WAL shared memory, atomic rename, and cleanup.

The query was also intentionally small. Wider SQL will reach more parser,
planner, collation, numeric, aggregate, sorter, temporary-storage, and error
paths. Multiple connections and threads will add synchronization and scheduling
contracts that this run did not need.

The next useful progression is therefore staged:

1. widen in-memory SQL with tables, inserts, predicates, aggregates, and
   transactions;
2. query an existing database read-only through an explicit guest mount;
3. create and modify a database in a scratch directory;
4. add safe single-process locking and journaling behavior; and
5. only then broaden toward WAL, concurrency, and arbitrary CLI workflows.

That ordering keeps SQLite engine coverage separate from filesystem emulation,
just as the init-file experiment separated SQLite from the home-directory/XPC
detour.

## The lesson was not “always take the shortcut”

The home-directory work was worthwhile. It strengthened Rosa's macOS process
model and allowed the default CLI path to succeed. The `-init` experiment was
worthwhile too, because it showed that the work could be scheduled rather than
accepted as an accidental dependency.

Compatibility projects contain many things that must eventually work. They do
not all need to sit on the same critical path.

The useful discipline is to ask, at each frontier:

- Is this behavior intrinsic to the application feature being tested?
- Is it broadly reusable runtime substrate?
- Can the guest observe a correct degraded result instead?
- Is there a supported application mode that isolates the next layer?
- Will finishing this path clarify the architecture, or merely delay the next
  meaningful milestone?

Rosa answered those questions both ways in the same afternoon. It completed
the reusable macOS substrate, then selected an in-memory database to postpone
filesystem breadth.

At 14:35, the next obstacle was a three-byte multiply instruction. At 15:30,
SQLite printed `1`.

The database fits in memory. The milestone does not.

---

For earlier context, see [Whack-a-Mole Through dyld](2026-08-30-whack-a-mole-through-dyld.md),
Rosa's [architecture](../architecture.md), [guest-memory model](../guest-memory.md),
and [Darwin boundary](../darwin-boundary.md).
