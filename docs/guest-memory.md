# Guest memory

Rosa currently exposes a 4 KiB guest-page contract through `guest::AddressSpace`, independent of the host's 16 KiB page size.

Implemented behavior is intentionally small:

- page-aligned anonymous mappings;
- complete Mach-O segment mappings with file bytes and zero-filled virtual tails;
- sparse no-access mappings such as the 4 GiB `__PAGEZERO`;
- overlap and integer-overflow rejection;
- explicit read/write/execute permission metadata;
- bounds-checked cross-mapping byte copies and little-endian 64-bit reads/writes;
- executable instruction views used by the decoder;
- no conversion from `GuestAddress` to a host pointer.

R2 uses a small read/write mapping as the x86 test stack. R3/R4 map a 1 MiB stack and populate Darwin-shaped `argc`, `argv`, `envp`, and `apple[]` vectors. `call` decrements guest `RSP` and writes a guest return RIP; `ret` reads that value and increments `RSP`.

`write(2)` copies its guest buffer through the mapping table before invoking the host API. No guest address becomes a host pointer.

Not implemented: 4 KiB subpage protection within a 16 KiB host page, `mmap`/`mprotect`/`munmap`, dirty tracking, identity-map experiments, generated load/store fast paths, or shared mappings.
