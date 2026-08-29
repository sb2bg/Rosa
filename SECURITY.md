# Security policy

## Project security model

Rosa is an experimental compatibility runtime and research tool. It is **not** a security sandbox, isolation boundary, malware-analysis environment, or replacement for macOS process security.

Rosa models a separate guest address space, permissions, registers, ports, syscalls, and Mach operations so translated programs cannot accidentally treat guest values as host pointers. Those design boundaries improve correctness and reduce unintended host exposure, but they have not been hardened or audited as a hostile-code containment system.

Do not run untrusted Mach-O files, dyld binaries, shared caches, or other guest inputs on a machine where host compromise would be unacceptable.

## In scope

Security reports are especially useful when they concern:

- a guest address being used directly as a host pointer;
- guest-controlled data reaching a host syscall or Mach API without semantic translation and validation;
- memory corruption in the decoder, IR pipeline, AArch64 emitter, executable-code allocator, Mach-O loader, or shared-cache parser;
- integer overflow or range-validation failure that permits an out-of-bounds host access;
- writable/executable memory being published before relocation or cache synchronization is complete;
- guest file paths escaping an intended locally provisioned artifact set;
- malformed input causing host resource leakage or uncontrolled resource growth;
- a discrepancy between documented guest isolation and actual host-visible behavior.

Correctly diagnosed unsupported instructions, syscalls, Mach traps, load commands, or cache formats are not security vulnerabilities by themselves.

## Reporting a vulnerability

Please report suspected vulnerabilities through this repository's **GitHub private vulnerability reporting** or a private GitHub security advisory. Include, when possible:

- the affected commit;
- the smallest input or operation sequence that demonstrates the issue;
- the host macOS and Apple Silicon versions;
- whether Rosetta 2 was installed;
- expected and observed guest/host behavior;
- crash output, Rosa diagnostics, and sanitizer findings;
- an assessment of whether the issue requires trusted or untrusted guest input.

Do not include Apple binaries, dyld shared-cache files, proprietary applications, secrets, or other data you are not permitted to redistribute. A script that constructs the malformed bytes or a structural description is preferred.

Please avoid filing a public issue until the report has been assessed when the problem could plausibly enable host memory corruption or boundary escape.

## Supported versions

Rosa is under active development and does not currently publish security-supported releases. Reports should be reproduced against the latest `main` commit when practical. Fixes may be developed on a dedicated branch and then merged into `main`.

## Disclosure and response

There is no guaranteed response or remediation timeline for this research project. Valid reports will be assessed according to reproducibility, impact on the host, and whether they cross a documented guest/host boundary.

A coordinated disclosure date should be agreed before publishing technical details of a host-impacting vulnerability.

## Apple artifacts

Rosa does not bundle Apple binaries. Security reproductions involving dyld or a shared cache must keep those artifacts local. Do not attach them to issues, advisories, commits, CI artifacts, or test fixtures.
