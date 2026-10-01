"""basename: the BSD utility."""

from case import Case

BINARY = "/usr/bin/basename"

CASES = [
    Case("path", ["/usr/lib/libSystem.B.dylib"]),
    Case("suffix", ["/tmp/report.txt", ".txt"]),
    Case("suffix-whole-name", [".txt", ".txt"]),
    Case("suffix-mismatch", ["/tmp/report.txt", ".md"]),
    Case("trailing-slashes", ["/usr/lib///"]),
    Case("root", ["/"]),
    Case("slashes-only", ["///"]),
    Case("relative", ["a/b"]),
    Case("bare", ["name"]),
    Case("empty", [""]),
    Case("multiple", ["-a", "/a/b", "/c/d/", "e"]),
    Case("multiple-suffix", ["-s", ".c", "/src/x.c", "y.c", "z.h"]),
    Case("utf8", ["/tmp/café.txt"]),
    Case("no-arguments", []),
    Case("too-many", ["a", "b", "c"]),
]
