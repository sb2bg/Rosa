"""head: the BSD utility."""

from case import Case

BINARY = "/usr/bin/head"

CASES = [
    Case("default", ["big.txt"]),
    Case("lines", ["-n", "3", "words.txt"]),
    Case("lines-long-option", ["--lines=2", "words.txt"]),
    Case("lines-attached", ["-n3", "words.txt"]),
    Case("legacy-count", ["-4", "words.txt"]),
    Case("bytes", ["-c", "5", "words.txt"]),
    Case("bytes-long-option", ["--bytes=7", "words.txt"]),
    Case("more-than-file", ["-n", "1000", "in.txt"]),
    Case("zero-lines", ["-n", "0", "in.txt"]),
    Case("files", ["-n", "2", "in.txt", "words.txt"]),
    Case("stdin", ["-n", "2"], stdin="words.txt"),
    Case("pipe", ["-c", "4"], stdin=b"abcdefgh"),
    Case("empty", ["empty.txt"]),
    Case("no-trailing-newline", ["noeol.txt"]),
    Case("long-line", ["-c", "100", "long.txt"]),
    Case("binary", ["binary.bin"]),
    Case("missing", ["missing.txt"]),
    Case("missing-then-file", ["missing.txt", "in.txt"]),
    Case("directory", ["tree"]),
    Case("invalid-count", ["-n", "lots", "in.txt"]),
    Case("lines-and-bytes", ["-n", "1", "-c", "1", "in.txt"]),
]
