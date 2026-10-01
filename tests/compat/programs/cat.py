"""cat: the BSD utility."""

from case import Case

BINARY = "/bin/cat"

CASES = [
    Case("file", ["in.txt"]),
    Case("files", ["in.txt", "words.txt"]),
    Case("stdin", [], stdin="words.txt"),
    Case("stdin-dash", ["in.txt", "-", "in.txt"], stdin="words.txt"),
    Case("pipe", [], stdin=b"piped\nbytes"),
    Case("empty", ["empty.txt"]),
    Case("no-trailing-newline", ["noeol.txt"]),
    Case("binary", ["binary.bin"]),
    Case("large", ["big.txt"]),
    Case("long-line", ["long.txt"]),
    Case("number", ["-n", "words.txt"]),
    Case("number-nonblank", ["-b", "words.txt"]),
    Case("squeeze", ["-s", "blanks.txt"]),
    Case("visible", ["-v", "binary.bin"]),
    Case("visible-high", ["-v", "latin1.txt"]),
    Case("ends", ["-e", "crlf.txt"]),
    Case("tabs", ["-t", "tabs.txt"]),
    Case("unbuffered", ["-u", "in.txt"]),
    Case("lock-stdout", ["-l", "in.txt"]),
    Case("combined", ["-nbsvet", "words.txt", "binary.bin"]),
    Case("missing", ["missing.txt"]),
    Case("missing-then-file", ["missing.txt", "in.txt"]),
    Case("directory", ["tree"]),
    Case("unreadable", ["unreadable.txt"]),
    Case("bad-option", ["-z", "in.txt"]),
]
