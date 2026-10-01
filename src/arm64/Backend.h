#pragma once

#include "arm64/Assembler.h"
#include "ir/IR.h"

namespace rosa::arm64 {

// Host lowering consumes prepared IR; it does not decode x86 or dispatch syscalls.
[[nodiscard]] Program compile(const ir::Block &block, bool retainProgramListing);

} // namespace rosa::arm64
