#pragma once

#include "ir/IR.h"
#include "x86/Instruction.h"

#include <span>

namespace rosa::x86 {

// Portable instruction semantics. Produces unoptimized IR with an explicit exit.
[[nodiscard]] ir::Block lowerToIr(std::span<const DecodedInstruction> decoded);

} // namespace rosa::x86
