#pragma once

#include "arm64/Assembler.h"
#include "ir/IR.h"
#include "x86/Instruction.h"

#include <span>
#include <string>

namespace rosa::debug {

[[nodiscard]] std::string dumpX86(std::span<const x86::DecodedInstruction> instructions);
[[nodiscard]] std::string dumpIr(const ir::Block &block);
[[nodiscard]] std::string dumpArm64(const arm64::Program &program);

} // namespace rosa::debug
