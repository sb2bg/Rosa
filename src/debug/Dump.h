#pragma once

#include "arm64/Assembler.h"
#include "dbt/Dispatcher.h"
#include "guest/AddressSpace.h"
#include "ir/IR.h"
#include "x86/Instruction.h"

#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace rosa::debug {

[[nodiscard]] std::string dumpX86(std::span<const x86::DecodedInstruction> instructions);
[[nodiscard]] std::string dumpIr(const ir::Block &block);
[[nodiscard]] std::string dumpArm64(const arm64::Program &program);
[[nodiscard]] std::string dumpGuestFailure(std::string_view imageHint,
                                           const std::exception &error,
                                           const x86::X86State &state,
                                           const guest::AddressSpace &addressSpace,
                                           const dbt::Dispatcher &dispatcher);

} // namespace rosa::debug
