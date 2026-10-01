#include "x86/DecodeInternal.h"

namespace rosa::x86::detail {

bool decodeControlTransfer(DecodeContext &context) {
    auto &[code, address, cursor, instruction] = context;
    [[maybe_unused]] const auto remaining = code;
    [[maybe_unused]] constexpr std::size_t instructionStart = 0;
    if (code[cursor] == 0xE8U || code[cursor] == 0xE9U) {
        if (code.size() - cursor < 5) {
            throw DecodeError(address, remaining, "truncated rel32 control transfer");
        }
        const auto opcode = code[cursor];
        const auto displacement = readI32(code.subspan(cursor + 1, 4));
        instruction.opcode = opcode == 0xE8U ? Opcode::CallRelative : Opcode::JmpRelative;
        instruction.length = 5;
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 5,
                    instruction.bytes.begin());
        instruction.branchTarget = relativeTarget(address, 5, displacement);
        instruction.fallthrough = guest::GuestAddress{address.value + 5};
        return true;
    }

    const bool hasBranchHint =
        code[cursor] == 0x2EU && code.size() - cursor >= 2 &&
        code[cursor + 1] >= 0x70U && code[cursor + 1] <= 0x7FU;
    const auto controlOffset = cursor + (hasBranchHint ? 1U : 0U);
    if (code[controlOffset] == 0xEBU || code[controlOffset] == 0x70U ||
        code[controlOffset] == 0x71U || code[controlOffset] == 0x72U ||
        code[controlOffset] == 0x73U || code[controlOffset] == 0x74U ||
        code[controlOffset] == 0x75U || code[controlOffset] == 0x76U ||
        code[controlOffset] == 0x77U || code[controlOffset] == 0x78U ||
        code[controlOffset] == 0x79U || code[controlOffset] == 0x7AU ||
        code[controlOffset] == 0x7BU || code[controlOffset] == 0x7CU ||
        code[controlOffset] == 0x7DU || code[controlOffset] == 0x7EU ||
        code[controlOffset] == 0x7FU) {
        if (code.size() - controlOffset < 2) {
            throw DecodeError(address, remaining, "truncated rel8 control transfer");
        }
        const auto opcode = code[controlOffset];
        const auto displacement =
            std::bit_cast<std::int8_t>(code[controlOffset + 1]);
        const auto length = static_cast<std::uint8_t>(
            2U + (hasBranchHint ? 1U : 0U));
        instruction.opcode = opcode == 0xEBU ? Opcode::JmpRelative : Opcode::JccRelative;
        instruction.length = length;
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(cursor), length,
            instruction.bytes.begin());
        instruction.branchTarget =
            relativeTarget(address, length, displacement);
        instruction.fallthrough =
            guest::GuestAddress{address.value + length};
        if (opcode != 0xEBU) {
            instruction.condition = opcode == 0x70U   ? Condition::Overflow
                                    : opcode == 0x71U ? Condition::NotOverflow
                                    : opcode == 0x72U ? Condition::Below
                                    : opcode == 0x73U ? Condition::AboveOrEqual
                                    : opcode == 0x74U ? Condition::Equal
                                    : opcode == 0x75U ? Condition::NotEqual
                                    : opcode == 0x76U ? Condition::BelowOrEqual
                                    : opcode == 0x78U ? Condition::Sign
                                    : opcode == 0x79U ? Condition::NotSign
                                    : opcode == 0x7AU ? Condition::ParityEven
                                    : opcode == 0x7BU ? Condition::ParityOdd
                                    : opcode == 0x7CU ? Condition::Less
                                    : opcode == 0x7DU ? Condition::GreaterOrEqual
                                    : opcode == 0x7EU ? Condition::LessOrEqual
                                    : opcode == 0x7FU ? Condition::Greater
                                                      : Condition::Above;
        }
        return true;
    }

    return false;
}

} // namespace rosa::x86::detail
