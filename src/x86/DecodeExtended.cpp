#include "x86/DecodeInternal.h"

namespace rosa::x86::detail {

bool decodeExtended(DecodeContext &context) {
    auto &[code, address, cursor, instruction] = context;
    [[maybe_unused]] const auto remaining = code;
    [[maybe_unused]] constexpr std::size_t instructionStart = 0;
    if (code[cursor] == 0x0FU) {
        if (code.size() - cursor >= 3 &&
            code[cursor + 1] == 0x01U) {
            const auto modrm = code[cursor + 2];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U || extension != 0x1U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only based no-index SIDT memory operands are supported from opcode 0F 01 /1");
            }
            auto operandCursor = cursor + 3;
            auto baseEncoding = rmEncoding;
            if (rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated SIDT SIB byte");
                }
                const auto sib = code[operandCursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (scaleBits != 0 || indexEncoding != 0x4U ||
                    (mode == 0 && baseEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only based no-index SIDT SIB operands are supported");
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated SIDT disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated SIDT disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            const auto length = operandCursor - cursor;
            instruction.opcode = Opcode::SidtMem;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(cursor), length,
                instruction.bytes.begin());
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(baseEncoding, false), displacement, 80});
            return true;
        }
        if (code.size() - cursor >= 2 && code[cursor + 1] == 0xA3U) {
            if (code.size() - cursor < 3) {
                throw DecodeError(address, remaining,
                                  "truncated BT r32, r32");
            }
            const auto modrm = code[cursor + 2];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct BT r32, r32 is supported");
            }
            instruction.opcode = Opcode::BitTestRegReg;
            instruction.length = 3;
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                instruction.bytes.begin());
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U),
                               false),
                32});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(
                                   (modrm >> 3U) & 0x7U),
                               false),
                32});
            return true;
        }
        if (code.size() - cursor >= 2 && code[cursor + 1] == 0xBAU) {
            if (code.size() - cursor < 3) {
                throw DecodeError(address, remaining,
                                  "truncated BT r/m32, imm8");
            }
            const auto modrm = code[cursor + 2];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (extension != 0x4U ||
                (mode != 0x3U &&
                 (rmEncoding == 0x4U ||
                  (mode == 0 && rmEncoding == 0x5U)))) {
                throw DecodeError(
                    address, remaining,
                    "only BT r32 or dword [base+disp8/disp32], imm8 is supported from 0F BA");
            }
            auto operandCursor = cursor + 3;
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated BT dword disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated BT dword disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated BT r/m32 immediate");
            }
            const auto immediate = code[operandCursor++];
            instruction.opcode = mode == 0x3U ? Opcode::BitTestRegImm
                                               : Opcode::BitTestMemImm;
            instruction.length = static_cast<std::uint8_t>(
                operandCursor - cursor);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(cursor),
                instruction.length, instruction.bytes.begin());
            if (mode == 0x3U) {
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, false), 32});
            } else {
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, false), displacement, 32});
            }
            instruction.operands.push_back(
                ImmediateOperand{immediate, 8});
            return true;
        }
        if (code.size() - cursor >= 3 &&
            (code[cursor + 1] == 0x40U ||
             code[cursor + 1] == 0x42U ||
             code[cursor + 1] == 0x43U ||
             code[cursor + 1] == 0x44U ||
             code[cursor + 1] == 0x45U ||
             code[cursor + 1] == 0x46U ||
             code[cursor + 1] == 0x47U ||
             code[cursor + 1] == 0x48U ||
             code[cursor + 1] == 0x49U ||
             code[cursor + 1] == 0x4CU ||
             code[cursor + 1] == 0x4DU ||
             code[cursor + 1] == 0x4EU ||
             code[cursor + 1] == 0x4FU)) {
            const auto modrm = code[cursor + 2];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            instruction.condition = code[cursor + 1] == 0x42U
                                        ? Condition::Below
                                    : code[cursor + 1] == 0x43U
                                        ? Condition::AboveOrEqual
                                    : code[cursor + 1] == 0x44U
                                        ? Condition::Equal
                                    : code[cursor + 1] == 0x45U
                                        ? Condition::NotEqual
                                    : code[cursor + 1] == 0x46U
                                        ? Condition::BelowOrEqual
                                    : code[cursor + 1] == 0x47U
                                        ? Condition::Above
                                    : code[cursor + 1] == 0x48U
                                        ? Condition::Sign
                                    : code[cursor + 1] == 0x49U
                                        ? Condition::NotSign
                                    : code[cursor + 1] == 0x4CU
                                        ? Condition::Less
                                    : code[cursor + 1] == 0x4DU
                                        ? Condition::GreaterOrEqual
                                    : code[cursor + 1] == 0x40U
                                        ? Condition::Overflow
                                    : code[cursor + 1] == 0x4FU
                                        ? Condition::Greater
                                        : Condition::LessOrEqual;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(
                    static_cast<std::uint8_t>((modrm >> 3U) & 0x7U),
                    false),
                32});
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            auto operandCursor = cursor + 3;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::CmovccReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, false), 32});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U;
                auto base = decodeRegister(rmEncoding, false);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CMOV memory SIB");
                    }
                    const auto sib = code[operandCursor++];
                    const auto scaleBits = static_cast<std::uint8_t>(
                        (sib >> 6U) & 0x3U);
                    const auto indexEncoding = static_cast<std::uint8_t>(
                        (sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, false);
                    }
                    if (indexEncoding != 0x4U) {
                        index = decodeRegister(indexEncoding, false);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative || (!hasBase && mode == 0) ||
                    mode == 0x2U) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated CMOV memory disp32");
                    }
                    displacement =
                        readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                } else if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CMOV memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(
                        code[operandCursor++]);
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                }
                instruction.opcode = Opcode::CmovccRegMem;
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax : base, displacement, 32,
                    index, scale, hasBase, ripRelative});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
        if (code.size() - cursor >= 3 &&
            code[cursor + 1] == 0xAFU) {
            const auto modrm = code[cursor + 2];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U) {
                instruction.opcode = Opcode::ImulRegReg;
                instruction.length = 3;
                std::copy_n(
                    code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                    instruction.bytes.begin());
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(regEncoding, false), 32});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, false), 32});
                return true;
            }
            // Two-operand IMUL r32 from memory (observed in dyld under an
            // Objective-C fixture).
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            auto operandCursor = cursor + 3;
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated IMUL r32 memory SIB");
                }
                const auto sib = code[operandCursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base IMUL r32 memory SIB is not supported");
                }
                if (indexEncoding != 0x4U) {
                    index = decodeRegister(indexEncoding, false);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated IMUL r32 memory disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U || ripRelative) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated IMUL r32 memory disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, operandCursor - instructionStart,
                    displacement));
            }
            instruction.opcode = Opcode::ImulRegMem;
            instruction.operands.push_back(
                RegisterOperand{decodeRegister(regEncoding, false), 32});
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 32,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(baseEncoding, false),
                                    displacement, 32, index, scale});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
        if (code.size() - cursor < 6 ||
            (code[cursor + 1] != 0x80U && code[cursor + 1] != 0x81U &&
             code[cursor + 1] != 0x82U && code[cursor + 1] != 0x83U &&
             code[cursor + 1] != 0x84U &&
             code[cursor + 1] != 0x85U && code[cursor + 1] != 0x86U &&
             code[cursor + 1] != 0x87U && code[cursor + 1] != 0x88U &&
             code[cursor + 1] != 0x89U && code[cursor + 1] != 0x8AU &&
             code[cursor + 1] != 0x8BU &&
             code[cursor + 1] != 0x8CU &&
             code[cursor + 1] != 0x8DU &&
             code[cursor + 1] != 0x8EU &&
             code[cursor + 1] != 0x8FU)) {
            throw DecodeError(address, remaining,
                              "only JO/JNO/JB/JAE/JE/JNE/JBE/JA/JS/JNS/JP/JNP/JL/JGE/JLE/JG rel32 from opcode 0F is supported");
        }
        const auto secondOpcode = code[cursor + 1];
        const auto displacement = readI32(code.subspan(cursor + 2, 4));
        instruction.opcode = Opcode::JccRelative;
        instruction.condition = secondOpcode == 0x80U   ? Condition::Overflow
                                : secondOpcode == 0x81U ? Condition::NotOverflow
                                : secondOpcode == 0x82U ? Condition::Below
                                : secondOpcode == 0x83U ? Condition::AboveOrEqual
                                : secondOpcode == 0x84U ? Condition::Equal
                                : secondOpcode == 0x85U ? Condition::NotEqual
                                : secondOpcode == 0x86U ? Condition::BelowOrEqual
                                : secondOpcode == 0x87U ? Condition::Above
                                : secondOpcode == 0x88U ? Condition::Sign
                                : secondOpcode == 0x89U ? Condition::NotSign
                                : secondOpcode == 0x8AU ? Condition::ParityEven
                                : secondOpcode == 0x8BU ? Condition::ParityOdd
                                : secondOpcode == 0x8CU ? Condition::Less
                                : secondOpcode == 0x8DU ? Condition::GreaterOrEqual
                                : secondOpcode == 0x8EU ? Condition::LessOrEqual
                                                        : Condition::Greater;
        instruction.length = 6;
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 6,
                    instruction.bytes.begin());
        instruction.branchTarget = relativeTarget(address, 6, displacement);
        instruction.fallthrough = guest::GuestAddress{address.value + 6};
        return true;
    }

    if (code[cursor] == 0x66U) {
        auto operandCursor = cursor + 1;
        if (operandCursor >= code.size()) {
            throw DecodeError(address, remaining,
                              "truncated after operand-size override");
        }
        const bool hasOperandRex =
            code[operandCursor] >= 0x40U && code[operandCursor] <= 0x4FU;
        const auto operandRex =
            hasOperandRex ? code[operandCursor++] : std::uint8_t{0};
        if (operandCursor < code.size() &&
            (operandRex & 0x8U) == 0 &&
            code[operandCursor] >= 0xB8U &&
            code[operandCursor] <= 0xBFU) {
            const auto movOpcode = code[operandCursor++];
            if (code.size() - operandCursor < sizeof(std::uint16_t)) {
                throw DecodeError(address, remaining,
                                  "truncated mov r16, imm16");
            }
            const auto immediate = static_cast<std::uint64_t>(
                static_cast<std::uint16_t>(code[operandCursor]) |
                (static_cast<std::uint16_t>(code[operandCursor + 1])
                 << 8U));
            operandCursor += sizeof(std::uint16_t);
            instruction.opcode = Opcode::MovRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(
                    static_cast<std::uint8_t>(movOpcode - 0xB8U),
                    (operandRex & 0x1U) != 0),
                16});
            instruction.operands.push_back(
                ImmediateOperand{immediate, 16});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
    }

    return false;
}

} // namespace rosa::x86::detail
