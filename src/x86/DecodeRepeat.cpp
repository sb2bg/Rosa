#include "x86/DecodeInternal.h"

namespace rosa::x86::detail {

bool decodeRepeat(DecodeContext &context) {
    auto &[code, address, cursor, instruction] = context;
    [[maybe_unused]] const auto remaining = code;
    [[maybe_unused]] constexpr std::size_t instructionStart = 0;
    if (code[cursor] == 0xF3U && code.size() - cursor >= 2 &&
        code[cursor + 1] == 0xA4U) {
        instruction.opcode = Opcode::RepMovsb;
        instruction.length = 2;
        instruction.bytes[0] = code[cursor];
        instruction.bytes[1] = code[cursor + 1];
        return true;
    }

    if (code[cursor] == 0xF3U && code.size() - cursor >= 2) {
        auto stosCursor = cursor + 1;
        const bool hasStosRex =
            stosCursor < code.size() && code[stosCursor] >= 0x40U &&
            code[stosCursor] <= 0x4FU;
        const auto stosRex = hasStosRex ? code[stosCursor++] : std::uint8_t{0};
        const bool isStos =
            code.size() - stosCursor >= 1 &&
            (code[stosCursor] == 0xAAU || code[stosCursor] == 0xABU);
        if (isStos) {
            if ((stosRex & 0x7U) != 0) {
                throw DecodeError(
                    address, remaining,
                    "only REX.W is supported for REP STOS");
            }
            const bool isByte = code[stosCursor] == 0xAAU;
            instruction.opcode = isByte                 ? Opcode::RepStosb
                                 : (stosRex & 0x8U) != 0 ? Opcode::RepStosq
                                                        : Opcode::RepStosd;
            const auto length = stosCursor + 1 - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() +
                            static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0xF3U && code.size() - cursor >= 5 &&
        code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU &&
        code[cursor + 2] == 0x0FU && code[cursor + 3] == 0x7FU) {
        const auto rex = code[cursor + 1];
        const bool rexW = (rex & 0x8U) != 0;
        const bool rexR = (rex & 0x4U) != 0;
        const bool rexX = (rex & 0x2U) != 0;
        const bool rexB = (rex & 0x1U) != 0;
        const auto modrm = code[cursor + 4];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (rexW || mode == 0x3U ||
            (rexX && rmEncoding != 0x4U) ||
            (mode == 0 && rmEncoding == 0x5U && !rexB)) {
            throw DecodeError(
                address, remaining,
                "only REX-extended MOVDQU [base+index*scale+disp8/disp32], xmm is supported");
        }
        auto operandCursor = cursor + 5;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (rmEncoding == 0x4U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated REX MOVDQU store SIB");
            }
            const auto sib = code[operandCursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "no-base REX MOVDQU store SIB is unsupported");
            }
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        }
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated REX MOVDQU store disp8");
            }
            displacement =
                std::bit_cast<std::int8_t>(code[operandCursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated REX MOVDQU store disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        instruction.opcode = Opcode::MovdquMemReg;
        instruction.operands.push_back(MemoryOperand{
            decodeRegister(baseEncoding, rexB), displacement, 128,
            index, scale});
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(static_cast<std::uint8_t>(
                ((modrm >> 3U) & 0x7U) | (rexR ? 8U : 0U)))});
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0xF3U && code.size() - cursor >= 3 &&
        code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x7FU) {
        if (code.size() - cursor < 4) {
            throw DecodeError(address, remaining, "truncated movdqu [base+disp], xmm");
        }
        const auto modrm = code[cursor + 3];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (mode > 0x2U) {
            throw DecodeError(
                address, remaining,
                "only MOVDQU [base/RIP+index*scale+disp8/disp32], xmm memory operands are supported");
        }
        const bool ripRelative =
            mode == 0 && rmEncoding == 0x5U;
        cursor += 4;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated MOVDQU SIB byte");
            }
            const auto sib = code[cursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding = static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(address, remaining,
                                  "no-base MOVDQU SIB addressing is not supported");
            }
            if (indexEncoding != 0x4U) {
                index = decodeRegister(indexEncoding, false);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        }
        std::int64_t displacement = 0;
        if (ripRelative) {
            if (code.size() - cursor < 4) {
                throw DecodeError(
                    address, remaining,
                    "truncated RIP-relative MOVDQU memory disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        } else if (mode == 0x1U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated MOVDQU memory disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[cursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated MOVDQU memory disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, cursor - instructionStart, displacement));
        }
        instruction.opcode = Opcode::MovdquMemReg;
        instruction.operands.push_back(MemoryOperand{
            decodeRegister(baseEncoding, false), displacement, 128,
            index, scale, !ripRelative, ripRelative});
        instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
            static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});

        const auto length = cursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart), length,
                    instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0xF3U && code.size() - cursor >= 2) {
        const auto afterPrefix = cursor + 1;
        const bool hasRex = code[afterPrefix] >= 0x40U &&
                            code[afterPrefix] <= 0x4FU;
        const auto opcodeOffset = afterPrefix + (hasRex ? 1U : 0U);
        if (code.size() - opcodeOffset >= 2 && code[opcodeOffset] == 0x0FU &&
            code[opcodeOffset + 1] == 0x6FU) {
            if (code.size() - opcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  "truncated movdqu xmm, [memory]");
            }
            const auto rex = hasRex ? code[afterPrefix] : 0U;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexX = (rex & 0x2U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            const auto modrm = code[opcodeOffset + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U;
            if (mode > 0x2U) {
                throw DecodeError(
                    address, remaining,
                    "only MOVDQU xmm, memory operands are supported");
            }
            auto operandCursor = opcodeOffset + 3;
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVDQU load SIB byte");
                }
                const auto sib = code[operandCursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(
                        address, remaining,
                        "no-base MOVDQU load SIB addressing is not supported");
                }
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative || mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVDQU load disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            } else if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVDQU load disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, operandCursor - instructionStart,
                    displacement));
            }
            instruction.opcode = Opcode::MovdquRegMem;
            instruction.operands.push_back(
                XmmRegisterOperand{static_cast<XmmRegister>(
                    static_cast<std::uint8_t>(((modrm >> 3U) & 0x7U) |
                                              (rexR ? 0x8U : 0U)))});
            instruction.operands.push_back(MemoryOperand{
                ripRelative ? Register::Rax
                            : decodeRegister(baseEncoding, rexB),
                displacement, 128, index, scale, !ripRelative,
                ripRelative});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
    }

    return false;
}

} // namespace rosa::x86::detail
