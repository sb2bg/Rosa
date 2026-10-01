#include "x86/DecodeInternal.h"

namespace rosa::x86::detail {

bool decodeSimdMemory(DecodeContext &context) {
    auto &[code, address, cursor, instruction] = context;
    [[maybe_unused]] const auto remaining = code;
    [[maybe_unused]] constexpr std::size_t instructionStart = 0;
    if (code[cursor] == 0xF2U && code.size() - cursor >= 4) {
        auto movsdCursor = cursor + 1;
        std::uint8_t movsdRex = 0;
        if (code[movsdCursor] >= 0x40U && code[movsdCursor] <= 0x4FU &&
            code.size() - movsdCursor >= 4) {
            movsdRex = code[movsdCursor++];
        }
        if (code.size() - movsdCursor >= 3 && code[movsdCursor] == 0x0FU &&
            (code[movsdCursor + 1] == 0x10U || code[movsdCursor + 1] == 0x11U)) {
            const bool movsdLoad = code[movsdCursor + 1] == 0x10U;
            const auto modrm = code[movsdCursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto xmmEncoding = static_cast<std::uint8_t>(
                ((modrm >> 3U) & 0x7U) | ((movsdRex & 0x4U) != 0 ? 8U : 0U));
            if (mode == 0x3U) {
                throw DecodeError(address, remaining,
                                  "register-direct MOVSD is not supported");
            }
            auto operandCursor = movsdCursor + 3;
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVSD memory SIB");
                }
                const auto sib = code[operandCursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base MOVSD memory SIB is not supported");
                }
                if (indexEncoding != 0x4U || (movsdRex & 0x2U) != 0) {
                    index = decodeRegister(indexEncoding, (movsdRex & 0x2U) != 0);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (!ripRelative && ((movsdRex & 0x2U) != 0)) {
                throw DecodeError(address, remaining,
                                  "REX.X requires a MOVSD memory SIB");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVSD memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U || ripRelative) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVSD memory disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            const auto xmm =
                XmmRegisterOperand{static_cast<XmmRegister>(xmmEncoding)};
            const auto memory = ripRelative
                                    ? MemoryOperand{Register::Rax, displacement, 64,
                                                    std::nullopt, 1, false, true}
                                    : MemoryOperand{
                                          decodeRegister(baseEncoding,
                                                         (movsdRex & 0x1U) != 0),
                                          displacement, 64, index, scale};
            instruction.opcode =
                movsdLoad ? Opcode::MovsdRegMem : Opcode::MovsdMemXmm;
            if (movsdLoad) {
                instruction.operands.push_back(xmm);
                instruction.operands.push_back(memory);
            } else {
                instruction.operands.push_back(memory);
                instruction.operands.push_back(xmm);
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
    }

    if ((code[cursor] == 0x0FU && code.size() - cursor >= 3 &&
         (code[cursor + 1] == 0x12U || code[cursor + 1] == 0x13U)) ||
        (code.size() - cursor >= 4 && code[cursor] >= 0x40U && code[cursor] <= 0x4FU &&
         code[cursor + 1] == 0x0FU &&
         (code[cursor + 2] == 0x12U || code[cursor + 2] == 0x13U))) {
        const bool movlpsHasRex = code[cursor] != 0x0FU;
        const auto movlpsRex = movlpsHasRex ? code[cursor] : std::uint8_t{0};
        const auto movlpsOpcodeOffset = cursor + (movlpsHasRex ? 2U : 1U);
        const bool movlpsLoad = code[movlpsOpcodeOffset] == 0x12U;
        const auto modrm = code[movlpsOpcodeOffset + 1];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        const auto xmmEncoding = static_cast<std::uint8_t>(
            ((modrm >> 3U) & 0x7U) | ((movlpsRex & 0x4U) != 0 ? 8U : 0U));
        if (mode == 0x3U) {
            throw DecodeError(address, remaining,
                              "register-direct MOVLPS is not supported");
        }
        auto operandCursor = movlpsOpcodeOffset + 2;
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOVLPS memory SIB");
            }
            const auto sib = code[operandCursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(address, remaining,
                                  "no-base MOVLPS memory SIB is not supported");
            }
            if (indexEncoding != 0x4U || (movlpsRex & 0x2U) != 0) {
                index = decodeRegister(indexEncoding, (movlpsRex & 0x2U) != 0);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        } else if (!ripRelative && ((movlpsRex & 0x2U) != 0)) {
            throw DecodeError(address, remaining,
                              "REX.X requires a MOVLPS memory SIB");
        }
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOVLPS memory disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[operandCursor++]);
        } else if (mode == 0x2U || ripRelative) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOVLPS memory disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        const auto xmm =
            XmmRegisterOperand{static_cast<XmmRegister>(xmmEncoding)};
        const auto memory = ripRelative
                                ? MemoryOperand{Register::Rax, displacement, 64,
                                                std::nullopt, 1, false, true}
                                : MemoryOperand{
                                      decodeRegister(baseEncoding,
                                                     (movlpsRex & 0x1U) != 0),
                                      displacement, 64, index, scale};
        instruction.opcode =
            movlpsLoad ? Opcode::MovlpsRegMem : Opcode::MovlpsMemXmm;
        if (movlpsLoad) {
            instruction.operands.push_back(xmm);
            instruction.operands.push_back(memory);
        } else {
            instruction.operands.push_back(memory);
            instruction.operands.push_back(xmm);
        }
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0xF2U && code.size() - cursor >= 4) {
        auto cvttCursor = cursor + 1;
        std::uint8_t cvttRex = 0;
        if (code[cvttCursor] >= 0x40U && code[cvttCursor] <= 0x4FU &&
            code.size() - cvttCursor >= 4) {
            cvttRex = code[cvttCursor++];
        }
        if (code.size() - cvttCursor >= 3 && code[cvttCursor] == 0x0FU &&
            code[cvttCursor + 1] == 0x2CU) {
            const auto modrm = code[cvttCursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto destination = decodeRegister(regEncoding, (cvttRex & 0x4U) != 0);
            const auto width =
                static_cast<std::uint8_t>((cvttRex & 0x8U) != 0 ? 64U : 32U);
            auto operandCursor = cvttCursor + 3;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::Cvttsd2siRegXmm;
                instruction.operands.push_back(RegisterOperand{destination, width});
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        rmEncoding | ((cvttRex & 0x1U) != 0 ? 8U : 0U)))});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && (cvttRex & 0x1U) == 0;
                if (rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U && (cvttRex & 0x1U) != 0)) {
                    throw DecodeError(
                        address, remaining,
                        "only RIP-relative or based CVTTSD2SI r32/r64, m64 is supported");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CVTTSD2SI m64 disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U || ripRelative) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated CVTTSD2SI m64 disp32");
                    }
                    displacement = readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                }
                instruction.opcode = Opcode::Cvttsd2siRegMem;
                instruction.operands.push_back(RegisterOperand{destination, width});
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 64,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{decodeRegister(rmEncoding,
                                                       (cvttRex & 0x1U) != 0),
                                        displacement, 64});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0xF2U && code.size() - cursor >= 4) {
        auto cvtCursor = cursor + 1;
        std::uint8_t cvtRex = 0;
        if (code[cvtCursor] >= 0x40U && code[cvtCursor] <= 0x4FU &&
            code.size() - cvtCursor >= 4) {
            cvtRex = code[cvtCursor++];
        }
        if (code.size() - cvtCursor >= 3 && code[cvtCursor] == 0x0FU &&
            code[cvtCursor + 1] == 0x2AU) {
            const auto modrm = code[cvtCursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto destination = XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>(regEncoding |
                                          ((cvtRex & 0x4U) != 0 ? 8U : 0U)))};
            const auto intWidth =
                static_cast<std::uint8_t>((cvtRex & 0x8U) != 0 ? 64U : 32U);
            auto operandCursor = cvtCursor + 3;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::Cvtsi2sdXmmReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, (cvtRex & 0x1U) != 0), intWidth});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && (cvtRex & 0x1U) == 0;
                if (rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U && (cvtRex & 0x1U) != 0)) {
                    throw DecodeError(
                        address, remaining,
                        "only RIP-relative or based CVTSI2SD xmm, r/m32/r/m64 is supported");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CVTSI2SD disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U || ripRelative) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated CVTSI2SD disp32");
                    }
                    displacement = readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                }
                instruction.opcode = Opcode::Cvtsi2sdXmmMem;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, intWidth,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{
                              decodeRegister(rmEncoding, (cvtRex & 0x1U) != 0),
                              displacement, intWidth});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0xF2U && code.size() - cursor >= 4) {
        auto cvtfCursor = cursor + 1;
        std::uint8_t cvtfRex = 0;
        if (code[cvtfCursor] >= 0x40U && code[cvtfCursor] <= 0x4FU &&
            code.size() - cvtfCursor >= 4) {
            cvtfRex = code[cvtfCursor++];
        }
        if (code.size() - cvtfCursor >= 3 && code[cvtfCursor] == 0x0FU &&
            code[cvtfCursor + 1] == 0x5AU) {
            const auto modrm = code[cvtfCursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto destination = XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>(regEncoding |
                                          ((cvtfRex & 0x4U) != 0 ? 8U : 0U)))};
            auto operandCursor = cvtfCursor + 3;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::Cvtss2sdXmmReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        rmEncoding | ((cvtfRex & 0x1U) != 0 ? 8U : 0U)))});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && (cvtfRex & 0x1U) == 0;
                auto baseEncoding = rmEncoding;
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CVTSS2SD SIB");
                    }
                    const auto sib = code[operandCursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(address, remaining,
                                          "no-base CVTSS2SD SIB is not supported");
                    }
                    if (indexEncoding != 0x4U || (cvtfRex & 0x2U) != 0) {
                        index = decodeRegister(indexEncoding,
                                               (cvtfRex & 0x2U) != 0);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                } else if (!ripRelative && ((cvtfRex & 0x2U) != 0)) {
                    throw DecodeError(address, remaining,
                                      "REX.X requires a CVTSS2SD SIB");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CVTSS2SD disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U || ripRelative) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated CVTSS2SD disp32");
                    }
                    displacement = readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                }
                instruction.opcode = Opcode::Cvtss2sdXmmMem;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 32,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{
                              decodeRegister(baseEncoding,
                                             (cvtfRex & 0x1U) != 0),
                              displacement, 32, index, scale});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0xF2U && code.size() - cursor >= 4) {
        auto scalarCursor = cursor + 1;
        std::uint8_t scalarRex = 0;
        if (code[scalarCursor] >= 0x40U && code[scalarCursor] <= 0x4FU &&
            code.size() - scalarCursor >= 4) {
            scalarRex = code[scalarCursor++];
        }
        if (code.size() - scalarCursor >= 3 && code[scalarCursor] == 0x0FU &&
            (code[scalarCursor + 1] == 0x51U || code[scalarCursor + 1] == 0x58U ||
             code[scalarCursor + 1] == 0x59U || code[scalarCursor + 1] == 0x5CU ||
             code[scalarCursor + 1] == 0x5DU || code[scalarCursor + 1] == 0x5EU ||
             code[scalarCursor + 1] == 0x5FU)) {
            const auto scalarOpcode = code[scalarCursor + 1];
            const auto modrm = code[scalarCursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto destination = XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>(regEncoding |
                                          ((scalarRex & 0x4U) != 0 ? 8U : 0U)))};
            auto operandCursor = scalarCursor + 3;
            if (mode == 0x3U) {
                instruction.opcode = scalarOpcode == 0x51U   ? Opcode::SqrtsdXmmReg
                                     : scalarOpcode == 0x58U ? Opcode::AddsdXmmReg
                                     : scalarOpcode == 0x59U ? Opcode::MulsdXmmReg
                                     : scalarOpcode == 0x5CU ? Opcode::SubsdXmmReg
                                     : scalarOpcode == 0x5DU ? Opcode::MinsdXmmReg
                                     : scalarOpcode == 0x5FU ? Opcode::MaxsdXmmReg
                                                             : Opcode::DivsdXmmReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        rmEncoding | ((scalarRex & 0x1U) != 0 ? 8U : 0U)))});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && (scalarRex & 0x1U) == 0;
                if (rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U && (scalarRex & 0x1U) != 0)) {
                    throw DecodeError(
                        address, remaining,
                        "only RIP-relative or based scalar-double xmm, m64 is supported");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated scalar-double disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U || ripRelative) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated scalar-double disp32");
                    }
                    displacement = readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                }
                instruction.opcode = scalarOpcode == 0x51U   ? Opcode::SqrtsdXmmMem
                                     : scalarOpcode == 0x58U ? Opcode::AddsdXmmMem
                                     : scalarOpcode == 0x59U ? Opcode::MulsdXmmMem
                                     : scalarOpcode == 0x5CU ? Opcode::SubsdXmmMem
                                     : scalarOpcode == 0x5DU ? Opcode::MinsdXmmMem
                                     : scalarOpcode == 0x5FU ? Opcode::MaxsdXmmMem
                                                             : Opcode::DivsdXmmMem;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 64,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{
                              decodeRegister(rmEncoding,
                                             (scalarRex & 0x1U) != 0),
                              displacement, 64});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
    }

    if ((code[cursor] == 0xF2U && code.size() - cursor >= 4 &&
         code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x12U) ||
        (code.size() - cursor >= 5 && code[cursor] == 0xF2U &&
         code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU &&
         code[cursor + 2] == 0x0FU && code[cursor + 3] == 0x12U)) {
        const bool hasMovddupRex = code[cursor + 1] != 0x0FU;
        const auto rex = hasMovddupRex ? code[cursor + 1] : 0U;
        const auto rexR = (rex & 0x4U) != 0;
        const auto rexB = (rex & 0x1U) != 0;
        if ((rex & 0xAU) != 0) {
            throw DecodeError(address, remaining,
                              "MOVDDUP does not support REX.W/X");
        }
        const auto opcodeOffset = cursor + (hasMovddupRex ? 2U : 1U);
        const auto modrm = code[opcodeOffset + 2];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        const auto destination = XmmRegisterOperand{static_cast<XmmRegister>(
            static_cast<std::uint8_t>(((modrm >> 3U) & 0x7U) |
                                      (rexR ? 8U : 0U)))};
        auto operandCursor = opcodeOffset + 3;
        if (mode == 0x3U) {
            instruction.opcode = Opcode::MovddupRegReg;
            instruction.operands.push_back(destination);
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    rmEncoding | (rexB ? 8U : 0U)))});
        } else {
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
            if (rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U && rexB)) {
                throw DecodeError(address, remaining,
                                  "only RIP-relative or based MOVDDUP xmm, m64 is supported");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVDDUP m64 disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U || ripRelative) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVDDUP m64 disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, operandCursor - instructionStart,
                    displacement));
            }
            instruction.opcode = Opcode::MovddupRegMem;
            instruction.operands.push_back(destination);
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 64,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(rmEncoding, rexB),
                                    displacement, 64});
        }
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    if ((code[cursor] == 0xF3U && code.size() - cursor >= 4 &&
         code[cursor + 1] == 0x0FU && code[cursor + 2] == 0xE6U) ||
        (code.size() - cursor >= 5 && code[cursor] == 0xF3U &&
         code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU &&
         code[cursor + 2] == 0x0FU && code[cursor + 3] == 0xE6U)) {
        const bool hasCvtdq2pdRex = code[cursor + 1] != 0x0FU;
        const auto rex = hasCvtdq2pdRex ? code[cursor + 1] : 0U;
        const auto rexR = (rex & 0x4U) != 0;
        const auto rexX = (rex & 0x2U) != 0;
        const auto rexB = (rex & 0x1U) != 0;
        const auto opcodeOffset = cursor + (hasCvtdq2pdRex ? 2U : 1U);
        const auto modrm = code[opcodeOffset + 2];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        const auto destination = XmmRegisterOperand{static_cast<XmmRegister>(
            static_cast<std::uint8_t>(((modrm >> 3U) & 0x7U) |
                                      (rexR ? 8U : 0U)))};
        auto operandCursor = opcodeOffset + 3;
        if (mode == 0x3U) {
            instruction.opcode = Opcode::Cvtdq2pdXmmReg;
            instruction.operands.push_back(destination);
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    rmEncoding | (rexB ? 8U : 0U)))});
        } else {
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
            if (mode == 0 && rmEncoding == 0x5U && rexB) {
                throw DecodeError(address, remaining,
                                  "R13-based CVTDQ2PD is not supported");
            }
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated CVTDQ2PD SIB byte");
                }
                const auto sib = code[operandCursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base CVTDQ2PD SIB is not supported");
                }
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (!ripRelative && rexX) {
                throw DecodeError(address, remaining,
                                  "REX.X requires a CVTDQ2PD SIB");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated CVTDQ2PD disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U || ripRelative) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated CVTDQ2PD disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, operandCursor - instructionStart,
                    displacement));
            }
            instruction.opcode = Opcode::Cvtdq2pdXmmMem;
            instruction.operands.push_back(destination);
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 64,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                    displacement, 64, index, scale});
        }
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    if ((code[cursor] == 0xF3U && code.size() - cursor >= 4 &&
         code[cursor + 1] == 0x0FU &&
         (code[cursor + 2] == 0x10U || code[cursor + 2] == 0x11U)) ||
        (code.size() - cursor >= 5 && code[cursor] == 0xF3U &&
         code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU &&
         code[cursor + 2] == 0x0FU &&
         (code[cursor + 3] == 0x10U || code[cursor + 3] == 0x11U))) {
        const bool hasMovssRex = code[cursor + 1] != 0x0FU;
        const auto rex = hasMovssRex ? code[cursor + 1] : 0U;
        const auto rexR = (rex & 0x4U) != 0;
        const auto rexX = (rex & 0x2U) != 0;
        const auto rexB = (rex & 0x1U) != 0;
        const auto opcodeOffset = cursor + (hasMovssRex ? 2U : 1U);
        const bool isLoad = code[opcodeOffset + 1] == 0x10U;
        const auto modrm = code[opcodeOffset + 2];
        const auto mode =
            static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        const auto xmm = XmmRegisterOperand{static_cast<XmmRegister>(
            static_cast<std::uint8_t>(((modrm >> 3U) & 0x7U) |
                                      (rexR ? 8U : 0U)))};
        if (mode == 0x3U) {
            throw DecodeError(
                address, remaining,
                "register-direct MOVSS is not supported");
        }
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
        if (mode == 0 && rmEncoding == 0x5U && rexB) {
            throw DecodeError(address, remaining,
                              "R13-based MOVSS is not supported");
        }
        auto operandCursor = opcodeOffset + 3;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOVSS SIB byte");
            }
            const auto sib = code[operandCursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(address, remaining,
                                  "no-base MOVSS SIB is not supported");
            }
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        } else if (!ripRelative && rexX) {
            throw DecodeError(address, remaining,
                              "REX.X requires a MOVSS SIB");
        }
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOVSS disp8");
            }
            displacement =
                std::bit_cast<std::int8_t>(code[operandCursor++]);
        } else if (mode == 0x2U || ripRelative) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOVSS disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, operandCursor - instructionStart, displacement));
        }
        const auto memory = ripRelative
                                ? MemoryOperand{Register::Rax, displacement, 32,
                                                std::nullopt, 1, false, true}
                                : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                                displacement, 32, index, scale};
        instruction.opcode =
            isLoad ? Opcode::MovssRegMem : Opcode::MovssMemXmm;
        if (isLoad) {
            instruction.operands.push_back(xmm);
            instruction.operands.push_back(memory);
        } else {
            instruction.operands.push_back(memory);
            instruction.operands.push_back(xmm);
        }
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
    }

    const bool movqLoadHasRex =
        code.size() - cursor >= 4 && code[cursor] == 0xF3U &&
        code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU &&
        code[cursor + 2] == 0x0FU && code[cursor + 3] == 0x7EU;
    const bool movqLoadWithoutRex =
        code.size() - cursor >= 3 && code[cursor] == 0xF3U &&
        code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x7EU;
    if (movqLoadHasRex || movqLoadWithoutRex) {
        const auto rex = movqLoadHasRex ? code[cursor + 1] : 0U;
        const auto modrmOffset = cursor + (movqLoadHasRex ? 4U : 3U);
        if (modrmOffset >= code.size()) {
            throw DecodeError(address, remaining,
                              "truncated MOVQ xmm, [memory]");
        }
        const auto modrm = code[modrmOffset];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (mode > 0x2U) {
            throw DecodeError(
                address, remaining,
                "only memory-source MOVQ xmm, qword [memory] is supported");
        }
        auto operandCursor = modrmOffset + 1;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        bool hasBase = true;
        bool ripRelative = mode == 0 && rmEncoding == 0x5U;
        if (rmEncoding == 0x4U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOVQ load SIB");
            }
            const auto sib = code[operandCursor++];
            scale = static_cast<std::uint8_t>(1U << (sib >> 6U));
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
            if (indexEncoding != 0x4U) {
                index = decodeRegister(indexEncoding,
                                       (rex & 0x2U) != 0);
            }
            hasBase = !(mode == 0 && baseEncoding == 0x5U);
            ripRelative = false;
        }
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOVQ load disp8");
            }
            displacement =
                std::bit_cast<std::int8_t>(code[operandCursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOVQ load disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        } else if (ripRelative || !hasBase) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOVQ load disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        instruction.opcode = Opcode::MovqXmmMem;
        instruction.operands.push_back(
            XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>(((modrm >> 3U) & 0x7U) |
                                          ((rex & 0x4U) != 0 ? 8U
                                                             : 0U)))});
        instruction.operands.push_back(MemoryOperand{
            hasBase && !ripRelative
                ? decodeRegister(baseEncoding, (rex & 0x1U) != 0)
                : Register::Rax,
            displacement, 64, index, scale, hasBase, ripRelative});
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
        code[cursor + 1] == 0x0FU && code[cursor + 2] == 0xD7U) {
        if (code.size() - cursor < 4) {
            throw DecodeError(address, remaining, "truncated pmovmskb r32, xmm");
        }
        const auto modrm = code[cursor + 3];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        if (mode != 0x3U) {
            throw DecodeError(address, remaining,
                              "only register-direct PMOVMSKB is supported");
        }
        instruction.opcode = Opcode::PmovmskbRegXmm;
        instruction.length = 4;
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 4,
                    instruction.bytes.begin());
        instruction.operands.push_back(RegisterOperand{
            decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), false), 32});
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(static_cast<std::uint8_t>(modrm & 0x7U))});
        return true;
    }

    const bool movapdStore = code[cursor] == 0x66U;
    const auto movapsStorePrefixEnd = cursor + (movapdStore ? 1U : 0U);
    const bool movapsStoreHasRex =
        movapsStorePrefixEnd < code.size() &&
        code[movapsStorePrefixEnd] >= 0x40U &&
        code[movapsStorePrefixEnd] <= 0x4FU;
    const auto movapsStoreOpcodeOffset =
        movapsStorePrefixEnd + (movapsStoreHasRex ? 1U : 0U);
    if (code.size() - movapsStoreOpcodeOffset >= 2 &&
        code[movapsStoreOpcodeOffset] == 0x0FU &&
        code[movapsStoreOpcodeOffset + 1] == 0x29U) {
        if (code.size() - movapsStoreOpcodeOffset < 3) {
            throw DecodeError(address, remaining, "truncated movaps [base+disp], xmm");
        }
        const auto rex =
            movapsStoreHasRex ? code[movapsStorePrefixEnd] : 0U;
        const bool rexR = (rex & 0x4U) != 0;
        const bool rexX = (rex & 0x2U) != 0;
        const bool rexB = (rex & 0x1U) != 0;
        const auto modrm = code[movapsStoreOpcodeOffset + 2];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
        if (mode > 0x2U) {
            throw DecodeError(
                address, remaining,
                "only MOVAPD/MOVAPS [base+index*scale/RIP+disp], xmm memory operands are supported");
        }
        cursor = movapsStoreOpcodeOffset + 3;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated aligned XMM store SIB byte");
            }
            const auto sib = code[cursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "no-base aligned XMM store SIB is not supported");
            }
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        }
        std::int64_t displacement = 0;
        if (ripRelative) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated RIP-relative MOVAPS disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        } else if (mode == 0x1U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated MOVAPS memory disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[cursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated MOVAPS memory disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, cursor - instructionStart, displacement));
        }
        instruction.opcode = movapdStore ? Opcode::MovapdMemReg
                                         : Opcode::MovapsMemReg;
        instruction.operands.push_back(
            ripRelative
                ? MemoryOperand{Register::Rax, displacement, 128,
                                std::nullopt, 1, false, true}
                : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                displacement, 128, index, scale});
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(
                static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) |
                    (rexR ? 0x8U : 0U)))});

        const auto length = cursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart), length,
                    instruction.bytes.begin());
        return true;
    }

    const bool movupdStore = code[cursor] == 0x66U;
    const auto movupsStorePrefixEnd = cursor + (movupdStore ? 1U : 0U);
    const bool movupsStoreHasRex =
        movupsStorePrefixEnd < code.size() &&
        code[movupsStorePrefixEnd] >= 0x40U &&
        code[movupsStorePrefixEnd] <= 0x4FU;
    const auto movupsStoreOpcodeOffset =
        movupsStorePrefixEnd + (movupsStoreHasRex ? 1U : 0U);
    if (code.size() - movupsStoreOpcodeOffset >= 2 &&
        code[movupsStoreOpcodeOffset] == 0x0FU &&
        code[movupsStoreOpcodeOffset + 1] == 0x11U) {
        if (code.size() - movupsStoreOpcodeOffset < 3) {
            throw DecodeError(address, remaining, "truncated movups [base+disp], xmm");
        }
        const auto rex = movupsStoreHasRex ? code[movupsStorePrefixEnd] : 0U;
        const bool rexR = (rex & 0x4U) != 0;
        const bool rexX = (rex & 0x2U) != 0;
        const bool rexB = (rex & 0x1U) != 0;
        const auto modrm = code[movupsStoreOpcodeOffset + 2];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (mode > 0x2U) {
            throw DecodeError(
                address, remaining,
                "only MOVUPS [base+disp8/disp32], xmm memory operands are supported");
        }
        cursor = movupsStoreOpcodeOffset + 3;
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated MOVUPS SIB byte");
            }
            const auto sib = code[cursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding = static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(address, remaining,
                                  "no-base MOVUPS SIB addressing is not supported");
            }
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        }
        std::int64_t displacement = 0;
        if (ripRelative) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated RIP-relative MOVUPS disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        } else if (mode == 0x1U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated MOVUPS memory disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[cursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated MOVUPS memory disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, cursor - instructionStart, displacement));
        }
        instruction.opcode = Opcode::MovupsMemReg;
        instruction.operands.push_back(
            ripRelative
                ? MemoryOperand{Register::Rax, displacement, 128,
                                std::nullopt, 1, false, true}
                : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                displacement, 128, index, scale});
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(
                static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) |
                    (rexR ? 0x8U : 0U)))});

        const auto length = cursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart), length,
                    instruction.bytes.begin());
        return true;
    }

    const bool movapdLoad = code[cursor] == 0x66U;
    const auto movupsLoadPrefixEnd = cursor + (movapdLoad ? 1U : 0U);
    const bool movupsLoadHasRex =
        movupsLoadPrefixEnd < code.size() &&
        code[movupsLoadPrefixEnd] >= 0x40U &&
        code[movupsLoadPrefixEnd] <= 0x4FU;
    const auto movupsLoadOpcodeOffset =
        movupsLoadPrefixEnd + (movupsLoadHasRex ? 1U : 0U);
    if (code.size() - movupsLoadOpcodeOffset >= 2 &&
        code[movupsLoadOpcodeOffset] == 0x0FU &&
        ((!movapdLoad &&
          (code[movupsLoadOpcodeOffset + 1] == 0x10U ||
           code[movupsLoadOpcodeOffset + 1] == 0x28U)) ||
         (movapdLoad &&
          // 66 0F 10 is MOVUPD, which loads exactly like MOVUPS.
          (code[movupsLoadOpcodeOffset + 1] == 0x28U ||
           code[movupsLoadOpcodeOffset + 1] == 0x10U)))) {
        const bool aligned = code[movupsLoadOpcodeOffset + 1] == 0x28U;
        if (code.size() - movupsLoadOpcodeOffset < 3) {
            throw DecodeError(address, remaining,
                              "truncated xmm load from guest memory");
        }
        const auto rex =
            movupsLoadHasRex ? code[movupsLoadPrefixEnd] : 0U;
        const bool rexR = (rex & 0x4U) != 0;
        const bool rexX = (rex & 0x2U) != 0;
        const bool rexB = (rex & 0x1U) != 0;
        const auto modrm = code[movupsLoadOpcodeOffset + 2];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (mode == 0x3U) {
            // 0F 10/0F 28 and 66 0F 10/66 0F 28 with a register source
            // are all full 128-bit copies; alignment only matters for
            // memory operands.
            instruction.opcode = movapdLoad ? Opcode::MovapdRegReg
                                            : Opcode::MovapsRegReg;
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) |
                    (rexR ? 0x8U : 0U)))});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    rmEncoding | (rexB ? 0x8U : 0U)))});
            const auto operandCursor = movupsLoadOpcodeOffset + 3;
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
        auto operandCursor = movupsLoadOpcodeOffset + 3;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated aligned/unaligned XMM load SIB byte");
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
                    "no-base aligned/unaligned XMM load SIB addressing is not supported");
            }
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        }
        std::int64_t displacement = 0;
        if (ripRelative) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated RIP-relative XMM load disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        } else if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOVUPS load disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[operandCursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOVUPS load disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, operandCursor - instructionStart, displacement));
        }
        instruction.opcode = movapdLoad && code[movupsLoadOpcodeOffset + 1] != 0x10U
                                 ? Opcode::MovapdRegMem
                             : aligned ? Opcode::MovapsRegMem
                                       : Opcode::MovupsRegMem;
        instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
            static_cast<std::uint8_t>(((modrm >> 3U) & 0x7U) |
                                      (rexR ? 0x8U : 0U)))});
        instruction.operands.push_back(
            ripRelative
                ? MemoryOperand{Register::Rax, displacement, 128,
                                std::nullopt, 1, false, true}
                : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                displacement, 128, index, scale});
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 4 &&
        code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x3AU &&
        code[cursor + 3] == 0x16U) {
        if (code.size() - cursor < 6) {
            throw DecodeError(address, remaining,
                              "truncated PEXTRD r32, xmm, imm8");
        }
        const auto modrm = code[cursor + 4];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        if (mode != 0x3U) {
            throw DecodeError(
                address, remaining,
                "only register-direct PEXTRD is supported");
        }
        instruction.opcode = Opcode::PextrdRegXmmImm;
        instruction.length = 6;
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 6,
                    instruction.bytes.begin());
        instruction.operands.push_back(
            RegisterOperand{decodeRegister(
                                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), false),
                            32});
        instruction.operands.push_back(
            XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>(modrm & 0x7U))});
        instruction.operands.push_back(
            ImmediateOperand{static_cast<std::uint8_t>(code[cursor + 5] & 0x3U), 8});
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 4 &&
        code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x3AU &&
        code[cursor + 3] == 0x0EU) {
        if (code.size() - cursor < 6) {
            throw DecodeError(address, remaining,
                              "truncated PBLENDW xmm, xmm, imm8");
        }
        const auto modrm = code[cursor + 4];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        if (mode != 0x3U) {
            throw DecodeError(
                address, remaining,
                "only register-direct PBLENDW is supported");
        }
        instruction.opcode = Opcode::PblendwRegRegImm;
        instruction.length = 6;
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(cursor), 6,
            instruction.bytes.begin());
        instruction.operands.push_back(
            XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
        instruction.operands.push_back(
            XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>(modrm & 0x7U))});
        instruction.operands.push_back(
            ImmediateOperand{code[cursor + 5], 8});
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 2 &&
        code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU) {
        const auto rex = code[cursor + 1];
        if (code.size() - cursor >= 5 && code[cursor + 2] == 0x0FU &&
            code[cursor + 3] == 0x3AU && code[cursor + 4] == 0x22U) {
            if (code.size() - cursor < 7) {
                throw DecodeError(address, remaining,
                                  "truncated PINSRD/PINSRQ register operand");
            }
            const auto modrm = code[cursor + 5];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct REX PINSRD/PINSRQ is supported");
            }
            instruction.opcode = Opcode::PinsrdXmmReg;
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) |
                    ((rex & 0x4U) != 0 ? 8U : 0U)))});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U),
                               (rex & 0x1U) != 0),
                static_cast<std::uint8_t>((rex & 0x8U) != 0 ? 64
                                                           : 32)});
            instruction.operands.push_back(
                ImmediateOperand{code[cursor + 6], 8});
            instruction.length = 7;
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                instruction.length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 4 &&
        code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x3AU &&
        code[cursor + 3] == 0x22U) {
        if (code.size() - cursor < 6) {
            throw DecodeError(address, remaining,
                              "truncated PINSRD xmm, [memory], imm8");
        }
        const auto modrm = code[cursor + 4];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (mode != 0x3U &&
            (rmEncoding == 0x4U ||
             (mode == 0 && rmEncoding == 0x5U))) {
            throw DecodeError(
                address, remaining,
                "only PINSRD xmm, r32/dword [base+disp8/disp32], imm8 is supported");
        }
        auto operandCursor = cursor + 5;
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated PINSRD disp8");
            }
            displacement =
                std::bit_cast<std::int8_t>(code[operandCursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated PINSRD disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        if (operandCursor >= code.size()) {
            throw DecodeError(address, remaining,
                              "truncated PINSRD lane immediate");
        }
        const auto lane = code[operandCursor++];
        instruction.opcode = mode == 0x3U ? Opcode::PinsrdXmmReg
                                          : Opcode::PinsrdXmmMem;
        instruction.operands.push_back(
            XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
        if (mode == 0x3U) {
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(rmEncoding, false), 32});
        } else {
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, false), displacement, 32});
        }
        instruction.operands.push_back(ImmediateOperand{lane, 8});
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
        const auto afterSizePrefix = cursor + 1;
        const bool hasRex = code[afterSizePrefix] >= 0x40U &&
                            code[afterSizePrefix] <= 0x4FU;
        const auto opcodeOffset = afterSizePrefix + (hasRex ? 1U : 0U);
        if (code.size() - opcodeOffset >= 3 &&
            code[opcodeOffset] == 0x0FU &&
            code[opcodeOffset + 1] == 0x3AU &&
            code[opcodeOffset + 2] == 0x20U) {
            if (code.size() - opcodeOffset < 5) {
                throw DecodeError(address, remaining,
                                  "truncated PINSRB xmm, r32, imm8");
            }
            const auto rex = hasRex ? code[afterSizePrefix] : 0U;
            const bool rexW = (rex & 0x8U) != 0;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            const auto modrm = code[opcodeOffset + 3];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (rexW) {
                throw DecodeError(
                    address, remaining,
                    "PINSRB does not support REX.W");
            }
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode != 0x3U) {
                if (rmEncoding == 0x4U || (mode == 0 && rmEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only PINSRB xmm, byte [base+disp8/disp32], imm8 memory operands are supported");
                }
                auto operandCursor = opcodeOffset + 4;
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated PINSRB memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated PINSRB memory disp32");
                    }
                    displacement = readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated PINSRB memory immediate");
                }
                const auto lane = code[operandCursor++];
                instruction.opcode = Opcode::PinsrbXmmMem;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) | (rexR ? 8U : 0U)))});
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement, 8});
                instruction.operands.push_back(ImmediateOperand{lane, 8});
                const auto length = operandCursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                return true;
            }
            instruction.opcode = Opcode::PinsrbXmmReg;
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) | (rexR ? 8U : 0U)))});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U),
                               rexB),
                32});
            instruction.operands.push_back(
                ImmediateOperand{code[opcodeOffset + 4], 8});
            const auto length = opcodeOffset + 5 - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 4 &&
        code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x3AU &&
        code[cursor + 3] == 0x0FU) {
        if (code.size() - cursor < 6) {
            throw DecodeError(address, remaining,
                              "truncated palignr xmm, xmm, imm8");
        }
        const auto modrm = code[cursor + 4];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        if (mode != 0x3U) {
            throw DecodeError(
                address, remaining,
                "only register-direct PALIGNR is supported");
        }
        instruction.opcode = Opcode::PalignrRegRegImm;
        instruction.length = 6;
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(cursor), 6,
            instruction.bytes.begin());
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(
                static_cast<std::uint8_t>(modrm & 0x7U))});
        instruction.operands.push_back(
            ImmediateOperand{code[cursor + 5], 8});
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
        code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x7FU) {
        if (code.size() - cursor < 4) {
            throw DecodeError(address, remaining,
                              "truncated movdqa [memory], xmm");
        }
        const auto modrm = code[cursor + 3];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (mode > 0x2U || (mode == 0 && rmEncoding == 0x5U)) {
            throw DecodeError(
                address, remaining,
                "only MOVDQA [base+index*scale+disp], xmm is supported");
        }
        cursor += 4;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (rmEncoding == 0x4U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOVDQA store SIB byte");
            }
            const auto sib = code[cursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "no-base MOVDQA store SIB addressing is not supported");
            }
            if (indexEncoding != 0x4U) {
                index = decodeRegister(indexEncoding, false);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        }
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOVDQA store disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[cursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOVDQA store disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        }
        instruction.opcode = Opcode::MovdqaMemReg;
        instruction.operands.push_back(MemoryOperand{
            decodeRegister(baseEncoding, false), displacement, 128,
            index, scale});
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(static_cast<std::uint8_t>(
                (modrm >> 3U) & 0x7U))});
        const auto length = cursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 5 &&
        code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU &&
        code[cursor + 2] == 0x0FU && code[cursor + 3] == 0x6FU) {
        const auto rex = code[cursor + 1];
        const bool rexW = (rex & 0x8U) != 0;
        const bool rexR = (rex & 0x4U) != 0;
        const bool rexX = (rex & 0x2U) != 0;
        const bool rexB = (rex & 0x1U) != 0;
        const auto modrm = code[cursor + 4];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (rexW || rexX || mode == 0x3U || rmEncoding == 0x4U) {
            throw DecodeError(
                address, remaining,
                "only REX-extended MOVDQA xmm, [base/RIP+disp8/disp32] is supported");
        }
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
        const bool needsDisp32 = mode == 0x2U || (mode == 0 && rmEncoding == 0x5U);
        auto operandCursor = cursor + 5;
        std::int64_t displacement = 0;
        if (needsDisp32) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated REX MOVDQA load disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        } else if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated REX MOVDQA load disp8");
            }
            displacement =
                std::bit_cast<std::int8_t>(code[operandCursor++]);
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, operandCursor - instructionStart, displacement));
        }
        instruction.opcode = Opcode::MovdqaRegMem;
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(static_cast<std::uint8_t>(
                ((modrm >> 3U) & 0x7U) | (rexR ? 8U : 0U)))});
        instruction.operands.push_back(MemoryOperand{
            ripRelative ? Register::Rax : decodeRegister(rmEncoding, rexB), displacement,
            128, std::nullopt, 1, !ripRelative, ripRelative});
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
        code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x6FU) {
        if (code.size() - cursor < 4) {
            throw DecodeError(address, remaining, "truncated movdqa xmm, [base+disp]");
        }
        const auto modrm = code[cursor + 3];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (mode == 0x3U) {
            instruction.opcode = Opcode::MovdqaRegReg;
            instruction.length = 4;
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(cursor), 4,
                instruction.bytes.begin());
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(
                    static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(rmEncoding)});
            return true;
        }
        if (mode > 0x2U) {
            throw DecodeError(
                address, remaining,
                "only MOVDQA xmm, [base/RIP+index*scale+disp] memory operands are supported");
        }
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
        cursor += 4;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated MOVDQA SIB byte");
            }
            const auto sib = code[cursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(address, remaining,
                                  "no-base MOVDQA SIB addressing is not supported");
            }
            if (indexEncoding != 0x4U) {
                index = decodeRegister(indexEncoding, false);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        }
        std::int64_t displacement = 0;
        if (ripRelative || mode == 0x2U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOVDQA memory disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        } else if (mode == 0x1U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated MOVDQA memory disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[cursor++]);
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, cursor - instructionStart, displacement));
        }
        instruction.opcode = Opcode::MovdqaRegMem;
        instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
            static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
        instruction.operands.push_back(MemoryOperand{
            ripRelative ? Register::Rax : decodeRegister(baseEncoding, false),
            displacement, 128, index, scale, !ripRelative, ripRelative});

        const auto length = cursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart), length,
                    instruction.bytes.begin());
        return true;
    }

    return false;
}

} // namespace rosa::x86::detail
