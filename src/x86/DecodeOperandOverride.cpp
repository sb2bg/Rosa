#include "x86/DecodeInternal.h"

namespace rosa::x86::detail {

bool decodeOperandOverride(DecodeContext &context) {
    auto &[code, address, cursor, instruction] = context;
    [[maybe_unused]] const auto remaining = code;
    [[maybe_unused]] constexpr std::size_t instructionStart = 0;
    if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
        const auto afterPrefix = cursor + 1;
        const bool hasUnpcklpsRex =
            code[afterPrefix] >= 0x40U && code[afterPrefix] <= 0x4FU;
        const auto unpcklpsOpcodeOffset =
            afterPrefix + (hasUnpcklpsRex ? 1U : 0U);
        if (code.size() - unpcklpsOpcodeOffset >= 2 &&
            code[unpcklpsOpcodeOffset] == 0x0FU &&
            code[unpcklpsOpcodeOffset + 1] == 0x14U) {
            if (code.size() - unpcklpsOpcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  "truncated unpcklps xmm, xmm/m128");
            }
            const auto rex =
                hasUnpcklpsRex ? code[afterPrefix] : 0U;
            const auto modrm = code[unpcklpsOpcodeOffset + 2];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if ((rex & 0xAU) != 0) {
                throw DecodeError(
                    address, remaining,
                    "UNPCKLPS does not support REX.W/X");
            }
            const auto destination = XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) |
                    ((rex & 0x4U) != 0 ? 8U : 0U)))};
            auto operandCursor = unpcklpsOpcodeOffset + 3;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::UnpcklpsRegReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        rmEncoding | ((rex & 0x1U) != 0 ? 8U : 0U)))});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) == 0;
                if (rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U &&
                     (rex & 0x1U) != 0)) {
                    throw DecodeError(
                        address, remaining,
                        "only RIP-relative or based UNPCKLPS xmm, m128 is supported");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated UNPCKLPS m128 disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U || ripRelative) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated UNPCKLPS m128 disp32");
                    }
                    displacement =
                        readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                }
                instruction.opcode = Opcode::UnpcklpsRegMem;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 128,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{
                              decodeRegister(rmEncoding,
                                             (rex & 0x1U) != 0),
                              displacement, 128});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
        const auto afterPrefix = cursor + 1;
        const bool hasHaddpdRex =
            code[afterPrefix] >= 0x40U && code[afterPrefix] <= 0x4FU;
        const auto haddpdOpcodeOffset =
            afterPrefix + (hasHaddpdRex ? 1U : 0U);
        if (code.size() - haddpdOpcodeOffset >= 2 &&
            code[haddpdOpcodeOffset] == 0x0FU &&
            code[haddpdOpcodeOffset + 1] == 0x7CU) {
            if (code.size() - haddpdOpcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  "truncated haddpd xmm, xmm/m128");
            }
            const auto rex =
                hasHaddpdRex ? code[afterPrefix] : 0U;
            const auto modrm = code[haddpdOpcodeOffset + 2];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if ((rex & 0xAU) != 0) {
                throw DecodeError(
                    address, remaining,
                    "HADDPD does not support REX.W/X");
            }
            const auto destination = XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) |
                    ((rex & 0x4U) != 0 ? 8U : 0U)))};
            auto operandCursor = haddpdOpcodeOffset + 3;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::HaddpdRegReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        rmEncoding | ((rex & 0x1U) != 0 ? 8U : 0U)))});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) == 0;
                if (rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U &&
                     (rex & 0x1U) != 0)) {
                    throw DecodeError(
                        address, remaining,
                        "only RIP-relative or based HADDPD xmm, m128 is supported");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated HADDPD m128 disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U || ripRelative) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated HADDPD m128 disp32");
                    }
                    displacement =
                        readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                }
                instruction.opcode = Opcode::HaddpdRegMem;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 128,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{
                              decodeRegister(rmEncoding,
                                             (rex & 0x1U) != 0),
                              displacement, 128});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
        const auto afterPrefix = cursor + 1;
        const bool hasUnpckhpsRex =
            code[afterPrefix] >= 0x40U && code[afterPrefix] <= 0x4FU;
        const auto unpckhpsOpcodeOffset =
            afterPrefix + (hasUnpckhpsRex ? 1U : 0U);
        if (code.size() - unpckhpsOpcodeOffset >= 2 &&
            code[unpckhpsOpcodeOffset] == 0x0FU &&
            code[unpckhpsOpcodeOffset + 1] == 0x15U) {
            if (code.size() - unpckhpsOpcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  "truncated unpckhps xmm, xmm/m128");
            }
            const auto rex =
                hasUnpckhpsRex ? code[afterPrefix] : 0U;
            const auto modrm = code[unpckhpsOpcodeOffset + 2];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if ((rex & 0xAU) != 0) {
                throw DecodeError(
                    address, remaining,
                    "UNPCKHPS does not support REX.W/X");
            }
            const auto destination = XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) |
                    ((rex & 0x4U) != 0 ? 8U : 0U)))};
            auto operandCursor = unpckhpsOpcodeOffset + 3;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::UnpckhpsRegReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        rmEncoding | ((rex & 0x1U) != 0 ? 8U : 0U)))});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) == 0;
                if (rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U &&
                     (rex & 0x1U) != 0)) {
                    throw DecodeError(
                        address, remaining,
                        "only RIP-relative or based UNPCKHPS xmm, m128 is supported");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated UNPCKHPS m128 disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U || ripRelative) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated UNPCKHPS m128 disp32");
                    }
                    displacement =
                        readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                }
                instruction.opcode = Opcode::UnpckhpsRegMem;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 128,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{
                              decodeRegister(rmEncoding,
                                             (rex & 0x1U) != 0),
                              displacement, 128});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
        const auto afterPrefix = cursor + 1;
        const bool hasDivpdRex =
            code[afterPrefix] >= 0x40U && code[afterPrefix] <= 0x4FU;
        const auto divpdOpcodeOffset =
            afterPrefix + (hasDivpdRex ? 1U : 0U);
        if (code.size() - divpdOpcodeOffset >= 2 &&
            code[divpdOpcodeOffset] == 0x0FU &&
            (code[divpdOpcodeOffset + 1] == 0x51U ||
             code[divpdOpcodeOffset + 1] == 0x58U ||
             code[divpdOpcodeOffset + 1] == 0x59U ||
             code[divpdOpcodeOffset + 1] == 0x5CU ||
             code[divpdOpcodeOffset + 1] == 0x5EU)) {
            const auto packedOpcode = code[divpdOpcodeOffset + 1];
            const char *packedName = packedOpcode == 0x51U   ? "SQRTPD"
                                     : packedOpcode == 0x58U ? "ADDPD"
                                     : packedOpcode == 0x59U ? "MULPD"
                                     : packedOpcode == 0x5CU ? "SUBPD"
                                                             : "DIVPD";
            if (code.size() - divpdOpcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  std::string("truncated ") + packedName +
                                      " xmm, xmm/m128");
            }
            const auto rex =
                hasDivpdRex ? code[afterPrefix] : 0U;
            const auto modrm = code[divpdOpcodeOffset + 2];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if ((rex & 0xAU) != 0) {
                throw DecodeError(
                    address, remaining,
                    std::string(packedName) + " does not support REX.W/X");
            }
            const auto destination = XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) |
                    ((rex & 0x4U) != 0 ? 8U : 0U)))};
            auto operandCursor = divpdOpcodeOffset + 3;
            if (mode == 0x3U) {
                instruction.opcode = packedOpcode == 0x51U   ? Opcode::SqrtpdRegReg
                                     : packedOpcode == 0x58U ? Opcode::AddpdRegReg
                                     : packedOpcode == 0x59U ? Opcode::MulpdRegReg
                                     : packedOpcode == 0x5CU ? Opcode::SubpdRegReg
                                                             : Opcode::DivpdRegReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        rmEncoding | ((rex & 0x1U) != 0 ? 8U : 0U)))});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) == 0;
                if (rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U &&
                     (rex & 0x1U) != 0)) {
                    throw DecodeError(
                        address, remaining,
                        std::string("only RIP-relative or based ") + packedName +
                            " xmm, m128 is supported");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          std::string("truncated ") + packedName +
                                              " m128 disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U || ripRelative) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          std::string("truncated ") + packedName +
                                              " m128 disp32");
                    }
                    displacement =
                        readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                }
                instruction.opcode = packedOpcode == 0x51U   ? Opcode::SqrtpdRegMem
                                                 : packedOpcode == 0x58U ? Opcode::AddpdRegMem
                                                 : packedOpcode == 0x59U ? Opcode::MulpdRegMem
                                                 : packedOpcode == 0x5CU ? Opcode::SubpdRegMem
                                                                         : Opcode::DivpdRegMem;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 128,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{
                              decodeRegister(rmEncoding,
                                             (rex & 0x1U) != 0),
                              displacement, 128});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
        const auto afterPrefix = cursor + 1;
        const bool hasXorpdRex =
            code[afterPrefix] >= 0x40U && code[afterPrefix] <= 0x4FU;
        const auto xorpdOpcodeOffset =
            afterPrefix + (hasXorpdRex ? 1U : 0U);
        if (code.size() - xorpdOpcodeOffset >= 2 &&
            code[xorpdOpcodeOffset] == 0x0FU &&
            code[xorpdOpcodeOffset + 1] == 0x57U) {
            if (code.size() - xorpdOpcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  "truncated xorpd xmm, xmm");
            }
            const auto rex =
                hasXorpdRex ? code[afterPrefix] : 0U;
            const auto modrm = code[xorpdOpcodeOffset + 2];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || (rex & 0xAU) != 0) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct XORPD xmm, xmm is supported");
            }
            instruction.opcode = Opcode::XorpdRegReg;
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) |
                    ((rex & 0x4U) != 0 ? 8U : 0U)))});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    (modrm & 0x7U) |
                    ((rex & 0x1U) != 0 ? 8U : 0U)))});
            const auto end = xorpdOpcodeOffset + 3;
            const auto length = end - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
        const auto afterSizePrefix = cursor + 1;
        const bool testHasRex = code[afterSizePrefix] >= 0x40U &&
                                code[afterSizePrefix] <= 0x4FU;
        const auto testOpcodeOffset = afterSizePrefix + (testHasRex ? 1U : 0U);
        if (testOpcodeOffset < code.size() &&
            code[testOpcodeOffset] == 0x0FU &&
            code.size() - testOpcodeOffset >= 2 &&
            code[testOpcodeOffset + 1] == 0x6EU) {
            if (code.size() - testOpcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  "truncated movd xmm, r32");
            }
            const auto rex = testHasRex ? code[afterSizePrefix] : 0U;
            const bool rexW = (rex & 0x8U) != 0;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexX = (rex & 0x2U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            const auto modrm = code[testOpcodeOffset + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U;
            if (mode != 0x3U && rexW) {
                throw DecodeError(
                    address, remaining,
                    "MOVQ XMM memory load is not yet supported");
            }
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) | (rexR ? 8U : 0U)))});
            auto operandCursor = testOpcodeOffset + 3;
            if (mode == 0x3U) {
                instruction.opcode =
                    rexW ? Opcode::MovqXmmReg : Opcode::MovdXmmReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB),
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            } else {
                auto baseEncoding = rmEncoding;
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (rmEncoding == 0x4U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(
                            address, remaining,
                            "truncated MOVD load SIB byte");
                    }
                    const auto sib = code[operandCursor++];
                    const auto scaleBits = static_cast<std::uint8_t>(
                        (sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "no-base MOVD load SIB addressing is not supported");
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated RIP-relative MOVD load disp32");
                    }
                    displacement =
                        readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                } else if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated MOVD load disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(
                        code[operandCursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated MOVD load disp32");
                    }
                    displacement =
                        readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                instruction.opcode = Opcode::MovdXmmMem;
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax
                                : decodeRegister(baseEncoding, rexB),
                    displacement, 32, index, scale, !ripRelative,
                    ripRelative});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
        if (testOpcodeOffset < code.size() &&
            code[testOpcodeOffset] == 0x0FU &&
            code.size() - testOpcodeOffset >= 2 &&
            code[testOpcodeOffset + 1] == 0x7EU) {
            if (code.size() - testOpcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  "truncated movd [memory], xmm");
            }
            const auto rex = testHasRex ? code[afterSizePrefix] : 0U;
            const bool rexW = (rex & 0x8U) != 0;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexX = (rex & 0x2U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            const auto modrm = code[testOpcodeOffset + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U;
            if (rexW && mode != 0x3U) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct MOVQ r64, xmm is supported with REX.W");
            }
            if (rexW) {
                instruction.opcode = Opcode::MovqRegXmm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 64});
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) |
                        (rexR ? 8U : 0U)))});
                const auto length = testOpcodeOffset + 3 - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                return true;
            }
            auto operandCursor = testOpcodeOffset + 3;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::MovdRegXmm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 32});
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) |
                        (rexR ? 8U : 0U)))});
                const auto length = operandCursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                return true;
            }
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVD store SIB byte");
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
                        "no-base MOVD store SIB addressing is not supported");
                }
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(
                        address, remaining,
                        "truncated RIP-relative MOVD store disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            } else if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVD store disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVD store disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            instruction.opcode = Opcode::MovdMemXmm;
            instruction.operands.push_back(MemoryOperand{
                ripRelative ? Register::Rax
                            : decodeRegister(baseEncoding, rexB),
                displacement, 32, index, scale, !ripRelative,
                ripRelative});
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
        if (testOpcodeOffset < code.size() &&
            code[testOpcodeOffset] == 0x01U) {
            if (code.size() - testOpcodeOffset < 2) {
                throw DecodeError(address, remaining,
                                  "truncated add word register, register");
            }
            const auto rex = testHasRex ? code[afterSizePrefix] : 0U;
            const bool rexW = (rex & 0x8U) != 0;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            const auto modrm = code[testOpcodeOffset + 1];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (rexW || mode != 0x3U) {
                // Memory-destination and REX.W forms fall through to
                // the general decoder; the 66 prefix is ignored there
                // for REX.W and selects word operands otherwise.
            } else {
                instruction.opcode = Opcode::AddRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(
                        static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                    16});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(
                                       (modrm >> 3U) & 0x7U),
                                   rexR),
                    16});
                const auto length = testOpcodeOffset + 2 - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                return true;
            }
        }
        if (testOpcodeOffset < code.size() && code[testOpcodeOffset] == 0x85U) {
            if (code.size() - testOpcodeOffset < 2) {
                throw DecodeError(address, remaining,
                                  "truncated test word register, register");
            }
            const auto rex = testHasRex ? code[afterSizePrefix] : 0U;
            const bool rexW = (rex & 0x8U) != 0;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            const auto modrm = code[testOpcodeOffset + 1];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (rexW || mode != 0x3U) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct TEST r16, r16 is supported with operand-size override");
            }
            instruction.opcode = Opcode::TestRegReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), 16});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR), 16});
            const auto length = testOpcodeOffset + 2 - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
    }

    const bool wordLogicImmediateHasRex =
        code[cursor] == 0x66U && code.size() - cursor >= 2 &&
        code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU;
    const auto wordLogicImmediateOpcodeOffset =
        cursor + 1U + (wordLogicImmediateHasRex ? 1U : 0U);
    if (code[cursor] == 0x66U &&
        wordLogicImmediateOpcodeOffset < code.size() &&
        code[wordLogicImmediateOpcodeOffset] == 0x81U) {
        if (code.size() - wordLogicImmediateOpcodeOffset < 4) {
            throw DecodeError(address, remaining,
                              "truncated word [memory], imm16");
        }
        const auto rex =
            wordLogicImmediateHasRex ? code[cursor + 1] : 0U;
        if ((rex & 0xAU) != 0) {
            throw DecodeError(
                address, remaining,
                "word immediate memory operation does not support REX.W/R");
        }
        const auto rexB = (rex & 0x1U) != 0;
        const auto rexX = (rex & 0x2U) != 0;
        const auto modrm = code[wordLogicImmediateOpcodeOffset + 1];
        const auto mode =
            static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto extension =
            static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
        const auto rmEncoding =
            static_cast<std::uint8_t>(modrm & 0x7U);
        if ((extension != 0x4U && extension != 0x7U && extension != 0x1U) ||
            mode > 0x2U || (mode == 0 && rmEncoding == 0x5U) ||
            (rexX && rmEncoding != 0x4U)) {
            throw DecodeError(
                address, remaining,
                "only OR /1, AND /4 and CMP /7 word [base+index*scale+disp8/disp32], imm16 are supported");
        }
        auto operandCursor = wordLogicImmediateOpcodeOffset + 2;
        auto base = decodeRegister(rmEncoding, rexB);
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (rmEncoding == 0x4U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated word logic immediate SIB");
            }
            const auto sib = code[operandCursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            const auto baseEncoding =
                static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "no-base word logic immediate SIB is not supported");
            }
            base = decodeRegister(baseEncoding, rexB);
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        }
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated CMP word disp8");
            }
            displacement =
                std::bit_cast<std::int8_t>(code[operandCursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated CMP word disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        if (code.size() - operandCursor < 2) {
            throw DecodeError(address, remaining,
                              "truncated CMP word immediate");
        }
        const auto immediate = static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(code[operandCursor]) |
            (static_cast<std::uint16_t>(code[operandCursor + 1]) << 8U));
        operandCursor += 2;
        instruction.opcode = extension == 0x4U   ? Opcode::AndMemImm
                             : extension == 0x1U ? Opcode::OrMemImm
                                                 : Opcode::CmpMemImm;
        instruction.operands.push_back(MemoryOperand{
            base, displacement, 16, index, scale});
        instruction.operands.push_back(ImmediateOperand{immediate, 16});
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
    }

    const bool wordShortImmediateHasRex =
        code[cursor] == 0x66U && code.size() - cursor >= 2 &&
        code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU;
    const auto wordShortImmediateOpcodeOffset =
        cursor + 1U + (wordShortImmediateHasRex ? 1U : 0U);
    if (code[cursor] == 0x66U &&
        wordShortImmediateOpcodeOffset < code.size() &&
        code[wordShortImmediateOpcodeOffset] == 0x83U) {
        if (code.size() - wordShortImmediateOpcodeOffset < 3) {
            throw DecodeError(address, remaining,
                              "truncated cmp word [memory], imm8");
        }
        const auto rex =
            wordShortImmediateHasRex ? code[cursor + 1] : 0U;
        if ((rex & 0xCU) != 0) {
            throw DecodeError(
                address, remaining,
                "CMP word immediate does not support REX.W/R");
        }
        const auto rexB = (rex & 0x1U) != 0;
        const auto rexX = (rex & 0x2U) != 0;
        const auto modrm = code[wordShortImmediateOpcodeOffset + 1];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if ((extension != 0x7U && !(extension == 0x4U && mode == 0x3U) &&
             !(extension == 0x1U && mode != 0x3U)) ||
            (mode == 0 && rmEncoding == 0x5U)) {
            throw DecodeError(
                address, remaining,
                "only CMP r16 or word [base+index*scale+disp8/disp32], imm8, AND r16, imm8, and OR word [base+index*scale+disp8/disp32], imm8 are supported");
        }
        auto operandCursor = wordShortImmediateOpcodeOffset + 2;
        auto base = decodeRegister(rmEncoding, rexB);
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (mode != 0x3U && rmEncoding == 0x4U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated CMP word SIB");
            }
            const auto sib = code[operandCursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            const auto baseEncoding =
                static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "no-base CMP word SIB is not supported");
            }
            base = decodeRegister(baseEncoding, rexB);
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        }
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated CMP word disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[operandCursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated CMP word disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        if (operandCursor >= code.size()) {
            throw DecodeError(address, remaining,
                              "truncated CMP word immediate");
        }
        const auto immediate =
            std::bit_cast<std::int8_t>(code[operandCursor++]);
        if (extension == 0x4U) {
            instruction.opcode = Opcode::AndRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(rmEncoding, rexB), 16});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 8});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
        if (extension == 0x1U) {
            instruction.opcode = Opcode::OrMemImm;
            instruction.operands.push_back(MemoryOperand{
                base, displacement, 16, index, scale});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 8});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
        instruction.opcode = mode == 0x3U ? Opcode::CmpRegImm
                                          : Opcode::CmpMemImm;
        if (mode == 0x3U) {
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(rmEncoding, rexB), 16});
        } else {
            instruction.operands.push_back(MemoryOperand{
                base, displacement, 16, index, scale});
        }
        instruction.operands.push_back(ImmediateOperand{
            static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 8});
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 2 &&
        code[cursor + 1] == 0xFFU) {
        if (code.size() - cursor < 3) {
            throw DecodeError(address, remaining,
                              "truncated inc word [memory]");
        }
        const auto modrm = code[cursor + 2];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (mode == 0x3U && extension <= 1) {
            instruction.opcode = extension == 0 ? Opcode::IncReg : Opcode::DecReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(rmEncoding, false), 16});
            const auto length = cursor + 3 - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
        if ((extension != 0 && extension != 1) || mode > 0x2U || rmEncoding == 0x4U ||
            (mode == 0 && rmEncoding == 0x5U)) {
            throw DecodeError(
                address, remaining,
                "only INC/DEC word register and INC/DEC word [base+disp8/disp32] are supported");
        }
        auto operandCursor = cursor + 3;
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated INC word disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[operandCursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated INC word disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        instruction.opcode = extension == 0 ? Opcode::IncMem : Opcode::DecMem;
        instruction.operands.push_back(MemoryOperand{
            decodeRegister(rmEncoding, false), displacement, 16});
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    const bool wordStoreHasRex =
        code[cursor] == 0x66U && code.size() - cursor >= 2 &&
        code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU;
    const auto wordStoreOpcodeOffset =
        cursor + 1U + (wordStoreHasRex ? 1U : 0U);
    if (code[cursor] == 0x66U &&
        wordStoreOpcodeOffset < code.size() &&
        code[wordStoreOpcodeOffset] == 0x89U) {
        if (code.size() - wordStoreOpcodeOffset < 2) {
            throw DecodeError(address, remaining,
                              "truncated mov word [memory], register");
        }
        const auto rex = wordStoreHasRex ? code[cursor + 1] : 0U;
        const bool rexW = (rex & 0x8U) != 0;
        const bool rexR = (rex & 0x4U) != 0;
        const bool rexX = (rex & 0x2U) != 0;
        const bool rexB = (rex & 0x1U) != 0;
        const auto modrm = code[wordStoreOpcodeOffset + 1];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        if (rexW || mode > 0x2U) {
            throw DecodeError(
                address, remaining,
                "only MOV word [base+index*scale/RIP+disp8/disp32], register is supported");
        }
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
        auto operandCursor = wordStoreOpcodeOffset + 2;
        auto base = decodeRegister(rmEncoding, rexB);
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOV word register-store SIB");
            }
            const auto sib = code[operandCursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            const auto baseEncoding =
                static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "no-base MOV word register-store SIB is not supported");
            }
            base = decodeRegister(baseEncoding, rexB);
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        } else if (rexX) {
            throw DecodeError(
                address, remaining,
                "REX.X requires a MOV word register-store SIB operand");
        }
        std::int64_t displacement = 0;
        if (ripRelative) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(
                    address, remaining,
                    "truncated RIP-relative MOV word register-store disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        } else if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOV word register-store disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[operandCursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOV word register-store disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, operandCursor - instructionStart, displacement));
        }
        instruction.opcode = Opcode::MovMemReg;
        instruction.operands.push_back(
            ripRelative
                ? MemoryOperand{Register::Rax, displacement, 16,
                                std::nullopt, 1, false, true}
                : MemoryOperand{base, displacement, 16, index, scale});
        instruction.operands.push_back(RegisterOperand{
            decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U),
                           rexR),
            16});
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    const bool wordImmediateHasRex =
        code[cursor] == 0x66U && code.size() - cursor >= 2 &&
        code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU;
    const auto wordImmediateOpcodeOffset =
        cursor + 1U + (wordImmediateHasRex ? 1U : 0U);
    if (code[cursor] == 0x66U &&
        wordImmediateOpcodeOffset < code.size() &&
        code[wordImmediateOpcodeOffset] == 0xC7U) {
        if (code.size() - wordImmediateOpcodeOffset < 4) {
            throw DecodeError(address, remaining,
                              "truncated mov word [memory], imm16");
        }
        const auto rex = wordImmediateHasRex ? code[cursor + 1] : 0U;
        const bool rexW = (rex & 0x8U) != 0;
        const bool rexR = (rex & 0x4U) != 0;
        const bool rexX = (rex & 0x2U) != 0;
        const bool rexB = (rex & 0x1U) != 0;
        const auto modrm = code[wordImmediateOpcodeOffset + 1];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        auto operandCursor = wordImmediateOpcodeOffset + 2;
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
        if (rexW || rexR || mode > 0x2U || extension != 0) {
            throw DecodeError(
                address, remaining,
                "only MOV word [base/RIP+index*scale+disp8/disp32], imm16 is supported");
        }
        auto base = decodeRegister(rmEncoding, rexB);
        std::optional<Register> index;
        std::uint8_t scale = 1;
        bool hasBase = !ripRelative;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOV word immediate SIB");
            }
            const auto sib = code[operandCursor++];
            const auto scaleBits =
                static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
            const auto indexEncoding =
                static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
            const auto baseEncoding =
                static_cast<std::uint8_t>(sib & 0x7U);
            if (mode == 0 && baseEncoding == 0x5U && !rexB) {
                throw DecodeError(
                    address, remaining,
                    "no-base MOV word immediate SIB is not supported");
            }
            base = decodeRegister(baseEncoding, rexB);
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        } else if (rexX) {
            throw DecodeError(
                address, remaining,
                "REX.X requires a MOV word immediate SIB operand");
        }
        std::int64_t displacement = 0;
        if (ripRelative || mode == 0x2U) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOV word memory disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        } else if (mode == 0x1U) {
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated MOV word memory disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[operandCursor++]);
        }
        if (code.size() - operandCursor < 2) {
            throw DecodeError(address, remaining, "truncated MOV word imm16");
        }
        const auto immediate = static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(code[operandCursor]) |
            (static_cast<std::uint16_t>(code[operandCursor + 1]) << 8U));
        operandCursor += 2;
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, operandCursor - instructionStart, displacement));
        }
        instruction.opcode = Opcode::MovMemImm;
        instruction.operands.push_back(MemoryOperand{
            ripRelative ? Register::Rax : base, displacement, 16, index, scale,
            hasBase, ripRelative});
        instruction.operands.push_back(ImmediateOperand{immediate, 16});
        const auto length = operandCursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    return false;
}

} // namespace rosa::x86::detail
