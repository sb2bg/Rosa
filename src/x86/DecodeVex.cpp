#include "x86/DecodeInternal.h"

namespace rosa::x86::detail {

bool decodeVex(DecodeContext &context) {
    auto &[code, address, cursor, instruction] = context;
    [[maybe_unused]] const auto remaining = code;
    [[maybe_unused]] constexpr std::size_t instructionStart = 0;
    if (code[cursor] == 0xC4U) {
        if (code.size() - cursor < 5) {
            throw DecodeError(address, remaining,
                              "truncated three-byte VEX instruction");
        }
        const auto vexMap = code[cursor + 1];
        const auto vex = code[cursor + 2];
        const auto opcode = code[cursor + 3];
        const bool vexR = (vexMap & 0x80U) == 0;
        const bool vexX = (vexMap & 0x40U) == 0;
        const bool vexB = (vexMap & 0x20U) == 0;
        const auto opcodeMap =
            static_cast<std::uint8_t>(vexMap & 0x1FU);
        const bool vexW = (vex & 0x80U) != 0;
        const auto encodedVvvv =
            static_cast<std::uint8_t>((vex >> 3U) & 0xFU);
        const bool vexL = (vex & 0x4U) != 0;
        const auto vexPrefix = static_cast<std::uint8_t>(vex & 0x3U);
        const auto modrm = code[cursor + 4];
        const auto mode =
            static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);

        if (opcodeMap == 0x2U && opcode == 0x18U && !vexW && vexL &&
            vexPrefix == 0x1U && encodedVvvv == 0xFU && !vexX &&
            mode == 0x3U) {
            const auto destinationEncoding = static_cast<std::uint8_t>(
                ((modrm >> 3U) & 0x7U) | (vexR ? 0x8U : 0U));
            const auto sourceEncoding = static_cast<std::uint8_t>(
                (modrm & 0x7U) | (vexB ? 0x8U : 0U));
            instruction.opcode = Opcode::VbroadcastssYmmReg;
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(destinationEncoding)});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(sourceEncoding)});
            instruction.length = 5;
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(cursor), 5,
                instruction.bytes.begin());
            return true;
        }

        throw DecodeError(
            address, remaining,
            "three-byte VEX opcode is not in the current Rosa subset");
    }

    if (code[cursor] == 0xC5U) {
        if (code.size() - cursor < 3) {
            throw DecodeError(address, remaining,
                              "truncated two-byte VEX instruction");
        }
        const auto vex = code[cursor + 1];
        const auto opcode = code[cursor + 2];
        const bool vexR = (vex & 0x80U) == 0;
        const auto encodedVvvv =
            static_cast<std::uint8_t>((vex >> 3U) & 0xFU);
        const auto sourceEncoding =
            static_cast<std::uint8_t>((~encodedVvvv) & 0xFU);
        const bool vexL = (vex & 0x4U) != 0;
        const auto vexPrefix = static_cast<std::uint8_t>(vex & 0x3U);

        if (opcode == 0x77U) {
            if (vex != 0xF8U) {
                throw DecodeError(
                    address, remaining,
                    "only the canonical VZEROUPPER encoding is supported");
            }
            instruction.opcode = Opcode::Vzeroupper;
            instruction.length = 3;
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                instruction.bytes.begin());
            return true;
        }

        if (opcode == 0x57U) {
            if (vexPrefix != 0 || code.size() - cursor < 4) {
                throw DecodeError(
                    address, remaining,
                    "only register VXORPS is supported");
            }
            const auto modrm = code[cursor + 3];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct VXORPS is supported");
            }
            const auto destinationEncoding = static_cast<std::uint8_t>(
                ((modrm >> 3U) & 0x7U) | (vexR ? 0x8U : 0U));
            instruction.opcode = vexL ? Opcode::VxorpsYmmRegRegReg
                                      : Opcode::VxorpsRegRegReg;
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(destinationEncoding)});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(sourceEncoding)});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(
                    static_cast<std::uint8_t>(modrm & 0x7U))});
            instruction.length = 4;
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(cursor), 4,
                instruction.bytes.begin());
            return true;
        }

        if (opcode == 0x10U || opcode == 0x11U || opcode == 0x28U ||
            opcode == 0x29U) {
            if ((!vexL && (opcode == 0x28U || opcode == 0x29U)) ||
                vexPrefix != 0 ||
                encodedVvvv != 0xFU ||
                code.size() - cursor < 4) {
                throw DecodeError(
                    address, remaining,
                    "only memory VMOVUPS and 256-bit memory VMOVAPS are supported");
            }
            const auto modrm = code[cursor + 3];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U) {
                throw DecodeError(
                    address, remaining,
                    "only memory VMOVUPS operands are supported");
            }
            auto operandCursor = cursor + 4;
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U;
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated VMOVUPS SIB byte");
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
                        "no-base VMOVUPS SIB addressing is not supported");
                }
                if (indexEncoding != 0x4U) {
                    index = decodeRegister(indexEncoding, false);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative || mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated VMOVUPS disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            } else if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated VMOVUPS disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            }
            const auto xmmEncoding = static_cast<std::uint8_t>(
                ((modrm >> 3U) & 0x7U) | (vexR ? 0x8U : 0U));
            const auto memory =
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement,
                                    static_cast<std::uint16_t>(
                                        vexL ? 256U : 128U),
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(baseEncoding, false),
                                    displacement,
                                    static_cast<std::uint16_t>(
                                        vexL ? 256U : 128U),
                                    index, scale};
            if (opcode == 0x10U) {
                instruction.opcode = vexL ? Opcode::VmovupsYmmRegMem
                                          : Opcode::VmovupsRegMem;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(xmmEncoding)});
                instruction.operands.push_back(memory);
            } else if (opcode == 0x11U) {
                instruction.opcode = vexL ? Opcode::VmovupsYmmMemReg
                                          : Opcode::VmovupsMemReg;
                instruction.operands.push_back(memory);
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(xmmEncoding)});
            } else if (opcode == 0x28U) {
                instruction.opcode = Opcode::VmovapsYmmRegMem;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(xmmEncoding)});
                instruction.operands.push_back(memory);
            } else {
                instruction.opcode = Opcode::VmovapsYmmMemReg;
                instruction.operands.push_back(memory);
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(xmmEncoding)});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }

        throw DecodeError(address, remaining,
                          "two-byte VEX opcode is not in the current Rosa subset");
    }

    return false;
}

} // namespace rosa::x86::detail
