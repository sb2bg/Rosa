#include "x86/Decoder.h"

#include <algorithm>
#include <bit>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>

namespace rosa::x86 {
namespace {

std::string makeErrorMessage(guest::GuestAddress address, std::span<const std::uint8_t> remaining,
                             const std::string &reason) {
    std::ostringstream stream;
    stream << "unsupported or malformed x86 instruction at guest RIP 0x" << std::hex
           << address.value << ": " << reason << "; bytes:";
    const auto shown = std::min<std::size_t>(remaining.size(), 15);
    for (std::size_t index = 0; index < shown; ++index) {
        stream << ' ' << std::setw(2) << std::setfill('0')
               << static_cast<unsigned>(remaining[index]);
    }
    return stream.str();
}

std::uint64_t readU64(std::span<const std::uint8_t> bytes) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
    }
    return value;
}

std::int32_t readI32(std::span<const std::uint8_t> bytes) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<std::uint32_t>(bytes[index]) << (index * 8U);
    }
    return std::bit_cast<std::int32_t>(value);
}

guest::GuestAddress relativeTarget(guest::GuestAddress address, std::size_t length,
                                   std::int64_t displacement) {
    if (address.value > std::numeric_limits<std::uint64_t>::max() - length) {
        throw std::runtime_error("x86 control-transfer fallthrough address overflows");
    }
    const auto fallthrough = address.value + length;
    if (displacement >= 0) {
        const auto positive = static_cast<std::uint64_t>(displacement);
        if (fallthrough > std::numeric_limits<std::uint64_t>::max() - positive) {
            throw std::runtime_error("x86 relative branch target overflows");
        }
        return guest::GuestAddress{fallthrough + positive};
    }
    const auto magnitude = static_cast<std::uint64_t>(-(displacement + 1)) + 1U;
    if (magnitude > fallthrough) {
        throw std::runtime_error("x86 relative branch target underflows");
    }
    return guest::GuestAddress{fallthrough - magnitude};
}

Register decodeRegister(std::uint8_t lowBits, bool rexB) {
    const auto encoded = static_cast<std::uint8_t>(lowBits | (rexB ? 8U : 0U));
    return static_cast<Register>(encoded);
}

} // namespace

DecodeError::DecodeError(guest::GuestAddress address, std::span<const std::uint8_t> remaining,
                         const std::string &reason)
    : std::runtime_error(makeErrorMessage(address, remaining, reason)), address_(address),
      remaining_(remaining.begin(), remaining.end()) {}

std::vector<DecodedInstruction> Decoder::decodeBlock(std::span<const std::uint8_t> code,
                                                     guest::GuestAddress start,
                                                     std::size_t maximumInstructions) const {
    if (maximumInstructions == 0) {
        throw std::invalid_argument("x86 decoder instruction limit must be nonzero");
    }
    std::vector<DecodedInstruction> result;
    std::size_t cursor = 0;

    while (cursor < code.size()) {
        const auto instructionStart = cursor;
        if (cursor > std::numeric_limits<std::uint64_t>::max() - start.value) {
            throw DecodeError(start, code.subspan(cursor), "guest RIP overflows");
        }
        const auto address = guest::GuestAddress{start.value + cursor};
        const auto remaining = code.subspan(cursor);
        DecodedInstruction instruction;
        instruction.address = address;

        if (code[cursor] == 0xC3U) {
            instruction.opcode = Opcode::Ret;
            instruction.length = 1;
            instruction.bytes[0] = code[cursor];
            result.push_back(instruction);
            return result;
        }

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
                result.push_back(std::move(instruction));
                cursor += 5;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
                result.push_back(std::move(instruction));
                cursor += 3;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
                result.push_back(std::move(instruction));
                cursor += 4;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }

            throw DecodeError(address, remaining,
                              "two-byte VEX opcode is not in the current Rosa subset");
        }

        if (code[cursor] == 0x6AU) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining, "truncated push imm8");
            }
            const auto immediate = std::bit_cast<std::int8_t>(code[cursor + 1]);
            instruction.opcode = Opcode::Push;
            instruction.length = 2;
            instruction.bytes[0] = code[cursor];
            instruction.bytes[1] = code[cursor + 1];
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 8});
            result.push_back(std::move(instruction));
            cursor += 2;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x68U) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining,
                                  "truncated push imm32");
            }
            const auto immediate = readI32(code.subspan(cursor + 1, 4));
            instruction.opcode = Opcode::Push;
            instruction.length = 5;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 5,
                        instruction.bytes.begin());
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)),
                32});
            result.push_back(std::move(instruction));
            cursor += 5;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0xA8U) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining, "truncated test al, imm8");
            }
            instruction.opcode = Opcode::TestRegImm;
            instruction.length = 2;
            instruction.bytes[0] = code[cursor];
            instruction.bytes[1] = code[cursor + 1];
            instruction.operands.push_back(RegisterOperand{Register::Rax, 8});
            instruction.operands.push_back(ImmediateOperand{code[cursor + 1], 8});
            result.push_back(std::move(instruction));
            cursor += 2;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0xA9U) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining,
                                  "truncated test eax, imm32");
            }
            const auto immediate = static_cast<std::uint32_t>(
                readI32(code.subspan(cursor + 1, 4)));
            instruction.opcode = Opcode::TestRegImm;
            instruction.length = 5;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 5,
                        instruction.bytes.begin());
            instruction.operands.push_back(
                RegisterOperand{Register::Rax, 32});
            instruction.operands.push_back(ImmediateOperand{immediate, 32});
            result.push_back(std::move(instruction));
            cursor += 5;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0xC1U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated rol r16, imm8");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode != 0x3U || extension != 0) {
                throw DecodeError(address, remaining,
                                  "only register-direct ROL r16, imm8 is supported from 66 C1");
            }
            instruction.opcode = Opcode::RolRegImm;
            instruction.length = 4;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 4,
                        instruction.bytes.begin());
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), false),
                16});
            instruction.operands.push_back(
                ImmediateOperand{code[cursor + 3], 8});
            result.push_back(std::move(instruction));
            cursor += 4;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        const bool testImmediateHasRex =
            code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
        const auto testImmediateOpcodeOffset =
            cursor + (testImmediateHasRex ? 1U : 0U);
        if (testImmediateOpcodeOffset < code.size() &&
            code[testImmediateOpcodeOffset] == 0xF6U) {
            if (code.size() - testImmediateOpcodeOffset < 2) {
                throw DecodeError(address, remaining,
                                  "truncated F6 ModRM byte");
            }
            const auto rex = testImmediateHasRex ? code[cursor] : 0U;
            const bool rexX = (rex & 0x2U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            const auto modrm = code[testImmediateOpcodeOffset + 1];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (extension == 0x2U && mode == 0x3U &&
                (rex & 0x4U) == 0 &&
                (testImmediateHasRex || rmEncoding < 0x4U)) {
                instruction.opcode = Opcode::NotReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
                const auto length = testImmediateOpcodeOffset + 2 -
                                    instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = testImmediateOpcodeOffset + 2;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (extension == 0x3U && mode == 0x3U &&
                (rex & 0x6U) == 0 &&
                (testImmediateHasRex || rmEncoding < 0x4U)) {
                instruction.opcode = Opcode::NegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
                const auto length = testImmediateOpcodeOffset + 2 -
                                    instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = testImmediateOpcodeOffset + 2;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (extension == 0x6U && mode == 0x3U &&
                (rex & 0x6U) == 0 &&
                (testImmediateHasRex || rmEncoding < 0x4U)) {
                instruction.opcode = Opcode::DivReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
                const auto length = testImmediateOpcodeOffset + 2 -
                                    instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = testImmediateOpcodeOffset + 2;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (extension != 0 ||
                (mode == 0x3U && !testImmediateHasRex && rmEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only representable-byte register/memory TEST /0, register NOT /2, register NEG /3, and register DIV /6 from opcode F6 are supported");
            }
            auto operandCursor = testImmediateOpcodeOffset + 2;
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            bool hasBase = true;
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (mode != 0x3U && rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated TEST byte SIB");
                }
                const auto sib = code[operandCursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                hasBase = !(mode == 0 && baseEncoding == 0x5U);
                if (hasBase) {
                    base = decodeRegister(baseEncoding, rexB);
                }
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative || (!hasBase && mode == 0) || mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated TEST byte disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            } else if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated TEST byte disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[operandCursor++]);
            }
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated TEST byte immediate");
            }
            const auto immediate = code[operandCursor++];
            const auto length = operandCursor - instructionStart;
            if (length > instruction.bytes.size()) {
                throw DecodeError(address, remaining,
                                  "TEST byte instruction is too long");
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(address, length, displacement));
            }
            instruction.opcode = mode == 0x3U ? Opcode::TestRegImm
                                               : Opcode::TestMemImm;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor),
                        instruction.length,
                        instruction.bytes.begin());
            if (mode == 0x3U) {
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
            } else {
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 8,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{base, displacement, 8, index, scale,
                                        hasBase, false});
            }
            instruction.operands.push_back(ImmediateOperand{immediate, 8});
            result.push_back(std::move(instruction));
            cursor += length;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x04U) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining,
                                  "truncated add al, imm8");
            }
            instruction.opcode = Opcode::AddRegImm;
            instruction.length = 2;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 2,
                        instruction.bytes.begin());
            instruction.operands.push_back(
                RegisterOperand{Register::Rax, 8});
            instruction.operands.push_back(
                ImmediateOperand{code[cursor + 1], 8});
            result.push_back(std::move(instruction));
            cursor += 2;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x3CU) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining,
                                  "truncated cmp al, imm8");
            }
            instruction.opcode = Opcode::CmpRegImm;
            instruction.length = 2;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 2,
                        instruction.bytes.begin());
            instruction.operands.push_back(
                RegisterOperand{Register::Rax, 8});
            instruction.operands.push_back(
                ImmediateOperand{code[cursor + 1], 8});
            result.push_back(std::move(instruction));
            cursor += 2;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x3DU) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining, "truncated cmp eax, imm32");
            }
            const auto immediate = static_cast<std::uint32_t>(
                readI32(code.subspan(cursor + 1, sizeof(std::uint32_t))));
            instruction.opcode = Opcode::CmpRegImm;
            instruction.length = 5;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 5,
                        instruction.bytes.begin());
            instruction.operands.push_back(RegisterOperand{Register::Rax, 32});
            instruction.operands.push_back(ImmediateOperand{immediate, 32});
            result.push_back(std::move(instruction));
            cursor += 5;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] >= 0xB0U && code[cursor] <= 0xB3U) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining, "truncated mov low-byte register, imm8");
            }
            const auto opcode = code[cursor];
            instruction.opcode = Opcode::MovRegImm;
            instruction.length = 2;
            instruction.bytes[0] = opcode;
            instruction.bytes[1] = code[cursor + 1];
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(opcode - 0xB0U), false), 8});
            instruction.operands.push_back(ImmediateOperand{code[cursor + 1], 8});
            result.push_back(std::move(instruction));
            cursor += 2;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] >= 0xB8U && code[cursor] <= 0xBFU) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining, "truncated mov r32, imm32");
            }
            const auto opcode = code[cursor];
            const auto immediate = static_cast<std::uint32_t>(
                readI32(code.subspan(cursor + 1, sizeof(std::uint32_t))));
            instruction.opcode = Opcode::MovRegImm;
            instruction.length = 5;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 5,
                        instruction.bytes.begin());
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(opcode - 0xB8U), false), 32});
            instruction.operands.push_back(ImmediateOperand{immediate, 32});
            result.push_back(std::move(instruction));
            cursor += 5;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x35U) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining, "truncated xor eax, imm32");
            }
            const auto immediate = static_cast<std::uint32_t>(
                readI32(code.subspan(cursor + 1, sizeof(std::uint32_t))));
            instruction.opcode = Opcode::XorRegImm;
            instruction.length = 5;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 5,
                        instruction.bytes.begin());
            instruction.operands.push_back(RegisterOperand{Register::Rax, 32});
            instruction.operands.push_back(ImmediateOperand{immediate, 32});
            result.push_back(std::move(instruction));
            cursor += 5;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x0DU) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining,
                                  "truncated or eax, imm32");
            }
            const auto immediate = static_cast<std::uint32_t>(
                readI32(code.subspan(cursor + 1, sizeof(std::uint32_t))));
            instruction.opcode = Opcode::OrRegImm;
            instruction.length = 5;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 5,
                        instruction.bytes.begin());
            instruction.operands.push_back(
                RegisterOperand{Register::Rax, 32});
            instruction.operands.push_back(ImmediateOperand{immediate, 32});
            result.push_back(std::move(instruction));
            cursor += 5;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if ((code[cursor] >= 0x50U && code[cursor] <= 0x57U) ||
            (code[cursor] >= 0x40U && code[cursor] <= 0x4FU &&
             code.size() - cursor >= 2 && code[cursor + 1] >= 0x50U &&
             code[cursor + 1] <= 0x57U)) {
            const bool hasRex = code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
            const auto rex = hasRex ? code[cursor] : 0U;
            const auto opcode = code[cursor + (hasRex ? 1U : 0U)];
            instruction.opcode = Opcode::Push;
            instruction.length = static_cast<std::uint8_t>(hasRex ? 2U : 1U);
            instruction.bytes[0] = code[cursor];
            if (hasRex) {
                instruction.bytes[1] = opcode;
            }
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(opcode - 0x50U),
                               (rex & 0x1U) != 0),
                64});
            result.push_back(std::move(instruction));
            cursor += hasRex ? 2U : 1U;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if ((code[cursor] >= 0x58U && code[cursor] <= 0x5FU) ||
            (code[cursor] >= 0x40U && code[cursor] <= 0x4FU &&
             code.size() - cursor >= 2 && code[cursor + 1] >= 0x58U &&
             code[cursor + 1] <= 0x5FU)) {
            const bool hasRex = code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
            const auto rex = hasRex ? code[cursor] : 0U;
            const auto opcode = code[cursor + (hasRex ? 1U : 0U)];
            instruction.opcode = Opcode::Pop;
            instruction.length = static_cast<std::uint8_t>(hasRex ? 2U : 1U);
            instruction.bytes[0] = code[cursor];
            if (hasRex) {
                instruction.bytes[1] = opcode;
            }
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(opcode - 0x58U),
                               (rex & 0x1U) != 0),
                64});
            result.push_back(std::move(instruction));
            cursor += hasRex ? 2U : 1U;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0xC9U) {
            instruction.opcode = Opcode::Leave;
            instruction.length = 1;
            instruction.bytes[0] = code[cursor];
            result.push_back(std::move(instruction));
            ++cursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x0FU && code.size() - cursor >= 2 && code[cursor + 1] == 0x05U) {
            instruction.opcode = Opcode::Syscall;
            instruction.length = 2;
            instruction.bytes[0] = 0x0F;
            instruction.bytes[1] = 0x05;
            instruction.fallthrough = relativeTarget(address, 2, 0);
            result.push_back(std::move(instruction));
            return result;
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0x90U) {
            instruction.opcode = Opcode::Nop;
            instruction.length = 2;
            instruction.bytes[0] = 0x66;
            instruction.bytes[1] = 0x90;
            result.push_back(std::move(instruction));
            cursor += 2;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x90U) {
            instruction.opcode = Opcode::Nop;
            instruction.length = 1;
            instruction.bytes[0] = 0x90;
            result.push_back(std::move(instruction));
            ++cursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        auto nopOpcodeOffset = cursor;
        while (nopOpcodeOffset < code.size() &&
               (code[nopOpcodeOffset] == 0x66U ||
                code[nopOpcodeOffset] == 0x2EU)) {
            ++nopOpcodeOffset;
        }
        if (nopOpcodeOffset < code.size() &&
            code[nopOpcodeOffset] >= 0x40U &&
            code[nopOpcodeOffset] <= 0x4FU) {
            ++nopOpcodeOffset;
        }
        if (code.size() - nopOpcodeOffset >= 2 &&
            code[nopOpcodeOffset] == 0x0FU &&
            code[nopOpcodeOffset + 1] == 0x1FU) {
            auto nopCursor = nopOpcodeOffset + 2;
            if (nopCursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated multi-byte NOP");
            }
            const auto modrm = code[nopCursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (extension != 0) {
                throw DecodeError(address, remaining,
                                  "multi-byte NOP requires ModRM /0");
            }
            bool requiresDisp32 = mode == 0 && rmEncoding == 0x5U;
            if (mode != 0x3U && rmEncoding == 0x4U) {
                if (nopCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated multi-byte NOP SIB");
                }
                const auto sib = code[nopCursor++];
                requiresDisp32 =
                    mode == 0 && static_cast<std::uint8_t>(sib & 0x7U) == 0x5U;
            }
            const auto displacementSize =
                mode == 0x1U ? std::size_t{1}
                : (mode == 0x2U || requiresDisp32) ? std::size_t{4}
                                                   : std::size_t{0};
            if (code.size() - nopCursor < displacementSize) {
                throw DecodeError(address, remaining,
                                  "truncated multi-byte NOP displacement");
            }
            nopCursor += displacementSize;
            instruction.opcode = Opcode::Nop;
            const auto length = nopCursor - instructionStart;
            if (length > instruction.bytes.size()) {
                throw DecodeError(address, remaining,
                                  "multi-byte NOP exceeds x86 instruction length");
            }
            static_cast<void>(relativeTarget(address, length, 0));
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor = nopCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x0FU && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0xAEU && code[cursor + 2] == 0xE8U) {
            instruction.opcode = Opcode::Lfence;
            instruction.length = 3;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                        instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor += 3;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x0FU && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0xAEU && code[cursor + 2] == 0xF0U) {
            instruction.opcode = Opcode::Mfence;
            instruction.length = 3;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                        instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor += 3;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x0FU && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0x31U) {
            instruction.opcode = Opcode::Rdtsc;
            instruction.length = 2;
            instruction.bytes[0] = 0x0F;
            instruction.bytes[1] = 0x31;
            result.push_back(std::move(instruction));
            cursor += 2;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        const bool setHasRex = code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
        const auto setOpcodeOffset = cursor + (setHasRex ? 1U : 0U);
        if (code.size() - setOpcodeOffset >= 2 &&
            code[setOpcodeOffset] == 0x0FU &&
            (code[setOpcodeOffset + 1] == 0x90U ||
             code[setOpcodeOffset + 1] == 0x92U ||
             code[setOpcodeOffset + 1] == 0x93U ||
             code[setOpcodeOffset + 1] == 0x94U ||
             code[setOpcodeOffset + 1] == 0x95U ||
             code[setOpcodeOffset + 1] == 0x96U ||
             code[setOpcodeOffset + 1] == 0x97U ||
             code[setOpcodeOffset + 1] == 0x98U ||
             code[setOpcodeOffset + 1] == 0x99U ||
             code[setOpcodeOffset + 1] == 0x9CU ||
             code[setOpcodeOffset + 1] == 0x9FU)) {
            if (code.size() - setOpcodeOffset < 3) {
                throw DecodeError(address, remaining, "truncated setcc r8");
            }
            const auto rex = setHasRex ? code[cursor] : 0U;
            const auto conditionOpcode = code[setOpcodeOffset + 1];
            const auto modrm = code[setOpcodeOffset + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool rexX = (rex & 0x2U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (extension != 0 ||
                (mode == 0x3U && !setHasRex && rmEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only register or byte memory SETO/SETB/SETAE/SETE/SETNE/SETBE/SETA/SETS/SETNS/SETL/SETG is supported");
            }
            instruction.condition =
                conditionOpcode == 0x90U   ? Condition::Overflow
                : conditionOpcode == 0x92U ? Condition::Below
                : conditionOpcode == 0x93U ? Condition::AboveOrEqual
                : conditionOpcode == 0x94U ? Condition::Equal
                : conditionOpcode == 0x95U ? Condition::NotEqual
                : conditionOpcode == 0x96U ? Condition::BelowOrEqual
                : conditionOpcode == 0x97U ? Condition::Above
                : conditionOpcode == 0x98U ? Condition::Sign
                : conditionOpcode == 0x99U ? Condition::NotSign
                : conditionOpcode == 0x9CU ? Condition::Less
                                           : Condition::Greater;
            auto operandCursor = setOpcodeOffset + 3;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::SetccReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, (rex & 0x1U) != 0), 8});
            } else {
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated SETcc SIB byte");
                    }
                    const auto sib = code[operandCursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative || (!hasBase && mode == 0) ||
                    mode == 0x2U) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated SETcc displacement");
                    }
                    displacement = readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                } else if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated SETcc byte disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                }
                instruction.opcode = Opcode::SetccMem;
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax : base, displacement, 8,
                    index, scale, hasBase, ripRelative});
            }
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        const bool movsxWordHasRex =
            code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
        const auto movsxWordOpcodeOffset =
            cursor + (movsxWordHasRex ? 1U : 0U);
        if (code.size() - movsxWordOpcodeOffset >= 2 &&
            code[movsxWordOpcodeOffset] == 0x0FU &&
            code[movsxWordOpcodeOffset + 1] == 0xBFU) {
            if (code.size() - movsxWordOpcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  "truncated movsx register, word source");
            }
            const auto rex = movsxWordHasRex ? code[cursor] : 0U;
            const bool rexW = (rex & 0x8U) != 0;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexX = (rex & 0x2U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            cursor = movsxWordOpcodeOffset + 2;
            const auto modrm = code[cursor++];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            const auto destination = RegisterOperand{
                decodeRegister(
                    static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
                static_cast<std::uint8_t>(rexW ? 64U : 32U)};
            if (mode == 0x3U) {
                instruction.opcode = Opcode::MovsxRegReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 16});
            } else {
                const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated MOVSX word SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative || (!hasBase && mode == 0) ||
                    mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated MOVSX word disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated MOVSX word disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::MovsxRegMem;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax : base, displacement, 16,
                    index, scale, hasBase, ripRelative});
            }
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code.size() - cursor >= 2 && code[cursor] == 0x0FU &&
            code[cursor + 1] == 0xBEU) {
            if (code.size() - cursor < 3) {
                throw DecodeError(address, remaining,
                                  "truncated movsx r32, byte [memory]");
            }
            auto operandCursor = cursor + 2;
            const auto modrm = code[operandCursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U) {
                if (rmEncoding >= 0x4U) {
                    throw DecodeError(
                        address, remaining,
                        "legacy high-byte MOVSX register source is unsupported");
                }
                instruction.opcode = Opcode::MovsxRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(
                                       (modrm >> 3U) & 0x7U),
                                   false),
                    32});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, false), 8});
                const auto length = operandCursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if ((mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVSX r32, byte [base+index*scale+disp8/disp32] is supported without REX");
            }
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVSX byte SIB");
                }
                const auto sib = code[operandCursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base MOVSX byte SIB is not supported");
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
                                      "truncated MOVSX byte disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVSX byte disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            instruction.opcode = Opcode::MovsxRegMem;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(
                    static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), false),
                32});
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(baseEncoding, false), displacement, 8, index,
                scale});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        const bool movzxByteHasRex = code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
        const auto movzxByteOpcodeOffset = cursor + (movzxByteHasRex ? 1U : 0U);
        if (code.size() - movzxByteOpcodeOffset >= 2 &&
            code[movzxByteOpcodeOffset] == 0x0FU &&
            code[movzxByteOpcodeOffset + 1] == 0xB6U) {
            if (code.size() - movzxByteOpcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  "truncated movzx r32, byte register");
            }
            const auto rex = movzxByteHasRex ? code[cursor] : 0U;
            const bool rexW = (rex & 0x8U) != 0;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexX = (rex & 0x2U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            cursor = movzxByteOpcodeOffset + 2;
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            const auto destination = RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
                static_cast<std::uint8_t>(rexW ? 64U : 32U)};
            if (mode == 0x3U) {
                instruction.opcode = Opcode::MovzxRegReg;
                instruction.operands.push_back(destination);
                if (!movzxByteHasRex && rmEncoding >= 0x4U) {
                    instruction.operands.push_back(RegisterOperand{
                        static_cast<Register>(rmEncoding - 0x4U), 8, 1});
                } else {
                    instruction.operands.push_back(RegisterOperand{
                        decodeRegister(rmEncoding, rexB), 8});
                }
            } else {
                auto baseEncoding = rmEncoding;
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated byte MOVZX memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    const bool hasIndex = indexEncoding != 0x4U || rexX;
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(address, remaining,
                                          "byte MOVZX SIB requires a register base");
                    }
                    if (hasIndex) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated byte MOVZX disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (ripRelative || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated byte MOVZX disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::MovzxRegMem;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 8,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                        displacement, 8, index, scale});
            }
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        const bool movzxHasRex = code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
        const auto movzxOpcodeOffset = cursor + (movzxHasRex ? 1U : 0U);
        if (code.size() - movzxOpcodeOffset >= 2 &&
            code[movzxOpcodeOffset] == 0x0FU && code[movzxOpcodeOffset + 1] == 0xB7U) {
            if (code.size() - movzxOpcodeOffset < 3) {
                throw DecodeError(address, remaining, "truncated movzx r32, word [memory]");
            }
            const auto rex = movzxHasRex ? code[cursor] : 0U;
            const bool rexW = (rex & 0x8U) != 0;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexX = (rex & 0x2U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            cursor = movzxOpcodeOffset + 2;
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (rexW ||
                (mode != 0x3U && mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVZX r32, r16 or word [base+disp8/disp32] is supported");
            }
            if (mode == 0x3U) {
                instruction.opcode = Opcode::MovzxRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR), 32});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 16});
                const auto length = cursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                            length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated MOVZX memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits = static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding = static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                const bool hasIndex = indexEncoding != 0x4U || rexX;
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "MOVZX SIB requires a register base");
                }
                if (hasIndex) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated MOVZX disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated MOVZX disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::MovzxRegMem;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR), 32});
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(baseEncoding, rexB), displacement, 16, index, scale});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart), length,
                        instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x0FU && code.size() - cursor >= 2 &&
            (code[cursor + 1] == 0xBCU ||
             code[cursor + 1] == 0xBDU)) {
            if (code.size() - cursor < 3) {
                throw DecodeError(
                    address, remaining,
                    code[cursor + 1] == 0xBCU
                        ? "truncated bsf r32, r32"
                        : "truncated bsr r32, r32");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(
                    address, remaining,
                    code[cursor + 1] == 0xBCU
                        ? "only register-direct 32-bit BSF is supported"
                        : "only register-direct 32-bit BSR is supported");
            }
            instruction.opcode = code[cursor + 1] == 0xBCU
                                     ? Opcode::BitScanForwardRegReg
                                     : Opcode::BitScanReverseRegReg;
            instruction.length = 3;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                        instruction.bytes.begin());
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), false), 32});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), false), 32});
            result.push_back(std::move(instruction));
            cursor += 3;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x0FU && code.size() - cursor >= 2 &&
            code[cursor + 1] >= 0xC8U && code[cursor + 1] <= 0xCFU) {
            instruction.opcode = Opcode::BswapReg;
            instruction.length = 2;
            instruction.bytes[0] = code[cursor];
            instruction.bytes[1] = code[cursor + 1];
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(code[cursor + 1] - 0xC8U),
                               false),
                32});
            result.push_back(std::move(instruction));
            cursor += 2;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] >= 0x40U && code[cursor] <= 0x4FU &&
            code.size() - cursor >= 3 && code[cursor + 1] == 0x0FU &&
            code[cursor + 2] >= 0xC8U && code[cursor + 2] <= 0xCFU) {
            const auto rex = code[cursor];
            instruction.opcode = Opcode::BswapReg;
            instruction.length = 3;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                        instruction.bytes.begin());
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(code[cursor + 2] - 0xC8U),
                               (rex & 0x1U) != 0),
                static_cast<std::uint8_t>((rex & 0x8U) != 0 ? 64U : 32U)});
            result.push_back(std::move(instruction));
            cursor += 3;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if ((code[cursor] == 0x0FU ||
             (code[cursor] >= 0x40U && code[cursor] <= 0x4FU)) &&
            code.size() - cursor >= 2) {
            const bool hasMovlhpsRex = code[cursor] != 0x0FU;
            const auto opcodeOffset = cursor + (hasMovlhpsRex ? 1U : 0U);
            if (opcodeOffset < code.size() && code[opcodeOffset] == 0x0FU &&
                code.size() - opcodeOffset >= 2 &&
                code[opcodeOffset + 1] == 0x16U) {
                if (code.size() - opcodeOffset < 3) {
                    throw DecodeError(address, remaining,
                                      "truncated movlhps xmm, xmm");
                }
                const auto rex = hasMovlhpsRex ? code[cursor] : 0U;
                const auto modrm = code[opcodeOffset + 2];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                if (mode != 0x3U) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct MOVLHPS xmm, xmm is supported");
                }
                instruction.opcode = Opcode::MovlhpsRegReg;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) |
                        ((rex & 0x4U) != 0 ? 8U : 0U)))});
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        (modrm & 0x7U) |
                        ((rex & 0x1U) != 0 ? 8U : 0U)))});
                const auto length = opcodeOffset + 3 - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = opcodeOffset + 3;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
        }

        if (code[cursor] == 0x0FU && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0x57U) {
            if (code.size() - cursor < 3) {
                throw DecodeError(address, remaining, "truncated xorps xmm, xmm/m128");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
            cursor += 3;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::XorpsRegReg;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(rmEncoding)});
            } else {
                if (rmEncoding == 0x4U) {
                    throw DecodeError(
                        address, remaining,
                        "only XORPS xmm, [base/RIP+disp8/disp32] memory operands are supported");
                }
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U;
                std::int64_t displacement = 0;
                if (ripRelative || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated XORPS memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated XORPS memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::XorpsRegMem;
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax
                                : decodeRegister(rmEncoding, false),
                    displacement, 128, std::nullopt, 1, !ripRelative,
                    ripRelative});
            }
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
                result.push_back(std::move(instruction));
                cursor = end;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
                if (rexW) {
                    throw DecodeError(
                        address, remaining,
                        "MOVQ XMM qword store is not yet supported");
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
                    result.push_back(std::move(instruction));
                    cursor = operandCursor;
                    if (result.size() == maximumInstructions) {
                        return result;
                    }
                    continue;
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
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
                    throw DecodeError(
                        address, remaining,
                        "only register-direct ADD r16, r16 is supported with operand-size override");
                }
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
                result.push_back(std::move(instruction));
                cursor = testOpcodeOffset + 2;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
                result.push_back(std::move(instruction));
                cursor = testOpcodeOffset + 2;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
            if ((rex & 0xEU) != 0) {
                throw DecodeError(
                    address, remaining,
                    "word immediate memory operation does not support REX.W/R/X");
            }
            const auto rexB = (rex & 0x1U) != 0;
            const auto modrm = code[wordLogicImmediateOpcodeOffset + 1];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if ((extension != 0x4U && extension != 0x7U) ||
                mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only AND /4 and CMP /7 word [base+disp8/disp32], imm16 are supported");
            }
            auto operandCursor = wordLogicImmediateOpcodeOffset + 2;
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
            instruction.opcode = extension == 0x4U ? Opcode::AndMemImm
                                                    : Opcode::CmpMemImm;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, rexB), displacement, 16});
            instruction.operands.push_back(ImmediateOperand{immediate, 16});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            if ((rex & 0xEU) != 0) {
                throw DecodeError(
                    address, remaining,
                    "CMP word immediate does not support REX.W/R/X");
            }
            const auto rexB = (rex & 0x1U) != 0;
            const auto modrm = code[wordShortImmediateOpcodeOffset + 1];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (extension != 0x7U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only CMP r16 or word [base+index*scale+disp8/disp32], imm8 is supported");
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
                if (indexEncoding != 0x4U) {
                    index = decodeRegister(indexEncoding, false);
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
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            if (extension != 0 || mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only INC word [base+disp8/disp32] is supported");
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
            instruction.opcode = Opcode::IncMem;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, false), displacement, 16});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
            const auto afterPrefix = cursor + 1;
            const bool hasPshufbRex = code[afterPrefix] >= 0x40U &&
                                      code[afterPrefix] <= 0x4FU;
            const auto opcodeOffset =
                afterPrefix + (hasPshufbRex ? 1U : 0U);
            if (opcodeOffset < code.size() && code[opcodeOffset] == 0x0FU &&
                code.size() - opcodeOffset >= 2 &&
                code[opcodeOffset + 1] == 0x38U) {
                if (code.size() - opcodeOffset < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated 0F 38 SIMD instruction");
                }
                if (code[opcodeOffset + 2] == 0x00U) {
                    const auto rex = hasPshufbRex ? code[afterPrefix] : 0U;
                    const auto modrm = code[opcodeOffset + 3];
                    const auto mode =
                        static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                    const auto rmEncoding =
                        static_cast<std::uint8_t>(modrm & 0x7U);
                    if (mode != 0x3U &&
                        (mode != 0 || rmEncoding != 0x5U ||
                         (rex & 0xBU) != 0)) {
                        throw DecodeError(
                            address, remaining,
                            "only register-direct or RIP-relative PSHUFB xmm, xmm/m128 is supported");
                    }
                    instruction.operands.push_back(XmmRegisterOperand{
                        static_cast<XmmRegister>(static_cast<std::uint8_t>(
                            ((modrm >> 3U) & 0x7U) |
                            ((rex & 0x4U) != 0 ? 8U : 0U)))});
                    auto operandCursor = opcodeOffset + 4;
                    if (mode == 0x3U) {
                        instruction.opcode = Opcode::PshufbRegReg;
                        instruction.operands.push_back(XmmRegisterOperand{
                            static_cast<XmmRegister>(
                                static_cast<std::uint8_t>(
                                    rmEncoding |
                                    ((rex & 0x1U) != 0 ? 8U : 0U)))});
                    } else {
                        if (code.size() - operandCursor < 4) {
                            throw DecodeError(
                                address, remaining,
                                "truncated RIP-relative PSHUFB displacement");
                        }
                        const auto displacement =
                            readI32(code.subspan(operandCursor, 4));
                        operandCursor += 4;
                        static_cast<void>(relativeTarget(
                            address, operandCursor - instructionStart,
                            displacement));
                        instruction.opcode = Opcode::PshufbRegMem;
                        instruction.operands.push_back(MemoryOperand{
                            Register::Rax, displacement, 128,
                            std::nullopt, 1, false, true});
                    }
                    const auto length = operandCursor - instructionStart;
                    instruction.length = static_cast<std::uint8_t>(length);
                    std::copy_n(
                        code.begin() +
                            static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
                    result.push_back(std::move(instruction));
                    cursor = operandCursor;
                    if (result.size() == maximumInstructions) {
                        return result;
                    }
                    continue;
                }
                if (code[opcodeOffset + 2] == 0x02U) {
                    const auto rex = hasPshufbRex ? code[afterPrefix] : 0U;
                    const auto modrm = code[opcodeOffset + 3];
                    const auto mode =
                        static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                    if (mode != 0x3U || (rex & 0xAU) != 0) {
                        throw DecodeError(
                            address, remaining,
                            "only register-direct PHADDD xmm, xmm is supported");
                    }
                    instruction.opcode = Opcode::PhadddRegReg;
                    instruction.operands.push_back(XmmRegisterOperand{
                        static_cast<XmmRegister>(static_cast<std::uint8_t>(
                            ((modrm >> 3U) & 0x7U) |
                            ((rex & 0x4U) != 0 ? 8U : 0U)))});
                    instruction.operands.push_back(XmmRegisterOperand{
                        static_cast<XmmRegister>(static_cast<std::uint8_t>(
                            (modrm & 0x7U) |
                            ((rex & 0x1U) != 0 ? 8U : 0U)))});
                    const auto length =
                        opcodeOffset + 4 - instructionStart;
                    instruction.length = static_cast<std::uint8_t>(length);
                    std::copy_n(
                        code.begin() +
                            static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
                    result.push_back(std::move(instruction));
                    cursor = opcodeOffset + 4;
                    if (result.size() == maximumInstructions) {
                        return result;
                    }
                    continue;
                }
                if (code[opcodeOffset + 2] == 0x21U) {
                    const auto rex = hasPshufbRex ? code[afterPrefix] : 0U;
                    const auto modrm = code[opcodeOffset + 3];
                    const auto mode =
                        static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                    const auto rmEncoding =
                        static_cast<std::uint8_t>(modrm & 0x7U);
                    if ((rex & 0xBU) != 0 || mode != 0 ||
                        rmEncoding != 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "only RIP-relative PMOVSXBD xmm, dword memory is supported");
                    }
                    auto operandCursor = opcodeOffset + 4;
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated RIP-relative PMOVSXBD displacement");
                    }
                    const auto displacement =
                        readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                    instruction.opcode = Opcode::PmovsxbdRegMem;
                    instruction.operands.push_back(XmmRegisterOperand{
                        static_cast<XmmRegister>(static_cast<std::uint8_t>(
                            ((modrm >> 3U) & 0x7U) |
                            ((rex & 0x4U) != 0 ? 8U : 0U)))});
                    instruction.operands.push_back(MemoryOperand{
                        Register::Rax, displacement, 32, std::nullopt, 1,
                        false, true});
                    const auto length = operandCursor - instructionStart;
                    instruction.length = static_cast<std::uint8_t>(length);
                    std::copy_n(
                        code.begin() +
                            static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
                    result.push_back(std::move(instruction));
                    cursor = operandCursor;
                    if (result.size() == maximumInstructions) {
                        return result;
                    }
                    continue;
                }
                if (code[opcodeOffset + 2] == 0x25U) {
                    const auto rex = hasPshufbRex ? code[afterPrefix] : 0U;
                    const auto modrm = code[opcodeOffset + 3];
                    const auto mode =
                        static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                    const auto rmEncoding =
                        static_cast<std::uint8_t>(modrm & 0x7U);
                    if ((rex & 0xBU) != 0 || mode != 0 ||
                        rmEncoding != 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "only RIP-relative PMOVSXDQ xmm, qword memory is supported");
                    }
                    auto operandCursor = opcodeOffset + 4;
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated RIP-relative PMOVSXDQ displacement");
                    }
                    const auto displacement =
                        readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart,
                        displacement));
                    instruction.opcode = Opcode::PmovsxdqRegMem;
                    instruction.operands.push_back(XmmRegisterOperand{
                        static_cast<XmmRegister>(static_cast<std::uint8_t>(
                            ((modrm >> 3U) & 0x7U) |
                            ((rex & 0x4U) != 0 ? 8U : 0U)))});
                    instruction.operands.push_back(MemoryOperand{
                        Register::Rax, displacement, 64, std::nullopt, 1,
                        false, true});
                    const auto length = operandCursor - instructionStart;
                    instruction.length = static_cast<std::uint8_t>(length);
                    std::copy_n(
                        code.begin() +
                            static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
                    result.push_back(std::move(instruction));
                    cursor = operandCursor;
                    if (result.size() == maximumInstructions) {
                        return result;
                    }
                    continue;
                }
            }
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 4 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x3AU &&
            code[cursor + 3] == 0x17U) {
            if (code.size() - cursor < 6) {
                throw DecodeError(address, remaining,
                                  "truncated EXTRACTPS [memory], xmm, imm8");
            }
            const auto modrm = code[cursor + 4];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U || (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only based no-index EXTRACTPS memory destinations are supported");
            }
            auto operandCursor = cursor + 5;
            auto baseEncoding = rmEncoding;
            if (rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated EXTRACTPS SIB byte");
                }
                const auto sib = code[operandCursor++];
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (indexEncoding != 0x4U ||
                    (mode == 0 && baseEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only based no-index EXTRACTPS SIB destinations are supported");
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated EXTRACTPS disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated EXTRACTPS disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated EXTRACTPS immediate");
            }
            const auto lane = code[operandCursor++];
            instruction.opcode = Opcode::ExtractpsMemXmmImm;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(baseEncoding, false), displacement, 32});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    (modrm >> 3U) & 0x7U))});
            instruction.operands.push_back(ImmediateOperand{lane, 8});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 4 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x38U &&
            code[cursor + 3] == 0x17U) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining,
                                  "truncated ptest xmm, xmm");
            }
            const auto modrm = code[cursor + 4];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(address, remaining,
                                  "only register-direct PTEST is supported");
            }
            instruction.opcode = Opcode::PtestRegReg;
            instruction.length = 5;
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                instruction.length, instruction.bytes.begin());
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>((modrm >> 3U) & 0x7U)});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(modrm & 0x7U)});
            result.push_back(std::move(instruction));
            cursor += 5;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 3) {
            const auto afterPrefix = cursor + 1;
            const bool hasPackedDwordRex =
                code[afterPrefix] >= 0x40U && code[afterPrefix] <= 0x4FU;
            const auto opcodeOffset =
                afterPrefix + (hasPackedDwordRex ? 1U : 0U);
            if (code.size() - opcodeOffset >= 2 &&
                code[opcodeOffset] == 0x0FU &&
                (code[opcodeOffset + 1] == 0x72U ||
                 code[opcodeOffset + 1] == 0x73U ||
                 code[opcodeOffset + 1] == 0xFEU ||
                 code[opcodeOffset + 1] == 0xD4U)) {
                const auto secondOpcode = code[opcodeOffset + 1];
                const auto isImmediateShift =
                    secondOpcode == 0x72U || secondOpcode == 0x73U;
                const auto requiredAfterOpcode =
                    isImmediateShift ? 2U : 1U;
                if (code.size() - (opcodeOffset + 2) <
                    requiredAfterOpcode) {
                    throw DecodeError(
                        address, remaining,
                        secondOpcode == 0x72U
                            ? "truncated PSLLD xmm, imm8"
                        : secondOpcode == 0x73U
                            ? "truncated PSRLQ xmm, imm8"
                        : secondOpcode == 0xFEU
                            ? "truncated PADDD xmm, xmm"
                            : "truncated PADDQ xmm, xmm");
                }
                const auto rex =
                    hasPackedDwordRex ? code[afterPrefix] : 0U;
                const auto modrm = code[opcodeOffset + 2];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                const auto regEncoding =
                    static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
                const auto rmEncoding =
                    static_cast<std::uint8_t>(modrm & 0x7U);
                const auto expectedOpcodeExtension =
                    secondOpcode == 0x72U ? 0x6U : 0x2U;
                if (mode != 0x3U || (rex & 0xAU) != 0 ||
                    (isImmediateShift &&
                     (regEncoding != expectedOpcodeExtension ||
                      (rex & 0x4U) != 0))) {
                    throw DecodeError(
                        address, remaining,
                        secondOpcode == 0x72U
                            ? "only register-direct PSLLD xmm, imm8 is supported"
                        : secondOpcode == 0x73U
                            ? "only register-direct PSRLQ xmm, imm8 is supported"
                            : "only register-direct PADDD xmm, xmm is supported");
                }
                if (isImmediateShift) {
                    instruction.opcode = secondOpcode == 0x72U
                                             ? Opcode::PslldRegImm
                                             : Opcode::PsrlqRegImm;
                    instruction.operands.push_back(XmmRegisterOperand{
                        static_cast<XmmRegister>(static_cast<std::uint8_t>(
                            rmEncoding | ((rex & 0x1U) != 0 ? 8U : 0U)))});
                    instruction.operands.push_back(ImmediateOperand{
                        code[opcodeOffset + 3], 8});
                } else {
                    instruction.opcode = secondOpcode == 0xFEU
                                             ? Opcode::PadddRegReg
                                             : Opcode::PaddqRegReg;
                    instruction.operands.push_back(XmmRegisterOperand{
                        static_cast<XmmRegister>(static_cast<std::uint8_t>(
                            regEncoding |
                            ((rex & 0x4U) != 0 ? 8U : 0U)))});
                    instruction.operands.push_back(XmmRegisterOperand{
                        static_cast<XmmRegister>(static_cast<std::uint8_t>(
                            rmEncoding | ((rex & 0x1U) != 0 ? 8U : 0U)))});
                }
                const auto end = opcodeOffset + 2 + requiredAfterOpcode;
                const auto length = end - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = end;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
            const auto afterPrefix = cursor + 1;
            const bool hasPunpcklRex =
                code[afterPrefix] >= 0x40U && code[afterPrefix] <= 0x4FU;
            const auto punpcklOpcodeOffset =
                afterPrefix + (hasPunpcklRex ? 1U : 0U);
            const auto punpcklSecondOpcode =
                (code.size() - punpcklOpcodeOffset >= 2 &&
                 code[punpcklOpcodeOffset] == 0x0FU)
                    ? code[punpcklOpcodeOffset + 1]
                    : 0U;
            if (punpcklSecondOpcode == 0x61U || punpcklSecondOpcode == 0x6CU) {
                if (code.size() - punpcklOpcodeOffset < 3) {
                    throw DecodeError(address, remaining,
                                      punpcklSecondOpcode == 0x61U
                                          ? "truncated PUNPCKLWD xmm, xmm"
                                          : "truncated PUNPCKLQDQ xmm, xmm");
                }
                const auto rex =
                    hasPunpcklRex ? code[afterPrefix] : 0U;
                const auto modrm = code[punpcklOpcodeOffset + 2];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                if (mode != 0x3U || (rex & 0xAU) != 0) {
                    throw DecodeError(address, remaining,
                                      punpcklSecondOpcode == 0x61U
                                          ? "only register-direct PUNPCKLWD xmm, xmm is supported"
                                          : "only register-direct PUNPCKLQDQ xmm, xmm is supported");
                }
                instruction.opcode = punpcklSecondOpcode == 0x61U
                                         ? Opcode::PunpcklwdRegReg
                                         : Opcode::PunpcklqdqRegReg;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) |
                        ((rex & 0x4U) != 0 ? 8U : 0U)))});
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        (modrm & 0x7U) |
                        ((rex & 0x1U) != 0 ? 8U : 0U)))});
                const auto end = punpcklOpcodeOffset + 3;
                const auto length = end - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = end;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
            const auto afterPrefix = cursor + 1;
            const bool hasPorRex = code[afterPrefix] >= 0x40U &&
                                   code[afterPrefix] <= 0x4FU;
            const auto opcodeOffset = afterPrefix + (hasPorRex ? 1U : 0U);
            if (opcodeOffset < code.size() && code[opcodeOffset] == 0x0FU &&
                code.size() - opcodeOffset >= 2 &&
                code[opcodeOffset + 1] == 0xEBU) {
                if (code.size() - opcodeOffset < 3) {
                    throw DecodeError(address, remaining,
                                      "truncated por xmm, xmm");
                }
                const auto rex = hasPorRex ? code[afterPrefix] : 0U;
                const auto modrm = code[opcodeOffset + 2];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                if (mode != 0x3U) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct POR xmm, xmm is supported");
                }
                instruction.opcode = Opcode::PorRegReg;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) |
                        ((rex & 0x4U) != 0 ? 8U : 0U)))});
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        (modrm & 0x7U) |
                        ((rex & 0x1U) != 0 ? 8U : 0U)))});
                const auto length = opcodeOffset + 3 - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = opcodeOffset + 3;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
            ((code[cursor + 1] == 0x0FU && code[cursor + 2] == 0xEFU) ||
             (code.size() - cursor >= 5 && code[cursor + 1] >= 0x40U &&
              code[cursor + 1] <= 0x4FU && code[cursor + 2] == 0x0FU &&
              code[cursor + 3] == 0xEFU))) {
            const auto rex = code[cursor + 1] == 0x0FU ? 0U : code[cursor + 1];
            const auto rexR = (rex & 0x4U) != 0;
            const auto rexB = (rex & 0x1U) != 0;
            const auto modrmOffset =
                code[cursor + 1] == 0x0FU ? cursor + 3 : cursor + 4;
            if (code.size() - modrmOffset < 1) {
                throw DecodeError(address, remaining,
                                  "truncated pxor xmm, xmm/m128");
            }
            const auto modrm = code[modrmOffset];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto destinationEncoding = static_cast<std::uint8_t>(
                ((modrm >> 3U) & 0x7U) | (rexR ? 8U : 0U));
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(destinationEncoding)});
            cursor = modrmOffset + 1;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::PxorRegReg;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(
                        static_cast<std::uint8_t>(rmEncoding | (rexB ? 8U : 0U)))});
            } else {
                if (rmEncoding == 0x4U) {
                    throw DecodeError(
                        address, remaining,
                        "only PXOR xmm, [base/RIP+disp8/disp32] memory operands are supported");
                }
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U;
                std::int64_t displacement = 0;
                if (ripRelative || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated PXOR memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated PXOR memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::PxorRegMem;
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax
                                : decodeRegister(rmEncoding, rexB),
                    displacement, 128, std::nullopt, 1, !ripRelative,
                    ripRelative});
            }
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0xDFU) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated pandn xmm, xmm");
            }
            const auto modrm = code[cursor + 3];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(address, remaining,
                                  "only register-direct PANDN is supported");
            }
            instruction.opcode = Opcode::PandnRegReg;
            instruction.length = 4;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 4,
                        instruction.bytes.begin());
            instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(modrm & 0x7U))});
            result.push_back(std::move(instruction));
            cursor += 4;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0xDBU) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated PAND xmm, [memory]");
            }
            const auto modrm = code[cursor + 3];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U) {
                instruction.opcode = Opcode::PandRegReg;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        (modrm >> 3U) & 0x7U))});
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(rmEncoding)});
                instruction.length = 4;
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    instruction.length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor += 4;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (rmEncoding == 0x4U) {
                throw DecodeError(
                    address, remaining,
                    "only PAND xmm, [base+disp8/disp32] or [RIP+disp32] is supported");
            }
            auto operandCursor = cursor + 4;
            std::int64_t displacement = 0;
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (ripRelative || mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated PAND memory disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            } else if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated PAND memory disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            }
            const auto length = operandCursor - instructionStart;
            if (ripRelative) {
                static_cast<void>(relativeTarget(address, length, displacement));
            }
            instruction.opcode = Opcode::PandRegMem;
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    (modrm >> 3U) & 0x7U))});
            instruction.operands.push_back(MemoryOperand{
                ripRelative ? Register::Rax : decodeRegister(rmEncoding, false),
                displacement, 128, std::nullopt, 1, !ripRelative,
                ripRelative});
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x74U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated pcmpeqb xmm, xmm/m128");
            }
            cursor += 3;
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if ((mode != 0x3U && rmEncoding == 0x4U) ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only PCMPEQB xmm, xmm or [base+disp8/disp32] is supported");
            }
            if (mode == 0x3U) {
                instruction.opcode = Opcode::PcmpeqbRegReg;
                instruction.operands.push_back(
                    XmmRegisterOperand{static_cast<XmmRegister>(
                        static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
                instruction.operands.push_back(
                    XmmRegisterOperand{static_cast<XmmRegister>(rmEncoding)});
                const auto length = cursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated PCMPEQB disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated PCMPEQB disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::PcmpeqbRegMem;
            instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, false), displacement, 128});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart), length,
                        instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 3) {
            const auto afterPrefix = cursor + 1;
            const bool hasPcmpeqdRex =
                code[afterPrefix] >= 0x40U && code[afterPrefix] <= 0x4FU;
            const auto pcmpeqdOpcodeOffset =
                afterPrefix + (hasPcmpeqdRex ? 1U : 0U);
            if (code.size() - pcmpeqdOpcodeOffset >= 2 &&
                code[pcmpeqdOpcodeOffset] == 0x0FU &&
                code[pcmpeqdOpcodeOffset + 1] == 0x76U) {
                if (code.size() - pcmpeqdOpcodeOffset < 3) {
                    throw DecodeError(address, remaining,
                                      "truncated PCMPEQD xmm, xmm");
                }
                const auto rex = hasPcmpeqdRex ? code[afterPrefix] : 0U;
                const auto modrm = code[pcmpeqdOpcodeOffset + 2];
                const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                if (mode != 0x3U || (rex & 0xAU) != 0) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct PCMPEQD is supported");
                }
                instruction.opcode = Opcode::PcmpeqdRegReg;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) | ((rex & 0x4U) != 0 ? 8U : 0U)))});
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        (modrm & 0x7U) | ((rex & 0x1U) != 0 ? 8U : 0U)))});
                const auto end = pcmpeqdOpcodeOffset + 3;
                const auto length = end - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = end;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x70U) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining,
                                  "truncated pshufd xmm, xmm, imm8");
            }
            const auto modrm = code[cursor + 3];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(address, remaining,
                                  "only register-direct PSHUFD is supported");
            }
            instruction.opcode = Opcode::PshufdRegRegImm;
            instruction.length = 5;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 5,
                        instruction.bytes.begin());
            instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
            instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>(modrm & 0x7U))});
            instruction.operands.push_back(ImmediateOperand{code[cursor + 4], 8});
            result.push_back(std::move(instruction));
            cursor += 5;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x66U) {
            const auto afterPrefix = cursor + 1U;
            const bool hasShufpdRex =
                afterPrefix < code.size() && code[afterPrefix] >= 0x40U &&
                code[afterPrefix] <= 0x4FU;
            const auto opcodeOffset =
                afterPrefix + (hasShufpdRex ? 1U : 0U);
            if (code.size() - opcodeOffset >= 2 &&
                code[opcodeOffset] == 0x0FU &&
                code[opcodeOffset + 1] == 0xC6U) {
                if (code.size() - opcodeOffset < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated shufpd xmm, xmm, imm8");
                }
                const auto rex = hasShufpdRex ? code[afterPrefix] : 0U;
                const auto modrm = code[opcodeOffset + 2];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                if (mode != 0x3U) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct SHUFPD is supported");
                }
                instruction.opcode = Opcode::ShufpdRegRegImm;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) |
                        ((rex & 0x4U) != 0 ? 0x8U : 0U)))});
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        (modrm & 0x7U) |
                        ((rex & 0x1U) != 0 ? 0x8U : 0U)))});
                instruction.operands.push_back(
                    ImmediateOperand{code[opcodeOffset + 3], 8});
                const auto operandCursor = opcodeOffset + 4;
                const auto length = operandCursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
        }

        const bool movqStoreHasRex =
            code.size() - cursor >= 4 && code[cursor] == 0x66U &&
            code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU &&
            code[cursor + 2] == 0x0FU && code[cursor + 3] == 0xD6U;
        const bool movqStoreWithoutRex =
            code.size() - cursor >= 3 && code[cursor] == 0x66U &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0xD6U;
        if (movqStoreHasRex || movqStoreWithoutRex) {
            const auto rex = movqStoreHasRex ? code[cursor + 1] : 0U;
            const auto modrmOffset = cursor + (movqStoreHasRex ? 4U : 3U);
            if (modrmOffset >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated movq [memory], xmm");
            }
            const auto modrm = code[modrmOffset];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVQ [base+index*scale+disp8/disp32], xmm memory operands are supported");
            }
            auto operandCursor = modrmOffset + 1;
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVQ memory SIB");
                }
                const auto sib = code[operandCursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base MOVQ memory SIB is not supported");
                }
                if (indexEncoding != 0x4U || (rex & 0x2U) != 0) {
                    index = decodeRegister(indexEncoding,
                                           (rex & 0x2U) != 0);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVQ memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVQ memory disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            instruction.opcode = Opcode::MovqMemXmm;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(baseEncoding, (rex & 0x1U) != 0),
                displacement, 64, index, scale});
            instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>(((modrm >> 3U) & 0x7U) |
                                          ((rex & 0x4U) != 0 ? 8U
                                                             : 0U)))});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0xF3U && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x11U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOVSS [memory], xmm");
            }
            const auto modrm = code[cursor + 3];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U || (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only based no-index MOVSS [memory], xmm is supported");
            }
            auto operandCursor = cursor + 4;
            auto baseEncoding = rmEncoding;
            if (rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVSS store SIB byte");
                }
                const auto sib = code[operandCursor++];
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (indexEncoding != 0x4U ||
                    (mode == 0 && baseEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only based no-index MOVSS store SIB operands are supported");
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVSS store disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVSS store disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            instruction.opcode = Opcode::MovssMemXmm;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(baseEncoding, false), displacement, 32});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    (modrm >> 3U) & 0x7U))});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            result.push_back(std::move(instruction));
            cursor += 4;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        const bool movupsStoreHasRex =
            code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
        const auto movupsStoreOpcodeOffset =
            cursor + (movupsStoreHasRex ? 1U : 0U);
        if (code.size() - movupsStoreOpcodeOffset >= 2 &&
            code[movupsStoreOpcodeOffset] == 0x0FU &&
            code[movupsStoreOpcodeOffset + 1] == 0x11U) {
            if (code.size() - movupsStoreOpcodeOffset < 3) {
                throw DecodeError(address, remaining, "truncated movups [base+disp], xmm");
            }
            const auto rex = movupsStoreHasRex ? code[cursor] : 0U;
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
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
              code[movupsLoadOpcodeOffset + 1] == 0x28U))) {
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
            if (movapdLoad && mode == 0x3U) {
                instruction.opcode = Opcode::MovapdRegReg;
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
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (mode > 0x2U) {
                throw DecodeError(
                    address, remaining,
                    "only MOVAPD/MOVAPS/MOVUPS xmm, [base+index*scale/RIP+disp] memory operands are supported");
            }
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
            instruction.opcode = movapdLoad ? Opcode::MovapdRegMem
                                 : aligned   ? Opcode::MovapsRegMem
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
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            result.push_back(std::move(instruction));
            cursor += 6;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
                result.push_back(std::move(instruction));
                cursor += 7;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
                if (rexW || mode != 0x3U) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct PINSRB xmm, r32, imm8 is supported");
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
                result.push_back(std::move(instruction));
                cursor = opcodeOffset + 5;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
            result.push_back(std::move(instruction));
            cursor += 6;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
                result.push_back(std::move(instruction));
                cursor += 4;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0xF3U && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0xA4U) {
            instruction.opcode = Opcode::RepMovsb;
            instruction.length = 2;
            instruction.bytes[0] = code[cursor];
            instruction.bytes[1] = code[cursor + 1];
            result.push_back(std::move(instruction));
            cursor += 2;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            result.push_back(std::move(instruction));
            cursor = operandCursor;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
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
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
        }

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
            result.push_back(std::move(instruction));
            return result;
        }

        const bool hasBranchHint =
            code[cursor] == 0x2EU && code.size() - cursor >= 2 &&
            code[cursor + 1] >= 0x70U && code[cursor + 1] <= 0x7FU;
        const auto controlOffset = cursor + (hasBranchHint ? 1U : 0U);
        if (code[controlOffset] == 0xEBU || code[controlOffset] == 0x72U ||
            code[controlOffset] == 0x73U || code[controlOffset] == 0x74U ||
            code[controlOffset] == 0x75U || code[controlOffset] == 0x76U ||
            code[controlOffset] == 0x77U || code[controlOffset] == 0x78U ||
            code[controlOffset] == 0x79U || code[controlOffset] == 0x7CU ||
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
                instruction.condition = opcode == 0x72U   ? Condition::Below
                                        : opcode == 0x73U ? Condition::AboveOrEqual
                                        : opcode == 0x74U ? Condition::Equal
                                        : opcode == 0x75U ? Condition::NotEqual
                                        : opcode == 0x76U ? Condition::BelowOrEqual
                                        : opcode == 0x78U ? Condition::Sign
                                        : opcode == 0x79U ? Condition::NotSign
                                        : opcode == 0x7CU ? Condition::Less
                                        : opcode == 0x7DU ? Condition::GreaterOrEqual
                                        : opcode == 0x7EU ? Condition::LessOrEqual
                                        : opcode == 0x7FU ? Condition::Greater
                                                          : Condition::Above;
            }
            result.push_back(std::move(instruction));
            return result;
        }

        if (code[cursor] == 0xF0U && code.size() - cursor >= 3 &&
            code[cursor + 1] >= 0x48U && code[cursor + 1] <= 0x4FU &&
            (code[cursor + 1] & 0x8U) != 0 && code[cursor + 2] == 0x01U) {
            const auto rex = code[cursor + 1];
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            cursor += 3;
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated LOCK ADD qword memory operand");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (mode == 0x3U || rmEncoding == 0x4U) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK ADD qword [base/RIP+disp8/disp32], r64 is supported");
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative LOCK ADD disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK ADD disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK ADD disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            instruction.opcode = Opcode::LockAddMemReg;
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 64,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(rmEncoding, rexB),
                                    displacement, 64});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, rexR), 64});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        const bool wordLockOrHasRex =
            code.size() - cursor >= 4 && code[cursor] == 0x66U &&
            code[cursor + 1] == 0xF0U && code[cursor + 2] >= 0x40U &&
            code[cursor + 2] <= 0x4FU &&
            (code[cursor + 3] == 0x81U ||
             code[cursor + 3] == 0x83U);
        const bool wordLockOrWithoutRex =
            code.size() - cursor >= 3 && code[cursor] == 0x66U &&
            code[cursor + 1] == 0xF0U &&
            (code[cursor + 2] == 0x81U ||
             code[cursor + 2] == 0x83U);
        if (wordLockOrHasRex || wordLockOrWithoutRex) {
            const auto rex = wordLockOrHasRex ? code[cursor + 2] : 0U;
            const auto immediateOpcode =
                code[cursor + (wordLockOrHasRex ? 3U : 2U)];
            if ((rex & 0x8U) != 0) {
                throw DecodeError(address, remaining,
                                  "REX.W is invalid for word LOCK OR");
            }
            cursor += wordLockOrHasRex ? 4U : 3U;
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated word LOCK OR memory operand");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U || extension != 0x1U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only word LOCK OR [base+disp8/disp32], imm8 is supported");
            }
            auto base = decodeRegister(rmEncoding, (rex & 0x1U) != 0);
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated word LOCK OR SIB");
                }
                const auto sib = code[cursor++];
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (indexEncoding != 0x4U || (rex & 0x2U) != 0 ||
                    (mode == 0 && baseEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only no-index, based SIB is supported for word LOCK OR");
                }
                base = decodeRegister(baseEncoding, (rex & 0x1U) != 0);
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated word LOCK OR disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated word LOCK OR disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            std::uint64_t immediate = 0;
            std::uint8_t immediateWidth = 0;
            if (immediateOpcode == 0x83U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated word LOCK OR imm8");
                }
                immediate = static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(
                        std::bit_cast<std::int8_t>(code[cursor++])));
                immediateWidth = 8;
            } else {
                if (code.size() - cursor < 2) {
                    throw DecodeError(address, remaining,
                                      "truncated word LOCK OR imm16");
                }
                immediate = static_cast<std::uint16_t>(
                    static_cast<std::uint16_t>(code[cursor]) |
                    (static_cast<std::uint16_t>(code[cursor + 1]) << 8U));
                cursor += 2;
                immediateWidth = 16;
            }
            instruction.opcode = Opcode::LockOrMemImm;
            instruction.operands.push_back(
                MemoryOperand{base, displacement, 16});
            instruction.operands.push_back(
                ImmediateOperand{immediate, immediateWidth});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0xF0U && code.size() - cursor >= 2 &&
            (code[cursor + 1] == 0x81U ||
             code[cursor + 1] == 0x83U)) {
            const auto immediateOpcode = code[cursor + 1];
            cursor += 2;
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated LOCK OR memory operand");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U || extension != 0x1U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK OR dword [base+disp8/disp32], imm8/imm32 is supported");
            }
            auto base = decodeRegister(rmEncoding, false);
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK OR SIB");
                }
                const auto sib = code[cursor++];
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (indexEncoding != 0x4U ||
                    (mode == 0 && baseEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only no-index, based SIB is supported for LOCK OR");
                }
                base = decodeRegister(baseEncoding, false);
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK OR disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK OR disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            std::uint64_t immediate = 0;
            std::uint8_t immediateWidth = 0;
            if (immediateOpcode == 0x83U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK OR imm8");
                }
                immediate = static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(
                        std::bit_cast<std::int8_t>(code[cursor++])));
                immediateWidth = 8;
            } else {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK OR imm32");
                }
                immediate = static_cast<std::uint32_t>(
                    static_cast<std::uint32_t>(code[cursor]) |
                    (static_cast<std::uint32_t>(code[cursor + 1]) << 8U) |
                    (static_cast<std::uint32_t>(code[cursor + 2]) << 16U) |
                    (static_cast<std::uint32_t>(code[cursor + 3]) << 24U));
                cursor += 4;
                immediateWidth = 32;
            }
            instruction.opcode = Opcode::LockOrMemImm;
            instruction.operands.push_back(
                MemoryOperand{base, displacement, 32});
            instruction.operands.push_back(
                ImmediateOperand{immediate, immediateWidth});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0xF0U && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0xFFU) {
            cursor += 2;
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated LOCK INC/DEC memory operand");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (mode == 0x3U || extension > 1U || rmEncoding == 0x4U) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK INC/DEC dword [base/RIP+disp8/disp32] is supported");
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(
                        address, remaining,
                        "truncated RIP-relative LOCK INC/DEC disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK INC/DEC disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK INC/DEC disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = extension == 0U ? Opcode::LockIncMem
                                                 : Opcode::LockDecMem;
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 32,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(rmEncoding, false),
                                    displacement, 32});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0xF0U && code.size() - cursor >= 4 &&
            code[cursor + 1] >= 0x48U && code[cursor + 1] <= 0x4FU &&
            code[cursor + 2] == 0x0FU && code[cursor + 3] == 0xC7U) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining,
                                  "truncated LOCK CMPXCHG16B memory operand");
            }
            const auto rex = code[cursor + 1];
            const bool rexB = (rex & 0x1U) != 0;
            const auto modrm = code[cursor + 4];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || extension != 0x1U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK CMPXCHG16B [base+disp8/disp32] is supported");
            }
            cursor += 5;
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK CMPXCHG16B disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK CMPXCHG16B disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::Cmpxchg16bMem;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, rexB), displacement, 128});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0xF0U) {
            auto xaddCursor = cursor + 1;
            const bool hasXaddRex =
                xaddCursor < code.size() && code[xaddCursor] >= 0x40U &&
                code[xaddCursor] <= 0x4FU;
            const auto xaddRex =
                hasXaddRex ? code[xaddCursor++] : std::uint8_t{0};
            const bool isXadd = code.size() - xaddCursor >= 2 &&
                                code[xaddCursor] == 0x0FU &&
                                code[xaddCursor + 1] == 0xC1U;
            if (isXadd) {
                cursor = xaddCursor + 2;
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK XADD memory operand");
                }
                const auto modrm = code[cursor++];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                const auto regEncoding =
                    static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
                const auto rmEncoding =
                    static_cast<std::uint8_t>(modrm & 0x7U);
                const bool rexW = (xaddRex & 0x8U) != 0;
                const bool rexR = (xaddRex & 0x4U) != 0;
                const bool rexX = (xaddRex & 0x2U) != 0;
                const bool rexB = (xaddRex & 0x1U) != 0;
                const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
                if (mode == 0x3U || rmEncoding == 0x4U || rexX ||
                    (mode == 0 && rmEncoding == 0x5U && rexB)) {
                    throw DecodeError(
                        address, remaining,
                        "only LOCK XADD dword/qword [base/RIP+disp8/disp32], r32/r64 is supported");
                }
                std::int64_t displacement = 0;
                if (ripRelative || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated LOCK XADD disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated LOCK XADD disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                const auto width =
                    static_cast<std::uint8_t>(rexW ? 64U : 32U);
                instruction.opcode = Opcode::LockXaddMemReg;
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, width,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{decodeRegister(rmEncoding, rexB),
                                        displacement, width});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(regEncoding, rexR), width});
                const auto length = cursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
        }

        if (code[cursor] == 0xF0U) {
            auto operandCursor = cursor + 1;
            if (operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated after LOCK prefix");
            }
            const bool hasLockRex = code[operandCursor] >= 0x40U &&
                                    code[operandCursor] <= 0x4FU;
            const auto lockRex =
                hasLockRex ? code[operandCursor++] : std::uint8_t{0};
            const bool lockRexW = (lockRex & 0x8U) != 0;
            const bool lockRexR = (lockRex & 0x4U) != 0;
            const bool lockRexX = (lockRex & 0x2U) != 0;
            const bool lockRexB = (lockRex & 0x1U) != 0;
            if (code.size() - operandCursor >= 2 && code[operandCursor] == 0xFFU) {
                const auto modrm = code[operandCursor + 1];
                const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
                const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
                const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !lockRexB;
                if (extension != 0x1U || mode > 0x2U || lockRexR || lockRexX ||
                    (mode == 0 && rmEncoding == 0x5U && lockRexB) || rmEncoding == 0x4U) {
                    throw DecodeError(
                        address, remaining,
                        "only LOCK DEC dword/qword [base/RIP+disp8/disp32] is supported from prefix F0 FF /1");
                }
                operandCursor += 2;
                std::int64_t displacement = 0;
                if (ripRelative || mode == 0x2U) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated LOCK DEC disp32");
                    }
                    displacement = readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                } else if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated LOCK DEC disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, operandCursor - instructionStart, displacement));
                }
                const auto width = static_cast<std::uint8_t>(lockRexW ? 64U : 32U);
                instruction.opcode = Opcode::LockDecMem;
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, width,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{decodeRegister(rmEncoding, lockRexB),
                                        displacement, width});
                const auto length = operandCursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (code.size() - operandCursor < 3 ||
                code[operandCursor] != 0x0FU ||
                code[operandCursor + 1] != 0xB1U) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK CMPXCHG r/m32/r64 or LOCK XADD r/m32, r32 is supported from prefix F0");
            }
            cursor = operandCursor + 2;
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool rexW = (lockRex & 0x8U) != 0;
            const bool rexR = (lockRex & 0x4U) != 0;
            const bool rexX = (lockRex & 0x2U) != 0;
            const bool rexB = (lockRex & 0x1U) != 0;
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U && !rexB;
            auto baseEncoding = rmEncoding;
            bool hasBase = !ripRelative;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK CMPXCHG SIB byte");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                hasBase = !(mode == 0 && baseEncoding == 0x5U && !rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                }
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
            if (mode == 0x3U ||
                (mode == 0 && rmEncoding == 0x5U && rexB) ||
                (rmEncoding != 0x4U && rexX)) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK CMPXCHG dword/qword memory operands are supported");
            }
            std::int64_t displacement = 0;
            if (ripRelative || !hasBase) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(
                        address, remaining,
                        "truncated displacement-only LOCK CMPXCHG operand");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK CMPXCHG disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK CMPXCHG disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.opcode = Opcode::CmpxchgMemReg;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(baseEncoding, rexB), displacement, width,
                index, scale, hasBase, ripRelative});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, rexR), width});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

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
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
                result.push_back(std::move(instruction));
                cursor += 3;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
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
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (code.size() - cursor >= 3 &&
                code[cursor + 1] == 0xAFU) {
                const auto modrm = code[cursor + 2];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                if (mode != 0x3U) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct IMUL r32, r32 is supported without REX");
                }
                instruction.opcode = Opcode::ImulRegReg;
                instruction.length = 3;
                std::copy_n(
                    code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                    instruction.bytes.begin());
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(
                                       (modrm >> 3U) & 0x7U),
                                   false),
                    32});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U),
                                   false),
                    32});
                result.push_back(std::move(instruction));
                cursor += 3;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (code.size() - cursor < 6 ||
                (code[cursor + 1] != 0x80U &&
                 code[cursor + 1] != 0x82U && code[cursor + 1] != 0x83U &&
                 code[cursor + 1] != 0x84U &&
                 code[cursor + 1] != 0x85U && code[cursor + 1] != 0x86U &&
                 code[cursor + 1] != 0x87U && code[cursor + 1] != 0x88U &&
                 code[cursor + 1] != 0x89U &&
                 code[cursor + 1] != 0x8CU &&
                 code[cursor + 1] != 0x8DU &&
                 code[cursor + 1] != 0x8EU &&
                 code[cursor + 1] != 0x8FU)) {
                throw DecodeError(address, remaining,
                                  "only JO/JB/JAE/JE/JNE/JBE/JA/JS/JNS/JL/JGE/JLE/JG rel32 from opcode 0F is supported");
            }
            const auto secondOpcode = code[cursor + 1];
            const auto displacement = readI32(code.subspan(cursor + 2, 4));
            instruction.opcode = Opcode::JccRelative;
            instruction.condition = secondOpcode == 0x80U   ? Condition::Overflow
                                    : secondOpcode == 0x82U ? Condition::Below
                                    : secondOpcode == 0x83U ? Condition::AboveOrEqual
                                    : secondOpcode == 0x84U ? Condition::Equal
                                    : secondOpcode == 0x85U ? Condition::NotEqual
                                    : secondOpcode == 0x86U ? Condition::BelowOrEqual
                                    : secondOpcode == 0x87U ? Condition::Above
                                    : secondOpcode == 0x88U ? Condition::Sign
                                    : secondOpcode == 0x89U ? Condition::NotSign
                                    : secondOpcode == 0x8CU ? Condition::Less
                                    : secondOpcode == 0x8DU ? Condition::GreaterOrEqual
                                    : secondOpcode == 0x8EU ? Condition::LessOrEqual
                                                            : Condition::Greater;
            instruction.length = 6;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 6,
                        instruction.bytes.begin());
            instruction.branchTarget = relativeTarget(address, 6, displacement);
            instruction.fallthrough = guest::GuestAddress{address.value + 6};
            result.push_back(std::move(instruction));
            return result;
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
                result.push_back(std::move(instruction));
                cursor = operandCursor;
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
        }

        const bool hasOperandSizeOverride = code[cursor] == 0x66U;
        if (hasOperandSizeOverride) {
            ++cursor;
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated after operand-size override");
            }
        }
        const bool hasGsOverride = code[cursor] == 0x65U;
        if (hasGsOverride) {
            ++cursor;
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated after GS segment override");
            }
        }
        const bool hasRex = code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
        if (!hasRex && code[cursor] != 0x05U &&
            code[cursor] != 0x24U && code[cursor] != 0x25U &&
            code[cursor] != 0x34U &&
            code[cursor] != 0x00U && code[cursor] != 0x01U &&
            code[cursor] != 0x02U && code[cursor] != 0x03U &&
            code[cursor] != 0x19U && code[cursor] != 0x1CU &&
            code[cursor] != 0x0CU &&
            code[cursor] != 0x88U &&
            code[cursor] != 0x89U &&
            code[cursor] != 0x8AU && code[cursor] != 0x8BU &&
            code[cursor] != 0x8DU &&
            code[cursor] != 0x85U && code[cursor] != 0x83U &&
            code[cursor] != 0x84U && code[cursor] != 0x30U &&
            code[cursor] != 0x31U &&
            code[cursor] != 0x32U &&
            code[cursor] != 0x20U && code[cursor] != 0x21U &&
            code[cursor] != 0x22U && code[cursor] != 0x23U &&
            code[cursor] != 0x08U &&
            code[cursor] != 0x09U && code[cursor] != 0x0AU &&
            code[cursor] != 0x0BU &&
            code[cursor] != 0x2DU &&
            code[cursor] != 0x69U &&
            code[cursor] != 0x87U &&
            code[cursor] != 0x28U && code[cursor] != 0x29U &&
            code[cursor] != 0x2BU &&
            code[cursor] != 0x33U &&
            code[cursor] != 0x38U && code[cursor] != 0x39U &&
            code[cursor] != 0x3AU &&
            code[cursor] != 0x3BU &&
            code[cursor] != 0x80U &&
            code[cursor] != 0x81U && code[cursor] != 0xC0U &&
            code[cursor] != 0xC1U && code[cursor] != 0x98U &&
            code[cursor] != 0xC6U && code[cursor] != 0xC7U &&
            code[cursor] != 0xD0U && code[cursor] != 0xD1U &&
            code[cursor] != 0xD2U &&
            code[cursor] != 0xD3U &&
            code[cursor] != 0xF7U &&
            code[cursor] != 0xFEU && code[cursor] != 0xFFU) {
            throw DecodeError(address, remaining, "expected REX prefix");
        }
        const auto rex = hasRex ? code[cursor] : 0U;
        const bool rexW = (rex & 0x8U) != 0;
        const bool rexB = (rex & 0x1U) != 0;
        const bool rexX = (rex & 0x2U) != 0;
        const bool rexR = (rex & 0x4U) != 0;
        if (hasRex) {
            ++cursor;
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated after REX prefix");
            }
        }

        const auto opcode = code[cursor++];
        if (hasOperandSizeOverride && opcode != 0x03U && opcode != 0x0BU && opcode != 0x39U &&
            opcode != 0x3BU && opcode != 0x89U && opcode != 0x8BU && opcode != 0xF7U &&
            opcode != 0xFFU) {
            throw DecodeError(
                address, remaining,
                "operand-size override is only supported for 16-bit ADD, OR, CMP, MOV, and memory INC in the general decoder");
        }
        if (hasGsOverride && opcode != 0x89U && opcode != 0x8BU &&
            opcode != 0xC7U &&
            opcode != 0x39U && opcode != 0x3BU) {
            throw DecodeError(address, remaining,
                              "GS segment override is only supported for MOV/CMP register/memory");
        }
        if (!rexW && opcode != 0x05U && opcode != 0x0DU && opcode != 0x24U &&
            opcode != 0x25U && opcode != 0x34U &&
            opcode != 0x00U && opcode != 0x01U && opcode != 0x02U &&
            opcode != 0x03U &&
            opcode != 0x19U && opcode != 0x1CU && opcode != 0x0CU &&
            opcode != 0x88U && opcode != 0x89U &&
            opcode != 0x8AU &&
            opcode != 0x8BU && opcode != 0x85U &&
            opcode != 0x8DU &&
            opcode != 0x08U && opcode != 0x09U && opcode != 0x0AU &&
            opcode != 0x0BU &&
            opcode != 0x2DU &&
            opcode != 0x69U &&
            opcode != 0x87U &&
            opcode != 0x84U && opcode != 0x83U && opcode != 0x3BU &&
            opcode != 0x3AU &&
            opcode != 0x30U && opcode != 0x31U && opcode != 0x32U &&
            opcode != 0x38U && opcode != 0x39U &&
            opcode != 0x80U &&
            opcode != 0x28U && opcode != 0x29U && opcode != 0x2BU &&
            opcode != 0x33U &&
            opcode != 0x20U && opcode != 0x21U && opcode != 0x22U &&
            opcode != 0x23U &&
            opcode != 0x0FU &&
            opcode != 0x81U && opcode != 0xC0U && opcode != 0xC1U &&
            opcode != 0x98U &&
            opcode != 0xC6U && opcode != 0xC7U && opcode != 0xD0U &&
            opcode != 0xD1U &&
            opcode != 0xD2U &&
            opcode != 0xD3U &&
            opcode != 0xF7U &&
            opcode != 0xFEU && opcode != 0xFFU &&
            (opcode < 0xB0U || opcode > 0xB7U) &&
            (opcode < 0xB8U || opcode > 0xBFU)) {
            throw DecodeError(address, remaining,
                              "only a 32-bit memory MOV is supported without REX.W");
        }
        if (opcode == 0x0DU) {
            if (code.size() - cursor < sizeof(std::uint32_t)) {
                throw DecodeError(address, remaining,
                                  "truncated or accumulator, imm32");
            }
            const auto immediate =
                readI32(code.subspan(cursor, sizeof(std::uint32_t)));
            cursor += sizeof(std::uint32_t);
            instruction.opcode = Opcode::OrRegImm;
            instruction.operands.push_back(RegisterOperand{
                Register::Rax,
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            instruction.operands.push_back(ImmediateOperand{
                rexW ? static_cast<std::uint64_t>(
                           static_cast<std::int64_t>(immediate))
                     : static_cast<std::uint64_t>(
                           static_cast<std::uint32_t>(immediate)),
                32});
        } else if (opcode == 0x24U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated and al, imm8");
            }
            instruction.opcode = Opcode::AndRegImm;
            instruction.operands.push_back(RegisterOperand{Register::Rax, 8});
            instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
        } else if (opcode == 0x25U) {
            if (code.size() - cursor < sizeof(std::uint32_t)) {
                throw DecodeError(address, remaining,
                                  "truncated and accumulator, imm32");
            }
            const auto immediate =
                readI32(code.subspan(cursor, sizeof(std::uint32_t)));
            cursor += sizeof(std::uint32_t);
            instruction.opcode = Opcode::AndRegImm;
            instruction.operands.push_back(RegisterOperand{
                Register::Rax,
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            instruction.operands.push_back(ImmediateOperand{
                rexW ? static_cast<std::uint64_t>(
                           static_cast<std::int64_t>(immediate))
                     : static_cast<std::uint64_t>(
                           static_cast<std::uint32_t>(immediate)),
                32});
        } else if (opcode == 0x34U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated xor al, imm8");
            }
            instruction.opcode = Opcode::XorRegImm;
            instruction.operands.push_back(RegisterOperand{Register::Rax, 8});
            instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
        } else if (opcode == 0x0CU) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated or al, imm8");
            }
            instruction.opcode = Opcode::OrRegImm;
            instruction.operands.push_back(RegisterOperand{Register::Rax, 8});
            instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
        } else if (opcode == 0x1CU) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated sbb al, imm8");
            }
            instruction.opcode = Opcode::SbbRegImm;
            instruction.operands.push_back(RegisterOperand{Register::Rax, 8});
            instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
        } else if (opcode == 0x05U) {
            if (code.size() - cursor < sizeof(std::uint32_t)) {
                throw DecodeError(address, remaining,
                                  "truncated add rax, imm32");
            }
            const auto immediate =
                readI32(code.subspan(cursor, sizeof(std::uint32_t)));
            cursor += sizeof(std::uint32_t);
            instruction.opcode = Opcode::AddRegImm;
            instruction.operands.push_back(RegisterOperand{
                Register::Rax,
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            instruction.operands.push_back(ImmediateOperand{
                rexW ? static_cast<std::uint64_t>(
                           static_cast<std::int64_t>(immediate))
                     : static_cast<std::uint64_t>(
                           static_cast<std::uint32_t>(immediate)),
                32});
        } else if (opcode == 0x2DU) {
            if (code.size() - cursor < sizeof(std::uint32_t)) {
                throw DecodeError(address, remaining,
                                  "truncated sub accumulator, imm32");
            }
            const auto immediate =
                readI32(code.subspan(cursor, sizeof(std::uint32_t)));
            cursor += sizeof(std::uint32_t);
            instruction.opcode = Opcode::SubRegImm;
            instruction.operands.push_back(RegisterOperand{
                Register::Rax,
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            instruction.operands.push_back(ImmediateOperand{
                rexW ? static_cast<std::uint64_t>(
                           static_cast<std::int64_t>(immediate))
                     : static_cast<std::uint64_t>(
                           static_cast<std::uint32_t>(immediate)),
                32});
        } else if (opcode == 0x98U && rexW) {
            instruction.opcode = Opcode::Cdqe;
        } else if (opcode == 0x98U && !hasRex) {
            instruction.opcode = Opcode::Cwde;
        } else if (hasRex && opcode >= 0xB0U && opcode <= 0xB7U) {
            instruction.opcode = Opcode::MovRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(opcode - 0xB0U), rexB), 8});
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated mov low-byte register, imm8");
            }
            instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
        } else if (opcode >= 0xB8U && opcode <= 0xBFU) {
            const auto immediateSize = rexW ? sizeof(std::uint64_t) : sizeof(std::uint32_t);
            if (code.size() - cursor < immediateSize) {
                throw DecodeError(address, remaining, "truncated mov register, immediate");
            }
            const auto immediate = rexW
                                       ? readU64(code.subspan(cursor, immediateSize))
                                       : static_cast<std::uint64_t>(static_cast<std::uint32_t>(
                                             readI32(code.subspan(cursor, immediateSize))));
            instruction.opcode = Opcode::MovRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(opcode - 0xB8U), rexB),
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            instruction.operands.push_back(
                ImmediateOperand{immediate, static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            cursor += immediateSize;
        } else if (opcode == 0x35U && rexW) {
            if (code.size() - cursor < sizeof(std::uint32_t)) {
                throw DecodeError(address, remaining, "truncated xor rax, imm32");
            }
            const auto immediate = readI32(code.subspan(cursor, sizeof(std::uint32_t)));
            cursor += sizeof(std::uint32_t);
            instruction.opcode = Opcode::XorRegImm;
            instruction.operands.push_back(RegisterOperand{Register::Rax, 64});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 32});
        } else if (opcode == 0x3DU && rexW) {
            if (code.size() - cursor < sizeof(std::uint32_t)) {
                throw DecodeError(address, remaining,
                                  "truncated cmp rax, imm32");
            }
            const auto immediate =
                readI32(code.subspan(cursor, sizeof(std::uint32_t)));
            cursor += sizeof(std::uint32_t);
            instruction.opcode = Opcode::CmpRegImm;
            instruction.operands.push_back(
                RegisterOperand{Register::Rax, 64});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(immediate)),
                32});
        } else if (opcode == 0x69U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated IMUL ModRM byte");
            }
            const auto modrm = code[cursor++];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto width =
                static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(
                    static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
                width});
            if (mode == 0x3U) {
                instruction.opcode = Opcode::ImulRegRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U),
                                   rexB),
                    width});
            } else {
                const auto rmEncoding =
                    static_cast<std::uint8_t>(modrm & 0x7U);
                if (rmEncoding == 0x4U || rexX) {
                    throw DecodeError(
                        address, remaining,
                        "SIB-addressed IMUL memory source is not yet supported");
                }
                const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
                std::int64_t displacement = 0;
                if (mode == 1) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated IMUL disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 2 || ripRelative) {
                    if (code.size() - cursor < sizeof(std::uint32_t)) {
                        throw DecodeError(address, remaining,
                                          "truncated IMUL disp32");
                    }
                    displacement = readI32(
                        code.subspan(cursor, sizeof(std::uint32_t)));
                    cursor += sizeof(std::uint32_t);
                }
                instruction.opcode = Opcode::ImulRegMemImm;
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax
                                : decodeRegister(rmEncoding, rexB),
                    displacement, width, std::nullopt, 1, !ripRelative,
                    ripRelative});
            }
            if (code.size() - cursor < sizeof(std::uint32_t)) {
                throw DecodeError(address, remaining,
                                  "truncated IMUL imm32");
            }
            const auto immediate =
                readI32(code.subspan(cursor, sizeof(std::uint32_t)));
            cursor += sizeof(std::uint32_t);
            instruction.operands.push_back(ImmediateOperand{
                rexW ? static_cast<std::uint64_t>(
                           static_cast<std::int64_t>(immediate))
                     : static_cast<std::uint64_t>(
                           static_cast<std::uint32_t>(immediate)),
                32});
        } else if (opcode == 0x6BU && rexW) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining,
                                  "truncated imul r64, r64, imm8");
            }
            const auto modrm = code[cursor++];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct IMUL r64, r64, imm8 is supported");
            }
            const auto immediate =
                std::bit_cast<std::int8_t>(code[cursor++]);
            instruction.opcode = Opcode::ImulRegRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(
                    static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
                64});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                64});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(immediate)),
                8});
        } else if (opcode == 0x0FU) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated 0F opcode");
            }
            const auto secondOpcode = code[cursor++];
            if (secondOpcode != 0x40U && secondOpcode != 0x42U &&
                secondOpcode != 0x43U &&
                secondOpcode != 0x44U && secondOpcode != 0x45U &&
                secondOpcode != 0x46U &&
                secondOpcode != 0x47U &&
                secondOpcode != 0x48U &&
                secondOpcode != 0x49U &&
                secondOpcode != 0x4CU &&
                secondOpcode != 0x4DU &&
                secondOpcode != 0x4EU &&
                secondOpcode != 0x4FU &&
                secondOpcode != 0xA3U &&
                secondOpcode != 0xA4U &&
                secondOpcode != 0xBAU &&
                secondOpcode != 0xBEU &&
                secondOpcode != 0xACU &&
                secondOpcode != 0xAFU && secondOpcode != 0xBCU &&
                secondOpcode != 0xBDU) {
                throw DecodeError(
                    address, remaining,
                    "only CMOVO/CMOVB/CMOVAE/CMOVE/CMOVNE/CMOVA/CMOVS/CMOVNS/CMOVL/CMOVGE/CMOVLE/CMOVG, BT, MOVSX, IMUL, SHLD, SHRD, BSF, and BSR register forms are supported from REX 0F");
            }
            const bool isConditionalMove =
                secondOpcode == 0x40U || secondOpcode == 0x42U ||
                secondOpcode == 0x43U || secondOpcode == 0x44U ||
                secondOpcode == 0x45U || secondOpcode == 0x46U ||
                secondOpcode == 0x47U || secondOpcode == 0x48U ||
                secondOpcode == 0x49U || secondOpcode == 0x4CU ||
                secondOpcode == 0x4DU || secondOpcode == 0x4EU ||
                secondOpcode == 0x4FU;
            if (!rexW && !isConditionalMove && secondOpcode != 0xBAU &&
                secondOpcode != 0xA3U && secondOpcode != 0xBEU &&
                secondOpcode != 0xAFU &&
                secondOpcode != 0xBCU && secondOpcode != 0xBDU) {
                throw DecodeError(
                    address, remaining,
                    "only 32-bit register CMOV, BT, MOVSX, IMUL, BSF, or BSR is supported from non-W REX 0F");
            }
            if (cursor >= code.size() ||
                ((secondOpcode == 0xA4U || secondOpcode == 0xACU ||
                  secondOpcode == 0xBAU) &&
                 code.size() - cursor < 2)) {
                throw DecodeError(address, remaining,
                                  secondOpcode == 0xA4U ? "truncated SHLD r64"
                                  : secondOpcode == 0xACU ? "truncated SHRD r64"
                                  : secondOpcode == 0xBAU ? "truncated BT register, imm8"
                                  : secondOpcode == 0xAFU ? "truncated IMUL r64"
                                  : secondOpcode == 0xBCU ? "truncated BSF r64"
                                  : secondOpcode == 0xBDU ? "truncated BSR r64"
                                                          : "truncated CMOVB r64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool isImulRipMemory =
                secondOpcode == 0xAFU && rexW && mode == 0 &&
                rmEncoding == 0x5U && !rexB && !rexX;
            const bool isMovsxMemory =
                secondOpcode == 0xBEU && mode != 0x3U &&
                !(mode == 0 && rmEncoding == 0x5U);
            if ((!isImulRipMemory && !isMovsxMemory && mode != 0x3U) ||
                (rexX && secondOpcode != 0xBAU && !isMovsxMemory)) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct CMOVO/CMOVB/CMOVAE/CMOVE/CMOVNE/CMOVA/CMOVS/CMOVNS/CMOVL/CMOVGE/CMOVLE/BT/MOVSX/IMUL/SHLD/SHRD/BSF/BSR is supported");
            }
            const auto rawReg =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto encodedReg = decodeRegister(rawReg, rexR);
            const auto encodedRm =
                decodeRegister(rmEncoding, rexB);
            if (secondOpcode == 0xA3U) {
                const auto width =
                    static_cast<std::uint8_t>(rexW ? 64U : 32U);
                instruction.opcode = Opcode::BitTestRegReg;
                instruction.operands.push_back(
                    RegisterOperand{encodedRm, width});
                instruction.operands.push_back(
                    RegisterOperand{encodedReg, width});
            } else if (secondOpcode == 0xBAU) {
                if ((rawReg != 0x4U && rawReg != 0x5U &&
                     rawReg != 0x6U) ||
                    rexR || rexX) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct BT/BTS/BTR r32/r64, imm8 is supported from 0F BA");
                }
                instruction.opcode = rawReg == 0x4U   ? Opcode::BitTestRegImm
                                     : rawReg == 0x5U ? Opcode::BitSetRegImm
                                                      : Opcode::BitResetRegImm;
                instruction.operands.push_back(
                    RegisterOperand{
                        encodedRm,
                        static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(
                    ImmediateOperand{code[cursor++], 8});
            } else if (secondOpcode == 0xBEU) {
                if (isMovsxMemory) {
                    auto baseEncoding = rmEncoding;
                    std::optional<Register> index;
                    std::uint8_t scale = 1;
                    if (rmEncoding == 0x4U) {
                        if (cursor >= code.size()) {
                            throw DecodeError(
                                address, remaining,
                                "truncated MOVSX byte SIB");
                        }
                        const auto sib = code[cursor++];
                        const auto scaleBits =
                            static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                        const auto indexEncoding =
                            static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                        baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                        if (mode == 0 && baseEncoding == 0x5U && !rexB) {
                            throw DecodeError(
                                address, remaining,
                                "no-base MOVSX byte SIB is not supported");
                        }
                        if (indexEncoding != 0x4U || rexX) {
                            index = decodeRegister(indexEncoding, rexX);
                            scale = static_cast<std::uint8_t>(1U << scaleBits);
                        }
                    }
                    std::int64_t displacement = 0;
                    if (mode == 0x1U) {
                        if (cursor >= code.size()) {
                            throw DecodeError(
                                address, remaining,
                                "truncated MOVSX r64 byte disp8");
                        }
                        displacement =
                            std::bit_cast<std::int8_t>(code[cursor++]);
                    } else if (mode == 0x2U) {
                        if (code.size() - cursor < 4) {
                            throw DecodeError(
                                address, remaining,
                                "truncated MOVSX r64 byte disp32");
                        }
                        displacement =
                            readI32(code.subspan(cursor, 4));
                        cursor += 4;
                    }
                    instruction.opcode = Opcode::MovsxRegMem;
                    instruction.operands.push_back(
                        RegisterOperand{
                            encodedReg,
                            static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                    instruction.operands.push_back(MemoryOperand{
                        rmEncoding == 0x4U ? decodeRegister(baseEncoding, rexB) : encodedRm,
                        displacement, 8, index, scale});
                } else if (rexX) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct MOVSX r32/r64, r8 is supported from REX 0F BE");
                } else {
                    instruction.opcode = Opcode::MovsxRegReg;
                    instruction.operands.push_back(
                        RegisterOperand{encodedReg,
                                        static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                    instruction.operands.push_back(
                        RegisterOperand{encodedRm, 8});
                }
            } else if (isConditionalMove) {
                instruction.opcode = Opcode::CmovccReg;
                instruction.condition = secondOpcode == 0x42U
                                            ? Condition::Below
                                        : secondOpcode == 0x43U
                                            ? Condition::AboveOrEqual
                                        : secondOpcode == 0x45U
                                            ? Condition::NotEqual
                                        : secondOpcode == 0x46U
                                            ? Condition::BelowOrEqual
                                        : secondOpcode == 0x47U
                                            ? Condition::Above
                                        : secondOpcode == 0x48U
                                            ? Condition::Sign
                                        : secondOpcode == 0x49U
                                            ? Condition::NotSign
                                        : secondOpcode == 0x4EU
                                            ? Condition::LessOrEqual
                                        : secondOpcode == 0x4FU
                                            ? Condition::Greater
                                        : secondOpcode == 0x4CU
                                            ? Condition::Less
                                        : secondOpcode == 0x4DU
                                            ? Condition::GreaterOrEqual
                                        : secondOpcode == 0x40U
                                            ? Condition::Overflow
                                            : Condition::Equal;
                const auto width =
                    static_cast<std::uint8_t>(rexW ? 64U : 32U);
                instruction.operands.push_back(
                    RegisterOperand{encodedReg, width});
                instruction.operands.push_back(
                    RegisterOperand{encodedRm, width});
            } else if (secondOpcode == 0xBCU) {
                instruction.opcode = Opcode::BitScanForwardRegReg;
                const auto width =
                    static_cast<std::uint8_t>(rexW ? 64U : 32U);
                instruction.operands.push_back(RegisterOperand{encodedReg, width});
                instruction.operands.push_back(RegisterOperand{encodedRm, width});
            } else if (secondOpcode == 0xBDU) {
                instruction.opcode = Opcode::BitScanReverseRegReg;
                const auto width =
                    static_cast<std::uint8_t>(rexW ? 64U : 32U);
                instruction.operands.push_back(RegisterOperand{encodedReg, width});
                instruction.operands.push_back(RegisterOperand{encodedRm, width});
            } else if (secondOpcode == 0xAFU) {
                const auto width =
                    static_cast<std::uint8_t>(rexW ? 64U : 32U);
                instruction.operands.push_back(
                    RegisterOperand{encodedReg, width});
                if (isImulRipMemory) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated IMUL RIP displacement");
                    }
                    const auto displacement =
                        readI32(code.subspan(cursor, 4));
                    cursor += 4;
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                    instruction.opcode = Opcode::ImulRegMem;
                    instruction.operands.push_back(MemoryOperand{
                        Register::Rax, displacement, 64, std::nullopt, 1,
                        false, true});
                } else {
                    instruction.opcode = Opcode::ImulRegReg;
                    instruction.operands.push_back(
                        RegisterOperand{encodedRm, width});
                }
            } else if (secondOpcode == 0xA4U) {
                instruction.opcode = Opcode::ShldRegRegImm;
                instruction.operands.push_back(RegisterOperand{encodedRm, 64});
                instruction.operands.push_back(RegisterOperand{encodedReg, 64});
                instruction.operands.push_back(
                    ImmediateOperand{code[cursor++], 8});
            } else {
                instruction.opcode = Opcode::ShrdRegRegImm;
                instruction.operands.push_back(RegisterOperand{encodedRm, 64});
                instruction.operands.push_back(RegisterOperand{encodedReg, 64});
                instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
            }
        } else if (opcode == 0x00U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated add r8, r8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto sourceEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto destinationEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode != 0x3U ||
                (!hasRex &&
                 (sourceEncoding >= 0x4U || destinationEncoding >= 0x4U))) {
                throw DecodeError(
                    address, remaining,
                    "only representable register-direct ADD r8, r8 is supported");
            }
            instruction.opcode = Opcode::AddRegReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(destinationEncoding, rexB), 8});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(sourceEncoding, rexR), 8});
        } else if (opcode == 0x02U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated add r8, byte [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto destinationEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U || (!hasRex && destinationEncoding >= 0x4U) ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only ADD r8, byte [base+index*scale+disp8/disp32] is supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated ADD byte memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base ADD byte SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated ADD byte memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated ADD byte memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::AddRegMem;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(destinationEncoding, rexR), 8});
            instruction.operands.push_back(
                MemoryOperand{base, displacement, 8, index, scale});
        } else if (opcode == 0x01U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated add r/m64, r64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto source = decodeRegister(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            if (mode == 0x3U) {
                const auto destination = decodeRegister(rmEncoding, rexB);
                const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
                instruction.opcode = Opcode::AddRegReg;
                instruction.operands.push_back(RegisterOperand{destination, width});
                instruction.operands.push_back(RegisterOperand{source, width});
            } else {
                if (hasOperandSizeOverride || mode > 0x2U ||
                    (rexX && rmEncoding != 0x4U)) {
                    throw DecodeError(
                        address, remaining,
                        "unsupported ADD memory-destination addressing form");
                }
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U;
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated ADD memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative || (!hasBase && mode == 0) ||
                    mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated ADD memory destination disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated ADD memory destination disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                const auto width =
                    static_cast<std::uint8_t>(rexW ? 64U : 32U);
                instruction.opcode = Opcode::AddMemReg;
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax : base, displacement, width,
                    index, scale, hasBase, ripRelative});
                instruction.operands.push_back(RegisterOperand{source, width});
            }
        } else if (opcode == 0x03U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated add r64, [base+disp]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U && !rexB;
            if (mode > 0x2U ||
                (mode == 0 && rmEncoding == 0x5U && rexB)) {
                throw DecodeError(
                    address, remaining,
                    "only ADD r32/r64 with based, indexed, or RIP-relative memory operands is supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated ADD qword memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding =
                    static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(
                        address, remaining,
                        "no-base ADD qword memory SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (rexX) {
                throw DecodeError(address, remaining,
                                  "REX.X requires an ADD qword memory SIB");
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative ADD displacement");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated ADD memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated ADD memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            const auto destination =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto width = static_cast<std::uint8_t>(
                rexW ? 64U : (hasOperandSizeOverride ? 16U : 32U));
            instruction.opcode = Opcode::AddRegMem;
            instruction.operands.push_back(RegisterOperand{destination, width});
            instruction.operands.push_back(
                MemoryOperand{base, displacement, width, index, scale,
                              !ripRelative, ripRelative});
        } else if (opcode == 0x08U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated or r8, r8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto sourceEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto destinationEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U &&
                (!hasRex &&
                 (sourceEncoding >= 0x4U || destinationEncoding >= 0x4U))) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct representable low-byte OR from opcode 08 is supported");
            }
            if (mode == 0x3U) {
                instruction.opcode = Opcode::OrRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(destinationEncoding, rexB), 8});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(sourceEncoding, rexR), 8});
            } else {
                if (mode > 0x2U ||
                    (mode == 0 && destinationEncoding == 0x5U) ||
                    (!hasRex && sourceEncoding >= 0x4U)) {
                    throw DecodeError(
                        address, remaining,
                        "only OR byte [base+index*scale+disp8/disp32], representable-byte-register is supported");
                }
                auto base = decodeRegister(destinationEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (destinationEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated byte OR SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "no-base byte OR SIB is not supported");
                    }
                    base = decodeRegister(baseEncoding, rexB);
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated byte OR disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated byte OR disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::OrMemReg;
                instruction.operands.push_back(MemoryOperand{
                    base, displacement, 8, index, scale});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(sourceEncoding, rexR), 8});
            }
        } else if (opcode == 0x09U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated OR r/m32/64, r32/64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto source = decodeRegister(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            if (mode == 0x3U) {
                const auto destination = decodeRegister(rmEncoding, rexB);
                instruction.opcode = Opcode::OrRegReg;
                instruction.operands.push_back(
                    RegisterOperand{destination, width});
                instruction.operands.push_back(
                    RegisterOperand{source, width});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U;
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated OR memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative || !hasBase || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated OR memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated OR memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                }
                instruction.opcode = Opcode::OrMemReg;
                instruction.operands.push_back(MemoryOperand{
                    hasBase ? base : Register::Rax, displacement, width,
                    index, scale, hasBase, ripRelative});
                instruction.operands.push_back(
                    RegisterOperand{source, width});
            }
        } else if (opcode == 0x0AU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated OR byte register, [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U;
            if (mode > 0x2U || (!hasRex && regEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only OR representable-byte-register, byte [base/RIP+index*scale+disp8/disp32] is supported");
            }
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated byte OR load SIB");
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
                        "no-base byte OR load SIB is not supported");
                }
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (rexX) {
                throw DecodeError(address, remaining,
                                  "REX.X requires a byte OR load SIB");
            }
            std::int64_t displacement = 0;
            if (ripRelative || mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated byte OR load disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated byte OR load disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            }
            instruction.opcode = Opcode::OrRegMem;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, rexR), 8});
            instruction.operands.push_back(MemoryOperand{
                ripRelative ? Register::Rax
                            : decodeRegister(baseEncoding, rexB),
                displacement, 8, index, scale, !ripRelative,
                ripRelative});
        } else if (opcode == 0x0BU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated OR r16/r32/r64, word/dword/qword [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto width = static_cast<std::uint8_t>(
                rexW ? 64U : (hasOperandSizeOverride ? 16U : 32U));
            if (mode == 0x3U) {
                instruction.opcode = Opcode::OrRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), width});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(regEncoding, rexR), width});
                const auto length = cursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                            length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated dword OR load SIB");
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
                        "no-base dword OR load SIB is not supported");
                }
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (rexX) {
                throw DecodeError(address, remaining,
                                  "REX.X requires a dword OR load SIB");
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(
                        address, remaining,
                        "truncated RIP-relative dword OR load disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated dword OR load disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated dword OR load disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            instruction.opcode = Opcode::OrRegMem;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, rexR), width});
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, width,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                    displacement, width, index, scale});
        } else if (opcode == 0x2BU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated sub register, [base+disp]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U && !rexB;
            if (mode > 0x2U || (rexX && rmEncoding != 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only SUB register, [base/RIP+index+disp8/disp32] memory operands are supported");
            }
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated SUB memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (scaleBits != 0 ||
                    (mode == 0 && baseEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only scale-one, based SIB addressing is supported for SUB memory operands");
                }
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative SUB disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated SUB memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated SUB memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            const auto destination =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto base = ripRelative
                                  ? Register::Rax
                                  : decodeRegister(baseEncoding, rexB);
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.opcode = Opcode::SubRegMem;
            instruction.operands.push_back(RegisterOperand{destination, width});
            instruction.operands.push_back(
                MemoryOperand{base, displacement, width, index, 1,
                              !ripRelative, ripRelative});
        } else if (opcode == 0x19U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated SBB register, register");
            }
            const auto modrm = code[cursor++];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto source = decodeRegister(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto destination = decodeRegister(
                static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            if (mode != 0x3U || rexX || source != destination) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct SBB r32/r64 with identical operands is supported");
            }
            const auto width =
                static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.opcode = Opcode::SbbRegReg;
            instruction.operands.push_back(
                RegisterOperand{destination, width});
            instruction.operands.push_back(RegisterOperand{source, width});
        } else if (opcode == 0x20U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated and r8, r8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto sourceEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto destinationEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode != 0x3U ||
                (!hasRex &&
                 (sourceEncoding >= 0x4U || destinationEncoding >= 0x4U))) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct representable low-byte AND from opcode 20 is supported");
            }
            instruction.opcode = Opcode::AndRegReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(destinationEncoding, rexB), 8});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(sourceEncoding, rexR), 8});
        } else if (opcode == 0x21U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated AND r/m32/64, r32/64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            const auto source =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U) {
                const auto destination = decodeRegister(rmEncoding, rexB);
                instruction.opcode = Opcode::AndRegReg;
                instruction.operands.push_back(
                    RegisterOperand{destination, width});
                instruction.operands.push_back(
                    RegisterOperand{source, width});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U;
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated AND memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative || !hasBase || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated AND memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated AND memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                }
                instruction.opcode = Opcode::AndMemReg;
                instruction.operands.push_back(MemoryOperand{
                    hasBase ? base : Register::Rax, displacement, width,
                    index, scale, hasBase, ripRelative});
                instruction.operands.push_back(
                    RegisterOperand{source, width});
            }
        } else if (opcode == 0x28U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated sub byte register, register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto sourceEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto destinationEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U) {
                if (!hasRex && (sourceEncoding >= 0x4U || destinationEncoding >= 0x4U)) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct representable low-byte SUB from opcode 28 is supported");
                }
                instruction.opcode = Opcode::SubRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(destinationEncoding, rexB), 8});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(sourceEncoding, rexR), 8});
            } else {
                const bool ripRelative = mode == 0 && destinationEncoding == 0x5U;
                if (mode > 0x2U || (!hasRex && sourceEncoding >= 0x4U) ||
                    (rexX && destinationEncoding != 0x4U)) {
                    throw DecodeError(
                        address, remaining,
                        "only SUB byte [base/RIP+index*scale+disp8/disp32], low-byte-register is supported");
                }
                auto baseEncoding = destinationEncoding;
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                auto base = decodeRegister(baseEncoding, rexB);
                if (!ripRelative && destinationEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated byte SUB SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (scaleBits != 0 || indexEncoding != 0x4U || rexX || !hasBase) {
                        throw DecodeError(
                            address, remaining,
                            "only no-index SIB addressing is supported for byte SUB");
                    }
                    base = decodeRegister(baseEncoding, rexB);
                }
                std::int64_t displacement = 0;
                if (ripRelative || (!hasBase && mode == 0) || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated byte SUB disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated byte SUB disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::SubMemReg;
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 8,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                        displacement, 8, index, scale,
                                        hasBase, false});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(sourceEncoding, rexR), 8});
            }
        } else if (opcode == 0x29U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated sub register, register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            const auto source =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U) {
                if (rexX) {
                    throw DecodeError(
                        address, remaining,
                        "REX.X is invalid for register-direct SUB");
                }
                instruction.opcode = Opcode::SubRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), width});
                instruction.operands.push_back(
                    RegisterOperand{source, width});
            } else {
                if (mode > 0x2U || (rexX && rmEncoding != 0x4U)) {
                    throw DecodeError(address, remaining,
                                      "unsupported SUB memory-destination addressing form");
                }
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U;
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated SUB memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative || !hasBase || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated SUB memory destination disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(
                            address, remaining,
                            "truncated SUB memory destination disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                }
                instruction.opcode = Opcode::SubMemReg;
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax : base, displacement, width,
                    index, scale, hasBase, ripRelative});
                instruction.operands.push_back(
                    RegisterOperand{source, width});
            }
        } else if (opcode == 0x30U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated xor byte register, register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto sourceEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto destinationEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode != 0x3U ||
                (!hasRex &&
                 (sourceEncoding >= 0x4U || destinationEncoding >= 0x4U))) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct representable low-byte XOR from opcode 30 is supported");
            }
            instruction.opcode = Opcode::XorRegReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(destinationEncoding, rexB), 8});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(sourceEncoding, rexR), 8});
        } else if (opcode == 0x31U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated xor register, register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct XOR from opcode 31 is supported");
            }
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            const auto source =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto destination =
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            instruction.opcode = Opcode::XorRegReg;
            instruction.operands.push_back(RegisterOperand{destination, width});
            instruction.operands.push_back(RegisterOperand{source, width});
        } else if (opcode == 0x32U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated xor byte register, [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto destinationEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || (mode == 0 && rmEncoding == 0x5U) ||
                (!hasRex && destinationEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only representable-byte XOR register, byte [base+index*scale+disp8/disp32] from opcode 32 is supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated byte XOR memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(
                        address, remaining,
                        "no-base byte XOR SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (rexX) {
                throw DecodeError(address, remaining,
                                  "REX.X requires a byte XOR SIB");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated byte XOR disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated byte XOR disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::XorRegMem;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(destinationEncoding, rexR), 8});
            instruction.operands.push_back(MemoryOperand{
                base, displacement, 8, index, scale});
        } else if (opcode == 0x63U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated movsxd r64, [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U && !rexB;
            if (!rexW || (mode == 0 && rmEncoding == 0x5U && !ripRelative)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVSXD r64, r32/dword [base/RIP+index*scale+disp] is supported");
            }
            if (mode == 0x3U) {
                instruction.opcode = Opcode::MovsxdRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(
                        static_cast<std::uint8_t>((modrm >> 3U) & 0x7U),
                        rexR),
                    64});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 32});
            } else {
                auto base = ripRelative ? Register::Rax
                                        : decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated MOVSXD memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    if (mode == 0 && baseEncoding == 0x5U && !rexB) {
                        throw DecodeError(
                            address, remaining,
                            "no-base MOVSXD SIB is not supported");
                    }
                    base = decodeRegister(baseEncoding, rexB);
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                } else if (rexX) {
                    throw DecodeError(address, remaining,
                                      "REX.X requires a SIB operand for MOVSXD");
                }
                std::int64_t displacement = 0;
                if (ripRelative) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated RIP-relative MOVSXD disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated MOVSXD disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated MOVSXD disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::MovsxdRegMem;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(
                        static_cast<std::uint8_t>((modrm >> 3U) & 0x7U),
                        rexR),
                    64});
                instruction.operands.push_back(MemoryOperand{
                    base, displacement, 32, index, scale, true,
                    ripRelative});
            }
        } else if (opcode == 0x33U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated xor register, [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto operandWidth =
                static_cast<std::uint8_t>(rexW ? 64U : 32U);
            if (mode == 0x3U) {
                if (rexX) {
                    throw DecodeError(
                        address, remaining,
                        "REX.X register-direct XOR from opcode 33 is unsupported");
                }
                instruction.opcode = Opcode::XorRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(
                        static_cast<std::uint8_t>((modrm >> 3U) & 0x7U),
                        rexR),
                    operandWidth});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), operandWidth});
            } else {
            if (mode == 0 && rmEncoding == 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "only XOR register, [base+index*scale+disp8/disp32] is supported");
            }
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated XOR memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits = static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding = static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base SIB addressing is not supported for XOR");
                }
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated XOR memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated XOR memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::XorRegMem;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
                operandWidth});
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(baseEncoding, rexB), displacement, operandWidth,
                index, scale});
            }
        } else if (opcode == 0x38U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated cmp byte register, register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto sourceEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (rexW || mode > 0x3U ||
                (!hasRex && sourceEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only representable-byte register or based memory CMP from opcode 38 is supported");
            }
            const auto source = RegisterOperand{
                decodeRegister(sourceEncoding, rexR), 8};
            if (mode == 0x3U) {
                if (rexX || (!hasRex && rmEncoding >= 0x4U)) {
                    throw DecodeError(
                        address, remaining,
                        "legacy high-byte or REX.X register CMP is unsupported");
                }
                instruction.opcode = Opcode::CmpRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
                instruction.operands.push_back(source);
            } else {
                auto baseEncoding = rmEncoding;
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CMP byte memory SIB");
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
                            "no-base CMP byte memory SIB is unsupported");
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                } else if (rexX) {
                    throw DecodeError(
                        address, remaining,
                        "REX.X requires a CMP byte memory SIB operand");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CMP byte memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (ripRelative || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated CMP byte memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::CmpMemReg;
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 8,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                        displacement, 8, index, scale});
                instruction.operands.push_back(source);
            }
        } else if (opcode == 0x39U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated cmp r/m, register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (rexX && mode != 0x3U && rmEncoding != 0x4U) {
                throw DecodeError(address, remaining,
                                  "only register-direct, RIP-relative, or [base+index*scale+disp8/disp32] CMP from opcode 39 is supported");
            }
            const auto rhs =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto width = static_cast<std::uint8_t>(
                rexW ? 64U : hasOperandSizeOverride ? 16U : 32U);
            if (mode == 0x3U) {
                const auto lhs = decodeRegister(rmEncoding, rexB);
                instruction.opcode = Opcode::CmpRegReg;
                instruction.operands.push_back(RegisterOperand{lhs, width});
                instruction.operands.push_back(RegisterOperand{rhs, width});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U;
                auto baseEncoding = rmEncoding;
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CMP memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (!hasBase &&
                        (!hasGsOverride || indexEncoding != 0x4U || rexX)) {
                        throw DecodeError(
                            address, remaining,
                            "only GS-absolute no-base CMP memory SIB is supported");
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (!hasBase) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated absolute or RIP-relative CMP memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CMP memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated CMP memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::CmpMemReg;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(baseEncoding, rexB), displacement, width,
                    index, scale, hasBase, ripRelative,
                    hasGsOverride ? Segment::Gs : Segment::None});
                instruction.operands.push_back(RegisterOperand{rhs, width});
            }
        } else if (opcode == 0x3AU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated cmp byte register, [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || (!hasRex && regEncoding >= 0x4U) ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only CMP byte register, [base+index*scale+disp8/disp32] is supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated CMP byte memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base CMP byte SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated CMP byte memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated CMP byte memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::CmpRegMem;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, rexR), 8});
            instruction.operands.push_back(
                MemoryOperand{base, displacement, 8, index, scale});
        } else if (opcode == 0x3BU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated cmp r32, [base+disp]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U && !rexB;
            if (mode > 0x2U || (rexX && rmEncoding != 0x4U) ||
                (mode == 0 && rmEncoding == 0x5U && !ripRelative)) {
                throw DecodeError(
                    address, remaining,
                    "only CMP register, [base+index*scale+disp8/disp32] memory operands are supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            bool hasBase = true;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated CMP register-memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding =
                    static_cast<std::uint8_t>(sib & 0x7U);
                hasBase = !(mode == 0 && baseEncoding == 0x5U && !rexB);
                if (hasBase) {
                    base = decodeRegister(baseEncoding, rexB);
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
                                      "truncated RIP-relative CMP disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            } else if (!hasBase && mode == 0) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated no-base CMP disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated CMP memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated CMP memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            const auto lhs =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto operandWidth = static_cast<std::uint8_t>(
                rexW ? 64U : hasOperandSizeOverride ? 16U : 32U);
            instruction.opcode = Opcode::CmpRegMem;
            instruction.operands.push_back(RegisterOperand{lhs, operandWidth});
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, operandWidth,
                                    std::nullopt, 1, false, true,
                                    hasGsOverride ? Segment::Gs
                                                  : Segment::None}
                    : MemoryOperand{base, displacement, operandWidth, index,
                                    scale, hasBase, false,
                                    hasGsOverride ? Segment::Gs
                                                  : Segment::None});
        } else if (opcode == 0x87U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated xchg [memory], register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (rexX || mode > 0x2U || rmEncoding == 0x4U) {
                throw DecodeError(
                    address, remaining,
                    "only XCHG dword/qword [base/RIP+disp8/disp32], register is supported");
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative XCHG memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated XCHG memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated XCHG memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            const auto operandWidth =
                static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.opcode = Opcode::XchgMemReg;
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, operandWidth,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(rmEncoding, rexB),
                                    displacement, operandWidth});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(
                    static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
                operandWidth});
        } else if (opcode == 0x88U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated mov byte [memory], register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (rexW || mode > 0x3U ||
                (!hasRex && regEncoding >= 0x4U) ||
                (!hasRex && mode == 0x3U && rmEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOV byte [base+index*scale+disp8/disp32], low-byte-register is supported");
            }
            if (mode == 0x3U) {
                instruction.opcode = Opcode::MovRegReg;
                instruction.operands.push_back(
                    RegisterOperand{decodeRegister(rmEncoding, rexB), 8});
                instruction.operands.push_back(
                    RegisterOperand{decodeRegister(regEncoding, rexR), 8});
            } else {
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOV byte store SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base MOV byte store SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative byte MOV disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated byte MOV disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated byte MOV disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            instruction.opcode = Opcode::MovMemReg;
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 8,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{base, displacement, 8, index, scale});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, rexR), 8});
            }
        } else if (opcode == 0x8AU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated mov byte register, [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || rexW ||
                (!hasRex && regEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOV byte register, [base+index*scale+disp8/disp32] is supported");
            }
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOV byte memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base MOV byte SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(
                        address, remaining,
                        "truncated RIP-relative byte MOV load disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated byte load disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated byte load disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            const auto destination =
                decodeRegister(regEncoding, rexR);
            instruction.opcode = Opcode::MovRegMem;
            instruction.operands.push_back(RegisterOperand{destination, 8});
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 8,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{base, displacement, 8, index, scale});
        } else if (opcode == 0x89U || opcode == 0x8BU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated mov r64, r64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto reg = decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto rm = decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            const auto operandWidth = static_cast<std::uint8_t>(
                rexW ? 64U : hasOperandSizeOverride ? 16U : 32U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0 && rmEncoding == 0x5U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative MOV displacement");
                }
                const auto displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
                const auto memory = MemoryOperand{
                    Register::Rax, displacement, operandWidth, std::nullopt, 1,
                    false, true,
                    hasGsOverride ? Segment::Gs : Segment::None};
                if (opcode == 0x89U) {
                    instruction.opcode = Opcode::MovMemReg;
                    instruction.operands.push_back(memory);
                    instruction.operands.push_back(RegisterOperand{reg, operandWidth});
                } else {
                    instruction.opcode = Opcode::MovRegMem;
                    instruction.operands.push_back(RegisterOperand{reg, operandWidth});
                    instruction.operands.push_back(memory);
                }
            } else if (mode == 0x3U && !rexX && !hasGsOverride) {
                instruction.opcode = Opcode::MovRegReg;
                instruction.operands.push_back(
                    RegisterOperand{opcode == 0x89U ? rm : reg, operandWidth});
                instruction.operands.push_back(
                    RegisterOperand{opcode == 0x89U ? reg : rm, operandWidth});
            } else {
                if (mode > 0x2U ||
                    (mode == 0 && rmEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only MOV register to/from [base+disp8/disp32] memory operands are supported");
                }
                auto base = rm;
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = true;
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining, "truncated MOV memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    const bool hasIndex = indexEncoding != 0x4U || rexX;
                    const bool noBase = mode == 0 && baseEncoding == 0x5U;
                    hasBase = !noBase;
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (hasIndex) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (!hasBase) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated no-base MOV SIB displacement");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated MOV memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated MOV memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (opcode == 0x89U) {
                    instruction.opcode = Opcode::MovMemReg;
                    instruction.operands.push_back(
                        MemoryOperand{
                            base, displacement, operandWidth, index, scale,
                            hasBase, false,
                            hasGsOverride ? Segment::Gs : Segment::None});
                    instruction.operands.push_back(RegisterOperand{reg, operandWidth});
                } else {
                    instruction.opcode = Opcode::MovRegMem;
                    instruction.operands.push_back(RegisterOperand{reg, operandWidth});
                    instruction.operands.push_back(
                        MemoryOperand{
                            base, displacement, operandWidth, index, scale,
                            hasBase, false,
                            hasGsOverride ? Segment::Gs : Segment::None});
                }
            }
        } else if (opcode == 0x22U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated and byte register, [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (mode == 0x3U || rmEncoding == 0x4U ||
                (!hasRex && regEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only AND representable-byte-register, byte [base/RIP+disp8/disp32] is supported");
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative byte AND disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated byte AND disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated byte AND disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::AndRegMem;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, rexR), 8});
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 8,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(rmEncoding, rexB),
                                    displacement, 8});
        } else if (opcode == 0x23U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated and register, [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U && !rexB;
            if (mode > 0x2U ||
                (mode == 0 && rmEncoding == 0x5U && rexB) ||
                (ripRelative && rexX)) {
                throw DecodeError(
                    address, remaining,
                    "only AND r32/r64, dword/qword [base+index*scale+disp8/disp32] or RIP-relative memory is supported from opcode 23");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated memory AND SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding =
                    static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(
                        address, remaining,
                        "no-base SIB memory AND is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated memory AND disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U || ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated memory AND disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            instruction.opcode = Opcode::AndRegMem;
            const auto width = static_cast<std::uint8_t>(rexW ? 64 : 32);
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, rexR), width});
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, width,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{base, displacement, width, index, scale});
        } else if (opcode == 0x84U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated test r/m8, r8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (!hasRex && regEncoding >= 0x4U) {
                throw DecodeError(
                    address, remaining,
                    "high-byte register TEST is not supported");
            }
            if (mode == 0x3U) {
                if (!hasRex && rmEncoding >= 0x4U) {
                    throw DecodeError(
                        address, remaining,
                        "high-byte register TEST is not supported");
                }
                instruction.opcode = Opcode::TestReg8Reg8;
                instruction.operands.push_back(
                    RegisterOperand{decodeRegister(rmEncoding, rexB), 8});
                instruction.operands.push_back(
                    RegisterOperand{decodeRegister(regEncoding, rexR), 8});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && !rexB;
                if (mode > 0x2U || (rexX && rmEncoding != 0x4U)) {
                    throw DecodeError(
                        address, remaining,
                        "unsupported TEST byte memory operand");
                }
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated TEST byte memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U && !rexB);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated TEST byte memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U || (!hasBase && !ripRelative) ||
                           ripRelative) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated TEST byte memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::TestMemReg;
                instruction.operands.push_back(MemoryOperand{
                    base, displacement, 8, index, scale, hasBase,
                    ripRelative});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(regEncoding, rexR), 8});
            }
        } else if (opcode == 0x85U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated test r64, r64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto reg = decodeRegister(regEncoding, rexR);
            const auto operandWidth = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            if (mode == 0x3U) {
                if (rexX) {
                    throw DecodeError(
                        address, remaining,
                        "REX.X is invalid for register-direct TEST");
                }
                instruction.opcode = Opcode::TestRegReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), operandWidth});
                instruction.operands.push_back(
                    RegisterOperand{reg, operandWidth});
            } else {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && !rexB;
                if (mode > 0x2U || (rexX && rmEncoding != 0x4U)) {
                    throw DecodeError(address, remaining,
                                      "unsupported TEST memory operand");
                }
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated TEST memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U && !rexB);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated TEST memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U || !hasBase || ripRelative) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated TEST memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::TestMemReg;
                instruction.operands.push_back(MemoryOperand{
                    base, displacement, operandWidth, index, scale, hasBase,
                    ripRelative});
                instruction.operands.push_back(
                    RegisterOperand{reg, operandWidth});
            }
        } else if (opcode == 0x8DU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated lea r64, [address]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto memoryRegister = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto destination = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode == 0 && memoryRegister == 5 && !rexB && !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated lea r64, [rip+disp32]");
                }
                const auto displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
                const auto length = cursor - instructionStart;
                const auto target = relativeTarget(address, length, displacement);
                instruction.opcode = Opcode::LeaRegRipRelative;
                instruction.operands.push_back(
                    RegisterOperand{decodeRegister(destination, rexR),
                                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{target.value, 64});
            } else {
                if (mode > 0x2U || (mode == 0 && memoryRegister == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only LEA r64, [base+index+disp8/disp32] addressing is supported");
                }
                auto base = decodeRegister(memoryRegister, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = true;
                if (memoryRegister == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining, "truncated LEA SIB byte");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits = static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                    }
                    if (mode == 0 && baseEncoding == 0x5U) {
                        hasBase = false;
                    } else {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                } else if (rexX) {
                    throw DecodeError(address, remaining,
                                      "REX.X requires a SIB operand for LEA");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining, "truncated LEA disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U || !hasBase) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining, "truncated LEA disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::LeaRegMem;
                instruction.operands.push_back(
                    RegisterOperand{decodeRegister(destination, rexR),
                                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(
                    MemoryOperand{base, displacement, 64, index, scale, hasBase});
            }
        } else if (opcode == 0xC0U) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining,
                                  "truncated byte shift register, imm8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (rexW || rexR || rexX || mode != 0x3U ||
                (extension != 0x4U && extension != 0x5U) ||
                (!hasRex && rmEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only SHL/SHR representable-byte-register, imm8 from opcode C0 is supported");
            }
            instruction.opcode = extension == 0x4U ? Opcode::ShlRegImm
                                                    : Opcode::ShrRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(rmEncoding, rexB), 8});
            instruction.operands.push_back(
                ImmediateOperand{code[cursor++], 8});
        } else if (opcode == 0xC1U) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining, "truncated shift register, imm8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const bool observedSar = extension == 0x7U;
            const bool observedRor =
                rexW && !rexR && !rexX && extension == 0x1U;
            const bool observedRol =
                !rexR && !rexX && extension == 0x0U;
            if (mode != 0x3U && extension == 0x5U && !rexR && !rexX) {
                const auto rmEncoding =
                    static_cast<std::uint8_t>(modrm & 0x7U);
                if (rexX || rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only SHR dword/qword [base+disp8/disp32], imm8 is supported for memory opcode C1 /5");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated SHR memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated SHR memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated SHR memory immediate");
                }
                instruction.opcode = Opcode::ShrMemImm;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement,
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(
                    ImmediateOperand{code[cursor++], 8});
            } else if (mode != 0x3U && rexW && extension == 0x4U) {
                const auto rmEncoding =
                    static_cast<std::uint8_t>(modrm & 0x7U);
                if (rexX || rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only SHL qword [base+disp8/disp32], imm8 is supported for memory opcode C1 /4");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated SHL memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated SHL memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated SHL memory immediate");
                }
                instruction.opcode = Opcode::ShlMemImm;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement, 64});
                instruction.operands.push_back(
                    ImmediateOperand{code[cursor++], 8});
            } else {
                if (mode != 0x3U ||
                    (!observedSar && !observedRor && !observedRol &&
                     (rexR || rexX ||
                      (extension != 0x4U && extension != 0x5U)))) {
                    throw DecodeError(
                        address, remaining,
                        "only ROL r32/r64, ROR r64, SHL/SHR r32/r64, and SAR r32/r64 register forms and SHR dword/qword memory from opcode C1 are supported");
                }
                instruction.opcode = extension == 0x0U   ? Opcode::RolRegImm
                                     : extension == 0x1U ? Opcode::RorRegImm
                                     : extension == 0x4U ? Opcode::ShlRegImm
                                     : extension == 0x5U ? Opcode::ShrRegImm
                                                         : Opcode::SarRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U),
                                   rexB),
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(
                    ImmediateOperand{code[cursor++], 8});
            }
        } else if (opcode == 0xD0U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated implicit-count byte shift");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode != 0x3U || extension != 0x5U ||
                (!hasRex && rmEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only SHR representable-byte-register, 1 from opcode D0 /5 is supported");
            }
            instruction.opcode = Opcode::ShrRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(rmEncoding, rexB), 8});
            instruction.operands.push_back(ImmediateOperand{1, 8});
        } else if (opcode == 0xD1U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated implicit-count shift register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (rexR || rexX || mode != 0x3U || extension != 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct SHR r32/r64, 1 from opcode D1 /5 is supported");
            }
            instruction.opcode = Opcode::ShrRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            instruction.operands.push_back(ImmediateOperand{1, 8});
        } else if (opcode == 0xD2U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated byte shift register, cl");
            }
            const auto modrm = code[cursor++];
            const auto mode =
                static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode != 0x3U || extension != 0x4U || rexW ||
                (!hasRex && rmEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only SHL representable-byte-register, CL from opcode D2 /4 is supported");
            }
            instruction.opcode = Opcode::ShlRegCl;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(rmEncoding, rexB), 8});
        } else if (opcode == 0xD3U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated shl register, cl");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode != 0x3U ||
                (extension != 0x0U && extension != 0x4U &&
                 extension != 0x5U) ||
                (extension == 0x0U && rexW) || rexR || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct ROL r32 /0 and SHL/SHR r32/r64 /4,/5 from opcode D3 are supported");
            }
            instruction.opcode = extension == 0x0U   ? Opcode::RolRegCl
                                 : extension == 0x4U ? Opcode::ShlRegCl
                                                     : Opcode::ShrRegCl;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
        } else if (opcode == 0xF7U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated F7 register operation");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (hasOperandSizeOverride && !rexW && extension != 0x3U) {
                throw DecodeError(
                    address, remaining,
                    "operand-size override is only supported for register NEG from opcode F7");
            }
            if (extension == 0x7U) {
                if (mode != 0x3U || rexW || rexR || rexX) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct IDIV r32 is supported from opcode F7 /7");
                }
                instruction.opcode = Opcode::IdivReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 32});
            } else if (extension == 0x6U) {
                if (mode == 0x3U) {
                    if (rexR || rexX) {
                        throw DecodeError(
                            address, remaining,
                            "unsupported REX bits for register DIV from opcode F7 /6");
                    }
                    instruction.opcode = Opcode::DivReg;
                    instruction.operands.push_back(RegisterOperand{
                        decodeRegister(rmEncoding, rexB),
                        static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                } else {
                if (rexW || rexR || rexX || mode > 0x2U ||
                    rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only DIV r32/r64 or dword [base+disp8/disp32] is supported from opcode F7 /6");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated DIV dword disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated DIV dword disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::DivMem;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement, 32});
                }
            } else if (extension == 0x4U && mode <= 0x2U && !rexR && !rexX &&
                       rmEncoding != 0x4U &&
                       !(mode == 0 && rmEncoding == 0x5U)) {
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated MUL memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated MUL memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::MulMem;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement,
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            } else if (extension == 0x5U && mode <= 0x2U && !rexR && !rexX &&
                       rmEncoding != 0x4U &&
                       !(mode == 0 && rmEncoding == 0x5U)) {
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated IMUL memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated IMUL memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::ImulMem;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement,
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            } else if (extension == 0x0U && mode <= 0x2U && !rexR && !rexX &&
                       rmEncoding != 0x4U &&
                       !(mode == 0 && rmEncoding == 0x5U)) {
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated TEST memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated TEST memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated TEST memory immediate");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::TestMemImm;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement,
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{
                    rexW ? static_cast<std::uint64_t>(
                               static_cast<std::int64_t>(immediate))
                         : static_cast<std::uint32_t>(immediate),
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            } else {
            if (mode != 0x3U ||
                (extension != 0x0U && extension != 0x2U &&
                 extension != 0x3U &&
                 extension != 0x4U && extension != 0x5U) ||
                (extension != 0x0U && (rexR || rexX))) {
                throw DecodeError(address, remaining,
                                  "only register-direct TEST /0, NOT /2, NEG /3, MUL /4, IMUL /5, DIV /6, IDIV r32 /7, and memory TEST /0, MUL /4 and IMUL /5 from opcode F7 are supported");
            }
            instruction.opcode = extension == 0x0U   ? Opcode::TestRegImm
                                 : extension == 0x2U ? Opcode::NotReg
                                 : extension == 0x3U ? Opcode::NegReg
                                 : extension == 0x4U ? Opcode::MulReg
                                                     : Opcode::ImulReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                static_cast<std::uint8_t>(
                    rexW ? 64U : hasOperandSizeOverride ? 16U : 32U)});
            if (extension == 0x0U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated TEST r32/r64, imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.operands.push_back(ImmediateOperand{
                    rexW ? static_cast<std::uint64_t>(
                               static_cast<std::int64_t>(immediate))
                         : static_cast<std::uint32_t>(immediate),
                    32});
            }
            }
        } else if (opcode == 0xC6U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated mov byte opcode C6");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (mode > 0x2U || extension != 0 || rexR ||
                (rexX && rmEncoding != 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOV byte [base/index/RIP+disp8/disp32], imm8 from opcode C6 /0 is supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOV byte SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding =
                    static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base MOV byte SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative MOV byte disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOV byte memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated MOV byte memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated MOV byte imm8");
            }
            const auto immediate = code[cursor++];
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            instruction.opcode = Opcode::MovMemImm;
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 8, std::nullopt,
                                    1, false, true}
                    : MemoryOperand{base, displacement, 8, index, scale});
            instruction.operands.push_back(ImmediateOperand{immediate, 8});
        } else if (opcode == 0xC7U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated mov opcode C7");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            // In 64-bit mode the non-SIB mod=00,r/m=5 encoding is
            // RIP-relative even when REX.B is present; that extension bit is
            // ignored for this special form.
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (extension != 0 || rexR || (rexX && rmEncoding != 0x4U) ||
                (hasGsOverride && mode == 0x3U)) {
                throw DecodeError(address, remaining,
                                  "only register or [base/SIB+disp] MOV from opcode C7 /0 is supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            bool hasBase = !ripRelative;
            if (mode != 0x3U && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOV immediate SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                const bool hasIndex = indexEncoding != 0x4U || rexX;
                const bool noBase = mode == 0 && baseEncoding == 0x5U;
                hasBase = !noBase;
                if (hasBase) {
                    base = decodeRegister(baseEncoding, rexB);
                }
                if (hasIndex) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative || !hasBase) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated displacement-only MOV memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated MOV memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated MOV memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated MOV imm32");
            }
            const auto immediate = readI32(code.subspan(cursor, 4));
            cursor += 4;
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            instruction.opcode = mode == 0x3U ? Opcode::MovRegImm : Opcode::MovMemImm;
            const auto operandWidth =
                static_cast<std::uint8_t>(rexW ? 64U : 32U);
            if (mode == 0x3U) {
                instruction.operands.push_back(
                    RegisterOperand{decodeRegister(rmEncoding, rexB), operandWidth});
            } else {
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, operandWidth,
                                        std::nullopt, 1, false, true,
                                        hasGsOverride ? Segment::Gs
                                                      : Segment::None}
                        : MemoryOperand{base, displacement, operandWidth,
                                        index, scale, hasBase, false,
                                        hasGsOverride ? Segment::Gs
                                                      : Segment::None});
            }
            instruction.operands.push_back(ImmediateOperand{
                rexW ? static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate))
                     : static_cast<std::uint64_t>(static_cast<std::uint32_t>(immediate)),
                32});
        } else if (opcode == 0x80U) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining, "truncated cmp byte [memory], imm8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (extension == 0 && mode == 0x3U && !rexW && !rexR && !rexX &&
                (hasRex || rmEncoding < 0x4U)) {
                const auto immediate = code[cursor++];
                instruction.opcode = Opcode::AddRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
                instruction.operands.push_back(
                    ImmediateOperand{immediate, 8});
                const auto length = cursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (extension == 0x1U && mode == 0x3U && !rexW && !rexR &&
                !rexX && (hasRex || rmEncoding < 0x4U)) {
                const auto immediate = code[cursor++];
                instruction.opcode = Opcode::OrRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
                instruction.operands.push_back(
                    ImmediateOperand{immediate, 8});
                const auto length = cursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (extension == 0x1U && mode <= 0x2U) {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U;
                auto baseEncoding = rmEncoding;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated byte OR SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (scaleBits != 0 || indexEncoding != 0x4U || rexX ||
                        !hasBase) {
                        throw DecodeError(
                            address, remaining,
                            "only no-index SIB addressing is supported for byte OR");
                    }
                } else if (rexX) {
                    throw DecodeError(address, remaining,
                                      "REX.X requires a byte OR SIB operand");
                }
                std::int64_t displacement = 0;
                if (ripRelative || (!hasBase && mode == 0) || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated byte OR disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated byte OR disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                }
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated byte OR immediate");
                }
                const auto immediate = code[cursor++];
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::OrMemImm;
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 8,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                        displacement, 8, std::nullopt, 1,
                                        hasBase, false});
                instruction.operands.push_back(
                    ImmediateOperand{immediate, 8});
                const auto length = cursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (extension == 0x4U && mode == 0x3U && !rexW && !rexR &&
                !rexX && (hasRex || rmEncoding < 0x4U)) {
                const auto immediate = code[cursor++];
                instruction.opcode = Opcode::AndRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
                instruction.operands.push_back(
                    ImmediateOperand{immediate, 8});
                const auto length = cursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (extension == 0x4U && mode <= 0x2U && !rexW && !rexR &&
                (!rexX || rmEncoding == 0x4U)) {
                const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated byte AND SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative || (!hasBase && mode == 0) ||
                    mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated byte AND disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated byte AND disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                }
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated byte AND immediate");
                }
                const auto immediate = code[cursor++];
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::AndMemImm;
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax : base, displacement, 8,
                    index, scale, hasBase, ripRelative});
                instruction.operands.push_back(
                    ImmediateOperand{immediate, 8});
                const auto length = cursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            if (extension == 0x6U && mode == 0x3U && !rexW && !rexR &&
                !rexX && (hasRex || rmEncoding < 0x4U)) {
                const auto immediate = code[cursor++];
                instruction.opcode = Opcode::XorRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
                instruction.operands.push_back(
                    ImmediateOperand{immediate, 8});
                const auto length = cursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                result.push_back(std::move(instruction));
                if (result.size() == maximumInstructions) {
                    return result;
                }
                continue;
            }
            // In 64-bit mode mod=00,r/m=101 remains RIP-relative even when
            // REX.B is present; REX.B does not turn this special encoding into
            // an R13 base.
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (extension != 0x7U || rexW || rexR ||
                (rexX && rmEncoding != 0x4U) ||
                (mode == 0x3U && !hasRex && rmEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only CMP representable-byte-register/[base/RIP+disp8/disp32], imm8 from opcode 80 /7 is supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && mode != 0x3U && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated byte CMP SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base byte CMP SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative byte CMP disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated byte CMP disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated byte CMP disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated byte CMP immediate");
            }
            const auto immediate = code[cursor++];
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            instruction.opcode = Opcode::CmpMemImm;
            if (mode == 0x3U) {
                instruction.opcode = Opcode::CmpRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
            } else {
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 8,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{base, displacement, 8, index, scale});
            }
            instruction.operands.push_back(ImmediateOperand{immediate, 8});
        } else if (opcode == 0x81U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated opcode 81");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode == 0x3U && extension == 0x0U && !rexR && !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated add register, imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::AddRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{
                    rexW ? static_cast<std::uint64_t>(
                               static_cast<std::int64_t>(immediate))
                         : static_cast<std::uint64_t>(
                               static_cast<std::uint32_t>(immediate)),
                    32});
            } else if (mode == 0x3U && extension == 0x2U && !rexW &&
                       !rexR && !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated adc r32, imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::AdcRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U),
                                   rexB),
                    32});
                instruction.operands.push_back(ImmediateOperand{
                    static_cast<std::uint32_t>(immediate), 32});
            } else if (mode == 0x3U && extension == 0x5U && rexW &&
                       !rexR && !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated sub r64, imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::SubRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                    64});
                instruction.operands.push_back(ImmediateOperand{
                    static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(immediate)),
                    32});
            } else if (mode == 0x3U && extension == 0x1U && !rexR &&
                       !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated or register, imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::OrRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{
                    rexW ? static_cast<std::uint64_t>(
                               static_cast<std::int64_t>(immediate))
                         : static_cast<std::uint64_t>(
                               static_cast<std::uint32_t>(immediate)),
                    32});
            } else if (mode == 0x3U && extension == 0x4U && !rexR &&
                       !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated and register, imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::AndRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{
                    rexW ? static_cast<std::uint64_t>(
                               static_cast<std::int64_t>(immediate))
                         : static_cast<std::uint64_t>(
                               static_cast<std::uint32_t>(immediate)),
                    32});
            } else if (mode == 0x3U && extension == 0x6U && !rexR && !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated xor register, imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::XorRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{
                    rexW ? static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate))
                         : static_cast<std::uint32_t>(immediate),
                    32});
            } else if (mode == 0x3U && extension == 0x7U && !rexR && !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated cmp register, imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::CmpRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{
                    rexW ? static_cast<std::uint64_t>(
                               static_cast<std::int64_t>(immediate))
                         : static_cast<std::uint64_t>(
                               static_cast<std::uint32_t>(immediate)),
                    32});
            } else if (mode <= 0x2U && extension == 0x7U && !rexR) {
                const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
                if (mode == 0 && rmEncoding == 0x5U) {
                    throw DecodeError(
                        address, remaining,
                        "RIP-relative CMP [memory], imm32 is not supported");
                }
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CMP memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "no-base CMP [memory], imm32 SIB is not supported");
                    }
                    base = decodeRegister(baseEncoding, rexB);
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CMP memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated CMP memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated CMP memory imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::CmpMemImm;
                instruction.operands.push_back(MemoryOperand{
                    base, displacement,
                    static_cast<std::uint8_t>(rexW ? 64U : 32U), index,
                    scale});
                instruction.operands.push_back(ImmediateOperand{
                    rexW ? static_cast<std::uint64_t>(
                               static_cast<std::int64_t>(immediate))
                         : static_cast<std::uint64_t>(
                               static_cast<std::uint32_t>(immediate)),
                    32});
            } else if (mode <= 0x2U && extension == 0x1U && !rexR) {
                const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
                if (mode == 0 && rmEncoding == 0x5U) {
                    throw DecodeError(
                        address, remaining,
                        "RIP-relative OR [memory], imm32 is not supported");
                }
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated OR memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "no-base OR [memory], imm32 SIB is not supported");
                    }
                    base = decodeRegister(baseEncoding, rexB);
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated OR memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated OR memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated OR memory imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::OrMemImm;
                instruction.operands.push_back(MemoryOperand{
                    base, displacement,
                    static_cast<std::uint8_t>(rexW ? 64U : 32U), index,
                    scale});
                instruction.operands.push_back(ImmediateOperand{
                    rexW ? static_cast<std::uint64_t>(
                               static_cast<std::int64_t>(immediate))
                         : static_cast<std::uint64_t>(
                               static_cast<std::uint32_t>(immediate)),
                    32});
            } else {
                throw DecodeError(
                    address, remaining,
                    "only ADD /0, OR /1, ADC r32 /2, AND /4, SUB /5, XOR /6, and CMP /7 forms from opcode 81 are supported");
            }
        } else if (opcode == 0xFEU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated inc r8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U && extension <= 1 &&
                (hasRex || rmEncoding < 0x4U)) {
                instruction.opcode = extension == 0 ? Opcode::IncReg
                                                     : Opcode::DecReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
            } else if (mode <= 0x2U && extension <= 1 && !rexR &&
                       (!rexX || rmEncoding == 0x4U) &&
                       !(mode == 0 && rmEncoding == 0x5U)) {
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated INC/DEC byte SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "no-base INC/DEC byte SIB is not supported");
                    }
                    base = decodeRegister(baseEncoding, rexB);
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated INC/DEC byte disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated INC/DEC byte disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = extension == 0 ? Opcode::IncMem
                                                     : Opcode::DecMem;
                instruction.operands.push_back(
                    MemoryOperand{base, displacement, 8, index, scale});
            } else {
                throw DecodeError(
                    address, remaining,
                    "only representable register-direct INC/DEC r8 and based INC/DEC byte memory are supported");
            }
        } else if (opcode == 0xFFU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated indirect call");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (hasOperandSizeOverride &&
                (extension != 0x0U || mode == 0x3U)) {
                throw DecodeError(
                    address, remaining,
                    "only memory INC is supported for operand-size-overridden opcode FF");
            }
            if (extension == 0x0U && mode <= 0x2U && !rexR &&
                (!rexX || rmEncoding == 0x4U)) {
                const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                bool hasBase = !ripRelative;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated INC memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    hasBase = !(mode == 0 && baseEncoding == 0x5U);
                    if (hasBase) {
                        base = decodeRegister(baseEncoding, rexB);
                    }
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative || (!hasBase && mode == 0)) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated INC memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated INC memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated INC memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::IncMem;
                instruction.operands.push_back(MemoryOperand{
                    ripRelative ? Register::Rax : base, displacement,
                    static_cast<std::uint8_t>(
                        rexW ? 64U : hasOperandSizeOverride ? 16U : 32U),
                    index,
                    scale, hasBase, ripRelative});
            } else if (extension == 0x1U && mode == 0x0U && rmEncoding == 0x5U &&
                       !rexR && !rexX && !rexB) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative DEC disp32");
                }
                const auto displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
                instruction.opcode = Opcode::DecMem;
                instruction.operands.push_back(MemoryOperand{
                    Register::Rax, displacement,
                    static_cast<std::uint8_t>(rexW ? 64U : 32U), std::nullopt,
                    1, false, true});
            } else if (extension == 0x1U && mode <= 0x2U && !rexR &&
                       !rexX && rmEncoding != 0x4U &&
                       !(mode == 0 && rmEncoding == 0x5U && !rexB)) {
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated DEC memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U || (mode == 0 && rmEncoding == 0x5U)) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated DEC memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::DecMem;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement,
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            } else if (extension == 0x0U && mode == 0x3U && !rexR && !rexX) {
                instruction.opcode = Opcode::IncReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB),
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            } else if (extension == 0x1U && mode == 0x3U && !rexR && !rexX) {
                instruction.opcode = Opcode::DecReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB),
                    static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            } else if (extension == 0x4U && mode == 0x3U && !rexR && !rexX) {
                instruction.opcode = Opcode::JmpReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 64});
            } else if (extension == 0x4U && mode == 0x0U &&
                       rmEncoding == 0x5U && !rexR && !rexX && !rexB) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative indirect JMP displacement");
                }
                const auto displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::JmpMem;
                instruction.operands.push_back(MemoryOperand{
                    Register::Rax, displacement, 64, std::nullopt, 1, false,
                    true});
            } else if (extension == 0x4U && mode <= 0x2U && !rexR &&
                       !rexX && !(mode == 0 && rmEncoding == 0x5U)) {
                auto baseEncoding = rmEncoding;
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated indirect JMP SIB byte");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    if (scaleBits != 0 || indexEncoding != 0x4U ||
                        (mode == 0 && baseEncoding == 0x5U && !rexB)) {
                        throw DecodeError(
                            address, remaining,
                            "only no-index SIB addressing is supported for indirect JMP");
                    }
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated indirect JMP disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated indirect JMP disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::JmpMem;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(baseEncoding, rexB), displacement, 64});
            } else if (extension == 0x6U && mode <= 0x2U && !rexR &&
                       !rexX && !(mode == 0 && rmEncoding == 0x5U)) {
                auto baseEncoding = rmEncoding;
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated PUSH memory SIB byte");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    if (scaleBits != 0 || indexEncoding != 0x4U ||
                        (mode == 0 && baseEncoding == 0x5U && !rexB)) {
                        throw DecodeError(
                            address, remaining,
                            "only no-index SIB addressing is supported for PUSH memory");
                    }
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated PUSH memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated PUSH memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::Push;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(baseEncoding, rexB), displacement, 64});
            } else if (extension == 0x2U && mode == 0x0U &&
                       rmEncoding == 0x5U && !rexR && !rexX && !rexB) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(
                        address, remaining,
                        "truncated RIP-relative indirect CALL displacement");
                }
                const auto displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = Opcode::CallMem;
                instruction.operands.push_back(MemoryOperand{
                    Register::Rax, displacement, 64, std::nullopt, 1, false,
                    true});
                instruction.fallthrough = guest::GuestAddress{
                    address.value + (cursor - instructionStart)};
            } else if (extension == 0x2U && mode == 0x3U && !rexR && !rexX) {
                instruction.opcode = Opcode::CallReg;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 64});
                instruction.fallthrough = guest::GuestAddress{
                    address.value + (cursor - instructionStart)};
            } else if (extension != 0x2U || mode > 0x2U || rexR || rexX ||
                       (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only register/memory INC /0, register/based/RIP-relative dword/qword memory DEC /1, register/memory CALL /2, register/based/RIP-relative memory JMP /4, and based qword memory PUSH /6 are supported from opcode FF");
            } else {
                auto baseEncoding = rmEncoding;
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated indirect CALL SIB byte");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits = static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    if (scaleBits != 0 || indexEncoding != 0x4U ||
                        (mode == 0 && baseEncoding == 0x5U && !rexB)) {
                        throw DecodeError(
                            address, remaining,
                            "only no-index SIB addressing is supported for indirect CALL");
                    }
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated indirect CALL disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated indirect CALL disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::CallMem;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(baseEncoding, rexB), displacement, 64});
                instruction.fallthrough = guest::GuestAddress{
                    address.value + (cursor - instructionStart)};
            }
        } else if (opcode == 0x83U) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining, "truncated add r64, imm8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (extension == 0x4U && mode <= 0x2U && rexW && !rexR) {
                if (mode == 0 && rmEncoding == 0x5U && !rexB) {
                    throw DecodeError(
                        address, remaining,
                        "RIP-relative short qword AND is not supported");
                }
                auto base = decodeRegister(rmEncoding, rexB);
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(
                            address, remaining,
                            "truncated short qword AND memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    if (indexEncoding != 0x4U || rexX) {
                        throw DecodeError(
                            address, remaining,
                            "only no-index short qword AND memory SIB is supported");
                    }
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "no-base short qword AND memory SIB is not supported");
                    }
                    base = decodeRegister(baseEncoding, rexB);
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(
                            address, remaining,
                            "truncated short qword AND memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated short qword AND memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (cursor >= code.size()) {
                    throw DecodeError(
                        address, remaining,
                        "truncated short qword AND memory immediate");
                }
                const auto immediate =
                    std::bit_cast<std::int8_t>(code[cursor++]);
                instruction.opcode = Opcode::AndMemImm;
                instruction.operands.push_back(
                    MemoryOperand{base, displacement, 64});
                instruction.operands.push_back(ImmediateOperand{
                    static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(immediate)),
                    8});
            } else if (extension == 0x1U && mode <= 0x2U && !rexR) {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && !rexB;
                auto base = decodeRegister(rmEncoding, rexB);
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(
                            address, remaining,
                            "truncated short OR memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    if (indexEncoding != 0x4U || rexX) {
                        throw DecodeError(
                            address, remaining,
                            "only no-index short OR memory SIB is supported");
                    }
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "no-base short OR memory SIB is not supported");
                    }
                    base = decodeRegister(baseEncoding, rexB);
                }
                std::int64_t displacement = 0;
                if (ripRelative || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated short OR memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(
                            address, remaining,
                            "truncated short OR memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                }
                if (cursor >= code.size()) {
                    throw DecodeError(
                        address, remaining,
                        "truncated short OR memory immediate");
                }
                const auto immediate =
                    std::bit_cast<std::int8_t>(code[cursor++]);
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::OrMemImm;
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement,
                                        static_cast<std::uint8_t>(rexW ? 64U : 32U),
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{base, displacement,
                                        static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{
                    static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(immediate)),
                    8});
            } else if (extension == 0x0U && mode <= 0x2U && !rexR) {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && !rexB;
                auto base = decodeRegister(rmEncoding, rexB);
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(
                            address, remaining,
                            "truncated short ADD memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    if (indexEncoding != 0x4U || rexX) {
                        throw DecodeError(
                            address, remaining,
                            "only no-index short ADD memory SIB is supported");
                    }
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "no-base short ADD memory SIB is not supported");
                    }
                    base = decodeRegister(baseEncoding, rexB);
                }
                std::int64_t displacement = 0;
                if (ripRelative || mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(
                            address, remaining,
                            "truncated short ADD memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(
                            address, remaining,
                            "truncated short ADD memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                }
                if (cursor >= code.size()) {
                    throw DecodeError(
                        address, remaining,
                        "truncated short ADD memory immediate");
                }
                const auto immediate =
                    std::bit_cast<std::int8_t>(code[cursor++]);
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::AddMemImm;
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement,
                                        static_cast<std::uint8_t>(rexW ? 64U : 32U),
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{base, displacement,
                                        static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{
                    static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(immediate)),
                    8});
            } else if (extension == 0x7U && mode <= 0x2U && !rexR) {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && !rexB;
                auto base = decodeRegister(rmEncoding, rexB);
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (!ripRelative && rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated short CMP memory SIB");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    const auto baseEncoding =
                        static_cast<std::uint8_t>(sib & 0x7U);
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(
                            address, remaining,
                            "no-base short CMP memory SIB is not supported");
                    }
                    base = decodeRegister(baseEncoding, rexB);
                    if (indexEncoding != 0x4U || rexX) {
                        index = decodeRegister(indexEncoding, rexX);
                        scale = static_cast<std::uint8_t>(1U << scaleBits);
                    }
                }
                std::int64_t displacement = 0;
                if (ripRelative) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated RIP-relative short CMP disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                } else if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated short memory CMP disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated short memory CMP disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated short memory CMP immediate");
                }
                const auto immediate = std::bit_cast<std::int8_t>(code[cursor++]);
                if (ripRelative) {
                    static_cast<void>(relativeTarget(
                        address, cursor - instructionStart, displacement));
                }
                instruction.opcode = Opcode::CmpMemImm;
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{
                              Register::Rax, displacement,
                              static_cast<std::uint8_t>(rexW ? 64U : 32U),
                              std::nullopt, 1, false, true}
                        : MemoryOperand{
                              base, displacement,
                              static_cast<std::uint8_t>(rexW ? 64U : 32U),
                              index, scale});
                instruction.operands.push_back(ImmediateOperand{
                    static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 8});
            } else {
            if (!rexW && extension != 0x0U && extension != 0x1U &&
                extension != 0x2U &&
                extension != 0x3U &&
                extension != 0x4U && extension != 0x5U && extension != 0x6U &&
                extension != 0x7U) {
                throw DecodeError(address, remaining,
                                  "only 32-bit ADD /0, OR /1, ADC /2, SBB /3, AND /4, SUB /5, XOR /6, and CMP /7 are supported from legacy opcode 83");
            }
            if (mode != 0x3U || rexR || rexX ||
                (extension != 0x0U && extension != 0x1U &&
                 extension != 0x2U &&
                 extension != 0x3U && extension != 0x4U &&
                 extension != 0x5U && extension != 0x6U &&
                 extension != 0x7U)) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct ADD /0, OR /1, ADC /2, SBB /3, AND /4, SUB /5, XOR /6, and CMP /7 from opcode 83 are supported");
            }
            const auto immediate = std::bit_cast<std::int8_t>(code[cursor++]);
            instruction.opcode = extension == 0   ? Opcode::AddRegImm
                                 : extension == 1 ? Opcode::OrRegImm
                                 : extension == 2 ? Opcode::AdcRegImm
                                 : extension == 3 ? Opcode::SbbRegImm
                                 : extension == 4 ? Opcode::AndRegImm
                                 : extension == 5 ? Opcode::SubRegImm
                                 : extension == 6 ? Opcode::XorRegImm
                                                  : Opcode::CmpRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 8});
            }
        } else {
            throw DecodeError(address, remaining, "opcode is not in the current Rosa subset");
        }

        const auto length = cursor - instructionStart;
        if (length > instruction.bytes.size()) {
            throw DecodeError(address, remaining, "instruction exceeds 15-byte x86 limit");
        }
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart), length,
                    instruction.bytes.begin());
        const auto terminatesBlock = instruction.opcode == Opcode::CallReg ||
                                     instruction.opcode == Opcode::CallMem ||
                                     instruction.opcode == Opcode::JmpReg ||
                                     instruction.opcode == Opcode::JmpMem;
        result.push_back(std::move(instruction));
        if (terminatesBlock) {
            return result;
        }
        if (result.size() == maximumInstructions) {
            return result;
        }
    }

    throw DecodeError(guest::GuestAddress{start.value + cursor}, {},
                      "basic block ended without a supported terminator");
}

} // namespace rosa::x86
