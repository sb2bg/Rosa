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

        const bool testImmediateHasRex =
            code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
        const auto testImmediateOpcodeOffset =
            cursor + (testImmediateHasRex ? 1U : 0U);
        if (testImmediateOpcodeOffset < code.size() &&
            code[testImmediateOpcodeOffset] == 0xF6U) {
            if (code.size() - testImmediateOpcodeOffset < 3) {
                throw DecodeError(address, remaining, "truncated test r8, imm8");
            }
            const auto rex = testImmediateHasRex ? code[cursor] : 0U;
            const bool rexW = (rex & 0x8U) != 0;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexX = (rex & 0x2U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            const auto modrm = code[testImmediateOpcodeOffset + 1];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto registerEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode != 0x3U || extension != 0 || rexW || rexR || rexX ||
                (!testImmediateHasRex && registerEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct representable low-byte TEST from opcode F6 /0 is supported");
            }
            instruction.opcode = Opcode::TestRegImm;
            const auto length = static_cast<std::uint8_t>(
                3U + (testImmediateHasRex ? 1U : 0U));
            instruction.length = length;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor),
                        instruction.length,
                        instruction.bytes.begin());
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(registerEncoding, rexB), 8});
            instruction.operands.push_back(
                ImmediateOperand{code[testImmediateOpcodeOffset + 2], 8});
            result.push_back(std::move(instruction));
            cursor += length;
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

        if (code[cursor] == 0x0FU && code.size() - cursor >= 2 && code[cursor + 1] == 0x05U) {
            instruction.opcode = Opcode::Syscall;
            instruction.length = 2;
            instruction.bytes[0] = 0x0F;
            instruction.bytes[1] = 0x05;
            instruction.fallthrough = relativeTarget(address, 2, 0);
            result.push_back(std::move(instruction));
            return result;
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
            (code[setOpcodeOffset + 1] == 0x94U ||
             code[setOpcodeOffset + 1] == 0x95U ||
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
            if (mode != 0x3U || extension != 0 ||
                (!setHasRex && rmEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct SETE/SETNE/SETG to representable low-byte registers is supported");
            }
            instruction.opcode = Opcode::SetccReg;
            instruction.condition = conditionOpcode == 0x94U ? Condition::Equal
                                    : conditionOpcode == 0x95U ? Condition::NotEqual
                                                               : Condition::Greater;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(rmEncoding, (rex & 0x1U) != 0), 8});
            const auto length = setOpcodeOffset + 3 - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            result.push_back(std::move(instruction));
            cursor = setOpcodeOffset + 3;
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
            if (mode == 0 && rmEncoding == 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "only MOVZX r32/r64, low-byte register or byte [base+index*scale+disp8/disp32] is supported");
            }
            const auto destination = RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
                static_cast<std::uint8_t>(rexW ? 64U : 32U)};
            if (mode == 0x3U) {
                if (!movzxByteHasRex && rmEncoding >= 0x4U) {
                    throw DecodeError(address, remaining,
                                      "legacy high-byte MOVZX registers are unsupported");
                }
                instruction.opcode = Opcode::MovzxRegReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, rexB), 8});
            } else {
                auto baseEncoding = rmEncoding;
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (rmEncoding == 0x4U) {
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
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated byte MOVZX disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::MovzxRegMem;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(baseEncoding, rexB), displacement, 8, index, scale});
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
            code[cursor + 1] == 0xBCU) {
            if (code.size() - cursor < 3) {
                throw DecodeError(address, remaining, "truncated bsf r32, r32");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(address, remaining,
                                  "only register-direct 32-bit BSF is supported");
            }
            instruction.opcode = Opcode::BitScanForwardRegReg;
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
            code[cursor + 1] == 0x57U) {
            if (code.size() - cursor < 3) {
                throw DecodeError(address, remaining, "truncated xorps xmm, xmm");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(address, remaining,
                                  "only register-direct XORPS is supported");
            }
            instruction.opcode = Opcode::XorpsRegReg;
            instruction.length = 3;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                        instruction.bytes.begin());
            instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(modrm & 0x7U))});
            result.push_back(std::move(instruction));
            cursor += 3;
            if (result.size() == maximumInstructions) {
                return result;
            }
            continue;
        }

        if (code[cursor] == 0x66U && code.size() - cursor >= 2) {
            const auto afterSizePrefix = cursor + 1;
            const bool testHasRex = code[afterSizePrefix] >= 0x40U &&
                                    code[afterSizePrefix] <= 0x4FU;
            const auto testOpcodeOffset = afterSizePrefix + (testHasRex ? 1U : 0U);
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

        if (code[cursor] == 0x66U && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0x83U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated cmp word [memory], imm8");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (extension != 0x7U ||
                (mode != 0x3U &&
                 (rmEncoding == 0x4U ||
                  (mode == 0 && rmEncoding == 0x5U)))) {
                throw DecodeError(
                    address, remaining,
                    "only CMP r16 or word [base+disp8/disp32], imm8 is supported");
            }
            auto operandCursor = cursor + 3;
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
                    decodeRegister(rmEncoding, false), 16});
            } else {
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, false), displacement, 16});
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

        if (code[cursor] == 0x66U && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0x89U) {
            if (code.size() - cursor < 3) {
                throw DecodeError(address, remaining,
                                  "truncated mov word [memory], register");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOV word [base+disp8/disp32], register is supported");
            }
            auto operandCursor = cursor + 3;
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
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
            instruction.opcode = Opcode::MovMemReg;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, false), displacement, 16});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U),
                               false),
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

        if (code[cursor] == 0x66U && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0xC7U) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining,
                                  "truncated mov word [memory], imm16");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            auto operandCursor = cursor + 3;
            if (mode > 0x2U || extension != 0 || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOV word [base+disp8/disp32], imm16 is supported");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOV word memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated MOV word memory disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            if (code.size() - operandCursor < 2) {
                throw DecodeError(address, remaining, "truncated MOV word imm16");
            }
            const auto immediate = static_cast<std::uint16_t>(
                static_cast<std::uint16_t>(code[operandCursor]) |
                (static_cast<std::uint16_t>(code[operandCursor + 1]) << 8U));
            operandCursor += 2;
            instruction.opcode = Opcode::MovMemImm;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, false), displacement, 16});
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

        if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0xEFU) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated pxor xmm, xmm");
            }
            const auto modrm = code[cursor + 3];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U) {
                throw DecodeError(address, remaining,
                                  "only register-direct PXOR is supported");
            }
            instruction.opcode = Opcode::PxorRegReg;
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
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x74U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated pcmpeqb xmm, [memory]");
            }
            cursor += 3;
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only PCMPEQB xmm, [base+disp8/disp32] is supported");
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

        if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0xD6U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated movq [memory], xmm");
            }
            const auto modrm = code[cursor + 3];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVQ [base+disp8/disp32], xmm memory operands are supported");
            }
            auto operandCursor = cursor + 4;
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
                decodeRegister(rmEncoding, false), displacement, 64});
            instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U))});
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

        if (code[cursor] == 0x0FU && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0x29U) {
            if (code.size() - cursor < 3) {
                throw DecodeError(address, remaining, "truncated movaps [base+disp], xmm");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (mode > 0x2U || rmEncoding == 0x4U) {
                throw DecodeError(
                    address, remaining,
                    "only MOVAPS [base/RIP+disp8/disp32], xmm memory operands are supported");
            }
            cursor += 3;
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
            instruction.opcode = Opcode::MovapsMemReg;
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 128,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(rmEncoding, false),
                                    displacement, 128});
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

        if (code[cursor] == 0x0FU && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0x11U) {
            if (code.size() - cursor < 3) {
                throw DecodeError(address, remaining, "truncated movups [base+disp], xmm");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U) {
                throw DecodeError(
                    address, remaining,
                    "only MOVUPS [base+disp8/disp32], xmm memory operands are supported");
            }
            cursor += 3;
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
                if (indexEncoding != 0x4U) {
                    index = decodeRegister(indexEncoding, false);
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
                    : MemoryOperand{decodeRegister(baseEncoding, false),
                                    displacement, 128, index, scale});
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

        const bool movupsLoadHasRex =
            code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
        const auto movupsLoadOpcodeOffset = cursor + (movupsLoadHasRex ? 1U : 0U);
        if (code.size() - movupsLoadOpcodeOffset >= 2 &&
            code[movupsLoadOpcodeOffset] == 0x0FU &&
            (code[movupsLoadOpcodeOffset + 1] == 0x10U ||
             code[movupsLoadOpcodeOffset + 1] == 0x28U)) {
            const bool aligned = code[movupsLoadOpcodeOffset + 1] == 0x28U;
            if (code.size() - movupsLoadOpcodeOffset < 3) {
                throw DecodeError(address, remaining,
                                  "truncated xmm load from guest memory");
            }
            const auto rex = movupsLoadHasRex ? code[cursor] : 0U;
            const bool rexR = (rex & 0x4U) != 0;
            const bool rexX = (rex & 0x2U) != 0;
            const bool rexB = (rex & 0x1U) != 0;
            const auto modrm = code[movupsLoadOpcodeOffset + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || rexX || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVAPS/MOVUPS xmm, [base+disp8/disp32] memory operands are supported");
            }
            auto operandCursor = movupsLoadOpcodeOffset + 3;
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
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
            instruction.opcode = aligned ? Opcode::MovapsRegMem
                                         : Opcode::MovupsRegMem;
            instruction.operands.push_back(XmmRegisterOperand{static_cast<XmmRegister>(
                static_cast<std::uint8_t>(((modrm >> 3U) & 0x7U) |
                                          (rexR ? 0x8U : 0U)))});
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, rexB), displacement, 128});
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

        if (code[cursor] == 0x66U && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x6FU) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated movdqa xmm, [base+disp]");
            }
            const auto modrm = code[cursor + 3];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVDQA xmm, [base+disp8/disp32] memory operands are supported");
            }
            cursor += 4;
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated MOVDQA memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated MOVDQA memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::MovdqaRegMem;
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

        if (code[cursor] == 0xF3U && code.size() - cursor >= 3 &&
            code[cursor + 1] == 0x0FU && code[cursor + 2] == 0x7FU) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated movdqu [base+disp], xmm");
            }
            const auto modrm = code[cursor + 3];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVDQU [base+disp8/disp32], xmm memory operands are supported");
            }
            cursor += 4;
            auto baseEncoding = rmEncoding;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated MOVDQU SIB byte");
                }
                const auto sib = code[cursor++];
                const auto indexEncoding = static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (indexEncoding != 0x4U || (mode == 0 && baseEncoding == 0x5U)) {
                    throw DecodeError(address, remaining,
                                      "only no-index MOVDQU SIB addressing is supported");
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
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
            instruction.opcode = Opcode::MovdquMemReg;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(baseEncoding, false), displacement, 128});
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
                if (mode > 0x2U || rexX || rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only MOVDQU xmm, [base+disp8/disp32] memory operands are supported");
                }
                auto operandCursor = opcodeOffset + 3;
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated MOVDQU load disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated MOVDQU load disp32");
                    }
                    displacement = readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                instruction.opcode = Opcode::MovdquRegMem;
                instruction.operands.push_back(
                    XmmRegisterOperand{static_cast<XmmRegister>(
                        static_cast<std::uint8_t>(((modrm >> 3U) & 0x7U) |
                                                  (rexR ? 0x8U : 0U)))});
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement, 128});
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

        if (code[cursor] == 0xEBU || code[cursor] == 0x72U || code[cursor] == 0x73U ||
            code[cursor] == 0x74U ||
            code[cursor] == 0x75U || code[cursor] == 0x76U || code[cursor] == 0x77U ||
            code[cursor] == 0x78U || code[cursor] == 0x7EU) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining, "truncated rel8 control transfer");
            }
            const auto opcode = code[cursor];
            const auto displacement = std::bit_cast<std::int8_t>(code[cursor + 1]);
            instruction.opcode = opcode == 0xEBU ? Opcode::JmpRelative : Opcode::JccRelative;
            instruction.length = 2;
            instruction.bytes[0] = opcode;
            instruction.bytes[1] = code[cursor + 1];
            instruction.branchTarget = relativeTarget(address, 2, displacement);
            instruction.fallthrough = guest::GuestAddress{address.value + 2};
            if (opcode != 0xEBU) {
                instruction.condition = opcode == 0x72U   ? Condition::Below
                                        : opcode == 0x73U ? Condition::AboveOrEqual
                                        : opcode == 0x74U ? Condition::Equal
                                        : opcode == 0x75U ? Condition::NotEqual
                                        : opcode == 0x76U ? Condition::BelowOrEqual
                                        : opcode == 0x78U ? Condition::Sign
                                        : opcode == 0x7EU ? Condition::LessOrEqual
                                                          : Condition::Above;
            }
            result.push_back(std::move(instruction));
            return result;
        }

        if (code[cursor] == 0xF0U && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0x83U) {
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
                    "only LOCK OR dword [base+disp8/disp32], imm8 is supported");
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
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated LOCK OR immediate");
            }
            const auto immediate = std::bit_cast<std::int8_t>(code[cursor++]);
            instruction.opcode = Opcode::LockOrMemImm;
            instruction.operands.push_back(
                MemoryOperand{base, displacement, 32});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(immediate)),
                8});
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
            if (code.size() - cursor < 4 || code[cursor + 1] != 0x0FU ||
                code[cursor + 2] != 0xB1U) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK CMPXCHG r/m32, r32 is supported from prefix F0");
            }
            cursor += 3;
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0x3U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK CMPXCHG dword [base+disp8/disp32], r32 is supported");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
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
            instruction.opcode = Opcode::CmpxchgMemReg;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, false), displacement, 32});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, false), 32});
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
            if (code.size() - cursor < 6 ||
                (code[cursor + 1] != 0x82U && code[cursor + 1] != 0x83U &&
                 code[cursor + 1] != 0x84U &&
                 code[cursor + 1] != 0x85U && code[cursor + 1] != 0x86U &&
                 code[cursor + 1] != 0x87U && code[cursor + 1] != 0x88U)) {
                throw DecodeError(address, remaining,
                                  "only JB/JAE/JE/JNE/JBE/JA/JS rel32 from opcode 0F is supported");
            }
            const auto secondOpcode = code[cursor + 1];
            const auto displacement = readI32(code.subspan(cursor + 2, 4));
            instruction.opcode = Opcode::JccRelative;
            instruction.condition = secondOpcode == 0x82U   ? Condition::Below
                                    : secondOpcode == 0x83U ? Condition::AboveOrEqual
                                    : secondOpcode == 0x84U ? Condition::Equal
                                    : secondOpcode == 0x85U ? Condition::NotEqual
                                    : secondOpcode == 0x86U ? Condition::BelowOrEqual
                                    : secondOpcode == 0x87U ? Condition::Above
                                                            : Condition::Sign;
            instruction.length = 6;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 6,
                        instruction.bytes.begin());
            instruction.branchTarget = relativeTarget(address, 6, displacement);
            instruction.fallthrough = guest::GuestAddress{address.value + 6};
            result.push_back(std::move(instruction));
            return result;
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
        if (!hasRex && code[cursor] != 0x24U && code[cursor] != 0x34U &&
            code[cursor] != 0x00U && code[cursor] != 0x02U &&
            code[cursor] != 0x88U &&
            code[cursor] != 0x89U &&
            code[cursor] != 0x8AU && code[cursor] != 0x8BU &&
            code[cursor] != 0x8DU &&
            code[cursor] != 0x85U && code[cursor] != 0x83U &&
            code[cursor] != 0x84U && code[cursor] != 0x31U &&
            code[cursor] != 0x20U && code[cursor] != 0x21U &&
            code[cursor] != 0x22U &&
            code[cursor] != 0x08U &&
            code[cursor] != 0x09U &&
            code[cursor] != 0x87U &&
            code[cursor] != 0x2BU && code[cursor] != 0x33U &&
            code[cursor] != 0x39U && code[cursor] != 0x3AU &&
            code[cursor] != 0x3BU &&
            code[cursor] != 0x80U &&
            code[cursor] != 0x81U && code[cursor] != 0xC1U &&
            code[cursor] != 0xC6U && code[cursor] != 0xC7U &&
            code[cursor] != 0xD3U &&
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
        if (hasGsOverride && opcode != 0x8BU) {
            throw DecodeError(address, remaining,
                              "GS segment override is only supported for MOV r32, r/m32");
        }
        if (!rexW && opcode != 0x24U && opcode != 0x34U &&
            opcode != 0x00U && opcode != 0x02U &&
            opcode != 0x88U && opcode != 0x89U &&
            opcode != 0x8AU &&
            opcode != 0x8BU && opcode != 0x85U &&
            opcode != 0x8DU &&
            opcode != 0x08U && opcode != 0x09U &&
            opcode != 0x87U &&
            opcode != 0x84U && opcode != 0x83U && opcode != 0x3BU &&
            opcode != 0x3AU &&
            opcode != 0x31U && opcode != 0x39U && opcode != 0x80U &&
            opcode != 0x2BU && opcode != 0x33U &&
            opcode != 0x20U && opcode != 0x21U && opcode != 0x22U &&
            opcode != 0x81U && opcode != 0xC1U &&
            opcode != 0xC6U && opcode != 0xC7U && opcode != 0xD3U &&
            opcode != 0xFEU && opcode != 0xFFU &&
            (opcode < 0xB8U || opcode > 0xBFU)) {
            throw DecodeError(address, remaining,
                              "only a 32-bit memory MOV is supported without REX.W");
        }
        if (opcode == 0x24U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated and al, imm8");
            }
            instruction.opcode = Opcode::AndRegImm;
            instruction.operands.push_back(RegisterOperand{Register::Rax, 8});
            instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
        } else if (opcode == 0x34U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated xor al, imm8");
            }
            instruction.opcode = Opcode::XorRegImm;
            instruction.operands.push_back(RegisterOperand{Register::Rax, 8});
            instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
        } else if (opcode == 0x98U && rexW) {
            instruction.opcode = Opcode::Cdqe;
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
        } else if (opcode == 0x0FU) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated REX.W 0F opcode");
            }
            const auto secondOpcode = code[cursor++];
            if (secondOpcode != 0x42U && secondOpcode != 0x43U &&
                secondOpcode != 0x44U &&
                secondOpcode != 0xACU &&
                secondOpcode != 0xAFU && secondOpcode != 0xBCU) {
                throw DecodeError(
                    address, remaining,
                    "only CMOVB/CMOVAE/CMOVE, IMUL, SHRD, and BSF register forms are supported from REX.W 0F");
            }
            if (cursor >= code.size() ||
                (secondOpcode == 0xACU && code.size() - cursor < 2)) {
                throw DecodeError(address, remaining,
                                  secondOpcode == 0xACU ? "truncated SHRD r64"
                                  : secondOpcode == 0xAFU ? "truncated IMUL r64"
                                  : secondOpcode == 0xBCU ? "truncated BSF r64"
                                                          : "truncated CMOVB r64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || rexX) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct CMOVB/CMOVAE/CMOVE/IMUL/SHRD/BSF is supported");
            }
            const auto encodedReg =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto encodedRm =
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            if (secondOpcode == 0x42U || secondOpcode == 0x43U ||
                secondOpcode == 0x44U) {
                instruction.opcode = Opcode::CmovccReg;
                instruction.condition = secondOpcode == 0x42U
                                            ? Condition::Below
                                        : secondOpcode == 0x43U
                                            ? Condition::AboveOrEqual
                                            : Condition::Equal;
                instruction.operands.push_back(RegisterOperand{encodedReg, 64});
                instruction.operands.push_back(RegisterOperand{encodedRm, 64});
            } else if (secondOpcode == 0xBCU) {
                instruction.opcode = Opcode::BitScanForwardRegReg;
                instruction.operands.push_back(RegisterOperand{encodedReg, 64});
                instruction.operands.push_back(RegisterOperand{encodedRm, 64});
            } else if (secondOpcode == 0xAFU) {
                instruction.opcode = Opcode::ImulRegReg;
                instruction.operands.push_back(RegisterOperand{encodedReg, 64});
                instruction.operands.push_back(RegisterOperand{encodedRm, 64});
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
                throw DecodeError(address, remaining, "truncated add r64, r64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct ADD from opcode 01 is supported");
            }
            const auto source =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto destination =
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            instruction.opcode = Opcode::AddRegReg;
            instruction.operands.push_back(RegisterOperand{destination, 64});
            instruction.operands.push_back(RegisterOperand{source, 64});
        } else if (opcode == 0x03U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated add r64, [base+disp]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (rexX || mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only ADD r64, [base+disp8/disp32] memory operands are supported");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
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
            const auto base = decodeRegister(rmEncoding, rexB);
            instruction.opcode = Opcode::AddRegMem;
            instruction.operands.push_back(RegisterOperand{destination, 64});
            instruction.operands.push_back(MemoryOperand{base, displacement, 64});
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
            if (mode != 0x3U ||
                (!hasRex &&
                 (sourceEncoding >= 0x4U || destinationEncoding >= 0x4U))) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct representable low-byte OR from opcode 08 is supported");
            }
            instruction.opcode = Opcode::OrRegReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(destinationEncoding, rexB), 8});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(sourceEncoding, rexR), 8});
        } else if (opcode == 0x09U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated or r64, r64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct OR from opcode 09 is supported");
            }
            const auto source =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto destination =
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.opcode = Opcode::OrRegReg;
            instruction.operands.push_back(RegisterOperand{destination, width});
            instruction.operands.push_back(RegisterOperand{source, width});
        } else if (opcode == 0x2BU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated sub register, [base+disp]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (rexX || mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only SUB register, [base+disp8/disp32] memory operands are supported");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
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
            const auto base = decodeRegister(rmEncoding, rexB);
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.opcode = Opcode::SubRegMem;
            instruction.operands.push_back(RegisterOperand{destination, width});
            instruction.operands.push_back(MemoryOperand{base, displacement, width});
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
                throw DecodeError(address, remaining, "truncated and register, register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct AND from opcode 21 is supported");
            }
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            const auto source =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto destination =
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            instruction.opcode = Opcode::AndRegReg;
            instruction.operands.push_back(RegisterOperand{destination, width});
            instruction.operands.push_back(RegisterOperand{source, width});
        } else if (opcode == 0x29U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated sub register, register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct SUB from opcode 29 is supported");
            }
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            const auto source =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto destination =
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            instruction.opcode = Opcode::SubRegReg;
            instruction.operands.push_back(RegisterOperand{destination, width});
            instruction.operands.push_back(RegisterOperand{source, width});
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
        } else if (opcode == 0x63U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated movsxd r64, [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (!rexW || mode > 0x2U || (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVSXD r64, dword [base+index*scale+disp] is supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated MOVSXD memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits = static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding = static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if ((indexEncoding == 0x4U && !rexX) ||
                    (mode == 0 && baseEncoding == 0x5U && !rexB)) {
                    throw DecodeError(address, remaining,
                                      "MOVSXD SIB requires register base and index");
                }
                base = decodeRegister(baseEncoding, rexB);
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            } else if (rexX) {
                throw DecodeError(address, remaining,
                                  "REX.X requires a SIB operand for MOVSXD");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated MOVSXD disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated MOVSXD disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::MovsxdRegMem;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR), 64});
            instruction.operands.push_back(MemoryOperand{
                base, displacement, 32, index, scale});
        } else if (opcode == 0x33U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated xor register, [memory]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || rexX || (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only XOR register, [base+disp8/disp32] is supported");
            }
            auto baseEncoding = rmEncoding;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated XOR memory SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits = static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding = static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (scaleBits != 0 || indexEncoding != 0x4U ||
                    (mode == 0 && baseEncoding == 0x5U && !rexB)) {
                    throw DecodeError(address, remaining,
                                      "only no-index SIB addressing is supported for XOR");
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
            const auto operandWidth = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
                operandWidth});
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(baseEncoding, rexB), displacement, operandWidth});
        } else if (opcode == 0x39U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated cmp r/m, register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (rexX || (mode != 0x3U && rmEncoding == 0x4U) ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(address, remaining,
                                  "only register-direct or [base+disp8/disp32] CMP from opcode 39 is supported");
            }
            const auto rhs =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            if (mode == 0x3U) {
                const auto lhs = decodeRegister(rmEncoding, rexB);
                instruction.opcode = Opcode::CmpRegReg;
                instruction.operands.push_back(RegisterOperand{lhs, width});
                instruction.operands.push_back(RegisterOperand{rhs, width});
            } else {
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
                instruction.opcode = Opcode::CmpMemReg;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement, width});
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
            if (rexX || mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only CMP register, [base+disp8/disp32] memory operands are supported");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
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
            const auto base = decodeRegister(rmEncoding, rexB);
            const auto operandWidth = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.opcode = Opcode::CmpRegMem;
            instruction.operands.push_back(RegisterOperand{lhs, operandWidth});
            instruction.operands.push_back(MemoryOperand{base, displacement, operandWidth});
        } else if (opcode == 0x87U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining,
                                  "truncated xchg dword [memory], register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (rexW || rexX || mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only XCHG dword [base+disp8/disp32], register is supported");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated XCHG dword disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated XCHG dword disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::XchgMemReg;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, rexB), displacement, 32});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(
                    static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
                32});
        } else if (opcode == 0x88U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated mov byte [memory], register");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (rexW || mode > 0x2U ||
                (!hasRex && regEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOV byte [base+index*scale+disp8/disp32], low-byte-register is supported");
            }
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
            const auto operandWidth = static_cast<std::uint8_t>(rexW ? 64U : 32U);
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
                    if (noBase && (!hasGsOverride || opcode != 0x8BU || hasIndex)) {
                        throw DecodeError(
                            address, remaining,
                            "unsupported MOV SIB addressing form");
                    }
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
                        MemoryOperand{base, displacement, operandWidth, index, scale});
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
        } else if (opcode == 0x84U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated test r8, r8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode != 0x3U ||
                (!hasRex &&
                 (regEncoding >= 0x4U || rmEncoding >= 0x4U))) {
                throw DecodeError(
                    address, remaining,
                    "only representable low-byte register TEST is supported");
            }
            instruction.opcode = Opcode::TestReg8Reg8;
            instruction.operands.push_back(
                RegisterOperand{decodeRegister(rmEncoding, rexB), 8});
            instruction.operands.push_back(
                RegisterOperand{decodeRegister(regEncoding, rexR), 8});
        } else if (opcode == 0x85U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated test r64, r64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct TEST from opcode 85 is supported");
            }
            const auto reg = decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto rm = decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            const auto operandWidth = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.opcode = Opcode::TestRegReg;
            instruction.operands.push_back(RegisterOperand{rm, operandWidth});
            instruction.operands.push_back(RegisterOperand{reg, operandWidth});
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
        } else if (opcode == 0xC1U) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining, "truncated shift register, imm8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode != 0x3U || rexR || rexX ||
                (extension != 0x4U && extension != 0x5U)) {
                throw DecodeError(address, remaining,
                                  "only SHL/SHR r32/r64 register forms from opcode C1 are supported");
            }
            instruction.opcode = extension == 0x4U ? Opcode::ShlRegImm : Opcode::ShrRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
        } else if (opcode == 0xD3U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated shl register, cl");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode != 0x3U || extension != 0x4U || rexR || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct SHL /4 from opcode D3 is supported");
            }
            instruction.opcode = Opcode::ShlRegCl;
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
            if (mode != 0x3U || (extension != 0x3U && extension != 0x4U) ||
                !rexW || rexR || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct NEG /3 and MUL /4 r64 from opcode F7 are supported");
            }
            instruction.opcode = extension == 0x3U ? Opcode::NegReg : Opcode::MulReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), 64});
        } else if (opcode == 0xC6U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated mov byte opcode C6");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
            if (mode > 0x2U || extension != 0 || rexR || rexX ||
                rmEncoding == 0x4U) {
                throw DecodeError(
                    address, remaining,
                    "only MOV byte [base/RIP+disp8/disp32], imm8 from opcode C6 /0 is supported");
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
                    : MemoryOperand{decodeRegister(rmEncoding, rexB),
                                    displacement, 8});
            instruction.operands.push_back(ImmediateOperand{immediate, 8});
        } else if (opcode == 0xC7U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated mov opcode C7");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
            if (extension != 0 || rexR || rexX ||
                (mode != 0x3U && (rmEncoding == 0x4U ||
                                  (mode == 0 && rmEncoding == 0x5U && !ripRelative)))) {
                throw DecodeError(address, remaining,
                                  "only register or [base+disp] MOV from opcode C7 /0 is supported");
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative MOV memory disp32");
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
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{decodeRegister(rmEncoding, rexB),
                                        displacement, operandWidth});
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
            if (mode == 0x3U && (extension == 0x0U || extension == 0x5U) &&
                rexW && !rexR && !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated add/sub r64, imm32");
                }
                const auto immediate = readI32(code.subspan(cursor, 4));
                cursor += 4;
                instruction.opcode = extension == 0x0U ? Opcode::AddRegImm
                                                       : Opcode::SubRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), 64});
                instruction.operands.push_back(ImmediateOperand{
                    static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 32});
            } else if (mode == 0x3U && extension == 0x4U && !rexW && !rexR &&
                       !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated and r32, imm32");
                }
                const auto immediate = static_cast<std::uint32_t>(
                    readI32(code.subspan(cursor, 4)));
                cursor += 4;
                instruction.opcode = Opcode::AndRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), 32});
                instruction.operands.push_back(ImmediateOperand{immediate, 32});
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
            } else if (mode == 0x3U && extension == 0x7U && !rexW && !rexR &&
                       !rexX) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining, "truncated cmp r32, imm32");
                }
                const auto immediate = static_cast<std::uint32_t>(
                    readI32(code.subspan(cursor, 4)));
                cursor += 4;
                instruction.opcode = Opcode::CmpRegImm;
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), 32});
                instruction.operands.push_back(ImmediateOperand{immediate, 32});
            } else if (mode <= 0x2U && extension == 0x7U && !rexW && !rexR &&
                       !rexX) {
                const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
                if (rmEncoding == 0x4U || (mode == 0 && rmEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only CMP [base+disp8/disp32], imm32 memory operands are supported");
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
                const auto immediate = static_cast<std::uint32_t>(
                    readI32(code.subspan(cursor, 4)));
                cursor += 4;
                instruction.opcode = Opcode::CmpMemImm;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement, 32});
                instruction.operands.push_back(ImmediateOperand{immediate, 32});
            } else {
                throw DecodeError(
                    address, remaining,
                    "only ADD /0, AND r32 /4, SUB /5, XOR /6, and CMP /7 forms from opcode 81 are supported");
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
            if (mode != 0x3U || extension > 1 ||
                (!hasRex && rmEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only representable register-direct INC/DEC r8 is supported");
            }
            instruction.opcode = extension == 0 ? Opcode::IncReg
                                                 : Opcode::DecReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(rmEncoding, rexB), 8});
        } else if (opcode == 0xFFU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated indirect call");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (extension == 0x0U && mode <= 0x2U && rexW && !rexR && !rexX &&
                rmEncoding != 0x4U &&
                !(mode == 0 && rmEncoding == 0x5U && !rexB)) {
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated INC qword memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated INC qword memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::IncMem;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement, 64});
            } else if (extension == 0x1U && mode <= 0x2U && rexW && !rexR &&
                       !rexX && rmEncoding != 0x4U &&
                       !(mode == 0 && rmEncoding == 0x5U && !rexB)) {
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated DEC qword memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated DEC qword memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::DecMem;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement, 64});
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
            } else if (extension != 0x2U || mode > 0x2U || rexR || rexX ||
                       (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only register INC /0, qword memory INC /0, register/qword memory DEC /1, CALL memory /2, and register JMP /4 are supported from opcode FF");
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
            if (extension == 0x7U && mode <= 0x2U && !rexR && !rexX) {
                const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
                if (rmEncoding == 0x4U) {
                    throw DecodeError(
                        address, remaining,
                        "only CMP dword [base/RIP+disp8/disp32], imm8 is supported");
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
                              decodeRegister(rmEncoding, rexB), displacement,
                              static_cast<std::uint8_t>(rexW ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{
                    static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 8});
            } else {
            if (!rexW && extension != 0x0U && extension != 0x1U &&
                extension != 0x4U && extension != 0x5U &&
                extension != 0x7U) {
                throw DecodeError(address, remaining,
                                  "only 32-bit ADD /0, OR /1, AND /4, SUB /5, and CMP /7 are supported from legacy opcode 83");
            }
            if (mode != 0x3U || rexR || rexX ||
                (extension != 0x0U && extension != 0x1U && extension != 0x4U && extension != 0x5U &&
                 extension != 0x7U)) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct ADD /0, OR /1, AND /4, SUB /5, and CMP /7 from opcode 83 are supported");
            }
            const auto immediate = std::bit_cast<std::int8_t>(code[cursor++]);
            instruction.opcode = extension == 0   ? Opcode::AddRegImm
                                 : extension == 1 ? Opcode::OrRegImm
                                 : extension == 4 ? Opcode::AndRegImm
                                 : extension == 5 ? Opcode::SubRegImm
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
        const auto terminatesBlock = instruction.opcode == Opcode::CallMem ||
                                     instruction.opcode == Opcode::JmpReg;
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
