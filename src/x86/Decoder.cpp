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

        if (code[cursor] == 0x0FU && code.size() - cursor >= 2 &&
            code[cursor + 1] == 0x29U) {
            if (code.size() - cursor < 3) {
                throw DecodeError(address, remaining, "truncated movaps [base+disp], xmm");
            }
            const auto modrm = code[cursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVAPS [base+disp8/disp32], xmm memory operands are supported");
            }
            cursor += 3;
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
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
            instruction.opcode = Opcode::MovapsMemReg;
            instruction.operands.push_back(MemoryOperand{
                decodeRegister(rmEncoding, false), displacement, 128});
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
            if (mode > 0x2U || (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only MOVUPS [base+disp8/disp32], xmm memory operands are supported");
            }
            cursor += 3;
            auto baseEncoding = rmEncoding;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining, "truncated MOVUPS SIB byte");
                }
                const auto sib = code[cursor++];
                const auto indexEncoding = static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (indexEncoding != 0x4U || (mode == 0 && baseEncoding == 0x5U)) {
                    throw DecodeError(address, remaining,
                                      "only no-index MOVUPS SIB addressing is supported");
                }
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
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
            instruction.opcode = Opcode::MovupsMemReg;
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

        if (code[cursor] == 0xEBU || code[cursor] == 0x74U || code[cursor] == 0x75U) {
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
                instruction.condition = opcode == 0x74U ? Condition::Equal : Condition::NotEqual;
            }
            result.push_back(std::move(instruction));
            return result;
        }

        if (code[cursor] == 0x0FU) {
            if (code.size() - cursor < 6 ||
                (code[cursor + 1] != 0x84U && code[cursor + 1] != 0x85U)) {
                throw DecodeError(address, remaining,
                                  "only JE/JNE rel32 from opcode 0F is supported");
            }
            const auto secondOpcode = code[cursor + 1];
            const auto displacement = readI32(code.subspan(cursor + 2, 4));
            instruction.opcode = Opcode::JccRelative;
            instruction.condition = secondOpcode == 0x84U ? Condition::Equal : Condition::NotEqual;
            instruction.length = 6;
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 6,
                        instruction.bytes.begin());
            instruction.branchTarget = relativeTarget(address, 6, displacement);
            instruction.fallthrough = guest::GuestAddress{address.value + 6};
            result.push_back(std::move(instruction));
            return result;
        }

        const bool hasRex = code[cursor] >= 0x40U && code[cursor] <= 0x4FU;
        if (!hasRex && code[cursor] != 0x8BU && code[cursor] != 0x83U) {
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
        if (!rexW && opcode != 0x8BU && opcode != 0x85U && opcode != 0x83U &&
            opcode != 0x3BU) {
            throw DecodeError(address, remaining,
                              "only a 32-bit memory MOV is supported without REX.W");
        }
        if (opcode >= 0xB8U && opcode <= 0xBFU) {
            if (code.size() - cursor < sizeof(std::uint64_t)) {
                throw DecodeError(address, remaining, "truncated mov r64, imm64");
            }
            instruction.opcode = Opcode::MovRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(opcode - 0xB8U), rexB), 64});
            instruction.operands.push_back(ImmediateOperand{readU64(code.subspan(cursor, 8)), 64});
            cursor += sizeof(std::uint64_t);
        } else if (opcode == 0x0FU) {
            if (code.size() - cursor < 3 || code[cursor] != 0xACU) {
                throw DecodeError(address, remaining,
                                  "only SHRD r64, r64, imm8 is supported from REX.W 0F");
            }
            ++cursor;
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct SHRD is supported");
            }
            const auto source =
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto destination =
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            instruction.opcode = Opcode::ShrdRegRegImm;
            instruction.operands.push_back(RegisterOperand{destination, 64});
            instruction.operands.push_back(RegisterOperand{source, 64});
            instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
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
            instruction.opcode = Opcode::OrRegReg;
            instruction.operands.push_back(RegisterOperand{destination, 64});
            instruction.operands.push_back(RegisterOperand{source, 64});
        } else if (opcode == 0x2BU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated sub r64, [base+disp]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (rexX || mode > 0x2U || rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only SUB r64, [base+disp8/disp32] memory operands are supported");
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
            instruction.opcode = Opcode::SubRegMem;
            instruction.operands.push_back(RegisterOperand{destination, 64});
            instruction.operands.push_back(MemoryOperand{base, displacement, 64});
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
        } else if (opcode == 0x89U || opcode == 0x8BU) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated mov r64, r64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto reg = decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
            const auto rm = decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB);
            const auto operandWidth = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            if (mode == 0x3U && !rexX && rexW) {
                instruction.opcode = Opcode::MovRegReg;
                instruction.operands.push_back(RegisterOperand{opcode == 0x89U ? rm : reg, 64});
                instruction.operands.push_back(RegisterOperand{opcode == 0x89U ? reg : rm, 64});
            } else {
                const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
                if (rexX || mode > 0x2U || rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U) || (!rexW && opcode != 0x8BU)) {
                    throw DecodeError(
                        address, remaining,
                        "only MOV r64 to/from [base+disp8/disp32] memory operands are supported");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
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
                        MemoryOperand{rm, displacement, operandWidth});
                    instruction.operands.push_back(RegisterOperand{reg, operandWidth});
                } else {
                    instruction.opcode = Opcode::MovRegMem;
                    instruction.operands.push_back(RegisterOperand{reg, operandWidth});
                    instruction.operands.push_back(
                        MemoryOperand{rm, displacement, operandWidth});
                }
            }
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
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining, "truncated lea r64, [rip+disp32]");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto memoryRegister = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode != 0 || memoryRegister != 5 || rexB || rexX) {
                throw DecodeError(address, remaining,
                                  "only RIP-relative LEA with disp32 is supported");
            }
            const auto displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
            const auto length = cursor - instructionStart;
            const auto target = relativeTarget(address, length, displacement);
            const auto destination = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            instruction.opcode = Opcode::LeaRegRipRelative;
            instruction.operands.push_back(RegisterOperand{decodeRegister(destination, rexR), 64});
            instruction.operands.push_back(ImmediateOperand{target.value, 64});
        } else if (opcode == 0xC1U) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining, "truncated shl r64, imm8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode != 0x3U || extension != 0x4U || rexR || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct SHL /4 from opcode C1 is supported");
            }
            instruction.opcode = Opcode::ShlRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), 64});
            instruction.operands.push_back(ImmediateOperand{code[cursor++], 8});
        } else if (opcode == 0xD3U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated shl r64, cl");
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
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), 64});
        } else if (opcode == 0xF7U) {
            if (code.size() - cursor < 1) {
                throw DecodeError(address, remaining, "truncated mul r64");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode != 0x3U || extension != 0x4U || rexR || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct MUL /4 from opcode F7 is supported");
            }
            instruction.opcode = Opcode::MulReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), 64});
        } else if (opcode == 0xC7U) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining, "truncated mov r64, imm32");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode != 0x3U || extension != 0 || rexR || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct MOV from opcode C7 /0 is supported");
            }
            const auto immediate = readI32(code.subspan(cursor, 4));
            cursor += 4;
            instruction.opcode = Opcode::MovRegImm;
            instruction.operands.push_back(
                RegisterOperand{decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), 64});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 32});
        } else if (opcode == 0x81U) {
            if (code.size() - cursor < 5) {
                throw DecodeError(address, remaining, "truncated sub r64, imm32");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode != 0x3U || extension != 0x5U || rexR || rexX) {
                throw DecodeError(address, remaining,
                                  "only register-direct SUB /5 from opcode 81 is supported");
            }
            const auto immediate = readI32(code.subspan(cursor, 4));
            cursor += 4;
            instruction.opcode = Opcode::SubRegImm;
            instruction.operands.push_back(
                RegisterOperand{decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), 64});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 32});
        } else if (opcode == 0x83U) {
            if (code.size() - cursor < 2) {
                throw DecodeError(address, remaining, "truncated add r64, imm8");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (!rexW && extension != 0x4U) {
                throw DecodeError(address, remaining,
                                  "only 32-bit AND /4 is supported from legacy opcode 83");
            }
            if (mode != 0x3U || rexR || rexX ||
                (extension != 0x0U && extension != 0x4U && extension != 0x5U &&
                 extension != 0x7U)) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct ADD /0, AND /4, SUB /5, and CMP /7 from opcode 83 are supported");
            }
            const auto immediate = std::bit_cast<std::int8_t>(code[cursor++]);
            instruction.opcode = extension == 0   ? Opcode::AddRegImm
                                 : extension == 4 ? Opcode::AndRegImm
                                 : extension == 5 ? Opcode::SubRegImm
                                                  : Opcode::CmpRegImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB),
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint64_t>(static_cast<std::int64_t>(immediate)), 8});
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
        result.push_back(std::move(instruction));
        if (result.size() == maximumInstructions) {
            return result;
        }
    }

    throw DecodeError(guest::GuestAddress{start.value + cursor}, {},
                      "basic block ended without a supported terminator");
}

} // namespace rosa::x86
