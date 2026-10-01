#include "x86/DecodeInternal.h"

namespace rosa::x86::detail {

bool decodeAtomic(DecodeContext &context) {
    auto &[code, address, cursor, instruction] = context;
    [[maybe_unused]] const auto remaining = code;
    [[maybe_unused]] constexpr std::size_t instructionStart = 0;
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
        return true;
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
        if (mode == 0x3U || (extension != 0x1U && extension != 0x4U) ||
            (mode == 0 && rmEncoding == 0x5U)) {
            throw DecodeError(
                address, remaining,
                "only word LOCK OR/AND [base+disp8/disp32], imm8/imm16 is supported");
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
                    "only no-index, based SIB is supported for word LOCK OR/AND");
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
                                  "truncated word LOCK OR/AND imm16");
            }
            immediate = static_cast<std::uint16_t>(
                static_cast<std::uint16_t>(code[cursor]) |
                (static_cast<std::uint16_t>(code[cursor + 1]) << 8U));
            cursor += 2;
            immediateWidth = 16;
        }
        instruction.opcode = extension == 0x1U ? Opcode::LockOrMemImm
                                               : Opcode::LockAndMemImm;
        instruction.operands.push_back(
            MemoryOperand{base, displacement, 16});
        instruction.operands.push_back(
            ImmediateOperand{immediate, immediateWidth});
        const auto length = cursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
    }

    {
        const bool hasLockImmRex =
            code.size() - cursor >= 3 && code[cursor] == 0xF0U &&
            code[cursor + 1] >= 0x40U && code[cursor + 1] <= 0x4FU;
        const auto lockImmOpcodeOffset = cursor + (hasLockImmRex ? 2U : 1U);
        const bool isLockImmOrAnd =
            code[cursor] == 0xF0U && code.size() - lockImmOpcodeOffset >= 1 &&
            (code[lockImmOpcodeOffset] == 0x80U ||
             code[lockImmOpcodeOffset] == 0x81U ||
             code[lockImmOpcodeOffset] == 0x83U);
        if (isLockImmOrAnd) {
        const auto immediateOpcode = code[lockImmOpcodeOffset];
        const auto lockImmRex = hasLockImmRex ? code[cursor + 1] : std::uint8_t{0};
        const bool lockImmRexW = (lockImmRex & 0x8U) != 0;
        if ((lockImmRex & 0x4U) != 0 ||
            (immediateOpcode == 0x80U && lockImmRexW)) {
            throw DecodeError(
                address, remaining,
                "LOCK ADD/OR/AND immediate does not support REX.R");
        }
        cursor = lockImmOpcodeOffset + 1;
        if (cursor >= code.size()) {
            throw DecodeError(address, remaining,
                              "truncated LOCK OR memory operand");
        }
        const auto modrm = code[cursor++];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto extension =
            static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
        if (mode == 0x3U || (extension != 0x0U && extension != 0x1U && extension != 0x4U)) {
            throw DecodeError(
                address, remaining,
                "only LOCK ADD/OR/AND byte/dword/qword memory, imm8/imm32 is supported");
        }
        const auto lockImmWidth = static_cast<std::uint16_t>(
            immediateOpcode == 0x80U ? 8U : (lockImmRexW ? 64U : 32U));
        const auto memory = decodeModrmMemory(context, cursor, modrm, lockImmRex, lockImmWidth);
        std::uint64_t immediate = 0;
        std::uint8_t immediateWidth = 0;
        if (immediateOpcode == 0x83U || immediateOpcode == 0x80U) {
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
        instruction.opcode = extension == 0x0U   ? Opcode::LockAddMemImm
                             : extension == 0x1U ? Opcode::LockOrMemImm
                                                 : Opcode::LockAndMemImm;
        instruction.operands.push_back(memory);
        instruction.operands.push_back(
            ImmediateOperand{immediate, immediateWidth});
        const auto length = cursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
        }
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
        if (mode == 0x3U || extension > 1U) {
            throw DecodeError(address, remaining,
                              "only LOCK INC/DEC dword memory is supported");
        }
        instruction.opcode = extension == 0U ? Opcode::LockIncMem
                                             : Opcode::LockDecMem;
        instruction.operands.push_back(decodeModrmMemory(context, cursor, modrm, 0, 32));
        const auto length = cursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
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
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
        if (mode > 0x2U || extension != 0x1U || rmEncoding == 0x4U ||
            (mode == 0 && rmEncoding == 0x5U && rexB)) {
            throw DecodeError(
                address, remaining,
                "only LOCK CMPXCHG16B [base+disp8/disp32/RIP] is supported");
        }
        cursor += 5;
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated LOCK CMPXCHG16B disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[cursor++]);
        } else if (mode == 0x2U || ripRelative) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated LOCK CMPXCHG16B disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, cursor - instructionStart, displacement));
        }
        instruction.opcode = Opcode::Cmpxchg16bMem;
        instruction.operands.push_back(
            ripRelative
                ? MemoryOperand{Register::Rax, displacement, 128,
                                std::nullopt, 1, false, true}
                : MemoryOperand{decodeRegister(rmEncoding, rexB),
                                displacement, 128});
        const auto length = cursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
    }

    {
        // Prefix order on the wire: [66] F0 [REX].
        auto xaddCursor = cursor;
        const bool hasXaddSizePrefix =
            xaddCursor < code.size() && code[xaddCursor] == 0x66U;
        if (hasXaddSizePrefix) {
            ++xaddCursor;
        }
        const bool hasXaddLock =
            xaddCursor < code.size() && code[xaddCursor] == 0xF0U;
        if (hasXaddLock) {
            ++xaddCursor;
        }
        const bool hasXaddRex =
            xaddCursor < code.size() && code[xaddCursor] >= 0x40U &&
            code[xaddCursor] <= 0x4FU;
        const auto xaddRex =
            hasXaddRex ? code[xaddCursor++] : std::uint8_t{0};
        const bool isXadd =
            hasXaddLock && code.size() - xaddCursor >= 2 &&
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
            if (mode == 0x3U ||
                (mode == 0 && rmEncoding == 0x5U && rexB)) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK XADD dword/qword [base/index*scale/RIP+disp8/disp32], r32/r64 is supported");
            }
            auto xaddBase = decodeRegister(rmEncoding, rexB);
            std::optional<Register> xaddIndex;
            std::uint8_t xaddScale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK XADD SIB");
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
                        "no-base LOCK XADD SIB is not supported");
                }
                xaddBase = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U) {
                    xaddIndex = decodeRegister(indexEncoding, rexX);
                    xaddScale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (rexX) {
                throw DecodeError(address, remaining,
                                  "REX.X requires a LOCK XADD SIB");
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
            const auto width = static_cast<std::uint8_t>(
                hasXaddSizePrefix ? 16U : (rexW ? 64U : 32U));
            instruction.opcode = Opcode::LockXaddMemReg;
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, width,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{xaddBase, displacement, width,
                                    xaddIndex, xaddScale});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, rexR), width});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
    }

    // A word CMPXCHG may carry its operand-size prefix before or after LOCK.
    bool lockWordOperand = false;
    if (code.size() - cursor >= 2 && code[cursor] == 0x66U && code[cursor + 1] == 0xF0U) {
        lockWordOperand = true;
        ++cursor;
    }
    if (code[cursor] == 0xF0U) {
        auto operandCursor = cursor + 1;
        if (operandCursor >= code.size()) {
            throw DecodeError(address, remaining,
                              "truncated after LOCK prefix");
        }
        if (code[operandCursor] == 0x66U) {
            lockWordOperand = true;
            if (++operandCursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated after LOCK operand-size prefix");
            }
        }
        if (lockWordOperand) {
            auto opcodeCursor = operandCursor;
            if (code[opcodeCursor] >= 0x40U && code[opcodeCursor] <= 0x4FU) {
                ++opcodeCursor;
            }
            if (code.size() - opcodeCursor < 3 || code[opcodeCursor] != 0x0FU ||
                code[opcodeCursor + 1] != 0xB1U) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK CMPXCHG r/m16, r16 is supported with an operand-size prefix");
            }
        }
        const bool hasLockRex = code[operandCursor] >= 0x40U &&
                                code[operandCursor] <= 0x4FU;
        const auto lockRex =
            hasLockRex ? code[operandCursor++] : std::uint8_t{0};
        const bool lockRexW = (lockRex & 0x8U) != 0;
        const bool lockRexR = (lockRex & 0x4U) != 0;
        if (code.size() - operandCursor >= 2 && code[operandCursor] == 0xFFU) {
            const auto modrm = code[operandCursor + 1];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension = static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if ((extension != 0x0U && extension != 0x1U) || mode > 0x2U || lockRexR) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK INC/DEC dword/qword memory is supported from prefix F0 FF /0/1");
            }
            operandCursor += 2;
            const auto width = static_cast<std::uint16_t>(lockRexW ? 64U : 32U);
            instruction.opcode = extension == 0x0U ? Opcode::LockIncMem
                                                   : Opcode::LockDecMem;
            instruction.operands.push_back(
                decodeModrmMemory(context, operandCursor, modrm, lockRex, width));
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
        if (code.size() - operandCursor >= 2 &&
            (code[operandCursor] == 0x01U || code[operandCursor] == 0x09U ||
             code[operandCursor] == 0x31U)) {
            // LOCK ADD/OR/XOR r/m32/r/m64, r32/r64. Guest code runs on one host
            // thread, so a locked XOR is the plain memory-destination XOR.
            const auto operation = code[operandCursor];
            const auto modrm = code[operandCursor + 1];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            if (mode == 0x3U) {
                throw DecodeError(address, remaining,
                                  "LOCK ADD/OR/XOR requires a memory destination");
            }
            operandCursor += 2;
            const auto width = static_cast<std::uint16_t>(lockRexW ? 64U : 32U);
            const auto memory = decodeModrmMemory(context, operandCursor, modrm, lockRex, width);
            instruction.opcode = operation == 0x01U   ? Opcode::LockAddMemReg
                                 : operation == 0x09U ? Opcode::LockOrMemReg
                                                      : Opcode::XorMemReg;
            instruction.operands.push_back(memory);
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, lockRexR), static_cast<std::uint8_t>(width)});
            cursor = operandCursor;
            const auto lockLength = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(lockLength);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                lockLength, instruction.bytes.begin());
            return true;
        }
        if (code.size() - operandCursor < 3 ||
            code[operandCursor] != 0x0FU ||
            (code[operandCursor + 1] != 0xB0U &&
             code[operandCursor + 1] != 0xB1U &&
             code[operandCursor + 1] != 0xBAU)) {
            throw DecodeError(
                address, remaining,
                "only LOCK CMPXCHG r/m8/r/m32/r/m64, LOCK BTS r/m32/r/m64, or LOCK XADD r/m32, r32 is supported from prefix F0");
        }
        if (code[operandCursor + 1] == 0xBAU) {
            cursor = operandCursor + 2;
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated LOCK BTS memory operand");
            }
            const auto modrm = code[cursor++];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto extension =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool rexW = (lockRex & 0x8U) != 0;
            const bool rexR = (lockRex & 0x4U) != 0;
            const bool rexX = (lockRex & 0x2U) != 0;
            const bool rexB = (lockRex & 0x1U) != 0;
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
            if (mode == 0x3U || extension != 0x5U || rexR || rexX ||
                (mode == 0 && rmEncoding == 0x5U && rexB)) {
                throw DecodeError(
                    address, remaining,
                    "only LOCK BTS dword/qword [base/index*scale/RIP+disp8/disp32], imm8 is supported");
            }
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK BTS SIB");
                }
                const auto sib = code[cursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base LOCK BTS SIB is not supported");
                }
                if (indexEncoding != 0x4U) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            }
            std::int64_t displacement = 0;
            if (ripRelative || mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK BTS disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated LOCK BTS disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[cursor++]);
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated LOCK BTS bit index");
            }
            const auto bitIndex = code[cursor++];
            const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.opcode = Opcode::LockBtsMemImm;
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, width,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(baseEncoding, rexB),
                                    displacement, width, index, scale});
            instruction.operands.push_back(ImmediateOperand{bitIndex, 8});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() +
                            static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
        const bool isByteCmpxchg = code[operandCursor + 1] == 0xB0U;
        if (isByteCmpxchg && (lockRex & 0x8U) != 0) {
            throw DecodeError(
                address, remaining,
                "REX.W is not supported for byte LOCK CMPXCHG");
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
        const auto width = static_cast<std::uint8_t>(
            isByteCmpxchg ? 8U : rexW ? 64U : lockWordOperand ? 16U : 32U);
        const bool highByteSource =
            isByteCmpxchg && !hasLockRex && regEncoding >= 0x4U;
        instruction.opcode = Opcode::CmpxchgMemReg;
        instruction.operands.push_back(MemoryOperand{
            decodeRegister(baseEncoding, rexB), displacement, width,
            index, scale, hasBase, ripRelative});
        instruction.operands.push_back(RegisterOperand{
            highByteSource
                ? decodeRegister(static_cast<std::uint8_t>(regEncoding - 0x4U),
                                 false)
                : decodeRegister(regEncoding, rexR),
            width, static_cast<std::uint8_t>(highByteSource ? 1U : 0U)});
        const auto length = cursor - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(
            code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
            length, instruction.bytes.begin());
        return true;
    }

    return false;
}

} // namespace rosa::x86::detail
