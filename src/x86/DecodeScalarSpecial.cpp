#include "x86/DecodeInternal.h"

namespace rosa::x86::detail {

bool decodeScalarSpecial(DecodeContext &context) {
    auto &[code, address, cursor, instruction] = context;
    [[maybe_unused]] const auto remaining = code;
    [[maybe_unused]] constexpr std::size_t instructionStart = 0;
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
        return true;
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
        return true;
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
        return true;
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
        return true;
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
        return true;
    }

    const bool testImmediateHasGs =
        code[cursor] == 0x65U && code.size() - cursor >= 2;
    const auto testImmediateBase = cursor + (testImmediateHasGs ? 1U : 0U);
    const bool testImmediateHasRex =
        testImmediateBase < code.size() && code[testImmediateBase] >= 0x40U &&
        code[testImmediateBase] <= 0x4FU;
    const auto testImmediateOpcodeOffset =
        testImmediateBase + (testImmediateHasRex ? 1U : 0U);
    if (testImmediateOpcodeOffset < code.size() &&
        code[testImmediateOpcodeOffset] == 0xF6U) {
        if (code.size() - testImmediateOpcodeOffset < 2) {
            throw DecodeError(address, remaining,
                              "truncated F6 ModRM byte");
        }
        const auto rex = testImmediateHasRex ? code[testImmediateBase] : 0U;
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
            return true;
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
            return true;
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
            return true;
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
                                    std::nullopt, 1, false, true,
                                    testImmediateHasGs ? Segment::Gs
                                                       : Segment::None}
                    : MemoryOperand{base, displacement, 8, index, scale,
                                    hasBase, false,
                                    testImmediateHasGs ? Segment::Gs
                                                       : Segment::None});
        }
        instruction.operands.push_back(ImmediateOperand{immediate, 8});
        return true;
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
        return true;
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
        return true;
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
        return true;
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
        return true;
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
        return true;
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
        return true;
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
        return true;
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
        return true;
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
        return true;
    }

    if (code[cursor] == 0xC9U) {
        instruction.opcode = Opcode::Leave;
        instruction.length = 1;
        instruction.bytes[0] = code[cursor];
        return true;
    }

    if (code[cursor] == 0x0FU && code.size() - cursor >= 2 && code[cursor + 1] == 0x05U) {
        instruction.opcode = Opcode::Syscall;
        instruction.length = 2;
        instruction.bytes[0] = 0x0F;
        instruction.bytes[1] = 0x05;
        instruction.fallthrough = relativeTarget(address, 2, 0);
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 2 &&
        code[cursor + 1] == 0x90U) {
        instruction.opcode = Opcode::Nop;
        instruction.length = 2;
        instruction.bytes[0] = 0x66;
        instruction.bytes[1] = 0x90;
        return true;
    }

    if (code[cursor] == 0x90U) {
        instruction.opcode = Opcode::Nop;
        instruction.length = 1;
        instruction.bytes[0] = 0x90;
        return true;
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
        return true;
    }

    if (code[cursor] == 0xFCU || code[cursor] == 0xFDU) {
        instruction.opcode = code[cursor] == 0xFCU ? Opcode::Cld : Opcode::Std;
        instruction.length = 1;
        instruction.bytes[0] = code[cursor];
        return true;
    }

    if (code[cursor] == 0x0FU && code.size() - cursor >= 3 &&
        code[cursor + 1] == 0xAEU && code[cursor + 2] == 0xE8U) {
        instruction.opcode = Opcode::Lfence;
        instruction.length = 3;
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                    instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0x0FU && code.size() - cursor >= 3 &&
        code[cursor + 1] == 0xAEU && code[cursor + 2] == 0xF0U) {
        instruction.opcode = Opcode::Mfence;
        instruction.length = 3;
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(cursor), 3,
                    instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0x0FU && code.size() - cursor >= 2 &&
        code[cursor + 1] == 0x31U) {
        instruction.opcode = Opcode::Rdtsc;
        instruction.length = 2;
        instruction.bytes[0] = 0x0F;
        instruction.bytes[1] = 0x31;
        return true;
    }

    if (code[cursor] == 0x0FU && code.size() - cursor >= 2 &&
        code[cursor + 1] == 0xA2U) {
        instruction.opcode = Opcode::Cpuid;
        instruction.length = 2;
        instruction.bytes[0] = 0x0F;
        instruction.bytes[1] = 0xA2;
        return true;
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
         code[setOpcodeOffset + 1] == 0x9DU ||
         code[setOpcodeOffset + 1] == 0x9EU ||
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
                "only register or byte memory SETO/SETB/SETAE/SETE/SETNE/SETBE/SETA/SETS/SETNS/SETL/SETGE/SETLE/SETG is supported");
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
            : conditionOpcode == 0x9DU ? Condition::GreaterOrEqual
            : conditionOpcode == 0x9EU ? Condition::LessOrEqual
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
        return true;
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
        return true;
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
            return true;
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
        return true;
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
        return true;
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
            return true;
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
        return true;
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
        return true;
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
        return true;
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
        return true;
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
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const auto destination = XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    (((modrm >> 3U) & 0x7U) |
                     ((rex & 0x4U) != 0 ? 8U : 0U))))};
            if (mode == 0x3U) {
                instruction.opcode = Opcode::MovlhpsRegReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        (rmEncoding |
                         ((rex & 0x1U) != 0 ? 8U : 0U))))});
                const auto length = opcodeOffset + 3 - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                return true;
            }
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) == 0;
            if (rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) != 0)) {
                throw DecodeError(
                    address, remaining,
                    "only RIP-relative or based MOVLHPS xmm, m64 is supported");
            }
            auto operandCursor = opcodeOffset + 3;
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVLHPS m64 disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U || ripRelative) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated MOVLHPS m64 disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, operandCursor - instructionStart,
                    displacement));
            }
            instruction.opcode = Opcode::MovlhpsRegMem;
            instruction.operands.push_back(destination);
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 64,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(rmEncoding,
                                                   (rex & 0x1U) != 0),
                                    displacement, 64});
            const auto memoryLength = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(memoryLength);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                memoryLength, instruction.bytes.begin());
            return true;
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
        return true;
    }

    return false;
}

} // namespace rosa::x86::detail
