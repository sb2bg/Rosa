#include "x86/DecodeInternal.h"

namespace rosa::x86::detail {

bool decodeGeneral(DecodeContext &context) {
    auto &[code, address, cursor, instruction] = context;
    [[maybe_unused]] const auto remaining = code;
    [[maybe_unused]] constexpr std::size_t instructionStart = 0;
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
        code[cursor] != 0x10U && code[cursor] != 0x11U &&
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
        code[cursor] != 0x86U &&
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
    if (hasOperandSizeOverride && opcode != 0x01U && opcode != 0x03U && opcode != 0x0BU && opcode != 0x39U &&
        opcode != 0x3BU && opcode != 0x89U && opcode != 0x8BU && opcode != 0xF7U &&
        opcode != 0xFFU && opcode != 0x21U && opcode != 0x09U && opcode != 0x33U) {
        throw DecodeError(
            address, remaining,
            "operand-size override is only supported for 16-bit ADD, OR, CMP, MOV, XOR r16, [memory], and memory INC in the general decoder");
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
        opcode != 0x03U && opcode != 0x11U &&
        opcode != 0x19U && opcode != 0x1CU && opcode != 0x0CU &&
        opcode != 0x88U && opcode != 0x89U &&
        opcode != 0x8AU &&
        opcode != 0x8BU && opcode != 0x85U &&
        opcode != 0x8DU &&
        opcode != 0x08U && opcode != 0x09U && opcode != 0x0AU &&
        opcode != 0x0BU &&
        opcode != 0x2DU &&
        opcode != 0x69U &&
        opcode != 0x86U &&
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
            secondOpcode != 0xABU &&
            secondOpcode != 0xA4U &&
            secondOpcode != 0xBAU &&
            secondOpcode != 0xBEU &&
            secondOpcode != 0xACU &&
            secondOpcode != 0xAFU && secondOpcode != 0xBCU &&
            secondOpcode != 0xBDU) {
            throw DecodeError(
                address, remaining,
                "only CMOVO/CMOVB/CMOVAE/CMOVE/CMOVNE/CMOVA/CMOVS/CMOVNS/CMOVL/CMOVGE/CMOVLE/CMOVG, BT/BTS, MOVSX, IMUL, SHLD, SHRD, BSF, and BSR register forms are supported from REX 0F");
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
            secondOpcode != 0xA3U && secondOpcode != 0xABU && secondOpcode != 0xBEU &&
            secondOpcode != 0xAFU &&
            secondOpcode != 0xBCU && secondOpcode != 0xBDU) {
            throw DecodeError(
                address, remaining,
                "only 32-bit register CMOV, BT/BTS, MOVSX, IMUL, BSF, or BSR is supported from non-W REX 0F");
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
        const bool isCmovMemory =
            isConditionalMove && mode != 0x3U;
        const bool isBtMemory =
            secondOpcode == 0xBAU &&
            (static_cast<std::uint8_t>((modrm >> 3U) & 0x7U) == 0x4U) &&
            mode != 0x3U && !(mode == 0 && rmEncoding == 0x5U);
        if ((!isImulRipMemory && !isMovsxMemory && !isCmovMemory && !isBtMemory &&
             mode != 0x3U) ||
            (rexX && secondOpcode != 0xBAU && !isMovsxMemory)) {
            throw DecodeError(
                address, remaining,
                "only register-direct CMOVO/CMOVB/CMOVAE/CMOVE/CMOVNE/CMOVA/CMOVS/CMOVNS/CMOVL/CMOVGE/CMOVLE/BT/BTS/MOVSX/IMUL/SHLD/SHRD/BSF/BSR and based BT m32/m64, imm8 are supported");
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
        } else if (secondOpcode == 0xABU) {
            const auto width =
                static_cast<std::uint8_t>(rexW ? 64U : 32U);
            instruction.opcode = Opcode::BitSetRegReg;
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
            if (isBtMemory) {
                const auto width =
                    static_cast<std::uint8_t>(rexW ? 64U : 32U);
                auto baseEncoding = rmEncoding;
                std::optional<Register> index;
                std::uint8_t scale = 1;
                if (rmEncoding == 0x4U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated BT memory SIB byte");
                    }
                    const auto sib = code[cursor++];
                    const auto scaleBits =
                        static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                    const auto indexEncoding =
                        static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                    baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                    if (mode == 0 && baseEncoding == 0x5U) {
                        throw DecodeError(address, remaining,
                                          "no-base BT memory SIB is not supported");
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
                                          "truncated BT memory disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated BT memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated BT memory imm8");
                }
                instruction.opcode = Opcode::BitTestMemImm;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(baseEncoding, rexB), displacement,
                    width, index, scale});
                instruction.operands.push_back(
                    ImmediateOperand{code[cursor++], 8});
                const auto memoryLength = cursor - instructionStart;
                instruction.length =
                    static_cast<std::uint8_t>(memoryLength);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    memoryLength, instruction.bytes.begin());
                return true;
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
            if (isCmovMemory) {
                if (rmEncoding == 0x4U ||
                    (mode == 0 && rmEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only CMOV register, [base+disp8/disp32] memory operands are supported");
                }
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (cursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated CMOV memory disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(code[cursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - cursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated CMOV memory disp32");
                    }
                    displacement = readI32(code.subspan(cursor, 4));
                    cursor += 4;
                }
                instruction.opcode = Opcode::CmovccRegMem;
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, rexB), displacement, width});
            } else {
                instruction.opcode = Opcode::CmovccReg;
                instruction.operands.push_back(
                    RegisterOperand{encodedRm, width});
            }
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
        if (mode == 0x3U) {
            if (!hasRex &&
                (sourceEncoding >= 0x4U || destinationEncoding >= 0x4U)) {
                throw DecodeError(
                    address, remaining,
                    "only representable register-direct ADD r8, r8 is supported");
            }
            instruction.opcode = Opcode::AddRegReg;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(destinationEncoding, rexB), 8});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(sourceEncoding, rexR), 8});
        } else {
            if ((!hasRex && sourceEncoding >= 0x4U) ||
                (mode == 0 && destinationEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only ADD byte [base+index*scale+disp8/disp32], low-byte-register is supported");
            }
            auto base = decodeRegister(destinationEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (destinationEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated ADD byte memory SIB");
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
                                      "no-base ADD byte SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (rexX) {
                throw DecodeError(address, remaining,
                                  "REX.X requires an ADD byte memory SIB");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated ADD byte disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated ADD byte disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            instruction.opcode = Opcode::AddMemReg;
            instruction.operands.push_back(MemoryOperand{
                base, displacement, 8, index, scale});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(sourceEncoding, rexR), 8});
        }
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
    } else if (opcode == 0x11U) {
        if (code.size() - cursor < 1) {
            throw DecodeError(address, remaining, "truncated adc r64, r64");
        }
        const auto modrm = code[cursor++];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        if (mode != 0x3U) {
            throw DecodeError(address, remaining,
                              "only register-direct ADC r32/r64, r32/r64 is supported");
        }
        const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
        instruction.opcode = Opcode::AdcRegReg;
        instruction.operands.push_back(RegisterOperand{
            decodeRegister(static_cast<std::uint8_t>(modrm & 0x7U), rexB), width});
        instruction.operands.push_back(RegisterOperand{
            decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
            width});
    } else if (opcode == 0x13U) {
        if (code.size() - cursor < 1) {
            throw DecodeError(address, remaining,
                              "truncated adc r32/r64, r/m32/r/m64");
        }
        const auto modrm = code[cursor++];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        const auto destination = decodeRegister(
            static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR);
        const auto width = static_cast<std::uint8_t>(rexW ? 64U : 32U);
        if (mode == 0x3U) {
            instruction.opcode = Opcode::AdcRegReg;
            instruction.operands.push_back(RegisterOperand{destination, width});
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(rmEncoding, rexB), width});
        } else {
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U && !rexB;
            if (mode > 0x2U || (mode == 0 && rmEncoding == 0x5U && rexB)) {
                throw DecodeError(
                    address, remaining,
                    "only ADC r32/r64 with based, indexed, or RIP-relative memory operands is supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated ADC memory SIB");
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
                        "no-base ADC memory SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (rexX) {
                throw DecodeError(address, remaining,
                                  "REX.X requires an ADC memory SIB");
            }
            std::int64_t displacement = 0;
            if (ripRelative) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated RIP-relative ADC displacement");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated ADC memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated ADC memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            instruction.opcode = Opcode::AdcRegMem;
            instruction.operands.push_back(RegisterOperand{destination, width});
            instruction.operands.push_back(
                MemoryOperand{ripRelative ? Register::Rax : base, displacement,
                              width, index, scale, !ripRelative, ripRelative});
        }
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
            if (mode > 0x2U ||
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
            const auto width = static_cast<std::uint8_t>(
                rexW ? 64U : (hasOperandSizeOverride ? 16U : 32U));
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
        const auto width = static_cast<std::uint8_t>(
            rexW ? 64U : (hasOperandSizeOverride ? 16U : 32U));
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
            return true;
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
        std::uint8_t scale = 1;
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
            if (mode == 0 && baseEncoding == 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "no-base SUB memory SIB is not supported");
            }
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
            }
            scale = static_cast<std::uint8_t>(1U << scaleBits);
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
            MemoryOperand{base, displacement, width, index, scale,
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
        const auto width = static_cast<std::uint8_t>(
            rexW ? 64U : (hasOperandSizeOverride ? 16U : 32U));
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
        const auto operandWidth = static_cast<std::uint8_t>(
            rexW ? 64U : hasOperandSizeOverride ? 16U : 32U);
        if (mode == 0x3U) {
            if (rexX || hasOperandSizeOverride) {
                throw DecodeError(
                    address, remaining,
                    "REX.X or 16-bit register-direct XOR from opcode 33 is unsupported");
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
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
        if (mode == 0 && rmEncoding == 0x5U && rexB) {
            throw DecodeError(
                address, remaining,
                "R13-based XOR from opcode 33 is not supported");
        }
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
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
        } else if (!ripRelative && rexX) {
            throw DecodeError(address, remaining,
                              "REX.X requires an XOR memory SIB");
        }
        std::int64_t displacement = 0;
        if (mode == 0x1U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining, "truncated XOR memory disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[cursor++]);
        } else if (mode == 0x2U || ripRelative) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated XOR memory disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, cursor - instructionStart, displacement));
        }
        instruction.opcode = Opcode::XorRegMem;
        instruction.operands.push_back(RegisterOperand{
            decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U), rexR),
            operandWidth});
        instruction.operands.push_back(
            ripRelative
                ? MemoryOperand{Register::Rax, displacement, operandWidth,
                                std::nullopt, 1, false, true}
                : MemoryOperand{decodeRegister(baseEncoding, rexB), displacement,
                                operandWidth, index, scale});
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
    } else if (opcode == 0x86U) {
        if (code.size() - cursor < 1) {
            throw DecodeError(address, remaining,
                              "truncated xchg byte [memory], register");
        }
        const auto modrm = code[cursor++];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto regEncoding =
            static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
        if (mode > 0x2U || (mode == 0 && rmEncoding == 0x5U && rexB) ||
            (!hasRex && regEncoding >= 0x4U)) {
            throw DecodeError(
                address, remaining,
                "only XCHG byte [base+index*scale+disp8/disp32/RIP], low-byte-register is supported");
        }
        auto base = decodeRegister(rmEncoding, rexB);
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated byte XCHG memory SIB");
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
                                  "no-base SIB byte XCHG is not supported");
            }
            base = decodeRegister(baseEncoding, rexB);
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        } else if (!ripRelative && rexX) {
            throw DecodeError(address, remaining,
                              "REX.X requires a byte XCHG memory SIB");
        }
        std::int64_t displacement = 0;
        if (ripRelative) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated RIP-relative byte XCHG disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
            static_cast<void>(relativeTarget(
                address, cursor - instructionStart, displacement));
        } else if (mode == 0x1U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated byte XCHG disp8");
            }
            displacement = std::bit_cast<std::int8_t>(code[cursor++]);
        } else if (mode == 0x2U) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated byte XCHG disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
        }
        instruction.opcode = Opcode::XchgMemReg;
        instruction.operands.push_back(
            ripRelative
                ? MemoryOperand{Register::Rax, displacement, 8,
                                std::nullopt, 1, false, true}
                : MemoryOperand{base, displacement, 8, index, scale});
        instruction.operands.push_back(RegisterOperand{
            decodeRegister(regEncoding, rexR), 8});
    } else if (opcode == 0x87U) {
        if (code.size() - cursor < 1) {
            throw DecodeError(address, remaining,
                              "truncated xchg [memory], register");
        }
        const auto modrm = code[cursor++];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB;
        if (mode > 0x2U || (mode == 0 && rmEncoding == 0x5U && rexB)) {
            throw DecodeError(
                address, remaining,
                "only XCHG dword/qword [base+index*scale+disp8/disp32/RIP], register is supported");
        }
        auto base = decodeRegister(rmEncoding, rexB);
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated XCHG memory SIB");
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
                                  "no-base SIB XCHG is not supported");
            }
            base = decodeRegister(baseEncoding, rexB);
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        } else if (!ripRelative && rexX) {
            throw DecodeError(address, remaining,
                              "REX.X requires an XCHG memory SIB");
        }
        std::int64_t displacement = 0;
        if (ripRelative) {
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated RIP-relative XCHG memory disp32");
            }
            displacement = readI32(code.subspan(cursor, 4));
            cursor += 4;
            static_cast<void>(relativeTarget(
                address, cursor - instructionStart, displacement));
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
                : MemoryOperand{base, displacement, operandWidth,
                                index, scale});
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
            (!hasRex && mode == 0x3U &&
             (regEncoding >= 0x4U || rmEncoding >= 0x4U))) {
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
        // Without REX, encodings 4-7 name AH/CH/DH/BH instead of
        // SPL/BPL/SIL/DIL. Fold them to their low-byte base register
        // with a one-byte lane offset.
        const bool highByteSource = !hasRex && regEncoding >= 0x4U;
        instruction.operands.push_back(RegisterOperand{
            highByteSource
                ? decodeRegister(static_cast<std::uint8_t>(regEncoding & 0x3U), false)
                : decodeRegister(regEncoding, rexR),
            8, highByteSource ? std::uint8_t{1} : std::uint8_t{0}});
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
        const bool ripRelative =
            mode == 0 && rmEncoding == 0x5U && !rexB;
        if (mode == 0x3U || (mode == 0 && rmEncoding == 0x5U && rexB) ||
            (ripRelative && rexX) || (!hasRex && regEncoding >= 0x4U)) {
            throw DecodeError(
                address, remaining,
                "only AND representable-byte-register, byte [base+index*scale+disp8/disp32/RIP] is supported");
        }
        auto base = decodeRegister(rmEncoding, rexB);
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated byte AND memory SIB");
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
                    "no-base SIB byte AND is not supported");
            }
            base = decodeRegister(baseEncoding, rexB);
            if (indexEncoding != 0x4U || rexX) {
                index = decodeRegister(indexEncoding, rexX);
                scale = static_cast<std::uint8_t>(1U << scaleBits);
            }
        } else if (!ripRelative && rexX) {
            throw DecodeError(address, remaining,
                              "REX.X requires a byte AND memory SIB");
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
                : MemoryOperand{base, displacement, 8, index, scale});
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
        if (rexR || rexX || mode != 0x3U ||
            (extension != 0x0U && extension != 0x5U && extension != 0x7U)) {
            throw DecodeError(
                address, remaining,
                "only register-direct ROL/SHR/SAR r32/r64, 1 from opcode D1 /0, /5, and /7 are supported");
        }
        instruction.opcode = extension == 0x0U   ? Opcode::RolRegImm
                             : extension == 0x5U ? Opcode::ShrRegImm
                                                 : Opcode::SarRegImm;
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
            (extension != 0x0U && extension != 0x1U && extension != 0x4U &&
             extension != 0x5U && extension != 0x7U) ||
            (extension == 0x0U && rexW) || rexR || rexX) {
            throw DecodeError(address, remaining,
                              "only register-direct ROL r32 /0, ROR r64 /1 and SHL/SHR/SAR r32/r64 /4,/5,/7 from opcode D3 are supported");
        }
        if (extension == 0x1U && !rexW) {
            throw DecodeError(address, remaining,
                              "only 64-bit ROR by CL is supported from opcode D3 /1");
        }
        instruction.opcode = extension == 0x0U   ? Opcode::RolRegCl
                             : extension == 0x1U ? Opcode::RorRegCl
                             : extension == 0x4U ? Opcode::ShlRegCl
                             : extension == 0x5U ? Opcode::ShrRegCl
                                                 : Opcode::SarRegCl;
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
        if (hasOperandSizeOverride && !rexW && extension != 0x3U && extension != 0x0U) {
            throw DecodeError(
                address, remaining,
                "operand-size override is only supported for register TEST /0 and NEG /3 from opcode F7");
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
            if (rexR || rexX || mode > 0x2U ||
                rmEncoding == 0x4U ||
                (mode == 0 && rmEncoding == 0x5U)) {
                throw DecodeError(
                    address, remaining,
                    "only DIV r32/r64 or dword/qword [base+disp8/disp32] is supported from opcode F7 /6");
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
                decodeRegister(rmEncoding, rexB), displacement,
                static_cast<std::uint8_t>(rexW ? 64U : 32U)});
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
            const auto testWidth = static_cast<std::uint8_t>(
                rexW ? 64U : hasOperandSizeOverride ? 16U : 32U);
            if (testWidth == 16U) {
                if (code.size() - cursor < 2) {
                    throw DecodeError(address, remaining,
                                      "truncated TEST r16, imm16");
                }
                const auto immediate =
                    static_cast<std::uint16_t>(code[cursor] | (code[cursor + 1] << 8U));
                cursor += 2;
                instruction.operands.push_back(ImmediateOperand{immediate, 16});
            } else {
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
            return true;
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
            return true;
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
            return true;
        }
        if (extension == 0x4U && mode == 0x3U && !rexW && !rexR &&
            !rexX) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated byte AND immediate");
            }
            const auto immediate = code[cursor++];
            // Without REX, encodings 4-7 name AH/CH/DH/BH (byte lane 1)
            // instead of SPL/BPL/SIL/DIL.
            const bool highByte = !hasRex && rmEncoding >= 0x4U;
            const auto reg = highByte ? decodeRegister(
                                            static_cast<std::uint8_t>(rmEncoding - 0x4U),
                                            false)
                                      : decodeRegister(rmEncoding, rexB);
            instruction.opcode = Opcode::AndRegImm;
            instruction.operands.push_back(RegisterOperand{
                reg, 8, static_cast<std::uint8_t>(highByte ? 1U : 0U)});
            instruction.operands.push_back(
                ImmediateOperand{immediate, 8});
            const auto length = cursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
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
            return true;
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
            return true;
        }
        if (extension == 0x2U && mode == 0x3U && !rexW && !rexR &&
            !rexX && (hasRex || rmEncoding < 0x4U)) {
            if (cursor >= code.size()) {
                throw DecodeError(address, remaining,
                                  "truncated adc r8, imm8");
            }
            const auto immediate = code[cursor++];
            instruction.opcode = Opcode::AdcRegImm;
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
            return true;
        }
        // In 64-bit mode mod=00,r/m=101 remains RIP-relative even when
        // REX.B is present; REX.B does not turn this special encoding into
        // an R13 base.
        const bool ripRelative = mode == 0 && rmEncoding == 0x5U;
        if (extension != 0x7U || rexW || rexR ||
            (rexX && rmEncoding != 0x4U)) {
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
            // Without REX, encodings 4-7 name AH/CH/DH/BH (byte lane 1).
            const bool highByte = !hasRex && rmEncoding >= 0x4U;
            const auto reg = highByte ? decodeRegister(
                                            static_cast<std::uint8_t>(rmEncoding - 0x4U),
                                            false)
                                      : decodeRegister(rmEncoding, rexB);
            instruction.operands.push_back(RegisterOperand{
                reg, 8, static_cast<std::uint8_t>(highByte ? 1U : 0U)});
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
            const bool ripRelative = mode == 0 && rmEncoding == 0x5U && !rexB && !rexX;
            if (mode == 0 && rmEncoding == 0x5U && !ripRelative) {
                throw DecodeError(
                    address, remaining,
                    "RIP-relative CMP [memory], imm32 requires no REX.B/X");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (!ripRelative && rmEncoding == 0x4U) {
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
            } else if (mode == 0x2U || ripRelative) {
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
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            instruction.opcode = Opcode::CmpMemImm;
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement,
                                    static_cast<std::uint8_t>(rexW ? 64U : 32U),
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{
                          base, displacement,
                          static_cast<std::uint8_t>(rexW ? 64U : 32U), index,
                          scale});
            instruction.operands.push_back(ImmediateOperand{
                rexW ? static_cast<std::uint64_t>(
                           static_cast<std::int64_t>(immediate))
                     : static_cast<std::uint64_t>(
                           static_cast<std::uint32_t>(immediate)),
                32});
        } else if (mode <= 0x2U && extension == 0x4U && !rexR) {
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode == 0 && rmEncoding == 0x5U) {
                throw DecodeError(
                    address, remaining,
                    "RIP-relative AND [memory], imm32 is not supported");
            }
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
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
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(
                        address, remaining,
                        "no-base AND [memory], imm32 SIB is not supported");
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
                                      "truncated AND memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            } else if (mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated AND memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            }
            if (code.size() - cursor < 4) {
                throw DecodeError(address, remaining, "truncated AND memory imm32");
            }
            const auto immediate = readI32(code.subspan(cursor, 4));
            cursor += 4;
            instruction.opcode = Opcode::AndMemImm;
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
                   (!rexX || rmEncoding == 0x4U) &&
                   !(mode == 0 && rmEncoding == 0x5U && !rexB)) {
            auto base = decodeRegister(rmEncoding, rexB);
            std::optional<Register> index;
            std::uint8_t scale = 1;
            if (rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated DEC memory SIB");
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
                        "no-base DEC memory SIB is not supported");
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
                base, displacement,
                static_cast<std::uint8_t>(rexW ? 64U : 32U), index, scale});
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
        } else if (extension != 0x2U || mode > 0x2U || rexR ||
                   (mode == 0 && rmEncoding == 0x5U)) {
            throw DecodeError(
                address, remaining,
                "only register/memory INC /0, register/based/SIB/RIP-relative dword/qword memory DEC /1, register/based/SIB/RIP-relative memory CALL /2, register/based/RIP-relative memory JMP /4, and based qword memory PUSH /6 are supported from opcode FF");
        } else {
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
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
                if (mode == 0 && baseEncoding == 0x5U && !rexB) {
                    throw DecodeError(
                        address, remaining,
                        "no-base SIB addressing is not supported for indirect CALL");
                }
                if (indexEncoding != 0x4U || rexX) {
                    index = decodeRegister(indexEncoding, rexX);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (rexX) {
                throw DecodeError(address, remaining,
                                  "REX.X requires an indirect CALL SIB byte");
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
                decodeRegister(baseEncoding, rexB), displacement, 64, index, scale});
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
        } else if (extension == 0x4U && mode <= 0x2U && !rexW && !rexR) {
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U && !rexB;
            auto base = decodeRegister(rmEncoding, rexB);
            if (!ripRelative && rmEncoding == 0x4U) {
                if (cursor >= code.size()) {
                    throw DecodeError(
                        address, remaining,
                        "truncated short dword AND memory SIB");
                }
                const auto sib = code[cursor++];
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                const auto baseEncoding =
                    static_cast<std::uint8_t>(sib & 0x7U);
                if (indexEncoding != 0x4U || rexX) {
                    throw DecodeError(
                        address, remaining,
                        "only no-index short dword AND memory SIB is supported");
                }
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(
                        address, remaining,
                        "no-base short dword AND memory SIB is not supported");
                }
                base = decodeRegister(baseEncoding, rexB);
            }
            std::int64_t displacement = 0;
            if (ripRelative || mode == 0x2U) {
                if (code.size() - cursor < 4) {
                    throw DecodeError(
                        address, remaining,
                        "truncated short dword AND memory disp32");
                }
                displacement = readI32(code.subspan(cursor, 4));
                cursor += 4;
            } else if (mode == 0x1U) {
                if (cursor >= code.size()) {
                    throw DecodeError(
                        address, remaining,
                        "truncated short dword AND memory disp8");
                }
                displacement = std::bit_cast<std::int8_t>(code[cursor++]);
            }
            if (cursor >= code.size()) {
                throw DecodeError(
                    address, remaining,
                    "truncated short dword AND memory immediate");
            }
            const auto immediate =
                std::bit_cast<std::int8_t>(code[cursor++]);
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, cursor - instructionStart, displacement));
            }
            instruction.opcode = Opcode::AndMemImm;
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 32,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{base, displacement, 32});
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
    return true;
}

} // namespace rosa::x86::detail
