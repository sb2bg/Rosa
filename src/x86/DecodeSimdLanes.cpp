#include "x86/DecodeInternal.h"

namespace rosa::x86::detail {

bool decodeSimdLanes(DecodeContext &context) {
    auto &[code, address, cursor, instruction] = context;
    [[maybe_unused]] const auto remaining = code;
    [[maybe_unused]] constexpr std::size_t instructionStart = 0;
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
                return true;
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
                return true;
            }
            if (code[opcodeOffset + 2] == 0x31U) {
                const auto rex = hasPshufbRex ? code[afterPrefix] : 0U;
                const auto modrm = code[opcodeOffset + 3];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                if (mode != 0x3U || (rex & 0xAU) != 0) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct PMOVZXBD xmm, xmm is supported");
                }
                instruction.opcode = Opcode::PmovzxbdXmmReg;
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
                return true;
            }
            if (code[opcodeOffset + 2] == 0x22U) {
                // PMOVSXBQ xmm, word [rip+disp32]: two bytes to two qwords.
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
                        "only RIP-relative PMOVSXBQ xmm, word memory is supported");
                }
                auto operandCursor = opcodeOffset + 4;
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(
                        address, remaining,
                        "truncated RIP-relative PMOVSXBQ displacement");
                }
                const auto displacement =
                    readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
                static_cast<void>(relativeTarget(
                    address, operandCursor - instructionStart,
                    displacement));
                instruction.opcode = Opcode::PmovsxbqRegMem;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) |
                        ((rex & 0x4U) != 0 ? 8U : 0U)))});
                instruction.operands.push_back(MemoryOperand{
                    Register::Rax, displacement, 16, std::nullopt, 1,
                    false, true});
                const auto length = operandCursor - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
                return true;
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
                return true;
            }
            if (code[opcodeOffset + 2] == 0x25U) {
                const auto rex = hasPshufbRex ? code[afterPrefix] : 0U;
                const auto modrm = code[opcodeOffset + 3];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                const auto rmEncoding =
                    static_cast<std::uint8_t>(modrm & 0x7U);
                if ((rex & 0xAU) != 0) {
                    throw DecodeError(
                        address, remaining,
                        "PMOVSXDQ does not support REX.W/X");
                }
                const auto destination = XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) |
                        ((rex & 0x4U) != 0 ? 8U : 0U)))};
                if (mode == 0x3U) {
                    instruction.opcode = Opcode::PmovsxdqRegReg;
                    instruction.operands.push_back(destination);
                    instruction.operands.push_back(XmmRegisterOperand{
                        static_cast<XmmRegister>(static_cast<std::uint8_t>(
                            rmEncoding | ((rex & 0x1U) != 0 ? 8U : 0U)))});
                    const auto operandCursor = opcodeOffset + 4;
                    const auto length = operandCursor - instructionStart;
                    instruction.length = static_cast<std::uint8_t>(length);
                    std::copy_n(
                        code.begin() +
                            static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
                    return true;
                }
                if (mode != 0 || rmEncoding != 0x5U || (rex & 0x1U) != 0) {
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
                return true;
            }
            if (code[opcodeOffset + 2] == 0x29U) {
                const auto rex = hasPshufbRex ? code[afterPrefix] : 0U;
                const auto modrm = code[opcodeOffset + 3];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                const auto rmEncoding =
                    static_cast<std::uint8_t>(modrm & 0x7U);
                if ((rex & 0xAU) != 0) {
                    throw DecodeError(
                        address, remaining,
                        "PCMPEQQ does not support REX.W/X");
                }
                const auto destination = XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) |
                        ((rex & 0x4U) != 0 ? 8U : 0U)))};
                auto operandCursor = opcodeOffset + 4;
                if (mode == 0x3U) {
                    instruction.opcode = Opcode::PcmpeqqRegReg;
                    instruction.operands.push_back(destination);
                    instruction.operands.push_back(XmmRegisterOperand{
                        static_cast<XmmRegister>(
                            static_cast<std::uint8_t>(
                                rmEncoding |
                                ((rex & 0x1U) != 0 ? 8U : 0U)))});
                } else {
                    const bool ripRelative =
                        mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) == 0;
                    if (rmEncoding == 0x4U ||
                        (mode == 0 && rmEncoding == 0x5U &&
                         (rex & 0x1U) != 0)) {
                        throw DecodeError(
                            address, remaining,
                            "only RIP-relative or based PCMPEQQ xmm, m128 is supported");
                    }
                    std::int64_t displacement = 0;
                    if (mode == 0x1U) {
                        if (operandCursor >= code.size()) {
                            throw DecodeError(
                                address, remaining,
                                "truncated PCMPEQQ m128 disp8");
                        }
                        displacement = std::bit_cast<std::int8_t>(
                            code[operandCursor++]);
                    } else if (mode == 0x2U || ripRelative) {
                        if (code.size() - operandCursor < 4) {
                            throw DecodeError(
                                address, remaining,
                                "truncated PCMPEQQ m128 disp32");
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
                    instruction.opcode = Opcode::PcmpeqqRegMem;
                    instruction.operands.push_back(destination);
                    instruction.operands.push_back(
                        ripRelative
                            ? MemoryOperand{Register::Rax, displacement,
                                            128, std::nullopt, 1, false,
                                            true}
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
            if (code[opcodeOffset + 2] == 0x15U) {
                const auto rex = hasPshufbRex ? code[afterPrefix] : 0U;
                const auto modrm = code[opcodeOffset + 3];
                const auto mode =
                    static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
                if (mode != 0x3U || (rex & 0xAU) != 0) {
                    throw DecodeError(
                        address, remaining,
                        "only register-direct BLENDVPD xmm, xmm is supported");
                }
                instruction.opcode = Opcode::BlendvpdRegReg;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        ((modrm >> 3U) & 0x7U) |
                        ((rex & 0x4U) != 0 ? 8U : 0U)))});
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        (modrm & 0x7U) |
                        ((rex & 0x1U) != 0 ? 8U : 0U)))});
                const auto blendLength = opcodeOffset + 4 - instructionStart;
                instruction.length = static_cast<std::uint8_t>(blendLength);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    blendLength, instruction.bytes.begin());
                return true;
            }
        }
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 4) {
        auto pinsrwCursor = cursor + 1;
        std::uint8_t pinsrwRex = 0;
        if (code[pinsrwCursor] >= 0x40U && code[pinsrwCursor] <= 0x4FU &&
            code.size() - pinsrwCursor >= 5) {
            pinsrwRex = code[pinsrwCursor++];
        }
        if (code.size() - pinsrwCursor >= 4 && code[pinsrwCursor] == 0x0FU &&
            code[pinsrwCursor + 1] == 0xC4U) {
            const auto modrm = code[pinsrwCursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            const bool sourceIs64 = (pinsrwRex & 0x8U) != 0;
            if (mode == 0x3U) {
                if (pinsrwRex == 0 && rmEncoding >= 0x4U) {
                    // Without any REX byte, encodings 4-7 name
                    // AH/CH/DH/BH instead of SPL/BPL/SIL/DIL.
                    throw DecodeError(
                        address, remaining,
                        "high-byte register PINSRW source is not supported");
                }
                instruction.opcode = Opcode::PinsrwXmmReg;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        regEncoding | ((pinsrwRex & 0x4U) != 0 ? 8U : 0U)))});
                instruction.operands.push_back(RegisterOperand{
                    decodeRegister(rmEncoding, (pinsrwRex & 0x1U) != 0),
                    static_cast<std::uint8_t>(sourceIs64 ? 64U : 32U)});
                instruction.operands.push_back(ImmediateOperand{
                    static_cast<std::uint8_t>(code[pinsrwCursor + 3] & 0x7U), 8});
            } else {
                if (sourceIs64 || (pinsrwRex & 0x2U) != 0) {
                    throw DecodeError(
                        address, remaining,
                        "only PINSRW xmm, m16, imm8 without REX.W/X is supported");
                }
                if (rmEncoding == 0x4U || (mode == 0 && rmEncoding == 0x5U)) {
                    throw DecodeError(
                        address, remaining,
                        "only based PINSRW xmm, m16, imm8 is supported");
                }
                auto operandCursor = pinsrwCursor + 3;
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated PINSRW m16 disp8");
                    }
                    displacement =
                        std::bit_cast<std::int8_t>(code[operandCursor++]);
                } else if (mode == 0x2U) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated PINSRW m16 disp32");
                    }
                    displacement = readI32(code.subspan(operandCursor, 4));
                    operandCursor += 4;
                }
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated PINSRW m16 imm8");
                }
                instruction.opcode = Opcode::PinsrwXmmMem;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        regEncoding | ((pinsrwRex & 0x4U) != 0 ? 8U : 0U)))});
                instruction.operands.push_back(MemoryOperand{
                    decodeRegister(rmEncoding, (pinsrwRex & 0x1U) != 0),
                    displacement, 16});
                instruction.operands.push_back(ImmediateOperand{
                    static_cast<std::uint8_t>(code[operandCursor] & 0x7U), 8});
                operandCursor += 1;
                const auto memoryLength = operandCursor - instructionStart;
                instruction.length =
                    static_cast<std::uint8_t>(memoryLength);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    memoryLength, instruction.bytes.begin());
                return true;
            }
            const auto length = pinsrwCursor + 4 - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 4) {
        auto pextrwCursor = cursor + 1;
        std::uint8_t pextrwRex = 0;
        if (code[pextrwCursor] >= 0x40U && code[pextrwCursor] <= 0x4FU &&
            code.size() - pextrwCursor >= 4) {
            pextrwRex = code[pextrwCursor++];
        }
        if (code.size() - pextrwCursor >= 3 && code[pextrwCursor] == 0x0FU &&
            code[pextrwCursor + 1] == 0xC5U) {
            if (code.size() - pextrwCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated PEXTRW r32, xmm, imm8");
            }
            if ((pextrwRex & 0x8U) != 0) {
                throw DecodeError(address, remaining,
                                  "REX.W is invalid for PEXTRW");
            }
            const auto modrm = code[pextrwCursor + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            if (mode != 0x3U) {
                throw DecodeError(address, remaining,
                                  "only register-direct PEXTRW r32, xmm, imm8 is supported");
            }
            const auto count =
                static_cast<std::uint8_t>(code[pextrwCursor + 3] & 0x7U);
            instruction.opcode = Opcode::PextrwRegXmmImm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(regEncoding, (pextrwRex & 0x4U) != 0), 32});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    rmEncoding | ((pextrwRex & 0x1U) != 0 ? 8U : 0U)))});
            instruction.operands.push_back(ImmediateOperand{count, 8});
            const auto length = pextrwCursor + 4 - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
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
        return true;
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
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 3) {
        const auto afterPrefix = cursor + 1;
        const bool hasPackedDoubleRex =
            code[afterPrefix] >= 0x40U && code[afterPrefix] <= 0x4FU;
        const auto opcodeOffset =
            afterPrefix + (hasPackedDoubleRex ? 1U : 0U);
        if (code.size() - opcodeOffset >= 3 &&
            code[opcodeOffset] == 0x0FU &&
            code[opcodeOffset + 1] == 0xC2U) {
            const auto rex = hasPackedDoubleRex ? code[afterPrefix] : 0U;
            const auto modrm = code[opcodeOffset + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || (rex & 0xAU) != 0) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct CMPPD xmm, xmm, imm8 is supported");
            }
            if (code.size() - opcodeOffset < 4) {
                throw DecodeError(address, remaining,
                                  "truncated CMPPD xmm, xmm, imm8");
            }
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            instruction.opcode = Opcode::CmppdRegRegImm;
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    regEncoding | ((rex & 0x4U) != 0 ? 8U : 0U)))});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    rmEncoding | ((rex & 0x1U) != 0 ? 8U : 0U)))});
            instruction.operands.push_back(ImmediateOperand{
                static_cast<std::uint8_t>(code[opcodeOffset + 3] & 0x7U), 8});
            const auto length = opcodeOffset + 4 - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 3) {
        const auto afterPrefix = cursor + 1;
        const bool hasPackedWordRex =
            code[afterPrefix] >= 0x40U && code[afterPrefix] <= 0x4FU;
        const auto opcodeOffset =
            afterPrefix + (hasPackedWordRex ? 1U : 0U);
        if (code.size() - opcodeOffset >= 3 &&
            code[opcodeOffset] == 0x0FU &&
            code[opcodeOffset + 1] == 0xFDU) {
            const auto rex = hasPackedWordRex ? code[afterPrefix] : 0U;
            const auto modrm = code[opcodeOffset + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || (rex & 0xAU) != 0) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct PADDW xmm, xmm is supported");
            }
            const auto regEncoding =
                static_cast<std::uint8_t>((modrm >> 3U) & 0x7U);
            const auto rmEncoding =
                static_cast<std::uint8_t>(modrm & 0x7U);
            instruction.opcode = Opcode::PaddwRegReg;
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    regEncoding | ((rex & 0x4U) != 0 ? 8U : 0U)))});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    rmEncoding | ((rex & 0x1U) != 0 ? 8U : 0U)))});
            const auto length = opcodeOffset + 3 - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
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
            const bool packedMemorySource =
                !isImmediateShift && secondOpcode == 0xFEU && mode != 0x3U;
            const bool isDwordShiftRight =
                isImmediateShift && secondOpcode == 0x72U && regEncoding == 0x2U;
            if ((mode != 0x3U && !packedMemorySource) || (rex & 0xAU) != 0 ||
                (isImmediateShift && !isDwordShiftRight &&
                 (regEncoding != expectedOpcodeExtension ||
                  (rex & 0x4U) != 0))) {
                throw DecodeError(
                    address, remaining,
                    secondOpcode == 0x72U
                        ? "only register-direct PSLLD/PSRLD xmm, imm8 is supported"
                    : secondOpcode == 0x73U
                        ? "only register-direct PSRLQ xmm, imm8 is supported"
                    : secondOpcode == 0xFEU
                        ? "only PADDD xmm, xmm/m128 is supported"
                        : "only register-direct PADDQ xmm, xmm is supported");
            }
            if (isImmediateShift) {
                instruction.opcode = isDwordShiftRight ? Opcode::PsrldRegImm
                                     : secondOpcode == 0x72U ? Opcode::PslldRegImm
                                                             : Opcode::PsrlqRegImm;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        rmEncoding | ((rex & 0x1U) != 0 ? 8U : 0U)))});
                instruction.operands.push_back(ImmediateOperand{
                    code[opcodeOffset + 3], 8});
            } else if (packedMemorySource) {
                const bool ripRelative =
                    mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) == 0;
                if (rmEncoding == 0x4U) {
                    throw DecodeError(
                        address, remaining,
                        "SIB-addressed PADDD xmm, m128 is not supported");
                }
                auto operandCursor = opcodeOffset + 3;
                std::int64_t displacement = 0;
                if (mode == 0x1U) {
                    if (operandCursor >= code.size()) {
                        throw DecodeError(address, remaining,
                                          "truncated PADDD m128 disp8");
                    }
                    displacement = std::bit_cast<std::int8_t>(
                        code[operandCursor++]);
                } else if (mode == 0x2U || ripRelative) {
                    if (code.size() - operandCursor < 4) {
                        throw DecodeError(address, remaining,
                                          "truncated PADDD m128 disp32");
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
                instruction.opcode = Opcode::PadddRegMem;
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        regEncoding | ((rex & 0x4U) != 0 ? 8U : 0U)))});
                instruction.operands.push_back(
                    ripRelative
                        ? MemoryOperand{Register::Rax, displacement, 128,
                                        std::nullopt, 1, false, true}
                        : MemoryOperand{
                              decodeRegister(rmEncoding,
                                             (rex & 0x1U) != 0),
                              displacement, 128});
                const auto memoryEnd = operandCursor - instructionStart;
                instruction.length =
                    static_cast<std::uint8_t>(memoryEnd);
                std::copy_n(
                    code.begin() +
                        static_cast<std::ptrdiff_t>(instructionStart),
                    memoryEnd, instruction.bytes.begin());
                return true;
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
            return true;
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
            return true;
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
            return true;
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
        return true;
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
        return true;
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
            return true;
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
        return true;
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
            return true;
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
        return true;
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
            return true;
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
        return true;
    }

    if (((code[cursor] == 0x0FU && code.size() - cursor >= 3) ||
         (code.size() - cursor >= 4 && code[cursor] >= 0x40U &&
          code[cursor] <= 0x4FU && code[cursor + 1] == 0x0FU)) &&
        code[cursor + (code[cursor] == 0x0FU ? 1U : 2U)] == 0x2EU) {
        const bool hasUcomisdRex = code[cursor] != 0x0FU;
        const auto rex = hasUcomisdRex ? code[cursor] : 0U;
        const auto modrmOffset = cursor + (hasUcomisdRex ? 3U : 2U);
        const auto modrm = code[modrmOffset];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        if (mode != 0x3U || (rex & 0xAU) != 0) {
            throw DecodeError(
                address, remaining,
                "only register-direct UCOMISD xmm, xmm is supported");
        }
        instruction.opcode = Opcode::UcomisdRegReg;
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(static_cast<std::uint8_t>(
                ((modrm >> 3U) & 0x7U) | ((rex & 0x4U) != 0 ? 8U : 0U)))});
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(static_cast<std::uint8_t>(
                (modrm & 0x7U) | ((rex & 0x1U) != 0 ? 8U : 0U)))});
        const auto length = modrmOffset + 1 - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 3) {
        const auto afterUcomissPrefix = cursor + 1;
        const bool hasUcomissRex =
            code[afterUcomissPrefix] >= 0x40U && code[afterUcomissPrefix] <= 0x4FU;
        const auto ucomissOpcodeOffset =
            afterUcomissPrefix + (hasUcomissRex ? 1U : 0U);
        if (code.size() - ucomissOpcodeOffset >= 3 &&
            code[ucomissOpcodeOffset] == 0x0FU &&
            code[ucomissOpcodeOffset + 1] == 0x2EU) {
            const auto rex = hasUcomissRex ? code[afterUcomissPrefix] : 0U;
            const auto modrm = code[ucomissOpcodeOffset + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if ((rex & 0x8U) != 0) {
                throw DecodeError(
                    address, remaining,
                    "UCOMISS does not support REX.W");
            }
            const auto destination = XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    ((modrm >> 3U) & 0x7U) | ((rex & 0x4U) != 0 ? 8U : 0U)))};
            if (mode == 0x3U) {
                instruction.opcode = Opcode::UcomissRegReg;
                instruction.operands.push_back(destination);
                instruction.operands.push_back(XmmRegisterOperand{
                    static_cast<XmmRegister>(static_cast<std::uint8_t>(
                        (modrm & 0x7U) | ((rex & 0x1U) != 0 ? 8U : 0U)))});
                const auto length = ucomissOpcodeOffset + 3 - instructionStart;
                instruction.length = static_cast<std::uint8_t>(length);
                std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                            length, instruction.bytes.begin());
                return true;
            }
            const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
            const bool ripRelative =
                mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) == 0;
            auto baseEncoding = rmEncoding;
            std::optional<Register> index;
            std::uint8_t scale = 1;
            auto operandCursor = ucomissOpcodeOffset + 3;
            if (!ripRelative && rmEncoding == 0x4U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated UCOMISS m32 SIB");
                }
                const auto sib = code[operandCursor++];
                const auto scaleBits =
                    static_cast<std::uint8_t>((sib >> 6U) & 0x3U);
                const auto indexEncoding =
                    static_cast<std::uint8_t>((sib >> 3U) & 0x7U);
                baseEncoding = static_cast<std::uint8_t>(sib & 0x7U);
                if (mode == 0 && baseEncoding == 0x5U) {
                    throw DecodeError(address, remaining,
                                      "no-base UCOMISS m32 SIB is not supported");
                }
                if (indexEncoding != 0x4U || (rex & 0x2U) != 0) {
                    index = decodeRegister(indexEncoding, (rex & 0x2U) != 0);
                    scale = static_cast<std::uint8_t>(1U << scaleBits);
                }
            } else if (!ripRelative && ((rex & 0x2U) != 0)) {
                throw DecodeError(address, remaining,
                                  "REX.X requires a UCOMISS m32 SIB");
            }
            std::int64_t displacement = 0;
            if (mode == 0x1U) {
                if (operandCursor >= code.size()) {
                    throw DecodeError(address, remaining,
                                      "truncated UCOMISS m32 disp8");
                }
                displacement =
                    std::bit_cast<std::int8_t>(code[operandCursor++]);
            } else if (mode == 0x2U || ripRelative) {
                if (code.size() - operandCursor < 4) {
                    throw DecodeError(address, remaining,
                                      "truncated UCOMISS m32 disp32");
                }
                displacement = readI32(code.subspan(operandCursor, 4));
                operandCursor += 4;
            }
            if (ripRelative) {
                static_cast<void>(relativeTarget(
                    address, operandCursor - instructionStart,
                    displacement));
            }
            instruction.opcode = Opcode::UcomissRegMem;
            instruction.operands.push_back(destination);
            instruction.operands.push_back(
                ripRelative
                    ? MemoryOperand{Register::Rax, displacement, 32,
                                    std::nullopt, 1, false, true}
                    : MemoryOperand{decodeRegister(baseEncoding,
                                                   (rex & 0x1U) != 0),
                                    displacement, 32, index, scale});
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                        length, instruction.bytes.begin());
            return true;
        }
    }

    if (((code[cursor] == 0x0FU && code.size() - cursor >= 4) ||
         (code.size() - cursor >= 5 && code[cursor] >= 0x40U &&
          code[cursor] <= 0x4FU && code[cursor + 1] == 0x0FU)) &&
        code[cursor + (code[cursor] == 0x0FU ? 1U : 2U)] == 0xC6U) {
        const bool hasShufpsRex = code[cursor] != 0x0FU;
        const auto rex = hasShufpsRex ? code[cursor] : 0U;
        const auto modrmOffset = cursor + (hasShufpsRex ? 3U : 2U);
        const auto modrm = code[modrmOffset];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        if (mode != 0x3U || (rex & 0xAU) != 0) {
            throw DecodeError(
                address, remaining,
                "only register-direct SHUFPS xmm, xmm, imm8 is supported");
        }
        if (code.size() - modrmOffset < 2) {
            throw DecodeError(address, remaining,
                              "truncated SHUFPS xmm, xmm, imm8");
        }
        instruction.opcode = Opcode::ShufpsRegRegImm;
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(static_cast<std::uint8_t>(
                ((modrm >> 3U) & 0x7U) | ((rex & 0x4U) != 0 ? 8U : 0U)))});
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(static_cast<std::uint8_t>(
                (modrm & 0x7U) | ((rex & 0x1U) != 0 ? 8U : 0U)))});
        instruction.operands.push_back(
            ImmediateOperand{code[modrmOffset + 1], 8});
        const auto length = modrmOffset + 2 - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    if (((code[cursor] == 0x0FU && code.size() - cursor >= 3) ||
         (code.size() - cursor >= 4 && code[cursor] >= 0x40U &&
          code[cursor] <= 0x4FU && code[cursor + 1] == 0x0FU)) &&
        code[cursor + (code[cursor] == 0x0FU ? 1U : 2U)] == 0x50U) {
        const bool hasMovmskpsRex = code[cursor] != 0x0FU;
        const auto rex = hasMovmskpsRex ? code[cursor] : 0U;
        const auto modrmOffset = cursor + (hasMovmskpsRex ? 3U : 2U);
        const auto modrm = code[modrmOffset];
        const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
        if (mode != 0x3U || (rex & 0xAU) != 0) {
            throw DecodeError(
                address, remaining,
                "only register-direct MOVMSKPS r32, xmm is supported");
        }
        instruction.opcode = Opcode::MovmskpsRegXmm;
        instruction.operands.push_back(RegisterOperand{
            decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U),
                           (rex & 0x4U) != 0),
            32});
        instruction.operands.push_back(XmmRegisterOperand{
            static_cast<XmmRegister>(static_cast<std::uint8_t>(
                (modrm & 0x7U) | ((rex & 0x1U) != 0 ? 8U : 0U)))});
        const auto length = modrmOffset + 1 - instructionStart;
        instruction.length = static_cast<std::uint8_t>(length);
        std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(instructionStart),
                    length, instruction.bytes.begin());
        return true;
    }

    if (code[cursor] == 0x66U && code.size() - cursor >= 3) {
        const auto afterMovmskpd = cursor + 1U;
        const bool hasMovmskpdRex =
            code[afterMovmskpd] >= 0x40U && code[afterMovmskpd] <= 0x4FU;
        const auto movmskpdOpcodeOffset =
            afterMovmskpd + (hasMovmskpdRex ? 1U : 0U);
        if (code.size() - movmskpdOpcodeOffset >= 3 &&
            code[movmskpdOpcodeOffset] == 0x0FU &&
            code[movmskpdOpcodeOffset + 1] == 0x50U) {
            const auto rex = hasMovmskpdRex ? code[afterMovmskpd] : 0U;
            const auto modrm = code[movmskpdOpcodeOffset + 2];
            const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
            if (mode != 0x3U || (rex & 0xAU) != 0) {
                throw DecodeError(
                    address, remaining,
                    "only register-direct MOVMSKPD r32, xmm is supported");
            }
            instruction.opcode = Opcode::MovmskpdRegXmm;
            instruction.operands.push_back(RegisterOperand{
                decodeRegister(static_cast<std::uint8_t>((modrm >> 3U) & 0x7U),
                               (rex & 0x4U) != 0),
                32});
            instruction.operands.push_back(XmmRegisterOperand{
                static_cast<XmmRegister>(static_cast<std::uint8_t>(
                    (modrm & 0x7U) | ((rex & 0x1U) != 0 ? 8U : 0U)))});
            const auto operandCursor = movmskpdOpcodeOffset + 3;
            const auto length = operandCursor - instructionStart;
            instruction.length = static_cast<std::uint8_t>(length);
            std::copy_n(
                code.begin() +
                    static_cast<std::ptrdiff_t>(instructionStart),
                length, instruction.bytes.begin());
            return true;
        }
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
            return true;
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
        const bool ripRelative =
            mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) == 0;
        if (mode > 0x2U || (mode == 0 && rmEncoding == 0x5U && (rex & 0x1U) != 0)) {
            throw DecodeError(
                address, remaining,
                "only MOVQ [base+index*scale+disp8/disp32/RIP], xmm memory operands are supported");
        }
        auto operandCursor = modrmOffset + 1;
        auto baseEncoding = rmEncoding;
        std::optional<Register> index;
        std::uint8_t scale = 1;
        if (!ripRelative && rmEncoding == 0x4U) {
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
        } else if (mode == 0x2U || ripRelative) {
            if (code.size() - operandCursor < 4) {
                throw DecodeError(address, remaining,
                                  "truncated MOVQ memory disp32");
            }
            displacement = readI32(code.subspan(operandCursor, 4));
            operandCursor += 4;
        }
        if (ripRelative) {
            static_cast<void>(relativeTarget(
                address, operandCursor - instructionStart, displacement));
        }
        instruction.opcode = Opcode::MovqMemXmm;
        instruction.operands.push_back(
            ripRelative
                ? MemoryOperand{Register::Rax, displacement, 64,
                                std::nullopt, 1, false, true}
                : MemoryOperand{
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
        return true;
    }

    return false;
}

} // namespace rosa::x86::detail
