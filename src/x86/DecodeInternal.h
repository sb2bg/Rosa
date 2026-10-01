#pragma once

#include "x86/Decoder.h"

#include <algorithm>
#include <bit>
#include <limits>

namespace rosa::x86::detail {

// One instruction, with offsets relative to its first byte. Recognition families
// run in a fixed order: false continues recognition, true completes the instruction,
// and malformed or unsupported recognized encodings throw DecodeError.
struct DecodeContext {
    std::span<const std::uint8_t> code;
    guest::GuestAddress address;
    std::size_t cursor{};
    DecodedInstruction instruction;
};

[[nodiscard]] bool decodeVex(DecodeContext &context);
[[nodiscard]] bool decodeScalarSpecial(DecodeContext &context);
[[nodiscard]] bool decodeOperandOverride(DecodeContext &context);
[[nodiscard]] bool decodeSimdLanes(DecodeContext &context);
[[nodiscard]] bool decodeSimdMemory(DecodeContext &context);
[[nodiscard]] bool decodeRepeat(DecodeContext &context);
[[nodiscard]] bool decodeControlTransfer(DecodeContext &context);
[[nodiscard]] bool decodeAtomic(DecodeContext &context);
[[nodiscard]] bool decodeExtended(DecodeContext &context);
[[nodiscard]] bool decodeGeneral(DecodeContext &context);

inline std::uint64_t readU64(std::span<const std::uint8_t> bytes) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
    }
    return value;
}

inline std::int32_t readI32(std::span<const std::uint8_t> bytes) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<std::uint32_t>(bytes[index]) << (index * 8U);
    }
    return std::bit_cast<std::int32_t>(value);
}

inline guest::GuestAddress relativeTarget(guest::GuestAddress address, std::size_t length,
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

inline Register decodeRegister(std::uint8_t lowBits, bool rexB) {
    const auto encoded = static_cast<std::uint8_t>(lowBits | (rexB ? 8U : 0U));
    return static_cast<Register>(encoded);
}

// Decodes the memory form (mode 0-2) of a ModRM byte, with cursor at the byte
// after ModRM. Covers [base], [base+index*scale], [index*scale+disp32] (no
// base), and [rip+disp32], each with its displacement, and leaves cursor
// after the operand. New instruction forms should use this instead of
// re-decoding SIB and displacement bytes inline.
inline MemoryOperand decodeModrmMemory(DecodeContext &context, std::size_t &cursor,
                                       std::uint8_t modrm, std::uint8_t rex,
                                       std::uint16_t width) {
    const auto &code = context.code;
    const auto mode = static_cast<std::uint8_t>((modrm >> 6U) & 0x3U);
    const auto rmEncoding = static_cast<std::uint8_t>(modrm & 0x7U);
    const bool rexB = (rex & 0x1U) != 0;
    const bool rexX = (rex & 0x2U) != 0;
    if (mode == 0x3U) {
        throw std::logic_error("decodeModrmMemory requires a memory ModRM form");
    }
    const auto truncated = [&](const char *what) {
        return DecodeError(context.address, code, std::string("truncated memory operand ") + what);
    };
    MemoryOperand memory{Register::Rax, 0, width};
    bool displacement32 = mode == 0x2U;
    if (rmEncoding == 0x4U) {
        if (cursor >= code.size()) {
            throw truncated("SIB");
        }
        const auto sib = code[cursor++];
        const auto indexEncoding =
            static_cast<std::uint8_t>(((sib >> 3U) & 0x7U) | (rexX ? 8U : 0U));
        if (indexEncoding != 0x4U) {
            memory.index = static_cast<Register>(indexEncoding);
            memory.scale = static_cast<std::uint8_t>(1U << ((sib >> 6U) & 0x3U));
        }
        if (mode == 0 && (sib & 0x7U) == 0x5U) {
            memory.hasBase = false;
            displacement32 = true;
        } else {
            memory.base = decodeRegister(static_cast<std::uint8_t>(sib & 0x7U), rexB);
        }
    } else if (mode == 0 && rmEncoding == 0x5U) {
        memory.hasBase = false;
        memory.ripRelative = true;
        displacement32 = true;
    } else {
        memory.base = decodeRegister(rmEncoding, rexB);
    }
    if (mode == 0x1U) {
        if (cursor >= code.size()) {
            throw truncated("disp8");
        }
        memory.displacement = std::bit_cast<std::int8_t>(code[cursor++]);
    } else if (displacement32) {
        if (code.size() - cursor < 4) {
            throw truncated("disp32");
        }
        memory.displacement = readI32(code.subspan(cursor, 4));
        cursor += 4;
    }
    return memory;
}

} // namespace rosa::x86::detail
