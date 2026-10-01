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

} // namespace rosa::x86::detail
