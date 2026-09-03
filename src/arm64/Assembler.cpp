#include "arm64/Assembler.h"

#include <array>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace rosa::arm64 {
namespace {

std::string regName(XRegister reg) { return "x" + std::to_string(reg.encoding); }

std::string hexImmediate(std::uint64_t value) {
    std::ostringstream stream;
    stream << "#0x" << std::hex << value;
    return stream.str();
}

} // namespace

void Assembler::requireRegister(XRegister reg) {
    if (reg.encoding > 30U) {
        throw std::invalid_argument("ARM64 general-purpose register must be x0...x30");
    }
}

void Assembler::emit(std::uint32_t word, std::string text) {
    words_.push_back(word);
    if (!recordListing_) {
        return;
    }
    try {
        listing_.push_back(std::move(text));
    } catch (...) {
        words_.pop_back();
        throw;
    }
}

void Assembler::emitFixup(std::uint32_t word, std::string text, FixupKind kind, Label label) {
    const auto index = words_.size();
    emit(word, std::move(text));
    try {
        fixups_.push_back(Fixup{kind, index, label});
    } catch (...) {
        if (recordListing_) {
            listing_.pop_back();
        }
        words_.pop_back();
        throw;
    }
}

void Assembler::mov(XRegister destination, XRegister source) {
    requireRegister(destination);
    requireRegister(source);
    const auto word = 0xAA0003E0U | (static_cast<std::uint32_t>(source.encoding) << 16U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word,
         recordListing_ ? "mov " + regName(destination) + ", " + regName(source) : std::string{});
}

void Assembler::mov32(XRegister destination, XRegister source) {
    requireRegister(destination);
    requireRegister(source);
    const auto word = 0x2A0003E0U | (static_cast<std::uint32_t>(source.encoding) << 16U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "mov w" + std::to_string(destination.encoding) + ", w" +
                                    std::to_string(source.encoding)
                              : std::string{});
}

void Assembler::movImmediate(XRegister destination, std::uint64_t value) {
    requireRegister(destination);

    std::array<std::uint16_t, 4> halfwords{};
    std::size_t nonzeroCount = 0;
    std::size_t nonOnesCount = 0;
    for (std::uint32_t halfword = 0; halfword < halfwords.size(); ++halfword) {
        const auto shift = halfword * 16U;
        halfwords[halfword] = static_cast<std::uint16_t>((value >> shift) & 0xFFFFU);
        nonzeroCount += halfwords[halfword] != 0 ? 1U : 0U;
        nonOnesCount += halfwords[halfword] != UINT16_MAX ? 1U : 0U;
    }
    const auto useMovn = nonOnesCount < nonzeroCount;
    bool emittedFirst = false;
    for (std::uint32_t halfword = 0; halfword < halfwords.size(); ++halfword) {
        const auto shift = halfword * 16U;
        const auto desired = halfwords[halfword];
        const auto fill = useMovn ? UINT16_MAX : 0U;
        if (desired == fill && (emittedFirst || (useMovn ? value != UINT64_MAX : value != 0))) {
            continue;
        }

        const auto immediate = static_cast<std::uint16_t>(
            useMovn && !emittedFirst ? static_cast<std::uint16_t>(~desired) : desired);
        const auto base = emittedFirst ? 0xF2800000U : useMovn ? 0x92800000U : 0xD2800000U;
        const auto word = base | (halfword << 21U) | (static_cast<std::uint32_t>(immediate) << 5U) |
                          static_cast<std::uint32_t>(destination.encoding);
        std::string text;
        if (recordListing_) {
            text = std::string(emittedFirst ? "movk "
                               : useMovn    ? "movn "
                                            : "movz ") +
                   regName(destination) + ", " + hexImmediate(immediate);
            if (shift != 0) {
                text += ", lsl #" + std::to_string(shift);
            }
        }
        emit(word, std::move(text));
        emittedFirst = true;
    }
}

void Assembler::movImmediate(XRegister destination, RelocatablePointer pointer) {
    requireRegister(destination);
    if (words_.size() > std::numeric_limits<std::uint32_t>::max() / sizeof(std::uint32_t)) {
        throw std::overflow_error("ARM64 pointer relocation offset overflows");
    }
    const auto firstWord = words_.size();
    const auto firstListing = listing_.size();
    try {
        for (std::uint32_t halfword = 0; halfword < 4; ++halfword) {
            const auto shift = halfword * 16U;
            const auto immediate =
                static_cast<std::uint16_t>((pointer.value >> shift) & UINT64_C(0xFFFF));
            const auto base = halfword == 0 ? 0xD2800000U : 0xF2800000U;
            const auto word = base | (halfword << 21U) |
                              (static_cast<std::uint32_t>(immediate) << 5U) |
                              static_cast<std::uint32_t>(destination.encoding);
            std::string text;
            if (recordListing_) {
                text = std::string(halfword == 0 ? "movz " : "movk ") + regName(destination) +
                       ", " + hexImmediate(immediate);
                if (shift != 0) {
                    text += ", lsl #" + std::to_string(shift);
                }
            }
            emit(word, std::move(text));
        }
        pointerRelocations_.push_back(
            static_cast<std::uint32_t>(firstWord * sizeof(std::uint32_t)));
    } catch (...) {
        words_.resize(firstWord);
        if (recordListing_) {
            listing_.resize(firstListing);
        }
        throw;
    }
}

void Assembler::add(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x8B000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "add " + regName(destination) + ", " + regName(lhs) + ", " + regName(rhs)
                   : std::string{});
}

void Assembler::add32(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x0B000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "add w" + std::to_string(destination.encoding) + ", w" +
                         std::to_string(lhs.encoding) + ", w" + std::to_string(rhs.encoding)
                   : std::string{});
}

void Assembler::addImmediate(XRegister destination, XRegister source, std::uint16_t immediate) {
    requireRegister(destination);
    requireRegister(source);
    if (immediate > 0x0FFFU) {
        throw std::invalid_argument("ARM64 ADD immediate must fit in 12 bits");
    }
    const auto word = 0x91000000U | (static_cast<std::uint32_t>(immediate) << 10U) |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "add " + regName(destination) + ", " + regName(source) + ", #" +
                                    std::to_string(immediate)
                              : std::string{});
}

void Assembler::addImmediate32(XRegister destination, XRegister source, std::uint16_t immediate) {
    requireRegister(destination);
    requireRegister(source);
    if (immediate > 0x0FFFU) {
        throw std::invalid_argument("ARM64 32-bit ADD immediate must fit in 12 bits");
    }
    const auto word = 0x11000000U | (static_cast<std::uint32_t>(immediate) << 10U) |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "add w" + std::to_string(destination.encoding) + ", w" +
                         std::to_string(source.encoding) + ", #" + std::to_string(immediate)
                   : std::string{});
}

void Assembler::sub(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0xCB000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "sub " + regName(destination) + ", " + regName(lhs) + ", " + regName(rhs)
                   : std::string{});
}

void Assembler::sub32(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x4B000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "sub w" + std::to_string(destination.encoding) + ", w" +
                         std::to_string(lhs.encoding) + ", w" + std::to_string(rhs.encoding)
                   : std::string{});
}

void Assembler::subImmediate(XRegister destination, XRegister source, std::uint16_t immediate) {
    requireRegister(destination);
    requireRegister(source);
    if (immediate > 0x0FFFU) {
        throw std::invalid_argument("ARM64 SUB immediate must fit in 12 bits");
    }
    const auto word = 0xD1000000U | (static_cast<std::uint32_t>(immediate) << 10U) |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "sub " + regName(destination) + ", " + regName(source) + ", #" +
                                    std::to_string(immediate)
                              : std::string{});
}

void Assembler::subImmediate32(XRegister destination, XRegister source, std::uint16_t immediate) {
    requireRegister(destination);
    requireRegister(source);
    if (immediate > 0x0FFFU) {
        throw std::invalid_argument("ARM64 32-bit SUB immediate must fit in 12 bits");
    }
    const auto word = 0x51000000U | (static_cast<std::uint32_t>(immediate) << 10U) |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "sub w" + std::to_string(destination.encoding) + ", w" +
                         std::to_string(source.encoding) + ", #" + std::to_string(immediate)
                   : std::string{});
}

void Assembler::lslImmediate(XRegister destination, XRegister source, std::uint8_t shift) {
    requireRegister(destination);
    requireRegister(source);
    if (shift >= 64U) {
        throw std::invalid_argument("64-bit LSL immediate must be less than 64");
    }
    if (shift == 0) {
        mov(destination, source);
        return;
    }
    const auto immr = static_cast<std::uint32_t>(64U - shift);
    const auto imms = static_cast<std::uint32_t>(63U - shift);
    const auto word = 0xD3400000U | (immr << 16U) | (imms << 10U) |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "lsl " + regName(destination) + ", " + regName(source) + ", #" +
                                    std::to_string(shift)
                              : std::string{});
}

void Assembler::lsrImmediate(XRegister destination, XRegister source, std::uint8_t shift) {
    requireRegister(destination);
    requireRegister(source);
    if (shift >= 64U) {
        throw std::invalid_argument("64-bit LSR immediate must be less than 64");
    }
    if (shift == 0) {
        mov(destination, source);
        return;
    }
    const auto word = 0xD340FC00U | (static_cast<std::uint32_t>(shift) << 16U) |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "lsr " + regName(destination) + ", " + regName(source) + ", #" +
                                    std::to_string(shift)
                              : std::string{});
}

void Assembler::asrImmediate(XRegister destination, XRegister source, std::uint8_t shift) {
    requireRegister(destination);
    requireRegister(source);
    if (shift >= 64U) {
        throw std::invalid_argument("64-bit ASR immediate must be less than 64");
    }
    if (shift == 0) {
        mov(destination, source);
        return;
    }
    const auto word = 0x9340FC00U | (static_cast<std::uint32_t>(shift) << 16U) |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "asr " + regName(destination) + ", " + regName(source) + ", #" +
                                    std::to_string(shift)
                              : std::string{});
}

void Assembler::asrImmediate32(XRegister destination, XRegister source, std::uint8_t shift) {
    requireRegister(destination);
    requireRegister(source);
    if (shift >= 32U) {
        throw std::invalid_argument("32-bit ASR immediate must be less than 32");
    }
    if (shift == 0) {
        mov32(destination, source);
        return;
    }
    const auto word = 0x13007C00U | (static_cast<std::uint32_t>(shift) << 16U) |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "asr w" + std::to_string(destination.encoding) + ", w" +
                                    std::to_string(source.encoding) + ", #" + std::to_string(shift)
                              : std::string{});
}

void Assembler::reverseBytes32(XRegister destination, XRegister source) {
    requireRegister(destination);
    requireRegister(source);
    const auto word = 0x5AC00800U | (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "rev w" + std::to_string(destination.encoding) + ", w" +
                                    std::to_string(source.encoding)
                              : std::string{});
}

void Assembler::reverseBytes64(XRegister destination, XRegister source) {
    requireRegister(destination);
    requireRegister(source);
    const auto word = 0xDAC00C00U | (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word,
         recordListing_ ? "rev " + regName(destination) + ", " + regName(source) : std::string{});
}

void Assembler::signExtend32(XRegister destination, XRegister source) {
    requireRegister(destination);
    requireRegister(source);
    const auto word = 0x93407C00U | (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "sxtw " + regName(destination) + ", w" + std::to_string(source.encoding)
                   : std::string{});
}

void Assembler::lslVariable(XRegister destination, XRegister source, XRegister shift) {
    requireRegister(destination);
    requireRegister(source);
    requireRegister(shift);
    const auto word = 0x9AC02000U | (static_cast<std::uint32_t>(shift.encoding) << 16U) |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "lsl " + regName(destination) + ", " + regName(source) + ", " + regName(shift)
                   : std::string{});
}

void Assembler::lsrVariable(XRegister destination, XRegister source, XRegister shift) {
    requireRegister(destination);
    requireRegister(source);
    requireRegister(shift);
    const auto word = 0x9AC02400U | (static_cast<std::uint32_t>(shift.encoding) << 16U) |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "lsr " + regName(destination) + ", " + regName(source) + ", " + regName(shift)
                   : std::string{});
}

void Assembler::multiplyLow(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x9B007C00U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "mul " + regName(destination) + ", " + regName(lhs) + ", " + regName(rhs)
                   : std::string{});
}

void Assembler::multiplyHighUnsigned(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x9BC07C00U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "umulh " + regName(destination) + ", " + regName(lhs) + ", " + regName(rhs)
                   : std::string{});
}

void Assembler::extract(XRegister destination, XRegister high, XRegister low, std::uint8_t lsb) {
    requireRegister(destination);
    requireRegister(high);
    requireRegister(low);
    if (lsb >= 64U) {
        throw std::invalid_argument("64-bit EXTR bit position must be less than 64");
    }
    const auto word = 0x93C00000U | (static_cast<std::uint32_t>(low.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lsb) << 10U) |
                      (static_cast<std::uint32_t>(high.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "extr " + regName(destination) + ", " + regName(high) + ", " +
                                    regName(low) + ", #" + std::to_string(lsb)
                              : std::string{});
}

void Assembler::bitAnd(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x8A000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "and " + regName(destination) + ", " + regName(lhs) + ", " + regName(rhs)
                   : std::string{});
}

void Assembler::bitAnd32(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x0A000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "and w" + std::to_string(destination.encoding) + ", w" +
                         std::to_string(lhs.encoding) + ", w" + std::to_string(rhs.encoding)
                   : std::string{});
}

void Assembler::bitOr(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0xAA000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "orr " + regName(destination) + ", " + regName(lhs) + ", " + regName(rhs)
                   : std::string{});
}

void Assembler::bitOr32(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x2A000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "orr w" + std::to_string(destination.encoding) + ", w" +
                         std::to_string(lhs.encoding) + ", w" + std::to_string(rhs.encoding)
                   : std::string{});
}

void Assembler::bitOrShiftedLeft(XRegister destination, XRegister lhs, XRegister rhs,
                                 std::uint8_t shift) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    if (shift >= 64U) {
        throw std::invalid_argument("64-bit ORR shift must be less than 64");
    }
    const auto word = 0xAA000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(shift) << 10U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "orr " + regName(destination) + ", " + regName(lhs) + ", " +
                                    regName(rhs) + ", lsl #" + std::to_string(shift)
                              : std::string{});
}

void Assembler::bitXor(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0xCA000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "eor " + regName(destination) + ", " + regName(lhs) + ", " + regName(rhs)
                   : std::string{});
}

void Assembler::bitXor32(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x4A000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "eor w" + std::to_string(destination.encoding) + ", w" +
                         std::to_string(lhs.encoding) + ", w" + std::to_string(rhs.encoding)
                   : std::string{});
}

void Assembler::bitXorShiftedRight(XRegister destination, XRegister lhs, XRegister rhs,
                                   std::uint8_t shift) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    if (shift >= 64U) {
        throw std::invalid_argument("64-bit EOR shift must be less than 64");
    }
    const auto word = 0xCA400000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(shift) << 10U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "eor " + regName(destination) + ", " + regName(lhs) + ", " +
                                    regName(rhs) + ", lsr #" + std::to_string(shift)
                              : std::string{});
}

void Assembler::compare(XRegister lhs, XRegister rhs) {
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0xEB00001FU | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U);
    emit(word, recordListing_ ? "cmp " + regName(lhs) + ", " + regName(rhs) : std::string{});
}

void Assembler::compareZero(XRegister value) {
    requireRegister(value);
    const auto word = 0xF100001FU | (static_cast<std::uint32_t>(value.encoding) << 5U);
    emit(word, recordListing_ ? "cmp " + regName(value) + ", #0" : std::string{});
}

void Assembler::conditionalSet(XRegister destination, BranchCondition condition) {
    requireRegister(destination);
    const auto encoding = static_cast<std::uint8_t>(condition);
    if (encoding > static_cast<std::uint8_t>(BranchCondition::SignedLessOrEqual)) {
        throw std::invalid_argument("invalid ARM64 conditional-set condition");
    }
    const auto inverse = static_cast<std::uint32_t>(encoding ^ 1U);
    const auto word =
        0x9A9F07E0U | (inverse << 12U) | static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "cset " + regName(destination) : std::string{});
}

void Assembler::conditionalSelect(XRegister destination, XRegister ifTrue, XRegister ifFalse,
                                  BranchCondition condition) {
    requireRegister(destination);
    requireRegister(ifTrue);
    requireRegister(ifFalse);
    const auto encoding = static_cast<std::uint8_t>(condition);
    if (encoding > static_cast<std::uint8_t>(BranchCondition::SignedLessOrEqual)) {
        throw std::invalid_argument("invalid ARM64 conditional-select condition");
    }
    const auto word = 0x9A800000U | (static_cast<std::uint32_t>(ifFalse.encoding) << 16U) |
                      (static_cast<std::uint32_t>(encoding) << 12U) |
                      (static_cast<std::uint32_t>(ifTrue.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "csel " + regName(destination) + ", " + regName(ifTrue) + ", " +
                                    regName(ifFalse)
                              : std::string{});
}

void Assembler::conditionalSelect32(XRegister destination, XRegister ifTrue, XRegister ifFalse,
                                    BranchCondition condition) {
    requireRegister(destination);
    requireRegister(ifTrue);
    requireRegister(ifFalse);
    const auto encoding = static_cast<std::uint8_t>(condition);
    if (encoding > static_cast<std::uint8_t>(BranchCondition::SignedLessOrEqual)) {
        throw std::invalid_argument("invalid ARM64 32-bit conditional-select condition");
    }
    const auto word = 0x1A800000U | (static_cast<std::uint32_t>(ifFalse.encoding) << 16U) |
                      (static_cast<std::uint32_t>(encoding) << 12U) |
                      (static_cast<std::uint32_t>(ifTrue.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "csel w" + std::to_string(destination.encoding) : std::string{});
}

void Assembler::conditionalSelectEqual(XRegister destination, XRegister ifEqual,
                                       XRegister ifNotEqual) {
    conditionalSelect(destination, ifEqual, ifNotEqual, BranchCondition::Equal);
}

void Assembler::ldr(XRegister destination, XRegister base, std::uint32_t byteOffset) {
    requireRegister(destination);
    requireRegister(base);
    if ((byteOffset % 8U) != 0 || byteOffset > 32760U) {
        throw std::invalid_argument("64-bit LDR offset must be aligned and <= 32760");
    }
    const auto scaledOffset = byteOffset / 8U;
    const auto word = 0xF9400000U | (scaledOffset << 10U) |
                      (static_cast<std::uint32_t>(base.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "ldr " + regName(destination) + ", [" + regName(base) + ", #" +
                                    std::to_string(byteOffset) + "]"
                              : std::string{});
}

void Assembler::ldr32(XRegister destination, XRegister base, std::uint32_t byteOffset) {
    requireRegister(destination);
    requireRegister(base);
    if ((byteOffset % 4U) != 0 || byteOffset > 16380U) {
        throw std::invalid_argument("32-bit LDR offset must be aligned and <= 16380");
    }
    const auto scaledOffset = byteOffset / 4U;
    const auto word = 0xB9400000U | (scaledOffset << 10U) |
                      (static_cast<std::uint32_t>(base.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "ldr w" + std::to_string(destination.encoding) + ", [" +
                                    regName(base) + ", #" + std::to_string(byteOffset) + "]"
                              : std::string{});
}

void Assembler::ldr8(XRegister destination, XRegister base, std::uint32_t byteOffset) {
    requireRegister(destination);
    requireRegister(base);
    if (byteOffset > 4095U) {
        throw std::invalid_argument("8-bit LDR offset must be <= 4095");
    }
    const auto word = 0x39400000U | (byteOffset << 10U) |
                      (static_cast<std::uint32_t>(base.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_ ? "ldrb w" + std::to_string(destination.encoding) + ", [" +
                                    regName(base) + ", #" + std::to_string(byteOffset) + "]"
                              : std::string{});
}

void Assembler::str(XRegister source, XRegister base, std::uint32_t byteOffset) {
    requireRegister(source);
    requireRegister(base);
    if ((byteOffset % 8U) != 0 || byteOffset > 32760U) {
        throw std::invalid_argument("64-bit STR offset must be aligned and <= 32760");
    }
    const auto scaledOffset = byteOffset / 8U;
    const auto word = 0xF9000000U | (scaledOffset << 10U) |
                      (static_cast<std::uint32_t>(base.encoding) << 5U) |
                      static_cast<std::uint32_t>(source.encoding);
    emit(word, recordListing_ ? "str " + regName(source) + ", [" + regName(base) + ", #" +
                                    std::to_string(byteOffset) + "]"
                              : std::string{});
}

void Assembler::str8(XRegister source, XRegister base, std::uint32_t byteOffset) {
    requireRegister(source);
    requireRegister(base);
    if (byteOffset > 4095U) {
        throw std::invalid_argument("8-bit STR offset must be <= 4095");
    }
    const auto word = 0x39000000U | (byteOffset << 10U) |
                      (static_cast<std::uint32_t>(base.encoding) << 5U) |
                      static_cast<std::uint32_t>(source.encoding);
    emit(word, recordListing_ ? "strb w" + std::to_string(source.encoding) + ", [" + regName(base) +
                                    ", #" + std::to_string(byteOffset) + "]"
                              : std::string{});
}

void Assembler::blr(XRegister target) {
    requireRegister(target);
    emit(0xD63F0000U | (static_cast<std::uint32_t>(target.encoding) << 5U),
         recordListing_ ? "blr " + regName(target) : std::string{});
}

Label Assembler::makeLabel() {
    if (labelPositions_.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::overflow_error("ARM64 label identifier space is exhausted");
    }
    const auto id = static_cast<std::uint32_t>(labelPositions_.size());
    labelPositions_.push_back(std::nullopt);
    return Label{id};
}

void Assembler::bind(Label label) {
    if (label.id >= labelPositions_.size()) {
        throw std::invalid_argument("cannot bind an unknown ARM64 label");
    }
    if (labelPositions_[label.id]) {
        throw std::invalid_argument("cannot bind an ARM64 label twice");
    }
    labelPositions_[label.id] = words_.size();
}

void Assembler::b(Label label) {
    if (label.id >= labelPositions_.size()) {
        throw std::invalid_argument("cannot branch to an unknown ARM64 label");
    }
    emitFixup(0x14000000U, recordListing_ ? "b L" + std::to_string(label.id) : std::string{},
              FixupKind::Branch26, label);
}

void Assembler::cbz(XRegister value, Label label) {
    requireRegister(value);
    if (label.id >= labelPositions_.size()) {
        throw std::invalid_argument("cannot compare-branch to an unknown ARM64 label");
    }
    const auto word = 0xB4000000U | static_cast<std::uint32_t>(value.encoding);
    emitFixup(word,
              recordListing_ ? "cbz " + regName(value) + ", L" + std::to_string(label.id)
                             : std::string{},
              FixupKind::CompareBranch19, label);
}

void Assembler::cbnz(XRegister value, Label label) {
    requireRegister(value);
    if (label.id >= labelPositions_.size()) {
        throw std::invalid_argument("cannot compare-branch to an unknown ARM64 label");
    }
    const auto word = 0xB5000000U | static_cast<std::uint32_t>(value.encoding);
    emitFixup(word,
              recordListing_ ? "cbnz " + regName(value) + ", L" + std::to_string(label.id)
                             : std::string{},
              FixupKind::CompareBranch19, label);
}

void Assembler::bConditional(BranchCondition condition, Label label) {
    if (label.id >= labelPositions_.size()) {
        throw std::invalid_argument("cannot conditionally branch to an unknown ARM64 label");
    }
    constexpr std::array<std::string_view, 14> suffixes{
        "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
    };
    const auto encoding = static_cast<std::uint8_t>(condition);
    if (encoding >= suffixes.size()) {
        throw std::invalid_argument("invalid ARM64 branch condition");
    }
    const auto word = 0x54000000U | static_cast<std::uint32_t>(encoding);
    emitFixup(word,
              recordListing_
                  ? "b." + std::string(suffixes[encoding]) + " L" + std::to_string(label.id)
                  : std::string{},
              FixupKind::CompareBranch19, label);
}

void Assembler::bUnsignedHigherOrSame(Label label) {
    bConditional(BranchCondition::UnsignedHigherOrSame, label);
}

void Assembler::tbz(XRegister value, std::uint8_t bit, Label label) {
    requireRegister(value);
    if (bit >= 64U || label.id >= labelPositions_.size()) {
        throw std::invalid_argument("invalid TBZ operand or label");
    }
    const auto word = 0x36000000U | (static_cast<std::uint32_t>(bit >> 5U) << 31U) |
                      (static_cast<std::uint32_t>(bit & 0x1FU) << 19U) |
                      static_cast<std::uint32_t>(value.encoding);
    emitFixup(word,
              recordListing_ ? "tbz " + regName(value) + ", #" + std::to_string(bit) + ", L" +
                                   std::to_string(label.id)
                             : std::string{},
              FixupKind::TestBranch14, label);
}

void Assembler::tbnz(XRegister value, std::uint8_t bit, Label label) {
    requireRegister(value);
    if (bit >= 64U || label.id >= labelPositions_.size()) {
        throw std::invalid_argument("invalid TBNZ operand or label");
    }
    const auto word = 0x37000000U | (static_cast<std::uint32_t>(bit >> 5U) << 31U) |
                      (static_cast<std::uint32_t>(bit & 0x1FU) << 19U) |
                      static_cast<std::uint32_t>(value.encoding);
    emitFixup(word,
              recordListing_ ? "tbnz " + regName(value) + ", #" + std::to_string(bit) + ", L" +
                                   std::to_string(label.id)
                             : std::string{},
              FixupKind::TestBranch14, label);
}

void Assembler::pushFrameRecord() { emit(0xA9BF7BFDU, "stp x29, x30, [sp, #-16]!"); }

void Assembler::popFrameRecord() { emit(0xA8C17BFDU, "ldp x29, x30, [sp], #16"); }

void Assembler::pushCalleeSaved19And20() { emit(0xA9BF53F3U, "stp x19, x20, [sp, #-16]!"); }

void Assembler::popCalleeSaved19And20() { emit(0xA8C153F3U, "ldp x19, x20, [sp], #16"); }

void Assembler::pushCalleeSaved19Through22() {
    pushCalleeSaved19And20();
    emit(0xA9BF5BF5U, "stp x21, x22, [sp, #-16]!");
}

void Assembler::popCalleeSaved19Through22() {
    emit(0xA8C15BF5U, "ldp x21, x22, [sp], #16");
    popCalleeSaved19And20();
}

void Assembler::pushCalleeSaved19Through24() {
    pushCalleeSaved19Through22();
    emit(0xA9BF63F7U, "stp x23, x24, [sp, #-16]!");
}

void Assembler::popCalleeSaved19Through24() {
    emit(0xA8C163F7U, "ldp x23, x24, [sp], #16");
    popCalleeSaved19Through22();
}

void Assembler::pushCallerSaved8Through15() {
    emit(0xA9BF27E8U, "stp x8, x9, [sp, #-16]!");
    emit(0xA9BF2FEAU, "stp x10, x11, [sp, #-16]!");
    emit(0xA9BF37ECU, "stp x12, x13, [sp, #-16]!");
    emit(0xA9BF3FEEU, "stp x14, x15, [sp, #-16]!");
}

void Assembler::popCallerSaved8Through15() {
    emit(0xA8C13FEEU, "ldp x14, x15, [sp], #16");
    emit(0xA8C137ECU, "ldp x12, x13, [sp], #16");
    emit(0xA8C12FEAU, "ldp x10, x11, [sp], #16");
    emit(0xA8C127E8U, "ldp x8, x9, [sp], #16");
}

void Assembler::pushCallerSaved5Through15() {
    emit(0xA9BF1BE5U, "stp x5, x6, [sp, #-16]!");
    emit(0xA9BF7BE7U, "stp x7, x30, [sp, #-16]!");
    pushCallerSaved8Through15();
}

void Assembler::popCallerSaved5Through15() {
    popCallerSaved8Through15();
    emit(0xA8C17BE7U, "ldp x7, x30, [sp], #16");
    emit(0xA8C11BE5U, "ldp x5, x6, [sp], #16");
}

void Assembler::pushCalleeSaved25Through28() {
    emit(0xA9BF6BF9U, "stp x25, x26, [sp, #-16]!");
    emit(0xA9BF73FBU, "stp x27, x28, [sp, #-16]!");
}

void Assembler::popCalleeSaved25Through28() {
    emit(0xA8C173FBU, "ldp x27, x28, [sp], #16");
    emit(0xA8C16BF9U, "ldp x25, x26, [sp], #16");
}

void Assembler::dmbIsh() { emit(0xD5033BBFU, "dmb ish"); }

void Assembler::isb() { emit(0xD5033FDFU, "isb"); }

void Assembler::ret() { emit(0xD65F03C0U, "ret"); }

Program Assembler::finish() && {
    if (words_.size() > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max())) {
        throw std::overflow_error("ARM64 program is too large to resolve branches");
    }
    for (const auto &fixup : fixups_) {
        if (!labelPositions_[fixup.label.id]) {
            throw std::runtime_error("ARM64 branch targets an unbound label");
        }
        const auto target = static_cast<std::int64_t>(*labelPositions_[fixup.label.id]);
        const auto source = static_cast<std::int64_t>(fixup.wordIndex);
        const auto displacement = target - source;
        if (fixup.kind == FixupKind::Branch26) {
            constexpr auto minimum = -(std::int64_t{1} << 25U);
            constexpr auto maximum = (std::int64_t{1} << 25U) - 1;
            if (displacement < minimum || displacement > maximum) {
                throw std::runtime_error("ARM64 B target is out of range");
            }
            words_[fixup.wordIndex] |= static_cast<std::uint32_t>(displacement) & 0x03FFFFFFU;
        } else if (fixup.kind == FixupKind::CompareBranch19) {
            constexpr auto minimum = -(std::int64_t{1} << 18U);
            constexpr auto maximum = (std::int64_t{1} << 18U) - 1;
            if (displacement < minimum || displacement > maximum) {
                throw std::runtime_error("ARM64 compare-branch target is out of range");
            }
            words_[fixup.wordIndex] |= (static_cast<std::uint32_t>(displacement) & 0x7FFFFU) << 5U;
        } else {
            constexpr auto minimum = -(std::int64_t{1} << 13U);
            constexpr auto maximum = (std::int64_t{1} << 13U) - 1;
            if (displacement < minimum || displacement > maximum) {
                throw std::runtime_error("ARM64 test-branch target is out of range");
            }
            words_[fixup.wordIndex] |= (static_cast<std::uint32_t>(displacement) & 0x3FFFU) << 5U;
        }
    }

    if (words_.size() > std::numeric_limits<std::size_t>::max() / sizeof(std::uint32_t)) {
        throw std::overflow_error("ARM64 program byte size overflows");
    }
    Program program;
    program.bytes.reserve(words_.size() * sizeof(std::uint32_t));
    for (const auto word : words_) {
        program.bytes.push_back(static_cast<std::uint8_t>(word & 0xFFU));
        program.bytes.push_back(static_cast<std::uint8_t>((word >> 8U) & 0xFFU));
        program.bytes.push_back(static_cast<std::uint8_t>((word >> 16U) & 0xFFU));
        program.bytes.push_back(static_cast<std::uint8_t>((word >> 24U) & 0xFFU));
    }
    program.listing = std::move(listing_);
    program.pointerRelocations = std::move(pointerRelocations_);
    return program;
}

} // namespace rosa::arm64
