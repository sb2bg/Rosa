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

void Assembler::emitFixup(std::uint32_t word, std::string text,
                          FixupKind kind, Label label) {
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
    emit(word, recordListing_
                   ? "mov " + regName(destination) + ", " + regName(source)
                   : std::string{});
}

void Assembler::movImmediate(XRegister destination, std::uint64_t value) {
    requireRegister(destination);

    std::array<std::uint16_t, 4> halfwords{};
    std::size_t nonzeroCount = 0;
    std::size_t nonOnesCount = 0;
    for (std::uint32_t halfword = 0; halfword < halfwords.size(); ++halfword) {
        const auto shift = halfword * 16U;
        halfwords[halfword] =
            static_cast<std::uint16_t>((value >> shift) & 0xFFFFU);
        nonzeroCount += halfwords[halfword] != 0 ? 1U : 0U;
        nonOnesCount += halfwords[halfword] != UINT16_MAX ? 1U : 0U;
    }
    const auto useMovn = nonOnesCount < nonzeroCount;
    bool emittedFirst = false;
    for (std::uint32_t halfword = 0; halfword < halfwords.size(); ++halfword) {
        const auto shift = halfword * 16U;
        const auto desired = halfwords[halfword];
        const auto fill = useMovn ? UINT16_MAX : 0U;
        if (desired == fill &&
            (emittedFirst || (useMovn ? value != UINT64_MAX : value != 0))) {
            continue;
        }

        const auto immediate =
            static_cast<std::uint16_t>(useMovn && !emittedFirst
                                           ? static_cast<std::uint16_t>(~desired)
                                           : desired);
        const auto base = emittedFirst
                              ? 0xF2800000U
                              : useMovn ? 0x92800000U : 0xD2800000U;
        const auto word = base | (halfword << 21U) | (static_cast<std::uint32_t>(immediate) << 5U) |
                          static_cast<std::uint32_t>(destination.encoding);
        std::string text;
        if (recordListing_) {
            text = std::string(emittedFirst ? "movk "
                                            : useMovn ? "movn " : "movz ") +
                   regName(destination) + ", " + hexImmediate(immediate);
            if (shift != 0) {
                text += ", lsl #" + std::to_string(shift);
            }
        }
        emit(word, std::move(text));
        emittedFirst = true;
    }
}

void Assembler::movImmediate(XRegister destination,
                             RelocatablePointer pointer) {
    requireRegister(destination);
    if (words_.size() >
        std::numeric_limits<std::uint32_t>::max() / sizeof(std::uint32_t)) {
        throw std::overflow_error("ARM64 pointer relocation offset overflows");
    }
    const auto firstWord = words_.size();
    const auto firstListing = listing_.size();
    try {
        for (std::uint32_t halfword = 0; halfword < 4; ++halfword) {
            const auto shift = halfword * 16U;
            const auto immediate = static_cast<std::uint16_t>(
                (pointer.value >> shift) & UINT64_C(0xFFFF));
            const auto base = halfword == 0 ? 0xD2800000U : 0xF2800000U;
            const auto word =
                base | (halfword << 21U) |
                (static_cast<std::uint32_t>(immediate) << 5U) |
                static_cast<std::uint32_t>(destination.encoding);
            std::string text;
            if (recordListing_) {
                text = std::string(halfword == 0 ? "movz " : "movk ") +
                       regName(destination) + ", " + hexImmediate(immediate);
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
                   ? "add " + regName(destination) + ", " + regName(lhs) +
                         ", " + regName(rhs)
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
                   ? "sub " + regName(destination) + ", " + regName(lhs) +
                         ", " + regName(rhs)
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
    emit(word, recordListing_
                   ? "lsl " + regName(destination) + ", " + regName(source) +
                         ", #" + std::to_string(shift)
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
    emit(word, recordListing_
                   ? "lsr " + regName(destination) + ", " + regName(source) +
                         ", #" + std::to_string(shift)
                   : std::string{});
}

void Assembler::asrImmediate(XRegister destination, XRegister source,
                             std::uint8_t shift) {
    requireRegister(destination);
    requireRegister(source);
    if (shift >= 64U) {
        throw std::invalid_argument("64-bit ASR immediate must be less than 64");
    }
    if (shift == 0) {
        mov(destination, source);
        return;
    }
    const auto word =
        0x9340FC00U | (static_cast<std::uint32_t>(shift) << 16U) |
        (static_cast<std::uint32_t>(source.encoding) << 5U) |
        static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "asr " + regName(destination) + ", " + regName(source) +
                         ", #" + std::to_string(shift)
                   : std::string{});
}

void Assembler::reverseBytes32(XRegister destination, XRegister source) {
    requireRegister(destination);
    requireRegister(source);
    const auto word = 0x5AC00800U |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "rev w" + std::to_string(destination.encoding) + ", w" +
                         std::to_string(source.encoding)
                   : std::string{});
}

void Assembler::reverseBytes64(XRegister destination, XRegister source) {
    requireRegister(destination);
    requireRegister(source);
    const auto word = 0xDAC00C00U |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "rev " + regName(destination) + ", " + regName(source)
                   : std::string{});
}

void Assembler::signExtend32(XRegister destination, XRegister source) {
    requireRegister(destination);
    requireRegister(source);
    const auto word = 0x93407C00U |
                      (static_cast<std::uint32_t>(source.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "sxtw " + regName(destination) + ", w" +
                         std::to_string(source.encoding)
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
                   ? "lsl " + regName(destination) + ", " + regName(source) +
                         ", " + regName(shift)
                   : std::string{});
}

void Assembler::lsrVariable(XRegister destination, XRegister source,
                            XRegister shift) {
    requireRegister(destination);
    requireRegister(source);
    requireRegister(shift);
    const auto word =
        0x9AC02400U |
        (static_cast<std::uint32_t>(shift.encoding) << 16U) |
        (static_cast<std::uint32_t>(source.encoding) << 5U) |
        static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "lsr " + regName(destination) + ", " + regName(source) +
                         ", " + regName(shift)
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
                   ? "mul " + regName(destination) + ", " + regName(lhs) +
                         ", " + regName(rhs)
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
                   ? "umulh " + regName(destination) + ", " + regName(lhs) +
                         ", " + regName(rhs)
                   : std::string{});
}

void Assembler::extract(XRegister destination, XRegister high, XRegister low,
                        std::uint8_t lsb) {
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
    emit(word, recordListing_
                   ? "extr " + regName(destination) + ", " + regName(high) +
                         ", " + regName(low) + ", #" + std::to_string(lsb)
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
                   ? "and " + regName(destination) + ", " + regName(lhs) +
                         ", " + regName(rhs)
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
                   ? "orr " + regName(destination) + ", " + regName(lhs) +
                         ", " + regName(rhs)
                   : std::string{});
}

void Assembler::bitOrShiftedLeft(XRegister destination, XRegister lhs,
                                 XRegister rhs, std::uint8_t shift) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    if (shift >= 64U) {
        throw std::invalid_argument("64-bit ORR shift must be less than 64");
    }
    const auto word = 0xAA000000U |
                      (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(shift) << 10U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "orr " + regName(destination) + ", " + regName(lhs) +
                         ", " + regName(rhs) + ", lsl #" +
                         std::to_string(shift)
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
                   ? "eor " + regName(destination) + ", " + regName(lhs) +
                         ", " + regName(rhs)
                   : std::string{});
}

void Assembler::bitXorShiftedRight(XRegister destination, XRegister lhs,
                                   XRegister rhs, std::uint8_t shift) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    if (shift >= 64U) {
        throw std::invalid_argument("64-bit EOR shift must be less than 64");
    }
    const auto word = 0xCA400000U |
                      (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(shift) << 10U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "eor " + regName(destination) + ", " + regName(lhs) +
                         ", " + regName(rhs) + ", lsr #" +
                         std::to_string(shift)
                   : std::string{});
}

void Assembler::compare(XRegister lhs, XRegister rhs) {
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0xEB00001FU |
                      (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U);
    emit(word, recordListing_
                   ? "cmp " + regName(lhs) + ", " + regName(rhs)
                   : std::string{});
}

void Assembler::conditionalSelectEqual(XRegister destination,
                                       XRegister ifEqual,
                                       XRegister ifNotEqual) {
    requireRegister(destination);
    requireRegister(ifEqual);
    requireRegister(ifNotEqual);
    const auto word = 0x9A800000U |
                      (static_cast<std::uint32_t>(ifNotEqual.encoding) << 16U) |
                      (static_cast<std::uint32_t>(ifEqual.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, recordListing_
                   ? "csel " + regName(destination) + ", " +
                         regName(ifEqual) + ", " + regName(ifNotEqual) +
                         ", eq"
                   : std::string{});
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
    emit(word, recordListing_
                   ? "ldr " + regName(destination) + ", [" + regName(base) +
                         ", #" + std::to_string(byteOffset) + "]"
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
    emit(word, recordListing_
                   ? "ldr w" + std::to_string(destination.encoding) + ", [" +
                         regName(base) + ", #" + std::to_string(byteOffset) +
                         "]"
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
    emit(word, recordListing_
                   ? "str " + regName(source) + ", [" + regName(base) +
                         ", #" + std::to_string(byteOffset) + "]"
                   : std::string{});
}

void Assembler::blr(XRegister target) {
    requireRegister(target);
    emit(0xD63F0000U | (static_cast<std::uint32_t>(target.encoding) << 5U),
         recordListing_ ? "blr " + regName(target) : std::string{});
}

Label Assembler::makeLabel() {
    if (labelPositions_.size() >
        std::numeric_limits<std::uint32_t>::max()) {
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
    emitFixup(0x14000000U,
              recordListing_ ? "b L" + std::to_string(label.id)
                             : std::string{},
              FixupKind::Branch26, label);
}

void Assembler::cbz(XRegister value, Label label) {
    requireRegister(value);
    if (label.id >= labelPositions_.size()) {
        throw std::invalid_argument("cannot compare-branch to an unknown ARM64 label");
    }
    const auto word = 0xB4000000U | static_cast<std::uint32_t>(value.encoding);
    emitFixup(word,
              recordListing_ ? "cbz " + regName(value) + ", L" +
                                   std::to_string(label.id)
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
              recordListing_ ? "cbnz " + regName(value) + ", L" +
                                   std::to_string(label.id)
                             : std::string{},
              FixupKind::CompareBranch19, label);
}

void Assembler::tbz(XRegister value, std::uint8_t bit, Label label) {
    requireRegister(value);
    if (bit >= 64U || label.id >= labelPositions_.size()) {
        throw std::invalid_argument("invalid TBZ operand or label");
    }
    const auto word = 0x36000000U | (static_cast<std::uint32_t>(bit >> 5U) << 31U) |
                      (static_cast<std::uint32_t>(bit & 0x1FU) << 19U) |
                      static_cast<std::uint32_t>(value.encoding);
    emitFixup(word, recordListing_
                        ? "tbz " + regName(value) + ", #" +
                              std::to_string(bit) + ", L" +
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
    emitFixup(word, recordListing_
                        ? "tbnz " + regName(value) + ", #" +
                              std::to_string(bit) + ", L" +
                              std::to_string(label.id)
                        : std::string{},
              FixupKind::TestBranch14, label);
}

void Assembler::pushFrameRecord() { emit(0xA9BF7BFDU, "stp x29, x30, [sp, #-16]!"); }

void Assembler::popFrameRecord() { emit(0xA8C17BFDU, "ldp x29, x30, [sp], #16"); }

void Assembler::pushCalleeSaved19And20() {
    emit(0xA9BF53F3U, "stp x19, x20, [sp, #-16]!");
}

void Assembler::popCalleeSaved19And20() {
    emit(0xA8C153F3U, "ldp x19, x20, [sp], #16");
}

void Assembler::dmbIsh() { emit(0xD5033BBFU, "dmb ish"); }

void Assembler::isb() { emit(0xD5033FDFU, "isb"); }

void Assembler::ret() { emit(0xD65F03C0U, "ret"); }

Program Assembler::finish() && {
    if (words_.size() >
        static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max())) {
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
            words_[fixup.wordIndex] |=
                (static_cast<std::uint32_t>(displacement) & 0x7FFFFU) << 5U;
        } else {
            constexpr auto minimum = -(std::int64_t{1} << 13U);
            constexpr auto maximum = (std::int64_t{1} << 13U) - 1;
            if (displacement < minimum || displacement > maximum) {
                throw std::runtime_error("ARM64 test-branch target is out of range");
            }
            words_[fixup.wordIndex] |= (static_cast<std::uint32_t>(displacement) & 0x3FFFU) << 5U;
        }
    }

    if (words_.size() >
        std::numeric_limits<std::size_t>::max() / sizeof(std::uint32_t)) {
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
