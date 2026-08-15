#include "arm64/Assembler.h"

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
    listing_.push_back(std::move(text));
}

void Assembler::mov(XRegister destination, XRegister source) {
    requireRegister(destination);
    requireRegister(source);
    const auto word = 0xAA0003E0U | (static_cast<std::uint32_t>(source.encoding) << 16U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, "mov " + regName(destination) + ", " + regName(source));
}

void Assembler::movImmediate(XRegister destination, std::uint64_t value) {
    requireRegister(destination);

    bool emittedFirst = false;
    for (std::uint32_t halfword = 0; halfword < 4; ++halfword) {
        const auto shift = halfword * 16U;
        const auto immediate = static_cast<std::uint16_t>((value >> shift) & 0xFFFFU);
        if (immediate == 0 && (emittedFirst || value != 0)) {
            continue;
        }

        const auto base = emittedFirst ? 0xF2800000U : 0xD2800000U;
        const auto word = base | (halfword << 21U) | (static_cast<std::uint32_t>(immediate) << 5U) |
                          static_cast<std::uint32_t>(destination.encoding);
        auto text = std::string(emittedFirst ? "movk " : "movz ") + regName(destination) + ", " +
                    hexImmediate(immediate);
        if (shift != 0) {
            text += ", lsl #" + std::to_string(shift);
        }
        emit(word, std::move(text));
        emittedFirst = true;
    }
}

void Assembler::add(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x8B000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, "add " + regName(destination) + ", " + regName(lhs) + ", " + regName(rhs));
}

void Assembler::sub(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0xCB000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, "sub " + regName(destination) + ", " + regName(lhs) + ", " + regName(rhs));
}

void Assembler::bitAnd(XRegister destination, XRegister lhs, XRegister rhs) {
    requireRegister(destination);
    requireRegister(lhs);
    requireRegister(rhs);
    const auto word = 0x8A000000U | (static_cast<std::uint32_t>(rhs.encoding) << 16U) |
                      (static_cast<std::uint32_t>(lhs.encoding) << 5U) |
                      static_cast<std::uint32_t>(destination.encoding);
    emit(word, "and " + regName(destination) + ", " + regName(lhs) + ", " + regName(rhs));
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
    emit(word, "ldr " + regName(destination) + ", [" + regName(base) + ", #" +
                   std::to_string(byteOffset) + "]");
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
    emit(word, "str " + regName(source) + ", [" + regName(base) + ", #" +
                   std::to_string(byteOffset) + "]");
}

void Assembler::blr(XRegister target) {
    requireRegister(target);
    emit(0xD63F0000U | (static_cast<std::uint32_t>(target.encoding) << 5U),
         "blr " + regName(target));
}

Label Assembler::makeLabel() {
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
    const auto index = words_.size();
    emit(0x14000000U, "b L" + std::to_string(label.id));
    fixups_.push_back(Fixup{FixupKind::Branch26, index, label});
}

void Assembler::tbz(XRegister value, std::uint8_t bit, Label label) {
    requireRegister(value);
    if (bit >= 64U || label.id >= labelPositions_.size()) {
        throw std::invalid_argument("invalid TBZ operand or label");
    }
    const auto index = words_.size();
    const auto word = 0x36000000U | (static_cast<std::uint32_t>(bit >> 5U) << 31U) |
                      (static_cast<std::uint32_t>(bit & 0x1FU) << 19U) |
                      static_cast<std::uint32_t>(value.encoding);
    emit(word,
         "tbz " + regName(value) + ", #" + std::to_string(bit) + ", L" + std::to_string(label.id));
    fixups_.push_back(Fixup{FixupKind::TestBranch14, index, label});
}

void Assembler::tbnz(XRegister value, std::uint8_t bit, Label label) {
    requireRegister(value);
    if (bit >= 64U || label.id >= labelPositions_.size()) {
        throw std::invalid_argument("invalid TBNZ operand or label");
    }
    const auto index = words_.size();
    const auto word = 0x37000000U | (static_cast<std::uint32_t>(bit >> 5U) << 31U) |
                      (static_cast<std::uint32_t>(bit & 0x1FU) << 19U) |
                      static_cast<std::uint32_t>(value.encoding);
    emit(word,
         "tbnz " + regName(value) + ", #" + std::to_string(bit) + ", L" + std::to_string(label.id));
    fixups_.push_back(Fixup{FixupKind::TestBranch14, index, label});
}

void Assembler::pushFrameRecord() { emit(0xA9BF7BFDU, "stp x29, x30, [sp, #-16]!"); }

void Assembler::popFrameRecord() { emit(0xA8C17BFDU, "ldp x29, x30, [sp], #16"); }

void Assembler::ret() { emit(0xD65F03C0U, "ret"); }

Program Assembler::finish() && {
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
        } else {
            constexpr auto minimum = -(std::int64_t{1} << 13U);
            constexpr auto maximum = (std::int64_t{1} << 13U) - 1;
            if (displacement < minimum || displacement > maximum) {
                throw std::runtime_error("ARM64 test-branch target is out of range");
            }
            words_[fixup.wordIndex] |= (static_cast<std::uint32_t>(displacement) & 0x3FFFU) << 5U;
        }
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
    return program;
}

} // namespace rosa::arm64
