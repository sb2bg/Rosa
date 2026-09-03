#include "ir/IR.h"

#include <array>
#include <utility>

namespace rosa::ir {

ValueId Builder::nextValue() { return ValueId{block_.valueCount++}; }

ValueId Builder::constant(std::uint64_t value, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::Constant,
        .width = width,
        .guestRip = rip,
        .result = result,
        .immediate = value,
    });
    return result;
}

ValueId Builder::readGuestRegister(x86::Register reg, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ReadGuestReg,
        .width = width,
        .guestRip = rip,
        .result = result,
        .guestRegister = reg,
    });
    return result;
}

ValueId Builder::readGuestGsBase(guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ReadGuestGsBase,
        .width = Width::I64,
        .guestRip = rip,
        .result = result,
    });
    return result;
}

void Builder::writeGuestRegister(x86::Register reg, ValueId value, Width width,
                                 guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::WriteGuestReg,
        .width = width,
        .guestRip = rip,
        .lhs = value,
        .guestRegister = reg,
    });
}

void Builder::conditionalMoveGuestRegister(x86::Register destination,
                                           x86::Register source,
                                           x86::Condition condition, Width width,
                                           guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ConditionalMoveGuestReg,
        .width = width,
        .guestRip = rip,
        .guestRegister = destination,
        .condition = condition,
        .immediate = static_cast<std::uint64_t>(source),
    });
}

void Builder::conditionalMoveGuestRegister(x86::Register destination,
                                           ValueId source,
                                           x86::Condition condition, Width width,
                                           guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ConditionalMoveGuestReg,
        .width = width,
        .guestRip = rip,
        .lhs = source,
        .guestRegister = destination,
        .condition = condition,
    });
}

ValueId Builder::readGuestXmmLane(x86::XmmRegister reg, bool high,
                                  guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ReadGuestXmmLane,
        .width = Width::I64,
        .guestRip = rip,
        .result = result,
        .guestXmmRegister = reg,
        .immediate = high ? 1U : 0U,
    });
    return result;
}

ValueId Builder::readGuestYmmUpperLane(x86::XmmRegister reg, bool high,
                                       guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ReadGuestYmmUpperLane,
        .width = Width::I64,
        .guestRip = rip,
        .result = result,
        .guestXmmRegister = reg,
        .immediate = high ? 1U : 0U,
    });
    return result;
}

void Builder::writeGuestXmmLane(x86::XmmRegister reg, bool high, ValueId value,
                                guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::WriteGuestXmmLane,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = value,
        .guestXmmRegister = reg,
        .immediate = high ? 1U : 0U,
    });
}

void Builder::writeGuestYmmUpperLane(x86::XmmRegister reg, bool high,
                                     ValueId value, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::WriteGuestYmmUpperLane,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = value,
        .guestXmmRegister = reg,
        .immediate = high ? 1U : 0U,
    });
}

void Builder::writeGuestXmmByte(x86::XmmRegister reg, std::uint8_t lane,
                                ValueId value, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::WriteGuestXmmByte,
        .width = Width::I8,
        .guestRip = rip,
        .lhs = value,
        .guestXmmRegister = reg,
        .immediate = lane,
    });
}

void Builder::writeGuestXmmDword(x86::XmmRegister reg, std::uint8_t lane,
                                 ValueId value, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::WriteGuestXmmDword,
        .width = Width::I32,
        .guestRip = rip,
        .lhs = value,
        .guestXmmRegister = reg,
        .immediate = lane,
    });
}

ValueId Builder::add(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::Add,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::sub(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::Sub,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::shiftLeft(ValueId value, std::uint8_t count, Width width,
                           guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftLeft,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = value,
        .immediate = count,
    });
    return result;
}

ValueId Builder::shiftLeft(ValueId value, ValueId count, Width width,
                           guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftLeft,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = value,
        .rhs = count,
    });
    return result;
}

ValueId Builder::shiftRightLogical(ValueId value, std::uint8_t count, Width width,
                                   guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftRightLogical,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = value,
        .immediate = count,
    });
    return result;
}

ValueId Builder::shiftRightLogical(ValueId value, ValueId count, Width width,
                                   guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftRightLogical,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = value,
        .rhs = count,
    });
    return result;
}

ValueId Builder::shiftRightArithmetic(ValueId value, std::uint8_t count,
                                      Width width,
                                      guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftRightArithmetic,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = value,
        .immediate = count,
    });
    return result;
}

ValueId Builder::shiftRightArithmetic(ValueId value, ValueId count,
                                      Width width,
                                      guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftRightArithmetic,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = value,
        .rhs = count,
    });
    return result;
}

ValueId Builder::multiplyLow(ValueId lhs, ValueId rhs, Width width,
                             guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::MultiplyLow,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::multiplyHighUnsigned(ValueId lhs, ValueId rhs, Width width,
                                      guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::MultiplyHighUnsigned,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::multiplyHighSigned(ValueId lhs, ValueId rhs, Width width,
                                    guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::MultiplyHighSigned,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::shiftRightDouble(ValueId low, ValueId high, std::uint8_t count,
                                  Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftRightDouble,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = low,
        .rhs = high,
        .immediate = count,
    });
    return result;
}

ValueId Builder::bitAnd(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::And,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::bitOr(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::Or,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::bitXor(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::Xor,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = lhs,
        .rhs = rhs,
    });
    return result;
}

ValueId Builder::byteSwap(ValueId value, Width width,
                          guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::ByteSwap,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = value,
    });
    return result;
}

ValueId Builder::signExtend32(ValueId value, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::SignExtend32,
        .width = Width::I64,
        .guestRip = rip,
        .result = result,
        .lhs = value,
    });
    return result;
}

ValueId Builder::evaluateCondition(x86::Condition condition,
                                   guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::EvaluateCondition,
        .width = Width::I8,
        .guestRip = rip,
        .result = result,
        .condition = condition,
    });
    return result;
}

ValueId Builder::loadGuest(ValueId address, Width width, guest::GuestAddress rip) {
    const auto result = nextValue();
    block_.operations.push_back(Operation{
        .opcode = Opcode::LoadGuest,
        .width = width,
        .guestRip = rip,
        .result = result,
        .lhs = address,
    });
    return result;
}

void Builder::storeGuest(ValueId address, ValueId value, Width width,
                         guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::StoreGuest,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = value,
    });
}

void Builder::storeGuestXmm(ValueId address, x86::XmmRegister reg, bool aligned,
                            guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::StoreGuestXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
        .immediate = aligned ? 1U : 0U,
    });
}

void Builder::storeGuestYmm(ValueId address, x86::XmmRegister reg,
                            bool aligned, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::StoreGuestYmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
        .immediate = aligned ? 1U : 0U,
    });
}

void Builder::loadGuestXmm(ValueId address, x86::XmmRegister reg, bool aligned,
                           guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LoadGuestXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
        .immediate = aligned ? 1U : 0U,
    });
}

void Builder::loadGuestYmm(ValueId address, x86::XmmRegister reg, bool aligned,
                           guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LoadGuestYmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
        .immediate = aligned ? 1U : 0U,
    });
}

void Builder::loadGuestSignExtendedBytesXmm(
    ValueId address, x86::XmmRegister reg, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LoadGuestSignExtendedBytesXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
    });
}

void Builder::loadGuestSignExtendedDwordsXmm(
    ValueId address, x86::XmmRegister reg, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LoadGuestSignExtendedDwordsXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
    });
}

void Builder::xorGuestMemoryXmm(ValueId address, x86::XmmRegister reg,
                                guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::XorGuestMemoryXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
    });
}

void Builder::andGuestMemoryXmm(ValueId address, x86::XmmRegister reg,
                                guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::AndGuestMemoryXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
    });
}

void Builder::addGuestMemoryXmm(ValueId address, x86::XmmRegister reg,
                                guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::AddGuestMemoryXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
    });
}

void Builder::testXmmBits(x86::XmmRegister destination,
                          x86::XmmRegister source,
                          guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::TestXmmBits,
        .width = Width::I64,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
    });
}

void Builder::compareEqualGuestBytesXmm(ValueId address, x86::XmmRegister reg,
                                        guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::CompareEqualGuestBytesXmm,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = reg,
    });
}

void Builder::compareEqualXmmBytes(x86::XmmRegister destination,
                                   x86::XmmRegister source,
                                   guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::CompareEqualXmmBytes,
        .width = Width::I64,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
    });
}

void Builder::compareEqualXmmDwords(x86::XmmRegister destination,
                                    x86::XmmRegister source,
                                    guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::CompareEqualXmmDwords,
        .width = Width::I32,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
    });
}

void Builder::shiftLeftXmmDwords(x86::XmmRegister destination,
                                 std::uint8_t count,
                                 guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftLeftXmmDwords,
        .width = Width::I32,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .immediate = count,
    });
}

void Builder::addXmmDwords(x86::XmmRegister destination,
                           x86::XmmRegister source,
                           guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::AddXmmDwords,
        .width = Width::I32,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
    });
}

void Builder::horizontalAddXmmDwords(x86::XmmRegister destination,
                                     x86::XmmRegister source,
                                     guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::HorizontalAddXmmDwords,
        .width = Width::I32,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
    });
}

void Builder::andNotXmm(x86::XmmRegister destination,
                        x86::XmmRegister source, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::AndNotXmm,
        .width = Width::I64,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
    });
}

void Builder::moveXmmByteMask(x86::Register destination, x86::XmmRegister source,
                              guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::MoveXmmByteMask,
        .width = Width::I32,
        .guestRip = rip,
        .guestRegister = destination,
        .guestXmmRegister = source,
    });
}

void Builder::shuffleXmmBytes(x86::XmmRegister destination,
                              x86::XmmRegister source,
                              guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShuffleXmmBytes,
        .width = Width::I8,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
    });
}

void Builder::shuffleGuestMemoryXmmBytes(ValueId address,
                                         x86::XmmRegister destination,
                                         guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShuffleXmmBytes,
        .width = Width::I8,
        .guestRip = rip,
        .lhs = address,
        .guestXmmRegister = destination,
    });
}

void Builder::shuffleXmmDwords(x86::XmmRegister destination,
                               x86::XmmRegister source,
                               std::uint8_t control,
                               guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShuffleXmmDwords,
        .width = Width::I32,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
        .immediate = control,
    });
}

void Builder::alignRightXmmBytes(x86::XmmRegister destination,
                                 x86::XmmRegister source,
                                 std::uint8_t count,
                                 guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::AlignRightXmmBytes,
        .width = Width::I8,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
        .immediate = count,
    });
}

void Builder::blendXmmWords(x86::XmmRegister destination,
                            x86::XmmRegister source, std::uint8_t mask,
                            guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::BlendXmmWords,
        .width = Width::I16,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
        .immediate = mask,
    });
}

void Builder::unpackLowXmmWords(x86::XmmRegister destination,
                                x86::XmmRegister source,
                                guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UnpackLowXmmWords,
        .width = Width::I16,
        .guestRip = rip,
        .guestXmmRegister = destination,
        .sourceGuestXmmRegister = source,
    });
}

void Builder::bitScanForward(x86::Register destination, x86::Register source,
                             Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::BitScanForward,
        .width = width,
        .guestRip = rip,
        .guestRegister = destination,
        .immediate = static_cast<std::uint64_t>(source),
    });
}

void Builder::bitScanReverse(x86::Register destination, x86::Register source,
                             Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::BitScanReverse,
        .width = width,
        .guestRip = rip,
        .guestRegister = destination,
        .immediate = static_cast<std::uint64_t>(source),
    });
}

void Builder::repeatMoveByte(guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::RepeatMoveByte,
        .width = Width::I8,
        .guestRip = rip,
    });
}

void Builder::divideUnsignedByte(ValueId divisor, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::DivideUnsignedByte,
        .width = Width::I8,
        .guestRip = rip,
        .lhs = divisor,
    });
}

void Builder::divideUnsignedDword(ValueId divisor,
                                  guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::DivideUnsignedDword,
        .width = Width::I32,
        .guestRip = rip,
        .lhs = divisor,
    });
}

void Builder::divideUnsignedQword(ValueId divisor,
                                  guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::DivideUnsignedQword,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = divisor,
    });
}

void Builder::divideSignedDword(ValueId divisor,
                                guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::DivideSignedDword,
        .width = Width::I32,
        .guestRip = rip,
        .lhs = divisor,
    });
}

void Builder::push(ValueId newStackPointer, ValueId value, Width width,
                   guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::Push,
        .width = width,
        .guestRip = rip,
        .lhs = newStackPointer,
        .rhs = value,
    });
}

void Builder::addGuestMemory(ValueId address, ValueId source, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::AddGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
    });
}

void Builder::subGuestMemory(ValueId address, ValueId source, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::SubGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
    });
}

void Builder::orGuestMemory(ValueId address, ValueId source, Width width,
                            guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::OrGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
    });
}

void Builder::andGuestMemory(ValueId address, ValueId source, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::AndGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
    });
}

void Builder::shiftLeftGuestMemory(ValueId address, std::uint8_t count,
                                   Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftLeftGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .immediate = count,
    });
}

void Builder::shiftRightLogicalGuestMemory(ValueId address, std::uint8_t count,
                                           Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ShiftRightGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .immediate = count,
    });
}

void Builder::incrementGuestMemory(ValueId address, Width width,
                                   guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::IncrementGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
    });
}

void Builder::decrementGuestMemory(ValueId address, Width width,
                                   guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::DecrementGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
    });
}

void Builder::compareExchangeGuestMemory(ValueId address, ValueId source,
                                         Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::CompareExchangeGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
    });
}

void Builder::compareExchangeGuestPair(ValueId address,
                                       guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::CompareExchangeGuestPair,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = address,
    });
}

void Builder::exchangeGuestMemory(ValueId address, ValueId source,
                                  x86::Register destination, Width width,
                                  guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExchangeGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
        .guestRegister = destination,
    });
}

void Builder::lockedAddGuestMemory(ValueId address, ValueId source,
                                   Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LockedAddGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
    });
}

void Builder::lockedExchangeAddGuestMemory(
    ValueId address, ValueId source, x86::Register sourceRegister,
    Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LockedExchangeAddGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = source,
        .guestRegister = sourceRegister,
    });
}

void Builder::lockedIncrementGuestMemory(ValueId address, Width width,
                                         guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LockedIncrementGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
    });
}

void Builder::lockedDecrementGuestMemory(ValueId address, Width width,
                                         guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LockedDecrementGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
    });
}

void Builder::lockedOrGuestMemory(ValueId address, ValueId immediate,
                                  Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LockedOrGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = immediate,
    });
}

void Builder::lockedAndGuestMemory(ValueId address, ValueId immediate,
                                   Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LockedAndGuestMemory,
        .width = width,
        .guestRip = rip,
        .lhs = address,
        .rhs = immediate,
    });
}

void Builder::storeGuestIdtr(ValueId address, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::StoreGuestIdtr,
        .guestRip = rip,
        .lhs = address,
    });
}

void Builder::loadFence(guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::LoadFence,
        .width = Width::I64,
        .guestRip = rip,
    });
}

void Builder::storeFence(guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::StoreFence,
        .width = Width::I64,
        .guestRip = rip,
    });
}

void Builder::readTimestampCounter(guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ReadTimestampCounter,
        .width = Width::I64,
        .guestRip = rip,
    });
}

void Builder::updateAddFlags(ValueId lhs, ValueId rhs, ValueId result, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateAddFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = rhs,
        .third = result,
    });
}

void Builder::updateAdcFlags(ValueId lhs, ValueId rhs, ValueId carry,
                             Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateAdcFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = rhs,
        .third = carry,
    });
}

void Builder::updateSbbFlags(ValueId lhs, ValueId rhs, ValueId borrow,
                             Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateSbbFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = rhs,
        .third = borrow,
    });
}

void Builder::updateIncFlags(ValueId original, ValueId result, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateIncFlags,
        .width = width,
        .guestRip = rip,
        .lhs = original,
        .rhs = result,
    });
}

void Builder::updateDecFlags(ValueId original, ValueId result, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateDecFlags,
        .width = width,
        .guestRip = rip,
        .lhs = original,
        .rhs = result,
    });
}

void Builder::updateSubFlags(ValueId lhs, ValueId rhs, ValueId result, Width width,
                             guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateSubFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = rhs,
        .third = result,
    });
}

void Builder::updateLogicFlags(ValueId result, Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateLogicFlags,
        .width = width,
        .guestRip = rip,
        .lhs = result,
    });
}

void Builder::updateShiftLeftFlags(ValueId lhs, ValueId result, std::uint8_t count,
                                   Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftLeftFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = result,
        .immediate = count,
    });
}

void Builder::updateShiftLeftFlags(ValueId lhs, ValueId result, ValueId count,
                                   Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftLeftFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = result,
        .third = count,
    });
}

void Builder::updateShiftRightFlags(ValueId lhs, ValueId result, std::uint8_t count,
                                    Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftRightFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = result,
        .immediate = count,
    });
}

void Builder::updateShiftRightFlags(ValueId lhs, ValueId result, ValueId count,
                                    Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftRightFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = result,
        .third = count,
    });
}

void Builder::updateShiftRightArithmeticFlags(ValueId lhs, ValueId result,
                                              std::uint8_t count, Width width,
                                              guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftRightArithmeticFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = result,
        .immediate = count,
    });
}

void Builder::updateShiftRightArithmeticFlags(ValueId lhs, ValueId result, ValueId count,
                                              Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftRightArithmeticFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = result,
        .third = count,
    });
}

void Builder::updateRotateLeftFlags(ValueId result, std::uint8_t count,
                                    Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateRotateLeftFlags,
        .width = width,
        .guestRip = rip,
        .lhs = result,
        .immediate = count,
    });
}

void Builder::updateRotateLeftFlags(ValueId result, ValueId count,
                                    Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateRotateLeftFlags,
        .width = width,
        .guestRip = rip,
        .lhs = result,
        .rhs = count,
    });
}

void Builder::updateRotateRightFlags(ValueId result, std::uint8_t count,
                                     Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateRotateRightFlags,
        .width = width,
        .guestRip = rip,
        .lhs = result,
        .immediate = count,
    });
}

void Builder::updateMultiplyFlags(ValueId high, Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateMultiplyFlags,
        .width = width,
        .guestRip = rip,
        .lhs = high,
    });
}

void Builder::updateSignedMultiplyFlags(ValueId lhs, ValueId rhs, Width width,
                                        guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateSignedMultiplyFlags,
        .width = width,
        .guestRip = rip,
        .lhs = lhs,
        .rhs = rhs,
    });
}

void Builder::updateShiftRightDoubleFlags(ValueId original, ValueId result,
                                          std::uint8_t count, Width width,
                                          guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateShiftRightDoubleFlags,
        .width = width,
        .guestRip = rip,
        .lhs = original,
        .rhs = result,
        .immediate = count,
    });
}

void Builder::updateBitTestFlags(ValueId value, std::uint8_t bitIndex,
                                 Width width, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::UpdateBitTestFlags,
        .width = width,
        .guestRip = rip,
        .lhs = value,
        .immediate = bitIndex,
    });
}

void Builder::exitBlock(guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .exitKind = ExitKind::Return,
    });
}

void Builder::exitDirect(guest::GuestAddress target, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .target = target,
        .exitKind = ExitKind::Direct,
    });
}

void Builder::exitDirect(ValueId target, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = target,
        .exitKind = ExitKind::Direct,
    });
}

void Builder::exitConditional(x86::Condition condition, guest::GuestAddress target,
                              guest::GuestAddress fallthrough, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .target = target,
        .fallthrough = fallthrough,
        .condition = condition,
        .exitKind = ExitKind::Conditional,
    });
}

void Builder::exitCall(guest::GuestAddress target, guest::GuestAddress returnAddress,
                       guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .target = target,
        .fallthrough = returnAddress,
        .exitKind = ExitKind::Call,
    });
}

void Builder::exitCall(ValueId target, guest::GuestAddress returnAddress,
                       guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .lhs = target,
        .fallthrough = returnAddress,
        .exitKind = ExitKind::Call,
    });
}

void Builder::exitSyscall(guest::GuestAddress nextRip, guest::GuestAddress rip) {
    block_.operations.push_back(Operation{
        .opcode = Opcode::ExitBlock,
        .width = Width::I64,
        .guestRip = rip,
        .target = nextRip,
        .exitKind = ExitKind::Syscall,
    });
}

Block Builder::finish() && { return std::move(block_); }

std::vector<std::string> verify(const Block &block) {
    std::vector<std::string> errors;
    std::vector<bool> defined(block.valueCount, false);
    bool sawExit = false;

    const auto checkUse = [&](std::optional<ValueId> value, const char *role) {
        if (!value) {
            errors.emplace_back(std::string("missing ") + role + " value");
            return;
        }
        if (value->value >= defined.size() || !defined[value->value]) {
            errors.emplace_back(std::string("use of undefined ") + role + " value");
        }
    };

    for (const auto &operation : block.operations) {
        if (sawExit) {
            errors.emplace_back("operation follows exit_block");
        }
        switch (operation.opcode) {
        case Opcode::Constant:
        case Opcode::ReadGuestReg:
        case Opcode::ReadGuestGsBase:
            break;
        case Opcode::ReadGuestXmmLane:
            if (!operation.guestXmmRegister) {
                errors.emplace_back("read_guest_xmm_lane has no register");
            }
            break;
        case Opcode::ReadGuestYmmUpperLane:
            if (!operation.guestXmmRegister || operation.immediate > 1) {
                errors.emplace_back(
                    "read_guest_ymm_upper_lane is incomplete");
            }
            break;
        case Opcode::WriteGuestReg:
            checkUse(operation.lhs, "source");
            if (!operation.guestRegister) {
                errors.emplace_back("write_guest_reg has no register");
            }
            break;
        case Opcode::ConditionalMoveGuestReg:
            if (!operation.guestRegister || !operation.condition ||
                (!operation.lhs && operation.immediate >= 16)) {
                errors.emplace_back("conditional_move_guest_reg is incomplete");
            }
            if (operation.lhs) {
                checkUse(operation.lhs, "source");
            }
            break;
        case Opcode::WriteGuestXmmLane:
            checkUse(operation.lhs, "source");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("write_guest_xmm_lane has no register");
            }
            break;
        case Opcode::WriteGuestYmmUpperLane:
            checkUse(operation.lhs, "source");
            if (!operation.guestXmmRegister || operation.immediate > 1) {
                errors.emplace_back(
                    "write_guest_ymm_upper_lane is incomplete");
            }
            break;
        case Opcode::WriteGuestXmmByte:
            checkUse(operation.lhs, "source");
            if (!operation.guestXmmRegister || operation.width != Width::I8 ||
                operation.immediate >= 16) {
                errors.emplace_back("write_guest_xmm_byte is incomplete");
            }
            break;
        case Opcode::WriteGuestXmmDword:
            checkUse(operation.lhs, "source");
            if (!operation.guestXmmRegister || operation.width != Width::I32 ||
                operation.immediate >= 4) {
                errors.emplace_back("write_guest_xmm_dword is incomplete");
            }
            break;
        case Opcode::Add:
        case Opcode::Sub:
        case Opcode::And:
        case Opcode::Or:
        case Opcode::Xor:
        case Opcode::MultiplyLow:
        case Opcode::MultiplyHighUnsigned:
        case Opcode::MultiplyHighSigned:
        case Opcode::ShiftRightDouble:
            checkUse(operation.lhs, "left");
            checkUse(operation.rhs, "right");
            break;
        case Opcode::ShiftLeft:
            checkUse(operation.lhs, "shifted");
            if (operation.rhs) {
                checkUse(operation.rhs, "shift count");
            }
            break;
        case Opcode::ShiftRightLogical:
        case Opcode::ShiftRightArithmetic:
            checkUse(operation.lhs, "shifted");
            if (operation.rhs) {
                checkUse(operation.rhs, "shift count");
            }
            break;
        case Opcode::SignExtend32:
            checkUse(operation.lhs, "source");
            break;
        case Opcode::ByteSwap:
            checkUse(operation.lhs, "source");
            if (operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back("byte_swap currently requires i32 or i64");
            }
            break;
        case Opcode::EvaluateCondition:
            if (!operation.condition) {
                errors.emplace_back("evaluate_condition has no condition");
            }
            break;
        case Opcode::RepeatMoveByte:
            if (operation.width != Width::I8) {
                errors.emplace_back("repeat_move_byte requires i8");
            }
            break;
        case Opcode::Push:
            checkUse(operation.lhs, "new stack pointer");
            checkUse(operation.rhs, "pushed value");
            break;
        case Opcode::AddGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (operation.width != Width::I8 && operation.width != Width::I16 &&
                operation.width != Width::I32 && operation.width != Width::I64) {
                errors.emplace_back(
                    "add_guest_memory currently requires i8, i16, i32, or i64");
            }
            break;
        case Opcode::SubGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (operation.width != Width::I8 && operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "sub_guest_memory currently requires i8, i32, or i64");
            }
            break;
        case Opcode::OrGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (operation.width != Width::I8 && operation.width != Width::I16 &&
                operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "or_guest_memory currently requires i8, i16, i32, or i64");
            }
            break;
        case Opcode::AndGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (operation.width != Width::I8 &&
                operation.width != Width::I16 &&
                operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "and_guest_memory currently requires i8, i16, i32, or i64");
            }
            break;
        case Opcode::ShiftLeftGuestMemory:
            checkUse(operation.lhs, "guest address");
            if (operation.width != Width::I64) {
                errors.emplace_back(
                    "shift_left_guest_memory currently requires i64");
            }
            break;
        case Opcode::ShiftRightGuestMemory:
            checkUse(operation.lhs, "guest address");
            if (operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "shift_right_guest_memory currently requires i32 or i64");
            }
            break;
        case Opcode::IncrementGuestMemory:
        case Opcode::DecrementGuestMemory:
            checkUse(operation.lhs, "guest address");
            break;
        case Opcode::CompareExchangeGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "compare_exchange_guest_memory currently requires i32 or i64");
            }
            break;
        case Opcode::CompareExchangeGuestPair:
            checkUse(operation.lhs, "guest address");
            if (operation.width != Width::I64) {
                errors.emplace_back(
                    "compare_exchange_guest_pair requires i64 lanes");
            }
            break;
        case Opcode::ExchangeGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (!operation.guestRegister) {
                errors.emplace_back(
                    "exchange_guest_memory lacks a destination register");
            }
            if (operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "exchange_guest_memory currently requires i32 or i64");
            }
            break;
        case Opcode::LockedAddGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (operation.width != Width::I64) {
                errors.emplace_back(
                    "locked_add_guest_memory currently requires i64");
            }
            break;
        case Opcode::LockedExchangeAddGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "source");
            if (!operation.guestRegister) {
                errors.emplace_back(
                    "locked_exchange_add_guest_memory lacks a source register");
            }
            if (operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "locked_exchange_add_guest_memory currently requires i32 or i64");
            }
            break;
        case Opcode::LockedIncrementGuestMemory:
            checkUse(operation.lhs, "guest address");
            if (operation.width != Width::I32 && operation.width != Width::I64) {
                errors.emplace_back(
                    "locked_increment_guest_memory currently requires i32 or i64");
            }
            break;
        case Opcode::LockedDecrementGuestMemory:
            checkUse(operation.lhs, "guest address");
            if (operation.width != Width::I32 && operation.width != Width::I64) {
                errors.emplace_back(
                    "locked_decrement_guest_memory currently requires i32 or i64");
            }
            break;
        case Opcode::LockedOrGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "immediate");
            if (operation.width != Width::I16 &&
                operation.width != Width::I32) {
                errors.emplace_back(
                    "locked_or_guest_memory currently requires i16 or i32");
            }
            break;
        case Opcode::LockedAndGuestMemory:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "immediate");
            if (operation.width != Width::I16) {
                errors.emplace_back(
                    "locked_and_guest_memory currently requires i16");
            }
            break;
        case Opcode::StoreGuestIdtr:
            checkUse(operation.lhs, "guest address");
            break;
        case Opcode::StoreGuest:
            checkUse(operation.lhs, "guest address");
            checkUse(operation.rhs, "stored value");
            break;
        case Opcode::StoreGuestXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("store_guest_xmm has no register");
            }
            break;
        case Opcode::StoreGuestYmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("store_guest_ymm has no register");
            }
            break;
        case Opcode::LoadGuestXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("load_guest_xmm has no register");
            }
            break;
        case Opcode::LoadGuestYmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("load_guest_ymm has no register");
            }
            break;
        case Opcode::LoadGuestSignExtendedBytesXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back(
                    "load_guest_sign_extended_bytes_xmm has no register");
            }
            break;
        case Opcode::LoadGuestSignExtendedDwordsXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back(
                    "load_guest_sign_extended_dwords_xmm has no register");
            }
            break;
        case Opcode::XorGuestMemoryXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("xor_guest_memory_xmm has no register");
            }
            break;
        case Opcode::AndGuestMemoryXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("and_guest_memory_xmm has no register");
            }
            break;
        case Opcode::AddGuestMemoryXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("add_guest_memory_xmm has no register");
            }
            break;
        case Opcode::TestXmmBits:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister) {
                errors.emplace_back("test_xmm_bits has incomplete registers");
            }
            break;
        case Opcode::CompareEqualGuestBytesXmm:
            checkUse(operation.lhs, "guest address");
            if (!operation.guestXmmRegister) {
                errors.emplace_back("compare_equal_guest_bytes_xmm has no register");
            }
            break;
        case Opcode::CompareEqualXmmBytes:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister) {
                errors.emplace_back("compare_equal_xmm_bytes has incomplete registers");
            }
            break;
        case Opcode::CompareEqualXmmDwords:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister ||
                operation.width != Width::I32) {
                errors.emplace_back(
                    "compare_equal_xmm_dwords has incomplete registers");
            }
            break;
        case Opcode::ShiftLeftXmmDwords:
            if (!operation.guestXmmRegister ||
                operation.width != Width::I32) {
                errors.emplace_back(
                    "shift_left_xmm_dwords has incomplete operands");
            }
            break;
        case Opcode::AddXmmDwords:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister ||
                operation.width != Width::I32) {
                errors.emplace_back(
                    "add_xmm_dwords has incomplete registers");
            }
            break;
        case Opcode::HorizontalAddXmmDwords:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister ||
                operation.width != Width::I32) {
                errors.emplace_back(
                    "horizontal_add_xmm_dwords has incomplete registers");
            }
            break;
        case Opcode::AndNotXmm:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister) {
                errors.emplace_back("and_not_xmm has incomplete registers");
            }
            break;
        case Opcode::MoveXmmByteMask:
            if (!operation.guestRegister || !operation.guestXmmRegister) {
                errors.emplace_back("move_xmm_byte_mask has incomplete registers");
            }
            break;
        case Opcode::ShuffleXmmBytes:
            if (!operation.guestXmmRegister ||
                operation.lhs.has_value() ==
                    operation.sourceGuestXmmRegister.has_value()) {
                errors.emplace_back("shuffle_xmm_bytes has incomplete registers");
            }
            if (operation.lhs) {
                checkUse(operation.lhs, "guest address");
            }
            break;
        case Opcode::ShuffleXmmDwords:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister || operation.immediate > 0xFFU) {
                errors.emplace_back("shuffle_xmm_dwords is incomplete");
            }
            break;
        case Opcode::AlignRightXmmBytes:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister ||
                operation.immediate > 0xFFU) {
                errors.emplace_back("align_right_xmm_bytes is incomplete");
            }
            break;
        case Opcode::BlendXmmWords:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister ||
                operation.immediate > 0xFFU) {
                errors.emplace_back("blend_xmm_words is incomplete");
            }
            break;
        case Opcode::UnpackLowXmmWords:
            if (!operation.guestXmmRegister ||
                !operation.sourceGuestXmmRegister ||
                operation.width != Width::I16) {
                errors.emplace_back(
                    "unpack_low_xmm_words has incomplete registers");
            }
            break;
        case Opcode::BitScanForward:
            if (!operation.guestRegister) {
                errors.emplace_back("bit_scan_forward has no destination register");
            }
            break;
        case Opcode::BitScanReverse:
            if (!operation.guestRegister) {
                errors.emplace_back("bit_scan_reverse has no destination register");
            }
            break;
        case Opcode::DivideUnsignedByte:
            checkUse(operation.lhs, "divisor");
            if (operation.width != Width::I8) {
                errors.emplace_back("divide_unsigned_byte has the wrong width");
            }
            break;
        case Opcode::DivideUnsignedDword:
            checkUse(operation.lhs, "divisor");
            if (operation.width != Width::I32) {
                errors.emplace_back(
                    "divide_unsigned_dword has the wrong width");
            }
            break;
        case Opcode::DivideUnsignedQword:
            checkUse(operation.lhs, "divisor");
            if (operation.width != Width::I64) {
                errors.emplace_back(
                    "divide_unsigned_qword has the wrong width");
            }
            break;
        case Opcode::DivideSignedDword:
            checkUse(operation.lhs, "divisor");
            if (operation.width != Width::I32) {
                errors.emplace_back(
                    "divide_signed_dword has the wrong width");
            }
            break;
        case Opcode::LoadGuest:
            checkUse(operation.lhs, "guest address");
            break;
        case Opcode::LoadFence:
        case Opcode::StoreFence:
        case Opcode::ReadTimestampCounter:
            break;
        case Opcode::UpdateAddFlags:
        case Opcode::UpdateSubFlags:
            checkUse(operation.lhs, "left");
            checkUse(operation.rhs, "right");
            checkUse(operation.third, "result");
            break;
        case Opcode::UpdateAdcFlags:
            checkUse(operation.lhs, "left");
            checkUse(operation.rhs, "right");
            checkUse(operation.third, "carry");
            if (operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back("update_adc_flags requires i32 or i64");
            }
            break;
        case Opcode::UpdateSbbFlags:
            checkUse(operation.lhs, "left");
            checkUse(operation.rhs, "right");
            checkUse(operation.third, "borrow");
            if (operation.width != Width::I8 && operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back("update_sbb_flags requires i8, i32, or i64");
            }
            break;
        case Opcode::UpdateIncFlags:
        case Opcode::UpdateDecFlags:
            checkUse(operation.lhs, "original");
            checkUse(operation.rhs, "result");
            break;
        case Opcode::UpdateLogicFlags:
            checkUse(operation.lhs, "result");
            break;
        case Opcode::UpdateMultiplyFlags:
            checkUse(operation.lhs, "high result");
            break;
        case Opcode::UpdateSignedMultiplyFlags:
            checkUse(operation.lhs, "left");
            checkUse(operation.rhs, "right");
            if (operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "update_signed_multiply_flags requires i32 or i64");
            }
            break;
        case Opcode::UpdateShiftRightDoubleFlags:
            checkUse(operation.lhs, "original");
            checkUse(operation.rhs, "result");
            break;
        case Opcode::UpdateBitTestFlags:
            checkUse(operation.lhs, "tested value");
            if (operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "update_bit_test_flags requires i32 or i64");
            }
            break;
        case Opcode::UpdateShiftLeftFlags:
            checkUse(operation.lhs, "original");
            checkUse(operation.rhs, "result");
            if (operation.third) {
                checkUse(operation.third, "shift count");
            }
            break;
        case Opcode::UpdateShiftRightFlags:
        case Opcode::UpdateShiftRightArithmeticFlags:
            checkUse(operation.lhs, "original");
            checkUse(operation.rhs, "result");
            if (operation.third) {
                checkUse(operation.third, "shift count");
            }
            break;
        case Opcode::UpdateRotateLeftFlags:
            checkUse(operation.lhs, "result");
            if (operation.rhs) {
                checkUse(operation.rhs, "rotate count");
            }
            if (operation.width != Width::I16 &&
                operation.width != Width::I32 &&
                operation.width != Width::I64) {
                errors.emplace_back(
                    "update_rotate_left_flags currently requires i16, i32, or i64");
            }
            break;
        case Opcode::UpdateRotateRightFlags:
            checkUse(operation.lhs, "result");
            if (operation.width != Width::I64) {
                errors.emplace_back(
                    "update_rotate_right_flags currently requires i64");
            }
            break;
        case Opcode::ExitBlock:
            if ((operation.exitKind == ExitKind::Call ||
                 operation.exitKind == ExitKind::Direct) &&
                operation.lhs) {
                checkUse(operation.lhs, "indirect exit target");
            } else if (operation.exitKind != ExitKind::Return && !operation.target) {
                errors.emplace_back("non-return exit has no target");
            }
            if ((operation.exitKind == ExitKind::Conditional ||
                 operation.exitKind == ExitKind::Call) &&
                !operation.fallthrough) {
                errors.emplace_back("conditional/call exit has no fallthrough");
            }
            if (operation.exitKind == ExitKind::Conditional && !operation.condition) {
                errors.emplace_back("conditional exit has no condition");
            }
            sawExit = true;
            break;
        }

        if (operation.result) {
            if (operation.result->value >= defined.size()) {
                errors.emplace_back("result value is outside block value table");
            } else if (defined[operation.result->value]) {
                errors.emplace_back("SSA value is defined more than once");
            } else {
                defined[operation.result->value] = true;
            }
        }
    }

    if (!sawExit) {
        errors.emplace_back("block has no exit_block");
    }
    return errors;
}

} // namespace rosa::ir
