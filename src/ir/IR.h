#pragma once

#include "guest/Address.h"
#include "x86/Instruction.h"
#include "x86/Registers.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rosa::ir {

enum class Width : std::uint8_t {
    I8 = 8,
    I16 = 16,
    I32 = 32,
    I64 = 64,
};

struct ValueId {
    std::uint32_t value{};
    auto operator<=>(const ValueId &) const = default;
};

enum class Opcode {
    Constant,
    ReadGuestReg,
    ReadGuestGsBase,
    WriteGuestReg,
    ConditionalMoveGuestReg,
    ReadGuestXmmLane,
    ReadGuestYmmUpperLane,
    WriteGuestXmmLane,
    WriteGuestYmmUpperLane,
    WriteGuestXmmByte,
    WriteGuestXmmDword,
    Add,
    Sub,
    ShiftLeft,
    ShiftRightLogical,
    ShiftRightArithmetic,
    MultiplyLow,
    MultiplyHighUnsigned,
    MultiplyHighSigned,
    ShiftRightDouble,
    And,
    Or,
    Xor,
    SignExtend32,
    ByteSwap,
    EvaluateCondition,
    LoadGuest,
    StoreGuest,
    StoreGuestXmm,
    StoreGuestYmm,
    LoadGuestXmm,
    LoadGuestYmm,
    LoadGuestSignExtendedBytesXmm,
    LoadGuestSignExtendedDwordsXmm,
    XorGuestMemoryXmm,
    AndGuestMemoryXmm,
    AddGuestMemoryXmm,
    TestXmmBits,
    CompareEqualGuestBytesXmm,
    CompareEqualGuestQwordsXmm,
    CompareEqualXmmBytes,
    CompareEqualXmmDwords,
    CompareEqualXmmQwords,
    ShiftLeftXmmDwords,
    AddXmmWords,
    ComparePackedDoubleXmm,
    ArithmeticPackedDoubleXmm,
    ArithmeticGuestMemoryPackedDoubleXmm,
    UnpackHighPackedSingleXmm,
    UnpackHighGuestPackedSingleXmm,
    HorizontalAddPackedDoubleXmm,
    HorizontalAddGuestPackedDoubleXmm,
    UnpackLowPackedSingleXmm,
    UnpackLowGuestPackedSingleXmm,
    UpdateUnorderedDoubleFlags,
    UpdateUnorderedFloatFlags,
    ConvertIntToDoubleXmm,
    ConvertDoubleToInt,
    ConvertFloatToDoubleXmm,
    ConvertInt32x2ToDoubleXmm,
    ScalarDoubleXmm,
    AddXmmDwords,
    HorizontalAddXmmDwords,
    AndNotXmm,
    MoveXmmByteMask,
    ShuffleXmmBytes,
    ShuffleXmmDwords,
    AlignRightXmmBytes,
    BlendXmmWords,
    UnpackLowXmmWords,
    BitScanForward,
    BitScanReverse,
    RepeatMoveByte,
    DivideUnsignedByte,
    DivideUnsignedDword,
    DivideUnsignedQword,
    DivideSignedDword,
    Push,
    AddGuestMemory,
    SubGuestMemory,
    OrGuestMemory,
    AndGuestMemory,
    ShiftLeftGuestMemory,
    ShiftRightGuestMemory,
    IncrementGuestMemory,
    DecrementGuestMemory,
    CompareExchangeGuestMemory,
    CompareExchangeGuestPair,
    ExchangeGuestMemory,
    LockedAddGuestMemory,
    LockedExchangeAddGuestMemory,
    LockedIncrementGuestMemory,
    LockedDecrementGuestMemory,
    LockedOrGuestMemory,
    LockedAndGuestMemory,
    StoreGuestIdtr,
    LoadFence,
    StoreFence,
    ReadTimestampCounter,
    Cpuid,
    UpdateAddFlags,
    UpdateAdcFlags,
    UpdateSbbFlags,
    UpdateIncFlags,
    UpdateDecFlags,
    UpdateSubFlags,
    UpdateLogicFlags,
    UpdateShiftLeftFlags,
    UpdateShiftRightFlags,
    UpdateShiftRightArithmeticFlags,
    UpdateRotateLeftFlags,
    UpdateRotateRightFlags,
    UpdateMultiplyFlags,
    UpdateSignedMultiplyFlags,
    UpdateShiftRightDoubleFlags,
    UpdateBitTestFlags,
    ExitBlock,
};

enum class ExitKind {
    Return,
    Direct,
    Conditional,
    Call,
    Syscall,
};

struct Operation {
    Opcode opcode{};
    Width width{Width::I64};
    guest::GuestAddress guestRip{};
    std::optional<ValueId> result;
    std::optional<ValueId> lhs;
    std::optional<ValueId> rhs;
    std::optional<ValueId> third;
    std::optional<x86::Register> guestRegister;
    std::optional<x86::XmmRegister> guestXmmRegister;
    std::optional<x86::XmmRegister> sourceGuestXmmRegister;
    std::optional<guest::GuestAddress> target;
    std::optional<guest::GuestAddress> fallthrough;
    std::optional<x86::Condition> condition;
    ExitKind exitKind{ExitKind::Return};
    std::uint64_t immediate{};
};

struct Block {
    guest::GuestAddress start{};
    std::vector<Operation> operations;
    std::uint32_t valueCount{};
};

class Builder {
  public:
    explicit Builder(guest::GuestAddress start) : block_{.start = start} {}

    ValueId constant(std::uint64_t value, Width width, guest::GuestAddress rip);
    ValueId readGuestRegister(x86::Register reg, Width width, guest::GuestAddress rip);
    ValueId readGuestGsBase(guest::GuestAddress rip);
    void writeGuestRegister(x86::Register reg, ValueId value, Width width, guest::GuestAddress rip);
    void conditionalMoveGuestRegister(x86::Register destination,
                                      x86::Register source,
                                      x86::Condition condition, Width width,
                                      guest::GuestAddress rip);
    void conditionalMoveGuestRegister(x86::Register destination,
                                      ValueId source,
                                      x86::Condition condition, Width width,
                                      guest::GuestAddress rip);
    ValueId readGuestXmmLane(x86::XmmRegister reg, bool high, guest::GuestAddress rip);
    ValueId readGuestYmmUpperLane(x86::XmmRegister reg, bool high,
                                  guest::GuestAddress rip);
    void writeGuestXmmLane(x86::XmmRegister reg, bool high, ValueId value,
                           guest::GuestAddress rip);
    void writeGuestYmmUpperLane(x86::XmmRegister reg, bool high,
                                ValueId value, guest::GuestAddress rip);
    void writeGuestXmmByte(x86::XmmRegister reg, std::uint8_t lane,
                           ValueId value, guest::GuestAddress rip);
    void writeGuestXmmDword(x86::XmmRegister reg, std::uint8_t lane,
                            ValueId value, guest::GuestAddress rip);
    ValueId add(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId sub(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId shiftLeft(ValueId value, std::uint8_t count, Width width,
                      guest::GuestAddress rip);
    ValueId shiftLeft(ValueId value, ValueId count, Width width, guest::GuestAddress rip);
    ValueId shiftRightLogical(ValueId value, std::uint8_t count, Width width,
                              guest::GuestAddress rip);
    ValueId shiftRightLogical(ValueId value, ValueId count, Width width,
                              guest::GuestAddress rip);
    ValueId shiftRightArithmetic(ValueId value, std::uint8_t count, Width width,
                                 guest::GuestAddress rip);
    ValueId shiftRightArithmetic(ValueId value, ValueId count, Width width,
                                 guest::GuestAddress rip);
    ValueId multiplyLow(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId multiplyHighUnsigned(ValueId lhs, ValueId rhs, Width width,
                                 guest::GuestAddress rip);
    ValueId multiplyHighSigned(ValueId lhs, ValueId rhs, Width width,
                               guest::GuestAddress rip);
    ValueId shiftRightDouble(ValueId low, ValueId high, std::uint8_t count, Width width,
                             guest::GuestAddress rip);
    ValueId bitAnd(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId bitOr(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId bitXor(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId byteSwap(ValueId value, Width width, guest::GuestAddress rip);
    ValueId signExtend32(ValueId value, guest::GuestAddress rip);
    ValueId evaluateCondition(x86::Condition condition, guest::GuestAddress rip);
    ValueId loadGuest(ValueId address, Width width, guest::GuestAddress rip);
    void storeGuest(ValueId address, ValueId value, Width width, guest::GuestAddress rip);
    void storeGuestXmm(ValueId address, x86::XmmRegister reg, bool aligned,
                       guest::GuestAddress rip);
    void storeGuestYmm(ValueId address, x86::XmmRegister reg, bool aligned,
                       guest::GuestAddress rip);
    void loadGuestXmm(ValueId address, x86::XmmRegister reg, bool aligned,
                      guest::GuestAddress rip);
    void loadGuestYmm(ValueId address, x86::XmmRegister reg, bool aligned,
                      guest::GuestAddress rip);
    void loadGuestSignExtendedBytesXmm(ValueId address,
                                       x86::XmmRegister reg,
                                       guest::GuestAddress rip);
    void loadGuestSignExtendedDwordsXmm(ValueId address,
                                        x86::XmmRegister reg,
                                        guest::GuestAddress rip);
    void xorGuestMemoryXmm(ValueId address, x86::XmmRegister reg,
                           guest::GuestAddress rip);
    void andGuestMemoryXmm(ValueId address, x86::XmmRegister reg,
                           guest::GuestAddress rip);
    void addGuestMemoryXmm(ValueId address, x86::XmmRegister reg,
                           guest::GuestAddress rip);
    void testXmmBits(x86::XmmRegister destination,
                     x86::XmmRegister source, guest::GuestAddress rip);
    void compareEqualGuestBytesXmm(ValueId address, x86::XmmRegister reg,
                                   guest::GuestAddress rip);
    void compareEqualGuestQwordsXmm(ValueId address, x86::XmmRegister reg,
                                    guest::GuestAddress rip);
    void compareEqualXmmBytes(x86::XmmRegister destination,
                              x86::XmmRegister source,
                              guest::GuestAddress rip);
    void compareEqualXmmDwords(x86::XmmRegister destination,
                               x86::XmmRegister source,
                               guest::GuestAddress rip);
    void compareEqualXmmQwords(x86::XmmRegister destination,
                               x86::XmmRegister source,
                               guest::GuestAddress rip);
    void shiftLeftXmmDwords(x86::XmmRegister destination,
                            std::uint8_t count,
                            guest::GuestAddress rip);
    void addXmmWords(x86::XmmRegister destination,
                     x86::XmmRegister source,
                     guest::GuestAddress rip);
    void comparePackedDoubleXmm(x86::XmmRegister destination,
                                x86::XmmRegister source,
                                std::uint8_t predicate,
                                guest::GuestAddress rip);
    // Selector: 0 = add, 1 = subtract, 2 = multiply, 3 = divide, 4 = sqrt.
    void arithmeticPackedDoubleXmm(x86::XmmRegister destination,
                                   x86::XmmRegister source,
                                   std::uint8_t operation,
                                   guest::GuestAddress rip);
    void arithmeticGuestMemoryPackedDoubleXmm(ValueId address,
                                              x86::XmmRegister destination,
                                              std::uint8_t operation,
                                              guest::GuestAddress rip);
    void unpackHighPackedSingleXmm(x86::XmmRegister destination,
                                   x86::XmmRegister source,
                                   guest::GuestAddress rip);
    void unpackHighGuestPackedSingleXmm(ValueId address,
                                        x86::XmmRegister destination,
                                        guest::GuestAddress rip);
    void horizontalAddPackedDoubleXmm(x86::XmmRegister destination,
                                      x86::XmmRegister source,
                                      guest::GuestAddress rip);
    void horizontalAddGuestPackedDoubleXmm(ValueId address,
                                           x86::XmmRegister destination,
                                           guest::GuestAddress rip);
    void unpackLowPackedSingleXmm(x86::XmmRegister destination,
                                  x86::XmmRegister source,
                                  guest::GuestAddress rip);
    void unpackLowGuestPackedSingleXmm(ValueId address,
                                       x86::XmmRegister destination,
                                       guest::GuestAddress rip);
    void updateUnorderedDoubleFlags(ValueId destinationBits,
                                        ValueId sourceBits,
                                        guest::GuestAddress rip);
    void updateUnorderedFloatFlags(ValueId destinationBits,
                                       ValueId sourceBits,
                                       guest::GuestAddress rip);
    void convertIntToDoubleXmm(ValueId value, x86::XmmRegister destination,
                               Width width, guest::GuestAddress rip);
    // Converts a double bit pattern to a truncated integer in a general
    // register; width selects the 32- or 64-bit destination. Out-of-range
    // inputs produce the integer-indefinite value, matching CVTTSD2SI.
    void convertDoubleToInt(ValueId bits, x86::Register destination,
                            Width width, guest::GuestAddress rip);
    void convertFloatToDoubleXmm(ValueId value, x86::XmmRegister destination,
                                 guest::GuestAddress rip);
    void convertInt32x2ToDoubleXmm(ValueId lowBits,
                                       x86::XmmRegister destination,
                                       guest::GuestAddress rip);
    // Selector: 0 = add, 1 = subtract, 2 = multiply, 3 = divide, 4 = sqrt.
    // The source is a raw double bit pattern; the destination high lane is preserved.
    void scalarDoubleXmm(ValueId sourceBits, x86::XmmRegister destination,
                         std::uint8_t operation, guest::GuestAddress rip);
    void addXmmDwords(x86::XmmRegister destination,
                      x86::XmmRegister source,
                      guest::GuestAddress rip);
    void horizontalAddXmmDwords(x86::XmmRegister destination,
                                x86::XmmRegister source,
                                guest::GuestAddress rip);
    void andNotXmm(x86::XmmRegister destination, x86::XmmRegister source,
                   guest::GuestAddress rip);
    void moveXmmByteMask(x86::Register destination, x86::XmmRegister source,
                         guest::GuestAddress rip);
    void shuffleXmmBytes(x86::XmmRegister destination,
                         x86::XmmRegister source, guest::GuestAddress rip);
    void shuffleGuestMemoryXmmBytes(ValueId address,
                                    x86::XmmRegister destination,
                                    guest::GuestAddress rip);
    void shuffleXmmDwords(x86::XmmRegister destination,
                          x86::XmmRegister source, std::uint8_t control,
                          guest::GuestAddress rip);
    void alignRightXmmBytes(x86::XmmRegister destination,
                            x86::XmmRegister source, std::uint8_t count,
                            guest::GuestAddress rip);
    void blendXmmWords(x86::XmmRegister destination,
                       x86::XmmRegister source, std::uint8_t mask,
                       guest::GuestAddress rip);
    void unpackLowXmmWords(x86::XmmRegister destination,
                           x86::XmmRegister source,
                           guest::GuestAddress rip);
    void bitScanForward(x86::Register destination, x86::Register source,
                        Width width, guest::GuestAddress rip);
    void bitScanReverse(x86::Register destination, x86::Register source,
                        Width width, guest::GuestAddress rip);
    void repeatMoveByte(guest::GuestAddress rip);
    void divideUnsignedByte(ValueId divisor, guest::GuestAddress rip);
    void divideUnsignedDword(ValueId divisor, guest::GuestAddress rip);
    void divideUnsignedQword(ValueId divisor, guest::GuestAddress rip);
    void divideSignedDword(ValueId divisor, guest::GuestAddress rip);
    void push(ValueId newStackPointer, ValueId value, Width width, guest::GuestAddress rip);
    void addGuestMemory(ValueId address, ValueId source, Width width,
                        guest::GuestAddress rip);
    void subGuestMemory(ValueId address, ValueId source, Width width,
                        guest::GuestAddress rip);
    void orGuestMemory(ValueId address, ValueId source, Width width,
                       guest::GuestAddress rip);
    void andGuestMemory(ValueId address, ValueId source, Width width,
                        guest::GuestAddress rip);
    void shiftLeftGuestMemory(ValueId address, std::uint8_t count, Width width,
                              guest::GuestAddress rip);
    void shiftRightLogicalGuestMemory(ValueId address, std::uint8_t count, Width width,
                                      guest::GuestAddress rip);
    void incrementGuestMemory(ValueId address, Width width,
                              guest::GuestAddress rip);
    void decrementGuestMemory(ValueId address, Width width,
                              guest::GuestAddress rip);
    void compareExchangeGuestMemory(ValueId address, ValueId source,
                                    Width width, guest::GuestAddress rip);
    void compareExchangeGuestPair(ValueId address, guest::GuestAddress rip);
    void exchangeGuestMemory(ValueId address, ValueId source,
                             x86::Register destination, Width width,
                             guest::GuestAddress rip);
    void lockedAddGuestMemory(ValueId address, ValueId source, Width width,
                              guest::GuestAddress rip);
    void lockedExchangeAddGuestMemory(ValueId address, ValueId source,
                                      x86::Register sourceRegister,
                                      Width width, guest::GuestAddress rip);
    void lockedIncrementGuestMemory(ValueId address, Width width,
                                    guest::GuestAddress rip);
    void lockedDecrementGuestMemory(ValueId address, Width width,
                                    guest::GuestAddress rip);
    void lockedOrGuestMemory(ValueId address, ValueId immediate,
                             Width width, guest::GuestAddress rip);
    void lockedAndGuestMemory(ValueId address, ValueId immediate,
                              Width width, guest::GuestAddress rip);
    void storeGuestIdtr(ValueId address, guest::GuestAddress rip);
    void loadFence(guest::GuestAddress rip);
    void storeFence(guest::GuestAddress rip);
    void readTimestampCounter(guest::GuestAddress rip);
    void cpuid(guest::GuestAddress rip);
    void updateAddFlags(ValueId lhs, ValueId rhs, ValueId result, Width width,
                        guest::GuestAddress rip);
    void updateAdcFlags(ValueId lhs, ValueId rhs, ValueId carry, Width width,
                        guest::GuestAddress rip);
    void updateSbbFlags(ValueId lhs, ValueId rhs, ValueId borrow, Width width,
                        guest::GuestAddress rip);
    void updateIncFlags(ValueId original, ValueId result, Width width,
                        guest::GuestAddress rip);
    void updateDecFlags(ValueId original, ValueId result, Width width,
                        guest::GuestAddress rip);
    void updateSubFlags(ValueId lhs, ValueId rhs, ValueId result, Width width,
                        guest::GuestAddress rip);
    void updateLogicFlags(ValueId result, Width width, guest::GuestAddress rip);
    void updateShiftLeftFlags(ValueId lhs, ValueId result, std::uint8_t count, Width width,
                              guest::GuestAddress rip);
    void updateShiftLeftFlags(ValueId lhs, ValueId result, ValueId count, Width width,
                              guest::GuestAddress rip);
    void updateShiftRightFlags(ValueId lhs, ValueId result, std::uint8_t count, Width width,
                               guest::GuestAddress rip);
    void updateShiftRightFlags(ValueId lhs, ValueId result, ValueId count,
                               Width width, guest::GuestAddress rip);
    void updateShiftRightArithmeticFlags(ValueId lhs, ValueId result,
                                         std::uint8_t count, Width width,
                                         guest::GuestAddress rip);
    void updateShiftRightArithmeticFlags(ValueId lhs, ValueId result, ValueId count, Width width,
                                         guest::GuestAddress rip);
    void updateRotateLeftFlags(ValueId result, std::uint8_t count, Width width,
                               guest::GuestAddress rip);
    void updateRotateLeftFlags(ValueId result, ValueId count, Width width,
                               guest::GuestAddress rip);
    void updateRotateRightFlags(ValueId result, std::uint8_t count,
                                Width width, guest::GuestAddress rip);
    void updateRotateRightFlags(ValueId result, ValueId count,
                                Width width, guest::GuestAddress rip);
    void updateMultiplyFlags(ValueId high, Width width, guest::GuestAddress rip);
    void updateSignedMultiplyFlags(ValueId lhs, ValueId rhs, Width width,
                                   guest::GuestAddress rip);
    void updateShiftRightDoubleFlags(ValueId original, ValueId result, std::uint8_t count,
                                     Width width, guest::GuestAddress rip);
    void updateBitTestFlags(ValueId value, std::uint8_t bitIndex, Width width,
                            guest::GuestAddress rip);
    void exitBlock(guest::GuestAddress rip);
    void exitDirect(guest::GuestAddress target, guest::GuestAddress rip);
    void exitDirect(ValueId target, guest::GuestAddress rip);
    void exitConditional(x86::Condition condition, guest::GuestAddress target,
                         guest::GuestAddress fallthrough, guest::GuestAddress rip);
    void exitCall(guest::GuestAddress target, guest::GuestAddress returnAddress,
                  guest::GuestAddress rip);
    void exitCall(ValueId target, guest::GuestAddress returnAddress,
                  guest::GuestAddress rip);
    void exitSyscall(guest::GuestAddress nextRip, guest::GuestAddress rip);

    [[nodiscard]] Block finish() &&;

  private:
    ValueId nextValue();
    Block block_;
};

[[nodiscard]] std::vector<std::string> verify(const Block &block);

} // namespace rosa::ir
