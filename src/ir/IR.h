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
    WriteGuestReg,
    ConditionalMoveGuestReg,
    ReadGuestXmmLane,
    WriteGuestXmmLane,
    Add,
    Sub,
    ShiftLeft,
    ShiftRightLogical,
    MultiplyLow,
    MultiplyHighUnsigned,
    ShiftRightDouble,
    And,
    Or,
    Xor,
    SignExtend32,
    EvaluateCondition,
    LoadGuest,
    StoreGuest,
    StoreGuestXmm,
    LoadGuestXmm,
    CompareEqualGuestBytesXmm,
    MoveXmmByteMask,
    ShuffleXmmDwords,
    BitScanForward,
    Push,
    IncrementGuestMemory,
    DecrementGuestMemory,
    LoadFence,
    ReadTimestampCounter,
    UpdateAddFlags,
    UpdateIncFlags,
    UpdateDecFlags,
    UpdateSubFlags,
    UpdateLogicFlags,
    UpdateShiftLeftFlags,
    UpdateShiftRightFlags,
    UpdateMultiplyFlags,
    UpdateSignedMultiplyFlags,
    UpdateShiftRightDoubleFlags,
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
    void writeGuestRegister(x86::Register reg, ValueId value, Width width, guest::GuestAddress rip);
    void conditionalMoveGuestRegister(x86::Register destination,
                                      x86::Register source,
                                      x86::Condition condition, Width width,
                                      guest::GuestAddress rip);
    ValueId readGuestXmmLane(x86::XmmRegister reg, bool high, guest::GuestAddress rip);
    void writeGuestXmmLane(x86::XmmRegister reg, bool high, ValueId value,
                           guest::GuestAddress rip);
    ValueId add(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId sub(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId shiftLeft(ValueId value, std::uint8_t count, Width width,
                      guest::GuestAddress rip);
    ValueId shiftLeft(ValueId value, ValueId count, Width width, guest::GuestAddress rip);
    ValueId shiftRightLogical(ValueId value, std::uint8_t count, Width width,
                              guest::GuestAddress rip);
    ValueId multiplyLow(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId multiplyHighUnsigned(ValueId lhs, ValueId rhs, Width width,
                                 guest::GuestAddress rip);
    ValueId shiftRightDouble(ValueId low, ValueId high, std::uint8_t count, Width width,
                             guest::GuestAddress rip);
    ValueId bitAnd(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId bitOr(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId bitXor(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId signExtend32(ValueId value, guest::GuestAddress rip);
    ValueId evaluateCondition(x86::Condition condition, guest::GuestAddress rip);
    ValueId loadGuest(ValueId address, Width width, guest::GuestAddress rip);
    void storeGuest(ValueId address, ValueId value, Width width, guest::GuestAddress rip);
    void storeGuestXmm(ValueId address, x86::XmmRegister reg, bool aligned,
                       guest::GuestAddress rip);
    void loadGuestXmm(ValueId address, x86::XmmRegister reg, bool aligned,
                      guest::GuestAddress rip);
    void compareEqualGuestBytesXmm(ValueId address, x86::XmmRegister reg,
                                   guest::GuestAddress rip);
    void moveXmmByteMask(x86::Register destination, x86::XmmRegister source,
                         guest::GuestAddress rip);
    void shuffleXmmDwords(x86::XmmRegister destination,
                          x86::XmmRegister source, std::uint8_t control,
                          guest::GuestAddress rip);
    void bitScanForward(x86::Register destination, x86::Register source,
                        Width width, guest::GuestAddress rip);
    void push(ValueId newStackPointer, ValueId value, Width width, guest::GuestAddress rip);
    void incrementGuestMemory(ValueId address, Width width,
                              guest::GuestAddress rip);
    void decrementGuestMemory(ValueId address, Width width,
                              guest::GuestAddress rip);
    void loadFence(guest::GuestAddress rip);
    void readTimestampCounter(guest::GuestAddress rip);
    void updateAddFlags(ValueId lhs, ValueId rhs, ValueId result, Width width,
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
    void updateMultiplyFlags(ValueId high, Width width, guest::GuestAddress rip);
    void updateSignedMultiplyFlags(ValueId lhs, ValueId rhs, Width width,
                                   guest::GuestAddress rip);
    void updateShiftRightDoubleFlags(ValueId original, ValueId result, std::uint8_t count,
                                     Width width, guest::GuestAddress rip);
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
