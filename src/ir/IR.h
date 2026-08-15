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
    Add,
    Sub,
    And,
    LoadGuest,
    StoreGuest,
    Push,
    LoadFence,
    UpdateAddFlags,
    UpdateSubFlags,
    UpdateLogicFlags,
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
    ValueId add(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId sub(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId bitAnd(ValueId lhs, ValueId rhs, Width width, guest::GuestAddress rip);
    ValueId loadGuest(ValueId address, Width width, guest::GuestAddress rip);
    void storeGuest(ValueId address, ValueId value, Width width, guest::GuestAddress rip);
    void push(ValueId newStackPointer, ValueId value, Width width, guest::GuestAddress rip);
    void loadFence(guest::GuestAddress rip);
    void updateAddFlags(ValueId lhs, ValueId rhs, ValueId result, Width width,
                        guest::GuestAddress rip);
    void updateSubFlags(ValueId lhs, ValueId rhs, ValueId result, Width width,
                        guest::GuestAddress rip);
    void updateLogicFlags(ValueId result, Width width, guest::GuestAddress rip);
    void exitBlock(guest::GuestAddress rip);
    void exitDirect(guest::GuestAddress target, guest::GuestAddress rip);
    void exitConditional(x86::Condition condition, guest::GuestAddress target,
                         guest::GuestAddress fallthrough, guest::GuestAddress rip);
    void exitCall(guest::GuestAddress target, guest::GuestAddress returnAddress,
                  guest::GuestAddress rip);
    void exitSyscall(guest::GuestAddress nextRip, guest::GuestAddress rip);

    [[nodiscard]] Block finish() &&;

  private:
    ValueId nextValue();
    Block block_;
};

[[nodiscard]] std::vector<std::string> verify(const Block &block);

} // namespace rosa::ir
