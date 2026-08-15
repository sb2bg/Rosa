#include "dbt/Translator.h"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace rosa::dbt {
namespace {

constexpr std::uint64_t flagCarry = 1U << 0U;
constexpr std::uint64_t flagReservedOne = 1U << 1U;
constexpr std::uint64_t flagParity = 1U << 2U;
constexpr std::uint64_t flagAuxiliaryCarry = 1U << 4U;
constexpr std::uint64_t flagZero = 1U << 6U;
constexpr std::uint64_t flagSign = 1U << 7U;
constexpr std::uint64_t flagOverflow = 1U << 11U;
constexpr std::uint64_t arithmeticFlagMask =
    flagCarry | flagParity | flagAuxiliaryCarry | flagZero | flagSign | flagOverflow;

struct GuestExecutionContext {
    guest::AddressSpace *addressSpace{};
    std::exception_ptr fault;
    guest::GuestAddress faultAddress{};
    std::size_t faultSize{};
};

extern "C" __attribute__((noinline)) x86::X86State *
commitPush64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t newStackPointer,
             std::uint64_t value) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated PUSH has no guest address space");
        }
        context->addressSpace->writeU64(guest::GuestAddress{newStackPointer}, value);
        state->rsp = newStackPointer;
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{newStackPointer};
            context->faultSize = sizeof(std::uint64_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
storeGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
             std::uint64_t value) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated guest store has no address space");
        }
        context->addressSpace->writeU64(guest::GuestAddress{address}, value);
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint64_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
updateAddFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs, std::uint64_t result) {
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (result < lhs) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if (((~(lhs ^ rhs) & (lhs ^ result)) >> 63U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateSubFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs, std::uint64_t result) {
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (lhs < rhs) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) >> 63U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateLogicFlags64(x86::X86State *state,
                                                                       std::uint64_t result) {
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    state->rflags = flags;
    return state;
}

template <typename Pointer> std::uint64_t pointerBits(Pointer pointer) {
    static_assert(std::is_pointer_v<Pointer>);
    static_assert(sizeof(pointer) == sizeof(std::uint64_t));
    std::uint64_t result = 0;
    std::memcpy(&result, &pointer, sizeof(result));
    return result;
}

ir::Block lowerToIr(const std::vector<x86::DecodedInstruction> &decoded) {
    if (decoded.empty()) {
        throw std::runtime_error("cannot lower an empty x86 block");
    }

    ir::Builder builder(decoded.front().address);
    for (const auto &instruction : decoded) {
        switch (instruction.opcode) {
        case x86::Opcode::MovRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: mov operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto value =
                builder.constant(immediate.value, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(reg.reg, value, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::MovRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: mov register operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto value =
                builder.readGuestRegister(source.reg, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(destination.reg, value, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::MovMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: mov store operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto base =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            const auto displacement = builder.constant(
                static_cast<std::uint64_t>(memory.displacement), ir::Width::I64,
                instruction.address);
            const auto address =
                builder.add(base, displacement, ir::Width::I64, instruction.address);
            const auto value =
                builder.readGuestRegister(source.reg, ir::Width::I64, instruction.address);
            builder.storeGuest(address, value, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::LeaRegRipRelative: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: lea operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto address = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto value = builder.constant(address.value, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(reg.reg, value, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::AddRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: add operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto lhs =
                builder.readGuestRegister(reg.reg, ir::Width::I64, instruction.address);
            const auto rhs = builder.constant(immediate.value, ir::Width::I64, instruction.address);
            const auto result = builder.add(lhs, rhs, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(reg.reg, result, ir::Width::I64, instruction.address);
            builder.updateAddFlags(lhs, rhs, result, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::SubRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: sub operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto lhs =
                builder.readGuestRegister(reg.reg, ir::Width::I64, instruction.address);
            const auto rhs = builder.constant(immediate.value, ir::Width::I64, instruction.address);
            const auto result = builder.sub(lhs, rhs, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(reg.reg, result, ir::Width::I64, instruction.address);
            builder.updateSubFlags(lhs, rhs, result, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::AndRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: and operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto lhs =
                builder.readGuestRegister(reg.reg, ir::Width::I64, instruction.address);
            const auto rhs = builder.constant(immediate.value, ir::Width::I64, instruction.address);
            const auto result = builder.bitAnd(lhs, rhs, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(reg.reg, result, ir::Width::I64, instruction.address);
            builder.updateLogicFlags(result, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::CmpRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: cmp operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto lhs =
                builder.readGuestRegister(reg.reg, ir::Width::I64, instruction.address);
            const auto rhs = builder.constant(immediate.value, ir::Width::I64, instruction.address);
            const auto result = builder.sub(lhs, rhs, ir::Width::I64, instruction.address);
            builder.updateSubFlags(lhs, rhs, result, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::Push: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: push operand count");
            }
            const auto stackPointer =
                builder.readGuestRegister(x86::Register::Rsp, ir::Width::I64,
                                          instruction.address);
            const auto eight = builder.constant(sizeof(std::uint64_t), ir::Width::I64,
                                                instruction.address);
            const auto newStackPointer =
                builder.sub(stackPointer, eight, ir::Width::I64, instruction.address);
            const auto value = std::holds_alternative<x86::ImmediateOperand>(
                                   instruction.operands[0])
                                   ? builder.constant(
                                         std::get<x86::ImmediateOperand>(instruction.operands[0])
                                             .value,
                                         ir::Width::I64, instruction.address)
                                   : builder.readGuestRegister(
                                         std::get<x86::RegisterOperand>(instruction.operands[0]).reg,
                                         ir::Width::I64, instruction.address);
            builder.push(newStackPointer, value, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::JmpRelative:
            builder.exitDirect(*instruction.branchTarget, instruction.address);
            break;
        case x86::Opcode::JccRelative:
            builder.exitConditional(*instruction.condition, *instruction.branchTarget,
                                    *instruction.fallthrough, instruction.address);
            break;
        case x86::Opcode::CallRelative:
            builder.exitCall(*instruction.branchTarget, *instruction.fallthrough,
                             instruction.address);
            break;
        case x86::Opcode::Syscall:
            builder.exitSyscall(*instruction.fallthrough, instruction.address);
            break;
        case x86::Opcode::Ret:
            builder.exitBlock(instruction.address);
            break;
        }
    }

    const auto lastOpcode = decoded.back().opcode;
    const bool hasTerminator = lastOpcode == x86::Opcode::JmpRelative ||
                               lastOpcode == x86::Opcode::JccRelative ||
                               lastOpcode == x86::Opcode::CallRelative ||
                               lastOpcode == x86::Opcode::Syscall || lastOpcode == x86::Opcode::Ret;
    if (!hasTerminator) {
        const auto &last = decoded.back();
        if (last.address.value > std::numeric_limits<std::uint64_t>::max() - last.length) {
            throw std::runtime_error("x86 instruction fallthrough overflows guest RIP");
        }
        builder.exitDirect(guest::GuestAddress{last.address.value + last.length}, last.address);
    }

    auto block = std::move(builder).finish();
    const auto errors = ir::verify(block);
    if (!errors.empty()) {
        throw std::runtime_error("IR verification failed: " + errors.front());
    }
    return block;
}

arm64::XRegister hostRegister(ir::ValueId value) {
    constexpr std::uint32_t first = 9;
    constexpr std::uint32_t last = 15;
    const auto encoding = first + value.value;
    if (encoding > last) {
        throw std::runtime_error(
            "R1 local register allocator exhausted x9...x15; split or shorten the block");
    }
    return arm64::XRegister{static_cast<std::uint8_t>(encoding)};
}

arm64::Program compileToArm64(const ir::Block &block) {
    arm64::Assembler assembler;
    bool hasHelperCall = false;
    bool hasGuestMemoryCall = false;
    for (const auto &operation : block.operations) {
        hasHelperCall |= operation.opcode == ir::Opcode::UpdateAddFlags ||
                         operation.opcode == ir::Opcode::UpdateSubFlags ||
                         operation.opcode == ir::Opcode::UpdateLogicFlags ||
                         operation.opcode == ir::Opcode::Push ||
                         operation.opcode == ir::Opcode::StoreGuest;
        hasGuestMemoryCall |= operation.opcode == ir::Opcode::Push ||
                              operation.opcode == ir::Opcode::StoreGuest;
    }
    if (hasHelperCall) {
        assembler.pushFrameRecord();
    }
    if (hasGuestMemoryCall) {
        assembler.pushCalleeSaved19And20();
        assembler.mov(arm64::x19, arm64::x1);
    }

    const auto emitEpilogue = [&] {
        if (hasGuestMemoryCall) {
            assembler.popCalleeSaved19And20();
        }
        if (hasHelperCall) {
            assembler.popFrameRecord();
        }
    };

    for (const auto &operation : block.operations) {
        switch (operation.opcode) {
        case ir::Opcode::Constant:
            assembler.movImmediate(hostRegister(*operation.result), operation.immediate);
            break;
        case ir::Opcode::ReadGuestReg:
            assembler.ldr(
                hostRegister(*operation.result), arm64::x0,
                static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
            break;
        case ir::Opcode::WriteGuestReg:
            assembler.str(
                hostRegister(*operation.lhs), arm64::x0,
                static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
            break;
        case ir::Opcode::Add:
            assembler.add(hostRegister(*operation.result), hostRegister(*operation.lhs),
                          hostRegister(*operation.rhs));
            break;
        case ir::Opcode::Sub:
            assembler.sub(hostRegister(*operation.result), hostRegister(*operation.lhs),
                          hostRegister(*operation.rhs));
            break;
        case ir::Opcode::And:
            assembler.bitAnd(hostRegister(*operation.result), hostRegister(*operation.lhs),
                             hostRegister(*operation.rhs));
            break;
        case ir::Opcode::Push: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&commitPush64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0,
                                   static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::StoreGuest: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&storeGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0,
                                   static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::UpdateAddFlags:
        case ir::Opcode::UpdateSubFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.mov(arm64::x3, hostRegister(*operation.third));
            assembler.movImmediate(arm64::x16, operation.opcode == ir::Opcode::UpdateAddFlags
                                                   ? pointerBits(&updateAddFlags64)
                                                   : pointerBits(&updateSubFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateLogicFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x16, pointerBits(&updateLogicFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ExitBlock: {
            BlockExit exit = BlockExit::Continue;
            switch (operation.exitKind) {
            case ir::ExitKind::Return:
                assembler.movImmediate(arm64::x16, operation.guestRip.value);
                exit = BlockExit::Return;
                break;
            case ir::ExitKind::Direct:
                assembler.movImmediate(arm64::x16, operation.target->value);
                break;
            case ir::ExitKind::Call:
                assembler.movImmediate(arm64::x16, operation.target->value);
                exit = BlockExit::Call;
                break;
            case ir::ExitKind::Syscall:
                assembler.movImmediate(arm64::x16, operation.target->value);
                assembler.str(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rcx)));
                assembler.ldr(arm64::x17, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                assembler.str(arm64::x17, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, r11)));
                exit = BlockExit::Syscall;
                break;
            case ir::ExitKind::Conditional: {
                constexpr std::uint8_t zeroFlagBit = 6;
                const auto notTaken = assembler.makeLabel();
                const auto selected = assembler.makeLabel();
                assembler.ldr(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                if (*operation.condition == x86::Condition::Equal) {
                    assembler.tbz(arm64::x16, zeroFlagBit, notTaken);
                } else {
                    assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                }
                assembler.movImmediate(arm64::x16, operation.target->value);
                assembler.b(selected);
                assembler.bind(notTaken);
                assembler.movImmediate(arm64::x16, operation.fallthrough->value);
                assembler.bind(selected);
                break;
            }
            }
            assembler.str(arm64::x16, arm64::x0,
                          static_cast<std::uint32_t>(offsetof(x86::X86State, rip)));
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(exit));
            assembler.ret();
            break;
        }
        }
    }
    return std::move(assembler).finish();
}

} // namespace

TranslatedBlock::TranslatedBlock(std::vector<x86::DecodedInstruction> decoded, ir::Block ir,
                                 arm64::Program program)
    : decoded_(std::move(decoded)), ir_(std::move(ir)), program_(std::move(program)),
      executable_(program_.bytes) {
    for (const auto &operation : ir_.operations) {
        if (operation.opcode == ir::Opcode::ExitBlock && operation.exitKind == ir::ExitKind::Call) {
            callReturnAddress_ = operation.fallthrough;
        }
    }
}

BlockExit TranslatedBlock::execute(x86::X86State &state,
                                   guest::AddressSpace *addressSpace) const {
    GuestExecutionContext context{.addressSpace = addressSpace};
    using Entry = std::uint64_t (*)(x86::X86State *, GuestExecutionContext *);
    const auto rawExit = executable_.entry<Entry>()(&state, &context);
    if (rawExit > static_cast<std::uint64_t>(BlockExit::MemoryFault)) {
        throw std::runtime_error("generated block returned an invalid exit reason");
    }
    if (rawExit == static_cast<std::uint64_t>(BlockExit::MemoryFault)) {
        if (context.fault) {
            std::rethrow_exception(context.fault);
        }
        throw std::runtime_error("generated block reported a guest-memory fault");
    }
    return static_cast<BlockExit>(rawExit);
}

TranslatedBlock Translator::translate(std::span<const std::uint8_t> code, guest::GuestAddress start,
                                      std::size_t maximumInstructions) const {
    auto decoded = decoder_.decodeBlock(code, start, maximumInstructions);
    auto intermediate = lowerToIr(decoded);
    auto program = compileToArm64(intermediate);
    return TranslatedBlock(std::move(decoded), std::move(intermediate), std::move(program));
}

} // namespace rosa::dbt
