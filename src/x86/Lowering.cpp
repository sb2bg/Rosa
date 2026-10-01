#include "x86/Lowering.h"

#include <bit>
#include <limits>
#include <stdexcept>
#include <utility>

namespace rosa::x86 {

ir::Block lowerToIr(std::span<const DecodedInstruction> decoded) {
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
            if (reg.width == 8) {
                const auto original =
                    builder.readGuestRegister(reg.reg, ir::Width::I64, instruction.address);
                const auto clearMask =
                    builder.constant(~std::uint64_t{0xFF}, ir::Width::I64, instruction.address);
                const auto cleared =
                    builder.bitAnd(original, clearMask, ir::Width::I64, instruction.address);
                const auto byte =
                    builder.constant(immediate.value, ir::Width::I64, instruction.address);
                const auto result =
                    builder.bitOr(cleared, byte, ir::Width::I64, instruction.address);
                builder.writeGuestRegister(reg.reg, result, ir::Width::I64, instruction.address);
                break;
            }
            const auto width = reg.width == 16   ? ir::Width::I16
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto value = builder.constant(immediate.value, width, instruction.address);
            builder.writeGuestRegister(reg.reg, value, width, instruction.address);
            break;
        }
        case x86::Opcode::MovRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: mov register operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 16 ? ir::Width::I16
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto value = builder.readGuestRegister(source.reg, width, instruction.address);
            builder.writeGuestRegister(destination.reg, value, width, instruction.address);
            break;
        }
        case x86::Opcode::MovMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: mov store operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto width = source.width == 8    ? ir::Width::I8
                               : source.width == 16 ? ir::Width::I16
                               : source.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            std::optional<ir::ValueId> address;
            if (memory.ripRelative) {
                address = builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address);
            } else if (memory.hasBase) {
                address =
                    builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            }
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = address
                              ? builder.add(*address, index, ir::Width::I64, instruction.address)
                              : index;
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = address ? builder.add(*address, displacement, ir::Width::I64,
                                                instruction.address)
                                  : displacement;
            }
            if (memory.segment == x86::Segment::Gs) {
                const auto gsBase = builder.readGuestGsBase(instruction.address);
                address = address
                              ? builder.add(gsBase, *address, ir::Width::I64, instruction.address)
                              : gsBase;
            }
            if (!address) {
                address = builder.constant(0, ir::Width::I64, instruction.address);
            }
            if (source.byteOffset > 1 ||
                (source.byteOffset == 1 && source.width != 8)) {
                throw std::runtime_error("invalid byte-lane MOV store source");
            }
            auto value = source.byteOffset == 0
                             ? builder.readGuestRegister(source.reg, width, instruction.address)
                             : builder.shiftRightLogical(
                                   builder.readGuestRegister(source.reg, ir::Width::I64,
                                                             instruction.address),
                                   8, ir::Width::I64, instruction.address);
            builder.storeGuest(*address, value, width, instruction.address);
            break;
        }
        case x86::Opcode::MovRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: mov load operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            std::optional<ir::ValueId> address;
            if (memory.ripRelative) {
                address = builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address);
            } else if (memory.hasBase) {
                address =
                    builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            }
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = address
                              ? builder.add(*address, index, ir::Width::I64, instruction.address)
                              : index;
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = address ? builder.add(*address, displacement, ir::Width::I64,
                                                instruction.address)
                                  : displacement;
            }
            if (memory.segment == x86::Segment::Gs) {
                const auto gsBase = builder.readGuestGsBase(instruction.address);
                address = address
                              ? builder.add(gsBase, *address, ir::Width::I64, instruction.address)
                              : gsBase;
            }
            if (!address) {
                address = builder.constant(0, ir::Width::I64, instruction.address);
            }
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 16 ? ir::Width::I16
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto value = builder.loadGuest(*address, width, instruction.address);
            builder.writeGuestRegister(destination.reg, value, width, instruction.address);
            break;
        }
        case x86::Opcode::MovzxRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: movzx register operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            auto value = builder.readGuestRegister(source.reg, ir::Width::I64, instruction.address);
            if (source.byteOffset != 0) {
                if (source.width != 8 || source.byteOffset != 1) {
                    throw std::runtime_error("MOVZX register source has an invalid byte lane");
                }
                value = builder.shiftRightLogical(value, 8, ir::Width::I64, instruction.address);
            }
            const auto mask = builder.constant(source.width == 8 ? 0xFF : 0xFFFF, ir::Width::I64,
                                               instruction.address);
            const auto byte = builder.bitAnd(value, mask, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(destination.reg, byte,
                                       destination.width == 64 ? ir::Width::I64 : ir::Width::I32,
                                       instruction.address);
            break;
        }
        case x86::Opcode::MovsxRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: movsx register operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto value =
                builder.readGuestRegister(source.reg, ir::Width::I64, instruction.address);
            const auto shift = static_cast<std::uint8_t>(64U - source.width);
            const auto shifted =
                builder.shiftLeft(value, shift, ir::Width::I64, instruction.address);
            const auto extended =
                builder.shiftRightArithmetic(shifted, shift, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(destination.reg, extended,
                                       destination.width == 64 ? ir::Width::I64 : ir::Width::I32,
                                       instruction.address);
            break;
        }
        case x86::Opcode::MovsxRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: movsx memory operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto value = builder.loadGuest(
                address, memory.width == 8 ? ir::Width::I8 : ir::Width::I16, instruction.address);
            const auto shift = static_cast<std::uint8_t>(64U - memory.width);
            const auto shifted =
                builder.shiftLeft(value, shift, ir::Width::I64, instruction.address);
            const auto extended =
                builder.shiftRightArithmetic(shifted, shift, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(destination.reg, extended,
                                       destination.width == 64 ? ir::Width::I64 : ir::Width::I32,
                                       instruction.address);
            break;
        }
        case x86::Opcode::MovzxRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: movzx operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            const auto displacement =
                builder.constant(static_cast<std::uint64_t>(memory.displacement), ir::Width::I64,
                                 instruction.address);
            address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            const auto value = builder.loadGuest(
                address, memory.width == 8 ? ir::Width::I8 : ir::Width::I16, instruction.address);
            builder.writeGuestRegister(destination.reg, value,
                                       destination.width == 64 ? ir::Width::I64 : ir::Width::I32,
                                       instruction.address);
            break;
        }
        case x86::Opcode::MovsxdRegReg: {
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (destination.width != 64 || source.width != 32) {
                throw std::runtime_error("MOVSXD register operands have invalid widths");
            }
            const auto value =
                builder.readGuestRegister(source.reg, ir::Width::I32, instruction.address);
            const auto extended = builder.signExtend32(value, instruction.address);
            builder.writeGuestRegister(destination.reg, extended, ir::Width::I64,
                                       instruction.address);
            break;
        }
        case x86::Opcode::MovsxdRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: movsxd operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto value = builder.loadGuest(address, ir::Width::I32, instruction.address);
            const auto extended = builder.signExtend32(value, instruction.address);
            builder.writeGuestRegister(destination.reg, extended, ir::Width::I64,
                                       instruction.address);
            break;
        }
        case x86::Opcode::Cdqe: {
            if (!instruction.operands.empty()) {
                throw std::runtime_error("internal decoder error: CDQE operands");
            }
            const auto value =
                builder.readGuestRegister(x86::Register::Rax, ir::Width::I32, instruction.address);
            const auto extended = builder.signExtend32(value, instruction.address);
            builder.writeGuestRegister(x86::Register::Rax, extended, ir::Width::I64,
                                       instruction.address);
            break;
        }
        case x86::Opcode::Cwde: {
            if (!instruction.operands.empty()) {
                throw std::runtime_error("internal decoder error: CWDE operands");
            }
            const auto value =
                builder.readGuestRegister(x86::Register::Rax, ir::Width::I16, instruction.address);
            const auto shifted =
                builder.shiftLeft(value, 48, ir::Width::I64, instruction.address);
            const auto extended =
                builder.shiftRightArithmetic(shifted, 48, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(x86::Register::Rax, extended, ir::Width::I32,
                                       instruction.address);
            break;
        }
        case x86::Opcode::MovMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: mov memory immediate count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto width = memory.width == 8    ? ir::Width::I8
                               : memory.width == 16 ? ir::Width::I16
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            std::optional<ir::ValueId> address;
            if (memory.ripRelative) {
                address = builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address);
            } else if (memory.hasBase) {
                address =
                    builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            }
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = address
                              ? builder.add(*address, index, ir::Width::I64, instruction.address)
                              : index;
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = address ? builder.add(*address, displacement, ir::Width::I64,
                                                instruction.address)
                                  : displacement;
            }
            if (memory.segment == x86::Segment::Gs) {
                const auto gsBase = builder.readGuestGsBase(instruction.address);
                address = address
                              ? builder.add(gsBase, *address, ir::Width::I64, instruction.address)
                              : gsBase;
            }
            if (!address) {
                address = builder.constant(0, ir::Width::I64, instruction.address);
            }
            const auto value = builder.constant(immediate.value, width, instruction.address);
            builder.storeGuest(*address, value, width, instruction.address);
            break;
        }
        case x86::Opcode::MovapsMemReg:
        case x86::Opcode::MovapdMemReg:
        case x86::Opcode::MovupsMemReg:
        case x86::Opcode::VmovupsMemReg:
        case x86::Opcode::MovdqaMemReg:
        case x86::Opcode::MovdquMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: movaps store operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            builder.storeGuestXmm(address, source,
                                  instruction.opcode == x86::Opcode::MovapsMemReg ||
                                      instruction.opcode == x86::Opcode::MovapdMemReg ||
                                      instruction.opcode == x86::Opcode::MovdqaMemReg,
                                  instruction.address);
            break;
        }
        case x86::Opcode::VmovupsYmmMemReg:
        case x86::Opcode::VmovapsYmmMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: YMM VMOVUPS store operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            if (memory.width != 256) {
                throw std::runtime_error("internal decoder error: YMM VMOVUPS store width");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            builder.storeGuestYmm(address, source,
                                  instruction.opcode == x86::Opcode::VmovapsYmmMemReg,
                                  instruction.address);
            break;
        }
        case x86::Opcode::MovapdRegReg:
        case x86::Opcode::MovapsRegReg:
        case x86::Opcode::MovdqaRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: aligned XMM register move operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto low = builder.readGuestXmmLane(source, false, instruction.address);
            const auto high = builder.readGuestXmmLane(source, true, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            builder.writeGuestXmmLane(destination, true, high, instruction.address);
            break;
        }
        case x86::Opcode::MovlhpsRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: MOVLHPS operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto sourceLow = builder.readGuestXmmLane(source, false, instruction.address);
            builder.writeGuestXmmLane(destination, true, sourceLow, instruction.address);
            break;
        }
        case x86::Opcode::MovlhpsRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: MOVLHPS memory operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (memory.width != 64 ||
                (memory.ripRelative ? memory.hasBase || memory.index.has_value()
                                    : !memory.hasBase) ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("unsupported qword MOVLHPS addressing");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                instruction.address);
            if (memory.displacement != 0) {
                const auto displacement = builder.constant(
                    static_cast<std::uint64_t>(memory.displacement),
                    ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64,
                                      instruction.address);
            }
            // Only the low lane is replaced; the high lane is preserved.
            const auto value =
                builder.loadGuest(address, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, value, instruction.address);
            break;
        }
        case x86::Opcode::MovddupRegReg:
        case x86::Opcode::MovddupRegMem: {
            const bool fromMemory =
                instruction.opcode == x86::Opcode::MovddupRegMem;
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: MOVDDUP operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            ir::ValueId duplicated{};
            if (!fromMemory) {
                const auto source =
                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
                duplicated = builder.readGuestXmmLane(source, false,
                                                      instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 64 ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error("unsupported qword MOVDDUP addressing");
                }
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.displacement != 0) {
                    const auto displacement = builder.constant(
                        static_cast<std::uint64_t>(memory.displacement),
                        ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                duplicated =
                    builder.loadGuest(address, ir::Width::I64, instruction.address);
            }
            builder.writeGuestXmmLane(destination, false, duplicated,
                                      instruction.address);
            builder.writeGuestXmmLane(destination, true, duplicated,
                                      instruction.address);
            break;
        }
        case x86::Opcode::PcmpeqqRegReg:
        case x86::Opcode::PcmpeqqRegMem: {
            const bool fromMemory =
                instruction.opcode == x86::Opcode::PcmpeqqRegMem;
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: PCMPEQQ operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            if (!fromMemory) {
                const auto source =
                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
                builder.compareEqualXmmQwords(destination, source,
                                              instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 128 ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase || memory.index.has_value()) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error(
                        "only RIP-relative or based PCMPEQQ xmm, m128 is implemented");
                }
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.displacement != 0) {
                    const auto displacement = builder.constant(
                        static_cast<std::uint64_t>(memory.displacement),
                        ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                // A single guest-memory helper performs the whole
                // read-and-compare: no IR value may stay live in a
                // caller-saved host register across the call.
                builder.compareEqualGuestQwordsXmm(address, destination,
                                                   instruction.address);
            }
            break;
        }
        case x86::Opcode::MovdXmmReg:
        case x86::Opcode::MovqXmmReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: MOVD XMM register operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto width =
                instruction.opcode == x86::Opcode::MovqXmmReg ? ir::Width::I64 : ir::Width::I32;
            const auto low = builder.readGuestRegister(source.reg, width, instruction.address);
            const auto zero = builder.constant(0, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            builder.writeGuestXmmLane(destination, true, zero, instruction.address);
            break;
        }
        case x86::Opcode::MovdXmmMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: MOVD XMM memory operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto low = builder.loadGuest(address, ir::Width::I32, instruction.address);
            const auto zero = builder.constant(0, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            builder.writeGuestXmmLane(destination, true, zero, instruction.address);
            break;
        }
        case x86::Opcode::MovsdRegMem:
        case x86::Opcode::MovsdMemXmm: {
            const bool isLoad = instruction.opcode == x86::Opcode::MovsdRegMem;
            const auto memory = std::get<x86::MemoryOperand>(
                instruction.operands[isLoad ? 1 : 0]);
            const auto xmm = std::get<x86::XmmRegisterOperand>(
                instruction.operands[isLoad ? 0 : 1]).reg;
            if (instruction.operands.size() != 2 || memory.width != 64 ||
                (memory.ripRelative ? memory.hasBase || memory.index.has_value()
                                    : !memory.hasBase) ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("unsupported qword scalar MOVSD addressing");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            if (isLoad) {
                const auto value =
                    builder.loadGuest(address, ir::Width::I64, instruction.address);
                builder.writeGuestXmmLane(xmm, false, value, instruction.address);
                builder.writeGuestXmmLane(
                    xmm, true,
                    builder.constant(0, ir::Width::I64, instruction.address),
                    instruction.address);
            } else {
                const auto value = builder.readGuestXmmLane(xmm, false, instruction.address);
                builder.storeGuest(address, value, ir::Width::I64, instruction.address);
            }
            break;
        }
        case x86::Opcode::Cvttsd2siRegXmm:
        case x86::Opcode::Cvttsd2siRegMem: {
            const bool fromMemory =
                instruction.opcode == x86::Opcode::Cvttsd2siRegMem;
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: CVTTSD2SI operand count");
            }
            const auto destination =
                std::get<x86::RegisterOperand>(instruction.operands[0]);
            if (destination.width != 32 && destination.width != 64) {
                throw std::runtime_error(
                    "only CVTTSD2SI r32/r64 is implemented");
            }
            const auto width =
                destination.width == 32 ? ir::Width::I32 : ir::Width::I64;
            ir::ValueId bits{};
            if (!fromMemory) {
                const auto source =
                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
                bits = builder.readGuestXmmLane(source, false,
                                                instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 64 ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error(
                        "unsupported CVTTSD2SI memory addressing");
                }
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.displacement != 0) {
                    const auto displacement = builder.constant(
                        static_cast<std::uint64_t>(memory.displacement),
                        ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                bits = builder.loadGuest(address, ir::Width::I64,
                                         instruction.address);
            }
            // The conversion helper is pure: the bits are consumed here, so
            // no IR value stays live across its call.
            builder.convertDoubleToInt(bits, destination.reg, width,
                                       instruction.address);
            break;
        }
        case x86::Opcode::Cvtsi2sdXmmReg:
        case x86::Opcode::Cvtsi2sdXmmMem: {
            const bool fromMemory = instruction.opcode == x86::Opcode::Cvtsi2sdXmmMem;
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: CVTSI2SD operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            ir::Width width = ir::Width::I32;
            ir::ValueId integer{};
            if (!fromMemory) {
                const auto source =
                    std::get<x86::RegisterOperand>(instruction.operands[1]);
                if ((source.width != 32 && source.width != 64) ||
                    source.byteOffset != 0) {
                    throw std::runtime_error(
                        "only 32-bit and 64-bit register CVTSI2SD is implemented");
                }
                width = source.width == 32 ? ir::Width::I32 : ir::Width::I64;
                integer = builder.readGuestRegister(source.reg, width,
                                                    instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if ((memory.width != 32 && memory.width != 64) ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error("unsupported CVTSI2SD memory addressing");
                }
                width = memory.width == 32 ? ir::Width::I32 : ir::Width::I64;
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.displacement != 0) {
                    const auto displacement = builder.constant(
                        static_cast<std::uint64_t>(memory.displacement),
                        ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                integer = builder.loadGuest(address, width, instruction.address);
            }
            // The conversion helper is pure: the integer is consumed here, so
            // no IR value stays live across its call.
            builder.convertIntToDoubleXmm(integer, destination, width,
                                          instruction.address);
            break;
        }
        case x86::Opcode::Cvtdq2pdXmmReg:
        case x86::Opcode::Cvtdq2pdXmmMem: {
            const bool fromMemory =
                instruction.opcode == x86::Opcode::Cvtdq2pdXmmMem;
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: CVTDQ2PD operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            ir::ValueId lowBits{};
            if (!fromMemory) {
                const auto source =
                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
                lowBits = builder.readGuestXmmLane(source, false,
                                                   instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 64 ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error(
                        "unsupported CVTDQ2PD memory addressing");
                }
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.index) {
                    auto index = builder.readGuestRegister(
                        *memory.index, ir::Width::I64, instruction.address);
                    if (memory.scale != 1) {
                        index = builder.shiftLeft(
                            index,
                            static_cast<std::uint8_t>(
                                std::countr_zero(memory.scale)),
                            ir::Width::I64, instruction.address);
                    }
                    address = builder.add(address, index, ir::Width::I64,
                                          instruction.address);
                }
                if (memory.displacement != 0) {
                    const auto displacement = builder.constant(
                        static_cast<std::uint64_t>(memory.displacement),
                        ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                lowBits = builder.loadGuest(address, ir::Width::I64,
                                            instruction.address);
            }
            // The conversion helper is pure: the low bits are consumed here,
            // so no IR value stays live across its call.
            builder.convertInt32x2ToDoubleXmm(lowBits, destination,
                                              instruction.address);
            break;
        }
        case x86::Opcode::Cvtss2sdXmmReg:
        case x86::Opcode::Cvtss2sdXmmMem: {
            const bool fromMemory =
                instruction.opcode == x86::Opcode::Cvtss2sdXmmMem;
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: CVTSS2SD operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            ir::ValueId floatBits{};
            if (!fromMemory) {
                const auto source =
                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
                floatBits = builder.readGuestXmmLane(source, false,
                                                     instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 32 ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error(
                        "unsupported CVTSS2SD memory addressing");
                }
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.index) {
                    auto index = builder.readGuestRegister(
                        *memory.index, ir::Width::I64, instruction.address);
                    if (memory.scale != 1) {
                        index = builder.shiftLeft(
                            index,
                            static_cast<std::uint8_t>(
                                std::countr_zero(memory.scale)),
                            ir::Width::I64, instruction.address);
                    }
                    address = builder.add(address, index, ir::Width::I64,
                                          instruction.address);
                }
                if (memory.displacement != 0) {
                    const auto displacement = builder.constant(
                        static_cast<std::uint64_t>(memory.displacement),
                        ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                floatBits = builder.loadGuest(address, ir::Width::I32,
                                              instruction.address);
            }
            // The conversion helper is pure: the float bits are consumed
            // here, so no IR value stays live across its call.
            builder.convertFloatToDoubleXmm(floatBits, destination,
                                            instruction.address);
            break;
        }
        case x86::Opcode::AddsdXmmReg:
        case x86::Opcode::AddsdXmmMem:
        case x86::Opcode::SubsdXmmReg:
        case x86::Opcode::SubsdXmmMem:
        case x86::Opcode::MulsdXmmReg:
        case x86::Opcode::MulsdXmmMem:
        case x86::Opcode::DivsdXmmReg:
        case x86::Opcode::DivsdXmmMem:
        case x86::Opcode::SqrtsdXmmReg:
        case x86::Opcode::SqrtsdXmmMem:
        case x86::Opcode::MinsdXmmReg:
        case x86::Opcode::MinsdXmmMem:
        case x86::Opcode::MaxsdXmmReg:
        case x86::Opcode::MaxsdXmmMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: scalar-double operand count");
            }
            const auto operation = instruction.opcode == x86::Opcode::AddsdXmmReg ||
                                           instruction.opcode == x86::Opcode::AddsdXmmMem
                                       ? std::uint8_t{0}
                                   : instruction.opcode == x86::Opcode::SubsdXmmReg ||
                                           instruction.opcode == x86::Opcode::SubsdXmmMem
                                       ? std::uint8_t{1}
                                   : instruction.opcode == x86::Opcode::MulsdXmmReg ||
                                           instruction.opcode == x86::Opcode::MulsdXmmMem
                                       ? std::uint8_t{2}
                                   : instruction.opcode == x86::Opcode::SqrtsdXmmReg ||
                                           instruction.opcode == x86::Opcode::SqrtsdXmmMem
                                       ? std::uint8_t{4}
                                   : instruction.opcode == x86::Opcode::MinsdXmmReg ||
                                           instruction.opcode == x86::Opcode::MinsdXmmMem
                                       ? std::uint8_t{5}
                                   : instruction.opcode == x86::Opcode::MaxsdXmmReg ||
                                           instruction.opcode == x86::Opcode::MaxsdXmmMem
                                       ? std::uint8_t{6}
                                       : std::uint8_t{3};
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const bool fromMemory =
                instruction.opcode == x86::Opcode::AddsdXmmMem ||
                instruction.opcode == x86::Opcode::SubsdXmmMem ||
                instruction.opcode == x86::Opcode::MulsdXmmMem ||
                instruction.opcode == x86::Opcode::DivsdXmmMem ||
                instruction.opcode == x86::Opcode::SqrtsdXmmMem ||
                instruction.opcode == x86::Opcode::MinsdXmmMem ||
                instruction.opcode == x86::Opcode::MaxsdXmmMem;
            ir::ValueId sourceBits{};
            if (!fromMemory) {
                const auto source =
                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
                sourceBits = builder.readGuestXmmLane(source, false,
                                                      instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 64 ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error(
                        "unsupported scalar-double memory addressing");
                }
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.displacement != 0) {
                    const auto displacement = builder.constant(
                        static_cast<std::uint64_t>(memory.displacement),
                        ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                sourceBits =
                    builder.loadGuest(address, ir::Width::I64, instruction.address);
            }
            // The arithmetic helper is pure: the source bits are consumed
            // here, so no IR value stays live across its call.
            builder.scalarDoubleXmm(sourceBits, destination, operation,
                                     instruction.address);
            break;
        }
        case x86::Opcode::DivpdRegReg:
        case x86::Opcode::DivpdRegMem:
        case x86::Opcode::SubpdRegReg:
        case x86::Opcode::SubpdRegMem:
        case x86::Opcode::MulpdRegReg:
        case x86::Opcode::MulpdRegMem:
        case x86::Opcode::AddpdRegReg:
        case x86::Opcode::AddpdRegMem:
        case x86::Opcode::SqrtpdRegReg:
        case x86::Opcode::SqrtpdRegMem: {
            const bool fromMemory =
                instruction.opcode == x86::Opcode::DivpdRegMem ||
                instruction.opcode == x86::Opcode::SubpdRegMem ||
                instruction.opcode == x86::Opcode::MulpdRegMem ||
                instruction.opcode == x86::Opcode::AddpdRegMem ||
                instruction.opcode == x86::Opcode::SqrtpdRegMem;
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: packed-double operand count");
            }
            const auto operation = instruction.opcode == x86::Opcode::AddpdRegReg ||
                                           instruction.opcode == x86::Opcode::AddpdRegMem
                                       ? std::uint8_t{0}
                                   : instruction.opcode == x86::Opcode::SubpdRegReg ||
                                           instruction.opcode == x86::Opcode::SubpdRegMem
                                       ? std::uint8_t{1}
                                   : instruction.opcode == x86::Opcode::MulpdRegReg ||
                                           instruction.opcode == x86::Opcode::MulpdRegMem
                                       ? std::uint8_t{2}
                                   : instruction.opcode == x86::Opcode::SqrtpdRegReg ||
                                           instruction.opcode == x86::Opcode::SqrtpdRegMem
                                       ? std::uint8_t{4}
                                       : std::uint8_t{3};
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            if (!fromMemory) {
                const auto source =
                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
                builder.arithmeticPackedDoubleXmm(destination, source, operation,
                                                  instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 128 ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase || memory.index.has_value()) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error(
                        "only RIP-relative or based packed-double xmm, m128 is implemented");
                }
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.displacement != 0) {
                    const auto displacement =
                        builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                         ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                // A single guest-memory helper performs the whole
                // read-and-combine: no IR value may stay live in a
                // caller-saved host register across the call.
                builder.arithmeticGuestMemoryPackedDoubleXmm(address, destination,
                                                             operation,
                                                             instruction.address);
            }
            break;
        }
        case x86::Opcode::UnpckhpsRegReg:
        case x86::Opcode::UnpckhpsRegMem: {
            const bool fromMemory =
                instruction.opcode == x86::Opcode::UnpckhpsRegMem;
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: UNPCKHPS operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            if (!fromMemory) {
                const auto source =
                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
                builder.unpackHighPackedSingleXmm(destination, source,
                                                  instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 128 ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase || memory.index.has_value()) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error(
                        "only RIP-relative or based UNPCKHPS xmm, m128 is implemented");
                }
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.displacement != 0) {
                    const auto displacement =
                        builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                         ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                // A single guest-memory helper performs the whole
                // read-and-interleave: no IR value may stay live in a
                // caller-saved host register across the call.
                builder.unpackHighGuestPackedSingleXmm(address, destination,
                                                       instruction.address);
            }
            break;
        }
        case x86::Opcode::HaddpdRegReg:
        case x86::Opcode::HaddpdRegMem: {
            const bool fromMemory =
                instruction.opcode == x86::Opcode::HaddpdRegMem;
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: HADDPD operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            if (!fromMemory) {
                const auto source =
                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
                builder.horizontalAddPackedDoubleXmm(destination, source,
                                                     instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 128 ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase || memory.index.has_value()) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error(
                        "only RIP-relative or based HADDPD xmm, m128 is implemented");
                }
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.displacement != 0) {
                    const auto displacement =
                        builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                         ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                // A single guest-memory helper performs the whole
                // read-and-add: no IR value may stay live in a
                // caller-saved host register across the call.
                builder.horizontalAddGuestPackedDoubleXmm(address, destination,
                                                          instruction.address);
            }
            break;
        }
        case x86::Opcode::UnpcklpsRegReg:
        case x86::Opcode::UnpcklpsRegMem: {
            const bool fromMemory =
                instruction.opcode == x86::Opcode::UnpcklpsRegMem;
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: UNPCKLPS operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            if (!fromMemory) {
                const auto source =
                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
                builder.unpackLowPackedSingleXmm(destination, source,
                                                 instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 128 ||
                    (memory.ripRelative
                         ? memory.hasBase || memory.index.has_value()
                         : !memory.hasBase || memory.index.has_value()) ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error(
                        "only RIP-relative or based UNPCKLPS xmm, m128 is implemented");
                }
                auto address =
                    memory.ripRelative
                        ? builder.constant(instruction.address.value + instruction.length,
                                           ir::Width::I64, instruction.address)
                        : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                    instruction.address);
                if (memory.displacement != 0) {
                    const auto displacement =
                        builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                         ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                // A single guest-memory helper performs the whole
                // read-and-interleave: no IR value may stay live in a
                // caller-saved host register across the call.
                builder.unpackLowGuestPackedSingleXmm(address, destination,
                                                      instruction.address);
            }
            break;
        }
        case x86::Opcode::MovlpsRegMem:
        case x86::Opcode::MovlpsMemXmm: {
            const bool isLoad = instruction.opcode == x86::Opcode::MovlpsRegMem;
            const auto memory = std::get<x86::MemoryOperand>(
                instruction.operands[isLoad ? 1 : 0]);
            const auto xmm = std::get<x86::XmmRegisterOperand>(
                instruction.operands[isLoad ? 0 : 1]).reg;
            if (instruction.operands.size() != 2 || memory.width != 64 ||
                (memory.ripRelative ? memory.hasBase || memory.index.has_value()
                                    : !memory.hasBase) ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("unsupported qword MOVLPS addressing");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            if (isLoad) {
                // Unlike MOVSD, MOVLPS preserves the destination high lane.
                const auto value =
                    builder.loadGuest(address, ir::Width::I64, instruction.address);
                builder.writeGuestXmmLane(xmm, false, value, instruction.address);
            } else {
                const auto value = builder.readGuestXmmLane(xmm, false, instruction.address);
                builder.storeGuest(address, value, ir::Width::I64, instruction.address);
            }
            break;
        }
        case x86::Opcode::MovdMemXmm:
        case x86::Opcode::MovssMemXmm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: scalar XMM memory-store operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            if (memory.width != 32 ||
                (memory.ripRelative ? memory.hasBase || memory.index.has_value()
                                    : !memory.hasBase) ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("unsupported dword scalar XMM store addressing");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto value = builder.readGuestXmmLane(source, false, instruction.address);
            builder.storeGuest(address, value, ir::Width::I32, instruction.address);
            break;
        }
        case x86::Opcode::MovssRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: scalar XMM memory-load operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (memory.width != 32 ||
                (memory.ripRelative ? memory.hasBase || memory.index.has_value()
                                    : !memory.hasBase) ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("unsupported dword scalar XMM load addressing");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            // MOVSS zeroes the upper three destination dwords; the I32 load
            // already zero-extends into the low lane.
            const auto value =
                builder.loadGuest(address, ir::Width::I32, instruction.address);
            builder.writeGuestXmmLane(destination, false, value, instruction.address);
            builder.writeGuestXmmLane(
                destination, true,
                builder.constant(0, ir::Width::I64, instruction.address),
                instruction.address);
            break;
        }
        case x86::Opcode::MovssXmmXmm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: MOVSS register operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            // Unlike the load form, register MOVSS keeps the destination's
            // upper three dwords.
            const auto sourceLow =
                builder.readGuestXmmLane(source, false, instruction.address);
            const auto destinationLow =
                builder.readGuestXmmLane(destination, false, instruction.address);
            const auto merged = builder.bitOr(
                builder.bitAnd(destinationLow,
                               builder.constant(0xFFFFFFFF00000000ULL, ir::Width::I64,
                                                instruction.address),
                               ir::Width::I64, instruction.address),
                builder.bitAnd(sourceLow,
                               builder.constant(0xFFFFFFFFULL, ir::Width::I64,
                                                instruction.address),
                               ir::Width::I64, instruction.address),
                ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, merged, instruction.address);
            break;
        }
        case x86::Opcode::MovdRegXmm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: MOVD register-XMM operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto value = builder.readGuestXmmLane(source, false, instruction.address);
            builder.writeGuestRegister(destination.reg, value, ir::Width::I32, instruction.address);
            break;
        }
        case x86::Opcode::MovqRegXmm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: MOVQ register-XMM operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            if (destination.width != 64) {
                throw std::runtime_error("only MOVQ r64, xmm is implemented");
            }
            const auto value = builder.readGuestXmmLane(source, false, instruction.address);
            builder.writeGuestRegister(destination.reg, value, ir::Width::I64,
                                       instruction.address);
            break;
        }
        case x86::Opcode::VmovupsYmmRegMem:
        case x86::Opcode::VmovapsYmmRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: YMM VMOVUPS load operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (memory.width != 256) {
                throw std::runtime_error("internal decoder error: YMM VMOVUPS load width");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            builder.loadGuestYmm(address, destination,
                                 instruction.opcode == x86::Opcode::VmovapsYmmRegMem,
                                 instruction.address);
            break;
        }
        case x86::Opcode::MovapsRegMem:
        case x86::Opcode::MovapdRegMem:
        case x86::Opcode::MovupsRegMem:
        case x86::Opcode::VmovupsRegMem:
        case x86::Opcode::MovdquRegMem:
        case x86::Opcode::MovdqaRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: movdqa load operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            builder.loadGuestXmm(address, destination,
                                 instruction.opcode == x86::Opcode::MovapsRegMem ||
                                     instruction.opcode == x86::Opcode::MovapdRegMem ||
                                     instruction.opcode == x86::Opcode::MovdqaRegMem,
                                 instruction.address);
            if (instruction.opcode == x86::Opcode::VmovupsRegMem) {
                const auto zero = builder.constant(0, ir::Width::I64, instruction.address);
                builder.writeGuestYmmUpperLane(destination, false, zero, instruction.address);
                builder.writeGuestYmmUpperLane(destination, true, zero, instruction.address);
            }
            break;
        }
        case x86::Opcode::MovqMemXmm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: movq store operands");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto value = builder.readGuestXmmLane(source, false, instruction.address);
            builder.storeGuest(address, value, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::MovqXmmMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: MOVQ XMM load operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto low = builder.loadGuest(address, ir::Width::I64, instruction.address);
            const auto zero = builder.constant(0, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            builder.writeGuestXmmLane(destination, true, zero, instruction.address);
            break;
        }
        case x86::Opcode::LeaRegRipRelative: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: lea operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto address = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto value = builder.constant(
                reg.width == 32 ? static_cast<std::uint32_t>(address.value) : address.value,
                reg.width == 32 ? ir::Width::I32 : ir::Width::I64, instruction.address);
            builder.writeGuestRegister(reg.reg, value,
                                       reg.width == 32 ? ir::Width::I32 : ir::Width::I64,
                                       instruction.address);
            break;
        }
        case x86::Opcode::LeaRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: lea memory operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            std::optional<ir::ValueId> result;
            if (memory.hasBase) {
                result =
                    builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            }
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                result = result ? builder.add(*result, index, ir::Width::I64, instruction.address)
                                : index;
            }
            if (memory.displacement != 0 || !result) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                result =
                    result ? builder.add(*result, displacement, ir::Width::I64, instruction.address)
                           : displacement;
            }
            if (destination.width == 32) {
                const auto mask = builder.constant(UINT32_MAX, ir::Width::I64, instruction.address);
                result = builder.bitAnd(*result, mask, ir::Width::I64, instruction.address);
            }
            builder.writeGuestRegister(destination.reg, *result,
                                       destination.width == 32 ? ir::Width::I32 : ir::Width::I64,
                                       instruction.address);
            break;
        }
        case x86::Opcode::AddRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: add operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (reg.width != 8 && reg.width != 32 && reg.width != 64) {
                throw std::runtime_error(
                    "only 8-bit, 32-bit, and 64-bit immediate ADD are implemented");
            }
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto result = builder.add(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateAddFlags(lhs, rhs, result, width, instruction.address);
            break;
        }
        case x86::Opcode::AdcRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: adc operand count");
            }
            const auto destination =
                std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (destination.width != source.width ||
                (destination.width != 32 && destination.width != 64)) {
                throw std::runtime_error("only ADC r32/r64, r32/r64 is implemented");
            }
            const auto width = destination.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto lhs =
                builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto rhs =
                builder.readGuestRegister(source.reg, width, instruction.address);
            const auto carry =
                builder.evaluateCondition(x86::Condition::Below, instruction.address);
            const auto sum = builder.add(lhs, rhs, width, instruction.address);
            const auto result = builder.add(sum, carry, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateAdcFlags(lhs, rhs, carry, width, instruction.address);
            break;
        }
        case x86::Opcode::AdcRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: adc memory operand count");
            }
            const auto destination =
                std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (destination.width != memory.width ||
                (destination.width != 32 && destination.width != 64)) {
                throw std::runtime_error("only ADC r32/r64, m32/m64 is implemented");
            }
            const auto width = destination.width == 32 ? ir::Width::I32 : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64,
                                      instruction.address);
            }
            const auto rhs = builder.loadGuest(address, width, instruction.address);
            const auto lhs =
                builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto carry =
                builder.evaluateCondition(x86::Condition::Below, instruction.address);
            const auto sum = builder.add(lhs, rhs, width, instruction.address);
            const auto result = builder.add(sum, carry, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateAdcFlags(lhs, rhs, carry, width, instruction.address);
            break;
        }
        case x86::Opcode::AdcRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: adc operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if ((reg.width != 8 && reg.width != 32 && reg.width != 64) ||
                reg.byteOffset != 0 ||
                (immediate.width != 8 && immediate.width != 32)) {
                throw std::runtime_error("only ADC r8/r32/r64, imm8/imm32 is implemented");
            }
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto carry =
                builder.evaluateCondition(x86::Condition::Below, instruction.address);
            const auto sum = builder.add(lhs, rhs, width, instruction.address);
            const auto result = builder.add(sum, carry, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateAdcFlags(lhs, rhs, carry, width, instruction.address);
            break;
        }
        case x86::Opcode::AddRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: register add operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (destination.width != source.width ||
                (destination.width != 8 && destination.width != 16 && destination.width != 32 &&
                 destination.width != 64)) {
                throw std::runtime_error(
                    "only 8-, 16-, 32-, and 64-bit register ADD are implemented");
            }
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 16 ? ir::Width::I16
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto rhs = builder.readGuestRegister(source.reg, width, instruction.address);
            const auto result = builder.add(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateAddFlags(lhs, rhs, result, width, instruction.address);
            break;
        }
        case x86::Opcode::AddRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: add memory operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (destination.width != memory.width ||
                (destination.width != 8 && destination.width != 16 &&
                 destination.width != 32 && destination.width != 64)) {
                throw std::runtime_error(
                    "only 8-bit, 16-bit, 32-bit, and 64-bit register-memory ADD are implemented");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 16 ? ir::Width::I16
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto rhs = builder.loadGuest(address, width, instruction.address);
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto result = builder.add(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateAddFlags(lhs, rhs, result, width, instruction.address);
            break;
        }
        case x86::Opcode::AddMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: memory-destination add operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != source.width ||
                (memory.width != 8 && memory.width != 16 && memory.width != 32 &&
                 memory.width != 64)) {
                throw std::runtime_error("only matching 8-, 16-, 32- and 64-bit "
                                          "memory-destination ADD is implemented");
            }
            const auto width = memory.width == 8    ? ir::Width::I8
                               : memory.width == 16 ? ir::Width::I16
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto sourceValue =
                builder.readGuestRegister(source.reg, width, instruction.address);
            builder.addGuestMemory(address, sourceValue, width, instruction.address);
            break;
        }
        case x86::Opcode::AddMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: memory immediate add operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (memory.width != 32 && memory.width != 64) {
                throw std::runtime_error(
                    "only 32- and 64-bit memory-destination short ADD is implemented");
            }
            if (immediate.width != 8) {
                throw std::runtime_error(
                    "only imm8 memory-destination short ADD is implemented");
            }
            const auto width = memory.width == 32 ? ir::Width::I32 : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : memory.hasBase
                      ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                      : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto sourceValue =
                builder.constant(immediate.value, width, instruction.address);
            builder.addGuestMemory(address, sourceValue, width, instruction.address);
            break;
        }
        case x86::Opcode::IncReg: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: increment operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 16 ? ir::Width::I16
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto original =
                builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto one = builder.constant(1, width, instruction.address);
            auto result = builder.add(original, one, width, instruction.address);
            if (width == ir::Width::I32) {
                const auto mask = builder.constant(UINT32_MAX, ir::Width::I64, instruction.address);
                result = builder.bitAnd(result, mask, ir::Width::I64, instruction.address);
            }
            builder.writeGuestRegister(destination.reg, result,
                                       width == ir::Width::I8 || width == ir::Width::I16
                                           ? width
                                           : ir::Width::I64,
                                       instruction.address);
            builder.updateIncFlags(original, result, width, instruction.address);
            break;
        }
        case x86::Opcode::DecReg: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: decrement operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 16 ? ir::Width::I16
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto original =
                builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto one = builder.constant(1, width, instruction.address);
            const auto result = builder.sub(original, one, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result,
                                       width == ir::Width::I8 || width == ir::Width::I16
                                           ? width
                                           : ir::Width::I64,
                                       instruction.address);
            builder.updateDecFlags(original, result, width, instruction.address);
            break;
        }
        case x86::Opcode::IncMem: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: memory increment operand");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            builder.incrementGuestMemory(address,
                                         memory.width == 8    ? ir::Width::I8
                                         : memory.width == 16 ? ir::Width::I16
                                         : memory.width == 32 ? ir::Width::I32
                                                              : ir::Width::I64,
                                         instruction.address);
            break;
        }
        case x86::Opcode::DecMem: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: memory decrement operand");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            builder.decrementGuestMemory(address,
                                         memory.width == 8    ? ir::Width::I8
                                         : memory.width == 16 ? ir::Width::I16
                                         : memory.width == 32 ? ir::Width::I32
                                                              : ir::Width::I64,
                                         instruction.address);
            break;
        }
        case x86::Opcode::LockBtsMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: LOCK BTS operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto bitIndex = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if ((memory.width != 32 && memory.width != 64) || bitIndex.width != 8) {
                throw std::runtime_error(
                    "only LOCK BTS dword/qword [base/index+disp], imm8 is implemented");
            }
            const auto width = memory.width == 32 ? ir::Width::I32 : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : memory.hasBase
                      ? builder.readGuestRegister(memory.base, ir::Width::I64,
                                                  instruction.address)
                      : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64,
                                      instruction.address);
            }
            builder.lockedBitSetGuestMemory(address,
                                            static_cast<std::uint8_t>(bitIndex.value),
                                            width, instruction.address);
            break;
        }
        case x86::Opcode::CmpxchgMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: cmpxchg memory operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != source.width ||
                (memory.width != 8 && memory.width != 32 && memory.width != 64) ||
                (source.byteOffset != 0 &&
                 (source.width != 8 || source.byteOffset != 1))) {
                throw std::runtime_error(
                    "only 8-, 32-, and 64-bit guest-memory CMPXCHG are implemented");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            ir::ValueId sourceValue{};
            if (source.byteOffset == 0) {
                sourceValue = builder.readGuestRegister(
                    source.reg,
                    source.width == 8    ? ir::Width::I8
                    : source.width == 32 ? ir::Width::I32
                                         : ir::Width::I64,
                    instruction.address);
            } else {
                // High-byte source (AH/CH/DH/BH): compare bits[15:8].
                const auto parent = builder.readGuestRegister(
                    source.reg, ir::Width::I64, instruction.address);
                const auto shifted = builder.shiftRightLogical(
                    parent, 8, ir::Width::I64, instruction.address);
                const auto laneMask =
                    builder.constant(0xFF, ir::Width::I64, instruction.address);
                sourceValue = builder.bitAnd(shifted, laneMask, ir::Width::I64,
                                             instruction.address);
            }
            builder.compareExchangeGuestMemory(address, sourceValue,
                                               memory.width == 8    ? ir::Width::I8
                                               : memory.width == 32 ? ir::Width::I32
                                                                    : ir::Width::I64,
                                               instruction.address);
            break;
        }
        case x86::Opcode::Cmpxchg16bMem: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: cmpxchg16b operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            if (memory.width != 128) {
                throw std::runtime_error("CMPXCHG16B requires a 128-bit memory operand");
            }
            const auto base =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                instruction.address);
            auto address = base;
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(base, displacement, ir::Width::I64, instruction.address);
            }
            builder.compareExchangeGuestPair(address, instruction.address);
            break;
        }
        case x86::Opcode::XchgMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: XCHG operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if ((memory.width != 8 && memory.width != 32 && memory.width != 64) ||
                source.width != memory.width || source.byteOffset != 0) {
                throw std::runtime_error(
                    "only matching 8-bit, 32-bit and 64-bit guest-memory XCHG with a low-byte source is implemented");
            }
            const auto width = memory.width == 8    ? ir::Width::I8
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto sourceValue =
                builder.readGuestRegister(source.reg, width, instruction.address);
            builder.exchangeGuestMemory(address, sourceValue, source.reg, width,
                                        instruction.address);
            break;
        }
        case x86::Opcode::LockAddMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: LOCK ADD operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != source.width ||
                (memory.width != 32 && memory.width != 64)) {
                throw std::runtime_error(
                    "only LOCK ADD dword/qword [base/RIP+disp], r32/r64 is implemented");
            }
            const auto width = memory.width == 32 ? ir::Width::I32 : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto sourceValue =
                builder.readGuestRegister(source.reg, width, instruction.address);
            builder.lockedAddGuestMemory(address, sourceValue, width, instruction.address);
            break;
        }
        case x86::Opcode::LockXaddMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: LOCK XADD operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != source.width ||
                (memory.width != 16 && memory.width != 32 && memory.width != 64)) {
                throw std::runtime_error(
                    "only LOCK XADD word/dword/qword [base/index+disp], r16/r32/r64 is implemented");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto sourceValue = builder.readGuestRegister(
                source.reg,
                source.width == 16   ? ir::Width::I16
                : source.width == 32 ? ir::Width::I32
                                     : ir::Width::I64,
                instruction.address);
            builder.lockedExchangeAddGuestMemory(
                address, sourceValue, source.reg,
                memory.width == 16   ? ir::Width::I16
                : memory.width == 32 ? ir::Width::I32
                                     : ir::Width::I64,
                instruction.address);
            break;
        }
        case x86::Opcode::LockOrMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: LOCK OR operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != source.width ||
                (memory.width != 32 && memory.width != 64)) {
                throw std::runtime_error(
                    "only LOCK OR dword/qword [base/RIP+disp], r32/r64 is implemented");
            }
            const auto width = memory.width == 32 ? ir::Width::I32 : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64,
                                      instruction.address);
            }
            const auto sourceValue =
                builder.readGuestRegister(source.reg, width, instruction.address);
            builder.lockedOrGuestMemory(address, sourceValue, width, instruction.address);
            break;
        }
        case x86::Opcode::LockOrMemImm:
        case x86::Opcode::LockAndMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: LOCK OR operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const bool wordForm =
                memory.width == 16 && (immediate.width == 8 || immediate.width == 16);
            const bool dwordForm =
                memory.width == 32 && (immediate.width == 8 || immediate.width == 32);
            const bool qwordForm =
                memory.width == 64 && (immediate.width == 8 || immediate.width == 32);
            const bool byteForm = memory.width == 8 && immediate.width == 8;
            if (!wordForm && !dwordForm && !qwordForm && !byteForm) {
                throw std::runtime_error("only LOCK OR/AND byte [base+disp], imm8, LOCK OR/AND "
                                         "word [base+disp], imm8/imm16, LOCK OR/AND dword "
                                         "[base+disp], imm8/imm32, and LOCK OR/AND qword "
                                         "[base+disp], imm8/imm32 are implemented");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64,
                                      instruction.address);
            }
            const auto width = memory.width == 8    ? ir::Width::I8
                               : memory.width == 16 ? ir::Width::I16
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            const auto value = builder.constant(immediate.value, width, instruction.address);
            if (instruction.opcode == x86::Opcode::LockOrMemImm) {
                builder.lockedOrGuestMemory(address, value, width, instruction.address);
            } else {
                builder.lockedAndGuestMemory(address, value, width, instruction.address);
            }
            break;
        }
        case x86::Opcode::LockIncMem:
        case x86::Opcode::LockDecMem: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: LOCK INC/DEC operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            if (memory.width != 32 && memory.width != 64) {
                throw std::runtime_error("only LOCK INC/DEC dword/qword [base+disp] is implemented");
            }
            const auto width = memory.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto base =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            auto address = base;
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(base, displacement, ir::Width::I64, instruction.address);
            }
            if (instruction.opcode == x86::Opcode::LockIncMem) {
                builder.lockedIncrementGuestMemory(address, width, instruction.address);
            } else {
                builder.lockedDecrementGuestMemory(address, width, instruction.address);
            }
            break;
        }
        case x86::Opcode::SubRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: sub operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (reg.width != 32 && reg.width != 64) {
                throw std::runtime_error("only 32-bit and 64-bit immediate SUB are implemented");
            }
            const auto width = reg.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto result = builder.sub(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateSubFlags(lhs, rhs, result, width, instruction.address);
            break;
        }
        case x86::Opcode::SbbRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: sbb operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if ((reg.width != 8 && reg.width != 16 && reg.width != 32 && reg.width != 64) ||
                immediate.width != 8) {
                throw std::runtime_error("only SBB r8/r16/r32/r64, imm8 is implemented");
            }
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 16 ? ir::Width::I16
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto borrow =
                builder.evaluateCondition(x86::Condition::Below, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto subtrahend = builder.add(rhs, borrow, width, instruction.address);
            const auto result = builder.sub(lhs, subtrahend, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateSbbFlags(lhs, rhs, borrow, width, instruction.address);
            break;
        }
        case x86::Opcode::SbbRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: register SBB operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (destination.reg != source.reg || destination.width != source.width ||
                (destination.width != 32 && destination.width != 64)) {
                throw std::runtime_error("only SBB r32/r64 with identical operands is implemented");
            }
            const auto width = destination.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto borrow =
                builder.evaluateCondition(x86::Condition::Below, instruction.address);
            const auto zero = builder.constant(0, width, instruction.address);
            const auto result = builder.sub(zero, borrow, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateSubFlags(zero, borrow, result, width, instruction.address);
            break;
        }
        case x86::Opcode::SubRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: register sub operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (destination.width != source.width ||
                (destination.width != 8 && destination.width != 32 && destination.width != 64)) {
                throw std::runtime_error(
                    "only matching 8-bit, 32-bit, and 64-bit register SUB are implemented");
            }
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto rhs = builder.readGuestRegister(source.reg, width, instruction.address);
            const auto result = builder.sub(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateSubFlags(lhs, rhs, result, width, instruction.address);
            break;
        }
        case x86::Opcode::SubRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: sub memory operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto width = destination.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto rhs = builder.loadGuest(address, width, instruction.address);
            // Read the destination after the load helper so no caller-saved IR value
            // remains live across the helper boundary.
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto result = builder.sub(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateSubFlags(lhs, rhs, result, width, instruction.address);
            break;
        }
        case x86::Opcode::SubMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: memory-destination SUB operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != source.width ||
                (memory.width != 8 && memory.width != 32 && memory.width != 64)) {
                throw std::runtime_error(
                    "only matching 8-, 32-, and 64-bit memory-destination SUB is implemented");
            }
            const auto width = memory.width == 8    ? ir::Width::I8
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto sourceValue =
                builder.readGuestRegister(source.reg, width, instruction.address);
            builder.subGuestMemory(address, sourceValue, width, instruction.address);
            break;
        }
        case x86::Opcode::ShlRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: shl operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto valueWidth = reg.width == 8 ? ir::Width::I64 : width;
            auto lhs = builder.readGuestRegister(reg.reg, valueWidth, instruction.address);
            if (reg.width == 8) {
                const auto byteMask = builder.constant(0xFF, ir::Width::I64, instruction.address);
                lhs = builder.bitAnd(lhs, byteMask, ir::Width::I64, instruction.address);
            }
            const auto count =
                static_cast<std::uint8_t>(immediate.value & (reg.width == 64 ? 0x3FU : 0x1FU));
            const auto result = builder.shiftLeft(lhs, count, valueWidth, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateShiftLeftFlags(lhs, result, count, width, instruction.address);
            break;
        }
        case x86::Opcode::ShlMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: shl memory operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (memory.width != 64) {
                throw std::runtime_error("internal decoder error: SHL memory width");
            }
            const auto base =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            const auto displacement =
                builder.constant(static_cast<std::uint64_t>(memory.displacement), ir::Width::I64,
                                 instruction.address);
            const auto address =
                builder.add(base, displacement, ir::Width::I64, instruction.address);
            const auto count = static_cast<std::uint8_t>(immediate.value & 0x3FU);
            builder.shiftLeftGuestMemory(address, count, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::ShrMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: shr memory operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (memory.width != 32 && memory.width != 64) {
                throw std::runtime_error("internal decoder error: SHR memory width");
            }
            const auto width = memory.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto base =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            const auto displacement =
                builder.constant(static_cast<std::uint64_t>(memory.displacement), ir::Width::I64,
                                 instruction.address);
            const auto address =
                builder.add(base, displacement, ir::Width::I64, instruction.address);
            const auto count =
                static_cast<std::uint8_t>(immediate.value & (memory.width == 64 ? 0x3FU : 0x1FU));
            builder.shiftRightLogicalGuestMemory(address, count, width, instruction.address);
            break;
        }
        case x86::Opcode::ShlRegCl: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: shl cl operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            auto lhs = builder.readGuestRegister(reg.reg, reg.width == 8 ? ir::Width::I64 : width,
                                                 instruction.address);
            if (reg.width == 8) {
                const auto byteMask = builder.constant(0xFF, ir::Width::I64, instruction.address);
                lhs = builder.bitAnd(lhs, byteMask, ir::Width::I64, instruction.address);
            }
            const auto count =
                builder.readGuestRegister(x86::Register::Rcx, ir::Width::I64, instruction.address);
            const auto countMask = builder.constant(reg.width == 64 ? 0x3F : 0x1F, ir::Width::I64,
                                                    instruction.address);
            const auto maskedCount =
                builder.bitAnd(count, countMask, ir::Width::I64, instruction.address);
            const auto result = builder.shiftLeft(lhs, maskedCount, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateShiftLeftFlags(lhs, result, maskedCount, width, instruction.address);
            break;
        }
        case x86::Opcode::ShrRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: shr operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 64 ? ir::Width::I64
                                                 : ir::Width::I32;
            auto lhs = builder.readGuestRegister(reg.reg, reg.width == 8 ? ir::Width::I64 : width,
                                                 instruction.address);
            if (reg.width == 8) {
                const auto mask = builder.constant(0xFF, ir::Width::I64, instruction.address);
                lhs = builder.bitAnd(lhs, mask, ir::Width::I64, instruction.address);
            }
            const auto count =
                static_cast<std::uint8_t>(immediate.value & (reg.width == 64 ? 0x3FU : 0x1FU));
            const auto result = builder.shiftRightLogical(lhs, count, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateShiftRightFlags(lhs, result, count, width, instruction.address);
            break;
        }
        case x86::Opcode::ShrRegCl: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: shr cl operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto width = reg.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto count =
                builder.readGuestRegister(x86::Register::Rcx, ir::Width::I64, instruction.address);
            const auto countMask = builder.constant(reg.width == 32 ? 0x1F : 0x3F, ir::Width::I64,
                                                    instruction.address);
            const auto maskedCount =
                builder.bitAnd(count, countMask, ir::Width::I64, instruction.address);
            const auto result =
                builder.shiftRightLogical(lhs, maskedCount, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateShiftRightFlags(lhs, result, maskedCount, width, instruction.address);
            break;
        }
        case x86::Opcode::SarRegCl: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: sar cl operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto width = reg.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto count =
                builder.readGuestRegister(x86::Register::Rcx, ir::Width::I64, instruction.address);
            const auto countMask = builder.constant(reg.width == 32 ? 0x1F : 0x3F, ir::Width::I64,
                                                    instruction.address);
            const auto maskedCount =
                builder.bitAnd(count, countMask, ir::Width::I64, instruction.address);
            const auto result =
                builder.shiftRightArithmetic(lhs, maskedCount, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateShiftRightArithmeticFlags(lhs, result, maskedCount, width,
                                                    instruction.address);
            break;
        }
        case x86::Opcode::SarRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: sar operands");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (reg.width != 32 && reg.width != 64) {
                throw std::runtime_error("internal decoder error: SAR width is not 32 or 64 bits");
            }
            const auto width = reg.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto lhs =
                builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto count = static_cast<std::uint8_t>(
                immediate.value & (reg.width == 64 ? 0x3FU : 0x1FU));
            const auto result =
                builder.shiftRightArithmetic(lhs, count, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateShiftRightArithmeticFlags(lhs, result, count, width,
                                                    instruction.address);
            break;
        }
        case x86::Opcode::RolRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: rol operands");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (reg.width != 16 && reg.width != 32 && reg.width != 64) {
                throw std::runtime_error("internal decoder error: ROL width");
            }
            const auto operandBits = reg.width;
            const auto count = static_cast<std::uint8_t>(
                (immediate.value & (reg.width == 64 ? 0x3FU : 0x1FU)) % operandBits);
            if (count == 0) {
                break;
            }
            const auto width = reg.width == 16   ? ir::Width::I16
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto unmasked = builder.readGuestRegister(reg.reg, width, instruction.address);
            auto original = unmasked;
            if (reg.width == 16) {
                const auto mask = builder.constant(0xFFFF, width, instruction.address);
                original = builder.bitAnd(unmasked, mask, width, instruction.address);
            }
            const auto left = builder.shiftLeft(original, count, width, instruction.address);
            const auto right =
                builder.shiftRightLogical(original, static_cast<std::uint8_t>(operandBits - count),
                                          width, instruction.address);
            const auto combined = builder.bitOr(left, right, width, instruction.address);
            builder.writeGuestRegister(reg.reg, combined, width, instruction.address);
            builder.updateRotateLeftFlags(combined, count, width, instruction.address);
            break;
        }
        case x86::Opcode::RolRegCl: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: ROL CL operands");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            if (reg.width != 32) {
                throw std::runtime_error("internal decoder error: ROL CL width");
            }
            const auto original =
                builder.readGuestRegister(reg.reg, ir::Width::I32, instruction.address);
            const auto cl =
                builder.readGuestRegister(x86::Register::Rcx, ir::Width::I64, instruction.address);
            const auto countMask = builder.constant(0x1F, ir::Width::I64, instruction.address);
            const auto count = builder.bitAnd(cl, countMask, ir::Width::I64, instruction.address);
            const auto left =
                builder.shiftLeft(original, count, ir::Width::I32, instruction.address);
            const auto zero = builder.constant(0, ir::Width::I64, instruction.address);
            const auto negativeCount =
                builder.sub(zero, count, ir::Width::I64, instruction.address);
            const auto rightCount =
                builder.bitAnd(negativeCount, countMask, ir::Width::I64, instruction.address);
            const auto right = builder.shiftRightLogical(original, rightCount, ir::Width::I32,
                                                         instruction.address);
            const auto result = builder.bitOr(left, right, ir::Width::I32, instruction.address);
            builder.writeGuestRegister(reg.reg, result, ir::Width::I32, instruction.address);
            builder.updateRotateLeftFlags(result, count, ir::Width::I32, instruction.address);
            break;
        }
        case x86::Opcode::RorRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: ror operands");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (reg.width != 64) {
                throw std::runtime_error("internal decoder error: ROR width");
            }
            const auto count = static_cast<std::uint8_t>(immediate.value & 0x3FU);
            if (count == 0) {
                break;
            }
            const auto original =
                builder.readGuestRegister(reg.reg, ir::Width::I64, instruction.address);
            const auto right =
                builder.shiftRightLogical(original, count, ir::Width::I64, instruction.address);
            const auto left = builder.shiftLeft(original, static_cast<std::uint8_t>(64U - count),
                                                ir::Width::I64, instruction.address);
            const auto result = builder.bitOr(right, left, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(reg.reg, result, ir::Width::I64, instruction.address);
            builder.updateRotateRightFlags(result, count, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::RorRegCl: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: ror cl operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            if (reg.width != 64) {
                throw std::runtime_error("only 64-bit ROR by CL is implemented");
            }
            const auto original =
                builder.readGuestRegister(reg.reg, ir::Width::I64, instruction.address);
            const auto rawCount =
                builder.readGuestRegister(x86::Register::Rcx, ir::Width::I64,
                                          instruction.address);
            const auto countMask =
                builder.constant(0x3F, ir::Width::I64, instruction.address);
            const auto count =
                builder.bitAnd(rawCount, countMask, ir::Width::I64, instruction.address);
            const auto right =
                builder.shiftRightLogical(original, count, ir::Width::I64,
                                          instruction.address);
            // Register-form shifts mask the count to six bits, so a zero
            // count also zeroes the complement: the result is the identity,
            // and the flag helper independently skips count zero.
            const auto complement = builder.sub(
                builder.constant(64, ir::Width::I64, instruction.address), count,
                ir::Width::I64, instruction.address);
            const auto left = builder.shiftLeft(original, complement, ir::Width::I64,
                                                instruction.address);
            const auto result = builder.bitOr(right, left, ir::Width::I64,
                                              instruction.address);
            builder.writeGuestRegister(reg.reg, result, ir::Width::I64, instruction.address);
            builder.updateRotateRightFlags(result, count, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::BswapReg: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: bswap operand");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            if (reg.width != 32 && reg.width != 64) {
                throw std::runtime_error("internal decoder error: BSWAP width");
            }
            const auto width = reg.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto original = builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto result = builder.byteSwap(original, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            break;
        }
        case x86::Opcode::NotReg: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: not operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            if (reg.width != 8 && reg.width != 32 && reg.width != 64) {
                throw std::runtime_error("only 8-, 32-, and 64-bit NOT are implemented");
            }
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto valueWidth = reg.width == 8 ? ir::Width::I64 : width;
            const auto original =
                builder.readGuestRegister(reg.reg, valueWidth, instruction.address);
            const auto mask = builder.constant(reg.width == 8    ? 0xFF
                                               : reg.width == 32 ? UINT32_MAX
                                                                 : UINT64_MAX,
                                               valueWidth, instruction.address);
            const auto result = builder.bitXor(original, mask, valueWidth, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            break;
        }
        case x86::Opcode::NegReg: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: neg operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            if (reg.width != 8 && reg.width != 16 && reg.width != 32 && reg.width != 64) {
                throw std::runtime_error("only 8-, 16-, 32-, and 64-bit NEG are implemented");
            }
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 16 ? ir::Width::I16
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto zero = builder.constant(0, width, instruction.address);
            const auto original = builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto result = builder.sub(zero, original, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateSubFlags(zero, original, result, width, instruction.address);
            break;
        }
        case x86::Opcode::MulReg: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: mul operand count");
            }
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[0]);
            if (source.width != 32 && source.width != 64) {
                throw std::runtime_error("only unsigned dword and qword MUL are implemented");
            }
            const auto width = source.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto lhs =
                builder.readGuestRegister(x86::Register::Rax, width, instruction.address);
            const auto rhs = builder.readGuestRegister(source.reg, width, instruction.address);
            if (source.width == 32) {
                const auto product =
                    builder.multiplyLow(lhs, rhs, ir::Width::I64, instruction.address);
                const auto high =
                    builder.shiftRightLogical(product, 32, ir::Width::I64, instruction.address);
                builder.writeGuestRegister(x86::Register::Rax, product, ir::Width::I32,
                                           instruction.address);
                builder.writeGuestRegister(x86::Register::Rdx, high, ir::Width::I32,
                                           instruction.address);
                builder.updateMultiplyFlags(high, ir::Width::I32, instruction.address);
            } else {
                const auto low = builder.multiplyLow(lhs, rhs, ir::Width::I64, instruction.address);
                const auto high =
                    builder.multiplyHighUnsigned(lhs, rhs, ir::Width::I64, instruction.address);
                builder.writeGuestRegister(x86::Register::Rax, low, ir::Width::I64,
                                           instruction.address);
                builder.writeGuestRegister(x86::Register::Rdx, high, ir::Width::I64,
                                           instruction.address);
                builder.updateMultiplyFlags(high, ir::Width::I64, instruction.address);
            }
            break;
        }
        case x86::Opcode::ImulReg: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: imul operand count");
            }
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[0]);
            if (source.width != 64) {
                throw std::runtime_error("only qword register IMUL is implemented");
            }
            const auto lhs =
                builder.readGuestRegister(x86::Register::Rax, ir::Width::I64, instruction.address);
            const auto rhs =
                builder.readGuestRegister(source.reg, ir::Width::I64, instruction.address);
            const auto low = builder.multiplyLow(lhs, rhs, ir::Width::I64, instruction.address);
            const auto high =
                builder.multiplyHighSigned(lhs, rhs, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(x86::Register::Rax, low, ir::Width::I64,
                                       instruction.address);
            builder.writeGuestRegister(x86::Register::Rdx, high, ir::Width::I64,
                                       instruction.address);
            builder.updateSignedMultiplyFlags(lhs, rhs, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::MulMem: {
            if (instruction.operands.size() != 1 ||
                !std::holds_alternative<x86::MemoryOperand>(instruction.operands[0])) {
                throw std::runtime_error("internal decoder error: memory mul operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            if ((memory.width != 32 && memory.width != 64) || !memory.hasBase ||
                memory.ripRelative || memory.index ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("only based dword/qword memory MUL is implemented");
            }
            const auto width = memory.width == 32 ? ir::Width::I32 : ir::Width::I64;
            auto address =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto rhs = builder.loadGuest(address, width, instruction.address);
            // Read RAX after the load helper so no caller-saved IR value
            // remains live across the helper boundary.
            const auto lhs =
                builder.readGuestRegister(x86::Register::Rax, width, instruction.address);
            if (memory.width == 32) {
                const auto product =
                    builder.multiplyLow(lhs, rhs, ir::Width::I64, instruction.address);
                const auto high =
                    builder.shiftRightLogical(product, 32, ir::Width::I64, instruction.address);
                builder.writeGuestRegister(x86::Register::Rax, product, ir::Width::I32,
                                           instruction.address);
                builder.writeGuestRegister(x86::Register::Rdx, high, ir::Width::I32,
                                           instruction.address);
                builder.updateMultiplyFlags(high, ir::Width::I32, instruction.address);
            } else {
                const auto low = builder.multiplyLow(lhs, rhs, ir::Width::I64, instruction.address);
                const auto high =
                    builder.multiplyHighUnsigned(lhs, rhs, ir::Width::I64, instruction.address);
                builder.writeGuestRegister(x86::Register::Rax, low, ir::Width::I64,
                                           instruction.address);
                builder.writeGuestRegister(x86::Register::Rdx, high, ir::Width::I64,
                                           instruction.address);
                builder.updateMultiplyFlags(high, ir::Width::I64, instruction.address);
            }
            break;
        }
        case x86::Opcode::ImulMem: {
            if (instruction.operands.size() != 1 ||
                !std::holds_alternative<x86::MemoryOperand>(instruction.operands[0])) {
                throw std::runtime_error("internal decoder error: memory imul operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            if (memory.width != 64 || !memory.hasBase || memory.ripRelative || memory.index ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("only based qword memory IMUL is implemented");
            }
            auto address =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto rhs = builder.loadGuest(address, ir::Width::I64, instruction.address);
            // Read RAX after the load helper so no caller-saved IR value
            // remains live across the helper boundary.
            const auto lhs =
                builder.readGuestRegister(x86::Register::Rax, ir::Width::I64, instruction.address);
            const auto low = builder.multiplyLow(lhs, rhs, ir::Width::I64, instruction.address);
            const auto high =
                builder.multiplyHighSigned(lhs, rhs, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(x86::Register::Rax, low, ir::Width::I64,
                                       instruction.address);
            builder.writeGuestRegister(x86::Register::Rdx, high, ir::Width::I64,
                                       instruction.address);
            builder.updateSignedMultiplyFlags(lhs, rhs, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::DivReg: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: div operand count");
            }
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[0]);
            if (source.width != 8 && source.width != 32 && source.width != 64) {
                throw std::runtime_error(
                    "only unsigned byte, dword, and qword register DIV are implemented");
            }
            const auto divisor = builder.readGuestRegister(source.reg,
                                                           source.width == 8    ? ir::Width::I8
                                                           : source.width == 32 ? ir::Width::I32
                                                                                : ir::Width::I64,
                                                           instruction.address);
            if (source.width == 8) {
                builder.divideUnsignedByte(divisor, instruction.address);
            } else if (source.width == 32) {
                builder.divideUnsignedDword(divisor, instruction.address);
            } else {
                builder.divideUnsignedQword(divisor, instruction.address);
            }
            break;
        }
        case x86::Opcode::DivMem: {
            if (instruction.operands.size() != 1 ||
                !std::holds_alternative<x86::MemoryOperand>(instruction.operands[0])) {
                throw std::runtime_error("internal decoder error: memory div operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            if (memory.width != 32 || !memory.hasBase || memory.ripRelative || memory.index ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("only based dword memory DIV is implemented");
            }
            auto address =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto divisor = builder.loadGuest(address, ir::Width::I32, instruction.address);
            builder.divideUnsignedDword(divisor, instruction.address);
            break;
        }
        case x86::Opcode::IdivReg: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: idiv operand count");
            }
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[0]);
            if (source.width != 32) {
                throw std::runtime_error("only signed dword register IDIV is implemented");
            }
            const auto divisor =
                builder.readGuestRegister(source.reg, ir::Width::I32, instruction.address);
            builder.divideSignedDword(divisor, instruction.address);
            break;
        }
        case x86::Opcode::ImulRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: imul operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (destination.width != source.width ||
                (destination.width != 32 && destination.width != 64)) {
                throw std::runtime_error(
                    "only matching 32-bit and 64-bit register IMUL are implemented");
            }
            const auto width = destination.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto rhs = builder.readGuestRegister(source.reg, width, instruction.address);
            const auto result = builder.multiplyLow(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateSignedMultiplyFlags(lhs, rhs, width, instruction.address);
            break;
        }
        case x86::Opcode::ImulRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: IMUL memory operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if ((destination.width != 32 && destination.width != 64) ||
                (memory.width != 32 && memory.width != 64) ||
                (memory.width == 32 && destination.width != 32) ||
                (memory.ripRelative
                     ? memory.hasBase || memory.index.has_value()
                     : !memory.hasBase)) {
                throw std::runtime_error(
                    "only 32-bit and 64-bit register-from-memory IMUL are implemented");
            }
            // The legacy REX decoder emits a 32-bit destination with a qword
            // memory operand; keep its established 64-bit lowering there.
            const auto width = destination.width == 32 && memory.width == 32
                                   ? ir::Width::I32
                                   : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                instruction.address);
            if (memory.index) {
                auto index = builder.readGuestRegister(
                    *memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index,
                        static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address =
                    builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64,
                                      instruction.address);
            }
            const auto rhs = builder.loadGuest(address, width, instruction.address);
            // Guest-memory helpers may clobber host temporaries. Materialize the
            // register operand only after the load returns successfully.
            const auto lhs =
                builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto result = builder.multiplyLow(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width,
                                       instruction.address);
            builder.updateSignedMultiplyFlags(lhs, rhs, width, instruction.address);
            break;
        }
        case x86::Opcode::ImulRegRegImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: immediate imul operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            if (destination.width != source.width ||
                (destination.width != 32 && destination.width != 64)) {
                throw std::runtime_error(
                    "only matching 32-bit and 64-bit immediate IMUL are implemented");
            }
            const auto width = destination.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(source.reg, width, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto result = builder.multiplyLow(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateSignedMultiplyFlags(lhs, rhs, width, instruction.address);
            break;
        }
        case x86::Opcode::ImulRegMemImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error(
                    "internal decoder error: memory immediate IMUL operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            if (destination.width != memory.width ||
                (destination.width != 32 && destination.width != 64) || memory.index ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("unsupported memory immediate IMUL operand shape");
            }
            const auto width = destination.width == 32 ? ir::Width::I32 : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto lhs = builder.loadGuest(address, width, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto result = builder.multiplyLow(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateSignedMultiplyFlags(lhs, rhs, width, instruction.address);
            break;
        }
        case x86::Opcode::ShrdRegRegImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: shrd operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            const auto original =
                builder.readGuestRegister(destination.reg, ir::Width::I64, instruction.address);
            const auto high =
                builder.readGuestRegister(source.reg, ir::Width::I64, instruction.address);
            const auto count = static_cast<std::uint8_t>(immediate.value & 0x3FU);
            const auto result = builder.shiftRightDouble(original, high, count, ir::Width::I64,
                                                         instruction.address);
            builder.writeGuestRegister(destination.reg, result, ir::Width::I64,
                                       instruction.address);
            builder.updateShiftRightDoubleFlags(original, result, count, ir::Width::I64,
                                                instruction.address);
            break;
        }
        case x86::Opcode::ShldRegRegImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: SHLD operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            if (destination.width != 64 || source.width != 64) {
                throw std::runtime_error("internal decoder error: SHLD width");
            }
            const auto original =
                builder.readGuestRegister(destination.reg, ir::Width::I64, instruction.address);
            const auto sourceValue =
                builder.readGuestRegister(source.reg, ir::Width::I64, instruction.address);
            const auto count = static_cast<std::uint8_t>(immediate.value & 0x3FU);
            auto result = original;
            if (count != 0) {
                const auto left =
                    builder.shiftLeft(original, count, ir::Width::I64, instruction.address);
                const auto right =
                    builder.shiftRightLogical(sourceValue, static_cast<std::uint8_t>(64U - count),
                                              ir::Width::I64, instruction.address);
                result = builder.bitOr(left, right, ir::Width::I64, instruction.address);
            }
            builder.writeGuestRegister(destination.reg, result, ir::Width::I64,
                                       instruction.address);
            builder.updateShiftLeftFlags(original, result, count, ir::Width::I64,
                                         instruction.address);
            break;
        }
        case x86::Opcode::OrRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: or operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 16 ? ir::Width::I16
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto rhs = builder.readGuestRegister(source.reg, width, instruction.address);
            const auto result = builder.bitOr(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::OrRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: OR memory-load operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (destination.width != memory.width ||
                (destination.width != 8 && destination.width != 16 &&
                 destination.width != 32 && destination.width != 64)) {
                throw std::runtime_error(
                    "only byte/word/dword/qword register-from-memory OR is implemented");
            }
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 16 ? ir::Width::I16
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto rhs = builder.loadGuest(address, width, instruction.address);
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto result = builder.bitOr(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::OrMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: memory or operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != source.width ||
                (memory.width != 8 && memory.width != 16 && memory.width != 32 &&
                 memory.width != 64)) {
                throw std::runtime_error("only matching byte, word, dword, and qword "
                                          "memory-destination OR is implemented");
            }
            const auto width = memory.width == 8    ? ir::Width::I8
                               : memory.width == 16 ? ir::Width::I16
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto sourceValue =
                builder.readGuestRegister(source.reg, width, instruction.address);
            builder.orGuestMemory(address, sourceValue, width, instruction.address);
            break;
        }
        case x86::Opcode::OrMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: memory immediate or operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto byteForm = memory.width == 8 && immediate.width == 8;
            const auto wordShortForm = memory.width == 16 && immediate.width == 8;
            const auto wordFullForm = memory.width == 16 && immediate.width == 16;
            const auto dwordShortForm = memory.width == 32 && immediate.width == 8;
            const auto qwordShortForm = memory.width == 64 && immediate.width == 8;
            const auto dwordFullForm = memory.width == 32 && immediate.width == 32;
            const auto qwordFullForm = memory.width == 64 && immediate.width == 32;
            if ((!byteForm && !wordShortForm && !wordFullForm && !dwordShortForm &&
                 !qwordShortForm && !dwordFullForm && !qwordFullForm) ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("only OR byte [memory], imm8, OR word [memory], "
                                          "imm8/imm16, and OR dword/qword [memory], imm8/imm32 "
                                          "are implemented");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : memory.hasBase
                      ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                      : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto width = byteForm   ? ir::Width::I8
                               : wordShortForm || wordFullForm ? ir::Width::I16
                               : dwordShortForm || dwordFullForm ? ir::Width::I32
                                                                 : ir::Width::I64;
            const auto sourceValue =
                builder.constant(immediate.value, width, instruction.address);
            builder.orGuestMemory(address, sourceValue, width, instruction.address);
            break;
        }
        case x86::Opcode::OrRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: or immediate operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto result = builder.bitOr(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::XorRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: xor operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            ir::ValueId result;
            if (width != ir::Width::I8 && destination.reg == source.reg) {
                result = builder.constant(0, width, instruction.address);
            } else {
                const auto lhs =
                    builder.readGuestRegister(destination.reg, width, instruction.address);
                const auto rhs = builder.readGuestRegister(source.reg, width, instruction.address);
                result = builder.bitXor(lhs, rhs, width, instruction.address);
            }
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::XorRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: xor memory operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto rhs = builder.loadGuest(address, width, instruction.address);
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto result = builder.bitXor(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::XorRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: xor immediate operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto result = builder.bitXor(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::AndRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: register and operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 16 ? ir::Width::I16
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto rhs = builder.readGuestRegister(source.reg, width, instruction.address);
            const auto result = builder.bitAnd(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::AndRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: and memory operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (destination.width != memory.width ||
                (destination.width != 8 && destination.width != 32 && destination.width != 64)) {
                throw std::runtime_error(
                    "only byte, dword, and qword register-from-memory AND are implemented");
            }
            const auto width = destination.width == 8    ? ir::Width::I8
                               : destination.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto rhs = builder.loadGuest(address, width, instruction.address);
            const auto lhs = builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto result = builder.bitAnd(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::AndMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: memory-destination AND operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != source.width ||
                (memory.width != 16 && memory.width != 32 && memory.width != 64)) {
                throw std::runtime_error(
                    "only matching 16-, 32- and 64-bit memory-destination AND is implemented");
            }
            const auto width = memory.width == 16    ? ir::Width::I16
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto sourceValue =
                builder.readGuestRegister(source.reg, width, instruction.address);
            builder.andGuestMemory(address, sourceValue, width, instruction.address);
            break;
        }
        case x86::Opcode::AndMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: memory immediate AND operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            const auto byteForm = memory.width == 8 && immediate.width == 8;
            const auto wordForm = memory.width == 16 && immediate.width == 16;
            const auto dwordShortForm = memory.width == 32 && immediate.width == 8;
            const auto qwordShortForm = memory.width == 64 && immediate.width == 8;
            const auto dwordFullForm = memory.width == 32 && immediate.width == 32;
            const auto qwordFullForm = memory.width == 64 && immediate.width == 32;
            if ((!byteForm && !wordForm && !dwordShortForm && !qwordShortForm &&
                 !dwordFullForm && !qwordFullForm) ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("only AND byte [memory], imm8, AND word [memory], imm16, "
                                          "and AND dword/qword [memory], imm8/imm32 are implemented");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto width = byteForm        ? ir::Width::I8
                               : wordForm        ? ir::Width::I16
                               : dwordShortForm || dwordFullForm ? ir::Width::I32
                                                                 : ir::Width::I64;
            const auto source = builder.constant(immediate.value, width, instruction.address);
            builder.andGuestMemory(address, source, width, instruction.address);
            break;
        }
        case x86::Opcode::BitScanForwardRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: bsf operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            builder.bitScanForward(destination.reg, source.reg,
                                   destination.width == 32 ? ir::Width::I32 : ir::Width::I64,
                                   instruction.address);
            break;
        }
        case x86::Opcode::BitTestRegImm: {
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto bitIndex = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (source.width != 32 && source.width != 64) {
                throw std::runtime_error("only 32-bit and 64-bit register BT are implemented");
            }
            const auto width = source.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto value = builder.readGuestRegister(source.reg, width, instruction.address);
            builder.updateBitTestFlags(value, static_cast<std::uint8_t>(bitIndex.value), width,
                                       instruction.address);
            break;
        }
        case x86::Opcode::BitSetRegImm:
        case x86::Opcode::BitResetRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: BTS/BTR operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto bitIndex = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (destination.width != 32 && destination.width != 64) {
                throw std::runtime_error("only 32-bit and 64-bit register BTS/BTR are implemented");
            }
            const auto width = destination.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto maskedBit = static_cast<std::uint8_t>(
                bitIndex.value & (destination.width == 32 ? 0x1FU : 0x3FU));
            const auto value =
                builder.readGuestRegister(destination.reg, width, instruction.address);
            const auto mask =
                builder.constant(std::uint64_t{1} << maskedBit, width, instruction.address);
            const auto result =
                instruction.opcode == x86::Opcode::BitSetRegImm
                    ? builder.bitOr(value, mask, width, instruction.address)
                    : builder.bitAnd(value,
                                     builder.constant(~(std::uint64_t{1} << maskedBit), width,
                                                      instruction.address),
                                     width, instruction.address);
            builder.writeGuestRegister(destination.reg, result, width, instruction.address);
            builder.updateBitTestFlags(value, maskedBit, width, instruction.address);
            break;
        }
        case x86::Opcode::BitTestRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: BT register operand count");
            }
            const auto valueRegister = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto indexRegister = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (valueRegister.width != indexRegister.width ||
                (valueRegister.width != 32 && valueRegister.width != 64)) {
                throw std::runtime_error(
                    "only matching 32-bit and 64-bit register-indexed BT is implemented");
            }
            const auto width = valueRegister.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto value =
                builder.readGuestRegister(valueRegister.reg, width, instruction.address);
            const auto index =
                builder.readGuestRegister(indexRegister.reg, width, instruction.address);
            const auto indexMask =
                builder.constant(valueRegister.width - 1U, width, instruction.address);
            const auto maskedIndex = builder.bitAnd(index, indexMask, width, instruction.address);
            const auto shifted =
                builder.shiftRightLogical(value, maskedIndex, width, instruction.address);
            builder.updateBitTestFlags(shifted, 0, width, instruction.address);
            break;
        }
        case x86::Opcode::BitSetRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: BTS register operand count");
            }
            const auto valueRegister = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto indexRegister = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (valueRegister.width != indexRegister.width ||
                (valueRegister.width != 32 && valueRegister.width != 64)) {
                throw std::runtime_error(
                    "only matching 32-bit and 64-bit register-indexed BTS is implemented");
            }
            const auto width = valueRegister.width == 32 ? ir::Width::I32 : ir::Width::I64;
            const auto value =
                builder.readGuestRegister(valueRegister.reg, width, instruction.address);
            const auto index =
                builder.readGuestRegister(indexRegister.reg, width, instruction.address);
            const auto indexMask =
                builder.constant(valueRegister.width - 1U, width, instruction.address);
            const auto maskedIndex = builder.bitAnd(index, indexMask, width, instruction.address);
            const auto shifted =
                builder.shiftRightLogical(value, maskedIndex, width, instruction.address);
            const auto one = builder.constant(1, width, instruction.address);
            const auto mask = builder.shiftLeft(one, maskedIndex, width, instruction.address);
            const auto result = builder.bitOr(value, mask, width, instruction.address);
            builder.writeGuestRegister(valueRegister.reg, result, width, instruction.address);
            builder.updateBitTestFlags(shifted, 0, width, instruction.address);
            break;
        }
        case x86::Opcode::BitTestMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: BT memory operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto bitIndex = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if ((memory.width != 32 && memory.width != 64) || bitIndex.width != 8 ||
                (memory.ripRelative ? memory.hasBase || memory.index.has_value()
                                    : !memory.hasBase) ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error(
                    "only based 32-bit and 64-bit BT memory operands are implemented");
            }
            const auto width = memory.width == 32 ? ir::Width::I32 : ir::Width::I64;
            // Like the register form, an immediate bit offset is masked to
            // the operand width; unlike a register offset it never strides
            // into a neighboring unit (pinned by differential tests).
            const auto maskedBit = static_cast<std::uint8_t>(
                bitIndex.value & (memory.width == 32 ? 0x1FU : 0x3FU));
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                instruction.address);
            if (memory.index) {
                auto index = builder.readGuestRegister(
                    *memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index,
                        static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address =
                    builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement = builder.constant(
                    static_cast<std::uint64_t>(memory.displacement),
                    ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64,
                                      instruction.address);
            }
            const auto value = builder.loadGuest(address, width, instruction.address);
            builder.updateBitTestFlags(value, maskedBit, width, instruction.address);
            break;
        }
        case x86::Opcode::BitScanReverseRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: bsr operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            builder.bitScanReverse(destination.reg, source.reg,
                                   destination.width == 32 ? ir::Width::I32 : ir::Width::I64,
                                   instruction.address);
            break;
        }
        case x86::Opcode::XorpsRegReg:
        case x86::Opcode::XorpdRegReg:
        case x86::Opcode::PxorRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: vector xor operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto destinationLow =
                builder.readGuestXmmLane(destination, false, instruction.address);
            const auto sourceLow = builder.readGuestXmmLane(source, false, instruction.address);
            const auto low =
                builder.bitXor(destinationLow, sourceLow, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            const auto destinationHigh =
                builder.readGuestXmmLane(destination, true, instruction.address);
            const auto sourceHigh = builder.readGuestXmmLane(source, true, instruction.address);
            const auto high =
                builder.bitXor(destinationHigh, sourceHigh, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, true, high, instruction.address);
            break;
        }
        case x86::Opcode::VxorpsRegRegReg:
        case x86::Opcode::VxorpsYmmRegRegReg: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: VXORPS operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto first = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto second = std::get<x86::XmmRegisterOperand>(instruction.operands[2]).reg;
            const auto firstLow = builder.readGuestXmmLane(first, false, instruction.address);
            const auto secondLow = builder.readGuestXmmLane(second, false, instruction.address);
            const auto low =
                builder.bitXor(firstLow, secondLow, ir::Width::I64, instruction.address);
            const auto firstHigh = builder.readGuestXmmLane(first, true, instruction.address);
            const auto secondHigh = builder.readGuestXmmLane(second, true, instruction.address);
            const auto high =
                builder.bitXor(firstHigh, secondHigh, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            builder.writeGuestXmmLane(destination, true, high, instruction.address);
            if (instruction.opcode == x86::Opcode::VxorpsYmmRegRegReg) {
                const auto firstUpperLow =
                    builder.readGuestYmmUpperLane(first, false, instruction.address);
                const auto secondUpperLow =
                    builder.readGuestYmmUpperLane(second, false, instruction.address);
                const auto upperLow = builder.bitXor(firstUpperLow, secondUpperLow, ir::Width::I64,
                                                     instruction.address);
                const auto firstUpperHigh =
                    builder.readGuestYmmUpperLane(first, true, instruction.address);
                const auto secondUpperHigh =
                    builder.readGuestYmmUpperLane(second, true, instruction.address);
                const auto upperHigh = builder.bitXor(firstUpperHigh, secondUpperHigh,
                                                      ir::Width::I64, instruction.address);
                builder.writeGuestYmmUpperLane(destination, false, upperLow, instruction.address);
                builder.writeGuestYmmUpperLane(destination, true, upperHigh, instruction.address);
            } else {
                const auto zero = builder.constant(0, ir::Width::I64, instruction.address);
                builder.writeGuestYmmUpperLane(destination, false, zero, instruction.address);
                builder.writeGuestYmmUpperLane(destination, true, zero, instruction.address);
            }
            break;
        }
        case x86::Opcode::VbroadcastssYmmReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: VBROADCASTSS operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto sourceLow = builder.readGuestXmmLane(source, false, instruction.address);
            const auto dwordMask =
                builder.constant(UINT32_MAX, ir::Width::I64, instruction.address);
            const auto dword =
                builder.bitAnd(sourceLow, dwordMask, ir::Width::I64, instruction.address);
            const auto upperDword =
                builder.shiftLeft(dword, 32, ir::Width::I64, instruction.address);
            const auto packed =
                builder.bitOr(dword, upperDword, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, packed, instruction.address);
            builder.writeGuestXmmLane(destination, true, packed, instruction.address);
            builder.writeGuestYmmUpperLane(destination, false, packed, instruction.address);
            builder.writeGuestYmmUpperLane(destination, true, packed, instruction.address);
            break;
        }
        case x86::Opcode::PxorRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PXOR memory operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            builder.xorGuestMemoryXmm(address, destination, instruction.address);
            break;
        }
        case x86::Opcode::XorpsRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: XORPS memory operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            builder.xorGuestMemoryXmm(address, destination, instruction.address);
            break;
        }
        case x86::Opcode::PandRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PAND register operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto destinationLow =
                builder.readGuestXmmLane(destination, false, instruction.address);
            const auto sourceLow = builder.readGuestXmmLane(source, false, instruction.address);
            const auto low =
                builder.bitAnd(destinationLow, sourceLow, ir::Width::I64, instruction.address);
            const auto destinationHigh =
                builder.readGuestXmmLane(destination, true, instruction.address);
            const auto sourceHigh = builder.readGuestXmmLane(source, true, instruction.address);
            const auto high =
                builder.bitAnd(destinationHigh, sourceHigh, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            builder.writeGuestXmmLane(destination, true, high, instruction.address);
            break;
        }
        case x86::Opcode::PandRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PAND memory operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            builder.andGuestMemoryXmm(address, destination, instruction.address);
            break;
        }
        case x86::Opcode::PtestRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PTEST operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            builder.testXmmBits(destination, source, instruction.address);
            break;
        }
        case x86::Opcode::PcmpeqbRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: pcmpeqb operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            const auto base =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            const auto displacement =
                builder.constant(static_cast<std::uint64_t>(memory.displacement), ir::Width::I64,
                                 instruction.address);
            const auto address =
                builder.add(base, displacement, ir::Width::I64, instruction.address);
            builder.compareEqualGuestBytesXmm(address, destination, instruction.address);
            break;
        }
        case x86::Opcode::PcmpeqbRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: pcmpeqb register operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            builder.compareEqualXmmBytes(destination, source, instruction.address);
            break;
        }
        case x86::Opcode::PcmpeqdRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PCMPEQD register operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            builder.compareEqualXmmDwords(destination, source, instruction.address);
            break;
        }
        case x86::Opcode::PslldRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PSLLD operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            builder.shiftLeftXmmDwords(destination, static_cast<std::uint8_t>(immediate.value),
                                       instruction.address);
            break;
        }
        case x86::Opcode::PsrldRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PSRLD operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto count = static_cast<std::uint8_t>(
                std::get<x86::ImmediateOperand>(instruction.operands[1]).value);
            if (count >= 32) {
                const auto zero = builder.constant(0, ir::Width::I64, instruction.address);
                builder.writeGuestXmmLane(destination, false, zero, instruction.address);
                builder.writeGuestXmmLane(destination, true, zero, instruction.address);
                break;
            }
            const auto dwordMask =
                builder.constant(0xFFFFFFFFU, ir::Width::I64, instruction.address);
            for (std::uint8_t lane = 0; lane < 2; ++lane) {
                const bool high = lane != 0;
                const auto laneValue =
                    builder.readGuestXmmLane(destination, high, instruction.address);
                const auto lowDword = builder.bitAnd(laneValue, dwordMask, ir::Width::I64,
                                                     instruction.address);
                const auto highDword = builder.shiftRightLogical(
                    laneValue, 32, ir::Width::I64, instruction.address);
                const auto shiftedLow =
                    builder.shiftRightLogical(lowDword, count, ir::Width::I64,
                                              instruction.address);
                const auto shiftedHigh =
                    builder.shiftRightLogical(highDword, count, ir::Width::I64,
                                              instruction.address);
                const auto combined = builder.bitOr(
                    shiftedLow,
                    builder.shiftLeft(shiftedHigh, 32, ir::Width::I64,
                                      instruction.address),
                    ir::Width::I64, instruction.address);
                builder.writeGuestXmmLane(destination, high, combined,
                                          instruction.address);
            }
            break;
        }
        case x86::Opcode::PsrlqRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PSRLQ operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto immediate = static_cast<std::uint8_t>(
                std::get<x86::ImmediateOperand>(instruction.operands[1]).value);
            if (immediate >= 64) {
                const auto zero = builder.constant(0, ir::Width::I64, instruction.address);
                builder.writeGuestXmmLane(destination, false, zero, instruction.address);
                builder.writeGuestXmmLane(destination, true, zero, instruction.address);
                break;
            }
            const auto low = builder.readGuestXmmLane(destination, false, instruction.address);
            const auto high = builder.readGuestXmmLane(destination, true, instruction.address);
            const auto shiftedLow =
                builder.shiftRightLogical(low, immediate, ir::Width::I64, instruction.address);
            const auto shiftedHigh =
                builder.shiftRightLogical(high, immediate, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, shiftedLow, instruction.address);
            builder.writeGuestXmmLane(destination, true, shiftedHigh, instruction.address);
            break;
        }
        case x86::Opcode::PadddRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PADDD operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            builder.addXmmDwords(destination, source, instruction.address);
            break;
        }
        case x86::Opcode::PaddwRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PADDW operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            builder.addXmmWords(destination, source, instruction.address);
            break;
        }
        case x86::Opcode::BlendvpdRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: BLENDVPD operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            // XMM0 supplies the per-lane mask MSB; arithmetic shift expands
            // each mask bit to a full lane selector without any helper call.
            const auto destinationLow =
                builder.readGuestXmmLane(destination, false, instruction.address);
            const auto destinationHigh =
                builder.readGuestXmmLane(destination, true, instruction.address);
            const auto sourceLow =
                builder.readGuestXmmLane(source, false, instruction.address);
            const auto sourceHigh =
                builder.readGuestXmmLane(source, true, instruction.address);
            const auto maskLow =
                builder.readGuestXmmLane(x86::XmmRegister::Xmm0, false,
                                         instruction.address);
            const auto maskHigh =
                builder.readGuestXmmLane(x86::XmmRegister::Xmm0, true,
                                         instruction.address);
            const auto selectLane = [&](ir::ValueId destinationLane,
                                        ir::ValueId sourceLane,
                                        ir::ValueId maskLane) {
                const auto selector = builder.shiftRightArithmetic(
                    maskLane, 63, ir::Width::I64, instruction.address);
                const auto allOnes = builder.constant(
                    UINT64_MAX, ir::Width::I64, instruction.address);
                const auto inverted = builder.bitXor(
                    selector, allOnes, ir::Width::I64, instruction.address);
                const auto kept = builder.bitAnd(destinationLane, inverted,
                                                 ir::Width::I64, instruction.address);
                const auto taken = builder.bitAnd(sourceLane, selector,
                                                  ir::Width::I64, instruction.address);
                return builder.bitOr(kept, taken, ir::Width::I64,
                                     instruction.address);
            };
            builder.writeGuestXmmLane(
                destination, false,
                selectLane(destinationLow, sourceLow, maskLow), instruction.address);
            builder.writeGuestXmmLane(
                destination, true,
                selectLane(destinationHigh, sourceHigh, maskHigh), instruction.address);
            break;
        }
        case x86::Opcode::CmppdRegRegImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: CMPPD operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto predicate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            if (predicate.width != 8 || predicate.value > 7) {
                throw std::runtime_error("only CMPPD with predicate 0-7 is implemented");
            }
            builder.comparePackedDoubleXmm(
                destination, source, static_cast<std::uint8_t>(predicate.value),
                instruction.address);
            break;
        }
        case x86::Opcode::PadddRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: PADDD memory operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (memory.width != 128 ||
                (memory.ripRelative
                     ? memory.hasBase || memory.index.has_value()
                     : !memory.hasBase || memory.index.has_value()) ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error(
                    "only RIP-relative or based PADDD xmm, m128 is implemented");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64,
                                      instruction.address);
            }
            // A single guest-memory helper performs the whole read-modify-write:
            // no IR value may stay live in a caller-saved host register across
            // the call.
            builder.addGuestMemoryXmm(address, destination, instruction.address);
            break;
        }
        case x86::Opcode::PaddqRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PADDQ operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto destinationLow =
                builder.readGuestXmmLane(destination, false, instruction.address);
            const auto sourceLow = builder.readGuestXmmLane(source, false, instruction.address);
            const auto low =
                builder.add(destinationLow, sourceLow, ir::Width::I64, instruction.address);
            const auto destinationHigh =
                builder.readGuestXmmLane(destination, true, instruction.address);
            const auto sourceHigh = builder.readGuestXmmLane(source, true, instruction.address);
            const auto high =
                builder.add(destinationHigh, sourceHigh, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            builder.writeGuestXmmLane(destination, true, high, instruction.address);
            break;
        }
        case x86::Opcode::PhadddRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PHADDD operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            builder.horizontalAddXmmDwords(destination, source, instruction.address);
            break;
        }
        case x86::Opcode::PmovzxbdXmmReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PMOVZXBD operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            // Read the source lane first: architecturally the low four
            // source bytes feed all four destination dwords, so an
            // in-place PMOVZXBD must not observe its own writes.
            const auto sourceLow =
                builder.readGuestXmmLane(source, false, instruction.address);
            const auto byteMask =
                builder.constant(0xFF, ir::Width::I64, instruction.address);
            std::optional<ir::ValueId> lowWidened;
            std::optional<ir::ValueId> highWidened;
            for (std::uint8_t lane = 0; lane < 4; ++lane) {
                auto byte = sourceLow;
                if (lane != 0) {
                    byte = builder.shiftRightLogical(sourceLow, static_cast<std::uint8_t>(lane * 8),
                                                     ir::Width::I64, instruction.address);
                }
                byte = builder.bitAnd(byte, byteMask, ir::Width::I64, instruction.address);
                const auto shift = static_cast<std::uint8_t>((lane % 2U) * 32U);
                if (shift != 0) {
                    byte = builder.shiftLeft(byte, shift, ir::Width::I64, instruction.address);
                }
                if (lane < 2) {
                    lowWidened = lowWidened ? builder.bitOr(*lowWidened, byte, ir::Width::I64,
                                                            instruction.address)
                                            : byte;
                } else {
                    highWidened = highWidened ? builder.bitOr(*highWidened, byte, ir::Width::I64,
                                                              instruction.address)
                                              : byte;
                }
            }
            builder.writeGuestXmmLane(destination, false, *lowWidened, instruction.address);
            builder.writeGuestXmmLane(destination, true, *highWidened, instruction.address);
            break;
        }
        case x86::Opcode::PorRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: POR register operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto destinationLow =
                builder.readGuestXmmLane(destination, false, instruction.address);
            const auto sourceLow = builder.readGuestXmmLane(source, false, instruction.address);
            const auto low =
                builder.bitOr(destinationLow, sourceLow, ir::Width::I64, instruction.address);
            const auto destinationHigh =
                builder.readGuestXmmLane(destination, true, instruction.address);
            const auto sourceHigh = builder.readGuestXmmLane(source, true, instruction.address);
            const auto high =
                builder.bitOr(destinationHigh, sourceHigh, ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            builder.writeGuestXmmLane(destination, true, high, instruction.address);
            break;
        }
        case x86::Opcode::PunpcklwdRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PUNPCKLWD operand count");
            }
            builder.unpackLowXmmWords(
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg,
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg,
                instruction.address);
            break;
        }
        case x86::Opcode::PunpcklqdqRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PUNPCKLQDQ operand count");
            }
            // DEST[63:0] is preserved; DEST[127:64] takes SRC[63:0].
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto sourceLow = builder.readGuestXmmLane(source, false, instruction.address);
            builder.writeGuestXmmLane(destination, true, sourceLow, instruction.address);
            break;
        }
        case x86::Opcode::PandnRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: pandn register operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            builder.andNotXmm(destination, source, instruction.address);
            break;
        }
        case x86::Opcode::PmovmskbRegXmm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: pmovmskb operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            builder.moveXmmByteMask(destination, source, instruction.address);
            break;
        }
        case x86::Opcode::PshufbRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PSHUFB operand count");
            }
            builder.shuffleXmmBytes(std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg,
                                    std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg,
                                    instruction.address);
            break;
        }
        case x86::Opcode::PshufbRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: memory PSHUFB operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (!memory.ripRelative || memory.hasBase || memory.index || memory.width != 128 ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error(
                    "only RIP-relative PSHUFB memory controls are implemented");
            }
            const auto base = builder.constant(instruction.address.value + instruction.length,
                                               ir::Width::I64, instruction.address);
            const auto displacement =
                builder.constant(static_cast<std::uint64_t>(memory.displacement), ir::Width::I64,
                                 instruction.address);
            const auto address =
                builder.add(base, displacement, ir::Width::I64, instruction.address);
            builder.shuffleGuestMemoryXmmBytes(address, destination, instruction.address);
            break;
        }
        case x86::Opcode::PshufdRegRegImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: pshufd operand count");
            }
            builder.shuffleXmmDwords(
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg,
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg,
                static_cast<std::uint8_t>(
                    std::get<x86::ImmediateOperand>(instruction.operands[2]).value),
                instruction.address);
            break;
        }
        case x86::Opcode::ShufpdRegRegImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: shufpd operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto control = static_cast<std::uint8_t>(
                std::get<x86::ImmediateOperand>(instruction.operands[2]).value);
            const auto low =
                builder.readGuestXmmLane(destination, (control & 0x1U) != 0, instruction.address);
            const auto high =
                builder.readGuestXmmLane(source, (control & 0x2U) != 0, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            builder.writeGuestXmmLane(destination, true, high, instruction.address);
            break;
        }
        case x86::Opcode::ShufpsRegRegImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: shufps operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto control = static_cast<std::uint8_t>(
                std::get<x86::ImmediateOperand>(instruction.operands[2]).value);
            // Low two result dwords come from the destination, high two from
            // the source; each selected by its own two-bit field.
            const auto destinationLow =
                builder.readGuestXmmLane(destination, false, instruction.address);
            const auto destinationHigh =
                builder.readGuestXmmLane(destination, true, instruction.address);
            const auto sourceLow =
                builder.readGuestXmmLane(source, false, instruction.address);
            const auto sourceHigh =
                builder.readGuestXmmLane(source, true, instruction.address);
            const auto dwordMask =
                builder.constant(0xFFFFFFFFU, ir::Width::I64, instruction.address);
            const auto selectDword = [&](ir::ValueId pairLow, ir::ValueId pairHigh,
                                         std::uint8_t field) {
                const auto lane = (field & 2U) != 0 ? pairHigh : pairLow;
                const auto dword =
                    (field & 1U) != 0
                        ? builder.shiftRightLogical(lane, 32, ir::Width::I64,
                                                    instruction.address)
                        : lane;
                return builder.bitAnd(dword, dwordMask, ir::Width::I64,
                                      instruction.address);
            };
            const auto low = builder.bitOr(
                selectDword(destinationLow, destinationHigh,
                            static_cast<std::uint8_t>(control & 0x3U)),
                builder.shiftLeft(
                    selectDword(destinationLow, destinationHigh,
                                static_cast<std::uint8_t>((control >> 2U) & 0x3U)),
                    32, ir::Width::I64, instruction.address),
                ir::Width::I64, instruction.address);
            const auto high = builder.bitOr(
                selectDword(sourceLow, sourceHigh,
                            static_cast<std::uint8_t>((control >> 4U) & 0x3U)),
                builder.shiftLeft(
                    selectDword(sourceLow, sourceHigh,
                                static_cast<std::uint8_t>((control >> 6U) & 0x3U)),
                    32, ir::Width::I64, instruction.address),
                ir::Width::I64, instruction.address);
            builder.writeGuestXmmLane(destination, false, low, instruction.address);
            builder.writeGuestXmmLane(destination, true, high, instruction.address);
            break;
        }
        case x86::Opcode::PinsrbXmmReg: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: PINSRB operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            const auto value =
                builder.readGuestRegister(source.reg, ir::Width::I64, instruction.address);
            builder.writeGuestXmmByte(destination,
                                      static_cast<std::uint8_t>(immediate.value & 0x0FU), value,
                                      instruction.address);
            break;
        }
        case x86::Opcode::PinsrbXmmMem: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: PINSRB memory operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            if (memory.width != 8 || !memory.hasBase || memory.index ||
                memory.ripRelative || memory.segment != x86::Segment::None) {
                throw std::runtime_error("only based byte PINSRB memory operands are implemented");
            }
            auto address =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto value = builder.loadGuest(address, ir::Width::I8, instruction.address);
            builder.writeGuestXmmByte(destination,
                                      static_cast<std::uint8_t>(immediate.value & 0x0FU), value,
                                      instruction.address);
            break;
        }
        case x86::Opcode::PinsrdXmmMem: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: PINSRD operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            auto address =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto value = builder.loadGuest(address, ir::Width::I32, instruction.address);
            builder.writeGuestXmmDword(destination, static_cast<std::uint8_t>(immediate.value & 3U),
                                       value, instruction.address);
            break;
        }
        case x86::Opcode::PinsrdXmmReg: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: PINSRD register operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            if (source.width == 64) {
                const auto value =
                    builder.readGuestRegister(source.reg, ir::Width::I64, instruction.address);
                builder.writeGuestXmmLane(destination, (immediate.value & 1U) != 0, value,
                                          instruction.address);
            } else if (source.width == 32) {
                const auto value =
                    builder.readGuestRegister(source.reg, ir::Width::I32, instruction.address);
                builder.writeGuestXmmDword(destination,
                                           static_cast<std::uint8_t>(immediate.value & 3U), value,
                                           instruction.address);
            } else {
                throw std::runtime_error("PINSRD/PINSRQ source has an unsupported width");
            }
            break;
        }
        case x86::Opcode::PextrwRegXmmImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: PEXTRW operand count");
            }
            const auto destination =
                std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto count =
                std::get<x86::ImmediateOperand>(instruction.operands[2]);
            if (destination.width != 32 || count.width != 8 || count.value > 7) {
                throw std::runtime_error(
                    "only PEXTRW r32, xmm, word-index is implemented");
            }
            const auto lane = builder.readGuestXmmLane(
                source, (count.value & 4U) != 0, instruction.address);
            const std::uint8_t shift =
                static_cast<std::uint8_t>((count.value & 3U) * 16U);
            auto word = lane;
            if (shift != 0) {
                word = builder.shiftRightLogical(word, shift, ir::Width::I64,
                                                 instruction.address);
            }
            word = builder.bitAnd(word,
                                  builder.constant(0xFFFFU, ir::Width::I64,
                                                   instruction.address),
                                  ir::Width::I64, instruction.address);
            builder.writeGuestRegister(destination.reg, word, ir::Width::I32,
                                       instruction.address);
            break;
        }
        case x86::Opcode::MovmskpsRegXmm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: MOVMSKPS operand count");
            }
            const auto destination =
                std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            if (destination.width != 32) {
                throw std::runtime_error("only MOVMSKPS r32, xmm is implemented");
            }
            const auto low = builder.readGuestXmmLane(source, false,
                                                      instruction.address);
            const auto high = builder.readGuestXmmLane(source, true,
                                                       instruction.address);
            // Sign bits of the four packed singles: bit 31/63 of each
            // lane, assembled low dword first.
            const auto one = builder.constant(1, ir::Width::I64, instruction.address);
            const auto bit0 = builder.bitAnd(
                builder.shiftRightLogical(low, 31, ir::Width::I64,
                                          instruction.address),
                one, ir::Width::I64, instruction.address);
            const auto bit1 = builder.shiftRightLogical(low, 63, ir::Width::I64,
                                                        instruction.address);
            const auto bit1Shifted = builder.shiftLeft(bit1, 1, ir::Width::I64,
                                                       instruction.address);
            const auto bit2 = builder.bitAnd(
                builder.shiftRightLogical(high, 31, ir::Width::I64,
                                          instruction.address),
                one, ir::Width::I64, instruction.address);
            const auto bit2Shifted = builder.shiftLeft(bit2, 2, ir::Width::I64,
                                                       instruction.address);
            const auto bit3 = builder.shiftRightLogical(high, 63, ir::Width::I64,
                                                        instruction.address);
            const auto bit3Shifted = builder.shiftLeft(bit3, 3, ir::Width::I64,
                                                       instruction.address);
            auto mask = builder.bitOr(bit0, bit1Shifted, ir::Width::I64,
                                      instruction.address);
            mask = builder.bitOr(mask, bit2Shifted, ir::Width::I64,
                                 instruction.address);
            mask = builder.bitOr(mask, bit3Shifted, ir::Width::I64,
                                 instruction.address);
            builder.writeGuestRegister(destination.reg, mask, ir::Width::I32,
                                       instruction.address);
            break;
        }
        case x86::Opcode::MovmskpdRegXmm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: MOVMSKPD operand count");
            }
            const auto destination =
                std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            if (destination.width != 32) {
                throw std::runtime_error("only MOVMSKPD r32, xmm is implemented");
            }
            const auto low = builder.readGuestXmmLane(source, false,
                                                      instruction.address);
            const auto high = builder.readGuestXmmLane(source, true,
                                                       instruction.address);
            // Sign bits of the two packed doubles: bit 63 of each lane.
            const auto bit0 = builder.shiftRightLogical(low, 63, ir::Width::I64,
                                                        instruction.address);
            const auto bit1 = builder.shiftRightLogical(high, 63, ir::Width::I64,
                                                        instruction.address);
            const auto bit1Shifted = builder.shiftLeft(bit1, 1, ir::Width::I64,
                                                       instruction.address);
            const auto mask = builder.bitOr(bit0, bit1Shifted, ir::Width::I64,
                                            instruction.address);
            builder.writeGuestRegister(destination.reg, mask, ir::Width::I32,
                                       instruction.address);
            break;
        }
        case x86::Opcode::PextrdRegXmmImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: PEXTRD operand count");
            }
            const auto destination =
                std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto count =
                std::get<x86::ImmediateOperand>(instruction.operands[2]);
            if (destination.width != 32 || count.width != 8 || count.value > 3) {
                throw std::runtime_error(
                    "only PEXTRD r32, xmm, dword-index is implemented");
            }
            const auto lane = builder.readGuestXmmLane(
                source, (count.value & 2U) != 0, instruction.address);
            auto dword = lane;
            if ((count.value & 1U) != 0) {
                dword = builder.shiftRightLogical(lane, 32, ir::Width::I64,
                                                  instruction.address);
            }
            dword = builder.bitAnd(dword,
                                   builder.constant(0xFFFFFFFFU, ir::Width::I64,
                                                    instruction.address),
                                   ir::Width::I64, instruction.address);
            builder.writeGuestRegister(destination.reg, dword, ir::Width::I32,
                                       instruction.address);
            break;
        }
        case x86::Opcode::UcomisdRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: UCOMISD operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto destinationBits = builder.readGuestXmmLane(
                destination, false, instruction.address);
            const auto sourceBits = builder.readGuestXmmLane(
                source, false, instruction.address);
            builder.updateUnorderedDoubleFlags(destinationBits, sourceBits,
                                               instruction.address);
            break;
        }
        case x86::Opcode::UcomissRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: UCOMISS operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto destinationBits = builder.readGuestXmmLane(
                destination, false, instruction.address);
            const auto sourceBits = builder.readGuestXmmLane(
                source, false, instruction.address);
            builder.updateUnorderedFloatFlags(destinationBits, sourceBits,
                                              instruction.address);
            break;
        }
        case x86::Opcode::UcomissRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: UCOMISS memory operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (memory.width != 32 ||
                (memory.ripRelative ? memory.hasBase || memory.index.has_value()
                                    : !memory.hasBase) ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("unsupported UCOMISS memory addressing");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64,
                                                instruction.address);
            if (memory.index) {
                auto index = builder.readGuestRegister(
                    *memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index,
                        static_cast<std::uint8_t>(
                            std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64,
                                      instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement = builder.constant(
                    static_cast<std::uint64_t>(memory.displacement),
                    ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64,
                                      instruction.address);
            }
            const auto sourceBits = builder.loadGuest(address, ir::Width::I32,
                                                      instruction.address);
            // The destination lane materializes after the load returns, so
            // no IR value stays live across a helper call.
            const auto destinationBits = builder.readGuestXmmLane(
                destination, false, instruction.address);
            builder.updateUnorderedFloatFlags(destinationBits, sourceBits,
                                              instruction.address);
            break;
        }
        case x86::Opcode::PinsrwXmmMem:
        case x86::Opcode::PinsrwXmmReg: {
            const bool fromMemory =
                instruction.opcode == x86::Opcode::PinsrwXmmMem;
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: PINSRW operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto count = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            if (count.width != 8 || count.value > 7) {
                throw std::runtime_error("only PINSRW word counts 0-7 are implemented");
            }
            ir::ValueId inserted{};
            if (!fromMemory) {
                const auto source =
                    std::get<x86::RegisterOperand>(instruction.operands[1]);
                if ((source.width != 32 && source.width != 64) ||
                    source.byteOffset != 0) {
                    throw std::runtime_error(
                        "only PINSRW xmm, r32/r64, imm8 is implemented");
                }
                const auto sourceValue = builder.readGuestRegister(
                    source.reg, ir::Width::I64, instruction.address);
                inserted = builder.bitAnd(
                    sourceValue,
                    builder.constant(0xFFFFU, ir::Width::I64, instruction.address),
                    ir::Width::I64, instruction.address);
            } else {
                const auto memory =
                    std::get<x86::MemoryOperand>(instruction.operands[1]);
                if (memory.width != 16 || !memory.hasBase || memory.index ||
                    memory.ripRelative ||
                    memory.segment != x86::Segment::None) {
                    throw std::runtime_error(
                        "only based PINSRW xmm, m16, imm8 is implemented");
                }
                auto address = builder.readGuestRegister(
                    memory.base, ir::Width::I64, instruction.address);
                if (memory.displacement != 0) {
                    const auto displacement = builder.constant(
                        static_cast<std::uint64_t>(memory.displacement),
                        ir::Width::I64, instruction.address);
                    address = builder.add(address, displacement, ir::Width::I64,
                                          instruction.address);
                }
                inserted = builder.loadGuest(address, ir::Width::I16,
                                             instruction.address);
            }
            // Splice the word into its lane: clear the target word, then OR
            // in the shifted value. All pure IR around at most one load.
            const bool high = (count.value & 4U) != 0;
            const std::uint8_t shift =
                static_cast<std::uint8_t>((count.value & 3U) * 16U);
            const auto lane = builder.readGuestXmmLane(destination, high,
                                                       instruction.address);
            const auto wordMask = builder.shiftLeft(
                builder.constant(0xFFFFU, ir::Width::I64, instruction.address), shift,
                ir::Width::I64, instruction.address);
            const auto allOnes =
                builder.constant(UINT64_MAX, ir::Width::I64, instruction.address);
            const auto cleared = builder.bitAnd(
                lane,
                builder.bitXor(wordMask, allOnes, ir::Width::I64,
                               instruction.address),
                ir::Width::I64, instruction.address);
            auto placed = inserted;
            if (shift != 0) {
                placed = builder.shiftLeft(inserted, shift, ir::Width::I64,
                                           instruction.address);
            }
            const auto combined = builder.bitOr(cleared, placed, ir::Width::I64,
                                                instruction.address);
            builder.writeGuestXmmLane(destination, high, combined,
                                      instruction.address);
            break;
        }
        case x86::Opcode::ExtractpsMemXmmImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: EXTRACTPS operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            if (memory.width != 32 || !memory.hasBase || memory.ripRelative || memory.index ||
                memory.segment != x86::Segment::None || immediate.width != 8) {
                throw std::runtime_error(
                    "only based dword EXTRACTPS memory destinations are implemented");
            }
            auto address =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto lane = static_cast<std::uint8_t>(immediate.value & 0x3U);
            auto value = builder.readGuestXmmLane(source, lane >= 2, instruction.address);
            if ((lane & 1U) != 0) {
                value = builder.shiftRightLogical(value, 32, ir::Width::I64, instruction.address);
            }
            builder.storeGuest(address, value, ir::Width::I32, instruction.address);
            break;
        }
        case x86::Opcode::PmovsxbdRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PMOVSXBD operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (!memory.ripRelative || memory.hasBase || memory.index || memory.width != 32) {
                throw std::runtime_error("only RIP-relative PMOVSXBD memory is implemented");
            }
            const auto base = builder.constant(instruction.address.value + instruction.length,
                                               ir::Width::I64, instruction.address);
            const auto displacement =
                builder.constant(static_cast<std::uint64_t>(memory.displacement), ir::Width::I64,
                                 instruction.address);
            const auto address =
                builder.add(base, displacement, ir::Width::I64, instruction.address);
            builder.loadGuestSignExtendedBytesXmm(address, destination, instruction.address);
            break;
        }
        case x86::Opcode::PmovsxdqRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PMOVSXDQ operand count");
            }
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source =
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto packed =
                builder.readGuestXmmLane(source, false, instruction.address);
            const auto dwordMask =
                builder.constant(0xFFFFFFFFU, ir::Width::I64, instruction.address);
            const auto lowDword =
                builder.bitAnd(packed, dwordMask, ir::Width::I64, instruction.address);
            const auto shifted = builder.shiftRightLogical(packed, 32, ir::Width::I64,
                                                           instruction.address);
            const auto highDword =
                builder.bitAnd(shifted, dwordMask, ir::Width::I64, instruction.address);
            // The lanes are consumed here, so no IR value stays live across
            // any call; sign extension itself is pure.
            builder.writeGuestXmmLane(
                destination, false,
                builder.signExtend32(lowDword, instruction.address), instruction.address);
            builder.writeGuestXmmLane(
                destination, true,
                builder.signExtend32(highDword, instruction.address), instruction.address);
            break;
        }
        case x86::Opcode::PmovsxdqRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: PMOVSXDQ operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (!memory.ripRelative || memory.hasBase || memory.index || memory.width != 64) {
                throw std::runtime_error("only RIP-relative PMOVSXDQ memory is implemented");
            }
            const auto base = builder.constant(instruction.address.value + instruction.length,
                                               ir::Width::I64, instruction.address);
            const auto displacement =
                builder.constant(static_cast<std::uint64_t>(memory.displacement), ir::Width::I64,
                                 instruction.address);
            const auto address =
                builder.add(base, displacement, ir::Width::I64, instruction.address);
            builder.loadGuestSignExtendedDwordsXmm(address, destination, instruction.address);
            break;
        }
        case x86::Opcode::PblendwRegRegImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: PBLENDW operand count");
            }
            const auto destination = std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const auto source = std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg;
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[2]);
            builder.blendXmmWords(destination, source, static_cast<std::uint8_t>(immediate.value),
                                  instruction.address);
            break;
        }
        case x86::Opcode::PalignrRegRegImm: {
            if (instruction.operands.size() != 3) {
                throw std::runtime_error("internal decoder error: palignr operand count");
            }
            builder.alignRightXmmBytes(
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg,
                std::get<x86::XmmRegisterOperand>(instruction.operands[1]).reg,
                static_cast<std::uint8_t>(
                    std::get<x86::ImmediateOperand>(instruction.operands[2]).value),
                instruction.address);
            break;
        }
        case x86::Opcode::AndRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: and operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (reg.byteOffset > 1 || (reg.byteOffset == 1 && reg.width != 8)) {
                throw std::runtime_error("invalid byte-lane AND register");
            }
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 16 ? ir::Width::I16
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            if (reg.byteOffset == 0) {
                const auto lhs = builder.readGuestRegister(reg.reg, width, instruction.address);
                const auto rhs = builder.constant(immediate.value, width, instruction.address);
                const auto result = builder.bitAnd(lhs, rhs, width, instruction.address);
                builder.writeGuestRegister(reg.reg, result, width, instruction.address);
                builder.updateLogicFlags(result, width, instruction.address);
                break;
            }
            // High-byte lane (AH/CH/DH/BH): extract bits[15:8], combine, and
            // merge back into the parent register.
            const auto parent =
                builder.readGuestRegister(reg.reg, ir::Width::I64, instruction.address);
            const auto shifted = builder.shiftRightLogical(parent, 8, ir::Width::I64,
                                                           instruction.address);
            const auto laneMask =
                builder.constant(0xFF, ir::Width::I64, instruction.address);
            const auto lhs = builder.bitAnd(shifted, laneMask, ir::Width::I64,
                                            instruction.address);
            const auto rhs =
                builder.constant(immediate.value, ir::Width::I64, instruction.address);
            const auto result =
                builder.bitAnd(lhs, rhs, ir::Width::I64, instruction.address);
            const auto clearMask =
                builder.constant(~std::uint64_t{0xFF00}, ir::Width::I64, instruction.address);
            const auto cleared =
                builder.bitAnd(parent, clearMask, ir::Width::I64, instruction.address);
            const auto placed = builder.shiftLeft(
                result, static_cast<std::uint8_t>(8), ir::Width::I64, instruction.address);
            const auto merged =
                builder.bitOr(cleared, placed, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(reg.reg, merged, ir::Width::I64, instruction.address);
            builder.updateLogicFlags(result, ir::Width::I8, instruction.address);
            break;
        }
        case x86::Opcode::TestRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: test operand count");
            }
            const auto lhsRegister = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto rhsRegister = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto width = lhsRegister.width == 16   ? ir::Width::I16
                               : lhsRegister.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(lhsRegister.reg, width, instruction.address);
            const auto rhs = builder.readGuestRegister(rhsRegister.reg, width, instruction.address);
            const auto result = builder.bitAnd(lhs, rhs, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::TestReg8Reg8: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: test byte operand count");
            }
            const auto lhsRegister = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto rhsRegister = std::get<x86::RegisterOperand>(instruction.operands[1]);
            const auto lhs =
                builder.readGuestRegister(lhsRegister.reg, ir::Width::I64, instruction.address);
            const auto rhs =
                builder.readGuestRegister(rhsRegister.reg, ir::Width::I64, instruction.address);
            const auto mask = builder.constant(0xFF, ir::Width::I64, instruction.address);
            const auto maskedLhs = builder.bitAnd(lhs, mask, ir::Width::I64, instruction.address);
            const auto maskedRhs = builder.bitAnd(rhs, mask, ir::Width::I64, instruction.address);
            const auto result =
                builder.bitAnd(maskedLhs, maskedRhs, ir::Width::I64, instruction.address);
            builder.updateLogicFlags(result, ir::Width::I8, instruction.address);
            break;
        }
        case x86::Opcode::TestMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: test byte memory operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != reg.width ||
                (memory.width != 8 && memory.width != 32 && memory.width != 64)) {
                throw std::runtime_error("unsupported internal TEST memory width");
            }
            const auto width = memory.width == 8    ? ir::Width::I8
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto memoryValue = builder.loadGuest(address, width, instruction.address);
            // Read the register after the memory helper call so its value is not
            // kept live in a caller-saved host register across the call.
            const auto registerValue =
                builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto result =
                builder.bitAnd(memoryValue, registerValue, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::TestRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: test immediate operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if ((reg.width == 8 && immediate.width != 8) ||
                (reg.width == 16 && immediate.width != 16) ||
                (reg.width == 32 && immediate.width != 32) ||
                (reg.width == 64 && immediate.width != 32) ||
                (reg.width != 8 && reg.width != 16 && reg.width != 32 &&
                 reg.width != 64)) {
                throw std::runtime_error("unsupported internal TEST immediate width");
            }
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 16 ? ir::Width::I16
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto value = builder.readGuestRegister(
                reg.reg, reg.width == 8 ? ir::Width::I64 : width, instruction.address);
            const auto mask = builder.constant(
                immediate.value, reg.width == 8 ? ir::Width::I64 : width, instruction.address);
            const auto result = builder.bitAnd(value, mask, reg.width == 8 ? ir::Width::I64 : width,
                                               instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::TestMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: test memory immediate operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (memory.width != immediate.width ||
                (memory.width != 8 && memory.width != 16 && memory.width != 32 &&
                 memory.width != 64)) {
                throw std::runtime_error("unsupported internal TEST memory immediate width");
            }
            const auto width = memory.width == 8    ? ir::Width::I8
                               : memory.width == 16 ? ir::Width::I16
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            if (memory.segment == x86::Segment::Gs) {
                const auto gsBase = builder.readGuestGsBase(instruction.address);
                address = builder.add(gsBase, address, ir::Width::I64, instruction.address);
            }
            const auto value = builder.loadGuest(address, width, instruction.address);
            const auto mask = builder.constant(immediate.value, width, instruction.address);
            const auto result = builder.bitAnd(value, mask, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
            break;
        }
        case x86::Opcode::CmpRegImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: cmp operand count");
            }
            const auto reg = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            if (reg.byteOffset > 1 || (reg.byteOffset == 1 && reg.width != 8)) {
                throw std::runtime_error("invalid byte-lane CMP register");
            }
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 16 ? ir::Width::I16
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            ir::ValueId lhs{};
            if (reg.byteOffset == 0) {
                lhs = builder.readGuestRegister(reg.reg, width, instruction.address);
            } else {
                // High-byte lane (AH/CH/DH/BH): compare bits[15:8].
                const auto parent =
                    builder.readGuestRegister(reg.reg, ir::Width::I64, instruction.address);
                const auto shifted = builder.shiftRightLogical(
                    parent, 8, ir::Width::I64, instruction.address);
                const auto laneMask =
                    builder.constant(0xFF, ir::Width::I64, instruction.address);
                lhs = builder.bitAnd(shifted, laneMask, ir::Width::I64, instruction.address);
            }
            const auto rhs = reg.byteOffset == 0
                                 ? builder.constant(immediate.value, width, instruction.address)
                                 : builder.constant(immediate.value, ir::Width::I64,
                                                    instruction.address);
            const auto result = reg.byteOffset == 0
                                    ? builder.sub(lhs, rhs, width, instruction.address)
                                    : builder.sub(lhs, rhs, ir::Width::I64, instruction.address);
            builder.updateSubFlags(lhs, rhs, result,
                                   reg.byteOffset == 0 ? width : ir::Width::I8,
                                   instruction.address);
            break;
        }
        case x86::Opcode::CmpRegReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: register cmp operand count");
            }
            const auto lhsRegister = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto rhsRegister = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (lhsRegister.width != rhsRegister.width ||
                (lhsRegister.width != 8 && lhsRegister.width != 16 && lhsRegister.width != 32 &&
                 lhsRegister.width != 64)) {
                throw std::runtime_error(
                    "only matching 8-bit, 16-bit, 32-bit, and 64-bit register CMP are implemented");
            }
            const auto width = lhsRegister.width == 8    ? ir::Width::I8
                               : lhsRegister.width == 16 ? ir::Width::I16
                               : lhsRegister.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(lhsRegister.reg, width, instruction.address);
            const auto rhs = builder.readGuestRegister(rhsRegister.reg, width, instruction.address);
            const auto result = builder.sub(lhs, rhs, width, instruction.address);
            builder.updateSubFlags(lhs, rhs, result, width, instruction.address);
            break;
        }
        case x86::Opcode::CmpRegMem: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: cmp memory operand count");
            }
            const auto lhsRegister = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            const auto width = lhsRegister.width == 8    ? ir::Width::I8
                               : lhsRegister.width == 16 ? ir::Width::I16
                               : lhsRegister.width == 32 ? ir::Width::I32
                                                         : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            if (memory.segment == x86::Segment::Gs) {
                const auto gsBase = builder.readGuestGsBase(instruction.address);
                address = builder.add(gsBase, address, ir::Width::I64, instruction.address);
            }
            const auto rhs = builder.loadGuest(address, width, instruction.address);
            const auto lhs = builder.readGuestRegister(lhsRegister.reg, width, instruction.address);
            const auto result = builder.sub(lhs, rhs, width, instruction.address);
            builder.updateSubFlags(lhs, rhs, result, width, instruction.address);
            break;
        }
        case x86::Opcode::CmpMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error(
                    "internal decoder error: cmp memory-register operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto rhsRegister = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != rhsRegister.width || (memory.width != 8 && memory.width != 16 &&
                                                      memory.width != 32 && memory.width != 64)) {
                throw std::runtime_error("only matching 8-bit, 16-bit, 32-bit, and 64-bit "
                                         "memory-register CMP are implemented");
            }
            const auto width = memory.width == 8    ? ir::Width::I8
                               : memory.width == 16 ? ir::Width::I16
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            if (memory.segment == x86::Segment::Gs) {
                const auto gsBase = builder.readGuestGsBase(instruction.address);
                address = builder.add(gsBase, address, ir::Width::I64, instruction.address);
            }
            const auto lhs = builder.loadGuest(address, width, instruction.address);
            const auto rhs = builder.readGuestRegister(rhsRegister.reg, width, instruction.address);
            const auto result = builder.sub(lhs, rhs, width, instruction.address);
            builder.updateSubFlags(lhs, rhs, result, width, instruction.address);
            break;
        }
        case x86::Opcode::CmpMemImm: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: cmp memory immediate count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto immediate = std::get<x86::ImmediateOperand>(instruction.operands[1]);
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto width = memory.width == 8    ? ir::Width::I8
                               : memory.width == 16 ? ir::Width::I16
                               : memory.width == 32 ? ir::Width::I32
                                                    : ir::Width::I64;
            const auto lhs = builder.loadGuest(address, width, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto result = builder.sub(lhs, rhs, width, instruction.address);
            builder.updateSubFlags(lhs, rhs, result, width, instruction.address);
            break;
        }
        case x86::Opcode::SetccReg: {
            if (instruction.operands.size() != 1 || !instruction.condition) {
                throw std::runtime_error("internal decoder error: setcc operand");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto value =
                builder.evaluateCondition(*instruction.condition, instruction.address);
            builder.writeGuestRegister(destination.reg, value, ir::Width::I8, instruction.address);
            break;
        }
        case x86::Opcode::SetccMem: {
            if (instruction.operands.size() != 1 || !instruction.condition) {
                throw std::runtime_error("internal decoder error: memory setcc operand");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            if (memory.width != 8 || (memory.ripRelative && memory.hasBase)) {
                throw std::runtime_error("invalid byte memory SETcc operand");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto value =
                builder.evaluateCondition(*instruction.condition, instruction.address);
            builder.storeGuest(address, value, ir::Width::I8, instruction.address);
            break;
        }
        case x86::Opcode::CmovccReg: {
            if (instruction.operands.size() != 2 || !instruction.condition) {
                throw std::runtime_error("internal decoder error: cmovcc operand");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (destination.width != source.width ||
                (destination.width != 32 && destination.width != 64)) {
                throw std::runtime_error(
                    "only matching 32-bit and 64-bit register CMOV are implemented");
            }
            builder.conditionalMoveGuestRegister(
                destination.reg, source.reg, *instruction.condition,
                destination.width == 32 ? ir::Width::I32 : ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::CmovccRegMem: {
            if (instruction.operands.size() != 2 || !instruction.condition) {
                throw std::runtime_error("internal decoder error: memory cmovcc operand");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[1]);
            if (destination.width != memory.width ||
                (destination.width != 32 && destination.width != 64) ||
                (memory.ripRelative && memory.hasBase)) {
                throw std::runtime_error("invalid 32-bit or 64-bit memory CMOV operand");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                : memory.hasBase
                    ? builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address)
                    : builder.constant(0, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            // Intel CMOV reads a memory source before testing the condition.
            const auto source = builder.loadGuest(
                address, destination.width == 32 ? ir::Width::I32 : ir::Width::I64,
                instruction.address);
            builder.conditionalMoveGuestRegister(
                destination.reg, source, *instruction.condition,
                destination.width == 32 ? ir::Width::I32 : ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::Push: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: push operand count");
            }
            ir::ValueId value;
            if (std::holds_alternative<x86::ImmediateOperand>(instruction.operands[0])) {
                value =
                    builder.constant(std::get<x86::ImmediateOperand>(instruction.operands[0]).value,
                                     ir::Width::I64, instruction.address);
            } else if (std::holds_alternative<x86::RegisterOperand>(instruction.operands[0])) {
                value = builder.readGuestRegister(
                    std::get<x86::RegisterOperand>(instruction.operands[0]).reg, ir::Width::I64,
                    instruction.address);
            } else {
                const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
                auto address =
                    builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
                if (memory.index) {
                    auto index = builder.readGuestRegister(*memory.index, ir::Width::I64,
                                                           instruction.address);
                    if (memory.scale != 1) {
                        const auto scale =
                            builder.constant(memory.scale, ir::Width::I64, instruction.address);
                        index =
                            builder.multiplyLow(index, scale, ir::Width::I64, instruction.address);
                    }
                    address = builder.add(address, index, ir::Width::I64, instruction.address);
                }
                if (memory.displacement != 0) {
                    const auto displacement =
                        builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                         ir::Width::I64, instruction.address);
                    address =
                        builder.add(address, displacement, ir::Width::I64, instruction.address);
                }
                value = builder.loadGuest(address, ir::Width::I64, instruction.address);
            }
            const auto stackPointer =
                builder.readGuestRegister(x86::Register::Rsp, ir::Width::I64, instruction.address);
            const auto eight =
                builder.constant(sizeof(std::uint64_t), ir::Width::I64, instruction.address);
            const auto newStackPointer =
                builder.sub(stackPointer, eight, ir::Width::I64, instruction.address);
            builder.push(newStackPointer, value, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::Pop: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: pop operand count");
            }
            const auto destination = std::get<x86::RegisterOperand>(instruction.operands[0]);
            const auto address =
                builder.readGuestRegister(x86::Register::Rsp, ir::Width::I64, instruction.address);
            const auto value = builder.loadGuest(address, ir::Width::I64, instruction.address);
            // Compute and commit the increment only after a successful guest load.
            const auto stackPointer =
                builder.readGuestRegister(x86::Register::Rsp, ir::Width::I64, instruction.address);
            const auto eight =
                builder.constant(sizeof(std::uint64_t), ir::Width::I64, instruction.address);
            const auto newStackPointer =
                builder.add(stackPointer, eight, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(x86::Register::Rsp, newStackPointer, ir::Width::I64,
                                       instruction.address);
            // Writing the destination last gives POP RSP its architectural result.
            builder.writeGuestRegister(destination.reg, value, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::Leave: {
            if (!instruction.operands.empty()) {
                throw std::runtime_error("internal decoder error: LEAVE has operands");
            }
            const auto framePointer =
                builder.readGuestRegister(x86::Register::Rbp, ir::Width::I64, instruction.address);
            // LEAVE commits RSP = RBP before attempting the implicit POP.
            // If that load faults, RSP retains the frame address and RBP is
            // unchanged.
            builder.writeGuestRegister(x86::Register::Rsp, framePointer, ir::Width::I64,
                                       instruction.address);
            const auto savedFrame =
                builder.loadGuest(framePointer, ir::Width::I64, instruction.address);
            const auto stackPointer =
                builder.readGuestRegister(x86::Register::Rsp, ir::Width::I64, instruction.address);
            const auto eight =
                builder.constant(sizeof(std::uint64_t), ir::Width::I64, instruction.address);
            const auto newStackPointer =
                builder.add(stackPointer, eight, ir::Width::I64, instruction.address);
            builder.writeGuestRegister(x86::Register::Rsp, newStackPointer, ir::Width::I64,
                                       instruction.address);
            builder.writeGuestRegister(x86::Register::Rbp, savedFrame, ir::Width::I64,
                                       instruction.address);
            break;
        }
        case x86::Opcode::Nop:
            break;
        case x86::Opcode::Vzeroupper: {
            const auto zero = builder.constant(0, ir::Width::I64, instruction.address);
            for (std::uint8_t encoded = 0; encoded < 16; ++encoded) {
                const auto reg = static_cast<x86::XmmRegister>(encoded);
                builder.writeGuestYmmUpperLane(reg, false, zero, instruction.address);
                builder.writeGuestYmmUpperLane(reg, true, zero, instruction.address);
            }
            break;
        }
        case x86::Opcode::Lfence:
            builder.loadFence(instruction.address);
            break;
        case x86::Opcode::Cld:
        case x86::Opcode::Std:
            builder.writeDirectionFlag(instruction.opcode == x86::Opcode::Std,
                                       instruction.address);
            break;
        case x86::Opcode::Mfence:
            builder.storeFence(instruction.address);
            break;
        case x86::Opcode::SidtMem: {
            if (instruction.operands.size() != 1 ||
                !std::holds_alternative<x86::MemoryOperand>(instruction.operands[0])) {
                throw std::runtime_error("internal decoder error: SIDT operand differs");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            if (memory.width != 80 || !memory.hasBase || memory.ripRelative || memory.index ||
                memory.segment != x86::Segment::None) {
                throw std::runtime_error("only based 80-bit SIDT memory operands are implemented");
            }
            auto address =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            builder.storeGuestIdtr(address, instruction.address);
            break;
        }
        case x86::Opcode::RepMovsb:
            builder.repeatMoveByte(instruction.address);
            break;
        case x86::Opcode::RepStosb:
        case x86::Opcode::RepStosd:
        case x86::Opcode::RepStosq: {
            const auto width = instruction.opcode == x86::Opcode::RepStosb   ? ir::Width::I8
                               : instruction.opcode == x86::Opcode::RepStosd ? ir::Width::I32
                                                                             : ir::Width::I64;
            builder.repeatStore(width, instruction.address);
            break;
        }
        case x86::Opcode::Rdtsc:
            builder.readTimestampCounter(instruction.address);
            break;
        case x86::Opcode::Cpuid:
            builder.cpuid(instruction.address);
            break;
        case x86::Opcode::JmpRelative:
            builder.exitDirect(*instruction.branchTarget, instruction.address);
            break;
        case x86::Opcode::JmpReg: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error("internal decoder error: indirect jump operand count");
            }
            const auto target = builder.readGuestRegister(
                std::get<x86::RegisterOperand>(instruction.operands[0]).reg, ir::Width::I64,
                instruction.address);
            builder.exitDirect(target, instruction.address);
            break;
        }
        case x86::Opcode::JmpMem: {
            if (instruction.operands.size() != 1) {
                throw std::runtime_error(
                    "internal decoder error: memory-indirect jump operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            if (memory.width != 64 || (memory.ripRelative && memory.hasBase) ||
                (!memory.ripRelative && !memory.hasBase)) {
                throw std::runtime_error(
                    "only based and RIP-relative qword memory JMP are implemented");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto target = builder.loadGuest(address, ir::Width::I64, instruction.address);
            builder.exitDirect(target, instruction.address);
            break;
        }
        case x86::Opcode::JccRelative:
            builder.exitConditional(*instruction.condition, *instruction.branchTarget,
                                    *instruction.fallthrough, instruction.address);
            break;
        case x86::Opcode::CallRelative:
            builder.exitCall(*instruction.branchTarget, *instruction.fallthrough,
                             instruction.address);
            break;
        case x86::Opcode::CallReg: {
            if (instruction.operands.size() != 1 || !instruction.fallthrough) {
                throw std::runtime_error("internal decoder error: register-indirect call operands");
            }
            const auto target = builder.readGuestRegister(
                std::get<x86::RegisterOperand>(instruction.operands[0]).reg, ir::Width::I64,
                instruction.address);
            builder.exitCall(target, *instruction.fallthrough, instruction.address);
            break;
        }
        case x86::Opcode::CallMem: {
            if (instruction.operands.size() != 1 || !instruction.fallthrough) {
                throw std::runtime_error("internal decoder error: indirect call operands");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            if (memory.width != 64 || (memory.ripRelative && memory.hasBase) ||
                (!memory.ripRelative && !memory.hasBase)) {
                throw std::runtime_error(
                    "only based and RIP-relative qword memory CALL are implemented");
            }
            auto address =
                memory.ripRelative
                    ? builder.constant(instruction.address.value + instruction.length,
                                       ir::Width::I64, instruction.address)
                    : builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            if (memory.index) {
                auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
                if (memory.scale != 1) {
                    index = builder.shiftLeft(
                        index, static_cast<std::uint8_t>(std::countr_zero(memory.scale)),
                        ir::Width::I64, instruction.address);
                }
                address = builder.add(address, index, ir::Width::I64, instruction.address);
            }
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(address, displacement, ir::Width::I64, instruction.address);
            }
            const auto target = builder.loadGuest(address, ir::Width::I64, instruction.address);
            builder.exitCall(target, *instruction.fallthrough, instruction.address);
            break;
        }
        case x86::Opcode::Syscall:
            builder.exitSyscall(*instruction.fallthrough, instruction.address);
            break;
        case x86::Opcode::Ret:
            builder.exitBlock(instruction.address);
            break;
        }
    }

    if (!terminatesBlock(decoded.back().opcode)) {
        const auto &last = decoded.back();
        if (last.address.value > std::numeric_limits<std::uint64_t>::max() - last.length) {
            throw std::runtime_error("x86 instruction fallthrough overflows guest RIP");
        }
        builder.exitDirect(guest::GuestAddress{last.address.value + last.length}, last.address);
    }

    auto block = std::move(builder).finish();
#ifndef NDEBUG
    const auto errors = ir::verify(block);
    if (!errors.empty()) {
        throw std::runtime_error("IR verification failed: " + errors.front());
    }
#endif
    return block;
}

} // namespace rosa::x86
