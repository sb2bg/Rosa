#include "dbt/LlvmBackend.h"
#include "guest/AddressSpace.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#if ROSA_HAS_LLVM

#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/OptimizationLevel.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include <atomic>
#include <mutex>

#endif

namespace rosa::dbt {
namespace {

constexpr std::size_t guestRegisterCount = 16;

struct MemoryLoopPlan {
    enum class Access : std::uint8_t { Read, Write };
    enum class Termination : std::uint8_t { ExactNotEqual, UnsignedBelow };

    x86::Register inductionRegister{};
    x86::Register baseRegister{};
    std::optional<x86::Register> stepRegister;
    std::uint64_t constantStep{};
    std::uint64_t limit{};
    std::uint64_t minimumOffset{};
    std::uint64_t maximumOffset{};
    Access access{Access::Read};
    Termination termination{Termination::ExactNotEqual};
};

struct LoopAnalysis {
    std::array<bool, guestRegisterCount> touchedRegisters{};
    const ir::Operation *finalFlags{};
    const ir::Operation *exit{};
    bool selfEdgeWhenConditionTrue{};
    std::optional<MemoryLoopPlan> memory;
};

bool isReplacingFlagUpdate(ir::Opcode opcode) noexcept {
    return opcode == ir::Opcode::UpdateAddFlags || opcode == ir::Opcode::UpdateSubFlags ||
           opcode == ir::Opcode::UpdateLogicFlags;
}

bool isPreservingCarryFlagUpdate(ir::Opcode opcode) noexcept {
    return opcode == ir::Opcode::UpdateIncFlags || opcode == ir::Opcode::UpdateDecFlags;
}

std::optional<LoopAnalysis> analyzeLoop(const ir::Block &block) {
    if (block.operations.empty() || block.valueCount == 0) {
        return std::nullopt;
    }

    LoopAnalysis analysis;
    std::vector<bool> defined(block.valueCount, false);
    std::vector<const ir::Operation *> definitions(block.valueCount, nullptr);
    std::vector<ir::Opcode> flagUpdates;
    std::vector<const ir::Operation *> memoryOperations;
    bool flagsAvailable = false;

    const auto define = [&defined, &definitions](const std::optional<ir::ValueId> &value,
                                                 const ir::Operation &operation) {
        if (!value || value->value >= defined.size() || defined[value->value]) {
            return false;
        }
        defined[value->value] = true;
        definitions[value->value] = &operation;
        return true;
    };
    const auto use = [&defined](const std::optional<ir::ValueId> &value) {
        return value && value->value < defined.size() && defined[value->value];
    };
    const auto touch = [&analysis](const std::optional<x86::Register> &guestRegister) {
        if (!guestRegister) {
            return false;
        }
        const auto index = static_cast<std::size_t>(*guestRegister);
        if (index >= analysis.touchedRegisters.size()) {
            return false;
        }
        analysis.touchedRegisters[index] = true;
        return true;
    };

    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];

        switch (operation.opcode) {
        case ir::Opcode::Constant:
            if (!define(operation.result, operation)) {
                return std::nullopt;
            }
            break;
        case ir::Opcode::ReadGuestReg:
            if (!touch(operation.guestRegister) || !define(operation.result, operation)) {
                return std::nullopt;
            }
            break;
        case ir::Opcode::WriteGuestReg:
            if (!touch(operation.guestRegister) || !use(operation.lhs)) {
                return std::nullopt;
            }
            break;
        case ir::Opcode::ConditionalMoveGuestReg:
            if (!touch(operation.guestRegister) || !operation.condition || !flagsAvailable ||
                (operation.lhs && !use(operation.lhs)) ||
                (!operation.lhs && operation.immediate >= guestRegisterCount)) {
                return std::nullopt;
            }
            if (!operation.lhs) {
                analysis.touchedRegisters[operation.immediate] = true;
            }
            break;
        case ir::Opcode::Add:
        case ir::Opcode::Sub:
        case ir::Opcode::And:
        case ir::Opcode::Or:
        case ir::Opcode::Xor:
            if (!use(operation.lhs) || !use(operation.rhs) ||
                !define(operation.result, operation)) {
                return std::nullopt;
            }
            break;
        case ir::Opcode::EvaluateCondition:
            if (!operation.condition || !flagsAvailable || !define(operation.result, operation)) {
                return std::nullopt;
            }
            break;
        case ir::Opcode::LoadGuest:
            if (operation.width != ir::Width::I8 || !use(operation.lhs) ||
                !define(operation.result, operation)) {
                return std::nullopt;
            }
            memoryOperations.push_back(&operation);
            break;
        case ir::Opcode::StoreGuest:
            if (operation.width != ir::Width::I8 || !use(operation.lhs) || !use(operation.rhs)) {
                return std::nullopt;
            }
            memoryOperations.push_back(&operation);
            break;
        case ir::Opcode::UpdateAddFlags:
        case ir::Opcode::UpdateSubFlags:
            if (!use(operation.lhs) || !use(operation.rhs) || !use(operation.third)) {
                return std::nullopt;
            }
            flagUpdates.push_back(operation.opcode);
            analysis.finalFlags = &operation;
            flagsAvailable = true;
            break;
        case ir::Opcode::UpdateIncFlags:
        case ir::Opcode::UpdateDecFlags:
            if (!use(operation.lhs) || !use(operation.rhs)) {
                return std::nullopt;
            }
            flagUpdates.push_back(operation.opcode);
            analysis.finalFlags = &operation;
            flagsAvailable = true;
            break;
        case ir::Opcode::UpdateLogicFlags:
            if (!use(operation.lhs)) {
                return std::nullopt;
            }
            flagUpdates.push_back(operation.opcode);
            analysis.finalFlags = &operation;
            flagsAvailable = true;
            break;
        case ir::Opcode::ExitBlock: {
            if (index + 1 != block.operations.size() ||
                operation.exitKind != ir::ExitKind::Conditional || !operation.condition ||
                !operation.target || !operation.fallthrough) {
                return std::nullopt;
            }
            const auto targetIsSelf = *operation.target == block.start;
            const auto fallthroughIsSelf = *operation.fallthrough == block.start;
            if (targetIsSelf == fallthroughIsSelf) {
                return std::nullopt;
            }
            analysis.exit = &operation;
            analysis.selfEdgeWhenConditionTrue = targetIsSelf;
            break;
        }
        default:
            return std::nullopt;
        }
    }

    if (!analysis.finalFlags || !analysis.exit || flagUpdates.empty()) {
        return std::nullopt;
    }

    // INC and DEC preserve CF. If an earlier instruction in the same block
    // replaced CF, the final carry value is loop-carried state rather than the
    // entry value. Keep that uncommon shape on the baseline tier for now.
    if (isPreservingCarryFlagUpdate(analysis.finalFlags->opcode)) {
        for (std::size_t index = 0; index + 1 < flagUpdates.size(); ++index) {
            if (isReplacingFlagUpdate(flagUpdates[index])) {
                return std::nullopt;
            }
        }
    }

    if (!memoryOperations.empty()) {
        const auto &update = *analysis.finalFlags;
        const auto &exit = *analysis.exit;
        const auto access = memoryOperations.front()->opcode == ir::Opcode::LoadGuest
                                ? MemoryLoopPlan::Access::Read
                                : MemoryLoopPlan::Access::Write;
        if (std::ranges::any_of(memoryOperations, [&](const auto *operation) {
                return (operation->opcode == ir::Opcode::LoadGuest) !=
                       (access == MemoryLoopPlan::Access::Read);
            })) {
            return std::nullopt;
        }
        const auto termination = exit.condition == x86::Condition::NotEqual
                                     ? MemoryLoopPlan::Termination::ExactNotEqual
                                     : MemoryLoopPlan::Termination::UnsignedBelow;
        if (update.opcode != ir::Opcode::UpdateSubFlags || update.width != ir::Width::I64 ||
            !update.lhs || !update.rhs || !analysis.selfEdgeWhenConditionTrue ||
            (access == MemoryLoopPlan::Access::Read &&
             exit.condition != x86::Condition::NotEqual) ||
            (access == MemoryLoopPlan::Access::Write && exit.condition != x86::Condition::Below)) {
            return std::nullopt;
        }
        const auto *limit = definitions[update.rhs->value];
        if (limit == nullptr || limit->opcode != ir::Opcode::Constant || limit->immediate == 0) {
            return std::nullopt;
        }

        std::optional<x86::Register> inductionRegister;
        std::optional<x86::Register> stepRegister;
        std::uint64_t constantStep{};
        std::size_t inductionWriteIndex = block.operations.size();
        for (std::size_t operationIndex = 0; operationIndex < block.operations.size();
             ++operationIndex) {
            const auto &operation = block.operations[operationIndex];
            if (operation.opcode != ir::Opcode::WriteGuestReg ||
                operation.width != ir::Width::I64 || !operation.guestRegister ||
                operation.lhs != update.lhs) {
                continue;
            }
            const auto *increment = definitions[operation.lhs->value];
            if (increment == nullptr || increment->opcode != ir::Opcode::Add ||
                increment->width != ir::Width::I64 || !increment->lhs || !increment->rhs) {
                continue;
            }
            for (const auto [readValue, stepValue] :
                 {std::pair{*increment->lhs, *increment->rhs},
                  std::pair{*increment->rhs, *increment->lhs}}) {
                const auto *read = definitions[readValue.value];
                const auto *stepDefinition = definitions[stepValue.value];
                if (read != nullptr && read->opcode == ir::Opcode::ReadGuestReg &&
                    read->width == ir::Width::I64 &&
                    read->guestRegister == operation.guestRegister && stepDefinition != nullptr &&
                    (stepDefinition->opcode == ir::Opcode::Constant ||
                     stepDefinition->opcode == ir::Opcode::ReadGuestReg)) {
                    inductionRegister = operation.guestRegister;
                    if (stepDefinition->opcode == ir::Opcode::Constant) {
                        constantStep = stepDefinition->immediate;
                    } else if (stepDefinition->width == ir::Width::I64 &&
                               stepDefinition->guestRegister) {
                        stepRegister = stepDefinition->guestRegister;
                    }
                    inductionWriteIndex = operationIndex;
                    break;
                }
            }
        }
        if (!inductionRegister || (!stepRegister && constantStep == 0)) {
            return std::nullopt;
        }
        const auto inductionWrites =
            std::ranges::count_if(block.operations, [&](const auto &operation) {
                return operation.guestRegister == inductionRegister &&
                       (operation.opcode == ir::Opcode::WriteGuestReg ||
                        operation.opcode == ir::Opcode::ConditionalMoveGuestReg);
            });
        if (inductionWrites != 1 || (stepRegister && *stepRegister == *inductionRegister)) {
            return std::nullopt;
        }

        std::optional<x86::Register> baseRegister;
        auto minimumOffset = UINT64_MAX;
        std::uint64_t maximumOffset{};
        for (const auto *memoryOperation : memoryOperations) {
            std::uint64_t offset{};
            std::size_t inductionTerms{};
            std::size_t baseTerms{};
            std::optional<x86::Register> loadBase;
            std::function<bool(ir::ValueId, std::size_t)> flatten = [&](ir::ValueId value,
                                                                        std::size_t depth) {
                if (depth > block.valueCount) {
                    return false;
                }
                const auto *definition = definitions[value.value];
                if (definition == nullptr) {
                    return false;
                }
                if (definition->opcode == ir::Opcode::Add && definition->width == ir::Width::I64 &&
                    definition->lhs && definition->rhs) {
                    return flatten(*definition->lhs, depth + 1) &&
                           flatten(*definition->rhs, depth + 1);
                }
                if (definition->opcode == ir::Opcode::Constant) {
                    if (definition->immediate > UINT64_MAX - offset) {
                        return false;
                    }
                    offset += definition->immediate;
                    return true;
                }
                if (definition->opcode != ir::Opcode::ReadGuestReg ||
                    definition->width != ir::Width::I64 || !definition->guestRegister) {
                    return false;
                }
                if (definition->guestRegister == inductionRegister) {
                    const auto definitionIndex =
                        static_cast<std::size_t>(definition - block.operations.data());
                    if (definitionIndex >= inductionWriteIndex) {
                        return false;
                    }
                    ++inductionTerms;
                    return inductionTerms == 1;
                }
                if (loadBase && loadBase != definition->guestRegister) {
                    return false;
                }
                loadBase = definition->guestRegister;
                ++baseTerms;
                return baseTerms == 1;
            };
            if (!memoryOperation->lhs || !flatten(*memoryOperation->lhs, 0) ||
                inductionTerms != 1 || baseTerms != 1 || !loadBase ||
                *loadBase == *inductionRegister || (baseRegister && baseRegister != loadBase)) {
                return std::nullopt;
            }
            baseRegister = loadBase;
            minimumOffset = std::min(minimumOffset, offset);
            maximumOffset = std::max(maximumOffset, offset);
        }
        if (!baseRegister) {
            return std::nullopt;
        }
        const auto baseChanges = std::ranges::any_of(block.operations, [&](const auto &operation) {
            return operation.guestRegister == baseRegister &&
                   (operation.opcode == ir::Opcode::WriteGuestReg ||
                    operation.opcode == ir::Opcode::ConditionalMoveGuestReg);
        });
        if (baseChanges) {
            return std::nullopt;
        }
        const auto stepChanges =
            stepRegister && std::ranges::any_of(block.operations, [&](const auto &operation) {
                return operation.guestRegister == stepRegister &&
                       (operation.opcode == ir::Opcode::WriteGuestReg ||
                        operation.opcode == ir::Opcode::ConditionalMoveGuestReg);
            });
        if (stepChanges || (stepRegister && *stepRegister == *baseRegister)) {
            return std::nullopt;
        }
        analysis.memory = MemoryLoopPlan{*inductionRegister, *baseRegister,    stepRegister,
                                         constantStep,       limit->immediate, minimumOffset,
                                         maximumOffset,      access,           termination};
    }

    return analysis;
}

struct PreparedMemory {
    std::uint8_t *bytes{};
    std::uint64_t guestBase{};
};

std::optional<PreparedMemory> prepareMemory(const MemoryLoopPlan &plan, x86::X86State &state,
                                            guest::AddressSpace *addressSpace,
                                            std::size_t maximumExecutions) noexcept {
    if (addressSpace == nullptr || maximumExecutions == 0) {
        return std::nullopt;
    }
    const auto readRegister = [&](x86::Register reg) {
        std::uint64_t value{};
        std::memcpy(&value, reinterpret_cast<const std::byte *>(&state) + x86::registerOffset(reg),
                    sizeof(value));
        return value;
    };
    const auto induction = readRegister(plan.inductionRegister);
    const auto base = readRegister(plan.baseRegister);
    const auto step = plan.stepRegister ? readRegister(*plan.stepRegister) : plan.constantStep;
    if (step == 0 || induction >= plan.limit) {
        return std::nullopt;
    }
    const auto remaining = plan.limit - induction;
    std::uint64_t naturalExecutions{};
    if (plan.termination == MemoryLoopPlan::Termination::ExactNotEqual) {
        if (remaining < step || remaining % step != 0) {
            return std::nullopt;
        }
        naturalExecutions = remaining / step;
    } else {
        naturalExecutions = 1U + (remaining - 1U) / step;
    }
    const auto executions =
        std::min<std::uint64_t>(naturalExecutions, static_cast<std::uint64_t>(maximumExecutions));
    if (executions == 0 || executions - 1U > UINT64_MAX / step) {
        return std::nullopt;
    }
    const auto lastAdvance = (executions - 1U) * step;
    const auto checkedAdd = [](std::uint64_t lhs,
                               std::uint64_t rhs) -> std::optional<std::uint64_t> {
        if (rhs > UINT64_MAX - lhs) {
            return std::nullopt;
        }
        return lhs + rhs;
    };
    const auto firstInductionAddress = checkedAdd(base, induction);
    const auto firstAddress = firstInductionAddress
                                  ? checkedAdd(*firstInductionAddress, plan.minimumOffset)
                                  : std::nullopt;
    const auto lastInduction = checkedAdd(induction, lastAdvance);
    const auto lastInductionAddress =
        lastInduction ? checkedAdd(base, *lastInduction) : std::nullopt;
    const auto lastAddress =
        lastInductionAddress ? checkedAdd(*lastInductionAddress, plan.maximumOffset) : std::nullopt;
    if (!firstAddress || !lastAddress || *lastAddress < *firstAddress) {
        return std::nullopt;
    }
    if (plan.termination == MemoryLoopPlan::Termination::UnsignedBelow &&
        executions == naturalExecutions && (!lastInduction || step > UINT64_MAX - *lastInduction)) {
        return std::nullopt;
    }
    try {
        const auto view = addressSpace->directMemoryView(guest::GuestAddress{*firstAddress},
                                                         plan.access == MemoryLoopPlan::Access::Read
                                                             ? guest::Permission::Read
                                                             : guest::Permission::Write);
        if (!view || *lastAddress < view->base.value ||
            *lastAddress - view->base.value >= view->bytes.size()) {
            return std::nullopt;
        }
        return PreparedMemory{view->bytes.data(), view->base.value};
    } catch (...) {
        return std::nullopt;
    }
}

#if ROSA_HAS_LLVM

constexpr std::uint64_t flagCarry = UINT64_C(1) << 0U;
constexpr std::uint64_t flagReservedOne = UINT64_C(1) << 1U;
constexpr std::uint64_t flagParity = UINT64_C(1) << 2U;
constexpr std::uint64_t flagAuxiliaryCarry = UINT64_C(1) << 4U;
constexpr std::uint64_t flagZero = UINT64_C(1) << 6U;
constexpr std::uint64_t flagSign = UINT64_C(1) << 7U;
constexpr std::uint64_t flagOverflow = UINT64_C(1) << 11U;
constexpr std::uint64_t arithmeticFlagMask =
    flagCarry | flagParity | flagAuxiliaryCarry | flagZero | flagSign | flagOverflow;

struct PendingFlags {
    ir::Opcode opcode{};
    ir::Width width{ir::Width::I64};
    llvm::Value *lhs{};
    llvm::Value *rhs{};
    llvm::Value *result{};
};

struct FlagValues {
    llvm::Value *carry{};
    llvm::Value *parity{};
    llvm::Value *auxiliaryCarry{};
    llvm::Value *zero{};
    llvm::Value *sign{};
    llvm::Value *overflow{};
};

std::runtime_error llvmError(const std::string &prefix, llvm::Error error) {
    return std::runtime_error(prefix + llvm::toString(std::move(error)));
}

struct CompiledLoop {
    OptimizedLoopEntry entry{};
    llvm::orc::ResourceTrackerSP resources;
};

class LlvmEngine {
  public:
    LlvmEngine() {
        if (llvm::InitializeNativeTarget()) {
            throw std::runtime_error("LLVM could not initialize the native target");
        }
        if (llvm::InitializeNativeTargetAsmPrinter()) {
            throw std::runtime_error("LLVM could not initialize the native assembly printer");
        }

        auto created = llvm::orc::LLJITBuilder().create();
        if (!created) {
            throw llvmError("LLVM ORC initialization failed: ", created.takeError());
        }
        jit_ = std::move(*created);
    }

    CompiledLoop compile(const ir::Block &block, const LoopAnalysis &analysis) {
        std::scoped_lock lock(mutex_);

        auto context = std::make_unique<llvm::LLVMContext>();
        auto module = std::make_unique<llvm::Module>("rosa.hot-loop", *context);
        module->setDataLayout(jit_->getDataLayout());
        module->setTargetTriple(jit_->getTargetTriple());

        const auto serial = nextFunction_.fetch_add(1, std::memory_order_relaxed);
        const auto functionName = "rosa_optimized_loop_" + std::to_string(serial);
        buildLoop(*module, functionName, block, analysis);
        optimize(*module);

        std::string verification;
        llvm::raw_string_ostream verificationStream(verification);
        if (llvm::verifyModule(*module, &verificationStream)) {
            verificationStream.flush();
            throw std::runtime_error("invalid LLVM module for optimized loop: " + verification);
        }

        auto resources = jit_->getMainJITDylib().createResourceTracker();
        if (auto error = jit_->addIRModule(
                resources, llvm::orc::ThreadSafeModule(std::move(module), std::move(context)))) {
            throw llvmError("LLVM could not add optimized loop: ", std::move(error));
        }
        auto symbol = jit_->lookup(functionName);
        if (!symbol) {
            throw llvmError("LLVM could not find optimized loop: ", symbol.takeError());
        }
        return CompiledLoop{symbol->toPtr<OptimizedLoopEntry>(), std::move(resources)};
    }

  private:
    static llvm::ConstantInt *constant64(llvm::LLVMContext &context, std::uint64_t value) {
        return llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), value);
    }

    static std::uint32_t widthBits(ir::Width width) { return static_cast<std::uint32_t>(width); }

    static std::uint64_t widthMask(ir::Width width) {
        return width == ir::Width::I64 ? UINT64_MAX : (UINT64_C(1) << widthBits(width)) - 1U;
    }

    static llvm::Value *normalize(llvm::IRBuilder<> &builder, llvm::Value *value, ir::Width width) {
        if (width == ir::Width::I64) {
            return value;
        }
        return builder.CreateAnd(value, constant64(builder.getContext(), widthMask(width)));
    }

    static llvm::Value *stateAddress(llvm::IRBuilder<> &builder, llvm::Value *state,
                                     std::size_t offset) {
        return builder.CreateGEP(llvm::Type::getInt8Ty(builder.getContext()), state,
                                 constant64(builder.getContext(), offset));
    }

    static llvm::Value *loadState64(llvm::IRBuilder<> &builder, llvm::Value *state,
                                    std::size_t offset, const llvm::Twine &name) {
        return builder.CreateLoad(llvm::Type::getInt64Ty(builder.getContext()),
                                  stateAddress(builder, state, offset), name);
    }

    static void storeState64(llvm::IRBuilder<> &builder, llvm::Value *state, std::size_t offset,
                             llvm::Value *value) {
        builder.CreateStore(value, stateAddress(builder, state, offset));
    }

    static llvm::Value *parityEven(llvm::IRBuilder<> &builder, llvm::Value *value) {
        auto *parity = builder.CreateXor(
            value, builder.CreateLShr(value, constant64(builder.getContext(), 4)));
        parity = builder.CreateXor(parity,
                                   builder.CreateLShr(parity, constant64(builder.getContext(), 2)));
        parity = builder.CreateXor(parity,
                                   builder.CreateLShr(parity, constant64(builder.getContext(), 1)));
        return builder.CreateICmpEQ(builder.CreateAnd(parity, constant64(builder.getContext(), 1)),
                                    constant64(builder.getContext(), 0));
    }

    static llvm::Value *bitIsSet(llvm::IRBuilder<> &builder, llvm::Value *value,
                                 std::uint64_t mask) {
        return builder.CreateICmpNE(
            builder.CreateAnd(value, constant64(builder.getContext(), mask)),
            constant64(builder.getContext(), 0));
    }

    static FlagValues calculateFlags(llvm::IRBuilder<> &builder, llvm::Value *incomingFlags,
                                     const PendingFlags &pending) {
        auto &context = builder.getContext();
        auto *result = normalize(builder, pending.result, pending.width);
        auto *lhs = pending.lhs ? normalize(builder, pending.lhs, pending.width) : nullptr;
        auto *rhs = pending.rhs ? normalize(builder, pending.rhs, pending.width) : nullptr;
        const auto signMask = UINT64_C(1) << (widthBits(pending.width) - 1U);
        auto *falseValue = llvm::ConstantInt::getFalse(context);
        FlagValues flags{
            .carry = falseValue,
            .parity = parityEven(builder, result),
            .auxiliaryCarry = falseValue,
            .zero = builder.CreateICmpEQ(result, constant64(context, 0)),
            .sign = bitIsSet(builder, result, signMask),
            .overflow = falseValue,
        };

        switch (pending.opcode) {
        case ir::Opcode::UpdateAddFlags:
            flags.carry = builder.CreateICmpULT(result, lhs);
            flags.auxiliaryCarry =
                bitIsSet(builder, builder.CreateXor(builder.CreateXor(lhs, rhs), result),
                         flagAuxiliaryCarry);
            flags.overflow =
                bitIsSet(builder,
                         builder.CreateAnd(builder.CreateNot(builder.CreateXor(lhs, rhs)),
                                           builder.CreateXor(lhs, result)),
                         signMask);
            break;
        case ir::Opcode::UpdateSubFlags:
            flags.carry = builder.CreateICmpULT(lhs, rhs);
            flags.auxiliaryCarry =
                bitIsSet(builder, builder.CreateXor(builder.CreateXor(lhs, rhs), result),
                         flagAuxiliaryCarry);
            flags.overflow = bitIsSet(
                builder,
                builder.CreateAnd(builder.CreateXor(lhs, rhs), builder.CreateXor(lhs, result)),
                signMask);
            break;
        case ir::Opcode::UpdateIncFlags:
        case ir::Opcode::UpdateDecFlags:
            flags.carry = bitIsSet(builder, incomingFlags, flagCarry);
            flags.auxiliaryCarry = bitIsSet(
                builder, builder.CreateXor(builder.CreateXor(lhs, constant64(context, 1)), result),
                flagAuxiliaryCarry);
            flags.overflow = builder.CreateICmpEQ(
                lhs,
                constant64(context, pending.opcode == ir::Opcode::UpdateIncFlags ? signMask - 1U
                                                                                 : signMask));
            break;
        case ir::Opcode::UpdateLogicFlags:
            break;
        default:
            throw std::runtime_error("LLVM loop lowering received unsupported flags");
        }
        return flags;
    }

    static llvm::Value *conditionValue(llvm::IRBuilder<> &builder, x86::Condition condition,
                                       const FlagValues &flags) {
        switch (condition) {
        case x86::Condition::Overflow:
            return flags.overflow;
        case x86::Condition::Equal:
            return flags.zero;
        case x86::Condition::NotEqual:
            return builder.CreateNot(flags.zero);
        case x86::Condition::Below:
            return flags.carry;
        case x86::Condition::AboveOrEqual:
            return builder.CreateNot(flags.carry);
        case x86::Condition::Above:
            return builder.CreateNot(builder.CreateOr(flags.carry, flags.zero));
        case x86::Condition::BelowOrEqual:
            return builder.CreateOr(flags.carry, flags.zero);
        case x86::Condition::Sign:
            return flags.sign;
        case x86::Condition::NotSign:
            return builder.CreateNot(flags.sign);
        case x86::Condition::Less:
            return builder.CreateXor(flags.sign, flags.overflow);
        case x86::Condition::GreaterOrEqual:
            return builder.CreateNot(builder.CreateXor(flags.sign, flags.overflow));
        case x86::Condition::LessOrEqual:
            return builder.CreateOr(flags.zero, builder.CreateXor(flags.sign, flags.overflow));
        case x86::Condition::Greater:
            return builder.CreateNot(
                builder.CreateOr(flags.zero, builder.CreateXor(flags.sign, flags.overflow)));
        }
        throw std::runtime_error("LLVM loop lowering received unsupported condition");
    }

    static llvm::Value *flagWhen(llvm::IRBuilder<> &builder, llvm::Value *condition,
                                 std::uint64_t flag) {
        return builder.CreateSelect(condition, constant64(builder.getContext(), flag),
                                    constant64(builder.getContext(), 0));
    }

    static llvm::Value *materializeFlags(llvm::IRBuilder<> &builder, llvm::Value *incomingFlags,
                                         const PendingFlags &pending, const FlagValues &values) {
        auto replacedFlags = arithmeticFlagMask;
        if (isPreservingCarryFlagUpdate(pending.opcode)) {
            replacedFlags &= ~flagCarry;
        }
        auto *flags = builder.CreateOr(
            builder.CreateAnd(incomingFlags, constant64(builder.getContext(), ~replacedFlags)),
            constant64(builder.getContext(), flagReservedOne));
        flags = builder.CreateOr(flags, flagWhen(builder, values.carry, flagCarry));
        flags = builder.CreateOr(flags, flagWhen(builder, values.parity, flagParity));
        flags =
            builder.CreateOr(flags, flagWhen(builder, values.auxiliaryCarry, flagAuxiliaryCarry));
        flags = builder.CreateOr(flags, flagWhen(builder, values.zero, flagZero));
        flags = builder.CreateOr(flags, flagWhen(builder, values.sign, flagSign));
        return builder.CreateOr(flags, flagWhen(builder, values.overflow, flagOverflow));
    }

    static void buildLoop(llvm::Module &module, const std::string &functionName,
                          const ir::Block &block, const LoopAnalysis &analysis) {
        auto &context = module.getContext();
        auto *i64 = llvm::Type::getInt64Ty(context);
        auto *pointer = llvm::PointerType::get(context, 0);
        auto *functionType = llvm::FunctionType::get(
            i64, std::array<llvm::Type *, 4>{pointer, i64, pointer, i64}, false);
        auto *function = llvm::Function::Create(functionType, llvm::GlobalValue::ExternalLinkage,
                                                functionName, module);
        function->setCallingConv(llvm::CallingConv::C);

        auto arguments = function->arg_begin();
        llvm::Value *state = arguments++;
        state->setName("state");
        llvm::Value *maximumExecutions = arguments++;
        maximumExecutions->setName("maximum_executions");
        llvm::Value *memoryBytes = arguments++;
        memoryBytes->setName("memory_bytes");
        llvm::Value *memoryGuestBase = arguments++;
        memoryGuestBase->setName("memory_guest_base");

        auto *entry = llvm::BasicBlock::Create(context, "entry", function);
        auto *body = llvm::BasicBlock::Create(context, "loop", function);
        auto *exit = llvm::BasicBlock::Create(context, "exit", function);
        llvm::IRBuilder<> builder(entry);

        std::array<llvm::Value *, guestRegisterCount> initialRegisters{};
        for (std::size_t index = 0; index < guestRegisterCount; ++index) {
            if (!analysis.touchedRegisters[index]) {
                continue;
            }
            const auto reg = static_cast<x86::Register>(index);
            initialRegisters[index] = loadState64(builder, state, x86::registerOffset(reg),
                                                  llvm::Twine("initial_") + x86::registerName(reg));
        }
        auto *incomingFlags =
            loadState64(builder, state, offsetof(x86::X86State, rflags), "incoming_flags");
        builder.CreateBr(body);

        builder.SetInsertPoint(body);
        std::array<llvm::PHINode *, guestRegisterCount> registerPhis{};
        std::array<llvm::Value *, guestRegisterCount> currentRegisters{};
        for (std::size_t index = 0; index < guestRegisterCount; ++index) {
            if (!analysis.touchedRegisters[index]) {
                continue;
            }
            registerPhis[index] = builder.CreatePHI(i64, 2);
            registerPhis[index]->addIncoming(initialRegisters[index], entry);
            currentRegisters[index] = registerPhis[index];
        }
        auto *remaining = builder.CreatePHI(i64, 2, "remaining");
        remaining->addIncoming(maximumExecutions, entry);

        std::vector<llvm::Value *> values(block.valueCount, nullptr);
        PendingFlags pending;
        const auto writeGuestRegister = [&](x86::Register guestRegister, ir::Width width,
                                            llvm::Value *source) {
            const auto index = static_cast<std::size_t>(guestRegister);
            source = normalize(builder, source, width);
            if (width == ir::Width::I64 || width == ir::Width::I32) {
                currentRegisters[index] = source;
                return;
            }
            const auto mask = widthMask(width);
            currentRegisters[index] = builder.CreateOr(
                builder.CreateAnd(currentRegisters[index], constant64(context, ~mask)), source);
        };
        for (const auto &operation : block.operations) {
            const auto value = [&values](const std::optional<ir::ValueId> &id) {
                return values[id->value];
            };
            switch (operation.opcode) {
            case ir::Opcode::Constant:
                values[operation.result->value] =
                    constant64(context, operation.immediate & widthMask(operation.width));
                break;
            case ir::Opcode::ReadGuestReg:
                values[operation.result->value] = normalize(
                    builder, currentRegisters[static_cast<std::size_t>(*operation.guestRegister)],
                    operation.width);
                break;
            case ir::Opcode::WriteGuestReg:
                writeGuestRegister(*operation.guestRegister, operation.width, value(operation.lhs));
                break;
            case ir::Opcode::ConditionalMoveGuestReg: {
                const auto flags = calculateFlags(builder, incomingFlags, pending);
                auto *condition = conditionValue(builder, *operation.condition, flags);
                auto *source =
                    operation.lhs ? value(operation.lhs) : currentRegisters[operation.immediate];
                const auto index = static_cast<std::size_t>(*operation.guestRegister);
                auto *selected = builder.CreateSelect(
                    condition, normalize(builder, source, operation.width),
                    normalize(builder, currentRegisters[index], operation.width));
                writeGuestRegister(*operation.guestRegister, operation.width, selected);
                break;
            }
            case ir::Opcode::Add:
                values[operation.result->value] = normalize(
                    builder, builder.CreateAdd(value(operation.lhs), value(operation.rhs)),
                    operation.width);
                break;
            case ir::Opcode::Sub:
                values[operation.result->value] = normalize(
                    builder, builder.CreateSub(value(operation.lhs), value(operation.rhs)),
                    operation.width);
                break;
            case ir::Opcode::And:
                values[operation.result->value] = normalize(
                    builder, builder.CreateAnd(value(operation.lhs), value(operation.rhs)),
                    operation.width);
                break;
            case ir::Opcode::Or:
                values[operation.result->value] =
                    normalize(builder, builder.CreateOr(value(operation.lhs), value(operation.rhs)),
                              operation.width);
                break;
            case ir::Opcode::Xor:
                values[operation.result->value] = normalize(
                    builder, builder.CreateXor(value(operation.lhs), value(operation.rhs)),
                    operation.width);
                break;
            case ir::Opcode::EvaluateCondition: {
                const auto flags = calculateFlags(builder, incomingFlags, pending);
                auto *condition = conditionValue(builder, *operation.condition, flags);
                values[operation.result->value] = builder.CreateZExt(condition, i64);
                break;
            }
            case ir::Opcode::LoadGuest: {
                auto *offset = builder.CreateSub(value(operation.lhs), memoryGuestBase);
                auto *address =
                    builder.CreateGEP(llvm::Type::getInt8Ty(context), memoryBytes, offset);
                auto *loaded = builder.CreateLoad(llvm::Type::getInt8Ty(context), address);
                values[operation.result->value] = builder.CreateZExt(loaded, i64);
                break;
            }
            case ir::Opcode::StoreGuest: {
                auto *offset = builder.CreateSub(value(operation.lhs), memoryGuestBase);
                auto *address =
                    builder.CreateGEP(llvm::Type::getInt8Ty(context), memoryBytes, offset);
                builder.CreateStore(
                    builder.CreateTrunc(value(operation.rhs), llvm::Type::getInt8Ty(context)),
                    address);
                break;
            }
            case ir::Opcode::UpdateAddFlags:
            case ir::Opcode::UpdateSubFlags:
                pending = PendingFlags{operation.opcode, operation.width, value(operation.lhs),
                                       value(operation.rhs), value(operation.third)};
                break;
            case ir::Opcode::UpdateIncFlags:
            case ir::Opcode::UpdateDecFlags:
                pending = PendingFlags{operation.opcode, operation.width, value(operation.lhs),
                                       nullptr, value(operation.rhs)};
                break;
            case ir::Opcode::UpdateLogicFlags:
                pending = PendingFlags{operation.opcode, operation.width, nullptr, nullptr,
                                       value(operation.lhs)};
                break;
            case ir::Opcode::ExitBlock:
                break;
            default:
                throw std::runtime_error("LLVM loop lowering received unsupported IR");
            }
        }

        auto *nextRemaining =
            builder.CreateSub(remaining, constant64(context, 1), "next_remaining");
        const auto flags = calculateFlags(builder, incomingFlags, pending);
        auto *condition = conditionValue(builder, *analysis.exit->condition, flags);
        auto *continueLoop =
            analysis.selfEdgeWhenConditionTrue ? condition : builder.CreateNot(condition);
        auto *hasBudget = builder.CreateICmpNE(nextRemaining, constant64(context, 0));
        builder.CreateCondBr(builder.CreateAnd(continueLoop, hasBudget), body, exit);

        for (std::size_t index = 0; index < guestRegisterCount; ++index) {
            if (registerPhis[index]) {
                registerPhis[index]->addIncoming(currentRegisters[index], body);
            }
        }
        remaining->addIncoming(nextRemaining, body);

        builder.SetInsertPoint(exit);
        for (std::size_t index = 0; index < guestRegisterCount; ++index) {
            if (!analysis.touchedRegisters[index]) {
                continue;
            }
            storeState64(builder, state, x86::registerOffset(static_cast<x86::Register>(index)),
                         currentRegisters[index]);
        }
        storeState64(builder, state, offsetof(x86::X86State, rflags),
                     materializeFlags(builder, incomingFlags, pending, flags));
        auto *nextRip =
            builder.CreateSelect(condition, constant64(context, analysis.exit->target->value),
                                 constant64(context, analysis.exit->fallthrough->value));
        storeState64(builder, state, offsetof(x86::X86State, rip), nextRip);
        builder.CreateRet(builder.CreateSub(maximumExecutions, nextRemaining));
    }

    static void optimize(llvm::Module &module) {
        llvm::LoopAnalysisManager loops;
        llvm::FunctionAnalysisManager functions;
        llvm::CGSCCAnalysisManager callGraph;
        llvm::ModuleAnalysisManager modules;
        llvm::PassBuilder passBuilder;
        passBuilder.registerModuleAnalyses(modules);
        passBuilder.registerCGSCCAnalyses(callGraph);
        passBuilder.registerFunctionAnalyses(functions);
        passBuilder.registerLoopAnalyses(loops);
        passBuilder.crossRegisterProxies(loops, functions, callGraph, modules);
        auto pipeline = passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O2);
        pipeline.run(module, modules);
    }

    std::unique_ptr<llvm::orc::LLJIT> jit_;
    std::mutex mutex_;
    std::atomic<std::uint64_t> nextFunction_{0};
};

LlvmEngine &engine() {
    // LLVM's process-wide target registries may already be torn down during
    // static destruction. Keeping the engine alive until process exit avoids
    // a static-destruction ordering dependency.
    static auto *instance = new LlvmEngine;
    return *instance;
}

#endif

} // namespace

struct OptimizedLoop::Impl {
    OptimizedLoopEntry entry{};
    std::optional<MemoryLoopPlan> memory;
#if ROSA_HAS_LLVM
    llvm::orc::ResourceTrackerSP resources;
#endif
};

OptimizedLoop::OptimizedLoop(std::unique_ptr<Impl> implementation)
    : implementation_(std::move(implementation)) {}

OptimizedLoop::~OptimizedLoop() {
#if ROSA_HAS_LLVM
    if (implementation_ && implementation_->resources) {
        llvm::consumeError(implementation_->resources->remove());
    }
#endif
}

OptimizedLoop::OptimizedLoop(OptimizedLoop &&) noexcept = default;
OptimizedLoop &OptimizedLoop::operator=(OptimizedLoop &&) noexcept = default;

OptimizedLoopEntry OptimizedLoop::entry() const noexcept {
    return implementation_ ? implementation_->entry : nullptr;
}

std::optional<std::size_t> OptimizedLoop::execute(x86::X86State &state,
                                                  guest::AddressSpace *addressSpace,
                                                  std::size_t maximumExecutions) const {
    if (!implementation_ || implementation_->entry == nullptr) {
        return std::nullopt;
    }
    PreparedMemory prepared;
    if (implementation_->memory) {
        const auto memory =
            prepareMemory(*implementation_->memory, state, addressSpace, maximumExecutions);
        if (!memory) {
            return std::nullopt;
        }
        prepared = *memory;
    }
    return implementation_->entry(&state, maximumExecutions, prepared.bytes, prepared.guestBase);
}

std::unique_ptr<OptimizedLoop> compileOptimizedLoop(const ir::Block &block) {
    const auto analysis = analyzeLoop(block);
    if (!analysis) {
        return {};
    }
#if ROSA_HAS_LLVM
    auto compiled = engine().compile(block, *analysis);
    auto implementation = std::make_unique<OptimizedLoop::Impl>();
    implementation->entry = compiled.entry;
    implementation->memory = analysis->memory;
    implementation->resources = std::move(compiled.resources);
    return std::unique_ptr<OptimizedLoop>(new OptimizedLoop(std::move(implementation)));
#else
    return {};
#endif
}

bool canCompileOptimizedLoop(const ir::Block &block) noexcept {
    try {
        return analyzeLoop(block).has_value();
    } catch (...) {
        return false;
    }
}

bool optimizedLoopUsesMemory(const ir::Block &block) noexcept {
    try {
        const auto analysis = analyzeLoop(block);
        return analysis && analysis->memory.has_value();
    } catch (...) {
        return false;
    }
}

bool llvmBackendAvailable() noexcept {
#if ROSA_HAS_LLVM
    return true;
#else
    return false;
#endif
}

} // namespace rosa::dbt
