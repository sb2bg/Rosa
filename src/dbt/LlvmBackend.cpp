#include "dbt/LlvmBackend.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>

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
#include <memory>
#include <mutex>
#include <utility>

#endif

namespace rosa::dbt {
namespace {

struct DecrementLoop {
    x86::Register guestRegister{};
    guest::GuestAddress fallthrough{};
};

std::optional<DecrementLoop>
matchDecrementLoop(const ir::Block &block) {
    if (block.operations.size() != 6 || block.valueCount != 3) {
        return std::nullopt;
    }

    const auto &read = block.operations[0];
    const auto &one = block.operations[1];
    const auto &subtract = block.operations[2];
    const auto &write = block.operations[3];
    const auto &flags = block.operations[4];
    const auto &exit = block.operations[5];

    const auto isValue = [](const std::optional<ir::ValueId> &value,
                            std::uint32_t expected) {
        return value && value->value == expected;
    };

    if (read.opcode != ir::Opcode::ReadGuestReg ||
        read.width != ir::Width::I64 || !read.guestRegister ||
        !isValue(read.result, 0) ||
        one.opcode != ir::Opcode::Constant ||
        one.width != ir::Width::I64 || one.immediate != 1 ||
        !isValue(one.result, 1) ||
        subtract.opcode != ir::Opcode::Sub ||
        subtract.width != ir::Width::I64 ||
        !isValue(subtract.result, 2) || !isValue(subtract.lhs, 0) ||
        !isValue(subtract.rhs, 1) ||
        write.opcode != ir::Opcode::WriteGuestReg ||
        write.width != ir::Width::I64 ||
        write.guestRegister != read.guestRegister ||
        !isValue(write.lhs, 2) ||
        flags.opcode != ir::Opcode::UpdateDecFlags ||
        flags.width != ir::Width::I64 || !isValue(flags.lhs, 0) ||
        !isValue(flags.rhs, 2) ||
        exit.opcode != ir::Opcode::ExitBlock ||
        exit.exitKind != ir::ExitKind::Conditional ||
        exit.condition != x86::Condition::NotEqual ||
        exit.target != block.start || !exit.fallthrough) {
        return std::nullopt;
    }

    return DecrementLoop{*read.guestRegister, *exit.fallthrough};
}

#if ROSA_HAS_LLVM

constexpr std::uint64_t flagReservedOne = UINT64_C(1) << 1U;
constexpr std::uint64_t flagParity = UINT64_C(1) << 2U;
constexpr std::uint64_t flagAuxiliaryCarry = UINT64_C(1) << 4U;
constexpr std::uint64_t flagZero = UINT64_C(1) << 6U;
constexpr std::uint64_t flagSign = UINT64_C(1) << 7U;
constexpr std::uint64_t flagOverflow = UINT64_C(1) << 11U;
constexpr std::uint64_t replacedDecFlags =
    flagParity | flagAuxiliaryCarry | flagZero | flagSign | flagOverflow;

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
            throw std::runtime_error(
                "LLVM could not initialize the native assembly printer");
        }

        auto created = llvm::orc::LLJITBuilder().create();
        if (!created) {
            throw llvmError("LLVM ORC initialization failed: ",
                            created.takeError());
        }
        jit_ = std::move(*created);
    }

    CompiledLoop compile(const ir::Block &block,
                         const DecrementLoop &loop) {
        std::scoped_lock lock(mutex_);

        auto context = std::make_unique<llvm::LLVMContext>();
        auto module = std::make_unique<llvm::Module>("rosa.hot-loop", *context);
        module->setDataLayout(jit_->getDataLayout());
        module->setTargetTriple(jit_->getTargetTriple());

        const auto serial = nextFunction_.fetch_add(1, std::memory_order_relaxed);
        const auto functionName = "rosa_optimized_loop_" +
                                  std::to_string(serial);
        buildDecrementLoop(*module, functionName, block, loop);
        optimize(*module);

        std::string verification;
        llvm::raw_string_ostream verificationStream(verification);
        if (llvm::verifyModule(*module, &verificationStream)) {
            verificationStream.flush();
            throw std::runtime_error("invalid LLVM module for optimized loop: " +
                                     verification);
        }

        auto resources = jit_->getMainJITDylib().createResourceTracker();
        if (auto error = jit_->addIRModule(
                resources, llvm::orc::ThreadSafeModule(
                               std::move(module), std::move(context)))) {
            throw llvmError("LLVM could not add optimized loop: ",
                            std::move(error));
        }
        auto symbol = jit_->lookup(functionName);
        if (!symbol) {
            throw llvmError("LLVM could not find optimized loop: ",
                            symbol.takeError());
        }
        return CompiledLoop{symbol->toPtr<OptimizedLoopEntry>(),
                            std::move(resources)};
    }

  private:
    static llvm::Value *stateAddress(llvm::IRBuilder<> &builder,
                                     llvm::Value *state,
                                     std::size_t offset) {
        auto &context = builder.getContext();
        return builder.CreateGEP(
            llvm::Type::getInt8Ty(context), state,
            llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), offset));
    }

    static llvm::Value *loadState64(llvm::IRBuilder<> &builder,
                                    llvm::Value *state,
                                    std::size_t offset,
                                    const char *name) {
        auto *address = stateAddress(builder, state, offset);
        return builder.CreateLoad(llvm::Type::getInt64Ty(builder.getContext()),
                                  address, name);
    }

    static void storeState64(llvm::IRBuilder<> &builder,
                             llvm::Value *state, std::size_t offset,
                             llvm::Value *value) {
        builder.CreateStore(value, stateAddress(builder, state, offset));
    }

    static llvm::Value *flagWhen(llvm::IRBuilder<> &builder,
                                 llvm::Value *condition,
                                 std::uint64_t flag) {
        auto *type = llvm::Type::getInt64Ty(builder.getContext());
        return builder.CreateSelect(condition, llvm::ConstantInt::get(type, flag),
                                    llvm::ConstantInt::get(type, 0));
    }

    static llvm::Value *decrementFlags(llvm::IRBuilder<> &builder,
                                       llvm::Value *incomingFlags,
                                       llvm::Value *original,
                                       llvm::Value *result) {
        auto &context = builder.getContext();
        auto *i64 = llvm::Type::getInt64Ty(context);
        const auto constant = [i64](std::uint64_t value) {
            return llvm::ConstantInt::get(i64, value);
        };

        auto *flags = builder.CreateAnd(incomingFlags,
                                        constant(~replacedDecFlags));
        flags = builder.CreateOr(flags, constant(flagReservedOne));

        // Fold the low byte to bit zero. A zero result bit means even parity.
        auto *parity = builder.CreateXor(
            result, builder.CreateLShr(result, constant(4)));
        parity = builder.CreateXor(
            parity, builder.CreateLShr(parity, constant(2)));
        parity = builder.CreateXor(
            parity, builder.CreateLShr(parity, constant(1)));
        auto *parityEven = builder.CreateICmpEQ(
            builder.CreateAnd(parity, constant(1)), constant(0));
        flags = builder.CreateOr(flags,
                                 flagWhen(builder, parityEven, flagParity));

        auto *auxiliary = builder.CreateICmpNE(
            builder.CreateAnd(builder.CreateXor(original, result),
                              constant(flagAuxiliaryCarry)),
            constant(0));
        flags = builder.CreateOr(
            flags, flagWhen(builder, auxiliary, flagAuxiliaryCarry));

        auto *zero = builder.CreateICmpEQ(result, constant(0));
        flags = builder.CreateOr(flags, flagWhen(builder, zero, flagZero));

        auto *sign = builder.CreateICmpNE(
            builder.CreateAnd(result, constant(UINT64_C(1) << 63U)),
            constant(0));
        flags = builder.CreateOr(flags, flagWhen(builder, sign, flagSign));

        auto *overflow = builder.CreateICmpEQ(
            original, constant(UINT64_C(1) << 63U));
        return builder.CreateOr(flags,
                                flagWhen(builder, overflow, flagOverflow));
    }

    static void buildDecrementLoop(llvm::Module &module,
                                   const std::string &functionName,
                                   const ir::Block &block,
                                   const DecrementLoop &loop) {
        auto &context = module.getContext();
        auto *i64 = llvm::Type::getInt64Ty(context);
        auto *pointer = llvm::PointerType::get(context, 0);
        auto *functionType = llvm::FunctionType::get(
            i64, std::array<llvm::Type *, 2>{pointer, i64}, false);
        auto *function = llvm::Function::Create(
            functionType, llvm::GlobalValue::ExternalLinkage, functionName,
            module);
        function->setCallingConv(llvm::CallingConv::C);

        auto arguments = function->arg_begin();
        llvm::Value *state = arguments++;
        state->setName("state");
        llvm::Value *maximumExecutions = arguments++;
        maximumExecutions->setName("maximum_executions");

        auto *entry = llvm::BasicBlock::Create(context, "entry", function);
        auto *body = llvm::BasicBlock::Create(context, "loop", function);
        auto *exit = llvm::BasicBlock::Create(context, "exit", function);
        llvm::IRBuilder<> builder(entry);

        auto *initialCounter = loadState64(
            builder, state, x86::registerOffset(loop.guestRegister),
            "initial_counter");
        auto *incomingFlags = loadState64(
            builder, state, offsetof(x86::X86State, rflags),
            "incoming_flags");
        builder.CreateBr(body);

        builder.SetInsertPoint(body);
        auto *counter = builder.CreatePHI(i64, 2, "counter");
        auto *remaining = builder.CreatePHI(i64, 2, "remaining");
        counter->addIncoming(initialCounter, entry);
        remaining->addIncoming(maximumExecutions, entry);

        auto *one = llvm::ConstantInt::get(i64, 1);
        auto *nextCounter = builder.CreateSub(counter, one, "next_counter");
        auto *nextRemaining =
            builder.CreateSub(remaining, one, "next_remaining");
        counter->addIncoming(nextCounter, body);
        remaining->addIncoming(nextRemaining, body);

        auto *branchTaken = builder.CreateICmpNE(
            nextCounter, llvm::ConstantInt::get(i64, 0));
        auto *hasBudget = builder.CreateICmpNE(
            nextRemaining, llvm::ConstantInt::get(i64, 0));
        builder.CreateCondBr(builder.CreateAnd(branchTaken, hasBudget), body,
                             exit);

        builder.SetInsertPoint(exit);
        storeState64(builder, state, x86::registerOffset(loop.guestRegister),
                     nextCounter);
        storeState64(builder, state, offsetof(x86::X86State, rflags),
                     decrementFlags(builder, incomingFlags, counter,
                                    nextCounter));
        auto *nextRip = builder.CreateSelect(
            branchTaken, llvm::ConstantInt::get(i64, block.start.value),
            llvm::ConstantInt::get(i64, loop.fallthrough.value));
        storeState64(builder, state, offsetof(x86::X86State, rip), nextRip);
        builder.CreateRet(
            builder.CreateSub(maximumExecutions, nextRemaining));
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
        auto pipeline = passBuilder.buildPerModuleDefaultPipeline(
            llvm::OptimizationLevel::O2);
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

std::unique_ptr<OptimizedLoop>
compileOptimizedLoop(const ir::Block &block) {
    const auto loop = matchDecrementLoop(block);
    if (!loop) {
        return {};
    }
#if ROSA_HAS_LLVM
    auto compiled = engine().compile(block, *loop);
    auto implementation = std::make_unique<OptimizedLoop::Impl>();
    implementation->entry = compiled.entry;
    implementation->resources = std::move(compiled.resources);
    return std::unique_ptr<OptimizedLoop>(
        new OptimizedLoop(std::move(implementation)));
#else
    return {};
#endif
}

bool llvmBackendAvailable() noexcept {
#if ROSA_HAS_LLVM
    return true;
#else
    return false;
#endif
}

} // namespace rosa::dbt
