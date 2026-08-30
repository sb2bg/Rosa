#pragma once

#include "ir/IR.h"
#include "x86/Registers.h"

#include <cstddef>
#include <memory>

namespace rosa::dbt {

using OptimizedLoopEntry =
    std::size_t (*)(x86::X86State *state, std::size_t maximumExecutions);

class OptimizedLoop {
  public:
    ~OptimizedLoop();
    OptimizedLoop(OptimizedLoop &&) noexcept;
    OptimizedLoop &operator=(OptimizedLoop &&) noexcept;

    OptimizedLoop(const OptimizedLoop &) = delete;
    OptimizedLoop &operator=(const OptimizedLoop &) = delete;

    [[nodiscard]] OptimizedLoopEntry entry() const noexcept;

  private:
    struct Impl;
    explicit OptimizedLoop(std::unique_ptr<Impl> implementation);
    std::unique_ptr<Impl> implementation_;

    friend std::unique_ptr<OptimizedLoop>
    compileOptimizedLoop(const ir::Block &block);
};

// Returns null when LLVM support is unavailable or the block is outside the
// deliberately small optimizing tier. The baseline translator remains the
// authoritative fallback for every unsupported IR shape.
[[nodiscard]] std::unique_ptr<OptimizedLoop>
compileOptimizedLoop(const ir::Block &block);

[[nodiscard]] bool llvmBackendAvailable() noexcept;

} // namespace rosa::dbt
