#pragma once

#include "ir/IR.h"
#include "x86/Registers.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace rosa::guest {
class AddressSpace;
}

namespace rosa::dbt {

using OptimizedLoopEntry = std::size_t (*)(x86::X86State *state, std::size_t maximumExecutions,
                                           std::uint8_t *memoryBytes,
                                           std::uint64_t memoryGuestBase);

class OptimizedLoop {
  public:
    ~OptimizedLoop();
    OptimizedLoop(OptimizedLoop &&) noexcept;
    OptimizedLoop &operator=(OptimizedLoop &&) noexcept;

    OptimizedLoop(const OptimizedLoop &) = delete;
    OptimizedLoop &operator=(const OptimizedLoop &) = delete;

    [[nodiscard]] OptimizedLoopEntry entry() const noexcept;
    [[nodiscard]] std::optional<std::size_t> execute(x86::X86State &state,
                                                     guest::AddressSpace *addressSpace,
                                                     std::size_t maximumExecutions) const;

  private:
    struct Impl;
    explicit OptimizedLoop(std::unique_ptr<Impl> implementation);
    std::unique_ptr<Impl> implementation_;

    friend std::unique_ptr<OptimizedLoop> compileOptimizedLoop(const ir::Block &block);
};

// Returns null when LLVM support is unavailable or the block is outside the
// deliberately small optimizing tier. The baseline translator remains the
// authoritative fallback for every unsupported IR shape.
[[nodiscard]] std::unique_ptr<OptimizedLoop> compileOptimizedLoop(const ir::Block &block);

// Performs the inexpensive structural check used to identify blocks worth
// warming up. This never initializes LLVM or compiles native code.
[[nodiscard]] bool canCompileOptimizedLoop(const ir::Block &block) noexcept;
[[nodiscard]] bool optimizedLoopUsesMemory(const ir::Block &block) noexcept;

[[nodiscard]] bool llvmBackendAvailable() noexcept;

} // namespace rosa::dbt
