#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <type_traits>
#include <vector>

namespace rosa::arm64 {

class ExecutableCode;

class ExecutableArena {
  public:
    static constexpr std::size_t defaultChunkSize = 16U * 1024U * 1024U;

    explicit ExecutableArena(std::size_t chunkSize = defaultChunkSize);
    ~ExecutableArena();

    ExecutableArena(const ExecutableArena &) = delete;
    ExecutableArena &operator=(const ExecutableArena &) = delete;

    [[nodiscard]] std::size_t mappingCount() const noexcept {
        return chunks_.size();
    }
    [[nodiscard]] std::size_t allocatedBytes() const noexcept {
        return allocatedBytes_;
    }
    [[nodiscard]] std::size_t usedBytes() const noexcept {
        return usedBytes_;
    }

  private:
    friend class ExecutableCode;

    struct Allocation {
        void *address{};
        std::size_t size{};
    };
    struct Chunk {
        void *mapping{};
        std::size_t size{};
        std::size_t used{};
    };

    [[nodiscard]] Allocation publish(std::span<const std::uint8_t> bytes);
    [[nodiscard]] Allocation reserve(std::size_t size);
    [[nodiscard]] std::vector<Allocation> publishBatch(
        std::span<const std::span<const std::uint8_t>> programs);

    std::size_t chunkSize_{};
    std::size_t pageSize_{};
    std::size_t allocatedBytes_{};
    std::size_t usedBytes_{};
    std::vector<Chunk> chunks_;
};

class ExecutableCode {
  public:
    explicit ExecutableCode(std::span<const std::uint8_t> bytes);
    ExecutableCode(std::shared_ptr<ExecutableArena> arena,
                   std::span<const std::uint8_t> bytes);
    ~ExecutableCode() = default;

    ExecutableCode(const ExecutableCode &) = delete;
    ExecutableCode &operator=(const ExecutableCode &) = delete;
    ExecutableCode(ExecutableCode &&other) noexcept;
    ExecutableCode &operator=(ExecutableCode &&other) noexcept;

    [[nodiscard]] static std::vector<ExecutableCode> publishBatch(
        std::shared_ptr<ExecutableArena> arena,
        std::span<const std::span<const std::uint8_t>> programs);

    template <typename Function> [[nodiscard]] Function entry() const {
        static_assert(std::is_pointer_v<Function>);
        static_assert(sizeof(Function) == sizeof(entry_));
        Function function{};
        std::memcpy(&function, &entry_, sizeof(function));
        return function;
    }

    [[nodiscard]] std::size_t size() const noexcept { return usedSize_; }

  private:
    ExecutableCode(std::shared_ptr<ExecutableArena> arena, void *entry,
                   std::size_t usedSize) noexcept;

    std::shared_ptr<ExecutableArena> arena_;
    void *entry_{};
    std::size_t usedSize_{};
};

} // namespace rosa::arm64
