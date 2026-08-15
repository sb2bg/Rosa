#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

namespace rosa::arm64 {

class ExecutableCode {
  public:
    explicit ExecutableCode(std::span<const std::uint8_t> bytes);
    ~ExecutableCode();

    ExecutableCode(const ExecutableCode &) = delete;
    ExecutableCode &operator=(const ExecutableCode &) = delete;
    ExecutableCode(ExecutableCode &&other) noexcept;
    ExecutableCode &operator=(ExecutableCode &&other) noexcept;

    template <typename Function> [[nodiscard]] Function entry() const {
        static_assert(std::is_pointer_v<Function>);
        static_assert(sizeof(Function) == sizeof(mapping_));
        Function function{};
        std::memcpy(&function, &mapping_, sizeof(function));
        return function;
    }

    [[nodiscard]] std::size_t size() const noexcept { return usedSize_; }

  private:
    void release() noexcept;

    void *mapping_{};
    std::size_t mappingSize_{};
    std::size_t usedSize_{};
};

} // namespace rosa::arm64
