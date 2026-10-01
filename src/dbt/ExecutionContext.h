#pragma once

#include "dbt/Execution.h"
#include "guest/AddressSpace.h"

#include <array>
#include <exception>
#include <memory>
#include <new>
#include <type_traits>

namespace rosa::dbt::runtime {

// Private generated-code ABI. Keep the emitter's offsetof accesses and the
// runtime helpers on the same definition; guest architectural state lives in X86State.
class LazyException {
  public:
    LazyException() = default;
    LazyException(const LazyException &) = delete;
    LazyException &operator=(const LazyException &) = delete;

    LazyException &operator=(std::exception_ptr fault) {
        if (present_) {
            std::destroy_at(pointer());
        }
        std::construct_at(pointer(), std::move(fault));
        present_ = true;
        return *this;
    }

    [[nodiscard]] explicit operator bool() const noexcept { return present_; }

    [[nodiscard]] std::exception_ptr take() {
        auto result = std::move(*pointer());
        std::destroy_at(pointer());
        present_ = false;
        return result;
    }

  private:
    [[nodiscard]] std::exception_ptr *pointer() noexcept {
        return std::launder(reinterpret_cast<std::exception_ptr *>(storage_.data()));
    }

    alignas(std::exception_ptr) std::array<std::byte, sizeof(std::exception_ptr)> storage_{};
    bool present_{};
};

static_assert(std::is_trivially_destructible_v<LazyException>);

struct DirectGuestMemoryCache {
    std::uint64_t base{};
    std::size_t size{};
    std::uint8_t *bytes{};
    bool attempted{};
};

struct GuestExecutionContext {
    guest::AddressSpace *addressSpace{};
    LazyException fault;
    guest::GuestAddress faultAddress{};
    std::size_t faultSize{};
    std::uint64_t loadedValue{};
    TimestampCounterReader timestampCounterReader{};
    std::size_t remainingBlockExecutions{1};
    std::uint64_t stopRepeating{};
    bool directMemoryEnabled{};
    DirectGuestMemoryCache directRead;
    DirectGuestMemoryCache directWrite;
    guest::GuestAddress faultRip{};
};

} // namespace rosa::dbt::runtime
