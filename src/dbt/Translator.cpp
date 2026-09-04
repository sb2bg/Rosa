#include "dbt/Translator.h"
#include "dbt/LlvmBackend.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <sstream>
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
constexpr std::uint64_t flagDirection = 1U << 10U;
constexpr std::uint64_t arithmeticFlagMask =
    flagCarry | flagParity | flagAuxiliaryCarry | flagZero | flagSign | flagOverflow;

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
};

[[nodiscard]] std::uint8_t *directGuestRead(GuestExecutionContext *context, std::uint64_t address) {
    if (context == nullptr || context->addressSpace == nullptr || !context->directMemoryEnabled) {
        return nullptr;
    }
    auto &cache = context->directRead;
    if (cache.bytes != nullptr && address >= cache.base && address - cache.base < cache.size) {
        return cache.bytes + (address - cache.base);
    }
    if (cache.attempted) {
        return nullptr;
    }
    cache.attempted = true;
    const auto view = context->addressSpace->directMemoryView(guest::GuestAddress{address},
                                                              guest::Permission::Read);
    if (!view) {
        return nullptr;
    }
    cache.base = view->base.value;
    cache.size = view->bytes.size();
    cache.bytes = view->bytes.data();
    return cache.bytes + (address - cache.base);
}

extern "C" __attribute__((noinline)) std::uint8_t *
validateDirectGuestReadSpan(GuestExecutionContext *context, std::uint64_t address,
                            std::uint64_t induction, std::uint64_t step, std::uint64_t limit,
                            std::uint64_t maximumOffset) noexcept {
    if (context == nullptr || step == 0 || induction >= limit) {
        return nullptr;
    }
    const auto &cache = context->directRead;
    if (cache.bytes == nullptr || address < cache.base || address - cache.base >= cache.size) {
        return nullptr;
    }

    const auto remaining = limit - induction;
    if (remaining < step || remaining % step != 0) {
        return nullptr;
    }
    const auto distanceToLastIteration = remaining - step;
    if (address > UINT64_MAX - distanceToLastIteration) {
        return nullptr;
    }
    const auto lastAddress = address + distanceToLastIteration;
    if (lastAddress > UINT64_MAX - maximumOffset) {
        return nullptr;
    }
    const auto lastByte = lastAddress + maximumOffset;
    if (lastByte < cache.base || lastByte - cache.base >= cache.size) {
        return nullptr;
    }
    return cache.bytes + (address - cache.base);
}

[[nodiscard]] std::uint8_t *directGuestWrite(GuestExecutionContext *context,
                                             std::uint64_t address) {
    if (context == nullptr || context->addressSpace == nullptr || !context->directMemoryEnabled) {
        return nullptr;
    }
    auto &cache = context->directWrite;
    if (cache.bytes != nullptr && address >= cache.base && address - cache.base < cache.size) {
        return cache.bytes + (address - cache.base);
    }
    if (cache.attempted) {
        return nullptr;
    }
    cache.attempted = true;
    const auto view = context->addressSpace->directMemoryView(guest::GuestAddress{address},
                                                              guest::Permission::Write);
    if (!view) {
        return nullptr;
    }
    cache.base = view->base.value;
    cache.size = view->bytes.size();
    cache.bytes = view->bytes.data();
    return cache.bytes + (address - cache.base);
}

extern "C" x86::X86State *updateLogicFlags8(x86::X86State *state, std::uint64_t result);
extern "C" x86::X86State *updateLogicFlags16(x86::X86State *state, std::uint64_t result);
extern "C" x86::X86State *updateLogicFlags32(x86::X86State *state, std::uint64_t result);
extern "C" x86::X86State *updateLogicFlags64(x86::X86State *state, std::uint64_t result);
extern "C" x86::X86State *updateSubFlags8(x86::X86State *state, std::uint64_t lhsValue,
                                          std::uint64_t rhsValue, std::uint64_t resultValue);

extern "C" __attribute__((noinline)) x86::X86State *commitPush64(GuestExecutionContext *context,
                                                                 x86::X86State *state,
                                                                 std::uint64_t newStackPointer,
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
divideUnsignedByte(GuestExecutionContext *context, x86::X86State *state,
                   std::uint64_t divisorValue) noexcept {
    try {
        if (state == nullptr) {
            throw std::runtime_error("generated byte DIV has no guest state");
        }
        const auto divisor = static_cast<std::uint8_t>(divisorValue);
        if (divisor == 0) {
            throw std::runtime_error("x86 divide error: byte divisor is zero");
        }
        const auto dividend = static_cast<std::uint16_t>(state->rax);
        const auto quotient = static_cast<std::uint16_t>(dividend / divisor);
        if (quotient > UINT8_MAX) {
            throw std::runtime_error("x86 divide error: byte quotient overflows AL");
        }
        const auto remainder = static_cast<std::uint8_t>(dividend % divisor);
        const auto result =
            static_cast<std::uint16_t>(quotient | (static_cast<std::uint16_t>(remainder) << 8U));
        state->rax = (state->rax & ~UINT64_C(0xFFFF)) | result;
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
divideUnsignedDword(GuestExecutionContext *context, x86::X86State *state,
                    std::uint64_t divisorValue) noexcept {
    try {
        if (state == nullptr) {
            throw std::runtime_error("generated dword DIV has no guest state");
        }
        const auto divisor = static_cast<std::uint32_t>(divisorValue);
        if (divisor == 0) {
            throw std::runtime_error("x86 divide error: dword divisor is zero");
        }
        const auto dividend =
            (static_cast<std::uint64_t>(static_cast<std::uint32_t>(state->rdx)) << 32U) |
            static_cast<std::uint32_t>(state->rax);
        const auto quotient = dividend / divisor;
        if (quotient > UINT32_MAX) {
            throw std::runtime_error("x86 divide error: dword quotient overflows EAX");
        }
        const auto remainder = dividend % divisor;
        state->rax = static_cast<std::uint32_t>(quotient);
        state->rdx = static_cast<std::uint32_t>(remainder);
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
divideSignedDword(GuestExecutionContext *context, x86::X86State *state,
                  std::uint64_t divisorValue) noexcept {
    try {
        if (state == nullptr) {
            throw std::runtime_error("generated dword IDIV has no guest state");
        }
        const auto divisor = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(divisorValue));
        if (divisor == 0) {
            throw std::runtime_error("x86 divide error: signed dword divisor is zero");
        }
        const auto dividendBits =
            (static_cast<std::uint64_t>(static_cast<std::uint32_t>(state->rdx)) << 32U) |
            static_cast<std::uint32_t>(state->rax);
        const auto dividend = std::bit_cast<std::int64_t>(dividendBits);
        if (dividend == std::numeric_limits<std::int64_t>::min() && divisor == -1) {
            throw std::runtime_error("x86 divide error: signed dword quotient overflows EAX");
        }
        const auto quotient = dividend / divisor;
        if (quotient < std::numeric_limits<std::int32_t>::min() ||
            quotient > std::numeric_limits<std::int32_t>::max()) {
            throw std::runtime_error("x86 divide error: signed dword quotient overflows EAX");
        }
        const auto remainder = dividend % divisor;
        state->rax = static_cast<std::uint32_t>(quotient);
        state->rdx = static_cast<std::uint32_t>(remainder);
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
divideUnsignedQword(GuestExecutionContext *context, x86::X86State *state,
                    std::uint64_t divisor) noexcept {
    try {
        if (state == nullptr) {
            throw std::runtime_error("generated qword DIV has no guest state");
        }
        if (divisor == 0) {
            throw std::runtime_error("x86 divide error: qword divisor is zero");
        }
        const auto dividend = (static_cast<unsigned __int128>(state->rdx) << 64U) | state->rax;
        const auto quotient = dividend / divisor;
        if (quotient > UINT64_MAX) {
            throw std::runtime_error("x86 divide error: qword quotient overflows RAX");
        }
        const auto remainder = dividend % divisor;
        state->rax = static_cast<std::uint64_t>(quotient);
        state->rdx = static_cast<std::uint64_t>(remainder);
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *storeGuest64(GuestExecutionContext *context,
                                                                 x86::X86State *state,
                                                                 std::uint64_t address,
                                                                 std::uint64_t value) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated guest store has no address space");
        }
        const auto executableVersion = context->addressSpace->executableVersion();
        context->addressSpace->writeU64(guest::GuestAddress{address}, value);
        context->stopRepeating |= context->addressSpace->executableVersion() != executableVersion;
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

extern "C" __attribute__((noinline)) x86::X86State *storeGuest8(GuestExecutionContext *context,
                                                                x86::X86State *state,
                                                                std::uint64_t address,
                                                                std::uint64_t value) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated byte guest store has no address space");
        }
        if (auto *direct = directGuestWrite(context, address); direct != nullptr) {
            *direct = static_cast<std::uint8_t>(value);
        } else {
            const auto executableVersion = context->addressSpace->executableVersion();
            const std::array bytes{static_cast<std::uint8_t>(value)};
            context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
            context->stopRepeating |=
                context->addressSpace->executableVersion() != executableVersion;
        }
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 1;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *storeGuest16(GuestExecutionContext *context,
                                                                 x86::X86State *state,
                                                                 std::uint64_t address,
                                                                 std::uint64_t value) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 16-bit guest store has no address space");
        }
        const auto executableVersion = context->addressSpace->executableVersion();
        const std::array bytes{
            static_cast<std::uint8_t>(value),
            static_cast<std::uint8_t>(value >> 8U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        context->stopRepeating |= context->addressSpace->executableVersion() != executableVersion;
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint16_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *storeGuest32(GuestExecutionContext *context,
                                                                 x86::X86State *state,
                                                                 std::uint64_t address,
                                                                 std::uint64_t value) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 32-bit guest store has no address space");
        }
        const auto executableVersion = context->addressSpace->executableVersion();
        std::array<std::uint8_t, sizeof(std::uint32_t)> bytes{};
        for (std::size_t index = 0; index < bytes.size(); ++index) {
            bytes[index] = static_cast<std::uint8_t>(value >> (index * 8U));
        }
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        context->stopRepeating |= context->addressSpace->executableVersion() != executableVersion;
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *storeGuestIdtr(GuestExecutionContext *context,
                                                                   x86::X86State *state,
                                                                   std::uint64_t address) noexcept {
    constexpr std::array<std::uint8_t, 10> guestIdtr{
        0xFF, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated SIDT has no guest address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, guestIdtr.size(),
                                              guest::Permission::Write);
        context->addressSpace->writeBytes(guest::GuestAddress{address}, guestIdtr);
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = guestIdtr.size();
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
storeGuestXmm128(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t registerIndex, std::uint64_t alignmentRequired) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated XMM guest store has no address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated XMM guest store has an invalid register");
        }
        if (alignmentRequired != 0 && (address & 0xFU) != 0) {
            throw std::runtime_error("MOVAPS guest address is not 16-byte aligned");
        }
        const auto &value = state->xmm[registerIndex];
        std::array<std::uint8_t, 16> bytes{};
        for (std::size_t index = 0; index < sizeof(std::uint64_t); ++index) {
            bytes[index] = static_cast<std::uint8_t>(value.low >> (index * 8U));
            bytes[index + sizeof(std::uint64_t)] =
                static_cast<std::uint8_t>(value.high >> (index * 8U));
        }
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 16;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
storeGuestYmm256(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t registerIndex, std::uint64_t alignmentRequired) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated YMM guest store has no address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated YMM guest store has an invalid register");
        }
        if (alignmentRequired != 0 && (address & 0x1FU) != 0) {
            throw std::runtime_error("VMOVAPS YMM guest address is not 32-byte aligned");
        }
        const auto &lower = state->xmm[registerIndex];
        const auto &upper = state->ymmUpper[registerIndex];
        std::array<std::uint8_t, 32> bytes{};
        const std::array lanes{lower.low, lower.high, upper.low, upper.high};
        for (std::size_t lane = 0; lane < lanes.size(); ++lane) {
            for (std::size_t byte = 0; byte < sizeof(std::uint64_t); ++byte) {
                bytes[lane * sizeof(std::uint64_t) + byte] =
                    static_cast<std::uint8_t>(lanes[lane] >> (byte * 8U));
            }
        }
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 32;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
loadGuestXmm128(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t registerIndex, std::uint64_t alignmentRequired) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated XMM guest load has no address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated XMM guest load has an invalid register");
        }
        if (alignmentRequired != 0 && (address & 0xFU) != 0) {
            throw std::runtime_error("aligned XMM guest address is not 16-byte aligned");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        x86::X86State::XmmValue value;
        for (std::size_t index = 0; index < sizeof(std::uint64_t); ++index) {
            value.low |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
            value.high |= static_cast<std::uint64_t>(bytes[index + sizeof(std::uint64_t)])
                          << (index * 8U);
        }
        state->xmm[registerIndex] = value;
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 16;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
loadGuestYmm256(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t registerIndex, std::uint64_t alignmentRequired) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated YMM guest load has no address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated YMM guest load has an invalid register");
        }
        if (alignmentRequired != 0 && (address & 0x1FU) != 0) {
            throw std::runtime_error("aligned YMM guest address is not 32-byte aligned");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 32);
        std::array<std::uint64_t, 4> lanes{};
        for (std::size_t lane = 0; lane < lanes.size(); ++lane) {
            for (std::size_t byte = 0; byte < sizeof(std::uint64_t); ++byte) {
                lanes[lane] |=
                    static_cast<std::uint64_t>(bytes[lane * sizeof(std::uint64_t) + byte])
                    << (byte * 8U);
            }
        }
        state->xmm[registerIndex] = {.low = lanes[0], .high = lanes[1]};
        state->ymmUpper[registerIndex] = {.low = lanes[2], .high = lanes[3]};
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 32;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
loadGuestSignExtendedBytesXmm(GuestExecutionContext *context, x86::X86State *state,
                              std::uint64_t address, std::uint64_t registerIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated PMOVSXBD has no guest address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated PMOVSXBD has an invalid XMM register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 4);
        std::array<std::uint32_t, 4> lanes{};
        for (std::size_t index = 0; index < lanes.size(); ++index) {
            lanes[index] = static_cast<std::uint32_t>(
                static_cast<std::int32_t>(std::bit_cast<std::int8_t>(bytes[index])));
        }
        state->xmm[registerIndex] = {
            .low = static_cast<std::uint64_t>(lanes[0]) |
                   (static_cast<std::uint64_t>(lanes[1]) << 32U),
            .high = static_cast<std::uint64_t>(lanes[2]) |
                    (static_cast<std::uint64_t>(lanes[3]) << 32U),
        };
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 4;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
loadGuestSignExtendedDwordsXmm(GuestExecutionContext *context, x86::X86State *state,
                               std::uint64_t address, std::uint64_t registerIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated PMOVSXDQ has no guest address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated PMOVSXDQ has an invalid XMM register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 8);
        std::uint32_t lowDword = 0;
        std::uint32_t highDword = 0;
        for (std::size_t index = 0; index < sizeof(std::uint32_t); ++index) {
            lowDword |= static_cast<std::uint32_t>(bytes[index]) << (index * 8U);
            highDword |= static_cast<std::uint32_t>(bytes[index + sizeof(std::uint32_t)])
                         << (index * 8U);
        }
        state->xmm[registerIndex] = {
            .low = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(std::bit_cast<std::int32_t>(lowDword))),
            .high = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(std::bit_cast<std::int32_t>(highDword))),
        };
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 8;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
compareEqualGuestBytesXmm128(GuestExecutionContext *context, x86::X86State *state,
                             std::uint64_t address, std::uint64_t registerIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated PCMPEQB has no address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated PCMPEQB has an invalid register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        const auto original = state->xmm[registerIndex];
        x86::X86State::XmmValue result;
        for (std::size_t index = 0; index < bytes.size(); ++index) {
            const auto lane = index < sizeof(std::uint64_t) ? original.low : original.high;
            const auto laneIndex = index % sizeof(std::uint64_t);
            const auto originalByte = static_cast<std::uint8_t>(lane >> (laneIndex * 8U));
            if (originalByte == bytes[index]) {
                auto &resultLane = index < sizeof(std::uint64_t) ? result.low : result.high;
                resultLane |= std::uint64_t{0xFF} << (laneIndex * 8U);
            }
        }
        state->xmm[registerIndex] = result;
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 16;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
xorGuestMemoryXmm128(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                     std::uint64_t registerIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated PXOR has no guest address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated PXOR has an invalid XMM register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        std::uint64_t sourceLow = 0;
        std::uint64_t sourceHigh = 0;
        std::memcpy(&sourceLow, bytes.data(), sizeof(sourceLow));
        std::memcpy(&sourceHigh, bytes.data() + sizeof(sourceLow), sizeof(sourceHigh));
        const auto original = state->xmm[registerIndex];
        state->xmm[registerIndex] = {
            .low = original.low ^ sourceLow,
            .high = original.high ^ sourceHigh,
        };
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 16;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
andGuestMemoryXmm128(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                     std::uint64_t registerIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated PAND has no guest address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated PAND has an invalid XMM register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        std::uint64_t sourceLow = 0;
        std::uint64_t sourceHigh = 0;
        std::memcpy(&sourceLow, bytes.data(), sizeof(sourceLow));
        std::memcpy(&sourceHigh, bytes.data() + sizeof(sourceLow), sizeof(sourceHigh));
        const auto original = state->xmm[registerIndex];
        state->xmm[registerIndex] = {
            .low = original.low & sourceLow,
            .high = original.high & sourceHigh,
        };
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 16;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
addGuestMemoryXmm128(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                     std::uint64_t registerIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated PADDD has no guest address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated PADDD has an invalid XMM register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        std::uint64_t sourceLow = 0;
        std::uint64_t sourceHigh = 0;
        std::memcpy(&sourceLow, bytes.data(), sizeof(sourceLow));
        std::memcpy(&sourceHigh, bytes.data() + sizeof(sourceLow), sizeof(sourceHigh));
        const auto original = state->xmm[registerIndex];
        const auto sumLane = [](std::uint64_t destinationLane, std::uint64_t sourceLane) {
            const auto low =
                static_cast<std::uint32_t>(destinationLane) + static_cast<std::uint32_t>(sourceLane);
            const auto high = static_cast<std::uint32_t>(destinationLane >> 32U) +
                              static_cast<std::uint32_t>(sourceLane >> 32U);
            return static_cast<std::uint64_t>(low) |
                   (static_cast<std::uint64_t>(high) << 32U);
        };
        state->xmm[registerIndex] = {
            .low = sumLane(original.low, sourceLow),
            .high = sumLane(original.high, sourceHigh),
        };
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 16;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
testXmmBits128(x86::X86State *state, std::uint64_t destinationIndex,
               std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    const auto intersection = (destination.low & source.low) | (destination.high & source.high);
    const auto sourceOutsideDestination =
        (~destination.low & source.low) | (~destination.high & source.high);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (intersection == 0) {
        flags |= flagZero;
    }
    if (sourceOutsideDestination == 0) {
        flags |= flagCarry;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
convertInt32ToDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                        std::uint64_t intValue) noexcept {
    if (destinationIndex >= state->xmm.size()) {
        return state;
    }
    // int32 is always exactly representable; the host conversion matches the
    // guest default MXCSR rounding mode (round to nearest).
    const auto bits = std::bit_cast<std::uint64_t>(
        static_cast<double>(static_cast<std::int32_t>(intValue)));
    state->xmm[destinationIndex] = {.low = bits, .high = 0};
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
convertInt64ToDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                        std::uint64_t intValue) noexcept {
    if (destinationIndex >= state->xmm.size()) {
        return state;
    }
    const auto bits = std::bit_cast<std::uint64_t>(
        static_cast<double>(static_cast<std::int64_t>(intValue)));
    state->xmm[destinationIndex] = {.low = bits, .high = 0};
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
scalarDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                std::uint64_t sourceBits, std::uint64_t operation) noexcept {
    if (destinationIndex >= state->xmm.size()) {
        return state;
    }
    // Host IEEE-754 arithmetic matches the guest default MXCSR behavior
    // (round to nearest, no denormal flushing on either side).
    const auto destination =
        std::bit_cast<double>(state->xmm[destinationIndex].low);
    const auto source = std::bit_cast<double>(sourceBits);
    const auto result = operation == 0U   ? destination + source
                        : operation == 1U ? destination - source
                        : operation == 2U ? destination * source
                                          : destination / source;
    state->xmm[destinationIndex].low = std::bit_cast<std::uint64_t>(result);
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
addXmmWords128(x86::X86State *state, std::uint64_t destinationIndex,
               std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    x86::X86State::XmmValue result;
    for (std::size_t index = 0; index < 8; ++index) {
        const auto shift = static_cast<std::uint8_t>((index & 3U) * 16U);
        const auto destinationLane = index < 4 ? destination.low : destination.high;
        const auto sourceLane = index < 4 ? source.low : source.high;
        const auto sum = static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(destinationLane >> shift) +
            static_cast<std::uint16_t>(sourceLane >> shift));
        auto &resultLane = index < 4 ? result.low : result.high;
        resultLane |= static_cast<std::uint64_t>(sum) << shift;
    }
    state->xmm[destinationIndex] = result;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
comparePackedDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                       std::uint64_t sourceIndex, std::uint64_t predicate) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    // Host IEEE-754 comparison matches SSE scalar semantics for every
    // predicate, including unordered inputs (MXCSR exception flags, which
    // Rosa does not model, aside).
    const auto compareLane = [predicate](std::uint64_t destinationBits,
                                         std::uint64_t sourceBits) {
        const auto destination = std::bit_cast<double>(destinationBits);
        const auto source = std::bit_cast<double>(sourceBits);
        const bool satisfied =
            (predicate & 7U) == 0U   ? destination == source
            : (predicate & 7U) == 1U ? destination < source
            : (predicate & 7U) == 2U ? destination <= source
            : (predicate & 7U) == 3U
                ? std::isnan(destination) || std::isnan(source)
            : (predicate & 7U) == 4U ? destination != source
            : (predicate & 7U) == 5U ? !(destination < source)
            : (predicate & 7U) == 6U ? !(destination <= source)
                                     : !std::isnan(destination) && !std::isnan(source);
        return satisfied ? UINT64_MAX : std::uint64_t{0};
    };
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    state->xmm[destinationIndex] = {
        .low = compareLane(destination.low, source.low),
        .high = compareLane(destination.high, source.high),
    };
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
compareEqualXmmBytes128(x86::X86State *state, std::uint64_t destinationIndex,
                        std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    x86::X86State::XmmValue result;
    for (std::size_t index = 0; index < 16; ++index) {
        const auto destinationLane =
            index < sizeof(std::uint64_t) ? destination.low : destination.high;
        const auto sourceLane = index < sizeof(std::uint64_t) ? source.low : source.high;
        const auto shift = (index % sizeof(std::uint64_t)) * 8U;
        const auto destinationByte = static_cast<std::uint8_t>(destinationLane >> shift);
        const auto sourceByte = static_cast<std::uint8_t>(sourceLane >> shift);
        if (destinationByte == sourceByte) {
            auto &resultLane = index < sizeof(std::uint64_t) ? result.low : result.high;
            resultLane |= std::uint64_t{0xFF} << shift;
        }
    }
    state->xmm[destinationIndex] = result;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
compareEqualXmmDwords128(x86::X86State *state, std::uint64_t destinationIndex,
                         std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    x86::X86State::XmmValue result;
    for (std::size_t index = 0; index < 4; ++index) {
        const auto shift = (index & 1U) * 32U;
        const auto destinationLane = index < 2 ? destination.low : destination.high;
        const auto sourceLane = index < 2 ? source.low : source.high;
        const auto destinationDword = static_cast<std::uint32_t>(destinationLane >> shift);
        const auto sourceDword = static_cast<std::uint32_t>(sourceLane >> shift);
        if (destinationDword == sourceDword) {
            auto &resultLane = index < 2 ? result.low : result.high;
            resultLane |= std::uint64_t{UINT32_MAX} << shift;
        }
    }
    state->xmm[destinationIndex] = result;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
shiftLeftXmmDwords128(x86::X86State *state, std::uint64_t destinationIndex,
                      std::uint64_t count) noexcept {
    if (destinationIndex >= state->xmm.size()) {
        return state;
    }
    const auto source = state->xmm[destinationIndex];
    x86::X86State::XmmValue result;
    if (count < 32) {
        for (std::size_t index = 0; index < 4; ++index) {
            const auto shift = (index & 1U) * 32U;
            const auto sourceLane = index < 2 ? source.low : source.high;
            const auto sourceDword = static_cast<std::uint32_t>(sourceLane >> shift);
            const auto shifted =
                static_cast<std::uint32_t>(static_cast<std::uint64_t>(sourceDword) << count);
            auto &resultLane = index < 2 ? result.low : result.high;
            resultLane |= static_cast<std::uint64_t>(shifted) << shift;
        }
    }
    state->xmm[destinationIndex] = result;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
addXmmDwords128(x86::X86State *state, std::uint64_t destinationIndex,
                std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    x86::X86State::XmmValue result;
    for (std::size_t index = 0; index < 4; ++index) {
        const auto shift = (index & 1U) * 32U;
        const auto destinationLane = index < 2 ? destination.low : destination.high;
        const auto sourceLane = index < 2 ? source.low : source.high;
        const auto sum =
            static_cast<std::uint32_t>(static_cast<std::uint32_t>(destinationLane >> shift) +
                                       static_cast<std::uint32_t>(sourceLane >> shift));
        auto &resultLane = index < 2 ? result.low : result.high;
        resultLane |= static_cast<std::uint64_t>(sum) << shift;
    }
    state->xmm[destinationIndex] = result;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
horizontalAddXmmDwords128(x86::X86State *state, std::uint64_t destinationIndex,
                          std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    const auto dword = [](x86::X86State::XmmValue value, std::size_t index) {
        const auto lane = index < 2 ? value.low : value.high;
        return static_cast<std::uint32_t>(lane >> ((index & 1U) * 32U));
    };
    const std::array sums{
        static_cast<std::uint32_t>(dword(destination, 0) + dword(destination, 1)),
        static_cast<std::uint32_t>(dword(destination, 2) + dword(destination, 3)),
        static_cast<std::uint32_t>(dword(source, 0) + dword(source, 1)),
        static_cast<std::uint32_t>(dword(source, 2) + dword(source, 3)),
    };
    state->xmm[destinationIndex] = {
        .low = static_cast<std::uint64_t>(sums[0]) | (static_cast<std::uint64_t>(sums[1]) << 32U),
        .high = static_cast<std::uint64_t>(sums[2]) | (static_cast<std::uint64_t>(sums[3]) << 32U),
    };
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
andNotXmm128(x86::X86State *state, std::uint64_t destinationIndex,
             std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    state->xmm[destinationIndex] = {
        .low = ~destination.low & source.low,
        .high = ~destination.high & source.high,
    };
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
moveXmmByteMask32(x86::X86State *state, std::uint64_t destinationIndex, std::uint64_t sourceIndex) {
    if (destinationIndex >= 16 || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto value = state->xmm[sourceIndex];
    std::uint64_t mask = 0;
    for (std::size_t index = 0; index < 16; ++index) {
        const auto lane = index < sizeof(std::uint64_t) ? value.low : value.high;
        const auto laneIndex = index % sizeof(std::uint64_t);
        mask |= ((lane >> (laneIndex * 8U + 7U)) & 1U) << index;
    }
    const auto destination = static_cast<x86::Register>(destinationIndex);
    std::memcpy(reinterpret_cast<std::byte *>(state) + x86::registerOffset(destination), &mask,
                sizeof(mask));
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *bitScanForward(x86::X86State *state,
                                                                   std::uint64_t destinationIndex,
                                                                   std::uint64_t sourceIndex,
                                                                   std::uint64_t operandWidth) {
    if (destinationIndex >= 16 || sourceIndex >= 16 || (operandWidth != 32 && operandWidth != 64)) {
        return state;
    }
    std::uint64_t sourceValue = 0;
    const auto source = static_cast<x86::Register>(sourceIndex);
    std::memcpy(&sourceValue,
                reinterpret_cast<const std::byte *>(state) + x86::registerOffset(source),
                sizeof(sourceValue));
    const auto value = operandWidth == 32
                           ? static_cast<std::uint64_t>(static_cast<std::uint32_t>(sourceValue))
                           : sourceValue;
    state->rflags = (state->rflags & ~flagZero) | flagReservedOne;
    if (value == 0) {
        state->rflags |= flagZero;
        return state;
    }
    const auto result = static_cast<std::uint64_t>(std::countr_zero(value));
    const auto destination = static_cast<x86::Register>(destinationIndex);
    std::memcpy(reinterpret_cast<std::byte *>(state) + x86::registerOffset(destination), &result,
                sizeof(result));
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *bitScanReverse(x86::X86State *state,
                                                                   std::uint64_t destinationIndex,
                                                                   std::uint64_t sourceIndex,
                                                                   std::uint64_t operandWidth) {
    if (destinationIndex >= 16 || sourceIndex >= 16 || (operandWidth != 32 && operandWidth != 64)) {
        return state;
    }
    std::uint64_t sourceValue = 0;
    const auto source = static_cast<x86::Register>(sourceIndex);
    std::memcpy(&sourceValue,
                reinterpret_cast<const std::byte *>(state) + x86::registerOffset(source),
                sizeof(sourceValue));
    const auto value = operandWidth == 32
                           ? static_cast<std::uint64_t>(static_cast<std::uint32_t>(sourceValue))
                           : sourceValue;
    state->rflags = (state->rflags & ~flagZero) | flagReservedOne;
    if (value == 0) {
        state->rflags |= flagZero;
        return state;
    }
    const auto result = static_cast<std::uint64_t>(std::bit_width(value) - 1);
    const auto destination = static_cast<x86::Register>(destinationIndex);
    std::memcpy(reinterpret_cast<std::byte *>(state) + x86::registerOffset(destination), &result,
                sizeof(result));
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *shuffleXmmDwords(x86::X86State *state,
                                                                     std::uint64_t destinationIndex,
                                                                     std::uint64_t sourceIndex,
                                                                     std::uint64_t control) {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size() ||
        control > 0xFFU) {
        return state;
    }
    const auto source = state->xmm[sourceIndex];
    const std::array<std::uint32_t, 4> sourceDwords{
        static_cast<std::uint32_t>(source.low),
        static_cast<std::uint32_t>(source.low >> 32U),
        static_cast<std::uint32_t>(source.high),
        static_cast<std::uint32_t>(source.high >> 32U),
    };
    std::array<std::uint32_t, 4> result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        const auto selection = static_cast<std::size_t>((control >> (index * 2U)) & 0x3U);
        result[index] = sourceDwords[selection];
    }
    state->xmm[destinationIndex] = {
        .low =
            static_cast<std::uint64_t>(result[0]) | (static_cast<std::uint64_t>(result[1]) << 32U),
        .high =
            static_cast<std::uint64_t>(result[2]) | (static_cast<std::uint64_t>(result[3]) << 32U),
    };
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
shuffleXmmBytes(x86::X86State *state, std::uint64_t destinationIndex, std::uint64_t sourceIndex) {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto input = state->xmm[destinationIndex];
    const auto control = state->xmm[sourceIndex];
    const auto byteAt = [](const x86::X86State::XmmValue &value,
                           std::size_t index) -> std::uint8_t {
        const auto lane = index < 8 ? value.low : value.high;
        return static_cast<std::uint8_t>(lane >> ((index & 7U) * 8U));
    };
    x86::X86State::XmmValue result{};
    for (std::size_t index = 0; index < 16; ++index) {
        const auto mask = byteAt(control, index);
        const auto value = (mask & 0x80U) != 0 ? std::uint8_t{0} : byteAt(input, mask & 0x0FU);
        auto &lane = index < 8 ? result.low : result.high;
        lane |= static_cast<std::uint64_t>(value) << ((index & 7U) * 8U);
    }
    state->xmm[destinationIndex] = result;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
shuffleGuestMemoryXmmBytes(GuestExecutionContext *context, x86::X86State *state,
                           std::uint64_t address, std::uint64_t destinationIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated PSHUFB has no address space");
        }
        if (destinationIndex >= state->xmm.size()) {
            throw std::runtime_error("generated PSHUFB has an invalid destination register");
        }
        const auto control = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        const auto input = state->xmm[destinationIndex];
        const auto byteAt = [](const x86::X86State::XmmValue &value,
                               std::size_t index) -> std::uint8_t {
            const auto lane = index < 8 ? value.low : value.high;
            return static_cast<std::uint8_t>(lane >> ((index & 7U) * 8U));
        };
        x86::X86State::XmmValue result{};
        for (std::size_t index = 0; index < control.size(); ++index) {
            const auto mask = control[index];
            const auto value = (mask & 0x80U) != 0 ? std::uint8_t{0} : byteAt(input, mask & 0x0FU);
            auto &lane = index < 8 ? result.low : result.high;
            lane |= static_cast<std::uint64_t>(value) << ((index & 7U) * 8U);
        }
        state->xmm[destinationIndex] = result;
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 16;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
alignRightXmmBytes(x86::X86State *state, std::uint64_t destinationIndex, std::uint64_t sourceIndex,
                   std::uint64_t count) {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size() ||
        count > 0xFFU) {
        return state;
    }
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    std::array<std::uint8_t, 32> concatenated{};
    std::memcpy(concatenated.data(), &source, sizeof(source));
    std::memcpy(concatenated.data() + sizeof(source), &destination, sizeof(destination));
    std::array<std::uint8_t, 16> result{};
    if (count < concatenated.size()) {
        const auto available = std::min<std::size_t>(result.size(), concatenated.size() - count);
        std::copy_n(concatenated.begin() + static_cast<std::ptrdiff_t>(count), available,
                    result.begin());
    }
    std::memcpy(&state->xmm[destinationIndex], result.data(), result.size());
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *blendXmmWords(x86::X86State *state,
                                                                  std::uint64_t destinationIndex,
                                                                  std::uint64_t sourceIndex,
                                                                  std::uint64_t mask) {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size() || mask > 0xFFU) {
        return state;
    }
    const auto source = state->xmm[sourceIndex];
    auto result = state->xmm[destinationIndex];
    for (std::uint8_t index = 0; index < 8; ++index) {
        if (((mask >> index) & 1U) == 0) {
            continue;
        }
        const auto shift = static_cast<std::uint8_t>((index & 3U) * 16U);
        const auto sourceLane = index < 4 ? source.low : source.high;
        auto &resultLane = index < 4 ? result.low : result.high;
        const auto word = (sourceLane >> shift) & 0xFFFFU;
        const auto wordMask = std::uint64_t{0xFFFF} << shift;
        resultLane = (resultLane & ~wordMask) | (word << shift);
    }
    state->xmm[destinationIndex] = result;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
unpackLowXmmWords(x86::X86State *state, std::uint64_t destinationIndex,
                  std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    x86::X86State::XmmValue result{};
    for (std::uint8_t index = 0; index < 4; ++index) {
        const auto inputShift = static_cast<std::uint8_t>(index * 16U);
        const auto destinationWord = (destination.low >> inputShift) & UINT64_C(0xFFFF);
        const auto sourceWord = (source.low >> inputShift) & UINT64_C(0xFFFF);
        const auto outputWord = static_cast<std::uint8_t>(index * 2U);
        auto &outputLane = outputWord < 4 ? result.low : result.high;
        const auto outputShift = static_cast<std::uint8_t>((outputWord & 3U) * 16U);
        outputLane |= destinationWord << outputShift;
        outputLane |= sourceWord << (outputShift + 16U);
    }
    state->xmm[destinationIndex] = result;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
loadGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated guest load has no address space");
        }
        context->loadedValue = context->addressSpace->readU64(guest::GuestAddress{address});
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
loadGuest8(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated guest load has no address space");
        }
        if (const auto *direct = directGuestRead(context, address); direct != nullptr) {
            context->loadedValue = *direct;
        } else {
            context->loadedValue = context->addressSpace->readU8(guest::GuestAddress{address});
        }
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint8_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *repeatMoveByte(GuestExecutionContext *context,
                                                                   x86::X86State *state) noexcept {
    std::uint64_t currentAddress = state != nullptr ? state->rsi : 0;
    try {
        if (context == nullptr || context->addressSpace == nullptr || state == nullptr) {
            throw std::runtime_error("generated REP MOVSB has no guest execution context");
        }
        const auto decrement = (state->rflags & flagDirection) != 0;
        while (state->rcx != 0) {
            currentAddress = state->rsi;
            const std::array value{
                context->addressSpace->readU8(guest::GuestAddress{currentAddress})};
            currentAddress = state->rdi;
            context->addressSpace->writeBytes(guest::GuestAddress{currentAddress}, value);
            state->rsi = decrement ? state->rsi - 1U : state->rsi + 1U;
            state->rdi = decrement ? state->rdi - 1U : state->rdi + 1U;
            --state->rcx;
        }
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{currentAddress};
            context->faultSize = sizeof(std::uint8_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
loadGuest16(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated guest load has no address space");
        }
        context->loadedValue = context->addressSpace->readU16(guest::GuestAddress{address});
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint16_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
loadGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated guest load has no address space");
        }
        context->loadedValue = context->addressSpace->readU32(guest::GuestAddress{address});
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
readTimestampCounter(GuestExecutionContext *context, x86::X86State *state) noexcept {
    try {
        if (context == nullptr || context->timestampCounterReader == nullptr) {
            throw std::runtime_error("generated RDTSC has no timestamp-counter source");
        }
        const auto value = context->timestampCounterReader();
        state->rax = static_cast<std::uint32_t>(value);
        state->rdx = static_cast<std::uint32_t>(value >> 32U);
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
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

extern "C" __attribute__((noinline)) x86::X86State *updateAddFlags8(x86::X86State *state,
                                                                    std::uint64_t lhsValue,
                                                                    std::uint64_t rhsValue,
                                                                    std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto rhs = static_cast<std::uint8_t>(rhsValue);
    const auto result = static_cast<std::uint8_t>(resultValue);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint16_t>(lhs) + static_cast<std::uint16_t>(rhs) > UINT8_MAX) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x80U) != 0) {
        flags |= flagSign;
    }
    if (((~(lhs ^ rhs) & (lhs ^ result)) & 0x80U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAddFlags16(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint16_t>(lhsValue);
    const auto rhs = static_cast<std::uint16_t>(rhsValue);
    const auto result = static_cast<std::uint16_t>(resultValue);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint32_t>(lhs) + static_cast<std::uint32_t>(rhs) > UINT16_MAX) {
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
    if ((result & 0x8000U) != 0) {
        flags |= flagSign;
    }
    if (((~(lhs ^ rhs) & (lhs ^ result)) & 0x8000U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAddFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto rhs = static_cast<std::uint32_t>(rhsValue);
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs) > UINT32_MAX) {
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
    if ((result & 0x80000000U) != 0) {
        flags |= flagSign;
    }
    if (((~(lhs ^ rhs) & (lhs ^ result)) & 0x80000000U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAdcFlags8(x86::X86State *state,
                                                                    std::uint64_t lhsValue,
                                                                    std::uint64_t rhsValue,
                                                                    std::uint64_t carryValue) {
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto rhs = static_cast<std::uint8_t>(rhsValue);
    const auto carry = static_cast<std::uint8_t>(carryValue & 1U);
    const auto wideResult =
        static_cast<std::uint16_t>(lhs) + static_cast<std::uint16_t>(rhs) + carry;
    const auto result = static_cast<std::uint8_t>(wideResult);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (wideResult > UINT8_MAX) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if ((lhs & 0xFU) + (rhs & 0xFU) + carry > 0xFU) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x80U) != 0) {
        flags |= flagSign;
    }
    const auto signedResult = static_cast<std::int16_t>(static_cast<std::int8_t>(lhs)) +
                              static_cast<std::int16_t>(static_cast<std::int8_t>(rhs)) + carry;
    if (signedResult > INT8_MAX || signedResult < INT8_MIN) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAdcFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t carryValue) {
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto rhs = static_cast<std::uint32_t>(rhsValue);
    const auto carry = static_cast<std::uint32_t>(carryValue & 1U);
    const auto wideResult =
        static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs) + carry;
    const auto result = static_cast<std::uint32_t>(wideResult);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (wideResult > UINT32_MAX) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if ((lhs & 0xFU) + (rhs & 0xFU) + carry > 0xFU) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x80000000U) != 0) {
        flags |= flagSign;
    }
    const auto signedResult = static_cast<std::int64_t>(static_cast<std::int32_t>(lhs)) +
                              static_cast<std::int64_t>(static_cast<std::int32_t>(rhs)) + carry;
    if (signedResult > INT32_MAX || signedResult < INT32_MIN) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateAdcFlags64(x86::X86State *state,
                                                                     std::uint64_t lhs,
                                                                     std::uint64_t rhs,
                                                                     std::uint64_t carryValue) {
    const auto carry = carryValue & 1U;
    const auto sum = lhs + rhs;
    const auto result = sum + carry;
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (sum < lhs || result < sum) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if ((lhs & 0xFU) + (rhs & 0xFU) + carry > 0xFU) {
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

extern "C" __attribute__((noinline)) x86::X86State *updateSbbFlags8(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t borrowValue) {
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto rhs = static_cast<std::uint8_t>(rhsValue);
    const auto borrow = static_cast<std::uint8_t>(borrowValue & 1U);
    const auto wideSubtrahend = static_cast<std::uint16_t>(rhs) + borrow;
    const auto result =
        static_cast<std::uint8_t>(static_cast<std::uint16_t>(lhs) - wideSubtrahend);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint16_t>(lhs) < wideSubtrahend) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result & 0x80U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) & 0x80U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSbbFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t borrowValue) {
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto rhs = static_cast<std::uint32_t>(rhsValue);
    const auto borrow = static_cast<std::uint32_t>(borrowValue & 1U);
    const auto wideSubtrahend = static_cast<std::uint64_t>(rhs) + borrow;
    const auto result =
        static_cast<std::uint32_t>(static_cast<std::uint64_t>(lhs) - wideSubtrahend);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (static_cast<std::uint64_t>(lhs) < wideSubtrahend) {
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
    if ((result & 0x80000000U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) & 0x80000000U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSbbFlags64(x86::X86State *state,
                                                                     std::uint64_t lhs,
                                                                     std::uint64_t rhs,
                                                                     std::uint64_t borrowValue) {
    const auto borrow = borrowValue & 1U;
    const auto subtrahend = rhs + borrow;
    const auto result = lhs - subtrahend;
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (subtrahend < rhs || lhs < subtrahend) {
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

template <typename Value>
x86::X86State *updateIncFlags(x86::X86State *state, std::uint64_t originalValue,
                              std::uint64_t resultValue) {
    const auto original = static_cast<Value>(originalValue);
    const auto result = static_cast<Value>(resultValue);
    auto flags = (state->rflags & ~(arithmeticFlagMask & ~flagCarry)) | flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((original ^ Value{1} ^ result) & Value{0x10}) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    constexpr auto signBit = static_cast<Value>(Value{1} << (sizeof(Value) * 8U - 1U));
    if ((result & signBit) != 0) {
        flags |= flagSign;
    }
    if (original == static_cast<Value>(signBit - 1U)) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateIncFlags32(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateIncFlags<std::uint32_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateIncFlags16(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateIncFlags<std::uint16_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateIncFlags8(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateIncFlags<std::uint8_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateIncFlags64(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateIncFlags<std::uint64_t>(state, original, result);
}

template <typename Value>
x86::X86State *updateDecFlags(x86::X86State *state, std::uint64_t originalValue,
                              std::uint64_t resultValue) {
    const auto original = static_cast<Value>(originalValue);
    const auto result = static_cast<Value>(resultValue);
    auto flags = (state->rflags & ~(arithmeticFlagMask & ~flagCarry)) | flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((original ^ Value{1} ^ result) & Value{0x10}) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    constexpr auto signBit = static_cast<Value>(Value{1} << (sizeof(Value) * 8U - 1U));
    if ((result & signBit) != 0) {
        flags |= flagSign;
    }
    if (original == signBit) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateDecFlags32(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateDecFlags<std::uint32_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateDecFlags16(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateDecFlags<std::uint16_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateDecFlags8(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateDecFlags<std::uint8_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *
updateDecFlags64(x86::X86State *state, std::uint64_t original, std::uint64_t result) {
    return updateDecFlags<std::uint64_t>(state, original, result);
}

extern "C" __attribute__((noinline)) x86::X86State *addGuest64(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t source) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 64-bit guest add has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, sizeof(std::uint64_t),
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original + source;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        return updateAddFlags64(state, original, source, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint64_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *addGuest8(GuestExecutionContext *context,
                                                              x86::X86State *state,
                                                              std::uint64_t address,
                                                              std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 8-bit guest add has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, 1,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU8(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint8_t>(original + static_cast<std::uint8_t>(sourceValue));
        const std::array bytes{result};
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        return updateAddFlags8(state, original, static_cast<std::uint8_t>(sourceValue), result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 1;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *addGuest16(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 16-bit guest add has no address space");
        }
        constexpr auto width = sizeof(std::uint16_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU16(guest::GuestAddress{address});
        const auto source = static_cast<std::uint16_t>(sourceValue);
        const auto result = static_cast<std::uint16_t>(original + source);
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateAddFlags16(state, original, source, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint16_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *addGuest32(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 32-bit guest add has no address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto source = static_cast<std::uint32_t>(sourceValue);
        const auto result = static_cast<std::uint32_t>(original + source);
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateAddFlags32(state, original, source, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" x86::X86State *updateSubFlags64(x86::X86State *state, std::uint64_t lhs,
                                           std::uint64_t rhs, std::uint64_t result);
extern "C" x86::X86State *updateSubFlags32(x86::X86State *state, std::uint64_t lhsValue,
                                           std::uint64_t rhsValue, std::uint64_t resultValue);

extern "C" __attribute__((noinline)) x86::X86State *subGuest64(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t source) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 64-bit guest subtract has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, sizeof(std::uint64_t),
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original - source;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        return updateSubFlags64(state, original, source, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint64_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *subGuest32(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 32-bit guest subtract has no address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto source = static_cast<std::uint32_t>(sourceValue);
        const auto result = static_cast<std::uint32_t>(original - source);
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateSubFlags32(state, original, source, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *subGuest8(GuestExecutionContext *context,
                                                             x86::X86State *state,
                                                             std::uint64_t address,
                                                             std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 8-bit guest subtract has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, 1,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU8(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint8_t>(original - static_cast<std::uint8_t>(sourceValue));
        const std::array bytes{result};
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        return updateSubFlags8(state, original, static_cast<std::uint8_t>(sourceValue), result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 1;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *orGuest8(GuestExecutionContext *context,
                                                             x86::X86State *state,
                                                             std::uint64_t address,
                                                             std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 8-bit guest OR has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, 1,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU8(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint8_t>(original | static_cast<std::uint8_t>(sourceValue));
        const std::array bytes{result};
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        return updateLogicFlags8(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 1;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *orGuest16(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 16-bit guest OR has no address space");
        }
        constexpr auto width = sizeof(std::uint16_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU16(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint16_t>(original | static_cast<std::uint16_t>(sourceValue));
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateLogicFlags16(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint16_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *orGuest32(GuestExecutionContext *context,
                                                              x86::X86State *state,
                                                              std::uint64_t address,
                                                              std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 32-bit guest OR has no address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint32_t>(original | static_cast<std::uint32_t>(sourceValue));
        context->addressSpace->writeU32(guest::GuestAddress{address}, result);
        return updateLogicFlags32(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *orGuest64(GuestExecutionContext *context,
                                                              x86::X86State *state,
                                                              std::uint64_t address,
                                                              std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 64-bit guest OR has no address space");
        }
        constexpr auto width = sizeof(std::uint64_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original | sourceValue;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        return updateLogicFlags64(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint64_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *andGuest8(GuestExecutionContext *context,
                                                              x86::X86State *state,
                                                              std::uint64_t address,
                                                              std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 8-bit guest AND has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, 1,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU8(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint8_t>(original & static_cast<std::uint8_t>(sourceValue));
        const std::array bytes{result};
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        return updateLogicFlags8(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 1;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *andGuest16(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 16-bit guest AND has no address space");
        }
        constexpr auto width = sizeof(std::uint16_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU16(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint16_t>(original & static_cast<std::uint16_t>(sourceValue));
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateLogicFlags16(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint16_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *andGuest64(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 64-bit guest AND has no address space");
        }
        constexpr auto width = sizeof(std::uint64_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original & sourceValue;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        return updateLogicFlags64(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint64_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *andGuest32(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 32-bit guest AND has no address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint32_t>(original & static_cast<std::uint32_t>(sourceValue));
        context->addressSpace->writeU32(guest::GuestAddress{address}, result);
        return updateLogicFlags32(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
incrementGuest8(GuestExecutionContext *context, x86::X86State *state,
                std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 8-bit guest increment has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, 1,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU8(guest::GuestAddress{address});
        const auto result = static_cast<std::uint8_t>(original + 1U);
        const std::array resultBytes{result};
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateIncFlags8(state, original, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint8_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
incrementGuest16(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 16-bit guest increment has no address space");
        }
        const auto original = context->addressSpace->readU16(guest::GuestAddress{address});
        const auto result = static_cast<std::uint16_t>(original + 1U);
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateIncFlags<std::uint16_t>(state, original, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint16_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
incrementGuest32(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 32-bit guest increment has no address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto result = static_cast<std::uint32_t>(original + 1U);
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateIncFlags32(state, original, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
incrementGuest64(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 64-bit guest increment has no address space");
        }
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original + 1U;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        return updateIncFlags<std::uint64_t>(state, original, result);
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
lockedIncrementGuest32(GuestExecutionContext *context, x86::X86State *state,
                       std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated LOCK INC has no guest address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto result = static_cast<std::uint32_t>(original + 1U);
        const std::array bytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        // The LOCK prefix is also a full memory fence. Guest execution is
        // single-threaded today; this preserves ordering at the helper
        // boundary without claiming multi-thread atomicity yet.
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateIncFlags32(state, original, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
lockedIncrementGuest64(GuestExecutionContext *context, x86::X86State *state,
                       std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated LOCK INC has no guest address space");
        }
        constexpr auto width = sizeof(std::uint64_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original + 1U;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        // The LOCK prefix is also a full memory fence. Guest execution is
        // single-threaded today; this preserves ordering at the helper
        // boundary without claiming multi-thread atomicity yet.
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateIncFlags64(state, original, result);
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
lockedDecrementGuest32(GuestExecutionContext *context, x86::X86State *state,
                       std::uint64_t address) noexcept {    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated LOCK DEC has no guest address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto result = static_cast<std::uint32_t>(original - 1U);
        const std::array bytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        // The LOCK prefix is also a full memory fence. Guest execution is
        // single-threaded today; this preserves ordering at the helper
        // boundary without claiming multi-thread atomicity yet.
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateDecFlags32(state, original, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
lockedDecrementGuest64(GuestExecutionContext *context, x86::X86State *state,
                       std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated LOCK DEC has no guest address space");
        }
        constexpr auto width = sizeof(std::uint64_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original - 1U;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        // The LOCK prefix is also a full memory fence. Guest execution is
        // single-threaded today; this preserves ordering at the helper
        // boundary without claiming multi-thread atomicity yet.
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateDecFlags64(state, original, result);
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
decrementGuest32(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 32-bit guest decrement has no address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto result = static_cast<std::uint32_t>(original - 1U);
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateDecFlags32(state, original, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
decrementGuest16(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 16-bit guest decrement has no address space");
        }
        const auto original = context->addressSpace->readU16(guest::GuestAddress{address});
        const auto result = static_cast<std::uint16_t>(original - 1U);
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateDecFlags16(state, original, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint16_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
decrementGuest64(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 64-bit guest decrement has no address space");
        }
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original - 1U;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        return updateDecFlags<std::uint64_t>(state, original, result);
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
decrementGuest8(GuestExecutionContext *context, x86::X86State *state,
                std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 8-bit guest decrement has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, 1,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU8(guest::GuestAddress{address});
        const auto result = static_cast<std::uint8_t>(original - 1U);
        const std::array resultBytes{result};
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateDecFlags8(state, original, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint8_t);
        }
        return nullptr;
    }
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

extern "C" __attribute__((noinline)) x86::X86State *updateSubFlags8(x86::X86State *state,
                                                                    std::uint64_t lhsValue,
                                                                    std::uint64_t rhsValue,
                                                                    std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto rhs = static_cast<std::uint8_t>(rhsValue);
    const auto result = static_cast<std::uint8_t>(resultValue);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (lhs < rhs) {
        flags |= flagCarry;
    }
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if (((lhs ^ rhs ^ result) & 0x10U) != 0) {
        flags |= flagAuxiliaryCarry;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 7U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) >> 7U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSubFlags16(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint16_t>(lhsValue);
    const auto rhs = static_cast<std::uint16_t>(rhsValue);
    const auto result = static_cast<std::uint16_t>(resultValue);
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
    if ((result >> 15U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) >> 15U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateSubFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue) {
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto rhs = static_cast<std::uint32_t>(rhsValue);
    const auto result = static_cast<std::uint32_t>(resultValue);
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
    if ((result >> 31U) != 0) {
        flags |= flagSign;
    }
    if ((((lhs ^ rhs) & (lhs ^ result)) >> 31U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
compareExchangeGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                       std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated CMPXCHG has no guest address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        // LOCK requires a writable read-modify-write operand even when the
        // comparison fails. The current single-guest-thread execution model
        // makes this helper indivisible with respect to guest execution.
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto memoryValue = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto accumulator = static_cast<std::uint32_t>(state->rax);
        const auto result = static_cast<std::uint32_t>(memoryValue - accumulator);
        if (accumulator == memoryValue) {
            const auto source = static_cast<std::uint32_t>(sourceValue);
            const std::array bytes{
                static_cast<std::uint8_t>(source),
                static_cast<std::uint8_t>(source >> 8U),
                static_cast<std::uint8_t>(source >> 16U),
                static_cast<std::uint8_t>(source >> 24U),
            };
            context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
            // The implicit 32-bit accumulator is architecturally written even
            // on the equal path, so its upper half is cleared in 64-bit mode.
            state->rax = accumulator;
        } else {
            state->rax = memoryValue;
        }
        return updateSubFlags32(state, memoryValue, accumulator, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
compareExchangeGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                       std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 64-bit CMPXCHG has no guest address space");
        }
        constexpr auto width = sizeof(std::uint64_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto memoryValue = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto accumulator = state->rax;
        const auto result = memoryValue - accumulator;
        if (accumulator == memoryValue) {
            std::array<std::uint8_t, width> bytes{};
            std::memcpy(bytes.data(), &sourceValue, sizeof(sourceValue));
            context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        } else {
            state->rax = memoryValue;
        }
        return updateSubFlags64(state, memoryValue, accumulator, result);
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
compareExchangeGuestPair(GuestExecutionContext *context, x86::X86State *state,
                         std::uint64_t address) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated CMPXCHG16B has no guest address space");
        }
        constexpr auto width = std::size_t{16};
        if ((address & (width - 1U)) != 0) {
            throw std::runtime_error("CMPXCHG16B requires a 16-byte aligned guest address");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, width);
        std::uint64_t memoryLow = 0;
        std::uint64_t memoryHigh = 0;
        std::memcpy(&memoryLow, bytes.data(), sizeof(memoryLow));
        std::memcpy(&memoryHigh, bytes.data() + sizeof(memoryLow), sizeof(memoryHigh));
        if (state->rax == memoryLow && state->rdx == memoryHigh) {
            std::array<std::uint8_t, width> replacement{};
            std::memcpy(replacement.data(), &state->rbx, sizeof(state->rbx));
            std::memcpy(replacement.data() + sizeof(state->rbx), &state->rcx, sizeof(state->rcx));
            context->addressSpace->writeBytes(guest::GuestAddress{address}, replacement);
            state->rflags |= flagZero;
        } else {
            state->rax = memoryLow;
            state->rdx = memoryHigh;
            state->rflags &= ~flagZero;
        }
        // Rosa currently has one guest thread. Keep the LOCK ordering boundary
        // explicit without claiming host-thread atomicity for guest mappings.
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = 16;
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
exchangeGuest8(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
               std::uint64_t sourceValue, std::uint64_t destinationEncoding) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated byte XCHG has no guest address space");
        }
        if (destinationEncoding > static_cast<std::uint64_t>(x86::Register::R15)) {
            throw std::runtime_error("generated byte XCHG has an invalid guest register");
        }
        constexpr auto width = sizeof(std::uint8_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto oldValue = context->addressSpace->readU8(guest::GuestAddress{address});
        const auto newValue = static_cast<std::uint8_t>(sourceValue);
        context->addressSpace->writeBytes(guest::GuestAddress{address},
                                          std::array<std::uint8_t, 1>{newValue});
        std::atomic_thread_fence(std::memory_order_seq_cst);
        const auto destination = static_cast<x86::Register>(destinationEncoding);
        std::memcpy(reinterpret_cast<std::uint8_t *>(state) + x86::registerOffset(destination),
                    &oldValue, sizeof(oldValue));
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint8_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
exchangeGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t sourceValue, std::uint64_t destinationEncoding) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated XCHG has no guest address space");
        }
        if (destinationEncoding > static_cast<std::uint64_t>(x86::Register::R15)) {
            throw std::runtime_error("generated XCHG has an invalid guest register");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto oldValue = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto newValue = static_cast<std::uint32_t>(sourceValue);
        const std::array bytes{
            static_cast<std::uint8_t>(newValue),
            static_cast<std::uint8_t>(newValue >> 8U),
            static_cast<std::uint8_t>(newValue >> 16U),
            static_cast<std::uint8_t>(newValue >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        const auto destination = static_cast<x86::Register>(destinationEncoding);
        const auto zeroExtended = static_cast<std::uint64_t>(oldValue);
        std::memcpy(reinterpret_cast<std::uint8_t *>(state) + x86::registerOffset(destination),
                    &zeroExtended, sizeof(zeroExtended));
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
exchangeGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t sourceValue, std::uint64_t destinationEncoding) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated XCHG has no guest address space");
        }
        if (destinationEncoding > static_cast<std::uint64_t>(x86::Register::R15)) {
            throw std::runtime_error("generated XCHG has an invalid guest register");
        }
        constexpr auto width = sizeof(std::uint64_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto oldValue = context->addressSpace->readU64(guest::GuestAddress{address});
        context->addressSpace->writeU64(guest::GuestAddress{address}, sourceValue);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        const auto destination = static_cast<x86::Register>(destinationEncoding);
        std::memcpy(reinterpret_cast<std::uint8_t *>(state) + x86::registerOffset(destination),
                    &oldValue, sizeof(oldValue));
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

extern "C" __attribute__((noinline)) x86::X86State *updateLogicFlags32(x86::X86State *state,
                                                                       std::uint64_t result) {
    const auto result32 = static_cast<std::uint32_t>(result);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result32 & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result32 == 0) {
        flags |= flagZero;
    }
    if ((result32 >> 31U) != 0) {
        flags |= flagSign;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
lockedOrGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t immediateValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated LOCK OR has no guest address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint32_t>(original | static_cast<std::uint32_t>(immediateValue));
        const std::array bytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        // LOCK OR is also used as a full fence. Guest execution is currently
        // single-threaded, while this host fence preserves ordering at the
        // generated helper boundary.
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateLogicFlags32(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
lockedOrGuest16(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t immediateValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated word LOCK OR has no guest address space");
        }
        constexpr auto width = sizeof(std::uint16_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU16(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint16_t>(original | static_cast<std::uint16_t>(immediateValue));
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateLogicFlags16(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint16_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
lockedAndGuest16(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t immediateValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated word LOCK AND has no guest address space");
        }
        constexpr auto width = sizeof(std::uint16_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU16(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint16_t>(original & static_cast<std::uint16_t>(immediateValue));
        const std::array resultBytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, resultBytes);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateLogicFlags16(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint16_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
lockedAddGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t source) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated LOCK ADD has no guest address space");
        }
        constexpr auto width = sizeof(std::uint64_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original + source;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        // Rosa currently has one guest thread. Keep the LOCK ordering boundary
        // explicit without claiming host-thread atomicity for guest mappings.
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateAddFlags64(state, original, source, result);
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
lockedExchangeAddGuest32(GuestExecutionContext *context, x86::X86State *state,
                         std::uint64_t address, std::uint64_t sourceValue,
                         std::uint64_t sourceEncoding) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated LOCK XADD has no guest address space");
        }
        if (sourceEncoding > static_cast<std::uint64_t>(x86::Register::R15)) {
            throw std::runtime_error("generated LOCK XADD has an invalid source register");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto source = static_cast<std::uint32_t>(sourceValue);
        const auto result = static_cast<std::uint32_t>(original + source);
        const std::array bytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        const auto sourceRegister = static_cast<x86::Register>(sourceEncoding);
        const auto zeroExtended = static_cast<std::uint64_t>(original);
        std::memcpy(reinterpret_cast<std::uint8_t *>(state) + x86::registerOffset(sourceRegister),
                    &zeroExtended, sizeof(zeroExtended));
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateAddFlags32(state, original, source, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
lockedExchangeAddGuest64(GuestExecutionContext *context, x86::X86State *state,
                         std::uint64_t address, std::uint64_t sourceValue,
                         std::uint64_t sourceEncoding) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 64-bit LOCK XADD has no guest address space");
        }
        if (sourceEncoding > static_cast<std::uint64_t>(x86::Register::R15)) {
            throw std::runtime_error("generated 64-bit LOCK XADD has an invalid source register");
        }
        constexpr auto width = sizeof(std::uint64_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original + sourceValue;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        const auto sourceRegister = static_cast<x86::Register>(sourceEncoding);
        std::memcpy(reinterpret_cast<std::uint8_t *>(state) + x86::registerOffset(sourceRegister),
                    &original, sizeof(original));
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateAddFlags64(state, original, sourceValue, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint64_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *updateLogicFlags16(x86::X86State *state,
                                                                       std::uint64_t result) {
    const auto result16 = static_cast<std::uint16_t>(result);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result16 & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result16 == 0) {
        flags |= flagZero;
    }
    if ((result16 >> 15U) != 0) {
        flags |= flagSign;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateLogicFlags8(x86::X86State *state,
                                                                      std::uint64_t result) {
    const auto result8 = static_cast<std::uint8_t>(result);
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if ((std::popcount(static_cast<unsigned>(result8)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result8 == 0) {
        flags |= flagZero;
    }
    if ((result8 >> 7U) != 0) {
        flags |= flagSign;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftLeftFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t result,
                       std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    const auto carry = (lhs >> (64U - count)) & 1U;
    flags |= carry;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (((result >> 63U) & 1U) ^ carry) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
shiftLeftGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t countValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 64-bit guest memory shift has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, sizeof(std::uint64_t),
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto count = static_cast<std::uint8_t>(countValue & 0x3FU);
        const auto result = count == 0 ? original : original << count;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        return updateShiftLeftFlags64(state, original, result, count);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint64_t);
        }
        return nullptr;
    }
}

extern "C" x86::X86State *updateShiftRightFlags32(x86::X86State *state, std::uint64_t lhsValue,
                                                   std::uint64_t resultValue,
                                                   std::uint64_t unmaskedCount);
extern "C" x86::X86State *updateShiftRightFlags64(x86::X86State *state, std::uint64_t lhs,
                                                   std::uint64_t result,
                                                   std::uint64_t unmaskedCount);

extern "C" __attribute__((noinline)) x86::X86State *
shiftRightGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                  std::uint64_t countValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 32-bit guest memory shift has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, sizeof(std::uint32_t),
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto count = static_cast<std::uint8_t>(countValue & 0x1FU);
        const auto result = count == 0 ? original : original >> count;
        context->addressSpace->writeU32(guest::GuestAddress{address}, result);
        return updateShiftRightFlags32(state, original, result, count);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint32_t);
        }
        return nullptr;
    }
}

extern "C" __attribute__((noinline)) x86::X86State *
shiftRightGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                  std::uint64_t countValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated 64-bit guest memory shift has no address space");
        }
        context->addressSpace->validateAccess(guest::GuestAddress{address}, sizeof(std::uint64_t),
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto count = static_cast<std::uint8_t>(countValue & 0x3FU);
        const auto result = count == 0 ? original : original >> count;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        return updateShiftRightFlags64(state, original, result, count);
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
updateShiftLeftFlags32(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                       std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    const auto carry = (lhs >> (32U - count)) & 1U;
    flags |= carry;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 31U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (((result >> 31U) & 1U) ^ carry) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftLeftFlags8(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                      std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto result = static_cast<std::uint8_t>(resultValue);
    auto replacedFlags = flagParity | flagZero | flagSign;
    if (count < 8) {
        replacedFlags |= flagCarry;
    }
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    std::uint64_t carry = 0;
    if (count < 8) {
        carry = (static_cast<unsigned>(lhs) >> (8U - count)) & 1U;
        flags |= carry;
    }
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 7U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && ((((result >> 7U) & 1U) ^ carry) != 0)) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateRotateLeftFlags16(x86::X86State *state, std::uint64_t resultValue,
                        std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    const auto effectiveCount = static_cast<std::uint8_t>(count % 16U);
    if (effectiveCount == 0) {
        return state;
    }
    const auto result = static_cast<std::uint16_t>(resultValue);
    auto replacedFlags = flagCarry;
    if (effectiveCount == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    const auto carry = static_cast<std::uint64_t>(result & 1U);
    flags |= carry;
    if (effectiveCount == 1 && ((((result >> 15U) & 1U) ^ carry) != 0)) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateRotateLeftFlags32(x86::X86State *state, std::uint64_t resultValue,
                        std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto replacedFlags = flagCarry;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    const auto carry = static_cast<std::uint64_t>(result & 1U);
    flags |= carry;
    if (count == 1 && ((((result >> 31U) & 1U) ^ carry) != 0)) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateRotateLeftFlags64(x86::X86State *state, std::uint64_t result, std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    const auto carry = result & 1U;
    flags |= carry;
    if (count == 1 && ((((result >> 63U) & 1U) ^ carry) != 0)) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateRotateRightFlags64(x86::X86State *state, std::uint64_t result, std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= result >> 63U;
    if (count == 1 && (((result >> 63U) ^ (result >> 62U)) & 1U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightFlags8(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                       std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto lhs = static_cast<std::uint8_t>(lhsValue);
    const auto result = static_cast<std::uint8_t>(resultValue);
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (static_cast<unsigned>(lhs) >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 7U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (lhs >> 7U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightFlags32(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                        std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (lhs >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 31U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (lhs >> 31U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t result,
                        std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (lhs >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (lhs >> 63U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightArithmeticFlags32(x86::X86State *state, std::uint64_t lhsValue,
                                  std::uint64_t resultValue, std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x1FU);
    if (count == 0) {
        return state;
    }
    const auto lhs = static_cast<std::uint32_t>(lhsValue);
    const auto result = static_cast<std::uint32_t>(resultValue);
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (lhs >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 31U) != 0) {
        flags |= flagSign;
    }
    // SAR defines OF as zero for a one-bit shift. It is undefined for
    // larger counts, so Rosa preserves the incoming value in that case.
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightArithmeticFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t result,
                                  std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (lhs >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    // SAR defines OF as zero for a one-bit shift. It is undefined for
    // larger counts, so Rosa preserves the incoming value in that case.
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *updateMultiplyFlags64(x86::X86State *state,
                                                                          std::uint64_t high) {
    auto flags = (state->rflags & ~(flagCarry | flagOverflow)) | flagReservedOne;
    if (high != 0) {
        flags |= flagCarry | flagOverflow;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateSignedMultiplyFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs) {
    std::int64_t ignoredResult = 0;
    const bool overflow = __builtin_mul_overflow(std::bit_cast<std::int64_t>(lhs),
                                                 std::bit_cast<std::int64_t>(rhs), &ignoredResult);
    state->rflags = (state->rflags & ~(flagCarry | flagOverflow)) | flagReservedOne;
    if (overflow) {
        state->rflags |= flagCarry | flagOverflow;
    }
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateSignedMultiplyFlags32(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs) {
    std::int32_t ignoredResult = 0;
    const bool overflow = __builtin_mul_overflow(
        std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(lhs)),
        std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(rhs)), &ignoredResult);
    state->rflags = (state->rflags & ~(flagCarry | flagOverflow)) | flagReservedOne;
    if (overflow) {
        state->rflags |= flagCarry | flagOverflow;
    }
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateBitTestFlags32(x86::X86State *state, std::uint64_t value, std::uint64_t unmaskedBitIndex) {
    const auto bitIndex = static_cast<std::uint8_t>(unmaskedBitIndex & 0x1FU);
    auto flags = (state->rflags & ~flagCarry) | flagReservedOne;
    flags |= (value >> bitIndex) & 1U;
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateBitTestFlags64(x86::X86State *state, std::uint64_t value, std::uint64_t unmaskedBitIndex) {
    const auto bitIndex = static_cast<std::uint8_t>(unmaskedBitIndex & 0x3FU);
    auto flags = (state->rflags & ~flagCarry) | flagReservedOne;
    flags |= (value >> bitIndex) & 1U;
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateShiftRightDoubleFlags64(x86::X86State *state, std::uint64_t original, std::uint64_t result,
                              std::uint64_t unmaskedCount) {
    const auto count = static_cast<std::uint8_t>(unmaskedCount & 0x3FU);
    if (count == 0) {
        return state;
    }
    auto replacedFlags = flagCarry | flagParity | flagZero | flagSign;
    if (count == 1) {
        replacedFlags |= flagOverflow;
    }
    auto flags = (state->rflags & ~replacedFlags) | flagReservedOne;
    flags |= (original >> (count - 1U)) & 1U;
    if ((std::popcount(static_cast<unsigned>(result & 0xFFU)) % 2) == 0) {
        flags |= flagParity;
    }
    if (result == 0) {
        flags |= flagZero;
    }
    if ((result >> 63U) != 0) {
        flags |= flagSign;
    }
    if (count == 1 && (((original ^ result) >> 63U) & 1U) != 0) {
        flags |= flagOverflow;
    }
    state->rflags = flags;
    return state;
}

template <typename Pointer> arm64::RelocatablePointer pointerBits(Pointer pointer) {
    static_assert(std::is_pointer_v<Pointer>);
    static_assert(sizeof(pointer) == sizeof(std::uint64_t));
    std::uint64_t result = 0;
    std::memcpy(&result, &pointer, sizeof(result));
    return arm64::RelocatablePointer{result};
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
        case x86::Opcode::AddsdXmmReg:
        case x86::Opcode::AddsdXmmMem:
        case x86::Opcode::SubsdXmmReg:
        case x86::Opcode::SubsdXmmMem:
        case x86::Opcode::MulsdXmmReg:
        case x86::Opcode::MulsdXmmMem:
        case x86::Opcode::DivsdXmmReg:
        case x86::Opcode::DivsdXmmMem: {
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
                                       : std::uint8_t{3};
            const auto destination =
                std::get<x86::XmmRegisterOperand>(instruction.operands[0]).reg;
            const bool fromMemory =
                instruction.opcode == x86::Opcode::AddsdXmmMem ||
                instruction.opcode == x86::Opcode::SubsdXmmMem ||
                instruction.opcode == x86::Opcode::MulsdXmmMem ||
                instruction.opcode == x86::Opcode::DivsdXmmMem;
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
        case x86::Opcode::CmpxchgMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: cmpxchg memory operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != source.width || (memory.width != 32 && memory.width != 64)) {
                throw std::runtime_error(
                    "only 32-bit and 64-bit guest-memory CMPXCHG are implemented");
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
            const auto sourceValue = builder.readGuestRegister(
                source.reg, source.width == 32 ? ir::Width::I32 : ir::Width::I64,
                instruction.address);
            builder.compareExchangeGuestMemory(address, sourceValue,
                                               memory.width == 32 ? ir::Width::I32 : ir::Width::I64,
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
            if (memory.width != 64 || source.width != 64) {
                throw std::runtime_error("only LOCK ADD qword [base/RIP+disp], r64 is implemented");
            }
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
                builder.readGuestRegister(source.reg, ir::Width::I64, instruction.address);
            builder.lockedAddGuestMemory(address, sourceValue, ir::Width::I64, instruction.address);
            break;
        }
        case x86::Opcode::LockXaddMemReg: {
            if (instruction.operands.size() != 2) {
                throw std::runtime_error("internal decoder error: LOCK XADD operand count");
            }
            const auto memory = std::get<x86::MemoryOperand>(instruction.operands[0]);
            const auto source = std::get<x86::RegisterOperand>(instruction.operands[1]);
            if (memory.width != source.width || (memory.width != 32 && memory.width != 64)) {
                throw std::runtime_error(
                    "only LOCK XADD dword/qword [base+disp], r32/r64 is implemented");
            }
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
            const auto sourceValue = builder.readGuestRegister(
                source.reg, source.width == 32 ? ir::Width::I32 : ir::Width::I64,
                instruction.address);
            builder.lockedExchangeAddGuestMemory(
                address, sourceValue, source.reg,
                memory.width == 32 ? ir::Width::I32 : ir::Width::I64, instruction.address);
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
                instruction.opcode == x86::Opcode::LockOrMemImm && memory.width == 32 &&
                (immediate.width == 8 || immediate.width == 32);
            if (!wordForm && !dwordForm) {
                throw std::runtime_error("only LOCK OR/AND word [base+disp], imm8/imm16 and LOCK OR "
                                         "dword [base+disp], imm8/imm32 are implemented");
            }
            const auto base =
                builder.readGuestRegister(memory.base, ir::Width::I64, instruction.address);
            auto address = base;
            if (memory.displacement != 0) {
                const auto displacement =
                    builder.constant(static_cast<std::uint64_t>(memory.displacement),
                                     ir::Width::I64, instruction.address);
                address = builder.add(base, displacement, ir::Width::I64, instruction.address);
            }
            const auto width = memory.width == 16 ? ir::Width::I16 : ir::Width::I32;
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
            if ((reg.width != 8 && reg.width != 32 && reg.width != 64) ||
                immediate.width != 8) {
                throw std::runtime_error("only SBB r8/r32/r64, imm8 is implemented");
            }
            const auto width = reg.width == 8    ? ir::Width::I8
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
                const auto index =
                    builder.readGuestRegister(*memory.index, ir::Width::I64, instruction.address);
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
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 16 ? ir::Width::I16
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto result = builder.bitAnd(lhs, rhs, width, instruction.address);
            builder.writeGuestRegister(reg.reg, result, width, instruction.address);
            builder.updateLogicFlags(result, width, instruction.address);
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
                (reg.width == 32 && immediate.width != 32) ||
                (reg.width == 64 && immediate.width != 32) ||
                (reg.width != 8 && reg.width != 32 && reg.width != 64)) {
                throw std::runtime_error("unsupported internal TEST immediate width");
            }
            const auto width = reg.width == 8    ? ir::Width::I8
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
            const auto width = reg.width == 8    ? ir::Width::I8
                               : reg.width == 16 ? ir::Width::I16
                               : reg.width == 32 ? ir::Width::I32
                                                 : ir::Width::I64;
            const auto lhs = builder.readGuestRegister(reg.reg, width, instruction.address);
            const auto rhs = builder.constant(immediate.value, width, instruction.address);
            const auto result = builder.sub(lhs, rhs, width, instruction.address);
            builder.updateSubFlags(lhs, rhs, result, width, instruction.address);
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
        case x86::Opcode::Rdtsc:
            builder.readTimestampCounter(instruction.address);
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

    const auto lastOpcode = decoded.back().opcode;
    const bool hasTerminator =
        lastOpcode == x86::Opcode::JmpRelative || lastOpcode == x86::Opcode::JmpReg ||
        lastOpcode == x86::Opcode::JmpMem || lastOpcode == x86::Opcode::JccRelative ||
        lastOpcode == x86::Opcode::CallRelative || lastOpcode == x86::Opcode::CallReg ||
        lastOpcode == x86::Opcode::CallMem || lastOpcode == x86::Opcode::Syscall ||
        lastOpcode == x86::Opcode::Ret;
    if (!hasTerminator) {
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

struct ZeroFlagSource {
    ir::ValueId value;
    ir::Width width;
};

std::optional<ZeroFlagSource> zeroFlagSourceForUpdate(const ir::Operation &operation) noexcept {
    switch (operation.opcode) {
    case ir::Opcode::UpdateAddFlags:
        if (operation.third) {
            return ZeroFlagSource{*operation.third, operation.width};
        }
        return std::nullopt;
    case ir::Opcode::UpdateSubFlags:
        if ((operation.width == ir::Width::I8 || operation.width == ir::Width::I64) &&
            operation.third) {
            return ZeroFlagSource{*operation.third, operation.width};
        }
        return std::nullopt;
    case ir::Opcode::UpdateLogicFlags:
        if (operation.lhs) {
            return ZeroFlagSource{*operation.lhs, operation.width};
        }
        return std::nullopt;
    default:
        return std::nullopt;
    }
}

bool isAnyFlagUpdate(ir::Opcode opcode) noexcept {
    switch (opcode) {
    case ir::Opcode::UpdateAddFlags:
    case ir::Opcode::UpdateAdcFlags:
    case ir::Opcode::UpdateSbbFlags:
    case ir::Opcode::UpdateIncFlags:
    case ir::Opcode::UpdateDecFlags:
    case ir::Opcode::UpdateSubFlags:
    case ir::Opcode::UpdateLogicFlags:
    case ir::Opcode::UpdateShiftLeftFlags:
    case ir::Opcode::UpdateShiftRightFlags:
    case ir::Opcode::UpdateShiftRightArithmeticFlags:
    case ir::Opcode::UpdateRotateLeftFlags:
    case ir::Opcode::UpdateRotateRightFlags:
    case ir::Opcode::UpdateMultiplyFlags:
    case ir::Opcode::UpdateSignedMultiplyFlags:
    case ir::Opcode::UpdateShiftRightDoubleFlags:
    case ir::Opcode::UpdateBitTestFlags:
        return true;
    default:
        return false;
    }
}

bool preservesZeroFlagSource(ir::Opcode opcode) noexcept {
    switch (opcode) {
    case ir::Opcode::Constant:
    case ir::Opcode::ReadGuestReg:
    case ir::Opcode::WriteGuestReg:
    case ir::Opcode::Add:
    case ir::Opcode::Sub:
    case ir::Opcode::ShiftLeft:
    case ir::Opcode::ShiftRightLogical:
    case ir::Opcode::ShiftRightArithmetic:
    case ir::Opcode::MultiplyLow:
    case ir::Opcode::MultiplyHighUnsigned:
    case ir::Opcode::MultiplyHighSigned:
    case ir::Opcode::ShiftRightDouble:
    case ir::Opcode::And:
    case ir::Opcode::Or:
    case ir::Opcode::Xor:
    case ir::Opcode::SignExtend32:
    case ir::Opcode::ByteSwap:
    case ir::Opcode::EvaluateCondition:
    case ir::Opcode::ConditionalMoveGuestReg:
        return true;
    default:
        return false;
    }
}

bool fullyReplacesArithmeticFlags(ir::Opcode opcode) noexcept {
    return opcode == ir::Opcode::UpdateAddFlags || opcode == ir::Opcode::UpdateAdcFlags ||
           opcode == ir::Opcode::UpdateSbbFlags || opcode == ir::Opcode::UpdateSubFlags ||
           opcode == ir::Opcode::UpdateLogicFlags;
}

bool isFlagSinkPure(ir::Opcode opcode) noexcept {
    switch (opcode) {
    case ir::Opcode::Constant:
    case ir::Opcode::ReadGuestReg:
    case ir::Opcode::WriteGuestReg:
    case ir::Opcode::Add:
    case ir::Opcode::Sub:
    case ir::Opcode::ShiftLeft:
    case ir::Opcode::ShiftRightLogical:
    case ir::Opcode::ShiftRightArithmetic:
    case ir::Opcode::MultiplyLow:
    case ir::Opcode::MultiplyHighUnsigned:
    case ir::Opcode::MultiplyHighSigned:
    case ir::Opcode::ShiftRightDouble:
    case ir::Opcode::And:
    case ir::Opcode::Or:
    case ir::Opcode::Xor:
    case ir::Opcode::SignExtend32:
    case ir::Opcode::ByteSwap:
        return true;
    default:
        return false;
    }
}

std::optional<std::size_t> logicFlagSinkTarget(const ir::Block &block,
                                               std::size_t updateIndex) noexcept {
    if (updateIndex >= block.operations.size() ||
        block.operations[updateIndex].opcode != ir::Opcode::UpdateLogicFlags) {
        return std::nullopt;
    }
    std::optional<std::size_t> target;
    for (auto index = updateIndex + 1; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        if (isFlagSinkPure(operation.opcode)) {
            continue;
        }
        if (!target && operation.opcode == ir::Opcode::LoadGuest &&
            operation.width == ir::Width::I8) {
            target = index;
            continue;
        }
        if (target && fullyReplacesArithmeticFlags(operation.opcode)) {
            return target;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::size_t> sunkLogicFlagUpdateAt(const ir::Block &block,
                                                 std::size_t loadIndex) noexcept {
    for (std::size_t index = 0; index < loadIndex; ++index) {
        if (logicFlagSinkTarget(block, index) == loadIndex) {
            return index;
        }
    }
    return std::nullopt;
}

std::optional<ZeroFlagSource> zeroFlagSourceAt(const ir::Block &block,
                                               std::size_t operationIndex) noexcept {
    while (operationIndex != 0) {
        const auto &candidate = block.operations[--operationIndex];
        if (isAnyFlagUpdate(candidate.opcode)) {
            return zeroFlagSourceForUpdate(candidate);
        }
        if (!preservesZeroFlagSource(candidate.opcode)) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> zeroFlagUpdateIndexAt(const ir::Block &block,
                                                 std::size_t operationIndex) noexcept {
    while (operationIndex != 0) {
        const auto index = --operationIndex;
        const auto &candidate = block.operations[index];
        if (isAnyFlagUpdate(candidate.opcode)) {
            return zeroFlagSourceForUpdate(candidate) ? std::optional<std::size_t>{index}
                                                      : std::nullopt;
        }
        if (!preservesZeroFlagSource(candidate.opcode)) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> deferredExitFlagUpdate(const ir::Block &block,
                                                  bool internalSelfEdge) noexcept {
    if (!internalSelfEdge || block.operations.empty()) {
        return std::nullopt;
    }
    const auto exitIndex = block.operations.size() - 1;
    const auto &exit = block.operations[exitIndex];
    if (exit.opcode != ir::Opcode::ExitBlock || exit.exitKind != ir::ExitKind::Conditional ||
        !exit.condition) {
        return std::nullopt;
    }
    if (*exit.condition == x86::Condition::ParityEven ||
        *exit.condition == x86::Condition::ParityOdd) {
        // ARM64 NZCV cannot express parity: always materialize guest PF and
        // take the flag-test exit path instead.
        return std::nullopt;
    }
    const auto updateIndex = zeroFlagUpdateIndexAt(block, exitIndex);
    if (!updateIndex) {
        return std::nullopt;
    }
    const auto &update = block.operations[*updateIndex];
    if (update.opcode != ir::Opcode::UpdateSubFlags || update.width != ir::Width::I64) {
        return std::nullopt;
    }
    return updateIndex;
}

bool consumesOnlyZeroFlag(const ir::Operation &operation) noexcept {
    return (operation.opcode == ir::Opcode::EvaluateCondition ||
            operation.opcode == ir::Opcode::ConditionalMoveGuestReg) &&
           operation.condition &&
           (*operation.condition == x86::Condition::Equal ||
            *operation.condition == x86::Condition::NotEqual);
}

std::vector<arm64::XRegister> allocateHostRegisters(const ir::Block &block,
                                                    bool fuseZeroFlagConsumers, bool sinkLogicFlags,
                                                    std::optional<std::size_t> deferredExitUpdate) {
    constexpr std::uint8_t firstRegister = 8;
    constexpr std::size_t registerCount = 8;
    std::vector<std::size_t> lastUses(block.valueCount);
    std::vector<bool> defined(block.valueCount);

    const auto checkValue = [&](ir::ValueId value) {
        if (value.value >= block.valueCount) {
            throw std::runtime_error("R1 register allocation saw an out-of-range IR value");
        }
    };
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        if (operation.result) {
            checkValue(*operation.result);
            defined[operation.result->value] = true;
            lastUses[operation.result->value] = index;
        }
        for (const auto value : {operation.lhs, operation.rhs, operation.third}) {
            if (value) {
                checkValue(*value);
                lastUses[value->value] = std::max(lastUses[value->value], index);
            }
        }
        if (fuseZeroFlagConsumers && consumesOnlyZeroFlag(operation)) {
            if (const auto source = zeroFlagSourceAt(block, index)) {
                checkValue(source->value);
                lastUses[source->value.value] = std::max(lastUses[source->value.value], index);
            }
        }
        if (sinkLogicFlags) {
            if (const auto target = logicFlagSinkTarget(block, index)) {
                if (operation.lhs) {
                    checkValue(*operation.lhs);
                    lastUses[operation.lhs->value] =
                        std::max(lastUses[operation.lhs->value], *target);
                }
            }
        }
    }

    if (deferredExitUpdate) {
        const auto &update = block.operations[*deferredExitUpdate];
        for (const auto value : {update.lhs, update.rhs, update.third}) {
            if (value) {
                checkValue(*value);
                lastUses[value->value] = block.operations.size() - 1;
            }
        }
    }

    std::vector<arm64::XRegister> assignments(block.valueCount);
    std::vector<bool> assigned(block.valueCount);
    std::array<std::optional<ir::ValueId>, registerCount> active;
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        for (auto &value : active) {
            if (value && lastUses[value->value] < index) {
                value.reset();
            }
        }
        const auto result = block.operations[index].result;
        if (!result) {
            continue;
        }
        const auto available =
            std::ranges::find_if(active, [](const auto &value) { return !value; });
        if (available == active.end()) {
            std::ostringstream reason;
            reason << "R1 linear-scan register allocator exhausted x8...x15"
                   << " at guest RIP 0x" << std::hex << block.operations[index].guestRip.value;
            throw std::runtime_error(reason.str());
        }
        const auto slot = static_cast<std::size_t>(std::distance(active.begin(), available));
        *available = *result;
        assignments[result->value] =
            arm64::XRegister{static_cast<std::uint8_t>(firstRegister + slot)};
        assigned[result->value] = true;
    }

    for (std::size_t value = 0; value < defined.size(); ++value) {
        if (defined[value] && !assigned[value]) {
            throw std::runtime_error("R1 register allocation left an IR value unassigned");
        }
    }
    return assignments;
}

bool isSafelyRepeatableOperation(const ir::Operation &operation) {
    switch (operation.opcode) {
    case ir::Opcode::Constant:
    case ir::Opcode::ReadGuestReg:
    case ir::Opcode::WriteGuestReg:
    case ir::Opcode::Add:
    case ir::Opcode::Sub:
    case ir::Opcode::ShiftLeft:
    case ir::Opcode::ShiftRightLogical:
    case ir::Opcode::ShiftRightArithmetic:
    case ir::Opcode::MultiplyLow:
    case ir::Opcode::MultiplyHighUnsigned:
    case ir::Opcode::MultiplyHighSigned:
    case ir::Opcode::ShiftRightDouble:
    case ir::Opcode::And:
    case ir::Opcode::Or:
    case ir::Opcode::Xor:
    case ir::Opcode::SignExtend32:
    case ir::Opcode::ByteSwap:
    case ir::Opcode::EvaluateCondition:
    case ir::Opcode::ConditionalMoveGuestReg:
    case ir::Opcode::LoadGuest:
    case ir::Opcode::UpdateAddFlags:
    case ir::Opcode::UpdateAdcFlags:
    case ir::Opcode::UpdateSbbFlags:
    case ir::Opcode::UpdateIncFlags:
    case ir::Opcode::UpdateDecFlags:
    case ir::Opcode::UpdateSubFlags:
    case ir::Opcode::UpdateLogicFlags:
    case ir::Opcode::UpdateShiftLeftFlags:
    case ir::Opcode::UpdateShiftRightFlags:
    case ir::Opcode::UpdateShiftRightArithmeticFlags:
    case ir::Opcode::UpdateRotateLeftFlags:
    case ir::Opcode::UpdateRotateRightFlags:
    case ir::Opcode::UpdateMultiplyFlags:
    case ir::Opcode::UpdateSignedMultiplyFlags:
    case ir::Opcode::UpdateShiftRightDoubleFlags:
    case ir::Opcode::UpdateBitTestFlags:
    case ir::Opcode::StoreGuest:
    case ir::Opcode::ExitBlock:
        return true;
    default:
        return false;
    }
}

void forwardFullWidthGuestReads(ir::Block &block, bool directMemoryLoop) {
    constexpr std::size_t registerCount = 16;
    const auto forwardsAcrossLoads =
        directMemoryLoop && std::ranges::any_of(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::LoadGuest && operation.width == ir::Width::I8;
        });
    const auto forwardsAcrossStores =
        directMemoryLoop && !forwardsAcrossLoads &&
        std::ranges::any_of(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::StoreGuest && operation.width == ir::Width::I8;
        });
    std::array<std::optional<ir::ValueId>, registerCount> currentValues;
    std::array<bool, registerCount> currentValuesAreFull{};
    std::array<bool, registerCount> currentValuesAreZeroExtended{};
    std::array<bool, registerCount> currentValuesAreZero{};
    std::vector<ir::ValueId> replacements(block.valueCount);
    std::vector<bool> zeroExtendedValues(block.valueCount);
    std::vector<bool> zeroValues(block.valueCount);
    std::vector<bool> conditionValues(block.valueCount);
    for (std::size_t value = 0; value < replacements.size(); ++value) {
        replacements[value] = ir::ValueId{static_cast<std::uint32_t>(value)};
    }
    const auto resolve = [&](ir::ValueId value) {
        while (replacements[value.value] != value) {
            value = replacements[value.value];
        }
        return value;
    };
    const auto canonicalize = [&](std::optional<ir::ValueId> &value) {
        if (value) {
            *value = resolve(*value);
        }
    };
    const auto isZeroExtended = [&](ir::ValueId value) {
        return zeroExtendedValues[resolve(value).value];
    };
    const auto isZero = [&](ir::ValueId value) { return zeroValues[resolve(value).value]; };
    const auto preservesHostValues = [&](const ir::Operation &operation) {
        switch (operation.opcode) {
        case ir::Opcode::Constant:
        case ir::Opcode::ReadGuestReg:
        case ir::Opcode::WriteGuestReg:
        case ir::Opcode::Add:
        case ir::Opcode::Sub:
        case ir::Opcode::ShiftLeft:
        case ir::Opcode::ShiftRightLogical:
        case ir::Opcode::ShiftRightArithmetic:
        case ir::Opcode::MultiplyLow:
        case ir::Opcode::MultiplyHighUnsigned:
        case ir::Opcode::MultiplyHighSigned:
        case ir::Opcode::ShiftRightDouble:
        case ir::Opcode::And:
        case ir::Opcode::Or:
        case ir::Opcode::Xor:
        case ir::Opcode::SignExtend32:
        case ir::Opcode::ByteSwap:
        case ir::Opcode::EvaluateCondition:
        case ir::Opcode::UpdateAddFlags:
        case ir::Opcode::UpdateLogicFlags:
            return true;
        case ir::Opcode::UpdateSubFlags:
            return operation.width == ir::Width::I8 || operation.width == ir::Width::I64;
        case ir::Opcode::LoadGuest:
            return forwardsAcrossLoads && operation.width == ir::Width::I8;
        case ir::Opcode::StoreGuest:
            return forwardsAcrossStores && operation.width == ir::Width::I8;
        default:
            return false;
        }
    };

    std::vector<ir::Operation> operations;
    operations.reserve(block.operations.size());
    for (auto operation : block.operations) {
        canonicalize(operation.lhs);
        canonicalize(operation.rhs);
        canonicalize(operation.third);

        if (forwardsAcrossLoads && operation.result && operation.opcode == ir::Opcode::Add) {
            const auto equivalent = std::ranges::find_if(operations, [&](const auto &candidate) {
                return candidate.result && candidate.opcode == operation.opcode &&
                       candidate.width == operation.width && candidate.lhs == operation.lhs &&
                       candidate.rhs == operation.rhs && candidate.third == operation.third &&
                       candidate.immediate == operation.immediate;
            });
            if (equivalent != operations.end()) {
                const auto source = resolve(*equivalent->result);
                replacements[operation.result->value] = source;
                zeroExtendedValues[operation.result->value] = zeroExtendedValues[source.value];
                zeroValues[operation.result->value] = zeroValues[source.value];
                conditionValues[operation.result->value] = conditionValues[source.value];
                continue;
            }
        }

        if (operation.opcode == ir::Opcode::ReadGuestReg && operation.guestRegister &&
            operation.result &&
            (operation.width == ir::Width::I32 || operation.width == ir::Width::I64)) {
            const auto index = static_cast<std::size_t>(*operation.guestRegister);
            if (index < currentValues.size() && currentValues[index] &&
                ((operation.width == ir::Width::I64 && currentValuesAreFull[index]) ||
                 (operation.width == ir::Width::I32 && currentValuesAreZeroExtended[index]))) {
                replacements[operation.result->value] = resolve(*currentValues[index]);
                zeroExtendedValues[operation.result->value] = currentValuesAreZeroExtended[index];
                zeroValues[operation.result->value] = currentValuesAreZero[index];
                continue;
            }
            if (index < currentValues.size()) {
                currentValues[index] = *operation.result;
                currentValuesAreFull[index] = operation.width == ir::Width::I64;
                currentValuesAreZeroExtended[index] = operation.width == ir::Width::I32;
                currentValuesAreZero[index] = false;
            }
        } else if (operation.opcode == ir::Opcode::WriteGuestReg && operation.guestRegister) {
            const auto index = static_cast<std::size_t>(*operation.guestRegister);
            if (index < currentValues.size()) {
                if ((operation.width == ir::Width::I32 || operation.width == ir::Width::I64) &&
                    operation.lhs) {
                    currentValues[index] = operation.lhs;
                    currentValuesAreFull[index] =
                        operation.width == ir::Width::I64 || isZeroExtended(*operation.lhs);
                    currentValuesAreZeroExtended[index] = isZeroExtended(*operation.lhs);
                    currentValuesAreZero[index] = isZero(*operation.lhs);
                } else if (operation.width == ir::Width::I8 && operation.lhs &&
                           currentValuesAreZero[index] &&
                           conditionValues[resolve(*operation.lhs).value]) {
                    currentValues[index] = operation.lhs;
                    currentValuesAreFull[index] = true;
                    currentValuesAreZeroExtended[index] = isZeroExtended(*operation.lhs);
                    currentValuesAreZero[index] = isZero(*operation.lhs);
                } else {
                    currentValues[index].reset();
                    currentValuesAreFull[index] = false;
                    currentValuesAreZeroExtended[index] = false;
                    currentValuesAreZero[index] = false;
                }
            }
        } else if (operation.opcode == ir::Opcode::ConditionalMoveGuestReg &&
                   operation.guestRegister) {
            const auto index = static_cast<std::size_t>(*operation.guestRegister);
            if (index < currentValues.size()) {
                currentValues[index].reset();
                currentValuesAreFull[index] = false;
                currentValuesAreZeroExtended[index] = false;
                currentValuesAreZero[index] = false;
            }
        } else if (!preservesHostValues(operation)) {
            currentValues.fill(std::nullopt);
            currentValuesAreFull.fill(false);
            currentValuesAreZeroExtended.fill(false);
            currentValuesAreZero.fill(false);
        }

        if (operation.result) {
            const auto result = operation.result->value;
            zeroValues[result] =
                operation.opcode == ir::Opcode::Constant && operation.immediate == 0;
            conditionValues[result] = operation.opcode == ir::Opcode::EvaluateCondition;
            zeroExtendedValues[result] =
                zeroValues[result] || conditionValues[result] ||
                (operation.width == ir::Width::I32 &&
                 (operation.opcode == ir::Opcode::Constant ||
                  operation.opcode == ir::Opcode::ReadGuestReg ||
                  operation.opcode == ir::Opcode::Add || operation.opcode == ir::Opcode::Sub ||
                  operation.opcode == ir::Opcode::And || operation.opcode == ir::Opcode::Or ||
                  operation.opcode == ir::Opcode::Xor ||
                  operation.opcode == ir::Opcode::LoadGuest));
        }
        operations.push_back(std::move(operation));
    }
    block.operations = std::move(operations);
}

bool hasInternalSelfEdge(const ir::Block &block) {
    if (!std::ranges::all_of(block.operations, isSafelyRepeatableOperation)) {
        return false;
    }
    return std::ranges::any_of(block.operations, [&block](const auto &operation) {
        return operation.opcode == ir::Opcode::ExitBlock &&
               ((operation.target && *operation.target == block.start) ||
                (operation.fallthrough && *operation.fallthrough == block.start));
    });
}

bool replacesArithmeticFlags(ir::Opcode opcode) noexcept {
    return fullyReplacesArithmeticFlags(opcode);
}

bool isPureBetweenFlagUpdates(ir::Opcode opcode) noexcept {
    switch (opcode) {
    case ir::Opcode::Constant:
    case ir::Opcode::ReadGuestReg:
    case ir::Opcode::WriteGuestReg:
    case ir::Opcode::Add:
    case ir::Opcode::Sub:
    case ir::Opcode::ShiftLeft:
    case ir::Opcode::ShiftRightLogical:
    case ir::Opcode::ShiftRightArithmetic:
    case ir::Opcode::MultiplyLow:
    case ir::Opcode::MultiplyHighUnsigned:
    case ir::Opcode::MultiplyHighSigned:
    case ir::Opcode::ShiftRightDouble:
    case ir::Opcode::And:
    case ir::Opcode::Or:
    case ir::Opcode::Xor:
    case ir::Opcode::SignExtend32:
    case ir::Opcode::ByteSwap:
        return true;
    default:
        return false;
    }
}

bool isDeadFlagUpdate(const ir::Block &block, std::size_t index,
                      bool fuseZeroFlagConsumers) noexcept {
    if (index >= block.operations.size() ||
        !replacesArithmeticFlags(block.operations[index].opcode)) {
        return false;
    }
    if (fuseZeroFlagConsumers && !zeroFlagSourceForUpdate(block.operations[index])) {
        return false;
    }
    for (++index; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        const auto opcode = operation.opcode;
        if (replacesArithmeticFlags(opcode)) {
            return true;
        }
        if (fuseZeroFlagConsumers && consumesOnlyZeroFlag(operation)) {
            continue;
        }
        if (!isPureBetweenFlagUpdates(opcode)) {
            return false;
        }
    }
    return false;
}

arm64::Program compileToArm64(const ir::Block &block, bool retainProgramListing) {
    arm64::Assembler assembler(retainProgramListing);
    const auto internalSelfEdge = hasInternalSelfEdge(block);
    // Keep condition consumption and flag-update elimination independently
    // switchable: the former is useful even when precise architectural flags
    // still need to be materialized for a later fault or side exit.
    const bool fuseZeroFlagConsumers = internalSelfEdge;
    const bool eliminateFusedFlagUpdates = fuseZeroFlagConsumers;
    const bool sinkLogicFlags = internalSelfEdge;
    const auto deferredExitUpdate = deferredExitFlagUpdate(block, internalSelfEdge);
    const auto hostRegisters =
        allocateHostRegisters(block, fuseZeroFlagConsumers, sinkLogicFlags, deferredExitUpdate);
    std::vector<std::optional<arm64::XRegister>> pinnedValueRegisters(block.valueCount);
    const auto hostRegister = [&](ir::ValueId value) {
        if (value.value >= hostRegisters.size()) {
            throw std::runtime_error("R1 code generation referenced an unallocated IR value");
        }
        if (pinnedValueRegisters[value.value]) {
            return *pinnedValueRegisters[value.value];
        }
        return hostRegisters[value.value];
    };
    std::vector<const ir::Operation *> definitions(block.valueCount);
    std::vector<std::size_t> definitionIndices(block.valueCount);
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        if (operation.result) {
            definitions[operation.result->value] = &operation;
            definitionIndices[operation.result->value] = index;
        }
    }
    const auto definingOperation = [&](ir::ValueId value) -> const ir::Operation * {
        if (value.value >= definitions.size()) {
            return nullptr;
        }
        return definitions[value.value];
    };
    std::vector<std::size_t> emittedUseCounts(block.valueCount);
    std::vector<std::size_t> emittedLastUses(block.valueCount);
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        if (isDeadFlagUpdate(block, index, eliminateFusedFlagUpdates)) {
            continue;
        }
        const auto &operation = block.operations[index];
        for (const auto value : {operation.lhs, operation.rhs, operation.third}) {
            if (value) {
                ++emittedUseCounts[value->value];
                emittedLastUses[value->value] = index;
            }
        }
    }
    const auto isZeroExtendedDefinition = [](const ir::Operation *definition) {
        return definition != nullptr && definition->width == ir::Width::I32 &&
               (definition->opcode == ir::Opcode::Constant ||
                definition->opcode == ir::Opcode::ReadGuestReg ||
                definition->opcode == ir::Opcode::Add || definition->opcode == ir::Opcode::Sub ||
                definition->opcode == ir::Opcode::And || definition->opcode == ir::Opcode::Or ||
                definition->opcode == ir::Opcode::Xor ||
                definition->opcode == ir::Opcode::LoadGuest);
    };
    std::optional<std::size_t> deferredExitResultOperation;
    if (deferredExitUpdate) {
        const auto &update = block.operations[*deferredExitUpdate];
        if (update.third) {
            const auto *definition = definingOperation(*update.third);
            if (definition != nullptr && definition->opcode == ir::Opcode::Sub &&
                definition->width == ir::Width::I64 && emittedUseCounts[update.third->value] == 1) {
                deferredExitResultOperation = definitionIndices[update.third->value];
            }
        }
    }
    std::vector<bool> foldedImmediate(block.valueCount);
    for (const auto &operation : block.operations) {
        if ((operation.opcode != ir::Opcode::Add && operation.opcode != ir::Opcode::Sub) ||
            (operation.width != ir::Width::I32 && operation.width != ir::Width::I64) ||
            !operation.rhs) {
            continue;
        }
        const auto *definition = definingOperation(*operation.rhs);
        if (definition != nullptr && definition->opcode == ir::Opcode::Constant &&
            definition->immediate <= 0x0FFFU && emittedUseCounts[operation.rhs->value] == 1) {
            foldedImmediate[operation.rhs->value] = true;
        }
    }
    const auto constantMaterializationCost = [](std::uint64_t value) {
        std::size_t movzCost = 0;
        std::size_t movnCost = 0;
        for (std::uint32_t shift = 0; shift < 64; shift += 16) {
            const auto halfword = static_cast<std::uint16_t>(value >> shift);
            movzCost += halfword != 0;
            movnCost += halfword != UINT16_MAX;
        }
        return std::max<std::size_t>(1, std::min(movzCost, movnCost));
    };
    std::optional<ir::ValueId> pinnedLoopConstant;
    std::size_t pinnedLoopConstantCost{};
    if (internalSelfEdge && deferredExitUpdate) {
        for (const auto &operation : block.operations) {
            if (operation.opcode != ir::Opcode::Constant || !operation.result ||
                foldedImmediate[operation.result->value] ||
                emittedUseCounts[operation.result->value] == 0) {
                continue;
            }
            const auto value = operation.width == ir::Width::I32 ? operation.immediate & UINT32_MAX
                                                                 : operation.immediate;
            const auto cost = constantMaterializationCost(value);
            if (cost > pinnedLoopConstantCost) {
                pinnedLoopConstant = *operation.result;
                pinnedLoopConstantCost = cost;
            }
        }
    }
    if (pinnedLoopConstant) {
        pinnedValueRegisters[pinnedLoopConstant->value] = arm64::x24;
    }
    const auto pinsDirectRead =
        internalSelfEdge && std::ranges::any_of(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::LoadGuest && operation.width == ir::Width::I8;
        });
    const auto pinsDirectWrite =
        internalSelfEdge && !pinsDirectRead &&
        std::ranges::any_of(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::StoreGuest && operation.width == ir::Width::I8;
        });
    const auto mayStopRepeating =
        internalSelfEdge && std::ranges::any_of(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::StoreGuest;
        });
    const auto canPinCallerSavedGuestRegisters =
        (pinsDirectRead || pinsDirectWrite) &&
        std::ranges::all_of(block.operations, [](const auto &operation) {
            switch (operation.opcode) {
            case ir::Opcode::Constant:
            case ir::Opcode::ReadGuestReg:
            case ir::Opcode::WriteGuestReg:
            case ir::Opcode::Add:
            case ir::Opcode::Sub:
            case ir::Opcode::And:
            case ir::Opcode::Or:
            case ir::Opcode::Xor:
            case ir::Opcode::EvaluateCondition:
            case ir::Opcode::ConditionalMoveGuestReg:
            case ir::Opcode::ExitBlock:
                return true;
            case ir::Opcode::LoadGuest:
            case ir::Opcode::StoreGuest:
                return operation.width == ir::Width::I8;
            case ir::Opcode::UpdateAddFlags:
            case ir::Opcode::UpdateLogicFlags:
                return true;
            case ir::Opcode::UpdateSubFlags:
                return operation.width == ir::Width::I8 || operation.width == ir::Width::I64;
            default:
                return false;
            }
        });
    std::array<std::size_t, 16> guestRegisterUses{};
    if (internalSelfEdge) {
        for (const auto &operation : block.operations) {
            if (operation.guestRegister &&
                (operation.opcode == ir::Opcode::ReadGuestReg ||
                 operation.opcode == ir::Opcode::WriteGuestReg ||
                 operation.opcode == ir::Opcode::ConditionalMoveGuestReg)) {
                ++guestRegisterUses[static_cast<std::size_t>(*operation.guestRegister)];
            }
        }
    }
    std::array<std::optional<arm64::XRegister>, 16> pinnedGuestRegisters;
    std::array<std::optional<arm64::XRegister>, 7> pinCandidates{
        arm64::x26, arm64::x27, arm64::x28, std::nullopt, std::nullopt, std::nullopt, std::nullopt};
    if (canPinCallerSavedGuestRegisters) {
        pinCandidates[3] = arm64::x5;
        pinCandidates[4] = arm64::x6;
        pinCandidates[5] = arm64::x7;
        pinCandidates[6] = arm64::x30;
    }
    for (const auto candidate : pinCandidates) {
        if (!candidate) {
            continue;
        }
        const auto mostUsed = std::ranges::max_element(guestRegisterUses);
        if (mostUsed == guestRegisterUses.end() || *mostUsed == 0) {
            break;
        }
        const auto index =
            static_cast<std::size_t>(std::distance(guestRegisterUses.begin(), mostUsed));
        pinnedGuestRegisters[index] = *candidate;
        *mostUsed = 0;
    }
    const auto pinnedGuestRegister = [&](x86::Register guestRegister) {
        return pinnedGuestRegisters[static_cast<std::size_t>(guestRegister)];
    };
    const auto nextGuestWrite = [&](std::size_t operationIndex, x86::Register guestRegister) {
        for (auto index = operationIndex + 1; index < block.operations.size(); ++index) {
            const auto &candidate = block.operations[index];
            if (candidate.guestRegister == guestRegister &&
                (candidate.opcode == ir::Opcode::WriteGuestReg ||
                 candidate.opcode == ir::Opcode::ConditionalMoveGuestReg)) {
                return index;
            }
        }
        return block.operations.size();
    };
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        if (!operation.guestRegister) {
            continue;
        }
        const auto pinned = pinnedGuestRegister(*operation.guestRegister);
        if (!pinned) {
            continue;
        }
        if (operation.opcode == ir::Opcode::ReadGuestReg && operation.result) {
            if (emittedLastUses[operation.result->value] <=
                nextGuestWrite(index, *operation.guestRegister)) {
                pinnedValueRegisters[operation.result->value] = *pinned;
            }
            continue;
        }
        if (operation.opcode != ir::Opcode::WriteGuestReg || !operation.lhs ||
            (operation.width != ir::Width::I64 &&
             !isZeroExtendedDefinition(definingOperation(*operation.lhs)))) {
            continue;
        }
        const auto source = *operation.lhs;
        const auto nextWrite = nextGuestWrite(index, *operation.guestRegister);
        if (emittedLastUses[source.value] > nextWrite ||
            (pinnedValueRegisters[source.value] &&
             pinnedValueRegisters[source.value]->encoding != pinned->encoding)) {
            continue;
        }
        const auto definitionIndex = definitionIndices[source.value];
        const auto interferes = [&] {
            for (std::size_t value = 0; value < pinnedValueRegisters.size(); ++value) {
                if (pinnedValueRegisters[value] &&
                    pinnedValueRegisters[value]->encoding == pinned->encoding &&
                    emittedLastUses[value] > definitionIndex) {
                    return true;
                }
            }
            return false;
        }();
        if (!interferes) {
            pinnedValueRegisters[source.value] = *pinned;
        }
    }
    const auto hasPinnedGuestRegisters = std::ranges::any_of(
        pinnedGuestRegisters, [](const auto &value) { return value.has_value(); });
    std::vector<bool> promotesNarrowGuestWrite(block.operations.size());
    std::array<bool, 16> guestRegisterKnownZero{};
    for (std::size_t index = 0; index < block.operations.size(); ++index) {
        const auto &operation = block.operations[index];
        if (operation.opcode == ir::Opcode::WriteGuestReg && operation.guestRegister &&
            operation.lhs) {
            const auto guestIndex = static_cast<std::size_t>(*operation.guestRegister);
            const auto *definition = definingOperation(*operation.lhs);
            if ((operation.width == ir::Width::I32 || operation.width == ir::Width::I64) &&
                definition != nullptr && definition->opcode == ir::Opcode::Constant &&
                definition->immediate == 0) {
                guestRegisterKnownZero[guestIndex] = true;
            } else if (operation.width == ir::Width::I8 && guestRegisterKnownZero[guestIndex] &&
                       definition != nullptr &&
                       definition->opcode == ir::Opcode::EvaluateCondition) {
                promotesNarrowGuestWrite[index] = true;
                guestRegisterKnownZero[guestIndex] = false;
            } else {
                guestRegisterKnownZero[guestIndex] = false;
            }
        } else if (operation.opcode == ir::Opcode::ConditionalMoveGuestReg &&
                   operation.guestRegister) {
            guestRegisterKnownZero[static_cast<std::size_t>(*operation.guestRegister)] = false;
        } else if (operation.opcode == ir::Opcode::Push ||
                   operation.opcode == ir::Opcode::RepeatMoveByte ||
                   operation.opcode == ir::Opcode::DivideUnsignedByte ||
                   operation.opcode == ir::Opcode::DivideUnsignedDword ||
                   operation.opcode == ir::Opcode::DivideUnsignedQword ||
                   operation.opcode == ir::Opcode::DivideSignedDword) {
            guestRegisterKnownZero.fill(false);
        }
    }
    struct DirectReadSpan {
        std::size_t firstLoadOperationIndex{};
        ir::ValueId address;
        ir::ValueId induction;
        std::uint16_t step{};
        std::uint16_t maximumOffset{};
        std::uint64_t limit{};
    };
    std::optional<DirectReadSpan> directReadSpan;
    struct AdjacentDirectRead {
        bool first{};
        std::uint16_t offset{};
        std::uint16_t maximumOffset{};
    };
    std::vector<std::optional<AdjacentDirectRead>> adjacentDirectReads(block.operations.size());
    if (canPinCallerSavedGuestRegisters && pinsDirectRead) {
        struct ReadCandidate {
            std::size_t operationIndex{};
            ir::ValueId root;
            std::uint64_t offset{};
        };
        std::vector<ReadCandidate> candidates;
        for (std::size_t index = 0; index < block.operations.size(); ++index) {
            const auto &operation = block.operations[index];
            if (operation.opcode != ir::Opcode::LoadGuest || operation.width != ir::Width::I8 ||
                !operation.lhs) {
                continue;
            }
            auto root = *operation.lhs;
            std::uint64_t offset{};
            while (const auto *definition = definingOperation(root)) {
                if (definition->opcode != ir::Opcode::Add || definition->width != ir::Width::I64 ||
                    !definition->lhs || !definition->rhs) {
                    break;
                }
                const auto *rhs = definingOperation(*definition->rhs);
                if (rhs == nullptr || rhs->opcode != ir::Opcode::Constant ||
                    rhs->immediate > UINT16_MAX - offset) {
                    break;
                }
                offset += rhs->immediate;
                root = *definition->lhs;
            }
            candidates.push_back(ReadCandidate{index, root, offset});
        }
        for (const auto &first : candidates) {
            if (first.offset != 0) {
                continue;
            }
            std::vector<ReadCandidate> group;
            for (const auto &candidate : candidates) {
                if (candidate.operationIndex >= first.operationIndex &&
                    candidate.root == first.root && candidate.offset <= 0x0FFFU) {
                    group.push_back(candidate);
                }
            }
            if (group.size() < 2) {
                continue;
            }
            const auto lastIndex = group.back().operationIndex;
            const auto keepsScratchRegisters = [&] {
                for (auto index = first.operationIndex + 1; index < lastIndex; ++index) {
                    const auto &operation = block.operations[index];
                    if (operation.opcode == ir::Opcode::LoadGuest &&
                        std::ranges::none_of(group, [&](const auto &member) {
                            return member.operationIndex == index;
                        })) {
                        return false;
                    }
                    if (isAnyFlagUpdate(operation.opcode) &&
                        !isDeadFlagUpdate(block, index, eliminateFusedFlagUpdates) &&
                        !(sinkLogicFlags && logicFlagSinkTarget(block, index)) &&
                        deferredExitUpdate != index) {
                        return false;
                    }
                }
                return true;
            }();
            if (!keepsScratchRegisters) {
                continue;
            }
            const auto maximumOffset = std::ranges::max_element(
                group, {}, [](const auto &candidate) { return candidate.offset; });
            adjacentDirectReads[first.operationIndex] =
                AdjacentDirectRead{true, 0, static_cast<std::uint16_t>(maximumOffset->offset)};
            for (std::size_t memberIndex = 1; memberIndex < group.size(); ++memberIndex) {
                const auto &candidate = group[memberIndex];
                adjacentDirectReads[candidate.operationIndex] =
                    AdjacentDirectRead{false, static_cast<std::uint16_t>(candidate.offset), 0};
            }
            if (deferredExitUpdate) {
                const auto &exit = block.operations.back();
                const auto &update = block.operations[*deferredExitUpdate];
                const auto *limit = update.rhs ? definingOperation(*update.rhs) : nullptr;
                const auto *address = definingOperation(first.root);
                if (exit.opcode == ir::Opcode::ExitBlock &&
                    exit.exitKind == ir::ExitKind::Conditional &&
                    exit.condition == x86::Condition::NotEqual && exit.target &&
                    *exit.target == block.start && update.opcode == ir::Opcode::UpdateSubFlags &&
                    update.width == ir::Width::I64 && limit != nullptr &&
                    limit->opcode == ir::Opcode::Constant && limit->immediate != 0 &&
                    address != nullptr && address->opcode == ir::Opcode::Add &&
                    address->width == ir::Width::I64 && address->lhs && address->rhs) {
                    for (const auto [induction, offset] :
                         {std::pair{*address->lhs, *address->rhs},
                          std::pair{*address->rhs, *address->lhs}}) {
                        const auto *inductionRead = definingOperation(induction);
                        const auto *offsetRead = definingOperation(offset);
                        if (inductionRead == nullptr || offsetRead == nullptr ||
                            inductionRead->opcode != ir::Opcode::ReadGuestReg ||
                            offsetRead->opcode != ir::Opcode::ReadGuestReg ||
                            inductionRead->width != ir::Width::I64 ||
                            offsetRead->width != ir::Width::I64 || !inductionRead->guestRegister ||
                            !offsetRead->guestRegister) {
                            continue;
                        }
                        const auto offsetChanges =
                            std::ranges::any_of(block.operations, [&](const auto &operation) {
                                return operation.guestRegister == offsetRead->guestRegister &&
                                       (operation.opcode == ir::Opcode::WriteGuestReg ||
                                        operation.opcode == ir::Opcode::ConditionalMoveGuestReg);
                            });
                        if (offsetChanges) {
                            continue;
                        }
                        for (auto writeIndex = lastIndex + 1; writeIndex < block.operations.size();
                             ++writeIndex) {
                            const auto &write = block.operations[writeIndex];
                            if (write.opcode != ir::Opcode::WriteGuestReg ||
                                write.guestRegister != inductionRead->guestRegister ||
                                write.width != ir::Width::I64 || !write.lhs ||
                                update.lhs != write.lhs) {
                                continue;
                            }
                            const auto *increment = definingOperation(*write.lhs);
                            if (increment == nullptr || increment->opcode != ir::Opcode::Add ||
                                increment->width != ir::Width::I64 || !increment->lhs ||
                                !increment->rhs) {
                                continue;
                            }
                            const auto stepValue = *increment->lhs == induction   ? increment->rhs
                                                   : *increment->rhs == induction ? increment->lhs
                                                                                  : std::nullopt;
                            const auto *step = stepValue ? definingOperation(*stepValue) : nullptr;
                            if (step == nullptr || step->opcode != ir::Opcode::Constant ||
                                step->immediate == 0 || step->immediate > 0x0FFFU) {
                                continue;
                            }
                            directReadSpan = DirectReadSpan{
                                first.operationIndex,
                                first.root,
                                induction,
                                static_cast<std::uint16_t>(step->immediate),
                                static_cast<std::uint16_t>(maximumOffset->offset),
                                limit->immediate,
                            };
                            break;
                        }
                        if (directReadSpan) {
                            break;
                        }
                    }
                }
            }
            break;
        }
    }
    struct DirectWriteSpan {
        std::size_t storeOperationIndex{};
        ir::ValueId address;
        ir::ValueId addressLhs;
        ir::ValueId addressRhs;
        ir::ValueId induction;
        ir::ValueId offset;
        arm64::XRegister step;
        std::uint64_t limit{};
    };
    std::optional<DirectWriteSpan> directWriteSpan;
    const auto directByteStoreCount =
        std::ranges::count_if(block.operations, [](const auto &operation) {
            return operation.opcode == ir::Opcode::StoreGuest && operation.width == ir::Width::I8;
        });
    if (canPinCallerSavedGuestRegisters && pinsDirectWrite && deferredExitUpdate &&
        directByteStoreCount == 1) {
        const auto &exit = block.operations.back();
        const auto &update = block.operations[*deferredExitUpdate];
        const auto *limit = update.rhs ? definingOperation(*update.rhs) : nullptr;
        for (std::size_t storeIndex = 0; storeIndex < block.operations.size() && !directWriteSpan;
             ++storeIndex) {
            const auto &store = block.operations[storeIndex];
            if (store.opcode != ir::Opcode::StoreGuest || store.width != ir::Width::I8 ||
                !store.lhs) {
                continue;
            }
            const auto *address = definingOperation(*store.lhs);
            if (address == nullptr || address->opcode != ir::Opcode::Add ||
                address->width != ir::Width::I64 || !address->lhs || !address->rhs ||
                exit.opcode != ir::Opcode::ExitBlock ||
                exit.exitKind != ir::ExitKind::Conditional ||
                exit.condition != x86::Condition::Below || !exit.target ||
                *exit.target != block.start || limit == nullptr ||
                limit->opcode != ir::Opcode::Constant || limit->immediate == 0) {
                continue;
            }
            for (const auto [induction, offset] : {std::pair{*address->lhs, *address->rhs},
                                                   std::pair{*address->rhs, *address->lhs}}) {
                const auto *inductionRead = definingOperation(induction);
                const auto *offsetRead = definingOperation(offset);
                if (inductionRead == nullptr || offsetRead == nullptr ||
                    inductionRead->opcode != ir::Opcode::ReadGuestReg ||
                    offsetRead->opcode != ir::Opcode::ReadGuestReg ||
                    inductionRead->width != ir::Width::I64 || offsetRead->width != ir::Width::I64 ||
                    !inductionRead->guestRegister || !offsetRead->guestRegister) {
                    continue;
                }
                const auto offsetChanges =
                    std::ranges::any_of(block.operations, [&](const auto &operation) {
                        return operation.guestRegister == offsetRead->guestRegister &&
                               (operation.opcode == ir::Opcode::WriteGuestReg ||
                                operation.opcode == ir::Opcode::ConditionalMoveGuestReg);
                    });
                if (offsetChanges) {
                    continue;
                }
                for (std::size_t writeIndex = storeIndex + 1; writeIndex < block.operations.size();
                     ++writeIndex) {
                    const auto &write = block.operations[writeIndex];
                    if (write.opcode != ir::Opcode::WriteGuestReg ||
                        write.guestRegister != inductionRead->guestRegister ||
                        write.width != ir::Width::I64 || !write.lhs || update.lhs != write.lhs) {
                        continue;
                    }
                    const auto *increment = definingOperation(*write.lhs);
                    if (increment == nullptr || increment->opcode != ir::Opcode::Add ||
                        increment->width != ir::Width::I64 || !increment->lhs || !increment->rhs) {
                        continue;
                    }
                    const auto stepValue = *increment->lhs == induction   ? increment->rhs
                                           : *increment->rhs == induction ? increment->lhs
                                                                          : std::nullopt;
                    const auto *stepRead = stepValue ? definingOperation(*stepValue) : nullptr;
                    if (stepRead == nullptr || stepRead->opcode != ir::Opcode::ReadGuestReg ||
                        !stepRead->guestRegister) {
                        continue;
                    }
                    const auto step = pinnedGuestRegister(*stepRead->guestRegister);
                    if (!step) {
                        continue;
                    }
                    directWriteSpan =
                        DirectWriteSpan{storeIndex, *store.lhs, *address->lhs, *address->rhs,
                                        induction,  offset,     *step,         limit->immediate};
                    break;
                }
                if (directWriteSpan) {
                    break;
                }
            }
        }
    }
    const auto pinnedDirectCacheOffset = pinsDirectRead
                                             ? offsetof(GuestExecutionContext, directRead)
                                             : offsetof(GuestExecutionContext, directWrite);
    bool hasHelperCall = false;
    bool hasExecutionContextCall = false;
    for (const auto &operation : block.operations) {
        hasHelperCall |=
            operation.opcode == ir::Opcode::UpdateAdcFlags ||
            operation.opcode == ir::Opcode::UpdateSbbFlags ||
            operation.opcode == ir::Opcode::UpdateIncFlags ||
            (operation.opcode == ir::Opcode::UpdateDecFlags && operation.width != ir::Width::I64) ||
            (operation.opcode == ir::Opcode::UpdateSubFlags && operation.width != ir::Width::I8 &&
             operation.width != ir::Width::I64) ||
            operation.opcode == ir::Opcode::UpdateShiftLeftFlags ||
            operation.opcode == ir::Opcode::UpdateShiftRightFlags ||
            operation.opcode == ir::Opcode::UpdateShiftRightArithmeticFlags ||
            operation.opcode == ir::Opcode::UpdateRotateLeftFlags ||
            operation.opcode == ir::Opcode::UpdateRotateRightFlags ||
            operation.opcode == ir::Opcode::UpdateMultiplyFlags ||
            operation.opcode == ir::Opcode::UpdateSignedMultiplyFlags ||
            operation.opcode == ir::Opcode::UpdateShiftRightDoubleFlags ||
            operation.opcode == ir::Opcode::UpdateBitTestFlags ||
            operation.opcode == ir::Opcode::Push ||
            operation.opcode == ir::Opcode::AddGuestMemory ||
            operation.opcode == ir::Opcode::SubGuestMemory ||
            operation.opcode == ir::Opcode::OrGuestMemory ||
            operation.opcode == ir::Opcode::AndGuestMemory ||
            operation.opcode == ir::Opcode::ShiftLeftGuestMemory ||
            operation.opcode == ir::Opcode::ShiftRightGuestMemory ||
            operation.opcode == ir::Opcode::IncrementGuestMemory ||
            operation.opcode == ir::Opcode::DecrementGuestMemory ||
            operation.opcode == ir::Opcode::CompareExchangeGuestMemory ||
            operation.opcode == ir::Opcode::CompareExchangeGuestPair ||
            operation.opcode == ir::Opcode::ExchangeGuestMemory ||
            operation.opcode == ir::Opcode::LockedAddGuestMemory ||
            operation.opcode == ir::Opcode::LockedExchangeAddGuestMemory ||
            operation.opcode == ir::Opcode::LockedIncrementGuestMemory ||
            operation.opcode == ir::Opcode::LockedDecrementGuestMemory ||
            operation.opcode == ir::Opcode::LockedOrGuestMemory ||
            operation.opcode == ir::Opcode::LockedAndGuestMemory ||
            operation.opcode == ir::Opcode::StoreGuestIdtr ||
            operation.opcode == ir::Opcode::StoreGuest ||
            operation.opcode == ir::Opcode::StoreGuestXmm ||
            operation.opcode == ir::Opcode::StoreGuestYmm ||
            operation.opcode == ir::Opcode::LoadGuestXmm ||
            operation.opcode == ir::Opcode::LoadGuestYmm ||
            operation.opcode == ir::Opcode::LoadGuestSignExtendedBytesXmm ||
            operation.opcode == ir::Opcode::LoadGuestSignExtendedDwordsXmm ||
            operation.opcode == ir::Opcode::XorGuestMemoryXmm ||
            operation.opcode == ir::Opcode::AndGuestMemoryXmm ||
            operation.opcode == ir::Opcode::AddGuestMemoryXmm ||
            operation.opcode == ir::Opcode::TestXmmBits ||
            operation.opcode == ir::Opcode::CompareEqualGuestBytesXmm ||
            operation.opcode == ir::Opcode::CompareEqualXmmBytes ||
            operation.opcode == ir::Opcode::CompareEqualXmmDwords ||
            operation.opcode == ir::Opcode::ShiftLeftXmmDwords ||
            operation.opcode == ir::Opcode::AddXmmWords ||
            operation.opcode == ir::Opcode::ComparePackedDoubleXmm ||
            operation.opcode == ir::Opcode::ConvertIntToDoubleXmm ||
            operation.opcode == ir::Opcode::ScalarDoubleXmm ||
            operation.opcode == ir::Opcode::AddXmmDwords ||
            operation.opcode == ir::Opcode::HorizontalAddXmmDwords ||
            operation.opcode == ir::Opcode::AndNotXmm ||
            operation.opcode == ir::Opcode::MoveXmmByteMask ||
            operation.opcode == ir::Opcode::ShuffleXmmBytes ||
            operation.opcode == ir::Opcode::ShuffleXmmDwords ||
            operation.opcode == ir::Opcode::AlignRightXmmBytes ||
            operation.opcode == ir::Opcode::BlendXmmWords ||
            operation.opcode == ir::Opcode::UnpackLowXmmWords ||
            operation.opcode == ir::Opcode::BitScanForward ||
            operation.opcode == ir::Opcode::BitScanReverse ||
            operation.opcode == ir::Opcode::RepeatMoveByte ||
            operation.opcode == ir::Opcode::DivideUnsignedByte ||
            operation.opcode == ir::Opcode::DivideUnsignedDword ||
            operation.opcode == ir::Opcode::DivideUnsignedQword ||
            operation.opcode == ir::Opcode::DivideSignedDword ||
            operation.opcode == ir::Opcode::LoadGuest ||
            operation.opcode == ir::Opcode::ReadTimestampCounter;
        hasExecutionContextCall |=
            operation.opcode == ir::Opcode::Push ||
            operation.opcode == ir::Opcode::DivideUnsignedByte ||
            operation.opcode == ir::Opcode::DivideUnsignedDword ||
            operation.opcode == ir::Opcode::DivideUnsignedQword ||
            operation.opcode == ir::Opcode::DivideSignedDword ||
            operation.opcode == ir::Opcode::AddGuestMemory ||
            operation.opcode == ir::Opcode::SubGuestMemory ||
            operation.opcode == ir::Opcode::OrGuestMemory ||
            operation.opcode == ir::Opcode::AndGuestMemory ||
            operation.opcode == ir::Opcode::ShiftLeftGuestMemory ||
            operation.opcode == ir::Opcode::ShiftRightGuestMemory ||
            operation.opcode == ir::Opcode::IncrementGuestMemory ||
            operation.opcode == ir::Opcode::DecrementGuestMemory ||
            operation.opcode == ir::Opcode::CompareExchangeGuestMemory ||
            operation.opcode == ir::Opcode::CompareExchangeGuestPair ||
            operation.opcode == ir::Opcode::ExchangeGuestMemory ||
            operation.opcode == ir::Opcode::LockedAddGuestMemory ||
            operation.opcode == ir::Opcode::LockedExchangeAddGuestMemory ||
            operation.opcode == ir::Opcode::LockedIncrementGuestMemory ||
            operation.opcode == ir::Opcode::LockedDecrementGuestMemory ||
            operation.opcode == ir::Opcode::LockedOrGuestMemory ||
            operation.opcode == ir::Opcode::LockedAndGuestMemory ||
            operation.opcode == ir::Opcode::StoreGuestIdtr ||
            operation.opcode == ir::Opcode::StoreGuest ||
            operation.opcode == ir::Opcode::StoreGuestXmm ||
            operation.opcode == ir::Opcode::StoreGuestYmm ||
            operation.opcode == ir::Opcode::LoadGuestXmm ||
            operation.opcode == ir::Opcode::LoadGuestYmm ||
            operation.opcode == ir::Opcode::LoadGuestSignExtendedBytesXmm ||
            operation.opcode == ir::Opcode::LoadGuestSignExtendedDwordsXmm ||
            operation.opcode == ir::Opcode::XorGuestMemoryXmm ||
            operation.opcode == ir::Opcode::AndGuestMemoryXmm ||
            operation.opcode == ir::Opcode::AddGuestMemoryXmm ||
            operation.opcode == ir::Opcode::CompareEqualGuestBytesXmm ||
            (operation.opcode == ir::Opcode::ShuffleXmmBytes && operation.lhs.has_value()) ||
            operation.opcode == ir::Opcode::RepeatMoveByte ||
            operation.opcode == ir::Opcode::LoadGuest ||
            operation.opcode == ir::Opcode::ReadTimestampCounter;
    }
    hasExecutionContextCall |= internalSelfEdge;
    if (hasHelperCall) {
        assembler.pushFrameRecord();
    }
    if (hasExecutionContextCall) {
        if (internalSelfEdge) {
            assembler.pushCalleeSaved19Through24();
            if (hasPinnedGuestRegisters) {
                assembler.pushCalleeSaved25Through28();
            }
        } else {
            assembler.pushCalleeSaved19Through22();
        }
        assembler.mov(arm64::x19, arm64::x1);
        if (internalSelfEdge) {
            if (hasPinnedGuestRegisters) {
                assembler.mov(arm64::x25, arm64::x0);
                for (std::size_t index = 0; index < pinnedGuestRegisters.size(); ++index) {
                    if (pinnedGuestRegisters[index]) {
                        assembler.ldr(*pinnedGuestRegisters[index], arm64::x25,
                                      static_cast<std::uint32_t>(
                                          x86::registerOffset(static_cast<x86::Register>(index))));
                    }
                }
            }
            assembler.ldr(arm64::x23, arm64::x19,
                          static_cast<std::uint32_t>(
                              offsetof(GuestExecutionContext, remainingBlockExecutions)));
            if (pinnedLoopConstant) {
                const auto *definition = definingOperation(*pinnedLoopConstant);
                assembler.movImmediate(arm64::x24, definition->width == ir::Width::I32
                                                       ? definition->immediate & UINT32_MAX
                                                       : definition->immediate);
            } else {
                assembler.movImmediate(arm64::x24, block.start.value);
            }
        }
        if (pinsDirectRead || pinsDirectWrite) {
            assembler.ldr(arm64::x20, arm64::x19,
                          static_cast<std::uint32_t>(pinnedDirectCacheOffset +
                                                     offsetof(DirectGuestMemoryCache, bytes)));
            assembler.ldr(arm64::x21, arm64::x19,
                          static_cast<std::uint32_t>(pinnedDirectCacheOffset +
                                                     offsetof(DirectGuestMemoryCache, base)));
            assembler.ldr(arm64::x22, arm64::x19,
                          static_cast<std::uint32_t>(pinnedDirectCacheOffset +
                                                     offsetof(DirectGuestMemoryCache, size)));
        }
        if (directWriteSpan) {
            assembler.movImmediate(arm64::x4, 0);
        }
    }
    const auto repeatedEntry = assembler.makeLabel();
    assembler.bind(repeatedEntry);
    std::optional<arm64::Label> directReadFastEntry;
    std::optional<arm64::Label> directWriteFastEntry;

    const auto emitEpilogue = [&] {
        if (hasExecutionContextCall) {
            if (internalSelfEdge) {
                if (hasPinnedGuestRegisters) {
                    for (std::size_t index = 0; index < pinnedGuestRegisters.size(); ++index) {
                        if (pinnedGuestRegisters[index]) {
                            assembler.str(*pinnedGuestRegisters[index], arm64::x25,
                                          static_cast<std::uint32_t>(x86::registerOffset(
                                              static_cast<x86::Register>(index))));
                        }
                    }
                    assembler.popCalleeSaved25Through28();
                }
                assembler.str(arm64::x23, arm64::x19,
                              static_cast<std::uint32_t>(
                                  offsetof(GuestExecutionContext, remainingBlockExecutions)));
                assembler.popCalleeSaved19Through24();
            } else {
                assembler.popCalleeSaved19Through22();
            }
        }
        if (hasHelperCall) {
            assembler.popFrameRecord();
        }
    };

    const auto emitStopRepeatingCheck = [&](arm64::Label returnToDispatcher) {
        if (!mayStopRepeating) {
            return;
        }
        if (pinsDirectWrite) {
            const auto directMapping = assembler.makeLabel();
            assembler.cbnz(arm64::x20, directMapping);
            assembler.ldr(
                arm64::x1, arm64::x19,
                static_cast<std::uint32_t>(offsetof(GuestExecutionContext, stopRepeating)));
            assembler.cbnz(arm64::x1, returnToDispatcher);
            assembler.bind(directMapping);
            return;
        }
        assembler.ldr(arm64::x1, arm64::x19,
                      static_cast<std::uint32_t>(offsetof(GuestExecutionContext, stopRepeating)));
        assembler.cbnz(arm64::x1, returnToDispatcher);
    };

    const auto emitLogicFlags = [&](arm64::XRegister result, ir::Width width) {
        const auto parityDone = assembler.makeLabel();
        const auto zeroDone = assembler.makeLabel();
        const auto signBit = width == ir::Width::I8    ? 7U
                             : width == ir::Width::I16 ? 15U
                             : width == ir::Width::I32 ? 31U
                                                       : 63U;

        if (width == ir::Width::I64) {
            assembler.mov(arm64::x1, result);
        } else {
            const auto valueMask = width == ir::Width::I8    ? std::uint64_t{UINT8_MAX}
                                   : width == ir::Width::I16 ? std::uint64_t{UINT16_MAX}
                                                             : std::uint64_t{UINT32_MAX};
            assembler.movImmediate(arm64::x17, valueMask);
            assembler.bitAnd(arm64::x1, result, arm64::x17);
        }

        assembler.ldr(arm64::x16, arm64::x0,
                      static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
        assembler.movImmediate(arm64::x17, ~arithmeticFlagMask);
        assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
        assembler.movImmediate(arm64::x17, flagReservedOne);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);

        assembler.mov(arm64::x17, arm64::x1);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 4);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 2);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 1);
        assembler.tbnz(arm64::x17, 0, parityDone);
        assembler.movImmediate(arm64::x17, flagParity);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(parityDone);

        assembler.cbnz(arm64::x1, zeroDone);
        assembler.movImmediate(arm64::x17, flagZero);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(zeroDone);

        assembler.lsrImmediate(arm64::x17, arm64::x1, static_cast<std::uint8_t>(signBit));
        assembler.bitOrShiftedLeft(arm64::x16, arm64::x16, arm64::x17, 7);
        assembler.str(arm64::x16, arm64::x0,
                      static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
    };

    const auto emitSubFlags64 = [&](arm64::XRegister lhs, arm64::XRegister rhs,
                                    arm64::XRegister result) {
        const auto carryDone = assembler.makeLabel();
        const auto parityDone = assembler.makeLabel();
        const auto auxiliaryDone = assembler.makeLabel();
        const auto zeroDone = assembler.makeLabel();
        const auto overflowDone = assembler.makeLabel();

        assembler.ldr(arm64::x16, arm64::x0,
                      static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
        assembler.movImmediate(arm64::x17, ~arithmeticFlagMask);
        assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
        assembler.movImmediate(arm64::x17, flagReservedOne);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);

        assembler.compare(lhs, rhs);
        assembler.bUnsignedHigherOrSame(carryDone);
        assembler.movImmediate(arm64::x17, flagCarry);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(carryDone);

        assembler.mov(arm64::x17, result);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 4);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 2);
        assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 1);
        assembler.tbnz(arm64::x17, 0, parityDone);
        assembler.movImmediate(arm64::x17, flagParity);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(parityDone);

        assembler.bitXor(arm64::x17, lhs, rhs);
        assembler.bitXor(arm64::x17, arm64::x17, result);
        assembler.tbz(arm64::x17, 4, auxiliaryDone);
        assembler.movImmediate(arm64::x17, flagAuxiliaryCarry);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(auxiliaryDone);

        assembler.cbnz(result, zeroDone);
        assembler.movImmediate(arm64::x17, flagZero);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(zeroDone);

        assembler.lsrImmediate(arm64::x17, result, 63);
        assembler.bitOrShiftedLeft(arm64::x16, arm64::x16, arm64::x17, 7);

        assembler.bitXor(arm64::x17, lhs, rhs);
        assembler.bitXor(arm64::x1, lhs, result);
        assembler.bitAnd(arm64::x17, arm64::x17, arm64::x1);
        assembler.tbz(arm64::x17, 63, overflowDone);
        assembler.movImmediate(arm64::x17, flagOverflow);
        assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
        assembler.bind(overflowDone);

        assembler.str(arm64::x16, arm64::x0,
                      static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
    };

    for (std::size_t operationIndex = 0; operationIndex < block.operations.size();
         ++operationIndex) {
        const auto &operation = block.operations[operationIndex];
        if (isDeadFlagUpdate(block, operationIndex, eliminateFusedFlagUpdates)) {
            continue;
        }
        if (sinkLogicFlags && logicFlagSinkTarget(block, operationIndex)) {
            continue;
        }
        if (deferredExitUpdate == operationIndex) {
            continue;
        }
        if (deferredExitResultOperation == operationIndex) {
            continue;
        }
        switch (operation.opcode) {
        case ir::Opcode::Constant:
            if (foldedImmediate[operation.result->value] ||
                (pinnedLoopConstant && *operation.result == *pinnedLoopConstant)) {
                break;
            }
            assembler.movImmediate(hostRegister(*operation.result),
                                   operation.width == ir::Width::I32
                                       ? operation.immediate & UINT32_MAX
                                       : operation.immediate);
            break;
        case ir::Opcode::ReadGuestReg:
            if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                if (hostRegister(*operation.result).encoding == pinned->encoding) {
                    break;
                }
                if (operation.width == ir::Width::I32) {
                    assembler.mov32(hostRegister(*operation.result), *pinned);
                } else {
                    assembler.mov(hostRegister(*operation.result), *pinned);
                }
            } else if (operation.width == ir::Width::I32) {
                assembler.ldr32(
                    hostRegister(*operation.result), arm64::x0,
                    static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
            } else {
                assembler.ldr(
                    hostRegister(*operation.result), arm64::x0,
                    static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
            }
            break;
        case ir::Opcode::ReadGuestGsBase:
            assembler.ldr(hostRegister(*operation.result), arm64::x0,
                          static_cast<std::uint32_t>(offsetof(x86::X86State, gsBase)));
            break;
        case ir::Opcode::ReadGuestXmmLane:
            assembler.ldr(hostRegister(*operation.result), arm64::x0,
                          static_cast<std::uint32_t>(x86::xmmLaneOffset(*operation.guestXmmRegister,
                                                                        operation.immediate != 0)));
            break;
        case ir::Opcode::ReadGuestYmmUpperLane:
            assembler.ldr(hostRegister(*operation.result), arm64::x0,
                          static_cast<std::uint32_t>(x86::ymmUpperLaneOffset(
                              *operation.guestXmmRegister, operation.immediate != 0)));
            break;
        case ir::Opcode::WriteGuestReg: {
            if (promotesNarrowGuestWrite[operationIndex]) {
                if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                    if (hostRegister(*operation.lhs).encoding != pinned->encoding) {
                        assembler.mov(*pinned, hostRegister(*operation.lhs));
                    }
                } else {
                    assembler.str(
                        hostRegister(*operation.lhs), arm64::x0,
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
                }
                break;
            }
            if (operation.width == ir::Width::I8 || operation.width == ir::Width::I16) {
                const auto offset =
                    static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister));
                const auto pinned = pinnedGuestRegister(*operation.guestRegister);
                if (pinned) {
                    assembler.mov(arm64::x16, *pinned);
                } else {
                    assembler.ldr(arm64::x16, arm64::x0, offset);
                }
                const auto valueMask =
                    operation.width == ir::Width::I8 ? std::uint64_t{0xFF} : std::uint64_t{0xFFFF};
                assembler.movImmediate(arm64::x17, ~valueMask);
                assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
                assembler.movImmediate(arm64::x17, valueMask);
                assembler.bitAnd(arm64::x17, hostRegister(*operation.lhs), arm64::x17);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                if (pinned) {
                    assembler.mov(*pinned, arm64::x16);
                } else {
                    assembler.str(arm64::x16, arm64::x0, offset);
                }
            } else if (operation.width == ir::Width::I32) {
                const auto *definition = definingOperation(*operation.lhs);
                const auto alreadyZeroExtended = isZeroExtendedDefinition(definition);
                if (alreadyZeroExtended) {
                    if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                        if (hostRegister(*operation.lhs).encoding != pinned->encoding) {
                            assembler.mov(*pinned, hostRegister(*operation.lhs));
                        }
                    } else {
                        assembler.str(hostRegister(*operation.lhs), arm64::x0,
                                      static_cast<std::uint32_t>(
                                          x86::registerOffset(*operation.guestRegister)));
                    }
                } else if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                    assembler.mov32(*pinned, hostRegister(*operation.lhs));
                } else {
                    assembler.movImmediate(arm64::x16, UINT32_MAX);
                    assembler.bitAnd(arm64::x16, hostRegister(*operation.lhs), arm64::x16);
                    assembler.str(
                        arm64::x16, arm64::x0,
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
                }
            } else {
                if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                    if (hostRegister(*operation.lhs).encoding != pinned->encoding) {
                        assembler.mov(*pinned, hostRegister(*operation.lhs));
                    }
                } else {
                    assembler.str(
                        hostRegister(*operation.lhs), arm64::x0,
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
                }
            }
            break;
        }
        case ir::Opcode::ConditionalMoveGuestReg: {
            if ((operation.width != ir::Width::I32 && operation.width != ir::Width::I64) ||
                (*operation.condition != x86::Condition::Below &&
                 *operation.condition != x86::Condition::BelowOrEqual &&
                 *operation.condition != x86::Condition::AboveOrEqual &&
                 *operation.condition != x86::Condition::Above &&
                 *operation.condition != x86::Condition::Equal &&
                 *operation.condition != x86::Condition::NotEqual &&
                 *operation.condition != x86::Condition::Overflow &&
                 *operation.condition != x86::Condition::NotOverflow &&
                 *operation.condition != x86::Condition::ParityEven &&
                 *operation.condition != x86::Condition::ParityOdd &&
                 *operation.condition != x86::Condition::Sign &&
                 *operation.condition != x86::Condition::NotSign &&
                 *operation.condition != x86::Condition::Less &&
                 *operation.condition != x86::Condition::GreaterOrEqual &&
                 *operation.condition != x86::Condition::LessOrEqual &&
                 *operation.condition != x86::Condition::Greater)) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32- and 64-bit register "
                    "CMOVO/CMOVNO/CMOVP/CMOVNP/CMOVB/CMOVBE/CMOVAE/CMOVE/CMOVNE/CMOVA/CMOVS/CMOVNS/CMOVL/CMOVGE/CMOVLE/CMOVG");
            }
            constexpr std::uint8_t carryFlagBit = 0;
            constexpr std::uint8_t zeroFlagBit = 6;
            constexpr std::uint8_t signFlagBit = 7;
            const auto notTaken = assembler.makeLabel();
            const auto zeroSource = fuseZeroFlagConsumers && consumesOnlyZeroFlag(operation)
                                        ? zeroFlagSourceAt(block, operationIndex)
                                        : std::nullopt;
            if (zeroSource) {
                const auto zeroSourceRegister = hostRegister(zeroSource->value);
                auto compared = zeroSourceRegister;
                if (zeroSource->width != ir::Width::I64) {
                    const auto valueMask =
                        zeroSource->width == ir::Width::I8    ? std::uint64_t{UINT8_MAX}
                        : zeroSource->width == ir::Width::I16 ? std::uint64_t{UINT16_MAX}
                                                              : std::uint64_t{UINT32_MAX};
                    assembler.movImmediate(arm64::x17, valueMask);
                    assembler.bitAnd(arm64::x16, zeroSourceRegister, arm64::x17);
                    compared = arm64::x16;
                }
                assembler.compareZero(compared);

                arm64::XRegister trueValue{};
                if (operation.lhs) {
                    trueValue = hostRegister(*operation.lhs);
                } else {
                    const auto source = static_cast<x86::Register>(operation.immediate);
                    if (const auto pinned = pinnedGuestRegister(source)) {
                        trueValue = *pinned;
                    } else {
                        assembler.ldr(arm64::x17, arm64::x0,
                                      static_cast<std::uint32_t>(x86::registerOffset(source)));
                        trueValue = arm64::x17;
                    }
                }

                const auto destinationPinned = pinnedGuestRegister(*operation.guestRegister);
                arm64::XRegister falseValue{};
                arm64::XRegister destination{};
                if (destinationPinned) {
                    falseValue = *destinationPinned;
                    destination = *destinationPinned;
                } else {
                    assembler.ldr(
                        arm64::x16, arm64::x0,
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
                    falseValue = arm64::x16;
                    destination = arm64::x17;
                }
                const auto condition = *operation.condition == x86::Condition::Equal
                                           ? arm64::BranchCondition::Equal
                                           : arm64::BranchCondition::NotEqual;
                if (operation.width == ir::Width::I32) {
                    assembler.conditionalSelect32(destination, trueValue, falseValue, condition);
                } else {
                    assembler.conditionalSelect(destination, trueValue, falseValue, condition);
                }
                if (!destinationPinned) {
                    assembler.str(
                        destination, arm64::x0,
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
                }
                break;
            }
            if (zeroSource) {
                const auto sourceRegister = hostRegister(zeroSource->value);
                if (zeroSource->width == ir::Width::I64) {
                    assembler.mov(arm64::x16, sourceRegister);
                } else {
                    const auto valueMask =
                        zeroSource->width == ir::Width::I8    ? std::uint64_t{UINT8_MAX}
                        : zeroSource->width == ir::Width::I16 ? std::uint64_t{UINT16_MAX}
                                                              : std::uint64_t{UINT32_MAX};
                    assembler.movImmediate(arm64::x17, valueMask);
                    assembler.bitAnd(arm64::x16, sourceRegister, arm64::x17);
                }
                if (*operation.condition == x86::Condition::Equal) {
                    assembler.cbnz(arm64::x16, notTaken);
                } else {
                    assembler.cbz(arm64::x16, notTaken);
                }
            } else {
                assembler.ldr(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                if (*operation.condition == x86::Condition::Below) {
                    assembler.tbz(arm64::x16, carryFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::BelowOrEqual) {
                    const auto taken = assembler.makeLabel();
                    assembler.tbnz(arm64::x16, carryFlagBit, taken);
                    assembler.tbz(arm64::x16, zeroFlagBit, notTaken);
                    assembler.bind(taken);
                } else if (*operation.condition == x86::Condition::AboveOrEqual) {
                    assembler.tbnz(arm64::x16, carryFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::Equal) {
                    assembler.tbz(arm64::x16, zeroFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::NotEqual) {
                    assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::Sign) {
                    assembler.tbz(arm64::x16, signFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::NotSign) {
                    assembler.tbnz(arm64::x16, signFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::Overflow) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    assembler.tbz(arm64::x16, overflowFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::NotOverflow) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    assembler.tbnz(arm64::x16, overflowFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::ParityEven) {
                    constexpr std::uint8_t parityFlagBit = 2;
                    assembler.tbz(arm64::x16, parityFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::ParityOdd) {
                    constexpr std::uint8_t parityFlagBit = 2;
                    assembler.tbnz(arm64::x16, parityFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::Less) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    assembler.lsrImmediate(arm64::x17, arm64::x16, overflowFlagBit - signFlagBit);
                    assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                    assembler.tbz(arm64::x17, signFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::GreaterOrEqual) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    assembler.lsrImmediate(arm64::x17, arm64::x16, overflowFlagBit - signFlagBit);
                    assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                    assembler.tbnz(arm64::x17, signFlagBit, notTaken);
                } else if (*operation.condition == x86::Condition::LessOrEqual) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    const auto taken = assembler.makeLabel();
                    assembler.tbnz(arm64::x16, zeroFlagBit, taken);
                    assembler.lsrImmediate(arm64::x17, arm64::x16, overflowFlagBit - signFlagBit);
                    assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                    assembler.tbz(arm64::x17, signFlagBit, notTaken);
                    assembler.bind(taken);
                } else if (*operation.condition == x86::Condition::Greater) {
                    constexpr std::uint8_t overflowFlagBit = 11;
                    assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                    assembler.lsrImmediate(arm64::x17, arm64::x16, overflowFlagBit - signFlagBit);
                    assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                    assembler.tbnz(arm64::x17, signFlagBit, notTaken);
                } else {
                    assembler.tbnz(arm64::x16, carryFlagBit, notTaken);
                    assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                }
            }
            if (operation.lhs) {
                assembler.mov(arm64::x17, hostRegister(*operation.lhs));
            } else {
                const auto source = static_cast<x86::Register>(operation.immediate);
                if (const auto pinned = pinnedGuestRegister(source)) {
                    assembler.mov(arm64::x17, *pinned);
                } else {
                    assembler.ldr(arm64::x17, arm64::x0,
                                  static_cast<std::uint32_t>(x86::registerOffset(source)));
                }
            }
            if (operation.width == ir::Width::I32) {
                assembler.mov32(arm64::x17, arm64::x17);
            }
            if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                assembler.mov(*pinned, arm64::x17);
            } else {
                assembler.str(
                    arm64::x17, arm64::x0,
                    static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister)));
            }
            assembler.bind(notTaken);
            if (operation.width == ir::Width::I32) {
                // CMOV r32 performs a 32-bit architectural destination write
                // even when the condition is false, clearing the upper half.
                if (const auto pinned = pinnedGuestRegister(*operation.guestRegister)) {
                    assembler.mov32(*pinned, *pinned);
                } else {
                    const auto destinationOffset =
                        static_cast<std::uint32_t>(x86::registerOffset(*operation.guestRegister));
                    assembler.ldr(arm64::x17, arm64::x0, destinationOffset);
                    assembler.mov32(arm64::x17, arm64::x17);
                    assembler.str(arm64::x17, arm64::x0, destinationOffset);
                }
            }
            break;
        }
        case ir::Opcode::WriteGuestXmmLane:
            assembler.str(hostRegister(*operation.lhs), arm64::x0,
                          static_cast<std::uint32_t>(x86::xmmLaneOffset(*operation.guestXmmRegister,
                                                                        operation.immediate != 0)));
            break;
        case ir::Opcode::WriteGuestYmmUpperLane:
            assembler.str(hostRegister(*operation.lhs), arm64::x0,
                          static_cast<std::uint32_t>(x86::ymmUpperLaneOffset(
                              *operation.guestXmmRegister, operation.immediate != 0)));
            break;
        case ir::Opcode::WriteGuestXmmByte: {
            const auto lane = static_cast<std::uint8_t>(operation.immediate);
            const auto byte = static_cast<std::uint8_t>(lane & 7U);
            const auto shift = static_cast<std::uint8_t>(byte * 8U);
            const auto offset = static_cast<std::uint32_t>(
                x86::xmmLaneOffset(*operation.guestXmmRegister, lane >= 8));
            assembler.ldr(arm64::x16, arm64::x0, offset);
            assembler.movImmediate(arm64::x17, ~(std::uint64_t{0xFF} << shift));
            assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
            assembler.movImmediate(arm64::x17, 0xFF);
            assembler.bitAnd(arm64::x17, hostRegister(*operation.lhs), arm64::x17);
            if (shift != 0) {
                assembler.lslImmediate(arm64::x17, arm64::x17, shift);
            }
            assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
            assembler.str(arm64::x16, arm64::x0, offset);
            break;
        }
        case ir::Opcode::WriteGuestXmmDword: {
            const auto lane = static_cast<std::uint8_t>(operation.immediate);
            const auto offset = static_cast<std::uint32_t>(
                x86::xmmLaneOffset(*operation.guestXmmRegister, lane >= 2));
            assembler.ldr(arm64::x16, arm64::x0, offset);
            assembler.movImmediate(arm64::x17,
                                   (lane & 1U) == 0 ? 0xFFFFFFFF00000000ULL : UINT32_MAX);
            assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
            assembler.movImmediate(arm64::x17, UINT32_MAX);
            assembler.bitAnd(arm64::x17, hostRegister(*operation.lhs), arm64::x17);
            if ((lane & 1U) != 0) {
                assembler.lslImmediate(arm64::x17, arm64::x17, 32);
            }
            assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
            assembler.str(arm64::x16, arm64::x0, offset);
            break;
        }
        case ir::Opcode::Add:
            if (directWriteSpan && operation.result == directWriteSpan->address) {
                break;
            }
            if (operation.rhs && foldedImmediate[operation.rhs->value]) {
                const auto immediate =
                    static_cast<std::uint16_t>(definingOperation(*operation.rhs)->immediate);
                if (operation.width == ir::Width::I32) {
                    assembler.addImmediate32(hostRegister(*operation.result),
                                             hostRegister(*operation.lhs), immediate);
                } else {
                    assembler.addImmediate(hostRegister(*operation.result),
                                           hostRegister(*operation.lhs), immediate);
                }
            } else if (operation.width == ir::Width::I32) {
                assembler.add32(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                hostRegister(*operation.rhs));
            } else {
                assembler.add(hostRegister(*operation.result), hostRegister(*operation.lhs),
                              hostRegister(*operation.rhs));
            }
            break;
        case ir::Opcode::Sub:
            if (operation.rhs && foldedImmediate[operation.rhs->value]) {
                const auto immediate =
                    static_cast<std::uint16_t>(definingOperation(*operation.rhs)->immediate);
                if (operation.width == ir::Width::I32) {
                    assembler.subImmediate32(hostRegister(*operation.result),
                                             hostRegister(*operation.lhs), immediate);
                } else {
                    assembler.subImmediate(hostRegister(*operation.result),
                                           hostRegister(*operation.lhs), immediate);
                }
            } else if (operation.width == ir::Width::I32) {
                assembler.sub32(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                hostRegister(*operation.rhs));
            } else {
                assembler.sub(hostRegister(*operation.result), hostRegister(*operation.lhs),
                              hostRegister(*operation.rhs));
            }
            break;
        case ir::Opcode::ShiftLeft:
            if (operation.rhs) {
                assembler.lslVariable(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                      hostRegister(*operation.rhs));
            } else {
                assembler.lslImmediate(hostRegister(*operation.result),
                                       hostRegister(*operation.lhs),
                                       static_cast<std::uint8_t>(operation.immediate));
            }
            break;
        case ir::Opcode::ShiftRightLogical:
            if (operation.rhs) {
                assembler.lsrVariable(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                      hostRegister(*operation.rhs));
            } else {
                assembler.lsrImmediate(hostRegister(*operation.result),
                                       hostRegister(*operation.lhs),
                                       static_cast<std::uint8_t>(operation.immediate));
            }
            break;
        case ir::Opcode::ShiftRightArithmetic:
            if (operation.rhs) {
                if (operation.width == ir::Width::I32) {
                    assembler.asrVariable32(hostRegister(*operation.result),
                                            hostRegister(*operation.lhs),
                                            hostRegister(*operation.rhs));
                } else {
                    assembler.asrVariable(hostRegister(*operation.result),
                                          hostRegister(*operation.lhs),
                                          hostRegister(*operation.rhs));
                }
            } else if (operation.width == ir::Width::I32) {
                assembler.asrImmediate32(hostRegister(*operation.result),
                                         hostRegister(*operation.lhs),
                                         static_cast<std::uint8_t>(operation.immediate));
            } else {
                assembler.asrImmediate(hostRegister(*operation.result),
                                       hostRegister(*operation.lhs),
                                       static_cast<std::uint8_t>(operation.immediate));
            }
            break;
        case ir::Opcode::MultiplyLow:
            assembler.multiplyLow(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                  hostRegister(*operation.rhs));
            break;
        case ir::Opcode::MultiplyHighUnsigned:
            assembler.multiplyHighUnsigned(hostRegister(*operation.result),
                                           hostRegister(*operation.lhs),
                                           hostRegister(*operation.rhs));
            break;
        case ir::Opcode::MultiplyHighSigned:
            assembler.multiplyHighSigned(hostRegister(*operation.result),
                                         hostRegister(*operation.lhs),
                                         hostRegister(*operation.rhs));
            break;
        case ir::Opcode::ShiftRightDouble:
            assembler.extract(hostRegister(*operation.result), hostRegister(*operation.rhs),
                              hostRegister(*operation.lhs),
                              static_cast<std::uint8_t>(operation.immediate));
            break;
        case ir::Opcode::And:
            if (operation.width == ir::Width::I32) {
                assembler.bitAnd32(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                   hostRegister(*operation.rhs));
            } else {
                assembler.bitAnd(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                 hostRegister(*operation.rhs));
            }
            break;
        case ir::Opcode::Or:
            if (operation.width == ir::Width::I32) {
                assembler.bitOr32(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                  hostRegister(*operation.rhs));
            } else {
                assembler.bitOr(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                hostRegister(*operation.rhs));
            }
            break;
        case ir::Opcode::Xor:
            if (operation.width == ir::Width::I32) {
                assembler.bitXor32(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                   hostRegister(*operation.rhs));
            } else {
                assembler.bitXor(hostRegister(*operation.result), hostRegister(*operation.lhs),
                                 hostRegister(*operation.rhs));
            }
            break;
        case ir::Opcode::SignExtend32:
            assembler.signExtend32(hostRegister(*operation.result), hostRegister(*operation.lhs));
            break;
        case ir::Opcode::ByteSwap:
            if (operation.width == ir::Width::I32) {
                assembler.reverseBytes32(hostRegister(*operation.result),
                                         hostRegister(*operation.lhs));
            } else {
                assembler.reverseBytes64(hostRegister(*operation.result),
                                         hostRegister(*operation.lhs));
            }
            break;
        case ir::Opcode::EvaluateCondition: {
            if (*operation.condition != x86::Condition::Overflow &&
                *operation.condition != x86::Condition::NotOverflow &&
                *operation.condition != x86::Condition::ParityEven &&
                *operation.condition != x86::Condition::ParityOdd &&
                *operation.condition != x86::Condition::Equal &&
                *operation.condition != x86::Condition::NotEqual &&
                *operation.condition != x86::Condition::Below &&
                *operation.condition != x86::Condition::BelowOrEqual &&
                *operation.condition != x86::Condition::Less &&
                *operation.condition != x86::Condition::Greater &&
                *operation.condition != x86::Condition::GreaterOrEqual &&
                *operation.condition != x86::Condition::LessOrEqual &&
                *operation.condition != x86::Condition::AboveOrEqual &&
                *operation.condition != x86::Condition::Above &&
                *operation.condition != x86::Condition::Sign &&
                *operation.condition != x86::Condition::NotSign) {
                throw std::runtime_error("ARM64 backend only implements "
                                          "overflow/not-overflow/parity/parity-odd/equality/below/"
                                          "below-or-equal/less/greater/"
                                          "greater-or-equal/less-or-equal/"
                                          "above-or-equal/above/sign/not-sign condition values");
            }
            constexpr std::uint8_t carryFlagBit = 0;
            constexpr std::uint8_t zeroFlagBit = 6;
            constexpr std::uint8_t signFlagBit = 7;
            constexpr std::uint8_t overflowFlagBit = 11;
            const auto done = assembler.makeLabel();
            const auto satisfied = assembler.makeLabel();
            const auto destination = hostRegister(*operation.result);
            if (fuseZeroFlagConsumers && consumesOnlyZeroFlag(operation)) {
                if (const auto source = zeroFlagSourceAt(block, operationIndex)) {
                    const auto sourceRegister = hostRegister(source->value);
                    auto compared = sourceRegister;
                    if (source->width == ir::Width::I64) {
                        compared = sourceRegister;
                    } else {
                        const auto valueMask =
                            source->width == ir::Width::I8    ? std::uint64_t{UINT8_MAX}
                            : source->width == ir::Width::I16 ? std::uint64_t{UINT16_MAX}
                                                              : std::uint64_t{UINT32_MAX};
                        assembler.movImmediate(arm64::x17, valueMask);
                        assembler.bitAnd(arm64::x16, sourceRegister, arm64::x17);
                        compared = arm64::x16;
                    }
                    assembler.compareZero(compared);
                    assembler.conditionalSet(destination,
                                             *operation.condition == x86::Condition::Equal
                                                 ? arm64::BranchCondition::Equal
                                                 : arm64::BranchCondition::NotEqual);
                    break;
                }
            }
            assembler.movImmediate(destination, 0);
            assembler.ldr(arm64::x16, arm64::x0,
                          static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
            if (*operation.condition == x86::Condition::Overflow) {
                assembler.tbz(arm64::x16, overflowFlagBit, done);
            } else if (*operation.condition == x86::Condition::NotOverflow) {
                assembler.tbnz(arm64::x16, overflowFlagBit, done);
            } else if (*operation.condition == x86::Condition::ParityEven) {
                constexpr std::uint8_t parityFlagBit = 2;
                assembler.tbz(arm64::x16, parityFlagBit, done);
            } else if (*operation.condition == x86::Condition::ParityOdd) {
                constexpr std::uint8_t parityFlagBit = 2;
                assembler.tbnz(arm64::x16, parityFlagBit, done);
            } else if (*operation.condition == x86::Condition::Equal) {
                assembler.tbz(arm64::x16, zeroFlagBit, done);
            } else if (*operation.condition == x86::Condition::NotEqual) {
                assembler.tbnz(arm64::x16, zeroFlagBit, done);
            } else if (*operation.condition == x86::Condition::Below) {
                assembler.tbz(arm64::x16, carryFlagBit, done);
            } else if (*operation.condition == x86::Condition::BelowOrEqual) {
                assembler.tbnz(arm64::x16, carryFlagBit, satisfied);
                assembler.tbz(arm64::x16, zeroFlagBit, done);
            } else if (*operation.condition == x86::Condition::AboveOrEqual) {
                assembler.tbnz(arm64::x16, carryFlagBit, done);
            } else if (*operation.condition == x86::Condition::Above) {
                assembler.tbnz(arm64::x16, carryFlagBit, done);
                assembler.tbnz(arm64::x16, zeroFlagBit, done);
            } else if (*operation.condition == x86::Condition::Sign) {
                assembler.tbz(arm64::x16, signFlagBit, done);
            } else if (*operation.condition == x86::Condition::NotSign) {
                assembler.tbnz(arm64::x16, signFlagBit, done);
            } else if (*operation.condition == x86::Condition::Less) {
                // OF is bit 11; align it with SF at bit 7 and require inequality.
                assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                assembler.tbz(arm64::x17, signFlagBit, done);
            } else if (*operation.condition == x86::Condition::GreaterOrEqual) {
                // OF is bit 11; align it with SF at bit 7 and require equality.
                assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                assembler.tbnz(arm64::x17, signFlagBit, done);
            } else if (*operation.condition == x86::Condition::LessOrEqual) {
                assembler.tbnz(arm64::x16, zeroFlagBit, satisfied);
                // OF is bit 11; align it with SF at bit 7 and require equality.
                assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                assembler.tbz(arm64::x17, signFlagBit, done);
            } else {
                assembler.tbnz(arm64::x16, zeroFlagBit, done);
                // OF is bit 11; align it with SF at bit 7 and require equality.
                assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                assembler.tbnz(arm64::x17, signFlagBit, done);
            }
            assembler.bind(satisfied);
            assembler.movImmediate(destination, 1);
            assembler.bind(done);
            break;
        }
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
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::RepeatMoveByte: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&repeatMoveByte));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::DivideUnsignedByte: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&divideUnsignedByte));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0,
                                   static_cast<std::uint64_t>(BlockExit::ExecutionFault));
            assembler.ret();
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::DivideUnsignedDword: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&divideUnsignedDword));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0,
                                   static_cast<std::uint64_t>(BlockExit::ExecutionFault));
            assembler.ret();
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::DivideSignedDword: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&divideSignedDword));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0,
                                   static_cast<std::uint64_t>(BlockExit::ExecutionFault));
            assembler.ret();
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::DivideUnsignedQword: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&divideUnsignedQword));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0,
                                   static_cast<std::uint64_t>(BlockExit::ExecutionFault));
            assembler.ret();
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::AddGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error("ARM64 backend only implements 8-, 16-, 32-, or 64-bit "
                                         "guest memory add");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&addGuest8)
                                                   : operation.width == ir::Width::I16
                                                         ? pointerBits(&addGuest16)
                                                         : operation.width == ir::Width::I32
                                                               ? pointerBits(&addGuest32)
                                                               : pointerBits(&addGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::SubGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I32 &&
                operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 8-, 32-, or 64-bit guest memory subtract");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&subGuest8)
                                            : operation.width == ir::Width::I32 ? pointerBits(&subGuest32)
                                                                                : pointerBits(&subGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::OrGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 8-, 16-, 32-, or 64-bit guest memory OR");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16,
                                   operation.width == ir::Width::I8    ? pointerBits(&orGuest8)
                                   : operation.width == ir::Width::I16 ? pointerBits(&orGuest16)
                                   : operation.width == ir::Width::I32 ? pointerBits(&orGuest32)
                                                                       : pointerBits(&orGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::AndGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 8-, 16-, 32-, or 64-bit guest memory AND");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16,
                                   operation.width == ir::Width::I8    ? pointerBits(&andGuest8)
                                   : operation.width == ir::Width::I16 ? pointerBits(&andGuest16)
                                   : operation.width == ir::Width::I32 ? pointerBits(&andGuest32)
                                                                       : pointerBits(&andGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::ShiftLeftGuestMemory: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&shiftLeftGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::ShiftRightGuestMemory: {
            if (operation.width != ir::Width::I32 &&
                operation.width != ir::Width::I64) {
                throw std::runtime_error("ARM64 backend only implements 32- and 64-bit "
                                         "guest memory shift right");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&shiftRightGuest32)
                                                   : pointerBits(&shiftRightGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::IncrementGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error("ARM64 backend only implements 8-, 16-, 32-, and 64-bit "
                                         "guest memory increment");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(
                arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&incrementGuest8)
                            : operation.width == ir::Width::I16 ? pointerBits(&incrementGuest16)
                            : operation.width == ir::Width::I32 ? pointerBits(&incrementGuest32)
                                                                : pointerBits(&incrementGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::DecrementGuestMemory: {
            if (operation.width != ir::Width::I8 && operation.width != ir::Width::I16 &&
                operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error("ARM64 backend only implements 8-, 16-, 32-, and 64-bit "
                                         "guest memory decrement");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(
                arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&decrementGuest8)
                             : operation.width == ir::Width::I16 ? pointerBits(&decrementGuest16)
                             : operation.width == ir::Width::I32 ? pointerBits(&decrementGuest32)
                                                                 : pointerBits(&decrementGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::CompareExchangeGuestMemory: {
            if (operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32-bit and 64-bit guest-memory CMPXCHG");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&compareExchangeGuest32)
                                                   : pointerBits(&compareExchangeGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::CompareExchangeGuestPair: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&compareExchangeGuestPair));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::ExchangeGuestMemory: {
            if ((operation.width != ir::Width::I8 && operation.width != ir::Width::I32 &&
                 operation.width != ir::Width::I64) ||
                !operation.guestRegister) {
                throw std::runtime_error(
                    "ARM64 backend only implements 8-bit, 32-bit and 64-bit guest-memory XCHG");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.movImmediate(arm64::x4, static_cast<std::uint64_t>(*operation.guestRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&exchangeGuest8)
                                                   : operation.width == ir::Width::I32
                                                         ? pointerBits(&exchangeGuest32)
                                                         : pointerBits(&exchangeGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedAddGuestMemory: {
            if (operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 64-bit guest-memory LOCK ADD");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&lockedAddGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedExchangeAddGuestMemory: {
            if ((operation.width != ir::Width::I32 && operation.width != ir::Width::I64) ||
                !operation.guestRegister) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32-bit and 64-bit guest-memory LOCK XADD");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.movImmediate(arm64::x4, static_cast<std::uint64_t>(*operation.guestRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&lockedExchangeAddGuest32)
                                                   : pointerBits(&lockedExchangeAddGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedOrGuestMemory: {
            if (operation.width != ir::Width::I16 && operation.width != ir::Width::I32) {
                throw std::runtime_error(
                    "ARM64 backend only implements 16- and 32-bit guest-memory LOCK OR");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I16
                                                   ? pointerBits(&lockedOrGuest16)
                                                   : pointerBits(&lockedOrGuest32));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedAndGuestMemory: {
            if (operation.width != ir::Width::I16) {
                throw std::runtime_error(
                    "ARM64 backend only implements 16-bit guest-memory LOCK AND");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&lockedAndGuest16));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LockedIncrementGuestMemory:
        case ir::Opcode::LockedDecrementGuestMemory: {
            if (operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32- and 64-bit guest-memory LOCK INC/DEC");
            }
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16,
                                   operation.opcode == ir::Opcode::LockedIncrementGuestMemory
                                       ? (operation.width == ir::Width::I32
                                              ? pointerBits(&lockedIncrementGuest32)
                                              : pointerBits(&lockedIncrementGuest64))
                                       : operation.width == ir::Width::I32
                                             ? pointerBits(&lockedDecrementGuest32)
                                             : pointerBits(&lockedDecrementGuest64));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::StoreGuest: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            const auto directByteWrite = pinsDirectWrite && operation.width == ir::Width::I8;
            const auto checkedHelper = assembler.makeLabel();
            const auto directFast = assembler.makeLabel();
            if (directWriteSpan) {
                directWriteFastEntry = directFast;
            }
            if (directByteWrite) {
                assembler.cbnz(directWriteSpan ? arm64::x4 : arm64::x20, directFast);
                assembler.bind(checkedHelper);
            }
            if (directWriteSpan) {
                assembler.add(hostRegister(directWriteSpan->address),
                              hostRegister(directWriteSpan->addressLhs),
                              hostRegister(directWriteSpan->addressRhs));
            }
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x3, hostRegister(*operation.rhs));
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(
                arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&storeGuest8)
                            : operation.width == ir::Width::I16 ? pointerBits(&storeGuest16)
                            : operation.width == ir::Width::I32 ? pointerBits(&storeGuest32)
                                                                : pointerBits(&storeGuest64));
            if (directByteWrite) {
                assembler.pushCallerSaved5Through15();
            }
            assembler.blr(arm64::x16);
            if (directByteWrite) {
                assembler.popCallerSaved5Through15();
            }
            assembler.cbz(arm64::x0, fault);
            if (directByteWrite) {
                assembler.ldr(
                    arm64::x20, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directWrite) +
                                               offsetof(DirectGuestMemoryCache, bytes)));
                assembler.ldr(
                    arm64::x21, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directWrite) +
                                               offsetof(DirectGuestMemoryCache, base)));
                assembler.ldr(
                    arm64::x22, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directWrite) +
                                               offsetof(DirectGuestMemoryCache, size)));
                if (directWriteSpan) {
                    const auto rejected = assembler.makeLabel();
                    const auto guarded = assembler.makeLabel();
                    assembler.cbz(arm64::x20, rejected);
                    assembler.compareZero(directWriteSpan->step);
                    assembler.bConditional(arm64::BranchCondition::Equal, rejected);
                    assembler.movImmediate(arm64::x16, directWriteSpan->limit);
                    assembler.compare(hostRegister(directWriteSpan->induction), arm64::x16);
                    assembler.bUnsignedHigherOrSame(rejected);
                    assembler.movImmediate(arm64::x17, UINT64_MAX - (directWriteSpan->limit - 1));
                    assembler.compare(directWriteSpan->step, arm64::x17);
                    assembler.bConditional(arm64::BranchCondition::UnsignedHigher, rejected);
                    assembler.movImmediate(arm64::x17, directWriteSpan->limit - 1);
                    assembler.add(arm64::x16, hostRegister(directWriteSpan->offset), arm64::x17);
                    assembler.compare(arm64::x16, hostRegister(directWriteSpan->offset));
                    assembler.bConditional(arm64::BranchCondition::UnsignedLower, rejected);
                    assembler.sub(arm64::x17, arm64::x16, arm64::x21);
                    assembler.compare(arm64::x17, arm64::x22);
                    assembler.bUnsignedHigherOrSame(rejected);
                    assembler.sub(arm64::x17, hostRegister(directWriteSpan->address), arm64::x21);
                    assembler.compare(arm64::x17, arm64::x22);
                    assembler.bUnsignedHigherOrSame(rejected);
                    assembler.add(arm64::x3, arm64::x20, arm64::x17);
                    assembler.add(arm64::x3, arm64::x3, directWriteSpan->step);
                    assembler.movImmediate(arm64::x4, 1);
                    assembler.b(guarded);
                    assembler.bind(rejected);
                    assembler.movImmediate(arm64::x4, 0);
                    assembler.bind(guarded);
                }
            }
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            if (directByteWrite) {
                assembler.bind(directFast);
                if (directWriteSpan) {
                    assembler.str8(hostRegister(*operation.rhs), arm64::x3, 0);
                    assembler.add(arm64::x3, arm64::x3, directWriteSpan->step);
                } else {
                    assembler.sub(arm64::x17, hostRegister(*operation.lhs), arm64::x21);
                    assembler.compare(arm64::x17, arm64::x22);
                    assembler.bUnsignedHigherOrSame(checkedHelper);
                    assembler.add(arm64::x16, arm64::x20, arm64::x17);
                    assembler.str8(hostRegister(*operation.rhs), arm64::x16, 0);
                }
            }
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::StoreGuestIdtr: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&storeGuestIdtr));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::StoreGuestXmm: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x4, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&storeGuestXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::StoreGuestYmm: {
            const auto fault = assembler.makeLabel();
            const auto committed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x4, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&storeGuestYmm256));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(committed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(committed);
            break;
        }
        case ir::Opcode::LoadGuestXmm: {
            const auto fault = assembler.makeLabel();
            const auto loaded = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x4, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&loadGuestXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(loaded);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(loaded);
            break;
        }
        case ir::Opcode::LoadGuestYmm: {
            const auto fault = assembler.makeLabel();
            const auto loaded = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x4, operation.immediate);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&loadGuestYmm256));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(loaded);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(loaded);
            break;
        }
        case ir::Opcode::LoadGuestSignExtendedBytesXmm: {
            const auto fault = assembler.makeLabel();
            const auto loaded = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&loadGuestSignExtendedBytesXmm));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(loaded);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(loaded);
            break;
        }
        case ir::Opcode::LoadGuestSignExtendedDwordsXmm: {
            const auto fault = assembler.makeLabel();
            const auto loaded = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&loadGuestSignExtendedDwordsXmm));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(loaded);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(loaded);
            break;
        }
        case ir::Opcode::CompareEqualGuestBytesXmm: {
            const auto fault = assembler.makeLabel();
            const auto compared = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&compareEqualGuestBytesXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(compared);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(compared);
            break;
        }
        case ir::Opcode::XorGuestMemoryXmm: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&xorGuestMemoryXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::AndGuestMemoryXmm: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&andGuestMemoryXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::AddGuestMemoryXmm: {
            const auto fault = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            assembler.mov(arm64::x1, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&addGuestMemoryXmm128));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(completed);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::TestXmmBits:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&testXmmBits128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::CompareEqualXmmBytes:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&compareEqualXmmBytes128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::CompareEqualXmmDwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&compareEqualXmmDwords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ShiftLeftXmmDwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&shiftLeftXmmDwords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::AddXmmWords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&addXmmWords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ComparePackedDoubleXmm:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&comparePackedDoubleXmm));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ConvertIntToDoubleXmm: {
            if (operation.width != ir::Width::I32 && operation.width != ir::Width::I64) {
                throw std::runtime_error(
                    "ARM64 backend only implements 32- and 64-bit integer to double conversion");
            }
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x16,
                                   operation.width == ir::Width::I32
                                       ? pointerBits(&convertInt32ToDoubleXmm)
                                       : pointerBits(&convertInt64ToDoubleXmm));
            assembler.blr(arm64::x16);
            break;
        }
        case ir::Opcode::ScalarDoubleXmm: {
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&scalarDoubleXmm));
            assembler.blr(arm64::x16);
            break;
        }
        case ir::Opcode::AddXmmDwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&addXmmDwords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::HorizontalAddXmmDwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&horizontalAddXmmDwords128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::AndNotXmm:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&andNotXmm128));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::MoveXmmByteMask:
            assembler.movImmediate(arm64::x1, static_cast<std::uint64_t>(*operation.guestRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&moveXmmByteMask32));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ShuffleXmmBytes:
            if (operation.lhs) {
                const auto fault = assembler.makeLabel();
                const auto completed = assembler.makeLabel();
                assembler.mov(arm64::x1, arm64::x0);
                assembler.mov(arm64::x2, hostRegister(*operation.lhs));
                assembler.movImmediate(arm64::x3,
                                       static_cast<std::uint64_t>(*operation.guestXmmRegister));
                assembler.mov(arm64::x0, arm64::x19);
                assembler.movImmediate(arm64::x16, pointerBits(&shuffleGuestMemoryXmmBytes));
                assembler.blr(arm64::x16);
                assembler.cbz(arm64::x0, fault);
                assembler.b(completed);
                assembler.bind(fault);
                emitEpilogue();
                assembler.movImmediate(arm64::x0,
                                       static_cast<std::uint64_t>(BlockExit::MemoryFault));
                assembler.ret();
                assembler.bind(completed);
            } else {
                assembler.movImmediate(arm64::x1,
                                       static_cast<std::uint64_t>(*operation.guestXmmRegister));
                assembler.movImmediate(
                    arm64::x2, static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
                assembler.movImmediate(arm64::x16, pointerBits(&shuffleXmmBytes));
                assembler.blr(arm64::x16);
            }
            break;
        case ir::Opcode::ShuffleXmmDwords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&shuffleXmmDwords));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::AlignRightXmmBytes:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&alignRightXmmBytes));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::BlendXmmWords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&blendXmmWords));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UnpackLowXmmWords:
            assembler.movImmediate(arm64::x1,
                                   static_cast<std::uint64_t>(*operation.guestXmmRegister));
            assembler.movImmediate(arm64::x2,
                                   static_cast<std::uint64_t>(*operation.sourceGuestXmmRegister));
            assembler.movImmediate(arm64::x16, pointerBits(&unpackLowXmmWords));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::BitScanForward:
            assembler.movImmediate(arm64::x1, static_cast<std::uint64_t>(*operation.guestRegister));
            assembler.movImmediate(arm64::x2, operation.immediate);
            assembler.movImmediate(arm64::x3, static_cast<std::uint64_t>(operation.width));
            assembler.movImmediate(arm64::x16, pointerBits(&bitScanForward));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::BitScanReverse:
            assembler.movImmediate(arm64::x1, static_cast<std::uint64_t>(*operation.guestRegister));
            assembler.movImmediate(arm64::x2, operation.immediate);
            assembler.movImmediate(arm64::x3, static_cast<std::uint64_t>(operation.width));
            assembler.movImmediate(arm64::x16, pointerBits(&bitScanReverse));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::LoadGuest: {
            const auto fault = assembler.makeLabel();
            const auto loaded = assembler.makeLabel();
            const auto completed = assembler.makeLabel();
            const auto directByteRead = pinsDirectRead && operation.width == ir::Width::I8;
            const auto checkedHelper = assembler.makeLabel();
            const auto directFast = assembler.makeLabel();
            const auto adjacent = adjacentDirectReads[operationIndex];
            if (directReadSpan && operationIndex == directReadSpan->firstLoadOperationIndex) {
                directReadFastEntry = directFast;
            }
            if (directByteRead) {
                assembler.cbnz(adjacent && !adjacent->first ? arm64::x4 : arm64::x20, directFast);
                assembler.bind(checkedHelper);
                if (sinkLogicFlags) {
                    if (const auto updateIndex = sunkLogicFlagUpdateAt(block, operationIndex)) {
                        const auto &update = block.operations[*updateIndex];
                        emitLogicFlags(hostRegister(*update.lhs), update.width);
                    }
                }
            }
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x2, hostRegister(*operation.lhs));
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16,
                                   operation.width == ir::Width::I8    ? pointerBits(&loadGuest8)
                                   : operation.width == ir::Width::I16 ? pointerBits(&loadGuest16)
                                   : operation.width == ir::Width::I32 ? pointerBits(&loadGuest32)
                                                                       : pointerBits(&loadGuest64));
            if (directByteRead) {
                assembler.pushCallerSaved5Through15();
            }
            assembler.blr(arm64::x16);
            if (directByteRead) {
                assembler.popCallerSaved5Through15();
            }
            assembler.cbz(arm64::x0, fault);
            assembler.b(loaded);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0, static_cast<std::uint64_t>(BlockExit::MemoryFault));
            assembler.ret();
            assembler.bind(loaded);
            assembler.ldr(hostRegister(*operation.result), arm64::x19,
                          static_cast<std::uint32_t>(offsetof(GuestExecutionContext, loadedValue)));
            if (directByteRead) {
                assembler.ldr(
                    arm64::x20, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directRead) +
                                               offsetof(DirectGuestMemoryCache, bytes)));
                assembler.ldr(
                    arm64::x21, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directRead) +
                                               offsetof(DirectGuestMemoryCache, base)));
                assembler.ldr(
                    arm64::x22, arm64::x19,
                    static_cast<std::uint32_t>(offsetof(GuestExecutionContext, directRead) +
                                               offsetof(DirectGuestMemoryCache, size)));
                if (directReadSpan && operationIndex == directReadSpan->firstLoadOperationIndex) {
                    const auto rejected = assembler.makeLabel();
                    const auto guarded = assembler.makeLabel();
                    assembler.pushCallerSaved5Through15();
                    assembler.mov(arm64::x1, hostRegister(directReadSpan->address));
                    assembler.mov(arm64::x2, hostRegister(directReadSpan->induction));
                    assembler.movImmediate(arm64::x3, directReadSpan->step);
                    assembler.movImmediate(arm64::x4, directReadSpan->limit);
                    assembler.movImmediate(arm64::x5, directReadSpan->maximumOffset);
                    assembler.mov(arm64::x0, arm64::x19);
                    assembler.movImmediate(arm64::x16, pointerBits(&validateDirectGuestReadSpan));
                    assembler.blr(arm64::x16);
                    assembler.popCallerSaved5Through15();
                    assembler.mov(arm64::x3, arm64::x0);
                    assembler.mov(arm64::x0, arm64::x25);
                    assembler.cbz(arm64::x3, rejected);
                    assembler.movImmediate(arm64::x4, 1);
                    assembler.b(guarded);
                    assembler.bind(rejected);
                    assembler.movImmediate(arm64::x4, 0);
                    assembler.movImmediate(arm64::x20, 0);
                    assembler.bind(guarded);
                } else if (adjacent) {
                    assembler.movImmediate(arm64::x4, 0);
                }
                assembler.b(completed);
                assembler.bind(directFast);
                if (directReadSpan && operationIndex == directReadSpan->firstLoadOperationIndex) {
                    assembler.ldr8(hostRegister(*operation.result), arm64::x3, 0);
                } else if (adjacent && !adjacent->first) {
                    assembler.ldr8(hostRegister(*operation.result), arm64::x3, adjacent->offset);
                } else {
                    assembler.sub(arm64::x17, hostRegister(*operation.lhs), arm64::x21);
                    if (adjacent) {
                        assembler.addImmediate(arm64::x16, arm64::x17, adjacent->maximumOffset);
                        assembler.compare(arm64::x16, arm64::x22);
                    } else {
                        assembler.compare(arm64::x17, arm64::x22);
                    }
                    assembler.bUnsignedHigherOrSame(checkedHelper);
                    assembler.add(adjacent ? arm64::x3 : arm64::x16, arm64::x20, arm64::x17);
                    assembler.ldr8(hostRegister(*operation.result),
                                   adjacent ? arm64::x3 : arm64::x16, 0);
                    if (adjacent) {
                        assembler.movImmediate(arm64::x4, 1);
                    }
                }
            }
            assembler.bind(completed);
            break;
        }
        case ir::Opcode::LoadFence:
            assembler.dmbIsh();
            assembler.isb();
            break;
        case ir::Opcode::StoreFence:
            assembler.dmbIsh();
            break;
        case ir::Opcode::ReadTimestampCounter: {
            const auto fault = assembler.makeLabel();
            const auto sampled = assembler.makeLabel();
            assembler.mov(arm64::x4, arm64::x0);
            assembler.mov(arm64::x1, arm64::x4);
            assembler.mov(arm64::x0, arm64::x19);
            assembler.movImmediate(arm64::x16, pointerBits(&readTimestampCounter));
            assembler.blr(arm64::x16);
            assembler.cbz(arm64::x0, fault);
            assembler.b(sampled);
            assembler.bind(fault);
            emitEpilogue();
            assembler.movImmediate(arm64::x0,
                                   static_cast<std::uint64_t>(BlockExit::ExecutionFault));
            assembler.ret();
            assembler.bind(sampled);
            break;
        }
        case ir::Opcode::UpdateAddFlags:
        case ir::Opcode::UpdateSubFlags: {
            if (operation.opcode == ir::Opcode::UpdateAddFlags) {
                const auto lhs = hostRegister(*operation.lhs);
                const auto rhs = hostRegister(*operation.rhs);
                const auto result = hostRegister(*operation.third);
                const auto carryDone = assembler.makeLabel();
                const auto parityDone = assembler.makeLabel();
                const auto auxiliaryDone = assembler.makeLabel();
                const auto zeroDone = assembler.makeLabel();
                const auto overflowDone = assembler.makeLabel();
                const auto signBit = operation.width == ir::Width::I8    ? 7U
                                     : operation.width == ir::Width::I16 ? 15U
                                     : operation.width == ir::Width::I32 ? 31U
                                                                         : 63U;

                if (operation.width == ir::Width::I64) {
                    assembler.mov(arm64::x1, lhs);
                    assembler.mov(arm64::x2, rhs);
                    assembler.mov(arm64::x3, result);
                } else {
                    const auto valueMask =
                        operation.width == ir::Width::I8    ? std::uint64_t{UINT8_MAX}
                        : operation.width == ir::Width::I16 ? std::uint64_t{UINT16_MAX}
                                                            : std::uint64_t{UINT32_MAX};
                    assembler.movImmediate(arm64::x17, valueMask);
                    assembler.bitAnd(arm64::x1, lhs, arm64::x17);
                    assembler.bitAnd(arm64::x2, rhs, arm64::x17);
                    assembler.bitAnd(arm64::x3, result, arm64::x17);
                }

                assembler.ldr(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                assembler.movImmediate(arm64::x17, ~arithmeticFlagMask);
                assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
                assembler.movImmediate(arm64::x17, flagReservedOne);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);

                assembler.compare(arm64::x3, arm64::x1);
                assembler.bUnsignedHigherOrSame(carryDone);
                assembler.movImmediate(arm64::x17, flagCarry);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(carryDone);

                assembler.mov(arm64::x17, arm64::x3);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 4);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 2);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 1);
                assembler.tbnz(arm64::x17, 0, parityDone);
                assembler.movImmediate(arm64::x17, flagParity);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(parityDone);

                assembler.bitXor(arm64::x17, arm64::x1, arm64::x2);
                assembler.bitXor(arm64::x17, arm64::x17, arm64::x3);
                assembler.tbz(arm64::x17, 4, auxiliaryDone);
                assembler.movImmediate(arm64::x17, flagAuxiliaryCarry);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(auxiliaryDone);

                assembler.cbnz(arm64::x3, zeroDone);
                assembler.movImmediate(arm64::x17, flagZero);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(zeroDone);

                assembler.lsrImmediate(arm64::x17, arm64::x3, static_cast<std::uint8_t>(signBit));
                assembler.bitOrShiftedLeft(arm64::x16, arm64::x16, arm64::x17, 7);

                assembler.bitXor(arm64::x17, arm64::x1, arm64::x3);
                assembler.bitXor(arm64::x1, arm64::x2, arm64::x3);
                assembler.bitAnd(arm64::x17, arm64::x17, arm64::x1);
                assembler.tbz(arm64::x17, static_cast<std::uint8_t>(signBit), overflowDone);
                assembler.movImmediate(arm64::x17, flagOverflow);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(overflowDone);

                assembler.str(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                break;
            }
            if (operation.opcode == ir::Opcode::UpdateSubFlags &&
                operation.width == ir::Width::I8) {
                const auto lhs = hostRegister(*operation.lhs);
                const auto rhs = hostRegister(*operation.rhs);
                const auto result = hostRegister(*operation.third);
                const auto carryDone = assembler.makeLabel();
                const auto parityDone = assembler.makeLabel();
                const auto auxiliaryDone = assembler.makeLabel();
                const auto zeroDone = assembler.makeLabel();
                const auto overflowDone = assembler.makeLabel();

                // The R1 allocator keeps live IR values in x8...x15, so the
                // ordinary argument registers are available as narrow-value
                // temporaries.  Mask first: byte operations intentionally
                // leave unrelated high bits in their host registers.
                assembler.movImmediate(arm64::x17, UINT8_MAX);
                assembler.bitAnd(arm64::x1, lhs, arm64::x17);
                assembler.bitAnd(arm64::x2, rhs, arm64::x17);
                assembler.bitAnd(arm64::x3, result, arm64::x17);

                assembler.ldr(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                assembler.movImmediate(arm64::x17, ~arithmeticFlagMask);
                assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
                assembler.movImmediate(arm64::x17, flagReservedOne);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);

                assembler.compare(arm64::x1, arm64::x2);
                assembler.bUnsignedHigherOrSame(carryDone);
                assembler.movImmediate(arm64::x17, flagCarry);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(carryDone);

                assembler.mov(arm64::x17, arm64::x3);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 4);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 2);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 1);
                assembler.tbnz(arm64::x17, 0, parityDone);
                assembler.movImmediate(arm64::x17, flagParity);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(parityDone);

                assembler.bitXor(arm64::x17, arm64::x1, arm64::x2);
                assembler.bitXor(arm64::x17, arm64::x17, arm64::x3);
                assembler.tbz(arm64::x17, 4, auxiliaryDone);
                assembler.movImmediate(arm64::x17, flagAuxiliaryCarry);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(auxiliaryDone);

                assembler.cbnz(arm64::x3, zeroDone);
                assembler.movImmediate(arm64::x17, flagZero);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(zeroDone);

                assembler.lsrImmediate(arm64::x17, arm64::x3, 7);
                assembler.bitOrShiftedLeft(arm64::x16, arm64::x16, arm64::x17, 7);

                assembler.bitXor(arm64::x17, arm64::x1, arm64::x2);
                assembler.bitXor(arm64::x1, arm64::x1, arm64::x3);
                assembler.bitAnd(arm64::x17, arm64::x17, arm64::x1);
                assembler.tbz(arm64::x17, 7, overflowDone);
                assembler.movImmediate(arm64::x17, flagOverflow);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(overflowDone);

                assembler.str(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                break;
            }
            if (operation.opcode == ir::Opcode::UpdateSubFlags &&
                operation.width == ir::Width::I64) {
                emitSubFlags64(hostRegister(*operation.lhs), hostRegister(*operation.rhs),
                               hostRegister(*operation.third));
                break;
            }
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.mov(arm64::x3, hostRegister(*operation.third));
            if (operation.opcode == ir::Opcode::UpdateAddFlags) {
                assembler.movImmediate(
                    arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&updateAddFlags8)
                                : operation.width == ir::Width::I16 ? pointerBits(&updateAddFlags16)
                                : operation.width == ir::Width::I32
                                    ? pointerBits(&updateAddFlags32)
                                    : pointerBits(&updateAddFlags64));
            } else {
                assembler.movImmediate(
                    arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&updateSubFlags8)
                                : operation.width == ir::Width::I16 ? pointerBits(&updateSubFlags16)
                                : operation.width == ir::Width::I32
                                    ? pointerBits(&updateSubFlags32)
                                    : pointerBits(&updateSubFlags64));
            }
            assembler.blr(arm64::x16);
            break;
        }
        case ir::Opcode::UpdateAdcFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.mov(arm64::x3, hostRegister(*operation.third));
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&updateAdcFlags8)
                                                   : operation.width == ir::Width::I32
                                                         ? pointerBits(&updateAdcFlags32)
                                                         : pointerBits(&updateAdcFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateSbbFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.mov(arm64::x3, hostRegister(*operation.third));
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&updateSbbFlags8)
                                                   : operation.width == ir::Width::I32
                                                         ? pointerBits(&updateSbbFlags32)
                                                         : pointerBits(&updateSbbFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateIncFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.movImmediate(
                arm64::x16, operation.width == ir::Width::I8    ? pointerBits(&updateIncFlags8)
                             : operation.width == ir::Width::I16 ? pointerBits(&updateIncFlags16)
                             : operation.width == ir::Width::I32 ? pointerBits(&updateIncFlags32)
                                                                 : pointerBits(&updateIncFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateDecFlags:
            if (operation.width == ir::Width::I64) {
                const auto original = hostRegister(*operation.lhs);
                const auto result = hostRegister(*operation.rhs);
                const auto parityDone = assembler.makeLabel();
                const auto auxiliaryDone = assembler.makeLabel();
                const auto zeroDone = assembler.makeLabel();

                assembler.ldr(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                assembler.movImmediate(arm64::x17, ~(arithmeticFlagMask & ~flagCarry));
                assembler.bitAnd(arm64::x16, arm64::x16, arm64::x17);
                assembler.movImmediate(arm64::x17, flagReservedOne);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);

                assembler.mov(arm64::x17, result);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 4);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 2);
                assembler.bitXorShiftedRight(arm64::x17, arm64::x17, arm64::x17, 1);
                assembler.tbnz(arm64::x17, 0, parityDone);
                assembler.movImmediate(arm64::x17, flagParity);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(parityDone);

                assembler.bitXor(arm64::x17, original, result);
                assembler.tbz(arm64::x17, 4, auxiliaryDone);
                assembler.movImmediate(arm64::x17, flagAuxiliaryCarry);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(auxiliaryDone);

                assembler.cbnz(result, zeroDone);
                assembler.movImmediate(arm64::x17, flagZero);
                assembler.bitOr(arm64::x16, arm64::x16, arm64::x17);
                assembler.bind(zeroDone);

                assembler.lsrImmediate(arm64::x17, result, 63);
                assembler.bitOrShiftedLeft(arm64::x16, arm64::x16, arm64::x17, 7);

                assembler.movImmediate(arm64::x17, UINT64_C(1) << 63U);
                assembler.compare(original, arm64::x17);
                assembler.movImmediate(arm64::x17, flagOverflow);
                assembler.bitOr(arm64::x17, arm64::x16, arm64::x17);
                assembler.conditionalSelectEqual(arm64::x16, arm64::x17, arm64::x16);
                assembler.str(arm64::x16, arm64::x0,
                              static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
            } else {
                assembler.mov(arm64::x1, hostRegister(*operation.lhs));
                assembler.mov(arm64::x2, hostRegister(*operation.rhs));
                assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                       ? pointerBits(&updateDecFlags8)
                                                       : operation.width == ir::Width::I16
                                                             ? pointerBits(&updateDecFlags16)
                                                             : pointerBits(&updateDecFlags32));
                assembler.blr(arm64::x16);
            }
            break;
        case ir::Opcode::UpdateLogicFlags:
            emitLogicFlags(hostRegister(*operation.lhs), operation.width);
            break;
        case ir::Opcode::UpdateShiftLeftFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            if (operation.third) {
                assembler.mov(arm64::x3, hostRegister(*operation.third));
            } else {
                assembler.movImmediate(arm64::x3, operation.immediate);
            }
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&updateShiftLeftFlags8)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&updateShiftLeftFlags32)
                                                   : pointerBits(&updateShiftLeftFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateShiftRightFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            if (operation.third) {
                assembler.mov(arm64::x3, hostRegister(*operation.third));
            } else {
                assembler.movImmediate(arm64::x3, operation.immediate);
            }
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I8
                                                   ? pointerBits(&updateShiftRightFlags8)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&updateShiftRightFlags32)
                                                   : pointerBits(&updateShiftRightFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateShiftRightArithmeticFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            if (operation.third) {
                assembler.mov(arm64::x3, hostRegister(*operation.third));
            } else {
                assembler.movImmediate(arm64::x3, operation.immediate);
            }
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&updateShiftRightArithmeticFlags32)
                                                   : pointerBits(&updateShiftRightArithmeticFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateRotateLeftFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            if (operation.rhs) {
                assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            } else {
                assembler.movImmediate(arm64::x2, operation.immediate);
            }
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I16
                                                   ? pointerBits(&updateRotateLeftFlags16)
                                               : operation.width == ir::Width::I32
                                                   ? pointerBits(&updateRotateLeftFlags32)
                                                   : pointerBits(&updateRotateLeftFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateRotateRightFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            if (operation.rhs) {
                assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            } else {
                assembler.movImmediate(arm64::x2, operation.immediate);
            }
            assembler.movImmediate(arm64::x16, pointerBits(&updateRotateRightFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateMultiplyFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x16, pointerBits(&updateMultiplyFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateSignedMultiplyFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I32
                                                   ? pointerBits(&updateSignedMultiplyFlags32)
                                                   : pointerBits(&updateSignedMultiplyFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateShiftRightDoubleFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.mov(arm64::x2, hostRegister(*operation.rhs));
            assembler.movImmediate(arm64::x3, operation.immediate);
            assembler.movImmediate(arm64::x16, pointerBits(&updateShiftRightDoubleFlags64));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::UpdateBitTestFlags:
            assembler.mov(arm64::x1, hostRegister(*operation.lhs));
            assembler.movImmediate(arm64::x2, operation.immediate);
            assembler.movImmediate(arm64::x16, operation.width == ir::Width::I64
                                                   ? pointerBits(&updateBitTestFlags64)
                                                   : pointerBits(&updateBitTestFlags32));
            assembler.blr(arm64::x16);
            break;
        case ir::Opcode::ExitBlock: {
            BlockExit exit = BlockExit::Continue;
            bool emittedInternalConditionalExit = false;
            switch (operation.exitKind) {
            case ir::ExitKind::Return:
                assembler.movImmediate(arm64::x16, operation.guestRip.value);
                exit = BlockExit::Return;
                break;
            case ir::ExitKind::Direct:
                if (operation.lhs) {
                    assembler.mov(arm64::x16, hostRegister(*operation.lhs));
                } else {
                    assembler.movImmediate(arm64::x16, operation.target->value);
                }
                break;
            case ir::ExitKind::Call:
                if (operation.lhs) {
                    assembler.mov(arm64::x16, hostRegister(*operation.lhs));
                } else {
                    assembler.movImmediate(arm64::x16, operation.target->value);
                }
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
                constexpr std::uint8_t carryFlagBit = 0;
                constexpr std::uint8_t signFlagBit = 7;
                constexpr std::uint8_t overflowFlagBit = 11;
                const auto notTaken = assembler.makeLabel();
                const auto taken = assembler.makeLabel();
                const auto selected = assembler.makeLabel();
                if (internalSelfEdge) {
                    assembler.subImmediate(arm64::x23, arm64::x23, 1);
                }
                if (deferredExitUpdate) {
                    const auto &update = block.operations[*deferredExitUpdate];
                    assembler.compare(hostRegister(*update.lhs), hostRegister(*update.rhs));
                    switch (*operation.condition) {
                    case x86::Condition::Overflow:
                        assembler.bConditional(arm64::BranchCondition::NoOverflow, notTaken);
                        break;
                    case x86::Condition::NotOverflow:
                        assembler.bConditional(arm64::BranchCondition::Overflow, notTaken);
                        break;
                    case x86::Condition::ParityEven:
                    case x86::Condition::ParityOdd:
                        // Unreachable: flag deferral is disabled for parity
                        // exits, which always take the flag-test path below.
                        throw std::runtime_error(
                            "ARM64 backend cannot test parity from deferred NZCV");
                    case x86::Condition::Equal:
                        assembler.bConditional(arm64::BranchCondition::NotEqual, notTaken);
                        break;
                    case x86::Condition::NotEqual:
                        assembler.bConditional(arm64::BranchCondition::Equal, notTaken);
                        break;
                    case x86::Condition::Below:
                        assembler.bConditional(arm64::BranchCondition::UnsignedHigherOrSame,
                                               notTaken);
                        break;
                    case x86::Condition::AboveOrEqual:
                        assembler.bConditional(arm64::BranchCondition::UnsignedLower, notTaken);
                        break;
                    case x86::Condition::Above:
                        assembler.bConditional(arm64::BranchCondition::UnsignedLowerOrSame,
                                               notTaken);
                        break;
                    case x86::Condition::BelowOrEqual:
                        assembler.bConditional(arm64::BranchCondition::UnsignedHigher, notTaken);
                        break;
                    case x86::Condition::Sign:
                        assembler.bConditional(arm64::BranchCondition::NonNegative, notTaken);
                        break;
                    case x86::Condition::NotSign:
                        assembler.bConditional(arm64::BranchCondition::Negative, notTaken);
                        break;
                    case x86::Condition::Less:
                        assembler.bConditional(arm64::BranchCondition::SignedGreaterOrEqual,
                                               notTaken);
                        break;
                    case x86::Condition::GreaterOrEqual:
                        assembler.bConditional(arm64::BranchCondition::SignedLess, notTaken);
                        break;
                    case x86::Condition::LessOrEqual:
                        assembler.bConditional(arm64::BranchCondition::SignedGreater, notTaken);
                        break;
                    case x86::Condition::Greater:
                        assembler.bConditional(arm64::BranchCondition::SignedLessOrEqual, notTaken);
                        break;
                    }
                } else {
                    assembler.ldr(arm64::x16, arm64::x0,
                                  static_cast<std::uint32_t>(offsetof(x86::X86State, rflags)));
                    if (*operation.condition == x86::Condition::Overflow) {
                        assembler.tbz(arm64::x16, overflowFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::NotOverflow) {
                        assembler.tbnz(arm64::x16, overflowFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::ParityEven) {
                        constexpr std::uint8_t parityFlagBit = 2;
                        assembler.tbz(arm64::x16, parityFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::ParityOdd) {
                        constexpr std::uint8_t parityFlagBit = 2;
                        assembler.tbnz(arm64::x16, parityFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Equal) {
                        assembler.tbz(arm64::x16, zeroFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::NotEqual) {
                        assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Below) {
                        assembler.tbz(arm64::x16, carryFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::AboveOrEqual) {
                        assembler.tbnz(arm64::x16, carryFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Above) {
                        assembler.tbnz(arm64::x16, carryFlagBit, notTaken);
                        assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::BelowOrEqual) {
                        assembler.tbnz(arm64::x16, carryFlagBit, taken);
                        assembler.tbz(arm64::x16, zeroFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Sign) {
                        assembler.tbz(arm64::x16, signFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::NotSign) {
                        assembler.tbnz(arm64::x16, signFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Less) {
                        // OF is bit 11, so shifting it down by four aligns it with SF.
                        assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                        assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                        assembler.tbz(arm64::x17, signFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::GreaterOrEqual) {
                        // OF is bit 11, so shifting it down by four aligns it with SF.
                        assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                        assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                        assembler.tbnz(arm64::x17, signFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::Greater) {
                        assembler.tbnz(arm64::x16, zeroFlagBit, notTaken);
                        assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                        assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                        assembler.tbnz(arm64::x17, signFlagBit, notTaken);
                    } else if (*operation.condition == x86::Condition::LessOrEqual) {
                        assembler.tbnz(arm64::x16, zeroFlagBit, taken);
                        // OF is bit 11, so shifting it down by four aligns it with SF.
                        assembler.lsrImmediate(arm64::x17, arm64::x16, 4);
                        assembler.bitXor(arm64::x17, arm64::x16, arm64::x17);
                        assembler.tbz(arm64::x17, signFlagBit, notTaken);
                    } else {
                        throw std::runtime_error(
                            "ARM64 backend received unsupported branch condition");
                    }
                }
                if (internalSelfEdge) {
                    const auto returnSelf = assembler.makeLabel();
                    const auto returnSelected = assembler.makeLabel();
                    const auto emitSelfEdge = [&] {
                        assembler.cbz(arm64::x23, returnSelf);
                        if (directWriteFastEntry) {
                            assembler.cbnz(arm64::x4, *directWriteFastEntry);
                        }
                        if (directReadFastEntry) {
                            const auto checkedEntry = assembler.makeLabel();
                            assembler.cbz(arm64::x4, checkedEntry);
                            assembler.addImmediate(arm64::x3, arm64::x3, directReadSpan->step);
                            assembler.b(*directReadFastEntry);
                            assembler.bind(checkedEntry);
                        }
                        emitStopRepeatingCheck(returnSelf);
                        assembler.b(repeatedEntry);
                    };
                    const auto emitSideExit = [&](guest::GuestAddress address) {
                        assembler.movImmediate(arm64::x16, address.value);
                        assembler.b(returnSelected);
                    };

                    assembler.bind(taken);
                    if (*operation.target == block.start) {
                        emitSelfEdge();
                    } else {
                        emitSideExit(*operation.target);
                    }
                    assembler.bind(notTaken);
                    if (*operation.fallthrough == block.start) {
                        emitSelfEdge();
                    } else {
                        emitSideExit(*operation.fallthrough);
                    }
                    assembler.bind(returnSelf);
                    if (pinnedLoopConstant) {
                        assembler.movImmediate(arm64::x16, block.start.value);
                    } else {
                        assembler.mov(arm64::x16, arm64::x24);
                    }
                    assembler.bind(returnSelected);
                    assembler.str(arm64::x16, arm64::x0,
                                  static_cast<std::uint32_t>(offsetof(x86::X86State, rip)));
                    if (deferredExitUpdate) {
                        const auto &update = block.operations[*deferredExitUpdate];
                        if (deferredExitResultOperation) {
                            assembler.sub(hostRegister(*update.third), hostRegister(*update.lhs),
                                          hostRegister(*update.rhs));
                        }
                        emitSubFlags64(hostRegister(*update.lhs), hostRegister(*update.rhs),
                                       hostRegister(*update.third));
                    }
                    emitEpilogue();
                    assembler.movImmediate(arm64::x0,
                                           static_cast<std::uint64_t>(BlockExit::Continue));
                    assembler.ret();
                    emittedInternalConditionalExit = true;
                    break;
                }
                assembler.bind(taken);
                assembler.movImmediate(arm64::x16, operation.target->value);
                assembler.b(selected);
                assembler.bind(notTaken);
                assembler.movImmediate(arm64::x16, operation.fallthrough->value);
                assembler.bind(selected);
                break;
            }
            }
            if (emittedInternalConditionalExit) {
                break;
            }
            assembler.str(arm64::x16, arm64::x0,
                          static_cast<std::uint32_t>(offsetof(x86::X86State, rip)));
            if (internalSelfEdge && exit == BlockExit::Continue) {
                const auto returnToDispatcher = assembler.makeLabel();
                assembler.subImmediate(arm64::x23, arm64::x23, 1);
                assembler.cbz(arm64::x23, returnToDispatcher);
                emitStopRepeatingCheck(returnToDispatcher);
                if (pinnedLoopConstant) {
                    assembler.movImmediate(arm64::x1, block.start.value);
                    assembler.bitXor(arm64::x1, arm64::x16, arm64::x1);
                } else {
                    assembler.bitXor(arm64::x1, arm64::x16, arm64::x24);
                }
                assembler.cbnz(arm64::x1, returnToDispatcher);
                assembler.b(repeatedEntry);
                assembler.bind(returnToDispatcher);
                if (deferredExitUpdate) {
                    const auto &update = block.operations[*deferredExitUpdate];
                    if (deferredExitResultOperation) {
                        assembler.sub(hostRegister(*update.third), hostRegister(*update.lhs),
                                      hostRegister(*update.rhs));
                    }
                    emitSubFlags64(hostRegister(*update.lhs), hostRegister(*update.rhs),
                                   hostRegister(*update.third));
                }
            }
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
                                 arm64::Program program,
                                 std::shared_ptr<arm64::ExecutableArena> executableArena,
                                 std::size_t maximumInstructions,
                                 std::optional<bool> cachedInternalSelfEdge,
                                 std::optional<guest::GuestAddress> cachedCallReturnAddress)
    : decoded_(std::move(decoded)), ir_(std::move(ir)), program_(std::move(program)),
      executable_(std::move(executableArena), program_.bytes) {
    if (decoded_.empty()) {
        throw std::invalid_argument("translated block has no decoded instructions");
    }
    maximumInstructions_ = maximumInstructions;
    lastInstructionAddress_ = decoded_.back().address;
    for (const auto &instruction : decoded_) {
        sourceBytes_.insert(sourceBytes_.end(), instruction.bytes.begin(),
                            instruction.bytes.begin() + instruction.length);
    }
    hasInternalSelfEdge_ = cachedInternalSelfEdge.value_or(::rosa::dbt::hasInternalSelfEdge(ir_));
    optimizationCandidate_ = llvmBackendAvailable() && canCompileOptimizedLoop(ir_);
    if (optimizationCandidate_ && optimizedLoopUsesMemory(ir_)) {
        optimizationWarmupExecutions_ = optimizedMemoryLoopWarmupExecutions;
    }
    for (const auto &operation : ir_.operations) {
        if (operation.opcode == ir::Opcode::ExitBlock && operation.exitKind == ir::ExitKind::Call) {
            callReturnAddress_ = operation.fallthrough;
        }
    }
    if (cachedCallReturnAddress) {
        callReturnAddress_ = cachedCallReturnAddress;
    }
}

TranslatedBlock::TranslatedBlock(std::vector<std::uint8_t> sourceBytes, guest::GuestAddress start,
                                 guest::GuestAddress lastInstructionAddress,
                                 std::size_t maximumInstructions, arm64::Program program,
                                 arm64::ExecutableCode executable, bool cachedInternalSelfEdge,
                                 std::optional<guest::GuestAddress> cachedCallReturnAddress)
    : sourceBytes_(std::move(sourceBytes)), lastInstructionAddress_(lastInstructionAddress),
      maximumInstructions_(maximumInstructions), ir_(ir::Block{.start = start}),
      program_(std::move(program)), executable_(std::move(executable)),
      callReturnAddress_(cachedCallReturnAddress), hasInternalSelfEdge_(cachedInternalSelfEdge) {
    // Persistent entries intentionally omit IR. A self edge is a cheap
    // over-approximation: rebuild IR only after that block becomes hot, then
    // let the optimizing tier perform its full structural check once.
    optimizationCandidate_ = llvmBackendAvailable() && hasInternalSelfEdge_;
}

const std::vector<x86::DecodedInstruction> &TranslatedBlock::decoded() const {
    if (decoded_.empty()) {
        decoded_ = x86::Decoder{}.decodeBlock(sourceBytes_, ir_.start, maximumInstructions_);
    }
    return decoded_;
}

void TranslatedBlock::promoteOptimizedLoopIfHot(std::size_t remainingBudget) {
    if (optimizationCandidate_ && optimizedLoop_ == nullptr &&
        executionCount_ >= optimizationWarmupExecutions_ &&
        remainingBudget >= optimizedLoopMinimumRemainingExecutions) {
        if (ir_.operations.empty()) {
            decoded_ = x86::Decoder{}.decodeBlock(sourceBytes_, ir_.start, maximumInstructions_);
            ir_ = lowerToIr(decoded_);
            forwardFullWidthGuestReads(ir_, ::rosa::dbt::hasInternalSelfEdge(ir_));
        }
        if (!canCompileOptimizedLoop(ir_)) {
            optimizationCandidate_ = false;
            return;
        }
        if (optimizedLoopUsesMemory(ir_)) {
            optimizationWarmupExecutions_ = optimizedMemoryLoopWarmupExecutions;
            if (executionCount_ < optimizationWarmupExecutions_) {
                return;
            }
        }
        optimizedLoop_ = compileOptimizedLoop(ir_);
        optimizationCandidate_ = optimizedLoop_ != nullptr;
    }
}

std::size_t TranslatedBlock::executionBatchLimit(std::size_t requested) const noexcept {
    if (!optimizationCandidate_ || optimizedLoop_ != nullptr ||
        executionCount_ >= optimizationWarmupExecutions_) {
        return requested;
    }
    const auto remainingWarmup = optimizationWarmupExecutions_ - executionCount_;
    return requested < remainingWarmup ? requested : remainingWarmup;
}

BlockExit TranslatedBlock::execute(x86::X86State &state, guest::AddressSpace *addressSpace,
                                   TimestampCounterReader timestampCounterReader) const {
    if (optimizedLoop_ != nullptr) {
        const auto executionCount = optimizedLoop_->execute(state, addressSpace, 1);
        if (executionCount && *executionCount != 1) {
            throw std::runtime_error("optimized loop executed an invalid number of blocks");
        }
        if (executionCount) {
            return BlockExit::Continue;
        }
    }
    GuestExecutionContext context{
        .addressSpace = addressSpace,
        .timestampCounterReader = timestampCounterReader,
    };
    using Entry = std::uint64_t (*)(x86::X86State *, GuestExecutionContext *);
    const auto rawExit = executable_.entry<Entry>()(&state, &context);
    if (context.fault) {
        std::rethrow_exception(context.fault.take());
    }
    if (rawExit > static_cast<std::uint64_t>(BlockExit::ExecutionFault)) {
        throw std::runtime_error("generated block returned an invalid exit reason");
    }
    if (rawExit == static_cast<std::uint64_t>(BlockExit::MemoryFault) ||
        rawExit == static_cast<std::uint64_t>(BlockExit::ExecutionFault)) {
        throw std::runtime_error("generated block reported a guest-memory fault");
    }
    return static_cast<BlockExit>(rawExit);
}

BlockExecutionResult TranslatedBlock::executeRepeated(x86::X86State &state,
                                                      guest::AddressSpace &addressSpace,
                                                      TimestampCounterReader timestampCounterReader,
                                                      std::size_t maximumExecutions) const {
    if (maximumExecutions == 0) {
        throw std::invalid_argument("repeated block execution requires a nonzero limit");
    }
    if (optimizedLoop_ != nullptr) {
        const auto executionCount =
            optimizedLoop_->execute(state, &addressSpace, maximumExecutions);
        if (executionCount && (*executionCount == 0 || *executionCount > maximumExecutions)) {
            throw std::runtime_error("optimized loop executed an invalid number of blocks");
        }
        if (executionCount) {
            return BlockExecutionResult{BlockExit::Continue, *executionCount};
        }
    }
    if (!hasInternalSelfEdge_) {
        return BlockExecutionResult{execute(state, &addressSpace, timestampCounterReader), 1};
    }

    GuestExecutionContext context{
        .addressSpace = &addressSpace,
        .timestampCounterReader = timestampCounterReader,
        .remainingBlockExecutions = maximumExecutions,
        .directMemoryEnabled = true,
    };
    using Entry = std::uint64_t (*)(x86::X86State *, GuestExecutionContext *);
    const auto entry = executable_.entry<Entry>();
    const auto rawExit = entry(&state, &context);
    const auto executionCount = maximumExecutions - context.remainingBlockExecutions;

    if (context.fault) {
        std::rethrow_exception(context.fault.take());
    }
    if (rawExit > static_cast<std::uint64_t>(BlockExit::ExecutionFault)) {
        throw std::runtime_error("generated block returned an invalid exit reason");
    }
    if (rawExit == static_cast<std::uint64_t>(BlockExit::MemoryFault) ||
        rawExit == static_cast<std::uint64_t>(BlockExit::ExecutionFault)) {
        throw std::runtime_error("generated block reported a guest-memory fault");
    }
    return BlockExecutionResult{static_cast<BlockExit>(rawExit), executionCount};
}

TranslatedBlock Translator::translate(std::span<const std::uint8_t> code, guest::GuestAddress start,
                                      std::size_t maximumInstructions) const {
    auto decoded = decoder_.decodeBlock(code, start, maximumInstructions);
    auto intermediate = lowerToIr(decoded);
    forwardFullWidthGuestReads(intermediate, hasInternalSelfEdge(intermediate));
    auto program = compileToArm64(intermediate, retainProgramListing_);
    return TranslatedBlock(std::move(decoded), std::move(intermediate), std::move(program),
                           executableArena_, maximumInstructions);
}

TranslatedBlock Translator::loadCached(std::vector<std::uint8_t> sourceBytes,
                                       guest::GuestAddress start,
                                       guest::GuestAddress lastInstructionAddress,
                                       std::size_t maximumInstructions, arm64::Program program,
                                       arm64::ExecutableCode executable, bool internalSelfEdge,
                                       std::optional<guest::GuestAddress> callReturnAddress) const {
    return TranslatedBlock(std::move(sourceBytes), start, lastInstructionAddress,
                           maximumInstructions, std::move(program), std::move(executable),
                           internalSelfEdge, callReturnAddress);
}

std::uint64_t translationHelperAnchor() noexcept {
    auto pointer = &updateLogicFlags8;
    std::uint64_t result{};
    static_assert(sizeof(pointer) == sizeof(result));
    std::memcpy(&result, &pointer, sizeof(result));
    return result;
}

std::uint64_t translationCacheBuildFingerprint() noexcept {
    constexpr std::string_view buildStamp = __DATE__ " " __TIME__;
    std::uint64_t hash = UINT64_C(1469598103934665603);
    for (const auto character : buildStamp) {
        hash ^= static_cast<std::uint8_t>(character);
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

} // namespace rosa::dbt
