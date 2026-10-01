#include "dbt/RuntimeHelpers.h"
#include "x86/Flags.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <span>
#include <stdexcept>

namespace rosa::dbt::runtime {
using namespace x86;

[[nodiscard]] static std::uint8_t *directGuestRead(GuestExecutionContext *context, std::uint64_t address) {
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

[[nodiscard]] static std::uint8_t *directGuestWrite(GuestExecutionContext *context,
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
compareEqualGuestQwordsXmm128(GuestExecutionContext *context, x86::X86State *state,
                              std::uint64_t address, std::uint64_t registerIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated PCMPEQQ has no address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated PCMPEQQ has an invalid register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        std::uint64_t sourceLow = 0;
        std::uint64_t sourceHigh = 0;
        std::memcpy(&sourceLow, bytes.data(), sizeof(sourceLow));
        std::memcpy(&sourceHigh, bytes.data() + sizeof(sourceLow), sizeof(sourceHigh));
        const auto original = state->xmm[registerIndex];
        state->xmm[registerIndex] = {
            .low = original.low == sourceLow ? UINT64_MAX : 0,
            .high = original.high == sourceHigh ? UINT64_MAX : 0,
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
arithmeticGuestMemoryPackedDoubleXmm128(GuestExecutionContext *context, x86::X86State *state,
                                        std::uint64_t address,
                                        std::uint64_t registerIndex,
                                        std::uint64_t operation) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated packed-double arithmetic has no address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated packed-double arithmetic has an invalid register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        std::uint64_t sourceLow = 0;
        std::uint64_t sourceHigh = 0;
        std::memcpy(&sourceLow, bytes.data(), sizeof(sourceLow));
        std::memcpy(&sourceHigh, bytes.data() + sizeof(sourceLow), sizeof(sourceHigh));
        // Host IEEE-754 arithmetic matches the guest default MXCSR behavior
        // (round to nearest, no denormal flushing on either side).
        const auto original = state->xmm[registerIndex];
        const auto lane = [operation](std::uint64_t destinationBits,
                                      std::uint64_t sourceBits) {
            const auto destinationValue = std::bit_cast<double>(destinationBits);
            const auto sourceValue = std::bit_cast<double>(sourceBits);
            const auto result = operation == 0U   ? destinationValue + sourceValue
                                : operation == 1U ? destinationValue - sourceValue
                                : operation == 2U ? destinationValue * sourceValue
                                : operation == 3U ? destinationValue / sourceValue
                                                  : std::sqrt(sourceValue);
            return std::bit_cast<std::uint64_t>(result);
        };
        state->xmm[registerIndex] = {
            .low = lane(original.low, sourceLow),
            .high = lane(original.high, sourceHigh),
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
unpackLowGuestPackedSingleXmm128(GuestExecutionContext *context, x86::X86State *state,
                                 std::uint64_t address,
                                 std::uint64_t registerIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated UNPCKLPS has no address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated UNPCKLPS has an invalid register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        std::uint64_t sourceLow = 0;
        std::memcpy(&sourceLow, bytes.data(), sizeof(sourceLow));
        const auto original = state->xmm[registerIndex];
        const auto destDword0 = static_cast<std::uint32_t>(original.low);
        const auto destDword1 = static_cast<std::uint32_t>(original.low >> 32U);
        const auto srcDword0 = static_cast<std::uint32_t>(sourceLow);
        const auto srcDword1 = static_cast<std::uint32_t>(sourceLow >> 32U);
        state->xmm[registerIndex] = {
            .low = static_cast<std::uint64_t>(destDword0) |
                   (static_cast<std::uint64_t>(srcDword0) << 32U),
            .high = static_cast<std::uint64_t>(destDword1) |
                    (static_cast<std::uint64_t>(srcDword1) << 32U),
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
horizontalAddGuestPackedDoubleXmm128(GuestExecutionContext *context, x86::X86State *state,
                                     std::uint64_t address,
                                     std::uint64_t registerIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated HADDPD has no address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated HADDPD has an invalid register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        std::uint64_t sourceLow = 0;
        std::uint64_t sourceHigh = 0;
        std::memcpy(&sourceLow, bytes.data(), sizeof(sourceLow));
        std::memcpy(&sourceHigh, bytes.data() + sizeof(sourceLow), sizeof(sourceHigh));
        // Host IEEE-754 arithmetic matches the guest default MXCSR behavior
        // (round to nearest, no denormal flushing on either side).
        const auto original = state->xmm[registerIndex];
        state->xmm[registerIndex] = {
            .low = std::bit_cast<std::uint64_t>(std::bit_cast<double>(original.low) +
                                                std::bit_cast<double>(original.high)),
            .high = std::bit_cast<std::uint64_t>(std::bit_cast<double>(sourceLow) +
                                                 std::bit_cast<double>(sourceHigh)),
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
unpackHighGuestPackedSingleXmm128(GuestExecutionContext *context, x86::X86State *state,
                                  std::uint64_t address,
                                  std::uint64_t registerIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated UNPCKHPS has no address space");
        }
        if (registerIndex >= state->xmm.size()) {
            throw std::runtime_error("generated UNPCKHPS has an invalid register");
        }
        const auto bytes = context->addressSpace->readBytes(guest::GuestAddress{address}, 16);
        std::uint64_t sourceHigh = 0;
        std::memcpy(&sourceHigh, bytes.data() + sizeof(sourceHigh), sizeof(sourceHigh));
        const auto original = state->xmm[registerIndex];
        const auto destDword2 = static_cast<std::uint32_t>(original.high);
        const auto destDword3 = static_cast<std::uint32_t>(original.high >> 32U);
        const auto srcDword2 = static_cast<std::uint32_t>(sourceHigh);
        const auto srcDword3 = static_cast<std::uint32_t>(sourceHigh >> 32U);
        state->xmm[registerIndex] = {
            .low = static_cast<std::uint64_t>(destDword2) |
                   (static_cast<std::uint64_t>(srcDword2) << 32U),
            .high = static_cast<std::uint64_t>(destDword3) |
                    (static_cast<std::uint64_t>(srcDword3) << 32U),
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
convertDoubleToInt64(x86::X86State *state, std::uint64_t destinationIndex,
                     std::uint64_t doubleBits) noexcept {
    if (destinationIndex > static_cast<std::uint64_t>(x86::Register::R15)) {
        return state;
    }
    // Truncation toward zero matches CVTTSD2SI; out-of-range inputs
    // produce the integer-indefinite value. The range checks make the
    // host cast well-defined.
    const auto value = std::bit_cast<double>(doubleBits);
    std::int64_t result = std::numeric_limits<std::int64_t>::min();
    if (!std::isnan(value) && value < 9.223372036854776e18 &&
        value >= -9.223372036854776e18) {
        result = static_cast<std::int64_t>(value);
    }
    const auto destination = static_cast<x86::Register>(destinationIndex);
    std::memcpy(reinterpret_cast<std::uint8_t *>(state) + x86::registerOffset(destination),
                &result, sizeof(result));
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
convertDoubleToInt32(x86::X86State *state, std::uint64_t destinationIndex,
                     std::uint64_t doubleBits) noexcept {
    if (destinationIndex > static_cast<std::uint64_t>(x86::Register::R15)) {
        return state;
    }
    const auto value = std::bit_cast<double>(doubleBits);
    std::int32_t result = std::numeric_limits<std::int32_t>::min();
    if (!std::isnan(value) && value < 2147483648.0 && value >= -2147483648.0) {
        result = static_cast<std::int32_t>(value);
    }
    // A 32-bit destination zero-extends into the full register.
    const auto zeroExtended = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
    const auto destination = static_cast<x86::Register>(destinationIndex);
    std::memcpy(reinterpret_cast<std::uint8_t *>(state) + x86::registerOffset(destination),
                &zeroExtended, sizeof(zeroExtended));
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
convertFloatToDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                        std::uint64_t floatBits) noexcept {
    if (destinationIndex >= state->xmm.size()) {
        return state;
    }
    // float-to-double is always exact; the host conversion matches the
    // guest default MXCSR rounding mode (round to nearest).
    const auto bits = std::bit_cast<std::uint64_t>(
        static_cast<double>(std::bit_cast<float>(
            static_cast<std::uint32_t>(floatBits))));
    state->xmm[destinationIndex] = {.low = bits, .high = 0};
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
convertInt32x2ToDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                          std::uint64_t lowBits) noexcept {
    if (destinationIndex >= state->xmm.size()) {
        return state;
    }
    // Both int32 lanes are always exactly representable as doubles.
    const auto low = std::bit_cast<std::uint64_t>(
        static_cast<double>(static_cast<std::int32_t>(lowBits)));
    const auto high = std::bit_cast<std::uint64_t>(
        static_cast<double>(static_cast<std::int32_t>(lowBits >> 32U)));
    state->xmm[destinationIndex] = {.low = low, .high = high};
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
    // MINSD/MAXSD write the source when either input is NaN or the
    // values compare equal (which folds -0.0/+0.0 to the source lane).
    const auto result = operation == 0U   ? destination + source
                        : operation == 1U ? destination - source
                        : operation == 2U ? destination * source
                        : operation == 3U ? destination / source
                        : operation == 4U ? std::sqrt(source)
                        : operation == 5U ? (std::isnan(destination) || std::isnan(source) ||
                                             destination == source
                                                 ? source
                                                 : std::min(destination, source))
                                          : (std::isnan(destination) || std::isnan(source) ||
                                             destination == source
                                                 ? source
                                                 : std::max(destination, source));
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
arithmeticPackedDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                          std::uint64_t sourceIndex, std::uint64_t operation) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    // Host IEEE-754 arithmetic matches the guest default MXCSR behavior
    // (round to nearest, no denormal flushing on either side).
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    const auto lane = [operation](std::uint64_t destinationBits, std::uint64_t sourceBits) {
        const auto destinationValue = std::bit_cast<double>(destinationBits);
        const auto sourceValue = std::bit_cast<double>(sourceBits);
        const auto result = operation == 0U   ? destinationValue + sourceValue
                            : operation == 1U ? destinationValue - sourceValue
                            : operation == 2U ? destinationValue * sourceValue
                            : operation == 3U ? destinationValue / sourceValue
                                              : std::sqrt(sourceValue);
        return std::bit_cast<std::uint64_t>(result);
    };
    state->xmm[destinationIndex] = {
        .low = lane(destination.low, source.low),
        .high = lane(destination.high, source.high),
    };
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
unpackLowPackedSingleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                         std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    // Copies first: interleaving is well-defined when both operands alias.
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    const auto destDword0 = static_cast<std::uint32_t>(destination.low);
    const auto destDword1 = static_cast<std::uint32_t>(destination.low >> 32U);
    const auto srcDword0 = static_cast<std::uint32_t>(source.low);
    const auto srcDword1 = static_cast<std::uint32_t>(source.low >> 32U);
    state->xmm[destinationIndex] = {
        .low = static_cast<std::uint64_t>(destDword0) |
               (static_cast<std::uint64_t>(srcDword0) << 32U),
        .high = static_cast<std::uint64_t>(destDword1) |
                (static_cast<std::uint64_t>(srcDword1) << 32U),
    };
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
horizontalAddPackedDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                             std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    // Host IEEE-754 arithmetic matches the guest default MXCSR behavior
    // (round to nearest, no denormal flushing on either side).
    // Copies first: the sum is well-defined when both operands alias.
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    state->xmm[destinationIndex] = {
        .low = std::bit_cast<std::uint64_t>(std::bit_cast<double>(destination.low) +
                                            std::bit_cast<double>(destination.high)),
        .high = std::bit_cast<std::uint64_t>(std::bit_cast<double>(source.low) +
                                             std::bit_cast<double>(source.high)),
    };
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
unpackHighPackedSingleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                          std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    // Copies first: interleaving is well-defined when both operands alias.
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    const auto destDword2 = static_cast<std::uint32_t>(destination.high);
    const auto destDword3 = static_cast<std::uint32_t>(destination.high >> 32U);
    const auto srcDword2 = static_cast<std::uint32_t>(source.high);
    const auto srcDword3 = static_cast<std::uint32_t>(source.high >> 32U);
    state->xmm[destinationIndex] = {
        .low = static_cast<std::uint64_t>(destDword2) |
               (static_cast<std::uint64_t>(srcDword2) << 32U),
        .high = static_cast<std::uint64_t>(destDword3) |
                (static_cast<std::uint64_t>(srcDword3) << 32U),
    };
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateUnorderedDoubleFlags(x86::X86State *state, std::uint64_t destinationBits,
                           std::uint64_t sourceBits) noexcept {
    const auto destination = std::bit_cast<double>(destinationBits);
    const auto source = std::bit_cast<double>(sourceBits);
    // UCOMISD zeroes OF, SF and AF; CF/PF/ZF follow the ordered result,
    // and an unordered (NaN) comparison sets ZF, PF and CF together.
    // Host IEEE-754 comparison matches exactly (MXCSR exception flags aside).
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (std::isnan(destination) || std::isnan(source)) {
        flags |= flagCarry | flagParity | flagZero;
    } else if (destination < source) {
        flags |= flagCarry;
    } else if (destination == source) {
        // Equal, including -0.0 against +0.0. Greater-than
        // leaves CF/PF/ZF all clear.
        flags |= flagZero;
    }
    state->rflags = flags;
    return state;
}

extern "C" __attribute__((noinline)) x86::X86State *
updateUnorderedFloatFlags(x86::X86State *state, std::uint64_t destinationBits,
                          std::uint64_t sourceBits) noexcept {
    const auto destination = std::bit_cast<float>(
        static_cast<std::uint32_t>(destinationBits));
    const auto source = std::bit_cast<float>(static_cast<std::uint32_t>(sourceBits));
    // UCOMISS zeroes OF, SF and AF exactly like UCOMISD.
    auto flags = (state->rflags & ~arithmeticFlagMask) | flagReservedOne;
    if (std::isnan(destination) || std::isnan(source)) {
        flags |= flagCarry | flagParity | flagZero;
    } else if (destination < source) {
        flags |= flagCarry;
    } else if (destination == source) {
        flags |= flagZero;
    }
    state->rflags = flags;
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
compareEqualXmmQwords128(x86::X86State *state, std::uint64_t destinationIndex,
                         std::uint64_t sourceIndex) noexcept {
    if (destinationIndex >= state->xmm.size() || sourceIndex >= state->xmm.size()) {
        return state;
    }
    const auto destination = state->xmm[destinationIndex];
    const auto source = state->xmm[sourceIndex];
    state->xmm[destinationIndex] = {
        .low = destination.low == source.low ? UINT64_MAX : 0,
        .high = destination.high == source.high ? UINT64_MAX : 0,
    };
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
repeatStore(GuestExecutionContext *context, x86::X86State *state,
            std::uint64_t widthBytes) noexcept {
    std::uint64_t currentAddress = state != nullptr ? state->rdi : 0;
    try {
        if (context == nullptr || context->addressSpace == nullptr || state == nullptr) {
            throw std::runtime_error("generated REP STOS has no guest execution context");
        }
        if (widthBytes != 1 && widthBytes != 2 && widthBytes != 4 && widthBytes != 8) {
            throw std::runtime_error("generated REP STOS has an invalid element width");
        }
        const auto value = state->rax & (widthBytes == 8 ? UINT64_MAX : ((1ULL << (widthBytes * 8U)) - 1U));
        const auto decrement = (state->rflags & flagDirection) != 0;
        const std::uint64_t step = decrement ? 0ULL - widthBytes : widthBytes;
        while (state->rcx != 0) {
            currentAddress = state->rdi;
            std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
            std::memcpy(bytes.data(), &value, static_cast<std::size_t>(widthBytes));
            context->addressSpace->writeBytes(
                guest::GuestAddress{currentAddress},
                std::span<const std::uint8_t>{bytes.data(),
                                              static_cast<std::size_t>(widthBytes)});
            state->rdi += step;
            --state->rcx;
        }
        return state;
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{currentAddress};
            context->faultSize = static_cast<std::size_t>(widthBytes);
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
cpuidGuest(x86::X86State *state) noexcept {
    // Reports a Nehalem-era Intel CPU: SSE4.2 is the newest advertised
    // vector extension, so feature dispatchers stay on instruction paths
    // Rosa implements (no AVX/AVX2/FMA/AES/PCLMULQDQ/RDRAND).
    const auto leaf = static_cast<std::uint32_t>(state->rax);
    const auto subleaf = static_cast<std::uint32_t>(state->rcx);
    std::uint32_t eax = 0;
    std::uint32_t ebx = 0;
    std::uint32_t ecx = 0;
    std::uint32_t edx = 0;
    if (leaf == 0U) {
        eax = 7U;                // Maximum basic leaf.
        ebx = 0x756E6547U;       // "Genu"
        edx = 0x49656E69U;       // "ineI"
        ecx = 0x6C65746EU;       // "ntel"
    } else if (leaf == 1U) {
        eax = 0x106A5U;          // Family 6, model 26, stepping 5.
        ebx = 0x800U;            // CLFLUSH line size 8.
        ecx = (1U << 0U) | (1U << 9U) | (1U << 19U) | (1U << 20U);  // SSE3/SSSE3/SSE4.1/SSE4.2.
        edx = (1U << 0U) | (1U << 4U) | (1U << 5U) | (1U << 6U) | (1U << 8U) |
              (1U << 9U) | (1U << 11U) | (1U << 12U) | (1U << 13U) | (1U << 14U) |
              (1U << 15U) | (1U << 16U) | (1U << 17U) | (1U << 19U) | (1U << 23U) |
              (1U << 24U) | (1U << 25U) | (1U << 26U);  // FPU..SSE2 baseline.
    } else if (leaf == 7U && subleaf == 0U) {
        eax = 0U;  // Maximum subleaf; no extended features advertised.
    } else if (leaf == 0x80000000U) {
        eax = 0x80000008U;  // Maximum extended leaf.
    } else if (leaf == 0x80000001U) {
        edx = (1U << 11U) | (1U << 20U) | (1U << 29U);  // SYSCALL/NX/long mode.
    }
    state->rax = eax;
    state->rbx = ebx;
    state->rcx = ecx;
    state->rdx = edx;
    return state;
}

} // namespace rosa::dbt::runtime
