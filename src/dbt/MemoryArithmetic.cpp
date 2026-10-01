#include "dbt/RuntimeHelpers.h"
#include "x86/Flags.h"
#include "dbt/FlagSemantics.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <stdexcept>

namespace rosa::dbt::runtime {
using namespace x86;

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

namespace {

// A memory-destination XOR of one width: read, combine, write, then the
// logic flags of the result.
template <typename Value>
x86::X86State *xorGuestMemory(GuestExecutionContext *context, x86::X86State *state,
                              std::uint64_t address, std::uint64_t sourceValue,
                              x86::X86State *(*updateFlags)(x86::X86State *, std::uint64_t)) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated guest XOR has no address space");
        }
        auto &addressSpace = *context->addressSpace;
        addressSpace.validateAccess(guest::GuestAddress{address}, sizeof(Value),
                                    guest::Permission::Read | guest::Permission::Write);
        const auto bytes = addressSpace.readBytes(guest::GuestAddress{address}, sizeof(Value));
        Value original{};
        std::memcpy(&original, bytes.data(), sizeof(Value));
        const auto result = static_cast<Value>(original ^ static_cast<Value>(sourceValue));
        std::array<std::uint8_t, sizeof(Value)> resultBytes{};
        std::memcpy(resultBytes.data(), &result, sizeof(Value));
        addressSpace.writeBytes(guest::GuestAddress{address}, resultBytes);
        return updateFlags(state, result);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(Value);
        }
        return nullptr;
    }
}

} // namespace

extern "C" __attribute__((noinline)) x86::X86State *
xorGuest8(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
          std::uint64_t sourceValue) noexcept {
    return xorGuestMemory<std::uint8_t>(context, state, address, sourceValue, updateLogicFlags8);
}

extern "C" __attribute__((noinline)) x86::X86State *
xorGuest16(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
           std::uint64_t sourceValue) noexcept {
    return xorGuestMemory<std::uint16_t>(context, state, address, sourceValue, updateLogicFlags16);
}

extern "C" __attribute__((noinline)) x86::X86State *
xorGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
           std::uint64_t sourceValue) noexcept {
    return xorGuestMemory<std::uint32_t>(context, state, address, sourceValue, updateLogicFlags32);
}

extern "C" __attribute__((noinline)) x86::X86State *
xorGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
           std::uint64_t sourceValue) noexcept {
    return xorGuestMemory<std::uint64_t>(context, state, address, sourceValue, updateLogicFlags64);
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
compareExchangeGuest8(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                      std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated byte CMPXCHG has no guest address space");
        }
        constexpr auto width = sizeof(std::uint8_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto memoryValue = context->addressSpace->readU8(guest::GuestAddress{address});
        const auto accumulator = static_cast<std::uint8_t>(state->rax);
        const auto result = static_cast<std::uint8_t>(memoryValue - accumulator);
        if (accumulator == memoryValue) {
            const auto source = static_cast<std::uint8_t>(sourceValue);
            const std::array bytes{source};
            context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        } else {
            // Only AL takes the memory value; the upper RAX bits are preserved.
            state->rax = (state->rax & ~std::uint64_t{0xFF}) | memoryValue;
        }
        return updateSubFlags8(state, memoryValue, accumulator, result);
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
compareExchangeGuest16(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                       std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated word CMPXCHG has no guest address space");
        }
        constexpr auto width = sizeof(std::uint16_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto memoryValue = context->addressSpace->readU16(guest::GuestAddress{address});
        const auto accumulator = static_cast<std::uint16_t>(state->rax);
        const auto result = static_cast<std::uint16_t>(memoryValue - accumulator);
        if (accumulator == memoryValue) {
            const auto source = static_cast<std::uint16_t>(sourceValue);
            const std::array bytes{
                static_cast<std::uint8_t>(source),
                static_cast<std::uint8_t>(source >> 8U),
            };
            context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        } else {
            // Only AX takes the memory value; the upper RAX bits are preserved.
            state->rax = (state->rax & ~std::uint64_t{0xFFFF}) | memoryValue;
        }
        return updateSubFlags16(state, memoryValue, accumulator, result);
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

extern "C" __attribute__((noinline)) x86::X86State *
lockedOrGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated qword LOCK OR has no guest address space");
        }
        constexpr auto width = sizeof(std::uint64_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original | sourceValue;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        std::atomic_thread_fence(std::memory_order_seq_cst);
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
lockedOrGuest8(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
               std::uint64_t immediateValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated byte LOCK OR has no guest address space");
        }
        constexpr auto width = sizeof(std::uint8_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU8(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint8_t>(original | static_cast<std::uint8_t>(immediateValue));
        const std::array bytes{result};
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateLogicFlags8(state, result);
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
lockedAndGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t immediateValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated qword LOCK AND has no guest address space");
        }
        constexpr auto width = sizeof(std::uint64_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{address});
        const auto result = original & immediateValue;
        context->addressSpace->writeU64(guest::GuestAddress{address}, result);
        std::atomic_thread_fence(std::memory_order_seq_cst);
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

extern "C" __attribute__((noinline)) x86::X86State *
lockedAndGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t immediateValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated LOCK AND has no guest address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto result =
            static_cast<std::uint32_t>(original & static_cast<std::uint32_t>(immediateValue));
        const std::array bytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        // LOCK AND is also used as a full fence. Guest execution is currently
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
lockedAddGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t sourceValue) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated dword LOCK ADD has no guest address space");
        }
        constexpr auto width = sizeof(std::uint32_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{address});
        const auto source = static_cast<std::uint32_t>(sourceValue);
        const auto result = original + source;
        const std::array bytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
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
lockedExchangeAddGuest16(GuestExecutionContext *context, x86::X86State *state,
                         std::uint64_t address, std::uint64_t sourceValue,
                         std::uint64_t sourceEncoding) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated word LOCK XADD has no guest address space");
        }
        if (sourceEncoding > static_cast<std::uint64_t>(x86::Register::R15)) {
            throw std::runtime_error("generated word LOCK XADD has an invalid source register");
        }
        constexpr auto width = sizeof(std::uint16_t);
        context->addressSpace->validateAccess(guest::GuestAddress{address}, width,
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU16(guest::GuestAddress{address});
        const auto source = static_cast<std::uint16_t>(sourceValue);
        const auto result = static_cast<std::uint16_t>(original + source);
        const std::array bytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{address}, bytes);
        // A 16-bit XADD preserves the upper register bits, unlike the
        // zero-extending 32-bit form. Flags come from the memory add.
        const auto sourceRegister = static_cast<x86::Register>(sourceEncoding);
        const auto parentOffset = x86::registerOffset(sourceRegister);
        std::memcpy(reinterpret_cast<std::uint8_t *>(state) + parentOffset, &original,
                    sizeof(original));
        std::atomic_thread_fence(std::memory_order_seq_cst);
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
lockedBitSetGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                    std::uint64_t bitIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated LOCK BTS has no guest address space");
        }
        const auto unitAddress = address + (bitIndex >> 5U) * sizeof(std::uint32_t);
        const auto bit = static_cast<std::uint32_t>(bitIndex & 0x1FU);
        context->addressSpace->validateAccess(guest::GuestAddress{unitAddress},
                                              sizeof(std::uint32_t),
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU32(guest::GuestAddress{unitAddress});
        const auto result = original | (1U << bit);
        const std::array bytes{
            static_cast<std::uint8_t>(result),
            static_cast<std::uint8_t>(result >> 8U),
            static_cast<std::uint8_t>(result >> 16U),
            static_cast<std::uint8_t>(result >> 24U),
        };
        context->addressSpace->writeBytes(guest::GuestAddress{unitAddress}, bytes);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateBitTestFlags32(state, original, bit);
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
lockedBitSetGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                    std::uint64_t bitIndex) noexcept {
    try {
        if (context == nullptr || context->addressSpace == nullptr) {
            throw std::runtime_error("generated qword LOCK BTS has no guest address space");
        }
        const auto unitAddress = address + (bitIndex >> 6U) * sizeof(std::uint64_t);
        const auto bit = static_cast<std::uint32_t>(bitIndex & 0x3FU);
        context->addressSpace->validateAccess(guest::GuestAddress{unitAddress},
                                              sizeof(std::uint64_t),
                                              guest::Permission::Read | guest::Permission::Write);
        const auto original = context->addressSpace->readU64(guest::GuestAddress{unitAddress});
        const auto result = original | (1ULL << bit);
        context->addressSpace->writeU64(guest::GuestAddress{unitAddress}, result);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return updateBitTestFlags64(state, original, bit);
    } catch (...) {
        if (context != nullptr) {
            context->fault = std::current_exception();
            context->faultAddress = guest::GuestAddress{address};
            context->faultSize = sizeof(std::uint64_t);
        }
        return nullptr;
    }
}

} // namespace rosa::dbt::runtime
