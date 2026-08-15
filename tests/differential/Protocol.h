#pragma once

#include "x86/Registers.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace rosa::differential {

constexpr std::uint32_t protocolMagic = 0x524F5341U;
constexpr std::size_t memorySize = 256;
constexpr std::size_t stackSize = 256;
constexpr std::uint8_t noRegister = 0xFFU;
constexpr std::uint32_t noOffset = UINT32_MAX;

enum class CaseId : std::uint32_t {
#define ROSA_DIFFERENTIAL_CASE(name, ...) name,
#include "Cases.def"
#undef ROSA_DIFFERENTIAL_CASE
    Count,
};

struct Request {
    std::uint32_t magic{protocolMagic};
    CaseId caseId{};
    x86::X86State state{};
    std::array<std::uint8_t, memorySize> memory{};
    std::uint8_t memoryBaseRegister{noRegister};
    std::uint8_t reserved0{};
    std::uint16_t reserved1{};
    std::uint32_t memoryBaseOffset{};
    std::uint32_t codePointerMemoryOffset{noOffset};
    std::uint32_t codePointerTargetOffset{};
};

struct Result {
    std::uint32_t magic{protocolMagic};
    std::uint32_t status{};
    x86::X86State initial{};
    x86::X86State final{};
    std::array<std::uint8_t, memorySize> memory{};
    std::array<std::uint8_t, stackSize> stack{};
};

static_assert(std::is_trivially_copyable_v<Request>);
static_assert(std::is_trivially_copyable_v<Result>);

} // namespace rosa::differential
