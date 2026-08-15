#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace rosa::x86 {

enum class Register : std::uint8_t {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
};

constexpr std::string_view registerName(Register reg) {
    constexpr std::array names{
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    };
    return names.at(static_cast<std::size_t>(reg));
}

struct alignas(16) X86State {
    std::uint64_t rax{};
    std::uint64_t rbx{};
    std::uint64_t rcx{};
    std::uint64_t rdx{};
    std::uint64_t rsi{};
    std::uint64_t rdi{};
    std::uint64_t rbp{};
    std::uint64_t rsp{};

    std::uint64_t r8{};
    std::uint64_t r9{};
    std::uint64_t r10{};
    std::uint64_t r11{};
    std::uint64_t r12{};
    std::uint64_t r13{};
    std::uint64_t r14{};
    std::uint64_t r15{};

    std::uint64_t rip{};
    std::uint64_t rflags{0x2};
};

static_assert(std::is_standard_layout_v<X86State>);

constexpr std::size_t registerOffset(Register reg) {
    switch (reg) {
    case Register::Rax:
        return offsetof(X86State, rax);
    case Register::Rbx:
        return offsetof(X86State, rbx);
    case Register::Rcx:
        return offsetof(X86State, rcx);
    case Register::Rdx:
        return offsetof(X86State, rdx);
    case Register::Rsi:
        return offsetof(X86State, rsi);
    case Register::Rdi:
        return offsetof(X86State, rdi);
    case Register::Rbp:
        return offsetof(X86State, rbp);
    case Register::Rsp:
        return offsetof(X86State, rsp);
    case Register::R8:
        return offsetof(X86State, r8);
    case Register::R9:
        return offsetof(X86State, r9);
    case Register::R10:
        return offsetof(X86State, r10);
    case Register::R11:
        return offsetof(X86State, r11);
    case Register::R12:
        return offsetof(X86State, r12);
    case Register::R13:
        return offsetof(X86State, r13);
    case Register::R14:
        return offsetof(X86State, r14);
    case Register::R15:
        return offsetof(X86State, r15);
    }
    return 0;
}

} // namespace rosa::x86
