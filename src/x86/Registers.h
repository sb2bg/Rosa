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

enum class XmmRegister : std::uint8_t {
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
};

constexpr std::string_view xmmRegisterName(XmmRegister reg) {
    constexpr std::array names{
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    };
    return names.at(static_cast<std::size_t>(reg));
}

constexpr std::string_view ymmRegisterName(XmmRegister reg) {
    constexpr std::array names{
        "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
        "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
    };
    return names.at(static_cast<std::size_t>(reg));
}

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

    struct XmmValue {
        std::uint64_t low{};
        std::uint64_t high{};
    };
    std::array<XmmValue, 16> xmm{};
    std::array<XmmValue, 16> ymmUpper{};

    // Architectural guest TLS state. This is never a host segment base.
    std::uint64_t gsBase{};
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

constexpr std::size_t xmmLaneOffset(XmmRegister reg, bool high) {
    return offsetof(X86State, xmm) +
           static_cast<std::size_t>(reg) * sizeof(X86State::XmmValue) +
           (high ? offsetof(X86State::XmmValue, high) : offsetof(X86State::XmmValue, low));
}

constexpr std::size_t ymmUpperLaneOffset(XmmRegister reg, bool high) {
    return offsetof(X86State, ymmUpper) +
           static_cast<std::size_t>(reg) * sizeof(X86State::XmmValue) +
           (high ? offsetof(X86State::XmmValue, high)
                 : offsetof(X86State::XmmValue, low));
}

} // namespace rosa::x86
