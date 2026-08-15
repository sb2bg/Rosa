#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rosa::arm64 {

struct XRegister {
    std::uint8_t encoding{};
};

inline constexpr XRegister x0{0};
inline constexpr XRegister x1{1};
inline constexpr XRegister x2{2};
inline constexpr XRegister x3{3};
inline constexpr XRegister x4{4};
inline constexpr XRegister x9{9};
inline constexpr XRegister x10{10};
inline constexpr XRegister x11{11};
inline constexpr XRegister x12{12};
inline constexpr XRegister x13{13};
inline constexpr XRegister x14{14};
inline constexpr XRegister x15{15};
inline constexpr XRegister x16{16};
inline constexpr XRegister x17{17};
inline constexpr XRegister x19{19};

struct Program {
    std::vector<std::uint8_t> bytes;
    std::vector<std::string> listing;
};

struct Label {
    std::uint32_t id{};
};

class Assembler {
  public:
    void mov(XRegister destination, XRegister source);
    void movImmediate(XRegister destination, std::uint64_t value);
    void add(XRegister destination, XRegister lhs, XRegister rhs);
    void sub(XRegister destination, XRegister lhs, XRegister rhs);
    void lslImmediate(XRegister destination, XRegister source, std::uint8_t shift);
    void lslVariable(XRegister destination, XRegister source, XRegister shift);
    void multiplyLow(XRegister destination, XRegister lhs, XRegister rhs);
    void multiplyHighUnsigned(XRegister destination, XRegister lhs, XRegister rhs);
    void extract(XRegister destination, XRegister high, XRegister low, std::uint8_t lsb);
    void bitAnd(XRegister destination, XRegister lhs, XRegister rhs);
    void bitOr(XRegister destination, XRegister lhs, XRegister rhs);
    void ldr(XRegister destination, XRegister base, std::uint32_t byteOffset);
    void ldr32(XRegister destination, XRegister base, std::uint32_t byteOffset);
    void str(XRegister source, XRegister base, std::uint32_t byteOffset);
    void blr(XRegister target);
    [[nodiscard]] Label makeLabel();
    void bind(Label label);
    void b(Label label);
    void cbz(XRegister value, Label label);
    void tbz(XRegister value, std::uint8_t bit, Label label);
    void tbnz(XRegister value, std::uint8_t bit, Label label);
    void pushFrameRecord();
    void popFrameRecord();
    void pushCalleeSaved19And20();
    void popCalleeSaved19And20();
    void dmbIsh();
    void isb();
    void ret();

    [[nodiscard]] const std::vector<std::uint32_t> &words() const noexcept { return words_; }
    [[nodiscard]] Program finish() &&;

  private:
    enum class FixupKind { Branch26, CompareBranch19, TestBranch14 };
    struct Fixup {
        FixupKind kind{};
        std::size_t wordIndex{};
        Label label{};
    };

    void emit(std::uint32_t word, std::string text);
    static void requireRegister(XRegister reg);

    std::vector<std::uint32_t> words_;
    std::vector<std::string> listing_;
    std::vector<std::optional<std::size_t>> labelPositions_;
    std::vector<Fixup> fixups_;
};

} // namespace rosa::arm64
