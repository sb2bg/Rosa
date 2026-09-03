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
inline constexpr XRegister x5{5};
inline constexpr XRegister x6{6};
inline constexpr XRegister x7{7};
inline constexpr XRegister x8{8};
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
inline constexpr XRegister x20{20};
inline constexpr XRegister x21{21};
inline constexpr XRegister x22{22};
inline constexpr XRegister x23{23};
inline constexpr XRegister x24{24};
inline constexpr XRegister x25{25};
inline constexpr XRegister x26{26};
inline constexpr XRegister x27{27};
inline constexpr XRegister x28{28};
inline constexpr XRegister x30{30};

struct Program {
    std::vector<std::uint8_t> bytes;
    std::vector<std::string> listing;
    std::vector<std::uint32_t> pointerRelocations;
};

struct RelocatablePointer {
    std::uint64_t value{};
};

struct Label {
    std::uint32_t id{};
};

enum class BranchCondition : std::uint8_t {
    Equal = 0,
    NotEqual = 1,
    UnsignedHigherOrSame = 2,
    UnsignedLower = 3,
    Negative = 4,
    NonNegative = 5,
    Overflow = 6,
    NoOverflow = 7,
    UnsignedHigher = 8,
    UnsignedLowerOrSame = 9,
    SignedGreaterOrEqual = 10,
    SignedLess = 11,
    SignedGreater = 12,
    SignedLessOrEqual = 13,
};

class Assembler {
  public:
    explicit Assembler(bool recordListing = true) : recordListing_(recordListing) {
        // Runtime blocks average well below this size. Reserving once avoids
        // repeatedly reallocating the instruction stream while it is emitted.
        words_.reserve(128);
        labelPositions_.reserve(8);
        fixups_.reserve(8);
        if (recordListing_) {
            listing_.reserve(128);
        }
    }

    void mov(XRegister destination, XRegister source);
    void mov32(XRegister destination, XRegister source);
    void movImmediate(XRegister destination, std::uint64_t value);
    void movImmediate(XRegister destination, RelocatablePointer pointer);
    void add(XRegister destination, XRegister lhs, XRegister rhs);
    void add32(XRegister destination, XRegister lhs, XRegister rhs);
    void addImmediate(XRegister destination, XRegister source, std::uint16_t immediate);
    void addImmediate32(XRegister destination, XRegister source, std::uint16_t immediate);
    void sub(XRegister destination, XRegister lhs, XRegister rhs);
    void sub32(XRegister destination, XRegister lhs, XRegister rhs);
    void subImmediate(XRegister destination, XRegister source, std::uint16_t immediate);
    void subImmediate32(XRegister destination, XRegister source, std::uint16_t immediate);
    void lslImmediate(XRegister destination, XRegister source, std::uint8_t shift);
    void lsrImmediate(XRegister destination, XRegister source, std::uint8_t shift);
    void asrImmediate(XRegister destination, XRegister source, std::uint8_t shift);
    void asrImmediate32(XRegister destination, XRegister source, std::uint8_t shift);
    void reverseBytes32(XRegister destination, XRegister source);
    void reverseBytes64(XRegister destination, XRegister source);
    void signExtend32(XRegister destination, XRegister source);
    void lslVariable(XRegister destination, XRegister source, XRegister shift);
    void lsrVariable(XRegister destination, XRegister source, XRegister shift);
    void multiplyLow(XRegister destination, XRegister lhs, XRegister rhs);
    void multiplyHighUnsigned(XRegister destination, XRegister lhs, XRegister rhs);
    void extract(XRegister destination, XRegister high, XRegister low, std::uint8_t lsb);
    void bitAnd(XRegister destination, XRegister lhs, XRegister rhs);
    void bitAnd32(XRegister destination, XRegister lhs, XRegister rhs);
    void bitOr(XRegister destination, XRegister lhs, XRegister rhs);
    void bitOr32(XRegister destination, XRegister lhs, XRegister rhs);
    void bitOrShiftedLeft(XRegister destination, XRegister lhs, XRegister rhs, std::uint8_t shift);
    void bitXor(XRegister destination, XRegister lhs, XRegister rhs);
    void bitXor32(XRegister destination, XRegister lhs, XRegister rhs);
    void bitXorShiftedRight(XRegister destination, XRegister lhs, XRegister rhs,
                            std::uint8_t shift);
    void compare(XRegister lhs, XRegister rhs);
    void compareZero(XRegister value);
    void conditionalSet(XRegister destination, BranchCondition condition);
    void conditionalSelect(XRegister destination, XRegister ifTrue, XRegister ifFalse,
                           BranchCondition condition);
    void conditionalSelect32(XRegister destination, XRegister ifTrue, XRegister ifFalse,
                             BranchCondition condition);
    void conditionalSelectEqual(XRegister destination, XRegister ifEqual, XRegister ifNotEqual);
    void ldr(XRegister destination, XRegister base, std::uint32_t byteOffset);
    void ldr32(XRegister destination, XRegister base, std::uint32_t byteOffset);
    void ldr8(XRegister destination, XRegister base, std::uint32_t byteOffset);
    void str(XRegister source, XRegister base, std::uint32_t byteOffset);
    void str8(XRegister source, XRegister base, std::uint32_t byteOffset);
    void blr(XRegister target);
    [[nodiscard]] Label makeLabel();
    void bind(Label label);
    void b(Label label);
    void cbz(XRegister value, Label label);
    void cbnz(XRegister value, Label label);
    void bConditional(BranchCondition condition, Label label);
    void bUnsignedHigherOrSame(Label label);
    void tbz(XRegister value, std::uint8_t bit, Label label);
    void tbnz(XRegister value, std::uint8_t bit, Label label);
    void pushFrameRecord();
    void popFrameRecord();
    void pushCalleeSaved19And20();
    void popCalleeSaved19And20();
    void pushCalleeSaved19Through22();
    void popCalleeSaved19Through22();
    void pushCalleeSaved19Through24();
    void popCalleeSaved19Through24();
    void pushCallerSaved8Through15();
    void popCallerSaved8Through15();
    void pushCallerSaved5Through15();
    void popCallerSaved5Through15();
    void pushCalleeSaved25Through28();
    void popCalleeSaved25Through28();
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
    void emitFixup(std::uint32_t word, std::string text, FixupKind kind, Label label);
    static void requireRegister(XRegister reg);

    std::vector<std::uint32_t> words_;
    std::vector<std::string> listing_;
    std::vector<std::optional<std::size_t>> labelPositions_;
    std::vector<Fixup> fixups_;
    std::vector<std::uint32_t> pointerRelocations_;
    bool recordListing_{};
};

} // namespace rosa::arm64
