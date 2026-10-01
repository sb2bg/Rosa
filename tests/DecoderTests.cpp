#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testSingleInstructionFamilies() {
    using rosa::x86::Opcode;
    struct Sample {
        std::vector<std::uint8_t> bytes;
        Opcode opcode;
    };
    const Sample samples[]{
        {{0x48, 0x83, 0xC0, 0x02}, Opcode::AddRegImm},
        {{0xC5, 0xF8, 0x77}, Opcode::Vzeroupper},
        {{0x66, 0x0F, 0xEF, 0xC0}, Opcode::PxorRegReg},
        {{0xF3, 0xAA}, Opcode::RepStosb},
        {{0xF0, 0x48, 0x01, 0x08}, Opcode::LockAddMemReg},
        {{0x48, 0x8B, 0x44, 0x8B, 0x10}, Opcode::MovRegMem},
        {{0x0F, 0x05}, Opcode::Syscall},
        {{0xE8, 0, 0, 0, 0}, Opcode::CallRelative},
        {{0x75, 0xFE}, Opcode::JccRelative},
        {{0xC3}, Opcode::Ret},
    };
    const rosa::x86::Decoder decoder;
    for (const auto &sample : samples) {
        auto bytes = sample.bytes;
        bytes.push_back(0xCC); // Subsequent unsupported bytes must not be decoded.
        const auto instruction = decoder.decodeInstruction(bytes, rosa::guest::GuestAddress{0x1000});
        expectEqual(instruction.opcode, sample.opcode, "single-instruction opcode differs");
        expectEqual(instruction.address.value, std::uint64_t{0x1000}, "instruction address differs");
        expectEqual(instruction.length, sample.bytes.size(), "single-instruction length differs");
        expect(std::equal(sample.bytes.begin(), sample.bytes.end(), instruction.bytes.begin()),
               "single-instruction source bytes differ");

        bytes.insert(bytes.begin(), 0x90);
        const auto block = decoder.decodeBlock(bytes, rosa::guest::GuestAddress{0x0FFF}, 2);
        expectEqual(block.size(), std::size_t{2}, "block instruction budget was not respected");
        expectEqual(block.back().opcode, instruction.opcode, "block recognition changed opcode");
        expectEqual(block.back().address, instruction.address, "block recognition changed RIP");
        expectEqual(block.back().bytes, instruction.bytes, "block recognition changed bytes");
        expectEqual(block.back().branchTarget, instruction.branchTarget, "block target differs");
        expectEqual(block.back().fallthrough, instruction.fallthrough, "block fallthrough differs");
    }
}

void testSingleInstructionIndexedOperand() {
    const std::array<std::uint8_t, 5> bytes{0x48, 0x8B, 0x44, 0x8B, 0x10};
    const auto instruction = rosa::x86::Decoder{}.decodeInstruction(
        bytes, rosa::guest::GuestAddress{0x1000});
    const auto &memory = std::get<rosa::x86::MemoryOperand>(instruction.operands.at(1));
    expectEqual(memory.base, rosa::x86::Register::Rbx, "SIB base differs");
    expectEqual(memory.index, std::optional{rosa::x86::Register::Rcx}, "SIB index differs");
    expectEqual(memory.scale, 4, "SIB scale differs");
    expectEqual(memory.displacement, 16, "SIB displacement differs");
    expectEqual(memory.width, 64, "SIB memory width differs");
}

void testDecoderStopsAtTerminator() {
    const std::array<std::uint8_t, 4> bytes{0x90, 0x75, 0xFD, 0xCC};
    const auto block = rosa::x86::Decoder{}.decodeBlock(bytes, rosa::guest::GuestAddress{0x1000});
    expectEqual(block.size(), std::size_t{2}, "decoder read past a conditional terminator");
    expectEqual(block.back().branchTarget, std::optional{rosa::guest::GuestAddress{0x1000}},
                "relative target did not use the instruction RIP");
    expectEqual(block.back().fallthrough, std::optional{rosa::guest::GuestAddress{0x1003}},
                "conditional fallthrough differs");
}

void testDecoderBoundaryErrors() {
    const rosa::x86::Decoder decoder;
    for (const auto &bytes : {std::vector<std::uint8_t>{}, {0x48}, {0xC5, 0xF8}, {0xF0}}) {
        bool rejected = false;
        try {
            static_cast<void>(decoder.decodeInstruction(bytes, rosa::guest::GuestAddress{0x1234}));
        } catch (const rosa::x86::DecodeError &error) {
            rejected = true;
            expectEqual(error.address().value, std::uint64_t{0x1234}, "decode error lost its RIP");
            expectEqual(error.remainingBytes(), bytes, "decode error lost its bytes");
        }
        expect(rejected, "decoder accepted an empty or truncated instruction");
    }
    const std::array<std::uint8_t, 2> bytes{0x90, 0xC3};
    bool rejected = false;
    try {
        static_cast<void>(decoder.decodeBlock(bytes, rosa::guest::GuestAddress{UINT64_MAX}, 2));
    } catch (const rosa::x86::DecodeError &) {
        rejected = true;
    }
    expect(rejected, "block decoder accepted a wrapping instruction address");
}

} // namespace

std::span<const TestCase> decoderTests() {
    static const TestCase cases[]{
        {"single-instruction recognition families", testSingleInstructionFamilies},
        {"single-instruction indexed operand", testSingleInstructionIndexedOperand},
        {"decoder terminator boundary", testDecoderStopsAtTerminator},
        {"decoder boundary errors", testDecoderBoundaryErrors},
    };
    return cases;
}

} // namespace rosa::tests
