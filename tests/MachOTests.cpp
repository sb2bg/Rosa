#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testControlledMachOParsing() {
    const auto file = rosa::macho::MachOFile::open(ROSA_TEST_MACHO_PATH);
    expectEqual(file.cpuType(), std::uint32_t{0x01000007U}, "Mach-O CPU type differs");
    expectEqual(file.fileType(), std::uint32_t{2}, "Mach-O file type differs");
    expect(!file.segments().empty(), "Mach-O has no parsed segments");
    bool sawMain = false;
    for (const auto &command : file.loadCommands()) {
        sawMain |= command.command == rosa::macho::lcMain;
    }
    expect(sawMain, "controlled Mach-O does not contain parsed LC_MAIN");
    constexpr std::array<std::uint8_t, 16> expectedUuid{0xE0, 0x8F, 0xEF, 0x1A, 0x86, 0x9A,
                                                        0x3D, 0xA3, 0x9A, 0x85, 0x62, 0x13,
                                                        0xBE, 0x73, 0xE0, 0xAF};
    expect(file.uuid().has_value(), "controlled Mach-O does not contain parsed LC_UUID");
    expectEqual(*file.uuid(), expectedUuid, "controlled Mach-O UUID differs");

    rosa::guest::AddressSpace addressSpace;
    const rosa::macho::Loader loader;
    const auto image = loader.mapImage(file, addressSpace);
    expectEqual(image.mappedSegments, std::size_t{3}, "Mach-O mapped-segment count differs");
    expectEqual(image.loadAddress.value, std::uint64_t{0x100000000ULL},
                "Mach-O load address differs");
    expectEqual(addressSpace.readU32(image.loadAddress), std::uint32_t{0xFEEDFACFU},
                "Mach-O load address does not point at its header");
    expectEqual(addressSpace.mappingCount(), image.mappedSegments,
                "guest mapping count differs from loaded segment count");
    expectEqual(addressSpace.executableBytes(image.entryPoint).front(), std::uint8_t{0x48},
                "Mach-O entry does not point to controlled x86 code");
    bool pageZeroRejected = false;
    try {
        static_cast<void>(addressSpace.readBytes(rosa::guest::GuestAddress{0}, 1));
    } catch (const std::runtime_error &) {
        pageZeroRejected = true;
    }
    expect(pageZeroRejected, "sparse __PAGEZERO did not reject guest reads");
}

void writeBigU32(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 2] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 3] = static_cast<std::uint8_t>(value);
}

void testUniversalMachOX86Selection() {
    const auto thin = rosa::macho::MachOFile::open(ROSA_TEST_MACHO_PATH);
    constexpr std::size_t fatHeaderSize = 8 + 20;
    std::vector<std::uint8_t> fat(fatHeaderSize + thin.bytes().size());
    fat[0] = 0xCA;
    fat[1] = 0xFE;
    fat[2] = 0xBA;
    fat[3] = 0xBE;
    writeBigU32(fat, 4, 1);
    writeBigU32(fat, 8, 0x01000007U);
    writeBigU32(fat, 12, 3);
    writeBigU32(fat, 16, fatHeaderSize);
    writeBigU32(fat, 20, static_cast<std::uint32_t>(thin.bytes().size()));
    writeBigU32(fat, 24, 0);
    std::copy(thin.bytes().begin(), thin.bytes().end(),
              fat.begin() + static_cast<std::ptrdiff_t>(fatHeaderSize));
    const auto selected = rosa::macho::MachOFile::parse(std::move(fat));
    expectEqual(selected.entryPoint(), thin.entryPoint(), "universal Mach-O x86_64 entry differs");
}

void testMalformedMachORejection() {
    const auto valid = rosa::macho::MachOFile::open(ROSA_TEST_MACHO_PATH);
    std::vector<std::uint8_t> bytes(valid.bytes().begin(), valid.bytes().end());
    expect(bytes.size() > 40, "controlled Mach-O is unexpectedly short");
    bytes[36] = 0;
    bytes[37] = 0;
    bytes[38] = 0;
    bytes[39] = 0;
    bool rejected = false;
    try {
        static_cast<void>(rosa::macho::MachOFile::parse(std::move(bytes)));
    } catch (const std::runtime_error &) {
        rejected = true;
    }
    expect(rejected, "zero-sized Mach-O load command was not rejected");
}

void testR3ControlledMachOExecution() {
    const rosa::macho::Loader loader;
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    const auto image = loader.mapImage(ROSA_TEST_MACHO_PATH, addressSpace);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = image.entryPoint.value;
    state.rsp = stackTop - sizeof(std::uint64_t);
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 64, sentinel);
    expectEqual(state.rax, std::uint64_t{42}, "controlled Mach-O guest RAX differs");
    expectEqual(result.executedBlocks, std::size_t{5},
                "controlled Mach-O executed-block count differs");
}

} // namespace

std::span<const TestCase> machOTests() {
    static const TestCase cases[]{
        {"controlled Mach-O parsing", testControlledMachOParsing},
        {"universal Mach-O x86 selection", testUniversalMachOX86Selection},
        {"malformed Mach-O rejection", testMalformedMachORejection},
        {"R3 controlled Mach-O execution", testR3ControlledMachOExecution},
    };
    return cases;
}

} // namespace rosa::tests
