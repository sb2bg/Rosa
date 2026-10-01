#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

std::string readGuestString(const rosa::guest::AddressSpace &addressSpace,
                            rosa::guest::GuestAddress address) {
    std::string result;
    for (;;) {
        const auto byte = addressSpace.readBytes(address, 1).front();
        if (byte == 0) {
            return result;
        }
        result.push_back(static_cast<char>(byte));
        ++address.value;
    }
}
void testX86Commpage() {
    rosa::guest::AddressSpace addressSpace;
    constexpr std::uint64_t continuousTimebase = 0x0123456789ABCDEFULL;
    constexpr std::uint64_t bootTimeUsec = 0x00123456789ABCDEULL;
    constexpr std::uint64_t dyldFlags = 0xFEDCBA9876543210ULL;
    rosa::darwin::mapX86Commpage(addressSpace, continuousTimebase, bootTimeUsec, dyldFlags);
    expectEqual(addressSpace.readU64(
                    rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                              rosa::darwin::x86CommpageCpuCapabilities64Offset}),
                rosa::darwin::x86CommpageCpuCapabilities64, "x86 commpage CPU capabilities differ");
    constexpr auto translatedCapability = UINT64_C(0x4000000000000000);
    expect((rosa::darwin::x86CommpageCpuCapabilities64 & translatedCapability) == 0,
           "x86 commpage falsely advertises Apple's translated-process bit");

    constexpr std::array<std::uint8_t, 14> loadCapabilities{
        0x48, 0xB8, 0x10, 0x00, 0xE0, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x48, 0x8B, 0x00, 0xC3};
    const rosa::dbt::Translator translator;
    const auto block = translator.translate(loadCapabilities, rosa::guest::GuestAddress{0x1000});
    rosa::x86::X86State loadState;
    loadState.rflags = 0x8D7;
    static_cast<void>(block.execute(loadState, &addressSpace));
    expectEqual(loadState.rax, rosa::darwin::x86CommpageCpuCapabilities64,
                "generated x86 load read the wrong CPU capabilities");
    expectEqual(loadState.rflags, std::uint64_t{0x8D7},
                "x86 commpage capability load changed flags");

    expectEqual(
        addressSpace.readU32(rosa::guest::GuestAddress{
            rosa::darwin::x86CommpageBase.value + rosa::darwin::x86CommpageCpuCapabilitiesOffset}),
        static_cast<std::uint32_t>(rosa::darwin::x86CommpageCpuCapabilities64),
        "x86 commpage legacy CPU capabilities differ");
    constexpr std::array<std::uint8_t, 13> loadLegacyCapabilities{
        0x48, 0xB9, 0x20, 0x00, 0xE0, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x8B, 0x09, 0xC3};
    const auto legacyCapabilitiesBlock =
        translator.translate(loadLegacyCapabilities, rosa::guest::GuestAddress{0x7FF802E7D2FDULL});
    rosa::x86::X86State legacyCapabilitiesState;
    legacyCapabilitiesState.rcx = UINT64_MAX;
    legacyCapabilitiesState.rflags = 0x2;
    static_cast<void>(legacyCapabilitiesBlock.execute(legacyCapabilitiesState, &addressSpace));
    expectEqual(legacyCapabilitiesState.rcx,
                static_cast<std::uint64_t>(
                    static_cast<std::uint32_t>(rosa::darwin::x86CommpageCpuCapabilities64)),
                "generated legacy capability probe differs");
    expectEqual(legacyCapabilitiesState.rflags, std::uint64_t{0x2},
                "legacy capability probe changed flags");

    const auto version =
        addressSpace.readBytes(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                         rosa::darwin::x86CommpageVersionOffset},
                               sizeof(rosa::darwin::x86CommpageVersion));
    expectEqual(
        version,
        std::vector<std::uint8_t>{static_cast<std::uint8_t>(rosa::darwin::x86CommpageVersion), 0},
        "x86 commpage version differs");
    expectEqual(
        addressSpace
            .readBytes(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                 rosa::darwin::x86CommpagePhysicalCpuCountOffset},
                       1)
            .front(),
        rosa::darwin::x86CommpagePhysicalCpuCount, "x86 commpage physical CPU count differs");
    expectEqual(
        addressSpace
            .readBytes(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                 rosa::darwin::x86CommpageActiveCpuCountOffset},
                       1)
            .front(),
        rosa::darwin::x86CommpageActiveCpuCount, "x86 commpage active CPU count differs");
    expectEqual(
        addressSpace
            .readBytes(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                 rosa::darwin::x86CommpageLogicalCpuCountOffset},
                       1)
            .front(),
        rosa::darwin::x86CommpageLogicalCpuCount, "x86 commpage logical CPU count differs");
    expectEqual(
        addressSpace
            .readBytes(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                 rosa::darwin::x86CommpageCpuClusterCountOffset},
                       1)
            .front(),
        rosa::darwin::x86CommpageCpuClusterCount, "x86 commpage CPU cluster count differs");
    expectEqual(
        addressSpace.readU64(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                       rosa::darwin::x86CommpageMemorySizeOffset}),
        rosa::darwin::x86CommpageMemorySize, "x86 commpage memory size differs");

    // Exact malloc probe: r14 holds commpage+0x10, so disp8 0x25 reads
    // _COMM_PAGE_PHYSICAL_CPUS at commpage+0x35.
    constexpr std::array<std::uint8_t, 6> loadPhysicalCpuCount{0x41, 0x0F, 0xB6, 0x56, 0x25, 0xC3};
    const auto physicalCpuBlock =
        translator.translate(loadPhysicalCpuCount, rosa::guest::GuestAddress{0x7FF802C75724ULL});
    rosa::x86::X86State physicalCpuState;
    physicalCpuState.r14 = rosa::darwin::x86CommpageBase.value + 0x10;
    physicalCpuState.rdx = UINT64_MAX;
    physicalCpuState.rflags = 0x8D7;
    static_cast<void>(physicalCpuBlock.execute(physicalCpuState, &addressSpace));
    expectEqual(physicalCpuState.rdx,
                static_cast<std::uint64_t>(rosa::darwin::x86CommpagePhysicalCpuCount),
                "generated malloc probe read the wrong physical CPU count");
    expectEqual(physicalCpuState.rflags, std::uint64_t{0x8D7},
                "physical CPU commpage load changed flags");
    constexpr std::array<std::uint8_t, 6> loadLogicalCpuCount{0x41, 0x0F, 0xB6, 0x4E, 0x26, 0xC3};
    const auto logicalCpuBlock =
        translator.translate(loadLogicalCpuCount, rosa::guest::GuestAddress{0x7FF802C7572FULL});
    rosa::x86::X86State logicalCpuState;
    logicalCpuState.r14 = rosa::darwin::x86CommpageBase.value + 0x10;
    logicalCpuState.rcx = UINT64_MAX;
    logicalCpuState.rflags = 0xAD7;
    static_cast<void>(logicalCpuBlock.execute(logicalCpuState, &addressSpace));
    expectEqual(logicalCpuState.rcx,
                static_cast<std::uint64_t>(rosa::darwin::x86CommpageLogicalCpuCount),
                "generated malloc probe read the wrong logical CPU count");
    expectEqual(logicalCpuState.rflags, std::uint64_t{0xAD7},
                "logical CPU commpage load changed flags");

    // Exact malloc probe: r12 holds commpage+0x1e, so disp8 0x1a reads the
    // uint64_t _COMM_PAGE_MEMORY_SIZE at commpage+0x38.
    constexpr std::array<std::uint8_t, 6> loadMemorySize{0x4D, 0x8B, 0x6C, 0x24, 0x1A, 0xC3};
    const auto memorySizeBlock =
        translator.translate(loadMemorySize, rosa::guest::GuestAddress{0x7FF802C71B53ULL});
    rosa::x86::X86State memorySizeState;
    memorySizeState.r12 = rosa::darwin::x86CommpageBase.value + 0x1E;
    memorySizeState.r13 = UINT64_MAX;
    memorySizeState.rflags = 0x6;
    static_cast<void>(memorySizeBlock.execute(memorySizeState, &addressSpace));
    expectEqual(memorySizeState.r13, rosa::darwin::x86CommpageMemorySize,
                "generated malloc probe read the wrong memory size");
    expectEqual(memorySizeState.r12, rosa::darwin::x86CommpageBase.value + 0x1E,
                "memory-size commpage load changed its base");
    expectEqual(memorySizeState.rflags, std::uint64_t{0x6},
                "memory-size commpage load changed flags");
    expectEqual(
        addressSpace
            .readBytes(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                 rosa::darwin::x86CommpageKernelPageShiftOffset},
                       1)
            .front(),
        rosa::darwin::x86CommpageKernelPageShift, "x86 commpage kernel page shift differs");
    expectEqual(
        addressSpace
            .readBytes(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                 rosa::darwin::x86CommpageUserPageShiftOffset},
                       1)
            .front(),
        rosa::darwin::x86CommpageUserPageShift, "x86 commpage user page shift differs");
    expectEqual(
        addressSpace.readU32(rosa::guest::GuestAddress{
            rosa::darwin::x86CommpageBase.value + rosa::darwin::x86CommpageKdebugEnableOffset}),
        std::uint32_t{0}, "x86 commpage kdebug state is not disabled");
    expectEqual(
        addressSpace.readU32(rosa::guest::GuestAddress{
            rosa::darwin::x86CommpageBase.value +
            rosa::darwin::x86CommpageAtmDiagnosticConfigOffset}),
        std::uint32_t{0}, "x86 commpage ATM diagnostic config is not disabled");

    // Exact mach_approximate_time gate: movabs rax, commpage+0x80;
    // cmp byte [rax+0x8], 0; the unsupported state takes the fallback.
    expectEqual(
        addressSpace.readU64(rosa::guest::GuestAddress{
            rosa::darwin::x86CommpageBase.value +
            rosa::darwin::x86CommpageApproximateTimeOffset}),
        std::uint64_t{0}, "x86 commpage approximate time is not disabled");
    expectEqual(
        addressSpace
            .readBytes(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                 rosa::darwin::x86CommpageApproximateTimeSupportedOffset},
                       1)
            .front(),
        std::uint8_t{0}, "x86 commpage approximate time is not unsupported");
    constexpr std::array<std::uint8_t, 15> probeApproximateTime{
        0x48, 0xB8, 0x80, 0x00, 0xE0, 0xFF, 0xFF, 0x7F, 0x00, 0x00,
        0x80, 0x78, 0x08, 0x00, 0xC3};
    const auto approximateBlock = translator.translate(
        probeApproximateTime, rosa::guest::GuestAddress{0x7FF802E30EF9ULL});
    rosa::x86::X86State approximateState;
    approximateState.rflags = 0x13;
    static_cast<void>(approximateBlock.execute(approximateState, &addressSpace));
    expectEqual(approximateState.rax, std::uint64_t{0x00007FFFFFE00080ULL},
                "generated approximate-time probe clobbered its address");
    expectEqual(approximateState.rflags, std::uint64_t{0x46},
                "unsupported approximate time did not set ZF");

    // Exact os_log probe: movabs rax, commpage+0x48; bt dword [rax], 8.
    // The disabled config leaves CF clear without touching other flags.
    constexpr std::array<std::uint8_t, 15> probeAtmDiagnostic{
        0x48, 0xB8, 0x48, 0x00, 0xE0, 0xFF, 0xFF, 0x7F, 0x00, 0x00,
        0x0F, 0xBA, 0x20, 0x08, 0xC3};
    const auto atmBlock = translator.translate(
        probeAtmDiagnostic, rosa::guest::GuestAddress{0x7FF802B81ABFULL});
    rosa::x86::X86State atmState;
    atmState.rflags = 0x46;
    static_cast<void>(atmBlock.execute(atmState, &addressSpace));
    expectEqual(atmState.rax, std::uint64_t{0x00007FFFFFE00048ULL},
                "generated ATM diagnostic probe clobbered its address");
    expectEqual(atmState.rflags, std::uint64_t{0x46},
                "disabled ATM diagnostic config set CF");
    expectEqual(
        addressSpace
            .readBytes(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                 rosa::darwin::x86CommpageDtraceDofEnabledOffset},
                       1)
            .front(),
        std::uint8_t{0}, "x86 commpage DTrace DOF registration is not disabled");

    // Exact cached-dyld gate: movabs rax, commpage+0x4c; mov al,[rax];
    // and al,1; ret. The generated code must observe the defined zero byte,
    // without treating the guest address as a host pointer.
    constexpr std::array<std::uint8_t, 17> loadDtraceDofEnabled{0x48, 0xB8, 0x4C, 0x00, 0xE0, 0xFF,
                                                                0xFF, 0x7F, 0x00, 0x00, 0x8A, 0x00,
                                                                0x24, 0x01, 0xC3, 0x90, 0x90};
    const auto dtraceBlock =
        translator.translate(loadDtraceDofEnabled, rosa::guest::GuestAddress{0x2000});
    rosa::x86::X86State dtraceState;
    dtraceState.rflags = 0x8D7;
    static_cast<void>(dtraceBlock.execute(dtraceState, &addressSpace));
    expectEqual(dtraceState.rax, std::uint64_t{0x00007FFFFFE00000ULL},
                "generated dyld DTrace gate did not observe disabled state");
    constexpr std::uint64_t definedLogicFlags =
        (1U << 0U) | (1U << 2U) | (1U << 6U) | (1U << 7U) | (1U << 11U);
    expectEqual(dtraceState.rflags & definedLogicFlags, std::uint64_t{(1U << 2U) | (1U << 6U)},
                "generated dyld DTrace gate flags differ");
    expectEqual(
        addressSpace.readU32(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                       rosa::darwin::x86CommpageCpuFamilyOffset}),
        rosa::darwin::x86CommpageCpuFamily, "x86 commpage CPU family differs");
    constexpr std::array<std::uint8_t, 14> loadCpuFamily{0x48, 0xB8, 0x10, 0x00, 0xE0, 0xFF, 0xFF,
                                                         0x7F, 0x00, 0x00, 0x8B, 0x40, 0x30, 0xC3};
    const auto cpuFamilyBlock =
        translator.translate(loadCpuFamily, rosa::guest::GuestAddress{0x3000});
    rosa::x86::X86State cpuFamilyState;
    cpuFamilyState.rflags = 0x8D7;
    static_cast<void>(cpuFamilyBlock.execute(cpuFamilyState, &addressSpace));
    expectEqual(cpuFamilyState.rax, static_cast<std::uint64_t>(rosa::darwin::x86CommpageCpuFamily),
                "generated platform resolver read the wrong CPU family");
    expectEqual(cpuFamilyState.rflags, std::uint64_t{0x8D7},
                "generated platform CPU-family load changed flags");
    expectEqual(addressSpace.readU64(
                    rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                              rosa::darwin::x86CommpageContinuousTimebaseOffset}),
                continuousTimebase, "x86 commpage continuous-time base differs");
    expectEqual(
        addressSpace.readU64(rosa::guest::GuestAddress{
            rosa::darwin::x86CommpageBase.value + rosa::darwin::x86CommpageBootTimeUsecOffset}),
        bootTimeUsec, "x86 commpage boot time differs");
    // Exact live libsystem_kernel sequence: movabs rax, commpage+0xc8;
    // mov rax,[rax]; ret.
    constexpr std::array<std::uint8_t, 14> loadBootTime{0x48, 0xB8, 0xC8, 0x00, 0xE0, 0xFF, 0xFF,
                                                        0x7F, 0x00, 0x00, 0x48, 0x8B, 0x00, 0xC3};
    const auto bootTimeBlock =
        translator.translate(loadBootTime, rosa::guest::GuestAddress{0x7FF802E40031ULL});
    rosa::x86::X86State bootTimeState;
    bootTimeState.rflags = 0x8D7;
    static_cast<void>(bootTimeBlock.execute(bootTimeState, &addressSpace));
    expectEqual(bootTimeState.rax, bootTimeUsec,
                "generated libsystem boot-time load read the wrong value");
    expectEqual(bootTimeState.rflags, std::uint64_t{0x8D7},
                "x86 commpage boot-time load changed flags");
    expectEqual(addressSpace.readBytes(
                    rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                              rosa::darwin::x86CommpageNewTimeOfDayDataOffset},
                    rosa::darwin::x86CommpageNewTimeOfDayDataSize),
                std::vector<std::uint8_t>(rosa::darwin::x86CommpageNewTimeOfDayDataSize, 0),
                "x86 commpage disabled time-of-day record differs");
    // Exact first live load from ___commpage_gettimeofday_internal. A zero
    // TimeStamp_tick selects the kernel fallback after the stable snapshot.
    constexpr std::array<std::uint8_t, 5> loadTimeOfDayTimestamp{0x4D, 0x8B, 0x3C, 0x24, 0xC3};
    const auto timeOfDayBlock =
        translator.translate(loadTimeOfDayTimestamp, rosa::guest::GuestAddress{0x7FF802E313EAULL});
    rosa::x86::X86State timeOfDayState;
    timeOfDayState.r12 =
        rosa::darwin::x86CommpageBase.value + rosa::darwin::x86CommpageNewTimeOfDayDataOffset;
    timeOfDayState.r15 = UINT64_MAX;
    timeOfDayState.rflags = 0x8D7;
    static_cast<void>(timeOfDayBlock.execute(timeOfDayState, &addressSpace));
    expectEqual(timeOfDayState.r15, std::uint64_t{0},
                "generated time-of-day load did not select the fallback");
    expectEqual(timeOfDayState.rflags, std::uint64_t{0x8D7},
                "time-of-day commpage load changed flags");
    expectEqual(
        addressSpace.readU64(rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                                       rosa::darwin::x86CommpageDyldFlagsOffset}),
        dyldFlags, "x86 commpage dyld flags differ");
    expectEqual(addressSpace.readU32(
                    rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                              rosa::darwin::x86CommpageNanotimeGenerationOffset}),
                std::uint32_t{1}, "x86 commpage nanotime generation differs");
    expectEqual(
        addressSpace.readU64(rosa::guest::GuestAddress{
            rosa::darwin::x86CommpageBase.value + rosa::darwin::x86CommpageNanotimeTscBaseOffset}),
        std::uint64_t{0}, "x86 commpage nanotime TSC base differs");
    expectEqual(
        addressSpace.readU32(rosa::guest::GuestAddress{
            rosa::darwin::x86CommpageBase.value + rosa::darwin::x86CommpageNanotimeScaleOffset}),
        rosa::darwin::x86CommpageNanotimeScale, "x86 commpage nanotime scale differs");
    expectEqual(
        addressSpace.readU32(rosa::guest::GuestAddress{
            rosa::darwin::x86CommpageBase.value + rosa::darwin::x86CommpageNanotimeShiftOffset}),
        std::uint32_t{0}, "x86 commpage nanotime shift differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{
                    rosa::darwin::x86CommpageBase.value +
                    rosa::darwin::x86CommpageNanotimeNanosecondsBaseOffset}),
                std::uint64_t{0}, "x86 commpage nanotime nanoseconds base differs");

    bool unsupportedReadRejected = false;
    try {
        static_cast<void>(addressSpace.readU64(rosa::darwin::x86CommpageBase));
    } catch (const std::runtime_error &error) {
        unsupportedReadRejected =
            std::string_view(error.what()).find("unsupported sparse") != std::string_view::npos;
    }
    expect(unsupportedReadRejected, "unsupported x86 commpage data did not fail loudly");

    bool writeRejected = false;
    try {
        addressSpace.writeU64(
            rosa::guest::GuestAddress{rosa::darwin::x86CommpageBase.value +
                                      rosa::darwin::x86CommpageContinuousTimebaseOffset},
            0);
    } catch (const std::runtime_error &error) {
        writeRejected =
            std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(writeRejected, "x86 commpage mapping was not read-only");
}

void testInitialDarwinStack() {
    constexpr rosa::guest::GuestAddress base{0x700000000000ULL};
    constexpr std::size_t size = 2 * rosa::guest::guestPageSize;
    const std::vector<std::string> arguments{"/guest/program", "argument"};
    const std::vector<std::string> environment{"A=B"};
    const std::vector<std::string> apple{"executable_path=/guest/program"};
    rosa::guest::AddressSpace addressSpace;
    const rosa::guest::StartupStackBuilder builder;
    const auto stack = builder.build(addressSpace, base, size, arguments, environment, apple);
    expectEqual(stack.stackPointer.value & 0xFU, std::uint64_t{0},
                "initial stack pointer is not 16-byte aligned");
    auto cursor = stack.stackPointer.value;
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{cursor}), std::uint64_t{2},
                "initial stack argc differs");
    cursor += 8;
    const auto argv0 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    cursor += 8;
    const auto argv1 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    cursor += 16; // Move past argv[1] and the argv null to envp[0].
    const auto env0 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    cursor += 16; // Move past envp[0] and the envp null to apple[0].
    const auto apple0 = addressSpace.readU64(rosa::guest::GuestAddress{cursor});
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{argv0}), arguments[0],
                "guest argv[0] differs");
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{argv1}), arguments[1],
                "guest argv[1] differs");
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{env0}), environment[0],
                "guest envp[0] differs");
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{apple0}), apple[0],
                "guest apple[0] differs");
}

void testInitialDyldStack() {
    constexpr rosa::guest::GuestAddress base{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress executableHeader{0x100000000ULL};
    constexpr std::size_t size = 2 * rosa::guest::guestPageSize;
    const std::vector<std::string> arguments{"/guest/program"};
    const std::vector<std::string> environment;
    const std::vector<std::string> apple{"executable_path=/guest/program"};
    rosa::guest::AddressSpace addressSpace;
    const rosa::guest::StartupStackBuilder builder;
    const auto stack =
        builder.build(addressSpace, base, size, arguments, environment, apple, executableHeader);
    expectEqual(stack.stackPointer.value & 0xFU, std::uint64_t{0},
                "initial dyld stack pointer is not 16-byte aligned");
    expectEqual(addressSpace.readU64(stack.stackPointer), executableHeader.value,
                "initial dyld stack lacks the main Mach-O header");
    expectEqual(addressSpace.readU64(
                    rosa::guest::GuestAddress{stack.stackPointer.value + sizeof(std::uint64_t)}),
                std::uint64_t{1}, "initial dyld stack argc differs");
    const auto argv0 = addressSpace.readU64(
        rosa::guest::GuestAddress{stack.stackPointer.value + (2 * sizeof(std::uint64_t))});
    expectEqual(readGuestString(addressSpace, rosa::guest::GuestAddress{argv0}), arguments[0],
                "initial dyld stack argv[0] differs");
}

} // namespace

std::span<const TestCase> startupTests() {
    static const TestCase cases[]{
        {"x86 commpage", testX86Commpage},
        {"initial Darwin stack", testInitialDarwinStack},
        {"initial dyld stack", testInitialDyldStack},
    };
    return cases;
}

} // namespace rosa::tests
