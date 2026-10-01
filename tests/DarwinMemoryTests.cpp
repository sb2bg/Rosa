#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testDarwinProcInfoSetDyldImages() {
    constexpr auto procInfoNumber = UINT64_C(0x02000150);
    constexpr std::uint64_t allImageInfoAddress = 0x7FF8436AF040ULL;
    constexpr std::uint64_t allImageInfoSize = 0x170;
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = procInfoNumber;
    state.rdi = 0x0F;
    state.rsi = static_cast<std::uint64_t>(::getpid());
    state.rdx = 0xA5A5A5A5;
    state.r10 = UINT64_MAX;
    state.r8 = allImageInfoAddress;
    state.r9 = allImageInfoSize;
    state.rflags = 0x8D7;

    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF7000648A8ULL});
    expect(!outcome.exited, "PROC_INFO_CALL_SET_DYLD_IMAGES terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "PROC_INFO_CALL_SET_DYLD_IMAGES did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "PROC_INFO_CALL_SET_DYLD_IMAGES did not clear BSD carry");
    expect(dispatcher.dyldInfo().has_value(),
           "PROC_INFO_CALL_SET_DYLD_IMAGES did not register guest metadata");
    expectEqual(dispatcher.dyldInfo()->address.value, allImageInfoAddress,
                "PROC_INFO_CALL_SET_DYLD_IMAGES registered the wrong address");
    expectEqual(dispatcher.dyldInfo()->size, allImageInfoSize,
                "PROC_INFO_CALL_SET_DYLD_IMAGES registered the wrong size");

    // XNU records this task-relative range without copying from it. An
    // unmapped, non-null guest address therefore succeeds and never reaches
    // the host kernel as a pointer.
    bool guestAddressWasRead = false;
    try {
        static_cast<void>(
            addressSpace.readBytes(rosa::guest::GuestAddress{allImageInfoAddress}, 1));
        guestAddressWasRead = true;
    } catch (const std::runtime_error &) {
    }
    expect(!guestAddressWasRead, "PROC_INFO_CALL_SET_DYLD_IMAGES test address unexpectedly mapped");

    state.rax = procInfoNumber;
    state.rflags = 0x8D6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "finalized dyld metadata update returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "finalized dyld metadata update did not set BSD carry");
    expectEqual(dispatcher.dyldInfo()->address.value, allImageInfoAddress,
                "rejected dyld metadata update changed the registered address");
}

void testDarwinProcInfoRejectsInvalidDyldImages() {
    constexpr auto procInfoNumber = UINT64_C(0x02000150);
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = procInfoNumber;
    state.rdi = 0x0F;
    state.rsi = static_cast<std::uint64_t>(::getpid()) + 1;
    state.r8 = 0x1000;
    state.r9 = 0x170;
    state.rflags = 0x8D6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "foreign-pid dyld metadata returned the wrong errno");
    expect(!dispatcher.dyldInfo().has_value(), "foreign-pid dyld metadata was registered");

    state.rax = procInfoNumber;
    state.rsi = static_cast<std::uint64_t>(::getpid());
    state.r8 = 0;
    state.rflags = 0x8D6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "null dyld metadata address returned the wrong errno");

    state.rax = procInfoNumber;
    state.r8 = UINT64_MAX - 0x10;
    state.r9 = 0x20;
    state.rflags = 0x8D6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "overflowing dyld metadata range returned the wrong errno");
    expect(!dispatcher.dyldInfo().has_value(), "invalid dyld metadata range was registered");
}

void testDarwinProcInfoUniqueIdentifier() {
    constexpr auto procInfoNumber = UINT64_C(0x02000150);
    constexpr rosa::guest::GuestAddress outputPage{0x8000};
    constexpr rosa::guest::GuestAddress output{0x8100};
    constexpr rosa::guest::GuestAddress readOnlyPage{0x9000};
    constexpr rosa::guest::GuestAddress readOnlyOutput{0x9100};
    constexpr std::array<std::uint8_t, 16> executableUuid{0xCB, 0x37, 0x17, 0xC7, 0x1C, 0x8A,
                                                          0x32, 0x5F, 0x91, 0xDD, 0x67, 0xCC,
                                                          0x9F, 0xB8, 0x0E, 0x67};
    constexpr std::array<std::uint8_t, 8> sentinel{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(outputPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(readOnlyPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(readOnlyOutput, sentinel);
    expectEqual(addressSpace.protect(readOnlyPage, rosa::guest::guestPageSize,
                                     rosa::guest::Permission::Read),
                rosa::guest::ProtectResult::Success,
                "could not make unique-identifier output read-only");
    rosa::darwin::SyscallDispatcher dispatcher(nullptr, executableUuid);
    rosa::x86::X86State state;
    state.rax = procInfoNumber;
    state.rdi = 2; // PROC_INFO_CALL_PIDINFO
    state.rsi = static_cast<std::uint64_t>(::getpid());
    state.rdx = 0x11; // PROC_PIDUNIQIDENTIFIERINFO
    state.r10 = 0;
    state.r8 = output.value;
    state.r9 = 56;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30C08ULL}));
    expectEqual(state.rax, std::uint64_t{56}, "unique-identifier proc_info size differs");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "unique-identifier proc_info did not clear BSD carry");
    expectEqual(addressSpace.readBytes(output, executableUuid.size()),
                std::vector<std::uint8_t>(executableUuid.begin(), executableUuid.end()),
                "unique-identifier proc_info used the wrong executable UUID");
    expect(addressSpace.readU64(rosa::guest::GuestAddress{output.value + 16}) != 0,
           "unique-identifier proc_info returned a zero process ID");
    expect(addressSpace.readU64(rosa::guest::GuestAddress{output.value + 24}) != 0,
           "unique-identifier proc_info returned a zero parent ID");

    addressSpace.writeBytes(output, sentinel);
    state.rax = procInfoNumber;
    state.r8 = output.value;
    state.r9 = 55;
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short unique-identifier proc_info returned wrong errno");
    expect((state.rflags & 1U) != 0, "short unique-identifier proc_info did not set BSD carry");
    expectEqual(addressSpace.readBytes(output, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "short unique-identifier proc_info changed its output");

    // Observed under an AppKit fixture: the same query with arg 1 fills the
    // identical unique-identifier record.
    state.rax = procInfoNumber;
    state.rdi = 2;
    state.rsi = static_cast<std::uint64_t>(::getpid());
    state.rdx = 0x11;
    state.r10 = 1;
    state.r8 = output.value;
    state.r9 = 56;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state,
                                          rosa::guest::GuestAddress{0x7FF802E30C08ULL}));
    expectEqual(state.rax, std::uint64_t{56}, "arg-1 unique-identifier proc_info size differs");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "arg-1 unique-identifier proc_info did not clear BSD carry");
    expectEqual(addressSpace.readBytes(output, executableUuid.size()),
                std::vector<std::uint8_t>(executableUuid.begin(), executableUuid.end()),
                "arg-1 unique-identifier proc_info used the wrong executable UUID");

    state.rax = procInfoNumber;
    state.r8 = readOnlyOutput.value;
    state.r9 = 56;
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "faulted unique-identifier proc_info returned wrong errno");
    expectEqual(addressSpace.readBytes(readOnlyOutput, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "faulted unique-identifier proc_info changed its output");
}

void testDarwinProcInfoShortBsdInfo() {
    constexpr auto procInfoNumber = UINT64_C(0x02000150);
    constexpr rosa::guest::GuestAddress outputPage{0x8000};
    constexpr rosa::guest::GuestAddress output{0x8100};
    constexpr rosa::guest::GuestAddress readOnlyPage{0x9000};
    constexpr rosa::guest::GuestAddress readOnlyOutput{0x9100};
    constexpr std::array<std::uint8_t, 8> sentinel{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(outputPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(readOnlyPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(readOnlyOutput, sentinel);
    expectEqual(addressSpace.protect(readOnlyPage, rosa::guest::guestPageSize,
                                     rosa::guest::Permission::Read),
                rosa::guest::ProtectResult::Success,
                "could not make short-BSD-info output read-only");

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = procInfoNumber;
    state.rdi = 2; // PROC_INFO_CALL_PIDINFO
    state.rsi = static_cast<std::uint64_t>(::getpid());
    state.rdx = 0x0D; // PROC_PIDT_SHORTBSDINFO
    state.r10 = 1;    // Include a zombie lookup if the live lookup misses.
    state.r8 = output.value;
    state.r9 = 64;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30C08ULL}));
    expectEqual(state.rax, std::uint64_t{64}, "short BSD proc_info size differs");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "short BSD proc_info did not clear BSD carry");
    expectEqual(addressSpace.readU32(output), static_cast<std::uint32_t>(::getpid()),
                "short BSD proc_info PID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 4}),
                static_cast<std::uint32_t>(::getppid()), "short BSD proc_info parent PID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 8}),
                static_cast<std::uint32_t>(::getpgrp()),
                "short BSD proc_info process group differs");
    expect(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 12}) != 0,
           "short BSD proc_info returned a zero process status");
    expect(addressSpace.readBytes(rosa::guest::GuestAddress{output.value + 16}, 16).front() != 0,
           "short BSD proc_info returned an empty command name");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 36}),
                static_cast<std::uint32_t>(::getuid()), "short BSD proc_info UID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 40}),
                static_cast<std::uint32_t>(::getgid()), "short BSD proc_info GID differs");
    expectEqual(state.r10, std::uint64_t{1}, "short BSD proc_info changed its lookup argument");

    addressSpace.writeBytes(output, sentinel);
    state.rax = procInfoNumber;
    state.r8 = output.value;
    state.r9 = 63;
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "short short-BSD-info buffer returned wrong errno");
    expectEqual(addressSpace.readBytes(output, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "short short-BSD-info buffer changed its output");

    state.rax = procInfoNumber;
    state.r8 = readOnlyOutput.value;
    state.r9 = 64;
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "faulted short BSD proc_info returned wrong errno");
    expectEqual(addressSpace.readBytes(readOnlyOutput, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "faulted short BSD proc_info changed its output");
}

void testDarwinMprotect() {
    constexpr auto mprotectNumber = UINT64_C(0x0200004A);
    constexpr auto pageSize = rosa::guest::guestPageSize;
    constexpr rosa::guest::GuestAddress mappingBase{0x100008000ULL};
    constexpr rosa::guest::GuestAddress guardPage{0x100009000ULL};
    constexpr auto readWrite = rosa::guest::Permission::Read | rosa::guest::Permission::Write;
    constexpr auto maximum = readWrite | rosa::guest::Permission::Execute;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(mappingBase, pageSize * 3, readWrite, maximum, "BSD mprotect test");
    addressSpace.writeU64(guardPage, 0x0123456789ABCDEFULL);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = mprotectNumber;
    state.rdi = guardPage.value;
    state.rsi = pageSize;
    state.rdx = 0;
    state.r10 = 0x40000000;
    state.rflags = 0x47;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E32B78ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "mprotect(PROT_NONE) did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x46}, "mprotect(PROT_NONE) did not clear BSD carry");
    expectEqual(state.r10, std::uint64_t{0x40000000},
                "mprotect changed an ignored argument register");
    expectEqual(addressSpace.mappingCount(), std::size_t{3},
                "mprotect did not split the guest mapping");
    bool guardRejected = false;
    try {
        static_cast<void>(addressSpace.readU64(guardPage));
    } catch (const std::runtime_error &error) {
        guardRejected =
            std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(guardRejected, "mprotect(PROT_NONE) left the guest guard page readable");

    state.rax = mprotectNumber;
    state.rdi = guardPage.value;
    state.rsi = pageSize;
    state.rdx = 3;
    state.rflags = 0x3;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "mprotect(PROT_READ|PROT_WRITE) did not succeed");
    expectEqual(addressSpace.readU64(guardPage), std::uint64_t{0x0123456789ABCDEFULL},
                "mprotect did not preserve guarded guest bytes");

    state.rax = mprotectNumber;
    state.rdi = guardPage.value + 1;
    state.rsi = pageSize;
    state.rdx = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "unaligned mprotect returned the wrong errno");
    expectEqual(addressSpace.readU64(guardPage), std::uint64_t{0x0123456789ABCDEFULL},
                "invalid mprotect changed guest protection");

    state.rax = mprotectNumber;
    state.rdi = 0x200000000ULL;
    state.rsi = pageSize;
    state.rdx = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOMEM),
                "unmapped mprotect returned the wrong errno");

    state.rax = mprotectNumber;
    state.rdi = guardPage.value;
    state.rsi = pageSize;
    state.rdx = 8;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "mprotect with unknown protection bits returned the wrong errno");
}

void testDarwinMadvise() {
    constexpr auto madviseNumber = UINT64_C(0x0200004B);
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    // Observed in libsqlite3: MADV_CAN_REUSE (9) over a malloc region.
    state.rax = madviseNumber;
    state.rdi = 0x100216000ULL;
    state.rsi = 0xC000ULL;
    state.rdx = 9;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "madvise(MADV_CAN_REUSE) did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x2}, "madvise did not clear BSD carry");

    state.rax = madviseNumber;
    state.rdx = 11;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "madvise with unknown behavior returned the wrong errno");
}

void testDarwinMapWithLinking() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto mapWithLinkingNumber = UINT64_C(0x02000226);
    constexpr auto pageSize = rosa::guest::guestPageSize;
    constexpr rosa::guest::GuestAddress pathPage{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress targetPage{0x10000};
    constexpr rosa::guest::GuestAddress requestPage{0x12000};
    constexpr rosa::guest::GuestAddress regionsAddress{0x12000};
    constexpr rosa::guest::GuestAddress blobAddress{0x13000};
    constexpr std::uint64_t blobSize = 80;
    constexpr auto readWrite = rosa::guest::Permission::Read | rosa::guest::Permission::Write;

    // One page of file bytes: a bind chain entry at offset 0 (ordinal 0,
    // addend 0x10, next 2 strides) followed by a rebase entry at offset 8
    // (target 0x2000, next 0).
    std::vector<std::uint8_t> fileBytes(pageSize, 0);
    const auto writeFileU64 = [&fileBytes](std::size_t offset, std::uint64_t value) {
        std::memcpy(fileBytes.data() + offset, &value, sizeof(value));
    };
    writeFileU64(0, 0x8010000010000000ULL);
    writeFileU64(8, 0x2000ULL);

    const auto filePath = std::filesystem::current_path() / "rosa-mwl-test.bin";
    struct UnlinkGuard {
        std::filesystem::path path;
        ~UnlinkGuard() {
            std::error_code error;
            std::filesystem::remove(path, error);
        }
    };
    const UnlinkGuard guard{filePath};
    const auto hostFd = ::open(filePath.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0600);
    expect(hostFd >= 0, "could not create map_with_linking test file");
    const auto written = ::write(hostFd, fileBytes.data(), fileBytes.size());
    expect(written == static_cast<ssize_t>(fileBytes.size()),
           "could not write map_with_linking test file");
    expect(::close(hostFd) == 0, "could not close map_with_linking test file");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(pathPage, pageSize, readWrite);
    addressSpace.mapAnonymous(targetPage, pageSize, readWrite);
    addressSpace.mapAnonymous(requestPage, pageSize * 2, readWrite);
    const auto fileString = filePath.string();
    std::vector<std::uint8_t> pathBytes(fileString.begin(), fileString.end());
    pathBytes.push_back(0);
    addressSpace.writeBytes(pathAddress, pathBytes);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = O_RDONLY;
    state.rdx = 0;
    state.rflags = 0x2;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEE844ULL}));
    expectEqual(state.rax, std::uint64_t{3},
                "map_with_linking setup open returned the wrong descriptor");

    // Blob: header (40 bytes), one-entry binds table, one-segment chains.
    // Slide 0x100 rebases target 0x2000 to 0x2100; binds[0] 0x5000 plus
    // addend 0x10 resolves to 0x5010.
    std::vector<std::uint8_t> blob(blobSize, 0);
    const auto writeBlobU16 = [&blob](std::size_t offset, std::uint16_t value) {
        std::memcpy(blob.data() + offset, &value, sizeof(value));
    };
    const auto writeBlobU32 = [&blob](std::size_t offset, std::uint32_t value) {
        std::memcpy(blob.data() + offset, &value, sizeof(value));
    };
    const auto writeBlobU64 = [&blob](std::size_t offset, std::uint64_t value) {
        std::memcpy(blob.data() + offset, &value, sizeof(value));
    };
    writeBlobU32(0, 7);
    writeBlobU16(4, 0x1000);
    writeBlobU16(6, 2);
    writeBlobU32(8, 40);
    writeBlobU32(12, 1);
    writeBlobU32(16, 48);
    writeBlobU32(20, 32);
    writeBlobU64(24, 0x100);
    writeBlobU64(32, targetPage.value);
    writeBlobU64(40, 0x5000);
    writeBlobU32(48, 1);
    writeBlobU32(52, 8);
    writeBlobU32(56, 24);
    writeBlobU16(60, 0x1000);
    writeBlobU16(62, 2);
    writeBlobU64(64, 0);
    writeBlobU32(72, 0);
    writeBlobU16(76, 1);
    writeBlobU16(78, 0);
    addressSpace.writeBytes(blobAddress, blob);

    std::vector<std::uint8_t> region(sizeof(std::uint32_t) * 8, 0);
    const auto writeRegionU32 = [&region](std::size_t offset, std::uint32_t value) {
        std::memcpy(region.data() + offset, &value, sizeof(value));
    };
    const auto writeRegionU64 = [&region](std::size_t offset, std::uint64_t value) {
        std::memcpy(region.data() + offset, &value, sizeof(value));
    };
    writeRegionU32(0, 3);
    writeRegionU32(4, 3);
    writeRegionU64(8, 0);
    writeRegionU64(16, targetPage.value);
    writeRegionU64(24, pageSize);
    addressSpace.writeBytes(regionsAddress, region);

    state.rax = mapWithLinkingNumber;
    state.rdi = regionsAddress.value;
    state.rsi = 1;
    state.rdx = blobAddress.value;
    state.r10 = blobSize;
    state.r8 = 0;
    state.r9 = 0;
    state.rflags = 0x2;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEE80CULL}));
    expectEqual(state.rax, std::uint64_t{0}, "map_with_linking did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x2}, "map_with_linking did not clear BSD carry");
    expectEqual(addressSpace.readU64(targetPage), std::uint64_t{0x5010},
                "map_with_linking bind fixup differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{targetPage.value + 8}),
                std::uint64_t{0x2100}, "map_with_linking rebase fixup differs");

    state.rax = mapWithLinkingNumber;
    state.rsi = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "empty map_with_linking request returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "empty map_with_linking request did not set BSD carry");

    writeRegionU32(0, 9);
    addressSpace.writeBytes(regionsAddress, region);
    state.rax = mapWithLinkingNumber;
    state.rsi = 1;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "map_with_linking with an unknown descriptor returned the wrong errno");

    state.rax = mapWithLinkingNumber;
    state.rdx = 0x50000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "map_with_linking with an unmapped blob returned the wrong errno");
}

void testDarwinMunmap() {
    constexpr auto munmapNumber = UINT64_C(0x02000049);
    constexpr rosa::guest::GuestAddress mappingBase{0x4000};
    constexpr auto pageSize = rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(mappingBase, pageSize * 3,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "BSD munmap test");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x5000}, 0x0123456789ABCDEFULL);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = munmapNumber;
    state.rdi = 0x5000;
    state.rsi = 8;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8E6F0ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "munmap did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "munmap did not clear BSD carry");
    expectEqual(addressSpace.mappingCount(), std::size_t{2},
                "munmap did not split its guest mapping");
    bool targetUnmapped = false;
    try {
        static_cast<void>(addressSpace.readU64(rosa::guest::GuestAddress{0x5000}));
    } catch (const std::runtime_error &error) {
        targetUnmapped = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(targetUnmapped, "munmap left its rounded guest page mapped");

    const auto beforeInvalid = addressSpace.mappingInfos();
    for (const auto [address, size] : std::array<std::pair<std::uint64_t, std::uint64_t>, 3>{
             std::pair{std::uint64_t{0x4001}, std::uint64_t{pageSize}},
             std::pair{std::uint64_t{0x4000}, std::uint64_t{0}},
             std::pair{UINT64_MAX - pageSize + 1, std::uint64_t{pageSize}}}) {
        state.rax = munmapNumber;
        state.rdi = address;
        state.rsi = size;
        state.rflags = 0x8D6;
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
        expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                    "invalid munmap returned the wrong errno");
        expectEqual(state.rflags, std::uint64_t{0x8D7}, "invalid munmap did not set BSD carry");
    }
    expectEqual(addressSpace.mappingInfos().size(), beforeInvalid.size(),
                "invalid munmap changed guest mappings");

    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, pageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "BSD munmap hole test");
    state.rax = munmapNumber;
    state.rdi = 0x8000;
    state.rsi = pageSize * 3;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "munmap range containing holes did not succeed");
}

void testGeneratedDarwinMunmap() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress target{0x8000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x49, 0x00, 0x00, 0x02, // mov eax, 0x2000049
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(target, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rdi = target.value;
    state.rsi = 1;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rflags = 0xAD7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated munmap terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "generated munmap did not succeed");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "generated munmap did not clear BSD carry");
    bool targetUnmapped = false;
    try {
        static_cast<void>(addressSpace.readBytes(target, 1));
    } catch (const std::runtime_error &error) {
        targetUnmapped = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(targetUnmapped, "generated munmap left guest memory mapped");
}

void testGeneratedDarwinGetpid() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x14, 0x00, 0x00, 0x02, // mov eax, 0x2000014
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated getpid terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(::getpid()),
                "generated getpid returned the wrong process identity");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated getpid did not preserve SYSCALL fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated getpid did not save input flags in R11");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "generated getpid did not clear the BSD error flag");
}

void testGeneratedDarwinThreadSelfid() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x74, 0x01, 0x00, 0x02, // mov eax, 0x2000174
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated thread_selfid terminated the guest");
    expectEqual(state.rax, std::uint64_t{1},
                "generated thread_selfid returned the wrong guest identity");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated thread_selfid did not preserve SYSCALL fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated thread_selfid did not save input flags in R11");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "generated thread_selfid did not clear the BSD error flag");
}

void testDarwinGetentropy() {
    constexpr auto callNumber = UINT64_C(0x020001F4);
    constexpr rosa::guest::GuestAddress buffer{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    std::array<std::uint8_t, 144> sentinel{};
    sentinel.fill(0xA5);
    addressSpace.writeBytes(buffer, sentinel);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = callNumber;
    state.rdi = buffer.value;
    state.rsi = 128;
    state.rflags = 0xAD7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF800064C50ULL});
    expect(!outcome.exited, "getentropy terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "getentropy did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "getentropy did not apply BSD success flags");
    const auto entropy = addressSpace.readBytes(buffer, 128);
    expect(std::ranges::any_of(entropy, [](std::uint8_t byte) { return byte != 0xA5; }),
           "getentropy left the entire guest buffer unchanged");
    const auto tail = addressSpace.readBytes(rosa::guest::GuestAddress{buffer.value + 128}, 16);
    expect(std::ranges::all_of(tail, [](std::uint8_t byte) { return byte == 0xA5; }),
           "getentropy wrote beyond the requested guest range");

    const std::array marker{std::uint8_t{0x5A}};
    constexpr rosa::guest::GuestAddress oversizedBuffer{0x8200};
    addressSpace.writeBytes(oversizedBuffer, marker);
    state.rax = callNumber;
    state.rdi = oversizedBuffer.value;
    state.rsi = 257;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "oversized getentropy returned the wrong guest errno");
    expectEqual(state.rflags, std::uint64_t{0x3}, "oversized getentropy did not set BSD carry");
    expectEqual(addressSpace.readBytes(oversizedBuffer, 1).front(), std::uint8_t{0x5A},
                "oversized getentropy changed guest memory");

    state.rax = callNumber;
    state.rdi = 0x8300;
    state.rsi = 256;
    state.rflags = 0x3;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "maximum-sized getentropy request failed");
    expectEqual(state.rflags, std::uint64_t{0x2},
                "maximum-sized getentropy did not clear BSD carry");

    constexpr rosa::guest::GuestAddress crossPageBuffer{0x8FF0};
    std::array<std::uint8_t, 16> crossPageSentinel{};
    crossPageSentinel.fill(0x3C);
    addressSpace.writeBytes(crossPageBuffer, crossPageSentinel);
    state.rax = callNumber;
    state.rdi = crossPageBuffer.value;
    state.rsi = 32;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "cross-page getentropy returned the wrong guest errno");
    expectEqual(state.rflags, std::uint64_t{0x3}, "cross-page getentropy did not set BSD carry");
    expectEqual(addressSpace.readBytes(crossPageBuffer, 16), std::vector<std::uint8_t>(16, 0x3C),
                "cross-page getentropy partially changed guest memory");

    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapAnonymous(rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read);
    state.rax = callNumber;
    state.rdi = 0x9000;
    state.rsi = 16;
    state.rflags = 0x2;
    static_cast<void>(
        dispatcher.dispatch(readOnlyAddressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "getentropy read-only target returned the wrong guest errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "getentropy read-only target did not set BSD carry");

    rosa::guest::AddressSpace emptyAddressSpace;
    state.rax = callNumber;
    state.rdi = UINT64_MAX;
    state.rsi = 0;
    state.rflags = 0x3;
    static_cast<void>(
        dispatcher.dispatch(emptyAddressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0},
                "zero-length getentropy rejected an unused guest pointer");
    expectEqual(state.rflags, std::uint64_t{0x2}, "zero-length getentropy did not clear BSD carry");
}

void testDarwinFsgetpath() {
    constexpr auto callNumber = UINT64_C(0x020001AB);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress guestFsidAddress{0x8100};
    constexpr rosa::guest::GuestAddress output{0x8200};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 8> guestFsidBytes{};
    addressSpace.writeBytes(guestFsidAddress, guestFsidBytes);
    std::array<std::uint8_t, 64> sentinel{};
    sentinel.fill(0xA5);
    addressSpace.writeBytes(output, sentinel);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = callNumber;
    state.rdi = output.value;
    state.rsi = 0x400;
    state.rdx = guestFsidAddress.value;
    state.r10 = 0;
    state.rflags = 0xAD7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF800064BC0ULL});
    expect(!outcome.exited, "empty-tuple fsgetpath terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOTSUP),
                "empty-tuple fsgetpath returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "empty-tuple fsgetpath did not set BSD carry");
    expectEqual(addressSpace.readBytes(output, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "failed empty-tuple fsgetpath changed its output buffer");

    state.rax = callNumber;
    state.rdi = output.value;
    state.rsi = 0x400;
    state.rdx = 0x9000;
    state.r10 = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "fsgetpath invalid guest fsid returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "fsgetpath invalid guest fsid did not set BSD carry");

    state.rax = callNumber;
    state.rdi = output.value;
    state.rsi = 8193;
    state.rdx = guestFsidAddress.value;
    state.r10 = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "oversized fsgetpath returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3}, "oversized fsgetpath did not set BSD carry");

    constexpr std::array<std::uint8_t, 8> nonemptyFsidBytes{1};
    addressSpace.writeBytes(guestFsidAddress, nonemptyFsidBytes);
    state.rax = callNumber;
    state.rdi = output.value;
    state.rsi = 0x400;
    state.rdx = guestFsidAddress.value;
    state.r10 = 2;
    state.rflags = 0x2;
    bool unsupportedIdentity = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedIdentity = std::string_view(error.what()).find("guest VFS identity resolver") !=
                              std::string_view::npos;
    }
    expect(unsupportedIdentity,
           "nonempty fsgetpath identity did not stop at the guest VFS boundary");
}

void testDarwinCsrCheck() {
    constexpr auto callNumber = UINT64_C(0x020001E3);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress maskAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 4> appleInternalMask{0x10, 0, 0, 0};
    addressSpace.writeBytes(maskAddress, appleInternalMask);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = callNumber;
    state.rdi = 0;
    state.rsi = maskAddress.value;
    state.rdx = sizeof(std::uint32_t);
    state.rflags = 0xAD6;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF7000051E8ULL});
    expect(!outcome.exited, "csrctl check terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(EPERM),
                "restrictive guest csrctl accepted AppleInternal");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "failed csrctl check did not set BSD carry");
    expectEqual(addressSpace.readBytes(maskAddress, appleInternalMask.size()),
                std::vector<std::uint8_t>(appleInternalMask.begin(), appleInternalMask.end()),
                "csrctl check changed its input mask");

    constexpr std::array<std::uint8_t, 4> zeroMask{};
    addressSpace.writeBytes(maskAddress, zeroMask);
    state.rax = callNumber;
    state.rdi = 0;
    state.rsi = maskAddress.value;
    state.rdx = sizeof(std::uint32_t);
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "zero-mask csrctl check failed");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "successful csrctl check did not clear BSD carry");

    state.rax = callNumber;
    state.rdi = 0;
    state.rsi = UINT64_MAX;
    state.rdx = 8;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "wrong-size csrctl check inspected its guest pointer");
    expectEqual(state.rflags, std::uint64_t{0x3}, "wrong-size csrctl check did not set BSD carry");

    state.rax = callNumber;
    state.rdi = 0;
    state.rsi = 0x9000;
    state.rdx = sizeof(std::uint32_t);
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "csrctl invalid guest pointer returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "csrctl invalid guest pointer did not set BSD carry");
}

void testGeneratedDarwinCsrCheck() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress maskAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0xE3, 0x01, 0x00, 0x02, // mov eax, 0x20001e3
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(maskAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 4> appleInternalMask{0x10, 0, 0, 0};
    addressSpace.writeBytes(maskAddress, appleInternalMask);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rdi = 0;
    state.rsi = maskAddress.value;
    state.rdx = sizeof(std::uint32_t);
    state.rflags = 0x8D6;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated csrctl check terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(EPERM),
                "generated csrctl check returned the wrong errno");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated csrctl check lost SYSCALL fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D6}, "generated csrctl check did not save input flags");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "generated csrctl check did not set BSD carry");
}

void testDarwinSharedRegionCheck() {
    constexpr auto callNumber = UINT64_C(0x02000126);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress output{0x8100};
    constexpr std::uint64_t sentinel = 0x0123456789ABCDEFULL;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(output, sentinel);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = callNumber;
    state.rdi = output.value;
    state.rflags = 0xAD6;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF800064A40ULL});
    expect(!outcome.exited, "shared-region check terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "missing shared region returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "missing shared region did not set BSD carry");
    expectEqual(addressSpace.readU64(output), sentinel,
                "missing shared region changed its output pointer");

    rosa::guest::AddressSpace emptyAddressSpace;
    state.rax = callNumber;
    state.rdi = UINT64_MAX - 8;
    state.rflags = 0x2;
    static_cast<void>(
        dispatcher.dispatch(emptyAddressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "missing shared region inspected an invalid guest pointer");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "invalid-pointer shared-region check did not set BSD carry");
}

void testGeneratedDarwinGetentropy() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress buffer{0x8000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0xF4, 0x01, 0x00, 0x02, // mov eax, 0x20001f4
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(buffer, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rdi = buffer.value;
    state.rsi = 32;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated getentropy terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "generated getentropy did not return success");
    expectEqual(state.rcx, std::uint64_t{0x1007}, "generated getentropy lost SYSCALL fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D7}, "generated getentropy did not save input flags");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "generated getentropy did not clear BSD carry");
}

void testDarwinThreadFastSetCthreadSelf() {
    constexpr auto callNumber = UINT64_C(0x03000003);
    constexpr std::uint64_t guestTsdBase = 0x00007FF8000C8F20ULL;
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = callNumber;
    state.rdi = guestTsdBase;
    state.rflags = 0x8D7;

    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF800064E32ULL});
    expect(!outcome.exited, "thread_fast_set_cthread_self terminated the guest");
    expectEqual(state.gsBase, guestTsdBase,
                "thread_fast_set_cthread_self stored the wrong guest GS base");
    expectEqual(state.rax, std::uint64_t{0x0F},
                "thread_fast_set_cthread_self returned the wrong selector");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "thread_fast_set_cthread_self applied BSD flag semantics");

    state.rax = callNumber;
    state.rdi = 0xFFFF800000000000ULL;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.gsBase, std::uint64_t{0},
                "thread_fast_set_cthread_self retained a non-user GS base");
    expectEqual(state.rax, std::uint64_t{0x0F},
                "invalid thread_fast_set_cthread_self changed its selector return");
}

void testGeneratedDarwinThreadFastSetCthreadSelf() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x03, 0x00, 0x00, 0x03, // mov eax, 0x3000003
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rdi = 0x00007FF8000C8F20ULL;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated thread_fast_set_cthread_self terminated the guest");
    expectEqual(state.rax, std::uint64_t{0x0F},
                "generated thread_fast_set_cthread_self returned the wrong selector");
    expectEqual(state.gsBase, std::uint64_t{0x00007FF8000C8F20ULL},
                "generated thread_fast_set_cthread_self lost the guest GS base");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated machdep call did not preserve SYSCALL fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated machdep call did not save input flags in R11");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "generated machdep call changed guest flags");
}

} // namespace

std::span<const TestCase> darwinMemoryTests() {
    static const TestCase cases[]{
        {"Darwin proc_info set dyld images", testDarwinProcInfoSetDyldImages},
        {"Darwin proc_info rejects invalid dyld images", testDarwinProcInfoRejectsInvalidDyldImages},
        {"Darwin proc_info unique identifier", testDarwinProcInfoUniqueIdentifier},
        {"Darwin proc_info short BSD info", testDarwinProcInfoShortBsdInfo},
        {"Darwin mprotect", testDarwinMprotect},
        {"Darwin madvise", testDarwinMadvise},
        {"Darwin map_with_linking", testDarwinMapWithLinking},
        {"Darwin munmap", testDarwinMunmap},
        {"generated Darwin munmap", testGeneratedDarwinMunmap},
        {"generated Darwin getpid", testGeneratedDarwinGetpid},
        {"generated Darwin thread_selfid", testGeneratedDarwinThreadSelfid},
        {"Darwin getentropy", testDarwinGetentropy},
        {"Darwin fsgetpath", testDarwinFsgetpath},
        {"Darwin csrctl check", testDarwinCsrCheck},
        {"generated Darwin csrctl check", testGeneratedDarwinCsrCheck},
        {"Darwin shared-region check", testDarwinSharedRegionCheck},
        {"generated Darwin getentropy", testGeneratedDarwinGetentropy},
        {"Darwin thread_fast_set_cthread_self", testDarwinThreadFastSetCthreadSelf},
        {"generated Darwin thread_fast_set_cthread_self", testGeneratedDarwinThreadFastSetCthreadSelf},
    };
    return cases;
}

} // namespace rosa::tests
