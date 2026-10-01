#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testDarwinAccessChrootMarker() {
    constexpr auto accessNumber = UINT64_C(0x02000021);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr std::string_view marker = "/AppleInternal/XBS/.isChrooted";
    std::vector<std::uint8_t> path(marker.begin(), marker.end());
    path.push_back(0);

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, path);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = accessNumber;
    state.rdi = pathAddress.value;
    state.rsi = F_OK;
    state.rflags = 0xAD6;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30318ULL}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                "chroot-marker access probe returned the wrong errno");
    expect((state.rflags & std::uint64_t{1}) != 0,
           "chroot-marker access probe did not set BSD carry");

    state.rax = accessNumber;
    state.rdi = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "access invalid path returned the wrong errno");
    expect((state.rflags & std::uint64_t{1}) != 0, "access invalid path did not set BSD carry");
}

void testDarwinAccessMappedDirectory() {
    constexpr auto accessNumber = UINT64_C(0x02000021);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    rosa::darwin::SyscallDispatcher dispatcher;
    auto directory = dispatcher.fileSpace().currentDirectory() / "test-fixtures";
    if (!std::filesystem::is_directory(directory)) {
        directory = dispatcher.fileSpace().currentDirectory() / "build/debug/test-fixtures";
    }
    expect(std::filesystem::is_directory(directory), "mapped access test directory is missing");
    const auto directoryString = directory.string();
    std::vector<std::uint8_t> path(directoryString.begin(), directoryString.end());
    path.push_back(0);

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, path);
    rosa::x86::X86State state;
    state.rax = accessNumber;
    state.rdi = pathAddress.value;
    state.rsi = R_OK;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30318ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "mapped-directory access did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "mapped-directory access did not clear BSD carry");

    const auto missingString = (directory / "missing-rosa-entry").string();
    std::vector<std::uint8_t> missing(missingString.begin(), missingString.end());
    missing.push_back(0);
    addressSpace.writeBytes(pathAddress, missing);
    state.rax = accessNumber;
    state.rsi = F_OK;
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                "missing mapped-path access returned the wrong errno");
    expect((state.rflags & 1U) != 0, "missing mapped-path access did not set BSD carry");
}

void testDarwinAccessRelativePath() {
    constexpr auto accessNumber = UINT64_C(0x02000021);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;

    // sqlite probes its default ":memory:" database name, which never
    // exists as a file in the guest working directory.
    const std::string missing = ":memory:";
    std::vector<std::uint8_t> missingBytes(missing.begin(), missing.end());
    missingBytes.push_back(0);
    addressSpace.writeBytes(pathAddress, missingBytes);
    state.rax = accessNumber;
    state.rdi = pathAddress.value;
    state.rsi = F_OK;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                "relative missing-path access returned the wrong errno");
    expect((state.rflags & 1U) != 0, "relative missing-path access did not set BSD carry");

    // A relative path resolving inside the guest working directory answers
    // from host metadata like the absolute mapped probes.
    std::string presentName;
    if (std::filesystem::is_directory(dispatcher.fileSpace().currentDirectory() /
                                      "test-fixtures")) {
        presentName = "test-fixtures";
    } else if (std::filesystem::is_directory(dispatcher.fileSpace().currentDirectory() /
                                             "build/debug/test-fixtures")) {
        presentName = "build/debug/test-fixtures";
    }
    expect(!presentName.empty(), "relative access fixture is missing");
    std::vector<std::uint8_t> presentBytes(presentName.begin(), presentName.end());
    presentBytes.push_back(0);
    addressSpace.writeBytes(pathAddress, presentBytes);
    state.rax = accessNumber;
    state.rsi = R_OK;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "relative present-path access did not succeed");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "relative present-path access did not clear BSD carry");

    // Modes outside the access bitmask fail instead of reaching the VFS.
    state.rax = accessNumber;
    state.rsi = 0x80;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "out-of-range access mode returned the wrong errno");
}

void testDarwinGetattrlistRootVolume() {
    constexpr auto getattrlistNumber = UINT64_C(0x020000DC);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress path{0x8010};
    constexpr rosa::guest::GuestAddress attributeList{0x8100};
    constexpr rosa::guest::GuestAddress output{0x8200};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(path, std::array<std::uint8_t, 2>{'/', 0});
    constexpr std::array<std::uint8_t, 24> requestedAttributes{
        0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    addressSpace.writeBytes(attributeList, requestedAttributes);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = getattrlistNumber;
    state.rdi = path.value;
    state.rsi = attributeList.value;
    state.rdx = output.value;
    state.r10 = 64;
    state.r8 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8D124ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "root getattrlist did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "root getattrlist did not clear BSD carry");
    expectEqual(addressSpace.readU32(output), std::uint32_t{64},
                "root getattrlist returned length differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 4}), std::uint32_t{1},
                "root getattrlist device differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 8}), std::uint32_t{1},
                "root getattrlist fsid differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 16}),
                std::uint32_t{0x03000000}, "root getattrlist format capabilities differ");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 20}),
                std::uint32_t{2}, "root getattrlist interface capabilities differ");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{output.value + 48}, 16),
                std::vector<std::uint8_t>({'R', 'O', 'S', 'A', '-', 'R', 'O', 'O', 'T', '-', 'V',
                                           'O', 'L', 'U', 'M', 'E'}),
                "root getattrlist UUID differs");

    state.rax = getattrlistNumber;
    state.rdx = 0xA000;
    state.r10 = 64;
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "root getattrlist invalid output returned the wrong errno");
    expect((state.rflags & 1U) != 0, "root getattrlist invalid output did not set BSD carry");
}

void testDarwinGetattrlistMappedFileFullPath() {
    constexpr auto getattrlistNumber = UINT64_C(0x020000DC);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8010};
    constexpr rosa::guest::GuestAddress attributeList{0x8100};
    constexpr rosa::guest::GuestAddress output{0x8200};
    constexpr rosa::guest::GuestAddress readOnlyPage{0x9000};
    constexpr rosa::guest::GuestAddress readOnlyOutput{0x9100};
    rosa::darwin::SyscallDispatcher dispatcher;
    auto fixturePath =
        dispatcher.fileSpace().currentDirectory() / "test-fixtures/hello-darwin-x86_64";
    if (!std::filesystem::is_regular_file(fixturePath)) {
        fixturePath = dispatcher.fileSpace().currentDirectory() /
                      "build/debug/test-fixtures/hello-darwin-x86_64";
    }
    const auto path = fixturePath.string();
    expect(std::filesystem::is_regular_file(path), "FULLPATH getattrlist fixture is missing");
    std::vector<std::uint8_t> pathBytes(path.begin(), path.end());
    pathBytes.push_back(0);
    const auto expectedSize =
        static_cast<std::uint32_t>((12U + pathBytes.size() + 3U) & ~std::size_t{3U});

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(readOnlyPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, pathBytes);
    constexpr std::array<std::uint8_t, 24> requestedAttributes{
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    addressSpace.writeBytes(attributeList, requestedAttributes);
    constexpr std::array<std::uint8_t, 8> sentinel{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28};
    addressSpace.writeBytes(rosa::guest::GuestAddress{output.value + expectedSize}, sentinel);

    rosa::x86::X86State state;
    state.rax = getattrlistNumber;
    state.rdi = pathAddress.value;
    state.rsi = attributeList.value;
    state.rdx = output.value;
    state.r10 = 0x40C;
    state.r8 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30300ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "FULLPATH getattrlist did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "FULLPATH getattrlist did not clear BSD carry");
    expectEqual(addressSpace.readU32(output), expectedSize,
                "FULLPATH getattrlist record length differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 4}), std::uint32_t{8},
                "FULLPATH getattrlist attrreference offset differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 8}),
                static_cast<std::uint32_t>(pathBytes.size()),
                "FULLPATH getattrlist attrreference length differs");
    expectEqual(
        addressSpace.readBytes(rosa::guest::GuestAddress{output.value + 12}, pathBytes.size()),
        pathBytes, "FULLPATH getattrlist path bytes differ");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{output.value + expectedSize},
                                       sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "FULLPATH getattrlist wrote past its record");

    addressSpace.writeBytes(output, sentinel);
    state.rax = getattrlistNumber;
    state.rdx = output.value;
    state.r10 = 4;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "truncated FULLPATH getattrlist did not succeed");
    expectEqual(addressSpace.readU32(output), expectedSize,
                "truncated FULLPATH getattrlist did not report full size");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{output.value + 4}, 4),
                std::vector<std::uint8_t>(sentinel.begin() + 4, sentinel.end()),
                "truncated FULLPATH getattrlist wrote past its buffer");

    addressSpace.writeBytes(readOnlyOutput, sentinel);
    expectEqual(addressSpace.protect(readOnlyPage, rosa::guest::guestPageSize,
                                     rosa::guest::Permission::Read),
                rosa::guest::ProtectResult::Success, "could not make FULLPATH output read-only");
    state.rax = getattrlistNumber;
    state.rdx = readOnlyOutput.value;
    state.r10 = 0x40C;
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "FULLPATH getattrlist invalid output returned wrong errno");
    expect((state.rflags & 1U) != 0, "FULLPATH getattrlist invalid output did not set BSD carry");
    expectEqual(addressSpace.readBytes(readOnlyOutput, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "faulted FULLPATH getattrlist changed its output");
}

void testDarwinFstatat64SyntheticDirectory() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto openatNumber = UINT64_C(0x020001CF);
    constexpr auto fstatat64Number = UINT64_C(0x020001D6);
    constexpr std::uint32_t rootFlags = 0x20100000;
    constexpr std::uint32_t directoryFlags = 0x00100000;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress rootPathAddress{0x8100};
    constexpr rosa::guest::GuestAddress cryptexPathAddress{0x8120};
    constexpr rosa::guest::GuestAddress dyldPathAddress{0x8160};
    constexpr rosa::guest::GuestAddress missingPathAddress{0x8190};
    constexpr rosa::guest::GuestAddress statAddress{0x8300};
    constexpr std::array<std::uint8_t, 2> rootPath{'/', 0};
    constexpr std::string_view cryptexPath = "System/Cryptexes/OS";
    constexpr std::string_view dyldPath = "System/Library/dyld/";
    constexpr std::array<std::uint8_t, 8> missingPath{'m', 'i', 's', 's', 'i', 'n', 'g', 0};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(rootPathAddress, rootPath);
    addressSpace.writeBytes(
        cryptexPathAddress,
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t *>(cryptexPath.data()),
                                      cryptexPath.size()});
    addressSpace.writeBytes(
        rosa::guest::GuestAddress{cryptexPathAddress.value + cryptexPath.size()},
        std::array<std::uint8_t, 1>{0});
    addressSpace.writeBytes(
        dyldPathAddress,
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t *>(dyldPath.data()),
                                      dyldPath.size()});
    addressSpace.writeBytes(rosa::guest::GuestAddress{dyldPathAddress.value + dyldPath.size()},
                            std::array<std::uint8_t, 1>{0});
    addressSpace.writeBytes(missingPathAddress, missingPath);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;

    state.rax = openNumber;
    state.rdi = rootPathAddress.value;
    state.rsi = rootFlags;
    state.rdx = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{3}, "fstatat64 setup did not open the guest root");

    state.rax = openatNumber;
    state.rdi = 3;
    state.rsi = cryptexPathAddress.value;
    state.rdx = directoryFlags;
    state.r10 = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{4}, "fstatat64 setup did not open the cryptex directory");

    constexpr std::array<std::uint8_t, 144> sentinel = [] {
        std::array<std::uint8_t, 144> bytes{};
        bytes.fill(0xA5);
        return bytes;
    }();
    addressSpace.writeBytes(statAddress, sentinel);
    state.rax = fstatat64Number;
    state.rdi = 4;
    state.rsi = dyldPathAddress.value;
    state.rdx = statAddress.value;
    state.r10 = 0;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEEBD8ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "fstatat64 did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "fstatat64 did not clear BSD carry");

    const auto metadata = addressSpace.readBytes(statAddress, sentinel.size());
    const auto loadU16 = [&metadata](std::size_t offset) {
        std::uint16_t value = 0;
        std::memcpy(&value, metadata.data() + offset, sizeof(value));
        return value;
    };
    const auto loadU32 = [&metadata](std::size_t offset) {
        std::uint32_t value = 0;
        std::memcpy(&value, metadata.data() + offset, sizeof(value));
        return value;
    };
    const auto loadU64 = [&metadata](std::size_t offset) {
        std::uint64_t value = 0;
        std::memcpy(&value, metadata.data() + offset, sizeof(value));
        return value;
    };
    expectEqual(loadU16(4), std::uint16_t{0040555}, "fstatat64 returned the wrong directory mode");
    expectEqual(loadU16(6), std::uint16_t{2}, "fstatat64 returned the wrong directory link count");
    expectEqual(loadU64(8), std::uint64_t{2}, "fstatat64 returned the wrong synthetic inode");
    expectEqual(loadU32(112), static_cast<std::uint32_t>(rosa::guest::guestPageSize),
                "fstatat64 returned the wrong block size");
    expect(std::all_of(metadata.begin() + 116, metadata.end(),
                       [](std::uint8_t byte) { return byte == 0; }),
           "fstatat64 did not zero reserved guest stat64 fields");

    addressSpace.writeBytes(statAddress, sentinel);
    state.rax = fstatat64Number;
    state.rdi = 99;
    state.rsi = dyldPathAddress.value;
    state.rdx = statAddress.value;
    state.r10 = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "fstatat64 invalid dirfd returned the wrong errno");
    expectEqual(addressSpace.readBytes(statAddress, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "failed fstatat64 changed guest stat memory");

    state.rax = fstatat64Number;
    state.rdi = 4;
    state.rsi = missingPathAddress.value;
    state.rdx = statAddress.value;
    state.r10 = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                "fstatat64 missing path returned the wrong errno");

    state.rax = fstatat64Number;
    state.rdi = 4;
    state.rsi = dyldPathAddress.value;
    state.rdx = 0x9000;
    state.r10 = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "fstatat64 invalid stat pointer returned the wrong errno");
}

void testDarwinOpenReadOnlyUserFile() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    const auto fixturePath =
        std::filesystem::canonical(std::filesystem::path{ROSA_TEST_HELLO_MACHO_PATH});
    const auto fixtureString = fixturePath.string();
    std::vector<std::uint8_t> fixtureBytes(fixtureString.begin(), fixtureString.end());
    fixtureBytes.push_back(0);
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, fixtureBytes);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = O_RDONLY;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEE844ULL}));
    expectEqual(state.rax, std::uint64_t{3},
                "read-only guest user-file open returned the wrong descriptor");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "read-only guest user-file open did not clear BSD carry");
    const auto *opened = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{3});
    expect(opened != nullptr && opened->kind == rosa::darwin::GuestFileKind::HostReadOnlyFile &&
               opened->guestPath == fixturePath && opened->flags == O_RDONLY,
           "read-only guest user-file open stored the wrong metadata");

    const auto missingString = fixtureString + ".missing";
    std::vector<std::uint8_t> missingBytes(missingString.begin(), missingString.end());
    missingBytes.push_back(0);
    addressSpace.writeBytes(pathAddress, missingBytes);
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = O_RDONLY;
    state.rdx = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                "missing read-only guest file returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "missing read-only guest file did not set BSD carry");
    expectEqual(dispatcher.fileSpace().size(), std::size_t{1},
                "failed read-only guest open allocated a descriptor");
}

void testDarwinOpenRelativeReadOnlyFile() {
    // Observed under grep: open(".git/HEAD", O_RDONLY) with a relative path.
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    const auto fixturePath =
        std::filesystem::canonical(std::filesystem::path{ROSA_TEST_HELLO_MACHO_PATH});
    const auto relativePath =
        std::filesystem::relative(fixturePath, std::filesystem::current_path());
    const auto relativeString = relativePath.string();
    expect(!relativePath.empty() && !std::filesystem::path{relativeString}.is_absolute(),
           "relative open fixture did not produce a relative path");
    std::vector<std::uint8_t> relativeBytes(relativeString.begin(), relativeString.end());
    relativeBytes.push_back(0);
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, relativeBytes);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = O_RDONLY;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30330ULL}));
    expectEqual(state.rax, std::uint64_t{3},
                "relative read-only guest open returned the wrong descriptor");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "relative read-only guest open did not clear BSD carry");
    const auto *opened = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{3});
    expect(opened != nullptr && opened->kind == rosa::darwin::GuestFileKind::HostReadOnlyFile &&
               opened->guestPath == fixturePath && opened->flags == O_RDONLY,
           "relative read-only guest open stored the wrong metadata");

    // A relative path escaping the current directory must stay loud.
    // ".." always resolves to the existing parent, which is outside the sandbox.
    constexpr std::array<std::uint8_t, 3> escapePath{'.', '.', 0};
    addressSpace.writeBytes(pathAddress, escapePath);
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = O_RDONLY;
    state.rdx = 0;
    state.rflags = 0x2;
    bool escaped = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        escaped = std::string_view(error.what()).find("no mapping for read-only path") !=
                  std::string_view::npos;
    }
    expect(escaped, "read-only guest open outside the sandbox did not fail loudly");
    expectEqual(dispatcher.fileSpace().size(), std::size_t{1},
                "escaped read-only guest open allocated a descriptor");
}

void testDarwinReadHostReadOnlyFile() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto readNumber = UINT64_C(0x02000003);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress bufferAddress{0x9000};
    const auto fixturePath =
        std::filesystem::canonical(std::filesystem::path{ROSA_TEST_HELLO_MACHO_PATH});
    std::ifstream fixtureStream(fixturePath, std::ios::binary);
    std::vector<std::uint8_t> fixtureBytes((std::istreambuf_iterator<char>(fixtureStream)),
                                           std::istreambuf_iterator<char>());
    expect(!fixtureBytes.empty(), "read test fixture is empty");
    const auto fixtureString = fixturePath.string();
    std::vector<std::uint8_t> pathBytes(fixtureString.begin(), fixtureString.end());
    pathBytes.push_back(0);
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize * 2,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, pathBytes);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = O_RDONLY;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{3}, "read-test open returned the wrong descriptor");

    constexpr std::uint64_t firstCount = 64;
    state.rax = readNumber;
    state.rdi = 3;
    state.rsi = bufferAddress.value;
    state.rdx = firstCount;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    const auto expectedFirst =
        std::min<std::size_t>(firstCount, fixtureBytes.size());
    expectEqual(state.rax, expectedFirst, "read-only file read returned the wrong count");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "read-only file read did not clear BSD carry");
    expect(addressSpace.readBytes(bufferAddress, expectedFirst) ==
               std::vector<std::uint8_t>(fixtureBytes.begin(),
                                         fixtureBytes.begin() +
                                             static_cast<std::ptrdiff_t>(expectedFirst)),
           "read-only file read returned the wrong bytes");

    // A second read must advance sequentially from the stored file position.
    state.rax = readNumber;
    state.rdi = 3;
    state.rsi = bufferAddress.value;
    state.rdx = firstCount;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    const auto expectedSecond =
        std::min<std::size_t>(firstCount, fixtureBytes.size() - expectedFirst);
    expectEqual(state.rax, expectedSecond, "sequential read returned the wrong count");
    expect(addressSpace.readBytes(bufferAddress, expectedSecond) ==
               std::vector<std::uint8_t>(fixtureBytes.begin() +
                                             static_cast<std::ptrdiff_t>(expectedFirst),
                                         fixtureBytes.begin() +
                                             static_cast<std::ptrdiff_t>(expectedFirst +
                                                                         expectedSecond)),
           "sequential read did not advance the file position");

    // Drain the remainder in bounded chunks, then verify end-of-file is sticky.
    std::size_t drained = expectedFirst + expectedSecond;
    while (drained < fixtureBytes.size()) {
        state.rax = readNumber;
        state.rdi = 3;
        state.rsi = bufferAddress.value;
        state.rdx = 1024;
        state.rflags = 0x8D7;
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
        expect(state.rax > 0 && state.rax <= 1024, "draining read returned no progress");
        const auto chunk = static_cast<std::size_t>(state.rax);
        expect(addressSpace.readBytes(bufferAddress, chunk) ==
                   std::vector<std::uint8_t>(fixtureBytes.begin() +
                                                 static_cast<std::ptrdiff_t>(drained),
                                             fixtureBytes.begin() +
                                                 static_cast<std::ptrdiff_t>(drained + chunk)),
               "draining read returned the wrong bytes");
        drained += chunk;
    }
    expectEqual(drained, fixtureBytes.size(), "draining reads did not reach end-of-file");
    state.rax = readNumber;
    state.rdi = 3;
    state.rsi = bufferAddress.value;
    state.rdx = 16;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "read at end-of-file did not return zero");

    state.rax = readNumber;
    state.rdi = 3;
    state.rsi = 0x700000000000ULL;
    state.rdx = 16;
    state.rflags = 0x2;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "read into unmapped memory returned the wrong errno");
}

void testDarwinOpenSystemDatabasesAbsent() {
    constexpr auto openNoCancelNumber = UINT64_C(0x0200018E);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;

    for (const char *path : {"/etc/passwd", "/etc/master.passwd", "/etc/group"}) {
        const std::string pathString(path);
        std::vector<std::uint8_t> pathBytes(pathString.begin(), pathString.end());
        pathBytes.push_back(0);
        addressSpace.writeBytes(pathAddress, pathBytes);
        state.rax = openNoCancelNumber;
        state.rdi = pathAddress.value;
        state.rsi = 0;
        state.rdx = 0;
        state.rflags = 0x2;
        static_cast<void>(dispatcher.dispatch(
            addressSpace, state, rosa::guest::GuestAddress{0x7FF802E305E0ULL}));
        expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                    "system database open did not report absence");
        expect((state.rflags & 1U) != 0, "system database open did not set BSD carry");
    }
    expectEqual(dispatcher.fileSpace().size(), std::size_t{0},
                "absent system database open allocated a descriptor");
}

void testDarwinOpenFeatureFlagsDisclosuresAbsent() {
    // Observed under an Objective-C fixture: libsystem_featureflags probes
    // its disclosure domains and falls back when they are absent.
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;

    for (const char *path : {"/System/Library/FeatureFlags/GlobalDisclosures.plist",
                             "/System/Library/FeatureFlags/Domain/MadeUp.plist",
                             "/System/AppleInternal/Library/FeatureFlags/"
                             "GlobalDisclosureOverrides.plist"}) {
        const std::string pathString(path);
        std::vector<std::uint8_t> pathBytes(pathString.begin(), pathString.end());
        pathBytes.push_back(0);
        addressSpace.writeBytes(pathAddress, pathBytes);
        state.rax = openNumber;
        state.rdi = pathAddress.value;
        state.rsi = O_RDONLY | O_NONBLOCK | O_CLOEXEC;
        state.rdx = 0;
        state.rflags = 0x2;
        static_cast<void>(dispatcher.dispatch(
            addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30330ULL}));
        expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                    "FeatureFlags disclosure open did not report absence");
        expect((state.rflags & 1U) != 0, "FeatureFlags disclosure open did not set BSD carry");
    }
    expectEqual(dispatcher.fileSpace().size(), std::size_t{0},
                "absent FeatureFlags disclosure open allocated a descriptor");
}

void testDarwinMmapReadOnlyUserFile() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto mmapNumber = UINT64_C(0x020000C5);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    const auto fixturePath =
        std::filesystem::canonical(std::filesystem::path{ROSA_TEST_HELLO_MACHO_PATH});
    const auto fixtureString = fixturePath.string();
    std::vector<std::uint8_t> fixtureBytes(fixtureString.begin(), fixtureString.end());
    fixtureBytes.push_back(0);
    struct stat fixtureMetadata{};
    expect(::stat(fixturePath.c_str(), &fixtureMetadata) == 0 && fixtureMetadata.st_size > 0,
           "could not inspect mmap fixture");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, fixtureBytes);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = O_RDONLY;
    state.rdx = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    const auto descriptor = state.rax;

    state.rax = mmapNumber;
    state.rdi = 0;
    state.rsi = static_cast<std::uint64_t>(fixtureMetadata.st_size);
    state.rdx = 1;
    state.r10 = 0x00040002;
    state.r8 = descriptor;
    state.r9 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8F678ULL}));
    constexpr auto expectedBase = UINT64_C(0x0000000100000000);
    expectEqual(state.rax, expectedBase, "mmap mapped-file base differs");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "mmap mapped-file did not clear BSD carry");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{state.rax}),
                std::uint32_t{0xFEEDFACF}, "mmap mapped-file Mach-O header differs");
    const auto roundedSize =
        (static_cast<std::uint64_t>(fixtureMetadata.st_size) + rosa::guest::guestPageSize - 1U) &
        ~(static_cast<std::uint64_t>(rosa::guest::guestPageSize) - 1U);
    expectEqual(
        addressSpace.readBytes(rosa::guest::GuestAddress{expectedBase + roundedSize - 1U}, 1)
            .front(),
        std::uint8_t{0}, "mmap did not zero the source file's final partial page");
    const auto mappings = addressSpace.mappingInfos();
    const auto mapped = std::ranges::find_if(mappings, [](const rosa::guest::MappingInfo &mapping) {
        return mapping.label == "mmap private file";
    });
    expect(mapped != mappings.end() && mapped->base.value == expectedBase &&
               mapped->size == roundedSize && mapped->permissions == rosa::guest::Permission::Read,
           "mmap stored the wrong guest mapping metadata");
    bool writeRejected = false;
    try {
        addressSpace.writeU64(rosa::guest::GuestAddress{expectedBase}, 0);
    } catch (const std::runtime_error &) {
        writeRejected = true;
    }
    expect(writeRejected, "read-only guest mmap accepted a write");

    const auto mappingCount = addressSpace.mappingCount();
    state.rax = mmapNumber;
    state.r8 = 99;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "mmap invalid descriptor returned the wrong errno");
    expectEqual(addressSpace.mappingCount(), mappingCount, "failed mmap installed a guest mapping");
}

void testDarwinFcntlGetPath() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto fcntlNumber = UINT64_C(0x0200005C);
    constexpr std::uint32_t openDirectory = 0x00100000;
    constexpr std::uint32_t fGetPath = 50;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress outputAddress{0x8200};
    constexpr std::array<std::uint8_t, 2> currentDirectoryPath{'.', 0};
    constexpr std::array<std::uint8_t, 8> outputSentinel{0xA5, 0xA5, 0xA5, 0xA5,
                                                         0xA5, 0xA5, 0xA5, 0xA5};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, currentDirectoryPath);
    addressSpace.writeBytes(outputAddress, outputSentinel);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = openDirectory;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    const auto descriptor = state.rax;

    state.rax = fcntlNumber;
    state.rdi = descriptor;
    state.rsi = fGetPath;
    state.rdx = outputAddress.value;
    state.rflags = 0xAD7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8E584ULL});
    expect(!outcome.exited, "fcntl F_GETPATH terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "fcntl F_GETPATH did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "fcntl F_GETPATH did not clear BSD carry");
    const auto expectedPath = std::filesystem::current_path().string();
    const auto guestPathBytes = addressSpace.readBytes(outputAddress, expectedPath.size() + 1);
    expect(std::equal(expectedPath.begin(), expectedPath.end(), guestPathBytes.begin()) &&
               guestPathBytes.back() == 0,
           "fcntl F_GETPATH returned the wrong guest path");
    expectEqual(dispatcher.fileSpace().size(), std::size_t{1},
                "fcntl F_GETPATH changed the guest descriptor namespace");

    addressSpace.writeBytes(outputAddress, outputSentinel);
    state.rax = fcntlNumber;
    state.rdi = 99;
    state.rsi = fGetPath;
    state.rdx = outputAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "fcntl F_GETPATH invalid descriptor returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "fcntl F_GETPATH invalid descriptor did not set BSD carry");
    expectEqual(addressSpace.readBytes(outputAddress, outputSentinel.size()),
                std::vector<std::uint8_t>(outputSentinel.begin(), outputSentinel.end()),
                "failed fcntl F_GETPATH changed its output");

    state.rax = fcntlNumber;
    state.rdi = descriptor;
    state.rsi = fGetPath;
    state.rdx = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "fcntl F_GETPATH invalid output returned the wrong errno");
    expectEqual(dispatcher.fileSpace().size(), std::size_t{1},
                "faulted fcntl F_GETPATH changed the descriptor namespace");

    state.rax = fcntlNumber;
    state.rdi = descriptor;
    state.rsi = 0;
    state.rdx = outputAddress.value;
    bool unsupportedCommand = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedCommand =
            std::string_view(error.what()).find("F_GETPATH") != std::string_view::npos;
    }
    expect(unsupportedCommand, "unobserved guest fcntl command did not fail loudly");
}

void testDarwinSimpleAslSocketFlow() {
    constexpr auto socketNumber = UINT64_C(0x02000061);
    constexpr auto connectNumber = UINT64_C(0x02000062);
    constexpr auto fcntlNumber = UINT64_C(0x0200005C);
    constexpr auto closeNumber = UINT64_C(0x02000006);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress socketAddress{0x8100};
    constexpr std::string_view systemLogPath = "/var/run/syslog";
    std::array<std::uint8_t, 106> sockaddr{};
    sockaddr[0] = static_cast<std::uint8_t>(sockaddr.size());
    sockaddr[1] = 1; // AF_UNIX
    std::copy(systemLogPath.begin(), systemLogPath.end(), sockaddr.begin() + 2);

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(socketAddress, sockaddr);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = socketNumber;
    state.rdi = 1; // AF_UNIX
    state.rsi = 2; // SOCK_DGRAM
    state.rdx = 0;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E32E7CULL}));
    expectEqual(state.rax, std::uint64_t{3}, "simple-ASL socket descriptor differs");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "socket did not clear BSD carry");
    const auto descriptor = static_cast<std::uint32_t>(state.rax);
    const auto *socket = dispatcher.fileSpace().lookup(
        rosa::darwin::GuestFileDescriptor{static_cast<std::int32_t>(descriptor)});
    expect(socket != nullptr && socket->kind == rosa::darwin::GuestFileKind::UnixDatagramSocket,
           "socket did not create a guest-only Unix datagram descriptor");

    state.rax = fcntlNumber;
    state.rdi = descriptor;
    state.rsi = 2; // F_SETFD
    state.rdx = 1; // FD_CLOEXEC
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "simple-ASL F_SETFD did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "simple-ASL F_SETFD did not clear BSD carry");

    state.rax = connectNumber;
    state.rdi = descriptor;
    state.rsi = socketAddress.value;
    state.rdx = sockaddr.size();
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                "guest ASL connect returned the wrong errno");
    expect((state.rflags & 1U) != 0, "guest ASL connect did not set BSD carry");
    expect(dispatcher.fileSpace().lookup(
               rosa::darwin::GuestFileDescriptor{static_cast<std::int32_t>(descriptor)}) != nullptr,
           "failed guest ASL connect closed its descriptor");

    state.rax = connectNumber;
    state.rsi = 0xA000;
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "guest connect bad address returned the wrong errno");

    state.rax = closeNumber;
    state.rdi = descriptor;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "simple-ASL socket close did not succeed");
    expectEqual(dispatcher.fileSpace().size(), std::size_t{0},
                "simple-ASL socket close retained its descriptor");
}

void testDarwinCloseGuestDescriptor() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto closeNumber = UINT64_C(0x02000006);
    constexpr std::uint32_t openDirectory = 0x00100000;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr std::array<std::uint8_t, 2> currentDirectoryPath{'.', 0};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, currentDirectoryPath);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = openDirectory;
    state.rdx = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    const auto descriptor = state.rax;
    expectEqual(dispatcher.fileSpace().size(), std::size_t{1},
                "close setup did not create a guest descriptor");

    state.rax = closeNumber;
    state.rdi = descriptor;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8CA4CULL});
    expect(!outcome.exited, "close terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "close did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "close did not clear BSD carry");
    expectEqual(dispatcher.fileSpace().size(), std::size_t{0},
                "close retained the guest descriptor");
    expect(dispatcher.fileSpace().lookup(
               rosa::darwin::GuestFileDescriptor{static_cast<std::int32_t>(descriptor)}) == nullptr,
           "closed guest descriptor remains discoverable");

    state.rax = closeNumber;
    state.rdi = descriptor;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "repeated close returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3}, "repeated close did not set BSD carry");
}

} // namespace

std::span<const TestCase> darwinFileMetadataTests() {
    static const TestCase cases[]{
        {"Darwin access chroot marker", testDarwinAccessChrootMarker},
        {"Darwin access mapped directory", testDarwinAccessMappedDirectory},
        {"Darwin access relative path", testDarwinAccessRelativePath},
        {"Darwin getattrlist root volume", testDarwinGetattrlistRootVolume},
        {"Darwin getattrlist mapped-file full path", testDarwinGetattrlistMappedFileFullPath},
        {"Darwin fstatat64 synthetic directory", testDarwinFstatat64SyntheticDirectory},
        {"Darwin open read-only user file", testDarwinOpenReadOnlyUserFile},
        {"Darwin open relative read-only file", testDarwinOpenRelativeReadOnlyFile},
        {"Darwin read host read-only file", testDarwinReadHostReadOnlyFile},
        {"Darwin open absent system databases", testDarwinOpenSystemDatabasesAbsent},
        {"Darwin open absent FeatureFlags disclosures", testDarwinOpenFeatureFlagsDisclosuresAbsent},
        {"Darwin mmap read-only user file", testDarwinMmapReadOnlyUserFile},
        {"Darwin fcntl F_GETPATH", testDarwinFcntlGetPath},
        {"Darwin simple-ASL socket flow", testDarwinSimpleAslSocketFlow},
        {"Darwin close guest descriptor", testDarwinCloseGuestDescriptor},
    };
    return cases;
}

} // namespace rosa::tests
