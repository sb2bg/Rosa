#include "TestSupport.h"
#include "TestSuite.h"
#include "TemporaryFile.h"

namespace rosa::tests {
namespace {

void testDarwinGetdirentriesHostDirectory() {
    // Observed under an AppKit fixture: getdirentries64(appDirFd, buf, count, &pos).
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto entriesNumber = UINT64_C(0x02000158);
    constexpr std::uint32_t openDirectory = 0x00100000;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress bufferAddress{0x9000};
    constexpr rosa::guest::GuestAddress positionAddress{0xB000};
    constexpr std::array<std::uint8_t, 2> currentDirectoryPath{'.', 0};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize * 4,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, currentDirectoryPath);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State openState;
    openState.rax = openNumber;
    openState.rdi = pathAddress.value;
    openState.rsi = openDirectory;
    openState.rdx = 0;
    openState.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, openState, rosa::guest::GuestAddress{0x1000}));
    expectEqual(openState.rax, std::uint64_t{3},
                "entries fixture open returned the wrong descriptor");

    rosa::x86::X86State state;
    state.rax = entriesNumber;
    state.rdi = 3;
    state.rsi = bufferAddress.value;
    state.rdx = 0x2000;
    state.rcx = positionAddress.value;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E3128CULL});
    expect(!outcome.exited, "getdirentries64 terminated the guest");
    expect(state.rax > 0, "getdirentries64 returned no bytes");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "getdirentries64 did not clear BSD carry");
    const auto first = addressSpace.readBytes(bufferAddress, 24);
    const std::uint16_t reclen = static_cast<std::uint16_t>(first[16]) |
                                 (static_cast<std::uint16_t>(first[17]) << 8U);
    const std::uint16_t namlen = static_cast<std::uint16_t>(first[18]) |
                                 (static_cast<std::uint16_t>(first[19]) << 8U);
    expect(reclen >= 24 && reclen <= state.rax, "getdirentries64 record length differs");
    expect(namlen > 0 && namlen <= 255, "getdirentries64 name length differs");
    const auto name = addressSpace.readBytes(
        rosa::guest::GuestAddress{bufferAddress.value + 21}, namlen);
    expect(std::string_view(reinterpret_cast<const char *>(name.data()), name.size()) == "." ||
               std::string_view(reinterpret_cast<const char *>(name.data()), name.size()) == "..",
           "getdirentries64 first entry is not a dot entry");

    // A second call resumes past the entries already returned.
    const auto firstCount = state.rax;
    state.rax = entriesNumber;
    state.rdi = 3;
    state.rsi = bufferAddress.value;
    state.rdx = 0x2000;
    state.rcx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expect(state.rax < firstCount, "getdirentries64 did not resume the listing");

    state.rax = entriesNumber;
    state.rdi = 99;
    state.rsi = bufferAddress.value;
    state.rdx = 0x2000;
    state.rcx = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "getdirentries64 on a bad descriptor returned the wrong errno");
}

void testDarwinFstatfsHostDirectory() {
    // Observed under an AppKit fixture: fstatfs64(appDirFd, buf).
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto fstatfsNumber = UINT64_C(0x0200015A);
    constexpr std::uint32_t openDirectory = 0x00100000;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress statAddress{0x9000};
    constexpr std::array<std::uint8_t, 2> currentDirectoryPath{'.', 0};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize * 2,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, currentDirectoryPath);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State openState;
    openState.rax = openNumber;
    openState.rdi = pathAddress.value;
    openState.rsi = openDirectory;
    openState.rdx = 0;
    openState.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, openState, rosa::guest::GuestAddress{0x1000}));
    expectEqual(openState.rax, std::uint64_t{3},
                "fstatfs fixture open returned the wrong descriptor");

    rosa::x86::X86State state;
    state.rax = fstatfsNumber;
    state.rdi = 3;
    state.rsi = statAddress.value;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E31274ULL});
    expect(!outcome.exited, "fstatfs64 terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "fstatfs64 returned an error");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "fstatfs64 did not clear BSD carry");
    const auto filesystem = addressSpace.readBytes(statAddress, 2168);
    const std::uint32_t blockSize =
        static_cast<std::uint32_t>(filesystem[0]) |
        (static_cast<std::uint32_t>(filesystem[1]) << 8U) |
        (static_cast<std::uint32_t>(filesystem[2]) << 16U) |
        (static_cast<std::uint32_t>(filesystem[3]) << 24U);
    expect(blockSize != 0, "fstatfs64 reported a zero block size");
    const std::string_view filesystemType(
        reinterpret_cast<const char *>(filesystem.data() + 72), 16);
    expect(filesystemType.find("apfs") != std::string_view::npos,
           "fstatfs64 reported an unexpected filesystem type");

    state.rax = fstatfsNumber;
    state.rdi = 99;
    state.rsi = statAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "fstatfs64 on a bad descriptor returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3}, "fstatfs64 on a bad descriptor did not set carry");
}

void testDarwinOpenDirectoryWithinCurrentDirectory() {
    // Observed under an AppKit fixture: open(appDir, O_RDONLY|O_DIRECTORY|O_CLOEXEC).
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr std::uint32_t openDirectory = 0x00100000;
    constexpr std::uint32_t openCloseOnExec = 0x01000000;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    const auto directoryString = std::filesystem::current_path().string();
    std::vector<std::uint8_t> directoryBytes(directoryString.begin(), directoryString.end());
    directoryBytes.push_back(0);
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, directoryBytes);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = openDirectory | openCloseOnExec;
    state.rdx = 0;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E305E8ULL});
    expect(!outcome.exited, "open application directory terminated the guest");
    expectEqual(state.rax, std::uint64_t{3},
                "open application directory returned the wrong guest descriptor");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "open application directory did not clear BSD carry");
    const auto *opened = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{3});
    expect(opened != nullptr && opened->kind == rosa::darwin::GuestFileKind::CurrentDirectory &&
               opened->guestPath == std::filesystem::current_path(),
           "open application directory stored the wrong guest metadata");

    // O_DIRECTORY against a regular file must fail like the host open.
    const auto fixtureString =
        std::filesystem::canonical(std::filesystem::path{ROSA_TEST_HELLO_MACHO_PATH}).string();
    std::vector<std::uint8_t> fixtureBytes(fixtureString.begin(), fixtureString.end());
    fixtureBytes.push_back(0);
    addressSpace.writeBytes(pathAddress, fixtureBytes);
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = openDirectory;
    state.rdx = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOTDIR),
                "directory open of a regular file returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "directory open of a regular file did not set BSD carry");
    expectEqual(guestOpenedDescriptors(dispatcher), std::size_t{1},
                "failed directory open allocated a descriptor");

    // Directories outside the current directory stay loud.
    constexpr std::array<std::uint8_t, 5> outsidePath{'/', 't', 'm', 'p', 0};
    addressSpace.writeBytes(pathAddress, outsidePath);
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = openDirectory;
    state.rdx = 0;
    bool escaped = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        escaped = std::string_view(error.what()).find("read-only directory path") !=
                  std::string_view::npos;
    }
    expect(escaped, "out-of-sandbox directory open did not fail loudly");
}

void testDarwinOpenCurrentDirectory() {
    constexpr auto openNumber = UINT64_C(0x02000005);
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
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEE844ULL});
    expect(!outcome.exited, "open current directory terminated the guest");
    expectEqual(state.rax, std::uint64_t{3},
                "open current directory returned the wrong guest descriptor");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "open current directory did not clear BSD carry");
    expectEqual(guestOpenedDescriptors(dispatcher), std::size_t{1},
                "open current directory did not create one guest descriptor");
    const auto *opened = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{3});
    expect(opened != nullptr && opened->kind == rosa::darwin::GuestFileKind::CurrentDirectory &&
               opened->guestPath == std::filesystem::current_path() &&
               opened->flags == openDirectory,
           "open current directory stored the wrong guest metadata");

    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = openDirectory;
    state.rdx = 0;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{4},
                "repeated guest open did not allocate a unique descriptor");
    expectEqual(guestOpenedDescriptors(dispatcher), std::size_t{2},
                "repeated guest open changed descriptor-space size incorrectly");

    state.rax = openNumber;
    state.rdi = 0x9000;
    state.rsi = openDirectory;
    state.rdx = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "open invalid guest path returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3}, "open invalid guest path did not set BSD carry");
    expectEqual(guestOpenedDescriptors(dispatcher), std::size_t{2},
                "faulted guest open allocated a descriptor");

    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = O_WRONLY;
    state.rdx = 0;
    bool unsupportedFlags = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedFlags = std::string_view(error.what()).find("read-only open of host files") !=
                           std::string_view::npos;
    }
    expect(unsupportedFlags, "unobserved guest open flags did not fail loudly");
    expectEqual(guestOpenedDescriptors(dispatcher), std::size_t{2},
                "unsupported guest open allocated a descriptor");
}

void testDarwinFeatureFlagsShmOpenProbe() {
    constexpr auto shmOpenNumber = UINT64_C(0x0200010A);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress nameAddress{0x8100};
    constexpr std::array<std::uint8_t, 27> featureFlagsName{
        'c', 'o', 'm', '.', 'a', 'p', 'p', 'l', 'e', '.', 'f', 'e', 'a', 't',
        'u', 'r', 'e', 'f', 'l', 'a', 'g', 's', '.', 's', 'h', 'm', 0};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(nameAddress, featureFlagsName);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = shmOpenNumber;
    state.rdi = nameAddress.value;
    state.rsi = 0;
    state.rdx = 0x7FF802D02113ULL;
    state.rflags = 0x8D6;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30FA4ULL}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                "FeatureFlags shm_open probe returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "FeatureFlags shm_open probe did not set BSD carry");
    expectEqual(guestOpenedDescriptors(dispatcher), std::size_t{0},
                "FeatureFlags shm_open probe allocated a guest descriptor");

    state.rax = shmOpenNumber;
    state.rdi = 0x9000;
    state.rsi = 0;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "shm_open invalid guest name returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "shm_open invalid guest name did not set BSD carry");

    state.rax = shmOpenNumber;
    state.rdi = nameAddress.value;
    state.rsi = O_CREAT | O_RDWR;
    bool unsupportedFlags = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedFlags =
            std::string_view(error.what()).find("FeatureFlags shared-memory probe") !=
            std::string_view::npos;
    }
    expect(unsupportedFlags, "unobserved guest shm_open flags did not fail loudly");
}

void testDarwinCsopsUnsignedStatus() {
    constexpr auto csopsNumber = UINT64_C(0x020000A9);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress statusAddress{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU32(statusAddress, UINT32_MAX);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = csopsNumber;
    state.rdi = static_cast<std::uint32_t>(::getpid());
    state.rsi = 0;
    state.rdx = statusAddress.value;
    state.r10 = sizeof(std::uint32_t);
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E311C8ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "csops status did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "csops status did not clear BSD carry");
    expectEqual(addressSpace.readU32(statusAddress), std::uint32_t{0},
                "unsigned guest csops status is not zero");

    addressSpace.writeU32(statusAddress, UINT32_MAX);
    state.rax = csopsNumber;
    state.rdi = static_cast<std::uint32_t>(::getpid());
    state.rsi = 0;
    state.rdx = 0x9000;
    state.r10 = sizeof(std::uint32_t);
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "csops invalid output returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3}, "csops invalid output did not set BSD carry");
    expectEqual(addressSpace.readU32(statusAddress), UINT32_MAX,
                "faulted csops changed a valid guest output buffer");

    state.rax = csopsNumber;
    state.rdi = static_cast<std::uint32_t>(::getpid());
    state.rsi = 1;
    state.rdx = statusAddress.value;
    state.r10 = sizeof(std::uint32_t);
    bool unsupportedOperation = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedOperation =
            std::string_view(error.what()).find("CS_OPS_STATUS") != std::string_view::npos;
    }
    expect(unsupportedOperation, "unobserved guest csops operation did not fail loudly");

    // Unsigned guests have no DER entitlements blob: EINVAL, buffer untouched.
    constexpr std::array<std::uint8_t, 8> blobSentinel{0xA5, 0xA5, 0xA5, 0xA5,
                                                      0xA5, 0xA5, 0xA5, 0xA5};
    addressSpace.writeBytes(statusAddress, blobSentinel);
    state.rax = csopsNumber;
    state.rdi = static_cast<std::uint32_t>(::getpid());
    state.rsi = 16;
    state.rdx = statusAddress.value;
    state.r10 = 0x408;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "unsigned csops DER entitlements returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "unsigned csops DER entitlements did not set BSD carry");
    expectEqual(addressSpace.readBytes(statusAddress, blobSentinel.size()),
                std::vector<std::uint8_t>(blobSentinel.begin(), blobSentinel.end()),
                "unsigned csops DER entitlements touched its output buffer");
}

void testDarwinCsopsAuditTokenUnsignedDerEntitlements() {
    constexpr auto csopsAuditTokenNumber = UINT64_C(0x020000AA);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress outputAddress{0x8100};
    constexpr rosa::guest::GuestAddress tokenAddress{0x8500};
    constexpr std::array<std::uint8_t, 16> sentinel{0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
                                                    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};

    audit_token_t token{};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    expectEqual(task_info(mach_task_self(), TASK_AUDIT_TOKEN, reinterpret_cast<task_info_t>(&token),
                          &count),
                KERN_SUCCESS, "csops_audittoken test could not query the host token");
    expectEqual(count, mach_msg_type_number_t{8}, "csops_audittoken test host-token count differs");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(outputAddress, sentinel);
    std::array<std::uint8_t, sizeof(token)> tokenBytes{};
    std::memcpy(tokenBytes.data(), &token, sizeof(token));
    addressSpace.writeBytes(tokenAddress, tokenBytes);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = csopsAuditTokenNumber;
    state.rdi = static_cast<std::uint32_t>(::getpid());
    state.rsi = 16; // CS_OPS_DER_ENTITLEMENTS_BLOB
    state.rdx = outputAddress.value;
    state.r10 = 0x408;
    state.r8 = tokenAddress.value;
    state.rflags = 0x8D6;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E302A8ULL}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "unsigned DER-entitlements query returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "unsigned DER-entitlements query did not set BSD carry");
    expectEqual(addressSpace.readBytes(outputAddress, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "unsigned DER-entitlements query changed its output buffer");

    state.rax = csopsAuditTokenNumber;
    state.r8 = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "DER-entitlements invalid audit token returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "DER-entitlements invalid audit token did not set carry");

    auto staleToken = token;
    ++staleToken.val[7];
    std::memcpy(tokenBytes.data(), &staleToken, sizeof(staleToken));
    addressSpace.writeBytes(tokenAddress, tokenBytes);
    state.rax = csopsAuditTokenNumber;
    state.r8 = tokenAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ESRCH),
                "DER-entitlements stale audit token returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "DER-entitlements stale audit token did not set carry");

    std::memcpy(tokenBytes.data(), &token, sizeof(token));
    addressSpace.writeBytes(tokenAddress, tokenBytes);
    state.rax = csopsAuditTokenNumber;
    state.rsi = 17;
    bool unsupportedOperation = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedOperation =
            std::string_view(error.what()).find("CS_OPS_DER_ENTITLEMENTS_BLOB") !=
            std::string_view::npos;
    }
    expect(unsupportedOperation, "unobserved csops_audittoken operation did not fail loudly");
}

void testDarwinOpenAndReadUrandomNoCancel() {
    constexpr auto openNoCancelNumber = UINT64_C(0x0200018E);
    constexpr auto readNoCancelNumber = UINT64_C(0x0200018C);
    constexpr auto closeNoCancelNumber = UINT64_C(0x0200018F);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress bufferAddress{0x8200};
    constexpr std::array<std::uint8_t, 13> randomPath{'/', 'd', 'e', 'v', '/', 'u', 'r',
                                                      'a', 'n', 'd', 'o', 'm', 0};

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, randomPath);
    constexpr std::array<std::uint8_t, 16> sentinel{0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
                                                    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};
    addressSpace.writeBytes(bufferAddress, sentinel);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = openNoCancelNumber;
    state.rdi = pathAddress.value;
    state.rsi = 0;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E305E8ULL}));
    expectEqual(state.rax, std::uint64_t{3},
                "open_nocancel /dev/urandom returned the wrong descriptor");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "open_nocancel /dev/urandom did not clear BSD carry");
    const auto *randomFile = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{3});
    expect(randomFile != nullptr && randomFile->kind == rosa::darwin::GuestFileKind::RandomDevice &&
               randomFile->guestPath == std::filesystem::path{"/dev/urandom"} &&
               randomFile->flags == 0,
           "open_nocancel stored the wrong random-device metadata");

    // sqlite opens /dev/urandom with O_CLOEXEC; close-on-exec is meaningless
    // without an exec boundary, so the flag is accepted and recorded.
    state.rax = openNoCancelNumber;
    state.rsi = 0x01000000;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{4},
                "open_nocancel /dev/urandom with O_CLOEXEC returned the wrong descriptor");
    expectEqual(state.rflags, std::uint64_t{0x8D6},
                "open_nocancel /dev/urandom with O_CLOEXEC did not clear BSD carry");
    const auto *cloexecFile = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{4});
    expect(cloexecFile != nullptr &&
               cloexecFile->kind == rosa::darwin::GuestFileKind::RandomDevice &&
               cloexecFile->flags == 0x01000000,
           "open_nocancel stored the wrong close-on-exec metadata");
    state.rax = closeNoCancelNumber;
    state.rdi = 4;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "close_nocancel close-on-exec fd did not succeed");

    state.rax = readNoCancelNumber;
    state.rdi = 3;
    state.rsi = bufferAddress.value;
    state.rdx = 8;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E305C8ULL}));
    expectEqual(state.rax, std::uint64_t{8},
                "read_nocancel /dev/urandom returned the wrong byte count");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "read_nocancel /dev/urandom did not clear BSD carry");
    expect(addressSpace.readBytes(bufferAddress, 8) != std::vector<std::uint8_t>(8, 0xA5),
           "read_nocancel /dev/urandom left its buffer unchanged");
    expectEqual(addressSpace.readBytes(rosa::guest::GuestAddress{bufferAddress.value + 8}, 8),
                std::vector<std::uint8_t>(8, 0xA5),
                "read_nocancel /dev/urandom wrote past its buffer");

    state.rax = readNoCancelNumber;
    state.rdi = 3;
    state.rsi = 0x9000;
    state.rdx = 8;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "read_nocancel invalid buffer returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "read_nocancel invalid buffer did not set BSD carry");

    state.rax = readNoCancelNumber;
    state.rdi = 99;
    state.rsi = bufferAddress.value;
    state.rdx = 8;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "read_nocancel invalid descriptor returned the wrong errno");

    state.rax = closeNoCancelNumber;
    state.rdi = 3;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30FBCULL}));
    expectEqual(state.rax, std::uint64_t{0}, "close_nocancel random device did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "close_nocancel random device did not clear BSD carry");
    expectEqual(guestOpenedDescriptors(dispatcher), std::size_t{0},
                "close_nocancel did not release the guest descriptor");

    state.rax = closeNoCancelNumber;
    state.rdi = 3;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "repeated close_nocancel returned the wrong errno");
}

void testDarwinOpenGuestRootDirectory() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr std::uint32_t openRootFlags = 0x20100000;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr std::array<std::uint8_t, 2> rootPath{'/', 0};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, rootPath);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = openRootFlags;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEE844ULL}));
    expectEqual(state.rax, std::uint64_t{3}, "open guest root returned the wrong descriptor");
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "open guest root did not clear BSD carry");
    const auto *opened = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{3});
    expect(opened != nullptr && opened->kind == rosa::darwin::GuestFileKind::RootDirectory &&
               opened->guestPath == std::filesystem::path{"/"} && opened->flags == openRootFlags,
           "open guest root stored the wrong synthetic metadata");

    state.rax = openNumber;
    state.rsi = openRootFlags & ~std::uint32_t{0x20000000};
    bool rejectedFlags = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        rejectedFlags =
            std::string_view(error.what()).find("read-only directory path") !=
            std::string_view::npos;
    }
    expect(rejectedFlags, "guest root open accepted an unobserved flag combination");
    expectEqual(guestOpenedDescriptors(dispatcher), std::size_t{1},
                "unsupported guest root open allocated a descriptor");
}

void testDarwinOpenatGuestCryptexDirectory() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto openatNumber = UINT64_C(0x020001CF);
    constexpr std::uint32_t rootFlags = 0x20100000;
    constexpr std::uint32_t directoryFlag = 0x00100000;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress rootPathAddress{0x8100};
    constexpr rosa::guest::GuestAddress relativePathAddress{0x8200};
    constexpr std::array<std::uint8_t, 2> rootPath{'/', 0};
    constexpr std::string_view relativePath = "System/Cryptexes/OS";
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(rootPathAddress, rootPath);
    addressSpace.writeBytes(
        relativePathAddress,
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t *>(relativePath.data()),
                                      relativePath.size()});
    addressSpace.writeBytes(
        rosa::guest::GuestAddress{relativePathAddress.value + relativePath.size()},
        std::array<std::uint8_t, 1>{0});
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = rootPathAddress.value;
    state.rsi = rootFlags;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));

    state.rax = openatNumber;
    state.rdi = 3;
    state.rsi = relativePathAddress.value;
    state.rdx = directoryFlag;
    state.r10 = 0;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEE85CULL}));
    expectEqual(state.rax, std::uint64_t{4}, "openat guest cryptex returned the wrong descriptor");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "openat guest cryptex did not clear BSD carry");
    const auto *opened = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{4});
    expect(opened != nullptr && opened->kind == rosa::darwin::GuestFileKind::SyntheticDirectory &&
               opened->guestPath == std::filesystem::path{"/System/Cryptexes/OS"} &&
               opened->flags == directoryFlag,
           "openat guest cryptex stored the wrong synthetic metadata");

    const auto sizeBeforeFailure = guestOpenedDescriptors(dispatcher);
    state.rax = openatNumber;
    state.rdi = 99;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "openat invalid guest dirfd returned the wrong errno");
    expectEqual(guestOpenedDescriptors(dispatcher), sizeBeforeFailure,
                "faulted openat allocated a guest descriptor");

    state.rax = openatNumber;
    state.rdi = 3;
    state.rsi = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "openat invalid guest path returned the wrong errno");
    expectEqual(guestOpenedDescriptors(dispatcher), sizeBeforeFailure,
                "faulted openat path allocated a guest descriptor");
}

void testDarwinDuplicateGuestDescriptor() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto dupNumber = UINT64_C(0x02000029);
    constexpr std::uint32_t rootFlags = 0x20100000;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr std::array<std::uint8_t, 2> rootPath{'/', 0};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, rootPath);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = rootFlags;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    const auto *original = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{3});
    expect(original != nullptr, "dup test did not create its original fd");
    const auto descriptionId = original->descriptionId;

    state.rax = dupNumber;
    state.rdi = 3;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEEB18ULL}));
    expectEqual(state.rax, std::uint64_t{4}, "dup returned the wrong guest descriptor");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "dup did not clear BSD carry");
    const auto *duplicate = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{4});
    expect(duplicate != nullptr && duplicate->descriptionId == descriptionId &&
               duplicate->kind == original->kind && duplicate->guestPath == original->guestPath &&
               duplicate->flags == original->flags,
           "dup did not share the guest open-description identity");

    state.rax = dupNumber;
    state.rdi = 99;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "dup invalid guest descriptor returned the wrong errno");
    expectEqual(guestOpenedDescriptors(dispatcher), std::size_t{2},
                "failed dup allocated a guest descriptor");
}

void testDarwinStat64SystemDatabasesAbsent() {
    constexpr auto stat64Number = UINT64_C(0x02000152);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress statAddress{0x8300};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, 144> sentinel = [] {
        std::array<std::uint8_t, 144> bytes{};
        bytes.fill(0xA5);
        return bytes;
    }();
    addressSpace.writeBytes(statAddress, sentinel);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;

    for (const char *path : {"/etc/passwd", "/etc/master.passwd", "/etc/group"}) {
        const std::string pathString(path);
        std::vector<std::uint8_t> pathBytes(pathString.begin(), pathString.end());
        pathBytes.push_back(0);
        addressSpace.writeBytes(pathAddress, pathBytes);
        state.rax = stat64Number;
        state.rdi = pathAddress.value;
        state.rsi = statAddress.value;
        state.rflags = 0x2;
        static_cast<void>(dispatcher.dispatch(
            addressSpace, state, rosa::guest::GuestAddress{0x7FF802E310E4ULL}));
        expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                    "system database stat64 did not report absence");
        expect((state.rflags & 1U) != 0, "system database stat64 did not set BSD carry");
    }
    expectEqual(addressSpace.readBytes(statAddress, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "absent system database stat64 touched its output buffer");
}

void testDarwinStat64RelativePath() {
    constexpr auto stat64Number = UINT64_C(0x02000152);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress statAddress{0x8300};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;

    // A missing relative path reports its errno like the absolute probes.
    const std::string missing = ":memory:";
    std::vector<std::uint8_t> missingBytes(missing.begin(), missing.end());
    missingBytes.push_back(0);
    addressSpace.writeBytes(pathAddress, missingBytes);
    state.rax = stat64Number;
    state.rdi = pathAddress.value;
    state.rsi = statAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(ENOENT),
                "relative missing-path stat64 returned the wrong errno");

    // A present relative path resolves against the guest working directory.
    const TemporaryFile fixture(dispatcher.fileSpace().currentDirectory());
    const auto presentName = fixture.path().filename().string();
    std::vector<std::uint8_t> presentBytes(presentName.begin(), presentName.end());
    presentBytes.push_back(0);
    addressSpace.writeBytes(pathAddress, presentBytes);
    state.rax = stat64Number;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "relative present-path stat64 did not succeed");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "relative present-path stat64 did not clear BSD carry");
}

void testDarwinStat64OutsideSandboxDirectory() {
    // Bundle-path ancestor walks stat containers outside the working
    // directory; metadata stays honest while open/read stay confined.
    constexpr auto stat64Number = UINT64_C(0x02000152);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress statAddress{0x8300};
    constexpr std::array<std::uint8_t, 2> rootPath{'/', 0};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, rootPath);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = stat64Number;
    state.rdi = pathAddress.value;
    state.rsi = statAddress.value;
    state.rflags = 0xAD7;
    const auto outcome = dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x7FF802E36DE4ULL});
    expect(!outcome.exited, "out-of-sandbox stat64 terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "out-of-sandbox stat64 did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "out-of-sandbox stat64 did not clear BSD carry");
    const auto metadata = addressSpace.readBytes(statAddress, 144);
    std::uint16_t mode = 0;
    std::memcpy(&mode, metadata.data() + 4, sizeof(mode));
    expect((mode & S_IFMT) == S_IFDIR, "out-of-sandbox stat64 root is not a directory");
}

void testDarwinLstat64MappedDirectory() {
    // Observed under an AppKit fixture: lstat64(appDir, buf).
    constexpr auto lstat64Number = UINT64_C(0x02000154);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress statAddress{0x8300};
    const auto directoryString = std::filesystem::current_path().string();
    std::vector<std::uint8_t> directoryBytes(directoryString.begin(), directoryString.end());
    directoryBytes.push_back(0);

    struct stat hostMetadata{};
    expect(::lstat(directoryString.c_str(), &hostMetadata) == 0,
           "could not lstat the mapped-directory fixture");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, directoryBytes);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = lstat64Number;
    state.rdi = pathAddress.value;
    state.rsi = statAddress.value;
    state.rflags = 0xAD7;
    const auto outcome = dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x7FF802E36DE4ULL});
    expect(!outcome.exited, "lstat64 mapped directory terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "lstat64 mapped directory did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "lstat64 mapped directory did not clear BSD carry");

    const auto metadata = addressSpace.readBytes(statAddress, 144);
    std::uint16_t mode = 0;
    std::memcpy(&mode, metadata.data() + 4, sizeof(mode));
    expectEqual(mode, static_cast<std::uint16_t>(hostMetadata.st_mode),
                "lstat64 mapped directory returned the wrong mode");
    expect((mode & S_IFMT) == S_IFDIR, "lstat64 mapped directory is not a directory");
}

void testDarwinStat64MappedDirectory() {
    // Observed under an AppKit fixture: stat64(appDir, buf).
    constexpr auto stat64Number = UINT64_C(0x02000152);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress statAddress{0x8300};
    const auto directoryString = std::filesystem::current_path().string();
    std::vector<std::uint8_t> directoryBytes(directoryString.begin(), directoryString.end());
    directoryBytes.push_back(0);

    struct stat hostMetadata{};
    expect(::stat(directoryString.c_str(), &hostMetadata) == 0,
           "could not stat the mapped-directory fixture");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, directoryBytes);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = stat64Number;
    state.rdi = pathAddress.value;
    state.rsi = statAddress.value;
    state.rflags = 0xAD7;
    const auto outcome = dispatcher.dispatch(
        addressSpace, state, rosa::guest::GuestAddress{0x7FF802E310E4ULL});
    expect(!outcome.exited, "stat64 mapped directory terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "stat64 mapped directory did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "stat64 mapped directory did not clear BSD carry");

    const auto metadata = addressSpace.readBytes(statAddress, 144);
    std::uint16_t mode = 0;
    std::memcpy(&mode, metadata.data() + 4, sizeof(mode));
    expectEqual(mode, static_cast<std::uint16_t>(hostMetadata.st_mode),
                "stat64 mapped directory returned the wrong mode");
    expect((mode & S_IFMT) == S_IFDIR, "stat64 mapped directory is not a directory");
}

void testDarwinStat64MappedFile() {
    constexpr auto stat64Number = UINT64_C(0x02000152);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress statAddress{0x8300};
    const auto fixturePath =
        std::filesystem::canonical(std::filesystem::path{ROSA_TEST_HELLO_MACHO_PATH});
    const auto fixtureString = fixturePath.string();
    std::vector<std::uint8_t> fixtureBytes(fixtureString.begin(), fixtureString.end());
    fixtureBytes.push_back(0);

    struct stat hostMetadata{};
    expect(::stat(fixturePath.c_str(), &hostMetadata) == 0,
           "could not stat the mapped-file fixture");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, fixtureBytes);
    constexpr std::array<std::uint8_t, 144> sentinel = [] {
        std::array<std::uint8_t, 144> bytes{};
        bytes.fill(0xA5);
        return bytes;
    }();
    addressSpace.writeBytes(statAddress, sentinel);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = stat64Number;
    state.rdi = pathAddress.value;
    state.rsi = statAddress.value;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8CED4ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "stat64 mapped file did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "stat64 mapped file did not clear BSD carry");

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
    expectEqual(loadU16(4), static_cast<std::uint16_t>(hostMetadata.st_mode),
                "stat64 mapped file returned the wrong mode");
    expectEqual(loadU16(6), static_cast<std::uint16_t>(hostMetadata.st_nlink),
                "stat64 mapped file returned the wrong link count");
    expectEqual(loadU64(8), static_cast<std::uint64_t>(hostMetadata.st_ino),
                "stat64 mapped file returned the wrong inode");
    expectEqual(loadU64(96), static_cast<std::uint64_t>(hostMetadata.st_size),
                "stat64 mapped file returned the wrong size");
    expectEqual(loadU32(112), static_cast<std::uint32_t>(hostMetadata.st_blksize),
                "stat64 mapped file returned the wrong block size");
    expect(std::all_of(metadata.begin() + 124, metadata.end(),
                       [](std::uint8_t byte) { return byte == 0; }),
           "stat64 mapped file did not zero reserved guest fields");

    state.rax = stat64Number;
    state.rsi = 0x9000;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "stat64 invalid output pointer returned the wrong errno");
    expect((state.rflags & std::uint64_t{1}) != 0,
           "stat64 invalid output pointer did not set BSD carry");
}

void testDarwinFstat64StandardDescriptor() {
    constexpr auto fstat64Number = UINT64_C(0x02000153);
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress statAddress{0x8100};
    constexpr std::size_t guestStatSize = 144;

    struct stat hostMetadata{};
    expect(::fstat(STDOUT_FILENO, &hostMetadata) == 0, "could not fstat the host stdout fixture");

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    constexpr std::array<std::uint8_t, guestStatSize> sentinel = [] {
        std::array<std::uint8_t, guestStatSize> bytes{};
        bytes.fill(0xA5);
        return bytes;
    }();
    addressSpace.writeBytes(statAddress, sentinel);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = fstat64Number;
    state.rdi = STDOUT_FILENO;
    state.rsi = statAddress.value;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30348ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "fstat64 stdout did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "fstat64 stdout did not clear BSD carry");

    const auto metadata = addressSpace.readBytes(statAddress, guestStatSize);
    std::uint16_t guestMode = 0;
    std::int64_t guestSize = 0;
    std::int32_t guestBlockSize = 0;
    std::memcpy(&guestMode, metadata.data() + 4, sizeof(guestMode));
    std::memcpy(&guestSize, metadata.data() + 96, sizeof(guestSize));
    std::memcpy(&guestBlockSize, metadata.data() + 112, sizeof(guestBlockSize));
    expectEqual(guestMode, static_cast<std::uint16_t>(hostMetadata.st_mode),
                "fstat64 stdout returned the wrong mode");
    expectEqual(guestSize, static_cast<std::int64_t>(hostMetadata.st_size),
                "fstat64 stdout returned the wrong size");
    expectEqual(guestBlockSize, static_cast<std::int32_t>(hostMetadata.st_blksize),
                "fstat64 stdout returned the wrong block size");

    addressSpace.writeBytes(statAddress, sentinel);
    state.rax = fstat64Number;
    state.rdi = STDOUT_FILENO;
    state.rsi = page.value + rosa::guest::guestPageSize;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "fstat64 invalid output returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3}, "fstat64 invalid output did not set BSD carry");
    expect(std::ranges::equal(addressSpace.readBytes(statAddress, guestStatSize), sentinel),
           "faulted fstat64 changed a valid output buffer");

    state.rax = fstat64Number;
    state.rdi = 99;
    state.rsi = statAddress.value;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "fstat64 unknown descriptor returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "fstat64 unknown descriptor did not set BSD carry");
}

void testDarwinFstatHostReadOnlyFile() {
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto fstat64Number = UINT64_C(0x02000153);
    constexpr std::uint32_t openDirectory = 0x00100000;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress statAddress{0x8200};
    constexpr std::size_t guestStatSize = 144;
    const auto fixturePath =
        std::filesystem::canonical(std::filesystem::path{ROSA_TEST_HELLO_MACHO_PATH});
    const auto fixtureString = fixturePath.string();
    std::vector<std::uint8_t> fixtureBytes(fixtureString.begin(), fixtureString.end());
    fixtureBytes.push_back(0);
    struct stat hostMetadata{};
    expect(::stat(fixturePath.c_str(), &hostMetadata) == 0,
           "could not stat the host fstat fixture");

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
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{3}, "fstat-test open returned the wrong descriptor");

    state.rax = fstat64Number;
    state.rdi = 3;
    state.rsi = statAddress.value;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E30348ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "fstat64 mapped file did not return success");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "fstat64 mapped file did not clear BSD carry");
    const auto metadata = addressSpace.readBytes(statAddress, guestStatSize);
    std::uint16_t guestMode = 0;
    std::int64_t guestSize = 0;
    std::memcpy(&guestMode, metadata.data() + 4, sizeof(guestMode));
    std::memcpy(&guestSize, metadata.data() + 96, sizeof(guestSize));
    expectEqual(guestMode, static_cast<std::uint16_t>(hostMetadata.st_mode),
                "fstat64 mapped file returned the wrong mode");
    expectEqual(guestSize, static_cast<std::int64_t>(hostMetadata.st_size),
                "fstat64 mapped file returned the wrong size");

    // An unmapped output buffer reports EFAULT without touching the descriptor.
    state.rax = fstat64Number;
    state.rdi = 3;
    state.rsi = page.value + rosa::guest::guestPageSize;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "fstat64 mapped file with invalid output returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0x3},
                "fstat64 mapped file with invalid output did not set BSD carry");
    expectEqual(guestOpenedDescriptors(dispatcher), std::size_t{1},
                "faulted fstat64 changed descriptor-space size");

    // A hosted directory descriptor answers from its host descriptor.
    constexpr std::array<std::uint8_t, 2> directoryPath{'.', 0};
    addressSpace.writeBytes(pathAddress, directoryPath);
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = openDirectory;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{4}, "fstat-test directory open failed");
    state.rax = fstat64Number;
    state.rdi = 4;
    state.rsi = statAddress.value;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rflags, std::uint64_t{0x8D6}, "fstat64 hosted directory did not succeed");
    std::uint16_t directoryMode = 0;
    std::memcpy(&directoryMode, addressSpace.readBytes(rosa::guest::GuestAddress{statAddress.value + 4}, 2).data(),
                sizeof(directoryMode));
    expect(S_ISDIR(directoryMode), "fstat64 hosted directory did not report a directory");

    // A synthetic descriptor has no host metadata and stays loud.
    constexpr std::uint32_t rootFlags = 0x20100000;
    constexpr std::array<std::uint8_t, 2> rootPath{'/', 0};
    addressSpace.writeBytes(pathAddress, rootPath);
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = rootFlags;
    state.rdx = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{5}, "fstat-test synthetic root open failed");
    state.rax = fstat64Number;
    state.rdi = 5;
    state.rsi = statAddress.value;
    bool unsupportedKind = false;
    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    } catch (const std::runtime_error &error) {
        unsupportedKind =
            std::string_view(error.what()).find("synthetic guest descriptors") != std::string_view::npos;
    }
    expect(unsupportedKind, "fstat64 synthetic descriptor did not fail loudly");
}

void testDarwinLseekHostReadOnlyFile() {
    // Observed under head: stdio seeks back over its read-ahead buffer.
    constexpr auto openNumber = UINT64_C(0x02000005);
    constexpr auto readNumber = UINT64_C(0x02000003);
    constexpr auto lseekNumber = UINT64_C(0x020000C7);
    constexpr int seekSet = 0;
    constexpr int seekCurrent = 1;
    constexpr int seekEnd = 2;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress pathAddress{0x8100};
    constexpr rosa::guest::GuestAddress bufferAddress{0x8200};
    const auto fixturePath =
        std::filesystem::canonical(std::filesystem::path{ROSA_TEST_HELLO_MACHO_PATH});
    std::ifstream fixtureStream(fixturePath, std::ios::binary);
    std::vector<std::uint8_t> fixtureBytes((std::istreambuf_iterator<char>(fixtureStream)),
                                           std::istreambuf_iterator<char>());
    expect(fixtureBytes.size() > 32, "lseek test fixture is too small");

    const auto fixtureString = fixturePath.string();
    std::vector<std::uint8_t> pathBytes(fixtureString.begin(), fixtureString.end());
    pathBytes.push_back(0);
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeBytes(pathAddress, pathBytes);
    rosa::darwin::SyscallDispatcher dispatcher;

    rosa::x86::X86State state;
    state.rax = openNumber;
    state.rdi = pathAddress.value;
    state.rsi = O_RDONLY;
    state.rdx = 0;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{3}, "lseek-test open returned the wrong descriptor");

    const auto seek = [&](std::int64_t offset, int whence) {
        state.rax = lseekNumber;
        state.rdi = 3;
        state.rsi = static_cast<std::uint64_t>(offset);
        state.rdx = static_cast<std::uint64_t>(whence);
        state.rflags = 0xAD7;
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    };
    const auto read = [&](std::uint64_t count) {
        state.rax = readNumber;
        state.rdi = 3;
        state.rsi = bufferAddress.value;
        state.rdx = count;
        state.rflags = 0xAD7;
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    };

    seek(10, seekSet);
    expectEqual(state.rax, std::uint64_t{10}, "lseek SEEK_SET returned the wrong position");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "lseek SEEK_SET did not clear BSD carry");
    read(4);
    expectEqual(state.rax, std::uint64_t{4}, "post-seek read returned the wrong count");
    expect(addressSpace.readBytes(bufferAddress, 4) ==
               std::vector<std::uint8_t>(fixtureBytes.begin() + 10, fixtureBytes.begin() + 14),
           "post-seek read returned the wrong bytes");

    // SEEK_CUR backs up over the bytes just read, like stdio's seek-back.
    seek(-4, seekCurrent);
    expectEqual(state.rax, std::uint64_t{10}, "lseek SEEK_CUR returned the wrong position");
    read(4);
    expect(addressSpace.readBytes(bufferAddress, 4) ==
               std::vector<std::uint8_t>(fixtureBytes.begin() + 10, fixtureBytes.begin() + 14),
           "re-read after SEEK_CUR returned the wrong bytes");

    seek(0, seekEnd);
    expectEqual(state.rax, fixtureBytes.size(), "lseek SEEK_END returned the wrong size");
    seek(-static_cast<std::int64_t>(fixtureBytes.size()), seekCurrent);
    expectEqual(state.rax, std::uint64_t{0}, "lseek back to origin failed");

    // Seeking before the origin is EINVAL and leaves the position alone.
    seek(-1, seekSet);
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "negative lseek SEEK_SET returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "negative lseek SEEK_SET did not set BSD carry");
    read(4);
    expect(addressSpace.readBytes(bufferAddress, 4) ==
               std::vector<std::uint8_t>(fixtureBytes.begin(), fixtureBytes.begin() + 4),
           "failed lseek moved the file position");

    seek(0, 99);
    expectEqual(state.rax, static_cast<std::uint64_t>(EINVAL),
                "lseek with a bad whence returned the wrong errno");

    state.rax = lseekNumber;
    state.rdi = 99;
    state.rsi = 0;
    state.rdx = seekSet;
    state.rflags = 0x2;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EBADF),
                "lseek unknown descriptor returned the wrong errno");
}

void testDarwinWriteNoCancel() {
    constexpr auto writeNoCancelNumber = UINT64_C(0x0200018D);
    constexpr rosa::guest::GuestAddress page{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = writeNoCancelNumber;
    state.rdi = STDOUT_FILENO;
    state.rsi = page.value;
    state.rdx = 0;
    state.r10 = 0x4000;
    state.rflags = 0xAD7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E32C00ULL});
    expect(!outcome.exited, "write_nocancel terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "zero-length write_nocancel returned the wrong count");
    expectEqual(state.rflags, std::uint64_t{0xAD6}, "write_nocancel did not clear BSD carry");
    expectEqual(state.r10, std::uint64_t{0x4000},
                "write_nocancel changed an ignored argument register");
}

void testDarwinGetfsstat64SyntheticRoot() {
    constexpr auto getfsstat64Number = UINT64_C(0x0200015B);
    constexpr std::uint64_t recordSize = 2168;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress output{0x8100};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = getfsstat64Number;
    state.rdi = 0;
    state.rsi = 0;
    state.rdx = 2;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802AEEC68ULL}));
    expectEqual(state.rax, std::uint64_t{1},
                "getfsstat64 count query returned the wrong mount count");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "getfsstat64 count query did not clear BSD carry");

    state.rax = getfsstat64Number;
    state.rdi = output.value;
    state.rsi = recordSize;
    state.rdx = 2;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{1},
                "getfsstat64 buffer query returned the wrong mount count");
    expectEqual(addressSpace.readU32(output),
                static_cast<std::uint32_t>(rosa::guest::guestPageSize),
                "getfsstat64 root block size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{output.value + 64}),
                std::uint32_t{0x5001}, "getfsstat64 root mount flags differ");
    const auto filesystemType =
        addressSpace.readBytes(rosa::guest::GuestAddress{output.value + 72}, 5);
    expect(filesystemType == std::vector<std::uint8_t>({'a', 'p', 'f', 's', 0}),
           "getfsstat64 filesystem type differs");
    const auto mountedOn = addressSpace.readBytes(rosa::guest::GuestAddress{output.value + 88}, 2);
    expect(mountedOn == std::vector<std::uint8_t>({'/', 0}), "getfsstat64 mount point differs");

    constexpr std::array<std::uint8_t, 4> sentinel{0xA5, 0xA5, 0xA5, 0xA5};
    addressSpace.writeBytes(output, sentinel);
    state.rax = getfsstat64Number;
    state.rdi = output.value;
    state.rsi = recordSize - 1;
    state.rdx = 2;
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "undersized getfsstat64 buffer returned a record");
    expectEqual(addressSpace.readBytes(output, sentinel.size()),
                std::vector<std::uint8_t>(sentinel.begin(), sentinel.end()),
                "undersized getfsstat64 changed its buffer");

    state.rax = getfsstat64Number;
    state.rdi = 0xA000;
    state.rsi = recordSize;
    state.rdx = 2;
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "getfsstat64 invalid buffer returned the wrong errno");
    expect((state.rflags & 1U) != 0, "getfsstat64 invalid buffer did not set BSD carry");
}

} // namespace

std::span<const TestCase> darwinFilesTests() {
    static const TestCase cases[]{
        {"Darwin getdirentries host directory", testDarwinGetdirentriesHostDirectory},
        {"Darwin fstatfs host directory", testDarwinFstatfsHostDirectory},
        {"Darwin open directory within current directory", testDarwinOpenDirectoryWithinCurrentDirectory},
        {"Darwin open current directory", testDarwinOpenCurrentDirectory},
        {"Darwin FeatureFlags shm_open probe", testDarwinFeatureFlagsShmOpenProbe},
        {"Darwin csops unsigned status", testDarwinCsopsUnsignedStatus},
        {"Darwin csops_audittoken unsigned DER entitlements", testDarwinCsopsAuditTokenUnsignedDerEntitlements},
        {"Darwin open/read urandom nocancel", testDarwinOpenAndReadUrandomNoCancel},
        {"Darwin open guest root directory", testDarwinOpenGuestRootDirectory},
        {"Darwin openat guest cryptex directory", testDarwinOpenatGuestCryptexDirectory},
        {"Darwin duplicate guest descriptor", testDarwinDuplicateGuestDescriptor},
        {"Darwin stat64 mapped file", testDarwinStat64MappedFile},
        {"Darwin stat64 outside-sandbox directory", testDarwinStat64OutsideSandboxDirectory},
        {"Darwin lstat64 mapped directory", testDarwinLstat64MappedDirectory},
        {"Darwin stat64 mapped directory", testDarwinStat64MappedDirectory},
        {"Darwin stat64 absent system databases", testDarwinStat64SystemDatabasesAbsent},
        {"Darwin stat64 relative path", testDarwinStat64RelativePath},
        {"Darwin fstat64 standard descriptor", testDarwinFstat64StandardDescriptor},
        {"Darwin fstat64 mapped read-only file", testDarwinFstatHostReadOnlyFile},
        {"Darwin lseek mapped read-only file", testDarwinLseekHostReadOnlyFile},
        {"Darwin write_nocancel", testDarwinWriteNoCancel},
        {"Darwin getfsstat64 synthetic root", testDarwinGetfsstat64SyntheticRoot},
    };
    return cases;
}

} // namespace rosa::tests
