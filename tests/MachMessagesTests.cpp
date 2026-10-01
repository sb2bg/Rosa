#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testMachMessage2Diagnostic() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    std::array<std::uint8_t, 100> message{};
    const auto encode32 = [&message](std::size_t offset, std::uint32_t value) {
        std::memcpy(message.data() + offset, &value, sizeof(value));
    };
    encode32(0, 0x80001513U);
    encode32(4, static_cast<std::uint32_t>(message.size()));
    encode32(8, 0x103U);
    encode32(12, 0x403U);
    encode32(16, 0);
    encode32(20, 4811U);
    encode32(24, 1);
    encode32(28, 0x503U);
    message[38] = 0x13;
    message[39] = 0;

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "mach_msg2 request");
    addressSpace.writeBytes(messageAddress, message);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "mach_msg2 arguments");
    addressSpace.writeU64(stackAddress, 0xDEADBEEF); // wrapper return address
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U},
                          0x34U); // receive size 52, priority zero
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U},
                          0); // timeout

    rosa::darwin::MachDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = 0x0000006480001513ULL;
    state.r10 = 0x0000040300000103ULL;
    state.r8 = 0x000012CB00000000ULL;
    state.r9 = 0x0000040300000001ULL;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;

    try {
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8B664ULL});
        throw std::runtime_error("mach_msg2 diagnostic accepted unsupported IPC");
    } catch (const std::runtime_error &error) {
        const std::string_view diagnostic{error.what()};
        expect(diagnostic.find("unsupported Darwin guest mach_msg2 trap") != std::string_view::npos,
               "mach_msg2 diagnostic lacks its boundary class");
        expect(diagnostic.find("send-size: 100") != std::string_view::npos,
               "mach_msg2 diagnostic lacks the send size");
        expect(diagnostic.find("receive-size: 52") != std::string_view::npos,
               "mach_msg2 diagnostic lacks the stack receive size");
        expect(diagnostic.find("timeout: 0") != std::string_view::npos,
               "mach_msg2 diagnostic lacks the stack timeout");
        expect(diagnostic.find("header.id: 4811") != std::string_view::npos,
               "mach_msg2 diagnostic lacks the message ID");
        expect(diagnostic.find("descriptor[0].name: 0x503") != std::string_view::npos,
               "mach_msg2 diagnostic lacks the first descriptor name");
        expect(diagnostic.find("descriptor[0].disposition: 0x13") != std::string_view::npos,
               "mach_msg2 diagnostic lacks the descriptor disposition");
        expect(diagnostic.find("0000: 13 15 00 80") != std::string_view::npos,
               "mach_msg2 diagnostic lacks the raw request bytes");
    }
    expectEqual(state.rax, rosa::darwin::MachDispatcher::machMessage2TrapNumber,
                "mach_msg2 diagnostic mutated RAX");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "mach_msg2 diagnostic mutated flags");
    expectEqual(dispatcher.portSpace().size(), std::size_t{1},
                "mach_msg2 diagnostic mutated the guest port namespace");
}

void testMachMessage2HostBasicInfoRequest() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr std::uint32_t requestSize = 40;
    constexpr std::uint32_t receiveSize = 320;
    constexpr std::uint32_t replySize = 88;
    constexpr std::uint32_t trailerSize = 8;
    constexpr std::uint32_t messageBits = 0x1513;

    rosa::darwin::MachDispatcher dispatcher;
    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::hostSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto hostName = static_cast<std::uint32_t>(state.rax);
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto replyName = static_cast<std::uint32_t>(state.rax);

    std::array<std::uint8_t, requestSize> request{};
    const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    encode32(0, messageBits);
    encode32(4, requestSize);
    encode32(8, hostName);
    encode32(12, replyName);
    encode32(16, 0);
    encode32(20, 200);
    request[28] = 1;  // native little-endian NDR integer representation
    encode32(32, 1);  // HOST_BASIC_INFO
    encode32(36, 12); // HOST_BASIC_INFO_COUNT

    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "host_info message");
    addressSpace.writeBytes(messageAddress, request);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "host_info stack arguments");
    addressSpace.writeU64(stackAddress, 0xDEADBEEF);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);

    state = {};
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(requestSize) << 32U) | messageBits;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | hostName;
    state.r8 = std::uint64_t{200} << 32U;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8B664ULL});
    expectEqual(state.rax, std::uint64_t{0}, "host_info mach_msg2 did not return MACH_MSG_SUCCESS");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "host_info mach_msg2 changed guest flags");
    expectEqual(addressSpace.readU32(messageAddress), std::uint32_t{0x1200},
                "host_info reply bits differ");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 4}),
                replySize, "host_info reply size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 12}),
                replyName, "host_info reply port differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 20}),
                std::uint32_t{300}, "host_info reply ID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 32}),
                std::uint32_t{0}, "host_info MIG result differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 36}),
                std::uint32_t{12}, "host_info output count differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 52}),
                std::uint32_t{7}, "host_info did not expose x86 CPU type");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 56}),
                std::uint32_t{4}, "host_info did not expose x86 CPU subtype");
    const auto maximumCpus =
        addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 40});
    const auto availableCpus =
        addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 44});
    expect(maximumCpus >= availableCpus && availableCpus != 0,
           "host_info returned invalid guest CPU counts");
    expect(addressSpace.readU64(rosa::guest::GuestAddress{messageAddress.value + 80}) != 0,
           "host_info returned zero maximum memory");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 88}),
                std::uint32_t{0}, "host_info trailer type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 92}),
                trailerSize, "host_info trailer size differs");
    const auto *hostPort = dispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{hostName});
    expect(hostPort != nullptr && hostPort->type == rosa::darwin::GuestPortType::Host &&
               hostPort->sendUrefs == 1,
           "host_info consumed or changed the guest host send right");

    rosa::darwin::MachDispatcher faultDispatcher;
    rosa::x86::X86State faultState;
    faultState.rax = rosa::darwin::MachDispatcher::hostSelfTrapNumber;
    faultDispatcher.dispatch(addressSpace, faultState, rosa::guest::GuestAddress{0x1000});
    const auto faultHost = static_cast<std::uint32_t>(faultState.rax);
    faultState.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    faultDispatcher.dispatch(addressSpace, faultState, rosa::guest::GuestAddress{0x1000});
    const auto faultReply = static_cast<std::uint32_t>(faultState.rax);
    encode32(8, faultHost);
    encode32(12, faultReply);
    rosa::guest::AddressSpace readOnlyAddressSpace;
    readOnlyAddressSpace.mapSegment(messageAddress, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read, request,
                                    "read-only host_info message");
    readOnlyAddressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                                      rosa::guest::Permission::Read |
                                          rosa::guest::Permission::Write);
    readOnlyAddressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    readOnlyAddressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);
    faultState = state;
    faultState.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    faultState.r10 = (static_cast<std::uint64_t>(faultReply) << 32U) | faultHost;
    faultState.r9 = static_cast<std::uint64_t>(faultReply) << 32U;
    const auto before = readOnlyAddressSpace.readBytes(messageAddress, request.size());
    bool faulted = false;
    try {
        faultDispatcher.dispatch(readOnlyAddressSpace, faultState,
                                 rosa::guest::GuestAddress{0x7FF802A8B664ULL});
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("mach_msg2") != std::string_view::npos;
    }
    expect(faulted, "host_info accepted a non-writable reply buffer");
    expect(readOnlyAddressSpace.readBytes(messageAddress, request.size()) == before,
           "faulted host_info mutated the guest message buffer");
    expectEqual(faultState.rax, rosa::darwin::MachDispatcher::machMessage2TrapNumber,
                "faulted host_info changed the trap result register");
}

void testMachMessage2HostPriorityInfoRequest() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr std::uint32_t requestSize = 40;
    constexpr std::uint32_t receiveSize = 320;
    constexpr std::uint32_t replySize = 72;
    constexpr std::uint32_t messageBits = 0x1513;

    rosa::darwin::MachDispatcher dispatcher;
    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::hostSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto hostName = static_cast<std::uint32_t>(state.rax);
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto replyName = static_cast<std::uint32_t>(state.rax);

    std::array<std::uint8_t, requestSize> request{};
    const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    encode32(0, messageBits);
    encode32(4, requestSize);
    encode32(8, hostName);
    encode32(12, replyName);
    encode32(20, 200);
    request[28] = 1;
    encode32(32, 5); // HOST_PRIORITY_INFO
    encode32(36, 8); // HOST_PRIORITY_INFO_COUNT

    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "host priority message");
    addressSpace.writeBytes(messageAddress, request);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "host priority stack arguments");
    addressSpace.writeU64(stackAddress, 0xDEADBEEF);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);

    state = {};
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(requestSize) << 32U) | messageBits;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | hostName;
    state.r8 = std::uint64_t{200} << 32U;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    expectEqual(state.rax, std::uint64_t{0}, "host priority mach_msg2 did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "host priority mach_msg2 changed flags");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 4}),
                replySize, "host priority reply size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 32}),
                std::uint32_t{0}, "host priority MIG result differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 36}),
                std::uint32_t{8}, "host priority output count differs");
    const auto readPriority = [&addressSpace, messageAddress](std::uint64_t offset) {
        return std::bit_cast<std::int32_t>(
            addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + offset}));
    };
    const auto kernelPriority = readPriority(40);
    const auto userPriority = readPriority(52);
    const auto minimumPriority = readPriority(64);
    const auto maximumPriority = readPriority(68);
    expect(minimumPriority <= userPriority && userPriority <= maximumPriority &&
               kernelPriority > maximumPriority,
           "host priority reply returned an incoherent range");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 72}),
                std::uint32_t{0}, "host priority trailer type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 76}),
                std::uint32_t{8}, "host priority trailer size differs");
}

void testMachMessage2HostClockServiceRequest() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr std::uint32_t requestSize = 36;
    constexpr std::uint32_t receiveSize = 48;
    constexpr std::uint32_t replySize = 40;
    constexpr std::uint32_t messageBits = 0x1513;

    rosa::darwin::MachDispatcher dispatcher;
    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::hostSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto hostName = static_cast<std::uint32_t>(state.rax);
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto replyName = static_cast<std::uint32_t>(state.rax);

    std::array<std::uint8_t, requestSize> request{};
    const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    encode32(0, messageBits);
    encode32(4, requestSize);
    encode32(8, hostName);
    encode32(12, replyName);
    encode32(20, 206); // host_get_clock_service
    request[28] = 1;   // native little-endian NDR integer representation
    encode32(32, 0);   // SYSTEM_CLOCK

    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "host clock-service message");
    addressSpace.writeBytes(messageAddress, request);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "host clock-service stack arguments");
    addressSpace.writeU64(stackAddress, 0xDEADBEEF);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);

    state = {};
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(requestSize) << 32U) | messageBits;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | hostName;
    state.r8 = std::uint64_t{206} << 32U;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    expectEqual(state.rax, std::uint64_t{0}, "host clock-service mach_msg2 did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "host clock-service mach_msg2 changed flags");
    expectEqual(addressSpace.readU32(messageAddress), std::uint32_t{0x80001200},
                "host clock-service reply bits differ");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 4}),
                replySize, "host clock-service reply size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 8}),
                std::uint32_t{0}, "host clock-service reply remote port differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 12}),
                replyName, "host clock-service reply local port differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 20}),
                std::uint32_t{306}, "host clock-service reply ID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 24}),
                std::uint32_t{1}, "host clock-service descriptor count differs");
    const auto clockName =
        addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 28});
    expect(clockName != 0 && clockName != hostName && clockName != replyName,
           "host clock-service returned an invalid clock port name");
    expectEqual(
        addressSpace.readBytes(rosa::guest::GuestAddress{messageAddress.value + 38}, 1).front(),
        std::uint8_t{17}, "host clock-service descriptor disposition differs");
    expectEqual(
        addressSpace.readBytes(rosa::guest::GuestAddress{messageAddress.value + 39}, 1).front(),
        std::uint8_t{0}, "host clock-service descriptor type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 40}),
                std::uint32_t{0}, "host clock-service trailer type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 44}),
                std::uint32_t{8}, "host clock-service trailer size differs");
    const auto *clockPort =
        dispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{clockName});
    expect(clockPort != nullptr && clockPort->type == rosa::darwin::GuestPortType::Clock &&
               !clockPort->hasReceiveRight && clockPort->sendUrefs == 1 &&
               clockPort->sendOnceUrefs == 0 && clockPort->context == 0,
           "host clock-service returned an invalid guest clock right");
}

void testMachMessage2HostGetSpecialPortRequest() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr std::uint32_t requestSize = 40;
    constexpr std::uint32_t receiveSize = 48;
    constexpr std::uint32_t replySize = 40;
    constexpr std::uint32_t messageBits = 0x1513;

    rosa::darwin::MachDispatcher dispatcher;
    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::hostSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto hostName = static_cast<std::uint32_t>(state.rax);
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto replyName = static_cast<std::uint32_t>(state.rax);

    std::array<std::uint8_t, requestSize> request{};
    const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    encode32(0, messageBits);
    encode32(4, requestSize);
    encode32(8, hostName);
    encode32(12, replyName);
    encode32(20, 412); // host_get_special_port
    request[28] = 1;   // native little-endian NDR integer representation
    encode32(32, 0xFFFFFFFFU); // HOST_LOCAL_NODE
    encode32(36, 1);           // HOST_PORT

    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "host special-port message");
    addressSpace.writeBytes(messageAddress, request);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "host special-port stack arguments");
    addressSpace.writeU64(stackAddress, 0xDEADBEEF);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);

    state = {};
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(requestSize) << 32U) | messageBits;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | hostName;
    state.r8 = std::uint64_t{412} << 32U;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    expectEqual(state.rax, std::uint64_t{0}, "host special-port mach_msg2 did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "host special-port mach_msg2 changed flags");
    expectEqual(addressSpace.readU32(messageAddress), std::uint32_t{0x80001200},
                "host special-port reply bits differ");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 4}),
                replySize, "host special-port reply size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 12}),
                replyName, "host special-port reply local port differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 20}),
                std::uint32_t{512}, "host special-port reply ID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 24}),
                std::uint32_t{1}, "host special-port descriptor count differs");
    const auto returnedName =
        addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 28});
    expectEqual(returnedName, hostName, "host special-port demotion returned the wrong port");
    const auto *hostPort =
        dispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{returnedName});
    expect(hostPort != nullptr && hostPort->type == rosa::darwin::GuestPortType::Host &&
               hostPort->sendUrefs == 2,
           "host special-port demotion did not add a host send right");
}

void testMachMessage2BootstrapSendFailsFast() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr std::uint32_t requestSize = 40;
    constexpr std::uint32_t receiveSize = 48;
    constexpr std::uint32_t messageBits = 0x80131513;

    rosa::darwin::MachDispatcher dispatcher;
    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto taskName = static_cast<std::uint32_t>(state.rax);
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto replyName = static_cast<std::uint32_t>(state.rax);

    // Fetch the synthetic bootstrap port through task_get_special_port.
    std::array<std::uint8_t, 36> bootstrapRequest{};
    const auto encodeBootstrap32 = [&bootstrapRequest](std::size_t offset, std::uint32_t value) {
        std::memcpy(bootstrapRequest.data() + offset, &value, sizeof(value));
    };
    encodeBootstrap32(0, 0x1513);
    encodeBootstrap32(4, 36);
    encodeBootstrap32(8, taskName);
    encodeBootstrap32(12, replyName);
    encodeBootstrap32(20, 3409);
    bootstrapRequest[28] = 1;
    encodeBootstrap32(32, 4);
    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "bootstrap fetch message");
    addressSpace.writeBytes(messageAddress, bootstrapRequest);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "bootstrap fetch stack arguments");
    addressSpace.writeU64(stackAddress, 0xDEADBEEF);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);
    state = {};
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(36) << 32U) | 0x1513;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | taskName;
    state.r8 = std::uint64_t{3409} << 32U;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{0}, "bootstrap fetch did not succeed");
    const auto bootstrapName =
        addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 28});
    expect(bootstrapName != 0, "bootstrap fetch returned a null port");

    // Sends to the serverless bootstrap port fail instead of blocking.
    std::array<std::uint8_t, requestSize> request{};
    const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    encode32(0, messageBits);
    encode32(4, requestSize);
    encode32(8, bootstrapName);
    encode32(12, replyName);
    encode32(20, 0x400000CF);
    addressSpace.writeBytes(messageAddress, request);
    state = {};
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(requestSize) << 32U) | messageBits;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | bootstrapName;
    state.r8 = (std::uint64_t{0x400000CF} << 32U) | 1U;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{0x10000003},
                "bootstrap send did not fail fast with invalid destination");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "failed bootstrap send changed flags");
}

void testMachMessage2TaskGetBootstrapPortRequest() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr std::uint32_t requestSize = 36;
    constexpr std::uint32_t receiveSize = 48;
    constexpr std::uint32_t replySize = 40;
    constexpr std::uint32_t messageBits = 0x1513;

    rosa::darwin::MachDispatcher dispatcher;
    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto taskName = static_cast<std::uint32_t>(state.rax);
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto replyName = static_cast<std::uint32_t>(state.rax);

    std::array<std::uint8_t, requestSize> request{};
    const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    encode32(0, messageBits);
    encode32(4, requestSize);
    encode32(8, taskName);
    encode32(12, replyName);
    encode32(20, 3409); // task_get_special_port
    request[28] = 1;    // native little-endian NDR integer representation
    encode32(32, 4);    // TASK_BOOTSTRAP_PORT

    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "task_get_special_port message");
    addressSpace.writeBytes(messageAddress, request);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "task_get_special_port stack arguments");
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);

    state = {};
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(requestSize) << 32U) | messageBits;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | taskName;
    state.r8 = std::uint64_t{3409} << 32U;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    expectEqual(state.rax, std::uint64_t{0},
                "task_get_special_port mach_msg2 did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "task_get_special_port mach_msg2 changed flags");
    expectEqual(addressSpace.readU32(messageAddress), std::uint32_t{0x80001200},
                "task_get_special_port reply bits differ");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 4}),
                replySize, "task_get_special_port reply size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 12}),
                replyName, "task_get_special_port reply port differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 20}),
                std::uint32_t{3509}, "task_get_special_port reply ID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 24}),
                std::uint32_t{1}, "task_get_special_port descriptor count differs");
    const auto bootstrapName =
        addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 28});
    expect(bootstrapName != 0 && bootstrapName != taskName && bootstrapName != replyName,
           "task_get_special_port returned an invalid bootstrap name");
    const auto descriptorTail =
        addressSpace.readBytes(rosa::guest::GuestAddress{messageAddress.value + 38}, 2);
    expectEqual(descriptorTail[0], std::uint8_t{17},
                "task_get_special_port descriptor disposition differs");
    expectEqual(descriptorTail[1], std::uint8_t{0},
                "task_get_special_port descriptor type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 40}),
                std::uint32_t{0}, "task_get_special_port trailer type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 44}),
                std::uint32_t{8}, "task_get_special_port trailer size differs");
    const auto *bootstrapPort =
        dispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{bootstrapName});
    expect(bootstrapPort != nullptr &&
               bootstrapPort->type == rosa::darwin::GuestPortType::Bootstrap &&
               !bootstrapPort->hasReceiveRight && bootstrapPort->sendUrefs == 1 &&
               bootstrapPort->sendOnceUrefs == 0,
           "task_get_special_port returned an invalid bootstrap right");

    rosa::darwin::MachDispatcher faultDispatcher;
    rosa::x86::X86State setupState;
    setupState.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    faultDispatcher.dispatch(addressSpace, setupState, rosa::guest::GuestAddress{0x1000});
    setupState.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    faultDispatcher.dispatch(addressSpace, setupState, rosa::guest::GuestAddress{0x1000});
    rosa::guest::AddressSpace faultAddressSpace;
    faultAddressSpace.mapSegment(messageAddress, rosa::guest::guestPageSize,
                                 rosa::guest::Permission::Read, request,
                                 "read-only task_get_special_port message");
    faultAddressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                                   rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                                   "task_get_special_port fault stack");
    faultAddressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    faultAddressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);
    auto faultState = state;
    faultState.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        faultDispatcher.dispatch(faultAddressSpace, faultState,
                                 rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("mach_msg2") != std::string_view::npos;
    }
    expect(faulted, "task_get_special_port accepted a read-only reply buffer");
    expectEqual(faultDispatcher.portSpace().size(), std::size_t{2},
                "faulted task_get_special_port allocated a bootstrap right");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted task_get_special_port changed flags");
}

void testMachMessage2TaskAuditTokenRequest() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr std::uint32_t requestSize = 40;
    constexpr std::uint32_t receiveCapacity = 424;
    constexpr std::uint32_t replySize = 72;
    constexpr std::uint32_t replyAndTrailerSize = 80;
    constexpr std::uint32_t messageBits = 0x1513;

    rosa::darwin::MachDispatcher dispatcher;
    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto taskName = static_cast<std::uint32_t>(state.rax);
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto replyName = static_cast<std::uint32_t>(state.rax);

    std::array<std::uint8_t, requestSize> request{};
    const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    encode32(0, messageBits);
    encode32(4, requestSize);
    encode32(8, taskName);
    encode32(12, replyName);
    encode32(20, 3405); // task_info
    request[28] = 1;    // native little-endian NDR integer representation
    encode32(32, 15);   // TASK_AUDIT_TOKEN
    encode32(36, 8);    // TASK_AUDIT_TOKEN_COUNT

    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "task audit-token message");
    addressSpace.writeBytes(messageAddress, request);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "task audit-token stack arguments");
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveCapacity);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);

    audit_token_t expectedToken{};
    mach_msg_type_number_t expectedCount = TASK_AUDIT_TOKEN_COUNT;
    expectEqual(task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                          reinterpret_cast<task_info_t>(&expectedToken), &expectedCount),
                KERN_SUCCESS, "host TASK_AUDIT_TOKEN setup query failed");
    expectEqual(expectedCount, mach_msg_type_number_t{8},
                "host TASK_AUDIT_TOKEN setup count differs");

    state = {};
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(requestSize) << 32U) | messageBits;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | taskName;
    state.r8 = std::uint64_t{3405} << 32U;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    expectEqual(state.rax, std::uint64_t{0},
                "task_info audit-token mach_msg2 did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "task_info audit-token mach_msg2 changed flags");
    expectEqual(addressSpace.readU32(messageAddress), std::uint32_t{0x1200},
                "task_info audit-token reply bits differ");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 4}),
                replySize, "task_info audit-token reply size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 12}),
                replyName, "task_info audit-token reply port differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 20}),
                std::uint32_t{3505}, "task_info audit-token reply ID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 32}),
                std::uint32_t{0}, "task_info audit-token reply RetCode differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 36}),
                std::uint32_t{8}, "task_info audit-token reply count differs");
    for (std::size_t index = 0; index < 8; ++index) {
        expectEqual(addressSpace.readU32(
                        rosa::guest::GuestAddress{messageAddress.value + 40U + index * 4U}),
                    static_cast<std::uint32_t>(expectedToken.val[index]),
                    "task_info audit-token reply value differs");
    }
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 72}),
                std::uint32_t{0}, "task_info audit-token trailer type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 76}),
                std::uint32_t{8}, "task_info audit-token trailer size differs");
    expectEqual(replyAndTrailerSize, std::uint32_t{80},
                "task_info audit-token reply fixture size differs");

    rosa::darwin::MachDispatcher faultDispatcher;
    rosa::x86::X86State setupState;
    setupState.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    faultDispatcher.dispatch(addressSpace, setupState, rosa::guest::GuestAddress{0x1000});
    setupState.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    faultDispatcher.dispatch(addressSpace, setupState, rosa::guest::GuestAddress{0x1000});
    rosa::guest::AddressSpace faultAddressSpace;
    faultAddressSpace.mapSegment(messageAddress, rosa::guest::guestPageSize,
                                 rosa::guest::Permission::Read, request,
                                 "read-only task audit-token message");
    faultAddressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                                   rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                                   "task audit-token fault stack");
    faultAddressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveCapacity);
    faultAddressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);
    auto faultState = state;
    faultState.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        faultDispatcher.dispatch(faultAddressSpace, faultState,
                                 rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("mach_msg2") != std::string_view::npos;
    }
    expect(faulted, "task_info audit-token accepted a read-only reply buffer");
    expectEqual(faultDispatcher.portSpace().size(), std::size_t{2},
                "faulted task_info audit-token changed the port namespace");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted task_info audit-token changed flags");
}

void testMachMessage2TaskSetDebugControlPortRequest() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr rosa::guest::GuestAddress optionsPage{0xA000};
    constexpr rosa::guest::GuestAddress optionsAddress{0xA100};
    constexpr rosa::guest::GuestAddress outputAddress{0xA200};
    constexpr std::uint32_t requestSize = 52;
    constexpr std::uint32_t receiveSize = 44;
    constexpr std::uint32_t replySize = 36;
    constexpr std::uint32_t messageBits = 0x80001513;
    constexpr std::uint64_t guard = 0x71B75ACE;

    const auto setupPorts = [=](rosa::darwin::MachDispatcher &dispatcher,
                                rosa::guest::AddressSpace &addressSpace) {
        addressSpace.mapAnonymous(optionsPage, rosa::guest::guestPageSize,
                                  rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                                  "task_set_special_port construction arguments");
        std::array<std::uint8_t, 24> options{};
        const std::uint32_t flags = 0x31;
        std::memcpy(options.data(), &flags, sizeof(flags));
        addressSpace.writeBytes(optionsAddress, options);

        rosa::x86::X86State state;
        state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
        const auto taskName = static_cast<std::uint32_t>(state.rax);
        state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
        const auto replyName = static_cast<std::uint32_t>(state.rax);
        state = {};
        state.rax = rosa::darwin::MachDispatcher::portConstructTrapNumber;
        state.rdi = taskName;
        state.rsi = optionsAddress.value;
        state.rdx = guard;
        state.r10 = outputAddress.value;
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
        expectEqual(state.rax, std::uint64_t{0}, "task_set_special_port guarded-port setup failed");
        return std::array<std::uint32_t, 3>{taskName, replyName,
                                            addressSpace.readU32(outputAddress)};
    };

    rosa::darwin::MachDispatcher dispatcher;
    rosa::guest::AddressSpace addressSpace;
    const auto [taskName, replyName, specialName] = setupPorts(dispatcher, addressSpace);
    const auto *specialPort =
        dispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{specialName});
    expect(specialPort != nullptr && specialPort->hasReceiveRight && specialPort->sendUrefs == 1,
           "task_set_special_port setup produced the wrong guarded right");

    std::array<std::uint8_t, requestSize> request{};
    const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    encode32(0, messageBits);
    encode32(4, requestSize);
    encode32(8, taskName);
    encode32(12, replyName);
    encode32(20, 3410); // task_set_special_port
    encode32(24, 1);    // one port descriptor
    encode32(28, specialName);
    request[32] = 0xF8; // live descriptor padding is unspecified
    request[33] = 0x7F;
    request[34] = 0x5A;
    request[35] = 0xA5;
    request[36] = 0xC3;
    request[37] = 0x3C;
    request[38] = 19; // MACH_MSG_TYPE_COPY_SEND
    request[39] = 0;  // MACH_MSG_PORT_DESCRIPTOR
    request[44] = 1;  // native little-endian NDR integer representation
    encode32(48, 10); // TASK_DEBUG_CONTROL_PORT

    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "task_set_special_port message");
    addressSpace.writeBytes(messageAddress, request);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "task_set_special_port stack arguments");
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);

    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(requestSize) << 32U) | messageBits;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | taskName;
    state.r8 = std::uint64_t{3410} << 32U;
    state.r9 = (static_cast<std::uint64_t>(replyName) << 32U) | 1U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    expectEqual(state.rax, std::uint64_t{0},
                "task_set_special_port mach_msg2 did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "task_set_special_port mach_msg2 changed flags");
    expectEqual(addressSpace.readU32(messageAddress), std::uint32_t{0x1200},
                "task_set_special_port reply bits differ");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 4}),
                replySize, "task_set_special_port reply size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 12}),
                replyName, "task_set_special_port reply port differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 20}),
                std::uint32_t{3510}, "task_set_special_port reply ID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 32}),
                std::uint32_t{0}, "task_set_special_port reply RetCode differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 36}),
                std::uint32_t{0}, "task_set_special_port trailer type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 40}),
                std::uint32_t{8}, "task_set_special_port trailer size differs");
    expect(dispatcher.taskDebugControlPort() &&
               dispatcher.taskDebugControlPort()->value == specialName,
           "task_set_special_port did not bind the debug-control port");
    specialPort = dispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{specialName});
    expect(specialPort != nullptr && specialPort->hasReceiveRight && specialPort->sendUrefs == 1,
           "COPY_SEND changed the caller's guarded-port urefs");

    rosa::darwin::MachDispatcher faultDispatcher;
    rosa::guest::AddressSpace faultAddressSpace;
    const auto faultNames = setupPorts(faultDispatcher, faultAddressSpace);
    expectEqual(faultNames, std::array<std::uint32_t, 3>{taskName, replyName, specialName},
                "task_set_special_port fault setup names differ");
    faultAddressSpace.mapSegment(messageAddress, rosa::guest::guestPageSize,
                                 rosa::guest::Permission::Read, request,
                                 "read-only task_set_special_port message");
    faultAddressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                                   rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                                   "task_set_special_port fault stack");
    faultAddressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    faultAddressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);
    auto faultState = state;
    faultState.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    faultState.rflags = 0xAD7;
    bool faulted = false;
    try {
        faultDispatcher.dispatch(faultAddressSpace, faultState,
                                 rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    } catch (const std::runtime_error &error) {
        faulted = std::string_view(error.what()).find("mach_msg2") != std::string_view::npos;
    }
    expect(faulted, "task_set_special_port accepted a read-only reply buffer");
    expect(!faultDispatcher.taskDebugControlPort(),
           "faulted task_set_special_port changed task special-port state");
    const auto *faultPort =
        faultDispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{specialName});
    expect(faultPort != nullptr && faultPort->hasReceiveRight && faultPort->sendUrefs == 1,
           "faulted task_set_special_port changed guarded-port rights");
    expectEqual(faultState.rflags, std::uint64_t{0xAD7},
                "faulted task_set_special_port changed flags");
}

void testMachMessage2SemaphoreCreateRequest() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr std::uint32_t requestSize = 40;
    constexpr std::uint32_t receiveSize = 48;
    constexpr std::uint32_t messageBits = 0x1513;

    rosa::darwin::MachDispatcher dispatcher;
    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto taskName = static_cast<std::uint32_t>(state.rax);
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto replyName = static_cast<std::uint32_t>(state.rax);

    std::array<std::uint8_t, requestSize> request{};
    const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    encode32(0, messageBits);
    encode32(4, requestSize);
    encode32(8, taskName);
    encode32(12, replyName);
    encode32(20, 3418); // semaphore_create
    request[28] = 1;    // native little-endian NDR integer representation
    encode32(32, 0);    // SYNC_POLICY_FIFO
    encode32(36, 0);    // initial value

    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "semaphore_create message");
    addressSpace.writeBytes(messageAddress, request);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "semaphore_create stack arguments");
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);

    state = {};
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(requestSize) << 32U) | messageBits;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | taskName;
    state.r8 = std::uint64_t{3418} << 32U;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    expectEqual(state.rax, std::uint64_t{0}, "semaphore_create mach_msg2 did not return success");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "semaphore_create mach_msg2 changed flags");
    expectEqual(addressSpace.readU32(messageAddress), std::uint32_t{0x80001200},
                "semaphore_create reply bits differ");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 4}),
                std::uint32_t{40}, "semaphore_create reply size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 12}),
                replyName, "semaphore_create reply port differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 20}),
                std::uint32_t{3518}, "semaphore_create reply ID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 24}),
                std::uint32_t{1}, "semaphore_create descriptor count differs");
    const auto semaphoreName =
        addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 28});
    const auto descriptorTail =
        addressSpace.readBytes(rosa::guest::GuestAddress{messageAddress.value + 38}, 2);
    expectEqual(descriptorTail[0], std::uint8_t{17},
                "semaphore_create descriptor disposition differs");
    expectEqual(descriptorTail[1], std::uint8_t{0}, "semaphore_create descriptor type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 40}),
                std::uint32_t{0}, "semaphore_create trailer type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 44}),
                std::uint32_t{8}, "semaphore_create trailer size differs");
    const auto *semaphorePort =
        dispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{semaphoreName});
    expect(semaphorePort != nullptr &&
               semaphorePort->type == rosa::darwin::GuestPortType::Semaphore &&
               !semaphorePort->hasReceiveRight && semaphorePort->sendUrefs == 1 &&
               semaphorePort->sendOnceUrefs == 0 && semaphorePort->optionFlags == 0 &&
               semaphorePort->context == 0,
           "semaphore_create returned an invalid guest semaphore right");
}

void testMachMessage2RestartableRangesRegisterRequest() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr std::uint32_t requestSize = 276;
    constexpr std::uint32_t receiveSize = 44;
    constexpr std::uint32_t messageBits = 0x1513;
    constexpr std::array<std::uint64_t, 15> locations{
        0x7FF802A1BFF3ULL, 0x7FF802A1C09AULL, 0x7FF802A1C45AULL, 0x7FF802A1C65AULL,
        0x7FF802A1C85AULL, 0x7FF802A1C287ULL, 0x7FF802A1CA47ULL, 0x7FF802A1C30BULL,
        0x7FF802A1CACBULL, 0x7FF802A1C19AULL, 0x7FF802A1C55AULL, 0x7FF802A1C75AULL,
        0x7FF802A1C95AULL, 0x7FF802A1C38BULL, 0x7FF802A1CB4BULL,
    };
    constexpr std::array<std::uint16_t, 15> lengths{
        0x66, 0x5A, 0x5A, 0x5A, 0x63, 0x5A, 0x63, 0x5A, 0x63, 0x54, 0x54, 0x54, 0x54, 0x54, 0x54,
    };
    constexpr std::array<std::uint16_t, 15> recoveryOffsets{
        0x66, 0xA9, 0xAB, 0xAD, 0xAA, 0x5A, 0x63, 0x5A, 0x63, 0x9A, 0x9A, 0x9A, 0x9A, 0x54, 0x54,
    };

    rosa::darwin::MachDispatcher dispatcher;
    rosa::guest::AddressSpace addressSpace;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto taskName = static_cast<std::uint32_t>(state.rax);
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto replyName = static_cast<std::uint32_t>(state.rax);

    std::array<std::uint8_t, requestSize> request{};
    const auto encode16 = [&request](std::size_t offset, std::uint16_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    const auto encode64 = [&request](std::size_t offset, std::uint64_t value) {
        std::memcpy(request.data() + offset, &value, sizeof(value));
    };
    encode32(0, messageBits);
    encode32(4, requestSize);
    encode32(8, taskName);
    encode32(12, replyName);
    encode32(20, 8000);
    request[28] = 1;
    encode32(32, static_cast<std::uint32_t>(locations.size()));
    for (std::size_t index = 0; index < locations.size(); ++index) {
        const auto offset = 36U + index * 16U;
        encode64(offset, locations[index]);
        encode16(offset + 8U, lengths[index]);
        encode16(offset + 10U, recoveryOffsets[index]);
        encode32(offset + 12U, 0);
    }

    addressSpace.mapAnonymous(messageAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "task_restartable_ranges_register message");
    addressSpace.writeBytes(messageAddress, request);
    addressSpace.mapAnonymous(stackAddress, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "task_restartable_ranges_register stack arguments");
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, receiveSize);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);

    state = {};
    state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
    state.rdi = messageAddress.value;
    state.rsi = 0x0000000200000003ULL;
    state.rdx = (static_cast<std::uint64_t>(requestSize) << 32U) | messageBits;
    state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | taskName;
    state.r8 = std::uint64_t{8000} << 32U;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = stackAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    expectEqual(state.rax, std::uint64_t{0}, "restartable-ranges mach_msg2 did not complete");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "restartable-ranges mach_msg2 changed flags");
    expectEqual(addressSpace.readU32(messageAddress), std::uint32_t{0x1200},
                "restartable-ranges reply bits differ");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 4U}),
                std::uint32_t{36}, "restartable-ranges reply size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 12U}),
                replyName, "restartable-ranges reply port differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 20U}),
                std::uint32_t{8100}, "restartable-ranges reply ID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 32U}),
                std::uint32_t{6}, "translated restartable-ranges result differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 36U}),
                std::uint32_t{0}, "restartable-ranges trailer type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 40U}),
                std::uint32_t{8}, "restartable-ranges trailer size differs");
}

void testMachMessage2MachVmMapRequest() {
    constexpr rosa::guest::GuestAddress messageAddress{0x8000};
    constexpr rosa::guest::GuestAddress stackAddress{0x9000};
    constexpr rosa::guest::GuestAddress portArguments{0xA000};
    constexpr rosa::guest::GuestAddress targetAddress{0x7FF700000000ULL};
    constexpr std::uint64_t targetSize = 0x120000;
    constexpr std::uint32_t requestBits = 0x80001513U;
    constexpr std::uint64_t requestOptions = 0x0000000200000003ULL;

    rosa::guest::AddressSpace addressSpace;
    for (const auto base : {messageAddress, stackAddress, portArguments}) {
        addressSpace.mapAnonymous(base, rosa::guest::guestPageSize,
                                  rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                                  "mach_msg2 test arguments");
    }
    rosa::darwin::MachDispatcher dispatcher;

    rosa::x86::X86State setupState;
    setupState.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    dispatcher.dispatch(addressSpace, setupState, rosa::guest::GuestAddress{0x1000});
    expectEqual(setupState.rax, std::uint64_t{0x103}, "mach_msg2 setup did not acquire task-self");

    std::array<std::uint8_t, 24> options{};
    constexpr std::uint32_t mpoReplyPort = 0x1000;
    std::memcpy(options.data(), &mpoReplyPort, sizeof(mpoReplyPort));
    addressSpace.writeBytes(portArguments, options);
    setupState.rax = rosa::darwin::MachDispatcher::portConstructTrapNumber;
    setupState.rdi = 0x103;
    setupState.rsi = portArguments.value;
    setupState.rdx = 0;
    setupState.r10 = portArguments.value + 0x20;
    dispatcher.dispatch(addressSpace, setupState, rosa::guest::GuestAddress{0x1000});
    expectEqual(setupState.rax, std::uint64_t{0},
                "mach_msg2 setup could not construct its reply port");
    const auto replyName =
        addressSpace.readU32(rosa::guest::GuestAddress{portArguments.value + 0x20});

    const auto makeRequest = [replyName](std::uint64_t address, std::uint64_t size) {
        std::array<std::uint8_t, 100> request{};
        const auto encode32 = [&request](std::size_t offset, std::uint32_t value) {
            std::memcpy(request.data() + offset, &value, sizeof(value));
        };
        const auto encode64 = [&request](std::size_t offset, std::uint64_t value) {
            std::memcpy(request.data() + offset, &value, sizeof(value));
        };
        encode32(0, requestBits);
        encode32(4, static_cast<std::uint32_t>(request.size()));
        encode32(8, 0x103);
        encode32(12, replyName);
        encode32(16, 0);
        encode32(20, 4811);
        encode32(24, 1);
        encode32(28, 0); // null memory-object port
        // The generated client's descriptor padding is not architectural.
        encode32(32, 0x42000000);
        request[38] = 0x13; // MACH_MSG_TYPE_COPY_SEND
        request[39] = 0;    // MACH_MSG_PORT_DESCRIPTOR
        request[44] = 1;    // native little-endian NDR record
        encode64(48, address);
        encode64(56, size);
        encode64(64, 0xFFF);
        encode32(72, 0); // fixed mapping
        encode64(76, 0);
        encode32(84, 0); // no copy
        encode32(88, 0); // VM_PROT_NONE
        encode32(92, 0); // VM_PROT_NONE maximum
        encode32(96, 1); // VM_INHERIT_COPY
        return request;
    };
    const auto makeState = [replyName] {
        rosa::x86::X86State state;
        state.rax = rosa::darwin::MachDispatcher::machMessage2TrapNumber;
        state.rdi = messageAddress.value;
        state.rsi = requestOptions;
        state.rdx = (std::uint64_t{100} << 32U) | requestBits;
        state.r10 = (static_cast<std::uint64_t>(replyName) << 32U) | 0x103U;
        state.r8 = std::uint64_t{4811} << 32U;
        state.r9 = (static_cast<std::uint64_t>(replyName) << 32U) | 1U;
        state.rsp = stackAddress.value;
        state.rflags = 0x8D7;
        return state;
    };
    addressSpace.writeU64(stackAddress, 0xDEADBEEF);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 8U}, 52);
    addressSpace.writeU64(rosa::guest::GuestAddress{stackAddress.value + 16U}, 0);
    const auto request = makeRequest(targetAddress.value, targetSize);
    addressSpace.writeBytes(messageAddress, request);
    auto state = makeState();
    const auto portsBefore = dispatcher.portSpace().size();
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8B664ULL});

    expectEqual(state.rax, std::uint64_t{0},
                "local mach_vm_map mach_msg2 did not return MACH_MSG_SUCCESS");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "local mach_vm_map mach_msg2 changed flags");
    expectEqual(addressSpace.readU32(messageAddress), std::uint32_t{0x1200},
                "mach_vm_map reply bits differ");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 4}),
                std::uint32_t{44}, "mach_vm_map reply size differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 8}),
                std::uint32_t{0}, "mach_vm_map reply remote name differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 12}),
                replyName, "mach_vm_map reply local name differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 20}),
                std::uint32_t{4911}, "mach_vm_map reply ID differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 32}),
                std::uint32_t{0}, "mach_vm_map MIG result differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{messageAddress.value + 36}),
                targetAddress.value, "mach_vm_map reply address differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 44}),
                std::uint32_t{0}, "mach_vm_map trailer type differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 48}),
                std::uint32_t{8}, "mach_vm_map trailer size differs");
    expectEqual(dispatcher.portSpace().size(), portsBefore,
                "local mach_vm_map fabricated persistent Mach rights");

    const auto mappings = addressSpace.mappingInfos();
    const auto reservation =
        std::ranges::find_if(mappings, [targetAddress](const rosa::guest::MappingInfo &mapping) {
            return mapping.base == targetAddress;
        });
    expect(reservation != mappings.end(), "local mach_vm_map did not create the fixed reservation");
    expectEqual(reservation->size, static_cast<std::size_t>(targetSize),
                "local mach_vm_map reservation size differs");
    expect(reservation->permissions == rosa::guest::Permission::None &&
               reservation->maximumPermissions == rosa::guest::Permission::None,
           "local mach_vm_map reservation permissions differ");
    bool inaccessible = false;
    try {
        static_cast<void>(addressSpace.readU32(targetAddress));
    } catch (const std::runtime_error &error) {
        inaccessible = std::string_view(error.what()).find("permissions") != std::string_view::npos;
    }
    expect(inaccessible, "VM_PROT_NONE mach_vm_map reservation was guest-readable");

    // A collision still completes mach_msg2; KERN_NO_SPACE is returned in
    // the MIG reply and no additional mapping or right is created.
    addressSpace.writeBytes(messageAddress, request);
    state = makeState();
    const auto mappingsBeforeCollision = addressSpace.mappingCount();
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8B664ULL});
    expectEqual(state.rax, std::uint64_t{0}, "colliding mach_vm_map did not complete mach_msg2");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{messageAddress.value + 32}),
                std::uint32_t{3}, "colliding mach_vm_map did not return KERN_NO_SPACE");
    expectEqual(addressSpace.mappingCount(), mappingsBeforeCollision,
                "colliding mach_vm_map changed the mapping count");
    expectEqual(dispatcher.portSpace().size(), portsBefore,
                "colliding mach_vm_map changed the port namespace");
}

void testUnsupportedMachTrapDiagnostic() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::syscallClass | 31U;

    try {
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1234}));
        throw std::runtime_error("unsupported Mach trap was accepted");
    } catch (const std::runtime_error &error) {
        const std::string_view message{error.what()};
        expect(message.find("unsupported Darwin guest Mach trap") != std::string_view::npos,
               "unsupported Mach trap diagnostic lacks its boundary class");
        expect(message.find("trap: 31") != std::string_view::npos,
               "unsupported Mach trap diagnostic lacks the trap number");
        expect(message.find("RIP: 0x1234") != std::string_view::npos,
               "unsupported Mach trap diagnostic lacks guest RIP");
    }
}

} // namespace

std::span<const TestCase> machMessagesTests() {
    static const TestCase cases[]{
        {"Mach message2 diagnostic", testMachMessage2Diagnostic},
        {"Mach message2 host basic-info request", testMachMessage2HostBasicInfoRequest},
        {"Mach message2 host priority-info request", testMachMessage2HostPriorityInfoRequest},
        {"Mach message2 host clock-service request", testMachMessage2HostClockServiceRequest},
        {"Mach message2 host special-port request", testMachMessage2HostGetSpecialPortRequest},
        {"Mach message2 task bootstrap-port request", testMachMessage2TaskGetBootstrapPortRequest},
        {"Mach message2 bootstrap send fails fast", testMachMessage2BootstrapSendFailsFast},
        {"Mach message2 task audit-token request", testMachMessage2TaskAuditTokenRequest},
        {"Mach message2 task debug-control-port request", testMachMessage2TaskSetDebugControlPortRequest},
        {"Mach message2 semaphore-create request", testMachMessage2SemaphoreCreateRequest},
        {"Mach message2 restartable-ranges request", testMachMessage2RestartableRangesRegisterRequest},
        {"Mach message2 mach_vm_map request", testMachMessage2MachVmMapRequest},
        {"unsupported Mach trap diagnostic", testUnsupportedMachTrapDiagnostic},
    };
    return cases;
}

} // namespace rosa::tests
