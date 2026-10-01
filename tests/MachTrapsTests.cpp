#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testMachThreadSelfTrap() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::threadSelfTrapNumber;
    state.rdi = 0x1111111111111111ULL;
    state.rsi = 0x2222222222222222ULL;
    state.rdx = 0x3333333333333333ULL;
    state.r10 = 0x4444444444444444ULL;
    state.r8 = 0x5555555555555555ULL;
    state.r9 = 0x6666666666666666ULL;
    state.rflags = 0x8D7;

    auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FA68ULL});
    expect(!outcome.exited, "thread_self_trap terminated the guest");
    const rosa::darwin::GuestMachPortName name{static_cast<std::uint32_t>(state.rax)};
    expect(name.value != 0 && name.value != 0x103,
           "thread_self_trap returned an invalid or task-self name");
    const auto *port = dispatcher.machDispatcher().portSpace().lookup(name);
    expect(port != nullptr && port->type == rosa::darwin::GuestPortType::Thread,
           "thread_self_trap did not create a guest thread object");
    expect(!port->hasReceiveRight && port->sendUrefs == 1 && port->sendOnceUrefs == 0,
           "thread_self_trap created the wrong guest rights");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "thread_self_trap applied BSD carry semantics");
    expectEqual(state.rdi, std::uint64_t{0x1111111111111111ULL},
                "thread_self_trap changed an ignored argument register");
    expectEqual(state.rdx, std::uint64_t{0x3333333333333333ULL},
                "thread_self_trap changed an ignored argument register");

    state.rax = rosa::darwin::MachDispatcher::threadSelfTrapNumber;
    outcome = dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expect(!outcome.exited, "repeated thread_self_trap terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(name.value),
                "repeated thread_self_trap returned a different guest name");
    port = dispatcher.machDispatcher().portSpace().lookup(name);
    expect(port != nullptr && port->sendUrefs == 2,
           "repeated thread_self_trap did not add another send uref");
}

void testMachTimerCreateTrap() {
    // Observed under an AppKit fixture: trap 91 mints a timer port.
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    const rosa::darwin::MachDispatcher mach;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::timerCreateTrapNumber;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2F900ULL});
    expect(!outcome.exited, "mk_timer_create_trap terminated the guest");
    const rosa::darwin::GuestMachPortName name{static_cast<std::uint32_t>(state.rax)};
    expect(state.rax != 0, "mk_timer_create_trap returned a null port");
    const auto *port = dispatcher.machDispatcher().portSpace().lookup(name);
    expect(port != nullptr && port->hasReceiveRight,
           "timer port is absent from its namespace");
    expectEqual(port->type, rosa::darwin::GuestPortType::Timer,
                "mk_timer_create_trap created the wrong port type");
    expect(dispatcher.machDispatcher().ownsReceiveRight(name),
           "timer port is not receivable");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mk_timer_create_trap applied BSD carry-flag semantics");
}

void testMachPortInsertMemberTrap() {
    // Observed under an AppKit fixture: trap 22 moves a receive right into
    // a freshly allocated port set.
    rosa::guest::AddressSpace addressSpace;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress output{0x8100};
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    const rosa::darwin::MachDispatcher mach;
    const auto allocate = [&](std::uint32_t right) {
        rosa::x86::X86State state;
        state.rax = rosa::darwin::MachDispatcher::portAllocateTrapNumber;
        state.rdi = mach.taskSelfPortName().value;
        state.rsi = right;
        state.rdx = output.value;
        state.rflags = 0x8D7;
        static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
        expectEqual(state.rax, std::uint64_t{0}, "member fixture allocate failed");
        return rosa::darwin::GuestMachPortName{addressSpace.readU32(output)};
    };
    const auto portSet = allocate(3);
    const auto member = allocate(1);

    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::portInsertMemberTrapNumber;
    state.rdi = mach.taskSelfPortName().value;
    state.rsi = member.value;
    state.rdx = portSet.value;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FA2CULL});
    expect(!outcome.exited, "mach_port_insert_member terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "mach_port_insert_member did not succeed");
    const auto *set = dispatcher.machDispatcher().portSpace().lookup(portSet);
    expect(set != nullptr && set->members.size() == 1 && set->members.front() == member,
           "port set membership differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mach_port_insert_member applied BSD carry-flag semantics");

    // Idempotent re-insertion keeps one entry.
    state.rax = rosa::darwin::MachDispatcher::portInsertMemberTrapNumber;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "repeated insert_member failed");
    expectEqual(dispatcher.machDispatcher().portSpace().lookup(portSet)->members.size(),
                std::size_t{1}, "repeated insert_member duplicated the member");

    // A set cannot join a set.
    state.rax = rosa::darwin::MachDispatcher::portInsertMemberTrapNumber;
    state.rsi = portSet.value;
    state.rdx = portSet.value;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{17},
                "set-into-set insert returned the wrong code");

    // Unknown names miss.
    state.rax = rosa::darwin::MachDispatcher::portInsertMemberTrapNumber;
    state.rsi = 0xDEAD;
    state.rdx = member.value;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{15},
                "insert_member with a bad set returned the wrong code");
}

void testMachPortAllocateTrap() {
    // Observed under an AppKit fixture: trap 16 allocates a port set.
    rosa::guest::AddressSpace addressSpace;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress output{0x8100};
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    const rosa::darwin::MachDispatcher mach;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::portAllocateTrapNumber;
    state.rdi = mach.taskSelfPortName().value;
    state.rsi = 3; // MACH_PORT_RIGHT_PORT_SET.
    state.rdx = output.value;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2F9F0ULL});
    expect(!outcome.exited, "mach_port_allocate_trap terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "mach_port_allocate_trap did not succeed");
    const rosa::darwin::GuestMachPortName name{addressSpace.readU32(output)};
    const auto *port = dispatcher.machDispatcher().portSpace().lookup(name);
    expect(port != nullptr && port->hasReceiveRight,
           "allocated port set is absent from its namespace");
    expectEqual(port->type, rosa::darwin::GuestPortType::PortSet,
                "mach_port_allocate_trap created the wrong port type");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mach_port_allocate_trap applied BSD carry-flag semantics");

    state.rax = rosa::darwin::MachDispatcher::portAllocateTrapNumber;
    state.rdi = mach.taskSelfPortName().value;
    state.rsi = 0; // MACH_PORT_RIGHT_SEND is not allocatable.
    state.rdx = output.value;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{18},
                "mach_port_allocate_trap with a bad right returned the wrong code");
}

void testMachMessage2ReceiveTimedOut() {
    // A receive-only mach_msg2 call with MACH_RCV_TIMEOUT and a zero timeout
    // on an empty owned port times out at once. The receive size and timeout
    // are the 7th and 8th arguments, read from the guest stack.
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x7000000FF000ULL},
                              rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State allocateState;
    allocateState.rax = UINT64_C(0x0100001A);
    allocateState.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, allocateState, rosa::guest::GuestAddress{0x1000}));
    const auto replyName = static_cast<std::uint32_t>(allocateState.rax);
    expect(replyName != 0, "mach_reply_port did not allocate a receive right");

    rosa::x86::X86State state;
    state.rax = UINT64_C(0x0100002F);
    state.rsi = 0x102; // MACH_RCV_MSG | MACH_RCV_TIMEOUT, no send.
    state.rdx = 0;
    state.r10 = 0;
    state.r8 = 0;
    state.r9 = static_cast<std::uint64_t>(replyName) << 32U;
    state.rsp = 0x7000000FFF00ULL;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB4CULL});
    expect(!outcome.exited, "receive-only mach_msg2 terminated the guest");
    expectEqual(state.rax, std::uint64_t{0x10004003},
                "receive-only mach_msg2 did not time out");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "receive-only mach_msg2 applied BSD carry-flag semantics");

    state.rax = UINT64_C(0x0100002F);
    state.rsi = 0x102;
    state.r9 = static_cast<std::uint64_t>(0xDEAD) << 32U;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0x10004002},
                "receive-only mach_msg2 on a foreign port missed INVALID_NAME");
}

void testMachTimebaseInfoTrap() {
    // Observed in libsystem_kernel under an AppKit fixture: trap 89 fills
    // mach_timebase_info { numer, denom } for the virtual TSC rate.
    rosa::guest::AddressSpace addressSpace;
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress info{0x8100};
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::timebaseInfoTrapNumber;
    state.rdi = info.value;
    state.rflags = 0x8D7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FC18ULL});
    expect(!outcome.exited, "mach_timebase_info_trap terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "mach_timebase_info_trap did not succeed");
    expectEqual(addressSpace.readU32(info), std::uint32_t{1},
                "mach_timebase_info_trap numer differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{info.value + 4}),
                std::uint32_t{2}, "mach_timebase_info_trap denom differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mach_timebase_info_trap applied BSD carry-flag semantics");

    state.rax = rosa::darwin::MachDispatcher::timebaseInfoTrapNumber;
    state.rdi = 0x9000;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{1},
                "mach_timebase_info_trap on a bad address returned the wrong code");
}

void testMachTaskSelfTrap() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    const rosa::darwin::MachDispatcher mach;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    state.rdi = 0x1111111111111111ULL;
    state.rsi = 0x2222222222222222ULL;
    state.rdx = 0x3333333333333333ULL;
    state.r10 = 0x4444444444444444ULL;
    state.r8 = 0x5555555555555555ULL;
    state.r9 = 0x6666666666666666ULL;
    state.rflags = 0x8D7;

    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF80000158CULL});
    expect(!outcome.exited, "task_self_trap terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(mach.taskSelfPortName().value),
                "task_self_trap returned the wrong guest port name");
    expect(state.rax != 0 && state.rax <= UINT32_MAX,
           "task_self_trap did not return a valid 32-bit guest port name");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "task_self_trap applied BSD carry-flag semantics");
    expectEqual(state.rdi, std::uint64_t{0x1111111111111111ULL},
                "task_self_trap changed an argument register");
    expectEqual(state.r9, std::uint64_t{0x6666666666666666ULL},
                "task_self_trap changed an argument register");

    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(mach.taskSelfPortName().value),
                "repeated task_self_trap returned a different guest name");
}

void testGeneratedMachTaskSelfTrap() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x1C, 0x00, 0x00, 0x01, // mov eax, 0x100001c
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
    expect(!result.exited, "generated task_self_trap terminated the guest");
    expectEqual(state.rax, std::uint64_t{0x103},
                "generated task_self_trap returned the wrong guest port");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated syscall did not save its fallthrough in RCX");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated syscall did not save the input flags in R11");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "generated task_self_trap changed guest flags");
}

void testMachHostSelfTrap() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::hostSelfTrapNumber;
    state.rdi = 0x1111111111111111ULL;
    state.rsi = 0x2222222222222222ULL;
    state.rdx = 0x3333333333333333ULL;
    state.r10 = 0x4444444444444444ULL;
    state.r8 = 0x5555555555555555ULL;
    state.r9 = 0x6666666666666666ULL;
    state.rflags = 0x8D7;

    auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8B598ULL});
    expect(!outcome.exited, "host_self_trap terminated the guest");
    const rosa::darwin::GuestMachPortName name{static_cast<std::uint32_t>(state.rax)};
    expect(name.value != 0 && name.value != 0x103,
           "host_self_trap returned an invalid or task-self name");
    const auto *port = dispatcher.machDispatcher().portSpace().lookup(name);
    expect(port != nullptr && port->type == rosa::darwin::GuestPortType::Host,
           "host_self_trap did not create a guest host object");
    expect(!port->hasReceiveRight && port->sendUrefs == 1 && port->sendOnceUrefs == 0,
           "host_self_trap created the wrong guest rights");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "host_self_trap applied BSD carry semantics");
    expectEqual(state.rdi, std::uint64_t{0x1111111111111111ULL},
                "host_self_trap changed an ignored argument register");

    state.rax = rosa::darwin::MachDispatcher::hostSelfTrapNumber;
    outcome = dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expect(!outcome.exited, "repeated host_self_trap terminated the guest");
    expectEqual(state.rax, static_cast<std::uint64_t>(name.value),
                "repeated host_self_trap returned a different guest name");
    port = dispatcher.machDispatcher().portSpace().lookup(name);
    expect(port != nullptr && port->sendUrefs == 2,
           "repeated host_self_trap did not copy out another send uref");
}

void testGeneratedMachHostSelfTrap() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x1D, 0x00, 0x00, 0x01, // mov eax, 0x100001d
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
    expect(!result.exited, "generated host_self_trap terminated the guest");
    expect(state.rax != 0 && state.rax != 0x103,
           "generated host_self_trap returned an invalid name");
    const auto *port = dispatcher.machDispatcher().portSpace().lookup(
        rosa::darwin::GuestMachPortName{static_cast<std::uint32_t>(state.rax)});
    expect(port != nullptr && port->type == rosa::darwin::GuestPortType::Host &&
               port->sendUrefs == 1,
           "generated host_self_trap did not create a host send right");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated host_self_trap saved the wrong fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated host_self_trap saved the wrong input flags");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "generated host_self_trap changed guest flags");
}

void testMachPortModRefsTrap() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::MachDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto taskSelf = state.rax;

    state.rax = rosa::darwin::MachDispatcher::portModRefsTrapNumber;
    state.rdi = taskSelf;
    state.rsi = taskSelf;
    state.rdx = 0;          // MACH_PORT_RIGHT_SEND
    state.r10 = UINT32_MAX; // signed delta -1 through the 32-bit trap ABI
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8B520ULL});
    expectEqual(state.rax, std::uint64_t{0},
                "mach_port_mod_refs did not drop the task-self send right");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mach_port_mod_refs applied BSD carry semantics");

    state.rax = rosa::darwin::MachDispatcher::portModRefsTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{15},
                "mach_port_mod_refs missing name returned the wrong result");

    state.rax = rosa::darwin::MachDispatcher::taskSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    state.rax = rosa::darwin::MachDispatcher::portModRefsTrapNumber;
    state.r10 = UINT32_MAX - 1U; // signed delta -2
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{18},
                "mach_port_mod_refs underflow returned the wrong result");

    state.rax = rosa::darwin::MachDispatcher::portModRefsTrapNumber;
    state.r10 = UINT32_MAX;
    state.rdx = 6; // MACH_PORT_RIGHT_NUMBER
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{18},
                "mach_port_mod_refs invalid right returned the wrong result");

    state.rax = rosa::darwin::MachDispatcher::portModRefsTrapNumber;
    state.rdi = 0xDEAD;
    state.rdx = 0;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{0x10000003},
                "mach_port_mod_refs invalid task returned the wrong result");
}

void testMachPortDeallocateTrap() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::MachDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::hostSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto hostName = static_cast<std::uint32_t>(state.rax);
    state.rax = rosa::darwin::MachDispatcher::hostSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto *host = dispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{hostName});
    expect(host != nullptr && host->sendUrefs == 2,
           "host_self setup did not create two send urefs");

    state = {};
    state.rax = rosa::darwin::MachDispatcher::portDeallocateTrapNumber;
    state.rdi = dispatcher.taskSelfPortName().value;
    state.rsi = hostName;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8B514ULL});
    expectEqual(state.rax, std::uint64_t{0}, "mach_port_deallocate did not return KERN_SUCCESS");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mach_port_deallocate applied BSD carry semantics");
    host = dispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{hostName});
    expect(host != nullptr && host->sendUrefs == 1,
           "mach_port_deallocate did not drop one send uref");

    state.rax = rosa::darwin::MachDispatcher::portDeallocateTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{0}, "final mach_port_deallocate failed");
    expect(dispatcher.portSpace().lookup(rosa::darwin::GuestMachPortName{hostName}) == nullptr,
           "final host send-right deallocation retained a dead name");

    state.rax = rosa::darwin::MachDispatcher::portDeallocateTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{15},
                "deallocating an absent port returned the wrong result");

    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto replyName = state.rax;
    state.rax = rosa::darwin::MachDispatcher::portDeallocateTrapNumber;
    state.rsi = replyName;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{17},
                "deallocating a receive-only name returned the wrong result");

    state.rax = rosa::darwin::MachDispatcher::portDeallocateTrapNumber;
    state.rdi = 0xDEAD;
    state.rsi = 0;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{0x10000003},
                "mach_port_deallocate invalid task returned the wrong result");
}

void testMachReplyPortTrap() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::MachDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    state.rdi = 0x1111111111111111ULL;
    state.r9 = 0x9999999999999999ULL;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF800001574ULL});
    const rosa::darwin::GuestMachPortName first{static_cast<std::uint32_t>(state.rax)};
    expect(first.value != 0, "mach_reply_port returned MACH_PORT_NULL");
    expect(dispatcher.ownsReceiveRight(first),
           "mach_reply_port did not allocate a guest receive right");
    expect(first != dispatcher.taskSelfPortName(),
           "mach_reply_port collided with the guest task-self port");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mach_reply_port applied BSD carry-flag semantics");
    expectEqual(state.rdi, std::uint64_t{0x1111111111111111ULL},
                "mach_reply_port changed an ignored argument register");
    expectEqual(state.r9, std::uint64_t{0x9999999999999999ULL},
                "mach_reply_port changed an ignored argument register");

    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF800001574ULL});
    const rosa::darwin::GuestMachPortName second{static_cast<std::uint32_t>(state.rax)};
    expect(second != first, "repeated mach_reply_port reused a receive-right name");
    expect(dispatcher.ownsReceiveRight(first) && dispatcher.ownsReceiveRight(second),
           "mach_reply_port lost a previously allocated receive right");
}

void testMachSpecialReplyPortTrap() {
    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::MachDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::specialReplyPortTrapNumber;
    state.rdi = 0x6000026000C0ULL;
    state.rsi = 0x803;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB70ULL});
    const rosa::darwin::GuestMachPortName first{static_cast<std::uint32_t>(state.rax)};
    expect(first.value != 0, "thread_get_special_reply_port returned MACH_PORT_NULL");
    expect(dispatcher.ownsReceiveRight(first),
           "thread_get_special_reply_port did not allocate a guest receive right");
    expect(first != dispatcher.taskSelfPortName(),
           "thread_get_special_reply_port collided with the guest task-self port");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "thread_get_special_reply_port applied BSD carry-flag semantics");

    // XNU's ipc_tt.c allocates a new port, with a send right, on every call
    // (the caller caches it per thread).
    const auto *firstPort = dispatcher.portSpace().lookup(first);
    expect(firstPort != nullptr && firstPort->sendUrefs == 1,
           "thread_get_special_reply_port did not include a send right");
    state.rax = rosa::darwin::MachDispatcher::specialReplyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2FB70ULL});
    const rosa::darwin::GuestMachPortName second{static_cast<std::uint32_t>(state.rax)};
    expect(second != first && dispatcher.ownsReceiveRight(second),
           "repeated thread_get_special_reply_port did not allocate a new port");

    state.rax = rosa::darwin::MachDispatcher::replyPortTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const rosa::darwin::GuestMachPortName fresh{static_cast<std::uint32_t>(state.rax)};
    expect(fresh != first, "mach_reply_port reused the special reply port name");
}

void testMachHostCreateVoucherTrap() {
    constexpr rosa::guest::GuestAddress page{0x8000};
    constexpr rosa::guest::GuestAddress recipesAddress{0x8100};
    constexpr rosa::guest::GuestAddress voucherAddress{0x8200};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(page, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::MachDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::hostSelfTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    const auto hostName = static_cast<std::uint32_t>(state.rax);

    // The observed libdispatch recipe: key 3, command 0x262, zero params.
    constexpr std::array<std::uint8_t, 16> recipes{3, 0, 0, 0, 0x62, 2, 0, 0,
                                                  0, 0, 0, 0, 0, 0, 0, 0};
    addressSpace.writeBytes(recipesAddress, recipes);
    state.rax = rosa::darwin::MachDispatcher::hostCreateMachVoucherTrapNumber;
    state.rdi = hostName;
    state.rsi = recipesAddress.value;
    state.rdx = recipes.size();
    state.r10 = voucherAddress.value;
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E309F3ULL});
    expectEqual(state.rax, std::uint64_t{0}, "voucher creation did not succeed");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "voucher creation changed flags");
    const auto first = addressSpace.readU64(voucherAddress);
    expect(first != 0, "voucher creation returned a null token");

    state.rax = rosa::darwin::MachDispatcher::hostCreateMachVoucherTrapNumber;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{0}, "second voucher creation did not succeed");
    const auto second = addressSpace.readU64(voucherAddress);
    expect(second != 0 && second != first, "voucher creation reused a token");

    state.rax = rosa::darwin::MachDispatcher::hostCreateMachVoucherTrapNumber;
    state.rdi = 0xDEAD;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{4},
                "voucher creation on a bad host port returned the wrong result");

    state.rax = rosa::darwin::MachDispatcher::hostCreateMachVoucherTrapNumber;
    state.rdi = hostName;
    state.rsi = 0x9000;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{1},
                "voucher creation with unreadable recipes returned the wrong result");
}

void testMachPortConstructTrap() {
    constexpr rosa::guest::GuestAddress optionsAddress{0x8100};
    constexpr rosa::guest::GuestAddress outputAddress{0x8200};
    constexpr std::uint32_t mpoReplyPort = 0x1000;
    constexpr std::uint64_t context = 0x0123456789ABCDEFULL;

    const auto writeOptions = [](rosa::guest::AddressSpace &addressSpace,
                                 rosa::guest::GuestAddress address, std::uint32_t flags,
                                 std::uint32_t queueLimit, std::uint64_t special0 = 0,
                                 std::uint64_t special1 = 0) {
        std::array<std::uint8_t, 24> bytes{};
        std::memcpy(bytes.data(), &flags, sizeof(flags));
        std::memcpy(bytes.data() + 4, &queueLimit, sizeof(queueLimit));
        std::memcpy(bytes.data() + 8, &special0, sizeof(special0));
        std::memcpy(bytes.data() + 16, &special1, sizeof(special1));
        addressSpace.writeBytes(address, bytes);
    };
    const auto invoke = [](rosa::darwin::MachDispatcher &dispatcher,
                           rosa::guest::AddressSpace &addressSpace,
                           rosa::guest::GuestAddress options, rosa::guest::GuestAddress output,
                           std::uint64_t portContext = context) {
        rosa::x86::X86State state;
        state.rax = rosa::darwin::MachDispatcher::portConstructTrapNumber;
        state.rdi = dispatcher.taskSelfPortName().value;
        state.rsi = options.value;
        state.rdx = portContext;
        state.r10 = output.value;
        state.rflags = 0x8D7;
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802A8B55CULL});
        return state;
    };

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "mach_port_construct arguments");
    writeOptions(addressSpace, optionsAddress, mpoReplyPort, 0);
    rosa::darwin::MachDispatcher dispatcher;

    const auto firstState = invoke(dispatcher, addressSpace, optionsAddress, outputAddress);
    expectEqual(firstState.rax, std::uint64_t{0},
                "mach_port_construct did not return KERN_SUCCESS");
    expectEqual(firstState.rflags, std::uint64_t{0x8D7},
                "mach_port_construct applied BSD carry semantics");
    const rosa::darwin::GuestMachPortName first{addressSpace.readU32(outputAddress)};
    expect(first != dispatcher.taskSelfPortName(), "mach_port_construct collided with task-self");
    const auto *firstPort = dispatcher.portSpace().lookup(first);
    expect(firstPort != nullptr, "constructed port is absent from its namespace");
    expect(firstPort->hasReceiveRight, "mach_port_construct did not create a receive right");
    expectEqual(firstPort->type, rosa::darwin::GuestPortType::Reply,
                "mach_port_construct created the wrong port type");
    expectEqual(firstPort->sendUrefs, std::uint32_t{0},
                "reply-port construction fabricated a send right");
    expectEqual(firstPort->sendOnceUrefs, std::uint32_t{0},
                "reply-port construction fabricated a send-once right");
    expectEqual(firstPort->context, context, "mach_port_construct lost the port context");
    expectEqual(firstPort->queueLimit, std::uint32_t{5},
                "mach_port_construct did not apply the default queue limit");
    expect(!firstPort->guarded, "MPO_REPLY_PORT unexpectedly created a guarded port");
    expect(dispatcher.portSpace().lookup(dispatcher.taskSelfPortName()) != nullptr,
           "task-self does not coexist in the guest port namespace");

    const auto secondState = invoke(dispatcher, addressSpace, optionsAddress, outputAddress, 0);
    expectEqual(secondState.rax, std::uint64_t{0}, "second mach_port_construct failed");
    const rosa::darwin::GuestMachPortName second{addressSpace.readU32(outputAddress)};
    expect(second != first, "mach_port_construct reused a live guest name");

    constexpr std::uint32_t guardedSendOptions = 0x31;
    constexpr std::uint64_t traceGuard = 0x71B75ACE;
    writeOptions(addressSpace, optionsAddress, guardedSendOptions, 0);
    rosa::darwin::MachDispatcher guardedDispatcher;
    const auto guardedState =
        invoke(guardedDispatcher, addressSpace, optionsAddress, outputAddress, traceGuard);
    expectEqual(guardedState.rax, std::uint64_t{0},
                "guarded send-right mach_port_construct failed");
    expectEqual(guardedState.rflags, std::uint64_t{0x8D7},
                "guarded mach_port_construct applied BSD carry semantics");
    const rosa::darwin::GuestMachPortName guardedName{addressSpace.readU32(outputAddress)};
    const auto *guardedPort = guardedDispatcher.portSpace().lookup(guardedName);
    expect(guardedPort != nullptr && guardedPort->hasReceiveRight,
           "guarded mach_port_construct omitted its receive right");
    expectEqual(guardedPort->type, rosa::darwin::GuestPortType::Ordinary,
                "guarded mach_port_construct created the wrong port type");
    expectEqual(guardedPort->sendUrefs, std::uint32_t{1},
                "MPO_INSERT_SEND_RIGHT did not create one send uref");
    expectEqual(guardedPort->sendOnceUrefs, std::uint32_t{0},
                "guarded mach_port_construct fabricated a send-once right");
    expect(guardedPort->guarded && guardedPort->strictGuard,
           "guarded mach_port_construct lost strict guard policy");
    expectEqual(guardedPort->guard, traceGuard,
                "guarded mach_port_construct stored the wrong guard");
    expectEqual(guardedPort->context, traceGuard,
                "guarded mach_port_construct stored the wrong context");
    expectEqual(guardedPort->queueLimit, std::uint32_t{5},
                "guarded mach_port_construct used the wrong default qlimit");
    expectEqual(guardedPort->optionFlags, guardedSendOptions,
                "guarded mach_port_construct lost its option flags");
    expect(guardedDispatcher.lastPortConstruct() &&
               guardedDispatcher.lastPortConstruct()->flags == guardedSendOptions &&
               guardedDispatcher.lastPortConstruct()->context == traceGuard,
           "guarded mach_port_construct observation differs");

    // Observed under an AppKit fixture: guard + queue-limit + send +
    // strict with an explicit queue limit of one.
    constexpr std::uint32_t queueLimitOptions = 0x33;
    constexpr std::uint64_t appGuard = 0x100812400ULL;
    writeOptions(addressSpace, optionsAddress, queueLimitOptions, 1);
    rosa::darwin::MachDispatcher queueLimitDispatcher;
    const auto queueLimitState =
        invoke(queueLimitDispatcher, addressSpace, optionsAddress, outputAddress, appGuard);
    expectEqual(queueLimitState.rax, std::uint64_t{0},
                "queue-limit mach_port_construct failed");
    const rosa::darwin::GuestMachPortName queueLimitName{addressSpace.readU32(outputAddress)};
    const auto *queueLimitPort = queueLimitDispatcher.portSpace().lookup(queueLimitName);
    expect(queueLimitPort != nullptr && queueLimitPort->hasReceiveRight,
           "queue-limit mach_port_construct omitted its receive right");
    expectEqual(queueLimitPort->type, rosa::darwin::GuestPortType::Ordinary,
                "queue-limit mach_port_construct created the wrong port type");
    expectEqual(queueLimitPort->sendUrefs, std::uint32_t{1},
                "queue-limit mach_port_construct omitted the send right");
    expect(queueLimitPort->guarded && queueLimitPort->strictGuard &&
               queueLimitPort->guard == appGuard,
           "queue-limit mach_port_construct lost its guard");
    expectEqual(queueLimitPort->queueLimit, std::uint32_t{1},
                "queue-limit mach_port_construct ignored the queue-limit field");

    rosa::darwin::MachDispatcher invalidOptionsDispatcher;
    writeOptions(addressSpace, optionsAddress, 0x1001, 0);
    bool invalidOptionsRejected = false;
    try {
        static_cast<void>(
            invoke(invalidOptionsDispatcher, addressSpace, optionsAddress, outputAddress));
    } catch (const std::runtime_error &) {
        invalidOptionsRejected = true;
    }
    expect(invalidOptionsRejected, "mach_port_construct accepted unimplemented option semantics");
    expectEqual(invalidOptionsDispatcher.portSpace().size(), std::size_t{1},
                "invalid port options mutated the namespace");

    rosa::darwin::MachDispatcher invalidPointerDispatcher;
    const auto invalidOptionsState = invoke(invalidPointerDispatcher, addressSpace,
                                            rosa::guest::GuestAddress{0xDEAD0000}, outputAddress);
    expectEqual(invalidOptionsState.rax, std::uint64_t{1},
                "invalid options pointer returned the wrong Mach result");
    expectEqual(invalidPointerDispatcher.portSpace().size(), std::size_t{1},
                "invalid options pointer allocated a port");

    rosa::guest::AddressSpace faultAddressSpace;
    faultAddressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, rosa::guest::guestPageSize,
                                   rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    faultAddressSpace.mapAnonymous(rosa::guest::GuestAddress{0x9000}, rosa::guest::guestPageSize,
                                   rosa::guest::Permission::Read);
    faultAddressSpace.mapAnonymous(rosa::guest::GuestAddress{0xA000}, rosa::guest::guestPageSize,
                                   rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    writeOptions(faultAddressSpace, optionsAddress, mpoReplyPort, 0);
    rosa::darwin::MachDispatcher faultDispatcher;
    const auto invalidOutputState = invoke(faultDispatcher, faultAddressSpace, optionsAddress,
                                           rosa::guest::GuestAddress{0x9000});
    expectEqual(invalidOutputState.rax, std::uint64_t{1},
                "invalid output pointer returned the wrong Mach result");
    expectEqual(faultDispatcher.portSpace().size(), std::size_t{1},
                "invalid output pointer left a constructed port");

    const auto recoveredState = invoke(faultDispatcher, faultAddressSpace, optionsAddress,
                                       rosa::guest::GuestAddress{0xA000});
    expectEqual(recoveredState.rax, std::uint64_t{0},
                "construct did not recover after output fault");
    expectEqual(faultAddressSpace.readU32(rosa::guest::GuestAddress{0xA000}), std::uint32_t{0x203},
                "failed construct consumed a guest port name");

    rosa::x86::X86State invalidTaskState;
    invalidTaskState.rax = rosa::darwin::MachDispatcher::portConstructTrapNumber;
    invalidTaskState.rdi = 0xDEAD;
    invalidTaskState.rsi = 0xDEAD0000;
    invalidTaskState.r10 = 0xDEAD1000;
    faultDispatcher.dispatch(faultAddressSpace, invalidTaskState,
                             rosa::guest::GuestAddress{0x1000});
    expectEqual(invalidTaskState.rax, std::uint64_t{0x10000003},
                "invalid construct task returned the wrong Mach result");
}

void testMachVmAllocateTrap() {
    constexpr rosa::guest::GuestAddress addressPointer{0x8000};
    constexpr rosa::guest::GuestAddress readOnlyPointer{0x9000};
    constexpr rosa::guest::GuestAddress occupied{0x100000000ULL};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(addressPointer, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "mach_vm_allocate address pointer");
    addressSpace.mapAnonymous(readOnlyPointer, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "mach_vm_allocate read-only pointer");
    addressSpace.mapAnonymous(occupied, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                              "occupied allocation base");
    addressSpace.writeU64(addressPointer, 0);
    expectEqual(addressSpace.protect(readOnlyPointer, rosa::guest::guestPageSize,
                                     rosa::guest::Permission::Read),
                rosa::guest::ProtectResult::Success,
                "could not make mach_vm_allocate pointer read-only");

    rosa::darwin::MachDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::vmAllocateTrapNumber;
    state.rdi = 0x103;
    state.rsi = addressPointer.value;
    state.rdx = 0x1001;
    state.r10 = 0x01000001; // VM_MEMORY_* | VM_FLAGS_ANYWHERE
    state.rflags = 0x8D7;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2F9A8ULL});
    expectEqual(state.rax, std::uint64_t{0}, "mach_vm_allocate did not return KERN_SUCCESS");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "mach_vm_allocate applied BSD carry semantics");
    const auto mapped = rosa::guest::GuestAddress{addressSpace.readU64(addressPointer)};
    expectEqual(mapped.value, occupied.value + rosa::guest::guestPageSize,
                "mach_vm_allocate anywhere placement differs");
    expectEqual(addressSpace.readU64(mapped), std::uint64_t{0},
                "mach_vm_allocate memory was not zero-filled");
    const auto mappings = addressSpace.mappingInfos();
    const auto allocation =
        std::ranges::find_if(mappings, [mapped](const rosa::guest::MappingInfo &mapping) {
            return mapping.base == mapped;
        });
    constexpr auto readWrite = rosa::guest::Permission::Read | rosa::guest::Permission::Write;
    constexpr auto allPermissions = readWrite | rosa::guest::Permission::Execute;
    expect(allocation != mappings.end() && allocation->size == 0x2000 &&
               allocation->permissions == readWrite &&
               allocation->maximumPermissions == allPermissions,
           "mach_vm_allocate mapping attributes differ");

    const auto countBeforeFault = addressSpace.mappingCount();
    state.rax = rosa::darwin::MachDispatcher::vmAllocateTrapNumber;
    state.rsi = readOnlyPointer.value;
    state.rdx = 0x1000;
    state.r10 = 1;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{1}, "mach_vm_allocate read-only pointer result differs");
    expectEqual(addressSpace.mappingCount(), countBeforeFault,
                "faulted mach_vm_allocate leaked a mapping");

    state.rax = rosa::darwin::MachDispatcher::vmAllocateTrapNumber;
    state.rdi = 0xDEAD;
    state.rsi = addressPointer.value;
    dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000});
    expectEqual(state.rax, std::uint64_t{0x10000003},
                "mach_vm_allocate invalid task result differs");
    expectEqual(addressSpace.mappingCount(), countBeforeFault,
                "invalid-task mach_vm_allocate changed mappings");
}

void testMachVmDeallocateTrap() {
    constexpr rosa::guest::GuestAddress mappingBase{0x4000};
    constexpr auto pageSize = rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(mappingBase, pageSize * 3,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "mach deallocate test");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x4000}, 0x1111111111111111ULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x5000}, 0x2222222222222222ULL);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x6000}, 0x3333333333333333ULL);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::vmDeallocateTrapNumber;
    state.rdi = 0x103;
    state.rsi = 0x5001;
    state.rdx = 1;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF7000014D8ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "mach_vm_deallocate did not return KERN_SUCCESS");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mach_vm_deallocate applied BSD carry semantics");
    expectEqual(state.rsi, std::uint64_t{0x5001},
                "mach_vm_deallocate changed its address argument");
    expectEqual(state.rdx, std::uint64_t{1}, "mach_vm_deallocate changed its size argument");
    const auto mappings = addressSpace.mappingInfos();
    expectEqual(mappings.size(), std::size_t{2},
                "mach_vm_deallocate did not split the surrounding mapping");
    expectEqual(mappings[0].base.value, std::uint64_t{0x4000},
                "mach_vm_deallocate prefix base differs");
    expectEqual(mappings[0].size, pageSize, "mach_vm_deallocate prefix size differs");
    expectEqual(mappings[1].base.value, std::uint64_t{0x6000},
                "mach_vm_deallocate suffix base differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x4000}),
                std::uint64_t{0x1111111111111111ULL}, "mach_vm_deallocate changed prefix bytes");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x6000}),
                std::uint64_t{0x3333333333333333ULL}, "mach_vm_deallocate changed suffix bytes");
    bool middleUnmapped = false;
    try {
        static_cast<void>(addressSpace.readU64(rosa::guest::GuestAddress{0x5000}));
    } catch (const std::runtime_error &error) {
        middleUnmapped = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(middleUnmapped, "mach_vm_deallocate left the rounded middle page mapped");

    const auto countAfterRemoval = addressSpace.mappingCount();
    state.rax = rosa::darwin::MachDispatcher::vmDeallocateTrapNumber;
    state.rsi = 0x5000;
    state.rdx = pageSize;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0},
                "mach_vm_deallocate did not accept a guest mapping hole");
    expectEqual(addressSpace.mappingCount(), countAfterRemoval,
                "deallocating a hole changed neighboring mappings");

    state.rax = rosa::darwin::MachDispatcher::vmDeallocateTrapNumber;
    state.rsi = 0x4001;
    state.rdx = 0;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "zero-size mach_vm_deallocate did not succeed");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x4000}),
                std::uint64_t{0x1111111111111111ULL},
                "zero-size mach_vm_deallocate removed guest memory");

    state.rax = rosa::darwin::MachDispatcher::vmDeallocateTrapNumber;
    state.rdi = 0xDEAD;
    state.rdx = pageSize;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0x10000003},
                "mach_vm_deallocate invalid task result differs");

    state.rax = rosa::darwin::MachDispatcher::vmDeallocateTrapNumber;
    state.rdi = 0x103;
    state.rsi = UINT64_MAX - 0x7FF;
    state.rdx = 0x1000;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{4}, "overflowing mach_vm_deallocate result differs");
}

void testGeneratedMachVmDeallocateTrap() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress target{0x8000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x0C, 0x00, 0x00, 0x01, // mov eax, 0x100000c
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
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rdi = 0x103;
    state.rsi = target.value;
    state.rdx = rosa::guest::guestPageSize;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated mach_vm_deallocate terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "generated mach_vm_deallocate result differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "generated mach_vm_deallocate changed flags");
    bool targetUnmapped = false;
    try {
        static_cast<void>(addressSpace.readU64(target));
    } catch (const std::runtime_error &error) {
        targetUnmapped = std::string_view(error.what()).find("unmapped") != std::string_view::npos;
    }
    expect(targetUnmapped, "generated mach_vm_deallocate left its target mapped");
}

void testMachVmProtectTrap() {
    constexpr rosa::guest::GuestAddress mappingBase{0x4000};
    constexpr auto pageSize = rosa::guest::guestPageSize;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(mappingBase, pageSize * 3,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "mach protect test");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x5000}, 0x0123456789ABCDEFULL);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.rdi = 0x103;
    state.rsi = 0x5000;
    state.rdx = 8;
    state.r10 = 0;
    state.r8 = 1; // VM_PROT_READ
    state.r9 = 0x9999999999999999ULL;
    state.rflags = 0x8D7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "mach_vm_protect did not return KERN_SUCCESS");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "mach_vm_protect applied BSD carry-flag semantics");
    expectEqual(state.r9, std::uint64_t{0x9999999999999999ULL},
                "mach_vm_protect consumed a nonexistent sixth argument");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x5000}),
                std::uint64_t{0x0123456789ABCDEFULL}, "mach_vm_protect changed guest bytes");

    const auto mappings = addressSpace.mappingInfos();
    expectEqual(mappings.size(), std::size_t{3},
                "mach_vm_protect did not split the mapping at guest-page boundaries");
    expectEqual(mappings[0].base.value, std::uint64_t{0x4000},
                "mach_vm_protect prefix mapping differs");
    expectEqual(mappings[1].base.value, std::uint64_t{0x5000},
                "mach_vm_protect protected mapping base differs");
    expectEqual(mappings[1].size, pageSize,
                "mach_vm_protect did not round an 8-byte range to one guest page");
    expect(mappings[1].permissions == rosa::guest::Permission::Read,
           "mach_vm_protect middle-page permissions differ");

    bool writeRejected = false;
    try {
        addressSpace.writeU64(rosa::guest::GuestAddress{0x5000}, 0);
    } catch (const std::runtime_error &) {
        writeRejected = true;
    }
    expect(writeRejected, "mach_vm_protect did not remove guest write permission");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x4000}, 1);
    addressSpace.writeU64(rosa::guest::GuestAddress{0x6000}, 2);

    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.r8 = 3; // VM_PROT_READ | VM_PROT_WRITE
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0},
                "mach_vm_protect could not restore a maximum guest permission");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x5000}, 0xFEDCBA9876543210ULL);

    const auto beforeFailure = addressSpace.mappingInfos();
    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.rsi = 0x7000;
    state.rdx = pageSize;
    state.r8 = 1;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{1},
                "mach_vm_protect unmapped range did not return KERN_INVALID_ADDRESS");
    const auto afterFailure = addressSpace.mappingInfos();
    expectEqual(afterFailure.size(), beforeFailure.size(),
                "failed mach_vm_protect changed the mapping count");
    for (std::size_t index = 0; index < beforeFailure.size(); ++index) {
        expect(afterFailure[index].permissions == beforeFailure[index].permissions,
               "failed mach_vm_protect changed guest permissions");
    }

    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.rdi = 0xDEAD;
    state.rsi = 0x5000;
    state.rdx = 8;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0x10000003},
                "mach_vm_protect invalid task did not return MACH_SEND_INVALID_DEST");

    addressSpace.mapAnonymous(rosa::guest::GuestAddress{0x8000}, pageSize,
                              rosa::guest::Permission::Read, "mach protect maximum test");
    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.rdi = 0x103;
    state.rsi = 0x8000;
    state.rdx = 8;
    state.r10 = 0;
    state.r8 = 3;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{2},
                "mach_vm_protect maximum violation did not return KERN_PROTECTION_FAILURE");

    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.r8 = 0x13; // VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE
    state.rflags = 0xAD7;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0}, "mach_vm_protect VM_PROT_COPY did not succeed");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "mach_vm_protect VM_PROT_COPY changed guest flags");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x8000}, 0xA5A5A5A5A5A5A5A5ULL);
    const auto copiedMappings = addressSpace.mappingInfos();
    const auto copied =
        std::ranges::find_if(copiedMappings, [](const rosa::guest::MappingInfo &mapping) {
            return mapping.base.value == 0x8000;
        });
    expect(copied != copiedMappings.end() &&
               copied->permissions ==
                   (rosa::guest::Permission::Read | rosa::guest::Permission::Write) &&
               copied->maximumPermissions ==
                   (rosa::guest::Permission::Read | rosa::guest::Permission::Write),
           "mach_vm_protect VM_PROT_COPY did not install private RW permissions");

    for (const auto [setMaximum, protection] :
         std::array<std::pair<std::uint64_t, std::uint64_t>, 2>{
             std::pair{std::uint64_t{1}, std::uint64_t{1}},
             std::pair{std::uint64_t{0}, std::uint64_t{8}}}) {
        state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
        state.rsi = 0x5000;
        state.r10 = setMaximum;
        state.r8 = protection;
        bool rejected = false;
        try {
            static_cast<void>(
                dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
        } catch (const std::runtime_error &error) {
            rejected = std::string_view(error.what()).find("Mach trap") != std::string_view::npos;
        }
        expect(rejected, "unsupported mach_vm_protect behavior did not fail diagnostically");
    }
}

void testMachVmMapTrap() {
    constexpr rosa::guest::GuestAddress addressPointer{0x8000};
    constexpr rosa::guest::GuestAddress occupied{0x100000000ULL};
    constexpr std::size_t requestedSize = 0x20000;
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(addressPointer, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "mach_vm_map address pointer");
    addressSpace.mapAnonymous(occupied, rosa::guest::guestPageSize, rosa::guest::Permission::Read,
                              "occupied allocation base");
    addressSpace.writeU64(addressPointer, 0);

    rosa::darwin::SyscallDispatcher dispatcher;
    rosa::x86::X86State state;
    state.rax = rosa::darwin::MachDispatcher::vmMapTrapNumber;
    state.rdi = 0x103;
    state.rsi = addressPointer.value;
    state.rdx = requestedSize;
    state.r10 = 0xFFF;
    state.r8 = 0x3C000001; // VM_MEMORY_DYLD | VM_FLAGS_ANYWHERE
    state.r9 = 3;          // VM_PROT_READ | VM_PROT_WRITE
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF8000014FCULL}));
    expectEqual(state.rax, std::uint64_t{0}, "mach_vm_map did not return KERN_SUCCESS");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "mach_vm_map applied BSD carry-flag semantics");
    const auto mapped = rosa::guest::GuestAddress{addressSpace.readU64(addressPointer)};
    expectEqual(mapped.value, occupied.value + rosa::guest::guestPageSize,
                "mach_vm_map anywhere allocation differs");
    expectEqual(addressSpace.readU64(mapped), std::uint64_t{0},
                "mach_vm_map anonymous memory was not zero-filled");
    const auto mappings = addressSpace.mappingInfos();
    const auto mappedInfo =
        std::ranges::find_if(mappings, [mapped](const rosa::guest::MappingInfo &mapping) {
            return mapping.base == mapped;
        });
    expect(mappedInfo != mappings.end(), "mach_vm_map did not record the guest mapping");
    expectEqual(mappedInfo->size, requestedSize, "mach_vm_map guest mapping size differs");
    expect(mappedInfo->permissions ==
               (rosa::guest::Permission::Read | rosa::guest::Permission::Write),
           "mach_vm_map current permissions differ");

    state.rax = rosa::darwin::MachDispatcher::vmProtectTrapNumber;
    state.rsi = mapped.value;
    state.rdx = requestedSize;
    state.r10 = 0;
    state.r8 = 5; // VM_PROT_READ | VM_PROT_EXECUTE
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0},
                "mach_vm_map did not retain VM_PROT_ALL maximum permissions");

    const auto countBeforeFailure = addressSpace.mappingCount();
    state.rax = rosa::darwin::MachDispatcher::vmMapTrapNumber;
    state.rdi = 0xDEAD;
    state.rsi = addressPointer.value;
    state.rdx = requestedSize;
    state.r10 = 0xFFF;
    state.r8 = 0x3C000001;
    state.r9 = 3;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{0x10000003},
                "mach_vm_map invalid task did not return MACH_SEND_INVALID_DEST");
    expectEqual(addressSpace.mappingCount(), countBeforeFailure,
                "failed mach_vm_map changed the mapping count");

    state.rax = rosa::darwin::MachDispatcher::vmMapTrapNumber;
    state.rdi = 0x103;
    state.rsi = 0xDEADBEEF;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{1},
                "mach_vm_map bad address pointer did not return KERN_INVALID_ADDRESS");
    expectEqual(addressSpace.mappingCount(), countBeforeFailure,
                "bad-pointer mach_vm_map changed the mapping count");

    constexpr std::uint64_t fixedHint = 0x200000123ULL;
    constexpr std::uint64_t fixedBase = 0x200000000ULL;
    addressSpace.writeU64(addressPointer, fixedHint);
    state.rax = rosa::darwin::MachDispatcher::vmMapTrapNumber;
    state.rdi = 0x103;
    state.rsi = addressPointer.value;
    state.rdx = 0x2345;
    state.r10 = 0;
    state.r8 = 0x0B000000; // VM_MEMORY_MALLOC | VM_FLAGS_FIXED
    state.r9 = 3;
    state.rflags = 0xAD7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2F9E4ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "fixed mach_vm_map did not return KERN_SUCCESS");
    expectEqual(addressSpace.readU64(addressPointer), fixedBase,
                "fixed mach_vm_map did not page-truncate its address");
    expectEqual(state.rflags, std::uint64_t{0xAD7}, "fixed mach_vm_map changed flags");
    const auto fixedMappings = addressSpace.mappingInfos();
    const auto fixedInfo =
        std::ranges::find_if(fixedMappings, [](const rosa::guest::MappingInfo &mapping) {
            return mapping.base.value == fixedBase;
        });
    expect(fixedInfo != fixedMappings.end() && fixedInfo->size == 0x3000 &&
               fixedInfo->permissions ==
                   (rosa::guest::Permission::Read | rosa::guest::Permission::Write),
           "fixed mach_vm_map mapping differs");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{fixedBase}), std::uint64_t{0},
                "fixed mach_vm_map was not zero-filled");

    const auto countAfterFixed = addressSpace.mappingCount();
    addressSpace.writeU64(addressPointer, fixedBase);
    state.rax = rosa::darwin::MachDispatcher::vmMapTrapNumber;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{3},
                "overlapping fixed mach_vm_map did not return KERN_NO_SPACE");
    expectEqual(addressSpace.mappingCount(), countAfterFixed,
                "overlapping fixed mach_vm_map changed the mappings");

    addressSpace.writeU64(addressPointer, 0);
    state.rax = rosa::darwin::MachDispatcher::vmMapTrapNumber;
    state.rdi = 0x103;
    state.rsi = addressPointer.value;
    state.rdx = 0x2000;
    state.r10 = 0;
    state.r8 = 0x49000001; // VM_MEMORY_* alias | VM_FLAGS_ANYWHERE
    state.r9 = 3;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2F9E4ULL}));
    expectEqual(state.rax, std::uint64_t{0}, "zero-mask mach_vm_map did not return KERN_SUCCESS");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "zero-mask mach_vm_map changed flags");
    const auto zeroMaskMapped = addressSpace.readU64(addressPointer);
    expect((zeroMaskMapped & (rosa::guest::guestPageSize - 1U)) == 0,
           "zero-mask mach_vm_map result was not page aligned");
    const auto zeroMaskMappings = addressSpace.mappingInfos();
    const auto zeroMaskInfo = std::ranges::find_if(
        zeroMaskMappings, [zeroMaskMapped](const rosa::guest::MappingInfo &mapping) {
            return mapping.base.value == zeroMaskMapped;
        });
    expect(zeroMaskInfo != zeroMaskMappings.end() && zeroMaskInfo->size == 0x2000 &&
               zeroMaskInfo->permissions ==
                   (rosa::guest::Permission::Read | rosa::guest::Permission::Write),
           "zero-mask mach_vm_map mapping differs");

    addressSpace.writeU64(addressPointer, 0);
    state.rax = rosa::darwin::MachDispatcher::vmMapTrapNumber;
    state.rdi = 0x103;
    state.rsi = addressPointer.value;
    state.rdx = 0x800000;
    state.r10 = 0x7FFFFF;
    state.r8 = 0x02000001; // VM_MEMORY_MALLOC_SMALL | VM_FLAGS_ANYWHERE
    state.r9 = 3;
    state.rflags = 0x8D7;
    static_cast<void>(
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF802E2F9E4ULL}));
    expectEqual(state.rax, std::uint64_t{0},
                "large-alignment mach_vm_map did not return KERN_SUCCESS");
    const auto alignedMapped = addressSpace.readU64(addressPointer);
    expect((alignedMapped & 0x7FFFFFU) == 0, "mach_vm_map did not honor its 8 MiB alignment mask");
    const auto alignedMappings = addressSpace.mappingInfos();
    const auto alignedInfo = std::ranges::find_if(
        alignedMappings, [alignedMapped](const rosa::guest::MappingInfo &mapping) {
            return mapping.base.value == alignedMapped;
        });
    expect(alignedInfo != alignedMappings.end() && alignedInfo->size == 0x800000 &&
               alignedInfo->permissions ==
                   (rosa::guest::Permission::Read | rosa::guest::Permission::Write),
           "large-alignment mach_vm_map mapping differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "large-alignment mach_vm_map changed flags");

    addressSpace.writeU64(addressPointer, 0);
    const auto countBeforeInvalidMask = addressSpace.mappingCount();
    state.rax = rosa::darwin::MachDispatcher::vmMapTrapNumber;
    state.r10 = 0x6FFF;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, std::uint64_t{4},
                "noncontiguous mach_vm_map mask did not return KERN_INVALID_ARGUMENT");
    expectEqual(addressSpace.mappingCount(), countBeforeInvalidMask,
                "invalid-mask mach_vm_map changed guest mappings");
}

void testGeneratedMachVmMapTrap() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress addressPointer{0x4000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x0F, 0x00, 0x00, 0x01, // mov eax, 0x100000f
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(addressPointer, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.writeU64(addressPointer, 0);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rdi = 0x103;
    state.rsi = addressPointer.value;
    state.rdx = 0x20000;
    state.r10 = 0xFFF;
    state.r8 = 0x3C000001;
    state.r9 = 3;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated mach_vm_map terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "generated mach_vm_map did not return KERN_SUCCESS");
    const auto mapped = rosa::guest::GuestAddress{addressSpace.readU64(addressPointer)};
    expect(mapped.value >= 0x100000000ULL, "generated mach_vm_map returned a low guest address");
    expectEqual(addressSpace.readU64(mapped), std::uint64_t{0},
                "generated mach_vm_map did not create zero-filled memory");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated mach_vm_map syscall fallthrough differs");
    expectEqual(state.rflags, std::uint64_t{0x8D7}, "generated mach_vm_map changed guest flags");
}

void testGeneratedMachVmProtectTrap() {
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress dataBase{0x4000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x0E, 0x00, 0x00, 0x01, // mov eax, 0x100000e
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(dataBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - 8;
    state.rdi = 0x103;
    state.rsi = dataBase.value;
    state.rdx = 8;
    state.r10 = 0;
    state.r8 = 3;
    state.rflags = 0x8D7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated mach_vm_protect terminated the guest");
    expectEqual(state.rax, std::uint64_t{0},
                "generated mach_vm_protect did not return KERN_SUCCESS");
    expectEqual(state.rcx, std::uint64_t{0x1007},
                "generated mach_vm_protect did not preserve SYSCALL fallthrough");
    expectEqual(state.r11, std::uint64_t{0x8D7},
                "generated mach_vm_protect did not save input flags in R11");
    expectEqual(state.rflags, std::uint64_t{0x8D7},
                "generated mach_vm_protect changed guest flags");
}

} // namespace

std::span<const TestCase> machTrapsTests() {
    static const TestCase cases[]{
        {"Mach thread-self trap", testMachThreadSelfTrap},
        {"Mach timer-create trap", testMachTimerCreateTrap},
        {"Mach port-insert-member trap", testMachPortInsertMemberTrap},
        {"Mach port-allocate trap", testMachPortAllocateTrap},
        {"Mach message2 receive timed out", testMachMessage2ReceiveTimedOut},
        {"Mach timebase-info trap", testMachTimebaseInfoTrap},
        {"Mach task-self trap", testMachTaskSelfTrap},
        {"generated Mach task-self trap", testGeneratedMachTaskSelfTrap},
        {"Mach host-self trap", testMachHostSelfTrap},
        {"generated Mach host-self trap", testGeneratedMachHostSelfTrap},
        {"Mach port mod-refs trap", testMachPortModRefsTrap},
        {"Mach port deallocate trap", testMachPortDeallocateTrap},
        {"Mach reply-port trap", testMachReplyPortTrap},
        {"Mach special reply-port trap", testMachSpecialReplyPortTrap},
        {"Mach host create voucher trap", testMachHostCreateVoucherTrap},
        {"Mach port construct trap", testMachPortConstructTrap},
        {"Mach VM allocate trap", testMachVmAllocateTrap},
        {"Mach VM deallocate trap", testMachVmDeallocateTrap},
        {"generated Mach VM deallocate trap", testGeneratedMachVmDeallocateTrap},
        {"Mach VM protect trap", testMachVmProtectTrap},
        {"Mach VM map trap", testMachVmMapTrap},
        {"generated Mach VM map trap", testGeneratedMachVmMapTrap},
        {"generated Mach VM protect trap", testGeneratedMachVmProtectTrap},
    };
    return cases;
}

} // namespace rosa::tests
