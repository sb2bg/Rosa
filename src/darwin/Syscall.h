#pragma once

#include "darwin/Mach.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "x86/Registers.h"

namespace rosa::darwin {

struct SyscallOutcome {
    bool exited{};
    int exitStatus{};
};

class SyscallDispatcher {
  public:
    [[nodiscard]] SyscallOutcome dispatch(guest::AddressSpace &addressSpace, x86::X86State &state,
                                          guest::GuestAddress syscallRip) const;

  private:
    MachDispatcher machDispatcher_;
};

} // namespace rosa::darwin
