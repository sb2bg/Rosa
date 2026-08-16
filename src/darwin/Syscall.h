#pragma once

#include "darwin/Mach.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "x86/Registers.h"

namespace rosa::darwin {

class GuestSharedCache;

struct SyscallOutcome {
    bool exited{};
    int exitStatus{};
};

class SyscallDispatcher {
  public:
    explicit SyscallDispatcher(const GuestSharedCache *sharedCache = nullptr)
        : sharedCache_(sharedCache) {}

    [[nodiscard]] SyscallOutcome dispatch(guest::AddressSpace &addressSpace, x86::X86State &state,
                                          guest::GuestAddress syscallRip);

  private:
    const GuestSharedCache *sharedCache_{};
    MachDispatcher machDispatcher_;
};

} // namespace rosa::darwin
