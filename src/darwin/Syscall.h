#pragma once

#include "darwin/Mach.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "x86/Registers.h"

#include <cstdint>
#include <optional>

namespace rosa::darwin {

class GuestSharedCache;

struct SyscallOutcome {
    bool exited{};
    int exitStatus{};
};

struct GuestDyldInfo {
    guest::GuestAddress address;
    std::uint64_t size{};
};

class SyscallDispatcher {
  public:
    explicit SyscallDispatcher(const GuestSharedCache *sharedCache = nullptr)
        : sharedCache_(sharedCache) {}

    [[nodiscard]] SyscallOutcome dispatch(guest::AddressSpace &addressSpace, x86::X86State &state,
                                          guest::GuestAddress syscallRip);
    [[nodiscard]] const std::optional<GuestDyldInfo> &dyldInfo() const noexcept {
        return dyldInfo_;
    }
    [[nodiscard]] const MachDispatcher &machDispatcher() const noexcept {
        return machDispatcher_;
    }

  private:
    const GuestSharedCache *sharedCache_{};
    MachDispatcher machDispatcher_;
    std::optional<GuestDyldInfo> dyldInfo_;
    bool dyldInfoFinal_{};
};

} // namespace rosa::darwin
