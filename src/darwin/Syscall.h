#pragma once

#include "darwin/Files.h"
#include "darwin/Mach.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "x86/Registers.h"

#include <array>
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

struct GuestPthreadRegistration {
    guest::GuestAddress threadStart;
    guest::GuestAddress workqueueThreadStart;
    std::uint32_t pthreadSize{};
    guest::GuestAddress dataAddress;
    std::uint64_t dataSize{};
    std::uint64_t dispatchQueueOffset{};
    std::uint32_t tsdOffset{};
    std::uint32_t returnToKernelOffset{};
    std::uint32_t machThreadSelfOffset{};
    std::uint32_t joinableOffsetBits{};
    std::uint32_t workqueueQuantumExpiryOffset{};
};

class SyscallDispatcher {
  public:
    explicit SyscallDispatcher(
        const GuestSharedCache *sharedCache = nullptr,
        const std::array<std::uint8_t, 16> &executableUuid = {})
        : sharedCache_(sharedCache), executableUuid_(executableUuid) {}

    [[nodiscard]] SyscallOutcome dispatch(guest::AddressSpace &addressSpace, x86::X86State &state,
                                          guest::GuestAddress syscallRip);
    [[nodiscard]] const std::optional<GuestDyldInfo> &dyldInfo() const noexcept {
        return dyldInfo_;
    }
    [[nodiscard]] const MachDispatcher &machDispatcher() const noexcept {
        return machDispatcher_;
    }
    [[nodiscard]] const GuestFileSpace &fileSpace() const noexcept {
        return fileSpace_;
    }
    [[nodiscard]] const std::optional<GuestPthreadRegistration> &
    pthreadRegistration() const noexcept {
        return pthreadRegistration_;
    }

  private:
    const GuestSharedCache *sharedCache_{};
    std::array<std::uint8_t, 16> executableUuid_{};
    GuestFileSpace fileSpace_;
    MachDispatcher machDispatcher_;
    std::optional<GuestDyldInfo> dyldInfo_;
    std::optional<GuestPthreadRegistration> pthreadRegistration_;
    bool dyldInfoFinal_{};
};

} // namespace rosa::darwin
