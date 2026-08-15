#pragma once

#include "guest/Address.h"
#include "x86/Instruction.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace rosa::x86 {

class DecodeError final : public std::runtime_error {
  public:
    DecodeError(guest::GuestAddress address, std::span<const std::uint8_t> remaining,
                const std::string &reason);

    [[nodiscard]] guest::GuestAddress address() const noexcept { return address_; }
    [[nodiscard]] const std::vector<std::uint8_t> &remainingBytes() const noexcept {
        return remaining_;
    }

  private:
    guest::GuestAddress address_;
    std::vector<std::uint8_t> remaining_;
};

class Decoder {
  public:
    [[nodiscard]] std::vector<DecodedInstruction>
    decodeBlock(std::span<const std::uint8_t> code, guest::GuestAddress start,
                std::size_t maximumInstructions = std::numeric_limits<std::size_t>::max()) const;
};

} // namespace rosa::x86
