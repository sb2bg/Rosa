#pragma once

#include "guest/Address.h"
#include "guest/AddressSpace.h"

#include <cstddef>
#include <optional>
#include <span>
#include <string>

namespace rosa::guest {

struct InitialStack {
    GuestAddress base{};
    std::size_t size{};
    GuestAddress stackPointer{};
};

class StartupStackBuilder {
  public:
    [[nodiscard]] InitialStack build(AddressSpace &addressSpace, GuestAddress base,
                                     std::size_t size, std::span<const std::string> arguments,
                                     std::span<const std::string> environment,
                                     std::span<const std::string> apple,
                                     std::optional<GuestAddress> mainExecutable =
                                         std::nullopt) const;
};

} // namespace rosa::guest
