#pragma once

#include <compare>
#include <cstdint>

namespace rosa::guest {

struct GuestAddress {
    std::uint64_t value{};

    auto operator<=>(const GuestAddress &) const = default;
};

} // namespace rosa::guest
