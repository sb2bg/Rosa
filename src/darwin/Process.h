#pragma once

#include "guest/Address.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace rosa::darwin {

inline constexpr guest::GuestAddress initialUserStackBase{
    0x700000000000ULL};
inline constexpr std::size_t initialUserStackSize = 1024U * 1024U;
inline constexpr std::uint64_t initialUserStackTop =
    initialUserStackBase.value + initialUserStackSize;

// libpthread needs a nonzero process secret for reversible pointer mangling.
// Real Darwin receives this kernel-generated value in the apple vector. Rosa's
// controlled single-process guest uses a deterministic guest-only token.
inline constexpr std::string_view pointerMungeApple =
    "ptr_munge=0x52534f415054524d";

} // namespace rosa::darwin
