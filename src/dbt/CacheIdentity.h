#pragma once

#include <cstdint>

namespace rosa::dbt {

[[nodiscard]] std::uint64_t translationHelperAnchor() noexcept;

// Identifies the linked image containing the translator and its runtime helpers.
// Throws if the host image has no identity; callers must bypass persistence.
[[nodiscard]] std::uint64_t translationCacheBuildFingerprint();

} // namespace rosa::dbt
