#include "guest/AddressSpace.h"

#include <algorithm>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace rosa::guest {

void AddressSpace::mapSegments(std::span<const SegmentMapping> requests) {
    if (requests.empty()) {
        return;
    }
    if (requests.size() >
        std::numeric_limits<std::size_t>::max() - mappings_.size()) {
        throw std::overflow_error("guest mapping batch count overflows");
    }

    // Validate every range against the live address space before allocating
    // backing storage. The live mapping vector remains untouched on failure.
    std::vector<std::size_t> order(requests.size());
    std::iota(order.begin(), order.end(), std::size_t{0});
    for (const auto &request : requests) {
        if (request.initialBytes.size() > request.size) {
            throw std::invalid_argument(
                "guest segment file bytes exceed virtual size");
        }
        validateNewMapping(request.base, request.size, request.permissions,
                           request.maximumPermissions);
    }
    std::ranges::sort(order, [&requests](std::size_t lhs, std::size_t rhs) {
        return requests[lhs].base.value < requests[rhs].base.value;
    });
    for (std::size_t index = 1; index < order.size(); ++index) {
        const auto &previous = requests[order[index - 1]];
        const auto &current = requests[order[index]];
        if (previous.base.value + previous.size > current.base.value) {
            throw std::invalid_argument(
                "guest mapping batch contains overlapping mappings");
        }
    }

    // Materialize every fallible allocation before moving a live mapping.
    std::vector<Mapping> pending;
    pending.reserve(requests.size());
    bool addsExecutableMapping = false;
    for (const auto index : order) {
        const auto &request = requests[index];
        addsExecutableMapping |=
            (static_cast<std::uint8_t>(request.permissions) &
             static_cast<std::uint8_t>(Permission::Execute)) != 0;
        std::vector<std::uint8_t> backing;
        if (request.maximumPermissions != Permission::None) {
            backing.resize(request.size);
            std::copy(request.initialBytes.begin(), request.initialBytes.end(),
                      backing.begin());
        }
        pending.push_back(Mapping{
            .base = request.base,
            .size = request.size,
            .permissions = request.permissions,
            .maximumPermissions = request.maximumPermissions,
            .bytes = std::move(backing),
            .label = request.label,
        });
    }

    static_assert(std::is_nothrow_move_constructible_v<Mapping>);
    std::vector<Mapping> updated;
    updated.reserve(mappings_.size() + pending.size());
    std::size_t existingIndex = 0;
    std::size_t pendingIndex = 0;
    while (existingIndex < mappings_.size() || pendingIndex < pending.size()) {
        if (pendingIndex == pending.size() ||
            (existingIndex < mappings_.size() &&
             mappings_[existingIndex].base.value <
                 pending[pendingIndex].base.value)) {
            updated.push_back(std::move(mappings_[existingIndex++]));
        } else {
            updated.push_back(std::move(pending[pendingIndex++]));
        }
    }
    mappings_.swap(updated);
    if (addsExecutableMapping) {
        ++executableVersion_;
    }
}

} // namespace rosa::guest
