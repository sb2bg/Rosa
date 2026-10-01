#pragma once

#include "ir/IR.h"

namespace rosa::ir {

// A repeatable self edge permits batching without crossing runtime boundaries.
[[nodiscard]] bool hasInternalSelfEdge(const Block &block);

// Shared preparation for baseline translation and lazily reconstructed hot IR.
// Memory forwarding retains the existing guarded self-loop restrictions.
void optimizeBlock(Block &block);

} // namespace rosa::ir
