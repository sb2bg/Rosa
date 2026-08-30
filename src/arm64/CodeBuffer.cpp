#include "arm64/CodeBuffer.h"

#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace rosa::arm64 {
namespace {

std::size_t roundUp(std::size_t value, std::size_t alignment) {
    if (alignment == 0) {
        throw std::invalid_argument("executable code alignment must be nonzero");
    }
    const auto remainder = value % alignment;
    if (remainder == 0) {
        return value;
    }
    const auto padding = alignment - remainder;
    if (value > std::numeric_limits<std::size_t>::max() - padding) {
        throw std::overflow_error("executable code mapping size overflows");
    }
    return value + padding;
}

class JitWriteScope {
  public:
    JitWriteScope() { pthread_jit_write_protect_np(0); }
    ~JitWriteScope() { pthread_jit_write_protect_np(1); }

    JitWriteScope(const JitWriteScope &) = delete;
    JitWriteScope &operator=(const JitWriteScope &) = delete;
};

} // namespace

ExecutableArena::ExecutableArena(std::size_t chunkSize)
    : chunkSize_(chunkSize) {
    const auto rawPageSize = sysconf(_SC_PAGESIZE);
    if (rawPageSize <= 0) {
        throw std::runtime_error("failed to query host page size");
    }
    pageSize_ = static_cast<std::size_t>(rawPageSize);
}

ExecutableArena::~ExecutableArena() {
    for (const auto &chunk : chunks_) {
        if (chunk.mapping != nullptr) {
            ::munmap(chunk.mapping, chunk.size);
        }
    }
}

ExecutableArena::Allocation
ExecutableArena::reserve(std::size_t size) {
    if (size == 0) {
        throw std::invalid_argument("cannot create an empty executable code buffer");
    }

    constexpr std::size_t codeAlignment = 16;
    Chunk *chunk = chunks_.empty() ? nullptr : &chunks_.back();
    auto offset = chunk == nullptr ? 0 : roundUp(chunk->used, codeAlignment);
    if (chunk == nullptr || offset > chunk->size ||
        size > chunk->size - offset) {
        const auto required = roundUp(size, codeAlignment);
        const auto allocationSize =
            roundUp(std::max(chunkSize_, required), pageSize_);
        if (allocationSize >
            std::numeric_limits<std::size_t>::max() - allocatedBytes_) {
            throw std::overflow_error("executable arena size overflows");
        }

        auto *mapping = mmap(nullptr, allocationSize,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
        if (mapping == MAP_FAILED) {
            mapping = nullptr;
            throw std::runtime_error(std::string("MAP_JIT allocation failed: ") +
                                     std::strerror(errno));
        }
        try {
            chunks_.push_back(Chunk{
                .mapping = mapping,
                .size = allocationSize,
            });
        } catch (...) {
            ::munmap(mapping, allocationSize);
            throw;
        }
        allocatedBytes_ += allocationSize;
        chunk = &chunks_.back();
        offset = 0;
    }

    if (offset > std::numeric_limits<std::size_t>::max() - size) {
        throw std::overflow_error("executable arena offset overflows");
    }
    const auto nextOffset = offset + size;
    const auto consumed = nextOffset - chunk->used;
    if (consumed >
        std::numeric_limits<std::size_t>::max() - usedBytes_) {
        throw std::overflow_error("executable arena used-byte count overflows");
    }
    auto *const destination = static_cast<std::uint8_t *>(chunk->mapping) + offset;
    usedBytes_ += consumed;
    chunk->used = nextOffset;
    return Allocation{destination, size};
}

ExecutableArena::Allocation
ExecutableArena::publish(std::span<const std::uint8_t> bytes) {
    const auto allocation = reserve(bytes.size());
    {
        JitWriteScope writable;
        std::memcpy(allocation.address, bytes.data(), bytes.size());
        sys_icache_invalidate(allocation.address, allocation.size);
    }
    return allocation;
}

std::vector<ExecutableArena::Allocation> ExecutableArena::publishBatch(
    std::span<const std::span<const std::uint8_t>> programs) {
    std::vector<Allocation> allocations;
    allocations.reserve(programs.size());
    for (const auto program : programs) {
        allocations.push_back(reserve(program.size()));
    }
    if (allocations.empty()) {
        return allocations;
    }
    {
        JitWriteScope writable;
        for (std::size_t index = 0; index < programs.size(); ++index) {
            std::memcpy(allocations[index].address, programs[index].data(),
                        programs[index].size());
        }
        auto rangeStart = reinterpret_cast<std::uintptr_t>(
            allocations.front().address);
        auto rangeEnd = rangeStart + allocations.front().size;
        for (std::size_t index = 1; index < allocations.size(); ++index) {
            const auto start = reinterpret_cast<std::uintptr_t>(
                allocations[index].address);
            if (start >= rangeEnd &&
                start - rangeEnd < 16U) {
                rangeEnd = start + allocations[index].size;
                continue;
            }
            sys_icache_invalidate(reinterpret_cast<void *>(rangeStart),
                                  rangeEnd - rangeStart);
            rangeStart = start;
            rangeEnd = start + allocations[index].size;
        }
        sys_icache_invalidate(reinterpret_cast<void *>(rangeStart),
                              rangeEnd - rangeStart);
    }
    return allocations;
}

ExecutableCode::ExecutableCode(std::span<const std::uint8_t> bytes)
    : ExecutableCode(std::make_shared<ExecutableArena>(0), bytes) {}

ExecutableCode::ExecutableCode(std::shared_ptr<ExecutableArena> arena,
                               std::span<const std::uint8_t> bytes)
    : arena_(std::move(arena)) {
    if (!arena_) {
        throw std::invalid_argument("executable code requires an arena");
    }
    const auto allocation = arena_->publish(bytes);
    entry_ = allocation.address;
    usedSize_ = allocation.size;
}

ExecutableCode::ExecutableCode(std::shared_ptr<ExecutableArena> arena,
                               void *entry, std::size_t usedSize) noexcept
    : arena_(std::move(arena)), entry_(entry), usedSize_(usedSize) {}

std::vector<ExecutableCode> ExecutableCode::publishBatch(
    std::shared_ptr<ExecutableArena> arena,
    std::span<const std::span<const std::uint8_t>> programs) {
    if (!arena) {
        throw std::invalid_argument("executable code requires an arena");
    }
    auto allocations = arena->publishBatch(programs);
    std::vector<ExecutableCode> result;
    result.reserve(allocations.size());
    for (const auto allocation : allocations) {
        result.push_back(
            ExecutableCode(arena, allocation.address, allocation.size));
    }
    return result;
}

ExecutableCode::ExecutableCode(ExecutableCode &&other) noexcept
    : arena_(std::move(other.arena_)),
      entry_(std::exchange(other.entry_, nullptr)),
      usedSize_(std::exchange(other.usedSize_, 0)) {}

ExecutableCode &ExecutableCode::operator=(ExecutableCode &&other) noexcept {
    if (this != &other) {
        arena_ = std::move(other.arena_);
        entry_ = std::exchange(other.entry_, nullptr);
        usedSize_ = std::exchange(other.usedSize_, 0);
    }
    return *this;
}

} // namespace rosa::arm64
