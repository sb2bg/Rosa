#include "arm64/CodeBuffer.h"

#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <limits>
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

ExecutableCode::ExecutableCode(std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        throw std::invalid_argument("cannot create an empty executable code buffer");
    }

    const auto rawPageSize = sysconf(_SC_PAGESIZE);
    if (rawPageSize <= 0) {
        throw std::runtime_error("failed to query host page size");
    }
    const auto pageSize = static_cast<std::size_t>(rawPageSize);
    mappingSize_ = roundUp(bytes.size(), pageSize);
    usedSize_ = bytes.size();

    mapping_ = mmap(nullptr, mappingSize_, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (mapping_ == MAP_FAILED) {
        mapping_ = nullptr;
        throw std::runtime_error(std::string("MAP_JIT allocation failed: ") + std::strerror(errno));
    }

    {
        JitWriteScope writable;
        std::memcpy(mapping_, bytes.data(), bytes.size());
        sys_icache_invalidate(mapping_, bytes.size());
    }
}

ExecutableCode::~ExecutableCode() { release(); }

ExecutableCode::ExecutableCode(ExecutableCode &&other) noexcept
    : mapping_(std::exchange(other.mapping_, nullptr)),
      mappingSize_(std::exchange(other.mappingSize_, 0)),
      usedSize_(std::exchange(other.usedSize_, 0)) {}

ExecutableCode &ExecutableCode::operator=(ExecutableCode &&other) noexcept {
    if (this != &other) {
        release();
        mapping_ = std::exchange(other.mapping_, nullptr);
        mappingSize_ = std::exchange(other.mappingSize_, 0);
        usedSize_ = std::exchange(other.usedSize_, 0);
    }
    return *this;
}

void ExecutableCode::release() noexcept {
    if (mapping_ != nullptr) {
        munmap(mapping_, mappingSize_);
        mapping_ = nullptr;
        mappingSize_ = 0;
        usedSize_ = 0;
    }
}

} // namespace rosa::arm64
