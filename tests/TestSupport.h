#pragma once

#include "arm64/Assembler.h"
#include "arm64/CodeBuffer.h"
#include "darwin/Commpage.h"
#include "darwin/Mach.h"
#include "darwin/SharedCache.h"
#include "darwin/Syscall.h"
#include "dbt/Dispatcher.h"
#include "dbt/LlvmBackend.h"
#include "dbt/Translator.h"
#include "debug/Dump.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "guest/StartupStack.h"
#include "ir/IR.h"
#include "macho/Loader.h"
#include "macho/MachOFile.h"
#include "x86/Decoder.h"
#include "x86/Instruction.h"
#include "x86/Registers.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mach/mach.h>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>


namespace rosa::tests {

constexpr std::uint64_t carryFlag = 1U << 0U;
constexpr std::uint64_t parityFlag = 1U << 2U;
constexpr std::uint64_t auxiliaryFlag = 1U << 4U;
constexpr std::uint64_t zeroFlag = 1U << 6U;
constexpr std::uint64_t signFlag = 1U << 7U;
constexpr std::uint64_t overflowFlag = 1U << 11U;
constexpr std::uint64_t directionFlag = 1U << 10U;
constexpr std::uint64_t arithmeticFlags =
    carryFlag | parityFlag | auxiliaryFlag | zeroFlag | signFlag | overflowFlag;
constexpr std::uint64_t logicDefinedFlags =
    carryFlag | parityFlag | zeroFlag | signFlag | overflowFlag;


template <typename Actual, typename Expected>
void expectEqual(const Actual &actual, const Expected &expected, std::string_view message) {
    if (actual != expected) {
        throw std::runtime_error(std::string(message));
    }
}

inline void expect(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

// Descriptors the guest opened itself, excluding the inherited standard
// streams, so expectations do not depend on how the test runner was launched.
inline std::size_t guestOpenedDescriptors(const rosa::darwin::SyscallDispatcher &dispatcher) {
    std::size_t inherited = 0;
    for (std::int32_t stream = 0; stream <= 2; ++stream) {
        const auto *file = dispatcher.fileSpace().lookup(rosa::darwin::GuestFileDescriptor{stream});
        inherited += file != nullptr && file->kind == rosa::darwin::GuestFileKind::StandardStream;
    }
    return dispatcher.fileSpace().size() - inherited;
}

inline std::uint64_t fixedTimestampCounter() { return 0x12345678ABCDEF01ULL; }

constexpr std::array<std::uint8_t, 15> r1Code{
    0x48, 0xB8, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC0, 0x02, 0xC3,
};

} // namespace rosa::tests
