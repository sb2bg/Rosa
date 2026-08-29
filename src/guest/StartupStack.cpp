#include "guest/StartupStack.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rosa::guest {
namespace {

std::size_t checkedAdd(std::size_t lhs, std::size_t rhs,
                       std::string_view description) {
    if (lhs > std::numeric_limits<std::size_t>::max() - rhs) {
        throw std::overflow_error(std::string(description) + " count overflows");
    }
    return lhs + rhs;
}

std::size_t checkedMultiply(std::size_t lhs, std::size_t rhs,
                            std::string_view description) {
    if (lhs != 0 && rhs > std::numeric_limits<std::size_t>::max() / lhs) {
        throw std::overflow_error(std::string(description) + " size overflows");
    }
    return lhs * rhs;
}

GuestAddress reserveString(GuestAddress base, std::uint64_t &cursor,
                           const std::string &string) {
    if (string.size() == std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error("initial guest stack string size overflows");
    }
    const auto byteCount = string.size() + 1U;
    if (cursor < base.value ||
        static_cast<std::uint64_t>(byteCount) > cursor - base.value) {
        throw std::runtime_error("initial guest stack does not have room for strings");
    }
    cursor -= static_cast<std::uint64_t>(byteCount);
    return GuestAddress{cursor};
}

std::vector<GuestAddress> reserveStrings(GuestAddress base, std::uint64_t &cursor,
                                         std::span<const std::string> strings) {
    std::vector<GuestAddress> addresses(strings.size());
    for (std::size_t index = strings.size(); index > 0; --index) {
        addresses[index - 1] = reserveString(base, cursor, strings[index - 1]);
    }
    return addresses;
}

void copyString(std::span<std::uint8_t> payload, GuestAddress payloadBase,
                GuestAddress destination, const std::string &string) {
    if (destination.value < payloadBase.value) {
        throw std::logic_error("initial guest stack string precedes payload");
    }
    const auto offsetValue = destination.value - payloadBase.value;
    if (offsetValue > payload.size()) {
        throw std::logic_error("initial guest stack string offset exceeds payload");
    }
    const auto offset = static_cast<std::size_t>(offsetValue);
    if (string.size() == std::numeric_limits<std::size_t>::max() ||
        string.size() + 1U > payload.size() - offset) {
        throw std::logic_error("initial guest stack string exceeds payload");
    }
    for (std::size_t index = 0; index < string.size(); ++index) {
        payload[offset + index] = static_cast<std::uint8_t>(string[index]);
    }
    payload[offset + string.size()] = 0;
}

void copyStrings(std::span<std::uint8_t> payload, GuestAddress payloadBase,
                 std::span<const std::string> strings,
                 std::span<const GuestAddress> destinations) {
    if (strings.size() != destinations.size()) {
        throw std::logic_error("initial guest stack string metadata differs");
    }
    for (std::size_t index = 0; index < strings.size(); ++index) {
        copyString(payload, payloadBase, destinations[index], strings[index]);
    }
}

void writeU64(std::span<std::uint8_t> payload, std::size_t offset,
              std::uint64_t value) {
    if (offset > payload.size() || sizeof(value) > payload.size() - offset) {
        throw std::logic_error("initial guest stack word exceeds payload");
    }
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        payload[offset + index] =
            static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

} // namespace

InitialStack StartupStackBuilder::build(AddressSpace &addressSpace, GuestAddress base,
                                        std::size_t size,
                                        std::span<const std::string> arguments,
                                        std::span<const std::string> environment,
                                        std::span<const std::string> apple,
                                        std::optional<GuestAddress> mainExecutable) const {
    if (arguments.empty()) {
        throw std::invalid_argument("initial Darwin guest stack requires argv[0]");
    }
    if (base.value > std::numeric_limits<std::uint64_t>::max() - size) {
        throw std::invalid_argument("initial guest stack range overflows");
    }
    const auto top = base.value + size;
    auto cursor = top;

    // Build every fallible host-side structure before installing the mapping.
    // A malformed or oversized startup vector must not leave a partially
    // initialized guest stack behind and prevent a caller from retrying.
    const auto appleAddresses = reserveStrings(base, cursor, apple);
    const auto environmentAddresses = reserveStrings(base, cursor, environment);
    const auto argumentAddresses = reserveStrings(base, cursor, arguments);

    std::size_t wordCount = mainExecutable ? 1U : 0U;
    wordCount = checkedAdd(wordCount, 1U, "initial guest stack word");
    wordCount = checkedAdd(wordCount, argumentAddresses.size(),
                           "initial guest stack word");
    wordCount = checkedAdd(wordCount, 1U, "initial guest stack word");
    wordCount = checkedAdd(wordCount, environmentAddresses.size(),
                           "initial guest stack word");
    wordCount = checkedAdd(wordCount, 1U, "initial guest stack word");
    wordCount = checkedAdd(wordCount, appleAddresses.size(),
                           "initial guest stack word");
    wordCount = checkedAdd(wordCount, 1U, "initial guest stack word");

    std::vector<std::uint64_t> words;
    words.reserve(wordCount);
    // dyld's KernelArgs begins with the main executable's Mach-O header,
    // followed by the normal argc/argv/envp/apple vectors. Direct executable
    // entry points receive the normal vectors without this dyld-only prefix.
    if (mainExecutable) {
        words.push_back(mainExecutable->value);
    }
    words.push_back(static_cast<std::uint64_t>(arguments.size()));
    for (const auto address : argumentAddresses) {
        words.push_back(address.value);
    }
    words.push_back(0);
    for (const auto address : environmentAddresses) {
        words.push_back(address.value);
    }
    words.push_back(0);
    for (const auto address : appleAddresses) {
        words.push_back(address.value);
    }
    words.push_back(0);

    const auto wordBytes = checkedMultiply(words.size(), sizeof(std::uint64_t),
                                           "initial guest stack word");
    if (cursor < base.value ||
        static_cast<std::uint64_t>(wordBytes) > cursor - base.value) {
        throw std::runtime_error(
            "initial guest stack does not have room for pointer vectors");
    }
    const auto stackPointerValue =
        (cursor - static_cast<std::uint64_t>(wordBytes)) & ~std::uint64_t{0xFU};
    if (stackPointerValue < base.value) {
        throw std::runtime_error("initial guest stack alignment underflows mapping");
    }
    const auto stackPointer = GuestAddress{stackPointerValue};
    const auto payloadSizeValue = top - stackPointer.value;
    if (payloadSizeValue > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error("initial guest stack payload size overflows");
    }
    std::vector<std::uint8_t> payload(
        static_cast<std::size_t>(payloadSizeValue));
    for (std::size_t index = 0; index < words.size(); ++index) {
        writeU64(payload, index * sizeof(std::uint64_t), words[index]);
    }
    copyStrings(payload, stackPointer, arguments, argumentAddresses);
    copyStrings(payload, stackPointer, environment, environmentAddresses);
    copyStrings(payload, stackPointer, apple, appleAddresses);

    addressSpace.mapAnonymous(base, size, Permission::Read | Permission::Write,
                              "guest stack");
    addressSpace.writeBytes(stackPointer, payload);
    return InitialStack{.base = base, .size = size, .stackPointer = stackPointer};
}

} // namespace rosa::guest
