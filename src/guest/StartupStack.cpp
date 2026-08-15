#include "guest/StartupStack.h"

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace rosa::guest {
namespace {

GuestAddress placeString(AddressSpace &addressSpace, GuestAddress base, std::uint64_t &cursor,
                         const std::string &string) {
    const auto byteCount = string.size() + 1U;
    if (byteCount > cursor - base.value) {
        throw std::runtime_error("initial guest stack does not have room for strings");
    }
    cursor -= byteCount;
    std::vector<std::uint8_t> bytes;
    bytes.reserve(byteCount);
    for (const auto character : string) {
        bytes.push_back(static_cast<std::uint8_t>(character));
    }
    bytes.push_back(0);
    addressSpace.writeBytes(GuestAddress{cursor}, bytes);
    return GuestAddress{cursor};
}

std::vector<GuestAddress> placeStrings(AddressSpace &addressSpace, GuestAddress base,
                                       std::uint64_t &cursor,
                                       std::span<const std::string> strings) {
    std::vector<GuestAddress> addresses(strings.size());
    for (std::size_t index = strings.size(); index > 0; --index) {
        addresses[index - 1] = placeString(addressSpace, base, cursor, strings[index - 1]);
    }
    return addresses;
}

} // namespace

InitialStack StartupStackBuilder::build(AddressSpace &addressSpace, GuestAddress base,
                                        std::size_t size, std::span<const std::string> arguments,
                                        std::span<const std::string> environment,
                                        std::span<const std::string> apple,
                                        std::optional<GuestAddress> mainExecutable) const {
    if (arguments.empty()) {
        throw std::invalid_argument("initial Darwin guest stack requires argv[0]");
    }
    if (base.value > std::numeric_limits<std::uint64_t>::max() - size) {
        throw std::invalid_argument("initial guest stack range overflows");
    }
    addressSpace.mapAnonymous(base, size, Permission::Read | Permission::Write, "guest stack");
    auto cursor = base.value + size;

    const auto appleAddresses = placeStrings(addressSpace, base, cursor, apple);
    const auto environmentAddresses = placeStrings(addressSpace, base, cursor, environment);
    const auto argumentAddresses = placeStrings(addressSpace, base, cursor, arguments);

    std::vector<std::uint64_t> words;
    words.reserve((mainExecutable ? 1U : 0U) + 1 + argumentAddresses.size() + 1 +
                  environmentAddresses.size() + 1 + appleAddresses.size() + 1);
    // dyld's KernelArgs begins with the main executable's Mach-O header,
    // followed by the normal argc/argv/envp/apple vectors. Direct executable
    // entry points receive the normal vectors without this dyld-only prefix.
    if (mainExecutable) {
        words.push_back(mainExecutable->value);
    }
    words.push_back(arguments.size());
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

    const auto wordBytes = words.size() * sizeof(std::uint64_t);
    if (wordBytes > cursor - base.value) {
        throw std::runtime_error("initial guest stack does not have room for pointer vectors");
    }
    const auto stackPointer = (cursor - wordBytes) & ~std::uint64_t{0xFU};
    if (stackPointer < base.value) {
        throw std::runtime_error("initial guest stack alignment underflows mapping");
    }
    for (std::size_t index = 0; index < words.size(); ++index) {
        addressSpace.writeU64(GuestAddress{stackPointer + (index * sizeof(std::uint64_t))},
                              words[index]);
    }
    return InitialStack{.base = base, .size = size, .stackPointer = GuestAddress{stackPointer}};
}

} // namespace rosa::guest
