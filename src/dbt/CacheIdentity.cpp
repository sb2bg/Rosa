#include "dbt/CacheIdentity.h"
#include "dbt/RuntimeHelpers.h"

#include <cstring>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <stdexcept>

namespace rosa::dbt {

std::uint64_t translationHelperAnchor() noexcept {
    auto pointer = &runtime::updateLogicFlags8;
    std::uint64_t result{};
    static_assert(sizeof(pointer) == sizeof(result));
    std::memcpy(&result, &pointer, sizeof(result));
    return result;
}

std::uint64_t translationCacheBuildFingerprint() {
    // A translation-unit timestamp misses edits to separately compiled passes,
    // emitters, and helpers. The linker UUID covers their final code layout and
    // remains stable across process ASLR slides. It also handles shared rosa_core.
    Dl_info image{};
    if (::dladdr(reinterpret_cast<const void *>(translationHelperAnchor()), &image) == 0 ||
        image.dli_fbase == nullptr) {
        throw std::runtime_error("cannot identify the translation runtime image");
    }
    const auto *header = static_cast<const mach_header_64 *>(image.dli_fbase);
    if (header->magic != MH_MAGIC_64) {
        throw std::runtime_error("translation runtime image is not 64-bit Mach-O");
    }
    const auto *commands = reinterpret_cast<const std::uint8_t *>(header + 1);
    std::size_t offset = 0;
    for (std::uint32_t index = 0; index < header->ncmds; ++index) {
        if (offset > header->sizeofcmds ||
            header->sizeofcmds - offset < sizeof(load_command)) {
            break;
        }
        const auto *command = reinterpret_cast<const load_command *>(commands + offset);
        if (command->cmdsize < sizeof(load_command) ||
            command->cmdsize > header->sizeofcmds - offset) {
            break;
        }
        if (command->cmd == LC_UUID && command->cmdsize >= sizeof(uuid_command)) {
            const auto *uuid = reinterpret_cast<const uuid_command *>(command);
            std::uint64_t hash = UINT64_C(1469598103934665603);
            for (const auto byte : uuid->uuid) {
                hash ^= byte;
                hash *= UINT64_C(1099511628211);
            }
            return hash;
        }
        offset += command->cmdsize;
    }
    throw std::runtime_error("translation runtime image has no linker UUID");
}

} // namespace rosa::dbt
