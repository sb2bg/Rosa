#include "darwin/SyscallInternal.h"

namespace rosa::darwin::detail {
namespace {

std::optional<guest::GuestAddress>
findMmapRange(const guest::AddressSpace &addressSpace, std::uint64_t size) {
    const auto alignUpToPage = [](std::uint64_t value)
        -> std::optional<std::uint64_t> {
        constexpr auto mask =
            static_cast<std::uint64_t>(guest::guestPageSize - 1U);
        if (value > std::numeric_limits<std::uint64_t>::max() - mask) {
            return std::nullopt;
        }
        return (value + mask) & ~mask;
    };

    auto candidate = minimumMmapAddress;
    auto mappings = addressSpace.mappingInfos();
    std::ranges::sort(mappings, {}, [](const guest::MappingInfo &mapping) {
        return mapping.base.value;
    });
    for (const auto &mapping : mappings) {
        const auto mappingEnd = mapping.base.value + mapping.size;
        if (mappingEnd <= candidate) {
            continue;
        }
        if (candidate <= mapping.base.value &&
            size <= mapping.base.value - candidate) {
            return guest::GuestAddress{candidate};
        }
        const auto next = alignUpToPage(mappingEnd);
        if (!next) {
            return std::nullopt;
        }
        candidate = *next;
    }
    if (candidate <= maximumUserMapEnd &&
        size <= maximumUserMapEnd - candidate) {
        return guest::GuestAddress{candidate};
    }
    return std::nullopt;
}

// Layouts mirror Apple's mach/dyld_pager.h and mach-o/fixup-chains.h for the
// map_with_linking_np blob. All integers are little-endian.
struct MapWithLinkingRegion {
    std::int32_t fd{};
    std::uint32_t protections{};
    std::uint64_t fileOffset{};
    std::uint64_t address{};
    std::uint64_t size{};
};

template <typename T>
T readMapWithLinkingField(const std::vector<std::uint8_t> &bytes, std::size_t offset) {
    static_assert(std::is_integral_v<T>);
    T value{};
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        throw std::out_of_range("map_with_linking field exceeds its extent");
    }
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

// Applies one page of DYLD_CHAINED_PTR_64 chained fixups exactly like XNU's
// fixupPage64: bind entries resolve through the blob's pre-resolved address
// table, rebase entries add the blob slide (or image address for
// offset-based chains). Throws std::out_of_range for a structurally short
// blob and std::runtime_error for guest-memory faults so the caller can map
// each to the right guest-visible result.
void applyMapWithLinkingPageFixups(guest::AddressSpace &addressSpace,
                                   const std::vector<std::uint8_t> &blob,
                                   std::uint64_t pageAddress) {
    constexpr std::uint16_t chainStartNone = 0xFFFF;
    constexpr std::uint64_t bindBit = 1ULL << 63U;
    constexpr std::uint64_t pageSize = guest::guestPageSize;

    const auto pointerFormat = readMapWithLinkingField<std::uint16_t>(blob, 6);
    const bool offsetBased = pointerFormat == 6;
    const auto bindsOffset = readMapWithLinkingField<std::uint32_t>(blob, 8);
    const auto bindsCount = readMapWithLinkingField<std::uint32_t>(blob, 12);
    const auto chainsOffset = readMapWithLinkingField<std::uint32_t>(blob, 16);
    const auto slide = readMapWithLinkingField<std::uint64_t>(blob, 24);
    const auto imageAddress = readMapWithLinkingField<std::uint64_t>(blob, 32);

    const auto segCount = readMapWithLinkingField<std::uint32_t>(blob, chainsOffset);
    for (std::uint32_t segIndex = 0; segIndex < segCount; ++segIndex) {
        const auto segInfoOffset =
            readMapWithLinkingField<std::uint32_t>(blob, chainsOffset + 4 + segIndex * 4U);
        const auto segOffset = static_cast<std::uint64_t>(chainsOffset) + segInfoOffset;
        if (segOffset > blob.size()) {
            throw std::out_of_range("map_with_linking chained segment escapes its blob");
        }
        const auto segSize = readMapWithLinkingField<std::uint32_t>(blob, segOffset);
        const auto segmentOffset = readMapWithLinkingField<std::uint64_t>(blob, segOffset + 8);
        const auto pageCount = readMapWithLinkingField<std::uint16_t>(blob, segOffset + 20);
        if (segSize < 24 ||
            segOffset + segSize > blob.size() ||
            segOffset + 22 > blob.size() ||
            static_cast<std::uint64_t>(pageCount) * 2U > blob.size() - (segOffset + 22)) {
            throw std::out_of_range("map_with_linking chained segment exceeds its blob");
        }
        const auto segStart = imageAddress + segmentOffset;
        const auto segEnd = segStart + static_cast<std::uint64_t>(pageCount) * pageSize;
        if (segStart > pageAddress || pageAddress >= segEnd) {
            continue;
        }
        const auto pageIndex = (pageAddress - segStart) / pageSize;
        const auto firstStart = readMapWithLinkingField<std::uint16_t>(
            blob, segOffset + 22 + pageIndex * 2U);
        if (firstStart == chainStartNone) {
            return;
        }
        auto location = pageAddress + firstStart;
        while (true) {
            if (location < pageAddress || location + sizeof(std::uint64_t) > pageAddress + pageSize) {
                throw std::out_of_range("map_with_linking chain leaves its page");
            }
            const auto value = addressSpace.readU64(guest::GuestAddress{location});
            const bool isBind = (value & bindBit) != 0;
            const auto delta = ((value >> 51U) & 0xFFFU) * 4U;
            if (isBind) {
                const auto ordinal = value & 0xFFFFFFULL;
                if (ordinal >= bindsCount) {
                    throw std::out_of_range("map_with_linking bind ordinal exceeds its table");
                }
                const auto addend = (value >> 24U) & 0xFFULL;
                const auto target = readMapWithLinkingField<std::uint64_t>(
                    blob, static_cast<std::uint64_t>(bindsOffset) + ordinal * 8U);
                addressSpace.writeU64(guest::GuestAddress{location}, target + addend);
            } else {
                const auto target = value & 0xFFFFFFFFFULL;
                const auto high8 = (value >> 36U) & 0xFFULL;
                const auto adjust = offsetBased ? imageAddress : slide;
                addressSpace.writeU64(guest::GuestAddress{location},
                                      target + adjust + (high8 << 56U));
            }
            if (delta == 0) {
                return;
            }
            if (delta > pageSize || location + delta < pageAddress ||
                location + delta + sizeof(std::uint64_t) > pageAddress + pageSize) {
                throw std::out_of_range("map_with_linking chain delta leaves its page");
            }
            location += delta;
        }
    }
    throw std::out_of_range("no map_with_linking chained segment covers the page");
}

} // namespace

SyscallOutcome handleMprotect(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    if ((state.rdi % guest::guestPageSize) != 0 ||
        (state.rdx & ~guestProtectionMask) != 0) {
        setError(state, EINVAL);
        return {};
    }
    auto permissions = guest::Permission::None;
    if ((state.rdx & guestProtectionRead) != 0) {
        permissions = permissions | guest::Permission::Read;
    }
    if ((state.rdx & guestProtectionWrite) != 0) {
        permissions = permissions | guest::Permission::Write;
    }
    if ((state.rdx & guestProtectionExecute) != 0) {
        permissions = permissions | guest::Permission::Execute;
    }
    switch (addressSpace.protect(guest::GuestAddress{state.rdi},
                                 state.rsi, permissions)) {
    case guest::ProtectResult::Success:
        setSuccess(state, 0);
        return {};
    case guest::ProtectResult::InvalidAddress:
        setError(state, ENOMEM);
        return {};
    case guest::ProtectResult::ProtectionFailure:
        setError(state, EACCES);
        return {};
    case guest::ProtectResult::InvalidArgument:
        setError(state, EINVAL);
        return {};
    }
    throw std::runtime_error("unreachable guest mprotect result");
}

SyscallOutcome handleMadvise(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(addressSpace);
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    // Advice never affects correctness: Rosa has no page cache, swap, or
    // wired pages to manage, so every known behavior is a successful
    // no-op. Reject only unknown behaviors, which indicate a guest bug.
    // Darwin behaviors run NORMAL..CAN_REUSE (0..9) plus PAGEOUT (10).
    if (state.rdx > 10) {
        setError(state, EINVAL);
        return {};
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleMunmap(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    static_cast<void>(task);
    // XNU's BSD munmap requires a page-aligned start and nonzero size,
    // rounds the end up, and accepts holes in the range. Keep the entire
    // operation inside Rosa's guest map.
    if ((state.rdi % guest::guestPageSize) != 0 || state.rsi == 0) {
        setError(state, EINVAL);
        return {};
    }
    switch (addressSpace.deallocate(guest::GuestAddress{state.rdi},
                                    state.rsi)) {
    case guest::DeallocateResult::Success:
        setSuccess(state, 0);
        return {};
    case guest::DeallocateResult::InvalidArgument:
        setError(state, EINVAL);
        return {};
    }
    throw std::runtime_error("unreachable guest munmap result");
}

SyscallOutcome handleMmap(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    const auto descriptor = GuestFileDescriptor{
        std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.r8))};
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr || file->kind != GuestFileKind::HostReadOnlyFile) {
        setError(state, EBADF);
        return {};
    }
    if (state.rdi != 0 || state.rdx != guestProtectionRead ||
        state.r10 != guestObservedFileMapFlags ||
        (state.r9 % guest::guestPageSize) != 0) {
        std::ostringstream reason;
        reason << "only the observed anywhere read-only private resilient-codesign file mmap is implemented; got address=0x"
               << std::hex << state.rdi << " length=0x" << state.rsi
               << " protection=0x" << state.rdx << " flags=0x"
               << state.r10 << " fd=" << std::dec << descriptor.value
               << " offset=0x" << std::hex << state.r9;
        throw unsupported(state, syscallRip, reason.str());
    }
    if (state.rsi == 0 ||
        state.rsi > std::numeric_limits<std::size_t>::max() ||
        state.rsi > std::numeric_limits<std::uint64_t>::max() -
                        (guest::guestPageSize - 1U)) {
        setError(state, EINVAL);
        return {};
    }
    const auto roundedSize =
        (state.rsi + guest::guestPageSize - 1U) &
        ~(static_cast<std::uint64_t>(guest::guestPageSize) - 1U);
    const auto mappedAddress = findMmapRange(addressSpace, roundedSize);
    if (!mappedAddress) {
        setError(state, ENOMEM);
        return {};
    }
    try {
        addressSpace.mapFileSegment(
            *mappedAddress, static_cast<std::size_t>(roundedSize),
            guest::Permission::Read, guest::Permission::Read,
            file->guestPath, state.r9, "mmap private file");
    } catch (const std::invalid_argument &) {
        setError(state, EINVAL);
        return {};
    }
    setSuccess(state, mappedAddress->value);
    return {};
}

SyscallOutcome handleMapWithLinking(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    // dyld's page-in linking: over-map file ranges, then apply the
    // chained fixups in the blob. Like XNU's dyld pager this resolves
    // binds through the blob's pre-resolved address table, so no
    // userspace symbol lookup is involved. Guest arguments are the
    // regions pointer in RDI, region count in RSI, blob pointer in RDX,
    // and blob size in R10.
    constexpr std::uint64_t maximumLinkInfoSize = 64U * 1024U * 1024U;
    const auto regionCount = state.rsi;
    const auto blobSize = state.r10;
    if (regionCount == 0 || regionCount > 5 || blobSize <= 40 ||
        blobSize > maximumLinkInfoSize) {
        setError(state, EINVAL);
        return {};
    }
    std::vector<std::uint8_t> regionBytes;
    std::vector<std::uint8_t> blob;
    try {
        regionBytes = addressSpace.readBytes(guest::GuestAddress{state.rdi},
                                             regionCount * sizeof(MapWithLinkingRegion));
        blob = addressSpace.readBytes(guest::GuestAddress{state.rdx},
                                      static_cast<std::size_t>(blobSize));
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    std::vector<MapWithLinkingRegion> regions;
    regions.reserve(static_cast<std::size_t>(regionCount));
    for (std::uint64_t index = 0; index < regionCount; ++index) {
        const auto base = index * sizeof(MapWithLinkingRegion);
        MapWithLinkingRegion region{};
        std::memcpy(&region.fd, regionBytes.data() + base, sizeof(region.fd));
        std::memcpy(&region.protections, regionBytes.data() + base + 4,
                    sizeof(region.protections));
        std::memcpy(&region.fileOffset, regionBytes.data() + base + 8,
                    sizeof(region.fileOffset));
        std::memcpy(&region.address, regionBytes.data() + base + 16,
                    sizeof(region.address));
        std::memcpy(&region.size, regionBytes.data() + base + 24, sizeof(region.size));
        regions.push_back(region);
    }
    for (std::size_t index = 1; index < regions.size(); ++index) {
        if (regions[index].fd != regions.front().fd) {
            std::ostringstream reason;
            reason << "map_with_linking with multiple backing files is not implemented; got fd="
                   << regions[index].fd << " after fd=" << regions.front().fd;
            throw unsupported(state, syscallRip, reason.str());
        }
    }
    const auto descriptor = GuestFileDescriptor{std::bit_cast<std::int32_t>(
        static_cast<std::uint32_t>(regions.front().fd))};
    const auto *file = task.fileSpace.lookup(descriptor);
    if (file == nullptr) {
        setError(state, EBADF);
        return {};
    }
    if (file->kind != GuestFileKind::HostReadOnlyFile) {
        std::ostringstream reason;
        reason << "map_with_linking requires a read-only file descriptor; got fd="
               << descriptor.value;
        throw unsupported(state, syscallRip, reason.str());
    }
    std::uint64_t blobVersion = 0;
    std::uint64_t blobPageSize = 0;
    std::uint64_t blobPointerFormat = 0;
    std::uint64_t bindsOffset = 0;
    std::uint64_t bindsCount = 0;
    std::uint64_t chainsOffset = 0;
    std::uint64_t chainsSize = 0;
    try {
        blobVersion = readMapWithLinkingField<std::uint32_t>(blob, 0);
        blobPageSize = readMapWithLinkingField<std::uint16_t>(blob, 4);
        blobPointerFormat = readMapWithLinkingField<std::uint16_t>(blob, 6);
        bindsOffset = readMapWithLinkingField<std::uint32_t>(blob, 8);
        bindsCount = readMapWithLinkingField<std::uint32_t>(blob, 12);
        chainsOffset = readMapWithLinkingField<std::uint32_t>(blob, 16);
        chainsSize = readMapWithLinkingField<std::uint32_t>(blob, 20);
    } catch (const std::out_of_range &) {
        setError(state, EFAULT);
        return {};
    }
    if (blobVersion != 7 || blobPageSize != guest::guestPageSize ||
        (blobPointerFormat != 2 && blobPointerFormat != 6) ||
        bindsOffset > blob.size() ||
        bindsCount > (blob.size() - static_cast<std::size_t>(bindsOffset)) / 8U ||
        chainsOffset > blob.size() ||
        chainsSize > blob.size() - static_cast<std::size_t>(chainsOffset)) {
        std::ostringstream reason;
        reason << "unsupported map_with_linking blob; got version=" << blobVersion
               << " page-size=" << blobPageSize << " pointer-format=" << blobPointerFormat
               << " binds=[" << bindsOffset << "+"
               << bindsCount * 8U << "] chains=[" << chainsOffset << "+"
               << chainsSize << "] blob-size=" << blob.size();
        throw unsupported(state, syscallRip, reason.str());
    }
    std::error_code fileSizeError;
    const auto hostFileSize = std::filesystem::file_size(file->guestPath, fileSizeError);
    if (fileSizeError) {
        setError(state, EIO);
        return {};
    }
    std::ifstream hostFile(file->guestPath, std::ios::binary);
    if (!hostFile) {
        setError(state, EIO);
        return {};
    }
    for (const auto &region : regions) {
        if (region.size == 0 || region.size > std::numeric_limits<std::size_t>::max() ||
            (region.address % guest::guestPageSize) != 0 ||
            (region.size % guest::guestPageSize) != 0) {
            std::ostringstream reason;
            reason << "map_with_linking region is not page aligned; got address=0x"
                   << std::hex << region.address << " size=0x" << region.size;
            throw unsupported(state, syscallRip, reason.str());
        }
        if ((region.protections & 0x4U) != 0) {
            std::ostringstream reason;
            reason << "executable map_with_linking region is not implemented; got address=0x"
                   << std::hex << region.address << " protections=0x"
                   << region.protections;
            throw unsupported(state, syscallRip, reason.str());
        }
        if (region.fileOffset > hostFileSize ||
            region.size > hostFileSize - region.fileOffset) {
            std::ostringstream reason;
            reason << "map_with_linking region extends past its file; got file-offset=0x"
                   << std::hex << region.fileOffset << " size=0x" << region.size;
            throw unsupported(state, syscallRip, reason.str());
        }
        const auto regionSize = static_cast<std::size_t>(region.size);
        try {
            addressSpace.validateAccess(guest::GuestAddress{region.address}, regionSize,
                                        guest::Permission::Read);
        } catch (const std::runtime_error &) {
            setError(state, EINVAL);
            return {};
        }
        // The kernel pager writes file bytes and fixups beneath the new
        // mapping's protections. Model that atomically: grant write
        // access, materialize the pages, then install the final
        // permissions. No guest thread can observe the intermediate
        // state in Rosa's single-threaded model.
        if (addressSpace.protect(guest::GuestAddress{region.address}, regionSize,
                                 guest::Permission::Read | guest::Permission::Write) !=
            guest::ProtectResult::Success) {
            setError(state, EACCES);
            return {};
        }
        constexpr std::size_t copyChunkSize = 1024U * 1024U;
        std::vector<std::uint8_t> chunk(copyChunkSize);
        std::uint64_t copied = 0;
        bool copyFailed = false;
        hostFile.clear();
        hostFile.seekg(static_cast<std::streamoff>(region.fileOffset));
        while (copied < region.size) {
            const auto want =
                static_cast<std::streamsize>(std::min<std::uint64_t>(
                    copyChunkSize, region.size - copied));
            hostFile.read(reinterpret_cast<char *>(chunk.data()), want);
            if (hostFile.gcount() != want) {
                copyFailed = true;
                break;
            }
            try {
                addressSpace.writeBytes(
                    guest::GuestAddress{region.address + copied},
                    std::span<const std::uint8_t>(chunk.data(),
                                                  static_cast<std::size_t>(want)));
            } catch (const std::runtime_error &) {
                copyFailed = true;
                break;
            }
            copied += static_cast<std::uint64_t>(want);
        }
        if (copyFailed) {
            setError(state, EIO);
            return {};
        }
        for (std::uint64_t page = region.address; page < region.address + region.size;
             page += guest::guestPageSize) {
            try {
                applyMapWithLinkingPageFixups(addressSpace, blob, page);
            } catch (const std::out_of_range &error) {
                std::ostringstream reason;
                reason << "map_with_linking fixups failed at page=0x" << std::hex << page
                       << ": " << error.what();
                throw unsupported(state, syscallRip, reason.str());
            } catch (const std::runtime_error &) {
                setError(state, EFAULT);
                return {};
            }
        }
        auto finalPermissions = guest::Permission::None;
        if ((region.protections & 0x1U) != 0) {
            finalPermissions = finalPermissions | guest::Permission::Read;
        }
        if ((region.protections & 0x2U) != 0) {
            finalPermissions = finalPermissions | guest::Permission::Write;
        }
        if (addressSpace.protect(guest::GuestAddress{region.address}, regionSize,
                                 finalPermissions) != guest::ProtectResult::Success) {
            setError(state, EACCES);
            return {};
        }
    }
    setSuccess(state, 0);
    return {};
}

SyscallOutcome handleSharedRegionCheck(SyscallCall &call) {
    auto &[addressSpace, state, syscallRip, task] = call;
    static_cast<void>(syscallRip);
    if (task.sharedCache == nullptr) {
        // Preserve XNU's no-cache result without touching the guest pointer.
        setError(state, EINVAL);
        return {};
    }
    try {
        addressSpace.writeU64(guest::GuestAddress{state.rdi},
                              task.sharedCache->regionStart().value +
                                  task.sharedCache->slide());
    } catch (const std::runtime_error &) {
        setError(state, EFAULT);
        return {};
    }
    setSuccess(state, 0);
    return {};
}

} // namespace rosa::darwin::detail
