#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void storeFixtureU32(std::span<std::uint8_t> bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

void storeFixtureU64(std::span<std::uint8_t> bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

void writeFixtureFile(const std::filesystem::path &path, std::span<const std::uint8_t> bytes) {
    const auto descriptor =
        ::open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        throw std::runtime_error("could not create shared-cache fixture");
    }
    std::size_t written = 0;
    while (written < bytes.size()) {
        const auto count = ::write(descriptor, bytes.data() + written, bytes.size() - written);
        if (count <= 0) {
            ::close(descriptor);
            throw std::runtime_error("could not write shared-cache fixture");
        }
        written += static_cast<std::size_t>(count);
    }
    ::close(descriptor);
}

std::vector<std::uint8_t>
makeSharedCacheFixtureFile(std::uint64_t mappingAddress, std::array<std::uint8_t, 16> uuid,
                           std::uint64_t sharedRegionStart, std::uint64_t sharedRegionSize,
                           std::uint32_t initialProtection, std::uint32_t maximumProtection,
                           bool includeSubcache) {
    constexpr std::size_t fileSize = rosa::guest::guestPageSize;
    constexpr std::size_t mappingOffset = 0x228;
    constexpr std::size_t mappingWithSlideOffset = 0x248;
    constexpr std::size_t subcacheOffset = 0x280;
    std::vector<std::uint8_t> bytes(fileSize);
    constexpr std::string_view magic = "dyld_v1  x86_64";
    std::copy(magic.begin(), magic.end(), bytes.begin());
    storeFixtureU32(bytes, 0x10, mappingOffset);
    storeFixtureU32(bytes, 0x14, 1);
    std::copy(uuid.begin(), uuid.end(), bytes.begin() + 0x58);
    storeFixtureU32(bytes, 0xD8, 1);
    storeFixtureU64(bytes, 0xE0, sharedRegionStart);
    storeFixtureU64(bytes, 0xE8, sharedRegionSize);
    storeFixtureU64(bytes, 0xF0, 0x4000);
    storeFixtureU32(bytes, 0x138, mappingWithSlideOffset);
    storeFixtureU32(bytes, 0x13C, 1);
    storeFixtureU32(bytes, 0x16C, 0x1A0500);
    storeFixtureU32(bytes, 0x188, includeSubcache ? subcacheOffset : 0);
    storeFixtureU32(bytes, 0x18C, includeSubcache ? 1 : 0);
    if (includeSubcache) {
        storeFixtureU64(bytes, 0x1F0, 0x1C000);
        storeFixtureU64(bytes, 0x1F8, 0x4000);
    }

    storeFixtureU64(bytes, mappingOffset, mappingAddress);
    storeFixtureU64(bytes, mappingOffset + 8, fileSize);
    storeFixtureU64(bytes, mappingOffset + 16, 0);
    storeFixtureU32(bytes, mappingOffset + 24, maximumProtection);
    storeFixtureU32(bytes, mappingOffset + 28, initialProtection);

    storeFixtureU64(bytes, mappingWithSlideOffset, mappingAddress);
    storeFixtureU64(bytes, mappingWithSlideOffset + 8, fileSize);
    storeFixtureU64(bytes, mappingWithSlideOffset + 16, 0);
    if (includeSubcache) {
        storeFixtureU64(bytes, mappingWithSlideOffset + 24, 0x300);
        storeFixtureU64(bytes, mappingWithSlideOffset + 32, 42);
    }
    storeFixtureU64(bytes, mappingWithSlideOffset + 40, 4);
    storeFixtureU32(bytes, mappingWithSlideOffset + 48, maximumProtection);
    storeFixtureU32(bytes, mappingWithSlideOffset + 52, initialProtection);
    if (includeSubcache) {
        storeFixtureU32(bytes, 0x300, 2);
        storeFixtureU32(bytes, 0x304, rosa::guest::guestPageSize);
        storeFixtureU32(bytes, 0x308, 40);
        storeFixtureU32(bytes, 0x30C, 1);
        storeFixtureU64(bytes, 0x318, 0x00FFFF0000000000ULL);
        storeFixtureU64(bytes, 0x320, sharedRegionStart);
        bytes[0x328] = 0x00;
        bytes[0x329] = 0x02; // chain starts at page offset 0x800
        storeFixtureU64(bytes, 0x800, 0x0000020000000900ULL);
        storeFixtureU64(bytes, 0x808, 0xA00);
    }
    return bytes;
}

class SharedCacheFixture {
  public:
    SharedCacheFixture() {
        std::array<char, 34> directoryTemplate{};
        constexpr std::string_view pattern = "/tmp/rosa-shared-cache-XXXXXX";
        std::copy(pattern.begin(), pattern.end(), directoryTemplate.begin());
        const auto *directory = ::mkdtemp(directoryTemplate.data());
        if (directory == nullptr) {
            throw std::runtime_error("could not create shared-cache fixture directory");
        }
        mainPath_ = std::filesystem::path(directory) / "dyld_shared_cache_x86_64";
        subcachePath_ = mainPath_;
        subcachePath_ += ".01";

        for (std::size_t index = 0; index < mainUuid_.size(); ++index) {
            mainUuid_[index] = static_cast<std::uint8_t>(index + 1U);
            subcacheUuid_[index] = static_cast<std::uint8_t>(0x80U + index);
        }
        auto main =
            makeSharedCacheFixtureFile(regionStart, mainUuid_, regionStart, regionSize, 5, 5, true);
        std::copy(subcacheUuid_.begin(), subcacheUuid_.end(), main.begin() + 0x280);
        storeFixtureU64(main, 0x290, subcacheVmOffset);
        constexpr std::string_view suffix = ".01";
        std::copy(suffix.begin(), suffix.end(), main.begin() + 0x298);
        constexpr std::size_t legacyImageTable = 0xD00;
        constexpr std::size_t imageTextTable = 0xD40;
        constexpr std::size_t firstPathOffset = 0xD80;
        constexpr std::size_t secondPathOffset = 0xDA0;
        storeFixtureU64(main, 0x88, imageTextTable);
        storeFixtureU64(main, 0x90, 2);
        storeFixtureU32(main, 0x1C0, legacyImageTable);
        storeFixtureU32(main, 0x1C4, 2);
        const auto storeImage = [&](std::size_t index, std::uint64_t address,
                                    std::uint32_t pathOffset,
                                    const std::array<std::uint8_t, 16> &uuid) {
            const auto legacyOffset = legacyImageTable + index * 32;
            storeFixtureU64(main, legacyOffset, address);
            storeFixtureU32(main, legacyOffset + 24, pathOffset);
            const auto textOffset = imageTextTable + index * 32;
            std::copy(uuid.begin(), uuid.end(), main.begin() + textOffset);
            storeFixtureU64(main, textOffset + 16, address);
            storeFixtureU32(main, textOffset + 24, 0x80);
            storeFixtureU32(main, textOffset + 28, pathOffset);
        };
        storeImage(0, regionStart + 0x100, firstPathOffset, mainUuid_);
        storeImage(1, regionStart + subcacheVmOffset + 0x100, secondPathOffset, subcacheUuid_);
        main[0x100] = 0xEB;
        main[0x101] = 0xFE; // stable two-byte loop inside image 0
        constexpr std::string_view firstPath = "/usr/lib/dyld";
        constexpr std::string_view secondPath = "/usr/lib/libSystem.B.dylib";
        std::copy(firstPath.begin(), firstPath.end(), main.begin() + firstPathOffset);
        std::copy(secondPath.begin(), secondPath.end(), main.begin() + secondPathOffset);
        auto subcache = makeSharedCacheFixtureFile(regionStart + subcacheVmOffset, subcacheUuid_,
                                                   regionStart + subcacheVmOffset, 0, 5, 5, false);
        writeFixtureFile(mainPath_, main);
        writeFixtureFile(subcachePath_, subcache);
    }

    SharedCacheFixture(const SharedCacheFixture &) = delete;
    SharedCacheFixture &operator=(const SharedCacheFixture &) = delete;

    ~SharedCacheFixture() {
        ::unlink(subcachePath_.c_str());
        ::unlink(mainPath_.c_str());
        ::rmdir(mainPath_.parent_path().c_str());
    }

    [[nodiscard]] const std::filesystem::path &mainPath() const noexcept { return mainPath_; }
    [[nodiscard]] const std::filesystem::path &subcachePath() const noexcept {
        return subcachePath_;
    }

    void overwriteU32(const std::filesystem::path &path, std::uint64_t offset,
                      std::uint32_t value) const {
        std::array<std::uint8_t, 4> bytes{};
        storeFixtureU32(bytes, 0, value);
        overwrite(path, offset, bytes);
    }

    void overwriteU64(const std::filesystem::path &path, std::uint64_t offset,
                      std::uint64_t value) const {
        std::array<std::uint8_t, 8> bytes{};
        storeFixtureU64(bytes, 0, value);
        overwrite(path, offset, bytes);
    }

    void overwrite(const std::filesystem::path &path, std::uint64_t offset,
                   std::span<const std::uint8_t> bytes) const {
        const auto descriptor = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
        expect(descriptor >= 0, "could not open shared-cache fixture for mutation");
        const auto count =
            ::pwrite(descriptor, bytes.data(), bytes.size(), static_cast<off_t>(offset));
        ::close(descriptor);
        expectEqual(count, static_cast<ssize_t>(bytes.size()),
                    "could not mutate shared-cache fixture");
    }

    static constexpr std::uint64_t regionStart = 0x100000;
    static constexpr std::uint64_t regionSize = 0x20000;
    static constexpr std::uint64_t subcacheVmOffset = 0x10000;

  private:
    std::filesystem::path mainPath_;
    std::filesystem::path subcachePath_;
    std::array<std::uint8_t, 16> mainUuid_{};
    std::array<std::uint8_t, 16> subcacheUuid_{};
};

void expectSharedCacheRejected(const std::filesystem::path &path, std::string_view expectedReason) {
    bool rejected = false;
    try {
        static_cast<void>(rosa::darwin::GuestSharedCache::open(path));
    } catch (const std::runtime_error &error) {
        rejected = std::string_view(error.what()).find(expectedReason) != std::string_view::npos;
    }
    expect(rejected, "malformed shared cache was not rejected diagnostically");
}

void testGuestSharedCacheParsingAndMapping() {
    SharedCacheFixture fixture;
    const auto cache = rosa::darwin::GuestSharedCache::open(fixture.mainPath());
    expect(cache.architecture() == rosa::darwin::SharedCacheArchitecture::X86_64,
           "shared-cache architecture differs");
    expectEqual(cache.regionStart().value, SharedCacheFixture::regionStart,
                "shared-cache region start differs");
    expectEqual(cache.regionSize(), SharedCacheFixture::regionSize,
                "shared-cache region size differs");
    expectEqual(cache.maximumSlide(), std::uint64_t{0x4000}, "shared-cache maximum slide differs");
    expectEqual(cache.slide(), std::uint64_t{0}, "shared-cache guest slide differs");
    expectEqual(cache.files().size(), std::size_t{2}, "shared-cache file count differs");
    expectEqual(cache.files()[1].suffix, std::string(".01"), "shared-cache suffix differs");
    expectEqual(cache.files()[1].cacheVmOffset, SharedCacheFixture::subcacheVmOffset,
                "shared-cache VM offset differs");
    expectEqual(cache.mappings().size(), std::size_t{2}, "shared-cache mapping count differs");
    expectEqual(cache.mappings()[0].flags, std::uint64_t{4},
                "shared-cache mapping-with-slide flags differ");
    expectEqual(cache.images().size(), std::size_t{2}, "shared-cache image metadata count differs");
    expectEqual(cache.images()[0].index, std::size_t{0}, "shared-cache image index differs");
    expectEqual(cache.images()[0].path, std::string("/usr/lib/dyld"),
                "shared-cache image path differs");
    expectEqual(cache.images()[0].loadAddress.value, SharedCacheFixture::regionStart + 0x100,
                "shared-cache image load address differs");
    expectEqual(cache.images()[0].textSize, std::uint64_t{0x80},
                "shared-cache image text size differs");
    expect(cache.images()[0].sourceSuffix.empty(), "main-cache image has a subcache suffix");
    expectEqual(cache.images()[1].sourceSuffix, std::string(".01"),
                "subcache image source suffix differs");
    expect(cache.imageForAddress(rosa::guest::GuestAddress{SharedCacheFixture::regionStart +
                                                           0x100}) == &cache.images()[0],
           "shared-cache resolver missed image range start");
    expect(cache.imageForAddress(rosa::guest::GuestAddress{SharedCacheFixture::regionStart +
                                                           0x17F}) == &cache.images()[0],
           "shared-cache resolver missed image range end byte");
    expect(cache.imageForAddress(
               rosa::guest::GuestAddress{SharedCacheFixture::regionStart + 0x180}) == nullptr,
           "shared-cache resolver included the half-open range end");
    expect(cache.imageForAddress(rosa::guest::GuestAddress{
               SharedCacheFixture::regionStart + SharedCacheFixture::subcacheVmOffset + 0x100}) ==
               &cache.images()[1],
           "shared-cache resolver missed a subcache image");

    rosa::guest::AddressSpace addressSpace;
    cache.mapInto(addressSpace);
    expectEqual(addressSpace.mappingCount(), std::size_t{3},
                "shared-cache guest mapping count differs");
    const auto magic = addressSpace.readBytes(cache.regionStart(), 7);
    expectEqual(std::string(magic.begin(), magic.end()), std::string("dyld_v1"),
                "shared-cache guest bytes differ");
    bool textWriteRejected = false;
    try {
        addressSpace.writeBytes(cache.regionStart(), std::array<std::uint8_t, 1>{0});
    } catch (const std::runtime_error &) {
        textWriteRejected = true;
    }
    expect(textWriteRejected, "shared-cache executable mapping accepted a write");
    constexpr rosa::guest::GuestAddress subcacheAddress{SharedCacheFixture::regionStart +
                                                        SharedCacheFixture::subcacheVmOffset};
    bool subcacheWriteRejected = false;
    try {
        addressSpace.writeU64(subcacheAddress, 0x0123456789ABCDEFULL);
    } catch (const std::runtime_error &) {
        subcacheWriteRejected = true;
    }
    expect(subcacheWriteRejected, "shared-cache executable subcache mapping accepted a write");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{cache.regionStart().value + 0x800}),
                cache.regionStart().value + 0x900,
                "shared-cache first chained pointer was not rebased");
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{cache.regionStart().value + 0x808}),
                cache.regionStart().value + 0xA00,
                "shared-cache terminal chained pointer was not rebased");
    expect(addressSpace.protect(subcacheAddress, rosa::guest::guestPageSize,
                                rosa::guest::Permission::Write) ==
               rosa::guest::ProtectResult::ProtectionFailure,
           "shared-cache mapping exceeded maximum protections");
    constexpr rosa::guest::GuestAddress dynamicAddress{SharedCacheFixture::regionStart + 0x1C000};
    const auto dynamicMagic = addressSpace.readBytes(dynamicAddress, 15);
    expectEqual(std::string(dynamicMagic.begin(), dynamicMagic.end()),
                std::string("dyld_data    v3"), "shared-cache dynamic-data magic differs");
    expectEqual(addressSpace.readU32(rosa::guest::GuestAddress{dynamicAddress.value + 36}),
                std::uint32_t{80}, "shared-cache dynamic-data path offset differs");
    bool dynamicWriteRejected = false;
    try {
        addressSpace.writeBytes(dynamicAddress, std::array<std::uint8_t, 1>{0});
    } catch (const std::runtime_error &) {
        dynamicWriteRejected = true;
    }
    expect(dynamicWriteRejected, "shared-cache dynamic data accepted a guest write");

    constexpr auto fsgetpathNumber = UINT64_C(0x020001AB);
    constexpr rosa::guest::GuestAddress fsgetpathOutputPage{0x8000};
    constexpr rosa::guest::GuestAddress fsgetpathOutput{0x8100};
    addressSpace.mapAnonymous(fsgetpathOutputPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::darwin::SyscallDispatcher syscallDispatcher(&cache);
    rosa::x86::X86State fsgetpathState;
    fsgetpathState.rax = fsgetpathNumber;
    fsgetpathState.rdi = fsgetpathOutput.value;
    fsgetpathState.rsi = 0x400;
    fsgetpathState.rdx = dynamicAddress.value + 16;
    fsgetpathState.r10 = addressSpace.readU64(rosa::guest::GuestAddress{dynamicAddress.value + 24});
    fsgetpathState.rflags = 0xAD7;
    static_cast<void>(syscallDispatcher.dispatch(addressSpace, fsgetpathState,
                                                 rosa::guest::GuestAddress{0x7FF802AEEBC0ULL}));
    const auto expectedCachePath = std::filesystem::canonical(fixture.mainPath()).string();
    expectEqual(fsgetpathState.rax, expectedCachePath.size() + 1U,
                "cache fsgetpath returned the wrong length");
    expectEqual(fsgetpathState.rflags, std::uint64_t{0xAD6},
                "cache fsgetpath did not clear BSD carry");
    const auto resolvedCachePath =
        addressSpace.readBytes(fsgetpathOutput, expectedCachePath.size() + 1U);
    expectEqual(std::string(resolvedCachePath.begin(), resolvedCachePath.end() - 1),
                expectedCachePath, "cache fsgetpath returned the wrong path");
    expectEqual(resolvedCachePath.back(), std::uint8_t{0},
                "cache fsgetpath omitted its null terminator");

    rosa::x86::X86State provenanceState;
    provenanceState.rip = SharedCacheFixture::regionStart + 0x100;
    rosa::dbt::Dispatcher provenanceDispatcher(addressSpace, 1, nullptr, &cache);
    std::string provenanceReport;
    try {
        static_cast<void>(provenanceDispatcher.run(provenanceState, 20));
    } catch (const std::runtime_error &error) {
        provenanceReport = rosa::debug::dumpGuestFailure(
            "fallback", error, provenanceState, addressSpace, provenanceDispatcher, &cache);
    }
    expectEqual(provenanceDispatcher.cacheImageExecutions().size(), std::size_t{1},
                "dispatcher did not track first cache-image execution");
    expectEqual(provenanceDispatcher.cacheImageExecutions()[0].image->index, std::size_t{0},
                "dispatcher tracked the wrong cache image");
    expectEqual(provenanceDispatcher.cacheImageExecutions()[0].firstRip.value,
                SharedCacheFixture::regionStart + 0x100,
                "dispatcher tracked the wrong first image RIP");
    expect(provenanceReport.find("image=/usr/lib/dyld") != std::string::npos,
           "failure report omitted canonical cache-image provenance");
    expect(provenanceReport.find("cache image: index=0") != std::string::npos,
           "failure report omitted cache-image index");
    expect(provenanceReport.find("cache images executed") != std::string::npos,
           "failure report omitted cache-image execution history");
}

void testGuestSharedCacheRejectsMalformedFiles() {
    {
        SharedCacheFixture fixture;
        constexpr std::array<std::uint8_t, 16> armMagic{'d', 'y', 'l', 'd', '_', 'v', '1', ' ',
                                                        ' ', ' ', 'a', 'r', 'm', '6', '4', 'e'};
        fixture.overwrite(fixture.mainPath(), 0, armMagic);
        expectSharedCacheRejected(fixture.mainPath(), "not x86_64");
    }
    {
        SharedCacheFixture fixture;
        fixture.overwriteU32(fixture.mainPath(), 0x230, 0x2000);
        expectSharedCacheRejected(fixture.mainPath(), "mapping exceeds source file");
    }
    {
        SharedCacheFixture fixture;
        fixture.overwriteU32(fixture.mainPath(), 0x240, 1);
        fixture.overwriteU32(fixture.mainPath(), 0x244, 3);
        expectSharedCacheRejected(fixture.mainPath(), "initial permissions exceed maximum");
    }
    {
        SharedCacheFixture fixture;
        std::array<std::uint8_t, 16> wrongUuid{};
        fixture.overwrite(fixture.subcachePath(), 0x58, wrongUuid);
        expectSharedCacheRejected(fixture.mainPath(), "subcache UUID differs");
    }
    {
        SharedCacheFixture fixture;
        constexpr std::array<std::uint8_t, 4> unsafeSuffix{'/', 'b', 'a', 'd'};
        fixture.overwrite(fixture.mainPath(), 0x298, unsafeSuffix);
        expectSharedCacheRejected(fixture.mainPath(), "suffix is unsafe");
    }
    {
        SharedCacheFixture fixture;
        fixture.overwriteU32(fixture.mainPath(), 0x300, 3);
        expectSharedCacheRejected(fixture.mainPath(), "slide-info version 2");
    }
    {
        SharedCacheFixture fixture;
        fixture.overwriteU32(fixture.mainPath(), 0x30C, 2);
        expectSharedCacheRejected(fixture.mainPath(), "slide page geometry");
    }
    {
        SharedCacheFixture fixture;
        fixture.overwriteU64(fixture.mainPath(), 0x90, 3);
        expectSharedCacheRejected(fixture.mainPath(), "image tables have different counts");
    }
    {
        SharedCacheFixture fixture;
        fixture.overwriteU64(fixture.mainPath(), 0xD00, 0x200000);
        fixture.overwriteU64(fixture.mainPath(), 0xD50, 0x200000);
        expectSharedCacheRejected(fixture.mainPath(),
                                  "image text is not in one executable mapping");
    }
    {
        SharedCacheFixture fixture;
        fixture.overwriteU64(fixture.mainPath(), 0xD00, UINT64_MAX - 0x10);
        fixture.overwriteU64(fixture.mainPath(), 0xD50, UINT64_MAX - 0x10);
        expectSharedCacheRejected(fixture.mainPath(), "image text range is invalid");
    }
    {
        SharedCacheFixture fixture;
        fixture.overwriteU32(fixture.mainPath(), 0xD18, 0xFF0);
        fixture.overwriteU32(fixture.mainPath(), 0xD5C, 0xFF0);
        constexpr std::array<std::uint8_t, 16> unterminated{'n', 'o', '-', 't', 'e', 'r', 'm', 'i',
                                                            'n', 'a', 't', 'o', 'r', '!', '!', '!'};
        fixture.overwrite(fixture.mainPath(), 0xFF0, unterminated);
        expectSharedCacheRejected(fixture.mainPath(), "is not NUL-terminated");
    }
}

void testDarwinSharedRegionCheckWithCache() {
    constexpr auto callNumber = UINT64_C(0x02000126);
    constexpr rosa::guest::GuestAddress outputPage{0x8000};
    constexpr rosa::guest::GuestAddress output{0x8100};
    SharedCacheFixture fixture;
    const auto cache = rosa::darwin::GuestSharedCache::open(fixture.mainPath());
    rosa::guest::AddressSpace addressSpace;
    cache.mapInto(addressSpace);
    addressSpace.mapAnonymous(outputPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);

    rosa::darwin::SyscallDispatcher dispatcher(&cache);
    rosa::x86::X86State state;
    state.rax = callNumber;
    state.rdi = output.value;
    state.rflags = 0xAD7;
    const auto outcome =
        dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x7FF800064A40ULL});
    expect(!outcome.exited, "cache-backed shared-region check terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "cache-backed shared-region check did not succeed");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "cache-backed shared-region check did not clear BSD carry");
    expectEqual(addressSpace.readU64(output), cache.regionStart().value,
                "cache-backed shared-region check copied out the wrong base");

    state.rax = callNumber;
    state.rdi = 0xDEADBEEF;
    state.rflags = 0xAD6;
    static_cast<void>(dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
    expectEqual(state.rax, static_cast<std::uint64_t>(EFAULT),
                "invalid shared-region output pointer returned the wrong errno");
    expectEqual(state.rflags, std::uint64_t{0xAD7},
                "invalid shared-region output pointer did not set BSD carry");
}

void testGeneratedDarwinSharedRegionCheckWithCache() {
    constexpr rosa::guest::GuestAddress codeBase{0x3000};
    constexpr rosa::guest::GuestAddress outputPage{0x8000};
    constexpr rosa::guest::GuestAddress output{0x8100};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress sentinel{UINT64_MAX};
    constexpr std::array<std::uint8_t, 8> code{
        0xB8, 0x26, 0x01, 0x00, 0x02, // mov eax, 0x2000126
        0x0F, 0x05,                   // syscall
        0xC3,                         // ret
    };
    SharedCacheFixture fixture;
    const auto cache = rosa::darwin::GuestSharedCache::open(fixture.mainPath());
    rosa::guest::AddressSpace addressSpace;
    cache.mapInto(addressSpace);
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code);
    addressSpace.mapAnonymous(outputPage, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rdi = output.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize - sizeof(std::uint64_t);
    state.rflags = 0xAD7;
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, sentinel.value);
    rosa::dbt::Dispatcher dispatcher(addressSpace, 1, nullptr, &cache);
    const auto result = dispatcher.run(state, 8, sentinel);
    expect(!result.exited, "generated shared-region check terminated the guest");
    expectEqual(state.rax, std::uint64_t{0}, "generated shared-region check did not succeed");
    expectEqual(state.rflags, std::uint64_t{0xAD6},
                "generated shared-region check did not clear BSD carry");
    expectEqual(addressSpace.readU64(output), cache.regionStart().value,
                "generated shared-region check copied out the wrong base");
}

void testGuestFailureReport() {
    constexpr std::array<std::uint8_t, 12> code{
        0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x0B,
    };
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x8000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute, code,
                            "test-image:__TEXT");
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "test stack");
    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackBase.value + rosa::guest::guestPageSize;
    state.rflags = 0x202;
    rosa::dbt::Dispatcher dispatcher(addressSpace, 1);
    std::string report;
    try {
        static_cast<void>(dispatcher.run(state, 8));
    } catch (const rosa::x86::DecodeError &error) {
        report =
            rosa::debug::dumpGuestFailure("fallback-image", error, state, addressSpace, dispatcher);
    }
    expect(!report.empty(), "unsupported instruction did not produce a guest failure report");
    expect(report.find("image=test-image:__TEXT") != std::string::npos,
           "guest failure report omitted the current image");
    expect(report.find("RIP=0x100a") != std::string::npos, "guest failure report omitted RIP");
    expect(report.find("RSP=0x9000") != std::string::npos, "guest failure report omitted RSP");
    expect(report.find("RFLAGS=0x202") != std::string::npos, "guest failure report omitted RFLAGS");
    expect(report.find("RAX=0x2a") != std::string::npos,
           "guest failure report omitted general registers");
    expect(report.find("0f 0b") != std::string::npos,
           "guest failure report omitted failing instruction bytes");
    expect(report.find("mov rax, 0x2a") != std::string::npos,
           "guest failure report omitted recent decoded history");
    expect(report.find("test stack") != std::string::npos,
           "guest failure report omitted the stack mapping");
    expect(report.find("executed=1 translations=1") != std::string::npos,
           "guest failure report omitted execution counters");
}












} // namespace

std::span<const TestCase> sharedCacheTests() {
    static const TestCase cases[]{
        {"guest shared-cache parsing and mapping", testGuestSharedCacheParsingAndMapping},
        {"guest shared-cache malformed files", testGuestSharedCacheRejectsMalformedFiles},
        {"Darwin shared-region check with cache", testDarwinSharedRegionCheckWithCache},
        {"generated Darwin shared-region check with cache", testGeneratedDarwinSharedRegionCheckWithCache},
        {"guest failure report", testGuestFailureReport},
    };
    return cases;
}

} // namespace rosa::tests
