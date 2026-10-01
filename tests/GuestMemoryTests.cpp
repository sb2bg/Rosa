#include "TestSupport.h"
#include "TestSuite.h"

namespace rosa::tests {
namespace {

void testGuestAddressSpace() {
    constexpr rosa::guest::GuestAddress base{0x4000};
    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapAnonymous(base, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                              "test mapping");
    addressSpace.writeU64(rosa::guest::GuestAddress{0x4FF8}, 0x0123456789ABCDEFULL);
    expectEqual(addressSpace.readU64(rosa::guest::GuestAddress{0x4FF8}),
                std::uint64_t{0x0123456789ABCDEFULL}, "guest memory round trip differs");

    bool rejected = false;
    try {
        addressSpace.writeU64(rosa::guest::GuestAddress{0x4FFC}, 1);
    } catch (const std::runtime_error &) {
        rejected = true;
    }
    expect(rejected, "cross-mapping guest memory access was not rejected");
    const auto mappings = addressSpace.mappingInfos();
    expectEqual(mappings.size(), std::size_t{1}, "mapping summary count differs");
    expectEqual(mappings[0].base.value, base.value, "mapping summary base differs");
    expectEqual(mappings[0].size, rosa::guest::guestPageSize, "mapping summary size differs");
    expectEqual(mappings[0].label, std::string("test mapping"), "mapping summary label differs");
}

void testGuestFileBackedAddressSpace() {
    std::array<char, 38> pathTemplate{};
    constexpr std::string_view pathPattern = "/tmp/rosa-address-space-XXXXXX";
    std::copy(pathPattern.begin(), pathPattern.end(), pathTemplate.begin());
    const auto descriptor = ::mkstemp(pathTemplate.data());
    expect(descriptor >= 0, "could not create file-backed mapping fixture");

    constexpr auto sourceOffset = std::uint64_t{3};
    constexpr auto sourceValue = UINT64_C(0x0123456789ABCDEF);
    expect(::ftruncate(descriptor, static_cast<off_t>(rosa::guest::guestPageSize + sourceOffset)) ==
               0,
           "could not size file-backed mapping fixture");
    expect(::pwrite(descriptor, &sourceValue, sizeof(sourceValue),
                    static_cast<off_t>(sourceOffset)) == static_cast<ssize_t>(sizeof(sourceValue)),
           "could not populate file-backed mapping fixture");
    ::close(descriptor);

    constexpr rosa::guest::GuestAddress base{0x4000};
    rosa::guest::AddressSpace addressSpace;
    try {
        addressSpace.mapFileSegment(base, rosa::guest::guestPageSize,
                                    rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                                    rosa::guest::Permission::Read | rosa::guest::Permission::Write,
                                    pathTemplate.data(), sourceOffset, "private file mapping");
        expectEqual(addressSpace.readU64(base), sourceValue, "file-backed guest bytes differ");

        constexpr auto privateValue = UINT64_C(0xFEDCBA9876543210);
        addressSpace.writeU64(base, privateValue);
        expectEqual(addressSpace.readU64(base), privateValue,
                    "private file-backed guest write differs");

        const auto sourceDescriptor = ::open(pathTemplate.data(), O_RDONLY | O_CLOEXEC);
        expect(sourceDescriptor >= 0, "could not reopen file-backed mapping fixture");
        std::uint64_t unchangedSource = 0;
        const auto readCount = ::pread(sourceDescriptor, &unchangedSource, sizeof(unchangedSource),
                                       static_cast<off_t>(sourceOffset));
        ::close(sourceDescriptor);
        expectEqual(readCount, static_cast<ssize_t>(sizeof(unchangedSource)),
                    "could not reread file-backed mapping fixture");
        expectEqual(unchangedSource, sourceValue, "private guest mapping modified its source file");

        expect(
            addressSpace.protect(base, rosa::guest::guestPageSize, rosa::guest::Permission::Read) ==
                rosa::guest::ProtectResult::Success,
            "file-backed guest protection failed");
        bool writeRejected = false;
        try {
            addressSpace.writeU64(base, 0);
        } catch (const std::runtime_error &) {
            writeRejected = true;
        }
        expect(writeRejected, "read-only file-backed guest mapping accepted a write");
        expectEqual(addressSpace.readU64(base), privateValue,
                    "protecting a file-backed mapping discarded private bytes");
    } catch (...) {
        ::unlink(pathTemplate.data());
        throw;
    }
    ::unlink(pathTemplate.data());
}

} // namespace

std::span<const TestCase> guestMemoryTests() {
    static const TestCase cases[]{
        {"guest address space", testGuestAddressSpace},
        {"guest file-backed address space", testGuestFileBackedAddressSpace},
    };
    return cases;
}

} // namespace rosa::tests
