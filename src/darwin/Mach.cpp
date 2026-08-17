#include "darwin/Mach.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <type_traits>

#include <mach/mach.h>

namespace rosa::darwin {
namespace {

constexpr std::uint64_t kernSuccess = 0;
constexpr std::uint64_t kernInvalidAddress = 1;
constexpr std::uint64_t kernProtectionFailure = 2;
constexpr std::uint64_t kernNoSpace = 3;
constexpr std::uint64_t kernInvalidArgument = 4;
constexpr std::uint64_t kernInvalidName = 15;
constexpr std::uint64_t kernInvalidRight = 17;
constexpr std::uint64_t kernInvalidValue = 18;
constexpr std::uint64_t kernUrefsOverflow = 19;
constexpr std::uint64_t machSendInvalidDestination = 0x10000003U;
constexpr std::uint64_t vmProtectionMask = 0x7U;
constexpr std::uint64_t vmProtectionCopy = 0x10U;
constexpr std::uint64_t vmFlagsAnywhere = 0x1U;
constexpr std::uint64_t vmFlagsAliasMask = 0xFF000000U;
constexpr std::uint64_t minimumAnywhereAddress = 0x0000000100000000ULL;
constexpr std::uint64_t maximumUserMapEnd = 0x00007FFFFFFFF000ULL;
constexpr std::uint32_t machPortRightSend = 0;
constexpr std::uint32_t machPortRightCount = 6;
constexpr std::uint32_t machPortUrefsMaximum = 0xFFFF;
constexpr std::uint32_t machPortQlimitDefault = 5;
constexpr std::uint32_t mpoReplyPort = 0x1000;
constexpr std::uint32_t observedDyldPortOptions = mpoReplyPort;
constexpr std::uint64_t mach64SendMessage = 0x1U;
constexpr std::uint64_t mach64ReceiveMessage = 0x2U;
constexpr std::uint64_t mach64SendKobjectCall = 0x0000000200000000ULL;
constexpr std::uint64_t observedMachMessage2Options =
    mach64SendMessage | mach64ReceiveMessage | mach64SendKobjectCall;
constexpr std::uint32_t machMessageHeaderComplex = 0x80000000U;
constexpr std::uint32_t machMessageTypeCopySend = 19U;
constexpr std::uint32_t machMessageTypeMakeSendOnce = 21U;
constexpr std::uint32_t machMessageTypeMoveSendOnce = 18U;
constexpr std::uint32_t machMessagePortDescriptor = 0U;
constexpr std::int32_t machVmMapMessageId = 4811;
constexpr std::int32_t machVmMapReplyId = machVmMapMessageId + 100;
constexpr std::uint32_t machVmMapRequestSize = 100U;
constexpr std::uint32_t machVmMapReplySize = 44U;
constexpr std::uint32_t machMessageTrailerSize = 8U;
constexpr std::uint32_t machVmMapReceiveSize =
    machVmMapReplySize + machMessageTrailerSize;
constexpr std::int32_t hostInfoMessageId = 200;
constexpr std::int32_t hostInfoReplyId = hostInfoMessageId + 100;
constexpr std::uint32_t hostInfoRequestSize = 40U;
constexpr std::uint32_t hostInfoReplySize = 88U;
constexpr std::uint32_t hostInfoReceiveSize = 320U;
constexpr std::uint32_t hostBasicInfoFlavor = 1U;
constexpr std::uint32_t hostBasicInfoCount = 12U;
constexpr std::int32_t guestCpuTypeX86 = 7;
constexpr std::int32_t guestCpuSubtypeX86Arch1 = 4;

struct GuestMachPortOptions {
    std::uint32_t flags{};
    std::uint32_t queueLimit{};
    std::array<std::uint64_t, 2> specialFields{};
};

static_assert(sizeof(GuestMachPortOptions) == 24);

template <typename Integer>
Integer decodeGuestInteger(std::span<const std::uint8_t> bytes,
                           std::size_t offset) {
    if (offset > bytes.size() || sizeof(Integer) > bytes.size() - offset) {
        throw std::invalid_argument("guest integer lies outside its byte buffer");
    }
    using Unsigned = std::make_unsigned_t<Integer>;
    Unsigned value{};
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<Unsigned>(bytes[offset + index]) << (index * 8U);
    }
    if constexpr (std::is_signed_v<Integer>) {
        return std::bit_cast<Integer>(value);
    } else {
        return value;
    }
}

template <typename Integer>
void encodeGuestInteger(std::span<std::uint8_t> bytes, std::size_t offset,
                        Integer value) {
    if (offset > bytes.size() || sizeof(Integer) > bytes.size() - offset) {
        throw std::invalid_argument("guest integer lies outside its byte buffer");
    }
    using Unsigned = std::make_unsigned_t<Integer>;
    const auto encoded = [&] {
        if constexpr (std::is_signed_v<Integer>) {
            return std::bit_cast<Unsigned>(value);
        }
        return static_cast<Unsigned>(value);
    }();
    for (std::size_t index = 0; index < sizeof(encoded); ++index) {
        bytes[offset + index] =
            static_cast<std::uint8_t>(encoded >> (index * 8U));
    }
}

GuestMachPortOptions decodeGuestPortOptions(
    std::span<const std::uint8_t> bytes) {
    if (bytes.size() != sizeof(GuestMachPortOptions)) {
        throw std::invalid_argument("guest mach_port_options_t has the wrong size");
    }
    return GuestMachPortOptions{
        .flags = decodeGuestInteger<std::uint32_t>(bytes, 0),
        .queueLimit = decodeGuestInteger<std::uint32_t>(bytes, 4),
        .specialFields = {
            decodeGuestInteger<std::uint64_t>(bytes, 8),
            decodeGuestInteger<std::uint64_t>(bytes, 16),
        },
    };
}

std::array<std::uint8_t, sizeof(std::uint32_t)>
encodeGuestPortName(GuestMachPortName name) {
    std::array<std::uint8_t, sizeof(std::uint32_t)> bytes{};
    encodeGuestInteger<std::uint32_t>(bytes, 0, name.value);
    return bytes;
}

struct GuestMachVmMapRequest {
    std::uint64_t address{};
    std::uint64_t size{};
    std::uint64_t mask{};
    std::uint32_t flags{};
    std::uint64_t offset{};
    std::uint32_t copy{};
    std::uint32_t currentProtection{};
    std::uint32_t maximumProtection{};
    std::uint32_t inheritance{};
};

struct GuestHostBasicInfo {
    std::int32_t maximumCpus{};
    std::int32_t availableCpus{};
    std::uint32_t memorySize{};
    std::int32_t cpuType{};
    std::int32_t cpuSubtype{};
    std::int32_t cpuThreadType{};
    std::int32_t physicalCpus{};
    std::int32_t maximumPhysicalCpus{};
    std::int32_t logicalCpus{};
    std::int32_t maximumLogicalCpus{};
    std::uint64_t maximumMemory{};
};

static_assert(sizeof(GuestHostBasicInfo) == hostBasicInfoCount * sizeof(std::uint32_t));

std::optional<GuestMachPortName> decodeObservedHostInfoRequest(
    std::span<const std::uint8_t> message, const x86::X86State &state,
    std::uint64_t receiveSizeAndPriority, std::uint64_t timeout,
    const GuestPortSpace &portSpace) {
    constexpr std::array<std::uint8_t, 8> nativeNdr{
        0, 0, 0, 0, 1, 0, 0, 0};
    constexpr auto observedBits =
        machMessageTypeCopySend | (machMessageTypeMakeSendOnce << 8U);

    const auto remoteName = static_cast<std::uint32_t>(state.r10);
    const auto localName = static_cast<std::uint32_t>(state.r10 >> 32U);
    const auto receiveName = static_cast<std::uint32_t>(state.r9 >> 32U);
    const auto *hostPort = portSpace.lookup(GuestMachPortName{remoteName});
    const auto *replyPort = portSpace.lookup(GuestMachPortName{localName});
    if (state.rsi != observedMachMessage2Options ||
        static_cast<std::uint32_t>(state.rdx) != observedBits ||
        static_cast<std::uint32_t>(state.rdx >> 32U) !=
            hostInfoRequestSize ||
        localName != receiveName || static_cast<std::uint32_t>(state.r8) != 0 ||
        static_cast<std::int32_t>(state.r8 >> 32U) != hostInfoMessageId ||
        static_cast<std::uint32_t>(state.r9) != 0 ||
        static_cast<std::uint32_t>(receiveSizeAndPriority) !=
            hostInfoReceiveSize ||
        static_cast<std::uint32_t>(receiveSizeAndPriority >> 32U) != 0 ||
        timeout != 0 || message.size() != hostInfoRequestSize ||
        hostPort == nullptr || hostPort->type != GuestPortType::Host ||
        hostPort->sendUrefs == 0 || replyPort == nullptr ||
        replyPort->type != GuestPortType::Reply ||
        !replyPort->hasReceiveRight) {
        return std::nullopt;
    }

    if (decodeGuestInteger<std::uint32_t>(message, 0) != observedBits ||
        decodeGuestInteger<std::uint32_t>(message, 4) !=
            hostInfoRequestSize ||
        decodeGuestInteger<std::uint32_t>(message, 8) != remoteName ||
        decodeGuestInteger<std::uint32_t>(message, 12) != localName ||
        decodeGuestInteger<std::uint32_t>(message, 16) != 0 ||
        decodeGuestInteger<std::int32_t>(message, 20) != hostInfoMessageId ||
        !std::ranges::equal(message.subspan(24, nativeNdr.size()), nativeNdr) ||
        decodeGuestInteger<std::uint32_t>(message, 32) !=
            hostBasicInfoFlavor ||
        decodeGuestInteger<std::uint32_t>(message, 36) !=
            hostBasicInfoCount) {
        return std::nullopt;
    }
    return GuestMachPortName{receiveName};
}

GuestHostBasicInfo queryGuestHostBasicInfo() {
    host_basic_info_data_t native{};
    mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
    const auto host = mach_host_self();
    const auto result = host_info(host, HOST_BASIC_INFO,
                                  reinterpret_cast<host_info_t>(&native),
                                  &count);
    static_cast<void>(mach_port_deallocate(mach_task_self(), host));
    if (result != KERN_SUCCESS || count < HOST_BASIC_INFO_COUNT) {
        std::ostringstream stream;
        stream << "host_info(HOST_BASIC_INFO) failed for guest translation: "
               << result << " count=" << count;
        throw std::runtime_error(stream.str());
    }

    // Rosetta's x86_64 host_info view reports CPU_TYPE_X86 and
    // CPU_SUBTYPE_X86_ARCH1. The topology and memory fields are the current
    // machine's values, copied through a host-local structure.
    return GuestHostBasicInfo{
        .maximumCpus = native.max_cpus,
        .availableCpus = native.avail_cpus,
        .memorySize = native.memory_size,
        .cpuType = guestCpuTypeX86,
        .cpuSubtype = guestCpuSubtypeX86Arch1,
        .cpuThreadType = native.cpu_threadtype,
        .physicalCpus = native.physical_cpu,
        .maximumPhysicalCpus = native.physical_cpu_max,
        .logicalCpus = native.logical_cpu,
        .maximumLogicalCpus = native.logical_cpu_max,
        .maximumMemory = native.max_mem,
    };
}

std::array<std::uint8_t, hostInfoReplySize + machMessageTrailerSize>
encodeHostInfoReply(GuestMachPortName receiveName,
                    const GuestHostBasicInfo &info) {
    std::array<std::uint8_t,
               hostInfoReplySize + machMessageTrailerSize> reply{};
    encodeGuestInteger<std::uint32_t>(
        reply, 0, machMessageTypeMoveSendOnce << 8U);
    encodeGuestInteger<std::uint32_t>(reply, 4, hostInfoReplySize);
    encodeGuestInteger<std::uint32_t>(reply, 8, 0);
    encodeGuestInteger<std::uint32_t>(reply, 12, receiveName.value);
    encodeGuestInteger<std::uint32_t>(reply, 16, 0);
    encodeGuestInteger<std::int32_t>(reply, 20, hostInfoReplyId);
    constexpr std::array<std::uint8_t, 8> nativeNdr{
        0, 0, 0, 0, 1, 0, 0, 0};
    std::ranges::copy(nativeNdr, reply.begin() + 24);
    encodeGuestInteger<std::uint32_t>(reply, 32, kernSuccess);
    encodeGuestInteger<std::uint32_t>(reply, 36, hostBasicInfoCount);
    encodeGuestInteger<std::int32_t>(reply, 40, info.maximumCpus);
    encodeGuestInteger<std::int32_t>(reply, 44, info.availableCpus);
    encodeGuestInteger<std::uint32_t>(reply, 48, info.memorySize);
    encodeGuestInteger<std::int32_t>(reply, 52, info.cpuType);
    encodeGuestInteger<std::int32_t>(reply, 56, info.cpuSubtype);
    encodeGuestInteger<std::int32_t>(reply, 60, info.cpuThreadType);
    encodeGuestInteger<std::int32_t>(reply, 64, info.physicalCpus);
    encodeGuestInteger<std::int32_t>(reply, 68, info.maximumPhysicalCpus);
    encodeGuestInteger<std::int32_t>(reply, 72, info.logicalCpus);
    encodeGuestInteger<std::int32_t>(reply, 76, info.maximumLogicalCpus);
    encodeGuestInteger<std::uint64_t>(reply, 80, info.maximumMemory);
    encodeGuestInteger<std::uint32_t>(reply, 88, 0);
    encodeGuestInteger<std::uint32_t>(reply, 92, machMessageTrailerSize);
    return reply;
}

std::optional<GuestMachVmMapRequest> decodeObservedMachVmMapRequest(
    std::span<const std::uint8_t> message, const x86::X86State &state,
    std::uint64_t receiveSizeAndPriority, std::uint64_t timeout,
    const GuestPortSpace &portSpace) {
    constexpr std::array<std::uint8_t, 8> nativeNdr{
        0, 0, 0, 0, 1, 0, 0, 0};
    constexpr auto observedBits =
        machMessageHeaderComplex | machMessageTypeCopySend |
        (machMessageTypeMakeSendOnce << 8U);

    const auto remoteName = static_cast<std::uint32_t>(state.r10);
    const auto localName = static_cast<std::uint32_t>(state.r10 >> 32U);
    const auto receiveName = static_cast<std::uint32_t>(state.r9 >> 32U);
    const auto *taskPort =
        portSpace.lookup(GuestMachPortName{remoteName});
    const auto *replyPort =
        portSpace.lookup(GuestMachPortName{localName});
    if (state.rsi != observedMachMessage2Options ||
        static_cast<std::uint32_t>(state.rdx) != observedBits ||
        static_cast<std::uint32_t>(state.rdx >> 32U) !=
            machVmMapRequestSize ||
        remoteName != GuestPortSpace::taskSelfName.value ||
        localName != receiveName ||
        static_cast<std::uint32_t>(state.r8) != 0 ||
        static_cast<std::int32_t>(state.r8 >> 32U) != machVmMapMessageId ||
        static_cast<std::uint32_t>(state.r9) != 1 ||
        static_cast<std::uint32_t>(receiveSizeAndPriority) !=
            machVmMapReceiveSize ||
        static_cast<std::uint32_t>(receiveSizeAndPriority >> 32U) != 0 ||
        timeout != 0 || message.size() != machVmMapRequestSize ||
        taskPort == nullptr || taskPort->sendUrefs == 0 ||
        replyPort == nullptr || !replyPort->hasReceiveRight ||
        replyPort->type != GuestPortType::Reply) {
        return std::nullopt;
    }

    if (decodeGuestInteger<std::uint32_t>(message, 0) != observedBits ||
        decodeGuestInteger<std::uint32_t>(message, 4) !=
            machVmMapRequestSize ||
        decodeGuestInteger<std::uint32_t>(message, 8) != remoteName ||
        decodeGuestInteger<std::uint32_t>(message, 12) != localName ||
        decodeGuestInteger<std::uint32_t>(message, 16) != 0 ||
        decodeGuestInteger<std::int32_t>(message, 20) != machVmMapMessageId ||
        decodeGuestInteger<std::uint32_t>(message, 24) != 1 ||
        decodeGuestInteger<std::uint32_t>(message, 28) != 0 ||
        message[38] != machMessageTypeCopySend ||
        message[39] != machMessagePortDescriptor ||
        !std::ranges::equal(message.subspan(40, nativeNdr.size()), nativeNdr)) {
        return std::nullopt;
    }

    return GuestMachVmMapRequest{
        .address = decodeGuestInteger<std::uint64_t>(message, 48),
        .size = decodeGuestInteger<std::uint64_t>(message, 56),
        .mask = decodeGuestInteger<std::uint64_t>(message, 64),
        .flags = decodeGuestInteger<std::uint32_t>(message, 72),
        .offset = decodeGuestInteger<std::uint64_t>(message, 76),
        .copy = decodeGuestInteger<std::uint32_t>(message, 84),
        .currentProtection = decodeGuestInteger<std::uint32_t>(message, 88),
        .maximumProtection = decodeGuestInteger<std::uint32_t>(message, 92),
        .inheritance = decodeGuestInteger<std::uint32_t>(message, 96),
    };
}

std::array<std::uint8_t, machVmMapReceiveSize> encodeMachVmMapReply(
    GuestMachPortName receiveName, std::uint32_t result,
    std::uint64_t mappedAddress) {
    std::array<std::uint8_t, machVmMapReceiveSize> reply{};
    encodeGuestInteger<std::uint32_t>(
        reply, 0, machMessageTypeMoveSendOnce << 8U);
    encodeGuestInteger<std::uint32_t>(reply, 4, machVmMapReplySize);
    encodeGuestInteger<std::uint32_t>(reply, 8, 0);
    encodeGuestInteger<std::uint32_t>(reply, 12, receiveName.value);
    encodeGuestInteger<std::uint32_t>(reply, 16, 0);
    encodeGuestInteger<std::int32_t>(reply, 20, machVmMapReplyId);
    constexpr std::array<std::uint8_t, 8> nativeNdr{
        0, 0, 0, 0, 1, 0, 0, 0};
    std::ranges::copy(nativeNdr, reply.begin() + 24);
    encodeGuestInteger<std::uint32_t>(reply, 32, result);
    encodeGuestInteger<std::uint64_t>(reply, 36, mappedAddress);
    // A receive with no trailer options appends the format-0 trailer.
    encodeGuestInteger<std::uint32_t>(reply, 44, 0);
    encodeGuestInteger<std::uint32_t>(reply, 48, machMessageTrailerSize);
    return reply;
}

guest::Permission permissionsFromProtection(std::uint64_t protection) {
    auto permissions = guest::Permission::None;
    if ((protection & 0x1U) != 0) {
        permissions = permissions | guest::Permission::Read;
    }
    if ((protection & 0x2U) != 0) {
        permissions = permissions | guest::Permission::Write;
    }
    if ((protection & 0x4U) != 0) {
        permissions = permissions | guest::Permission::Execute;
    }
    return permissions;
}

std::optional<std::uint64_t> alignUp(std::uint64_t value,
                                     std::uint64_t mask) {
    if (value > std::numeric_limits<std::uint64_t>::max() - mask) {
        return std::nullopt;
    }
    return (value + mask) & ~mask;
}

std::optional<guest::GuestAddress>
findAnywhereRange(const guest::AddressSpace &addressSpace,
                  std::uint64_t hint, std::uint64_t size,
                  std::uint64_t alignmentMask) {
    const auto aligned =
        alignUp(std::max(hint, minimumAnywhereAddress), alignmentMask);
    if (!aligned) {
        return std::nullopt;
    }
    auto candidate = *aligned;
    auto mappings = addressSpace.mappingInfos();
    std::ranges::sort(mappings, {},
                      [](const guest::MappingInfo &mapping) {
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
        const auto next = alignUp(mappingEnd, alignmentMask);
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

std::runtime_error unsupported(const x86::X86State &state, guest::GuestAddress rip) {
    std::ostringstream stream;
    stream << "unsupported Darwin guest Mach trap\n"
           << "  number: 0x" << std::hex << state.rax << '\n'
           << "  trap: " << std::dec << MachDispatcher::trapNumber(state.rax) << '\n'
           << "  RIP: 0x" << std::hex << rip.value << '\n'
           << "  args: 0x" << state.rdi << " 0x" << state.rsi << " 0x" << state.rdx << " 0x"
           << state.r10 << " 0x" << state.r8 << " 0x" << state.r9;
    return std::runtime_error(stream.str());
}

std::runtime_error inspectUnsupportedMachMessage2(
    const guest::AddressSpace &addressSpace, const x86::X86State &state,
    guest::GuestAddress rip) {
    constexpr std::uint64_t maximumInspectedMessageSize = 64U * 1024U;
    const auto bits = static_cast<std::uint32_t>(state.rdx);
    const auto sendSize = static_cast<std::uint32_t>(state.rdx >> 32U);
    const auto remoteName = static_cast<std::uint32_t>(state.r10);
    const auto localName = static_cast<std::uint32_t>(state.r10 >> 32U);
    const auto voucherName = static_cast<std::uint32_t>(state.r8);
    const auto messageId = static_cast<std::int32_t>(state.r8 >> 32U);
    const auto descriptorCount = static_cast<std::uint32_t>(state.r9);
    const auto receiveName = static_cast<std::uint32_t>(state.r9 >> 32U);

    std::ostringstream stream;
    stream << "unsupported Darwin guest mach_msg2 trap\n"
           << "  RIP: 0x" << std::hex << rip.value << '\n'
           << "  data: 0x" << state.rdi << '\n'
           << "  options: 0x" << state.rsi << '\n'
           << "  bits: 0x" << bits << '\n'
           << "  send-size: " << std::dec << sendSize << '\n'
           << "  remote-name: 0x" << std::hex << remoteName << '\n'
           << "  local-name: 0x" << localName << '\n'
           << "  voucher-name: 0x" << voucherName << '\n'
           << "  message-id: " << std::dec << messageId << '\n'
           << "  descriptor-count: " << descriptorCount << '\n'
           << "  receive-name: 0x" << std::hex << receiveName << '\n';

    if (state.rsp > std::numeric_limits<std::uint64_t>::max() - 16U) {
        stream << "  stack-arguments: unavailable (RSP overflow)";
        return std::runtime_error(stream.str());
    }
    try {
        const auto receiveSizeAndPriority = addressSpace.readU64(
            guest::GuestAddress{state.rsp + 8U});
        const auto timeout = addressSpace.readU64(
            guest::GuestAddress{state.rsp + 16U});
        stream << "  receive-size: " << std::dec
               << static_cast<std::uint32_t>(receiveSizeAndPriority) << '\n'
               << "  priority: 0x" << std::hex
               << static_cast<std::uint32_t>(receiveSizeAndPriority >> 32U)
               << '\n'
               << "  timeout: " << std::dec << timeout << '\n';
    } catch (const std::runtime_error &error) {
        stream << "  stack-arguments: unavailable (" << error.what() << ")\n";
    }

    if (sendSize < 24U || sendSize > maximumInspectedMessageSize) {
        stream << "  message: not inspected (invalid diagnostic size)";
        return std::runtime_error(stream.str());
    }

    try {
        const auto message = addressSpace.readBytes(
            guest::GuestAddress{state.rdi}, sendSize);
        stream << "  header.bits: 0x" << std::hex
               << decodeGuestInteger<std::uint32_t>(message, 0) << '\n'
               << "  header.size: " << std::dec
               << decodeGuestInteger<std::uint32_t>(message, 4) << '\n'
               << "  header.remote: 0x" << std::hex
               << decodeGuestInteger<std::uint32_t>(message, 8) << '\n'
               << "  header.local: 0x"
               << decodeGuestInteger<std::uint32_t>(message, 12) << '\n'
               << "  header.voucher: 0x"
               << decodeGuestInteger<std::uint32_t>(message, 16) << '\n'
               << "  header.id: " << std::dec
               << decodeGuestInteger<std::int32_t>(message, 20) << '\n';
        if (message.size() >= 28U) {
            stream << "  body.descriptor-count: "
                   << decodeGuestInteger<std::uint32_t>(message, 24) << '\n';
        }
        if (descriptorCount != 0 && message.size() >= 40U) {
            stream << "  descriptor[0].name: 0x" << std::hex
                   << decodeGuestInteger<std::uint32_t>(message, 28) << '\n'
                   << "  descriptor[0].disposition: 0x"
                   << static_cast<unsigned>(message[38]) << '\n'
                   << "  descriptor[0].type: 0x"
                   << static_cast<unsigned>(message[39]) << '\n';
        }
        stream << "  message-bytes:";
        for (std::size_t offset = 0; offset < message.size(); ++offset) {
            if ((offset % 16U) == 0) {
                stream << "\n    " << std::hex << std::setw(4)
                       << std::setfill('0') << offset << ":";
            }
            stream << ' ' << std::setw(2) << std::setfill('0')
                   << static_cast<unsigned>(message[offset]);
        }
    } catch (const std::runtime_error &error) {
        stream << "  message: unavailable (" << error.what() << ')';
    }
    return std::runtime_error(stream.str());
}

} // namespace

bool MachDispatcher::ownsReceiveRight(GuestMachPortName name) const {
    return portSpace_.ownsReceiveRight(name);
}

std::string MachDispatcher::portSpaceSummary() const {
    std::ostringstream stream;
    stream << portSpace_.summary();
    if (lastPortConstruct_) {
        const auto &request = *lastPortConstruct_;
        stream << "\n    last construct: target=0x" << std::hex
               << request.target.value << " options*=0x"
               << request.optionsPointer.value << " flags=0x" << request.flags
               << std::dec << " qlimit-field=" << request.queueLimit
               << " special[0]=0x" << std::hex << request.specialFields[0]
               << " special[1]=0x" << request.specialFields[1]
               << " context=0x" << request.context << " output*=0x"
               << request.outputPointer.value << std::dec;
    }
    return stream.str();
}

void MachDispatcher::dispatch(guest::AddressSpace &addressSpace, x86::X86State &state,
                              guest::GuestAddress syscallRip) {
    if (!isMachTrap(state.rax)) {
        throw unsupported(state, syscallRip);
    }

    // XNU's x86_64 mach_call_munger64 writes only the trap result to saved RAX. In particular,
    // Mach traps do not use the BSD carry-flag error convention.
    switch (trapNumber(state.rax)) {
    case 12U: {
        // XNU trap 12 is _kernelrpc_mach_vm_deallocate_trap. The operation
        // removes the page-rounded address range from the target task's map;
        // ranges containing holes still succeed.
        if (state.rdi != taskSelfPortName().value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        switch (addressSpace.deallocate(guest::GuestAddress{state.rsi},
                                        state.rdx)) {
        case guest::DeallocateResult::Success:
            state.rax = kernSuccess;
            return;
        case guest::DeallocateResult::InvalidArgument:
            state.rax = kernInvalidArgument;
            return;
        }
        throw std::runtime_error("unreachable guest deallocation result");
    }
    case 14U: {
        // XNU trap 14 is _kernelrpc_mach_vm_protect_trap. Its five x86_64
        // arguments are target, address, size, set_maximum, and new_protection.
        if (state.rdi != taskSelfPortName().value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        if (state.r10 != 0) {
            throw unsupported(state, syscallRip);
        }
        if ((state.r8 & ~(vmProtectionMask | vmProtectionCopy)) != 0) {
            throw unsupported(state, syscallRip);
        }
        const auto permissions = permissionsFromProtection(state.r8);
        const auto makePrivateCopy = (state.r8 & vmProtectionCopy) != 0;
        switch (addressSpace.protect(guest::GuestAddress{state.rsi}, state.rdx,
                                     permissions, makePrivateCopy)) {
        case guest::ProtectResult::Success:
            state.rax = kernSuccess;
            return;
        case guest::ProtectResult::InvalidAddress:
            state.rax = kernInvalidAddress;
            return;
        case guest::ProtectResult::ProtectionFailure:
            state.rax = kernProtectionFailure;
            return;
        case guest::ProtectResult::InvalidArgument:
            state.rax = kernInvalidArgument;
            return;
        }
        throw std::runtime_error("unreachable guest protection result");
    }
    case 15U: {
        // XNU's _kernelrpc_mach_vm_map_trap is the six-argument anonymous
        // fast path used when object is null, maximum protection is ALL, and
        // inheritance is DEFAULT. The second argument points to an in/out
        // guest mach_vm_address_t.
        if (state.rdi != taskSelfPortName().value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        if ((state.r8 & ~vmFlagsAliasMask) != vmFlagsAnywhere ||
            state.r10 != guest::guestPageSize - 1U) {
            throw unsupported(state, syscallRip);
        }
        if ((state.r9 & ~vmProtectionMask) != 0 || state.rdx == 0 ||
            state.rdx > std::numeric_limits<std::size_t>::max() ||
            state.rdx > std::numeric_limits<std::uint64_t>::max() -
                            (guest::guestPageSize - 1U)) {
            state.rax = kernInvalidArgument;
            return;
        }
        std::uint64_t hint = 0;
        try {
            hint = addressSpace.readU64(guest::GuestAddress{state.rsi});
        } catch (const std::runtime_error &) {
            state.rax = kernInvalidAddress;
            return;
        }
        const auto roundedSize =
            (state.rdx + guest::guestPageSize - 1U) &
            ~(static_cast<std::uint64_t>(guest::guestPageSize) - 1U);
        const auto mappedAddress = findAnywhereRange(
            addressSpace, hint, roundedSize, state.r10);
        if (!mappedAddress) {
            state.rax = kernNoSpace;
            return;
        }
        const auto currentPermissions = permissionsFromProtection(state.r9);
        constexpr auto maximumPermissions =
            guest::Permission::Read | guest::Permission::Write |
            guest::Permission::Execute;
        addressSpace.mapAnonymous(
            *mappedAddress, static_cast<std::size_t>(roundedSize),
            currentPermissions, maximumPermissions,
            "mach_vm_map anonymous");
        try {
            addressSpace.writeU64(guest::GuestAddress{state.rsi},
                                  mappedAddress->value);
        } catch (const std::runtime_error &) {
            // XNU performs mach_copyout after creating the mapping; a failed
            // copyout returns KERN_INVALID_ADDRESS but does not undo it.
            state.rax = kernInvalidAddress;
            return;
        }
        state.rax = kernSuccess;
        return;
    }
    case 19U: {
        // XNU trap 19 is _kernelrpc_mach_port_mod_refs_trap. Model the
        // task-self send right currently exposed by Rosa's guest namespace.
        if (state.rdi != taskSelfPortName().value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        const auto right = static_cast<std::uint32_t>(state.rdx);
        if (right >= machPortRightCount) {
            state.rax = kernInvalidValue;
            return;
        }
        const auto name = static_cast<std::uint32_t>(state.rsi);
        auto *port = portSpace_.lookup(GuestMachPortName{name});
        if (port == nullptr || port->sendUrefs == 0) {
            state.rax = kernInvalidName;
            return;
        }
        if (right != machPortRightSend) {
            state.rax = kernInvalidRight;
            return;
        }
        const auto delta = std::bit_cast<std::int32_t>(
            static_cast<std::uint32_t>(state.r10));
        const auto updated = static_cast<std::int64_t>(port->sendUrefs) +
                             static_cast<std::int64_t>(delta);
        if (updated < 0) {
            state.rax = kernInvalidValue;
            return;
        }
        if (updated > machPortUrefsMaximum) {
            state.rax = kernUrefsOverflow;
            return;
        }
        port->sendUrefs = static_cast<std::uint32_t>(updated);
        state.rax = kernSuccess;
        return;
    }
    case 24U: {
        // XNU's x86_64 trap ABI is target, options pointer, 64-bit context,
        // and output-name pointer in RDI, RSI, RDX, and R10 respectively.
        // Decode the guest structure explicitly instead of aliasing a host ABI
        // type. The macOS 26.5 structure is 24 bytes.
        if (state.rdi != taskSelfPortName().value) {
            state.rax = machSendInvalidDestination;
            return;
        }

        GuestMachPortOptions options;
        try {
            const auto bytes = addressSpace.readBytes(
                guest::GuestAddress{state.rsi}, sizeof(GuestMachPortOptions));
            options = decodeGuestPortOptions(bytes);
        } catch (const std::runtime_error &) {
            state.rax = kernInvalidAddress;
            return;
        }
        lastPortConstruct_ = GuestPortConstructObservation{
            .target = GuestMachPortName{static_cast<std::uint32_t>(state.rdi)},
            .optionsPointer = guest::GuestAddress{state.rsi},
            .flags = options.flags,
            .queueLimit = options.queueLimit,
            .specialFields = options.specialFields,
            .context = state.rdx,
            .outputPointer = guest::GuestAddress{state.r10},
        };

        // This is the exact reply-port type requested by the cached macOS
        // 26.5 dyld. Other option combinations remain loud until their rights
        // and policy semantics have been observed and understood.
        if (options.flags != observedDyldPortOptions) {
            throw unsupported(state, syscallRip);
        }

        try {
            addressSpace.validateAccess(guest::GuestAddress{state.r10},
                                        sizeof(std::uint32_t),
                                        guest::Permission::Write);
        } catch (const std::runtime_error &) {
            state.rax = kernInvalidAddress;
            return;
        }

        GuestPort port;
        port.type = GuestPortType::Reply;
        port.context = state.rdx;
        port.queueLimit = machPortQlimitDefault;
        port.optionFlags = options.flags;
        const auto name = portSpace_.allocateReceiveRight(port);
        if (!name) {
            state.rax = kernNoSpace;
            return;
        }
        try {
            const auto encoded = encodeGuestPortName(*name);
            addressSpace.writeBytes(guest::GuestAddress{state.r10}, encoded);
        } catch (const std::runtime_error &) {
            // Rosa intentionally provides stronger fault atomicity than the
            // XNU trap wrapper: a failed guest copyout leaves no created right.
            portSpace_.rollbackLastAllocation(*name);
            state.rax = kernInvalidAddress;
            return;
        }
        state.rax = kernSuccess;
        return;
    }
    case 26U: {
        // mach_reply_port allocates a fresh receive right in the calling task on every call.
        GuestPort port;
        port.type = GuestPortType::Reply;
        port.queueLimit = machPortQlimitDefault;
        const auto name = portSpace_.allocateReceiveRight(port);
        if (!name) {
            state.rax = 0; // MACH_PORT_NULL models allocation exhaustion.
            return;
        }
        state.rax = name->value;
        return;
    }
    case 28U: {
        auto *taskSelf = portSpace_.lookup(taskSelfPortName());
        if (taskSelf == nullptr) {
            throw std::runtime_error("guest task-self port is absent from its namespace");
        }
        if (taskSelf->sendUrefs == machPortUrefsMaximum) {
            state.rax = 0;
            return;
        }
        ++taskSelf->sendUrefs;
        state.rax = taskSelfPortName().value;
        return;
    }
    case 29U: {
        // XNU host_self_trap has no arguments. It copies a send right for the
        // task's host object into the calling IPC space. Rosa keeps the
        // corresponding object and right entirely in its guest namespace.
        const auto name =
            portSpace_.copyoutHostSendRight(machPortUrefsMaximum);
        state.rax = name ? name->value : 0; // MACH_PORT_NULL on exhaustion.
        return;
    }
    case 47U: {
        // The first observed mach_msg2 call is the MIG mach_vm_map request
        // used by cached dyld to reserve its former standalone address range.
        // Keep this a narrow task-kobject path: there is no generic message
        // queue, host port forwarding, or fabricated IPC success here.
        if (state.rsp > std::numeric_limits<std::uint64_t>::max() - 16U) {
            throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                 syscallRip);
        }

        std::uint64_t receiveSizeAndPriority{};
        std::uint64_t timeout{};
        std::vector<std::uint8_t> message;
        try {
            receiveSizeAndPriority = addressSpace.readU64(
                guest::GuestAddress{state.rsp + 8U});
            timeout = addressSpace.readU64(
                guest::GuestAddress{state.rsp + 16U});
            const auto sendSize = static_cast<std::uint32_t>(state.rdx >> 32U);
            message = addressSpace.readBytes(
                guest::GuestAddress{state.rdi}, sendSize);
        } catch (const std::runtime_error &) {
            throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                 syscallRip);
        }

        if (const auto receiveName = decodeObservedHostInfoRequest(
                message, state, receiveSizeAndPriority, timeout, portSpace_)) {
            constexpr auto replySize =
                hostInfoReplySize + machMessageTrailerSize;
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdi}, replySize,
                    guest::Permission::Write);
            } catch (const std::runtime_error &) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto reply =
                encodeHostInfoReply(*receiveName, queryGuestHostBasicInfo());
            addressSpace.writeBytes(guest::GuestAddress{state.rdi}, reply);
            state.rax = kernSuccess;
            return;
        }

        const auto request = decodeObservedMachVmMapRequest(
            message, state, receiveSizeAndPriority, timeout, portSpace_);
        if (!request || request->size == 0 ||
            request->size > std::numeric_limits<std::size_t>::max() ||
            (request->address % guest::guestPageSize) != 0 ||
            (request->size % guest::guestPageSize) != 0 ||
            request->address >
                std::numeric_limits<std::uint64_t>::max() - request->size ||
            request->mask != guest::guestPageSize - 1U ||
            request->flags != 0 || request->offset != 0 ||
            request->copy != 0 || request->currentProtection != 0 ||
            request->maximumProtection != 0 || request->inheritance != 1) {
            throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                 syscallRip);
        }

        try {
            addressSpace.validateAccess(
                guest::GuestAddress{state.rdi}, machVmMapReceiveSize,
                guest::Permission::Write);
        } catch (const std::runtime_error &) {
            // The combined send/receive fault path would require queueing the
            // reply after a failed copyout. Keep it unsupported and atomic
            // until a real guest needs that behavior.
            throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                 syscallRip);
        }

        auto result = static_cast<std::uint32_t>(kernSuccess);
        bool mapped = false;
        try {
            addressSpace.mapAnonymous(
                guest::GuestAddress{request->address},
                static_cast<std::size_t>(request->size),
                guest::Permission::None, guest::Permission::None,
                "mach_vm_map fixed no-access reservation");
            mapped = true;
        } catch (const std::invalid_argument &) {
            result = static_cast<std::uint32_t>(kernNoSpace);
        }

        const auto receiveName = GuestMachPortName{
            static_cast<std::uint32_t>(state.r9 >> 32U)};
        const auto reply =
            encodeMachVmMapReply(receiveName, result, request->address);
        try {
            addressSpace.writeBytes(guest::GuestAddress{state.rdi}, reply);
        } catch (const std::runtime_error &) {
            if (mapped) {
                static_cast<void>(addressSpace.deallocate(
                    guest::GuestAddress{request->address}, request->size));
            }
            throw;
        }

        // mach_msg2 itself succeeded; the MIG operation result lives in the
        // reply body and is decoded by the guest's generated client stub.
        state.rax = kernSuccess;
        return;
    }
    default:
        throw unsupported(state, syscallRip);
    }
}

} // namespace rosa::darwin
