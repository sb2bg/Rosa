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
constexpr std::uint64_t kernResourceShortage = 6;
constexpr std::uint64_t machSendInvalidDestination = 0x10000003U;
constexpr std::uint64_t machMsgOptionSend = 0x1U;
constexpr std::uint64_t machReceiveInvalidName = 0x10004002U;
constexpr std::uint64_t machReceiveTimedOut = 0x10004003U;
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
constexpr std::uint32_t mpoContextAsGuard = 0x01;
constexpr std::uint32_t mpoQueueLimit = 0x02;
constexpr std::uint32_t mpoInsertSendRight = 0x10;
constexpr std::uint32_t mpoStrict = 0x20;
constexpr std::uint32_t mpoReplyPort = 0x1000;
constexpr std::uint64_t mach64SendMessage = 0x1U;
constexpr std::uint64_t mach64ReceiveMessage = 0x2U;
constexpr std::uint64_t mach64SendKobjectCall = 0x0000000200000000ULL;
constexpr std::uint64_t observedMachMessage2Options =
    mach64SendMessage | mach64ReceiveMessage | mach64SendKobjectCall;
constexpr std::uint32_t machMessageHeaderComplex = 0x80000000U;
constexpr std::uint32_t machMessageTypeCopySend = 19U;
constexpr std::uint32_t machMessageTypeMakeSendOnce = 21U;
constexpr std::uint32_t machMessageTypeMoveSend = 17U;
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
constexpr std::uint32_t hostPriorityInfoFlavor = 5U;
constexpr std::uint32_t hostPriorityInfoCount = 8U;
constexpr std::uint32_t hostPriorityInfoReplySize = 72U;
constexpr std::int32_t hostGetClockServiceMessageId = 206;
constexpr std::int32_t hostGetClockServiceReplyId =
    hostGetClockServiceMessageId + 100;
constexpr std::uint32_t hostGetClockServiceRequestSize = 36U;
constexpr std::uint32_t hostGetClockServiceReplySize = 40U;
constexpr std::uint32_t hostGetClockServiceReceiveSize =
    hostGetClockServiceReplySize + machMessageTrailerSize;
constexpr std::uint32_t systemClockId = 0U;
constexpr std::int32_t hostGetSpecialPortMessageId = 412;
constexpr std::int32_t hostGetSpecialPortReplyId =
    hostGetSpecialPortMessageId + 100;
constexpr std::uint32_t hostGetSpecialPortRequestSize = 40U;
constexpr std::uint32_t hostGetSpecialPortReplySize = 40U;
constexpr std::uint32_t hostGetSpecialPortReceiveSize =
    hostGetSpecialPortReplySize + machMessageTrailerSize;
constexpr std::int32_t hostLocalNode = -1;
constexpr std::uint32_t hostUnprivilegedPortSelector = 1U;
constexpr std::int32_t taskInfoMessageId = 3405;
constexpr std::int32_t taskInfoReplyId = taskInfoMessageId + 100;
constexpr std::uint32_t taskInfoRequestSize = 40U;
constexpr std::uint32_t taskInfoReceiveCapacity = 424U;
constexpr std::uint32_t taskInfoReplyBaseSize = 40U;
constexpr std::uint32_t taskAuditTokenFlavor = 15U;
constexpr std::uint32_t taskAuditTokenCount = 8U;
constexpr std::uint32_t taskAuditTokenReplySize =
    taskInfoReplyBaseSize + taskAuditTokenCount * sizeof(std::uint32_t);
constexpr std::uint32_t taskAuditTokenReceiveSize =
    taskAuditTokenReplySize + machMessageTrailerSize;
constexpr std::int32_t taskGetSpecialPortMessageId = 3409;
constexpr std::int32_t taskGetSpecialPortReplyId =
    taskGetSpecialPortMessageId + 100;
constexpr std::uint32_t taskGetSpecialPortRequestSize = 36U;
constexpr std::uint32_t taskGetSpecialPortReplySize = 40U;
constexpr std::uint32_t taskGetSpecialPortReceiveSize =
    taskGetSpecialPortReplySize + machMessageTrailerSize;
constexpr std::uint32_t taskBootstrapPortSelector = 4U;
constexpr std::int32_t taskSetSpecialPortMessageId = 3410;
constexpr std::int32_t taskSetSpecialPortReplyId =
    taskSetSpecialPortMessageId + 100;
constexpr std::uint32_t taskSetSpecialPortRequestSize = 52U;
constexpr std::uint32_t taskSetSpecialPortReplySize = 36U;
constexpr std::uint32_t taskSetSpecialPortReceiveSize =
    taskSetSpecialPortReplySize + machMessageTrailerSize;
constexpr std::uint32_t taskDebugControlPortSelector = 10U;
constexpr std::int32_t semaphoreCreateMessageId = 3418;
constexpr std::int32_t semaphoreCreateReplyId =
    semaphoreCreateMessageId + 100;
constexpr std::uint32_t semaphoreCreateRequestSize = 40U;
constexpr std::uint32_t semaphoreCreateReplySize = 40U;
constexpr std::uint32_t semaphoreCreateReceiveSize =
    semaphoreCreateReplySize + machMessageTrailerSize;
constexpr std::uint32_t syncPolicyFifo = 0U;
constexpr std::int32_t restartableRangesRegisterMessageId = 8000;
constexpr std::int32_t restartableRangesRegisterReplyId =
    restartableRangesRegisterMessageId + 100;
constexpr std::uint32_t restartableRangesRequestHeaderSize = 36U;
constexpr std::uint32_t restartableRangeSize = 16U;
constexpr std::uint32_t restartableRangesMaximumCount = 64U;
constexpr std::uint32_t restartableRangesReplySize = 36U;
constexpr std::uint32_t restartableRangesReceiveSize =
    restartableRangesReplySize + machMessageTrailerSize;
constexpr std::uint16_t restartableRangeOffsetMaximum = 4096U;
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

struct GuestHostPriorityInfo {
    std::int32_t kernelPriority{};
    std::int32_t systemPriority{};
    std::int32_t serverPriority{};
    std::int32_t userPriority{};
    std::int32_t depressPriority{};
    std::int32_t idlePriority{};
    std::int32_t minimumPriority{};
    std::int32_t maximumPriority{};
};

static_assert(sizeof(GuestHostBasicInfo) == hostBasicInfoCount * sizeof(std::uint32_t));
static_assert(sizeof(GuestHostPriorityInfo) ==
              hostPriorityInfoCount * sizeof(std::uint32_t));

std::optional<GuestMachPortName> decodeObservedHostInfoRequest(
    std::span<const std::uint8_t> message, const x86::X86State &state,
    std::uint64_t receiveSizeAndPriority, std::uint64_t timeout,
    const GuestPortSpace &portSpace, std::uint32_t expectedFlavor,
    std::uint32_t expectedCount) {
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
            expectedFlavor ||
        decodeGuestInteger<std::uint32_t>(message, 36) !=
            expectedCount) {
        return std::nullopt;
    }
    return GuestMachPortName{receiveName};
}

std::optional<GuestMachPortName> decodeObservedHostClockServiceRequest(
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
            hostGetClockServiceRequestSize ||
        localName != receiveName || static_cast<std::uint32_t>(state.r8) != 0 ||
        static_cast<std::int32_t>(state.r8 >> 32U) !=
            hostGetClockServiceMessageId ||
        static_cast<std::uint32_t>(state.r9) != 0 ||
        static_cast<std::uint32_t>(receiveSizeAndPriority) !=
            hostGetClockServiceReceiveSize ||
        static_cast<std::uint32_t>(receiveSizeAndPriority >> 32U) != 0 ||
        timeout != 0 || message.size() != hostGetClockServiceRequestSize ||
        hostPort == nullptr || hostPort->type != GuestPortType::Host ||
        hostPort->sendUrefs == 0 || replyPort == nullptr ||
        replyPort->type != GuestPortType::Reply ||
        !replyPort->hasReceiveRight) {
        return std::nullopt;
    }
    if (decodeGuestInteger<std::uint32_t>(message, 0) != observedBits ||
        decodeGuestInteger<std::uint32_t>(message, 4) !=
            hostGetClockServiceRequestSize ||
        decodeGuestInteger<std::uint32_t>(message, 8) != remoteName ||
        decodeGuestInteger<std::uint32_t>(message, 12) != localName ||
        decodeGuestInteger<std::uint32_t>(message, 16) != 0 ||
        decodeGuestInteger<std::int32_t>(message, 20) !=
            hostGetClockServiceMessageId ||
        !std::ranges::equal(message.subspan(24, nativeNdr.size()), nativeNdr) ||
        decodeGuestInteger<std::uint32_t>(message, 32) != systemClockId) {
        return std::nullopt;
    }
    return GuestMachPortName{receiveName};
}

std::optional<GuestMachPortName> decodeObservedHostGetSpecialPortRequest(
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
            hostGetSpecialPortRequestSize ||
        localName != receiveName || static_cast<std::uint32_t>(state.r8) != 0 ||
        static_cast<std::int32_t>(state.r8 >> 32U) !=
            hostGetSpecialPortMessageId ||
        static_cast<std::uint32_t>(state.r9) != 0 ||
        static_cast<std::uint32_t>(receiveSizeAndPriority) !=
            hostGetSpecialPortReceiveSize ||
        static_cast<std::uint32_t>(receiveSizeAndPriority >> 32U) != 0 ||
        timeout != 0 || message.size() != hostGetSpecialPortRequestSize ||
        hostPort == nullptr || hostPort->type != GuestPortType::Host ||
        hostPort->sendUrefs == 0 || replyPort == nullptr ||
        replyPort->type != GuestPortType::Reply ||
        !replyPort->hasReceiveRight) {
        return std::nullopt;
    }
    if (decodeGuestInteger<std::uint32_t>(message, 0) != observedBits ||
        decodeGuestInteger<std::uint32_t>(message, 4) !=
            hostGetSpecialPortRequestSize ||
        decodeGuestInteger<std::uint32_t>(message, 8) != remoteName ||
        decodeGuestInteger<std::uint32_t>(message, 12) != localName ||
        decodeGuestInteger<std::uint32_t>(message, 16) != 0 ||
        decodeGuestInteger<std::int32_t>(message, 20) !=
            hostGetSpecialPortMessageId ||
        !std::ranges::equal(message.subspan(24, nativeNdr.size()), nativeNdr) ||
        decodeGuestInteger<std::int32_t>(message, 32) != hostLocalNode ||
        decodeGuestInteger<std::uint32_t>(message, 36) !=
            hostUnprivilegedPortSelector) {
        return std::nullopt;
    }
    return GuestMachPortName{receiveName};
}

std::optional<GuestMachPortName> decodeObservedTaskGetSpecialPortRequest(
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
    const auto *taskPort = portSpace.lookup(GuestMachPortName{remoteName});
    const auto *replyPort = portSpace.lookup(GuestMachPortName{localName});
    if (state.rsi != observedMachMessage2Options ||
        static_cast<std::uint32_t>(state.rdx) != observedBits ||
        static_cast<std::uint32_t>(state.rdx >> 32U) !=
            taskGetSpecialPortRequestSize ||
        localName != receiveName || static_cast<std::uint32_t>(state.r8) != 0 ||
        static_cast<std::int32_t>(state.r8 >> 32U) !=
            taskGetSpecialPortMessageId ||
        static_cast<std::uint32_t>(state.r9) != 0 ||
        static_cast<std::uint32_t>(receiveSizeAndPriority) !=
            taskGetSpecialPortReceiveSize ||
        static_cast<std::uint32_t>(receiveSizeAndPriority >> 32U) != 0 ||
        timeout != 0 || message.size() != taskGetSpecialPortRequestSize ||
        remoteName != GuestPortSpace::taskSelfName.value ||
        taskPort == nullptr || taskPort->sendUrefs == 0 ||
        replyPort == nullptr || replyPort->type != GuestPortType::Reply ||
        !replyPort->hasReceiveRight) {
        return std::nullopt;
    }
    if (decodeGuestInteger<std::uint32_t>(message, 0) != observedBits ||
        decodeGuestInteger<std::uint32_t>(message, 4) !=
            taskGetSpecialPortRequestSize ||
        decodeGuestInteger<std::uint32_t>(message, 8) != remoteName ||
        decodeGuestInteger<std::uint32_t>(message, 12) != localName ||
        decodeGuestInteger<std::uint32_t>(message, 16) != 0 ||
        decodeGuestInteger<std::int32_t>(message, 20) !=
            taskGetSpecialPortMessageId ||
        !std::ranges::equal(message.subspan(24, nativeNdr.size()), nativeNdr) ||
        decodeGuestInteger<std::uint32_t>(message, 32) !=
            taskBootstrapPortSelector) {
        return std::nullopt;
    }
    return GuestMachPortName{receiveName};
}

std::optional<GuestMachPortName> decodeObservedTaskAuditTokenRequest(
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
    const auto *taskPort = portSpace.lookup(GuestMachPortName{remoteName});
    const auto *replyPort = portSpace.lookup(GuestMachPortName{localName});
    if (state.rsi != observedMachMessage2Options ||
        static_cast<std::uint32_t>(state.rdx) != observedBits ||
        static_cast<std::uint32_t>(state.rdx >> 32U) !=
            taskInfoRequestSize ||
        localName != receiveName || static_cast<std::uint32_t>(state.r8) != 0 ||
        static_cast<std::int32_t>(state.r8 >> 32U) != taskInfoMessageId ||
        static_cast<std::uint32_t>(state.r9) != 0 ||
        static_cast<std::uint32_t>(receiveSizeAndPriority) !=
            taskInfoReceiveCapacity ||
        static_cast<std::uint32_t>(receiveSizeAndPriority >> 32U) != 0 ||
        timeout != 0 || message.size() != taskInfoRequestSize ||
        remoteName != GuestPortSpace::taskSelfName.value ||
        taskPort == nullptr || taskPort->sendUrefs == 0 ||
        replyPort == nullptr || replyPort->type != GuestPortType::Reply ||
        !replyPort->hasReceiveRight) {
        return std::nullopt;
    }
    if (decodeGuestInteger<std::uint32_t>(message, 0) != observedBits ||
        decodeGuestInteger<std::uint32_t>(message, 4) !=
            taskInfoRequestSize ||
        decodeGuestInteger<std::uint32_t>(message, 8) != remoteName ||
        decodeGuestInteger<std::uint32_t>(message, 12) != localName ||
        decodeGuestInteger<std::uint32_t>(message, 16) != 0 ||
        decodeGuestInteger<std::int32_t>(message, 20) != taskInfoMessageId ||
        !std::ranges::equal(message.subspan(24, nativeNdr.size()), nativeNdr) ||
        decodeGuestInteger<std::uint32_t>(message, 32) !=
            taskAuditTokenFlavor ||
        decodeGuestInteger<std::uint32_t>(message, 36) !=
            taskAuditTokenCount) {
        return std::nullopt;
    }
    return GuestMachPortName{receiveName};
}

struct GuestTaskSetSpecialPortRequest {
    GuestMachPortName receiveName;
    GuestMachPortName specialPortName;
};

std::optional<GuestTaskSetSpecialPortRequest>
decodeObservedTaskSetSpecialPortRequest(
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
    const auto *taskPort = portSpace.lookup(GuestMachPortName{remoteName});
    const auto *replyPort = portSpace.lookup(GuestMachPortName{localName});
    if (state.rsi != observedMachMessage2Options ||
        static_cast<std::uint32_t>(state.rdx) != observedBits ||
        static_cast<std::uint32_t>(state.rdx >> 32U) !=
            taskSetSpecialPortRequestSize ||
        localName != receiveName || static_cast<std::uint32_t>(state.r8) != 0 ||
        static_cast<std::int32_t>(state.r8 >> 32U) !=
            taskSetSpecialPortMessageId ||
        static_cast<std::uint32_t>(state.r9) != 1 ||
        static_cast<std::uint32_t>(receiveSizeAndPriority) !=
            taskSetSpecialPortReceiveSize ||
        static_cast<std::uint32_t>(receiveSizeAndPriority >> 32U) != 0 ||
        timeout != 0 || message.size() != taskSetSpecialPortRequestSize ||
        remoteName != GuestPortSpace::taskSelfName.value ||
        taskPort == nullptr || taskPort->sendUrefs == 0 ||
        replyPort == nullptr || replyPort->type != GuestPortType::Reply ||
        !replyPort->hasReceiveRight) {
        return std::nullopt;
    }
    const auto specialPortName =
        decodeGuestInteger<std::uint32_t>(message, 28);
    const auto *specialPort =
        portSpace.lookup(GuestMachPortName{specialPortName});
    if (decodeGuestInteger<std::uint32_t>(message, 0) != observedBits ||
        decodeGuestInteger<std::uint32_t>(message, 4) !=
            taskSetSpecialPortRequestSize ||
        decodeGuestInteger<std::uint32_t>(message, 8) != remoteName ||
        decodeGuestInteger<std::uint32_t>(message, 12) != localName ||
        decodeGuestInteger<std::uint32_t>(message, 16) != 0 ||
        decodeGuestInteger<std::int32_t>(message, 20) !=
            taskSetSpecialPortMessageId ||
        decodeGuestInteger<std::uint32_t>(message, 24) != 1 ||
        specialPort == nullptr || specialPort->sendUrefs == 0 ||
        message[38] != machMessageTypeCopySend ||
        message[39] != machMessagePortDescriptor ||
        !std::ranges::equal(message.subspan(40, nativeNdr.size()), nativeNdr) ||
        decodeGuestInteger<std::uint32_t>(message, 48) !=
            taskDebugControlPortSelector) {
        return std::nullopt;
    }
    return GuestTaskSetSpecialPortRequest{
        .receiveName = GuestMachPortName{receiveName},
        .specialPortName = GuestMachPortName{specialPortName},
    };
}

std::optional<GuestMachPortName> decodeObservedSemaphoreCreateRequest(
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
    const auto *taskPort = portSpace.lookup(GuestMachPortName{remoteName});
    const auto *replyPort = portSpace.lookup(GuestMachPortName{localName});
    if (state.rsi != observedMachMessage2Options ||
        static_cast<std::uint32_t>(state.rdx) != observedBits ||
        static_cast<std::uint32_t>(state.rdx >> 32U) !=
            semaphoreCreateRequestSize ||
        localName != receiveName || static_cast<std::uint32_t>(state.r8) != 0 ||
        static_cast<std::int32_t>(state.r8 >> 32U) !=
            semaphoreCreateMessageId ||
        static_cast<std::uint32_t>(state.r9) != 0 ||
        static_cast<std::uint32_t>(receiveSizeAndPriority) !=
            semaphoreCreateReceiveSize ||
        static_cast<std::uint32_t>(receiveSizeAndPriority >> 32U) != 0 ||
        timeout != 0 || message.size() != semaphoreCreateRequestSize ||
        remoteName != GuestPortSpace::taskSelfName.value ||
        taskPort == nullptr || taskPort->sendUrefs == 0 ||
        replyPort == nullptr || replyPort->type != GuestPortType::Reply ||
        !replyPort->hasReceiveRight) {
        return std::nullopt;
    }
    if (decodeGuestInteger<std::uint32_t>(message, 0) != observedBits ||
        decodeGuestInteger<std::uint32_t>(message, 4) !=
            semaphoreCreateRequestSize ||
        decodeGuestInteger<std::uint32_t>(message, 8) != remoteName ||
        decodeGuestInteger<std::uint32_t>(message, 12) != localName ||
        decodeGuestInteger<std::uint32_t>(message, 16) != 0 ||
        decodeGuestInteger<std::int32_t>(message, 20) !=
            semaphoreCreateMessageId ||
        !std::ranges::equal(message.subspan(24, nativeNdr.size()), nativeNdr) ||
        decodeGuestInteger<std::uint32_t>(message, 32) != syncPolicyFifo ||
        decodeGuestInteger<std::int32_t>(message, 36) != 0) {
        return std::nullopt;
    }
    return GuestMachPortName{receiveName};
}

struct GuestRestartableRange {
    std::uint64_t location{};
    std::uint16_t length{};
    std::uint16_t recoveryOffset{};
    std::uint32_t flags{};
};

std::optional<GuestMachPortName>
decodeObservedRestartableRangesRegisterRequest(
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
    const auto *taskPort = portSpace.lookup(GuestMachPortName{remoteName});
    const auto *replyPort = portSpace.lookup(GuestMachPortName{localName});
    if (message.size() < restartableRangesRequestHeaderSize ||
        state.rsi != observedMachMessage2Options ||
        static_cast<std::uint32_t>(state.rdx) != observedBits ||
        static_cast<std::uint32_t>(state.rdx >> 32U) != message.size() ||
        localName != receiveName || static_cast<std::uint32_t>(state.r8) != 0 ||
        static_cast<std::int32_t>(state.r8 >> 32U) !=
            restartableRangesRegisterMessageId ||
        static_cast<std::uint32_t>(state.r9) != 0 ||
        static_cast<std::uint32_t>(receiveSizeAndPriority) !=
            restartableRangesReceiveSize ||
        static_cast<std::uint32_t>(receiveSizeAndPriority >> 32U) != 0 ||
        timeout != 0 || remoteName != GuestPortSpace::taskSelfName.value ||
        taskPort == nullptr || taskPort->sendUrefs == 0 ||
        replyPort == nullptr || replyPort->type != GuestPortType::Reply ||
        !replyPort->hasReceiveRight) {
        return std::nullopt;
    }
    if (decodeGuestInteger<std::uint32_t>(message, 0) != observedBits ||
        decodeGuestInteger<std::uint32_t>(message, 4) != message.size() ||
        decodeGuestInteger<std::uint32_t>(message, 8) != remoteName ||
        decodeGuestInteger<std::uint32_t>(message, 12) != localName ||
        decodeGuestInteger<std::uint32_t>(message, 16) != 0 ||
        decodeGuestInteger<std::int32_t>(message, 20) !=
            restartableRangesRegisterMessageId ||
        !std::ranges::equal(message.subspan(24, nativeNdr.size()), nativeNdr)) {
        return std::nullopt;
    }
    const auto count = decodeGuestInteger<std::uint32_t>(message, 32);
    if (count == 0 || count > restartableRangesMaximumCount ||
        message.size() != restartableRangesRequestHeaderSize +
                              static_cast<std::size_t>(count) *
                                  restartableRangeSize) {
        return std::nullopt;
    }
    std::vector<GuestRestartableRange> ranges;
    ranges.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto offset = restartableRangesRequestHeaderSize +
                            static_cast<std::size_t>(index) *
                                restartableRangeSize;
        ranges.push_back(GuestRestartableRange{
            .location = decodeGuestInteger<std::uint64_t>(message, offset),
            .length = decodeGuestInteger<std::uint16_t>(message, offset + 8U),
            .recoveryOffset =
                decodeGuestInteger<std::uint16_t>(message, offset + 10U),
            .flags = decodeGuestInteger<std::uint32_t>(message, offset + 12U),
        });
    }
    std::ranges::sort(ranges, {}, &GuestRestartableRange::location);
    for (std::size_t index = 0; index < ranges.size(); ++index) {
        const auto &range = ranges[index];
        if (range.length > restartableRangeOffsetMaximum ||
            range.recoveryOffset > restartableRangeOffsetMaximum ||
            range.flags != 0 ||
            range.location >
                std::numeric_limits<std::uint64_t>::max() - range.length ||
            range.location > std::numeric_limits<std::uint64_t>::max() -
                                 range.recoveryOffset ||
            (index + 1U < ranges.size() &&
             range.location + range.length > ranges[index + 1U].location)) {
            return std::nullopt;
        }
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

GuestHostPriorityInfo queryGuestHostPriorityInfo() {
    host_priority_info_data_t native{};
    mach_msg_type_number_t count = HOST_PRIORITY_INFO_COUNT;
    const auto host = mach_host_self();
    const auto result = host_info(host, HOST_PRIORITY_INFO,
                                  reinterpret_cast<host_info_t>(&native),
                                  &count);
    static_cast<void>(mach_port_deallocate(mach_task_self(), host));
    if (result != KERN_SUCCESS || count < HOST_PRIORITY_INFO_COUNT) {
        std::ostringstream stream;
        stream << "host_info(HOST_PRIORITY_INFO) failed for guest translation: "
               << result << " count=" << count;
        throw std::runtime_error(stream.str());
    }
    return GuestHostPriorityInfo{
        .kernelPriority = native.kernel_priority,
        .systemPriority = native.system_priority,
        .serverPriority = native.server_priority,
        .userPriority = native.user_priority,
        .depressPriority = native.depress_priority,
        .idlePriority = native.idle_priority,
        .minimumPriority = native.minimum_priority,
        .maximumPriority = native.maximum_priority,
    };
}

std::array<std::uint32_t, taskAuditTokenCount>
queryGuestTaskAuditToken() {
    audit_token_t native{};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    const auto result = task_info(
        mach_task_self(), TASK_AUDIT_TOKEN,
        reinterpret_cast<task_info_t>(&native), &count);
    if (result != KERN_SUCCESS || count != taskAuditTokenCount) {
        std::ostringstream stream;
        stream << "task_info(TASK_AUDIT_TOKEN) failed for guest translation: "
               << result << " count=" << count;
        throw std::runtime_error(stream.str());
    }
    std::array<std::uint32_t, taskAuditTokenCount> token{};
    std::ranges::copy(native.val, token.begin());
    return token;
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

std::array<std::uint8_t,
           hostPriorityInfoReplySize + machMessageTrailerSize>
encodeHostPriorityInfoReply(GuestMachPortName receiveName,
                            const GuestHostPriorityInfo &info) {
    std::array<std::uint8_t,
               hostPriorityInfoReplySize + machMessageTrailerSize> reply{};
    encodeGuestInteger<std::uint32_t>(
        reply, 0, machMessageTypeMoveSendOnce << 8U);
    encodeGuestInteger<std::uint32_t>(reply, 4,
                                      hostPriorityInfoReplySize);
    encodeGuestInteger<std::uint32_t>(reply, 8, 0);
    encodeGuestInteger<std::uint32_t>(reply, 12, receiveName.value);
    encodeGuestInteger<std::uint32_t>(reply, 16, 0);
    encodeGuestInteger<std::int32_t>(reply, 20, hostInfoReplyId);
    constexpr std::array<std::uint8_t, 8> nativeNdr{
        0, 0, 0, 0, 1, 0, 0, 0};
    std::ranges::copy(nativeNdr, reply.begin() + 24);
    encodeGuestInteger<std::uint32_t>(reply, 32, kernSuccess);
    encodeGuestInteger<std::uint32_t>(reply, 36, hostPriorityInfoCount);
    encodeGuestInteger<std::int32_t>(reply, 40, info.kernelPriority);
    encodeGuestInteger<std::int32_t>(reply, 44, info.systemPriority);
    encodeGuestInteger<std::int32_t>(reply, 48, info.serverPriority);
    encodeGuestInteger<std::int32_t>(reply, 52, info.userPriority);
    encodeGuestInteger<std::int32_t>(reply, 56, info.depressPriority);
    encodeGuestInteger<std::int32_t>(reply, 60, info.idlePriority);
    encodeGuestInteger<std::int32_t>(reply, 64, info.minimumPriority);
    encodeGuestInteger<std::int32_t>(reply, 68, info.maximumPriority);
    encodeGuestInteger<std::uint32_t>(reply, 72, 0);
    encodeGuestInteger<std::uint32_t>(reply, 76,
                                      machMessageTrailerSize);
    return reply;
}

std::array<std::uint8_t, hostGetClockServiceReceiveSize>
encodeHostClockServiceReply(GuestMachPortName receiveName,
                            GuestMachPortName clockServiceName) {
    std::array<std::uint8_t, hostGetClockServiceReceiveSize> reply{};
    encodeGuestInteger<std::uint32_t>(
        reply, 0, machMessageHeaderComplex |
                      (machMessageTypeMoveSendOnce << 8U));
    encodeGuestInteger<std::uint32_t>(reply, 4,
                                      hostGetClockServiceReplySize);
    encodeGuestInteger<std::uint32_t>(reply, 8, 0);
    encodeGuestInteger<std::uint32_t>(reply, 12, receiveName.value);
    encodeGuestInteger<std::uint32_t>(reply, 16, 0);
    encodeGuestInteger<std::int32_t>(reply, 20,
                                     hostGetClockServiceReplyId);
    encodeGuestInteger<std::uint32_t>(reply, 24, 1);
    encodeGuestInteger<std::uint32_t>(reply, 28,
                                      clockServiceName.value);
    reply[38] = machMessageTypeMoveSend;
    reply[39] = machMessagePortDescriptor;
    encodeGuestInteger<std::uint32_t>(reply, 40, 0);
    encodeGuestInteger<std::uint32_t>(reply, 44,
                                      machMessageTrailerSize);
    return reply;
}

std::array<std::uint8_t, hostGetSpecialPortReceiveSize>
encodeHostGetSpecialPortReply(GuestMachPortName receiveName,
                              GuestMachPortName hostName) {
    std::array<std::uint8_t, hostGetSpecialPortReceiveSize> reply{};
    encodeGuestInteger<std::uint32_t>(
        reply, 0, machMessageHeaderComplex |
                      (machMessageTypeMoveSendOnce << 8U));
    encodeGuestInteger<std::uint32_t>(reply, 4,
                                      hostGetSpecialPortReplySize);
    encodeGuestInteger<std::uint32_t>(reply, 8, 0);
    encodeGuestInteger<std::uint32_t>(reply, 12, receiveName.value);
    encodeGuestInteger<std::uint32_t>(reply, 16, 0);
    encodeGuestInteger<std::int32_t>(reply, 20,
                                     hostGetSpecialPortReplyId);
    encodeGuestInteger<std::uint32_t>(reply, 24, 1);
    encodeGuestInteger<std::uint32_t>(reply, 28, hostName.value);
    reply[38] = machMessageTypeMoveSend;
    reply[39] = machMessagePortDescriptor;
    encodeGuestInteger<std::uint32_t>(reply, 40, 0);
    encodeGuestInteger<std::uint32_t>(reply, 44,
                                      machMessageTrailerSize);
    return reply;
}

std::array<std::uint8_t, taskGetSpecialPortReceiveSize>
encodeTaskGetSpecialPortReply(GuestMachPortName receiveName,
                              GuestMachPortName specialPortName) {
    std::array<std::uint8_t, taskGetSpecialPortReceiveSize> reply{};
    encodeGuestInteger<std::uint32_t>(
        reply, 0, machMessageHeaderComplex |
                      (machMessageTypeMoveSendOnce << 8U));
    encodeGuestInteger<std::uint32_t>(reply, 4,
                                      taskGetSpecialPortReplySize);
    encodeGuestInteger<std::uint32_t>(reply, 8, 0);
    encodeGuestInteger<std::uint32_t>(reply, 12, receiveName.value);
    encodeGuestInteger<std::uint32_t>(reply, 16, 0);
    encodeGuestInteger<std::int32_t>(reply, 20,
                                     taskGetSpecialPortReplyId);
    encodeGuestInteger<std::uint32_t>(reply, 24, 1);
    encodeGuestInteger<std::uint32_t>(reply, 28, specialPortName.value);
    reply[38] = machMessageTypeMoveSend;
    reply[39] = machMessagePortDescriptor;
    encodeGuestInteger<std::uint32_t>(reply, 40, 0);
    encodeGuestInteger<std::uint32_t>(reply, 44,
                                      machMessageTrailerSize);
    return reply;
}

std::array<std::uint8_t, taskAuditTokenReceiveSize>
encodeTaskAuditTokenReply(
    GuestMachPortName receiveName,
    const std::array<std::uint32_t, taskAuditTokenCount> &token) {
    constexpr std::array<std::uint8_t, 8> nativeNdr{
        0, 0, 0, 0, 1, 0, 0, 0};
    std::array<std::uint8_t, taskAuditTokenReceiveSize> reply{};
    encodeGuestInteger<std::uint32_t>(
        reply, 0, machMessageTypeMoveSendOnce << 8U);
    encodeGuestInteger<std::uint32_t>(reply, 4,
                                      taskAuditTokenReplySize);
    encodeGuestInteger<std::uint32_t>(reply, 8, 0);
    encodeGuestInteger<std::uint32_t>(reply, 12, receiveName.value);
    encodeGuestInteger<std::uint32_t>(reply, 16, 0);
    encodeGuestInteger<std::int32_t>(reply, 20, taskInfoReplyId);
    std::ranges::copy(nativeNdr, reply.begin() + 24);
    encodeGuestInteger<std::uint32_t>(reply, 32,
                                      static_cast<std::uint32_t>(kernSuccess));
    encodeGuestInteger<std::uint32_t>(reply, 36,
                                      taskAuditTokenCount);
    for (std::size_t index = 0; index < token.size(); ++index) {
        encodeGuestInteger<std::uint32_t>(reply, 40 + index * 4U,
                                          token[index]);
    }
    encodeGuestInteger<std::uint32_t>(reply, taskAuditTokenReplySize, 0);
    encodeGuestInteger<std::uint32_t>(
        reply, taskAuditTokenReplySize + sizeof(std::uint32_t),
        machMessageTrailerSize);
    return reply;
}

std::array<std::uint8_t, taskSetSpecialPortReceiveSize>
encodeTaskSetSpecialPortReply(GuestMachPortName receiveName) {
    constexpr std::array<std::uint8_t, 8> nativeNdr{
        0, 0, 0, 0, 1, 0, 0, 0};
    std::array<std::uint8_t, taskSetSpecialPortReceiveSize> reply{};
    encodeGuestInteger<std::uint32_t>(
        reply, 0, machMessageTypeMoveSendOnce << 8U);
    encodeGuestInteger<std::uint32_t>(reply, 4,
                                      taskSetSpecialPortReplySize);
    encodeGuestInteger<std::uint32_t>(reply, 8, 0);
    encodeGuestInteger<std::uint32_t>(reply, 12, receiveName.value);
    encodeGuestInteger<std::uint32_t>(reply, 16, 0);
    encodeGuestInteger<std::int32_t>(reply, 20,
                                     taskSetSpecialPortReplyId);
    std::ranges::copy(nativeNdr, reply.begin() + 24);
    encodeGuestInteger<std::uint32_t>(reply, 32,
                                      static_cast<std::uint32_t>(kernSuccess));
    encodeGuestInteger<std::uint32_t>(reply, 36, 0);
    encodeGuestInteger<std::uint32_t>(reply, 40,
                                      machMessageTrailerSize);
    return reply;
}

std::array<std::uint8_t, semaphoreCreateReceiveSize>
encodeSemaphoreCreateReply(GuestMachPortName receiveName,
                           GuestMachPortName semaphoreName) {
    std::array<std::uint8_t, semaphoreCreateReceiveSize> reply{};
    encodeGuestInteger<std::uint32_t>(
        reply, 0, machMessageHeaderComplex |
                      (machMessageTypeMoveSendOnce << 8U));
    encodeGuestInteger<std::uint32_t>(reply, 4,
                                      semaphoreCreateReplySize);
    encodeGuestInteger<std::uint32_t>(reply, 8, 0);
    encodeGuestInteger<std::uint32_t>(reply, 12, receiveName.value);
    encodeGuestInteger<std::uint32_t>(reply, 16, 0);
    encodeGuestInteger<std::int32_t>(reply, 20,
                                     semaphoreCreateReplyId);
    encodeGuestInteger<std::uint32_t>(reply, 24, 1);
    encodeGuestInteger<std::uint32_t>(reply, 28, semaphoreName.value);
    reply[38] = machMessageTypeMoveSend;
    reply[39] = machMessagePortDescriptor;
    encodeGuestInteger<std::uint32_t>(reply, 40, 0);
    encodeGuestInteger<std::uint32_t>(reply, 44,
                                      machMessageTrailerSize);
    return reply;
}

std::array<std::uint8_t, restartableRangesReceiveSize>
encodeRestartableRangesRegisterReply(GuestMachPortName receiveName) {
    std::array<std::uint8_t, restartableRangesReceiveSize> reply{};
    encodeGuestInteger<std::uint32_t>(
        reply, 0, machMessageTypeMoveSendOnce << 8U);
    encodeGuestInteger<std::uint32_t>(reply, 4,
                                      restartableRangesReplySize);
    encodeGuestInteger<std::uint32_t>(reply, 8, 0);
    encodeGuestInteger<std::uint32_t>(reply, 12, receiveName.value);
    encodeGuestInteger<std::uint32_t>(reply, 16, 0);
    encodeGuestInteger<std::int32_t>(
        reply, 20, restartableRangesRegisterReplyId);
    constexpr std::array<std::uint8_t, 8> nativeNdr{
        0, 0, 0, 0, 1, 0, 0, 0};
    std::ranges::copy(nativeNdr, reply.begin() + 24);
    // XNU's CONFIG_ROSETTA path rejects registration for translated tasks so
    // libobjc uses its translated-process fallback synchronization strategy.
    encodeGuestInteger<std::uint32_t>(
        reply, 32, static_cast<std::uint32_t>(kernResourceShortage));
    encodeGuestInteger<std::uint32_t>(reply, 36, 0);
    encodeGuestInteger<std::uint32_t>(reply, 40, machMessageTrailerSize);
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
    case 10U: {
        // XNU trap 10 is _kernelrpc_mach_vm_allocate_trap. Its second
        // argument points to an in/out mach_vm_address_t. Anonymous task
        // allocations begin read/write and retain VM_PROT_ALL as their
        // maximum protection.
        if (state.rdi != taskSelfPortName().value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        constexpr auto guestPageMask = guest::guestPageSize - 1U;
        const auto placementFlags = state.r10 & ~vmFlagsAliasMask;
        if (placementFlags != vmFlagsAnywhere || state.rdx == 0 ||
            state.rdx > std::numeric_limits<std::size_t>::max() ||
            state.rdx > std::numeric_limits<std::uint64_t>::max() -
                            guestPageMask) {
            state.rax = kernInvalidArgument;
            return;
        }
        std::uint64_t hint = 0;
        try {
            addressSpace.validateAccess(
                guest::GuestAddress{state.rsi}, sizeof(hint),
                guest::Permission::Read | guest::Permission::Write);
            hint = addressSpace.readU64(guest::GuestAddress{state.rsi});
        } catch (const std::runtime_error &) {
            state.rax = kernInvalidAddress;
            return;
        }
        const auto roundedSize =
            (state.rdx + guestPageMask) &
            ~static_cast<std::uint64_t>(guestPageMask);
        const auto mappedAddress = findAnywhereRange(
            addressSpace, hint, roundedSize, guestPageMask);
        if (!mappedAddress) {
            state.rax = kernNoSpace;
            return;
        }
        constexpr auto currentPermissions =
            guest::Permission::Read | guest::Permission::Write;
        constexpr auto maximumPermissions =
            currentPermissions | guest::Permission::Execute;
        addressSpace.mapAnonymous(
            *mappedAddress, static_cast<std::size_t>(roundedSize),
            currentPermissions, maximumPermissions,
            "mach_vm_allocate anonymous anywhere");
        addressSpace.writeU64(guest::GuestAddress{state.rsi},
                              mappedAddress->value);
        state.rax = kernSuccess;
        return;
    }
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
        constexpr auto guestPageMask = guest::guestPageSize - 1U;
        const auto placementFlags = state.r8 & ~vmFlagsAliasMask;
        const bool anywhere = placementFlags == vmFlagsAnywhere;
        const bool fixed = placementFlags == 0;
        if ((!anywhere && !fixed) || (fixed && state.r10 != 0)) {
            throw unsupported(state, syscallRip);
        }
        const auto alignmentMask =
            state.r10 == 0 ? static_cast<std::uint64_t>(guestPageMask)
                           : state.r10;
        if (anywhere &&
            (alignmentMask < guestPageMask ||
             alignmentMask >= maximumUserMapEnd ||
             (alignmentMask & guestPageMask) != guestPageMask ||
             (alignmentMask & (alignmentMask + 1U)) != 0)) {
            state.rax = kernInvalidArgument;
            return;
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
        std::optional<guest::GuestAddress> mappedAddress;
        if (anywhere) {
            mappedAddress = findAnywhereRange(
                addressSpace, hint, roundedSize, alignmentMask);
            if (!mappedAddress) {
                state.rax = kernNoSpace;
                return;
            }
        } else {
            const auto fixedBase =
                hint & ~(static_cast<std::uint64_t>(guestPageMask));
            if (fixedBase > std::numeric_limits<std::uint64_t>::max() -
                                roundedSize) {
                state.rax = kernInvalidArgument;
                return;
            }
            const auto fixedEnd = fixedBase + roundedSize;
            const auto overlaps = std::ranges::any_of(
                addressSpace.mappingInfos(),
                [fixedBase, fixedEnd](const guest::MappingInfo &mapping) {
                    const auto mappingEnd =
                        mapping.base.value + mapping.size;
                    return fixedBase < mappingEnd &&
                           mapping.base.value < fixedEnd;
                });
            if (overlaps) {
                state.rax = kernNoSpace;
                return;
            }
            mappedAddress = guest::GuestAddress{fixedBase};
        }
        const auto currentPermissions = permissionsFromProtection(state.r9);
        constexpr auto maximumPermissions =
            guest::Permission::Read | guest::Permission::Write |
            guest::Permission::Execute;
        addressSpace.mapAnonymous(
            *mappedAddress, static_cast<std::size_t>(roundedSize),
            currentPermissions, maximumPermissions,
            anywhere ? "mach_vm_map anonymous anywhere"
                     : "mach_vm_map anonymous fixed");
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
    case 16U: {
        // XNU trap 16 allocates a receive right, vanilla or port set, in
        // the target task and copies out its name. Only RECEIVE and
        // PORT_SET rights are valid here.
        if (state.rdi != taskSelfPortName().value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        const auto right = static_cast<std::uint32_t>(state.rsi);
        if (right != 1 && right != 3) {
            state.rax = kernInvalidValue;
            return;
        }
        GuestPort port;
        port.type = right == 3 ? GuestPortType::PortSet : GuestPortType::Ordinary;
        port.queueLimit = machPortQlimitDefault;
        const auto name = portSpace_.allocateReceiveRight(port);
        if (!name) {
            state.rax = kernNoSpace;
            return;
        }
        try {
            const auto encoded = encodeGuestPortName(*name);
            addressSpace.writeBytes(guest::GuestAddress{state.rdx}, encoded);
        } catch (const std::runtime_error &) {
            portSpace_.rollbackLastAllocation(*name);
            state.rax = kernInvalidAddress;
            return;
        }
        state.rax = kernSuccess;
        return;
    }
    case 18U: {
        // XNU trap 18 drops one send, send-once, or dead-name uref in the
        // target task's IPC space. Rosa currently has explicit send and
        // send-once rights; no dead-name state has been observed yet.
        if (state.rdi != taskSelfPortName().value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        switch (portSpace_.deallocateUref(GuestMachPortName{
            static_cast<std::uint32_t>(state.rsi)})) {
        case GuestPortDeallocateResult::Success:
            state.rax = kernSuccess;
            return;
        case GuestPortDeallocateResult::InvalidName:
            state.rax = kernInvalidName;
            return;
        case GuestPortDeallocateResult::InvalidRight:
            state.rax = kernInvalidRight;
            return;
        }
        throw std::runtime_error("unreachable guest port deallocation result");
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
    case 22U: {
        // XNU trap 22 moves a receive right into a port set. Both names
        // must be live; the set must be a set and the member an owned
        // receive right that is not itself a set. Insertion is idempotent.
        // Queues stay empty (no asynchronous senders), so membership only
        // matters for receives addressed at the set itself.
        if (state.rdi != taskSelfPortName().value) {
            state.rax = machSendInvalidDestination;
            return;
        }
        auto *portSet = portSpace_.lookup(GuestMachPortName{
            static_cast<std::uint32_t>(state.rsi)});
        const auto *member = portSpace_.lookup(GuestMachPortName{
            static_cast<std::uint32_t>(state.rdx)});
        if (portSet == nullptr || member == nullptr) {
            state.rax = kernInvalidName;
            return;
        }
        if (portSet->type != GuestPortType::PortSet ||
            !member->hasReceiveRight || member->type == GuestPortType::PortSet) {
            state.rax = kernInvalidRight;
            return;
        }
        const auto memberName = member->name;
        if (std::find(portSet->members.begin(), portSet->members.end(), memberName) ==
            portSet->members.end()) {
            portSet->members.push_back(memberName);
        }
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

        // Only policy-free combinations are modeled: reply ports, and
        // ordinary ports built from guard, queue-limit, send-right, and
        // strict bits. Tempowner, importance, de-nap, immovable, filter, and
        // other policy-bearing bits stay loud.
        constexpr std::uint32_t modeledPortOptions =
            mpoContextAsGuard | mpoQueueLimit | mpoInsertSendRight | mpoStrict |
            mpoReplyPort;
        const bool replyPort = (options.flags & mpoReplyPort) != 0;
        if ((options.flags & ~modeledPortOptions) != 0 ||
            (replyPort && (options.flags & ~mpoReplyPort) != 0)) {
            // Unknown policy bits, and policy bits combined with a reply
            // port (whose guard/send semantics Rosa does not model), stay
            // loud rather than silently dropping policy.
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
        port.type = replyPort ? GuestPortType::Reply : GuestPortType::Ordinary;
        port.context = state.rdx;
        port.queueLimit = (options.flags & mpoQueueLimit) != 0
                              ? options.queueLimit
                              : machPortQlimitDefault;
        port.optionFlags = options.flags;
        if (!replyPort) {
            if ((options.flags & mpoInsertSendRight) != 0) {
                port.sendUrefs = 1;
            }
            if ((options.flags & mpoContextAsGuard) != 0) {
                port.guarded = true;
                port.guard = state.rdx;
            }
            port.strictGuard = (options.flags & mpoStrict) != 0;
        }
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
    case 27U: {
        // thread_self_trap has no arguments. Rosa currently has one guest
        // thread, so every copyout names the same thread object and adds one
        // guest send uref without exposing the host thread or its Mach port.
        const auto name =
            portSpace_.copyoutThreadSendRight(machPortUrefsMaximum);
        state.rax = name ? name->value : 0;
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
        // A receive-only call (no MACH_SEND_MSG bit) on an owned receive
        // right can never observe a message: Rosa runs the single guest
        // thread to completion and models no asynchronous senders, so the
        // queue is always empty. Answer MACH_RCV_TIMED_OUT immediately
        // instead of blocking forever; the result is identical, only the
        // wait is skipped.
        if ((static_cast<std::uint32_t>(state.rsi) & machMsgOptionSend) == 0) {
            const auto receiveName = GuestMachPortName{
                static_cast<std::uint32_t>(state.r9 >> 32U)};
            if (!portSpace_.ownsReceiveRight(receiveName)) {
                state.rax = machReceiveInvalidName;
                return;
            }
            state.rax = machReceiveTimedOut;
            return;
        }
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

        // Rosa runs no launchd/bootstrap server. The first observed use is
        // a best-effort notification-center XPC lookup during library init;
        // fail the send so the guest proceeds degraded instead of blocking
        // forever on a reply that can never arrive.
        if (const auto *remotePort = portSpace_.lookup(GuestMachPortName{
                static_cast<std::uint32_t>(state.r10)});
            remotePort != nullptr &&
            remotePort->type == GuestPortType::Bootstrap) {
            state.rax = machSendInvalidDestination;
            return;
        }

        if (const auto receiveName = decodeObservedHostInfoRequest(
                message, state, receiveSizeAndPriority, timeout, portSpace_,
                hostBasicInfoFlavor, hostBasicInfoCount)) {
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

        if (const auto receiveName = decodeObservedHostInfoRequest(
                message, state, receiveSizeAndPriority, timeout, portSpace_,
                hostPriorityInfoFlavor, hostPriorityInfoCount)) {
            constexpr auto replySize =
                hostPriorityInfoReplySize + machMessageTrailerSize;
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdi}, replySize,
                    guest::Permission::Write);
            } catch (const std::runtime_error &) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto reply = encodeHostPriorityInfoReply(
                *receiveName, queryGuestHostPriorityInfo());
            addressSpace.writeBytes(guest::GuestAddress{state.rdi}, reply);
            state.rax = kernSuccess;
            return;
        }

        if (const auto receiveName =
                decodeObservedHostClockServiceRequest(
                    message, state, receiveSizeAndPriority, timeout,
                    portSpace_)) {
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdi},
                    hostGetClockServiceReceiveSize,
                    guest::Permission::Write);
            } catch (const std::runtime_error &) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto clockService =
                portSpace_.copyoutClockSendRight(systemClockId,
                                                 machPortUrefsMaximum);
            if (!clockService) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto reply = encodeHostClockServiceReply(
                *receiveName, *clockService);
            addressSpace.writeBytes(guest::GuestAddress{state.rdi}, reply);
            state.rax = kernSuccess;
            return;
        }

        if (const auto receiveName =
                decodeObservedHostGetSpecialPortRequest(
                    message, state, receiveSizeAndPriority, timeout,
                    portSpace_)) {
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdi},
                    hostGetSpecialPortReceiveSize,
                    guest::Permission::Write);
            } catch (const std::runtime_error &) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            // libdispatch demotes its host-self send right through
            // HOST_LOCAL_NODE/HOST_PORT. Rosa's guest is unprivileged, so
            // XNU answers with another send right to the same host object.
            const auto host = portSpace_.copyoutHostSendRight(
                machPortUrefsMaximum);
            if (!host) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto reply =
                encodeHostGetSpecialPortReply(*receiveName, *host);
            addressSpace.writeBytes(guest::GuestAddress{state.rdi}, reply);
            state.rax = kernSuccess;
            return;
        }

        if (const auto receiveName =
                decodeObservedTaskGetSpecialPortRequest(
                    message, state, receiveSizeAndPriority, timeout,
                    portSpace_)) {
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdi},
                    taskGetSpecialPortReceiveSize,
                    guest::Permission::Write);
            } catch (const std::runtime_error &) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto bootstrap = portSpace_.copyoutBootstrapSendRight(
                machPortUrefsMaximum);
            if (!bootstrap) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto reply = encodeTaskGetSpecialPortReply(
                *receiveName, *bootstrap);
            addressSpace.writeBytes(guest::GuestAddress{state.rdi}, reply);
            state.rax = kernSuccess;
            return;
        }

        if (const auto receiveName = decodeObservedTaskAuditTokenRequest(
                message, state, receiveSizeAndPriority, timeout,
                portSpace_)) {
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdi},
                    taskAuditTokenReceiveSize,
                    guest::Permission::Write);
            } catch (const std::runtime_error &) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto reply = encodeTaskAuditTokenReply(
                *receiveName, queryGuestTaskAuditToken());
            addressSpace.writeBytes(guest::GuestAddress{state.rdi}, reply);
            state.rax = kernSuccess;
            return;
        }

        if (const auto request = decodeObservedTaskSetSpecialPortRequest(
                message, state, receiveSizeAndPriority, timeout,
                portSpace_)) {
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdi},
                    taskSetSpecialPortReceiveSize,
                    guest::Permission::Write);
            } catch (const std::runtime_error &) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto reply =
                encodeTaskSetSpecialPortReply(request->receiveName);
            addressSpace.writeBytes(guest::GuestAddress{state.rdi}, reply);
            taskDebugControlPort_ = request->specialPortName;
            state.rax = kernSuccess;
            return;
        }

        if (const auto receiveName = decodeObservedSemaphoreCreateRequest(
                message, state, receiveSizeAndPriority, timeout,
                portSpace_)) {
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdi},
                    semaphoreCreateReceiveSize, guest::Permission::Write);
            } catch (const std::runtime_error &) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto semaphore = portSpace_.allocateSemaphoreSendRight(
                syncPolicyFifo, 0);
            if (!semaphore) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto reply =
                encodeSemaphoreCreateReply(*receiveName, *semaphore);
            addressSpace.writeBytes(guest::GuestAddress{state.rdi}, reply);
            state.rax = kernSuccess;
            return;
        }

        if (const auto receiveName =
                decodeObservedRestartableRangesRegisterRequest(
                    message, state, receiveSizeAndPriority, timeout,
                    portSpace_)) {
            try {
                addressSpace.validateAccess(
                    guest::GuestAddress{state.rdi},
                    restartableRangesReceiveSize,
                    guest::Permission::Write);
            } catch (const std::runtime_error &) {
                throw inspectUnsupportedMachMessage2(addressSpace, state,
                                                     syscallRip);
            }
            const auto reply =
                encodeRestartableRangesRegisterReply(*receiveName);
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
    case 50U: {
        // thread_get_special_reply_port takes no arguments and returns the
        // calling thread's stable special reply port, creating it on first
        // use. Rosa has one guest thread, so one synthetic reply receive
        // right is cached for the process lifetime.
        if (!specialReplyPort_) {
            GuestPort port;
            port.type = GuestPortType::Reply;
            port.queueLimit = machPortQlimitDefault;
            const auto name = portSpace_.allocateReceiveRight(port);
            if (!name) {
                state.rax = 0; // MACH_PORT_NULL models allocation exhaustion.
                return;
            }
            specialReplyPort_ = *name;
        }
        state.rax = specialReplyPort_->value;
        return;
    }
    case 70U: {
        // host_create_mach_voucher_trap takes the host port, a recipe
        // buffer and size, and a voucher copyout. Rosa has no voucher
        // banks or attributes, so each successful call mints a new
        // synthetic voucher token for the process. Vouchers are inert
        // guest metadata here: no message path consumes them yet.
        constexpr std::uint64_t maximumRecipeSize = 1024U * 1024U;
        const auto *hostPort = portSpace_.lookup(
            GuestMachPortName{static_cast<std::uint32_t>(state.rdi)});
        if (hostPort == nullptr || hostPort->type != GuestPortType::Host ||
            hostPort->sendUrefs == 0 || state.r10 == 0 ||
            state.rdx > maximumRecipeSize) {
            state.rax = kernInvalidArgument;
            return;
        }
        try {
            // Validate the recipe buffer and the voucher copyout without
            // interpreting recipe contents.
            static_cast<void>(addressSpace.readBytes(
                guest::GuestAddress{state.rsi},
                static_cast<std::size_t>(state.rdx)));
            addressSpace.validateAccess(guest::GuestAddress{state.r10},
                                        sizeof(std::uint64_t),
                                        guest::Permission::Write);
        } catch (const std::runtime_error &) {
            state.rax = kernInvalidAddress;
            return;
        }
        const auto voucher = nextVoucher_++;
        vouchers_.insert(voucher);
        try {
            addressSpace.writeU64(guest::GuestAddress{state.r10}, voucher);
        } catch (const std::runtime_error &) {
            vouchers_.erase(voucher);
            state.rax = kernInvalidAddress;
            return;
        }
        state.rax = kernSuccess;
        return;
    }
    case 89U: {
        // XNU trap 89 is mach_timebase_info_trap: it fills one
        // mach_timebase_info struct { uint32 numer, denom }. Rosa's virtual
        // x86 timestamp counter ticks at twice the nanosecond rate
        // (sampleX86TimestampCounter), so the coherent ratio is 1/2.
        try {
            addressSpace.validateAccess(guest::GuestAddress{state.rdi},
                                        2U * sizeof(std::uint32_t),
                                        guest::Permission::Write);
            addressSpace.writeU32(guest::GuestAddress{state.rdi}, 1);
            addressSpace.writeU32(
                guest::GuestAddress{state.rdi + sizeof(std::uint32_t)}, 2);
        } catch (const std::runtime_error &) {
            state.rax = kernInvalidAddress;
            return;
        }
        state.rax = kernSuccess;
        return;
    }
    default:
        throw unsupported(state, syscallRip);
    }
}

} // namespace rosa::darwin
