#include "darwin/Mach.h"

#include <mach/mach.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>

// Mach messages between the guest's own ports (XNU ipc_kmsg/ipc_mqueue).
// Every guest port lives in one IPC space, so a right carried by a message
// keeps its name; copyin counts the receiver's new urefs at send time.

namespace rosa::darwin {
namespace {

constexpr std::uint64_t optionSendMessage = 0x1;
constexpr std::uint64_t optionReceiveMessage = 0x2;
constexpr std::uint64_t optionReceiveLarge = 0x4;
constexpr std::uint64_t optionReceiveLargeIdentity = 0x8;
constexpr std::uint64_t optionSendTimeout = 0x10;
constexpr std::uint64_t optionReceiveTimeout = 0x100;
constexpr std::uint64_t optionMessageVector = 0x100000000ULL;

constexpr std::uint32_t typeMoveReceive = 16;
constexpr std::uint32_t typeMoveSend = 17;
constexpr std::uint32_t typeMoveSendOnce = 18;
constexpr std::uint32_t typeCopySend = 19;
constexpr std::uint32_t typeMakeSend = 20;
constexpr std::uint32_t typeMakeSendOnce = 21;
constexpr std::uint32_t bitsComplex = 0x80000000U;
constexpr std::uint32_t bitsTypeMask = 0x1F;

constexpr std::uint8_t descriptorPort = 0;
constexpr std::uint8_t descriptorOutOfLine = 1;
constexpr std::uint8_t descriptorOutOfLinePorts = 2;
constexpr std::uint8_t descriptorOutOfLineVolatile = 3;

constexpr std::uint64_t messageSuccess = 0;
constexpr std::uint64_t sendInvalidData = 0x10000002;
constexpr std::uint64_t sendInvalidDestination = 0x10000003;
constexpr std::uint64_t sendTimedOut = 0x10000004;
constexpr std::uint64_t sendMessageTooSmall = 0x10000008;
constexpr std::uint64_t sendInvalidReply = 0x10000009;
constexpr std::uint64_t sendInvalidRight = 0x1000000A;
constexpr std::uint64_t sendInvalidMemory = 0x1000000C;
constexpr std::uint64_t sendInvalidType = 0x1000000F;
constexpr std::uint64_t sendInvalidHeader = 0x10000010;
constexpr std::uint64_t receiveInvalidName = 0x10004002;
constexpr std::uint64_t receiveTimedOut = 0x10004003;
constexpr std::uint64_t receiveTooLarge = 0x10004004;
constexpr std::uint64_t receiveInvalidData = 0x10004008;
constexpr std::uint64_t receivePortDied = 0x10004009;

constexpr std::size_t headerSize = 24;
constexpr std::uint32_t portNull = 0;
constexpr std::uint32_t portDead = 0xFFFFFFFF;
constexpr std::uint32_t urefsMaximum = 0xFFFF;

template <typename T> T readField(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
        throw std::out_of_range("guest Mach message field");
    }
    T value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

template <typename T> void writeField(std::span<std::uint8_t> bytes, std::size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

// The right a receiver holds for a sent disposition (ipc_object_copyin_type).
std::uint32_t receivedType(std::uint32_t disposition) {
    switch (disposition) {
    case typeMoveReceive:
        return typeMoveReceive;
    case typeMoveSend:
    case typeCopySend:
    case typeMakeSend:
        return typeMoveSend;
    case typeMoveSendOnce:
    case typeMakeSendOnce:
        return typeMoveSendOnce;
    default:
        return 0;
    }
}

// REQUESTED_TRAILER_SIZE for x86_64's 4-byte-packed trailers.
std::size_t trailerSize(std::uint64_t options) {
    switch ((options >> 24U) & 0xFU) {
    case 0:
        return 8;
    case 1:
        return 12;
    case 2:
        return 20;
    case 3:
        return 52;
    case 4:
        return 60;
    default:
        return 68;
    }
}

std::array<std::uint32_t, 8> hostAuditToken() {
    audit_token_t native{};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, reinterpret_cast<task_info_t>(&native),
                  &count) != KERN_SUCCESS) {
        throw std::runtime_error("task_info(TASK_AUDIT_TOKEN) failed for a guest Mach trailer");
    }
    std::array<std::uint32_t, 8> token{};
    std::ranges::copy(native.val, token.begin());
    return token;
}

} // namespace

bool MachDispatcher::isGuestQueue(const GuestPort &port) noexcept {
    return port.hasReceiveRight &&
           (port.type == GuestPortType::Ordinary || port.type == GuestPortType::Reply);
}

// Checks that the sender holds the right `disposition` needs.
bool MachDispatcher::holdsRight(const GuestPort &port, std::uint32_t disposition) noexcept {
    switch (disposition) {
    case typeMoveSend:
    case typeCopySend:
        return port.sendUrefs != 0;
    case typeMakeSend:
    case typeMakeSendOnce:
    case typeMoveReceive:
        return port.hasReceiveRight;
    case typeMoveSendOnce:
        return port.sendOnceUrefs != 0;
    default:
        return false;
    }
}

// The receiver's new urefs; moved rights change nothing in one IPC space.
void MachDispatcher::transferRight(GuestPort &port, std::uint32_t disposition) noexcept {
    switch (disposition) {
    case typeCopySend:
    case typeMakeSend:
        port.sendUrefs = std::min(port.sendUrefs + 1U, urefsMaximum);
        break;
    case typeMakeSendOnce:
        ++port.sendOnceUrefs;
        break;
    default:
        break;
    }
}

std::uint64_t MachDispatcher::sendGuestMessage(guest::AddressSpace &addressSpace,
                                               const x86::X86State &state, GuestPort &destination,
                                               std::uint64_t timeout) {
    const auto options = state.rsi;
    const auto bits = static_cast<std::uint32_t>(state.rdx);
    const auto sendSize = static_cast<std::uint32_t>(state.rdx >> 32U);
    const auto localName = static_cast<std::uint32_t>(state.r10 >> 32U);
    const auto id = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.r8 >> 32U));
    if (sendSize < headerSize || (sendSize & 3U) != 0) {
        return sendMessageTooSmall;
    }
    std::vector<std::uint8_t> body;
    try {
        body = addressSpace.readBytes(guest::GuestAddress{state.rdi + headerSize},
                                      sendSize - headerSize);
    } catch (const std::runtime_error &) {
        return sendInvalidData;
    }
    const auto remoteType = bits & bitsTypeMask;
    const auto localType = (bits >> 8U) & bitsTypeMask;
    if (!holdsRight(destination, remoteType)) {
        return sendInvalidDestination;
    }
    GuestPort *reply = nullptr;
    if (localType != 0 && localName != portNull && localName != portDead) {
        reply = portSpace_.lookup(GuestMachPortName{localName});
        if (reply == nullptr || !holdsRight(*reply, localType)) {
            return sendInvalidReply;
        }
    } else if (localType == 0 && localName != portNull) {
        return sendInvalidHeader;
    }
    // Send-once messages bypass the queue limit, as in XNU.
    const bool sendOnce = remoteType == typeMoveSendOnce || remoteType == typeMakeSendOnce;
    if (!sendOnce && destination.queueLimit != 0 &&
        destination.messages.size() >= destination.queueLimit) {
        if ((options & optionSendTimeout) != 0 && timeout == 0) {
            return sendTimedOut;
        }
        throw std::runtime_error("a guest Mach send would block on a full queue");
    }

    GuestMachMessage message;
    message.id = id;
    message.replyPort = GuestMachPortName{reply != nullptr ? localName : 0};
    message.bits = receivedType(localType) | (receivedType(remoteType) << 8U) |
                   (bits & bitsComplex);
    // Validate descriptors before any right or memory changes hands.
    struct Transfer {
        GuestPort *port;
        std::uint32_t disposition;
    };
    std::vector<Transfer> transfers;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> deallocations;
    if ((bits & bitsComplex) != 0) {
        try {
            const auto count = readField<std::uint32_t>(body, 0);
            std::size_t offset = 4;
            for (std::uint32_t index = 0; index < count; ++index) {
                const auto type = readField<std::uint8_t>(body, offset + 11);
                if (type == descriptorPort) {
                    const auto name = readField<std::uint32_t>(body, offset);
                    const auto disposition = readField<std::uint8_t>(body, offset + 10);
                    if (name != portNull && name != portDead) {
                        auto *port = portSpace_.lookup(GuestMachPortName{name});
                        if (port == nullptr || !holdsRight(*port, disposition)) {
                            return sendInvalidRight;
                        }
                        transfers.push_back({port, disposition});
                    }
                    body[offset + 10] = static_cast<std::uint8_t>(receivedType(disposition));
                    offset += 12;
                } else if (type == descriptorOutOfLine || type == descriptorOutOfLineVolatile ||
                           type == descriptorOutOfLinePorts) {
                    const auto address = readField<std::uint64_t>(body, offset);
                    const auto deallocate = readField<std::uint8_t>(body, offset + 8) != 0;
                    const auto countOrSize = readField<std::uint32_t>(body, offset + 12);
                    const auto size = type == descriptorOutOfLinePorts
                                          ? static_cast<std::uint64_t>(countOrSize) * 4U
                                          : countOrSize;
                    GuestMachMessage::OutOfLine copy{.addressOffset = offset};
                    if (size != 0) {
                        try {
                            copy.bytes = addressSpace.readBytes(guest::GuestAddress{address}, size);
                        } catch (const std::runtime_error &) {
                            return sendInvalidMemory;
                        }
                    }
                    if (type == descriptorOutOfLinePorts) {
                        const auto disposition = readField<std::uint8_t>(body, offset + 10);
                        for (std::size_t port = 0; port < countOrSize; ++port) {
                            const auto name = readField<std::uint32_t>(copy.bytes, port * 4U);
                            if (name == portNull || name == portDead) {
                                continue;
                            }
                            auto *entry = portSpace_.lookup(GuestMachPortName{name});
                            if (entry == nullptr || !holdsRight(*entry, disposition)) {
                                return sendInvalidRight;
                            }
                            transfers.push_back({entry, disposition});
                        }
                        body[offset + 10] = static_cast<std::uint8_t>(receivedType(disposition));
                    }
                    if (deallocate && size != 0) {
                        deallocations.emplace_back(address, size);
                    }
                    message.outOfLine.push_back(std::move(copy));
                    offset += 16;
                } else {
                    return sendInvalidType;
                }
            }
        } catch (const std::out_of_range &) {
            return sendMessageTooSmall;
        }
    }

    // Commit: consumed destination rights, the receiver's new rights, and
    // out-of-line memory the sender gave away.
    if (remoteType == typeMoveSend && destination.sendUrefs != 0) {
        --destination.sendUrefs;
    } else if (remoteType == typeMoveSendOnce && destination.sendOnceUrefs != 0) {
        --destination.sendOnceUrefs;
    }
    if (reply != nullptr) {
        transferRight(*reply, localType);
    }
    for (const auto &transfer : transfers) {
        transferRight(*transfer.port, transfer.disposition);
    }
    for (const auto &[address, size] : deallocations) {
        constexpr auto pageMask = static_cast<std::uint64_t>(guest::guestPageSize - 1U);
        const auto first = address & ~pageMask;
        const auto last = (address + size + pageMask) & ~pageMask;
        static_cast<void>(addressSpace.deallocate(guest::GuestAddress{first}, last - first));
    }
    message.body = std::move(body);
    message.arrival = nextMessageArrival_++;
    destination.messages.push_back(std::move(message));
    messageQueued(addressSpace, destination.name);
    return messageSuccess;
}

void MachDispatcher::messageQueued(guest::AddressSpace &addressSpace, GuestMachPortName port) {
    // A receiver parked on the port, or on a set holding it, takes the
    // message now; otherwise watchers learn the port became ready.
    if (scheduler_ != nullptr) {
        if (scheduler_->wake(GuestWaitKind::MachReceive, port.value, 1) == 0) {
            for (const auto set : portSpace_.portSetsContaining(port)) {
                if (scheduler_->wake(GuestWaitKind::MachReceive, set.value, 1) != 0) {
                    break;
                }
            }
        }
    }
    updateReadiness(addressSpace, port);
}

void MachDispatcher::updateReadiness(guest::AddressSpace &addressSpace, GuestMachPortName port) {
    if (!portReadiness_) {
        return;
    }
    const auto *entry = portSpace_.lookup(port);
    portReadiness_(addressSpace, port, entry != nullptr && !entry->messages.empty());
    for (const auto set : portSpace_.portSetsContaining(port)) {
        const auto *setEntry = portSpace_.lookup(set);
        bool ready = false;
        for (const auto member : setEntry->members) {
            const auto *memberEntry = portSpace_.lookup(member);
            ready |= memberEntry != nullptr && !memberEntry->messages.empty();
        }
        portReadiness_(addressSpace, set, ready);
    }
}

GuestPort *MachDispatcher::nextMessagePort(GuestMachPortName receiveName) {
    auto *port = portSpace_.lookup(receiveName);
    if (port == nullptr) {
        return nullptr;
    }
    if (port->type != GuestPortType::PortSet) {
        return port->messages.empty() ? nullptr : port;
    }
    GuestPort *oldest = nullptr;
    for (const auto member : port->members) {
        auto *entry = portSpace_.lookup(member);
        if (entry != nullptr && !entry->messages.empty() &&
            (oldest == nullptr || entry->messages.front().arrival < oldest->messages.front().arrival)) {
            oldest = entry;
        }
    }
    return oldest;
}

std::optional<std::uint64_t> MachDispatcher::tryReceiveGuestMessage(
    guest::AddressSpace &addressSpace, const GuestReceive &receive) {
    auto *port = nextMessagePort(receive.name);
    if (port == nullptr) {
        return std::nullopt;
    }
    auto &message = port->messages.front();
    const auto messageSize = headerSize + message.body.size();
    const auto trailer = trailerSize(receive.options);
    if (receive.size < messageSize + trailer) {
        if ((receive.options & optionReceiveLarge) != 0) {
            // The message stays queued; the header reports the size needed.
            try {
                addressSpace.writeU32(guest::GuestAddress{receive.buffer + 4},
                                      static_cast<std::uint32_t>(messageSize + trailer));
                if ((receive.options & optionReceiveLargeIdentity) != 0) {
                    addressSpace.writeU32(guest::GuestAddress{receive.buffer + 12},
                                          port->name.value);
                }
            } catch (const std::runtime_error &) {
                return receiveInvalidData;
            }
            return receiveTooLarge;
        }
        port->messages.pop_front();
        updateReadiness(addressSpace, port->name);
        return receiveTooLarge;
    }

    auto body = message.body;
    for (const auto &copy : message.outOfLine) {
        std::uint64_t address = 0;
        if (!copy.bytes.empty()) {
            constexpr auto pageMask = static_cast<std::uint64_t>(guest::guestPageSize - 1U);
            const auto size = (copy.bytes.size() + pageMask) & ~pageMask;
            const auto region = findGuestAnywhereRange(addressSpace, 0, size, pageMask);
            if (!region) {
                return receiveInvalidData;
            }
            constexpr auto readWrite = guest::Permission::Read | guest::Permission::Write;
            addressSpace.mapAnonymous(*region, static_cast<std::size_t>(size), readWrite,
                                      readWrite | guest::Permission::Execute,
                                      "Mach out-of-line memory");
            addressSpace.writeBytes(*region, copy.bytes);
            address = region->value;
        }
        writeField<std::uint64_t>(body, copy.addressOffset, address);
        // Received memory is a virtual copy the receiver owns.
        body[copy.addressOffset + 8] = 0;
        body[copy.addressOffset + 9] = 1;
    }
    std::vector<std::uint8_t> bytes(messageSize + trailer);
    writeField<std::uint32_t>(bytes, 0, message.bits);
    writeField<std::uint32_t>(bytes, 4, static_cast<std::uint32_t>(messageSize));
    writeField<std::uint32_t>(bytes, 8, message.replyPort.value);
    writeField<std::uint32_t>(bytes, 12, port->name.value);
    writeField<std::uint32_t>(bytes, 16, 0);
    writeField<std::int32_t>(bytes, 20, message.id);
    std::ranges::copy(body, bytes.begin() + headerSize);
    // mach_msg_mac_trailer_t, truncated to the requested elements.
    std::array<std::uint8_t, 68> full{};
    writeField<std::uint32_t>(full, 0, 0);
    writeField<std::uint32_t>(full, 4, static_cast<std::uint32_t>(trailer));
    writeField<std::uint32_t>(full, 8, port->sequenceNumber);
    writeField<std::uint32_t>(full, 12, static_cast<std::uint32_t>(::geteuid()));
    writeField<std::uint32_t>(full, 16, static_cast<std::uint32_t>(::getegid()));
    const auto audit = hostAuditToken();
    std::memcpy(full.data() + 20, audit.data(), sizeof(audit));
    writeField<std::uint64_t>(full, 52, port->context);
    std::copy_n(full.begin(), trailer, bytes.begin() + static_cast<std::ptrdiff_t>(messageSize));
    try {
        addressSpace.writeBytes(guest::GuestAddress{receive.buffer}, bytes);
    } catch (const std::runtime_error &) {
        return receiveInvalidData;
    }
    port->messages.pop_front();
    ++port->sequenceNumber;
    updateReadiness(addressSpace, port->name);
    return messageSuccess;
}

void MachDispatcher::receiveGuestMessage(guest::AddressSpace &addressSpace, x86::X86State &state,
                                         const GuestReceive &receive) {
    const auto *entry = portSpace_.lookup(receive.name);
    if (entry == nullptr || (!entry->hasReceiveRight && entry->type != GuestPortType::PortSet)) {
        state.rax = receiveInvalidName;
        return;
    }
    if (const auto result = tryReceiveGuestMessage(addressSpace, receive)) {
        state.rax = *result;
        return;
    }
    if ((receive.options & optionReceiveTimeout) != 0 && receive.timeout == 0) {
        state.rax = receiveTimedOut;
        return;
    }
    if (scheduler_ == nullptr) {
        throw std::runtime_error("a Mach receive would block with no guest scheduler");
    }
    std::ostringstream description;
    description << "mach_msg receive on 0x" << std::hex << receive.name.value;
    GuestWait wait{
        .kind = GuestWaitKind::MachReceive,
        .channel = receive.name.value,
        .complete =
            [this, &addressSpace, receive](x86::X86State &waiter, GuestWakeReason reason) {
                waiter.rax = reason == GuestWakeReason::TimedOut    ? receiveTimedOut
                             : reason == GuestWakeReason::Destroyed ? receivePortDied
                                                                    : tryReceiveGuestMessage(
                                                                          addressSpace, receive)
                                                                          .value_or(receiveTimedOut);
            },
        .description = description.str(),
    };
    if ((receive.options & optionReceiveTimeout) != 0) {
        wait.deadline = GuestClock::now() + std::chrono::milliseconds{receive.timeout};
    }
    scheduler_->block(std::move(wait));
}

void MachDispatcher::destroyReceiveRight(guest::AddressSpace &addressSpace, GuestPort &port) {
    // XNU's ipc_port_destroy: queued messages die with the port, receivers
    // parked on it see MACH_RCV_PORT_DIED, and remaining send rights in this
    // space become a dead name.
    const auto name = port.name;
    port.hasReceiveRight = false;
    port.messages.clear();
    port.dead = port.sendUrefs != 0 || port.sendOnceUrefs != 0;
    if (scheduler_ != nullptr) {
        static_cast<void>(scheduler_->wake(GuestWaitKind::MachReceive, name.value, SIZE_MAX,
                                           GuestWakeReason::Destroyed));
    }
    if (portReadiness_) {
        portReadiness_(addressSpace, name, false);
    }
    portSpace_.removeFromPortSets(name);
    portSpace_.eraseIfEmpty(name);
}

void MachDispatcher::queueTimerExpiration(guest::AddressSpace &addressSpace, GuestPort &timer) {
    // mk_timer_expire_msg_t: a header sent COPY_SEND to the timer port and
    // three zero quadwords.
    GuestMachMessage message;
    message.bits = typeMoveSend << 8U;
    message.body.assign(24, 0);
    message.arrival = nextMessageArrival_++;
    timer.messages.push_back(std::move(message));
    messageQueued(addressSpace, timer.name);
}

std::optional<std::uint64_t> MachDispatcher::fireDueTimers(guest::AddressSpace &addressSpace,
                                                           std::uint64_t now) {
    std::vector<GuestMachPortName> due;
    std::optional<std::uint64_t> next;
    portSpace_.forEachPort([&](GuestPort &port) {
        if (port.type == GuestPortType::Timer && port.timerDeadline) {
            if (*port.timerDeadline <= now) {
                due.push_back(port.name);
            } else {
                next = next ? std::min(*next, *port.timerDeadline) : *port.timerDeadline;
            }
        }
    });
    for (const auto name : due) {
        if (auto *timer = portSpace_.lookup(name); timer != nullptr && timer->hasReceiveRight) {
            timer->timerDeadline.reset();
            queueTimerExpiration(addressSpace, *timer);
        }
    }
    return next;
}

bool MachDispatcher::dispatchGuestMessage(guest::AddressSpace &addressSpace,
                                          x86::X86State &state) {
    const auto options = state.rsi;
    if ((options & optionMessageVector) != 0) {
        return false;
    }
    std::uint64_t receiveSizeAndPriority{};
    std::uint64_t timeout{};
    try {
        receiveSizeAndPriority = addressSpace.readU64(guest::GuestAddress{state.rsp + 8U});
        timeout = addressSpace.readU64(guest::GuestAddress{state.rsp + 16U});
    } catch (const std::runtime_error &) {
        return false;
    }
    const GuestReceive receive{
        .name = GuestMachPortName{static_cast<std::uint32_t>(state.r9 >> 32U)},
        .buffer = state.rdi,
        .size = static_cast<std::uint32_t>(receiveSizeAndPriority),
        .options = options,
        .timeout = static_cast<std::uint32_t>(timeout),
    };
    if ((options & optionSendMessage) != 0) {
        auto *destination =
            portSpace_.lookup(GuestMachPortName{static_cast<std::uint32_t>(state.r10)});
        if (destination == nullptr || !isGuestQueue(*destination)) {
            return false;
        }
        const auto result =
            sendGuestMessage(addressSpace, state, *destination, static_cast<std::uint32_t>(timeout));
        if (result != messageSuccess || (options & optionReceiveMessage) == 0) {
            state.rax = result;
            return true;
        }
    } else if ((options & optionReceiveMessage) == 0) {
        state.rax = messageSuccess;
        return true;
    }
    receiveGuestMessage(addressSpace, state, receive);
    return true;
}

} // namespace rosa::darwin
