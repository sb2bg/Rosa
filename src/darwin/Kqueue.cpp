#include "darwin/Kqueue.h"

#include <algorithm>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace rosa::darwin {
namespace {

constexpr std::int16_t evfiltSystemCount = 18;

// EVFILT_USER fflags (event.h).
constexpr std::uint32_t noteTrigger = 0x01000000;
constexpr std::uint32_t noteFlagsControlMask = 0xC0000000;
constexpr std::uint32_t noteFlagsMask = 0x00FFFFFF;
constexpr std::uint32_t noteFlagsAnd = 0x40000000;
constexpr std::uint32_t noteFlagsOr = 0x80000000;
constexpr std::uint32_t noteFlagsCopy = 0xC0000000;

// EVFILT_TIMER fflags (event.h).
constexpr std::uint32_t noteSeconds = 0x001;
constexpr std::uint32_t noteMicroseconds = 0x002;
constexpr std::uint32_t noteNanoseconds = 0x004;
constexpr std::uint32_t noteAbsolute = 0x008;
constexpr std::uint32_t noteMachTime = 0x100;
constexpr std::uint32_t noteTimerUnits = noteSeconds | noteMicroseconds | noteNanoseconds | noteMachTime;

// pthread_priority_t bits (priority_private.h).
constexpr std::uint32_t pthreadPriorityEventManager = 0x02000000;
constexpr std::uint32_t pthreadPrioritySchedulingPriority = 0x20000000;
constexpr std::uint32_t pthreadPriorityValidQosMask = 0x00003F00;

struct TimerParameters {
    std::uint64_t deadline{};
    std::uint64_t interval{};
};

// XNU's filt_timervalidate in guest mach_absolute_time units.
int validateTimer(const GuestKevent &change, std::uint64_t now, TimerParameters &parameters) {
    std::uint64_t nanosecondsPerUnit = 0;
    switch (change.fflags & noteTimerUnits) {
    case noteSeconds:
        nanosecondsPerUnit = 1'000'000'000;
        break;
    case noteMicroseconds:
        nanosecondsPerUnit = 1'000;
        break;
    case noteNanoseconds:
        nanosecondsPerUnit = 1;
        break;
    case noteMachTime:
        break;
    case 0:
        nanosecondsPerUnit = 1'000'000;
        break;
    default:
        return EINVAL;
    }
    const auto toTicks = [&](std::uint64_t units, std::uint64_t &ticks) {
        if (nanosecondsPerUnit == 0) {
            ticks = units;
            return true;
        }
        std::uint64_t nanoseconds{};
        return !__builtin_mul_overflow(units, nanosecondsPerUnit, &nanoseconds) &&
               !__builtin_mul_overflow(nanoseconds, guestMachTicksPerNanosecond, &ticks);
    };
    if ((change.fflags & noteAbsolute) != 0) {
        if (nanosecondsPerUnit == 0) {
            parameters.deadline = static_cast<std::uint64_t>(change.data);
        } else {
            // A calendar deadline converts to mach time once, at registration.
            std::uint64_t deadlineNanoseconds{};
            if (__builtin_mul_overflow(static_cast<std::uint64_t>(change.data), nanosecondsPerUnit,
                                       &deadlineNanoseconds)) {
                return ERANGE;
            }
            const auto calendarNow = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
            parameters.deadline =
                calendarNow < deadlineNanoseconds
                    ? now + (deadlineNanoseconds - calendarNow) * guestMachTicksPerNanosecond
                    : 0;
        }
        parameters.interval = 0;
    } else if (change.data < 0) {
        // Negative intervals fire once, immediately.
        parameters.deadline = 0;
        parameters.interval = 0;
    } else {
        std::uint64_t interval{};
        if (!toTicks(static_cast<std::uint64_t>(change.data), interval)) {
            return ERANGE;
        }
        parameters.deadline = now + interval;
        parameters.interval = interval;
    }
    return 0;
}

void armTimer(GuestKnote &knote, const TimerParameters &parameters, std::uint64_t now) {
    knote.timerInterval = parameters.interval;
    knote.registration.ext[0] = parameters.deadline;
    if (parameters.deadline <= now) {
        knote.timerDeadline.reset();
        knote.active = true;
    } else {
        knote.timerDeadline = parameters.deadline;
        knote.active = false;
    }
}

bool inertFilter(std::int16_t filter) {
    // Sources whose conditions never arise for a guest: memory pressure, VM
    // pressure, signals (Rosa delivers none), and other processes.
    return filter == evfiltMemoryStatus || filter == evfiltVm || filter == evfiltSignal ||
           filter == evfiltProc;
}

} // namespace

GuestKevent GuestKevent::decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < size) {
        throw std::runtime_error("truncated guest kevent_qos_s");
    }
    GuestKevent event;
    std::memcpy(&event.ident, bytes.data(), 8);
    std::memcpy(&event.filter, bytes.data() + 8, 2);
    std::memcpy(&event.flags, bytes.data() + 10, 2);
    std::memcpy(&event.qos, bytes.data() + 12, 4);
    std::memcpy(&event.udata, bytes.data() + 16, 8);
    std::memcpy(&event.fflags, bytes.data() + 24, 4);
    std::memcpy(&event.xflags, bytes.data() + 28, 4);
    std::memcpy(&event.data, bytes.data() + 32, 8);
    std::memcpy(event.ext.data(), bytes.data() + 40, 32);
    return event;
}

void GuestKevent::encode(std::span<std::uint8_t> bytes) const {
    if (bytes.size() < size) {
        throw std::runtime_error("truncated guest kevent_qos_s");
    }
    std::memcpy(bytes.data(), &ident, 8);
    std::memcpy(bytes.data() + 8, &filter, 2);
    std::memcpy(bytes.data() + 10, &flags, 2);
    std::memcpy(bytes.data() + 12, &qos, 4);
    std::memcpy(bytes.data() + 16, &udata, 8);
    std::memcpy(bytes.data() + 24, &fflags, 4);
    std::memcpy(bytes.data() + 28, &xflags, 4);
    std::memcpy(bytes.data() + 32, &data, 8);
    std::memcpy(bytes.data() + 40, ext.data(), 32);
}

std::uint32_t GuestKqueue::bucketFor(std::int32_t qos) const noexcept {
    if (!workqueue_) {
        return 0;
    }
    const auto priority = static_cast<std::uint32_t>(qos);
    if ((priority & pthreadPriorityEventManager) != 0 ||
        (priority & pthreadPrioritySchedulingPriority) != 0) {
        return kqueueManagerBucket;
    }
    const auto bits = (priority & pthreadPriorityValidQosMask) >> 8U;
    // On the workqueue kqueue, outside of QoS means the event manager.
    return bits == 0 ? kqueueManagerBucket : static_cast<std::uint32_t>(std::countr_zero(bits)) + 1;
}

GuestKnote *GuestKqueue::find(const GuestKevent &change) {
    for (auto &knote : knotes_) {
        const auto &registered = knote->registration;
        if (registered.ident == change.ident && registered.filter == change.filter &&
            ((change.flags & evUdataSpecific) == 0 || registered.udata == change.udata)) {
            return knote.get();
        }
    }
    return nullptr;
}

bool GuestKqueue::deliverable(const GuestKnote &knote) const noexcept {
    return knote.active && !knote.disabled && !knote.suppressedBy;
}

int GuestKqueue::attach(GuestKnote &knote, const GuestKevent &change, std::uint64_t now) {
    switch (change.filter) {
    case evfiltUser:
        knote.active = (change.fflags & noteTrigger) != 0;
        return 0;
    case evfiltTimer: {
        TimerParameters parameters;
        if (const auto error = validateTimer(change, now, parameters); error != 0) {
            return error;
        }
        knote.registration.flags |= evClear;
        if ((change.fflags & noteAbsolute) != 0) {
            knote.registration.flags |= evOneshot;
        }
        armTimer(knote, parameters, now);
        return 0;
    }
    case evfiltMachPort:
        // Active while the watched receive right or port set has messages;
        // guest IPC reports that through setMachPortReady.
        knote.active = false;
        return 0;
    default:
        if (inertFilter(change.filter)) {
            return 0;
        }
        std::ostringstream reason;
        reason << "kevent filter " << change.filter << " is not modeled (ident=0x" << std::hex
               << change.ident << " flags=0x" << change.flags << " fflags=0x" << change.fflags
               << " qos=0x" << change.qos << " ext=0x" << change.ext[0] << ",0x" << change.ext[1]
               << ")";
        throw std::runtime_error(reason.str());
    }
}

int GuestKqueue::touch(GuestKnote &knote, const GuestKevent &change, std::uint64_t now) {
    switch (change.filter) {
    case evfiltUser: {
        const auto flags = change.fflags & noteFlagsMask;
        switch (change.fflags & noteFlagsControlMask) {
        case noteFlagsAnd:
            knote.savedFilterFlags &= flags;
            break;
        case noteFlagsOr:
            knote.savedFilterFlags |= flags;
            break;
        case noteFlagsCopy:
            knote.savedFilterFlags = flags;
            break;
        default:
            break;
        }
        knote.savedData = change.data;
        if ((change.fflags & noteTrigger) != 0) {
            knote.active = true;
        }
        return 0;
    }
    case evfiltTimer: {
        if (((knote.savedFilterFlags ^ change.fflags) & noteAbsolute) != 0) {
            return EINVAL;
        }
        TimerParameters parameters;
        if (const auto error = validateTimer(change, now, parameters); error != 0) {
            return error;
        }
        knote.savedFilterFlags = change.fflags;
        armTimer(knote, parameters, now);
        return 0;
    }
    default:
        return 0;
    }
}

int GuestKqueue::registerChange(const GuestKevent &requested, std::uint64_t now) {
    if (requested.filter >= 0 || requested.filter < -evfiltSystemCount) {
        return EINVAL;
    }
    auto change = requested;
    if ((change.flags & evDelete) != 0) {
        change.flags &= static_cast<std::uint16_t>(~evAdd);
    }
    if ((change.flags & evDisable) != 0) {
        change.flags &= static_cast<std::uint16_t>(~evEnable);
    }
    auto *knote = find(change);
    if (knote == nullptr) {
        if ((change.flags & evAdd) == 0) {
            return ENOENT;
        }
        auto created = std::make_unique<GuestKnote>();
        created->registration = change;
        created->savedFilterFlags = change.fflags;
        created->savedData = change.data;
        created->disabled = (change.flags & evDisable) != 0;
        created->bucket = bucketFor(change.qos);
        if (const auto error = attach(*created, change, now); error != 0) {
            return error;
        }
        knotes_.push_back(std::move(created));
        return 0;
    }
    if ((change.flags & evDelete) != 0) {
        std::erase_if(knotes_, [&](const auto &candidate) { return candidate.get() == knote; });
        return 0;
    }
    if (const auto error = touch(*knote, change, now); error != 0) {
        return error;
    }
    if ((knote->registration.flags & evUdataSpecific) == 0) {
        knote->registration.udata = change.udata;
    }
    if ((change.flags & evDisable) != 0) {
        knote->disabled = true;
    }
    if ((change.flags & evEnable) != 0) {
        knote->disabled = false;
    }
    return 0;
}

std::vector<GuestKevent> GuestKqueue::process(std::optional<std::uint32_t> bucket,
                                              std::size_t maximum, std::uint64_t now,
                                              std::optional<std::uint64_t> thread) {
    std::vector<GuestKevent> events;
    std::vector<GuestKnote *> oneshots;
    for (auto &entry : knotes_) {
        if (events.size() == maximum) {
            break;
        }
        auto &knote = *entry;
        if (!deliverable(knote) || (bucket && knote.bucket != *bucket)) {
            continue;
        }
        auto event = knote.registration;
        switch (knote.registration.filter) {
        case evfiltUser:
            event.fflags = knote.savedFilterFlags;
            event.data = knote.savedData;
            if ((knote.registration.flags & evClear) != 0) {
                knote.active = false;
            }
            break;
        case evfiltTimer: {
            // XNU's filt_timerprocess: one expiry, or for an interval timer
            // every whole interval since it was armed, then re-arm.
            event.data = 1;
            event.ext[0] = 0;
            knote.active = false;
            if (knote.timerInterval != 0) {
                const auto firstDeadline = knote.registration.ext[0];
                const auto armedAt = firstDeadline - knote.timerInterval;
                const auto fired = std::max<std::uint64_t>(1, (now - armedAt) / knote.timerInterval);
                event.data = static_cast<std::int64_t>(fired);
                if ((knote.registration.flags & evOneshot) == 0) {
                    knote.registration.ext[0] = firstDeadline + fired * knote.timerInterval;
                    knote.timerDeadline = knote.registration.ext[0];
                }
            }
            break;
        }
        default:
            break;
        }
        events.push_back(event);
        if ((knote.registration.flags & evOneshot) != 0) {
            oneshots.push_back(&knote);
        } else if ((knote.registration.flags & evDispatch) != 0) {
            knote.disabled = true;
        }
        if (thread) {
            knote.suppressedBy = thread;
        }
    }
    std::erase_if(knotes_, [&](const auto &candidate) {
        return std::ranges::find(oneshots, candidate.get()) != oneshots.end();
    });
    return events;
}

void GuestKqueue::unsuppress(std::uint64_t thread) {
    for (auto &knote : knotes_) {
        if (knote->suppressedBy == thread) {
            knote->suppressedBy.reset();
        }
    }
}

void GuestKqueue::setMachPortReady(std::uint64_t port, bool ready) {
    // MACH_RCV_MSG asks the kernel to receive the message into the event.
    constexpr std::uint32_t machReceiveMessage = 0x2;
    for (auto &knote : knotes_) {
        if (knote->registration.filter == evfiltMachPort && knote->registration.ident == port) {
            if (ready && (knote->savedFilterFlags & machReceiveMessage) != 0) {
                std::ostringstream reason;
                reason << "EVFILT_MACHPORT direct receive on port 0x" << std::hex << port
                       << " is not modeled";
                throw std::runtime_error(reason.str());
            }
            knote->active = ready;
        }
    }
}

bool GuestKqueue::expireTimers(std::uint64_t now) {
    bool fired = false;
    for (auto &knote : knotes_) {
        if (knote->timerDeadline && *knote->timerDeadline <= now) {
            knote->timerDeadline.reset();
            knote->active = true;
            fired = true;
        }
    }
    return fired;
}

std::optional<std::uint64_t> GuestKqueue::nextTimerDeadline() const {
    std::optional<std::uint64_t> earliest;
    for (const auto &knote : knotes_) {
        if (knote->timerDeadline) {
            earliest = earliest ? std::min(*earliest, *knote->timerDeadline) : *knote->timerDeadline;
        }
    }
    return earliest;
}

std::optional<std::uint32_t> GuestKqueue::readyBucket() const {
    std::optional<std::uint32_t> best;
    for (const auto &knote : knotes_) {
        if (deliverable(*knote) && (!best || knote->bucket > *best)) {
            best = knote->bucket;
        }
    }
    return best;
}

bool GuestKqueue::hasReadyEvents(std::uint32_t bucket) const {
    return std::ranges::any_of(knotes_, [&](const auto &knote) {
        return deliverable(*knote) && knote->bucket == bucket;
    });
}

} // namespace rosa::darwin
