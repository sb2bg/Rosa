#include "darwin/PortSpace.h"

#include <bit>
#include <iomanip>
#include <limits>
#include <sstream>

namespace rosa::darwin {

GuestPortSpace::GuestPortSpace() {
    GuestPort taskSelf;
    taskSelf.name = taskSelfName;
    ports_.emplace(taskSelf.name.value, taskSelf);
}

const GuestPort *GuestPortSpace::lookup(GuestMachPortName name) const {
    const auto found = ports_.find(name.value);
    return found == ports_.end() ? nullptr : &found->second;
}

GuestPort *GuestPortSpace::lookup(GuestMachPortName name) {
    const auto found = ports_.find(name.value);
    return found == ports_.end() ? nullptr : &found->second;
}

bool GuestPortSpace::ownsReceiveRight(GuestMachPortName name) const {
    const auto *port = lookup(name);
    return port != nullptr && port->hasReceiveRight;
}

std::optional<GuestMachPortName>
GuestPortSpace::allocateReceiveRight(GuestPort attributes) {
    attributes.hasReceiveRight = true;
    return allocatePort(attributes);
}

std::optional<GuestMachPortName>
GuestPortSpace::copyoutHostSendRight(std::uint32_t maximumUrefs) {
    if (hostSelfName_) {
        auto *port = lookup(*hostSelfName_);
        if (port == nullptr || port->type != GuestPortType::Host ||
            port->sendUrefs == 0) {
            return std::nullopt;
        }
        if (port->sendUrefs == maximumUrefs) {
            return std::nullopt;
        }
        ++port->sendUrefs;
        return hostSelfName_;
    }

    GuestPort host;
    host.type = GuestPortType::Host;
    host.sendUrefs = 1;
    hostSelfName_ = allocatePort(host);
    return hostSelfName_;
}

std::optional<GuestMachPortName>
GuestPortSpace::copyoutThreadSendRight(std::uint32_t maximumUrefs) {
    if (threadSelfName_) {
        auto *port = lookup(*threadSelfName_);
        if (port == nullptr || port->type != GuestPortType::Thread ||
            port->sendUrefs == 0) {
            return std::nullopt;
        }
        if (port->sendUrefs == maximumUrefs) {
            return std::nullopt;
        }
        ++port->sendUrefs;
        return threadSelfName_;
    }

    GuestPort thread;
    thread.type = GuestPortType::Thread;
    thread.sendUrefs = 1;
    threadSelfName_ = allocatePort(thread);
    return threadSelfName_;
}

std::optional<GuestMachPortName>
GuestPortSpace::copyoutBootstrapSendRight(std::uint32_t maximumUrefs) {
    if (bootstrapName_) {
        auto *port = lookup(*bootstrapName_);
        if (port == nullptr || port->type != GuestPortType::Bootstrap ||
            port->sendUrefs == 0 || port->sendUrefs == maximumUrefs) {
            return std::nullopt;
        }
        ++port->sendUrefs;
        return bootstrapName_;
    }

    GuestPort bootstrap;
    bootstrap.type = GuestPortType::Bootstrap;
    bootstrap.sendUrefs = 1;
    bootstrapName_ = allocatePort(bootstrap);
    return bootstrapName_;
}

std::optional<GuestMachPortName>
GuestPortSpace::copyoutClockSendRight(std::uint32_t clockId,
                                     std::uint32_t maximumUrefs) {
    const auto existing = clockServiceNames_.find(clockId);
    if (existing != clockServiceNames_.end()) {
        auto *port = lookup(existing->second);
        if (port == nullptr || port->type != GuestPortType::Clock ||
            port->context != clockId || port->sendUrefs == 0) {
            return std::nullopt;
        }
        if (port->sendUrefs == maximumUrefs) {
            return std::nullopt;
        }
        ++port->sendUrefs;
        return existing->second;
    }

    GuestPort clock;
    clock.type = GuestPortType::Clock;
    clock.context = clockId;
    clock.sendUrefs = 1;
    const auto name = allocatePort(clock);
    if (name) {
        clockServiceNames_.emplace(clockId, *name);
    }
    return name;
}

std::optional<GuestMachPortName>
GuestPortSpace::allocateSemaphoreSendRight(std::uint32_t policy,
                                           std::int32_t value) {
    GuestPort semaphore;
    semaphore.type = GuestPortType::Semaphore;
    semaphore.sendUrefs = 1;
    semaphore.context = std::bit_cast<std::uint32_t>(value);
    semaphore.optionFlags = policy;
    return allocatePort(semaphore);
}

GuestPortDeallocateResult
GuestPortSpace::deallocateUref(GuestMachPortName name) {
    // MACH_PORT_NULL and MACH_PORT_DEAD are accepted no-ops by XNU's
    // mach_port_deallocate_kernel path.
    if (name.value == 0 || name.value == UINT32_MAX) {
        return GuestPortDeallocateResult::Success;
    }
    auto found = ports_.find(name.value);
    if (found == ports_.end()) {
        return GuestPortDeallocateResult::InvalidName;
    }
    auto &port = found->second;
    if (port.sendUrefs != 0) {
        --port.sendUrefs;
    } else if (port.sendOnceUrefs != 0) {
        --port.sendOnceUrefs;
    } else {
        return GuestPortDeallocateResult::InvalidRight;
    }

    if (name != taskSelfName && !port.hasReceiveRight &&
        port.sendUrefs == 0 && port.sendOnceUrefs == 0) {
        if (hostSelfName_ == name) {
            hostSelfName_.reset();
        }
        if (threadSelfName_ == name) {
            threadSelfName_.reset();
        }
        if (bootstrapName_ == name) {
            bootstrapName_.reset();
        }
        if (port.type == GuestPortType::Clock) {
            clockServiceNames_.erase(static_cast<std::uint32_t>(port.context));
        }
        ports_.erase(found);
    }
    return GuestPortDeallocateResult::Success;
}

std::optional<GuestMachPortName>
GuestPortSpace::allocatePort(GuestPort attributes) {
    auto candidate = nextSyntheticName_;
    while (ports_.contains(candidate)) {
        if (candidate > std::numeric_limits<std::uint32_t>::max() -
                            syntheticNameStride) {
            return std::nullopt;
        }
        candidate += syntheticNameStride;
    }
    if (candidate > std::numeric_limits<std::uint32_t>::max() -
                        syntheticNameStride) {
        return std::nullopt;
    }

    attributes.name = GuestMachPortName{candidate};
    ports_.emplace(candidate, attributes);
    nextSyntheticName_ = candidate + syntheticNameStride;
    return attributes.name;
}

void GuestPortSpace::rollbackLastAllocation(GuestMachPortName name) noexcept {
    const auto found = ports_.find(name.value);
    if (found == ports_.end() || name == taskSelfName) {
        return;
    }
    if (found->second.type == GuestPortType::Clock) {
        clockServiceNames_.erase(
            static_cast<std::uint32_t>(found->second.context));
    }
    ports_.erase(found);
    if (hostSelfName_ == name) {
        hostSelfName_.reset();
    }
    if (threadSelfName_ == name) {
        threadSelfName_.reset();
    }
    if (bootstrapName_ == name) {
        bootstrapName_.reset();
    }
    if (name.value <= std::numeric_limits<std::uint32_t>::max() -
                          syntheticNameStride &&
        name.value + syntheticNameStride == nextSyntheticName_) {
        nextSyntheticName_ = name.value;
    }
}

std::string GuestPortSpace::summary() const {
    std::ostringstream stream;
    stream << "ports=" << ports_.size();
    for (const auto &[name, port] : ports_) {
        const auto type =
            port.type == GuestPortType::Reply       ? "reply"
            : port.type == GuestPortType::Host      ? "host"
            : port.type == GuestPortType::Thread    ? "thread"
            : port.type == GuestPortType::Bootstrap ? "bootstrap"
            : port.type == GuestPortType::Clock     ? "clock"
            : port.type == GuestPortType::Semaphore ? "semaphore"
                                                     : "ordinary";
        stream << "\n    name=0x" << std::hex << name << std::dec
               << " type=" << type
               << " receive=" << (port.hasReceiveRight ? "yes" : "no")
               << " send-urefs=" << port.sendUrefs
               << " send-once-urefs=" << port.sendOnceUrefs
               << " qlimit=" << port.queueLimit
               << " context=0x" << std::hex << port.context << std::dec;
        if (port.guarded) {
            stream << " guard=0x" << std::hex << port.guard << std::dec
                   << " strict=" << (port.strictGuard ? "yes" : "no");
        }
        if (port.importanceReceiver) {
            stream << " importance-receiver=yes";
        }
    }
    return stream.str();
}

} // namespace rosa::darwin
