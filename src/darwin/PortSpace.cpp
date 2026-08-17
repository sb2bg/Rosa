#include "darwin/PortSpace.h"

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
    attributes.hasReceiveRight = true;
    ports_.emplace(candidate, attributes);
    nextSyntheticName_ = candidate + syntheticNameStride;
    return attributes.name;
}

void GuestPortSpace::rollbackLastAllocation(GuestMachPortName name) noexcept {
    const auto found = ports_.find(name.value);
    if (found == ports_.end() || name == taskSelfName) {
        return;
    }
    ports_.erase(found);
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
        stream << "\n    name=0x" << std::hex << name << std::dec
               << " type="
               << (port.type == GuestPortType::Reply ? "reply" : "ordinary")
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
