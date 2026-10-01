#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace rosa::darwin {

struct GuestMachPortName {
    std::uint32_t value{};

    auto operator<=>(const GuestMachPortName &) const = default;
};

enum class GuestPortType : std::uint8_t {
    Ordinary,
    Reply,
    Host,
    Thread,
    Bootstrap,
    Clock,
    Semaphore,
    PortSet,
    Timer,
};

enum class GuestPortDeallocateResult : std::uint8_t {
    Success,
    InvalidName,
    InvalidRight,
};

// A message queued on a guest receive right, already in the form the
// receiver sees: header bits with the reply and destination types as
// received, port descriptors rewritten, out-of-line memory carried as bytes.
struct GuestMachMessage {
    std::uint32_t bits{};
    GuestMachPortName replyPort;
    std::int32_t id{};
    // Everything after the 24-byte header, descriptors included.
    std::vector<std::uint8_t> body;
    struct OutOfLine {
        // Offset of the descriptor's address field within `body`.
        std::size_t addressOffset{};
        std::vector<std::uint8_t> bytes;
    };
    std::vector<OutOfLine> outOfLine;
    // Task-wide arrival order, for receiving from a port set.
    std::uint64_t arrival{};
};

struct GuestPort {
    GuestMachPortName name;
    GuestPortType type{GuestPortType::Ordinary};
    bool hasReceiveRight{};
    std::uint32_t sendUrefs{};
    std::uint32_t sendOnceUrefs{};
    std::uint64_t context{};
    std::uint32_t queueLimit{};
    bool guarded{};
    std::uint64_t guard{};
    bool strictGuard{};
    bool importanceReceiver{};
    std::uint32_t optionFlags{};
    std::vector<GuestMachPortName> members{};
    std::deque<GuestMachMessage> messages{};
    std::uint32_t sequenceNumber{};
    // A dead name: the port's receive right was destroyed while this space
    // still held send rights to it.
    bool dead{};
    // An armed mk_timer's deadline, in guest mach_absolute_time units.
    std::optional<std::uint64_t> timerDeadline{};
};

class GuestPortSpace {
  public:
    static constexpr GuestMachPortName taskSelfName{0x103U};

    GuestPortSpace();

    [[nodiscard]] const GuestPort *lookup(GuestMachPortName name) const;
    [[nodiscard]] GuestPort *lookup(GuestMachPortName name);
    [[nodiscard]] bool ownsReceiveRight(GuestMachPortName name) const;
    [[nodiscard]] std::optional<GuestMachPortName>
    allocateReceiveRight(GuestPort attributes = {});
    [[nodiscard]] std::optional<GuestMachPortName>
    copyoutHostSendRight(std::uint32_t maximumUrefs);
    // Each guest thread has one thread object; its port's context is the
    // guest thread id.
    [[nodiscard]] std::optional<GuestMachPortName>
    copyoutThreadSendRight(std::uint64_t threadId, std::uint32_t maximumUrefs);
    [[nodiscard]] std::optional<GuestMachPortName> threadPortName(std::uint64_t threadId) const;
    [[nodiscard]] std::optional<GuestMachPortName>
    copyoutBootstrapSendRight(std::uint32_t maximumUrefs);
    [[nodiscard]] std::optional<GuestMachPortName>
    copyoutClockSendRight(std::uint32_t clockId, std::uint32_t maximumUrefs);
    [[nodiscard]] std::optional<GuestMachPortName>
    allocateSemaphoreSendRight(std::uint32_t policy, std::int32_t value);
    [[nodiscard]] GuestPortDeallocateResult
    deallocateUref(GuestMachPortName name);
    void rollbackLastAllocation(GuestMachPortName name) noexcept;

    template <typename Visit> void forEachPort(Visit visit) {
        for (auto &[name, port] : ports_) {
            visit(port);
        }
    }

    // Removes `member` from every port set.
    void removeFromPortSets(GuestMachPortName member);
    // Drops an entry that holds no rights.
    void eraseIfEmpty(GuestMachPortName name);

    // The port sets that hold `member`.
    [[nodiscard]] std::vector<GuestMachPortName> portSetsContaining(GuestMachPortName member) const;

    [[nodiscard]] std::size_t size() const noexcept { return ports_.size(); }
    [[nodiscard]] std::string summary() const;

  private:
    static constexpr std::uint32_t syntheticNameStride = 0x100U;

    [[nodiscard]] std::optional<GuestMachPortName>
    allocatePort(GuestPort attributes);

    std::map<std::uint32_t, GuestPort> ports_;
    std::uint32_t nextSyntheticName_{0x203U};
    std::optional<GuestMachPortName> hostSelfName_;
    std::map<std::uint64_t, GuestMachPortName> threadNames_;
    std::optional<GuestMachPortName> bootstrapName_;
    std::map<std::uint32_t, GuestMachPortName> clockServiceNames_;
};

} // namespace rosa::darwin
