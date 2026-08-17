#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace rosa::darwin {

struct GuestMachPortName {
    std::uint32_t value{};

    auto operator<=>(const GuestMachPortName &) const = default;
};

enum class GuestPortType : std::uint8_t {
    Ordinary,
    Reply,
    Host,
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
    void rollbackLastAllocation(GuestMachPortName name) noexcept;

    [[nodiscard]] std::size_t size() const noexcept { return ports_.size(); }
    [[nodiscard]] std::string summary() const;

  private:
    static constexpr std::uint32_t syntheticNameStride = 0x100U;

    [[nodiscard]] std::optional<GuestMachPortName>
    allocatePort(GuestPort attributes);

    std::map<std::uint32_t, GuestPort> ports_;
    std::uint32_t nextSyntheticName_{0x203U};
    std::optional<GuestMachPortName> hostSelfName_;
};

} // namespace rosa::darwin
