#pragma once

#include "guest/Address.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rosa::macho {

inline constexpr std::uint32_t lcSegment64 = 0x19;
inline constexpr std::uint32_t lcUnixThread = 0x5;
inline constexpr std::uint32_t lcMain = 0x80000028U;
inline constexpr std::uint32_t mhExecute = 0x2;
inline constexpr std::uint32_t mhDylinker = 0x7;

struct Segment {
    std::string name;
    guest::GuestAddress virtualAddress{};
    std::uint64_t virtualSize{};
    std::uint64_t fileOffset{};
    std::uint64_t fileSize{};
    std::uint32_t maximumProtection{};
    std::uint32_t initialProtection{};
};

struct LoadCommand {
    std::uint32_t command{};
    std::uint32_t size{};
    std::size_t fileOffset{};
};

class MachOFile {
  public:
    static MachOFile open(const std::filesystem::path &path);
    static MachOFile parse(std::vector<std::uint8_t> bytes);

    [[nodiscard]] std::uint32_t cpuType() const noexcept { return cpuType_; }
    [[nodiscard]] std::uint32_t fileType() const noexcept { return fileType_; }
    [[nodiscard]] const std::vector<Segment> &segments() const noexcept { return segments_; }
    [[nodiscard]] const std::vector<LoadCommand> &loadCommands() const noexcept {
        return loadCommands_;
    }
    [[nodiscard]] guest::GuestAddress entryPoint() const;
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return bytes_; }

  private:
    std::vector<std::uint8_t> bytes_;
    std::uint32_t cpuType_{};
    std::uint32_t fileType_{};
    std::vector<Segment> segments_;
    std::vector<LoadCommand> loadCommands_;
    std::optional<std::uint64_t> mainEntryFileOffset_;
    std::optional<guest::GuestAddress> unixThreadEntry_;
};

[[nodiscard]] std::string loadCommandName(std::uint32_t command);

} // namespace rosa::macho
