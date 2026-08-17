#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>

namespace rosa::darwin {

struct GuestFileDescriptor {
    std::int32_t value{};

    auto operator<=>(const GuestFileDescriptor &) const = default;
};

enum class GuestFileKind {
    CurrentDirectory,
};

struct GuestOpenFile {
    GuestFileDescriptor descriptor;
    GuestFileKind kind{};
    std::filesystem::path guestPath;
    std::uint32_t flags{};
};

// Task-local guest descriptors are metadata owned by Rosa. They are never
// interpreted as host descriptors without an explicit future bridge.
class GuestFileSpace {
  public:
    GuestFileSpace();
    explicit GuestFileSpace(std::filesystem::path currentDirectory);

    [[nodiscard]] GuestFileDescriptor openCurrentDirectory(
        std::uint32_t flags);
    [[nodiscard]] const GuestOpenFile *lookup(
        GuestFileDescriptor descriptor) const noexcept;
    [[nodiscard]] bool close(GuestFileDescriptor descriptor) noexcept;

    [[nodiscard]] const std::filesystem::path &currentDirectory() const noexcept {
        return currentDirectory_;
    }
    [[nodiscard]] std::size_t size() const noexcept { return files_.size(); }

  private:
    std::filesystem::path currentDirectory_;
    std::map<GuestFileDescriptor, GuestOpenFile> files_;
    std::int32_t nextDescriptor_{3};
};

} // namespace rosa::darwin
