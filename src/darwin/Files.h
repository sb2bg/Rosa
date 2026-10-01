#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>

namespace rosa::darwin {

struct GuestFileDescriptor {
    std::int32_t value{};

    auto operator<=>(const GuestFileDescriptor &) const = default;
};

enum class GuestFileKind {
    CurrentDirectory,
    RootDirectory,
    SyntheticDirectory,
    HostReadOnlyFile,
    StandardStream,
    RandomDevice,
    UnixDatagramSocket,
};

// What the guest can reach through paths and standard-stream ioctls.
enum class GuestHostAccess {
    // Paths resolve only inside the working directory, and the standard
    // streams answer terminal ioctls as a synthetic 80x24 console. This keeps
    // controlled fixtures independent of how Rosa itself was launched.
    Controlled,
    // The guest reads the host filesystem like an ordinary process and its
    // standard-stream ioctls reach the streams Rosa inherited.
    HostReadOnly,
};

// Owns one host descriptor and closes it when the last owner releases it.
class HostDescriptor {
  public:
    HostDescriptor() = default;
    explicit HostDescriptor(int descriptor) noexcept : descriptor_(descriptor) {}
    HostDescriptor(const HostDescriptor &) = delete;
    HostDescriptor &operator=(const HostDescriptor &) = delete;
    HostDescriptor(HostDescriptor &&other) noexcept;
    HostDescriptor &operator=(HostDescriptor &&other) noexcept;
    ~HostDescriptor();

    [[nodiscard]] int get() const noexcept { return descriptor_; }
    [[nodiscard]] bool valid() const noexcept { return descriptor_ >= 0; }

  private:
    int descriptor_{-1};
};

// One open file description. Every descriptor duplicated from it shares this
// record, so the host file offset and status flags move together as in XNU.
// Host-backed kinds own a real host descriptor; synthetic kinds have none.
struct GuestOpenFile {
    std::uint64_t descriptionId{};
    GuestFileKind kind{};
    std::filesystem::path guestPath;
    std::uint32_t flags{};
    // getdirentries64 resume index for hosted directories. Regular-file
    // positions live in the host descriptor.
    std::uint64_t directoryIndex{0};
    HostDescriptor host;

    [[nodiscard]] bool hostBacked() const noexcept { return host.valid(); }
};

// The guest descriptor table. Descriptors are allocated lowest-free, and a
// new task inherits Rosa's standard streams as descriptors 0, 1, and 2.
class GuestFileSpace {
  public:
    GuestFileSpace();
    explicit GuestFileSpace(std::filesystem::path currentDirectory);

    void setHostAccess(GuestHostAccess access) noexcept { hostAccess_ = access; }
    [[nodiscard]] GuestHostAccess hostAccess() const noexcept { return hostAccess_; }
    // The single path policy: may the guest observe this canonical host path?
    [[nodiscard]] bool permitsHostPath(const std::filesystem::path &canonicalPath) const;

    [[nodiscard]] GuestFileDescriptor openCurrentDirectory(std::uint32_t flags);
    [[nodiscard]] GuestFileDescriptor openRootDirectory(std::uint32_t flags);
    [[nodiscard]] GuestFileDescriptor openSyntheticDirectory(
        std::filesystem::path guestPath, std::uint32_t flags);
    // Adopts an already opened host descriptor for a canonical host path.
    [[nodiscard]] GuestFileDescriptor openHostFile(std::filesystem::path canonicalPath,
                                                   std::uint32_t flags, HostDescriptor host);
    [[nodiscard]] GuestFileDescriptor openRandomDevice(std::uint32_t flags);
    [[nodiscard]] GuestFileDescriptor openUnixDatagramSocket();
    // Returns the lowest free descriptor at or above minimum sharing the
    // source's open file description, or nullopt for a closed source.
    [[nodiscard]] std::optional<GuestFileDescriptor> duplicate(
        GuestFileDescriptor descriptor, std::int32_t minimum = 0, bool closeOnExec = false);
    [[nodiscard]] const GuestOpenFile *lookup(
        GuestFileDescriptor descriptor) const noexcept;
    [[nodiscard]] GuestOpenFile *lookupMutable(
        GuestFileDescriptor descriptor) noexcept;
    [[nodiscard]] std::optional<bool> closeOnExec(GuestFileDescriptor descriptor) const noexcept;
    [[nodiscard]] bool setCloseOnExec(GuestFileDescriptor descriptor, bool enabled) noexcept;
    [[nodiscard]] bool close(GuestFileDescriptor descriptor) noexcept;

    [[nodiscard]] const std::filesystem::path &currentDirectory() const noexcept {
        return currentDirectory_;
    }
    [[nodiscard]] std::size_t size() const noexcept { return descriptors_.size(); }

  private:
    struct DescriptorEntry {
        std::shared_ptr<GuestOpenFile> description;
        bool closeOnExec{};
    };

    [[nodiscard]] GuestFileDescriptor lowestFreeDescriptor(std::int32_t minimum) const;
    [[nodiscard]] GuestFileDescriptor install(GuestOpenFile file, bool closeOnExec = false,
                                              std::int32_t minimum = 0);
    void inheritStandardStreams();

    std::filesystem::path currentDirectory_;
    std::map<GuestFileDescriptor, DescriptorEntry> descriptors_;
    std::uint64_t nextDescriptionId_{1};
    GuestHostAccess hostAccess_{GuestHostAccess::Controlled};
};

} // namespace rosa::darwin
