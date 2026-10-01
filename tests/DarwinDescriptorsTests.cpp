#include "TestSupport.h"
#include "TestSuite.h"
#include "TemporaryFile.h"

#include <sys/attr.h>

#include <fstream>
#include <initializer_list>

namespace rosa::tests {
namespace {

constexpr std::uint64_t readNumber = 0x02000003;
constexpr std::uint64_t writeNumber = 0x02000004;
constexpr std::uint64_t openNumber = 0x02000005;
constexpr std::uint64_t closeNumber = 0x02000006;
constexpr std::uint64_t dupNumber = 0x02000029;
constexpr std::uint64_t fcntlNumber = 0x0200005C;
constexpr std::uint64_t lseekNumber = 0x020000C7;
constexpr std::uint64_t fcntlNoCancelNumber = 0x02000196;
constexpr std::uint64_t stat64Number = 0x02000152;
constexpr std::uint64_t lstat64Number = 0x02000154;
constexpr std::uint64_t fstatat64Number = 0x020001D6;
constexpr std::uint64_t getattrlistbulkNumber = 0x020001CD;
constexpr rosa::guest::GuestAddress secondPathAddress{0x8800};
constexpr rosa::guest::GuestAddress statAddress{0x9400};
constexpr rosa::guest::GuestAddress pathAddress{0x8000};
constexpr rosa::guest::GuestAddress bufferAddress{0x9000};

struct SyscallResult {
    std::uint64_t value{};
    bool failed{};
};

// One guest task with scratch memory for a path and an I/O buffer.
class GuestTaskFixture {
  public:
    GuestTaskFixture() {
        addressSpace.mapAnonymous(pathAddress, rosa::guest::guestPageSize * 2,
                                  rosa::guest::Permission::Read | rosa::guest::Permission::Write);
    }

    SyscallResult call(std::uint64_t number, std::initializer_list<std::uint64_t> arguments) {
        rosa::x86::X86State state;
        std::array<std::uint64_t, 6> registers{};
        std::ranges::copy(arguments, registers.begin());
        state.rax = number;
        state.rdi = registers[0];
        state.rsi = registers[1];
        state.rdx = registers[2];
        state.r10 = registers[3];
        state.rflags = 0x2;
        static_cast<void>(
            dispatcher.dispatch(addressSpace, state, rosa::guest::GuestAddress{0x1000}));
        return {state.rax, (state.rflags & 1U) != 0};
    }

    std::uint64_t open(const std::filesystem::path &path, std::uint64_t flags = O_RDONLY) {
        const auto text = path.string();
        std::vector<std::uint8_t> bytes(text.begin(), text.end());
        bytes.push_back(0);
        addressSpace.writeBytes(pathAddress, bytes);
        const auto result = call(openNumber, {pathAddress.value, flags, 0});
        expect(!result.failed, "fixture open failed");
        return result.value;
    }

    std::string read(std::uint64_t descriptor, std::uint64_t count) {
        const auto result = call(readNumber, {descriptor, bufferAddress.value, count});
        expect(!result.failed, "fixture read failed");
        const auto bytes = addressSpace.readBytes(bufferAddress, result.value);
        return {bytes.begin(), bytes.end()};
    }

    rosa::guest::AddressSpace addressSpace;
    rosa::darwin::SyscallDispatcher dispatcher;
};

void writeFixture(const std::filesystem::path &path, std::string_view contents) {
    std::ofstream stream(path, std::ios::binary);
    stream << contents;
}

// A directory holding file.txt and link.txt -> file.txt, removed on exit.
class LinkFixture {
  public:
    LinkFixture() {
        std::string pattern = (std::filesystem::current_path() / ".rosa-test-dir-XXXXXX").string();
        if (::mkdtemp(pattern.data()) == nullptr) {
            throw std::runtime_error("cannot create temporary test directory");
        }
        path_ = pattern;
        writeFixture(path_ / "file.txt", "contents");
        std::filesystem::create_symlink("file.txt", path_ / "link.txt");
    }
    ~LinkFixture() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    LinkFixture(const LinkFixture &) = delete;
    LinkFixture &operator=(const LinkFixture &) = delete;

    [[nodiscard]] const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

void writeGuestString(GuestTaskFixture &task, rosa::guest::GuestAddress address,
                      const std::string &text) {
    std::vector<std::uint8_t> bytes(text.begin(), text.end());
    bytes.push_back(0);
    task.addressSpace.writeBytes(address, bytes);
}

std::uint16_t statMode(GuestTaskFixture &task) {
    std::uint16_t mode = 0;
    std::memcpy(&mode,
                task.addressSpace.readBytes(rosa::guest::GuestAddress{statAddress.value + 4}, 2)
                    .data(),
                sizeof(mode));
    return mode;
}

void testDuplicatedDescriptorsShareTheFileOffset() {
    const TemporaryFile file(std::filesystem::current_path());
    writeFixture(file.path(), "abcdef");
    GuestTaskFixture task;
    const auto original = task.open(file.path());
    const auto duplicate = task.call(dupNumber, {original});
    expect(!duplicate.failed, "dup failed");

    expectEqual(task.read(original, 2), std::string{"ab"}, "first read differs");
    expectEqual(task.read(duplicate.value, 2), std::string{"cd"},
                "dup did not continue from the shared offset");
    expectEqual(task.call(lseekNumber, {original, 0, SEEK_CUR}).value, std::uint64_t{4},
                "lseek did not observe the shared offset");

    // The open file description outlives any one of its descriptors.
    expect(!task.call(closeNumber, {original}).failed, "close failed");
    expectEqual(task.read(duplicate.value, 8), std::string{"ef"},
                "closing one descriptor ended the shared description");
}

void testDescriptorsAllocateLowestFree() {
    const TemporaryFile file(std::filesystem::current_path());
    GuestTaskFixture task;
    const auto first = task.open(file.path());
    const auto second = task.open(file.path());
    expectEqual(second, first + 1, "second open was not the next descriptor");
    expect(!task.call(closeNumber, {first}).failed, "close failed");
    expectEqual(task.open(file.path()), first, "open did not reuse the lowest free descriptor");

    constexpr std::uint64_t dupFd = 0;
    constexpr std::uint64_t getFd = 1;
    constexpr std::uint64_t setFd = 2;
    constexpr std::uint64_t dupFdCloseOnExec = 67;
    const auto high = task.call(fcntlNumber, {second, dupFd, 10});
    expectEqual(high.value, std::uint64_t{10}, "F_DUPFD ignored its minimum");
    expectEqual(task.call(fcntlNumber, {10, getFd}).value, std::uint64_t{0},
                "F_DUPFD inherited close-on-exec");

    // Close-on-exec belongs to the descriptor, not the shared description.
    expect(!task.call(fcntlNumber, {10, setFd, FD_CLOEXEC}).failed, "F_SETFD failed");
    expectEqual(task.call(fcntlNumber, {10, getFd}).value, std::uint64_t{FD_CLOEXEC},
                "F_SETFD did not set close-on-exec");
    expectEqual(task.call(fcntlNumber, {second, getFd}).value, std::uint64_t{0},
                "F_SETFD leaked to a sibling descriptor");
    const auto cloexec = task.call(fcntlNumber, {second, dupFdCloseOnExec, 0});
    expectEqual(cloexec.value, second + 1, "F_DUPFD_CLOEXEC skipped the lowest free descriptor");
    expectEqual(task.call(fcntlNumber, {cloexec.value, getFd}).value, std::uint64_t{FD_CLOEXEC},
                "F_DUPFD_CLOEXEC did not set close-on-exec");
}

void testHostDescriptorsReportHostErrors() {
    const TemporaryFile file(std::filesystem::current_path());
    GuestTaskFixture task;
    // A directory opened without O_DIRECTORY succeeds and refuses to read,
    // which is how grep reports "Is a directory".
    const auto directory = task.open(".");
    const auto directoryRead = task.call(readNumber, {directory, bufferAddress.value, 16});
    expect(directoryRead.failed, "read of a directory succeeded");
    expectEqual(directoryRead.value, static_cast<std::uint64_t>(EISDIR),
                "read of a directory returned the wrong errno");

    const auto readOnly = task.open(file.path());
    const auto writeResult = task.call(writeNumber, {readOnly, bufferAddress.value, 1});
    expect(writeResult.failed, "write to a read-only descriptor succeeded");
    expectEqual(writeResult.value, static_cast<std::uint64_t>(EBADF),
                "write to a read-only descriptor returned the wrong errno");
}

void testHostAccessPolicyGovernsPaths() {
    const TemporaryFile file(std::filesystem::temp_directory_path());
    writeFixture(file.path(), "outside");
    const auto canonical = std::filesystem::canonical(file.path());
    if (canonical.string().starts_with(std::filesystem::current_path().string())) {
        return; // The runner's temporary directory is inside the working directory.
    }
    GuestTaskFixture task;
    bool confined = false;
    try {
        static_cast<void>(task.open(canonical));
    } catch (const std::runtime_error &error) {
        confined = std::string_view(error.what()).find("no mapping") != std::string_view::npos;
    }
    expect(confined, "a controlled guest opened a path outside its working directory");

    task.dispatcher.setHostAccess(rosa::darwin::GuestHostAccess::HostReadOnly);
    const auto descriptor = task.open(canonical);
    expectEqual(task.read(descriptor, 16), std::string{"outside"},
                "a host-access guest could not read a host file");
}

void testAdvisoryLocksReachTheHost() {
    // Observed under cat -l: F_SETLKW on standard output, via fcntl_nocancel.
    const TemporaryFile file(std::filesystem::current_path());
    GuestTaskFixture task;
    const auto descriptor = task.open(file.path());
    constexpr std::uint64_t getLock = 7;
    constexpr std::uint64_t setLockWait = 9;
    // struct flock {off_t start, off_t len, pid_t pid, short type, short whence}.
    constexpr rosa::guest::GuestAddress lockAddress{0x9800};
    const auto writeLock = [&](std::int16_t type) {
        std::array<std::uint8_t, 24> lock{};
        std::memcpy(lock.data() + 20, &type, sizeof(type));
        task.addressSpace.writeBytes(lockAddress, lock);
    };
    writeLock(F_RDLCK);
    expect(!task.call(fcntlNoCancelNumber, {descriptor, setLockWait, lockAddress.value}).failed,
           "F_SETLKW through fcntl_nocancel failed");

    // F_GETLK reports no conflict to the lock owner and copies the record back.
    writeLock(F_WRLCK);
    expect(!task.call(fcntlNumber, {descriptor, getLock, lockAddress.value}).failed,
           "F_GETLK failed");
    std::int16_t type = 0;
    std::memcpy(&type, task.addressSpace.readBytes(
                           rosa::guest::GuestAddress{lockAddress.value + 20}, 2).data(),
                sizeof(type));
    expectEqual(type, static_cast<std::int16_t>(F_UNLCK), "F_GETLK did not copy out the result");
}

void testMetadataQueriesKeepSymlinkIdentity() {
    const LinkFixture fixture;
    GuestTaskFixture task;
    const auto link = (fixture.path() / "link.txt").string();
    writeGuestString(task, pathAddress, link);

    expect(!task.call(lstat64Number, {pathAddress.value, statAddress.value}).failed,
           "lstat64 of a symlink failed");
    expect(S_ISLNK(statMode(task)), "lstat64 followed the final symlink");
    expect(!task.call(stat64Number, {pathAddress.value, statAddress.value}).failed,
           "stat64 of a symlink failed");
    expect(S_ISREG(statMode(task)), "stat64 did not follow the final symlink");

    // Observed under grep -r: fts stats entries with fstatat64(AT_FDCWD, ...).
    constexpr std::uint64_t atCurrentDirectory = 0xFFFFFFFE;
    constexpr std::uint64_t symlinkNoFollow = 0x20;
    expect(!task.call(fstatat64Number,
                      {atCurrentDirectory, pathAddress.value, statAddress.value, symlinkNoFollow})
                .failed,
           "fstatat64 AT_SYMLINK_NOFOLLOW failed");
    expect(S_ISLNK(statMode(task)), "fstatat64 AT_SYMLINK_NOFOLLOW followed the symlink");

    // A relative path resolves against the directory descriptor.
    const auto directory = task.open(fixture.path(), O_RDONLY | O_DIRECTORY);
    writeGuestString(task, secondPathAddress, "link.txt");
    expect(!task.call(fstatat64Number, {directory, secondPathAddress.value, statAddress.value, 0})
                .failed,
           "fstatat64 relative to a directory descriptor failed");
    expect(S_ISREG(statMode(task)), "fstatat64 relative lookup did not follow the symlink");

    const auto missing = task.call(lstat64Number, {secondPathAddress.value, statAddress.value});
    expect(missing.failed && missing.value == ENOENT,
           "a relative lstat64 resolved against the directory descriptor");
}

void testOpenNoFollowRefusesSymlink() {
    const LinkFixture fixture;
    GuestTaskFixture task;
    writeGuestString(task, pathAddress, (fixture.path() / "link.txt").string());
    const auto result = task.call(openNumber, {pathAddress.value, O_RDONLY | O_NOFOLLOW, 0});
    expect(result.failed, "O_NOFOLLOW opened a symlink");
    expectEqual(result.value, static_cast<std::uint64_t>(ELOOP),
                "O_NOFOLLOW on a symlink returned the wrong errno");
    expectEqual(guestOpenedDescriptors(task.dispatcher), std::size_t{0},
                "a refused open allocated a descriptor");
}

void testGetattrlistbulkListsDirectory() {
    // Observed under grep -r: macOS fts reads directories with getattrlistbulk.
    const LinkFixture fixture;
    GuestTaskFixture task;
    const auto directory = task.open(fixture.path(), O_RDONLY | O_DIRECTORY);
    struct attrlist attributes {};
    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME;
    constexpr rosa::guest::GuestAddress listAddress{0x9600};
    task.addressSpace.writeBytes(listAddress,
                                 std::span<const std::uint8_t>{
                                     reinterpret_cast<const std::uint8_t *>(&attributes),
                                     sizeof(attributes)});
    std::vector<std::string> names;
    for (int round = 0; round < 4; ++round) {
        const auto result = task.call(getattrlistbulkNumber,
                                      {directory, listAddress.value, bufferAddress.value, 0x400});
        expect(!result.failed, "getattrlistbulk failed");
        if (result.value == 0) {
            break;
        }
        std::uint64_t offset = 0;
        for (std::uint64_t entry = 0; entry < result.value; ++entry) {
            const auto base = bufferAddress.value + offset;
            const auto length = task.addressSpace.readU32(rosa::guest::GuestAddress{base});
            // length, attribute_set_t (20 bytes), then the name reference.
            const auto referenceAddress = base + 4 + sizeof(attribute_set_t);
            const auto dataOffset = static_cast<std::int32_t>(
                task.addressSpace.readU32(rosa::guest::GuestAddress{referenceAddress}));
            const auto nameLength =
                task.addressSpace.readU32(rosa::guest::GuestAddress{referenceAddress + 4});
            const auto name = task.addressSpace.readBytes(
                rosa::guest::GuestAddress{referenceAddress + static_cast<std::uint64_t>(dataOffset)},
                nameLength - 1);
            names.emplace_back(name.begin(), name.end());
            offset += length;
        }
    }
    std::ranges::sort(names);
    expect(names == std::vector<std::string>{"file.txt", "link.txt"},
           "getattrlistbulk did not list the directory entries");
}

void testInheritedStandardInputIsReadable() {
    std::array<int, 2> pipe{};
    expect(::pipe(pipe.data()) == 0, "cannot create a standard-input pipe");
    const int savedInput = ::dup(STDIN_FILENO);
    expect(savedInput >= 0, "cannot save standard input");
    ::dup2(pipe[0], STDIN_FILENO);
    ::close(pipe[0]);
    // The task inherits whatever standard input is at construction time.
    GuestTaskFixture task;
    ::dup2(savedInput, STDIN_FILENO);
    ::close(savedInput);

    constexpr std::string_view message = "beta\n";
    expect(::write(pipe[1], message.data(), message.size()) ==
               static_cast<ssize_t>(message.size()),
           "cannot fill the standard-input pipe");
    ::close(pipe[1]);
    expectEqual(task.read(STDIN_FILENO, 64), std::string{message},
                "guest standard input did not read the inherited stream");
    expectEqual(task.read(STDIN_FILENO, 64), std::string{},
                "guest standard input did not reach end of file");
}

} // namespace

std::span<const TestCase> darwinDescriptorsTests() {
    static const TestCase cases[]{
        {"duplicated descriptors share the file offset",
         testDuplicatedDescriptorsShareTheFileOffset},
        {"descriptors allocate lowest free", testDescriptorsAllocateLowestFree},
        {"host descriptors report host errors", testHostDescriptorsReportHostErrors},
        {"host access policy governs paths", testHostAccessPolicyGovernsPaths},
        {"advisory locks reach the host", testAdvisoryLocksReachTheHost},
        {"metadata queries keep symlink identity", testMetadataQueriesKeepSymlinkIdentity},
        {"O_NOFOLLOW refuses a symlink", testOpenNoFollowRefusesSymlink},
        {"getattrlistbulk lists a directory", testGetattrlistbulkListsDirectory},
        {"inherited standard input is readable", testInheritedStandardInputIsReadable},
    };
    return cases;
}

} // namespace rosa::tests
