#pragma once

#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace rosa::tests {

// Own the fixture so failures and concurrent test runs do not leave files behind.
class TemporaryFile {
  public:
    explicit TemporaryFile(const std::filesystem::path &directory)
        : path_((directory / ".rosa-test-XXXXXX").string()) {
        const auto descriptor = ::mkstemp(path_.data());
        if (descriptor < 0) {
            throw std::runtime_error("cannot create temporary test fixture");
        }
        ::close(descriptor);
    }

    ~TemporaryFile() { ::unlink(path_.c_str()); }
    TemporaryFile(const TemporaryFile &) = delete;
    TemporaryFile &operator=(const TemporaryFile &) = delete;

    [[nodiscard]] std::filesystem::path path() const { return path_; }

  private:
    std::string path_;
};

} // namespace rosa::tests
