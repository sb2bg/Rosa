#pragma once

#include <span>
#include <string_view>

namespace rosa::tests {

struct TestCase {
    std::string_view name;
    void (*run)();
};

struct TestSuite {
    std::string_view name;
    std::span<const TestCase> (*cases)();
};

} // namespace rosa::tests
