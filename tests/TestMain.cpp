#include "TestSuites.h"

#include <exception>
#include <iostream>
#include <string_view>

int main(int argc, char **argv) {
    if (argc > 2) {
        std::cerr << "usage: rosa_tests [suite|--list]\n";
        return 2;
    }
    const std::string_view selection = argc == 2 ? argv[1] : "";
    std::size_t failures = 0;
    std::size_t executed = 0;
    bool matched = selection.empty();
    for (const auto &suite : rosa::tests::suites) {
        if (selection == "--list") {
            std::cout << suite.name << '\n';
            continue;
        }
        if (!selection.empty() && selection != suite.name) {
            continue;
        }
        matched = true;
        const auto cases = suite.cases();
        if (cases.empty()) {
            std::cout << "[skip] " << suite.name << ": unavailable in this build\n";
        }
        for (const auto &test : cases) {
            ++executed;
            try {
                test.run();
                std::cout << "[pass] " << test.name << '\n';
            } catch (const std::exception &error) {
                ++failures;
                std::cerr << "[fail] " << test.name << ": " << error.what() << '\n';
            }
        }
    }
    if (selection == "--list") {
        return 0;
    }
    if (!matched) {
        std::cerr << "unknown test suite: " << selection << '\n';
        return 2;
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << executed << " tests passed\n";
    return 0;
}
