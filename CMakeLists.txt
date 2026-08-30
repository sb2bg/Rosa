cmake_minimum_required(VERSION 3.25)

project(Rosa VERSION 0.1.0 LANGUAGES C CXX)

include(CheckIPOSupported)

if(NOT APPLE)
    message(FATAL_ERROR "Rosa's initial JIT backend currently requires macOS")
endif()

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
    message(FATAL_ERROR "Rosa's initial JIT backend currently requires an arm64 host")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(ROSA_SANITIZERS "" CACHE STRING "Comma-separated Clang host sanitizers")
option(ROSA_ENABLE_LLVM_JIT
       "Use LLVM as an optimizing JIT tier when development libraries are available"
       ON)
option(ROSA_ENABLE_RELEASE_IPO
       "Enable interprocedural optimization for release runtime builds"
       ON)

set(ROSA_RELEASE_IPO_AVAILABLE OFF)
if(ROSA_ENABLE_RELEASE_IPO)
    check_ipo_supported(RESULT ROSA_RELEASE_IPO_AVAILABLE
                        OUTPUT ROSA_RELEASE_IPO_ERROR)
    if(NOT ROSA_RELEASE_IPO_AVAILABLE)
        message(STATUS "Rosa release IPO unavailable: ${ROSA_RELEASE_IPO_ERROR}")
    endif()
endif()

set(ROSA_HAS_LLVM OFF)
if(ROSA_ENABLE_LLVM_JIT)
    find_package(LLVM CONFIG QUIET PATHS
        "/opt/homebrew/opt/llvm/lib/cmake/llvm"
        "/usr/local/opt/llvm/lib/cmake/llvm"
    )
    if(LLVM_FOUND)
        set(ROSA_HAS_LLVM ON)
        message(STATUS "Rosa LLVM optimizing JIT: LLVM ${LLVM_PACKAGE_VERSION}")
    else()
        message(STATUS "Rosa LLVM optimizing JIT: unavailable; using baseline JIT")
    endif()
endif()

add_library(rosa_core
    src/arm64/Assembler.cpp
    src/arm64/CodeBuffer.cpp
    src/dbt/Translator.cpp
    src/dbt/LlvmBackend.cpp
    src/dbt/BlockCache.cpp
    src/dbt/Dispatcher.cpp
    src/debug/Dump.cpp
    src/darwin/Commpage.cpp
    src/darwin/Files.cpp
    src/darwin/Mach.cpp
    src/darwin/PortSpace.cpp
    src/darwin/SharedCache.cpp
    src/darwin/Syscall.cpp
    src/ir/IR.cpp
    src/guest/AddressSpace.cpp
    src/guest/MappingBatch.cpp
    src/guest/StartupStack.cpp
    src/macho/MachOFile.cpp
    src/macho/Loader.cpp
    src/x86/Decoder.cpp
)

target_include_directories(rosa_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_definitions(rosa_core PRIVATE
    ROSA_HAS_LLVM=$<BOOL:${ROSA_HAS_LLVM}>
)
if(ROSA_HAS_LLVM)
    target_include_directories(rosa_core SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
    llvm_map_components_to_libnames(ROSA_LLVM_LIBRARIES
        Core
        OrcJIT
        Passes
        nativecodegen
    )
    target_link_libraries(rosa_core PRIVATE ${ROSA_LLVM_LIBRARIES})
endif()
target_compile_options(rosa_core PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wshadow
    -Werror=return-type
)

if(ROSA_SANITIZERS)
    target_compile_options(rosa_core PUBLIC -fsanitize=${ROSA_SANITIZERS} -fno-omit-frame-pointer)
    target_link_options(rosa_core PUBLIC -fsanitize=${ROSA_SANITIZERS})
endif()

add_executable(rosa src/main.cpp)
target_link_libraries(rosa PRIVATE rosa_core)
if(ROSA_RELEASE_IPO_AVAILABLE)
    set_property(TARGET rosa_core rosa PROPERTY
                 INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

set(ROSA_BENCHMARK_ENTRYPOINT
    "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/entrypoint-x86_64")
add_custom_command(
    OUTPUT "${ROSA_BENCHMARK_ENTRYPOINT}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${CMAKE_CURRENT_BINARY_DIR}/benchmarks"
    COMMAND "${CMAKE_CXX_COMPILER}"
            -target x86_64-apple-macos11
            -nostdlib
            -Wl,-e,_start
            -Wl,-no_pie
            "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/entrypoint-x86_64.s"
            -lSystem
            -o "${ROSA_BENCHMARK_ENTRYPOINT}"
    DEPENDS benchmarks/entrypoint-x86_64.s
    VERBATIM
)
add_custom_target(rosa_benchmark_entrypoint_fixture
                  DEPENDS "${ROSA_BENCHMARK_ENTRYPOINT}")
add_custom_target(
    benchmark_entrypoint
    COMMAND "${CMAKE_COMMAND}" -E time "$<TARGET_FILE:rosa>" run
            --max-blocks 200000010 "${ROSA_BENCHMARK_ENTRYPOINT}"
    DEPENDS rosa rosa_benchmark_entrypoint_fixture
    USES_TERMINAL
    VERBATIM
)

set(ROSA_FRONTIER_ORDINARY_C
    "${CMAKE_CURRENT_BINARY_DIR}/frontier-fixtures/ordinary-c-x86_64")
add_custom_command(
    OUTPUT "${ROSA_FRONTIER_ORDINARY_C}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${CMAKE_CURRENT_BINARY_DIR}/frontier-fixtures"
    COMMAND "${CMAKE_C_COMPILER}"
            -target x86_64-apple-macos11
            -O2
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/ordinary-c-x86_64.c"
            -o "${ROSA_FRONTIER_ORDINARY_C}"
    DEPENDS tests/fixtures/ordinary-c-x86_64.c
    VERBATIM
)
add_custom_target(rosa_frontier_ordinary_c ALL
                  DEPENDS "${ROSA_FRONTIER_ORDINARY_C}")

set(ROSA_BENCHMARK_PRIME_SIEVE
    "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/prime-sieve-x86_64")
add_custom_command(
    OUTPUT "${ROSA_BENCHMARK_PRIME_SIEVE}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${CMAKE_CURRENT_BINARY_DIR}/benchmarks"
    COMMAND "${CMAKE_C_COMPILER}"
            -target x86_64-apple-macos11
            -O2
            "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/prime-sieve-x86_64.c"
            -o "${ROSA_BENCHMARK_PRIME_SIEVE}"
    DEPENDS benchmarks/prime-sieve-x86_64.c
    VERBATIM
)
add_custom_target(rosa_benchmark_prime_sieve_fixture ALL
                  DEPENDS "${ROSA_BENCHMARK_PRIME_SIEVE}")

include(CTest)
if(BUILD_TESTING)
    set(ROSA_TEST_FIXTURE_DIR "${CMAKE_CURRENT_BINARY_DIR}/test-fixtures")
    set(ROSA_TEST_MACHO "${ROSA_TEST_FIXTURE_DIR}/r2-x86_64")
    set(ROSA_TEST_HELLO_MACHO "${ROSA_TEST_FIXTURE_DIR}/hello-darwin-x86_64")
    set(ROSA_TEST_C_MAIN_MACHO "${ROSA_TEST_FIXTURE_DIR}/c-main-x86_64")
    add_custom_command(
        OUTPUT "${ROSA_TEST_MACHO}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${ROSA_TEST_FIXTURE_DIR}"
        COMMAND "${CMAKE_CXX_COMPILER}"
                -target x86_64-apple-macos11
                -nostdlib
                -Wl,-e,_start
                -Wl,-no_pie
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/r2-x86_64.s"
                -lSystem
                -o "${ROSA_TEST_MACHO}"
        DEPENDS tests/fixtures/r2-x86_64.s
        VERBATIM
    )
    add_custom_target(rosa_test_macho ALL DEPENDS "${ROSA_TEST_MACHO}")
    add_custom_command(
        OUTPUT "${ROSA_TEST_HELLO_MACHO}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${ROSA_TEST_FIXTURE_DIR}"
        COMMAND "${CMAKE_CXX_COMPILER}"
                -target x86_64-apple-macos11
                -nostdlib
                -Wl,-e,_start
                -Wl,-no_pie
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/hello-darwin-x86_64.s"
                -lSystem
                -o "${ROSA_TEST_HELLO_MACHO}"
        DEPENDS tests/fixtures/hello-darwin-x86_64.s
        VERBATIM
    )
    add_custom_target(rosa_test_hello_macho ALL DEPENDS "${ROSA_TEST_HELLO_MACHO}")
    add_custom_command(
        OUTPUT "${ROSA_TEST_C_MAIN_MACHO}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${ROSA_TEST_FIXTURE_DIR}"
        COMMAND "${CMAKE_C_COMPILER}"
                -target x86_64-apple-macos11
                -std=c17
                -O2
                -fno-stack-protector
                -nostdlib
                -Wl,-e,_start
                -Wl,-no_pie
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/c-main-start-x86_64.s"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/c-main-x86_64.c"
                -lSystem
                -o "${ROSA_TEST_C_MAIN_MACHO}"
        DEPENDS
            tests/fixtures/c-main-start-x86_64.s
            tests/fixtures/c-main-x86_64.c
        VERBATIM
    )
    add_custom_target(rosa_test_c_main_macho ALL
                      DEPENDS "${ROSA_TEST_C_MAIN_MACHO}")

    option(ROSA_ENABLE_ROSETTA_DIFFERENTIAL_TESTS
           "Run x86 semantic differential tests when Apple Rosetta is available" ON)
    if(ROSA_ENABLE_ROSETTA_DIFFERENTIAL_TESTS)
        execute_process(
            COMMAND /usr/bin/arch -x86_64 /usr/bin/true
            RESULT_VARIABLE ROSA_ROSETTA_PROBE_RESULT
            OUTPUT_QUIET
            ERROR_QUIET
        )
    else()
        set(ROSA_ROSETTA_PROBE_RESULT 1)
    endif()
    if(ROSA_ROSETTA_PROBE_RESULT EQUAL 0)
        set(ROSA_TEST_X86_ORACLE "${ROSA_TEST_FIXTURE_DIR}/rosa-x86-oracle")
        add_custom_command(
            OUTPUT "${ROSA_TEST_X86_ORACLE}"
            COMMAND "${CMAKE_CXX_COMPILER}"
                    -arch x86_64
                    -std=c++23
                    -Wall
                    -Wextra
                    -Wpedantic
                    -I "${CMAKE_CURRENT_SOURCE_DIR}/src"
                    -I "${CMAKE_CURRENT_SOURCE_DIR}/tests/differential"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tests/differential/Oracle.cpp"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tests/differential/OracleRunner.S"
                    -o "${ROSA_TEST_X86_ORACLE}"
            DEPENDS
                tests/differential/Oracle.cpp
                tests/differential/OracleRunner.S
                tests/differential/Protocol.h
                tests/differential/Cases.def
                src/x86/Registers.h
            VERBATIM
        )
        add_custom_target(rosa_test_x86_oracle ALL DEPENDS "${ROSA_TEST_X86_ORACLE}")
    endif()

    add_executable(rosa_tests tests/TestMain.cpp)
    target_link_libraries(rosa_tests PRIVATE rosa_core)
    if(ROSA_RELEASE_IPO_AVAILABLE)
        set_property(TARGET rosa_tests PROPERTY
                     INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    endif()
    target_compile_definitions(rosa_tests PRIVATE
        ROSA_TEST_MACHO_PATH="${ROSA_TEST_MACHO}"
        ROSA_TEST_HELLO_MACHO_PATH="${ROSA_TEST_HELLO_MACHO}"
    )
    add_dependencies(rosa_tests rosa_test_macho rosa_test_hello_macho
                     rosa_test_c_main_macho)
    if(ROSA_ROSETTA_PROBE_RESULT EQUAL 0)
        target_compile_definitions(rosa_tests PRIVATE
            ROSA_HAS_X86_ORACLE=1
            ROSA_TEST_X86_ORACLE_PATH="${ROSA_TEST_X86_ORACLE}"
        )
        add_dependencies(rosa_tests rosa_test_x86_oracle)
    endif()
    add_test(NAME rosa_tests COMMAND rosa_tests)
    add_test(NAME rosa_hello_darwin COMMAND rosa run "${ROSA_TEST_HELLO_MACHO}")
    set_tests_properties(rosa_hello_darwin PROPERTIES
        PASS_REGULAR_EXPRESSION "hello from Intel Darwin;guest exited: status=0"
    )
    add_test(NAME rosa_c_main COMMAND rosa run --max-blocks 21000000
             --dump-x86
             "${ROSA_TEST_C_MAIN_MACHO}" -- rosa jit)
    if(ROSA_HAS_LLVM)
        set_tests_properties(rosa_c_main PROPERTIES
            PASS_REGULAR_EXPRESSION
                "C main returned 42;Execution tier: LLVM O2 hot loop;guest exited: status=0"
        )
    else()
        set_tests_properties(rosa_c_main PROPERTIES
            PASS_REGULAR_EXPRESSION "C main returned 42;guest exited: status=0"
        )
    endif()
endif()
