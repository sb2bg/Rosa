set(ROSA_TEST_FIXTURE_DIR "${PROJECT_BINARY_DIR}/test-fixtures")
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
            "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/r2-x86_64.s"
            -lSystem
            -o "${ROSA_TEST_MACHO}"
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/r2-x86_64.s
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
            "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/hello-darwin-x86_64.s"
            -lSystem
            -o "${ROSA_TEST_HELLO_MACHO}"
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/hello-darwin-x86_64.s
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
            "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/c-main-start-x86_64.s"
            "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/c-main-x86_64.c"
            -lSystem
            -o "${ROSA_TEST_C_MAIN_MACHO}"
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/c-main-start-x86_64.s
        ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/c-main-x86_64.c
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
                -I "${PROJECT_SOURCE_DIR}/src"
                -I "${PROJECT_SOURCE_DIR}/tests/differential"
                "${CMAKE_CURRENT_SOURCE_DIR}/differential/Oracle.cpp"
                "${CMAKE_CURRENT_SOURCE_DIR}/differential/OracleRunner.S"
                -o "${ROSA_TEST_X86_ORACLE}"
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/differential/Oracle.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/differential/OracleRunner.S
            ${CMAKE_CURRENT_SOURCE_DIR}/differential/Protocol.h
            ${CMAKE_CURRENT_SOURCE_DIR}/differential/Cases.def
            ${PROJECT_SOURCE_DIR}/src/x86/Registers.h
        VERBATIM
    )
    add_custom_target(rosa_test_x86_oracle ALL DEPENDS "${ROSA_TEST_X86_ORACLE}")
endif()

# One registry owns test source selection, C++ registration, and CTest names.
set(ROSA_TEST_SUITES
    Decoder
    Startup
    Optimization
    GuestMemory
    Ir
    Differential
    Assembler
    Stack
    Arithmetic
    CompareAndAtomic
    Move
    ShiftAndMultiply
    Logic
    SimdInteger
    SimdExtended
    SimdLanes
    DarwinProcess
    DarwinFiles
    DarwinFileMetadata
    DarwinMemory
    MachTraps
    MachMessages
    IntegerSemantics
    SharedCache
    ControlFlow
    Conditions
    MachO
)
set(ROSA_TEST_SOURCES TestMain.cpp)
set(ROSA_SUITE_DECLARATIONS "")
set(ROSA_SUITE_ENTRIES "")
foreach(suite IN LISTS ROSA_TEST_SUITES)
    list(APPEND ROSA_TEST_SOURCES "${suite}Tests.cpp")
    string(SUBSTRING "${suite}" 0 1 initial)
    string(TOLOWER "${initial}" initial)
    string(SUBSTRING "${suite}" 1 -1 suffix)
    set(function "${initial}${suffix}Tests")
    string(APPEND ROSA_SUITE_DECLARATIONS
        "std::span<const TestCase> ${function}();\n")
    string(APPEND ROSA_SUITE_ENTRIES "    {\"${suite}\", ${function}},\n")
endforeach()
configure_file(TestSuites.h.in "${CMAKE_CURRENT_BINARY_DIR}/TestSuites.h" @ONLY)

add_executable(rosa_tests ${ROSA_TEST_SOURCES})
target_include_directories(rosa_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(rosa_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
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
foreach(suite IN LISTS ROSA_TEST_SUITES)
    add_test(NAME rosa_${suite} COMMAND rosa_tests ${suite})
    set_tests_properties(rosa_${suite} PROPERTIES
        LABELS "unit;${suite}" WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")
endforeach()
set_tests_properties(rosa_Differential PROPERTIES SKIP_REGULAR_EXPRESSION "\\[skip\\]")
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
