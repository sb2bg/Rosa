#include "arm64/Assembler.h"
#include "arm64/CodeBuffer.h"
#include "dbt/Dispatcher.h"
#include "dbt/Translator.h"
#include "darwin/Commpage.h"
#include "darwin/SharedCache.h"
#include "debug/Dump.h"
#include "guest/Address.h"
#include "guest/AddressSpace.h"
#include "guest/StartupStack.h"
#include "macho/Loader.h"
#include "macho/MachOFile.h"
#include "x86/Registers.h"

#include <array>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct DumpOptions {
    bool x86{};
    bool ir{};
    bool arm64{};
};

struct RunOptions {
    std::filesystem::path executable;
    std::optional<std::filesystem::path> dyld;
    std::optional<std::filesystem::path> sharedCache;
    DumpOptions dumps;
};

void printUsage(std::ostream &stream) {
    stream << "usage:\n"
              "  rosa selftest r0 [--dump-arm64]\n"
              "  rosa selftest r1 [--dump-x86] [--dump-ir] [--dump-arm64]\n"
              "  rosa selftest r2 [--dump-x86] [--dump-ir] [--dump-arm64]\n"
              "  rosa inspect [--segments] [--load-commands] <x86_64-mach-o>\n"
              "  rosa cache inspect <dyld_shared_cache_x86_64>\n"
              "  rosa run <controlled-x86_64-mach-o> [--dump-x86] [--dump-ir] [--dump-arm64]\n"
              "  rosa run [--dyld <x86_64-dyld>] [--shared-cache <cache>] "
              "<x86_64-mach-o> [dump options]\n";
}

DumpOptions parseDumpOptions(int argc, char **argv, int first) {
    DumpOptions options;
    for (int index = first; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--dump-x86") {
            options.x86 = true;
        } else if (argument == "--dump-ir") {
            options.ir = true;
        } else if (argument == "--dump-arm64") {
            options.arm64 = true;
        } else {
            throw std::invalid_argument("unknown option: " + std::string(argument));
        }
    }
    return options;
}

RunOptions parseRunOptions(int argc, char **argv) {
    RunOptions options;
    bool sawExecutable = false;
    for (int index = 2; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--dyld") {
            if (++index >= argc || options.dyld) {
                throw std::invalid_argument("--dyld requires exactly one path");
            }
            options.dyld = std::filesystem::path(argv[index]);
        } else if (argument == "--shared-cache") {
            if (++index >= argc || options.sharedCache) {
                throw std::invalid_argument("--shared-cache requires exactly one path");
            }
            options.sharedCache = std::filesystem::path(argv[index]);
        } else if (argument == "--dump-x86") {
            options.dumps.x86 = true;
        } else if (argument == "--dump-ir") {
            options.dumps.ir = true;
        } else if (argument == "--dump-arm64") {
            options.dumps.arm64 = true;
        } else if (!argument.starts_with("--") && !sawExecutable) {
            options.executable = std::filesystem::path(argument);
            sawExecutable = true;
        } else {
            throw std::invalid_argument("invalid run argument: " + std::string(argument));
        }
    }
    if (!sawExecutable) {
        throw std::invalid_argument("run requires an x86_64 Mach-O path");
    }
    return options;
}

std::string permissionText(rosa::guest::Permission permissions) {
    const auto raw = static_cast<std::uint8_t>(permissions);
    std::string result;
    result += (raw & static_cast<std::uint8_t>(rosa::guest::Permission::Read)) != 0 ? 'r' : '-';
    result += (raw & static_cast<std::uint8_t>(rosa::guest::Permission::Write)) != 0 ? 'w' : '-';
    result += (raw & static_cast<std::uint8_t>(rosa::guest::Permission::Execute)) != 0 ? 'x' : '-';
    return result;
}

void inspectSharedCache(int argc, char **argv) {
    if (argc != 4 || std::string_view(argv[2]) != "inspect") {
        throw std::invalid_argument("cache inspect requires one shared-cache path");
    }
    const auto path = std::filesystem::path(argv[3]);
    const auto cache = rosa::darwin::GuestSharedCache::open(path);
    const auto version = cache.osVersion();
    std::cout << path << ": dyld shared cache\n"
              << "architecture: " << cache.architectureName() << '\n'
              << "magic: " << cache.magic() << '\n'
              << "uuid: " << rosa::darwin::formatSharedCacheUuid(cache.uuid()) << '\n'
              << "platform: " << cache.platform() << '\n'
              << "OS version: " << (version >> 16U) << '.'
              << ((version >> 8U) & 0xFFU) << '.' << (version & 0xFFU) << " (0x"
              << std::hex << version << std::dec << ")\n"
              << "preferred region: 0x" << std::hex << cache.regionStart().value
              << "-0x" << (cache.regionStart().value + cache.regionSize())
              << " (size=0x" << cache.regionSize() << ")\n"
              << "maximum slide: 0x" << cache.maximumSlide() << '\n'
              << "chosen guest slide: 0x" << cache.slide() << '\n'
              << "dyld Mach-O: 0x" << cache.dyldMachHeader().value << '\n'
              << "dyld entry: 0x" << cache.dyldEntryPoint().value << std::dec << '\n'
              << "cached images: " << cache.imageCount() << '\n'
              << "files: " << cache.files().size() << '\n';
    for (const auto &file : cache.files()) {
        std::cout << "  " << (file.suffix.empty() ? "main" : file.suffix)
                  << " vm-offset=0x" << std::hex << file.cacheVmOffset
                  << " uuid=" << rosa::darwin::formatSharedCacheUuid(file.uuid)
                  << std::dec << " path=" << file.path << '\n';
    }
    std::cout << "mappings: " << cache.mappings().size() << '\n';
    for (const auto &mapping : cache.mappings()) {
        std::cout << "  " << (mapping.sourceSuffix.empty() ? "main" : mapping.sourceSuffix)
                  << " guest=0x" << std::hex << mapping.address.value
                  << " size=0x" << mapping.size << " fileoff=0x" << mapping.fileOffset
                  << " init=" << permissionText(mapping.initialPermissions)
                  << " max=" << permissionText(mapping.maximumPermissions)
                  << " slide-info=0x" << mapping.slideInfoFileOffset << "+0x"
                  << mapping.slideInfoFileSize << " flags=0x" << mapping.flags
                  << std::dec << '\n';
    }
}

void runR0(const DumpOptions &options) {
    rosa::arm64::Assembler assembler;
    assembler.movImmediate(rosa::arm64::x0, 42);
    assembler.ret();
    auto program = std::move(assembler).finish();

    if (options.arm64) {
        std::cout << "ARM64\n" << rosa::debug::dumpArm64(program);
    }

    rosa::arm64::ExecutableCode executable(program.bytes);
    using Entry = std::uint64_t (*)();
    const auto result = executable.entry<Entry>()();
    if (result != 42) {
        throw std::runtime_error("R0 generated function returned " + std::to_string(result));
    }
    std::cout << "R0 passed: emitted ARM64 returned 42 (" << program.bytes.size()
              << " generated bytes)\n";
}

void runR1(const DumpOptions &options) {
    constexpr std::array<std::uint8_t, 15> x86Code{
        0x48, 0xB8, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC0, 0x02, 0xC3,
    };
    constexpr rosa::guest::GuestAddress start{0x1000};

    const rosa::dbt::Translator translator;
    const auto block = translator.translate(x86Code, start);
    if (options.x86) {
        std::cout << "x86_64\n" << rosa::debug::dumpX86(block.decoded());
    }
    if (options.ir) {
        std::cout << "Rosa IR\n" << rosa::debug::dumpIr(block.intermediateRepresentation());
    }
    if (options.arm64) {
        std::cout << "ARM64\n" << rosa::debug::dumpArm64(block.program());
    }

    rosa::x86::X86State state;
    state.rip = start.value;
    static_cast<void>(block.execute(state));
    if (state.rax != 42) {
        throw std::runtime_error("R1 guest RAX was " + std::to_string(state.rax));
    }
    std::cout << "R1 passed: guest RAX = 42 (" << block.program().bytes.size()
              << " generated ARM64 bytes)\n";
}

void runR2(const DumpOptions &options) {
    constexpr std::array<std::uint8_t, 41> x86Code{
        0x48, 0xB8, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 40
        0x48, 0x83, 0xF8, 0x28,                                     // cmp rax, 40
        0x75, 0x07,                                                 // jne fail
        0xE8, 0x0E, 0x00, 0x00, 0x00,                               // call add_two
        0xEB, 0x11,                                                 // jmp done
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fail: mov rax, 0
        0xEB, 0x05,                                                 // jmp done
        0x48, 0x83, 0xC0, 0x02,                                     // add_two: add rax, 2
        0xC3,                                                       // ret
        0xC3,                                                       // done: ret
    };
    constexpr rosa::guest::GuestAddress codeBase{0x1000};
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr rosa::guest::GuestAddress returnSentinel{UINT64_MAX};
    constexpr auto stackTop = stackBase.value + rosa::guest::guestPageSize;

    rosa::guest::AddressSpace addressSpace;
    addressSpace.mapSegment(codeBase, rosa::guest::guestPageSize,
                            rosa::guest::Permission::Read | rosa::guest::Permission::Execute,
                            x86Code);
    addressSpace.mapAnonymous(stackBase, rosa::guest::guestPageSize,
                              rosa::guest::Permission::Read | rosa::guest::Permission::Write);

    rosa::x86::X86State state;
    state.rip = codeBase.value;
    state.rsp = stackTop - sizeof(std::uint64_t);
    addressSpace.writeU64(rosa::guest::GuestAddress{state.rsp}, returnSentinel.value);

    rosa::dbt::Dispatcher dispatcher(addressSpace);
    const auto result = dispatcher.run(state, 64, returnSentinel);
    if (state.rax != 42 || state.rsp != stackTop) {
        throw std::runtime_error("R2 multi-block guest state differs");
    }

    if (options.x86 || options.ir || options.arm64) {
        for (const auto &[address, block] : dispatcher.cache().blocks()) {
            std::cout << "Translated block 0x" << std::hex << address << std::dec << '\n';
            if (options.x86) {
                std::cout << "x86_64\n" << rosa::debug::dumpX86(block->decoded());
            }
            if (options.ir) {
                std::cout << "Rosa IR\n"
                          << rosa::debug::dumpIr(block->intermediateRepresentation());
            }
            if (options.arm64) {
                std::cout << "ARM64\n" << rosa::debug::dumpArm64(block->program());
            }
        }
    }

    std::cout << "R2 passed: guest RAX = 42 across " << result.executedBlocks
              << " executed blocks (" << result.translatedBlocks << " translations)\n";
}

void dumpCachedBlocks(const rosa::dbt::Dispatcher &dispatcher, const DumpOptions &options) {
    if (!options.x86 && !options.ir && !options.arm64) {
        return;
    }
    for (const auto &[address, block] : dispatcher.cache().blocks()) {
        std::cout << "Translated block 0x" << std::hex << address << std::dec << '\n';
        if (options.x86) {
            std::cout << "x86_64\n" << rosa::debug::dumpX86(block->decoded());
        }
        if (options.ir) {
            std::cout << "Rosa IR\n" << rosa::debug::dumpIr(block->intermediateRepresentation());
        }
        if (options.arm64) {
            std::cout << "ARM64\n" << rosa::debug::dumpArm64(block->program());
        }
    }
}

void inspectMachO(int argc, char **argv) {
    bool showSegments = false;
    bool showLoadCommands = false;
    std::optional<std::filesystem::path> path;
    for (int index = 2; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--segments") {
            showSegments = true;
        } else if (argument == "--load-commands") {
            showLoadCommands = true;
        } else if (!argument.starts_with("--") && !path) {
            path = std::filesystem::path(argument);
        } else {
            throw std::invalid_argument("invalid inspect argument: " + std::string(argument));
        }
    }
    if (!path) {
        throw std::invalid_argument("inspect requires an x86_64 Mach-O path");
    }

    const auto file = rosa::macho::MachOFile::open(*path);
    std::cout << *path << ": x86_64 Mach-O "
              << (file.fileType() == rosa::macho::mhDylinker ? "dynamic linker" : "executable")
              << '\n'
              << "entry: 0x" << std::hex << file.entryPoint().value << std::dec << '\n'
              << "load commands: " << file.loadCommands().size() << '\n'
              << "segments: " << file.segments().size() << '\n';
    if (showSegments) {
        for (const auto &segment : file.segments()) {
            std::cout << "  " << segment.name << " vm=0x" << std::hex
                      << segment.virtualAddress.value << " vmsize=0x" << segment.virtualSize
                      << " fileoff=0x" << segment.fileOffset << " filesize=0x" << segment.fileSize
                      << " prot=" << segment.initialProtection << std::dec << '\n';
        }
    }
    if (showLoadCommands) {
        for (const auto &command : file.loadCommands()) {
            std::cout << "  " << rosa::macho::loadCommandName(command.command)
                      << " size=" << command.size << " fileoff=0x" << std::hex << command.fileOffset
                      << std::dec << '\n';
        }
    }
}

int runMachO(const std::filesystem::path &path, const DumpOptions &options) {
    const rosa::macho::Loader loader;
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr std::size_t stackSize = 1024U * 1024U;
    rosa::guest::AddressSpace addressSpace;
    const auto image = loader.mapImage(path, addressSpace);
    const auto pathString = path.string();
    const std::vector<std::string> arguments{pathString};
    const std::vector<std::string> environment;
    const std::vector<std::string> apple{"executable_path=" + pathString};
    const rosa::guest::StartupStackBuilder stackBuilder;
    const auto stack =
        stackBuilder.build(addressSpace, stackBase, stackSize, arguments, environment, apple);
    rosa::x86::X86State state;
    state.rip = image.entryPoint.value;
    state.rsp = stack.stackPointer.value;
    rosa::dbt::Dispatcher dispatcher(addressSpace);
    rosa::dbt::DispatchResult result;
    try {
        result = dispatcher.run(state, 1'000);
    } catch (const std::exception &error) {
        std::cerr << rosa::debug::dumpGuestFailure(path.string(), error, state, addressSpace,
                                                   dispatcher);
        throw;
    }
    dumpCachedBlocks(dispatcher, options);
    if (!result.exited) {
        throw std::runtime_error("top-level Mach-O returned without Darwin exit(2)");
    }
    std::cout << "guest exited: status=" << result.exitStatus
              << ", blocks=" << result.executedBlocks
              << ", translations=" << result.translatedBlocks << '\n';
    return result.exitStatus;
}

int runDyldExperiment(const std::filesystem::path &executablePath,
                      const std::optional<std::filesystem::path> &dyldPath,
                      const std::optional<std::filesystem::path> &sharedCachePath,
                      const DumpOptions &options) {
    constexpr std::uint64_t dyldSlide = 0x00007FF800000000ULL;
    constexpr rosa::guest::GuestAddress stackBase{0x700000000000ULL};
    constexpr std::size_t stackSize = 1024U * 1024U;
    constexpr std::size_t maximumProbeBlocks = 1000000;

    const auto executableFile = rosa::macho::MachOFile::open(executablePath);
    std::optional<rosa::macho::MachOFile> dyldFile;
    if (dyldPath) {
        dyldFile.emplace(rosa::macho::MachOFile::open(*dyldPath));
        if (dyldFile->fileType() != rosa::macho::mhDylinker) {
            throw std::runtime_error("manual --dyld file is not MH_DYLINKER");
        }
    }
    std::optional<rosa::darwin::GuestSharedCache> sharedCache;
    if (sharedCachePath) {
        sharedCache.emplace(rosa::darwin::GuestSharedCache::open(*sharedCachePath));
        if (sharedCache->dyldEntryPoint().value == 0) {
            throw std::runtime_error("guest shared cache has no dyld-in-cache entry point");
        }
    }
    if (!dyldFile && !sharedCache) {
        throw std::invalid_argument("dyld experiment requires --dyld or --shared-cache");
    }

    rosa::guest::AddressSpace addressSpace;
    const rosa::macho::Loader loader;
    const auto executableString = executablePath.string();
    const auto dyldString = sharedCachePath ? sharedCachePath->string()
                                            : dyldPath->string();
    const auto executable =
        loader.mapImage(executableFile, addressSpace, 0, executableString);
    std::optional<rosa::macho::LoadedImage> dyld;
    if (sharedCache) {
        sharedCache->mapInto(addressSpace);
    } else {
        dyld.emplace(loader.mapImage(*dyldFile, addressSpace, dyldSlide, dyldString));
    }
    rosa::darwin::mapX86Commpage(
        addressSpace, rosa::darwin::sampleHostContinuousTimebase());
    const std::vector<std::string> arguments{executableString};
    const std::vector<std::string> environment;
    std::vector<std::string> apple{"executable_path=" + executableString};
    if (dyldPath) {
        apple.push_back("dyld_file=" + dyldPath->string());
    }
    const rosa::guest::StartupStackBuilder stackBuilder;
    const auto stack =
        stackBuilder.build(addressSpace, stackBase, stackSize, arguments,
                           environment, apple, executable.loadAddress);

    rosa::x86::X86State state;
    state.rip = sharedCache ? sharedCache->dyldEntryPoint().value
                            : dyld->entryPoint.value;
    state.rsp = stack.stackPointer.value;
    std::cout << "dyld experiment: app-entry=0x" << std::hex << executable.entryPoint.value
              << " dyld-entry=0x" << state.rip << " initial-rsp=0x" << state.rsp;
    if (sharedCache) {
        std::cout << " shared-cache=0x" << sharedCache->regionStart().value
                  << " slide=0x" << sharedCache->slide();
    }
    std::cout << std::dec << '\n';

    // Single-instruction translations make the first unsupported dyld requirement observable
    // after every preceding supported instruction has executed as generated ARM64.
    rosa::dbt::Dispatcher dispatcher(addressSpace, 1,
                                     &rosa::darwin::sampleX86TimestampCounter);
    try {
        const auto result = dispatcher.run(state, maximumProbeBlocks);
        dumpCachedBlocks(dispatcher, options);
        if (result.exited) {
            std::cout << "dyld experiment exited: status=" << result.exitStatus << '\n';
            return result.exitStatus;
        }
        throw std::runtime_error("dyld returned without a guest exit syscall");
    } catch (const std::exception &error) {
        std::cerr << rosa::debug::dumpGuestFailure(dyldString, error, state, addressSpace,
                                                   dispatcher);
        dumpCachedBlocks(dispatcher, options);
        throw std::runtime_error("dyld experiment stopped after " +
                                 std::to_string(dispatcher.cache().size()) +
                                 " translated block(s): " + error.what());
    }
}

} // namespace

int main(int argc, char **argv) {
    try {
        if (argc < 2) {
            printUsage(std::cerr);
            return 2;
        }

        const std::string_view command(argv[1]);
        if (command == "inspect") {
            inspectMachO(argc, argv);
            return 0;
        }
        if (command == "cache") {
            inspectSharedCache(argc, argv);
            return 0;
        }
        if (command == "run") {
            const auto options = parseRunOptions(argc, argv);
            if (options.dyld || options.sharedCache) {
                return runDyldExperiment(options.executable, options.dyld,
                                         options.sharedCache, options.dumps);
            }
            return runMachO(options.executable, options.dumps);
        }
        if (command != "selftest" || argc < 3) {
            printUsage(std::cerr);
            return 2;
        }

        const auto options = parseDumpOptions(argc, argv, 3);
        const std::string_view milestone(argv[2]);
        if (milestone == "r0") {
            runR0(options);
        } else if (milestone == "r1") {
            runR1(options);
        } else if (milestone == "r2") {
            runR2(options);
        } else {
            throw std::invalid_argument("unknown selftest milestone: " + std::string(milestone));
        }
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
