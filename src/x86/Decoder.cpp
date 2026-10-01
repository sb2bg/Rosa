#include "x86/Decoder.h"
#include "x86/DecodeInternal.h"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <utility>

namespace rosa::x86 {
namespace {

std::string makeErrorMessage(guest::GuestAddress address, std::span<const std::uint8_t> remaining,
                             const std::string &reason) {
    std::ostringstream stream;
    stream << "unsupported or malformed x86 instruction at guest RIP 0x" << std::hex
           << address.value << ": " << reason << "; bytes:";
    const auto shown = std::min<std::size_t>(remaining.size(), 15);
    for (std::size_t index = 0; index < shown; ++index) {
        stream << ' ' << std::setw(2) << std::setfill('0')
               << static_cast<unsigned>(remaining[index]);
    }
    return stream.str();
}

} // namespace

DecodeError::DecodeError(guest::GuestAddress address, std::span<const std::uint8_t> remaining,
                         const std::string &reason)
    : std::runtime_error(makeErrorMessage(address, remaining, reason)), address_(address),
      remaining_(remaining.begin(), remaining.end()) {}

DecodedInstruction Decoder::decodeInstruction(std::span<const std::uint8_t> code,
                                               guest::GuestAddress address) const {
    if (code.empty()) {
        throw DecodeError(address, code, "cannot decode an empty instruction");
    }
    detail::DecodeContext context{.code = code, .address = address,
                                  .instruction = {.address = address}};
    if (code.front() == 0xC3U) {
        context.instruction.opcode = Opcode::Ret;
        context.instruction.length = 1;
        context.instruction.bytes[0] = code.front();
        return std::move(context.instruction);
    }
    // Preserve recognition priority: specialized prefix forms precede the
    // general operand-size/GS/REX decoder. Each family owns its diagnostics.
    const bool decoded =
        detail::decodeVex(context) ||
        detail::decodeScalarSpecial(context) ||
        detail::decodeOperandOverride(context) ||
        detail::decodeSimdLanes(context) ||
        detail::decodeSimdMemory(context) ||
        detail::decodeRepeat(context) ||
        detail::decodeControlTransfer(context) ||
        detail::decodeAtomic(context) ||
        detail::decodeExtended(context) ||
        detail::decodeGeneral(context);
    if (!decoded) {
        throw DecodeError(address, code, "opcode is not in the current Rosa subset");
    }
    return std::move(context.instruction);
}

std::vector<DecodedInstruction> Decoder::decodeBlock(std::span<const std::uint8_t> code,
                                                     guest::GuestAddress start,
                                                     std::size_t maximumInstructions) const {
    if (maximumInstructions == 0) {
        throw std::invalid_argument("x86 decoder instruction limit must be nonzero");
    }
    std::vector<DecodedInstruction> result;
    std::size_t cursor = 0;
    while (cursor < code.size()) {
        if (cursor > std::numeric_limits<std::uint64_t>::max() - start.value) {
            throw DecodeError(start, code.subspan(cursor), "guest RIP overflows");
        }
        auto instruction = decodeInstruction(code.subspan(cursor),
                                             guest::GuestAddress{start.value + cursor});
        cursor += instruction.length;
        const auto terminates = terminatesBlock(instruction.opcode);
        result.push_back(std::move(instruction));
        if (terminates || result.size() == maximumInstructions) {
            return result;
        }
    }
    throw DecodeError(guest::GuestAddress{start.value + cursor}, {},
                      "basic block ended without a supported terminator");
}

} // namespace rosa::x86
