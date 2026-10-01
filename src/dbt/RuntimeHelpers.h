#pragma once

#include "dbt/ExecutionContext.h"
#include "x86/Registers.h"

namespace rosa::dbt::runtime {

// C ABI entry points called by generated code. Exceptions are captured in the
// execution context and rethrown only after returning to C++.
extern "C" std::uint8_t *
validateDirectGuestReadSpan(GuestExecutionContext *context, std::uint64_t address,
                            std::uint64_t induction, std::uint64_t step, std::uint64_t limit,
                            std::uint64_t maximumOffset) noexcept;

extern "C" x86::X86State *updateLogicFlags8(x86::X86State *state,
                                                                      std::uint64_t result);

extern "C" x86::X86State *updateLogicFlags16(x86::X86State *state,
                                                                       std::uint64_t result);

extern "C" x86::X86State *updateLogicFlags32(x86::X86State *state,
                                                                       std::uint64_t result);

extern "C" x86::X86State *updateLogicFlags64(x86::X86State *state,
                                                                       std::uint64_t result);

extern "C" x86::X86State *updateSubFlags8(x86::X86State *state,
                                                                    std::uint64_t lhsValue,
                                                                    std::uint64_t rhsValue,
                                                                    std::uint64_t resultValue);

extern "C" x86::X86State *commitPush64(GuestExecutionContext *context,
                                                                 x86::X86State *state,
                                                                 std::uint64_t newStackPointer,
                                                                 std::uint64_t value) noexcept;

extern "C" x86::X86State *
divideUnsignedByte(GuestExecutionContext *context, x86::X86State *state,
                   std::uint64_t divisorValue) noexcept;

extern "C" x86::X86State *
divideUnsignedDword(GuestExecutionContext *context, x86::X86State *state,
                    std::uint64_t divisorValue) noexcept;

extern "C" x86::X86State *
divideSignedDword(GuestExecutionContext *context, x86::X86State *state,
                  std::uint64_t divisorValue) noexcept;

extern "C" x86::X86State *
divideUnsignedQword(GuestExecutionContext *context, x86::X86State *state,
                    std::uint64_t divisor) noexcept;

extern "C" x86::X86State *storeGuest64(GuestExecutionContext *context,
                                                                 x86::X86State *state,
                                                                 std::uint64_t address,
                                                                 std::uint64_t value) noexcept;

extern "C" x86::X86State *storeGuest8(GuestExecutionContext *context,
                                                                x86::X86State *state,
                                                                std::uint64_t address,
                                                                std::uint64_t value) noexcept;

extern "C" x86::X86State *storeGuest16(GuestExecutionContext *context,
                                                                 x86::X86State *state,
                                                                 std::uint64_t address,
                                                                 std::uint64_t value) noexcept;

extern "C" x86::X86State *storeGuest32(GuestExecutionContext *context,
                                                                 x86::X86State *state,
                                                                 std::uint64_t address,
                                                                 std::uint64_t value) noexcept;

extern "C" x86::X86State *storeGuestIdtr(GuestExecutionContext *context,
                                                                   x86::X86State *state,
                                                                   std::uint64_t address) noexcept;

extern "C" x86::X86State *
storeGuestXmm128(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t registerIndex, std::uint64_t alignmentRequired) noexcept;

extern "C" x86::X86State *
storeGuestYmm256(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t registerIndex, std::uint64_t alignmentRequired) noexcept;

extern "C" x86::X86State *
loadGuestXmm128(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t registerIndex, std::uint64_t alignmentRequired) noexcept;

extern "C" x86::X86State *
loadGuestYmm256(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t registerIndex, std::uint64_t alignmentRequired) noexcept;

extern "C" x86::X86State *
loadGuestSignExtendedBytesXmm(GuestExecutionContext *context, x86::X86State *state,
                              std::uint64_t address, std::uint64_t registerIndex) noexcept;

extern "C" x86::X86State *
loadGuestSignExtendedDwordsXmm(GuestExecutionContext *context, x86::X86State *state,
                               std::uint64_t address, std::uint64_t registerIndex) noexcept;

extern "C" x86::X86State *
compareEqualGuestBytesXmm128(GuestExecutionContext *context, x86::X86State *state,
                             std::uint64_t address, std::uint64_t registerIndex) noexcept;

extern "C" x86::X86State *
compareEqualGuestQwordsXmm128(GuestExecutionContext *context, x86::X86State *state,
                              std::uint64_t address, std::uint64_t registerIndex) noexcept;

extern "C" x86::X86State *
arithmeticGuestMemoryPackedDoubleXmm128(GuestExecutionContext *context, x86::X86State *state,
                                        std::uint64_t address,
                                        std::uint64_t registerIndex,
                                        std::uint64_t operation) noexcept;

extern "C" x86::X86State *
unpackLowGuestPackedSingleXmm128(GuestExecutionContext *context, x86::X86State *state,
                                 std::uint64_t address,
                                 std::uint64_t registerIndex) noexcept;

extern "C" x86::X86State *
horizontalAddGuestPackedDoubleXmm128(GuestExecutionContext *context, x86::X86State *state,
                                     std::uint64_t address,
                                     std::uint64_t registerIndex) noexcept;

extern "C" x86::X86State *
unpackHighGuestPackedSingleXmm128(GuestExecutionContext *context, x86::X86State *state,
                                  std::uint64_t address,
                                  std::uint64_t registerIndex) noexcept;

extern "C" x86::X86State *
xorGuestMemoryXmm128(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                     std::uint64_t registerIndex) noexcept;

extern "C" x86::X86State *
andGuestMemoryXmm128(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                     std::uint64_t registerIndex) noexcept;

extern "C" x86::X86State *
addGuestMemoryXmm128(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                     std::uint64_t registerIndex) noexcept;

extern "C" x86::X86State *
testXmmBits128(x86::X86State *state, std::uint64_t destinationIndex,
               std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
convertInt32ToDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                        std::uint64_t intValue) noexcept;

extern "C" x86::X86State *
convertDoubleToInt64(x86::X86State *state, std::uint64_t destinationIndex,
                     std::uint64_t doubleBits) noexcept;

extern "C" x86::X86State *
convertDoubleToInt32(x86::X86State *state, std::uint64_t destinationIndex,
                     std::uint64_t doubleBits) noexcept;

extern "C" x86::X86State *
convertInt64ToDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                        std::uint64_t intValue) noexcept;

extern "C" x86::X86State *
convertFloatToDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                        std::uint64_t floatBits) noexcept;

extern "C" x86::X86State *
convertInt32x2ToDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                          std::uint64_t lowBits) noexcept;

extern "C" x86::X86State *
scalarDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                std::uint64_t sourceBits, std::uint64_t operation) noexcept;

extern "C" x86::X86State *
addXmmWords128(x86::X86State *state, std::uint64_t destinationIndex,
               std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
comparePackedDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                       std::uint64_t sourceIndex, std::uint64_t predicate) noexcept;

extern "C" x86::X86State *
arithmeticPackedDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                          std::uint64_t sourceIndex, std::uint64_t operation) noexcept;

extern "C" x86::X86State *
unpackLowPackedSingleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                         std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
horizontalAddPackedDoubleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                             std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
unpackHighPackedSingleXmm(x86::X86State *state, std::uint64_t destinationIndex,
                          std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
updateUnorderedDoubleFlags(x86::X86State *state, std::uint64_t destinationBits,
                           std::uint64_t sourceBits) noexcept;

extern "C" x86::X86State *
updateUnorderedFloatFlags(x86::X86State *state, std::uint64_t destinationBits,
                          std::uint64_t sourceBits) noexcept;

extern "C" x86::X86State *
compareEqualXmmBytes128(x86::X86State *state, std::uint64_t destinationIndex,
                        std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
compareEqualXmmDwords128(x86::X86State *state, std::uint64_t destinationIndex,
                         std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
compareEqualXmmQwords128(x86::X86State *state, std::uint64_t destinationIndex,
                         std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
shiftLeftXmmDwords128(x86::X86State *state, std::uint64_t destinationIndex,
                      std::uint64_t count) noexcept;

extern "C" x86::X86State *
addXmmDwords128(x86::X86State *state, std::uint64_t destinationIndex,
                std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
packUnsignedSaturateDwords128(x86::X86State *state, std::uint64_t destinationIndex,
                              std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
horizontalAddXmmDwords128(x86::X86State *state, std::uint64_t destinationIndex,
                          std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
andNotXmm128(x86::X86State *state, std::uint64_t destinationIndex,
             std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
moveXmmByteMask32(x86::X86State *state, std::uint64_t destinationIndex, std::uint64_t sourceIndex);

extern "C" x86::X86State *bitScanForward(x86::X86State *state,
                                                                   std::uint64_t destinationIndex,
                                                                   std::uint64_t sourceIndex,
                                                                   std::uint64_t operandWidth);

extern "C" x86::X86State *bitScanReverse(x86::X86State *state,
                                                                   std::uint64_t destinationIndex,
                                                                   std::uint64_t sourceIndex,
                                                                   std::uint64_t operandWidth);

extern "C" x86::X86State *shuffleXmmDwords(x86::X86State *state,
                                                                     std::uint64_t destinationIndex,
                                                                     std::uint64_t sourceIndex,
                                                                     std::uint64_t control);

extern "C" x86::X86State *
shuffleXmmBytes(x86::X86State *state, std::uint64_t destinationIndex, std::uint64_t sourceIndex);

extern "C" x86::X86State *
shuffleGuestMemoryXmmBytes(GuestExecutionContext *context, x86::X86State *state,
                           std::uint64_t address, std::uint64_t destinationIndex) noexcept;

extern "C" x86::X86State *
alignRightXmmBytes(x86::X86State *state, std::uint64_t destinationIndex, std::uint64_t sourceIndex,
                   std::uint64_t count);

extern "C" x86::X86State *blendXmmWords(x86::X86State *state,
                                                                  std::uint64_t destinationIndex,
                                                                  std::uint64_t sourceIndex,
                                                                  std::uint64_t mask);

extern "C" x86::X86State *
unpackLowXmmWords(x86::X86State *state, std::uint64_t destinationIndex,
                  std::uint64_t sourceIndex) noexcept;

extern "C" x86::X86State *
loadGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address) noexcept;

extern "C" x86::X86State *
loadGuest8(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address) noexcept;

extern "C" x86::X86State *repeatMoveByte(GuestExecutionContext *context,
                                                                   x86::X86State *state) noexcept;

extern "C" x86::X86State *
repeatStore(GuestExecutionContext *context, x86::X86State *state,
            std::uint64_t widthBytes) noexcept;

extern "C" x86::X86State *
loadGuest16(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address) noexcept;

extern "C" x86::X86State *
loadGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address) noexcept;

extern "C" x86::X86State *
readTimestampCounter(GuestExecutionContext *context, x86::X86State *state) noexcept;

extern "C" x86::X86State *
cpuidGuest(x86::X86State *state) noexcept;

extern "C" x86::X86State *
updateAddFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs, std::uint64_t result);

extern "C" x86::X86State *updateAddFlags8(x86::X86State *state,
                                                                    std::uint64_t lhsValue,
                                                                    std::uint64_t rhsValue,
                                                                    std::uint64_t resultValue);

extern "C" x86::X86State *updateAddFlags16(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue);

extern "C" x86::X86State *updateAddFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue);

extern "C" x86::X86State *updateAdcFlags8(x86::X86State *state,
                                                                    std::uint64_t lhsValue,
                                                                    std::uint64_t rhsValue,
                                                                    std::uint64_t carryValue);

extern "C" x86::X86State *updateAdcFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t carryValue);

extern "C" x86::X86State *updateAdcFlags64(x86::X86State *state,
                                                                     std::uint64_t lhs,
                                                                     std::uint64_t rhs,
                                                                     std::uint64_t carryValue);

extern "C" x86::X86State *updateSbbFlags8(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t borrowValue);

extern "C" x86::X86State *updateSbbFlags16(x86::X86State *state, std::uint64_t lhsValue,
                                           std::uint64_t rhsValue, std::uint64_t borrowValue);

extern "C" x86::X86State *updateSbbFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t borrowValue);

extern "C" x86::X86State *updateSbbFlags64(x86::X86State *state,
                                                                     std::uint64_t lhs,
                                                                     std::uint64_t rhs,
                                                                     std::uint64_t borrowValue);

extern "C" x86::X86State *
updateIncFlags32(x86::X86State *state, std::uint64_t original, std::uint64_t result);

extern "C" x86::X86State *
updateIncFlags16(x86::X86State *state, std::uint64_t original, std::uint64_t result);

extern "C" x86::X86State *
updateIncFlags8(x86::X86State *state, std::uint64_t original, std::uint64_t result);

extern "C" x86::X86State *
updateIncFlags64(x86::X86State *state, std::uint64_t original, std::uint64_t result);

extern "C" x86::X86State *
updateDecFlags32(x86::X86State *state, std::uint64_t original, std::uint64_t result);

extern "C" x86::X86State *
updateDecFlags16(x86::X86State *state, std::uint64_t original, std::uint64_t result);

extern "C" x86::X86State *
updateDecFlags8(x86::X86State *state, std::uint64_t original, std::uint64_t result);

extern "C" x86::X86State *
updateDecFlags64(x86::X86State *state, std::uint64_t original, std::uint64_t result);

extern "C" x86::X86State *addGuest64(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t source) noexcept;

extern "C" x86::X86State *addGuest8(GuestExecutionContext *context,
                                                              x86::X86State *state,
                                                              std::uint64_t address,
                                                              std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *addGuest16(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *addGuest32(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *
updateSubFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs, std::uint64_t result);

extern "C" x86::X86State *updateSubFlags32(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue);

extern "C" x86::X86State *subGuest64(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t source) noexcept;

extern "C" x86::X86State *subGuest32(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *subGuest8(GuestExecutionContext *context,
                                                             x86::X86State *state,
                                                             std::uint64_t address,
                                                             std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *xorGuest8(GuestExecutionContext *context, x86::X86State *state,
                                    std::uint64_t address, std::uint64_t sourceValue) noexcept;
extern "C" x86::X86State *xorGuest16(GuestExecutionContext *context, x86::X86State *state,
                                     std::uint64_t address, std::uint64_t sourceValue) noexcept;
extern "C" x86::X86State *xorGuest32(GuestExecutionContext *context, x86::X86State *state,
                                     std::uint64_t address, std::uint64_t sourceValue) noexcept;
extern "C" x86::X86State *xorGuest64(GuestExecutionContext *context, x86::X86State *state,
                                     std::uint64_t address, std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *orGuest8(GuestExecutionContext *context,
                                                             x86::X86State *state,
                                                             std::uint64_t address,
                                                             std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *orGuest16(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *orGuest32(GuestExecutionContext *context,
                                                              x86::X86State *state,
                                                              std::uint64_t address,
                                                              std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *orGuest64(GuestExecutionContext *context,
                                                              x86::X86State *state,
                                                              std::uint64_t address,
                                                              std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *andGuest8(GuestExecutionContext *context,
                                                              x86::X86State *state,
                                                              std::uint64_t address,
                                                              std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *andGuest16(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *andGuest64(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *andGuest32(GuestExecutionContext *context,
                                                               x86::X86State *state,
                                                               std::uint64_t address,
                                                               std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *
incrementGuest8(GuestExecutionContext *context, x86::X86State *state,
                std::uint64_t address) noexcept;

extern "C" x86::X86State *
incrementGuest16(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept;

extern "C" x86::X86State *
incrementGuest32(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept;

extern "C" x86::X86State *
incrementGuest64(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept;

extern "C" x86::X86State *
lockedIncrementGuest32(GuestExecutionContext *context, x86::X86State *state,
                       std::uint64_t address) noexcept;

extern "C" x86::X86State *
lockedIncrementGuest64(GuestExecutionContext *context, x86::X86State *state,
                       std::uint64_t address) noexcept;

extern "C" x86::X86State *
lockedDecrementGuest32(GuestExecutionContext *context, x86::X86State *state,
                       std::uint64_t address) noexcept;

extern "C" x86::X86State *
lockedDecrementGuest64(GuestExecutionContext *context, x86::X86State *state,
                       std::uint64_t address) noexcept;

extern "C" x86::X86State *
decrementGuest32(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept;

extern "C" x86::X86State *
decrementGuest16(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept;

extern "C" x86::X86State *
decrementGuest64(GuestExecutionContext *context, x86::X86State *state,
                 std::uint64_t address) noexcept;

extern "C" x86::X86State *
decrementGuest8(GuestExecutionContext *context, x86::X86State *state,
                std::uint64_t address) noexcept;

extern "C" x86::X86State *updateSubFlags16(x86::X86State *state,
                                                                     std::uint64_t lhsValue,
                                                                     std::uint64_t rhsValue,
                                                                     std::uint64_t resultValue);

extern "C" x86::X86State *
compareExchangeGuest8(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                      std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *
compareExchangeGuest16(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                       std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *
compareExchangeGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                       std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *
compareExchangeGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                       std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *
compareExchangeGuestPair(GuestExecutionContext *context, x86::X86State *state,
                         std::uint64_t address) noexcept;

extern "C" x86::X86State *
exchangeGuest8(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
               std::uint64_t sourceValue, std::uint64_t destinationEncoding) noexcept;

extern "C" x86::X86State *
exchangeGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t sourceValue, std::uint64_t destinationEncoding) noexcept;

extern "C" x86::X86State *
exchangeGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t sourceValue, std::uint64_t destinationEncoding) noexcept;

extern "C" x86::X86State *
lockedOrGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *
lockedOrGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t immediateValue) noexcept;

extern "C" x86::X86State *
lockedOrGuest8(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
               std::uint64_t immediateValue) noexcept;

extern "C" x86::X86State *
lockedOrGuest16(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                std::uint64_t immediateValue) noexcept;

extern "C" x86::X86State *
lockedAndGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t immediateValue) noexcept;

extern "C" x86::X86State *
lockedAndGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t immediateValue) noexcept;

extern "C" x86::X86State *
lockedAndGuest16(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t immediateValue) noexcept;

extern "C" x86::X86State *
lockedAddGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t sourceValue) noexcept;

extern "C" x86::X86State *
lockedAddGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t source) noexcept;

extern "C" x86::X86State *
lockedExchangeAddGuest16(GuestExecutionContext *context, x86::X86State *state,
                         std::uint64_t address, std::uint64_t sourceValue,
                         std::uint64_t sourceEncoding) noexcept;

extern "C" x86::X86State *
lockedExchangeAddGuest32(GuestExecutionContext *context, x86::X86State *state,
                         std::uint64_t address, std::uint64_t sourceValue,
                         std::uint64_t sourceEncoding) noexcept;

extern "C" x86::X86State *
lockedExchangeAddGuest64(GuestExecutionContext *context, x86::X86State *state,
                         std::uint64_t address, std::uint64_t sourceValue,
                         std::uint64_t sourceEncoding) noexcept;

extern "C" x86::X86State *
updateShiftLeftFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t result,
                       std::uint64_t unmaskedCount);

extern "C" x86::X86State *
shiftLeftGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                 std::uint64_t countValue) noexcept;

extern "C" x86::X86State *
updateShiftRightFlags32(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                        std::uint64_t unmaskedCount);

extern "C" x86::X86State *
updateShiftRightFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t result,
                        std::uint64_t unmaskedCount);

extern "C" x86::X86State *
shiftRightGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                  std::uint64_t countValue) noexcept;

extern "C" x86::X86State *
shiftRightGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                  std::uint64_t countValue) noexcept;

extern "C" x86::X86State *
updateShiftLeftFlags32(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                       std::uint64_t unmaskedCount);

extern "C" x86::X86State *
updateShiftLeftFlags8(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                      std::uint64_t unmaskedCount);

extern "C" x86::X86State *
updateRotateLeftFlags16(x86::X86State *state, std::uint64_t resultValue,
                        std::uint64_t unmaskedCount);

extern "C" x86::X86State *
updateRotateLeftFlags32(x86::X86State *state, std::uint64_t resultValue,
                        std::uint64_t unmaskedCount);

extern "C" x86::X86State *
updateRotateLeftFlags64(x86::X86State *state, std::uint64_t result, std::uint64_t unmaskedCount);

extern "C" x86::X86State *
updateRotateRightFlags64(x86::X86State *state, std::uint64_t result, std::uint64_t unmaskedCount);

extern "C" x86::X86State *
updateRotateRightFlags32(x86::X86State *state, std::uint64_t result, std::uint64_t unmaskedCount);

extern "C" x86::X86State *
updateShiftRightFlags8(x86::X86State *state, std::uint64_t lhsValue, std::uint64_t resultValue,
                       std::uint64_t unmaskedCount);

extern "C" x86::X86State *
updateShiftRightArithmeticFlags32(x86::X86State *state, std::uint64_t lhsValue,
                                  std::uint64_t resultValue, std::uint64_t unmaskedCount);

extern "C" x86::X86State *
updateShiftRightArithmeticFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t result,
                                  std::uint64_t unmaskedCount);

extern "C" x86::X86State *updateMultiplyFlags64(x86::X86State *state,
                                                                          std::uint64_t high);

extern "C" x86::X86State *
updateSignedMultiplyFlags64(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs);

extern "C" x86::X86State *
updateSignedMultiplyFlags32(x86::X86State *state, std::uint64_t lhs, std::uint64_t rhs);

extern "C" x86::X86State *
updateBitTestFlags32(x86::X86State *state, std::uint64_t value, std::uint64_t unmaskedBitIndex);

extern "C" x86::X86State *
updateBitTestFlags64(x86::X86State *state, std::uint64_t value, std::uint64_t unmaskedBitIndex);

extern "C" x86::X86State *
lockedBitSetGuest32(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                    std::uint64_t bitIndex) noexcept;

extern "C" x86::X86State *
lockedBitSetGuest64(GuestExecutionContext *context, x86::X86State *state, std::uint64_t address,
                    std::uint64_t bitIndex) noexcept;

extern "C" x86::X86State *
updateShiftRightDoubleFlags64(x86::X86State *state, std::uint64_t original, std::uint64_t result,
                              std::uint64_t unmaskedCount);

} // namespace rosa::dbt::runtime
