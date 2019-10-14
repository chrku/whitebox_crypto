//
// Created by Christoph Kummer on 26.02.19.
//

#ifndef WHITEBOX_DEFINITIONS_H_
#define WHITEBOX_DEFINITIONS_H_

#include <array>
#include <cstdint>
#include <cstdlib>

namespace WhiteBox {
constexpr int AES_KEY_LENGTH_BYTES = 16;
constexpr int AES_BLOCK_SIZE_BYTES = 16;
constexpr int NUM_ROUNDS_AES_128 = 10;
constexpr int NUM_ROUND_KEYS_AES_128 = 11;
constexpr int ROUND_XOR_TABLES = 96;

constexpr size_t XOR_TABLE_OFFSET = 16 * 4;

typedef std::array<uint8_t, NUM_ROUND_KEYS_AES_128 * AES_KEY_LENGTH_BYTES>
    ExpandedKey;
typedef std::array<uint8_t, AES_KEY_LENGTH_BYTES> State;
typedef std::array<uint32_t, AES_KEY_LENGTH_BYTES> IntermediateState;
typedef std::array<uint32_t, 8> IntermediateState2;

typedef std::array<uint8_t, std::numeric_limits<uint8_t>::max() + 1> TBox;
typedef std::array<TBox, AES_KEY_LENGTH_BYTES> RoundTBoxes;
typedef std::array<RoundTBoxes, NUM_ROUNDS_AES_128> TBoxes;

typedef std::array<uint32_t, std::numeric_limits<uint8_t>::max() + 1> TyiTable;
typedef std::array<TyiTable, AES_KEY_LENGTH_BYTES> TyiTablesRound;
typedef std::array<TyiTablesRound, NUM_ROUNDS_AES_128> TyiTables;

typedef std::array<uint8_t, std::numeric_limits<uint8_t>::max() + 1> XorTable;
typedef std::array<XorTable, ROUND_XOR_TABLES> RoundXorTables;
typedef std::array<RoundXorTables, NUM_ROUNDS_AES_128> XorTables;

typedef std::array<uint32_t, std::numeric_limits<uint8_t>::max() + 1>
    MixingTable;
typedef std::array<MixingTable, AES_KEY_LENGTH_BYTES> RoundMixingTables;
typedef std::array<RoundMixingTables, NUM_ROUNDS_AES_128> MixingTables;
}  // namespace WhiteBox

#endif  // WHITEBOX_DEFINITIONS_H_
