
#include <iostream>
#include <string>
#include <memory>
#include <algorithm>

struct WhiteBoxData;

#include "whiteboxtable.h"

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

// This is more of a convenience than a performance improvement
// as there is still a whole copy of the array needed
void shift_rows_in_place(const State &current_state, State& output_state) {
  // AES shift-rows permutation, according to the standard
  output_state[0] = current_state[0];
  output_state[1] = current_state[5];
  output_state[2] = current_state[10];
  output_state[3] = current_state[15];

  output_state[4] = current_state[4];
  output_state[5] = current_state[9];
  output_state[6] = current_state[14];
  output_state[7] = current_state[3];

  output_state[8] = current_state[8];
  output_state[9] = current_state[13];
  output_state[10] = current_state[2];
  output_state[11] = current_state[7];

  output_state[12] = current_state[12];
  output_state[13] = current_state[1];
  output_state[14] = current_state[6];
  output_state[15] = current_state[11];
}

void inverse_shift_rows_in_place(const State &current_state, State& output_state) {
  output_state[0] = current_state[0];
  output_state[1] = current_state[13];
  output_state[2] = current_state[10];
  output_state[3] = current_state[7];

  output_state[4] = current_state[4];
  output_state[5] = current_state[1];
  output_state[6] = current_state[14];
  output_state[7] = current_state[11];

  output_state[8] = current_state[8];
  output_state[9] = current_state[5];
  output_state[10] = current_state[2];
  output_state[11] = current_state[15];

  output_state[12] = current_state[12];
  output_state[13] = current_state[9];
  output_state[14] = current_state[6];
  output_state[15] = current_state[3];
}

void calculate_intermediate_tyi_box_results(
  const WhiteBoxData &tables,
  const State &state, IntermediateState &output_state,
  size_t round) {
  for (size_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
    output_state[i] = tables.tyiTables_[round][i][state[i]];
  }
}

void calculate_mixing_table_results(
  const WhiteBoxData &white_box_encryption_data, const State &state,
  IntermediateState &output_state, size_t round) {
  for (size_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
    output_state[i] = white_box_encryption_data.mixingTables_[round][i][state[i]];
  }
}

void calculate_first_xor_cascade(const WhiteBoxData &tables,
                                 const IntermediateState &state,
                                 IntermediateState2 &output_state,
                                 size_t round,
                                 bool use_mixing_tables) {
  const auto &xor_tables =
    (use_mixing_tables) ? tables.mixingXorTables_ : tables.xorTables_;

  for (size_t i = 0; i < AES_KEY_LENGTH_BYTES; i += 4) {
    uint32_t intermediate_1 = state[i];
    uint32_t intermediate_2 = state[i + 1];
    uint32_t intermediate_3 = state[i + 2];
    uint32_t intermediate_4 = state[i + 3];

    auto nibble_1 = static_cast<uint8_t>((intermediate_1 & 0xFU) << 4);
    auto nibble_2 = static_cast<uint8_t>(intermediate_1 & 0xF0U);
    auto nibble_3 = static_cast<uint8_t>((intermediate_1 & 0xF00U) >> 4);
    auto nibble_4 = static_cast<uint8_t>((intermediate_1 & 0xF000U) >> 8);
    auto nibble_5 = static_cast<uint8_t>((intermediate_1 & 0xF0000U) >> 12);
    auto nibble_6 = static_cast<uint8_t>((intermediate_1 & 0xF00000U) >> 16);
    auto nibble_7 = static_cast<uint8_t>((intermediate_1 & 0xF000000U) >> 20);
    auto nibble_8 = static_cast<uint8_t>((intermediate_1 & 0xF0000000U) >> 24);

    auto nibble_9 = static_cast<uint8_t>(intermediate_2 & 0xFU);
    auto nibble_10 = static_cast<uint8_t>((intermediate_2 & 0xF0U) >> 4);
    auto nibble_11 = static_cast<uint8_t>((intermediate_2 & 0xF00U) >> 8);
    auto nibble_12 = static_cast<uint8_t>((intermediate_2 & 0xF000U) >> 12);
    auto nibble_13 = static_cast<uint8_t>((intermediate_2 & 0xF0000U) >> 16);
    auto nibble_14 = static_cast<uint8_t>((intermediate_2 & 0xF00000U) >> 20);
    auto nibble_15 = static_cast<uint8_t>((intermediate_2 & 0xF000000U) >> 24);
    auto nibble_16 = static_cast<uint8_t>((intermediate_2 & 0xF0000000U) >> 28);

    auto nibble_17 = static_cast<uint8_t>((intermediate_3 & 0xFU) << 4);
    auto nibble_18 = static_cast<uint8_t>(intermediate_3 & 0xF0U);
    auto nibble_19 = static_cast<uint8_t>((intermediate_3 & 0xF00U) >> 4);
    auto nibble_20 = static_cast<uint8_t>((intermediate_3 & 0xF000U) >> 8);
    auto nibble_21 = static_cast<uint8_t>((intermediate_3 & 0xF0000U) >> 12);
    auto nibble_22 = static_cast<uint8_t>((intermediate_3 & 0xF00000U) >> 16);
    auto nibble_23 = static_cast<uint8_t>((intermediate_3 & 0xF000000U) >> 20);
    auto nibble_24 = static_cast<uint8_t>((intermediate_3 & 0xF0000000U) >> 24);

    auto nibble_25 = static_cast<uint8_t>(intermediate_4 & 0xFU);
    auto nibble_26 = static_cast<uint8_t>((intermediate_4 & 0xF0U) >> 4);
    auto nibble_27 = static_cast<uint8_t>((intermediate_4 & 0xF00U) >> 8);
    auto nibble_28 = static_cast<uint8_t>((intermediate_4 & 0xF000U) >> 12);
    auto nibble_29 = static_cast<uint8_t>((intermediate_4 & 0xF0000U) >> 16);
    auto nibble_30 = static_cast<uint8_t>((intermediate_4 & 0xF00000U) >> 20);
    auto nibble_31 = static_cast<uint8_t>((intermediate_4 & 0xF000000U) >> 24);
    auto nibble_32 = static_cast<uint8_t>((intermediate_4 & 0xF0000000U) >> 28);

    uint8_t intermediate_nibble_8 =
      xor_tables[round][i * 4][nibble_8 | nibble_16];
    uint8_t intermediate_nibble_7 =
      xor_tables[round][i * 4 + 1][nibble_7 | nibble_15];
    uint8_t intermediate_nibble_6 =
      xor_tables[round][i * 4 + 2][nibble_6 | nibble_14];
    uint8_t intermediate_nibble_5 =
      xor_tables[round][i * 4 + 3][nibble_5 | nibble_13];
    uint8_t intermediate_nibble_4 =
      xor_tables[round][i * 4 + 4][nibble_4 | nibble_12];
    uint8_t intermediate_nibble_3 =
      xor_tables[round][i * 4 + 5][nibble_3 | nibble_11];
    uint8_t intermediate_nibble_2 =
      xor_tables[round][i * 4 + 6][nibble_2 | nibble_10];
    uint8_t intermediate_nibble_1 =
      xor_tables[round][i * 4 + 7][nibble_1 | nibble_9];

    uint32_t res_1 =
      (intermediate_nibble_8 << 28) | (intermediate_nibble_7 << 24) |
      (intermediate_nibble_6 << 20) | (intermediate_nibble_5 << 16) |
      (intermediate_nibble_4 << 12) | (intermediate_nibble_3 << 8) |
      (intermediate_nibble_2 << 4) | intermediate_nibble_1;

    uint8_t intermediate_nibble_16 =
      xor_tables[round][i * 4 + 8][nibble_24 | nibble_32];
    uint8_t intermediate_nibble_15 =
      xor_tables[round][i * 4 + 9][nibble_23 | nibble_31];
    uint8_t intermediate_nibble_14 =
      xor_tables[round][i * 4 + 10][nibble_22 | nibble_30];
    uint8_t intermediate_nibble_13 =
      xor_tables[round][i * 4 + 11][nibble_21 | nibble_29];
    uint8_t intermediate_nibble_12 =
      xor_tables[round][i * 4 + 12][nibble_20 | nibble_28];
    uint8_t intermediate_nibble_11 =
      xor_tables[round][i * 4 + 13][nibble_19 | nibble_27];
    uint8_t intermediate_nibble_10 =
      xor_tables[round][i * 4 + 14][nibble_18 | nibble_26];
    uint8_t intermediate_nibble_9 =
      xor_tables[round][i * 4 + 15][nibble_17 | nibble_25];

    uint32_t res_2 =
      (intermediate_nibble_16 << 28) | (intermediate_nibble_15 << 24) |
      (intermediate_nibble_14 << 20) | (intermediate_nibble_13 << 16) |
      (intermediate_nibble_12 << 12) | (intermediate_nibble_11 << 8) |
      (intermediate_nibble_10 << 4) | intermediate_nibble_9;

    output_state[(i / 2)] = res_1;
    output_state[(i / 2) + 1] = res_2;
  }
}

void calculate_second_xor_cascade(const WhiteBoxData &tables,
                                  const IntermediateState2 &state,
                                  State &output_state, size_t round,
                                  bool use_mixing_tables) {
  const auto &xor_tables =
    (use_mixing_tables) ? tables.mixingXorTables_ : tables.xorTables_;

  for (size_t i = 0; i < AES_KEY_LENGTH_BYTES / 2; i += 2) {
    uint32_t left = state[i];
    uint32_t right = state[i + 1];

    auto nibble_1 = static_cast<uint8_t>((left & 0xFU) << 4);
    auto nibble_2 = static_cast<uint8_t>(left & 0xF0U);
    auto nibble_3 = static_cast<uint8_t>((left & 0xF00U) >> 4);
    auto nibble_4 = static_cast<uint8_t>((left & 0xF000U) >> 8);
    auto nibble_5 = static_cast<uint8_t>((left & 0xF0000U) >> 12);
    auto nibble_6 = static_cast<uint8_t>((left & 0xF00000U) >> 16);
    auto nibble_7 = static_cast<uint8_t>((left & 0xF000000U) >> 20);
    auto nibble_8 = static_cast<uint8_t>((left & 0xF0000000U) >> 24);

    auto nibble_9 = static_cast<uint8_t>(right & 0xFU);
    auto nibble_10 = static_cast<uint8_t>((right & 0xF0U) >> 4);
    auto nibble_11 = static_cast<uint8_t>((right & 0xF00U) >> 8);
    auto nibble_12 = static_cast<uint8_t>((right & 0xF000U) >> 12);
    auto nibble_13 = static_cast<uint8_t>((right & 0xF0000U) >> 16);
    auto nibble_14 = static_cast<uint8_t>((right & 0xF00000U) >> 20);
    auto nibble_15 = static_cast<uint8_t>((right & 0xF000000U) >> 24);
    auto nibble_16 = static_cast<uint8_t>((right & 0xF0000000U) >> 28);

    uint8_t final_nibble_8 =
      xor_tables[round][i * 4 + XOR_TABLE_OFFSET][nibble_8 | nibble_16];
    uint8_t final_nibble_7 =
      xor_tables[round][i * 4 + XOR_TABLE_OFFSET + 1][nibble_7 | nibble_15];
    uint8_t final_nibble_6 =
      xor_tables[round][i * 4 + XOR_TABLE_OFFSET + 2][nibble_6 | nibble_14];
    uint8_t final_nibble_5 =
      xor_tables[round][i * 4 + XOR_TABLE_OFFSET + 3][nibble_5 | nibble_13];
    uint8_t final_nibble_4 =
      xor_tables[round][i * 4 + XOR_TABLE_OFFSET + 4][nibble_4 | nibble_12];
    uint8_t final_nibble_3 =
      xor_tables[round][i * 4 + XOR_TABLE_OFFSET + 5][nibble_3 | nibble_11];
    uint8_t final_nibble_2 =
      xor_tables[round][i * 4 + XOR_TABLE_OFFSET + 6][nibble_2 | nibble_10];
    uint8_t final_nibble_1 =
      xor_tables[round][i * 4 + XOR_TABLE_OFFSET + 7][nibble_1 | nibble_9];

    output_state[2 * i] = (final_nibble_8 << 4) | final_nibble_7;
    output_state[2 * i + 1] = (final_nibble_6 << 4) | final_nibble_5;
    output_state[2 * i + 2] = (final_nibble_4 << 4) | final_nibble_3;
    output_state[2 * i + 3] = (final_nibble_2 << 4) | final_nibble_1;
  }
}

void apply_final_round_t_boxes(const WhiteBoxData &tables, const State& state, State& output_state) {
  for (size_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
    output_state[i] = tables.finalRoundTBoxes_[i][state[i]];
  }
}

State interpret_white_box_mixing(const WhiteBoxData &white_box_encryption_data,
                                 const State &state, bool decrypt) {
  State finalResult = state;
  State shifted_state;
  IntermediateState intermediateState;
  IntermediateState2 intermediateState2;

  for (size_t i = 0; i < 9; ++i) {
    if (!decrypt)
      shift_rows_in_place(finalResult, shifted_state);
    else
      inverse_shift_rows_in_place(finalResult, shifted_state);

    calculate_intermediate_tyi_box_results(
      white_box_encryption_data, shifted_state, intermediateState, i);
    calculate_first_xor_cascade(
      white_box_encryption_data, intermediateState, intermediateState2, i, false);
    calculate_second_xor_cascade(white_box_encryption_data,
                                 intermediateState2, finalResult, i, false);
    calculate_mixing_table_results(
      white_box_encryption_data, finalResult, intermediateState, i);
    calculate_first_xor_cascade(
      white_box_encryption_data, intermediateState, intermediateState2, i, true);
    calculate_second_xor_cascade(white_box_encryption_data,
                                 intermediateState2, finalResult, i, true);
  }

  if (!decrypt)
    shift_rows_in_place(finalResult, shifted_state);
  else
    inverse_shift_rows_in_place(finalResult, shifted_state);
  apply_final_round_t_boxes(white_box_encryption_data, shifted_state, finalResult);

  return finalResult;
}

State interpret_white_box(const WhiteBoxData &white_box_encryption_data,
                          const State &input_state, bool decrypt) {

    State state1 = interpret_white_box_mixing(white_box_encryption_data, input_state,
                                      decrypt);
    State state2 = interpret_white_box_mixing(white_box_encryption_data, input_state,
                                      decrypt);
    State defaultState;
    defaultState.fill(0);

    if (state1 == state2)
      return interpret_white_box_mixing(white_box_encryption_data, input_state,
                                        decrypt);
    else
      return defaultState;
}

bool parse_aes_state(std::array<uint8_t, AES_KEY_LENGTH_BYTES> &aes_state,
                     const std::string &arg_string) {
  std::string state_string(arg_string);
  // Strip white space
  auto iter = std::remove(state_string.begin(), state_string.end(), ' ');
  state_string.erase(iter, state_string.end());
  // Zero-pad string for easier parsing
  if (state_string.size() < AES_KEY_LENGTH_BYTES * 2) {
    state_string.insert(0, AES_KEY_LENGTH_BYTES * 2 - state_string.size(), '0');
  } else if (state_string.size() > AES_KEY_LENGTH_BYTES * 2) {
    return false;
  }

  for (auto i = 0; i < AES_KEY_LENGTH_BYTES * 2; i += 2) {
    char *p;
    std::string key_byte_string = state_string.substr(i, 2);
    unsigned long key_byte = std::strtoul(key_byte_string.c_str(), &p, 16);
    aes_state[i / 2] = static_cast<uint8_t>(key_byte);
    if (*p != '\0') {
      return false;
    }
  }
  return true;
}

int main(int argc, char* argv[]) {

  if (argc < 2) {
    std::cout << "Usage: whitebox <state> [encrypt|decrypt]" << std::endl;
    return -1;
  }

  bool decrypt = false;
  if (argc > 2) {
    std::string decrypt = argv[2];
    if (decrypt == "decrypt")
      decrypt = true;
  }

  std::string arg = argv[1];
  State aes_state;

  if (!parse_aes_state(aes_state, arg)) {
    std::cout << "Could not parse state as hex string" << std::endl;
    return -1;
  }

  State result = interpret_white_box(data, aes_state, decrypt);

  for (auto byte : result) {
    std::cout << std::hex << static_cast<int>(byte);
  }
  std::cout << std::endl;

  return 0;
}
