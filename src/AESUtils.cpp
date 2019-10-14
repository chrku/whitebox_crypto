//
// Created by Christoph Kummer on 26.02.19.
//

#include <algorithm>
#include <cassert>
#include <cstdlib>

#include <AESUtils.h>

namespace WhiteBox {
bool parse_aes_state(std::array<uint8_t, AES_KEY_LENGTH_BYTES> &aes_key,
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
    aes_key[i / 2] = static_cast<uint8_t>(key_byte);
    if (*p != '\0') {
      return false;
    }
  }
  return true;
}

uint8_t apply_AES_SBox(uint8_t input) { return AES_SBOX[input]; }

uint8_t apply_AES_inverse_SBox(uint8_t input) {
  return AES_INVERSE_SBOX[input];
}

std::array<uint8_t, 4> sub_word(const ExpandedKey &key, size_t index) {
  std::array<uint8_t, 4> return_val{};

  return_val[0] = apply_AES_SBox(key[index]);
  return_val[1] = apply_AES_SBox(key[index + 1]);
  return_val[2] = apply_AES_SBox(key[index + 2]);
  return_val[3] = apply_AES_SBox(key[index + 3]);

  return return_val;
}

void rot_word(std::array<uint8_t, 4> &input) {
  uint8_t temp = input[0];
  input[0] = input[1];
  input[1] = input[2];
  input[2] = input[3];
  input[3] = temp;
}

ExpandedKey aes_key_schedule(State aes_key) {
  ExpandedKey expanded_key;

  const unsigned int N = AES_KEY_LENGTH_BYTES / 4;  // 4

  // Do AES key schedule
  // The key is expanded according to the AES key schedule
  // See https://en.wikipedia.org/wiki/Rijndael_key_schedule
  for (std::size_t i = 0; i < (NUM_ROUNDS_AES_128 + 1) * N; ++i) {
    if (i < N) {
      expanded_key[i * N] = aes_key[i * N];
      expanded_key[i * N + 1] = aes_key[i * N + 1];
      expanded_key[i * N + 2] = aes_key[i * N + 2];
      expanded_key[i * N + 3] = aes_key[i * N + 3];
    } else if (i >= N && i % N == 0) {
      auto sub_value = sub_word(expanded_key, i * N - N);
      rot_word(sub_value);

      expanded_key[i * N] = expanded_key[i * N - N * N] ^ sub_value[0] ^
                            AES_ROUND_CONSTANTS[i / N - 1];
      expanded_key[i * N + 1] =
          expanded_key[i * N - (N * N - 1)] ^ sub_value[1];
      expanded_key[i * N + 2] =
          expanded_key[i * N - (N * N - 2)] ^ sub_value[2];
      expanded_key[i * N + 3] =
          expanded_key[i * N - (N * N - 3)] ^ sub_value[3];
    } else {
      expanded_key[i * N] =
          expanded_key[i * N - N * N] ^ expanded_key[i * N - N];
      expanded_key[i * N + 1] =
          expanded_key[i * N - (N * N - 1)] ^ expanded_key[i * N - (N - 1)];
      expanded_key[i * N + 2] =
          expanded_key[i * N - (N * N - 2)] ^ expanded_key[i * N - (N - 2)];
      expanded_key[i * N + 3] =
          expanded_key[i * N - (N * N - 3)] ^ expanded_key[i * N - (N - 3)];
    }
  }
  return expanded_key;
}

// AES functions, used for testing

State shift_rows(State current_state) {
  State new_state;

  // AES shift-rows permutation, according to the standard
  new_state[0] = current_state[0];
  new_state[1] = current_state[5];
  new_state[2] = current_state[10];
  new_state[3] = current_state[15];

  new_state[4] = current_state[4];
  new_state[5] = current_state[9];
  new_state[6] = current_state[14];
  new_state[7] = current_state[3];

  new_state[8] = current_state[8];
  new_state[9] = current_state[13];
  new_state[10] = current_state[2];
  new_state[11] = current_state[7];

  new_state[12] = current_state[12];
  new_state[13] = current_state[1];
  new_state[14] = current_state[6];
  new_state[15] = current_state[11];

  return new_state;
}

State inverse_shift_rows(State current_state) {
  State new_state;

  // AES inverse shift-rows permutation, according to the standard
  new_state[0] = current_state[0];
  new_state[1] = current_state[13];
  new_state[2] = current_state[10];
  new_state[3] = current_state[7];

  new_state[4] = current_state[4];
  new_state[5] = current_state[1];
  new_state[6] = current_state[14];
  new_state[7] = current_state[11];

  new_state[8] = current_state[8];
  new_state[9] = current_state[5];
  new_state[10] = current_state[2];
  new_state[11] = current_state[15];

  new_state[12] = current_state[12];
  new_state[13] = current_state[9];
  new_state[14] = current_state[6];
  new_state[15] = current_state[3];

  return new_state;
}

uint32_t get_inverse_shifted_index(uint32_t index) {
  switch (index) {
    case 0:
      return 0;
    case 1:
      return 13;
    case 2:
      return 10;
    case 3:
      return 7;
    case 4:
      return 4;
    case 5:
      return 1;
    case 6:
      return 14;
    case 7:
      return 11;
    case 8:
      return 8;
    case 9:
      return 5;
    case 10:
      return 2;
    case 11:
      return 15;
    case 12:
      return 12;
    case 13:
      return 9;
    case 14:
      return 6;
    case 15:
      return 3;
    default:
      std::abort();
  }
}

uint32_t get_shifted_index(uint32_t index) {
  switch (index) {
    case 0:
      return 0;
    case 1:
      return 5;
    case 2:
      return 10;
    case 3:
      return 15;
    case 4:
      return 4;
    case 5:
      return 9;
    case 6:
      return 14;
    case 7:
      return 3;
    case 8:
      return 8;
    case 9:
      return 13;
    case 10:
      return 2;
    case 11:
      return 7;
    case 12:
      return 12;
    case 13:
      return 1;
    case 14:
      return 6;
    case 15:
      return 11;
    default:
      std::abort();
  }
}

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

// Multiplication in Rijndael's finite field
// As described by https://www.samiam.org/galois.html
// and also on Wikipedia https://en.wikipedia.org/wiki/Rijndael_MixColumns
uint8_t galois_mul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (size_t i = 0; i < 8; ++i) {
    if (b % 2 == 1) {
      p ^= a;
    }
    bool high_set = (a & 0x80) == 0x80;
    a <<= 1;
    if (high_set) a ^= 0x1b;
    b >>= 1;
  }

  return p;
}

State operator^(const State &lhs, const State &rhs) {
  State return_val;
  // Apply lambda to each of these sequences
  std::transform(lhs.begin(), lhs.end(), rhs.begin(), return_val.begin(),
                 [](auto a, auto b) { return a ^ b; });
  return return_val;
}
}  // namespace WhiteBox
