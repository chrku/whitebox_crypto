//
// Created by Christoph Kummer on 26.02.19.
//

#include <WhiteBoxTableGenerator.h>
#include <iostream>
#include <vector>

#include <NTL/GF2X.h>
#include <NTL/vec_GF2.h>

#include <RandomPermutation.h>

namespace WhiteBox {
  WhiteBoxTableGenerator::WhiteBoxTableGenerator(
      std::array<uint8_t, AES_KEY_LENGTH_BYTES> aes_key,
      bool use_internal_encoding, bool use_mixing_bijections)
      : aesKey_(aes_key), usesMixingBijections_(use_mixing_bijections) {
    // Calculate round keys
    expandedAesKey_ = aes_key_schedule(aesKey_);

    // Encryption
    // Calculate T-Boxes and Tyi Tables
    TBoxes intermediateTBoxes = calculateTBoxes();
    calculateTyiTables(intermediateTBoxes);
    calculateXorTables(&xorTables_);

    // Decryption
    intermediateTBoxes = calculateTBoxesDecryption();
    calculateTyiTablesDecryption(intermediateTBoxes);
    calculateXorTables(&xorTablesDecryption_);

    if (use_mixing_bijections) {
      calculateMixingBijections();
    }

    if (use_internal_encoding) {
      if (use_mixing_bijections) {
        calculateInternalEncodingsWithMixingBijections();
      } else {
        calculateInternalEncodings();
      }
    }
  }

  TBoxes WhiteBoxTableGenerator::calculateTBoxes() {
    // Calculate T-Boxes for each round
    TBoxes tBoxes{};
    for (size_t i = 1; i < NUM_ROUNDS_AES_128; ++i) {
      State current_round_key;

      // Copy round key to current state
      std::copy(expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * (i - 1),
                expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * (i - 1) +
                AES_KEY_LENGTH_BYTES,
                current_round_key.begin());
      // Apply shift-rows to state
      current_round_key = shift_rows(current_round_key);

      // Create the 16 T-Boxes for this round
      for (size_t j = 0; j < AES_KEY_LENGTH_BYTES; ++j) {
        for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
          tBoxes[i - 1][j][x] =
              apply_AES_SBox(static_cast<uint8_t>(x ^ current_round_key[j]));
        }
      }
    }

    // The last round has special rules
    State round_key_9{};
    State round_key_10{};

    // Copy round keys 9 and 10
    std::copy(
        expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * 9,
        expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * 9 + AES_KEY_LENGTH_BYTES,
        round_key_9.begin());
    std::copy(expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * 10,
              expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * 10 +
              AES_KEY_LENGTH_BYTES,
              round_key_10.begin());

    // Only round key 9 gets shifted in this round
    State shifted_round_key_9 = shift_rows(round_key_9);
    for (size_t j = 0; j < AES_KEY_LENGTH_BYTES; ++j) {
      for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
        // These T-Boxes are inherent to the resultant algorithm, therefore
        // they must be saved separately
        finalRoundTBoxes_[j][x] =
            apply_AES_SBox(static_cast<uint8_t>(x ^ shifted_round_key_9[j])) ^
            round_key_10[j];
      }
    }

    return tBoxes;
  }

  TBoxes WhiteBoxTableGenerator::calculateTBoxesDecryption() {
    // We start with the last round in decryption
    State round_key_9{};
    State round_key_10{};

    // Copy round keys 9 and 10
    std::copy(
        expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * 9,
        expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * 9 + AES_KEY_LENGTH_BYTES,
        round_key_9.begin());
    std::copy(expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * 10,
              expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * 10 +
              AES_KEY_LENGTH_BYTES,
              round_key_10.begin());

    // Calculate T-Boxes for each round
    TBoxes tBoxes{};
    // Only round key 9 gets shifted in this round
    State shifted_round_key_10 = inverse_shift_rows(round_key_10);

    for (size_t j = 0; j < AES_KEY_LENGTH_BYTES; ++j) {
      for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
        tBoxes[0][j][x] = apply_AES_inverse_SBox(
            static_cast<uint8_t>(x ^ shifted_round_key_10[j])) ^
                          round_key_9[j];
      }
    }

    for (size_t i = 8; i >= 1; --i) {
      State current_round_key;

      // Copy round key to current state
      std::copy(expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * i,
                expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES * i +
                AES_KEY_LENGTH_BYTES,
                current_round_key.begin());

      // Create the 16 T-Boxes for this round
      for (size_t j = 0; j < AES_KEY_LENGTH_BYTES; ++j) {
        for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
          tBoxes[8 - i + 1][j][x] =
              apply_AES_inverse_SBox(static_cast<uint8_t>(x)) ^
              current_round_key[j];
        }
      }
    }

    // Generate the T-Boxes for the last round
    State round_key_0{};
    std::copy(expandedAesKey_.begin(),
              expandedAesKey_.begin() + AES_KEY_LENGTH_BYTES,
              round_key_0.begin());
    for (size_t j = 0; j < AES_KEY_LENGTH_BYTES; ++j) {
      for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
        finalRoundTBoxesDecryption_[j][x] =
            apply_AES_inverse_SBox(static_cast<uint8_t>(x)) ^ round_key_0[j];
      }
    }

    return tBoxes;
  }

  void WhiteBoxTableGenerator::calculateMixingBijections() {
    std::vector<MixingBijection<uint8_t>> bijections_8;
    std::vector<MixingBijection<uint8_t>> bijections_8_dec;
    std::vector<MixingBijection<uint32_t>> bijections_32;
    std::vector<MixingBijection<uint32_t>> bijections_32_dec;
    std::vector<MixingBijection<uint32_t>> bijections_8_concat;
    std::vector<MixingBijection<uint32_t>> bijections_8_concat_dec;

    calculateXorTables(&mixingXorTables_);
    calculateXorTables(&mixingXorTablesDecryption_);

    for (uint32_t i = 0; i < 9; ++i) {
      bijections_32.clear();
      bijections_32_dec.clear();
      for (uint32_t j = 0; j < 4; ++j) {
        bijections_32.emplace_back(rng);
        bijections_32_dec.emplace_back(rng);
      }

      mixTyiTables(i, bijections_8, bijections_32, i != 0);
      mixTyiTablesDecryption(i, bijections_8_dec, bijections_32_dec, i != 0);

      bijections_8.clear();
      bijections_8_dec.clear();
      for (uint32_t j = 0; j < 16; ++j) {
        bijections_8.emplace_back(rng);
        bijections_8_dec.emplace_back(rng);
      }
      bijections_8_concat.clear();
      bijections_8_concat_dec.clear();
      for (uint32_t j = 0; j < 16; j += 4) {
        MixingBijection<uint32_t> mb_concat =
            concatenateBijections(bijections_8[j + 3], bijections_8[j + 2],
                                  bijections_8[j + 1], bijections_8[j]);
        MixingBijection<uint32_t> mb_concat_dec = concatenateBijections(
            bijections_8_dec[j + 3], bijections_8_dec[j + 2],
            bijections_8_dec[j + 1], bijections_8_dec[j]);
        bijections_8_concat.push_back(mb_concat);
        bijections_8_concat_dec.push_back(mb_concat_dec);
      }

      calculateMixingTables(&mixingTables_, i, bijections_32, bijections_8_concat,
                            true);
      calculateMixingTables(&mixingTablesDecryption_, i, bijections_32_dec,
                            bijections_8_concat_dec, true);
    }

    mixFinalRoundTBoxes(bijections_8);
    mixFinalRoundTBoxesDecryption(bijections_8_dec);
  }

  void WhiteBoxTableGenerator::calculateMixingTables(
      MixingTables *mixing_tables, size_t round,
      const std::vector<MixingBijection<uint32_t>> &bijections_32,
      const std::vector<MixingBijection<uint32_t>> &bijections_8_concat,
      bool use_output_mixing_bijections) const {
    if (mixing_tables == nullptr) return;

    for (size_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
        NTL::vec_GF2 v;
        v.SetLength(32);

        for (size_t j = 0; j < 32; ++j) {
          v.put(j, 0);
        }

        if (i % 4 == 3) {
          for (size_t k = 0; k < 8; ++k) {
            auto zero_at_pos = static_cast<uint32_t>((x & (1 << k)) != 0);
            v.put(k, zero_at_pos);
          }
        } else if (i % 4 == 2) {
          for (size_t k = 8; k < 16; ++k) {
            auto zero_at_pos = static_cast<uint32_t>((x & (1 << (k - 8))) != 0);
            v.put(k, zero_at_pos);
          }
        } else if (i % 4 == 1) {
          for (size_t k = 16; k < 24; ++k) {
            auto zero_at_pos = static_cast<uint32_t>((x & (1 << (k - 16))) != 0);
            v.put(k, zero_at_pos);
          }
        } else if (i % 4 == 0) {
          for (size_t k = 24; k < 32; ++k) {
            auto zero_at_pos = static_cast<uint32_t>((x & (1 << (k - 24))) != 0);
            v.put(k, zero_at_pos);
          }
        }

        uint32_t transformed = bijections_32[i / 4].applyInverseTransformation(v);
        if (use_output_mixing_bijections) {
          transformed =
              bijections_8_concat[i / 4].applyTransformation(transformed);
        }
        (*mixing_tables)[round][i][x] = transformed;
      }
    }
  }

  void WhiteBoxTableGenerator::mixTyiTables(
      size_t round, const std::vector<MixingBijection<uint8_t>> &bijections_8,
      const std::vector<MixingBijection<uint32_t>> &bijections_32,
      bool use_input_mixing_bijection) {
    for (uint32_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      TyiTable look_up_copy = tyiTables_[round][i];
      uint32_t shifted_index = get_shifted_index(i);

      for (uint32_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
        auto transformed_val = static_cast<uint8_t>(j);
        if (use_input_mixing_bijection) {
          transformed_val =
              bijections_8[shifted_index].applyInverseTransformation(
                  transformed_val);
        }
        uint32_t tyi_Val = look_up_copy[transformed_val];
        tyi_Val = bijections_32[i / 4].applyTransformation(tyi_Val);
        tyiTables_[round][i][j] = tyi_Val;
      }
    }
  }

  void WhiteBoxTableGenerator::mixTyiTablesDecryption(
      size_t round, const std::vector<MixingBijection<uint8_t>> &bijections_8,
      const std::vector<MixingBijection<uint32_t>> &bijections_32,
      bool use_input_mixing_bijection) {
    for (uint32_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      TyiTable look_up_copy = tyiTablesDecryption_[round][i];
      uint32_t shifted_index = get_inverse_shifted_index(i);

      for (uint32_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
        auto transformed_val = static_cast<uint8_t>(j);
        if (use_input_mixing_bijection) {
          transformed_val =
              bijections_8[shifted_index].applyInverseTransformation(
                  transformed_val);
        }
        uint32_t tyi_Val = look_up_copy[transformed_val];
        tyi_Val = bijections_32[i / 4].applyTransformation(tyi_Val);
        tyiTablesDecryption_[round][i][j] = tyi_Val;
      }
    }
  }

  void WhiteBoxTableGenerator::mixFinalRoundTBoxes(
      const std::vector<MixingBijection<uint8_t>> &bijections_8) {
    RoundTBoxes look_up_copy = finalRoundTBoxes_;
    for (uint32_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      uint32_t shifted_index = get_shifted_index(i);
      for (uint32_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
        auto transformed_val = static_cast<uint8_t>(j);
        transformed_val = bijections_8[shifted_index].applyInverseTransformation(
            transformed_val);
        uint8_t result = look_up_copy[i][transformed_val];
        finalRoundTBoxes_[i][j] = result;
      }
    }
  }

  void WhiteBoxTableGenerator::mixFinalRoundTBoxesDecryption(
      const std::vector<MixingBijection<uint8_t>> &bijections_8) {
    RoundTBoxes look_up_copy = finalRoundTBoxesDecryption_;
    for (uint32_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      uint32_t shifted_index = get_inverse_shifted_index(i);
      for (uint32_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
        auto transformed_val = static_cast<uint8_t>(j);
        transformed_val = bijections_8[shifted_index].applyInverseTransformation(
            transformed_val);
        uint8_t result = look_up_copy[i][transformed_val];
        finalRoundTBoxesDecryption_[i][j] = result;
      }
    }
  }

  void WhiteBoxTableGenerator::calculateInternalEncodings() {
    std::vector<RandomPermutation<uint8_t>> tyi_output;
    std::vector<RandomPermutation<uint8_t>> tyi_output_dec;
    std::vector<RandomPermutation<uint8_t>> xor1_output;
    std::vector<RandomPermutation<uint8_t>> xor1_output_dec;
    std::vector<RandomPermutation<uint8_t>> xor2_output;
    std::vector<RandomPermutation<uint8_t>> xor2_output_dec;

    for (size_t i = 0; i < 9; ++i) {
      // Calculate Tyi output encodings
      tyi_output.clear();
      tyi_output_dec.clear();
      for (size_t j = 0; j < 16 * 8; ++j) {
        tyi_output.emplace_back(rng, 16);
        tyi_output_dec.emplace_back(rng, 16);
      }
      encodeTyiTables(i, xor2_output, tyi_output, true, i != 0);
      encodeTyiTablesDecryption(i, xor2_output_dec, tyi_output_dec, true, i != 0);

      // Calculate XOR1 output encodings
      xor1_output.clear();
      xor1_output_dec.clear();
      for (size_t j = 0; j < 8 * 8; ++j) {
        xor1_output.emplace_back(rng, 16);
        xor1_output_dec.emplace_back(rng, 16);
      }
      encodeXorTables(&xorTables_, i, tyi_output, xor1_output, true, false);
      encodeXorTables(&xorTablesDecryption_, i, tyi_output_dec, xor1_output_dec,
                      true, false);

      // Calculate XOR2 output encodings
      xor2_output.clear();
      xor2_output_dec.clear();
      for (size_t j = 0; j < 32; ++j) {
        xor2_output.emplace_back(rng, 16);
        xor2_output_dec.emplace_back(rng, 16);
      }
      encodeXorTables(&xorTables_, i, xor1_output, xor2_output, true, true);
      encodeXorTables(&xorTablesDecryption_, i, xor1_output_dec, xor2_output_dec,
                      true, true);
    }

    encodeFinalTBoxes(xor2_output);
    encodeFinalTBoxesDecryption(xor2_output_dec);
  }

  void WhiteBoxTableGenerator::calculateInternalEncodingsWithMixingBijections() {
    std::vector<RandomPermutation<uint8_t>> tyi_output;
    std::vector<RandomPermutation<uint8_t>> xor1_output;
    std::vector<RandomPermutation<uint8_t>> xor2_output;
    std::vector<RandomPermutation<uint8_t>> mixing_table_output;
    std::vector<RandomPermutation<uint8_t>> xor3_output;
    std::vector<RandomPermutation<uint8_t>> xor4_output;
    std::vector<RandomPermutation<uint8_t>> tyi_output_dec;
    std::vector<RandomPermutation<uint8_t>> xor1_output_dec;
    std::vector<RandomPermutation<uint8_t>> xor2_output_dec;
    std::vector<RandomPermutation<uint8_t>> mixing_table_output_dec;
    std::vector<RandomPermutation<uint8_t>> xor3_output_dec;
    std::vector<RandomPermutation<uint8_t>> xor4_output_dec;

    for (size_t i = 0; i < 9; ++i) {
      // Calculate Tyi output encodings
      tyi_output.clear();
      tyi_output_dec.clear();
      for (size_t j = 0; j < 16 * 8; ++j) {
        tyi_output.emplace_back(rng, 16);
        tyi_output_dec.emplace_back(rng, 16);
      }
      encodeTyiTables(i, xor4_output, tyi_output, true, i != 0);
      encodeTyiTablesDecryption(i, xor4_output_dec, tyi_output_dec, true, i != 0);

      // Calculate XOR1 output encodings
      xor1_output.clear();
      xor1_output_dec.clear();
      for (size_t j = 0; j < 8 * 8; ++j) {
        xor1_output.emplace_back(rng, 16);
        xor1_output_dec.emplace_back(rng, 16);
      }
      encodeXorTables(&xorTables_, i, tyi_output, xor1_output, true, false);
      encodeXorTables(&xorTablesDecryption_, i, tyi_output_dec, xor1_output_dec,
                      true, false);

      // Calculate XOR2 output encodings
      xor2_output.clear();
      xor2_output_dec.clear();
      for (size_t j = 0; j < 32; ++j) {
        xor2_output.emplace_back(rng, 16);
        xor2_output_dec.emplace_back(rng, 16);
      }
      encodeXorTables(&xorTables_, i, xor1_output, xor2_output, true, true);
      encodeXorTables(&xorTablesDecryption_, i, xor1_output_dec, xor2_output_dec,
                      true, true);

      mixing_table_output.clear();
      mixing_table_output_dec.clear();
      for (size_t j = 0; j < 16 * 8; ++j) {
        mixing_table_output.emplace_back(rng, 16);
        mixing_table_output_dec.emplace_back(rng, 16);
      }
      encodeMixingTables(i, xor2_output, mixing_table_output, true);
      encodeMixingTablesDecryption(i, xor2_output_dec, mixing_table_output_dec,
                                   true);

      xor3_output.clear();
      xor3_output_dec.clear();
      for (size_t j = 0; j < 8 * 8; ++j) {
        xor3_output.emplace_back(rng, 16);
        xor3_output_dec.emplace_back(rng, 16);
      }
      encodeXorTables(&mixingXorTables_, i, mixing_table_output, xor3_output,
                      true, false);
      encodeXorTables(&mixingXorTablesDecryption_, i, mixing_table_output_dec,
                      xor3_output_dec, true, false);

      xor4_output.clear();
      xor4_output_dec.clear();
      for (size_t j = 0; j < 32; ++j) {
        xor4_output.emplace_back(rng, 16);
        xor4_output_dec.emplace_back(rng, 16);
      }
      encodeXorTables(&mixingXorTables_, i, xor3_output, xor4_output, true, true);
      encodeXorTables(&mixingXorTablesDecryption_, i, xor3_output_dec,
                      xor4_output_dec, true, true);
    }

    encodeFinalTBoxes(xor4_output);
    encodeFinalTBoxesDecryption(xor4_output_dec);
  }

  void WhiteBoxTableGenerator::encodeXorTables(
      XorTables *xor_tables, size_t round,
      const std::vector<RandomPermutation<uint8_t>> &input_encodings,
      const std::vector<RandomPermutation<uint8_t>> &output_encodings,
      bool add_output_encodings, bool use_offset) const {
    const size_t offset = (use_offset) ? XOR_TABLE_OFFSET : 0;
    const size_t limit = (use_offset) ? 4 : 8;
    if (xor_tables == nullptr) return;

    for (size_t i = 0; i < limit; ++i) {
      for (size_t j = 0; j < 8; ++j) {
        XorTable &current_table = (*xor_tables)[round][j + i * 8 + offset];
        for (size_t k = 0; k <= std::numeric_limits<uint8_t>::max(); ++k) {
          auto x = static_cast<uint8_t>((k & 0xf0) >> 4);
          auto y = static_cast<uint8_t>(k & 0xf);

          const RandomPermutation<uint8_t> &perm_1 =
              input_encodings.at(j + i * 16);
          const RandomPermutation<uint8_t> &perm_2 =
              input_encodings.at(j + i * 16 + 8);
          uint8_t left_nibble_encoded = perm_1.getOutputInverse(x);
          uint8_t right_nibble_encoded = perm_2.getOutputInverse(y);
          uint8_t xor_result_encoded = left_nibble_encoded ^ right_nibble_encoded;
          if (add_output_encodings) {
            const RandomPermutation<uint8_t> &perm_3 =
                output_encodings.at(j + i * 8);
            xor_result_encoded = perm_3.getOutput(xor_result_encoded);
          }
          current_table[(x << 4) | y] = xor_result_encoded;
        }
      }
    }
  }

  void WhiteBoxTableGenerator::encodeTyiTables(
      size_t round,
      const std::vector<RandomPermutation<uint8_t>> &input_encodings,
      const std::vector<RandomPermutation<uint8_t>> &output_encodings,
      bool add_output_encoding, bool add_input_encoding) {
    for (uint32_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      TyiTable look_up_copy = tyiTables_[round][i];
      for (uint32_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
        // Need copy as to not mess up loop
        uint32_t temp = j;
        uint32_t shifted_index = get_shifted_index(i);

        if (add_input_encoding) {
          auto x = static_cast<uint8_t>((j & 0xf0));
          x >>= 4;
          auto y = static_cast<uint8_t>(j & 0xf);

          uint32_t encoded_1 =
              input_encodings.at(shifted_index * 2).getOutputInverse(x);
          uint32_t encoded_2 =
              input_encodings.at(shifted_index * 2 + 1).getOutputInverse(y);

          temp = (encoded_1 << 4) | encoded_2;
        }

        uint32_t result = look_up_copy[temp];

        // Encode nibbles
        if (add_output_encoding) {
          // Get all 8 nibbles of result
          auto nibble_8 = static_cast<uint8_t>(result & 0xf);
          auto nibble_7 = static_cast<uint8_t>((result & 0xf0) >> 4);
          auto nibble_6 = static_cast<uint8_t>((result & 0xf00) >> 8);
          auto nibble_5 = static_cast<uint8_t>((result & 0xf000) >> 12);
          auto nibble_4 = static_cast<uint8_t>((result & 0xf0000) >> 16);
          auto nibble_3 = static_cast<uint8_t>((result & 0xf00000) >> 20);
          auto nibble_2 = static_cast<uint8_t>((result & 0xf000000) >> 24);
          auto nibble_1 = static_cast<uint8_t>((result & 0xf0000000) >> 28);
          nibble_1 = output_encodings.at(i * 8).getOutput(nibble_1);
          nibble_2 = output_encodings.at(i * 8 + 1).getOutput(nibble_2);
          nibble_3 = output_encodings.at(i * 8 + 2).getOutput(nibble_3);
          nibble_4 = output_encodings.at(i * 8 + 3).getOutput(nibble_4);
          nibble_5 = output_encodings.at(i * 8 + 4).getOutput(nibble_5);
          nibble_6 = output_encodings.at(i * 8 + 5).getOutput(nibble_6);
          nibble_7 = output_encodings.at(i * 8 + 6).getOutput(nibble_7);
          nibble_8 = output_encodings.at(i * 8 + 7).getOutput(nibble_8);
          result = (nibble_1 << 28) | (nibble_2 << 24) | (nibble_3 << 20) |
                   (nibble_4 << 16) | (nibble_5 << 12) | (nibble_6 << 8) |
                   (nibble_7 << 4) | nibble_8;
        }
        tyiTables_[round][i][j] = result;
      }
    }
  }

  void WhiteBoxTableGenerator::encodeTyiTablesDecryption(
      size_t round,
      const std::vector<RandomPermutation<uint8_t>> &input_encodings,
      const std::vector<RandomPermutation<uint8_t>> &output_encodings,
      bool add_output_encoding, bool add_input_encoding) {
    for (uint32_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      TyiTable look_up_copy = tyiTablesDecryption_[round][i];
      for (uint32_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
        // Need copy as to not mess up loop
        uint32_t temp = j;
        uint32_t shifted_index = get_inverse_shifted_index(i);

        if (add_input_encoding) {
          auto x = static_cast<uint8_t>((j & 0xf0));
          x >>= 4;
          auto y = static_cast<uint8_t>(j & 0xf);

          uint32_t encoded_1 =
              input_encodings.at(shifted_index * 2).getOutputInverse(x);
          uint32_t encoded_2 =
              input_encodings.at(shifted_index * 2 + 1).getOutputInverse(y);

          temp = (encoded_1 << 4) | encoded_2;
        }

        uint32_t result = look_up_copy[temp];

        // Encode nibbles
        if (add_output_encoding) {
          // Get all 8 nibbles of result
          auto nibble_8 = static_cast<uint8_t>(result & 0xf);
          auto nibble_7 = static_cast<uint8_t>((result & 0xf0) >> 4);
          auto nibble_6 = static_cast<uint8_t>((result & 0xf00) >> 8);
          auto nibble_5 = static_cast<uint8_t>((result & 0xf000) >> 12);
          auto nibble_4 = static_cast<uint8_t>((result & 0xf0000) >> 16);
          auto nibble_3 = static_cast<uint8_t>((result & 0xf00000) >> 20);
          auto nibble_2 = static_cast<uint8_t>((result & 0xf000000) >> 24);
          auto nibble_1 = static_cast<uint8_t>((result & 0xf0000000) >> 28);
          nibble_1 = output_encodings.at(i * 8).getOutput(nibble_1);
          nibble_2 = output_encodings.at(i * 8 + 1).getOutput(nibble_2);
          nibble_3 = output_encodings.at(i * 8 + 2).getOutput(nibble_3);
          nibble_4 = output_encodings.at(i * 8 + 3).getOutput(nibble_4);
          nibble_5 = output_encodings.at(i * 8 + 4).getOutput(nibble_5);
          nibble_6 = output_encodings.at(i * 8 + 5).getOutput(nibble_6);
          nibble_7 = output_encodings.at(i * 8 + 6).getOutput(nibble_7);
          nibble_8 = output_encodings.at(i * 8 + 7).getOutput(nibble_8);
          result = (nibble_1 << 28) | (nibble_2 << 24) | (nibble_3 << 20) |
                   (nibble_4 << 16) | (nibble_5 << 12) | (nibble_6 << 8) |
                   (nibble_7 << 4) | nibble_8;
        }
        tyiTablesDecryption_[round][i][j] = result;
      }
    }
  }

  void WhiteBoxTableGenerator::encodeFinalTBoxes(
      const std::vector<RandomPermutation<uint8_t>> &input_encodings) {
    RoundTBoxes look_up_copy = finalRoundTBoxes_;
    for (uint32_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      for (uint32_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
        // Need copy as to not mess up loop
        uint32_t temp;
        uint32_t shifted_index = get_shifted_index(i);

        auto x = static_cast<uint8_t>((j & 0xf0));
        x >>= 4;
        auto y = static_cast<uint8_t>(j & 0xf);

        uint32_t encoded_1 =
            input_encodings.at(shifted_index * 2).getOutputInverse(x);
        uint32_t encoded_2 =
            input_encodings.at(shifted_index * 2 + 1).getOutputInverse(y);

        temp = (encoded_1 << 4) | encoded_2;
        uint8_t result = look_up_copy[i][temp];
        finalRoundTBoxes_[i][j] = result;
      }
    }
  }

  void WhiteBoxTableGenerator::encodeFinalTBoxesDecryption(
      const std::vector<RandomPermutation<uint8_t>> &input_encodings) {
    RoundTBoxes look_up_copy = finalRoundTBoxesDecryption_;
    for (uint32_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      for (uint32_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
        // Need copy as to not mess up loop
        uint32_t temp;
        uint32_t shifted_index = get_inverse_shifted_index(i);

        auto x = static_cast<uint8_t>((j & 0xf0));
        x >>= 4;
        auto y = static_cast<uint8_t>(j & 0xf);

        uint32_t encoded_1 =
            input_encodings.at(shifted_index * 2).getOutputInverse(x);
        uint32_t encoded_2 =
            input_encodings.at(shifted_index * 2 + 1).getOutputInverse(y);

        temp = (encoded_1 << 4) | encoded_2;
        uint8_t result = look_up_copy[i][temp];
        finalRoundTBoxesDecryption_[i][j] = result;
      }
    }
  }

  void WhiteBoxTableGenerator::encodeMixingTables(
      size_t round,
      const std::vector<RandomPermutation<uint8_t>> &input_encodings,
      const std::vector<RandomPermutation<uint8_t>> &output_encodings,
      bool add_output_encodings) {
    for (uint32_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      MixingTable look_up_copy = mixingTables_[round][i];
      for (uint32_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
        // Need copy as to not mess up loop
        uint32_t temp;

        auto x = static_cast<uint8_t>((j & 0xf0));
        x >>= 4;
        auto y = static_cast<uint8_t>(j & 0xf);

        uint32_t encoded_1 = input_encodings.at(i * 2).getOutputInverse(x);
        uint32_t encoded_2 = input_encodings.at(i * 2 + 1).getOutputInverse(y);

        temp = (encoded_1 << 4) | encoded_2;

        uint32_t result = look_up_copy[temp];

        // Encode nibbles
        if (add_output_encodings) {
          // Get all 8 nibbles of result
          auto nibble_8 = static_cast<uint8_t>(result & 0xf);
          auto nibble_7 = static_cast<uint8_t>((result & 0xf0) >> 4);
          auto nibble_6 = static_cast<uint8_t>((result & 0xf00) >> 8);
          auto nibble_5 = static_cast<uint8_t>((result & 0xf000) >> 12);
          auto nibble_4 = static_cast<uint8_t>((result & 0xf0000) >> 16);
          auto nibble_3 = static_cast<uint8_t>((result & 0xf00000) >> 20);
          auto nibble_2 = static_cast<uint8_t>((result & 0xf000000) >> 24);
          auto nibble_1 = static_cast<uint8_t>((result & 0xf0000000) >> 28);
          nibble_1 = output_encodings.at(i * 8).getOutput(nibble_1);
          nibble_2 = output_encodings.at(i * 8 + 1).getOutput(nibble_2);
          nibble_3 = output_encodings.at(i * 8 + 2).getOutput(nibble_3);
          nibble_4 = output_encodings.at(i * 8 + 3).getOutput(nibble_4);
          nibble_5 = output_encodings.at(i * 8 + 4).getOutput(nibble_5);
          nibble_6 = output_encodings.at(i * 8 + 5).getOutput(nibble_6);
          nibble_7 = output_encodings.at(i * 8 + 6).getOutput(nibble_7);
          nibble_8 = output_encodings.at(i * 8 + 7).getOutput(nibble_8);
          result = (nibble_1 << 28) | (nibble_2 << 24) | (nibble_3 << 20) |
                   (nibble_4 << 16) | (nibble_5 << 12) | (nibble_6 << 8) |
                   (nibble_7 << 4) | nibble_8;
        }
        mixingTables_[round][i][j] = result;
      }
    }
  }

  void WhiteBoxTableGenerator::encodeMixingTablesDecryption(
      size_t round,
      const std::vector<RandomPermutation<uint8_t>> &input_encodings,
      const std::vector<RandomPermutation<uint8_t>> &output_encodings,
      bool add_output_encodings) {
    for (uint32_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      MixingTable look_up_copy = mixingTablesDecryption_[round][i];
      for (uint32_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
        // Need copy as to not mess up loop
        uint32_t temp;

        auto x = static_cast<uint8_t>((j & 0xf0));
        x >>= 4;
        auto y = static_cast<uint8_t>(j & 0xf);

        uint32_t encoded_1 = input_encodings.at(i * 2).getOutputInverse(x);
        uint32_t encoded_2 = input_encodings.at(i * 2 + 1).getOutputInverse(y);

        temp = (encoded_1 << 4) | encoded_2;

        uint32_t result = look_up_copy[temp];

        // Encode nibbles
        if (add_output_encodings) {
          // Get all 8 nibbles of result
          auto nibble_8 = static_cast<uint8_t>(result & 0xf);
          auto nibble_7 = static_cast<uint8_t>((result & 0xf0) >> 4);
          auto nibble_6 = static_cast<uint8_t>((result & 0xf00) >> 8);
          auto nibble_5 = static_cast<uint8_t>((result & 0xf000) >> 12);
          auto nibble_4 = static_cast<uint8_t>((result & 0xf0000) >> 16);
          auto nibble_3 = static_cast<uint8_t>((result & 0xf00000) >> 20);
          auto nibble_2 = static_cast<uint8_t>((result & 0xf000000) >> 24);
          auto nibble_1 = static_cast<uint8_t>((result & 0xf0000000) >> 28);
          nibble_1 = output_encodings.at(i * 8).getOutput(nibble_1);
          nibble_2 = output_encodings.at(i * 8 + 1).getOutput(nibble_2);
          nibble_3 = output_encodings.at(i * 8 + 2).getOutput(nibble_3);
          nibble_4 = output_encodings.at(i * 8 + 3).getOutput(nibble_4);
          nibble_5 = output_encodings.at(i * 8 + 4).getOutput(nibble_5);
          nibble_6 = output_encodings.at(i * 8 + 5).getOutput(nibble_6);
          nibble_7 = output_encodings.at(i * 8 + 6).getOutput(nibble_7);
          nibble_8 = output_encodings.at(i * 8 + 7).getOutput(nibble_8);
          result = (nibble_1 << 28) | (nibble_2 << 24) | (nibble_3 << 20) |
                   (nibble_4 << 16) | (nibble_5 << 12) | (nibble_6 << 8) |
                   (nibble_7 << 4) | nibble_8;
        }
        mixingTablesDecryption_[round][i][j] = result;
      }
    }
  }

  void WhiteBoxTableGenerator::calculateTyiTables(const TBoxes &tBoxes) {
    for (int i = 0; i < NUM_ROUNDS_AES_128 - 1; ++i) {
      for (size_t j = 0; j < AES_KEY_LENGTH_BYTES; ++j) {
        const TBox &t_box = tBoxes[i][j];
        if (j % 4 == 0) {
          for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
            uint8_t t = t_box[x];

            uint8_t byte_1 = galois_mul(0x2, t);
            uint8_t byte_2 = t;
            uint8_t byte_3 = t;
            uint8_t byte_4 = galois_mul(0x3, t);

            tyiTables_[i][j][x] =
                static_cast<unsigned int>((static_cast<uint32_t>(byte_1) << 24U) |
                                          (static_cast<uint32_t>(byte_2) << 16U) |
                                          (static_cast<uint32_t>(byte_3) << 8U) |
                                          static_cast<uint32_t>(byte_4));
          }
        } else if (j % 4 == 1) {
          for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
            uint8_t t = t_box[x];

            uint8_t byte_1 = galois_mul(0x3, t);
            uint8_t byte_2 = galois_mul(0x2, t);
            uint8_t byte_3 = t;
            uint8_t byte_4 = t;

            tyiTables_[i][j][x] =
                static_cast<unsigned int>((static_cast<uint32_t>(byte_1) << 24U) |
                                          (static_cast<uint32_t>(byte_2) << 16U) |
                                          (static_cast<uint32_t>(byte_3) << 8U) |
                                          static_cast<uint32_t>(byte_4));
          }
        } else if (j % 4 == 2) {
          for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
            uint8_t t = t_box[x];

            uint8_t byte_1 = t;
            uint8_t byte_2 = galois_mul(0x3, t);
            uint8_t byte_3 = galois_mul(0x2, t);
            uint8_t byte_4 = t;

            tyiTables_[i][j][x] =
                static_cast<unsigned int>((static_cast<uint32_t>(byte_1) << 24U) |
                                          (static_cast<uint32_t>(byte_2) << 16U) |
                                          (static_cast<uint32_t>(byte_3) << 8U) |
                                          static_cast<uint32_t>(byte_4));
          }
        } else {
          for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
            uint8_t t = t_box[x];

            uint8_t byte_1 = t;
            uint8_t byte_2 = t;
            uint8_t byte_3 = galois_mul(0x3, t);
            uint8_t byte_4 = galois_mul(0x2, t);

            tyiTables_[i][j][x] =
                static_cast<unsigned int>((static_cast<uint32_t>(byte_1) << 24U) |
                                          (static_cast<uint32_t>(byte_2) << 16U) |
                                          (static_cast<uint32_t>(byte_3) << 8U) |
                                          static_cast<uint32_t>(byte_4));
          }
        }
      }
    }
  }

  void WhiteBoxTableGenerator::calculateTyiTablesDecryption(
      const TBoxes &tBoxes) {
    for (uint32_t i = 0; i < NUM_ROUNDS_AES_128 - 1; ++i) {
      for (uint32_t j = 0; j < AES_KEY_LENGTH_BYTES; ++j) {
        const TBox &t_box = tBoxes[i][j];
        if (j % 4 == 0) {
          for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
            uint8_t t = t_box[x];

            uint8_t byte_1 = galois_mul(0xe, t);
            uint8_t byte_2 = galois_mul(0x9, t);
            uint8_t byte_3 = galois_mul(0xd, t);
            uint8_t byte_4 = galois_mul(0xb, t);

            tyiTablesDecryption_[i][j][x] =
                static_cast<unsigned int>((static_cast<uint32_t>(byte_1) << 24U) |
                                          (static_cast<uint32_t>(byte_2) << 16U) |
                                          (static_cast<uint32_t>(byte_3) << 8U) |
                                          static_cast<uint32_t>(byte_4));
          }
        } else if (j % 4 == 1) {
          for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
            uint8_t t = t_box[x];

            uint8_t byte_1 = galois_mul(0xb, t);
            uint8_t byte_2 = galois_mul(0xe, t);
            uint8_t byte_3 = galois_mul(0x9, t);
            uint8_t byte_4 = galois_mul(0xd, t);

            tyiTablesDecryption_[i][j][x] =
                static_cast<unsigned int>((static_cast<uint32_t>(byte_1) << 24U) |
                                          (static_cast<uint32_t>(byte_2) << 16U) |
                                          (static_cast<uint32_t>(byte_3) << 8U) |
                                          static_cast<uint32_t>(byte_4));
          }
        } else if (j % 4 == 2) {
          for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
            uint8_t t = t_box[x];

            uint8_t byte_1 = galois_mul(0xd, t);
            uint8_t byte_2 = galois_mul(0xb, t);
            uint8_t byte_3 = galois_mul(0xe, t);
            uint8_t byte_4 = galois_mul(0x9, t);

            tyiTablesDecryption_[i][j][x] =
                static_cast<unsigned int>((static_cast<uint32_t>(byte_1) << 24U) |
                                          (static_cast<uint32_t>(byte_2) << 16U) |
                                          (static_cast<uint32_t>(byte_3) << 8U) |
                                          static_cast<uint32_t>(byte_4));
          }
        } else {
          for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
            uint8_t t = t_box[x];

            uint8_t byte_1 = galois_mul(0x9, t);
            uint8_t byte_2 = galois_mul(0xd, t);
            uint8_t byte_3 = galois_mul(0xb, t);
            uint8_t byte_4 = galois_mul(0xe, t);

            tyiTablesDecryption_[i][j][x] =
                static_cast<unsigned int>((static_cast<uint32_t>(byte_1) << 24U) |
                                          (static_cast<uint32_t>(byte_2) << 16U) |
                                          (static_cast<uint32_t>(byte_3) << 8U) |
                                          static_cast<uint32_t>(byte_4));
          }
        }
      }
    }
  }

  void WhiteBoxTableGenerator::calculateXorTables(XorTables *xor_tables) const {
    if (xor_tables != nullptr) {
      for (size_t i = 0; i < 9; ++i) {
        for (size_t j = 0; j < 96; ++j) {
          for (size_t x = 0; x <= std::numeric_limits<uint8_t>::max(); ++x) {
            auto lower_nibble = static_cast<uint8_t>(x & 0xF);
            auto upper_nibble = static_cast<uint8_t>(x & 0xF0);
            (*xor_tables)[i][j][x] = (upper_nibble >> 4) ^ lower_nibble;
          }
        }
      }
    }
  }

  WhiteBoxData *WhiteBoxTableGenerator::getEncryptionTable() const {
    auto *data = new WhiteBoxData;

    // Since array has value semantics, this works
    // It is an expensive operation though
    data->finalRoundTBoxes_ = this->finalRoundTBoxes_;
    data->tyiTables_ = this->tyiTables_;
    data->xorTables_ = this->xorTables_;

    data->usesMixingBijections_ = this->usesMixingBijections_;

    data->mixingXorTables_ = this->mixingXorTables_;
    data->mixingTables_ = this->mixingTables_;

    return data;
  }

  WhiteBoxData *WhiteBoxTableGenerator::getDecryptionTable() const {
    auto *data = new WhiteBoxData;

    data->finalRoundTBoxes_ = this->finalRoundTBoxesDecryption_;
    data->tyiTables_ = this->tyiTablesDecryption_;
    data->xorTables_ = this->xorTablesDecryption_;

    data->usesMixingBijections_ = this->usesMixingBijections_;

    data->mixingXorTables_ = this->mixingXorTablesDecryption_;
    data->mixingTables_ = this->mixingTablesDecryption_;

    return data;
  }
}  // namespace WhiteBox
