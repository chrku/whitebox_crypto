//
// Created by Christoph Kummer on 26.02.19.
//

#include <iostream>

#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/pkcspad.h>

#include <WhiteBoxCipher.h>
#include <WhiteBoxInterpreter.h>

namespace WhiteBox {
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

      auto nibble_1 = static_cast<uint8_t>((intermediate_1 & 0xFU) << 4U);
      auto nibble_2 = static_cast<uint8_t>(intermediate_1 & 0xF0U);
      auto nibble_3 = static_cast<uint8_t>((intermediate_1 & 0xF00U) >> 4U);
      auto nibble_4 = static_cast<uint8_t>((intermediate_1 & 0xF000U) >> 8U);
      auto nibble_5 = static_cast<uint8_t>((intermediate_1 & 0xF0000U) >> 12U);
      auto nibble_6 = static_cast<uint8_t>((intermediate_1 & 0xF00000U) >> 16U);
      auto nibble_7 = static_cast<uint8_t>((intermediate_1 & 0xF000000U) >> 20U);
      auto nibble_8 = static_cast<uint8_t>((intermediate_1 & 0xF0000000U) >> 24U);

      auto nibble_9 = static_cast<uint8_t>(intermediate_2 & 0xFU);
      auto nibble_10 = static_cast<uint8_t>((intermediate_2 & 0xF0U) >> 4U);
      auto nibble_11 = static_cast<uint8_t>((intermediate_2 & 0xF00U) >> 8U);
      auto nibble_12 = static_cast<uint8_t>((intermediate_2 & 0xF000U) >> 12U);
      auto nibble_13 = static_cast<uint8_t>((intermediate_2 & 0xF0000U) >> 16U);
      auto nibble_14 = static_cast<uint8_t>((intermediate_2 & 0xF00000U) >> 20U);
      auto nibble_15 = static_cast<uint8_t>((intermediate_2 & 0xF000000U) >> 24U);
      auto nibble_16 = static_cast<uint8_t>((intermediate_2 & 0xF0000000U) >> 28U);

      auto nibble_17 = static_cast<uint8_t>((intermediate_3 & 0xFU) << 4U);
      auto nibble_18 = static_cast<uint8_t>(intermediate_3 & 0xF0U);
      auto nibble_19 = static_cast<uint8_t>((intermediate_3 & 0xF00U) >> 4U);
      auto nibble_20 = static_cast<uint8_t>((intermediate_3 & 0xF000U) >> 8U);
      auto nibble_21 = static_cast<uint8_t>((intermediate_3 & 0xF0000U) >> 12U);
      auto nibble_22 = static_cast<uint8_t>((intermediate_3 & 0xF00000U) >> 16U);
      auto nibble_23 = static_cast<uint8_t>((intermediate_3 & 0xF000000U) >> 20U);
      auto nibble_24 = static_cast<uint8_t>((intermediate_3 & 0xF0000000U) >> 24U);

      auto nibble_25 = static_cast<uint8_t>(intermediate_4 & 0xFU);
      auto nibble_26 = static_cast<uint8_t>((intermediate_4 & 0xF0U) >> 4U);
      auto nibble_27 = static_cast<uint8_t>((intermediate_4 & 0xF00U) >> 8U);
      auto nibble_28 = static_cast<uint8_t>((intermediate_4 & 0xF000U) >> 12U);
      auto nibble_29 = static_cast<uint8_t>((intermediate_4 & 0xF0000U) >> 16U);
      auto nibble_30 = static_cast<uint8_t>((intermediate_4 & 0xF00000U) >> 20U);
      auto nibble_31 = static_cast<uint8_t>((intermediate_4 & 0xF000000U) >> 24U);
      auto nibble_32 = static_cast<uint8_t>((intermediate_4 & 0xF0000000U) >> 28U);

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
        (intermediate_nibble_8 << 28U) | (intermediate_nibble_7 << 24U) |
        (intermediate_nibble_6 << 20U) | (intermediate_nibble_5 << 16U) |
        (intermediate_nibble_4 << 12U) | (intermediate_nibble_3 << 8U) |
        (intermediate_nibble_2 << 4U) | intermediate_nibble_1;

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
        (intermediate_nibble_16 << 28U) | (intermediate_nibble_15 << 24U) |
        (intermediate_nibble_14 << 20U) | (intermediate_nibble_13 << 16U) |
        (intermediate_nibble_12 << 12U) | (intermediate_nibble_11 << 8U) |
        (intermediate_nibble_10 << 4U) | intermediate_nibble_9;

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

      auto nibble_1 = static_cast<uint8_t>((left & 0xFU) << 4U);
      auto nibble_2 = static_cast<uint8_t>(left & 0xF0U);
      auto nibble_3 = static_cast<uint8_t>((left & 0xF00U) >> 4U);
      auto nibble_4 = static_cast<uint8_t>((left & 0xF000U) >> 8U);
      auto nibble_5 = static_cast<uint8_t>((left & 0xF0000U) >> 12U);
      auto nibble_6 = static_cast<uint8_t>((left & 0xF00000U) >> 16U);
      auto nibble_7 = static_cast<uint8_t>((left & 0xF000000U) >> 20U);
      auto nibble_8 = static_cast<uint8_t>((left & 0xF0000000U) >> 24U);

      auto nibble_9 = static_cast<uint8_t>(right & 0xFU);
      auto nibble_10 = static_cast<uint8_t>((right & 0xF0U) >> 4U);
      auto nibble_11 = static_cast<uint8_t>((right & 0xF00U) >> 8U);
      auto nibble_12 = static_cast<uint8_t>((right & 0xF000U) >> 12U);
      auto nibble_13 = static_cast<uint8_t>((right & 0xF0000U) >> 16U);
      auto nibble_14 = static_cast<uint8_t>((right & 0xF00000U) >> 20U);
      auto nibble_15 = static_cast<uint8_t>((right & 0xF000000U) >> 24U);
      auto nibble_16 = static_cast<uint8_t>((right & 0xF0000000U) >> 28U);

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

      output_state[2 * i] = static_cast<uint8_t>((final_nibble_8 << 4U)) | final_nibble_7;
      output_state[2 * i + 1] = static_cast<uint8_t>((final_nibble_6 << 4U)) | final_nibble_5;
      output_state[2 * i + 2] = static_cast<uint8_t>((final_nibble_4 << 4U)) | final_nibble_3;
      output_state[2 * i + 3] = static_cast<uint8_t>((final_nibble_2 << 4U)) | final_nibble_1;
    }
  }

  void apply_final_round_t_boxes(const WhiteBoxData &tables, const State& state, State& output_state) {
    for (size_t i = 0; i < AES_KEY_LENGTH_BYTES; ++i) {
      output_state[i] = tables.finalRoundTBoxes_[i][state[i]];
    }
  }

  State interpret_white_box_no_mixing(
    const WhiteBoxData &white_box_encryption_data, const State &state, bool decrypt) {
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
    }

    if (!decrypt)
      shift_rows_in_place(finalResult, shifted_state);
    else
      inverse_shift_rows_in_place(finalResult, shifted_state);

    apply_final_round_t_boxes(white_box_encryption_data, shifted_state, finalResult);

    return finalResult;
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
    if (!white_box_encryption_data.usesMixingBijections_) {
      return interpret_white_box_no_mixing(white_box_encryption_data, input_state,
                                           decrypt);
    } else {
      return interpret_white_box_mixing(white_box_encryption_data, input_state,
                                        decrypt);
    }
  }

  void encrypt_cbc_mode(
    std::istream &input_stream, std::ostream &output_stream, WhiteBoxData *data,
    State iv,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme) {
    WhiteBoxCipher cipher(data, true);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption enc;
    enc.SetCipherWithIV(cipher, iv.data(), AES_BLOCK_SIZE_BYTES);

    // Create filter, source and sink
    auto *sink = new CryptoPP::FileSink(output_stream);
    auto *filter = new CryptoPP::StreamTransformationFilter(enc, sink, padding_scheme);

    // This will encrypt and write to the file
    CryptoPP::FileSource source(input_stream, true, filter);
  }

  void decrypt_cbc_mode(
    std::istream &input_stream, std::ostream &output_stream, WhiteBoxData *data,
    State iv,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme) {
    WhiteBoxCipher cipher(data, false);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption dec;
    dec.SetCipherWithIV(cipher, iv.data(), AES_BLOCK_SIZE_BYTES);

    // Create filter, source and sink
    auto *sink = new CryptoPP::FileSink(output_stream);
    auto *filter = new CryptoPP::StreamTransformationFilter(dec, sink, padding_scheme);

    // This will encrypt and write to the file
    CryptoPP::FileSource source(input_stream, true, filter);
  }

  void encrypt_ecb_mode(
    std::istream &input_stream, std::ostream &output_stream, WhiteBoxData *data,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme) {
    WhiteBoxCipher cipher(data, true);
    CryptoPP::ECB_Mode_ExternalCipher::Encryption enc;
    enc.SetCipher(cipher);

    // Create filter, source and sink
    auto *sink = new CryptoPP::FileSink(output_stream);
    auto *filter = new CryptoPP::StreamTransformationFilter(enc, sink, padding_scheme);

    // This will encrypt and write to the file
    CryptoPP::FileSource source(input_stream, true, filter);
  }

  void decrypt_ecb_mode(
    std::istream &input_stream, std::ostream &output_stream, WhiteBoxData *data,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme) {
    WhiteBoxCipher cipher(data, false);
    CryptoPP::ECB_Mode_ExternalCipher::Decryption dec;
    dec.SetCipher(cipher);

    // Create filter, source and sink
    auto *sink = new CryptoPP::FileSink(output_stream);
    auto *filter = new CryptoPP::StreamTransformationFilter(dec, sink, padding_scheme);

    // This will encrypt and write to the file
    CryptoPP::FileSource source(input_stream, true, filter);
  }

  void encrypt_ctr_mode(
    std::istream &input_stream, std::ostream &output_stream, WhiteBoxData *data,
    State iv,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme) {
    WhiteBoxCipher cipher(data, true);
    CryptoPP::CTR_Mode_ExternalCipher::Encryption enc;
    enc.SetCipherWithIV(cipher, iv.data(), AES_BLOCK_SIZE_BYTES);

    // Create filter, source and sink
    auto *sink = new CryptoPP::FileSink(output_stream);
    auto *filter = new CryptoPP::StreamTransformationFilter(enc, sink, padding_scheme);

    // This will encrypt and write to the file
    CryptoPP::FileSource source(input_stream, true, filter);
  }

  void decrypt_ctr_mode(
    std::istream &input_stream, std::ostream &output_stream, WhiteBoxData *data,
    State iv,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme) {
    WhiteBoxCipher cipher(data, true);
    CryptoPP::CTR_Mode_ExternalCipher::Decryption dec;
    dec.SetCipherWithIV(cipher, iv.data(), AES_BLOCK_SIZE_BYTES);

    // Create filter, source and sink
    auto *sink = new CryptoPP::FileSink(output_stream);
    auto *filter = new CryptoPP::StreamTransformationFilter(dec, sink, padding_scheme);

    // This will encrypt and write to the file
    CryptoPP::FileSource source(input_stream, true, filter);
  }
}  // namespace WhiteBox
