//
// Created by Christoph Kummer on 26.02.19.
//

#ifndef WHITEBOX_WHITEBOX_INTERPRETER_H_
#define WHITEBOX_WHITEBOX_INTERPRETER_H_

#include <iostream>

#include <WhiteBoxTableGenerator.h>

namespace WhiteBox {
/*!
 * \brief Apply the encryption function given by the table. This produces
 * a plain/ciphertext.
 * \param white_box_encryption_data white box tables,
 * calculated by the white box generator in this project.
 * \param state Input state, i.e. the plain/ciphertext
 * \param decrypt whether to encrypt or decrypt
 * \return output state, i.e. plain/ciphertext
 */
State interpret_white_box(const WhiteBoxData &white_box_encryption_data,
                          const State& input_state, bool decrypt);

/*!
 * \brief Calculate the first kind of XOR operation needed by the white box,
 * given the tables. For more details, see Chow's or Muir's paper;
 * this takes the output of the Tyi/mixing tables and XORs it together,
 * which is done in two steps; this implements step one.
 * \param tables white box tables
 * \param state input state
 * \param output_state result state
 * \param round round this is to be done in
 * \param use_mixing_tables determines whether this is for the mixing bijection
 * step or not, for details see the papers.
 */
void calculate_first_xor_cascade(const WhiteBoxData &tables,
                                               const IntermediateState& state,
                                               IntermediateState2& output_state,
                                               size_t round,
                                               bool use_mixing_tables);

/*!
 * \brief Calculate the second kind of XOR operation needed by the white box,
 * given the tables. For more details, see Chow's or Muir's paper;
 * this takes the output of the Tyi/mixing tables and XORs it together,
 * which is done in two steps; this implements step two.
 * \param tables white box tables
 * \param state input state
 * \param output_state resultant state
 * \param round round this is to be done in
 * \param use_mixing_tables determines whether this is for the mixing bijection
 * step or not, for details see the papers.
 */
void calculate_second_xor_cascade(const WhiteBoxData &tables,
                                   const IntermediateState2& state,
                                   State& output_state, size_t round,
                                   bool use_mixing_tables);

/*!
 * \brief Calculate the results of the mixing operation. This essentially
 * applies the inverse of the mixing bijections. This produces intermediate
 * state that is then XORed together.
 * \param white_box_encryption_data white box
 * tables
 * \param state input state
 * \param output_state result state of the operation
 * \param round round this is applied in
 */
void calculate_mixing_table_results(
    const WhiteBoxData &white_box_encryption_data, const State& state,
    IntermediateState& output_state, size_t round);

/*!
 * \brief Calculate the results of the Tyi tables. This essentially applies
 * the MixColumns step, together with the SubBytes/AddRoundKey steps.
 * This produces intermediate state that is then XORed together.
 * \param white_box_encryption_data white box tables
 * \param state input state
 * \param output_state resultant state of the operation
 * \param round round this is applied in
 */
void calculate_intermediate_tyi_box_results(
    const WhiteBoxData &tables, const State& state, IntermediateState& output_state, size_t round);

/*!
 * \brief Apply the T-Boxes of the final round
 * \param tables white box tables
 * \param state input state
 * \param output_state final AES state
 */
void apply_final_round_t_boxes(const WhiteBoxData &tables, const State& state, State& output_state);

/*!
 * \brief Encrypt the given input stream in AES-CBC mode, using a white box
 * table \param input_stream the input data stream to be encrypted \param
 * output_stream the output data stream to be written to \param data white box
 * data used for encryption \param iv initialization vector \param
 * padding_scheme padding scheme to use
 */
void encrypt_cbc_mode(
    std::istream& input_stream, std::ostream& output_stream, WhiteBoxData *data,
    State iv,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme =
        CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING);

/*!
 * \brief Decrypt the given input stream in AES-CBC mode, using a white box
 * table \param input_stream the input data stream to be decrypted \param
 * output_stream the output data stream to be written to \param data white box
 * data used for decryption \param iv initialization vector \param
 * padding_scheme padding scheme to use
 */
void decrypt_cbc_mode(
    std::istream& input_stream, std::ostream& output_stream, WhiteBoxData *data,
    State iv,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme =
        CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING);

/*!
 * \brief Encrypt the given input stream in AES-ECB mode, using a white box
 * table \param input_stream the input data stream to be encrypted \param
 * output_stream the output data stream to be written to \param data white box
 * data used for encryption \param padding_scheme padding scheme to use
 */
void encrypt_ecb_mode(
    std::istream& input_stream, std::ostream& output_stream, WhiteBoxData *data,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme =
        CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING);

/*!
 * \brief Decrypt the given input stream in AES-ECB mode, using a white box
 * table \param input_stream the input data stream to be decrypted \param
 * output_stream the output data stream to be written to \param data white box
 * data used for decryption \param padding_scheme padding scheme to use
 */
void decrypt_ecb_mode(
    std::istream& input_stream, std::ostream& output_stream, WhiteBoxData *data,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme =
        CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING);

/*!
 * \brief Encrypt the given input stream in AES-CTR mode, using a white box
 * table \param input_stream the input data stream to be encrypted \param
 * output_stream the output data stream to be written to \param data white box
 * data used for encryption \param iv initialization vector \param
 * padding_scheme padding scheme to use
 */
void encrypt_ctr_mode(
    std::istream& input_stream, std::ostream& output_stream, WhiteBoxData *data,
    State iv,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme =
        CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING);

/*!
 * \brief Decrypt the given input stream in AES-CTR mode, using a white box
 * table \param input_stream the input data stream to be decrypted \param
 * output_stream the output data stream to be written to \param data white box
 * data used for decryption \param iv initialization vector \param
 * padding_scheme padding scheme to use
 */
void decrypt_ctr_mode(
    std::istream& input_stream, std::ostream& output_stream, WhiteBoxData *data,
    State iv,
    CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding_scheme =
        CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING);

}  // namespace WhiteBox

#endif  // WHITEBOX_WHITEBOXINTERPRETER_H_
