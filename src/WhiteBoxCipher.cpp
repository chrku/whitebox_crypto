//
// Created by christoph on 07.03.19.
//

#include <WhiteBoxCipher.h>
#include <WhiteBoxInterpreter.h>

namespace WhiteBox {
WhiteBoxCipher::WhiteBoxCipher(WhiteBoxData *data, bool encrypt)
    : encrypt_(encrypt), tables_(data) {}

unsigned int WhiteBoxCipher::BlockSize() const { return AES_BLOCK_SIZE_BYTES; }

bool WhiteBoxCipher::IsForwardTransformation() const { return encrypt_; }

void WhiteBoxCipher::ProcessAndXorBlock(const byte *in_block,
                                        const byte *xor_block,
                                        byte *out_block) const {
  State input_state;
  State xor_state;

  if (in_block != nullptr)
    std::copy_n(in_block, AES_BLOCK_SIZE_BYTES, input_state.begin());

  if (xor_block != nullptr)
    std::copy_n(xor_block, AES_BLOCK_SIZE_BYTES, xor_state.begin());

  State output_state = interpret_white_box(*tables_, input_state, !encrypt_);

  if (xor_block != nullptr) {
    State result_state = output_state ^ xor_state;
    if (out_block != nullptr)
      std::copy_n(result_state.begin(), AES_BLOCK_SIZE_BYTES, out_block);
  } else {
    std::copy_n(output_state.begin(), AES_BLOCK_SIZE_BYTES, out_block);
  }
}

size_t WhiteBoxCipher::GetValidKeyLength(size_t keylength) const {
  return AES_KEY_LENGTH_BYTES;
}

CryptoPP::SimpleKeyingInterface::IV_Requirement WhiteBoxCipher::IVRequirement()
    const {
  return RANDOM_IV;
}

size_t WhiteBoxCipher::DefaultKeyLength() const { return AES_KEY_LENGTH_BYTES; }

size_t WhiteBoxCipher::MaxKeyLength() const { return AES_KEY_LENGTH_BYTES; }

size_t WhiteBoxCipher::MinKeyLength() const { return AES_KEY_LENGTH_BYTES; }

// Setting the key does nothing for a white box implementation
void WhiteBoxCipher::UncheckedSetKey(const byte *key, unsigned int length,
                                     const CryptoPP::NameValuePairs &params) {}

// Due to using unique_ptr, no need to explicitly call delete on the tables
WhiteBoxCipher::~WhiteBoxCipher() = default;
}  // namespace WhiteBox