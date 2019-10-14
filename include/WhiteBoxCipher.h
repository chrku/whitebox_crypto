//
// Created by christoph on 07.03.19.
//

#ifndef WHITEBOX_WHITEBOXCIPHER_H_
#define WHITEBOX_WHITEBOXCIPHER_H_

#include <cryptopp/seckey.h>

#include <WhiteBoxTableGenerator.h>

namespace WhiteBox {
class WhiteBoxCipher : public CryptoPP::FixedBlockSize<16>,
                       public CryptoPP::FixedKeyLength<16>,
                       public CryptoPP::BlockCipher {
 public:
  /*!
   * \brief Create a Crypto++ compatible block cipher handle
   * from a white box table object. Can be used to implement
   * modes of operation using classes from Crypto++
   * \param data the data to be used; ownership is not transferred
   * \param encrypt whether to encrypt or decrypt
   */
  WhiteBoxCipher(WhiteBoxData *data, bool encrypt);

  /*!
   * \brief Destroy the object and underlying tables
   */
  ~WhiteBoxCipher() override;

  // The methods below all inherit their documentation from CryptoPP;
  // they are needed for correct operation

  void ProcessAndXorBlock(const byte *in_block, const byte *xor_block,
                          byte *out_block) const override;

  unsigned int BlockSize() const override;

  bool IsForwardTransformation() const override;

  IV_Requirement IVRequirement() const override;

  size_t GetValidKeyLength(size_t keylength) const override;

  size_t DefaultKeyLength() const override;

  size_t MaxKeyLength() const override;

  size_t MinKeyLength() const override;

  void UncheckedSetKey(const byte *key, unsigned int length,
                       const CryptoPP::NameValuePairs &params) override;

  WhiteBoxCipher(const WhiteBoxCipher &wbc) = delete;

  WhiteBoxCipher &operator=(const WhiteBoxCipher &wbc) = delete;

  WhiteBoxCipher(const WhiteBoxCipher &&wbc) = delete;

  WhiteBoxCipher &operator=(const WhiteBoxCipher &&wbc) = delete;

 private:
  bool encrypt_;
  WhiteBoxData *tables_;
};
}  // namespace WhiteBox

#endif  // WHITEBOX_WHITEBOXCIPHER_H_
