//
// Created by Christoph Kummer on 26.02.19.
//

#ifndef WHITEBOX_WHITEBOX_TABLE_GENERATOR_H_
#define WHITEBOX_WHITEBOX_TABLE_GENERATOR_H_

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/array.hpp>

#include <AESUtils.h>
#include <MixingBijection.h>
#include <RandomPermutation.h>

namespace WhiteBox {
/*!
 * \brief Serializable white-box data that can later be used for
 * encryption or decryption
 */
struct WhiteBoxData {
  friend class boost::serialization::access;

  // Is this table protected with mixing bijections
  bool usesMixingBijections_;

  // All the tables needed for the encryption/decryption
  RoundTBoxes finalRoundTBoxes_;
  TyiTables tyiTables_;
  XorTables xorTables_;

  // Tables needed for mixing bijections
  MixingTables mixingTables_;
  XorTables mixingXorTables_;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int version) {
    ar &usesMixingBijections_;

    ar &finalRoundTBoxes_;
    ar &tyiTables_;
    ar &xorTables_;

    ar &mixingTables_;
    ar &mixingXorTables_;
  }

  void serializeDefinition(std::ostream& o) const {
    o << "#include <array>\n\n";
    o << "struct WhiteBoxData {\n";
    o << "\tbool usesMixingBijections_;\n";
    o << "\tstd::array<std::array<uint8_t, 256>, 16> finalRoundTBoxes_;\n";
    o << "\tstd::array<std::array<std::array<uint32_t, 256>, 16>, 10> tyiTables_;\n";
    o << "\tstd::array<std::array<std::array<uint8_t, 256>, 96>, 10> xorTables_;\n";
    o << "\tstd::array<std::array<std::array<uint32_t, 256>, 16>, 10> mixingTables_;\n";
    o << "\tstd::array<std::array<std::array<uint8_t, 256>, 96>, 10> mixingXorTables_;\n";
    o << "};\n\n";
  }

  void serializeToCStruct(std::ostream& o) const {
    serializeDefinition(o);
    o << "WhiteBoxData data = {\n";
    if (usesMixingBijections_)
      o << ".usesMixingBijections_ = true,\n";
    else
      o << ".usesMixingBijections_ = false,\n";
    serializeTBoxes(o);
    serializeTyiTables(o);
    serializeXorTables(o);
    serializeMixingTables(o);
    serializeMixingXorTables(o);
    o << "};\n";
  }

  void serializeTBoxes(std::ostream &o) const {
    o << ".finalRoundTBoxes_ = {{\n";
    for (size_t i = 0; i < finalRoundTBoxes_.size(); ++i) {
      o << "{{\n";
      for (size_t j = 0; j < finalRoundTBoxes_[i].size(); ++j) {
        if (j != finalRoundTBoxes_[i].size() - 1)
          o << static_cast<int>(finalRoundTBoxes_[i][j]) << ",";
        else
          o << static_cast<int>(finalRoundTBoxes_[i][j]);
      }
      if (i != finalRoundTBoxes_.size() - 1)
        o << "}},\n";
      else
        o << "}}\n";
    }
    o << "}},\n";
  }

  void serializeTyiTables(std::ostream &o) const {
    o << ".tyiTables_ = {{\n";
    for (size_t i = 0; i < tyiTables_.size(); ++i) {
      o << "{{\n";
      for (size_t j = 0; j < tyiTables_[i].size(); ++j) {
        o << "{{\n";
        for (size_t k = 0; k < tyiTables_[i][j].size(); ++k) {
          if (k != tyiTables_[i][j].size() - 1)
            o << static_cast<uint32_t>(tyiTables_[i][j][k]) << ",";
          else
            o << static_cast<uint32_t>(tyiTables_[i][j][k]);
        }
        if (j != tyiTables_[i].size() - 1)
          o << "}},\n";
        else
          o << "}}\n";
      }
      if (i != tyiTables_.size() - 1)
        o << "}},\n";
      else
        o << "}}\n";
    }
    o << "}}, \n";
  }

  void serializeXorTables(std::ostream &o) const {
    o << ".xorTables_ = {{\n";
    for (size_t i = 0; i < xorTables_.size(); ++i) {
      o << "{{\n";
      for (size_t j = 0; j < xorTables_[i].size(); ++j) {
        o << "{{\n";
        for (size_t k = 0; k < xorTables_[i][j].size(); ++k) {
          if (k != xorTables_[i][j].size() - 1)
            o << static_cast<uint32_t>(xorTables_[i][j][k]) << ",";
          else
            o << static_cast<uint32_t>(xorTables_[i][j][k]);
        }
        if (j != xorTables_[i].size() - 1)
          o << "}},\n";
        else
          o << "}}\n";
      }
      if (i != xorTables_.size() - 1)
        o << "}},\n";
      else
        o << "}}\n";
    }
    o << "}}, \n";
  }

  void serializeMixingTables(std::ostream &o) const {
    o << ".mixingTables_ = {{\n";
    for (size_t i = 0; i < mixingTables_.size(); ++i) {
      o << "{{\n";
      for (size_t j = 0; j < mixingTables_[i].size(); ++j) {
        o << "{{\n";
        for (size_t k = 0; k < mixingTables_[i][j].size(); ++k) {
          if (k != mixingTables_[i][j].size() - 1)
            o << static_cast<uint32_t>(mixingTables_[i][j][k]) << ",";
          else
            o << static_cast<uint32_t>(mixingTables_[i][j][k]);
        }
        if (j != mixingTables_[i].size() - 1)
          o << "}},\n";
        else
          o << "}}\n";
      }
      if (i != mixingTables_.size() - 1)
        o << "}},\n";
      else
        o << "}}\n";
    }
    o << "}}, \n";
  }

  void serializeMixingXorTables(std::ostream &o) const {
    o << ".mixingXorTables_ = {{\n";
    for (size_t i = 0; i < mixingXorTables_.size(); ++i) {
      o << "{{\n";
      for (size_t j = 0; j < mixingXorTables_[i].size(); ++j) {
        o << "{{\n";
        for (size_t k = 0; k < mixingXorTables_[i][j].size(); ++k) {
          if (k != mixingXorTables_[i][j].size() - 1)
            o << static_cast<uint32_t>(mixingXorTables_[i][j][k]) << ",";
          else
            o << static_cast<uint32_t>(mixingXorTables_[i][j][k]);
        }
        if (j != mixingXorTables_[i].size() - 1)
          o << "}},\n";
        else
          o << "}}\n";
      }
      if (i != mixingXorTables_.size() - 1)
        o << "}},\n";
      else
        o << "}}\n";
    }
    o << "}}, \n";
  }
};

/*!
 * \brief This class manages the creation of tables needed
 * for the white-box crypto scheme. All the calculations happen here.
 * After construction, the tables may be retrieved and serialized.
 */
class WhiteBoxTableGenerator {
 public:
  /*!
   * \brief This constructs the data used for white-box encryption
   * from a given key
   * \param aes_key the key to be embedded into the data
   * \param use_internal_encoding whether to use internal encodings
   * default true, required for security
   * \param use_mixing_bijections whether to use mixing bijections,
   * default true, required for security
   */
  explicit WhiteBoxTableGenerator(State aes_key,
                                  bool use_internal_encoding = true,
                                  bool use_mixing_bijections = true);

  /*!
   * \brief Get the encryption table, which can be used to encrypt data
   * This returns a pointer that was allocated on the heap.
   * \return pointer to the data
   */
  WhiteBoxData *getEncryptionTable() const;

  /*!
   * \brief Get the decryption table, which can be used to decrypt data
   * This returns a pointer that was allocated on the heap.
   * \return pointer to the data
   */
  WhiteBoxData *getDecryptionTable() const;

  // Copying is disallowed
  WhiteBoxTableGenerator(const WhiteBoxTableGenerator &w) = delete;
  WhiteBoxTableGenerator &operator=(const WhiteBoxTableGenerator &w) = delete;
  WhiteBoxTableGenerator(const WhiteBoxTableGenerator &&w) = delete;
  WhiteBoxTableGenerator &operator=(const WhiteBoxTableGenerator &&w) = delete;

 private:
  std::array<uint8_t, AES_KEY_LENGTH_BYTES> aesKey_;
  ExpandedKey expandedAesKey_;
  bool usesMixingBijections_;
  CryptoPP::AutoSeededRandomPool rng;

  TBoxes calculateTBoxes();

  TBoxes calculateTBoxesDecryption();

  void calculateTyiTables(const TBoxes &tBoxes);

  void calculateTyiTablesDecryption(const TBoxes &tboxes);

  void calculateMixingBijections();

  void calculateInternalEncodings();

  void calculateInternalEncodingsWithMixingBijections();

  void encodeTyiTables(
      size_t round,
      const std::vector<RandomPermutation<uint8_t>> &input_encodings,
      const std::vector<RandomPermutation<uint8_t>> &output_encodings,
      bool add_output_encoding, bool add_input_encoding);

  void encodeTyiTablesDecryption(
      size_t round,
      const std::vector<RandomPermutation<uint8_t>> &input_encodings,
      const std::vector<RandomPermutation<uint8_t>> &output_encodings,
      bool add_output_encoding, bool add_input_encoding);

  void encodeXorTables(
      XorTables *xor_tables, size_t round,
      const std::vector<RandomPermutation<uint8_t>> &input_encodings,
      const std::vector<RandomPermutation<uint8_t>> &output_encodings,
      bool add_output_encodings, bool use_offset) const;

  void encodeMixingTables(
      size_t round,
      const std::vector<RandomPermutation<uint8_t>> &input_encodings,
      const std::vector<RandomPermutation<uint8_t>> &output_encodings,
      bool add_output_encodings);

  void encodeMixingTablesDecryption(
      size_t round,
      const std::vector<RandomPermutation<uint8_t>> &input_encodings,
      const std::vector<RandomPermutation<uint8_t>> &output_encodings,
      bool add_output_encodings);

  void calculateMixingTables(
      MixingTables *mixing_tables, size_t round,
      const std::vector<MixingBijection<uint32_t>> &bijections_32,
      const std::vector<MixingBijection<uint32_t>> &bijections_8_concat,
      bool use_output_mixing_bijections) const;

  void encodeFinalTBoxes(
      const std::vector<RandomPermutation<uint8_t>> &input_encodings);

  void encodeFinalTBoxesDecryption(
      const std::vector<RandomPermutation<uint8_t>> &input_encodings);

  void calculateXorTables(XorTables *xor_tables) const;

  void mixTyiTables(size_t round,
                    const std::vector<MixingBijection<uint8_t>> &bijections_8,
                    const std::vector<MixingBijection<uint32_t>> &bijections_32,
                    bool use_input_mixing_bijection);

  void mixTyiTablesDecryption(
      size_t round, const std::vector<MixingBijection<uint8_t>> &bijections_8,
      const std::vector<MixingBijection<uint32_t>> &bijections_32,
      bool use_input_mixing_bijection);

  void mixFinalRoundTBoxes(
      const std::vector<MixingBijection<uint8_t>> &bijections_8);

  void mixFinalRoundTBoxesDecryption(
      const std::vector<MixingBijection<uint8_t>> &bijections_8);

  // All the tables needed for the encryption
  RoundTBoxes finalRoundTBoxes_;
  TyiTables tyiTables_;
  XorTables xorTables_;
  MixingTables mixingTables_;
  XorTables mixingXorTables_;

  // All the tables needed for the decryption
  RoundTBoxes finalRoundTBoxesDecryption_;
  TyiTables tyiTablesDecryption_;
  XorTables xorTablesDecryption_;
  MixingTables mixingTablesDecryption_;
  XorTables mixingXorTablesDecryption_;
};
}  // namespace WhiteBox

#endif  // WHITEBOX_WHITEBOX_TABLE_GENERATOR_H_
