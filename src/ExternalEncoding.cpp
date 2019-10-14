//
// Created by Christoph Kummer on 27.03.19.
//

#include <ExternalEncoding.h>

namespace WhiteBox {

  ExternalEncoding::ExternalEncoding(CryptoPP::AutoSeededRandomPool &rng)
    : encodings_ ({{RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256),
                    RandomPermutation<uint8_t>(rng, 256)}})
  {

  }

  void ExternalEncoding::applyToWhiteBox(WhiteBoxData* data, bool input) const {
    if (input) {
      for (size_t i = 0; i < 15; ++i) {
        TyiTable& current_table = data->tyiTables_[0][i];
        TyiTable table_copy = data->tyiTables_[0][i];
        for (size_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
          uint8_t encoded = encodings_[i].getOutput(static_cast<uint32_t>(j));
          auto temp = static_cast<uint8_t>(table_copy[encoded]);
          current_table[j] = temp;
        }
      }
    } else {
      for (size_t i = 0; i < 15; ++i) {
        TBox& current_tbox = data->finalRoundTBoxes_[i];
        TBox table_copy = data->finalRoundTBoxes_[i];
        for (size_t j = 0; j <= std::numeric_limits<uint8_t>::max(); ++j) {
          auto temp = static_cast<uint8_t>(table_copy[j]);
          uint8_t encoded = encodings_[i].getOutput(static_cast<uint32_t>(temp));
          current_tbox[j] = encoded;
        }
      }
    }
  }
} // namespace WhiteBox