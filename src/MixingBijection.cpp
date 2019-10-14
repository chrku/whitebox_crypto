//
// Created by Christoph Kummer on 02.03.19.
//

#include <MixingBijection.h>

namespace WhiteBox {
MixingBijection<uint32_t> concatenateBijections(
    const MixingBijection<uint8_t> &b1, const MixingBijection<uint8_t> &b2,
    const MixingBijection<uint8_t> &b3, const MixingBijection<uint8_t> &b4) {
  MixingBijection<uint32_t> combined(0);
  for (size_t i = 0; i < 8; ++i) {
    for (size_t j = 0; j < 8; ++j) {
      combined.matrix.put(i, j, b1.matrix.get(i, j));
      combined.inverse.put(i, j, b1.inverse.get(i, j));

      combined.matrix.put(i + 8, j + 8, b2.matrix.get(i, j));
      combined.inverse.put(i + 8, j + 8, b2.inverse.get(i, j));

      combined.matrix.put(i + 16, j + 16, b3.matrix.get(i, j));
      combined.inverse.put(i + 16, j + 16, b3.inverse.get(i, j));

      combined.matrix.put(i + 24, j + 24, b4.matrix.get(i, j));
      combined.inverse.put(i + 24, j + 24, b4.inverse.get(i, j));
    }
  }

  return combined;
}
}  // namespace WhiteBox
