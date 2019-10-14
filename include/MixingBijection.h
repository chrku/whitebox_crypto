//
// Created by Christoph Kummer on 01.03.19.
//

#ifndef WHITEBOX_MIXINGBIJECTION_H_
#define WHITEBOX_MIXINGBIJECTION_H_

#include <bitset>

#include <NTL/GF2.h>
#include <NTL/mat_GF2.h>
#include <NTL/vec_GF2.h>
#include <cryptopp/osrng.h>

#include <AESUtils.h>

namespace WhiteBox {
/*!
 * \brief This class defines mixing bijections. These are invertible
 * linear transformations that are used as a diffusion step in Chow's
 * AES white box scheme. They are invertible matrices over GF(2).
 * \tparam T numerical data type which the mixing bijection can
 * transform; a uint32_t mixing bijection can transform
 * 32 bit integers, for example
 */
template <typename T>
class MixingBijection {
 public:
  /*!
   * \brief Construct a random mixing bijection of the given type
   * \param rng source of randomness
   */
  explicit MixingBijection(CryptoPP::AutoSeededRandomPool &rng) : matrix() {
    // Size in bits to construct matrix over GF2
    constexpr size_t size = sizeof(T) * 8;
    matrix.SetDims(size, size);

    bool is_invertible = false;

    // Fill matrix until invertible
    while (!is_invertible) {
      for (size_t i = 0; i < size; ++i) {
        for (size_t j = 0; j < size; ++j) {
          uint32_t random_bit = rng.GenerateBit();
          matrix.put(i, j, random_bit);
        }
      }

      auto det = NTL::determinant(matrix);
      if (det != 0) is_invertible = true;
    }

    inverse = NTL::inv(matrix);
  }

  /*!
   * \brief Construct a mixing bijection consisting of the given value
   * \param value either 0 or 1, as the bijections are
   * defined in GF(2).
   */
  explicit MixingBijection(uint32_t value) {
    constexpr size_t size = sizeof(T) * 8;
    matrix.SetDims(size, size);

    for (size_t i = 0; i < size; ++i) {
      for (size_t j = 0; j < size; ++j) {
        if (i == j) {
          matrix.put(i, j, value);
        } else {
          matrix.put(i, j, 0);
        }
      }
    }

    inverse = matrix;
  }

  /*!
   * \brief Copy constructor
   * \param mb value to be copied from
   */
  MixingBijection(const MixingBijection &mb) {
    matrix = mb.matrix;
    inverse = mb.inverse;
  }

  /*!
   * \brief Assignment operator
   * \param mb value to be assigned
   * \return new value after assignment
   */
  MixingBijection &operator=(const MixingBijection &mb) {
    matrix = mb.matrix;
    inverse = mb.inverse;

    return *this;
  }

  /*!
   * \brief Get the identity bijection for the given type.
   * This bijection does nothing if used to transform
   * a given value.
   * \return the identity bijection
   */
  static MixingBijection<T> &getIdentityBijection() {
    static MixingBijection identityBijection(1);
    return identityBijection;
  }

  /*!
   * \brief Apply the transformation given by this bijection
   * to the input value
   * \param operand input value
   * \return transformed value
   */
  T applyTransformation(const T &operand) const {
    T return_value;

    NTL::vec_GF2 v;
    v.SetLength(sizeof(T) * 8);

    for (size_t k = 0; k < sizeof(T) * 8; ++k) {
      auto zero_at_pos = static_cast<uint32_t>((operand & (1U << k)) != 0U);
      v.put(k, zero_at_pos);
    }

    v = matrix * v;

    for (size_t k = 0; k < sizeof(T) * 8; ++k) {
      if (v.at(k) == 1) {
        return_value |= (1U << k);
      } else {
        return_value &= ~(1U << k);
      }
    }

    return return_value;
  }

  /*!
   * \brief Apply the inverse transformation given by this bijection
   * to the input value
   * \param operand input value
   * \return transformed value
   */
  T applyInverseTransformation(const T &operand) const {
    T return_value;

    NTL::vec_GF2 v;
    v.SetLength(sizeof(T) * 8);

    for (size_t k = 0; k < sizeof(T) * 8; ++k) {
      auto zero_at_pos = static_cast<T>((operand & (1 << k)) != 0U);
      v.put(k, zero_at_pos);
    }

    v = inverse * v;

    for (size_t k = 0; k < sizeof(T) * 8; ++k) {
      if (v.at(k) == 1) {
        return_value |= (1U << k);
      } else {
        return_value &= ~(1U << k);
      }
    }

    return return_value;
  }

  /*!
   * \brief Apply the inverse transformation given by this bijection
   * to the input value
   * \param operand input value, as bit vector
   * \return transformed value
   */
  T applyInverseTransformation(const NTL::vec_GF2 &operand) const {
    T return_value;

    NTL::vec_GF2 v = inverse * operand;

    for (size_t k = 0; k < sizeof(T) * 8; ++k) {
      if (v.at(k) != 0) {
        return_value |= (1U << k);
      } else {
        return_value &= ~(1U << k);
      }
    }

    return return_value;
  }

  /*!
   * \brief Print the bijection to a stream
   * \tparam X bijection type
   * \param os output stream
   * \param mix bijection to be printed
   * \return stream handle
   */
  template <typename X>
  friend std::ostream &operator<<(std::ostream &os,
                                  const MixingBijection<X> &mix);

  /*!
   * \brief Concatenate 4 8-bit bijections to a 32-bit bijection;
   * this is used in Chow's AES whitebox construction. The bijections
   * are concatenated into a matrix of the following form:
   * | b1 | 0  | 0  | 0  |
   * | 0  | b2 | 0  | 0  |
   * | 0  | 0  | b3 | 0  |
   * | 0  | 0  | 0  | b4 |
   * \param b1 input bijection
   * \param b2 input bijection
   * \param b3 input bijection
   * \param b4 input bijection
   * \return concatenated 32-bit bijection
   */
  friend MixingBijection<uint32_t> concatenateBijections(
      const MixingBijection<uint8_t> &b1, const MixingBijection<uint8_t> &b2,
      const MixingBijection<uint8_t> &b3, const MixingBijection<uint8_t> &b4);

 private:
  NTL::mat_GF2 matrix;
  NTL::mat_GF2 inverse;
};

template <typename T>
std::ostream &operator<<(std::ostream &os, const MixingBijection<T> &mix) {
  os << "Mixing bijection: " << std::endl;
  os << mix.matrix;
  os << "Inverse bijection: " << std::endl;
  os << mix.inverse;
  os << std::endl;
  return os;
}
}  // namespace WhiteBox

#endif  // WHITEBOX_MIXINGBIJECTION_H_
