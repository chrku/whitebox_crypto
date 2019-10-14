//
// Created by Christoph Kummer on 28.02.19.
//

#ifndef WHITEBOX_RANDOMPERMUTATION_H_
#define WHITEBOX_RANDOMPERMUTATION_H_

#include <cassert>
#include <iostream>
#include <vector>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <cryptopp/osrng.h>

namespace WhiteBox {
/*!
 * \brief This defines a random permutation of a type.
 * It can be used to retrieve another element of the type,
 * given that it is in the range of the permutation. This
 * is used for the encodings in Chow's AES whitebox construction.
 * \tparam T type of the elements of the permutation
 */
template <typename T>
class RandomPermutation {
 public:

  /*!
   * \brief Constructs a new random permutation and its inverse,
   * given a source of randomness. The permutations are
   * produced using the Fisher-Yates shuffle algorithm.
   * \param rng the source of randomness
   * \param size size of the permutation; for numerical types,
   * this means that [0..size) are valid inputs for the permutation
   */
  explicit RandomPermutation(CryptoPP::AutoSeededRandomPool &rng,
                             uint32_t size) {
    permutationLUT_.reserve(size);
    inversePermutationLUT_.reserve(size);

    for (size_t c = 0; c < size; ++c) {
      permutationLUT_.push_back(static_cast<T>(c));
      inversePermutationLUT_.push_back(static_cast<T>(c));
    }

    // Fisher-Yates shuffle algorithm
    for (uint32_t c = 0; c < size - 1; ++c) {
      uint32_t index = rng.GenerateWord32(0, size - 1);
      std::swap(inversePermutationLUT_[permutationLUT_[c]],
                inversePermutationLUT_[permutationLUT_[index]]);
      std::swap(permutationLUT_[c], permutationLUT_[index]);
    }
  }

  /*!
   * \brief Copy constructor.
   * \param r value to be copied from
   */
  RandomPermutation(const RandomPermutation &r) {
    permutationLUT_ = r.permutationLUT_;
    inversePermutationLUT_ = r.inversePermutationLUT_;
  }

  /*!
   * \brief Assignment operator
   * \param r value to be assigned
   * \return new value, with assignment applied
   */
  RandomPermutation &operator=(const RandomPermutation &r) {
    permutationLUT_ = r.permutationLUT_;
    inversePermutationLUT_ = r.inversePermutationLUT_;

    return *this;
  }

  /*!
   * \brief Apply permutation to value
   * \param index value to apply permutation to
   * \return the transformed value
   */
  T getOutput(uint32_t index) const { return permutationLUT_.at(index); }

  /*!
   * \brief Apply inverse permutation to value
   * \param index value to apply permutation to
   * \return the transformed value
   */
  T getOutputInverse(uint32_t index) const {
    return inversePermutationLUT_.at(index);
  }

  template <class Archive>
  void serialize(Archive &ar, const unsigned int version) {
    ar & permutationLUT_;
    ar & inversePermutationLUT_;
  }

  /*!
   * \brief Print permutation to stream
   * \tparam X type of the permutation; must be printable
   * \param os output stream
   * \param perm permutation to be printed
   * \return stream handle
   */
  template <typename X>
  friend std::ostream &operator<<(std::ostream &os,
                                  const RandomPermutation<X> &perm);

 private:
  std::vector<T> permutationLUT_;
  std::vector<T> inversePermutationLUT_;
};

template <typename T>
std::ostream &operator<<(std::ostream &os, const RandomPermutation<T> &perm) {
  for (uint32_t index = 0; index < perm.permutationLUT_.size(); index += 4) {
    os << index << " <-> " << static_cast<uint64_t>(perm.permutationLUT_[index])
       << " ";
    os << index + 1 << " <-> "
       << static_cast<uint64_t>(perm.permutationLUT_[index + 1]) << " ";
    os << index + 2 << " <-> "
       << static_cast<uint64_t>(perm.permutationLUT_[index + 2]) << " ";
    os << index + 3 << " <-> "
       << static_cast<uint64_t>(perm.permutationLUT_[index + 3]) << " ";
    os << std::endl;
  }
  return os;
}
}  // namespace WhiteBox

#endif  // WHITEBOX_RANDOMPERMUTATION_H_
