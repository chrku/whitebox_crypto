//
// Created by Christoph Kummer on 27.03.19.
//

#ifndef WHITEBOX_EXTERNALENCODING_H_
#define WHITEBOX_EXTERNALENCODING_H_

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/array.hpp>
#include <cryptopp/osrng.h>


#include <RandomPermutation.h>
#include <WhiteBoxTableGenerator.h>

namespace WhiteBox {
  /**
   * \brief External encodings for white boxes,
   * constructed according to the scheme of Muir et al.
   * (16 concatenated 8-bit encodings).
   */
  class ExternalEncoding {
  public:
    friend class boost::serialization::access;

    explicit ExternalEncoding(CryptoPP::AutoSeededRandomPool &rng);
    ExternalEncoding(const ExternalEncoding& e) = default;
    ExternalEncoding& operator=(const ExternalEncoding& rhs) = default;

    void applyToWhiteBox(WhiteBoxData* data, bool input) const;

    template <class Archive>
    void serialize(Archive &ar, const unsigned int version) {
      ar & encodings_;
    }
  private:
    std::array<RandomPermutation<uint8_t>, 16> encodings_;
  };
} // namespace Whitebox

#endif //WHITEBOX_EXTERNALENCODING_H_
