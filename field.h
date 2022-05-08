#pragma once

#include <crypto++/secblock.h>

#include "ioutil.h"

namespace psafe {
class Field {
protected:
  CryptoPP::SecBlock<byte> block_;
  uint32_t length_;
  uint8_t tag_;

public:
  Field(const CryptoPP::SecBlock<byte> &block)
      : block_(block), length_(Le32(&block[0])), tag_(block[4]) {}

  Field(CryptoPP::SecBlock<byte> &&block)
      : block_(block), length_(Le32(&block[0])), tag_(block[4]) {}

  Field(const Field &field)
      : block_(field.block_), length_(field.length_), tag_(field.tag_) {}

  Field(Field &&field) {
    block_.swap(field.block_);
    length_ = field.length_;
    tag_ = field.tag_;
  }

  uint32_t Length() const { return length_; }

  uint8_t Tag() const { return tag_; }

  std::string Text() const {
    return std::string(reinterpret_cast<const char *>(block_.begin() + 5),
                       length_);
  }
};
} // namespace psafe
