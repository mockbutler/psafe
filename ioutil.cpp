#include "ioutil.h"

#include <iostream>

#include "crypto.h"

namespace psafe {
uint32_t Le32(const byte *buf) {
  return (buf[0]) | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

std::vector<byte> ReadBytes(std::istream &source, size_t count) {
  std::vector<byte> buf(count);
  if (!source.read(reinterpret_cast<char *>(&buf[0]), buf.size())) {
    throw std::runtime_error("Error reading bytes.");
  }
  return buf;
}
} // namespace psafe