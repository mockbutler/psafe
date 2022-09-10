#pragma once

#include <cryptopp/secblock.h>

#include "ioutil.h"

namespace psafe {
	class Field {
	protected:
		CryptoPP::SecBlock<byte> block_;
		uint32_t length_;
		uint8_t tag_;

	public:
		static constexpr size_t HeaderSize = 5;

		Field(const CryptoPP::SecBlock<byte>& block)
			: block_(block), length_(Le32(&block[0])), tag_(block[4]) {}

		Field(CryptoPP::SecBlock<byte>&& block)
			: block_(block), length_(Le32(&block[0])), tag_(block[4]) {}

		Field(const Field& field)
			: block_(field.block_), length_(field.length_), tag_(field.tag_) {}

		Field(Field&& field) :
			block_{ std::move(field.block_) },
			length_{ std::move(field.length_) },
			tag_{ std::move(field.tag_) }
		{}

		uint32_t Length() const { return length_; }

		uint8_t Tag() const { return tag_; }

		std::string Text() const {
			return std::string(reinterpret_cast<const char*>(block_.begin() + HeaderSize),
				length_);
		}
	};
}
