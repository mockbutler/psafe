#pragma once

#include <iosfwd>

#include "crypto.h"

namespace psafe {
	class FieldLoader {
		static constexpr byte DbEndBlock[] = {
			'P', 'W', 'S', '3', '-', 'E', 'O', 'F', 'P', 'W', 'S', '3', '-', 'E', 'O', 'F'
		};

		std::istream& source_;
		CryptoPP::CBC_Mode< CryptoPP::Twofish >::Decryption& decryptor_;
		CryptoPP::HMAC< CryptoPP::SHA256 >& hmac_;

	public:
		FieldLoader(
			std::istream& source,
			CryptoPP::CBC_Mode< CryptoPP::Twofish >::Decryption& decryptor,
			CryptoPP::HMAC< CryptoPP::SHA256 >& hmac) :
			source_(source),
			decryptor_(decryptor),
			hmac_(hmac)
		{}

		std::optional<CryptoPP::SecBlock<byte>> LoadNext();
	};
}
