#include "ioutil.h"

#include <iostream>

#include "crypto.h"

namespace psafe {
	uint32_t Le32(const byte* buf) {
		return (buf[0]) | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
	}

	std::vector<byte> ReadBytes(std::istream& source, size_t count) {
		std::vector<byte> buf(count);
		if (!source.read(reinterpret_cast<char*>(&buf[0]), buf.size())) {
			throw std::runtime_error("Error reading bytes.");
		}
		return buf;
	}

	void DumpHex(std::ostream& stream, const byte* buf, size_t count) {
		static constexpr char Hex[]{ '0', '1', '2', '3', '4', '5', '6', '7',
									'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
		for (size_t i = 0; i < count; i++) {
			stream << Hex[buf[i] >> 4] << Hex[buf[i] & 15];
		}
		stream << " : ";
		for (size_t i = 0; i < count; i++) {
			if (isprint(buf[i])) {
				//stream << static_cast<wchar_t>(buf[i]);
				stream << buf[i];
			}
			else {
				stream << ' ';
			}
		}
		stream << std::endl;
	}
}
