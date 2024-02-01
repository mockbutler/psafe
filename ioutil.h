#pragma once

#include <cstdint>
#include <vector>

#include <crypto++/cryptlib.h>

namespace psafe {
	uint32_t Le32(const byte* buf);

	std::vector<byte> ReadBytes(std::istream& source, size_t count);

	template <size_t BlockSize>
	std::vector<byte> ReadBlocks(std::istream& source, size_t count)
	{
		return ReadBytes(source, count * BlockSize);
	}
}