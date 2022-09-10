#pragma once
// Copyright 2013-2022 Marc Butler <mockbutler@gmail.com>. All Rights Reserved.

#include <cstdint>

#include "crypto.h"
#include "field.h"
#include "record.h"

namespace psafe {
	enum class HeaderFieldTag : uint8_t {
		Version = 0x00,
		UUID = 0x01,
		NonDefaultPreferences = 0x02,
		TreeDisplayStatus = 0x03,
		TimestampOfLastSave = 0x04,
		WhoPerformedLastSave = 0x05,
		WhatPerformedLastSave = 0x06,
		LastSavedByUser = 0x07,
		LastSavedOnHost = 0x08,
		DatabaseName = 0x09,
		DatabaseDescription = 0x0a,
		DatabaseFilters = 0x0b,
		// Reserved 0x0c
		// Reserved 0x0d
		// Reserved 0x0e
		RecentlyUsedEntries = 0x0f,
		NamedPasswordPolicies = 0x10,
		EmptyGroups = 0x11,
		// Reserved 0x12
		EndOfEntry = 0xff
	};

	inline bool operator==(const HeaderFieldTag& tag, uint8_t raw) {
		return static_cast<uint8_t>(tag) == raw;
	}

	inline bool operator==(uint8_t raw, const HeaderFieldTag& tag) {
		return static_cast<uint8_t>(tag) == raw;
	}

	class PasswordSafe {
		friend std::ostream& operator<<(std::ostream& out, const PasswordSafe& safe);

		std::vector<byte> salt_;
		std::map<uint8_t, Field> headers_;
		std::list<Record> records_;
		uint32_t iterations_;
		std::vector<byte> initialValue_;
		CryptoPP::SecBlock<byte> randomKeyK_;
		CryptoPP::SecBlock<byte> randomKeyL_;

	public:
		static std::unique_ptr<PasswordSafe>
			Load(std::istream& source, const CryptoPP::SecBlock<byte>& passPhrase);
		const Field& HeaderField(HeaderFieldTag field);
	};
}