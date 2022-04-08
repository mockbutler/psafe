#pragma once
// Copyright 2013-2022 Marc Butler <mockbutler@gmail.com>. All Rights Reserved.

#include <cstdint>

#include "crypto.h"
#include "field.h"

namespace psafe {

	enum class HeaderFieldType : uint8_t {
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

	enum class RecordFieldName : uint8_t {
		UUID = 0x01,
		Group = 0x02,
		Title = 0x03,
		Username = 0x04,
		Notes = 0x05,
		Password = 0x06,
		CreationTime = 0x07,
		PasswordModificationTime = 0x08,
		LastAccessTime = 0x09,
		PasswordExpiryTime = 0x0a,
		// Reserved 0x0b
		LastModificationTime = 0x0c,
		URL = 0x0d,
		Autotype = 0x0e,
		PasswordHistory = 0x0f,
		PasswordPolicy = 0x10,
		PasswordExpiryInterval = 0x11,
		RunCommand = 0x12,
		DoubleClickAction = 0x13,
		EmailAddress = 0x14,
		ProtectedEntry = 0x15,
		OwnSymbolsForPassword = 0x16,
		ShiftDoubleClickAction = 0x17,
		PasswordPolicyName = 0x18,
		EntryKeyboardShortcut = 0x19,
		EndOfEntry = 0xff
	};

	inline bool operator==(const RecordFieldName& rfType, uint8_t rawType) {
		return static_cast<uint8_t>(rfType) == rawType;
	}

	inline bool operator==(uint8_t rawType, const RecordFieldName& rfType) {
		return static_cast<uint8_t>(rfType) == rawType;
	}

	class Record {
		std::map<RecordFieldName, Field> fields_;
	public:
		Record(std::list<Field>&& fields)
		{
			for (auto i = fields.begin(); i != fields.end(); ++i) {
				fields_.emplace(std::make_pair(
					static_cast<RecordFieldName>(i->Tag()), std::move(*i)));
			}
			fields.clear();
		}

		bool HasField(RecordFieldName ftype) const { 
			return fields_.find(ftype) != fields_.end();
		}

		const Field& GetField(RecordFieldName name) const {
			auto iter = fields_.find(name); 
			return iter->second;
		}
	};

	class PasswordSafe {
		friend std::ostream& operator<<(std::ostream& out, const PasswordSafe& safe);

		std::vector<byte> salt_;
		std::list<Field> headers_;
		std::list<Record> records_;
		uint32_t iterations_;
		std::vector<byte> initialValue_;
		CryptoPP::SecBlock<byte> randomKeyK_;
		CryptoPP::SecBlock<byte> randomKeyL_;

	public:
		static std::unique_ptr<PasswordSafe> Load(std::istream& source, const CryptoPP::SecBlock<byte>& passPhrase);
	};
}
