#pragma once

namespace psafe {

	enum class RecordFieldTag : uint8_t {
		UUID                     = 0x01,
		Group                    = 0x02,
		Title                    = 0x03,
		Username                 = 0x04,
		Notes                    = 0x05,
		Password                 = 0x06,
		CreationTime             = 0x07,
		PasswordModificationTime = 0x08,
		LastAccessTime           = 0x09,
		PasswordExpiryTime       = 0x0a,
		RESERVED1                = 0x0b,
		LastModificationTime     = 0x0c,
		URL                      = 0x0d,
		Autotype                 = 0x0e,
		PasswordHistory          = 0x0f,
		PasswordPolicy           = 0x10,
		PasswordExpiryInterval   = 0x11,
		RunCommand               = 0x12,
		DoubleClickAction        = 0x13,
		EmailAddress             = 0x14,
		ProtectedEntry           = 0x15,
		OwnSymbolsForPassword    = 0x16,
		ShiftDoubleClickAction   = 0x17,
		PasswordPolicyName       = 0x18,
		EntryKeyboardShortcut    = 0x19,
		EndOfEntry               = 0xff
	};

	inline bool operator==(const RecordFieldTag& rfType, uint8_t rawType) {
		return static_cast<uint8_t>(rfType) == rawType;
	}

	inline bool operator==(uint8_t rawType, const RecordFieldTag& rfType) {
		return static_cast<uint8_t>(rfType) == rawType;
	}

	class Record {
		std::map<RecordFieldTag, Field> fields_;

	public:
		Record(std::list<Field>&& fields) {
			for (auto i = fields.begin(); i != fields.end(); ++i) {
				fields_.emplace(
					std::make_pair(static_cast<RecordFieldTag>(i->Tag()), std::move(*i)));
			}
			fields.clear();
		}

		bool HasField(RecordFieldTag ftype) const {
			return fields_.find(ftype) != fields_.end();
		}

		std::list<RecordFieldTag> Fields() const {
			std::list<RecordFieldTag> retval;
			for (const auto& [key, _] : fields_) {
				retval.push_back(key);
			}
			return retval;
		}

		const Field& GetField(RecordFieldTag tag) const {
			if (auto entry = fields_.find(tag); entry != fields_.end()) {
				return entry->second;
			}
			throw std::invalid_argument("Record field tag.");
		}
	};
}
