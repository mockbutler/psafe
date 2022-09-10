// Copyright 2013-2022 Marc Butler <mockbutler@gmail.com>. All Rights Reserved.

#include "psafe.h"

#include <time.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include <wchar.h>

#include <cassert>
#include <cstdint>
#include <fstream>
#include <ios>
#include <iostream>
#include <list>

#include "fieldloader.h"

namespace psafe {

	std::optional<CryptoPP::SecBlock<byte>> FieldLoader::LoadNext() {
		using namespace CryptoPP;

		std::optional<CryptoPP::SecBlock<byte>> field;

		auto firstBlock = ReadBytes(source_, CryptoPP::Twofish::BLOCKSIZE);
		if (equal(begin(firstBlock), end(firstBlock), begin(DbEndBlock))) {
			return field;
		}

		CryptoPP::SecBlock<byte> blocks(Twofish::BLOCKSIZE);
		decryptor_.ProcessData(blocks, firstBlock.data(), firstBlock.size());

		auto dataLength = Le32(blocks);
		if (dataLength > 11) {
			auto blockCount = (dataLength + 4) / Twofish::BLOCKSIZE;
			blocks.resize((blockCount + 1) * Twofish::BLOCKSIZE);
			auto remainingBlocks = ReadBlocks<Twofish::BLOCKSIZE>(source_, blockCount);
			decryptor_.ProcessData(blocks.BytePtr() + Twofish::BLOCKSIZE,
				remainingBlocks.data(), remainingBlocks.size());
		}
		hmac_.Update(blocks.BytePtr() + Field::HeaderSize, dataLength);

		field = blocks;
		return field;
	}

	std::ostream& operator<<(std::ostream& out, const PasswordSafe& safe) {
		out << "Header field count: " << safe.headers_.size() << std::endl;
		out << "Record field count: " << safe.records_.size() << std::endl;
		return out;
	}

	std::unique_ptr<PasswordSafe>
		PasswordSafe::Load(std::istream& source,
			const CryptoPP::SecBlock<byte>& passPhrase) {
		using namespace CryptoPP;

		static constexpr byte Tag[] = { 'P', 'W', 'S', '3' };
		auto tag = ReadBytes(source, sizeof(Tag));
		if (memcmp(Tag, tag.data(), tag.size()) != 0) {
			throw std::runtime_error(
				"Invalid tag. Corrupt or not a PasswordSafe V3 database.");
		}
		auto salt = ReadBytes(source, 32);
		auto iterField = ReadBytes(source, 4);
		auto iterations = Le32(iterField.data());
		auto stretchedKeyHash = ReadBytes(source, SHA256::DIGESTSIZE);
		auto b1b2 = ReadBytes(source, CryptoPP::Twofish::BLOCKSIZE * 2);
		auto b3b4 = ReadBytes(source, CryptoPP::Twofish::BLOCKSIZE * 2);
		auto initialValue = ReadBytes(source, 16);

		SecBlock<byte> stretchedKey(SHA256::DIGESTSIZE);
		SHA256 stretch;
		stretch.Update(passPhrase, passPhrase.SizeInBytes());
		stretch.Update(salt.data(), salt.size());
		stretch.Final(stretchedKey);
		byte stretchTmp[SHA256::DIGESTSIZE] = {};
		auto iter = iterations;
		while (iter-- > 0) {
			memmove(stretchTmp, stretchedKey, sizeof(stretchTmp));
			stretch.Restart();
			stretch.CalculateDigest(stretchedKey, stretchTmp, sizeof(stretchTmp));
		}
		if (!stretch.VerifyDigest(stretchedKeyHash.data(), stretchedKey,
			stretchedKey.SizeInBytes())) {
			throw std::runtime_error("Invalid pass phrase.");
		}

		// Extract random key K.
		ECB_Mode<Twofish>::Decryption decryptK;
		decryptK.SetKey(stretchedKey, stretchedKey.SizeInBytes());
		SecBlock<byte> randomKeyK(Twofish::BLOCKSIZE * 2);
		decryptK.ProcessData(randomKeyK, b1b2.data(), randomKeyK.SizeInBytes());

		// Extract random key L
		ECB_Mode<Twofish>::Decryption decryptL;
		decryptL.SetKey(stretchedKey, stretchedKey.SizeInBytes());
		SecBlock<byte> randomKeyL(Twofish::BLOCKSIZE * 2);
		decryptL.ProcessData(randomKeyL, b3b4.data(), randomKeyL.SizeInBytes());

		CBC_Mode<Twofish>::Decryption cbc;
		cbc.SetKeyWithIV(randomKeyK, randomKeyK.SizeInBytes(),
			initialValue.data(), initialValue.size());

		HMAC<SHA256> hmac;
		hmac.SetKey(randomKeyL.data(), randomKeyL.size());

		std::map<uint8_t, Field> headers;
		FieldLoader loader(source, cbc, hmac);
		for (;;) {
			auto rawField = loader.LoadNext();
			if (!rawField.has_value()) {
				throw std::runtime_error("Premature end of header fields.");
			}
			Field field{ rawField.value() };
			if (field.Tag() == HeaderFieldTag::EndOfEntry) {
				break;
			}
			headers.insert(std::make_pair(field.Tag(), field));
		}

		std::list<Record> records;
		std::list<Field> recordFields;
		for (;;) {
			auto field = loader.LoadNext();
			if (!field.has_value()) {
				break;
			}
			recordFields.emplace_back(field.value());
			if (recordFields.back().Tag() == RecordFieldTag::EndOfEntry) {
				records.push_back(std::move(recordFields));
			}
		}

		auto expectedHmac = ReadBytes(source, SHA256::DIGESTSIZE);
		if (!hmac.Verify(expectedHmac.data())) {
			throw std::runtime_error("HMAC validation failed.");
		}

		PasswordSafe* instance = new PasswordSafe;
		instance->salt_.swap(salt);
		instance->iterations_ = iterations;
		instance->initialValue_.swap(initialValue);
		instance->randomKeyK_.swap(randomKeyK);
		instance->randomKeyL_.swap(randomKeyL);
		instance->headers_.swap(headers);
		instance->records_.swap(records);
		return std::unique_ptr<PasswordSafe>(instance);
	}

	const Field& PasswordSafe::HeaderField(HeaderFieldTag field) {
		auto tag = static_cast<uint8_t>(field);
		auto iter = headers_.find(tag);
		if (iter == headers_.end()) {
			throw std::runtime_error("Header field not present.");
		}
		return iter->second;
	}

}

int main(int argc, char** argv) {
	using namespace psafe;

	if (setlocale(LC_ALL, "") == NULL) {
		std::wcerr << L"setlocale" << std::endl;
		exit(EXIT_FAILURE);
	}

	if (argc < 2) {
		return 1;
	}

	try {
		std::ifstream passwordSafeDb(argv[1]);
		auto passLen = strlen(argv[2]);
		auto pass = reinterpret_cast<const byte*>(argv[2]);
		CryptoPP::SecBlock<byte> passPhrase(pass, passLen);
		auto safe = PasswordSafe::Load(passwordSafeDb, passPhrase);
		std::cout << *safe << std::endl;
	}
	catch (std::exception& ex) {
		std::cout << ex.what() << std::endl;
		return 1;
	}

	return 0;
}
