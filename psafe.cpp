// Copyright 2013-2022 Marc Butler <mockbutler@gmail.com>. All Rights Reserved.

#include <cassert>
#include <cstdint>
#include <fstream>
#include <ios>
#include <iostream>
#include <list>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include "fieldloader.h"
#include "psafe.h"

namespace psafe {

	std::optional<CryptoPP::SecBlock<byte>> FieldLoader::LoadNext()
	{
		using namespace CryptoPP;

		std::optional<CryptoPP::SecBlock<byte>> field;

		auto firstBlock = ReadBytes(source_, CryptoPP::Twofish::BLOCKSIZE);
		if (memcmp(firstBlock.data(), DbEndBlock, firstBlock.size()) == 0) {
			return field;
		}

		CryptoPP::SecBlock<byte> blocks(Twofish::BLOCKSIZE);
		decryptor_.ProcessData(blocks, &firstBlock[0], firstBlock.size());

		auto dataLength = Le32(blocks);
		if (dataLength > 11) {
			auto blockCount = (dataLength + 4) / Twofish::BLOCKSIZE;
			blocks.resize((blockCount + 1) * Twofish::BLOCKSIZE);
			auto remainingBlocks = ReadBlocks<Twofish::BLOCKSIZE>(source_, blockCount);
			decryptor_.ProcessData(blocks.BytePtr() + Twofish::BLOCKSIZE, &remainingBlocks[0], remainingBlocks.size());
		}
		hmac_.Update(blocks.BytePtr() + 5, dataLength);

		field = blocks;
		return field;
	}

	void DumpHex(std::wostream& stream, const byte* buf, size_t count)
	{
		static constexpr wchar_t Hex[]{
			'0', '1', '2', '3', '4', '5', '6', '7',
			'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
		for (size_t i = 0; i < count; i++) {
			stream << Hex[buf[i] >> 4] << Hex[buf[i] & 15];
		}
		stream << " : ";
		for (size_t i = 0; i < count; i++) {
			if (isprint(buf[i])) {
				stream << static_cast<wchar_t>(buf[i]);
			}
			else {
				stream << ' ';
			}
		}
		stream << std::endl;
	}

	std::ostream& operator<<(std::ostream& out, const PasswordSafe& safe)
	{
		out << "Header field count: " << safe.headers_.size() << std::endl;
		out << "Record field count: " << safe.records_.size() << std::endl;
		for (auto i = safe.records_.begin(); i != safe.records_.end(); ++i) {
			if (!i->HasField(RecordFieldName::Group))
				continue;
			out << i->GetField(RecordFieldName::Group).Text() << std::endl;
		}
		for (auto i = safe.records_.begin(); i != safe.records_.end(); ++i) {
			out << i->GetField(RecordFieldName::Title).Text() << std::endl;
		}
		return out;
	}

	std::unique_ptr<PasswordSafe> PasswordSafe::Load(std::istream& source, const CryptoPP::SecBlock<byte>& passPhrase)
	{
		using namespace CryptoPP;

		static constexpr byte Tag[] = { 'P', 'W', 'S', '3' };
		auto tag = ReadBytes(source, sizeof(Tag));
		if (memcmp(Tag, &tag[0], tag.size()) != 0) {
			throw std::runtime_error("Invalid tag. Corrupt or not a PasswordSafe V3 database.");
		}
		auto salt = ReadBytes(source, 32);
		auto iterField = ReadBytes(source, 4);
		auto iterations = Le32(&iterField[0]);
		auto stretchedKeyHash = ReadBytes(source, SHA256::DIGESTSIZE);
		auto b1b2 = ReadBytes(source, CryptoPP::Twofish::BLOCKSIZE * 2);
		auto b3b4 = ReadBytes(source, CryptoPP::Twofish::BLOCKSIZE * 2);
		auto initialValue = ReadBytes(source, 16);

		SecBlock<byte> stretchedKey(SHA256::DIGESTSIZE);
		SHA256 stretch;
		stretch.Update(passPhrase, passPhrase.SizeInBytes());
		stretch.Update(&salt[0], salt.size());
		stretch.Final(stretchedKey);
		byte stretchTmp[SHA256::DIGESTSIZE] = {};
		auto iter = iterations;
		while (iter-- > 0) {
			memmove(stretchTmp, stretchedKey, sizeof(stretchTmp));
			stretch.Restart();
			stretch.CalculateDigest(stretchedKey, stretchTmp, sizeof(stretchTmp));
		}
		if (!SHA256().VerifyDigest(&stretchedKeyHash[0], stretchedKey, stretchedKey.SizeInBytes())) {
			throw std::runtime_error("Invalid pass pharse.");
		}

		// Extract random key K.
		ECB_Mode<Twofish>::Decryption decryptK;
		decryptK.SetKey(stretchedKey, stretchedKey.SizeInBytes());
		SecBlock<byte> randomKeyK(Twofish::BLOCKSIZE * 2);
		decryptK.ProcessData(randomKeyK, &b1b2[0], randomKeyK.SizeInBytes());

		// Extract random key L
		ECB_Mode<Twofish>::Decryption decryptL;
		decryptL.SetKey(stretchedKey, stretchedKey.SizeInBytes());
		SecBlock<byte> randomKeyL(Twofish::BLOCKSIZE * 2);
		decryptL.ProcessData(randomKeyL, &b3b4[0], randomKeyL.SizeInBytes());

		CBC_Mode< Twofish >::Decryption cbc;
		cbc.SetKeyWithIV(randomKeyK, randomKeyK.SizeInBytes(), &initialValue[0], initialValue.size());

		HMAC< SHA256 > hmac;
		hmac.SetKey(&randomKeyL[0], randomKeyL.size());

		std::list<Field> headers;
		FieldLoader loader(source, cbc, hmac);
		bool hasRecords = true;
		for (;;) {
			auto field = loader.LoadNext();
			if (!field.has_value()) {
				throw std::runtime_error("Premature end of header fields.");
				break;
			}
			else if (field.value()[4] == 0xff) {
				break;
			}
			else {
				headers.push_back(field.value());
			}
		}

		std::list<Record> records;
		std::list<Field> recordFields;
		if (hasRecords) {
			for (;;) {
				auto field = loader.LoadNext();
				if (!field.has_value()) {
					break;
				}
				recordFields.emplace_back(field.value());
				if (recordFields.back().Tag() == RecordFieldName::EndOfEntry) {
					records.push_back(Record{ std::move(recordFields) });
				}
			}
		}

		auto expectedHmac = ReadBytes(source, SHA256::DIGESTSIZE);
		if (!hmac.Verify(&expectedHmac[0])) {
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
}

int main(int argc, char** argv)
{
	using namespace psafe;

	if (setlocale(LC_ALL, "") == NULL) {
		std::wcerr << L"setlocale" << std::endl;
		exit(EXIT_FAILURE);
	}

	if (argc < 2) {
		return 1;
	}

	std::ifstream passwordSafeDb(argv[1]);
	CryptoPP::SecBlock<byte> pass(reinterpret_cast<const byte*>(argv[2]), strlen(argv[2]));
	auto safe = PasswordSafe::Load(passwordSafeDb, pass);
	std::cout << *safe << std::endl;

	return 0;
}
