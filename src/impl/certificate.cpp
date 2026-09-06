/**
 * Copyright (c) 2019 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "certificate.hpp"
#include "threadpool.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace rtc::impl {

#if USE_GNUTLS

Certificate Certificate::FromString(string crt_pem, string key_pem) {
	PLOG_DEBUG << "Importing certificate from PEM string (GnuTLS)";

	shared_ptr<gnutls_certificate_credentials_t> creds(gnutls::new_credentials(),
	                                                   gnutls::free_credentials);
	gnutls_datum_t crt_datum = gnutls::make_datum(crt_pem.data(), crt_pem.size());
	gnutls_datum_t key_datum = gnutls::make_datum(key_pem.data(), key_pem.size());
	gnutls::check(
	    gnutls_certificate_set_x509_key_mem(*creds, &crt_datum, &key_datum, GNUTLS_X509_FMT_PEM),
	    "Unable to import PEM certificate and key");

	return Certificate(std::move(creds));
}

Certificate Certificate::FromFile(const string &crt_pem_file, const string &key_pem_file,
                                  const string &pass) {
	PLOG_DEBUG << "Importing certificate from PEM file (GnuTLS): " << crt_pem_file;

	shared_ptr<gnutls_certificate_credentials_t> creds(gnutls::new_credentials(),
	                                                   gnutls::free_credentials);
	gnutls::check(gnutls_certificate_set_x509_key_file2(*creds, crt_pem_file.c_str(),
	                                                    key_pem_file.c_str(), GNUTLS_X509_FMT_PEM,
	                                                    pass.c_str(), 0),
	              "Unable to import PEM certificate and key from file");

	return Certificate(std::move(creds));
}

Certificate Certificate::Generate(CertificateType type, const string &commonName) {
	PLOG_DEBUG << "Generating certificate (GnuTLS)";

	using namespace gnutls;
	unique_ptr<gnutls_x509_crt_t, decltype(&free_crt)> crt(new_crt(), free_crt);
	unique_ptr<gnutls_x509_privkey_t, decltype(&free_privkey)> privkey(new_privkey(), free_privkey);

	switch (type) {
	// RFC 8827 WebRTC Security Architecture 6.5. Communications Security
	// All implementations MUST support DTLS 1.2 with the TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	// cipher suite and the P-256 curve
	// See https://www.rfc-editor.org/rfc/rfc8827.html#section-6.5
	case CertificateType::Default:
	case CertificateType::Ecdsa: {
		gnutls::check(gnutls_x509_privkey_generate(*privkey, GNUTLS_PK_ECDSA,
		                                           GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1),
		                                           0),
		              "Unable to generate ECDSA P-256 key pair");
		break;
	}
	case CertificateType::Rsa: {
		const unsigned int bits = 2048;
		gnutls::check(gnutls_x509_privkey_generate(*privkey, GNUTLS_PK_RSA, bits, 0),
		              "Unable to generate RSA key pair");
		break;
	}
	default:
		throw std::invalid_argument("Unknown certificate type");
	}

	using namespace std::chrono;
	auto now = time_point_cast<seconds>(system_clock::now());
	gnutls_x509_crt_set_activation_time(*crt, (now - hours(1)).time_since_epoch().count());
	gnutls_x509_crt_set_expiration_time(*crt, (now + hours(24 * 365)).time_since_epoch().count());
	gnutls_x509_crt_set_version(*crt, 1);
	gnutls_x509_crt_set_key(*crt, *privkey);
	gnutls_x509_crt_set_dn_by_oid(*crt, GNUTLS_OID_X520_COMMON_NAME, 0, commonName.data(),
	                              commonName.size());

	const size_t serialSize = 16;
	char serial[serialSize];
	gnutls_rnd(GNUTLS_RND_NONCE, serial, serialSize);
	gnutls_x509_crt_set_serial(*crt, serial, serialSize);

	gnutls::check(gnutls_x509_crt_sign2(*crt, *crt, *privkey, GNUTLS_DIG_SHA256, 0),
	              "Unable to auto-sign certificate");

	return Certificate(*crt, *privkey);
}

Certificate::Certificate(gnutls_x509_crt_t crt, gnutls_x509_privkey_t privkey)
    : mCredentials(gnutls::new_credentials(), gnutls::free_credentials),
      mFingerprint(make_fingerprint(crt, CertificateFingerprint::Algorithm::Sha256)) {

	gnutls::check(gnutls_certificate_set_x509_key(*mCredentials, &crt, 1, privkey),
	              "Unable to set certificate and key pair in credentials");
}

Certificate::Certificate(shared_ptr<gnutls_certificate_credentials_t> creds)
    : mCredentials(std::move(creds)),
      mFingerprint(make_fingerprint(*mCredentials, CertificateFingerprint::Algorithm::Sha256)) {}

gnutls_certificate_credentials_t Certificate::credentials() const { return *mCredentials; }

string make_fingerprint(gnutls_certificate_credentials_t credentials,
                        CertificateFingerprint::Algorithm fingerprintAlgorithm) {
	auto new_crt_list = [credentials]() -> gnutls_x509_crt_t * {
		gnutls_x509_crt_t *crt_list = nullptr;
		unsigned int crt_list_size = 0;
		gnutls::check(gnutls_certificate_get_x509_crt(credentials, 0, &crt_list, &crt_list_size));
		assert(crt_list_size == 1);
		return crt_list;
	};

	auto free_crt_list = [](gnutls_x509_crt_t *crt_list) {
		gnutls_x509_crt_deinit(crt_list[0]);
		gnutls_free(crt_list);
	};

	unique_ptr<gnutls_x509_crt_t, decltype(free_crt_list)> crt_list(new_crt_list(), free_crt_list);

	return make_fingerprint(*crt_list, fingerprintAlgorithm);
}

string make_fingerprint(gnutls_x509_crt_t crt,
                        CertificateFingerprint::Algorithm fingerprintAlgorithm) {
	const size_t size = CertificateFingerprint::AlgorithmSize(fingerprintAlgorithm);
	std::vector<unsigned char> buffer(size);
	size_t len = size;

	gnutls_digest_algorithm_t hashFunc;
	switch (fingerprintAlgorithm) {
	case CertificateFingerprint::Algorithm::Sha1:
		hashFunc = GNUTLS_DIG_SHA1;
		break;
	case CertificateFingerprint::Algorithm::Sha224:
		hashFunc = GNUTLS_DIG_SHA224;
		break;
	case CertificateFingerprint::Algorithm::Sha256:
		hashFunc = GNUTLS_DIG_SHA256;
		break;
	case CertificateFingerprint::Algorithm::Sha384:
		hashFunc = GNUTLS_DIG_SHA384;
		break;
	case CertificateFingerprint::Algorithm::Sha512:
		hashFunc = GNUTLS_DIG_SHA512;
		break;
	default:
		throw std::invalid_argument("Unknown fingerprint algorithm");
	}

	gnutls::check(gnutls_x509_crt_get_fingerprint(crt, hashFunc, buffer.data(), &len),
	              "X509 fingerprint error");

	std::ostringstream oss;
	oss << std::hex << std::uppercase << std::setfill('0');
	for (size_t i = 0; i < len; ++i) {
		if (i)
			oss << std::setw(1) << ':';
		oss << std::setw(2) << unsigned(buffer.at(i));
	}
	return oss.str();
}

#elif USE_MBEDTLS
string make_fingerprint(mbedtls_x509_crt *crt,
                        CertificateFingerprint::Algorithm fingerprintAlgorithm) {
	const int size = CertificateFingerprint::AlgorithmSize(fingerprintAlgorithm);
	std::vector<unsigned char> buffer(size);
	std::stringstream fingerprint;

	psa_algorithm_t alg = PSA_ALG_NONE;

	switch (fingerprintAlgorithm) {
	case CertificateFingerprint::Algorithm::Sha1:
		alg = PSA_ALG_SHA_1;
		break;
	case CertificateFingerprint::Algorithm::Sha224:
		alg = PSA_ALG_SHA_224;
		break;
	case CertificateFingerprint::Algorithm::Sha256:
		alg = PSA_ALG_SHA_256;
		break;
	case CertificateFingerprint::Algorithm::Sha384:
		alg = PSA_ALG_SHA_384;
		break;
	case CertificateFingerprint::Algorithm::Sha512:
		alg = PSA_ALG_SHA_512;
		break;
	default:
		throw std::invalid_argument("Unknown fingerprint algorithm");
	}

	size_t hash_size = 0;
	int ret = mbedtls::safe_psa([&] {
		return psa_hash_compute(alg, crt->raw.p, crt->raw.len,
		        buffer.data(), buffer.size(), &hash_size);
	});
	mbedtls::check(ret, "Failed to generate certificate fingerprint");
	if (hash_size != buffer.size()) {
		throw std::runtime_error("Unexpected hash size");
	}

	for (auto i = 0; i < size; i++) {
		fingerprint << std::setfill('0') << std::setw(2) << std::hex
		            << static_cast<int>(buffer.at(i));
		if (i != (size - 1)) {
			fingerprint << ":";
		}
	}

	return fingerprint.str();
}

Certificate::Certificate(shared_ptr<mbedtls_x509_crt> crt, shared_ptr<mbedtls_pk_context> pk)
    : mCrt(crt), mPk(pk),
      mFingerprint(make_fingerprint(crt.get(), CertificateFingerprint::Algorithm::Sha256)) {}

Certificate Certificate::FromString(string crt_pem, string key_pem) {
	PLOG_DEBUG << "Importing certificate from PEM string (MbedTLS)";

	auto crt = mbedtls::new_x509_crt();
	auto pk = mbedtls::new_pk_context();

	mbedtls::check(mbedtls_x509_crt_parse(crt.get(),
	                                      reinterpret_cast<const unsigned char *>(crt_pem.c_str()),
	                                      crt_pem.size() + 1),
	               "Failed to parse certificate");
#if MBEDTLS_VERSION_MAJOR < 4
	mbedtls::check(mbedtls_pk_parse_key(pk.get(),
	                                    reinterpret_cast<const unsigned char *>(key_pem.c_str()),
	                                    key_pem.size() + 1, NULL, 0, NULL, 0),
	               "Failed to parse key");
#else
	mbedtls::check(mbedtls_pk_parse_key(pk.get(),
	                                    reinterpret_cast<const unsigned char *>(key_pem.c_str()),
	                                    key_pem.size() + 1, NULL, 0),
	               "Failed to parse key");
#endif

	return Certificate(std::move(crt), std::move(pk));
}

Certificate Certificate::FromFile(const string &crt_pem_file, const string &key_pem_file,
                                  const string &pass) {
	PLOG_DEBUG << "Importing certificate from PEM file (MbedTLS): " << crt_pem_file;

	auto crt = mbedtls::new_x509_crt();
	auto pk = mbedtls::new_pk_context();

	mbedtls::check(mbedtls_x509_crt_parse_file(crt.get(), crt_pem_file.c_str()),
	               "Failed to parse certificate");
#if MBEDTLS_VERSION_MAJOR < 4
	mbedtls::check(mbedtls_pk_parse_keyfile(pk.get(), key_pem_file.c_str(), pass.c_str(), 0, NULL),
	               "Failed to parse key");
#else
	mbedtls::check(mbedtls_pk_parse_keyfile(pk.get(), key_pem_file.c_str(), pass.c_str()),
	               "Failed to parse key");
#endif

	return Certificate(std::move(crt), std::move(pk));
}

Certificate Certificate::Generate(CertificateType type, const string &commonName) {
	PLOG_DEBUG << "Generating certificate (MbedTLS)";

	mbedtls_x509write_cert wcrt;
	auto crt = mbedtls::new_x509_crt();
	auto pk = mbedtls::new_pk_context();

	mbedtls_x509write_crt_init(&wcrt);

	try {
		switch (type) {
		// RFC 8827 WebRTC Security Architecture 6.5. Communications Security
		// All implementations MUST support DTLS 1.2 with the
		// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite and the P-256 curve
		// See https://www.rfc-editor.org/rfc/rfc8827.html#section-6.5
		case CertificateType::Default:
		case CertificateType::Ecdsa: {
			int ret = mbedtls::safe_psa([&] {
				psa_key_id_t slot = PSA_KEY_ID_NULL;
				psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
				psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
				psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY);
				psa_set_key_bits(&attr, 256);
				int ret = psa_generate_key(&attr, &slot);
				if (ret) {
					psa_destroy_key(slot);
					return ret;
				}
				ret = mbedtls_pk_copy_from_psa(slot, pk.get());
				psa_destroy_key(slot);
				return ret;
			});
			mbedtls::check(ret, "Unable to generate ECDSA P-256 key pair");
			break;
		}
		case CertificateType::Rsa: {
			const unsigned int nbits = 2048;
			int ret = mbedtls::safe_psa([&] {
				psa_key_id_t slot = PSA_KEY_ID_NULL;
				psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
				psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
				psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY);
				psa_set_key_bits(&attr, nbits);
				int ret = psa_generate_key(&attr, &slot);
				if (ret) {
					psa_destroy_key(slot);
					return ret;
				}
				ret = mbedtls_pk_copy_from_psa(slot, pk.get());
				psa_destroy_key(slot);
				return ret;
			});
			mbedtls::check(ret, "Unable to generate RSA key pair");
			break;
		}
		default:
			throw std::invalid_argument("Unknown certificate type");
		}

		auto now = std::chrono::system_clock::now();
		string notBefore = mbedtls::format_time(now - std::chrono::hours(1));
		string notAfter = mbedtls::format_time(now + std::chrono::hours(24 * 365));

		const size_t serialBufferSize = 16;
		unsigned char serialBuffer[serialBufferSize];
		int ret = mbedtls::safe_psa([&] {
			return psa_generate_random(serialBuffer, serialBufferSize);
		});
		mbedtls::check(ret, "Failed to generate certificate");

		std::string name = std::string("O=" + commonName + ",CN=" + commonName);
		mbedtls::check(mbedtls_x509write_crt_set_serial_raw(&wcrt, serialBuffer, serialBufferSize),
		               "Failed to generate certificate");
		mbedtls::check(mbedtls_x509write_crt_set_subject_name(&wcrt, name.c_str()),
		               "Failed to generate certificate");
		mbedtls::check(mbedtls_x509write_crt_set_issuer_name(&wcrt, name.c_str()),
		               "Failed to generate certificate");
		mbedtls::check(
		    mbedtls_x509write_crt_set_validity(&wcrt, notBefore.c_str(), notAfter.c_str()),
		    "Failed to generate certificate");

		mbedtls_x509write_crt_set_version(&wcrt, MBEDTLS_X509_CRT_VERSION_3);
		mbedtls_x509write_crt_set_subject_key(&wcrt, pk.get());
		mbedtls_x509write_crt_set_issuer_key(&wcrt, pk.get());
		mbedtls_x509write_crt_set_md_alg(&wcrt, MBEDTLS_MD_SHA256);

		const size_t certificateBufferSize = 4096;
		unsigned char certificateBuffer[certificateBufferSize];
		std::memset(certificateBuffer, 0, certificateBufferSize);

#if MBEDTLS_VERSION_MAJOR < 4
		auto certificateLen = mbedtls_x509write_crt_der(
		    &wcrt, certificateBuffer, certificateBufferSize, &mbedtls::random_func, nullptr);
#else
		auto certificateLen = mbedtls_x509write_crt_der(
		    &wcrt, certificateBuffer, certificateBufferSize);
#endif
		if (certificateLen <= 0) {
			throw std::runtime_error("Certificate generation failed");
		}

		mbedtls::check(mbedtls_x509_crt_parse_der(
		                   crt.get(), (certificateBuffer + certificateBufferSize - certificateLen),
		                   certificateLen),
		               "Failed to generate certificate");
	} catch (...) {
		mbedtls_x509write_crt_free(&wcrt);
		throw;
	}

	mbedtls_x509write_crt_free(&wcrt);
	return Certificate(std::move(crt), std::move(pk));
}

std::tuple<shared_ptr<mbedtls_x509_crt>, shared_ptr<mbedtls_pk_context>>
Certificate::credentials() const {
	return {mCrt, mPk};
}

#elif USE_SCHANNEL

namespace {

NCRYPT_PROV_HANDLE open_provider() {
	NCRYPT_PROV_HANDLE prov = 0;
	schannel::check(NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0),
	                "Failed to open CNG key storage provider");
	return prov;
}

// SChannel resolves the private key by key container name rather than through an in-process
// handle, so each certificate gets its own named key, deleted again when the certificate is freed.
std::wstring make_key_name() {
	unsigned char random[16];
	if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		throw std::runtime_error("Unable to generate key container name");

	std::wostringstream oss;
	oss << L"libdatachannel-" << std::hex << std::setfill(L'0');
	for (auto b : random)
		oss << std::setw(2) << unsigned(b);

	return oss.str();
}

void free_cert(const CERT_CONTEXT *cert) {
	if (!cert)
		return;

	DWORD size = 0;
	if (CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size) &&
	    size > 0) {
		std::vector<BYTE> buffer(size);
		auto *info = reinterpret_cast<CRYPT_KEY_PROV_INFO *>(buffer.data());
		if (CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, info, &size)) {
			NCRYPT_PROV_HANDLE prov = 0;
			if (NCryptOpenStorageProvider(&prov, info->pwszProvName, 0) == ERROR_SUCCESS) {
				NCRYPT_KEY_HANDLE key = 0;
				if (NCryptOpenKey(prov, &key, info->pwszContainerName, 0, NCRYPT_SILENT_FLAG) ==
				    ERROR_SUCCESS)
					NCryptDeleteKey(key, NCRYPT_SILENT_FLAG); // also frees the handle
				NCryptFreeObject(prov);
			}
		}
	}

	CertFreeCertificateContext(cert);
}

void set_cert_key(PCCERT_CONTEXT cert, const std::wstring &keyName) {
	CRYPT_KEY_PROV_INFO info = {};
	info.pwszContainerName = const_cast<LPWSTR>(keyName.c_str());
	info.pwszProvName = const_cast<LPWSTR>(MS_KEY_STORAGE_PROVIDER);
	info.dwProvType = 0; // CNG
	info.dwKeySpec = 0;

	if (!CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &info))
		throw std::runtime_error("Unable to attach private key to certificate: " +
		                         schannel::error_string(static_cast<long>(GetLastError())));
}

std::vector<BYTE> pem_to_der(const string &pem) {
	DWORD size = 0;
	if (!CryptStringToBinaryA(pem.data(), DWORD(pem.size()), CRYPT_STRING_BASE64HEADER, nullptr,
	                          &size, nullptr, nullptr))
		throw std::invalid_argument("Unable to parse PEM block");

	std::vector<BYTE> der(size);
	if (!CryptStringToBinaryA(pem.data(), DWORD(pem.size()), CRYPT_STRING_BASE64HEADER, der.data(),
	                          &size, nullptr, nullptr))
		throw std::invalid_argument("Unable to decode PEM block");

	der.resize(size);
	return der;
}

// Only PKCS#8 blobs can be imported under a key container name, which SChannel requires to find
// the key again later
NCRYPT_KEY_HANDLE import_key(NCRYPT_PROV_HANDLE prov, const std::vector<BYTE> &der,
                             const std::wstring &keyName) {
	NCryptBuffer nameBuffer = {};
	nameBuffer.BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
	nameBuffer.cbBuffer = ULONG((keyName.size() + 1) * sizeof(wchar_t));
	nameBuffer.pvBuffer = const_cast<wchar_t *>(keyName.c_str());

	NCryptBufferDesc params = {};
	params.ulVersion = NCRYPTBUFFER_VERSION;
	params.cBuffers = 1;
	params.pBuffers = &nameBuffer;

	NCRYPT_KEY_HANDLE key = 0;
	schannel::check(NCryptImportKey(prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &params, &key,
	                                const_cast<PBYTE>(der.data()), DWORD(der.size()),
	                                NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_SILENT_FLAG),
	                "Unable to import PEM key (only PKCS#8 keys are supported with SChannel)");

	return key;
}

} // namespace

string make_fingerprint(PCCERT_CONTEXT cert,
                        CertificateFingerprint::Algorithm fingerprintAlgorithm) {
	LPCWSTR hashFunc;
	switch (fingerprintAlgorithm) {
	case CertificateFingerprint::Algorithm::Sha1:
		hashFunc = BCRYPT_SHA1_ALGORITHM;
		break;
	case CertificateFingerprint::Algorithm::Sha256:
		hashFunc = BCRYPT_SHA256_ALGORITHM;
		break;
	case CertificateFingerprint::Algorithm::Sha384:
		hashFunc = BCRYPT_SHA384_ALGORITHM;
		break;
	case CertificateFingerprint::Algorithm::Sha512:
		hashFunc = BCRYPT_SHA512_ALGORITHM;
		break;
	default:
		// SHA-224 has no BCrypt algorithm identifier
		throw std::invalid_argument("Unsupported fingerprint algorithm");
	}

	const size_t size = CertificateFingerprint::AlgorithmSize(fingerprintAlgorithm);
	std::vector<unsigned char> buffer(size);
	auto len = DWORD(size);

	if (!CryptHashCertificate2(hashFunc, 0, nullptr, cert->pbCertEncoded, cert->cbCertEncoded,
	                           buffer.data(), &len))
		throw std::runtime_error("X509 fingerprint error: " +
		                         schannel::error_string(static_cast<long>(GetLastError())));

	std::ostringstream oss;
	oss << std::hex << std::uppercase << std::setfill('0');
	for (DWORD i = 0; i < len; ++i) {
		if (i)
			oss << std::setw(1) << ':';
		oss << std::setw(2) << unsigned(buffer.at(i));
	}
	return oss.str();
}

Certificate::Certificate(shared_ptr<const CERT_CONTEXT> cert)
    : mCert(std::move(cert)),
      mFingerprint(make_fingerprint(mCert.get(), CertificateFingerprint::Algorithm::Sha256)) {}

Certificate Certificate::FromString(string crt_pem, string key_pem) {
	PLOG_DEBUG << "Importing certificate from PEM string (SChannel)";

	auto crtDer = pem_to_der(crt_pem);
	auto keyDer = pem_to_der(key_pem);

	PCCERT_CONTEXT cert =
	    CertCreateCertificateContext(X509_ASN_ENCODING, crtDer.data(), DWORD(crtDer.size()));
	if (!cert)
		throw std::invalid_argument("Unable to import PEM certificate");

	const std::wstring keyName = make_key_name();

	NCRYPT_PROV_HANDLE prov = 0;
	NCRYPT_KEY_HANDLE key = 0;
	try {
		prov = open_provider();
		key = import_key(prov, keyDer, keyName);
		set_cert_key(cert, keyName);
	} catch (...) {
		CertFreeCertificateContext(cert);
		if (key)
			NCryptDeleteKey(key, NCRYPT_SILENT_FLAG);
		if (prov)
			NCryptFreeObject(prov);
		throw;
	}

	NCryptFreeObject(key);
	NCryptFreeObject(prov);
	return Certificate(shared_ptr<const CERT_CONTEXT>(cert, free_cert));
}

Certificate Certificate::FromFile(const string &crt_pem_file, const string &key_pem_file,
                                  const string &pass) {
	PLOG_DEBUG << "Importing certificate from PEM file (SChannel): " << crt_pem_file;

	if (!pass.empty())
		throw std::invalid_argument("Encrypted PEM keys are not supported with SChannel");

	auto read = [](const string &filename) -> string {
		std::ifstream ifs(filename, std::ifstream::in | std::ifstream::binary);
		if (!ifs.is_open())
			throw std::invalid_argument("Unable to open PEM file: " + filename);

		return string(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
	};

	return FromString(read(crt_pem_file), read(key_pem_file));
}

Certificate Certificate::Generate(CertificateType type, const string &commonName) {
	PLOG_DEBUG << "Generating certificate (SChannel)";

	LPCWSTR algorithm;
	LPSTR signatureOid;
	DWORD length = 0;
	switch (type) {
	// RFC 8827 WebRTC Security Architecture 6.5. Communications Security
	// All implementations MUST support DTLS 1.2 with the TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	// cipher suite and the P-256 curve
	// See https://www.rfc-editor.org/rfc/rfc8827.html#section-6.5
	case CertificateType::Default:
	case CertificateType::Ecdsa:
		algorithm = NCRYPT_ECDSA_P256_ALGORITHM;
		signatureOid = const_cast<LPSTR>(szOID_ECDSA_SHA256);
		break;
	case CertificateType::Rsa:
		algorithm = NCRYPT_RSA_ALGORITHM;
		signatureOid = const_cast<LPSTR>(szOID_RSA_SHA256RSA);
		length = 2048;
		break;
	default:
		throw std::invalid_argument("Unknown certificate type");
	}

	const std::wstring keyName = make_key_name();

	NCRYPT_PROV_HANDLE prov = open_provider();
	NCRYPT_KEY_HANDLE key = 0;
	PCCERT_CONTEXT cert = nullptr;
	try {
		// NCRYPT_SILENT_FLAG guarantees the provider never displays any UI
		schannel::check(NCryptCreatePersistedKey(prov, &key, algorithm, keyName.c_str(), 0,
		                                         NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_SILENT_FLAG),
		                "Unable to create key pair");

		if (length)
			schannel::check(NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY,
			                                  reinterpret_cast<PBYTE>(&length), sizeof(length),
			                                  NCRYPT_SILENT_FLAG),
			                "Unable to set key length");

		schannel::check(NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG), "Unable to generate key pair");

		std::wstring subject(commonName.begin(), commonName.end());
		subject = L"CN=" + subject;

		DWORD nameSize = 0;
		if (!CertStrToNameW(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR, nullptr, nullptr,
		                    &nameSize, nullptr))
			throw std::runtime_error("Unable to encode certificate subject name");

		std::vector<BYTE> nameBuffer(nameSize);
		if (!CertStrToNameW(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR, nullptr,
		                    nameBuffer.data(), &nameSize, nullptr))
			throw std::runtime_error("Unable to encode certificate subject name");

		CERT_NAME_BLOB subjectBlob = {nameSize, nameBuffer.data()};

		CRYPT_ALGORITHM_IDENTIFIER signature = {};
		signature.pszObjId = signatureOid;

		const ULONGLONG second = 10000000ULL; // in 100ns intervals
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		ULARGE_INTEGER now;
		now.LowPart = fileTime.dwLowDateTime;
		now.HighPart = fileTime.dwHighDateTime;

		ULARGE_INTEGER before = now, after = now;
		before.QuadPart -= 3600ULL * second;
		after.QuadPart += 24ULL * 365 * 3600 * second;

		FILETIME beforeTime = {before.LowPart, before.HighPart};
		FILETIME afterTime = {after.LowPart, after.HighPart};

		SYSTEMTIME notBefore, notAfter;
		FileTimeToSystemTime(&beforeTime, &notBefore);
		FileTimeToSystemTime(&afterTime, &notAfter);

		// Passing the key container info explicitly avoids the provider query the call would
		// otherwise perform to build it, which not all providers support
		CRYPT_KEY_PROV_INFO keyProvInfo = {};
		keyProvInfo.pwszContainerName = const_cast<LPWSTR>(keyName.c_str());
		keyProvInfo.pwszProvName = const_cast<LPWSTR>(MS_KEY_STORAGE_PROVIDER);
		keyProvInfo.dwProvType = 0; // CNG
		keyProvInfo.dwKeySpec = 0;

		cert = CertCreateSelfSignCertificate(key, &subjectBlob, 0, &keyProvInfo, &signature,
		                                     &notBefore, &notAfter, nullptr);
		if (!cert)
			throw std::runtime_error("Unable to auto-sign certificate: " +
			                         schannel::error_string(static_cast<long>(GetLastError())));

	} catch (...) {
		if (key)
			NCryptDeleteKey(key, NCRYPT_SILENT_FLAG);
		NCryptFreeObject(prov);
		throw;
	}

	NCryptFreeObject(key);
	NCryptFreeObject(prov);
	return Certificate(shared_ptr<const CERT_CONTEXT>(cert, free_cert));
}

PCCERT_CONTEXT Certificate::credentials() const { return mCert.get(); }

#else // OPENSSL

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

namespace {

// Dummy password callback that copies the password from user data
int dummy_pass_cb(char *buf, int size, int /*rwflag*/, void *u) {
	const char *pass = static_cast<char *>(u);
	return snprintf(buf, size, "%s", pass);
}

} // namespace

Certificate Certificate::FromString(string crt_pem, string key_pem) {
	PLOG_DEBUG << "Importing certificate from PEM string (OpenSSL)";

	BIO *bio = BIO_new(BIO_s_mem());
	BIO_write(bio, crt_pem.data(), int(crt_pem.size()));
	auto x509 = shared_ptr<X509>(PEM_read_bio_X509(bio, nullptr, nullptr, nullptr), X509_free);
	if (!x509) {
		BIO_free(bio);
		throw std::invalid_argument("Unable to import PEM certificate");
	}
	std::vector<shared_ptr<X509>> chain;
	while (auto extra =
	           shared_ptr<X509>(PEM_read_bio_X509(bio, nullptr, nullptr, nullptr), X509_free)) {
		chain.push_back(std::move(extra));
	}
	BIO_free(bio);

	bio = BIO_new(BIO_s_mem());
	BIO_write(bio, key_pem.data(), int(key_pem.size()));
	auto pkey = shared_ptr<EVP_PKEY>(PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr),
	                                 EVP_PKEY_free);
	BIO_free(bio);
	if (!pkey)
		throw std::invalid_argument("Unable to import PEM key");

	return {x509, pkey, std::move(chain)};
}

Certificate Certificate::FromFile(const string &crt_pem_file, const string &key_pem_file,
                                  const string &pass) {
	PLOG_DEBUG << "Importing certificate from PEM file (OpenSSL): " << crt_pem_file;

	BIO *bio = openssl::BIO_new_from_file(crt_pem_file);
	if (!bio)
		throw std::invalid_argument("Unable to open PEM certificate file");

	auto x509 = shared_ptr<X509>(PEM_read_bio_X509(bio, nullptr, nullptr, nullptr), X509_free);
	if (!x509) {
		BIO_free(bio);
		throw std::invalid_argument("Unable to import PEM certificate from file");
	}
	std::vector<shared_ptr<X509>> chain;
	while (auto extra =
	           shared_ptr<X509>(PEM_read_bio_X509(bio, nullptr, nullptr, nullptr), X509_free)) {
		chain.push_back(std::move(extra));
	}
	BIO_free(bio);

	bio = openssl::BIO_new_from_file(key_pem_file);
	if (!bio)
		throw std::invalid_argument("Unable to open PEM key file");

	auto pkey = shared_ptr<EVP_PKEY>(
	    PEM_read_bio_PrivateKey(bio, nullptr, dummy_pass_cb, const_cast<char *>(pass.c_str())),
	    EVP_PKEY_free);
	BIO_free(bio);
	if (!pkey)
		throw std::invalid_argument("Unable to import PEM key from file");

	return {x509, pkey, std::move(chain)};
}

Certificate Certificate::Generate(CertificateType type, const string &commonName) {
	PLOG_DEBUG << "Generating certificate (OpenSSL)";

	shared_ptr<X509> x509(X509_new(), X509_free);
	unique_ptr<BIGNUM, decltype(&BN_free)> serial_number(BN_new(), BN_free);
	unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name(X509_NAME_new(), X509_NAME_free);
	if (!x509 || !serial_number || !name)
		throw std::runtime_error("Unable to allocate structures for certificate generation");

	shared_ptr<EVP_PKEY> pkey;
	switch (type) {
	// RFC 8827 WebRTC Security Architecture 6.5. Communications Security
	// All implementations MUST support DTLS 1.2 with the TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	// cipher suite and the P-256 curve
	// See https://www.rfc-editor.org/rfc/rfc8827.html#section-6.5
	case CertificateType::Default:
	case CertificateType::Ecdsa: {
		PLOG_VERBOSE << "Generating ECDSA P-256 key pair";
#if OPENSSL_VERSION_NUMBER >= 0x30000000
		pkey = shared_ptr<EVP_PKEY>(EVP_EC_gen("prime256v1"), EVP_PKEY_free);
		if (!pkey)
			throw std::runtime_error("Unable to generate ECDSA P-256 key pair");
#else
		pkey = shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free);
		unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ecc(
		    EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
		if (!pkey || !ecc)
			throw std::runtime_error("Unable to allocate structure for ECDSA P-256 key pair");

		EC_KEY_set_asn1_flag(ecc.get(), OPENSSL_EC_NAMED_CURVE); // Set ASN1 OID
		if (!EC_KEY_generate_key(ecc.get()) || !EVP_PKEY_assign_EC_KEY(pkey.get(), ecc.get()))
			throw std::runtime_error("Unable to generate ECDSA P-256 key pair");

		ecc.release(); // the key will be freed when pkey is freed
#endif
		break;
	}
	case CertificateType::Rsa: {
		PLOG_VERBOSE << "Generating RSA key pair";
		const unsigned int bits = 2048;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
		pkey = shared_ptr<EVP_PKEY>(EVP_RSA_gen(bits), EVP_PKEY_free);
		if (!pkey)
			throw std::runtime_error("Unable to generate RSA key pair");
#else
		pkey = shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free);
		unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), RSA_free);
		unique_ptr<BIGNUM, decltype(&BN_free)> exponent(BN_new(), BN_free);
		if (!pkey || !rsa || !exponent)
			throw std::runtime_error("Unable to allocate structures for RSA key pair");

		const unsigned int e = 65537; // 2^16 + 1
		if (!BN_set_word(exponent.get(), e) ||
		    !RSA_generate_key_ex(rsa.get(), bits, exponent.get(), NULL) ||
		    !EVP_PKEY_assign_RSA(pkey.get(), rsa.get()))
			throw std::runtime_error("Unable to generate RSA key pair");

		rsa.release(); // the key will be freed when pkey is freed
#endif
		break;
	}
	default:
		throw std::invalid_argument("Unknown certificate type");
	}

	const size_t serialSize = 16;
	auto *commonNameBytes =
	    reinterpret_cast<unsigned char *>(const_cast<char *>(commonName.c_str()));

	if (!X509_gmtime_adj(X509_getm_notBefore(x509.get()), 3600 * -1) ||
	    !X509_gmtime_adj(X509_getm_notAfter(x509.get()), 3600 * 24 * 365) ||
#if OPENSSL_VERSION_NUMBER >= 0x30000000
	    !X509_set_version(x509.get(), X509_VERSION_1) || 
#else
		!X509_set_version(x509.get(), 0) ||
#endif 					
		!BN_rand(serial_number.get(), serialSize, 0, 0) ||
	    !BN_to_ASN1_INTEGER(serial_number.get(), X509_get_serialNumber(x509.get())) ||
	    !X509_NAME_add_entry_by_NID(name.get(), NID_commonName, MBSTRING_UTF8, commonNameBytes, -1,
	                                -1, 0) ||
	    !X509_set_subject_name(x509.get(), name.get()) ||
	    !X509_set_issuer_name(x509.get(), name.get()))
		throw std::runtime_error("Unable to set certificate properties");

	if (!X509_set_pubkey(x509.get(), pkey.get()))
		throw std::runtime_error("Unable to set certificate public key");

	if (!X509_sign(x509.get(), pkey.get(), EVP_sha256()))
		throw std::runtime_error("Unable to auto-sign certificate");

	return {x509, pkey};
}

Certificate::Certificate(shared_ptr<X509> x509, shared_ptr<EVP_PKEY> pkey,
                         std::vector<shared_ptr<X509>> chain)
    : mX509(std::move(x509)), mPKey(std::move(pkey)), mChain(std::move(chain)),
      mFingerprint(make_fingerprint(mX509.get(), CertificateFingerprint::Algorithm::Sha256)) {}

std::tuple<X509 *, EVP_PKEY *> Certificate::credentials() const {
	return {mX509.get(), mPKey.get()};
}

std::vector<X509 *> Certificate::chain() const {
	std::vector<X509 *> v;
	v.reserve(mChain.size());
	std::transform(mChain.begin(), mChain.end(), std::back_inserter(v),
	               [](const auto &c) { return c.get(); });
	return v;
}

string make_fingerprint(X509 *x509, CertificateFingerprint::Algorithm fingerprintAlgorithm) {
	size_t size = CertificateFingerprint::AlgorithmSize(fingerprintAlgorithm);
	std::vector<unsigned char> buffer(size);
	auto len = static_cast<unsigned int>(size);

	const EVP_MD *hashFunc;
	switch (fingerprintAlgorithm) {
	case CertificateFingerprint::Algorithm::Sha1:
		hashFunc = EVP_sha1();
		break;
	case CertificateFingerprint::Algorithm::Sha224:
		hashFunc = EVP_sha224();
		break;
	case CertificateFingerprint::Algorithm::Sha256:
		hashFunc = EVP_sha256();
		break;
	case CertificateFingerprint::Algorithm::Sha384:
		hashFunc = EVP_sha384();
		break;
	case CertificateFingerprint::Algorithm::Sha512:
		hashFunc = EVP_sha512();
		break;
	default:
		throw std::invalid_argument("Unknown fingerprint algorithm");
	}

	if (!X509_digest(x509, hashFunc, buffer.data(), &len))
		throw std::runtime_error("X509 fingerprint error");

	std::ostringstream oss;
	oss << std::hex << std::uppercase << std::setfill('0');
	for (size_t i = 0; i < len; ++i) {
		if (i)
			oss << std::setw(1) << ':';
		oss << std::setw(2) << unsigned(buffer.at(i));
	}
	return oss.str();
}

#endif

// Common for GnuTLS, Mbed TLS, and OpenSSL

future_certificate_ptr make_certificate(CertificateType type) {
	return ThreadPool::Instance().enqueue([type, token = Init::Instance().token()]() {
		return std::make_shared<Certificate>(Certificate::Generate(type, "libdatachannel"));
	});
}

CertificateFingerprint Certificate::fingerprint() const {
	return CertificateFingerprint{CertificateFingerprint::Algorithm::Sha256, mFingerprint};
}

} // namespace rtc::impl
