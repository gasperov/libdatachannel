/**
 * Copyright (c) 2019-2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef RTC_TLS_H
#define RTC_TLS_H

#include "common.hpp"

#include <chrono>

#if USE_GNUTLS

#include <gnutls/gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/dtls.h>
#include <gnutls/x509.h>

namespace rtc::gnutls {

bool check(int ret, const string &message = "GnuTLS error");

gnutls_certificate_credentials_t *new_credentials();
void free_credentials(gnutls_certificate_credentials_t *creds);

gnutls_x509_crt_t *new_crt();
void free_crt(gnutls_x509_crt_t *crt);

gnutls_x509_privkey_t *new_privkey();
void free_privkey(gnutls_x509_privkey_t *privkey);

gnutls_datum_t make_datum(char *data, size_t size);

} // namespace rtc::gnutls

#elif USE_MBEDTLS

#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

// Mbed TLS version 3, relies on internal states when build with MBEDTLS_USE_PSA_CRYPTO.
// Mbed TLS version 4 always realies on internal states.
// In those scenarios, MBEDTLS_THREADING_C is required when using any Mbed TLS function
// unless all calls comes from the same thread.
#if !defined(MBEDTLS_THREADING_C) && (MBEDTLS_VERSION_MAJOR >= 4 || defined(MBEDTLS_USE_PSA_CRYPTO))
#error "Mbed TLS was not build with threading support (MBEDTLS_THREADING_C)."
#endif

namespace rtc::mbedtls {

void init();

int random_func(void *rng, unsigned char *out, size_t len);

int safe_psa(std::function<int()> func);

bool check(int ret, const string &message = "MbedTLS error");

string format_time(const std::chrono::system_clock::time_point &tp);

std::shared_ptr<mbedtls_pk_context> new_pk_context();
std::shared_ptr<mbedtls_x509_crt> new_x509_crt();

} // namespace rtc::mbedtls

#elif USE_SCHANNEL

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <bcrypt.h>
#include <ncrypt.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>
#include <wincrypt.h>

#if RTC_ENABLE_WEBSOCKET
#error "SChannel does not implement the TLS transport used by WebSocket support yet, build with NO_WEBSOCKET=ON"
#endif

// SChannel exposes the pieces DTLS-SRTP needs (SECBUFFER_SRTP_PROTECTION_PROFILES to offer the
// profiles, SECPKG_ATTR_SRTP_PARAMETERS to read the negotiated one, and SECPKG_ATTR_KEYING_MATERIAL
// to export the keys), but they are not wired up here yet.
#if RTC_ENABLE_MEDIA
#error "SChannel does not implement DTLS-SRTP for media transport yet, build with NO_MEDIA=ON"
#endif

namespace rtc::schannel {

void init();

string error_string(long status);

bool check(long status, const string &message = "SChannel error");

} // namespace rtc::schannel

#else // OPENSSL

#ifdef _WIN32
// Include winsock2.h header first since OpenSSL may include winsock.h
#include <winsock2.h>
#endif

#include <openssl/ssl.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#ifndef BIO_EOF
#define BIO_EOF -1
#endif

namespace rtc::openssl {

void init();
string error_string(unsigned long error);

bool check(int success, const string &message = "OpenSSL error");
bool check_error(int err, const string &message = "OpenSSL error");

BIO *BIO_new_from_file(const string &filename);

void SSL_CTX_add_cert_to_store_from_pem(SSL_CTX *ctx, const string &pem);

} // namespace rtc::openssl

#endif

#endif
