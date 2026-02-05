/**
 *
 *  @file kdf.cpp
 *  @author Gaspard Kirira
 *
 *  Copyright 2025, Gaspard Kirira.
 *  All rights reserved.
 *  https://github.com/vixcpp/vix
 *
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
 *
 *  Vix.cpp
 *
 */
#include <vix/crypto/kdf.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
#include <openssl/evp.h>
#include <openssl/kdf.h>
#endif

namespace vix::crypto
{

  static Result<void> hkdf_sha256_openssl(std::span<const std::uint8_t> ikm,
                                          std::span<const std::uint8_t> salt,
                                          std::span<const std::uint8_t> info,
                                          std::span<std::uint8_t> out) noexcept
  {
#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
    if (out.empty())
      return Result<void>{};

    // EVP_KDF based HKDF (OpenSSL 3.x preferred). Works on 1.1.1 with EVP_PKEY HKDF too,
    // but EVP_KDF is the cleanest if available.
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf)
      return Result<void>{ErrorCode::provider_error, "EVP_KDF_fetch(HKDF) failed"};

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx)
      return Result<void>{ErrorCode::provider_error, "EVP_KDF_CTX_new failed"};

    // OpenSSL params
    // digest = SHA256
    // key = ikm
    // salt = salt
    // info = info
    OSSL_PARAM params[6];
    std::size_t p = 0;

    params[p++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, const_cast<char *>("SHA256"), 0);

    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY,
        const_cast<std::uint8_t *>(ikm.data()),
        ikm.size());

    if (!salt.empty())
    {
      params[p++] = OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_SALT,
          const_cast<std::uint8_t *>(salt.data()),
          salt.size());
    }

    if (!info.empty())
    {
      params[p++] = OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_INFO,
          const_cast<std::uint8_t *>(info.data()),
          info.size());
    }

    params[p++] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out.data(), out.size(), params) != 1)
    {
      EVP_KDF_CTX_free(kctx);
      return Result<void>{ErrorCode::provider_error, "EVP_KDF_derive(HKDF-SHA256) failed"};
    }

    EVP_KDF_CTX_free(kctx);
    return Result<void>{};
#else
    (void)ikm;
    (void)salt;
    (void)info;
    (void)out;
    return Result<void>{ErrorCode::provider_unavailable, "OpenSSL provider not enabled"};
#endif
  }

  Result<void> kdf(KdfAlg alg,
                   std::span<const std::uint8_t> ikm,
                   std::span<const std::uint8_t> salt,
                   std::span<const std::uint8_t> info,
                   std::span<std::uint8_t> out) noexcept
  {
    switch (alg)
    {
    case KdfAlg::hkdf_sha256:
      return hkdf_sha256(ikm, salt, info, out);
    default:
      return Result<void>{ErrorCode::not_supported, "unsupported kdf algorithm"};
    }
  }

  Result<void> hkdf_sha256(std::span<const std::uint8_t> ikm,
                           std::span<const std::uint8_t> salt,
                           std::span<const std::uint8_t> info,
                           std::span<std::uint8_t> out) noexcept
  {
    if (ikm.empty())
      return Result<void>{ErrorCode::invalid_argument, "ikm must not be empty"};

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
    return hkdf_sha256_openssl(ikm, salt, info, out);
#else
    (void)ikm;
    (void)salt;
    (void)info;
    (void)out;
    return Result<void>{ErrorCode::provider_unavailable, "No HKDF provider available"};
#endif
  }

} // namespace vix::crypto
