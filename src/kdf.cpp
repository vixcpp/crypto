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

#include <limits>

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif
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

    if (ikm.empty())
      return Result<void>{ErrorCode::invalid_argument, "ikm must not be empty"};

    // OpenSSL 1.1.1 APIs take int sizes in multiple places.
    const auto max_i = static_cast<std::size_t>(std::numeric_limits<int>::max());
    if (ikm.size() > max_i)
      return Result<void>{ErrorCode::invalid_argument, "ikm too large"};
    if (salt.size() > max_i)
      return Result<void>{ErrorCode::invalid_argument, "salt too large"};
    if (info.size() > max_i)
      return Result<void>{ErrorCode::invalid_argument, "info too large"};

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // ------------------------------------------------------------
    // OpenSSL 3.x: EVP_KDF + OSSL_PARAM
    // ------------------------------------------------------------
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf)
      return Result<void>{ErrorCode::provider_error, "EVP_KDF_fetch(HKDF) failed"};

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx)
      return Result<void>{ErrorCode::provider_error, "EVP_KDF_CTX_new failed"};

    // digest=SHA256, key=ikm, salt?, info?
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
    // ------------------------------------------------------------
    // OpenSSL 1.1.1: EVP_PKEY HKDF
    // ------------------------------------------------------------
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx)
      return Result<void>{ErrorCode::provider_error, "EVP_PKEY_CTX_new_id(HKDF) failed"};

    if (EVP_PKEY_derive_init(pctx) != 1)
    {
      EVP_PKEY_CTX_free(pctx);
      return Result<void>{ErrorCode::provider_error, "EVP_PKEY_derive_init(HKDF) failed"};
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) != 1)
    {
      EVP_PKEY_CTX_free(pctx);
      return Result<void>{ErrorCode::provider_error, "EVP_PKEY_CTX_set_hkdf_md failed"};
    }

    if (!salt.empty())
    {
      if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size())) != 1)
      {
        EVP_PKEY_CTX_free(pctx);
        return Result<void>{ErrorCode::provider_error, "EVP_PKEY_CTX_set1_hkdf_salt failed"};
      }
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), static_cast<int>(ikm.size())) != 1)
    {
      EVP_PKEY_CTX_free(pctx);
      return Result<void>{ErrorCode::provider_error, "EVP_PKEY_CTX_set1_hkdf_key failed"};
    }

    if (!info.empty())
    {
      if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), static_cast<int>(info.size())) != 1)
      {
        EVP_PKEY_CTX_free(pctx);
        return Result<void>{ErrorCode::provider_error, "EVP_PKEY_CTX_add1_hkdf_info failed"};
      }
    }

    std::size_t out_len = out.size();
    if (EVP_PKEY_derive(pctx, out.data(), &out_len) != 1)
    {
      EVP_PKEY_CTX_free(pctx);
      return Result<void>{ErrorCode::provider_error, "EVP_PKEY_derive(HKDF-SHA256) failed"};
    }

    EVP_PKEY_CTX_free(pctx);

    // Some providers may return a shorter length if misconfigured; treat as error.
    if (out_len != out.size())
      return Result<void>{ErrorCode::provider_error, "HKDF produced unexpected size"};

    return Result<void>{};
#endif

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

    // Allow empty out as a no-op (caller asked for 0 bytes)
    if (out.empty())
      return Result<void>{};

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
    return hkdf_sha256_openssl(ikm, salt, info, out);
#else
    (void)salt;
    (void)info;
    return Result<void>{ErrorCode::provider_unavailable, "No HKDF provider available"};
#endif
  }

} // namespace vix::crypto
