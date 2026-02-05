/**
 *
 *  @file hash.cpp
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
#include <vix/crypto/hash.hpp>

#include <array>
#include <cstring>

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
#include <openssl/evp.h>
#endif

namespace vix::crypto
{

  static Result<void> sha256_openssl(std::span<const std::uint8_t> data,
                                     std::span<std::uint8_t> out) noexcept
  {
#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
    if (out.size() != 32)
      return Result<void>{ErrorCode::invalid_argument, "sha256 output must be 32 bytes"};

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
      return Result<void>{ErrorCode::provider_error, "EVP_MD_CTX_new failed"};

    const EVP_MD *md = EVP_sha256();
    if (!md)
    {
      EVP_MD_CTX_free(ctx);
      return Result<void>{ErrorCode::provider_error, "EVP_sha256 not available"};
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1)
    {
      EVP_MD_CTX_free(ctx);
      return Result<void>{ErrorCode::provider_error, "EVP_DigestInit_ex failed"};
    }

    if (!data.empty())
    {
      if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
      {
        EVP_MD_CTX_free(ctx);
        return Result<void>{ErrorCode::provider_error, "EVP_DigestUpdate failed"};
      }
    }

    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(ctx, out.data(), &out_len) != 1)
    {
      EVP_MD_CTX_free(ctx);
      return Result<void>{ErrorCode::provider_error, "EVP_DigestFinal_ex failed"};
    }

    EVP_MD_CTX_free(ctx);

    if (out_len != 32)
      return Result<void>{ErrorCode::provider_error, "sha256 produced unexpected size"};

    return Result<void>{};
#else
    (void)data;
    (void)out;
    return Result<void>{ErrorCode::provider_unavailable, "OpenSSL provider not enabled"};
#endif
  }

  Result<void> hash(HashAlg alg,
                    std::span<const std::uint8_t> data,
                    std::span<std::uint8_t> out) noexcept
  {
    switch (alg)
    {
    case HashAlg::sha256:
      return sha256(data, out);
    default:
      return Result<void>{ErrorCode::not_supported, "unsupported hash algorithm"};
    }
  }

  Result<void> sha256(std::span<const std::uint8_t> data,
                      std::span<std::uint8_t> out) noexcept
  {
    if (out.size() != 32)
      return Result<void>{ErrorCode::invalid_argument, "sha256 output must be 32 bytes"};

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
    return sha256_openssl(data, out);
#else
    (void)data;
    (void)out;
    return Result<void>{ErrorCode::provider_unavailable, "No SHA-256 provider available"};
#endif
  }

  Result<void> sha256(std::string_view data,
                      std::span<std::uint8_t> out) noexcept
  {
    const auto *p = reinterpret_cast<const std::uint8_t *>(data.data());
    return sha256(std::span<const std::uint8_t>(p, data.size()), out);
  }

} // namespace vix::crypto
