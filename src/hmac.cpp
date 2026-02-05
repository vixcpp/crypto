/**
 *
 *  @file hmac.cpp
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
#include <vix/crypto/hmac.hpp>

#include <cstring>
#include <limits>

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

namespace vix::crypto
{

  static Result<void> hmac_sha256_openssl(
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> data,
      std::span<std::uint8_t> out) noexcept
  {
#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
    if (out.size() != 32)
      return Result<void>{ErrorCode::invalid_argument, "hmac-sha256 output must be 32 bytes"};

    if (key.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
      return Result<void>{ErrorCode::invalid_argument, "key too large"};

    if (data.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
      return Result<void>{ErrorCode::invalid_argument, "data too large"};

    unsigned int out_len = 0;

    unsigned char *res = HMAC(EVP_sha256(),
                              key.data(),
                              static_cast<int>(key.size()),
                              data.empty() ? nullptr : data.data(),
                              static_cast<int>(data.size()),
                              out.data(),
                              &out_len);

    if (!res)
      return Result<void>{ErrorCode::provider_error, "OpenSSL HMAC(EVP_sha256) failed"};

    if (out_len != 32)
      return Result<void>{ErrorCode::provider_error, "hmac-sha256 produced unexpected size"};

    return Result<void>{};
#else
    (void)key;
    (void)data;
    (void)out;
    return Result<void>{ErrorCode::provider_unavailable, "OpenSSL provider not enabled"};
#endif
  }

  Result<void> hmac(
      HmacAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> data,
      std::span<std::uint8_t> out) noexcept
  {
    switch (alg)
    {
    case HmacAlg::sha256:
      return hmac_sha256(key, data, out);
    default:
      return Result<void>{ErrorCode::not_supported, "unsupported hmac algorithm"};
    }
  }

  Result<void> hmac_sha256(
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> data,
      std::span<std::uint8_t> out) noexcept
  {
    if (out.size() != 32)
      return Result<void>{ErrorCode::invalid_argument, "hmac-sha256 output must be 32 bytes"};

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
    return hmac_sha256_openssl(key, data, out);
#else
    (void)key;
    (void)data;
    (void)out;
    return Result<void>{ErrorCode::provider_unavailable, "No HMAC provider available"};
#endif
  }

  Result<void> hmac_sha256(
      std::span<const std::uint8_t> key,
      std::string_view data,
      std::span<std::uint8_t> out) noexcept
  {
    const auto *p = reinterpret_cast<const std::uint8_t *>(data.data());
    return hmac_sha256(key, std::span<const std::uint8_t>(p, data.size()), out);
  }

} // namespace vix::crypto
