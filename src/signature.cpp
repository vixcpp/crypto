/**
 *
 *  @file signature.cpp
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
#include <vix/crypto/signature.hpp>
#include <vix/crypto/random.hpp>

#include <cstddef>
#include <cstdint>

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
#include <openssl/evp.h>
#endif

namespace vix::crypto
{

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)

  // Internal convention for Ed25519 private key material:
  // - Caller provides 64 bytes: seed(32) || public_key(32)
  // - We use seed(32) for EVP_PKEY_new_raw_private_key
  static Result<EVP_PKEY *> ed25519_load_private(std::span<const std::uint8_t> private_key) noexcept
  {
    if (private_key.size() != 64 && private_key.size() != 32)
      return Result<EVP_PKEY *>{ErrorCode::invalid_key, "ed25519 private key must be 64 or 32 bytes"};

    const std::uint8_t *seed = private_key.data();
    const std::size_t seed_len = 32;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed, seed_len);
    if (!pkey)
      return Result<EVP_PKEY *>{ErrorCode::provider_error, "EVP_PKEY_new_raw_private_key(ED25519) failed"};

    return Result<EVP_PKEY *>{pkey};
  }

  static Result<EVP_PKEY *> ed25519_load_public(std::span<const std::uint8_t> public_key) noexcept
  {
    if (public_key.size() != 32)
      return Result<EVP_PKEY *>{ErrorCode::invalid_key, "ed25519 public key must be 32 bytes"};

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
    if (!pkey)
      return Result<EVP_PKEY *>{ErrorCode::provider_error, "EVP_PKEY_new_raw_public_key(ED25519) failed"};

    return Result<EVP_PKEY *>{pkey};
  }

#endif

  Result<void> signature_keygen(
      SignatureAlg alg,
      std::span<std::uint8_t> out_public_key,
      std::span<std::uint8_t> out_private_key) noexcept
  {
    switch (alg)
    {
    case SignatureAlg::ed25519:
    {
#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
      if (out_public_key.size() != 32)
        return Result<void>{ErrorCode::invalid_argument, "ed25519 public key output must be 32 bytes"};
      if (out_private_key.size() != 64)
        return Result<void>{ErrorCode::invalid_argument, "ed25519 private key output must be 64 bytes"};

      // Generate a 32-byte seed
      auto seed_span = out_private_key.subspan(0, 32);
      auto r = random_bytes(seed_span);
      if (!r.ok())
        return Result<void>{r.error()};

      // Build an EVP private key from seed, then derive raw public key
      EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed_span.data(), seed_span.size());
      if (!pkey)
        return Result<void>{ErrorCode::provider_error, "EVP_PKEY_new_raw_private_key(ED25519) failed"};

      std::size_t pub_len = 32;
      if (EVP_PKEY_get_raw_public_key(pkey, out_public_key.data(), &pub_len) != 1 || pub_len != 32)
      {
        EVP_PKEY_free(pkey);
        return Result<void>{ErrorCode::provider_error, "EVP_PKEY_get_raw_public_key failed"};
      }

      // Store pub alongside seed in out_private_key: seed(32) || pub(32)
      auto priv_pub = out_private_key.subspan(32, 32);
      for (std::size_t i = 0; i < 32; ++i)
        priv_pub[i] = out_public_key[i];

      EVP_PKEY_free(pkey);
      return Result<void>{};
#else
      (void)out_public_key;
      (void)out_private_key;
      return Result<void>{ErrorCode::provider_unavailable, "No signature provider available"};
#endif
    }

    default:
      return Result<void>{ErrorCode::not_supported, "unsupported signature algorithm"};
    }
  }

  Result<void> sign(
      SignatureAlg alg,
      std::span<const std::uint8_t> private_key,
      std::span<const std::uint8_t> message,
      std::span<std::uint8_t> out_signature) noexcept
  {
    switch (alg)
    {
    case SignatureAlg::ed25519:
    {
#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
      if (out_signature.size() != 64)
        return Result<void>{ErrorCode::invalid_argument, "ed25519 signature output must be 64 bytes"};

      auto pk = ed25519_load_private(private_key);
      if (!pk.ok())
        return Result<void>{pk.error()};

      EVP_PKEY *pkey = pk.value();

      EVP_MD_CTX *ctx = EVP_MD_CTX_new();
      if (!ctx)
      {
        EVP_PKEY_free(pkey);
        return Result<void>{ErrorCode::provider_error, "EVP_MD_CTX_new failed"};
      }

      if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1)
      {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Result<void>{ErrorCode::provider_error, "EVP_DigestSignInit failed"};
      }

      std::size_t sig_len = out_signature.size();
      if (EVP_DigestSign(ctx,
                         out_signature.data(),
                         &sig_len,
                         message.empty() ? nullptr : message.data(),
                         message.size()) != 1)
      {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Result<void>{ErrorCode::sign_failed, "EVP_DigestSign failed"};
      }

      EVP_MD_CTX_free(ctx);
      EVP_PKEY_free(pkey);

      if (sig_len != 64)
        return Result<void>{ErrorCode::provider_error, "ed25519 signature produced unexpected size"};

      return Result<void>{};
#else
      (void)private_key;
      (void)message;
      (void)out_signature;
      return Result<void>{ErrorCode::provider_unavailable, "No signature provider available"};
#endif
    }

    default:
      return Result<void>{ErrorCode::not_supported, "unsupported signature algorithm"};
    }
  }

  Result<void> verify(
      SignatureAlg alg,
      std::span<const std::uint8_t> public_key,
      std::span<const std::uint8_t> message,
      std::span<const std::uint8_t> signature) noexcept
  {
    switch (alg)
    {
    case SignatureAlg::ed25519:
    {
#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
      if (signature.size() != 64)
        return Result<void>{ErrorCode::invalid_argument, "ed25519 signature must be 64 bytes"};

      auto pk = ed25519_load_public(public_key);
      if (!pk.ok())
        return Result<void>{pk.error()};

      EVP_PKEY *pkey = pk.value();

      EVP_MD_CTX *ctx = EVP_MD_CTX_new();
      if (!ctx)
      {
        EVP_PKEY_free(pkey);
        return Result<void>{ErrorCode::provider_error, "EVP_MD_CTX_new failed"};
      }

      if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) != 1)
      {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Result<void>{ErrorCode::provider_error, "EVP_DigestVerifyInit failed"};
      }

      const int rc = EVP_DigestVerify(
          ctx,
          signature.data(),
          signature.size(),
          message.empty() ? nullptr : message.data(),
          message.size());

      EVP_MD_CTX_free(ctx);
      EVP_PKEY_free(pkey);

      if (rc == 1)
        return Result<void>{};

      if (rc == 0)
        return Result<void>{ErrorCode::verify_failed, "ed25519 signature invalid"};

      return Result<void>{ErrorCode::provider_error, "EVP_DigestVerify failed"};
#else
      (void)public_key;
      (void)message;
      (void)signature;
      return Result<void>{ErrorCode::provider_unavailable, "No signature provider available"};
#endif
    }

    default:
      return Result<void>{ErrorCode::not_supported, "unsupported signature algorithm"};
    }
  }

} // namespace vix::crypto
