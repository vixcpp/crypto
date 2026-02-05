/**
 *
 *  @file aead.cpp
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
#include <vix/crypto/aead.hpp>

#include <cstring>

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
#include <openssl/evp.h>
#endif

namespace vix::crypto
{

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)

  static Result<void> aes_256_gcm_encrypt(
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      std::span<const std::uint8_t> aad,
      std::span<const std::uint8_t> plaintext,
      std::span<std::uint8_t> ciphertext,
      std::span<std::uint8_t> tag) noexcept
  {
    if (key.size() != 32)
      return Result<void>{ErrorCode::invalid_argument, "aes-256-gcm key must be 32 bytes"};
    if (nonce.size() != 12)
      return Result<void>{ErrorCode::invalid_argument, "aes-256-gcm nonce must be 12 bytes"};
    if (tag.size() != 16)
      return Result<void>{ErrorCode::invalid_argument, "aes-256-gcm tag must be 16 bytes"};
    if (ciphertext.size() != plaintext.size())
      return Result<void>{ErrorCode::invalid_argument, "ciphertext size must match plaintext size"};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
      return Result<void>{ErrorCode::provider_error, "EVP_CIPHER_CTX_new failed"};

    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    if (!cipher)
    {
      EVP_CIPHER_CTX_free(ctx);
      return Result<void>{ErrorCode::provider_error, "EVP_aes_256_gcm not available"};
    }

    int ok = 1;

    ok = ok && (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                    static_cast<int>(nonce.size()), nullptr) == 1);
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1);

    if (!ok)
    {
      EVP_CIPHER_CTX_free(ctx);
      return Result<void>{ErrorCode::provider_error, "EVP_EncryptInit_ex failed"};
    }

    int out_len = 0;

    if (!aad.empty())
    {
      if (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1)
      {
        EVP_CIPHER_CTX_free(ctx);
        return Result<void>{ErrorCode::provider_error, "EVP_EncryptUpdate(AAD) failed"};
      }
    }

    if (!plaintext.empty())
    {
      if (EVP_EncryptUpdate(
              ctx,
              ciphertext.data(),
              &out_len,
              plaintext.data(),
              static_cast<int>(plaintext.size())) != 1)
      {
        EVP_CIPHER_CTX_free(ctx);
        return Result<void>{ErrorCode::encrypt_failed, "EVP_EncryptUpdate failed"};
      }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1)
    {
      EVP_CIPHER_CTX_free(ctx);
      return Result<void>{ErrorCode::encrypt_failed, "EVP_EncryptFinal_ex failed"};
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
    {
      EVP_CIPHER_CTX_free(ctx);
      return Result<void>{ErrorCode::provider_error, "EVP_CTRL_GCM_GET_TAG failed"};
    }

    EVP_CIPHER_CTX_free(ctx);
    return Result<void>{};
  }

  static Result<void> aes_256_gcm_decrypt(
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      std::span<const std::uint8_t> aad,
      std::span<const std::uint8_t> ciphertext,
      std::span<const std::uint8_t> tag,
      std::span<std::uint8_t> plaintext) noexcept
  {
    if (key.size() != 32)
      return Result<void>{ErrorCode::invalid_argument, "aes-256-gcm key must be 32 bytes"};
    if (nonce.size() != 12)
      return Result<void>{ErrorCode::invalid_argument, "aes-256-gcm nonce must be 12 bytes"};
    if (tag.size() != 16)
      return Result<void>{ErrorCode::invalid_argument, "aes-256-gcm tag must be 16 bytes"};
    if (plaintext.size() != ciphertext.size())
      return Result<void>{ErrorCode::invalid_argument, "plaintext size must match ciphertext size"};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
      return Result<void>{ErrorCode::provider_error, "EVP_CIPHER_CTX_new failed"};

    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    if (!cipher)
    {
      EVP_CIPHER_CTX_free(ctx);
      return Result<void>{ErrorCode::provider_error, "EVP_aes_256_gcm not available"};
    }

    int ok = 1;

    ok = ok && (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                    static_cast<int>(nonce.size()), nullptr) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1);

    if (!ok)
    {
      EVP_CIPHER_CTX_free(ctx);
      return Result<void>{ErrorCode::provider_error, "EVP_DecryptInit_ex failed"};
    }

    int out_len = 0;

    if (!aad.empty())
    {
      if (EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1)
      {
        EVP_CIPHER_CTX_free(ctx);
        return Result<void>{ErrorCode::provider_error, "EVP_DecryptUpdate(AAD) failed"};
      }
    }

    if (!ciphertext.empty())
    {
      if (EVP_DecryptUpdate(
              ctx,
              plaintext.data(),
              &out_len,
              ciphertext.data(),
              static_cast<int>(ciphertext.size())) != 1)
      {
        EVP_CIPHER_CTX_free(ctx);
        return Result<void>{ErrorCode::decrypt_failed, "EVP_DecryptUpdate failed"};
      }
    }

    // Set expected tag BEFORE final
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<std::uint8_t *>(tag.data())) != 1)
    {
      EVP_CIPHER_CTX_free(ctx);
      return Result<void>{ErrorCode::provider_error, "EVP_CTRL_GCM_SET_TAG failed"};
    }

    int final_len = 0;
    const int rc = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);

    EVP_CIPHER_CTX_free(ctx);

    if (rc != 1)
      return Result<void>{ErrorCode::authentication_failed, "aes-256-gcm tag verification failed"};

    return Result<void>{};
  }

#endif // OpenSSL

  Result<void> aead_encrypt(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      std::span<const std::uint8_t> aad,
      std::span<const std::uint8_t> plaintext,
      std::span<std::uint8_t> ciphertext,
      std::span<std::uint8_t> tag) noexcept
  {
    switch (alg)
    {
    case AeadAlg::aes_256_gcm:
#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
      return aes_256_gcm_encrypt(key, nonce, aad, plaintext, ciphertext, tag);
#else
      (void)key;
      (void)nonce;
      (void)aad;
      (void)plaintext;
      (void)ciphertext;
      (void)tag;
      return Result<void>{ErrorCode::provider_unavailable, "No AEAD provider available"};
#endif
    default:
      return Result<void>{ErrorCode::not_supported, "unsupported aead algorithm"};
    }
  }

  Result<void> aead_decrypt(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      std::span<const std::uint8_t> aad,
      std::span<const std::uint8_t> ciphertext,
      std::span<const std::uint8_t> tag,
      std::span<std::uint8_t> plaintext) noexcept
  {
    switch (alg)
    {
    case AeadAlg::aes_256_gcm:
#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
      return aes_256_gcm_decrypt(key, nonce, aad, ciphertext, tag, plaintext);
#else
      (void)key;
      (void)nonce;
      (void)aad;
      (void)ciphertext;
      (void)tag;
      (void)plaintext;
      return Result<void>{ErrorCode::provider_unavailable, "No AEAD provider available"};
#endif
    default:
      return Result<void>{ErrorCode::not_supported, "unsupported aead algorithm"};
    }
  }

} // namespace vix::crypto
