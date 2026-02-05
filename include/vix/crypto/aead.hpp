/**
 *
 *  @file aead.hpp
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
#ifndef VIX_CRYPTO_AEAD_HPP
#define VIX_CRYPTO_AEAD_HPP

#include <cstddef>
#include <cstdint>
#include <span>

#include <vix/crypto/Result.hpp>

/**
 * @file aead.hpp
 * @brief AEAD primitives and algorithm parameters.
 *
 * @details
 * This header defines the AEAD algorithm enum and the low-level encrypt/decrypt
 * APIs used by higher-level helpers (see `aead_easy.hpp`).
 *
 * The functions in this file operate on caller-provided buffers:
 * - ciphertext size must equal plaintext size
 * - plaintext size must equal ciphertext size
 * - tag size must match `aead_tag_size(alg)`
 *
 * @note AEAD requires unique nonces per key. Reusing a nonce with the same key
 * breaks security.
 */

namespace vix::crypto
{

  /**
   * @brief Supported AEAD algorithms.
   *
   * AEAD (Authenticated Encryption with Associated Data) provides confidentiality
   * and integrity in a single primitive. The AAD is authenticated but not encrypted.
   */
  enum class AeadAlg : std::uint8_t
  {
    /// AES-256-GCM (32-byte key, 12-byte nonce, 16-byte tag).
    aes_256_gcm = 1
  };

  /**
   * @brief Get the key size in bytes for an AEAD algorithm.
   *
   * @param alg AEAD algorithm.
   * @return Key size in bytes, or 0 if @p alg is unknown.
   */
  constexpr std::size_t aead_key_size(AeadAlg alg) noexcept
  {
    switch (alg)
    {
    case AeadAlg::aes_256_gcm:
      return 32;
    default:
      return 0;
    }
  }

  /**
   * @brief Get the nonce size in bytes for an AEAD algorithm.
   *
   * @param alg AEAD algorithm.
   * @return Nonce size in bytes, or 0 if @p alg is unknown.
   */
  constexpr std::size_t aead_nonce_size(AeadAlg alg) noexcept
  {
    switch (alg)
    {
    case AeadAlg::aes_256_gcm:
      return 12;
    default:
      return 0;
    }
  }

  /**
   * @brief Get the authentication tag size in bytes for an AEAD algorithm.
   *
   * @param alg AEAD algorithm.
   * @return Tag size in bytes, or 0 if @p alg is unknown.
   */
  constexpr std::size_t aead_tag_size(AeadAlg alg) noexcept
  {
    switch (alg)
    {
    case AeadAlg::aes_256_gcm:
      return 16;
    default:
      return 0;
    }
  }

  /**
   * @brief Encrypt and authenticate data using AEAD.
   *
   * @param alg AEAD algorithm.
   * @param key Secret key (size must match `aead_key_size(alg)`).
   * @param nonce Unique nonce (size must match `aead_nonce_size(alg)`).
   * @param aad Additional authenticated data (AAD), may be empty.
   * @param plaintext Input plaintext.
   * @param ciphertext Output ciphertext (must be the same size as @p plaintext).
   * @param tag Output authentication tag (size must match `aead_tag_size(alg)`).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> aead_encrypt(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      std::span<const std::uint8_t> aad,
      std::span<const std::uint8_t> plaintext,
      std::span<std::uint8_t> ciphertext,
      std::span<std::uint8_t> tag) noexcept;

  /**
   * @brief Decrypt and authenticate data using AEAD.
   *
   * On success, writes plaintext into the output buffer. If authentication fails,
   * returns an error and the plaintext output must be treated as invalid.
   *
   * @param alg AEAD algorithm.
   * @param key Secret key (size must match `aead_key_size(alg)`).
   * @param nonce Nonce used during encryption (size must match `aead_nonce_size(alg)`).
   * @param aad Additional authenticated data (AAD) that must match the one used for encryption.
   * @param ciphertext Input ciphertext.
   * @param tag Authentication tag (size must match `aead_tag_size(alg)`).
   * @param plaintext Output plaintext (must be the same size as @p ciphertext).
   *
   * @return `Result<void>` ok on success, or an error on failure (including auth failure).
   */
  Result<void> aead_decrypt(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      std::span<const std::uint8_t> aad,
      std::span<const std::uint8_t> ciphertext,
      std::span<const std::uint8_t> tag,
      std::span<std::uint8_t> plaintext) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_AEAD_HPP
