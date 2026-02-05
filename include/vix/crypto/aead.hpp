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

namespace vix::crypto
{

  /**
   * @brief Supported AEAD algorithms.
   *
   * AEAD provides confidentiality + integrity in one primitive.
   */
  enum class AeadAlg : std::uint8_t
  {
    aes_256_gcm = 1
  };

  /**
   * @brief Get key size (in bytes) for an AEAD algorithm.
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
   * @brief Get nonce size (in bytes) for an AEAD algorithm.
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
   * @brief Get authentication tag size (in bytes) for an AEAD algorithm.
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
   * @param alg AEAD algorithm
   * @param key Secret key (size must match aead_key_size)
   * @param nonce Unique nonce (size must match aead_nonce_size)
   * @param aad Additional authenticated data (can be empty)
   * @param plaintext Input plaintext
   * @param ciphertext Output ciphertext (same size as plaintext)
   * @param tag Output authentication tag (size must match aead_tag_size)
   */
  Result<void> aead_encrypt(AeadAlg alg,
                            std::span<const std::uint8_t> key,
                            std::span<const std::uint8_t> nonce,
                            std::span<const std::uint8_t> aad,
                            std::span<const std::uint8_t> plaintext,
                            std::span<std::uint8_t> ciphertext,
                            std::span<std::uint8_t> tag) noexcept;

  /**
   * @brief Decrypt and authenticate data using AEAD.
   *
   * @param alg AEAD algorithm
   * @param key Secret key
   * @param nonce Nonce used during encryption
   * @param aad Additional authenticated data
   * @param ciphertext Input ciphertext
   * @param tag Authentication tag
   * @param plaintext Output plaintext (same size as ciphertext)
   */
  Result<void> aead_decrypt(AeadAlg alg,
                            std::span<const std::uint8_t> key,
                            std::span<const std::uint8_t> nonce,
                            std::span<const std::uint8_t> aad,
                            std::span<const std::uint8_t> ciphertext,
                            std::span<const std::uint8_t> tag,
                            std::span<std::uint8_t> plaintext) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_AEAD_HPP
