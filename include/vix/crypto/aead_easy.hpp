/**
 *
 *  @file aead_easy.hpp
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
#ifndef VIX_CRYPTO_AEAD_EASY_HPP
#define VIX_CRYPTO_AEAD_EASY_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <vix/crypto/Result.hpp>
#include <vix/crypto/aead.hpp>
#include <vix/crypto/bytes.hpp>

/**
 * @file aead_easy.hpp
 * @brief Small convenience wrappers for AEAD seal/open.
 *
 * @details
 * This header provides a minimal, allocation-friendly API on top of the lower-level
 * AEAD primitives in @ref vix::crypto::aead_encrypt and @ref vix::crypto::aead_decrypt.
 * It handles ciphertext sizing and returns typed results for common use cases.
 *
 * - `seal(...)` produces ciphertext + authentication tag.
 * - `open(...)` verifies the tag and returns plaintext bytes.
 * - `open_string(...)` is a helper that decodes plaintext bytes into a `std::string`.
 *
 * @note This API expects the caller to supply a correct key and nonce size for the chosen
 * algorithm (`AeadAlg`). It does not derive keys, does not generate nonces, and does not
 * manage replay protection.
 */

namespace vix::crypto::aead
{
  /**
   * @brief Output container returned by @ref seal.
   *
   * Holds the encrypted payload (`ciphertext`) and the authentication tag (`tag`).
   * The tag is always 16 bytes as used by the underlying AEAD implementation.
   */
  struct Sealed final
  {
    std::vector<std::uint8_t> ciphertext{};
    std::array<std::uint8_t, 16> tag{};
  };

  /**
   * @brief Encrypt and authenticate a plaintext buffer.
   *
   * @param alg AEAD algorithm identifier.
   * @param key Secret key bytes (size must match @p alg requirements).
   * @param nonce Nonce bytes (size must match @p alg requirements).
   * @param plaintext Input plaintext bytes.
   * @param aad Optional additional authenticated data (AAD), not encrypted.
   *
   * @return `Result<Sealed>` containing ciphertext + tag on success, or an error.
   */
  inline Result<Sealed> seal(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      std::span<const std::uint8_t> plaintext,
      std::span<const std::uint8_t> aad = {}) noexcept
  {
    Sealed out{};
    out.ciphertext.resize(plaintext.size());

    auto r = aead_encrypt(alg, key, nonce, aad, plaintext, out.ciphertext, out.tag);
    if (!r.ok())
      return Result<Sealed>{r.error()};

    return Result<Sealed>{std::move(out)};
  }

  /**
   * @brief Encrypt and authenticate a string payload.
   *
   * Convenience overload that converts `plaintext` and `aad` to byte spans.
   *
   * @param alg AEAD algorithm identifier.
   * @param key Secret key bytes (size must match @p alg requirements).
   * @param nonce Nonce bytes (size must match @p alg requirements).
   * @param plaintext Input plaintext string.
   * @param aad Optional additional authenticated data (AAD).
   *
   * @return `Result<Sealed>` containing ciphertext + tag on success, or an error.
   */
  inline Result<Sealed> seal(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      std::string_view plaintext,
      std::string_view aad = {}) noexcept
  {
    return seal(alg, key, nonce, vix::crypto::bytes(plaintext), vix::crypto::bytes(aad));
  }

  /**
   * @brief Verify and decrypt a sealed payload into raw bytes.
   *
   * @param alg AEAD algorithm identifier.
   * @param key Secret key bytes (size must match @p alg requirements).
   * @param nonce Nonce bytes (size must match @p alg requirements).
   * @param sealed Ciphertext + tag produced by @ref seal.
   * @param aad Optional additional authenticated data (AAD) that must match the one used for sealing.
   *
   * @return `Result<std::vector<std::uint8_t>>` containing plaintext bytes on success, or an error.
   */
  inline Result<std::vector<std::uint8_t>> open(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      const Sealed &sealed,
      std::span<const std::uint8_t> aad = {}) noexcept
  {
    std::vector<std::uint8_t> out;
    out.resize(sealed.ciphertext.size());

    auto r = aead_decrypt(alg, key, nonce, aad, sealed.ciphertext, sealed.tag, out);
    if (!r.ok())
      return Result<std::vector<std::uint8_t>>{r.error()};

    return Result<std::vector<std::uint8_t>>{std::move(out)};
  }

  /**
   * @brief Verify and decrypt a sealed payload using string AAD.
   *
   * @param alg AEAD algorithm identifier.
   * @param key Secret key bytes (size must match @p alg requirements).
   * @param nonce Nonce bytes (size must match @p alg requirements).
   * @param sealed Ciphertext + tag produced by @ref seal.
   * @param aad Additional authenticated data (AAD) that must match the one used for sealing.
   *
   * @return Plaintext bytes on success, or an error.
   */
  inline Result<std::vector<std::uint8_t>> open(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      const Sealed &sealed,
      std::string_view aad) noexcept
  {
    return open(alg, key, nonce, sealed, vix::crypto::bytes(aad));
  }

  /**
   * @brief Verify and decrypt a sealed payload into a `std::string`.
   *
   * @param alg AEAD algorithm identifier.
   * @param key Secret key bytes (size must match @p alg requirements).
   * @param nonce Nonce bytes (size must match @p alg requirements).
   * @param sealed Ciphertext + tag produced by @ref seal.
   * @param aad Optional additional authenticated data (AAD) that must match the one used for sealing.
   *
   * @return `Result<std::string>` containing plaintext as a string on success, or an error.
   *
   * @note The resulting string is constructed from raw bytes. It is suitable for UTF-8 or
   * any binary-safe string usage, but no encoding validation is performed.
   */
  inline Result<std::string> open_string(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      const Sealed &sealed,
      std::span<const std::uint8_t> aad = {}) noexcept
  {
    auto r = open(alg, key, nonce, sealed, aad);
    if (!r.ok())
      return Result<std::string>{r.error()};

    const auto &bytes_out = r.value();
    return Result<std::string>{std::string(bytes_out.begin(), bytes_out.end())};
  }

  /**
   * @brief Verify and decrypt a sealed payload into a `std::string` using string AAD.
   *
   * @param alg AEAD algorithm identifier.
   * @param key Secret key bytes (size must match @p alg requirements).
   * @param nonce Nonce bytes (size must match @p alg requirements).
   * @param sealed Ciphertext + tag produced by @ref seal.
   * @param aad Additional authenticated data (AAD) that must match the one used for sealing.
   *
   * @return Plaintext string on success, or an error.
   */
  inline Result<std::string> open_string(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      const Sealed &sealed,
      std::string_view aad) noexcept
  {
    return open_string(alg, key, nonce, sealed, vix::crypto::bytes(aad));
  }

} // namespace vix::crypto::aead

#endif // VIX_CRYPTO_AEAD_EASY_HPP
