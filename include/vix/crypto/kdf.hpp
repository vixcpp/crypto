/**
 *
 *  @file kdf.hpp
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
#ifndef VIX_CRYPTO_KDF_HPP
#define VIX_CRYPTO_KDF_HPP

#include <cstddef>
#include <cstdint>
#include <span>

#include <vix/crypto/Result.hpp>

/**
 * @file kdf.hpp
 * @brief Key derivation functions (KDF).
 *
 * @details
 * This header defines the public key derivation API for `vix::crypto`.
 * KDFs are used to derive one or more cryptographically strong keys from
 * input keying material.
 *
 * The API is explicit and allocation-free:
 * - all inputs are provided as byte spans
 * - the caller controls the output length via the output buffer
 * - no implicit randomness or global state
 */

namespace vix::crypto
{
  /**
   * @brief Supported key derivation functions.
   */
  enum class KdfAlg : std::uint8_t
  {
    /// HKDF using SHA-256 (RFC 5869).
    hkdf_sha256 = 1
  };

  /**
   * @brief Derive key material using a key derivation function.
   *
   * @param alg KDF algorithm.
   * @param ikm Input keying material (must not be empty for HKDF).
   * @param salt Optional salt (may be empty).
   * @param info Optional context / application-specific info (may be empty).
   * @param out Output key material buffer (its length defines the derived key size).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> kdf(
      KdfAlg alg,
      std::span<const std::uint8_t> ikm,
      std::span<const std::uint8_t> salt,
      std::span<const std::uint8_t> info,
      std::span<std::uint8_t> out) noexcept;

  /**
   * @brief HKDF-SHA256 convenience wrapper.
   *
   * Derives key material using HKDF as specified in RFC 5869 with SHA-256.
   *
   * @param ikm Input keying material (must not be empty).
   * @param salt Optional salt (may be empty).
   * @param info Optional context / application-specific info (may be empty).
   * @param out Output key material buffer (its length defines the derived key size).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> hkdf_sha256(
      std::span<const std::uint8_t> ikm,
      std::span<const std::uint8_t> salt,
      std::span<const std::uint8_t> info,
      std::span<std::uint8_t> out) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_KDF_HPP
