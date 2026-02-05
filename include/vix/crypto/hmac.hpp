/**
 *
 *  @file hmac.hpp
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
#ifndef VIX_CRYPTO_HMAC_HPP
#define VIX_CRYPTO_HMAC_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <vix/crypto/Result.hpp>
#include <vix/crypto/hash.hpp>

/**
 * @file hmac.hpp
 * @brief One-shot HMAC primitives.
 *
 * @details
 * This header defines the public HMAC (Hash-based Message Authentication Code)
 * API for the `vix::crypto` module.
 *
 * The design mirrors the hashing API:
 * - explicit algorithm selection
 * - no allocation
 * - caller-provided output buffers
 * - one-shot usage
 *
 * HMAC provides message integrity and authenticity using a secret key.
 */

namespace vix::crypto
{

  /**
   * @brief Supported HMAC algorithms.
   *
   * For now, this mirrors @ref HashAlg. Keeping a distinct enum preserves
   * API clarity and allows future divergence.
   */
  enum class HmacAlg : std::uint8_t
  {
    /// HMAC-SHA256 (32-byte output).
    sha256 = 1
  };

  /**
   * @brief Get the output size in bytes for an HMAC algorithm.
   *
   * @param alg HMAC algorithm.
   * @return Output size in bytes, or 0 if @p alg is unknown.
   */
  constexpr std::size_t hmac_size(HmacAlg alg) noexcept
  {
    switch (alg)
    {
    case HmacAlg::sha256:
      return 32;
    default:
      return 0;
    }
  }

  /**
   * @brief Compute an HMAC (one-shot).
   *
   * Computes `HMAC(key, data)` and writes the result into @p out.
   *
   * @param alg HMAC algorithm.
   * @param key Secret key bytes.
   * @param data Input bytes.
   * @param out Output buffer (must be exactly `hmac_size(alg)` bytes).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> hmac(
      HmacAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> data,
      std::span<std::uint8_t> out) noexcept;

  /**
   * @brief Convenience one-shot HMAC-SHA256.
   *
   * @param key Secret key bytes.
   * @param data Input bytes.
   * @param out Output buffer (must be exactly 32 bytes).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> hmac_sha256(
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> data,
      std::span<std::uint8_t> out) noexcept;

  /**
   * @brief HMAC-SHA256 with string input.
   *
   * The string is interpreted as a raw byte sequence. No encoding conversion
   * is performed.
   *
   * @param key Secret key bytes.
   * @param data Input string view.
   * @param out Output buffer (must be exactly 32 bytes).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> hmac_sha256(
      std::span<const std::uint8_t> key,
      std::string_view data,
      std::span<std::uint8_t> out) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_HMAC_HPP
