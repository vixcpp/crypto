/**
 *
 *  @file hash.hpp
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
#ifndef VIX_CRYPTO_HASH_HPP
#define VIX_CRYPTO_HASH_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <vix/crypto/Result.hpp>

/**
 * @file hash.hpp
 * @brief One-shot cryptographic hashing primitives.
 *
 * @details
 * This header defines the public hashing API for the `vix::crypto` module.
 * The interface is explicit, allocation-free, and designed for deterministic
 * low-level usage.
 *
 * All functions operate in a one-shot fashion: the entire input is provided
 * at once and the caller supplies the output buffer.
 *
 * @note Streaming / incremental hashing is intentionally out of scope for
 * this API.
 */

namespace vix::crypto
{

  /**
   * @brief Supported hash algorithms.
   *
   * The initial stable baseline is SHA-256, which is widely supported and
   * suitable for identifiers, integrity checks, and cryptographic protocols.
   */
  enum class HashAlg : std::uint8_t
  {
    /// SHA-256 (32-byte output).
    sha256 = 1
  };

  /**
   * @brief Get the output size in bytes for a hash algorithm.
   *
   * @param alg Hash algorithm.
   * @return Output size in bytes, or 0 if @p alg is unknown.
   */
  constexpr std::size_t hash_size(HashAlg alg) noexcept
  {
    switch (alg)
    {
    case HashAlg::sha256:
      return 32;
    default:
      return 0;
    }
  }

  /**
   * @brief Compute a cryptographic hash (one-shot).
   *
   * Computes `hash(data)` and writes the result into @p out.
   *
   * @param alg Hash algorithm.
   * @param data Input bytes.
   * @param out Output buffer (must be exactly `hash_size(alg)` bytes).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> hash(
      HashAlg alg,
      std::span<const std::uint8_t> data,
      std::span<std::uint8_t> out) noexcept;

  /**
   * @brief Convenience one-shot SHA-256.
   *
   * @param data Input bytes.
   * @param out Output buffer (must be exactly 32 bytes).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> sha256(
      std::span<const std::uint8_t> data,
      std::span<std::uint8_t> out) noexcept;

  /**
   * @brief Hash a string using SHA-256.
   *
   * The string is interpreted as a raw byte sequence. No encoding conversion
   * is performed.
   *
   * @param data Input string view.
   * @param out Output buffer (must be exactly 32 bytes).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> sha256(
      std::string_view data,
      std::span<std::uint8_t> out) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_HASH_HPP
