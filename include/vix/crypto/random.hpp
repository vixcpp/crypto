/**
 *
 *  @file random.hpp
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
#ifndef VIX_CRYPTO_RANDOM_HPP
#define VIX_CRYPTO_RANDOM_HPP

#include <cstddef>
#include <cstdint>
#include <span>

#include <vix/crypto/Result.hpp>

/**
 * @file random.hpp
 * @brief Cryptographically secure random number generation.
 *
 * @details
 * This header defines the root entropy API for the `vix::crypto` module.
 * All cryptographic operations that require randomness must ultimately
 * rely on these functions.
 *
 * Design guarantees:
 * - backed by a cryptographically secure RNG
 * - no user-provided seeding
 * - explicit failure if secure entropy is unavailable
 */

namespace vix::crypto
{

  /**
   * @brief Fill a buffer with cryptographically secure random bytes.
   *
   * This function is the root of trust for the crypto module.
   * It must be backed by a secure system or provider RNG.
   *
   * Rules:
   * - Never deterministic
   * - Never seeded manually by the caller
   * - Fails explicitly if secure entropy is unavailable
   *
   * @param out Buffer to fill with random bytes.
   * @return `Result<void>` ok on success, or an explicit error on failure.
   */
  Result<void> random_bytes(std::span<std::uint8_t> out) noexcept;

  /**
   * @brief Generate a uniformly distributed random unsigned integer.
   *
   * The value is generated using rejection sampling to avoid modulo bias.
   *
   * @param max Exclusive upper bound (must be > 0).
   * @return `Result<std::uint64_t>` containing a random value in the range
   * `[0, max)` on success, or an error on failure.
   */
  Result<std::uint64_t> random_uint(std::uint64_t max) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_RANDOM_HPP
