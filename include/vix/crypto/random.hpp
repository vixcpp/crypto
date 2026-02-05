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
   * @param out Buffer to fill with random bytes
   * @return Result<void> Success or explicit error
   */
  Result<void> random_bytes(std::span<std::uint8_t> out) noexcept;

  /**
   * @brief Generate a uniformly random unsigned integer.
   *
   * The value is generated using rejection sampling to avoid modulo bias.
   *
   * @param max Exclusive upper bound (must be > 0)
   * @return Result<std::uint64_t> Random value in range [0, max)
   */
  Result<std::uint64_t> random_uint(std::uint64_t max) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_RANDOM_HPP
