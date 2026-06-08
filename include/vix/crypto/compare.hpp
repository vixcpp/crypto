/**
 *
 *  @file compare.hpp
 *  @author Gaspard Kirira
 *
 *  Copyright 2026, Gaspard Kirira.
 *  All rights reserved.
 *  https://github.com/vixcpp/vix
 *
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
 *
 *  Vix.cpp
 *
 */

#ifndef VIX_CRYPTO_COMPARE_HPP
#define VIX_CRYPTO_COMPARE_HPP

#include <cstdint>
#include <span>

/**
 * @file compare.hpp
 * @brief Constant-time comparison helpers for cryptographic data.
 *
 * @details
 * This header exposes small comparison primitives for security-sensitive
 * code.
 *
 * Normal comparisons such as `a == b` may return as soon as a difference is
 * found. That behavior can leak information through timing differences when
 * comparing hashes, MACs, tokens, or derived secrets.
 *
 * The helpers in this file process all bytes before returning, making them
 * suitable for comparing cryptographic values.
 */

namespace vix::crypto
{
  /**
   * @brief Compare two byte sequences in constant time.
   *
   * This function compares all bytes before returning. It is intended for
   * security-sensitive comparisons such as password hashes, HMAC values,
   * authentication tags, and token digests.
   *
   * @param a First byte sequence.
   * @param b Second byte sequence.
   *
   * @return true if both sequences have the same size and identical content.
   *
   * @note If the sizes differ, the function still performs a deterministic
   * amount of work based on the largest input size before returning false.
   */
  [[nodiscard]] bool constant_time_equal(
      std::span<const std::uint8_t> a,
      std::span<const std::uint8_t> b) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_COMPARE_HPP
