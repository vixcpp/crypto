/**
 *
 *  @file hex.hpp
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
#ifndef VIX_CRYPTO_HEX_HPP
#define VIX_CRYPTO_HEX_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

/**
 * @file hex.hpp
 * @brief Hexadecimal encoding helpers.
 *
 * @details
 * This header provides a small, allocation-friendly utility for converting
 * raw bytes into a lowercase hexadecimal string representation.
 *
 * The API is intentionally minimal and deterministic:
 * - no locale dependence
 * - no dynamic formatting
 * - constant lookup table
 */

namespace vix::crypto
{
  /**
   * @brief Encode bytes as a lowercase hexadecimal string.
   *
   * Each input byte is expanded into two hexadecimal characters using
   * the range `0-9a-f`.
   *
   * @param bytes Input byte sequence.
   * @return Lowercase hexadecimal string representation.
   */
  inline std::string hex_lower(std::span<const std::uint8_t> bytes)
  {
    static constexpr char lut[] = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2);

    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
      const std::uint8_t b = bytes[i];
      out[2 * i + 0] = lut[(b >> 4) & 0x0F];
      out[2 * i + 1] = lut[b & 0x0F];
    }
    return out;
  }
} // namespace vix::crypto

#endif // VIX_CRYPTO_HEX_HPP
