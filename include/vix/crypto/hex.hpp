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

namespace vix::crypto
{
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

#endif
