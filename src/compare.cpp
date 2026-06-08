/**
 *
 *  @file compare.cpp
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

#include <vix/crypto/compare.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace vix::crypto
{
  bool constant_time_equal(
      std::span<const std::uint8_t> a,
      std::span<const std::uint8_t> b) noexcept
  {
    const std::size_t max_size = std::max(a.size(), b.size());

    std::uint8_t diff = static_cast<std::uint8_t>(a.size() ^ b.size());

    for (std::size_t i = 0; i < max_size; ++i)
    {
      const std::uint8_t av = i < a.size() ? a[i] : 0;
      const std::uint8_t bv = i < b.size() ? b[i] : 0;

      diff = static_cast<std::uint8_t>(diff | (av ^ bv));
    }

    return diff == 0;
  }
} // namespace vix::crypto
