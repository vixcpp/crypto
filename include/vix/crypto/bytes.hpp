/**
 *
 *  @file bytes.hpp
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
#ifndef VIX_CRYPTO_BYTES_HPP
#define VIX_CRYPTO_BYTES_HPP

#include <cstdint>
#include <span>
#include <string_view>

/**
 * @file bytes.hpp
 * @brief Lightweight helpers for viewing strings as byte spans.
 *
 * @details
 * This header provides a minimal utility to reinterpret textual data
 * (`std::string_view`) as a read-only byte sequence (`std::span<const uint8_t>`).
 *
 * It is primarily intended for cryptographic APIs that operate on raw bytes
 * while still allowing ergonomic use with string-based inputs.
 *
 * No allocation or copy is performed. The returned span directly references
 * the underlying string memory.
 *
 * @warning The lifetime of the returned span is tied to the lifetime of the
 * input `std::string_view`. The data must remain valid for the duration of use.
 */

namespace vix::crypto
{
  /**
   * @brief View a string as a span of bytes.
   *
   * @param s Input string view.
   * @return Read-only span of bytes pointing to the string data.
   *
   * @note This function performs a `reinterpret_cast` and does not validate
   * encoding. It is safe for binary-safe operations such as hashing,
   * encryption, or authentication.
   */
  inline std::span<const std::uint8_t> bytes(std::string_view s) noexcept
  {
    return {
        reinterpret_cast<const std::uint8_t *>(s.data()),
        s.size()};
  }
} // namespace vix::crypto

#endif // VIX_CRYPTO_BYTES_HPP
