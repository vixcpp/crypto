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

namespace vix::crypto
{

  /**
   * @brief Supported HMAC algorithms.
   *
   * For now, this mirrors HashAlg. This keeps the API explicit
   * and allows future divergence if needed.
   */
  enum class HmacAlg : std::uint8_t
  {
    sha256 = 1
  };

  /**
   * @brief Get output size (in bytes) for an HMAC algorithm.
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
   * @brief One-shot HMAC.
   *
   * Computes HMAC(key, data) into out.
   *
   * @param alg HMAC algorithm
   * @param key Secret key bytes
   * @param data Input bytes
   * @param out Output buffer (must be exactly hmac_size(alg))
   */
  Result<void> hmac(HmacAlg alg,
                    std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t> data,
                    std::span<std::uint8_t> out) noexcept;

  /**
   * @brief Convenience HMAC-SHA256.
   */
  Result<void> hmac_sha256(std::span<const std::uint8_t> key,
                           std::span<const std::uint8_t> data,
                           std::span<std::uint8_t> out) noexcept;

  /**
   * @brief HMAC-SHA256 with string_view input.
   *
   * Data bytes are interpreted as-is (no encoding conversion).
   */
  Result<void> hmac_sha256(std::span<const std::uint8_t> key,
                           std::string_view data,
                           std::span<std::uint8_t> out) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_HMAC_HPP
