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

namespace vix::crypto
{

  /**
   * @brief Supported hash algorithms.
   *
   * We start with sha256 as the stable baseline used across systems.
   */
  enum class HashAlg : std::uint8_t
  {
    sha256 = 1
  };

  /**
   * @brief Get the output size (in bytes) for a hash algorithm.
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
   * @brief One-shot hashing API.
   *
   * Computes hash(data) into out.
   *
   * @param alg Hash algorithm
   * @param data Input bytes
   * @param out Output buffer (must be exactly hash_size(alg))
   */
  Result<void> hash(HashAlg alg,
                    std::span<const std::uint8_t> data,
                    std::span<std::uint8_t> out) noexcept;

  /**
   * @brief Convenience one-shot SHA-256.
   *
   * @param data Input bytes
   * @param out Output buffer (must be 32 bytes)
   */
  Result<void> sha256(std::span<const std::uint8_t> data,
                      std::span<std::uint8_t> out) noexcept;

  /**
   * @brief Hash a string_view (bytes are interpreted as-is, no encoding conversion).
   */
  Result<void> sha256(std::string_view data,
                      std::span<std::uint8_t> out) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_HASH_HPP
