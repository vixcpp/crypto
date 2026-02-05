/**
 *
 *  @file kdf.hpp
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
#ifndef VIX_CRYPTO_KDF_HPP
#define VIX_CRYPTO_KDF_HPP

#include <cstddef>
#include <cstdint>
#include <span>

#include <vix/crypto/Result.hpp>
#include <vix/crypto/hash.hpp>
#include <vix/crypto/hmac.hpp>

namespace vix::crypto
{

  /**
   * @brief Supported key derivation functions.
   *
   * We start with HKDF-SHA256, which is widely used and well specified.
   */
  enum class KdfAlg : std::uint8_t
  {
    hkdf_sha256 = 1
  };

  /**
   * @brief Derive key material using a KDF.
   *
   * @param alg KDF algorithm
   * @param ikm Input keying material
   * @param salt Optional salt (can be empty)
   * @param info Optional context/application-specific info
   * @param out Output key material buffer (length defines output size)
   */
  Result<void> kdf(KdfAlg alg,
                   std::span<const std::uint8_t> ikm,
                   std::span<const std::uint8_t> salt,
                   std::span<const std::uint8_t> info,
                   std::span<std::uint8_t> out) noexcept;

  /**
   * @brief HKDF-SHA256 convenience wrapper.
   *
   * RFC 5869 compliant.
   */
  Result<void> hkdf_sha256(std::span<const std::uint8_t> ikm,
                           std::span<const std::uint8_t> salt,
                           std::span<const std::uint8_t> info,
                           std::span<std::uint8_t> out) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_KDF_HPP
