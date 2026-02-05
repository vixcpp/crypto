/**
 *
 *  @file signature.hpp
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
#ifndef VIX_CRYPTO_SIGNATURE_HPP
#define VIX_CRYPTO_SIGNATURE_HPP

#include <cstddef>
#include <cstdint>
#include <span>

#include <vix/crypto/Result.hpp>

namespace vix::crypto
{

  /**
   * @brief Supported signature algorithms.
   *
   * Start with Ed25519:
   * - modern
   * - fast
   * - deterministic
   * - widely deployed
   */
  enum class SignatureAlg : std::uint8_t
  {
    ed25519 = 1
  };

  /**
   * @brief Size of public key (in bytes) for a signature algorithm.
   */
  constexpr std::size_t signature_public_key_size(SignatureAlg alg) noexcept
  {
    switch (alg)
    {
    case SignatureAlg::ed25519:
      return 32;
    default:
      return 0;
    }
  }

  /**
   * @brief Size of private key (in bytes) for a signature algorithm.
   */
  constexpr std::size_t signature_private_key_size(SignatureAlg alg) noexcept
  {
    switch (alg)
    {
    case SignatureAlg::ed25519:
      return 64;
    default:
      return 0;
    }
  }

  /**
   * @brief Size of signature (in bytes) for a signature algorithm.
   */
  constexpr std::size_t signature_size(SignatureAlg alg) noexcept
  {
    switch (alg)
    {
    case SignatureAlg::ed25519:
      return 64;
    default:
      return 0;
    }
  }

  /**
   * @brief Generate a signature keypair.
   *
   * @param alg Signature algorithm
   * @param out_public_key Output public key buffer
   * @param out_private_key Output private key buffer
   */
  Result<void> signature_keygen(SignatureAlg alg,
                                std::span<std::uint8_t> out_public_key,
                                std::span<std::uint8_t> out_private_key) noexcept;

  /**
   * @brief Sign a message.
   *
   * @param alg Signature algorithm
   * @param private_key Private key bytes
   * @param message Message to sign
   * @param out_signature Output signature buffer
   */
  Result<void> sign(SignatureAlg alg,
                    std::span<const std::uint8_t> private_key,
                    std::span<const std::uint8_t> message,
                    std::span<std::uint8_t> out_signature) noexcept;

  /**
   * @brief Verify a signature.
   *
   * @param alg Signature algorithm
   * @param public_key Public key bytes
   * @param message Signed message
   * @param signature Signature bytes
   */
  Result<void> verify(SignatureAlg alg,
                      std::span<const std::uint8_t> public_key,
                      std::span<const std::uint8_t> message,
                      std::span<const std::uint8_t> signature) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_SIGNATURE_HPP
