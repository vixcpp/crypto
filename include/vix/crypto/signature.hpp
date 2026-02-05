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

/**
 * @file signature.hpp
 * @brief Low-level digital signature primitives.
 *
 * @details
 * This header defines the core signature API for the `vix::crypto` module.
 * It exposes explicit, allocation-free primitives for:
 * - key pair generation
 * - message signing
 * - signature verification
 *
 * The API is intentionally low-level and buffer-oriented. Higher-level,
 * ergonomic helpers are provided in `signature_easy.hpp`.
 *
 * Design principles:
 * - explicit algorithms
 * - fixed-size buffers
 * - no exceptions
 * - deterministic control flow
 */

namespace vix::crypto
{

  /**
   * @brief Supported digital signature algorithms.
   *
   * The initial implementation targets Ed25519, chosen for its strong
   * security properties, deterministic signatures, and widespread adoption.
   */
  enum class SignatureAlg : std::uint8_t
  {
    /// Ed25519 signature scheme.
    ed25519 = 1
  };

  /**
   * @brief Get public key size in bytes for a signature algorithm.
   *
   * @param alg Signature algorithm.
   * @return Public key size in bytes, or 0 if @p alg is unknown.
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
   * @brief Get private key size in bytes for a signature algorithm.
   *
   * @param alg Signature algorithm.
   * @return Private key size in bytes, or 0 if @p alg is unknown.
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
   * @brief Get signature size in bytes for a signature algorithm.
   *
   * @param alg Signature algorithm.
   * @return Signature size in bytes, or 0 if @p alg is unknown.
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
   * @brief Generate a signature key pair.
   *
   * @param alg Signature algorithm.
   * @param out_public_key Output buffer for the public key
   * (must be `signature_public_key_size(alg)` bytes).
   * @param out_private_key Output buffer for the private key
   * (must be `signature_private_key_size(alg)` bytes).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> signature_keygen(
      SignatureAlg alg,
      std::span<std::uint8_t> out_public_key,
      std::span<std::uint8_t> out_private_key) noexcept;

  /**
   * @brief Sign a message using a private key.
   *
   * @param alg Signature algorithm.
   * @param private_key Private key bytes
   * (must be `signature_private_key_size(alg)` bytes).
   * @param message Message bytes to sign.
   * @param out_signature Output buffer for the signature
   * (must be `signature_size(alg)` bytes).
   *
   * @return `Result<void>` ok on success, or an error on failure.
   */
  Result<void> sign(
      SignatureAlg alg,
      std::span<const std::uint8_t> private_key,
      std::span<const std::uint8_t> message,
      std::span<std::uint8_t> out_signature) noexcept;

  /**
   * @brief Verify a digital signature.
   *
   * Verifies that @p signature is a valid signature of @p message under
   * @p public_key.
   *
   * @param alg Signature algorithm.
   * @param public_key Public key bytes
   * (must be `signature_public_key_size(alg)` bytes).
   * @param message Original signed message.
   * @param signature Signature bytes
   * (must be `signature_size(alg)` bytes).
   *
   * @return `Result<void>` ok if the signature is valid, or an error otherwise.
   */
  Result<void> verify(
      SignatureAlg alg,
      std::span<const std::uint8_t> public_key,
      std::span<const std::uint8_t> message,
      std::span<const std::uint8_t> signature) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_SIGNATURE_HPP
