/**
 *
 *  @file signature_easy.hpp
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
#ifndef VIX_CRYPTO_SIGNATURE_EASY_HPP
#define VIX_CRYPTO_SIGNATURE_EASY_HPP

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

#include <vix/crypto/Result.hpp>
#include <vix/crypto/bytes.hpp>
#include <vix/crypto/signature.hpp>

/**
 * @file signature_easy.hpp
 * @brief High-level helpers for digital signatures.
 *
 * @details
 * This header provides ergonomic, allocation-free wrappers around the low-level
 * signature primitives defined in `signature.hpp`.
 *
 * It is designed for common usage patterns:
 * - key pair generation
 * - signing byte buffers or strings
 * - signature verification
 *
 * All helpers return explicit `Result` types and never throw.
 */

namespace vix::crypto::signature
{

  /**
   * @brief Owning container for a public/private key pair.
   *
   * Layout:
   * - `public_key`: public verification key
   * - `private_key`: private signing key (format depends on algorithm)
   *
   * For Ed25519, the private key is encoded as:
   * `seed (32 bytes) || public_key (32 bytes)`.
   */
  struct Keypair final
  {
    std::array<std::uint8_t, 32> public_key{};
    std::array<std::uint8_t, 64> private_key{};
  };

  /**
   * @brief Generate a signature key pair.
   *
   * @param alg Signature algorithm (defaults to Ed25519).
   * @return `Result<Keypair>` containing the generated keys on success,
   * or an error on failure.
   */
  inline Result<Keypair> keygen(SignatureAlg alg = SignatureAlg::ed25519) noexcept
  {
    Keypair kp{};

    auto r = ::vix::crypto::signature_keygen(alg, kp.public_key, kp.private_key);
    if (!r.ok())
      return Result<Keypair>{r.error()};

    return Result<Keypair>{kp};
  }

  /**
   * @brief Sign a message using a private key.
   *
   * @param alg Signature algorithm.
   * @param private_key Private signing key.
   * @param message Message bytes to sign.
   *
   * @return `Result<std::array<uint8_t, 64>>` containing the signature on success,
   * or an error on failure.
   */
  inline Result<std::array<std::uint8_t, 64>> sign(
      SignatureAlg alg,
      std::span<const std::uint8_t> private_key,
      std::span<const std::uint8_t> message) noexcept
  {
    std::array<std::uint8_t, 64> out{};

    auto r = ::vix::crypto::sign(alg, private_key, message, out);
    if (!r.ok())
      return Result<std::array<std::uint8_t, 64>>{r.error()};

    return Result<std::array<std::uint8_t, 64>>{out};
  }

  /**
   * @brief Sign a string message using a private key.
   *
   * The string is interpreted as raw bytes. No encoding conversion is performed.
   *
   * @param alg Signature algorithm.
   * @param private_key Private signing key.
   * @param message Message string to sign.
   *
   * @return Signature on success, or an error on failure.
   */
  inline Result<std::array<std::uint8_t, 64>> sign(
      SignatureAlg alg,
      std::span<const std::uint8_t> private_key,
      std::string_view message) noexcept
  {
    return ::vix::crypto::signature::sign(
        alg, private_key, ::vix::crypto::bytes(message));
  }

  /**
   * @brief Verify a digital signature.
   *
   * @param alg Signature algorithm.
   * @param public_key Public verification key.
   * @param message Original message bytes.
   * @param sig Signature bytes.
   *
   * @return `Result<void>` ok if the signature is valid, or an error otherwise.
   */
  inline Result<void> verify(
      SignatureAlg alg,
      std::span<const std::uint8_t> public_key,
      std::span<const std::uint8_t> message,
      std::span<const std::uint8_t> sig) noexcept
  {
    return ::vix::crypto::verify(alg, public_key, message, sig);
  }

  /**
   * @brief Verify a digital signature for a string message.
   *
   * The string is interpreted as raw bytes. No encoding conversion is performed.
   *
   * @param alg Signature algorithm.
   * @param public_key Public verification key.
   * @param message Original message string.
   * @param sig Signature bytes.
   *
   * @return `Result<void>` ok if the signature is valid, or an error otherwise.
   */
  inline Result<void> verify(
      SignatureAlg alg,
      std::span<const std::uint8_t> public_key,
      std::string_view message,
      std::span<const std::uint8_t> sig) noexcept
  {
    return ::vix::crypto::signature::verify(
        alg, public_key, ::vix::crypto::bytes(message), sig);
  }

} // namespace vix::crypto::signature

#endif // VIX_CRYPTO_SIGNATURE_EASY_HPP
