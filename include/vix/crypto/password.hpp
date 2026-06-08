/**
 *
 *  @file password.hpp
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

#ifndef VIX_CRYPTO_PASSWORD_HPP
#define VIX_CRYPTO_PASSWORD_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <vix/crypto/Result.hpp>

/**
 * @file password.hpp
 * @brief Password hashing helpers for authentication systems.
 *
 * @details
 * This header exposes a small production-oriented password hashing API.
 *
 * The API stores password hashes in a self-describing encoded format:
 *
 * @code
 * vix-pbkdf2-sha256$310000$<salt_hex>$<hash_hex>
 * @endcode
 *
 * This allows applications to store one string in a database while keeping
 * the algorithm, iteration count, salt, and derived hash together.
 *
 * Password verification parses the encoded string, derives the password hash
 * again, and compares it using constant-time comparison.
 */

namespace vix::crypto
{
  /**
   * @brief Supported password hashing algorithms.
   */
  enum class PasswordHashAlg : std::uint8_t
  {
    /**
     * @brief PBKDF2 using HMAC-SHA256.
     */
    pbkdf2_sha256 = 1
  };

  /**
   * @brief Parameters used to hash a password.
   */
  struct PasswordHashParams final
  {
    /**
     * @brief Number of PBKDF2 iterations.
     *
     * Higher values are slower and more resistant to brute force attacks.
     */
    std::uint32_t iterations{310000};

    /**
     * @brief Random salt size in bytes.
     */
    std::size_t salt_size{16};

    /**
     * @brief Derived hash size in bytes.
     */
    std::size_t hash_size{32};

    /**
     * @brief Algorithm used for password hashing.
     */
    PasswordHashAlg alg{PasswordHashAlg::pbkdf2_sha256};
  };

  /**
   * @brief Hash a password using secure password hashing parameters.
   *
   * @param password Plain-text password.
   * @param params Password hashing parameters.
   *
   * @return Encoded password hash on success, or an error.
   */
  [[nodiscard]] Result<std::string> password_hash(
      std::string_view password,
      const PasswordHashParams &params = {}) noexcept;

  /**
   * @brief Verify a password against an encoded password hash.
   *
   * @param password Plain-text password to verify.
   * @param encoded_hash Encoded password hash produced by password_hash().
   *
   * @return true if the password matches, false if it does not match, or an
   * error when the encoded hash is invalid or the crypto provider fails.
   */
  [[nodiscard]] Result<bool> password_verify(
      std::string_view password,
      std::string_view encoded_hash) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_PASSWORD_HPP
