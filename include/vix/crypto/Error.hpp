/**
 *
 *  @file Error.hpp
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
#ifndef VIX_CRYPTO_ERROR_HPP
#define VIX_CRYPTO_ERROR_HPP

#include <cstdint>
#include <string_view>

/**
 * @file Error.hpp
 * @brief Error codes and lightweight error type for crypto APIs.
 *
 * @details
 * This header defines the public error model used by the `vix::crypto` module.
 * Errors are explicit values returned through result types rather than
 * exceptions.
 *
 * Design goals:
 * - Stable numeric error codes (ABI-friendly)
 * - No dynamic allocation
 * - Cheap to copy and pass by value
 * - Suitable for low-level and security-sensitive code
 */

namespace vix::crypto
{

  /**
   * @brief Enumerates all crypto error categories exposed by the public API.
   *
   * The numeric values of this enum are part of the public ABI and must remain
   * stable. New error codes may be appended, but existing values must not change.
   */
  enum class ErrorCode : std::uint8_t
  {
    /// No error.
    ok = 0,

    // Generic / misuse
    invalid_argument,
    invalid_state,
    not_supported,

    // Randomness / entropy
    entropy_unavailable,
    weak_entropy,

    // Hash / MAC
    hash_failed,
    mac_failed,

    // Key material
    invalid_key,
    key_generation_failed,
    key_derivation_failed,

    // AEAD / encryption
    encrypt_failed,
    decrypt_failed,
    authentication_failed,

    // Signatures
    sign_failed,
    verify_failed,

    // Backend / provider
    provider_error,
    provider_unavailable,

    // Internal invariant violation (should never happen)
    internal_error
  };

  /**
   * @brief Lightweight error object for crypto operations.
   *
   * This type intentionally carries minimal information:
   * - an error code
   * - an optional static or externally-owned message
   *
   * It performs no allocation and is safe to copy, store, and return by value.
   */
  struct Error
  {
    /// Error category.
    ErrorCode code{ErrorCode::ok};

    /// Optional human-readable message (non-owning).
    std::string_view message{};

    /// Construct a success error.
    constexpr Error() = default;

    /// Construct an error with code and optional message.
    constexpr Error(ErrorCode c, std::string_view msg = {})
        : code(c), message(msg)
    {
    }

    /**
     * @brief Check whether this represents success.
     *
     * @return `true` if `code == ErrorCode::ok`.
     */
    constexpr bool ok() const noexcept
    {
      return code == ErrorCode::ok;
    }

    /**
     * @brief Explicit boolean conversion.
     *
     * Allows usage such as:
     * @code
     * if (!err) { ... }
     * @endcode
     */
    constexpr explicit operator bool() const noexcept
    {
      return ok();
    }
  };

  /**
   * @brief Convenience helper returning a success error.
   */
  constexpr Error ok() noexcept
  {
    return {};
  }

} // namespace vix::crypto

#endif // VIX_CRYPTO_ERROR_HPP
