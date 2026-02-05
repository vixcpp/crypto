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

namespace vix::crypto
{

  /**
   * @brief Enumerates all crypto error categories exposed by the public API.
   *
   * Design rules:
   * - Stable numeric values (ABI-friendly)
   * - No exceptions in public APIs
   * - Errors are explicit and inspectable
   */
  enum class ErrorCode : std::uint8_t
  {
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
   * This type is intentionally trivial:
   * - cheap to copy
   * - no allocation
   * - safe to pass by value
   */
  struct Error
  {
    ErrorCode code{ErrorCode::ok};
    std::string_view message{};

    constexpr Error() = default;
    constexpr Error(ErrorCode c, std::string_view msg = {})
        : code(c), message(msg)
    {
    }

    /// True when error represents success
    constexpr bool ok() const noexcept
    {
      return code == ErrorCode::ok;
    }

    /// Explicit bool conversion for quick checks
    constexpr explicit operator bool() const noexcept
    {
      return ok();
    }
  };

  /// Convenience helper for success
  constexpr Error ok() noexcept
  {
    return {};
  }

} // namespace vix::crypto

#endif // VIX_CRYPTO_ERROR_HPP
