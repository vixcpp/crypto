/**
 *
 *  @file keys.hpp
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
#ifndef VIX_CRYPTO_KEYS_HPP
#define VIX_CRYPTO_KEYS_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <vix/crypto/Result.hpp>

/**
 * @file keys.hpp
 * @brief Secret key ownership and generation helpers.
 *
 * @details
 * This header defines a small RAII type for handling secret key material
 * safely, along with helpers for generating cryptographically secure keys.
 *
 * Design goals:
 * - explicit ownership of sensitive memory
 * - zeroization on destruction and move-assignment
 * - no accidental copying
 * - simple span-based access for crypto primitives
 */

namespace vix::crypto
{

  /**
   * @brief Owning container for secret key material.
   *
   * `SecretKey` is a minimal RAII wrapper around a byte buffer intended for
   * cryptographic keys and other sensitive material.
   *
   * Properties:
   * - owns its memory
   * - movable but non-copyable
   * - zeroizes memory on destruction and before move-assignment
   * - exposes data through `std::span` for explicit use
   *
   * This type performs no cryptographic validation. The caller is responsible
   * for ensuring the key size and usage are correct for the chosen algorithm.
   */
  class SecretKey
  {
  public:
    /// Construct an empty key.
    SecretKey() = default;

    /**
     * @brief Construct a key with the given size.
     *
     * The contents are uninitialized. Callers should fill the buffer or use
     * `generate_secret_key`.
     *
     * @param size Key size in bytes.
     */
    explicit SecretKey(std::size_t size)
        : bytes_(size)
    {
    }

    /**
     * @brief Take ownership of an existing byte buffer.
     *
     * @param bytes Key material to own.
     */
    explicit SecretKey(std::vector<std::uint8_t> bytes)
        : bytes_(std::move(bytes))
    {
    }

    /// Non-copyable.
    SecretKey(const SecretKey &) = delete;
    SecretKey &operator=(const SecretKey &) = delete;

    /// Movable.
    SecretKey(SecretKey &&other) noexcept
        : bytes_(std::move(other.bytes_))
    {
    }

    /// Move-assignable with zeroization of previous contents.
    SecretKey &operator=(SecretKey &&other) noexcept
    {
      if (this != &other)
      {
        zeroize();
        bytes_ = std::move(other.bytes_);
      }
      return *this;
    }

    /// Zeroizes key material on destruction.
    ~SecretKey()
    {
      zeroize();
    }

    /// Return key size in bytes.
    std::size_t size() const noexcept
    {
      return bytes_.size();
    }

    /// Check whether the key is empty.
    bool empty() const noexcept
    {
      return bytes_.empty();
    }

    /**
     * @brief Read-only view of the key material.
     *
     * @return Span of key bytes.
     */
    std::span<const std::uint8_t> bytes() const noexcept
    {
      return bytes_;
    }

    /**
     * @brief Mutable view of the key material.
     *
     * Intended for controlled initialization or derivation.
     *
     * @return Mutable span of key bytes.
     */
    std::span<std::uint8_t> bytes_mut() noexcept
    {
      return bytes_;
    }

  private:
    void zeroize() noexcept
    {
      for (auto &b : bytes_)
        b = 0;
    }

    std::vector<std::uint8_t> bytes_;
  };

  /**
   * @brief Generate a random secret key.
   *
   * Uses the platform cryptographic RNG to generate a key of the requested
   * size.
   *
   * @param size Key size in bytes.
   * @return `Result<SecretKey>` containing the generated key on success,
   * or an error on failure.
   */
  Result<SecretKey> generate_secret_key(std::size_t size) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_KEYS_HPP
