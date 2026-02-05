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

namespace vix::crypto
{

  /**
   * @brief Lightweight owning container for secret key material.
   *
   * Design rules:
   * - Owns its memory
   * - Explicit size
   * - Zeroized on destruction
   * - Movable, non-copyable by default
   */
  class SecretKey
  {
  public:
    SecretKey() = default;

    explicit SecretKey(std::size_t size)
        : bytes_(size)
    {
    }

    explicit SecretKey(std::vector<std::uint8_t> bytes)
        : bytes_(std::move(bytes))
    {
    }

    SecretKey(const SecretKey &) = delete;
    SecretKey &operator=(const SecretKey &) = delete;

    SecretKey(SecretKey &&other) noexcept
        : bytes_(std::move(other.bytes_))
    {
    }

    SecretKey &operator=(SecretKey &&other) noexcept
    {
      if (this != &other)
      {
        zeroize();
        bytes_ = std::move(other.bytes_);
      }
      return *this;
    }

    ~SecretKey()
    {
      zeroize();
    }

    std::size_t size() const noexcept
    {
      return bytes_.size();
    }

    bool empty() const noexcept
    {
      return bytes_.empty();
    }

    std::span<const std::uint8_t> bytes() const noexcept
    {
      return bytes_;
    }

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
   * @brief Generate a random secret key of given size.
   *
   * @param size Key size in bytes
   */
  Result<SecretKey> generate_secret_key(std::size_t size) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_KEYS_HPP
