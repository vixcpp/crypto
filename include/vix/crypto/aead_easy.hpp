/**
 *
 *  @file aead_easy.hpp
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
#ifndef VIX_CRYPTO_AEAD_EASY_HPP
#define VIX_CRYPTO_AEAD_EASY_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <vix/crypto/Result.hpp>
#include <vix/crypto/aead.hpp>
#include <vix/crypto/bytes.hpp>

namespace vix::crypto::aead
{
  struct Sealed final
  {
    std::vector<std::uint8_t> ciphertext{};
    std::array<std::uint8_t, 16> tag{};
  };

  inline Result<Sealed> seal(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      std::span<const std::uint8_t> plaintext,
      std::span<const std::uint8_t> aad = {}) noexcept
  {
    Sealed out{};
    out.ciphertext.resize(plaintext.size());

    auto r = aead_encrypt(alg, key, nonce, aad, plaintext, out.ciphertext, out.tag);
    if (!r.ok())
      return Result<Sealed>{r.error()};

    return Result<Sealed>{std::move(out)};
  }

  inline Result<Sealed> seal(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      std::string_view plaintext,
      std::string_view aad = {}) noexcept
  {
    return seal(alg, key, nonce, vix::crypto::bytes(plaintext), vix::crypto::bytes(aad));
  }

  inline Result<std::vector<std::uint8_t>> open(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      const Sealed &sealed,
      std::span<const std::uint8_t> aad = {}) noexcept
  {
    std::vector<std::uint8_t> out;
    out.resize(sealed.ciphertext.size());

    auto r = aead_decrypt(alg, key, nonce, aad, sealed.ciphertext, sealed.tag, out);
    if (!r.ok())
      return Result<std::vector<std::uint8_t>>{r.error()};

    return Result<std::vector<std::uint8_t>>{std::move(out)};
  }

  inline Result<std::vector<std::uint8_t>> open(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      const Sealed &sealed,
      std::string_view aad) noexcept
  {
    return open(alg, key, nonce, sealed, vix::crypto::bytes(aad));
  }

  inline Result<std::string> open_string(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      const Sealed &sealed,
      std::span<const std::uint8_t> aad = {}) noexcept
  {
    auto r = open(alg, key, nonce, sealed, aad);
    if (!r.ok())
      return Result<std::string>{r.error()};

    const auto &bytes_out = r.value();
    return Result<std::string>{std::string(bytes_out.begin(), bytes_out.end())};
  }

  inline Result<std::string> open_string(
      AeadAlg alg,
      std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> nonce,
      const Sealed &sealed,
      std::string_view aad) noexcept
  {
    return open_string(alg, key, nonce, sealed, vix::crypto::bytes(aad));
  }

} // namespace vix::crypto::aead

#endif // VIX_CRYPTO_AEAD_EASY_HPP
