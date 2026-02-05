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

namespace vix::crypto::signature
{
  struct Keypair final
  {
    std::array<std::uint8_t, 32> public_key{};
    std::array<std::uint8_t, 64> private_key{}; // seed(32) || pub(32)
  };

  inline Result<Keypair> keygen(SignatureAlg alg = SignatureAlg::ed25519) noexcept
  {
    Keypair kp{};

    auto r = ::vix::crypto::signature_keygen(alg, kp.public_key, kp.private_key);
    if (!r.ok())
      return Result<Keypair>{r.error()};

    return Result<Keypair>{kp};
  }

  inline Result<std::array<std::uint8_t, 64>> sign(SignatureAlg alg,
                                                   std::span<const std::uint8_t> private_key,
                                                   std::span<const std::uint8_t> message) noexcept
  {
    std::array<std::uint8_t, 64> out{};

    auto r = ::vix::crypto::sign(alg, private_key, message, out);
    if (!r.ok())
      return Result<std::array<std::uint8_t, 64>>{r.error()};

    return Result<std::array<std::uint8_t, 64>>{out};
  }

  inline Result<std::array<std::uint8_t, 64>> sign(SignatureAlg alg,
                                                   std::span<const std::uint8_t> private_key,
                                                   std::string_view message) noexcept
  {
    return ::vix::crypto::signature::sign(alg, private_key, ::vix::crypto::bytes(message));
  }

  inline Result<void> verify(SignatureAlg alg,
                             std::span<const std::uint8_t> public_key,
                             std::span<const std::uint8_t> message,
                             std::span<const std::uint8_t> sig) noexcept
  {
    return ::vix::crypto::verify(alg, public_key, message, sig);
  }

  inline Result<void> verify(SignatureAlg alg,
                             std::span<const std::uint8_t> public_key,
                             std::string_view message,
                             std::span<const std::uint8_t> sig) noexcept
  {
    // ✅ Qualification explicite: plus aucune ambiguïté d'overload
    return ::vix::crypto::signature::verify(alg, public_key, ::vix::crypto::bytes(message), sig);
  }

} // namespace vix::crypto::signature

#endif // VIX_CRYPTO_SIGNATURE_EASY_HPP
