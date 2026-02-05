/**
 *
 *  @file aead_roundtrip.cpp
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
#include <vix/crypto/crypto.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>

int main()
{
  using namespace vix::crypto;

  constexpr AeadAlg alg = AeadAlg::aes_256_gcm;

  std::array<std::uint8_t, 32> key{};
  std::array<std::uint8_t, 12> nonce{};

  if (!random_bytes(key).ok() || !random_bytes(nonce).ok())
  {
    std::cerr << "random failed\n";
    return 1;
  }

  constexpr std::string_view aad = "vix-crypto:aead-demo";
  constexpr std::string_view msg = "hello from vix crypto";

  auto sealed = aead::seal(alg, key, nonce, msg, aad);
  if (!sealed.ok())
  {
    std::cerr << "seal failed: " << sealed.error().message << "\n";
    return 1;
  }

  auto open = aead::open_string(alg, key, nonce, sealed.value(), aad);
  if (!open.ok())
  {
    std::cerr << "open failed: " << open.error().message << "\n";
    return 1;
  }

  std::cout << ((open.value() == msg) ? "OK\n" : "FAILED\n");
  return (open.value() == msg) ? 0 : 2;
}
