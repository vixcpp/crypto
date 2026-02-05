/**
 *
 *  @file hash_sha256.cpp
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
  constexpr std::string_view msg = "vix crypto: sha256 demo";
  std::array<std::uint8_t, 32> out{};

  auto r = vix::crypto::sha256(msg, out);
  if (!r.ok())
  {
    std::cerr << "sha256 failed: " << r.error().message << "\n";
    return 1;
  }

  std::cout << vix::crypto::hex_lower(out) << "\n";
  return 0;
}
