/**
 *
 *  @file sign_verify.cpp
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

#include <iostream>
#include <string_view>

int main()
{
  using namespace vix::crypto;

  constexpr std::string_view msg = "vix crypto: ed25519 sign/verify demo";

  auto kp = signature::keygen(SignatureAlg::ed25519);
  if (!kp.ok())
  {
    std::cerr << "keygen failed: " << kp.error().message << "\n";
    return 1;
  }

  auto sig = signature::sign(SignatureAlg::ed25519, kp.value().private_key, msg);
  if (!sig.ok())
  {
    std::cerr << "sign failed: " << sig.error().message << "\n";
    return 1;
  }

  auto ok = signature::verify(SignatureAlg::ed25519, kp.value().public_key, msg, sig.value());
  if (!ok.ok())
  {
    std::cerr << "verify failed: " << ok.error().message << "\n";
    return 2;
  }

  std::cout << "OK\n";
  return 0;
}
