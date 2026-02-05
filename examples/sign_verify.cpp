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

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string_view>
#include <vector>

namespace
{

  void print_hex(std::span<const std::uint8_t> bytes)
  {
    std::ios old_state(nullptr);
    old_state.copyfmt(std::cout);

    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(bytes[i]);
    }

    std::cout.copyfmt(old_state);
  }

  int run()
  {
    using namespace vix::crypto;

    constexpr SignatureAlg alg = SignatureAlg::ed25519;

    std::array<std::uint8_t, 32> pub{};
    std::array<std::uint8_t, 64> priv{};
    std::array<std::uint8_t, 64> sig{};

    auto kg = signature_keygen(alg, pub, priv);
    if (!kg.ok())
    {
      std::cerr << "keygen failed: "
                << static_cast<int>(kg.error().code)
                << " " << kg.error().message << "\n";
      return 1;
    }

    constexpr std::string_view msg_sv = "vix crypto: ed25519 sign/verify demo";
    const auto *msg_ptr = reinterpret_cast<const std::uint8_t *>(msg_sv.data());
    std::span<const std::uint8_t> msg(msg_ptr, msg_sv.size());

    auto s = sign(alg, priv, msg, sig);
    if (!s.ok())
    {
      std::cerr << "sign failed: "
                << static_cast<int>(s.error().code)
                << " " << s.error().message << "\n";
      return 1;
    }

    auto v = verify(alg, pub, msg, sig);
    if (!v.ok())
    {
      std::cerr << "verify failed: "
                << static_cast<int>(v.error().code)
                << " " << v.error().message << "\n";
      return 2;
    }

    std::cout << "alg: ed25519\n";
    std::cout << "msg: " << msg_sv << "\n";
    std::cout << "pub: ";
    print_hex(pub);
    std::cout << "\n";
    std::cout << "sig: ";
    print_hex(sig);
    std::cout << "\n";
    std::cout << "verify: OK\n";

    // Negative test (flip one byte in signature)
    auto bad_sig = sig;
    bad_sig[0] ^= 0x01;

    auto v2 = verify(alg, pub, msg, bad_sig);
    std::cout << "verify(tampered): " << (v2.ok() ? "UNEXPECTED OK" : "EXPECTED FAIL") << "\n";

    return v2.ok() ? 3 : 0;
  }

} // namespace

int main()
{
  return run();
}
