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

    constexpr AeadAlg alg = AeadAlg::aes_256_gcm;

    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};

    auto rk = random_bytes(key);
    if (!rk.ok())
    {
      std::cerr << "random key failed: "
                << static_cast<int>(rk.error().code)
                << " " << rk.error().message << "\n";
      return 1;
    }

    auto rn = random_bytes(nonce);
    if (!rn.ok())
    {
      std::cerr << "random nonce failed: "
                << static_cast<int>(rn.error().code)
                << " " << rn.error().message << "\n";
      return 1;
    }

    constexpr std::string_view aad_sv = "vix-crypto:aead-demo";
    constexpr std::string_view msg_sv = "hello from vix crypto";

    std::vector<std::uint8_t> plaintext(msg_sv.begin(), msg_sv.end());
    std::vector<std::uint8_t> ciphertext(plaintext.size());
    std::vector<std::uint8_t> decrypted(plaintext.size());
    std::array<std::uint8_t, 16> tag{};

    auto enc = aead_encrypt(
        alg,
        key,
        nonce,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(aad_sv.data()),
            aad_sv.size()),
        plaintext,
        ciphertext,
        tag);

    if (!enc.ok())
    {
      std::cerr << "encrypt failed: "
                << static_cast<int>(enc.error().code)
                << " " << enc.error().message << "\n";
      return 1;
    }

    auto dec = aead_decrypt(
        alg,
        key,
        nonce,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(aad_sv.data()),
            aad_sv.size()),
        ciphertext,
        tag,
        decrypted);

    if (!dec.ok())
    {
      std::cerr << "decrypt failed: "
                << static_cast<int>(dec.error().code)
                << " " << dec.error().message << "\n";
      return 1;
    }

    const bool same = (decrypted == plaintext);

    std::cout << "alg: aes-256-gcm\n";
    std::cout << "aad: " << aad_sv << "\n";
    std::cout << "msg: " << msg_sv << "\n";
    std::cout << "ciphertext: ";
    print_hex(ciphertext);
    std::cout << "\n";
    std::cout << "tag:        ";
    print_hex(tag);
    std::cout << "\n";
    std::cout << "roundtrip:  " << (same ? "OK" : "FAILED") << "\n";

    return same ? 0 : 2;
  }

} // namespace

int main()
{
  return run();
}
