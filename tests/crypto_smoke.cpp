/**
 *
 *  @file crypto_smoke.cpp
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
#include <cstring>
#include <iostream>
#include <vector>

using namespace vix::crypto;

namespace
{

  int test_random()
  {
    std::array<std::uint8_t, 32> a{};
    std::array<std::uint8_t, 32> b{};

    auto r1 = random_bytes(a);
    auto r2 = random_bytes(b);

    if (!r1.ok() || !r2.ok())
      return 1;

    // Extremely unlikely to be equal
    return std::memcmp(a.data(), b.data(), a.size()) == 0 ? 2 : 0;
  }

  int test_hash()
  {
    constexpr const char *msg = "crypto-smoke-test";
    std::array<std::uint8_t, 32> h1{};
    std::array<std::uint8_t, 32> h2{};

    auto r1 = sha256(std::string_view(msg), h1);
    auto r2 = sha256(std::string_view(msg), h2);

    if (!r1.ok() || !r2.ok())
      return 1;

    return std::memcmp(h1.data(), h2.data(), h1.size()) == 0 ? 0 : 2;
  }

  int test_hmac()
  {
    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 32> mac1{};
    std::array<std::uint8_t, 32> mac2{};

    auto rk = random_bytes(key);
    if (!rk.ok())
      return 1;

    constexpr const char *msg = "hmac-smoke";

    auto r1 = hmac_sha256(key,
                          std::string_view(msg),
                          mac1);
    auto r2 = hmac_sha256(key,
                          std::string_view(msg),
                          mac2);

    if (!r1.ok() || !r2.ok())
      return 1;

    return std::memcmp(mac1.data(), mac2.data(), mac1.size()) == 0 ? 0 : 2;
  }

  int test_kdf()
  {
    std::array<std::uint8_t, 32> ikm{};
    std::array<std::uint8_t, 32> out1{};
    std::array<std::uint8_t, 32> out2{};

    auto rk = random_bytes(ikm);
    if (!rk.ok())
      return 1;

    auto r1 = hkdf_sha256(ikm, {}, {}, out1);
    auto r2 = hkdf_sha256(ikm, {}, {}, out2);

    if (!r1.ok() || !r2.ok())
      return 1;

    return std::memcmp(out1.data(), out2.data(), out1.size()) == 0 ? 0 : 2;
  }

  int test_aead()
  {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};
    std::array<std::uint8_t, 16> tag{};

    auto rk = random_bytes(key);
    auto rn = random_bytes(nonce);
    if (!rk.ok() || !rn.ok())
      return 1;

    constexpr const char *msg = "aead-smoke";
    std::vector<std::uint8_t> pt(msg, msg + std::strlen(msg));
    std::vector<std::uint8_t> ct(pt.size());
    std::vector<std::uint8_t> out(pt.size());

    auto enc = aead_encrypt(AeadAlg::aes_256_gcm,
                            key,
                            nonce,
                            {},
                            pt,
                            ct,
                            tag);
    if (!enc.ok())
      return 1;

    auto dec = aead_decrypt(AeadAlg::aes_256_gcm,
                            key,
                            nonce,
                            {},
                            ct,
                            tag,
                            out);
    if (!dec.ok())
      return 2;

    return (pt == out) ? 0 : 3;
  }

  int test_signature()
  {
    std::array<std::uint8_t, 32> pub{};
    std::array<std::uint8_t, 64> priv{};
    std::array<std::uint8_t, 64> sig{};

    auto kg = signature_keygen(SignatureAlg::ed25519, pub, priv);
    if (!kg.ok())
      return 1;

    constexpr const char *msg = "signature-smoke";
    std::span<const std::uint8_t> m(
        reinterpret_cast<const std::uint8_t *>(msg),
        std::strlen(msg));

    auto s = sign(SignatureAlg::ed25519, priv, m, sig);
    if (!s.ok())
      return 2;

    auto v = verify(SignatureAlg::ed25519, pub, m, sig);
    if (!v.ok())
      return 3;

    sig[0] ^= 0x01;
    auto v2 = verify(SignatureAlg::ed25519, pub, m, sig);

    return v2.ok() ? 4 : 0;
  }

} // namespace

int main()
{
  if (int r = test_random(); r != 0)
    return r;
  if (int r = test_hash(); r != 0)
    return r;
  if (int r = test_hmac(); r != 0)
    return r;
  if (int r = test_kdf(); r != 0)
    return r;
  if (int r = test_aead(); r != 0)
    return r;
  if (int r = test_signature(); r != 0)
    return r;

  std::cout << "[crypto] smoke tests: OK\n";
  return 0;
}
