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
#include <iomanip>
#include <iostream>
#include <string_view>

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
    constexpr std::string_view msg = "vix crypto: sha256 demo";

    std::array<std::uint8_t, 32> out{};

    auto r = vix::crypto::sha256(msg, out);
    if (!r.ok())
    {
      std::cerr << "sha256 failed: "
                << static_cast<int>(r.error().code)
                << " " << r.error().message << "\n";
      return 1;
    }

    std::cout << "message: " << msg << "\n";
    std::cout << "sha256:  ";
    print_hex(out);
    std::cout << "\n";

    return 0;
  }

} // namespace

int main()
{
  return run();
}
