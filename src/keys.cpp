/**
 *
 *  @file keys.cpp
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
#include <vix/crypto/keys.hpp>
#include <vix/crypto/random.hpp>

namespace vix::crypto
{

  Result<SecretKey> generate_secret_key(std::size_t size) noexcept
  {
    if (size == 0)
      return Result<SecretKey>{ErrorCode::invalid_argument, "key size must be > 0"};

    SecretKey k(size);

    auto r = random_bytes(k.bytes_mut());
    if (!r.ok())
      return Result<SecretKey>{r.error()};

    return Result<SecretKey>{std::move(k)};
  }

} // namespace vix::crypto
