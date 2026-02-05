/**
 *
 *  @file random.cpp
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
#include <vix/crypto/random.hpp>

#include <cstdint>
#include <limits>

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
#include <openssl/rand.h>
#endif

#if defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#endif

namespace vix::crypto
{

  Result<void> random_bytes(std::span<std::uint8_t> out) noexcept
  {
    if (out.empty())
      return Result<void>{};

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
    // OpenSSL CSPRNG
    if (RAND_bytes(reinterpret_cast<unsigned char *>(out.data()),
                   static_cast<int>(out.size())) == 1)
    {
      return Result<void>{};
    }
    return Result<void>{ErrorCode::entropy_unavailable, "OpenSSL RAND_bytes failed"};
#elif defined(__linux__)
    // Linux getrandom() syscall (CSPRNG)
    std::size_t filled = 0;

    while (filled < out.size())
    {
      const auto n = ::getrandom(out.data() + filled,
                                 out.size() - filled,
                                 0);

      if (n < 0)
      {
        if (errno == EINTR)
          continue;
        return Result<void>{ErrorCode::entropy_unavailable, "getrandom() failed"};
      }

      if (n == 0)
        return Result<void>{ErrorCode::entropy_unavailable, "getrandom() returned 0"};

      filled += static_cast<std::size_t>(n);
    }

    return Result<void>{};
#else
    // No provider available on this platform yet
    (void)out;
    return Result<void>{ErrorCode::not_supported,
                        "No secure RNG provider available on this platform"};
#endif
  }

  Result<std::uint64_t> random_uint(std::uint64_t max) noexcept
  {
    if (max == 0)
      return Result<std::uint64_t>{ErrorCode::invalid_argument, "max must be > 0"};

    // Rejection sampling to avoid modulo bias.
    // We accept values in [0, limit) where limit is the largest multiple of max.
    const std::uint64_t limit =
        (std::numeric_limits<std::uint64_t>::max() / max) * max;

    for (;;)
    {
      std::uint64_t x = 0;
      auto r = random_bytes(std::span<std::uint8_t>(
          reinterpret_cast<std::uint8_t *>(&x), sizeof(x)));

      if (!r.ok())
        return Result<std::uint64_t>{r.error()};

      if (x < limit)
        return Result<std::uint64_t>{x % max};
    }
  }

} // namespace vix::crypto
