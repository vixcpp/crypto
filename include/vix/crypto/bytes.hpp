#ifndef VIX_CRYPTO_BYTES_HPP
#define VIX_CRYPTO_BYTES_HPP

#include <cstdint>
#include <span>
#include <string_view>

namespace vix::crypto
{
  inline std::span<const std::uint8_t> bytes(std::string_view s) noexcept
  {
    return {
        reinterpret_cast<const std::uint8_t *>(s.data()),
        s.size()};
  }
} // namespace vix::crypto

#endif
