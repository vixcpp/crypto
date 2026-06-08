/**
 *
 *  @file password.cpp
 *  @author Gaspard Kirira
 *
 *  Copyright 2026, Gaspard Kirira.
 *  All rights reserved.
 *  https://github.com/vixcpp/vix
 *
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
 *
 *  Vix.cpp
 *
 */

#include <vix/crypto/password.hpp>

#include <vix/crypto/compare.hpp>
#include <vix/crypto/hex.hpp>
#include <vix/crypto/random.hpp>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
#include <openssl/evp.h>
#endif

namespace vix::crypto
{
  namespace
  {
    constexpr std::string_view k_pdkdf2_sha256_prefix{"vix-pbkdf2-sha256"};
    constexpr std::uint32_t k_min_iterations{100000};
    constexpr std::size_t k_min_salt_size{16};
    constexpr std::size_t k_min_hash_size{32};

    [[nodiscard]] bool is_hex_char(char c) noexcept
    {
      return (c >= '0' && c <= '9') ||
             (c >= 'a' && c <= 'f') ||
             (c >= 'A' && c <= 'F');
    }

    [[nodiscard]] std::uint8_t hex_value(char c) noexcept
    {
      if (c >= '0' && c <= '9')
        return static_cast<std::uint8_t>(c - '0');

      if (c >= 'a' && c <= 'f')
        return static_cast<std::uint8_t>(10 + (c - 'a'));

      if (c >= 'A' && c <= 'F')
        return static_cast<std::uint8_t>(10 + (c - 'A'));

      return 0;
    }

    [[nodiscard]] Result<std::vector<std::uint8_t>> hex_decode(
        std::string_view input) noexcept
    {
      if ((input.size() % 2) != 0)
      {
        return Result<std::vector<std::uint8_t>>{
            ErrorCode::invalid_argument,
            "hex input must have an even size"};
      }

      std::vector<std::uint8_t> out;
      out.resize(input.size() / 2);

      for (std::size_t i = 0; i < out.size(); ++i)
      {
        const char hi = input[i * 2];
        const char lo = input[i * 2 + 1];

        if (!is_hex_char(hi) || !is_hex_char(lo))
        {
          return Result<std::vector<std::uint8_t>>{
              ErrorCode::invalid_argument,
              "hex input contains invalid characters"};
        }

        out[i] = static_cast<std::uint8_t>(
            static_cast<std::uint8_t>(hex_value(hi) << 4U) |
            hex_value(lo));
      }

      return Result<std::vector<std::uint8_t>>{std::move(out)};
    }

    [[nodiscard]] Result<std::uint32_t> parse_u32(
        std::string_view input) noexcept
    {
      if (input.empty())
      {
        return Result<std::uint32_t>{
            ErrorCode::invalid_argument,
            "number cannot be empty"};
      }

      std::uint32_t value = 0;

      const auto *first = input.data();
      const auto *last = input.data() + input.size();

      const auto result = std::from_chars(first, last, value);

      if (result.ec != std::errc{} || result.ptr != last)
      {
        return Result<std::uint32_t>{
            ErrorCode::invalid_argument,
            "invalid number"};
      }

      return Result<std::uint32_t>{value};
    }

    struct EncodedPasswordHash final
    {
      std::uint32_t iterations{0};
      std::vector<std::uint8_t> salt{};
      std::vector<std::uint8_t> hash{};
    };

    [[nodiscard]] Result<EncodedPasswordHash> parse_encoded_password_hash(
        std::string_view encoded_hash) noexcept
    {
      const std::size_t first = encoded_hash.find('$');
      if (first == std::string_view::npos)
      {
        return Result<EncodedPasswordHash>{
            ErrorCode::invalid_argument,
            "encoded password hash is missing algorithm"};
      }

      const std::size_t second = encoded_hash.find('$', first + 1);
      if (second == std::string_view::npos)
      {
        return Result<EncodedPasswordHash>{
            ErrorCode::invalid_argument,
            "encoded password hash is missing iterations"};
      }

      const std::size_t third = encoded_hash.find('$', second + 1);
      if (third == std::string_view::npos)
      {
        return Result<EncodedPasswordHash>{
            ErrorCode::invalid_argument,
            "encoded password hash is missing salt"};
      }

      if (encoded_hash.find('$', third + 1) != std::string_view::npos)
      {
        return Result<EncodedPasswordHash>{
            ErrorCode::invalid_argument,
            "encoded password hash contains too many fields"};
      }

      const std::string_view alg = encoded_hash.substr(0, first);
      const std::string_view iterations_text =
          encoded_hash.substr(first + 1, second - first - 1);
      const std::string_view salt_hex =
          encoded_hash.substr(second + 1, third - second - 1);
      const std::string_view hash_hex =
          encoded_hash.substr(third + 1);

      if (alg != k_pdkdf2_sha256_prefix)
      {
        return Result<EncodedPasswordHash>{
            ErrorCode::not_supported,
            "unsupported password hash algorithm"};
      }

      auto iterations = parse_u32(iterations_text);
      if (!iterations.ok())
        return Result<EncodedPasswordHash>{iterations.error()};

      auto salt = hex_decode(salt_hex);
      if (!salt.ok())
        return Result<EncodedPasswordHash>{salt.error()};

      auto hash = hex_decode(hash_hex);
      if (!hash.ok())
        return Result<EncodedPasswordHash>{hash.error()};

      if (iterations.value() < k_min_iterations)
      {
        return Result<EncodedPasswordHash>{
            ErrorCode::invalid_argument,
            "password hash iteration count is too low"};
      }

      if (salt.value().size() < k_min_salt_size)
      {
        return Result<EncodedPasswordHash>{
            ErrorCode::invalid_argument,
            "password hash salt is too small"};
      }

      if (hash.value().size() < k_min_hash_size)
      {
        return Result<EncodedPasswordHash>{
            ErrorCode::invalid_argument,
            "password hash output is too small"};
      }

      EncodedPasswordHash parsed{};
      parsed.iterations = iterations.value();
      parsed.salt = std::move(salt.value());
      parsed.hash = std::move(hash.value());

      return Result<EncodedPasswordHash>{std::move(parsed)};
    }

    [[nodiscard]] Result<void> pbkdf2_sha256(
        std::string_view password,
        std::span<const std::uint8_t> salt,
        std::uint32_t iterations,
        std::span<std::uint8_t> out) noexcept
    {
      if (password.empty())
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "password cannot be empty"};
      }

      if (salt.empty())
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "salt cannot be empty"};
      }

      if (iterations < k_min_iterations)
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "password hash iteration count is too low"};
      }

      if (out.empty())
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "password hash output cannot be empty"};
      }

      if (password.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max()))
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "password is too large"};
      }

      if (salt.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max()))
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "salt is too large"};
      }

      if (out.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max()))
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "password hash output is too large"};
      }

      if (iterations >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()))
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "password hash iteration count is too large"};
      }

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
      const int rc = PKCS5_PBKDF2_HMAC(
          password.data(),
          static_cast<int>(password.size()),
          salt.data(),
          static_cast<int>(salt.size()),
          static_cast<int>(iterations),
          EVP_sha256(),
          static_cast<int>(out.size()),
          out.data());

      if (rc != 1)
      {
        return Result<void>{
            ErrorCode::key_derivation_failed,
            "PKCS5_PBKDF2_HMAC failed"};
      }

      return Result<void>{};
#else
      (void)password;
      (void)salt;
      (void)iterations;
      (void)out;

      return Result<void>{
          ErrorCode::provider_unavailable,
          "OpenSSL provider not enabled"};
#endif
    }

    [[nodiscard]] Result<void> validate_password_params(
        const PasswordHashParams &params) noexcept
    {
      if (params.alg != PasswordHashAlg::pbkdf2_sha256)
      {
        return Result<void>{
            ErrorCode::not_supported,
            "unsupported password hash algorithm"};
      }

      if (params.iterations < k_min_iterations)
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "password hash iteration count is too low"};
      }

      if (params.salt_size < k_min_salt_size)
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "password hash salt size is too small"};
      }

      if (params.hash_size < k_min_hash_size)
      {
        return Result<void>{
            ErrorCode::invalid_argument,
            "password hash output size is too small"};
      }

      return Result<void>{};
    }

  } // namespace

  Result<std::string> password_hash(
      std::string_view password,
      const PasswordHashParams &params) noexcept
  {
    auto validation = validate_password_params(params);
    if (!validation.ok())
      return Result<std::string>{validation.error()};

    if (password.empty())
    {
      return Result<std::string>{
          ErrorCode::invalid_argument,
          "password cannot be empty"};
    }

    std::vector<std::uint8_t> salt;
    salt.resize(params.salt_size);

    auto random = random_bytes(salt);
    if (!random.ok())
      return Result<std::string>{random.error()};

    std::vector<std::uint8_t> derived;
    derived.resize(params.hash_size);

    auto derived_result = pbkdf2_sha256(
        password,
        salt,
        params.iterations,
        derived);

    if (!derived_result.ok())
      return Result<std::string>{derived_result.error()};

    std::string encoded;
    encoded.reserve(
        k_pdkdf2_sha256_prefix.size() +
        1 +
        10 +
        1 +
        salt.size() * 2 +
        1 +
        derived.size() * 2);

    encoded += k_pdkdf2_sha256_prefix;
    encoded += '$';
    encoded += std::to_string(params.iterations);
    encoded += '$';
    encoded += hex_lower(salt);
    encoded += '$';
    encoded += hex_lower(derived);

    return Result<std::string>{std::move(encoded)};
  }

  Result<bool> password_verify(
      std::string_view password,
      std::string_view encoded_hash) noexcept
  {
    if (password.empty())
    {
      return Result<bool>{
          ErrorCode::invalid_argument,
          "password cannot be empty"};
    }

    if (encoded_hash.empty())
    {
      return Result<bool>{
          ErrorCode::invalid_argument,
          "encoded password hash cannot be empty"};
    }

    auto parsed = parse_encoded_password_hash(encoded_hash);
    if (!parsed.ok())
      return Result<bool>{parsed.error()};

    std::vector<std::uint8_t> derived;
    derived.resize(parsed.value().hash.size());

    auto derived_result = pbkdf2_sha256(
        password,
        parsed.value().salt,
        parsed.value().iterations,
        derived);

    if (!derived_result.ok())
      return Result<bool>{derived_result.error()};

    const bool matched = constant_time_equal(derived, parsed.value().hash);

    return Result<bool>{matched};
  }

} // namespace vix::crypto
