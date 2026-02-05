/**
 *
 *  @file Result.hpp
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
#ifndef VIX_CRYPTO_RESULT_HPP
#define VIX_CRYPTO_RESULT_HPP

#include <utility>
#include <type_traits>

#include <vix/crypto/Error.hpp>

namespace vix::crypto
{

  /**
   * @brief Explicit result type for crypto operations.
   *
   * This is a minimal expected-like type:
   * - Holds either a value T or an Error
   * - No exceptions
   * - Trivial control flow
   *
   * Design goals:
   * - Make failure explicit at call sites
   * - Avoid hidden control flow
   * - Cheap and predictable
   */
  template <typename T>
  class Result
  {
  public:
    using value_type = T;

    /// Construct a successful result
    constexpr Result(const T &value)
        : has_value_(true)
    {
      new (&storage_.value) T(value);
    }

    constexpr Result(T &&value)
        : has_value_(true)
    {
      new (&storage_.value) T(std::move(value));
    }

    /// Construct a failed result
    constexpr Result(Error err)
        : has_value_(false)
    {
      new (&storage_.error) Error(err);
    }

    constexpr Result(ErrorCode code, std::string_view msg = {})
        : Result(Error{code, msg})
    {
    }

    /// Copy
    Result(const Result &other)
        : has_value_(other.has_value_)
    {
      if (has_value_)
        new (&storage_.value) T(other.storage_.value);
      else
        new (&storage_.error) Error(other.storage_.error);
    }

    /// Move
    Result(Result &&other) noexcept(std::is_nothrow_move_constructible_v<T>)
        : has_value_(other.has_value_)
    {
      if (has_value_)
        new (&storage_.value) T(std::move(other.storage_.value));
      else
        new (&storage_.error) Error(other.storage_.error);
    }

    Result &operator=(Result other) noexcept
    {
      swap(other);
      return *this;
    }

    ~Result()
    {
      destroy();
    }

    /// True if result holds a value
    constexpr bool ok() const noexcept
    {
      return has_value_;
    }

    constexpr explicit operator bool() const noexcept
    {
      return ok();
    }

    /// Access the value (caller must ensure ok())
    T &value() &
    {
      return storage_.value;
    }

    const T &value() const &
    {
      return storage_.value;
    }

    T &&value() &&
    {
      return std::move(storage_.value);
    }

    /// Access the error (caller must ensure !ok())
    const Error &error() const noexcept
    {
      return storage_.error;
    }

    /// Swap helper
    void swap(Result &other) noexcept
    {
      using std::swap;

      if (has_value_ && other.has_value_)
      {
        swap(storage_.value, other.storage_.value);
      }
      else if (!has_value_ && !other.has_value_)
      {
        swap(storage_.error, other.storage_.error);
      }
      else
      {
        Result tmp(std::move(other));
        other.destroy();
        other.has_value_ = has_value_;
        if (has_value_)
          new (&other.storage_.value) T(std::move(storage_.value));
        else
          new (&other.storage_.error) Error(storage_.error);

        destroy();
        has_value_ = tmp.has_value_;
        if (tmp.has_value_)
          new (&storage_.value) T(std::move(tmp.storage_.value));
        else
          new (&storage_.error) Error(tmp.storage_.error);
      }
    }

  private:
    void destroy() noexcept
    {
      if (has_value_)
        storage_.value.~T();
      else
        storage_.error.~Error();
    }

    union Storage
    {
      T value;
      Error error;

      Storage() {}
      ~Storage() {}
    } storage_;

    bool has_value_{false};
  };

  /// Specialization for Result<void>
  template <>
  class Result<void>
  {
  public:
    constexpr Result() = default;
    constexpr Result(Error err)
        : error_(err)
    {
    }

    constexpr Result(ErrorCode code, std::string_view msg = {})
        : error_(Error{code, msg})
    {
    }

    constexpr bool ok() const noexcept
    {
      return error_.ok();
    }

    constexpr explicit operator bool() const noexcept
    {
      return ok();
    }

    const Error &error() const noexcept
    {
      return error_;
    }

  private:
    Error error_{};
  };

} // namespace vix::crypto

#endif // VIX_CRYPTO_RESULT_HPP
