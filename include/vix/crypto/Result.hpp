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

/**
 * @file Result.hpp
 * @brief Explicit result type for crypto APIs.
 *
 * @details
 * This header defines `vix::crypto::Result`, a minimal expected-like type used
 * throughout the crypto module to make failure explicit.
 *
 * Core principles:
 * - no exceptions
 * - explicit success / failure paths
 * - predictable control flow
 * - cheap to copy or move
 *
 * `Result<T>` holds either:
 * - a value of type `T`, or
 * - an `Error` describing the failure.
 *
 * A specialization for `Result<void>` is provided for operations that only
 * signal success or failure.
 */

namespace vix::crypto
{

  /**
   * @brief Explicit result type holding either a value or an error.
   *
   * @tparam T Value type on success.
   *
   * This type is intentionally small and low-level. It performs no allocation
   * and never throws.
   */
  template <typename T>
  class Result
  {
  public:
    using value_type = T;

    /**
     * @brief Construct a successful result from a value.
     */
    constexpr Result(const T &value)
        : has_value_(true)
    {
      new (&storage_.value) T(value);
    }

    /**
     * @brief Construct a successful result from a value (move).
     */
    constexpr Result(T &&value)
        : has_value_(true)
    {
      new (&storage_.value) T(std::move(value));
    }

    /**
     * @brief Construct a failed result from an error.
     */
    constexpr Result(Error err)
        : has_value_(false)
    {
      new (&storage_.error) Error(err);
    }

    /**
     * @brief Construct a failed result from an error code and optional message.
     */
    constexpr Result(ErrorCode code, std::string_view msg = {})
        : Result(Error{code, msg})
    {
    }

    /// Copy constructor.
    Result(const Result &other)
        : has_value_(other.has_value_)
    {
      if (has_value_)
        new (&storage_.value) T(other.storage_.value);
      else
        new (&storage_.error) Error(other.storage_.error);
    }

    /// Move constructor.
    Result(Result &&other) noexcept(std::is_nothrow_move_constructible_v<T>)
        : has_value_(other.has_value_)
    {
      if (has_value_)
        new (&storage_.value) T(std::move(other.storage_.value));
      else
        new (&storage_.error) Error(other.storage_.error);
    }

    /// Copy-and-swap assignment.
    Result &operator=(Result other) noexcept
    {
      swap(other);
      return *this;
    }

    ~Result()
    {
      destroy();
    }

    /**
     * @brief Check whether the result represents success.
     */
    constexpr bool ok() const noexcept
    {
      return has_value_;
    }

    /**
     * @brief Explicit boolean conversion.
     */
    constexpr explicit operator bool() const noexcept
    {
      return ok();
    }

    /**
     * @brief Access the contained value.
     *
     * @warning The caller must ensure `ok() == true`.
     */
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

    /**
     * @brief Access the error.
     *
     * @warning The caller must ensure `ok() == false`.
     */
    const Error &error() const noexcept
    {
      return storage_.error;
    }

    /**
     * @brief Swap two results.
     */
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

  /**
   * @brief Specialization of Result for void-returning operations.
   *
   * Represents either success or failure without an associated value.
   */
  template <>
  class Result<void>
  {
  public:
    /// Construct a successful result.
    constexpr Result() = default;

    /// Construct a failed result from an error.
    constexpr Result(Error err)
        : error_(err)
    {
    }

    /// Construct a failed result from an error code and optional message.
    constexpr Result(ErrorCode code, std::string_view msg = {})
        : error_(Error{code, msg})
    {
    }

    /**
     * @brief Check whether the result represents success.
     */
    constexpr bool ok() const noexcept
    {
      return error_.ok();
    }

    /**
     * @brief Explicit boolean conversion.
     */
    constexpr explicit operator bool() const noexcept
    {
      return ok();
    }

    /**
     * @brief Access the error.
     */
    const Error &error() const noexcept
    {
      return error_;
    }

  private:
    Error error_{};
  };

} // namespace vix::crypto

#endif // VIX_CRYPTO_RESULT_HPP
