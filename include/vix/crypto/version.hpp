/**
 *
 *  @file version.hpp
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
#ifndef VIX_CRYPTO_VERSION_HPP
#define VIX_CRYPTO_VERSION_HPP

namespace vix::crypto
{

  // Semantic versioning
  inline constexpr int version_major = 0;
  inline constexpr int version_minor = 1;
  inline constexpr int version_patch = 0;

  // Pre-release / metadata (empty when not used)
  inline constexpr const char *version_prerelease = "";
  inline constexpr const char *version_metadata = "";

  // Human-readable version string: "0.1.0"
  inline constexpr const char *version_string = "0.1.0";

  // ABI version (bump on breaking ABI changes)
  inline constexpr int abi_version = 0;

} // namespace vix::crypto

#endif // VIX_CRYPTO_VERSION_HPP
