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

/**
 * @file version.hpp
 * @brief Version information for the vix::crypto module.
 *
 * @details
 * This header exposes compile-time constants describing the version of the
 * `vix::crypto` module.
 *
 * The version follows semantic versioning:
 *   MAJOR.MINOR.PATCH
 *
 * - MAJOR: incompatible API or ABI changes
 * - MINOR: backward-compatible feature additions
 * - PATCH: backward-compatible bug fixes
 *
 * An explicit ABI version is also provided to allow consumers to detect
 * binary incompatibilities.
 */

namespace vix::crypto
{

  /// Major version (breaking API changes).
  inline constexpr int version_major = 0;

  /// Minor version (backward-compatible features).
  inline constexpr int version_minor = 1;

  /// Patch version (bug fixes).
  inline constexpr int version_patch = 0;

  /// Optional pre-release tag (empty when not used).
  inline constexpr const char *version_prerelease = "";

  /// Optional build metadata (empty when not used).
  inline constexpr const char *version_metadata = "";

  /**
   * @brief Human-readable version string.
   *
   * Format: "MAJOR.MINOR.PATCH".
   */
  inline constexpr const char *version_string = "0.3.0";

  /**
   * @brief ABI version.
   *
   * This value must be incremented whenever a change breaks binary
   * compatibility, even if the semantic version does not change.
   */
  inline constexpr int abi_version = 0;

} // namespace vix::crypto

#endif // VIX_CRYPTO_VERSION_HPP
