/**
 *
 *  @file certificate.hpp
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
#ifndef VIX_CRYPTO_CERTIFICATE_HPP
#define VIX_CRYPTO_CERTIFICATE_HPP

#include <filesystem>
#include <string>
#include <vector>
#include <string_view>

#include <vix/crypto/Result.hpp>

/**
 * @file certificate.hpp
 * @brief TLS certificate inspection helpers.
 *
 * @details
 * This header provides lightweight utilities for inspecting X.509 TLS
 * certificates. It is useful for deployment tooling such as `vix proxy`
 * because it can validate certificate files before Nginx is reloaded.
 *
 * Scope:
 * - certificate file existence
 * - PEM parsing
 * - expiration status
 * - subject and issuer extraction
 * - DNS name extraction
 *
 * This API does not generate certificates and does not integrate with ACME
 * or Let's Encrypt. Those responsibilities belong to deployment tooling.
 */

namespace vix::crypto
{
  /**
   * @brief Basic information extracted from a TLS certificate.
   */
  struct CertificateInfo final
  {
    /**
     * @brief Whether the certificate file exists.
     */
    bool exists{false};

    /**
     * @brief Whether the certificate file was readable.
     */
    bool readable{false};

    /**
     * @brief Whether the certificate was parsed successfully.
     */
    bool validFormat{false};

    /**
     * @brief Whether the certificate is expired.
     */
    bool expired{false};

    /**
     * @brief Certificate subject, when available.
     */
    std::string subject{};

    /**
     * @brief Certificate issuer, when available.
     */
    std::string issuer{};

    /**
     * @brief NotBefore field as a string, when available.
     */
    std::string notBefore{};

    /**
     * @brief NotAfter field as a string, when available.
     */
    std::string notAfter{};

    /**
     * @brief DNS names extracted from the certificate SAN extension.
     */
    std::vector<std::string> dnsNames{};
  };

  /**
   * @brief Inspect a PEM-encoded TLS certificate file.
   *
   * @param path Certificate path.
   * @return Certificate information on success, or an explicit error on failure.
   */
  Result<CertificateInfo> inspect_certificate(
      const std::filesystem::path &path) noexcept;

  /**
   * @brief Check whether a certificate matches a DNS domain.
   *
   * The check uses DNS names from the Subject Alternative Name extension.
   * Wildcards are supported only in the common form `*.example.com`.
   *
   * @param info Certificate information returned by inspect_certificate().
   * @param domain Domain to validate.
   * @return true if the certificate contains a matching DNS name.
   */
  bool certificate_matches_domain(
      const CertificateInfo &info,
      std::string_view domain) noexcept;

} // namespace vix::crypto

#endif // VIX_CRYPTO_CERTIFICATE_HPP
