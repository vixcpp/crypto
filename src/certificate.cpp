/**
 *
 *  @file certificate.cpp
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
#include <vix/crypto/certificate.hpp>

#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

namespace fs = std::filesystem;

namespace vix::crypto
{
  namespace
  {
    bool equals_ignore_ascii_case(
        std::string_view a,
        std::string_view b) noexcept
    {
      if (a.size() != b.size())
        return false;

      for (std::size_t i = 0; i < a.size(); ++i)
      {
        char ca = a[i];
        char cb = b[i];

        if (ca >= 'A' && ca <= 'Z')
          ca = static_cast<char>(ca - 'A' + 'a');

        if (cb >= 'A' && cb <= 'Z')
          cb = static_cast<char>(cb - 'A' + 'a');

        if (ca != cb)
          return false;
      }

      return true;
    }

    bool dns_pattern_matches(
        std::string_view pattern,
        std::string_view domain) noexcept
    {
      if (equals_ignore_ascii_case(pattern, domain))
        return true;

      constexpr std::string_view wildcard_prefix{"*."};

      if (pattern.size() <= wildcard_prefix.size() ||
          pattern.substr(0, wildcard_prefix.size()) != wildcard_prefix)
      {
        return false;
      }

      const std::string_view suffix = pattern.substr(1);

      if (domain.size() <= suffix.size())
        return false;

      if (!equals_ignore_ascii_case(
              domain.substr(domain.size() - suffix.size()),
              suffix))
      {
        return false;
      }

      const std::string_view left =
          domain.substr(0, domain.size() - suffix.size());

      return !left.empty() && left.find('.') == std::string_view::npos;
    }

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)

    struct FileCloser final
    {
      void operator()(FILE *file) const noexcept
      {
        if (file != nullptr)
          std::fclose(file);
      }
    };

    struct X509Deleter final
    {
      void operator()(X509 *cert) const noexcept
      {
        if (cert != nullptr)
          X509_free(cert);
      }
    };

    struct BioDeleter final
    {
      void operator()(BIO *bio) const noexcept
      {
        if (bio != nullptr)
          BIO_free(bio);
      }
    };

    using FilePtr = std::unique_ptr<FILE, FileCloser>;
    using X509Ptr = std::unique_ptr<X509, X509Deleter>;
    using BioPtr = std::unique_ptr<BIO, BioDeleter>;

    std::string x509_name_to_string(X509_NAME *name)
    {
      if (name == nullptr)
        return {};

      BioPtr bio(BIO_new(BIO_s_mem()));

      if (!bio)
        return {};

      if (X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253) < 0)
        return {};

      char *data = nullptr;
      const long size = BIO_get_mem_data(bio.get(), &data);

      if (data == nullptr || size <= 0)
        return {};

      return std::string(data, static_cast<std::size_t>(size));
    }

    std::string asn1_time_to_string(const ASN1_TIME *time)
    {
      if (time == nullptr)
        return {};

      BioPtr bio(BIO_new(BIO_s_mem()));

      if (!bio)
        return {};

      if (ASN1_TIME_print(bio.get(), time) != 1)
        return {};

      char *data = nullptr;
      const long size = BIO_get_mem_data(bio.get(), &data);

      if (data == nullptr || size <= 0)
        return {};

      return std::string(data, static_cast<std::size_t>(size));
    }

    bool certificate_is_expired(const ASN1_TIME *not_after)
    {
      if (not_after == nullptr)
        return true;

      return X509_cmp_current_time(not_after) < 0;
    }

    std::vector<std::string> extract_dns_names(X509 *cert)
    {
      std::vector<std::string> names;

      if (cert == nullptr)
        return names;

      GENERAL_NAMES *general_names =
          static_cast<GENERAL_NAMES *>(
              X509_get_ext_d2i(
                  cert,
                  NID_subject_alt_name,
                  nullptr,
                  nullptr));

      if (general_names == nullptr)
        return names;

      const int count = sk_GENERAL_NAME_num(general_names);

      for (int i = 0; i < count; ++i)
      {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(general_names, i);

        if (name == nullptr || name->type != GEN_DNS)
          continue;

        const ASN1_IA5STRING *dns = name->d.dNSName;

        if (dns == nullptr)
          continue;

        const unsigned char *data = ASN1_STRING_get0_data(dns);
        const int length = ASN1_STRING_length(dns);

        if (data == nullptr || length <= 0)
          continue;

        names.emplace_back(
            reinterpret_cast<const char *>(data),
            static_cast<std::size_t>(length));
      }

      GENERAL_NAMES_free(general_names);
      return names;
    }

#endif
  }

  Result<CertificateInfo> inspect_certificate(
      const std::filesystem::path &path) noexcept
  {
    CertificateInfo info{};

    std::error_code ec;

    info.exists = fs::exists(path, ec);

    if (ec || !info.exists)
    {
      return Result<CertificateInfo>{
          ErrorCode::invalid_argument,
          "certificate file does not exist"};
    }

    if (!fs::is_regular_file(path, ec))
    {
      return Result<CertificateInfo>{
          ErrorCode::invalid_argument,
          "certificate path is not a regular file"};
    }

#if defined(VIX_CRYPTO_HAS_OPENSSL) && (VIX_CRYPTO_HAS_OPENSSL == 1)

    FilePtr file(std::fopen(path.string().c_str(), "rb"));

    if (!file)
    {
      return Result<CertificateInfo>{
          ErrorCode::invalid_argument,
          "certificate file is not readable"};
    }

    info.readable = true;

    X509Ptr cert(PEM_read_X509(file.get(), nullptr, nullptr, nullptr));

    if (!cert)
    {
      return Result<CertificateInfo>{
          ErrorCode::invalid_argument,
          "certificate is not a valid PEM X.509 certificate"};
    }

    info.validFormat = true;
    info.subject = x509_name_to_string(X509_get_subject_name(cert.get()));
    info.issuer = x509_name_to_string(X509_get_issuer_name(cert.get()));
    info.notBefore = asn1_time_to_string(X509_get0_notBefore(cert.get()));
    info.notAfter = asn1_time_to_string(X509_get0_notAfter(cert.get()));
    info.expired = certificate_is_expired(X509_get0_notAfter(cert.get()));
    info.dnsNames = extract_dns_names(cert.get());

    return Result<CertificateInfo>{std::move(info)};

#else

    (void)path;

    return Result<CertificateInfo>{
        ErrorCode::provider_unavailable,
        "OpenSSL provider not enabled"};

#endif
  }

  bool certificate_matches_domain(
      const CertificateInfo &info,
      std::string_view domain) noexcept
  {
    if (domain.empty())
      return false;

    for (const auto &name : info.dnsNames)
    {
      if (dns_pattern_matches(name, domain))
        return true;
    }

    return false;
  }

} // namespace vix::crypto
