/**
 *
 *  @file crypto.hpp
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
#ifndef VIX_CRYPTO_CRYPTO_HPP
#define VIX_CRYPTO_CRYPTO_HPP

/**
 * @file crypto.hpp
 * @brief Public entry point for the Vix crypto module.
 *
 * @details
 * This header defines the stable, user-facing API surface of the
 * `vix::crypto` module.
 *
 * It is intended to be the single include required by applications
 * that consume cryptographic functionality provided by Vix.
 *
 * Scope:
 * - cryptographically secure randomness
 * - hashing and MACs
 * - key derivation and key handling
 * - authenticated encryption (AEAD)
 * - digital signatures
 *
 * Design principles:
 * - explicit error handling (no exceptions)
 * - small, composable primitives
 * - provider-agnostic interfaces
 * - predictable and transparent control flow
 * - excellent developer experience (DX)
 *
 * This header intentionally avoids including any provider-specific
 * or implementation details.
 */

// Versioning and error model
#include <vix/crypto/version.hpp>
#include <vix/crypto/Error.hpp>
#include <vix/crypto/Result.hpp>

// Core primitives
#include <vix/crypto/random.hpp>
#include <vix/crypto/hash.hpp>
#include <vix/crypto/hmac.hpp>
#include <vix/crypto/kdf.hpp>
#include <vix/crypto/keys.hpp>
#include <vix/crypto/aead.hpp>
#include <vix/crypto/signature.hpp>

// DX helpers (official, header-only)
#include <vix/crypto/bytes.hpp>
#include <vix/crypto/hex.hpp>
#include <vix/crypto/aead_easy.hpp>
#include <vix/crypto/signature_easy.hpp>

#endif // VIX_CRYPTO_CRYPTO_HPP
