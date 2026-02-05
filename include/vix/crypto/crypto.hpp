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
 * @brief Public entry point for the Vix crypto module.
 *
 * This header exposes the stable, explicit crypto API surface.
 * No heavy includes, no providers, no implementation details.
 *
 * Design principles:
 * - Explicit errors (no exceptions)
 * - Small, composable primitives
 * - Provider-agnostic interfaces
 * - Excellent developer experience (DX)
 */

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
