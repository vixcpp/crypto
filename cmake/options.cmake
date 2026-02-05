#  @file options.cmake
#  @author Gaspard Kirira
#
#  Copyright 2025, Gaspard Kirira. All rights reserved.
#  https://github.com/vixcpp/vix
#  Use of this source code is governed by a MIT license
#  that can be found in the License file.
#
# ====================================================================
# Vix.cpp - Crypto Module Options
# ====================================================================
# Purpose:
#   Centralize crypto module build options.
#   This file is safe to include from the umbrella build.
# ====================================================================

# Provider selection
option(VIX_CRYPTO_USE_OPENSSL "Enable OpenSSL provider for crypto primitives" ON)

# Dependency auto-provisioning (non-umbrella only)
option(VIX_CRYPTO_FETCH_UTILS "Auto-fetch vix::utils if missing" ON)
option(VIX_CRYPTO_FETCH_OPENSSL "Auto-fetch OpenSSL if missing (non-umbrella only)" OFF)

# Tests
option(VIX_CRYPTO_BUILD_TESTS "Build crypto module tests" OFF)
