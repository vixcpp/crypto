#  @file CMakeLists.txt
#  @author Gaspard Kirira
#
#  Copyright 2025, Gaspard Kirira.
#  All rights reserved.
#  https://github.com/vixcpp/vix
#  Use of this source code is governed by a MIT license
#  that can be found in the License file.
#
# ====================================================================
# Vix.cpp - Crypto Module Examples
# ====================================================================
# Purpose:
#   Small, self-contained examples demonstrating the crypto primitives.
#   These binaries are meant for developers and documentation, not install.
# ====================================================================

cmake_minimum_required(VERSION 3.20)

# Examples are only meaningful if the crypto target exists
if (NOT TARGET vix::crypto)
  message(FATAL_ERROR "[crypto/examples] vix::crypto target not found")
endif()

# Helper macro to reduce boilerplate
function(vix_crypto_example name)
  add_executable(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE vix::crypto)

  target_compile_features(${name} PRIVATE cxx_std_20)

  if (TARGET vix_warnings)
    target_link_libraries(${name} PRIVATE vix_warnings)
  endif()

  if (VIX_ENABLE_SANITIZERS AND TARGET vix_sanitizers)
    target_link_libraries(${name} PRIVATE vix_sanitizers)
  endif()
endfunction()

# --------------------------------------------------------------------
# Examples
# --------------------------------------------------------------------

vix_crypto_example(hash_sha256)
vix_crypto_example(aead_roundtrip)
vix_crypto_example(sign_verify)
