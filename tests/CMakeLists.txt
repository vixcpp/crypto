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
# Vix.cpp - Crypto Module Tests
# ====================================================================
# Purpose:
#   Minimal, fast tests to validate core crypto invariants.
#   These tests are not exhaustive cryptographic proofs, but
#   sanity checks to ensure providers, wiring, and APIs work.
# ====================================================================

cmake_minimum_required(VERSION 3.20)

if (NOT TARGET vix::crypto)
  message(FATAL_ERROR "[crypto/tests] vix::crypto target not found")
endif()

include(CTest)
enable_testing()

add_executable(crypto_smoke
  crypto_smoke.cpp
)

target_compile_features(crypto_smoke
  PRIVATE
    cxx_std_20
)

target_link_libraries(crypto_smoke
  PRIVATE
    vix::crypto
)

if (TARGET vix_warnings)
  target_link_libraries(crypto_smoke
    PRIVATE
      vix_warnings
  )
endif()

if (VIX_ENABLE_SANITIZERS AND NOT MSVC)
  target_compile_options(crypto_smoke
    PRIVATE
      -fno-omit-frame-pointer
      -fsanitize=address,undefined
  )

  target_link_options(crypto_smoke
    PRIVATE
      -fsanitize=address,undefined
  )
endif()

add_test(
  NAME vix_crypto_smoke
  COMMAND crypto_smoke
)
