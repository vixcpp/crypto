#  @file CMakeLists.txt
#  @author Gaspard Kirira
#
#  Copyright 2025, Gaspard Kirira. All rights reserved.
#  https://github.com/vixcpp/vix
#  Use of this source code is governed by a MIT license
#  that can be found in the License file.
#
# ====================================================================
# Vix.cpp - Crypto Module
# ====================================================================
# Purpose:
#   Modern cryptography primitives for Vix.
#   Provides explicit, auditable building blocks for secure runtimes:
#   randomness, hashing, HMAC, KDF, AEAD, and signatures.
#
#   Design goals:
#   - Explicit APIs (no hidden magic)
#   - Dependency-light, portable
#   - Default: no exceptions in public APIs (errors are explicit types)
#
#   Builds as STATIC when sources exist, otherwise as a header-only
#   INTERFACE target.
#
# Public Targets:
#   - vix_crypto   : The actual library target (STATIC or INTERFACE)
#   - vix::crypto  : Namespaced alias for consumers
#
# Public Dependencies:
#   - vix::utils (optional but recommended, for logging/bytes helpers)
#   - OpenSSL::Crypto (optional, provider for primitives when enabled)
#
# Installation/Export:
#   Installs into the umbrella export-set `VixTargets`.
# ====================================================================

cmake_minimum_required(VERSION 3.20)
project(vix_crypto VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)

# Global settings
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --------------------------------------------------------------------
# Umbrella build policy:
# When building inside the Vix umbrella, dependencies are managed by the
# umbrella (add_subdirectory order + options). Crypto must not
# FetchContent nor add sibling subdirectories in umbrella mode.
# --------------------------------------------------------------------
if (DEFINED VIX_UMBRELLA_BUILD AND VIX_UMBRELLA_BUILD)
  set(VIX_CRYPTO_FETCH_UTILS OFF CACHE BOOL "Auto-fetch vix::utils if missing" FORCE)
  set(VIX_CRYPTO_FETCH_OPENSSL OFF CACHE BOOL "Auto-fetch OpenSSL if missing" FORCE)
endif()

# Sources discovery
file(GLOB_RECURSE CRYPTO_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

# --------------------------------------------------------------------
# Options
# --------------------------------------------------------------------
option(VIX_CRYPTO_USE_OPENSSL "Enable OpenSSL provider for crypto primitives" ON)

option(VIX_CRYPTO_FETCH_UTILS "Auto-fetch vix::utils if missing" ON)
option(VIX_CRYPTO_FETCH_OPENSSL "Auto-fetch OpenSSL if missing (non-umbrella only)" OFF)

# --------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------

# vix::utils (optional but recommended)
if (DEFINED VIX_UMBRELLA_BUILD AND VIX_UMBRELLA_BUILD)
  # In umbrella mode, if utils exists, we link it; if not, we continue without it.
  # Crypto must remain usable without utils.
else()
  if (NOT TARGET vix::utils)
    if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/../utils/CMakeLists.txt")
      message(STATUS "[crypto] Adding utils from umbrella: ../utils")
      add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../utils" "utils")
    elseif (VIX_CRYPTO_FETCH_UTILS)
      include(FetchContent)
      message(STATUS "[crypto] Fetching vix::utils via FetchContent")
      FetchContent_Declare(vix_utils
        GIT_REPOSITORY https://github.com/vixcpp/utils.git
        GIT_TAG        v0.1.0
      )
      FetchContent_MakeAvailable(vix_utils)
    else()
      message(STATUS "[crypto] vix::utils not found (continuing without it).")
    endif()
  endif()
endif()

set(VIX_UTILS_TARGET "")
if (TARGET vix::utils)
  set(VIX_UTILS_TARGET vix::utils)
endif()

# OpenSSL provider (optional)
set(VIX_OPENSSL_TARGETS "")

if (VIX_CRYPTO_USE_OPENSSL)
  if (TARGET OpenSSL::Crypto)
    set(VIX_OPENSSL_TARGETS OpenSSL::Crypto)
  else()
    if (DEFINED VIX_UMBRELLA_BUILD AND VIX_UMBRELLA_BUILD)
      # In umbrella mode we do not search, we rely on umbrella toolchain.
      message(STATUS "[crypto] Umbrella build: OpenSSL::Crypto not found. Building without OpenSSL provider.")
      set(VIX_CRYPTO_USE_OPENSSL OFF)
    else()
      if (VIX_CRYPTO_FETCH_OPENSSL)
        # We intentionally avoid auto-fetching OpenSSL by default.
        # If enabled, user is expected to provide it via toolchain/package manager.
        message(STATUS "[crypto] VIX_CRYPTO_FETCH_OPENSSL=ON but no FetchContent provider is configured. "
                       "Please install OpenSSL and set OPENSSL_ROOT_DIR if needed.")
      endif()

      find_package(OpenSSL QUIET)
      if (OpenSSL_FOUND AND TARGET OpenSSL::Crypto)
        message(STATUS "[crypto] OpenSSL found -> provider enabled")
        set(VIX_OPENSSL_TARGETS OpenSSL::Crypto)
      else()
        message(STATUS "[crypto] OpenSSL not found -> provider disabled")
        set(VIX_CRYPTO_USE_OPENSSL OFF)
      endif()
    endif()
  endif()
endif()

# --------------------------------------------------------------------
# Target
# --------------------------------------------------------------------

# STATIC
if (CRYPTO_SOURCES)
  message(STATUS "[crypto] Building STATIC library with detected sources.")

  add_library(vix_crypto STATIC ${CRYPTO_SOURCES})
  add_library(vix::crypto ALIAS vix_crypto)

  target_compile_features(vix_crypto PUBLIC cxx_std_20)

  target_include_directories(vix_crypto
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  if (VIX_UTILS_TARGET)
    target_link_libraries(vix_crypto PUBLIC ${VIX_UTILS_TARGET})
  endif()

  if (VIX_OPENSSL_TARGETS)
    target_link_libraries(vix_crypto PUBLIC ${VIX_OPENSSL_TARGETS})
    target_compile_definitions(vix_crypto PUBLIC VIX_CRYPTO_HAS_OPENSSL=1)
  else()
    target_compile_definitions(vix_crypto PUBLIC VIX_CRYPTO_HAS_OPENSSL=0)
  endif()

  if (TARGET vix_warnings)
    target_link_libraries(vix_crypto PUBLIC vix_warnings)
  endif()

  if (VIX_ENABLE_SANITIZERS AND TARGET vix_sanitizers)
    target_link_libraries(vix_crypto PUBLIC vix_sanitizers)
  endif()

  set_target_properties(vix_crypto PROPERTIES
    OUTPUT_NAME vix_crypto
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    EXPORT_NAME crypto
  )

  install(TARGETS vix_crypto
    EXPORT VixTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  if (NOT (DEFINED VIX_UMBRELLA_BUILD AND VIX_UMBRELLA_BUILD))
    install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h")
  endif()

# HEADER-ONLY
else()
  message(STATUS "[crypto] Building HEADER-ONLY library (no sources).")

  add_library(vix_crypto INTERFACE)
  add_library(vix::crypto ALIAS vix_crypto)

  target_compile_features(vix_crypto INTERFACE cxx_std_20)

  target_include_directories(vix_crypto INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  if (VIX_UTILS_TARGET)
    target_link_libraries(vix_crypto INTERFACE ${VIX_UTILS_TARGET})
  endif()

  if (VIX_OPENSSL_TARGETS)
    target_link_libraries(vix_crypto INTERFACE ${VIX_OPENSSL_TARGETS})
    target_compile_definitions(vix_crypto INTERFACE VIX_CRYPTO_HAS_OPENSSL=1)
  else()
    target_compile_definitions(vix_crypto INTERFACE VIX_CRYPTO_HAS_OPENSSL=0)
  endif()

  if (VIX_ENABLE_SANITIZERS AND TARGET vix_sanitizers)
    target_link_libraries(vix_crypto INTERFACE vix_sanitizers)
  endif()

  install(TARGETS vix_crypto
    EXPORT VixTargets
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  if (NOT (DEFINED VIX_UMBRELLA_BUILD AND VIX_UMBRELLA_BUILD))
    install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h")
  endif()

endif()

# Tests
option(VIX_CRYPTO_BUILD_TESTS "Build crypto module tests" OFF)

if (VIX_CRYPTO_BUILD_TESTS)
  include(CTest)
  enable_testing()
  add_subdirectory(tests)
endif()

# Summary
message(STATUS "------------------------------------------------------")
message(STATUS "vix::crypto configured (${PROJECT_VERSION})")
if (CRYPTO_SOURCES)
  message(STATUS "Mode: STATIC / sources found")
else()
  message(STATUS "Mode: HEADER-ONLY / no sources")
endif()
message(STATUS "OpenSSL provider: ${VIX_CRYPTO_USE_OPENSSL} (VIX_CRYPTO_HAS_OPENSSL set accordingly)")
if (VIX_UTILS_TARGET)
  message(STATUS "Utils target: ${VIX_UTILS_TARGET}")
else()
  message(STATUS "Utils target: (none)")
endif()
message(STATUS "Include dir: ${CMAKE_CURRENT_SOURCE_DIR}/include (for <vix/crypto/...>)")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "------------------------------------------------------")
