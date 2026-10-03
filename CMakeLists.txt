# AuroraSecret - batch file and folder encryption.
#
# The only external dependency is Monocypher, which this file either picks up
# from third_party/monocypher, from -DAURORASECRET_MONOCYPHER_DIR=<dir>, or
# downloads once at configure time.
cmake_minimum_required(VERSION 3.16)

project(AuroraSecret
  VERSION 1.0.0
  DESCRIPTION "Command line batch file and folder encryption"
  LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(AURORASECRET_BUILD_TESTS "Build and register the test suite" ON)
option(AURORASECRET_FETCH_MONOCYPHER "Download Monocypher when it is not vendored" ON)
option(AURORASECRET_MSVC_STATIC_RUNTIME "Link the MSVC runtime statically" OFF)
option(AURORASECRET_LINUX_STATIC "Produce a fully static binary on Linux" OFF)
option(AURORASECRET_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
set(AURORASECRET_MONOCYPHER_VERSION "4.0.2" CACHE STRING
    "Monocypher version to download when it is not vendored")
set(AURORASECRET_MONOCYPHER_DIR "" CACHE PATH
    "Existing Monocypher source directory (must contain src/monocypher.c)")

if(MSVC AND AURORASECRET_MSVC_STATIC_RUNTIME)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
      CACHE STRING "MSVC runtime library" FORCE)
endif()

# ---------------------------------------------------------------------------
# Monocypher (cryptography)
#
# Three ways to get it, in order of preference:
#   1. -DAURORASECRET_MONOCYPHER_DIR=<checkout>  (a checkout or a bare pair)
#   2. third_party/monocypher/                   (vendored, the normal source)
#   3. a verified download into the build tree   (fallback)
# The source file and the include directory are tracked separately, because a
# Monocypher checkout keeps them in src/ while the vendored copy does not.
# ---------------------------------------------------------------------------
set(_aurora_monocypher_source "")
set(_aurora_monocypher_include "")

if(AURORASECRET_MONOCYPHER_DIR)
  if(EXISTS "${AURORASECRET_MONOCYPHER_DIR}/src/monocypher.c")
    set(_aurora_monocypher_source "${AURORASECRET_MONOCYPHER_DIR}/src/monocypher.c")
    set(_aurora_monocypher_include "${AURORASECRET_MONOCYPHER_DIR}/src")
  elseif(EXISTS "${AURORASECRET_MONOCYPHER_DIR}/monocypher.c")
    set(_aurora_monocypher_source "${AURORASECRET_MONOCYPHER_DIR}/monocypher.c")
    set(_aurora_monocypher_include "${AURORASECRET_MONOCYPHER_DIR}")
  else()
    message(FATAL_ERROR
      "-DAURORASECRET_MONOCYPHER_DIR=${AURORASECRET_MONOCYPHER_DIR} does not "
      "contain monocypher.c (neither at its root nor in src/).")
  endif()
  message(STATUS "Monocypher: using ${_aurora_monocypher_source}")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher/monocypher.c")
  set(_aurora_monocypher_source
      "${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher/monocypher.c")
  set(_aurora_monocypher_include
      "${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher")
  message(STATUS "Monocypher: using the vendored copy in third_party/monocypher/")
elseif(AURORASECRET_FETCH_MONOCYPHER)
  set(_aurora_monocypher_dir "${CMAKE_BINARY_DIR}/_deps/monocypher")
  set(_aurora_monocypher_roots
      "https://raw.githubusercontent.com/LoupVaillant/Monocypher/${AURORASECRET_MONOCYPHER_VERSION}"
      "https://github.com/LoupVaillant/Monocypher/raw/${AURORASECRET_MONOCYPHER_VERSION}")

  # Known good checksums, so a proxy or an error page cannot slip through.
  set(_aurora_monocypher_sha256_c "")
  set(_aurora_monocypher_sha256_h "")
  if(AURORASECRET_MONOCYPHER_VERSION STREQUAL "4.0.2")
    set(_aurora_monocypher_sha256_c
        "02174117935699d418443c75a558a287deb06ef8cf7c1adced61d9047d2f323d")
    set(_aurora_monocypher_sha256_h
        "fcaf6ed771358bb4f40fba016f6518ae86ec02b1b877d2cc35ad92d3a26fd7b3")
  endif()

  foreach(_file IN ITEMS src/monocypher.c src/monocypher.h)
    if(EXISTS "${_aurora_monocypher_dir}/${_file}")
      continue()
    endif()
    if(_file STREQUAL "src/monocypher.c")
      set(_expected_sha256 "${_aurora_monocypher_sha256_c}")
    else()
      set(_expected_sha256 "${_aurora_monocypher_sha256_h}")
    endif()
    file(MAKE_DIRECTORY "${_aurora_monocypher_dir}/src")
    set(_downloaded FALSE)
    foreach(_root IN LISTS _aurora_monocypher_roots)
      if(_downloaded)
        continue()
      endif()
      message(STATUS "Downloading Monocypher ${AURORASECRET_MONOCYPHER_VERSION}: ${_file}")
      file(DOWNLOAD "${_root}/${_file}" "${_aurora_monocypher_dir}/${_file}"
           TLS_VERIFY ON STATUS _download_status)
      list(GET _download_status 0 _download_code)
      if(_download_code EQUAL 0 AND EXISTS "${_aurora_monocypher_dir}/${_file}")
        file(SIZE "${_aurora_monocypher_dir}/${_file}" _download_size)
        if(_download_size LESS 1000)
          message(STATUS "  rejected: only ${_download_size} bytes, probably an error page")
        elseif(_expected_sha256)
          file(SHA256 "${_aurora_monocypher_dir}/${_file}" _actual_sha256)
          if(_actual_sha256 STREQUAL _expected_sha256)
            set(_downloaded TRUE)
          else()
            message(STATUS "  rejected: checksum ${_actual_sha256} does not match")
          endif()
        else()
          set(_downloaded TRUE)
        endif()
      else()
        list(GET _download_status 1 _download_message)
        message(STATUS "  rejected: ${_download_message}")
      endif()
      if(NOT _downloaded)
        file(REMOVE "${_aurora_monocypher_dir}/${_file}")
      endif()
    endforeach()
    if(NOT _downloaded)
      message(FATAL_ERROR
        "Could not download a verified ${_file} from GitHub.\n"
        "The vendored copy under third_party/monocypher/ is the normal source;\n"
        "restore it, or fetch the sources yourself:\n"
        "  git clone --depth 1 --branch ${AURORASECRET_MONOCYPHER_VERSION} "
        "https://github.com/LoupVaillant/Monocypher\n"
        "  copy src/monocypher.c and src/monocypher.h into third_party/monocypher/\n"
        "or configure with -DAURORASECRET_MONOCYPHER_DIR=<path to Monocypher>.")
    endif()
  endforeach()

  file(READ "${_aurora_monocypher_dir}/src/monocypher.h" _monocypher_header LIMIT 200000)
  if(NOT _monocypher_header MATCHES "crypto_aead_lock" OR
     NOT _monocypher_header MATCHES "crypto_argon2")
    message(FATAL_ERROR
      "The downloaded monocypher.h does not look like Monocypher 4.x. "
      "Vendor the sources in third_party/monocypher/ or point "
      "-DAURORASECRET_MONOCYPHER_DIR at a valid checkout.")
  endif()
  set(_aurora_monocypher_source "${_aurora_monocypher_dir}/src/monocypher.c")
  set(_aurora_monocypher_include "${_aurora_monocypher_dir}/src")
  message(STATUS "Monocypher ${AURORASECRET_MONOCYPHER_VERSION}: downloaded into ${_aurora_monocypher_dir}")
else()
  message(FATAL_ERROR
    "Monocypher sources not found. Place monocypher.c and monocypher.h in "
    "third_party/monocypher/, pass -DAURORASECRET_MONOCYPHER_DIR=<dir>, or "
    "configure with -DAURORASECRET_FETCH_MONOCYPHER=ON (default) and network "
    "access.")
endif()

add_library(monocypher STATIC "${_aurora_monocypher_source}")
target_include_directories(monocypher PUBLIC "${_aurora_monocypher_include}")
set_target_properties(monocypher PROPERTIES
  C_STANDARD 99
  POSITION_INDEPENDENT_CODE ON)
if(MSVC)
  target_compile_options(monocypher PRIVATE /W0 /utf-8)
else()
  target_compile_options(monocypher PRIVATE -w)
endif()

# ---------------------------------------------------------------------------
# AuroraSecret
# ---------------------------------------------------------------------------
add_library(aurorasecret_core STATIC
  src/cli.cpp
  src/container.cpp
  src/crypto.cpp
  src/extract.cpp
  src/fsutil.cpp
  src/fileio.cpp
  src/log.cpp
  src/password.cpp
  src/random.cpp
  src/util.cpp
  src/walk.cpp)

target_include_directories(aurorasecret_core
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(aurorasecret_core PRIVATE monocypher)
set_target_properties(aurorasecret_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(WIN32)
  # BCryptGenRandom lives in random.cpp, so every consumer (the executable and
  # the test binary) needs the library.
  target_link_libraries(aurorasecret_core PUBLIC bcrypt)
endif()

if(MSVC)
  target_compile_options(aurorasecret_core PRIVATE /W4 /permissive- /utf-8)
  target_compile_definitions(aurorasecret_core PRIVATE
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
    NOMINMAX)
else()
  target_compile_options(aurorasecret_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Keep the POSIX APIs (isatty, tcgetattr, getrandom, fileno, ...) visible even
# though the code is compiled with -std=c++17 instead of -std=gnu++17.
if(APPLE)
  target_compile_definitions(aurorasecret_core PRIVATE _DARWIN_C_SOURCE)
elseif(UNIX)
  target_compile_definitions(aurorasecret_core PRIVATE _DEFAULT_SOURCE)
endif()

if(AURORASECRET_WARNINGS_AS_ERRORS)
  if(MSVC)
    target_compile_options(aurorasecret_core PRIVATE /WX)
  else()
    target_compile_options(aurorasecret_core PRIVATE -Werror)
  endif()
endif()

# Version and commit stamps.
set(AURORASECRET_GIT_COMMIT "unknown")
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE _aurora_commit
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE _aurora_git_result)
  if(_aurora_git_result EQUAL 0 AND _aurora_commit)
    set(AURORASECRET_GIT_COMMIT "${_aurora_commit}")
  endif()
endif()
target_compile_definitions(aurorasecret_core PUBLIC
  AURORASECRET_VERSION_STRING="${PROJECT_VERSION}"
  AURORASECRET_GIT_COMMIT="${AURORASECRET_GIT_COMMIT}")

add_executable(aurorasecret src/main.cpp)
target_link_libraries(aurorasecret PRIVATE aurorasecret_core)

if(WIN32)
  # CommandLineToArgvW, used by main.cpp only.
  target_link_libraries(aurorasecret PRIVATE shell32)
endif()

if(UNIX AND NOT APPLE AND AURORASECRET_LINUX_STATIC)
  target_link_options(aurorasecret PRIVATE -static)
  message(STATUS "Linux: linking a fully static binary")
endif()

include(GNUInstallDirs)
install(TARGETS aurorasecret RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES README.md LICENSE DESTINATION "${CMAKE_INSTALL_DOCDIR}")

if(AURORASECRET_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

message(STATUS "AuroraSecret ${PROJECT_VERSION} (commit ${AURORASECRET_GIT_COMMIT})")