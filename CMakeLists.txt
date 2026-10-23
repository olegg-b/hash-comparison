cmake_minimum_required(VERSION 3.16)
project(hash_comparison LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(NATIVE "Optimize for the build machine (-march=native)" OFF)

find_package(Threads REQUIRED)

# OpenSSL is optional: without it the sha256 candidate is disabled.
find_package(OpenSSL QUIET COMPONENTS Crypto)

# TBB is optional: without it BLAKE3 builds single-threaded.
find_package(TBB QUIET)

# CMake 4.x compatibility for older deps
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
if(POLICY CMP0149)
    cmake_policy(SET CMP0149 NEW)
endif()
if(POLICY CMP0126)
    cmake_policy(SET CMP0126 OLD)
endif()
if(POLICY CMP0125)
    cmake_policy(SET CMP0125 OLD)
endif()
if(POLICY CMP0128)
    cmake_policy(SET CMP0128 NEW)
endif()

include(FetchContent)
file(DOWNLOAD
     https://github.com/cpm-cmake/CPM.cmake/releases/download/v0.42.3/CPM.cmake
     ${CMAKE_BINARY_DIR}/CPM.cmake)
include(${CMAKE_BINARY_DIR}/CPM.cmake)

CPMAddPackage(
    NAME CLI11
    GITHUB_REPOSITORY CLIUtils/CLI11
    GIT_TAG v2.6.2
    EXCLUDE_FROM_ALL YES
    SYSTEM YES
    OPTIONS "CLI11_BUILD_DOCS OFF" "CLI11_BUILD_EXAMPLES OFF" "CLI11_BUILD_TESTS OFF"
            "CLI11_INSTALL OFF"
)

# xxHash: compile xxhash.c + the x86 runtime dispatcher so XXH3 selects the
# best SIMD level at run time (SSE2/AVX2/AVX512). Consumers include xxhash.h
# followed by xxh_x86dispatch.h, which reroutes the XXH3 entry points to the
# dispatcher (the upstream xxhsum "dispatch" build does exactly this).
CPMAddPackage(
    NAME xxhash
    GITHUB_REPOSITORY Cyan4973/xxHash
    GIT_TAG v0.8.4
    DOWNLOAD_ONLY YES
)
add_library(xxhash STATIC)
target_sources(xxhash PRIVATE
    ${xxhash_SOURCE_DIR}/xxhash.c
    ${xxhash_SOURCE_DIR}/xxh_x86dispatch.c
)
target_include_directories(xxhash PUBLIC ${xxhash_SOURCE_DIR})
target_compile_definitions(xxhash PUBLIC XXH_STATIC_LINKING_ONLY=1)

# aws-checksums provides CRC-64/NVME with hardware paths and the
# combine(crc1, crc2, len2) operation. It expects aws-c-common's CMake modules
# and target to be visible in the parent scope (the AWS CRT superbuild pattern,
# enabled here via IN_SOURCE_BUILD).
CPMAddPackage(
    NAME aws-c-common
    GITHUB_REPOSITORY awslabs/aws-c-common
    GIT_TAG v1.0.3
    EXCLUDE_FROM_ALL YES
    SYSTEM YES
    OPTIONS "BUILD_TESTING OFF"
)
list(APPEND CMAKE_MODULE_PATH ${aws-c-common_SOURCE_DIR}/cmake)

CPMAddPackage(
    NAME aws-checksums
    GITHUB_REPOSITORY awslabs/aws-checksums
    GIT_TAG v1.0.1
    EXCLUDE_FROM_ALL YES
    SYSTEM YES
    OPTIONS "IN_SOURCE_BUILD ON" "BUILD_TESTING OFF"
)

# BLAKE3: official C implementation with runtime-dispatched SIMD (asm paths).
# Multithreading via oneTBB is enabled automatically if TBB is found at configure time.
# Install libtbb-dev to enable multithreaded BLAKE3.
CPMAddPackage(
    NAME blake3
    GITHUB_REPOSITORY BLAKE3-team/BLAKE3
    GIT_TAG 1.8.7
    SOURCE_SUBDIR c
    EXCLUDE_FROM_ALL YES
    SYSTEM YES
    OPTIONS "BLAKE3_USE_TBB ${TBB_FOUND}" "BLAKE3_FETCH_TBB OFF"
)

add_executable(hash-bench src/main.cpp)
target_link_libraries(hash-bench PRIVATE
    CLI11::CLI11
    xxhash
    aws-checksums
    blake3
    Threads::Threads
)
if(OpenSSL_FOUND)
    target_link_libraries(hash-bench PRIVATE OpenSSL::Crypto)
    target_compile_definitions(hash-bench PRIVATE HASH_BENCH_HAVE_OPENSSL=1)
else()
    message(WARNING "OpenSSL not found: the sha256 candidate will be disabled. Install libssl-dev to enable it.")
endif()
if(TBB_FOUND)
    target_link_libraries(hash-bench PRIVATE TBB::tbb)
    target_compile_definitions(hash-bench PRIVATE HASH_BENCH_HAVE_TBB=1)
else()
    message(WARNING "TBB not found: BLAKE3 will build single-threaded. Install libtbb-dev to enable multithreaded BLAKE3.")
endif()
if(NATIVE)
    target_compile_options(hash-bench PRIVATE -march=native)
endif()
target_compile_options(hash-bench PRIVATE -Wall -Wextra)

# Make include dirs explicit in case the dependency targets do not export them.
if(TARGET aws-checksums)
    target_include_directories(hash-bench PRIVATE ${aws-checksums_SOURCE_DIR}/include)
endif()
if(TARGET blake3)
    target_include_directories(hash-bench PRIVATE ${blake3_SOURCE_DIR}/c)
endif()