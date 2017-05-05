# export PATH="$PWD/../bfprefix/bin:$PATH"
# cmake ..

cmake_minimum_required(VERSION 3.6)
project(hypervisor C CXX)

include(ExternalProject)
find_package(Git REQUIRED)

set(BFPREFIX "${CMAKE_SOURCE_DIR}/bfprefix")

# ------------------------------------------------------------------------------
# Repos
# ------------------------------------------------------------------------------

set(BFSDK_URL "https://github.com/rianquinn/bfsdk.git" CACHE STRING "default SDK repository URL")
set(BFSDK_TAG "master" CACHE STRING "default SDK repository branch")

set(BFSYSROOT_URL "https://github.com/rianquinn/bfsysroot.git" CACHE STRING "default sysroot repository URL")
set(BFSYSROOT_TAG "master" CACHE STRING "default sysroot repository branch")

set(BFELF_LOADER_URL "https://github.com/rianquinn/bfelf_loader.git" CACHE STRING "default ELF loader repository URL")
set(BFELF_LOADER_TAG "master" CACHE STRING "default ELF loader repository branch")

set(BFM_URL "https://github.com/rianquinn/bfm.git" CACHE STRING "default BFM repository URL")
set(BFM_TAG "master" CACHE STRING "default BFM repository branch")

set(BFVMM_URL "https://github.com/rianquinn/bfvmm.git" CACHE STRING "default VMM repository URL")
set(BFVMM_TAG "master" CACHE STRING "default VMM repository branch")

set(BFDRIVER_URL "https://github.com/rianquinn/bfdriver.git" CACHE STRING "default driver repository URL")
set(BFDRIVER_TAG "master" CACHE STRING "default driver repository branch")

# ------------------------------------------------------------------------------
# SDK
# ------------------------------------------------------------------------------

list(APPEND BFSDK_CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
)

ExternalProject_Add(
    bfsdk
    GIT_REPOSITORY      ${BFSDK_URL}
    GIT_TAG             ${BFSDK_TAG}
    CMAKE_ARGS          ${BFSDK_CMAKE_ARGS}
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfsdk/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfsdk/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfsdk/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfsdk
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfsdk/build
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
)

# ------------------------------------------------------------------------------
# Sysroot
# ------------------------------------------------------------------------------

list(APPEND BFSYSROOT_CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
    "-DCMAKE_TOOLCHAIN_FILE=${BFPREFIX}/cmake/CMakeToolchain_VMM_40.txt"
    "-DDISABLE_WARNINGS=ON"
)

ExternalProject_Add(
    bfsysroot
    GIT_REPOSITORY      ${BFSYSROOT_URL}
    GIT_TAG             ${BFSYSROOT_TAG}
    CMAKE_ARGS          ${BFSYSROOT_CMAKE_ARGS}
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfsysroot/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfsysroot/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfsysroot/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfsysroot
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfsysroot/build
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
    DEPENDS             bfsdk
    INSTALL_COMMAND     ""
)

# ------------------------------------------------------------------------------
# ELF Loader
# ------------------------------------------------------------------------------

list(APPEND BFELF_LOADER_CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
)

ExternalProject_Add(
    bfelf_loader
    GIT_REPOSITORY      ${BFELF_LOADER_URL}
    GIT_TAG             ${BFELF_LOADER_TAG}
    CMAKE_ARGS          ${BFELF_LOADER_CMAKE_ARGS}
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfelf_loader/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfelf_loader/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfelf_loader/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfelf_loader
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfelf_loader/build
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
    DEPENDS             bfsdk
)

# ------------------------------------------------------------------------------
# BFM
# ------------------------------------------------------------------------------

list(APPEND BFM_CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
)

ExternalProject_Add(
    bfm
    GIT_REPOSITORY      ${BFM_URL}
    GIT_TAG             ${BFM_TAG}
    CMAKE_ARGS          ${BFM_CMAKE_ARGS}
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfm/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfm/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfm/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfm
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfm/build
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
    DEPENDS             bfsdk bfelf_loader
)

# ------------------------------------------------------------------------------
# VMM
# ------------------------------------------------------------------------------

list(APPEND BFVMM_CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
    "-DCMAKE_TOOLCHAIN_FILE=${BFPREFIX}/cmake/CMakeToolchain_VMM_40.txt"
)

ExternalProject_Add(
    bfvmm
    GIT_REPOSITORY      ${BFVMM_URL}
    GIT_TAG             ${BFVMM_TAG}
    CMAKE_ARGS          ${BFVMM_CMAKE_ARGS}
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfvmm/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfvmm/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfvmm/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfvmm
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfvmm/build
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
    DEPENDS             bfsdk bfsysroot
    INSTALL_COMMAND     ""
)

# ------------------------------------------------------------------------------
# Driver
# ------------------------------------------------------------------------------

list(APPEND BFDRIVER_CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
)

ExternalProject_Add(
    bfdriver
    GIT_REPOSITORY      ${BFDRIVER_URL}
    GIT_TAG             ${BFDRIVER_TAG}
    CMAKE_ARGS          ${BFDRIVER_CMAKE_ARGS}
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfdriver/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfdriver/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfdriver/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfdriver
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfdriver/build
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
    DEPENDS             bfsdk bfelf_loader
    INSTALL_COMMAND     ""
)
