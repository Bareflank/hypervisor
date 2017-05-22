# export PATH="$PWD/../bfprefix/bin:$PATH"
# cmake ..

cmake_minimum_required(VERSION 3.6)
project(hypervisor C CXX)

include(ExternalProject)
find_package(Git REQUIRED)

set(BFPREFIX "${CMAKE_SOURCE_DIR}/bfprefix")

if(NOT UNAME STREQUAL "Cygwin")
    set(SUDO sudo)
endif()

# ------------------------------------------------------------------------------
# Repos
# ------------------------------------------------------------------------------

set(BFSDK_URL "https://github.com/bareflank/bfsdk.git" CACHE STRING "default SDK repository URL")
set(BFSDK_TAG "master" CACHE STRING "default SDK repository branch")

set(BFSYSROOT_URL "https://github.com/bareflank/bfsysroot.git" CACHE STRING "default sysroot repository URL")
set(BFSYSROOT_TAG "master" CACHE STRING "default sysroot repository branch")

set(BFELF_LOADER_URL "https://github.com/bareflank/bfelf_loader.git" CACHE STRING "default ELF loader repository URL")
set(BFELF_LOADER_TAG "master" CACHE STRING "default ELF loader repository branch")

set(BFM_URL "https://github.com/bareflank/bfm.git" CACHE STRING "default BFM repository URL")
set(BFM_TAG "master" CACHE STRING "default BFM repository branch")

set(BFVMM_URL "https://github.com/bareflank/bfvmm.git" CACHE STRING "default VMM repository URL")
set(BFVMM_TAG "master" CACHE STRING "default VMM repository branch")

set(BFDRIVER_URL "https://github.com/bareflank/bfdriver.git" CACHE STRING "default driver repository URL")
set(BFDRIVER_TAG "master" CACHE STRING "default driver repository branch")

message("-- BFSDK_URL: ${BFSDK_URL}")
message("-- BFSDK_TAG: ${BFSDK_TAG}")
message("-- BFSYSROOT_URL: ${BFSYSROOT_URL}")
message("-- BFSYSROOT_TAG: ${BFSYSROOT_TAG}")
message("-- BFELF_LOADER_URL: ${BFELF_LOADER_URL}")
message("-- BFELF_LOADER_TAG: ${BFELF_LOADER_TAG}")
message("-- BFM_URL: ${BFM_URL}")
message("-- BFM_TAG: ${BFM_TAG}")
message("-- BFVMM_URL: ${BFVMM_URL}")
message("-- BFVMM_TAG: ${BFVMM_TAG}")
message("-- BFDRIVER_URL: ${BFDRIVER_URL}")
message("-- BFDRIVER_TAG: ${BFDRIVER_TAG}")

# ------------------------------------------------------------------------------
# Update Disconnected
# ------------------------------------------------------------------------------

if(UPDATE_DISCONNECTED)
    message("-- Update Disconnected: On")
endif()

# ------------------------------------------------------------------------------
# SDK
# ------------------------------------------------------------------------------

list(APPEND BFSDK_CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
    "-DUPDATE_DISCONNECTED=${UPDATE_DISCONNECTED}"
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
    BUILD_COMMAND       ""
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
    BUILD_COMMAND       ""
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
    BUILD_COMMAND       ""
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
    BUILD_COMMAND       ""
    DEPENDS             bfsdk bfsysroot
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
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    DEPENDS             bfsdk bfelf_loader
)

# ------------------------------------------------------------------------------
# Test SDK
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    list(APPEND TEST_BFSDK_CMAKE_ARGS
        "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
        "-DENABLE_UNITTESTING=${ENABLE_UNITTESTING}"
        "-DUPDATE_DISCONNECTED=${UPDATE_DISCONNECTED}"
    )

    ExternalProject_Add(
        test_bfsdk
        DOWNLOAD_COMMAND    ""
        SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfsdk
        CMAKE_ARGS          ${TEST_BFSDK_CMAKE_ARGS}
        TMP_DIR             ${CMAKE_BINARY_DIR}/test_bfsdk/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/test_bfsdk/stamp
        DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/test_bfsdk/download
        BINARY_DIR          ${CMAKE_BINARY_DIR}/test_bfsdk/build
        INSTALL_COMMAND     ""
        DEPENDS             bfsdk
    )

endif()

# ------------------------------------------------------------------------------
# Test Sysroot
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Test ELF Loader
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    list(APPEND TEST_BFELF_LOADER_CMAKE_ARGS
        "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
        "-DENABLE_UNITTESTING=${ENABLE_UNITTESTING}"
    )

    ExternalProject_Add(
        test_bfelf_loader
        DOWNLOAD_COMMAND    ""
        SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfelf_loader
        CMAKE_ARGS          ${TEST_BFELF_LOADER_CMAKE_ARGS}
        TMP_DIR             ${CMAKE_BINARY_DIR}/test_bfelf_loader/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/test_bfelf_loader/stamp
        DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/test_bfelf_loader/download
        BINARY_DIR          ${CMAKE_BINARY_DIR}/test_bfelf_loader/build
        INSTALL_COMMAND     ""
        DEPENDS             bfelf_loader
    )

endif()

# ------------------------------------------------------------------------------
# Test BFM
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    list(APPEND TEST_BFM_CMAKE_ARGS
        "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
        "-DENABLE_UNITTESTING=${ENABLE_UNITTESTING}"
    )

    ExternalProject_Add(
        test_bfm
        DOWNLOAD_COMMAND    ""
        SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfm
        CMAKE_ARGS          ${TEST_BFM_CMAKE_ARGS}
        TMP_DIR             ${CMAKE_BINARY_DIR}/test_bfm/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/test_bfm/stamp
        DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/test_bfm/download
        BINARY_DIR          ${CMAKE_BINARY_DIR}/test_bfm/build
        INSTALL_COMMAND     ""
        DEPENDS             bfm
    )

endif()

# ------------------------------------------------------------------------------
# Test VMM
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    list(APPEND TEST_BFVMM_CMAKE_ARGS
        "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
        "-DENABLE_UNITTESTING=${ENABLE_UNITTESTING}"
    )

    ExternalProject_Add(
        test_bfvmm
        DOWNLOAD_COMMAND    ""
        SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfvmm
        CMAKE_ARGS          ${TEST_BFVMM_CMAKE_ARGS}
        TMP_DIR             ${CMAKE_BINARY_DIR}/test_bfvmm/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/test_bfvmm/stamp
        DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/test_bfvmm/download
        BINARY_DIR          ${CMAKE_BINARY_DIR}/test_bfvmm/build
        INSTALL_COMMAND     ""
        DEPENDS             bfvmm
    )

endif()

# ------------------------------------------------------------------------------
# Test Driver
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    list(APPEND TEST_BFDRIVER_CMAKE_ARGS
        "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
        "-DENABLE_UNITTESTING=${ENABLE_UNITTESTING}"
    )

    ExternalProject_Add(
        test_bfdriver
        DOWNLOAD_COMMAND    ""
        SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfdriver
        CMAKE_ARGS          ${TEST_BFDRIVER_CMAKE_ARGS}
        TMP_DIR             ${CMAKE_BINARY_DIR}/test_bfdriver/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/test_bfdriver/stamp
        DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/test_bfdriver/download
        BINARY_DIR          ${CMAKE_BINARY_DIR}/test_bfdriver/build
        INSTALL_COMMAND     ""
        DEPENDS             bfdriver
    )

endif()

# ------------------------------------------------------------------------------
# Clean
# ------------------------------------------------------------------------------

add_custom_target(distclean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfdriver
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfelf_loader
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfm
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfprefix
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfsdk
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfsysroot
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfvmm
)

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${CMAKE_SOURCE_DIR}/bfprefix)

# ------------------------------------------------------------------------------
# BFM Shortcuts
# ------------------------------------------------------------------------------

add_custom_target(quick COMMAND ${SUDO} ${CMAKE_SOURCE_DIR}/bfprefix/bin/bfm quick)
add_custom_target(stop COMMAND ${SUDO} ${CMAKE_SOURCE_DIR}/bfprefix/bin/bfm stop)
add_custom_target(unload COMMAND ${SUDO} ${CMAKE_SOURCE_DIR}/bfprefix/bin/bfm unload)
add_custom_target(dump COMMAND ${SUDO} ${CMAKE_SOURCE_DIR}/bfprefix/bin/bfm dump)
add_custom_target(status COMMAND ${SUDO} ${CMAKE_SOURCE_DIR}/bfprefix/bin/bfm status)

# ------------------------------------------------------------------------------
# Driver Shortcuts
# ------------------------------------------------------------------------------

add_custom_target(driver_build COMMAND make driver_build > /dev/null VERBATIM WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bfdriver/build)
add_custom_target(driver_load COMMAND make driver_load > /dev/null VERBATIM WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bfdriver/build)
add_custom_target(driver_unload COMMAND make driver_unload > /dev/null VERBATIM WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bfdriver/build)
add_custom_target(driver_clean COMMAND make driver_clean > /dev/null VERBATIM WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bfdriver/build)
add_custom_target(driver_quick DEPENDS driver_load driver_build)

# ------------------------------------------------------------------------------
# Test
# ------------------------------------------------------------------------------

cmake_policy(PUSH)

if(POLICY CMP0037)
    cmake_policy(SET CMP0037 OLD)       # allow `make test`
endif()

add_custom_target(test
    COMMAND make -C ${CMAKE_BINARY_DIR}/test_bfdriver/build test
    COMMAND make -C ${CMAKE_BINARY_DIR}/test_bfelf_loader/build test
    COMMAND make -C ${CMAKE_BINARY_DIR}/test_bfm/build test
    COMMAND make -C ${CMAKE_BINARY_DIR}/test_bfsdk/build test
#    COMMAND make -C ${CMAKE_BINARY_DIR}/bfsysroot/build test
    COMMAND make -C ${CMAKE_BINARY_DIR}/test_bfvmm/build test
)

cmake_policy(POP)

# ------------------------------------------------------------------------------
# Git Report
# ------------------------------------------------------------------------------

add_custom_target(report)

add_custom_command(TARGET report COMMAND git -C ${CMAKE_SOURCE_DIR}/bfdriver diff --stat COMMENT "Diff: bfdriver")
add_custom_command(TARGET report COMMAND git -C ${CMAKE_SOURCE_DIR}/bfelf_loader diff --stat COMMENT "Diff: bfelf_loader")
add_custom_command(TARGET report COMMAND git -C ${CMAKE_SOURCE_DIR}/bfm diff --stat COMMENT "Diff: bfm")
add_custom_command(TARGET report COMMAND git -C ${CMAKE_SOURCE_DIR}/bfsdk diff --stat COMMENT "Diff: bfsdk")
add_custom_command(TARGET report COMMAND git -C ${CMAKE_SOURCE_DIR}/bfsysroot diff --stat COMMENT "Diff: bfsysroot")
add_custom_command(TARGET report COMMAND git -C ${CMAKE_SOURCE_DIR}/bfvmm diff --stat COMMENT "Diff: bfvmm")
