# export PATH="$PWD/../bfprefix/bin:$PATH"
# cmake ..

cmake_minimum_required(VERSION 3.6)
project(hypervisor C CXX)

include(ExternalProject)
find_package(Git REQUIRED)

set(BFPREFIX "${CMAKE_SOURCE_DIR}/bfprefix")
set(BFPREFIX_TEST "${CMAKE_SOURCE_DIR}/bfprefix_test")

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
# Path
# ------------------------------------------------------------------------------

if(NOT $ENV{PATH} MATCHES "bfprefix")
    message (FATAL_ERROR "bfprefix has not been added to your path")
endif()

# ------------------------------------------------------------------------------
# Update Disconnected
# ------------------------------------------------------------------------------

if(UPDATE_DISCONNECTED)
    message("-- Update Disconnected: On")
endif()

# ------------------------------------------------------------------------------
# Toolchain File
# ------------------------------------------------------------------------------

find_program(NASM_BIN nasm)

if(NASM_BIN STREQUAL "NASM_BIN-NOTFOUND")
    message(FATAL_ERROR "Unable to find nasm, or nasm is not installed")
endif()

find_program(PYTHON_BIN python)

if(PYTHON_BIN STREQUAL "PYTHON_BIN-NOTFOUND")
    message(FATAL_ERROR "Unable to find python, or python is not installed")
endif()

find_program(GIT_BIN git)

if(GIT_BIN STREQUAL "GIT_BIN-NOTFOUND")
    message(FATAL_ERROR "Unable to find git, or git is not installed")
endif()

find_program(CLANG_BIN_40 clang-4.0)
find_program(CLANG_BIN_39 clang-3.9)
find_program(CLANG_BIN_38 clang-3.8)
find_program(CLANG_BIN clang)

if(NOT CLANG_BIN_40 STREQUAL "CLANG_BIN_40-NOTFOUND")
    set(CLANG_BIN ${CLANG_BIN_40})
    set(PREFERRED_VMM_TOOLCHAIN "${BFPREFIX}/cmake/CMakeToolchain_VMM_40.txt")
elseif(NOT CLANG_BIN_39 STREQUAL "CLANG_BIN_39-NOTFOUND")
    set(CLANG_BIN ${CLANG_BIN_39})
    set(PREFERRED_VMM_TOOLCHAIN "${BFPREFIX}/cmake/CMakeToolchain_VMM_39.txt")
elseif(NOT CLANG_BIN_38 STREQUAL "CLANG_BIN_38-NOTFOUND")
    set(CLANG_BIN ${CLANG_BIN_38})
    set(PREFERRED_VMM_TOOLCHAIN "${BFPREFIX}/cmake/CMakeToolchain_VMM_38.txt")
elseif(NOT CLANG_BIN STREQUAL "CLANG_BIN-NOTFOUND")
    set(PREFERRED_VMM_TOOLCHAIN "${BFPREFIX}/cmake/CMakeToolchain_VMM.txt")
else()
    message(FATAL_ERROR "Unable to find clang, or clang is not installed")
endif()

message(STATUS "git: ${GIT_BIN}")
message(STATUS "python: ${PYTHON_BIN}")
message(STATUS "clang: ${CLANG_BIN}")
message(STATUS "nasm: ${NASM_BIN}")
message(STATUS "preferred vmm toolchain: ${PREFERRED_VMM_TOOLCHAIN}")

set(VMM_TOOLCHAIN_FILE ${PREFERRED_VMM_TOOLCHAIN} CACHE STRING "default VMM toolchain file")

# ------------------------------------------------------------------------------
# SDK
# ------------------------------------------------------------------------------

list(APPEND BFSDK_CMAKE_ARGS
    "-DBFSOURCE_DIR=${CMAKE_SOURCE_DIR}"
    "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
    "-DENABLE_TIDY=${ENABLE_TIDY}"
    "-DENABLE_UNITTESTING=${ENABLE_UNITTESTING}"
    "-DENABLE_COVERAGE_LLVM=${ENABLE_COVERAGE_LLVM}"
    "-DUPDATE_DISCONNECTED=${UPDATE_DISCONNECTED}"
)

ExternalProject_Add(
    bfsdk
    GIT_REPOSITORY      ${BFSDK_URL}
    GIT_TAG             ${BFSDK_TAG}
    CMAKE_ARGS          ${BFSDK_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfsdk/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfsdk/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfsdk/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfsdk/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfsdk
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfsdk/build
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
    BUILD_COMMAND       ""
)

if(ENABLE_UNITTESTING OR ENABLE_TIDY OR ENABLE_COVERAGE_LLVM)

    ExternalProject_Add_Step(
        bfsdk
        test_prefix_install
        COMMAND             ${CMAKE_COMMAND} -E make_directory ${BFPREFIX_TEST}
        COMMAND             ${CMAKE_COMMAND} -E create_symlink ${BFPREFIX}/bin ${BFPREFIX_TEST}/bin
        COMMAND             ${CMAKE_COMMAND} -E create_symlink ${BFPREFIX}/cmake ${BFPREFIX_TEST}/cmake
        COMMAND             ${CMAKE_COMMAND} -E create_symlink ${BFPREFIX}/include ${BFPREFIX_TEST}/include
        DEPENDEES           install
    )

endif()

# ------------------------------------------------------------------------------
# Sysroot
# ------------------------------------------------------------------------------

list(APPEND BFSYSROOT_CMAKE_ARGS
    "-DBFSOURCE_DIR=${CMAKE_SOURCE_DIR}"
    "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
    "-DCMAKE_TOOLCHAIN_FILE=${VMM_TOOLCHAIN_FILE}"
    "-DDISABLE_WARNINGS=ON"
)

ExternalProject_Add(
    bfsysroot
    GIT_REPOSITORY      ${BFSYSROOT_URL}
    GIT_TAG             ${BFSYSROOT_TAG}
    CMAKE_ARGS          ${BFSYSROOT_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfsysroot/prefix
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
    "-DENABLE_TIDY=${ENABLE_TIDY}"
    "-DENABLE_UNITTESTING=${ENABLE_UNITTESTING}"
    "-DENABLE_COVERAGE_LLVM=${ENABLE_COVERAGE_LLVM}"
)

ExternalProject_Add(
    bfelf_loader
    GIT_REPOSITORY      ${BFELF_LOADER_URL}
    GIT_TAG             ${BFELF_LOADER_TAG}
    CMAKE_ARGS          ${BFELF_LOADER_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfelf_loader/prefix
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
    "-DENABLE_TIDY=${ENABLE_TIDY}"
    "-DENABLE_UNITTESTING=${ENABLE_UNITTESTING}"
    "-DENABLE_COVERAGE_LLVM=${ENABLE_COVERAGE_LLVM}"
)

ExternalProject_Add(
    bfm
    GIT_REPOSITORY      ${BFM_URL}
    GIT_TAG             ${BFM_TAG}
    CMAKE_ARGS          ${BFM_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfm/prefix
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
    "-DCMAKE_TOOLCHAIN_FILE=${VMM_TOOLCHAIN_FILE}"
)

ExternalProject_Add(
    bfvmm
    GIT_REPOSITORY      ${BFVMM_URL}
    GIT_TAG             ${BFVMM_TAG}
    CMAKE_ARGS          ${BFVMM_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfvmm/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfvmm/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfvmm/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfvmm/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfvmm
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfvmm/build
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
    BUILD_COMMAND       ""
    DEPENDS             bfsdk bfsysroot
)

if(ENABLE_UNITTESTING OR ENABLE_TIDY OR ENABLE_COVERAGE_LLVM)

    list(APPEND TEST_BFVMM_CMAKE_ARGS
        "-DCMAKE_INSTALL_PREFIX=${BFPREFIX_TEST}"
        "-DENABLE_TIDY=${ENABLE_TIDY}"
        "-DENABLE_UNITTESTING=${ENABLE_UNITTESTING}"
        "-DENABLE_COVERAGE_LLVM=${ENABLE_COVERAGE_LLVM}"
    )

    ExternalProject_Add(
        test_bfvmm
        DOWNLOAD_COMMAND    ""
        SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfvmm
        CMAKE_ARGS          ${TEST_BFVMM_CMAKE_ARGS}
        PREFIX              ${CMAKE_BINARY_DIR}/test_bfvmm/prefix
        TMP_DIR             ${CMAKE_BINARY_DIR}/test_bfvmm/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/test_bfvmm/stamp
        BINARY_DIR          ${CMAKE_BINARY_DIR}/test_bfvmm/build
        BUILD_COMMAND       ""
        DEPENDS             bfvmm
    )

endif()

# ------------------------------------------------------------------------------
# Driver
# ------------------------------------------------------------------------------

list(APPEND BFDRIVER_CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX=${BFPREFIX}"
    "-DENABLE_TIDY=${ENABLE_TIDY}"
    "-DENABLE_UNITTESTING=${ENABLE_UNITTESTING}"
    "-DENABLE_COVERAGE_LLVM=${ENABLE_COVERAGE_LLVM}"
)

ExternalProject_Add(
    bfdriver
    GIT_REPOSITORY      ${BFDRIVER_URL}
    GIT_TAG             ${BFDRIVER_TAG}
    CMAKE_ARGS          ${BFDRIVER_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfdriver/prefix
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
# Clean
# ------------------------------------------------------------------------------

add_custom_target(super-clean
    COMMENT "running make super-clean for the hypervisor, bfsysroot and bfsdk"
    COMMAND ${CMAKE_COMMAND} --build . --target clean

    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target super-clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target super-clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfvmm/build --target clean

    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target clean

    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BFPREFIX}/bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BFPREFIX}/include
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BFPREFIX}/lib
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BFPREFIX}/sysroots

    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BFPREFIX_TEST}/bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BFPREFIX_TEST}/include
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BFPREFIX_TEST}/lib
)

add_custom_target(dist-clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target dist-clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfdriver
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfelf_loader
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfm
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfprefix
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfprefix_test
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfsdk
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfsysroot
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bfvmm
)

# ------------------------------------------------------------------------------
# BFM Shortcuts
# ------------------------------------------------------------------------------

add_custom_target(quick COMMAND ${SUDO} ${BFPREFIX}/bin/bfm quick)
add_custom_target(stop COMMAND ${SUDO} ${BFPREFIX}/bin/bfm stop)
add_custom_target(unload COMMAND ${SUDO} ${BFPREFIX}/bin/bfm unload)
add_custom_target(dump COMMAND ${SUDO} ${BFPREFIX}/bin/bfm dump)
add_custom_target(status COMMAND ${SUDO} ${BFPREFIX}/bin/bfm status)

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
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target test
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target test
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target test
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target test
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target test
)

cmake_policy(POP)

# ------------------------------------------------------------------------------
# Tidy
# ------------------------------------------------------------------------------

if(ENABLE_TIDY)

    add_custom_target(tidy
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfdriver/build --target tidy
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target tidy
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target tidy
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target tidy
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target tidy
    )

    add_custom_target(tidy-all
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfdriver/build --target tidy-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target tidy-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target tidy-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target tidy-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target tidy-all
    )

endif()

# ------------------------------------------------------------------------------
# Astyle
# ------------------------------------------------------------------------------

add_custom_target(format
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target format
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target format
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target format
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target format
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target format
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfvmm/build --target format
)

add_custom_target(format-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target format-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target format-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target format-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target format-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target format-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfvmm/build --target format-all
)

# ------------------------------------------------------------------------------
# Coverage
# ------------------------------------------------------------------------------

add_custom_target(llvm_coverage
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target llvm_coverage
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target llvm_coverage
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target llvm_coverage
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target llvm_coverage
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target llvm_coverage
)

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
