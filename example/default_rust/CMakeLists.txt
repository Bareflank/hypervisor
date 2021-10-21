#
# Copyright (C) 2020 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

include(ExternalProject)

# ------------------------------------------------------------------------------
# Notes
# ------------------------------------------------------------------------------

# - Extensions must be compiled with the extension toolchain. Bareflank's
#   build systems already has support for configuring where your extension
#   might be located. Please see the readme for more details.
#
# - If you set up the build system properly, HYPERVISOR_TARGET_ARCH and
#   CMAKE_BUILD_TYPE will already be set for you, as well as most of the
#   other HYPERVISOR_ variables that the microkernel can use.
#
# - The goal of each example is to prevent the need for any macros that the
#   microkernel's build system already provides which is why some macros
#   are duplicated here.
#

# ------------------------------------------------------------------------------
# Rust
# ------------------------------------------------------------------------------

# NOTE:
# - Autogenerate the Cargo.toml with the configuration from CMake so that
#   both projects match.
#

if(NOT EXISTS ${CMAKE_BINARY_DIR}/rust_files.txt)

    # --------------------------------------------------------------------------
    # Rebuild Flag
    # --------------------------------------------------------------------------

    set(HYPERVISOR_CONSTANTS ${CMAKE_BINARY_DIR}/rust_files.txt)
    file(WRITE ${CMAKE_BINARY_DIR}/rust_files.txt "touched\n")

    # --------------------------------------------------------------------------
    # Cargo.toml
    # --------------------------------------------------------------------------

    set(HYPERVISOR_CARGO_TOML ${CMAKE_CURRENT_LIST_DIR}/Cargo.toml)

    file(WRITE ${HYPERVISOR_CARGO_TOML} "[package]\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "name = \"rust\"\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "version = \"1.0.0\"\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "edition = \"2018\"\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "[lib]\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "path = \"src/lib.rs\"\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "crate-type = [\"staticlib\"]\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "[features]\n")

    set(SYSCALL_DEFAULT_FEATURES "[\"custom_print_thread_id\"")

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"AuthenticAMD\"")
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"GenuineIntel\"")
    endif()

    if(NOT ENABLE_COLOR)
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"disable_color\"")
    endif()

    if(BSL_DEBUG_LEVEL STREQUAL "bsl::V")
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"debug_level_v\"")
    endif()

    if(BSL_DEBUG_LEVEL STREQUAL "bsl::VV")
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"debug_level_v\",\"debug_level_vv\"")
    endif()

    if(BSL_DEBUG_LEVEL STREQUAL "bsl::VVV")
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"debug_level_v\",\"debug_level_vv\",\"debug_level_vvv\"")
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"release_mode\"]")
    else()
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES}]")
    endif()

    file(APPEND ${HYPERVISOR_CARGO_TOML} "default = ${SYSCALL_DEFAULT_FEATURES}\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "debug_level_v = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "debug_level_vv = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "debug_level_vvv = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "disable_color = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "release_mode = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "AuthenticAMD = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "GenuineIntel = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "custom_print_thread_id = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "\n")

    file(APPEND ${HYPERVISOR_CARGO_TOML} "[dependencies]\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "bsl = { path = \"${bsl_SOURCE_DIR}\", features = ${SYSCALL_DEFAULT_FEATURES} }\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "syscall = { path = \"${hypervisor_SOURCE_DIR}/syscall\", features = ${SYSCALL_DEFAULT_FEATURES} }\n")
endif()

# NOTE:
# - CMake cannot build Rust code, so we need to use cargo for that. To get
#   the build system to do this, we will use external project add, and provide
#   it with the instructions to compile our rust code.
#
# - The Rust code will produce a library file when it is done that we will
#   link our main executable against. This allows us to bring in C and C++
#   dependencies so that the Rust code doesn't have to do everything from
#   scratch.
#

if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
    set(CARGO_MODE release)
    set(CARGO_MODE_ARG "--release")
else()
    set(CARGO_MODE debug)
    set(CARGO_MODE_ARG "")
endif()

ExternalProject_Add(
    rust_compile
    PREFIX              ${CMAKE_BINARY_DIR}/rust_compile
    STAMP_DIR           ${CMAKE_BINARY_DIR}/rust_compile/stamp
    TMP_DIR             ${CMAKE_BINARY_DIR}/rust_compile/tmp
    BINARY_DIR          ${CMAKE_BINARY_DIR}/rust_compile/build
    LOG_DIR             ${CMAKE_BINARY_DIR}/rust_compile/logs
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}
    UPDATE_COMMAND      cmake -E echo -- Checking for changes
    CONFIGURE_COMMAND   cmake -E chdir ${CMAKE_CURRENT_LIST_DIR} rustup override set nightly
    BUILD_COMMAND       cmake -E chdir ${CMAKE_CURRENT_LIST_DIR} cargo build -Z build-std=core ${CARGO_MODE_ARG}
    BUILD_BYPRODUCTS    ${CMAKE_CURRENT_LIST_DIR}/target/x86_64-unknown-none/${CARGO_MODE}/librust.a
    INSTALL_COMMAND     cmake -E echo -- Skip
    LOG_CONFIGURE       ON
)

# NOTE:
# - Since the static library that we compiled is created external to this
#   build, we need to tell CMake that it exists and that it can be imported.
#

add_library(rust STATIC IMPORTED)

# NOTE:
# - Something actually has to tell CMake where the rust code is located after
#   it was compiled which is what this does.
#

set_target_properties(rust
    PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_LIST_DIR}/target/x86_64-unknown-none/${CARGO_MODE}/librust.a
)

# ------------------------------------------------------------------------------
# Executable
# ------------------------------------------------------------------------------

add_executable(extension_bin empty.cpp)

# ------------------------------------------------------------------------------
# Source Files
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_sources(extension_bin PRIVATE src/x64/intrinsic_cpuid_impl.S)
endif()

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

# NOTE:
# - The only library that is probably needed here is the loader. If you are
#   using C, you do not need the BSL, and you can provide your own syscall and
#   runtime libraries if you want. We provide our own versions to make things
#   easy, but if you prefer to implement your extension another way, you
#   can do so. The microkernel's ABI is the only piece of code that the project
#   is aiming to keep stable, so if it changes, you can continue to use an
#   old implementation, or write your own.
#

target_link_libraries(extension_bin PRIVATE
    runtime
    syscall
    rust
)

# NOTE:
# - In the call to target_link_libraries we tell CMake that our code depends
#   on the imported rust static library, but we never told CMake that this
#   library depends on the execution of the external project add code. If
#   we don't do this, we could end up with order issues in parallel builds.
#

add_dependencies(extension_bin rust_compile)

# ------------------------------------------------------------------------------
# Strip
# ------------------------------------------------------------------------------

# NOTE:
# - If this is a release or minsizerel build, we strip just to make the
#   finaly executable as small as possible. Note that this is entirely
#   optional and can be removed if you wish.
#

if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
    add_custom_command(TARGET extension_bin POST_BUILD COMMAND ${CMAKE_STRIP} extension_bin)
endif()
