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
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    UPDATE_COMMAND      cmake -E echo -- Checking for changes
    CONFIGURE_COMMAND   cmake -E chdir ${CMAKE_CURRENT_LIST_DIR}/src rustup override set nightly > log.txt 2> log.txt
    BUILD_COMMAND       cmake -E chdir ${CMAKE_CURRENT_LIST_DIR}/src cargo build -Z build-std=core ${CARGO_MODE_ARG}
    BUILD_BYPRODUCTS    ${CMAKE_CURRENT_LIST_DIR}/src/target/x86_64-unknown-none/${CARGO_MODE}/librust.a
    INSTALL_COMMAND     cmake -E echo -- Checking for changes
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
    PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_LIST_DIR}/src/target/x86_64-unknown-none/${CARGO_MODE}/librust.a
)

# ------------------------------------------------------------------------------
# Executable
# ------------------------------------------------------------------------------

add_executable(example_default_rust empty.cpp)

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

target_link_libraries(example_default_rust PRIVATE
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

add_dependencies(example_default_rust rust_compile)

# ------------------------------------------------------------------------------
# Strip
# ------------------------------------------------------------------------------

# NOTE:
# - If this is a release or minsizerel build, we strip just to make the
#   finaly executable as small as possible. Note that this is entirely
#   optional and can be removed if you wish.
#

if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
    add_custom_command(TARGET example_default_rust POST_BUILD COMMAND ${CMAKE_STRIP} example_default_rust)
endif()
