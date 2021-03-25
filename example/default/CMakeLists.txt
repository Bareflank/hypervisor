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
# Executable
# ------------------------------------------------------------------------------

add_executable(example_default)

# ------------------------------------------------------------------------------
# Macros
# ------------------------------------------------------------------------------

# NOTE:
# - We use this macro to add source files to an executable because Ninja on
#   Windows will not recompile without the dependencies being stated explicitly
#   simpilar to how Visual Studio works. This simplifies the process.
#

macro(example_target_source NAME SOURCE_FILE)
    target_sources(${NAME} PRIVATE ${SOURCE_FILE})
    set_property(SOURCE ${SOURCE_FILE} APPEND PROPERTY OBJECT_DEPENDS ${ARGN})
endmacro(example_target_source)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

# NOTE:
# - Add each include folder as needed. This is what allows us to handle
#   each architecture. Common code simply calls into code that has the same
#   name across all architectures, and the build system handles making sure
#   the right code is compiled in. This prevents the need for any compile time
#   macros in the code.
#

target_include_directories(example_default PRIVATE
    include
    src
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_include_directories(example_default PRIVATE
        include/x64
        src/x64
    )

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        target_include_directories(example_default PRIVATE
            include/x64/amd
            src/x64/amd
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        target_include_directories(example_default PRIVATE
            include/x64/intel
            src/x64/intel
        )
    endif()
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    target_include_directories(example_default PRIVATE
        include/arm/aarch64
        src/arm/aarch64
    )
endif()

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

# NOTE:
# -  We need to explicitly declare each header due to Windows dependency
#    issues with header files.
#

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/include/dummy_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/bootstrap_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/fail_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vp_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vp_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vps_pool_t.hpp
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_cpuid_impl.hpp
    )

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd/arch_dummy_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/gs_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/tls_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/intrinsic_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/vmexit_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/vps_t.hpp
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/arch_dummy_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/gs_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/tls_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/intrinsic_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/vmexit_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/vps_t.hpp
        )
    endif()
endif()

if(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/arm/aarch64/arch_dummy_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/gs_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/tls_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/intrinsic_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/vmexit_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/arm/aarch64/vps_t.hpp
    )
endif()

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

# NOTE:
# - Add the sources to the executable. See the note above about why we
#   use the macro for doing this.
#

example_target_source(example_default src/main.cpp ${HEADERS})

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    example_target_source(example_default src/x64/intrinsic_cpuid_impl.S ${HEADERS})
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

target_link_libraries(example_default PRIVATE
    runtime
    bsl
    loader
    syscall
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

# NOTE:
# - If this is a release or minsizerel build, we strip just to make the
#   finaly executable as small as possible. Note that this is entirely
#   optional and can be removed if you wish.
#

if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
    add_custom_command(TARGET example_default POST_BUILD COMMAND ${CMAKE_STRIP} example_default)
endif()

# NOTE:
# - You can install wherever you want. We install into the bin folder,
#   which the build system can find for starting/stopping the hypervisor.
#   If you provide your own tools, you can install to wherever is easier
#   for you.
#

install(TARGETS example_default DESTINATION bin)
