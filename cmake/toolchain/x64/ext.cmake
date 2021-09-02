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

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_CXX_COMPILER_WORKS 1)

string(CONCAT HYPERVISOR_EXT_CXX_FLAGS
    "--target=x86_64-elf "
    "-ffreestanding "
    "-mno-mmx "
    "-mno-sse "
    "-mno-sse2 "
    "-mno-sse3 "
    "-mno-ssse3 "
    "-mno-sse4.1 "
    "-mno-sse4.2 "
    "-mno-sse4 "
    "-mno-avx "
    "-mno-aes "
    "-mno-sse4a "
    "-mcmodel=large "
    "-std=c++20 "
)

if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
    string(CONCAT HYPERVISOR_EXT_CXX_FLAGS
        ${HYPERVISOR_EXT_CXX_FLAGS}
        "-flto "
    )
endif()

string(CONCAT HYPERVISOR_EXT_LINK_FLAGS
    "-static "
    "-nostdlib "
    "-z noexecstack "
    "--gc-sections "
    "-T ${CMAKE_BINARY_DIR}/toolchain/x64/ext.ld "
)

set(CMAKE_ASM_COMPILE_OBJECT
    "<CMAKE_CXX_COMPILER> ${HYPERVISOR_EXT_CXX_FLAGS} <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>")

set(CMAKE_CXX_COMPILE_OBJECT
    "<CMAKE_CXX_COMPILER> ${HYPERVISOR_EXT_CXX_FLAGS} <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>")

set(CMAKE_CXX_LINK_EXECUTABLE
    "${HYPERVISOR_CXX_LINKER} ${HYPERVISOR_EXT_LINK_FLAGS} <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
)

################################################################################
# Hack For Windows
################################################################################

# For some reason, CMake on Windows is adding extra stuff to the compiler
# includes and flags. The following fixes this issue by telling CMake not
# to configure the compiler. We need to add C++20 to the command above
# to make this work.
# https://gitlab.kitware.com/cmake/cmake/-/issues/21789

set(__COMPILER_CLANG 1)

macro(__compiler_clang lang)
endmacro()

macro(__compiler_clang_cxx_standards lang)
endmacro()

macro(__compiler_check_default_language_standard lang)
endmacro()
