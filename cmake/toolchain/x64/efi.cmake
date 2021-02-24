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
set(CMAKE_C_COMPILER_WORKS 1)

string(CONCAT HYPERVISOR_EFI_C_FLAGS
    "--target=x86_64-unknown-windows "
    "-ffreestanding "
    "-fshort-wchar "
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
)

string(CONCAT HYPERVISOR_EFI_LINK_FLAGS
    "--target=x86_64-unknown-windows "
    "-nostdlib "
    "-Wl,-entry:efi_main "
    "-Wl,-subsystem:efi_application "
    "-fuse-ld=${HYPERVISOR_EFI_LINKER}"
)

set(CMAKE_ASM_COMPILE_OBJECT
    "<CMAKE_C_COMPILER> ${HYPERVISOR_EFI_C_FLAGS} <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>")

set(CMAKE_C_COMPILE_OBJECT
    "<CMAKE_C_COMPILER> ${HYPERVISOR_EFI_C_FLAGS} <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>")

set(CMAKE_C_LINK_EXECUTABLE
    "<CMAKE_C_COMPILER> ${HYPERVISOR_EFI_LINK_FLAGS} <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
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

macro(__compiler_clang_C_standards lang)
endmacro()

macro(__compiler_check_default_language_standard lang)
endmacro()
