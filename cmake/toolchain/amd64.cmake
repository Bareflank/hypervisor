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

string(CONCAT HYPERVISOR_CXX_FLAGS
    "--target=amd64-elf "
    "-ffreestanding "
    "-mno-red-zone "
    "-D__bareflank__ "
)

string(CONCAT HYPERVISOR_LINK_FLAGS
    "-static "
    "-nostdlib "
    "-z max-page-size=0x1000 "
    "-z noexecstack "
)

set(CMAKE_ASM_COMPILE_OBJECT
    "<CMAKE_CXX_COMPILER> ${HYPERVISOR_CXX_FLAGS} <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>")

set(CMAKE_CXX_COMPILE_OBJECT
    "<CMAKE_CXX_COMPILER> ${HYPERVISOR_CXX_FLAGS} <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>")

set(CMAKE_CXX_LINK_EXECUTABLE
    "${HYPERVISOR_CXX_LINKER} ${HYPERVISOR_LINK_FLAGS} <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
)
