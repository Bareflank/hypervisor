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

if (NOT EXISTS ${CMAKE_BINARY_DIR}/toolchain/x64/ext.ld)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/toolchain)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/toolchain/x64)
    set(HYPERVISOR_TOOLCHAIN_X64_MK_LD ${CMAKE_BINARY_DIR}/toolchain/x64/ext.ld)

    file(WRITE ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "/* ---- AUTO GENERATED ---- */\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "ENTRY(_start)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "SECTIONS {\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    . = ${HYPERVISOR_EXT_CODE_ADDR};\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .text : ALIGN(0x1000) { *(.text .text.*); }\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .rodata : ALIGN(0x1000) { *(.rodata .rodata.*); }\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .data : ALIGN(0x1000) { *(.data .data.*); }\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .bss : ALIGN(0x1000) { *(.bss .bss.*); }\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "}\n")
endif()
