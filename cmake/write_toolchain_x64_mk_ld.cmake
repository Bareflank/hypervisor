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

if (NOT EXISTS ${CMAKE_BINARY_DIR}/toolchain/x64/mk.ld)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/toolchain)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/toolchain/x64)
    set(HYPERVISOR_TOOLCHAIN_X64_MK_LD ${CMAKE_BINARY_DIR}/toolchain/x64/mk.ld)

    file(WRITE ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "/* ---- AUTO GENERATED ---- */\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "ENTRY(mk_main_entry)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "OUTPUT_FORMAT(elf64-x86-64)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "SECTIONS {\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    . = ${HYPERVISOR_MK_CODE_ADDR};\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .text : ALIGN(${BSL_PAGE_SIZE}) {\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "        *(.text)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    }\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .init : ALIGN(${BSL_PAGE_SIZE}) {\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "        *(.init)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    }\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .init_array : ALIGN(${BSL_PAGE_SIZE}) {\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "        *(.init_array)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    }\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .fini : ALIGN(${BSL_PAGE_SIZE}) {\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "        *(.fini)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    }\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .fini_array : ALIGN(${BSL_PAGE_SIZE}) {\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "        *(.fini_array)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    }\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .rodata : ALIGN(${BSL_PAGE_SIZE}) {\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "        *(.rodata)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    }\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .data : ALIGN(${BSL_PAGE_SIZE}) {\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "        *(.data)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    }\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    .bss : ALIGN(${BSL_PAGE_SIZE}) {\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "        *(.bss)\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "    }\n")

    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "}\n")
    file(APPEND ${HYPERVISOR_TOOLCHAIN_X64_MK_LD} "\n")
endif()
