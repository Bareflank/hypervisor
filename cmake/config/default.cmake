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

include(${bsl_SOURCE_DIR}/cmake/function/bf_add_config.cmake)

if(NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    bf_add_config(
        CONFIG_NAME HYPERVISOR_DEFAULT_BUILD_VMMCTL
        CONFIG_TYPE BOOL
        DEFAULT_VAL ON
        DESCRIPTION "Define the default value for HYPERVISOR_BUILD_VMMCTL"
        SKIP_VALIDATION
    )
else()
    bf_add_config(
        CONFIG_NAME HYPERVISOR_DEFAULT_BUILD_EFI
        CONFIG_TYPE BOOL
        DEFAULT_VAL ON
        DESCRIPTION "Define the default value for HYPERVISOR_BUILD_EFI"
        SKIP_VALIDATION
    )

    set(HYPERVISOR_TARGET_ARCH ${CMAKE_SYSTEM_PROCESSOR})
endif()

option(HYPERVISOR_BUILD_LOADER "Turns on/off building the loader" ON)
option(HYPERVISOR_BUILD_VMMCTL "Turns on/off building the vmmctl" ${HYPERVISOR_DEFAULT_BUILD_VMMCTL})
option(HYPERVISOR_BUILD_MICROKERNEL "Turns on/off building the microkernel" ON)
option(HYPERVISOR_BUILD_EFI "Turns on/off building the EFI loader" ${HYPERVISOR_DEFAULT_BUILD_EFI})

if(NOT DEFINED HYPERVISOR_TARGET_ARCH)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        execute_process(
            COMMAND ${CMAKE_CURRENT_LIST_DIR}/../../utils/linux/get_target_arch
            OUTPUT_VARIABLE HYPERVISOR_DEFAULT_TARGET_ARCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        execute_process(
            COMMAND ${CMAKE_CURRENT_LIST_DIR}/../../utils/windows/get_target_arch
            OUTPUT_VARIABLE HYPERVISOR_DEFAULT_TARGET_ARCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    else()
        message(FATAL_ERROR "Unsupported CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
    endif()
else()
    set(HYPERVISOR_DEFAULT_TARGET_ARCH ${HYPERVISOR_TARGET_ARCH})
endif()

if(NOT DEFINED HYPERVISOR_CXX_LINKER)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(HYPERVISOR_DEFAULT_CXX_LINKER "ld.lld")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set(HYPERVISOR_DEFAULT_CXX_LINKER "ld.lld")
    else()
        message(FATAL_ERROR "Unsupported CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
    endif()
else()
    set(HYPERVISOR_DEFAULT_CXX_LINKER ${HYPERVISOR_CXX_LINKER})
endif()

if(NOT DEFINED HYPERVISOR_EFI_LINKER)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(HYPERVISOR_DEFAULT_EFI_LINKER "lld-link")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set(HYPERVISOR_DEFAULT_EFI_LINKER "lld-link")
    else()
        message(FATAL_ERROR "Unsupported CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
    endif()
else()
    set(HYPERVISOR_DEFAULT_EFI_LINKER ${HYPERVISOR_EFI_LINKER})
endif()

if(NOT DEFINED HYPERVISOR_EFI_FS0)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(HYPERVISOR_DEFAULT_EFI_FS0 "/boot/efi/")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set(HYPERVISOR_DEFAULT_EFI_FS0 "X:/")
    else()
        message(FATAL_ERROR "Unsupported CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
    endif()
else()
    set(HYPERVISOR_DEFAULT_EFI_FS0 ${HYPERVISOR_EFI_FS0})
endif()

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXTENSIONS
    CONFIG_TYPE STRING
    DEFAULT_VAL "example_default"
    DESCRIPTION "Define the extension list used by the build system"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXTENSIONS_DIR
    CONFIG_TYPE STRING
    DEFAULT_VAL "${CMAKE_SOURCE_DIR}/example/default"
    DESCRIPTION "Defines the extension to use"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_TARGET_ARCH
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_DEFAULT_TARGET_ARCH}
    DESCRIPTION "The target architecture for the build"
    OPTIONS AuthenticAMD GenuineIntel aarch64
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_CXX_LINKER
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_DEFAULT_CXX_LINKER}
    DESCRIPTION "Define the linker to use for cross-compiling"
    OPTIONS ld.lld
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EFI_LINKER
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_DEFAULT_EFI_LINKER}
    DESCRIPTION "Define the linker to use for linking EFI applications"
    OPTIONS lld-link
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EFI_FS0
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_DEFAULT_EFI_FS0}
    DESCRIPTION "Define the file location of FS0 for UEFI"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_PAGE_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL ${BSL_PAGE_SIZE}
    DESCRIPTION "Defines the hypervisor's page size in bytes"
    OPTIONS 0x1000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_PAGE_SHIFT
    CONFIG_TYPE STRING
    DEFAULT_VAL "12"
    DESCRIPTION "Defines the hypervisor's page size in bytes (as a shift)"
    OPTIONS 12
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    bf_add_config(
        CONFIG_NAME HYPERVISOR_SERIAL_PORT
        CONFIG_TYPE STRING
        DEFAULT_VAL "0x03F8"
        DESCRIPTION "Defines the hypervisor's serial port"
        SKIP_VALIDATION
    )
else()
    bf_add_config(
        CONFIG_NAME HYPERVISOR_SERIAL_PORTH
        CONFIG_TYPE STRING
        DEFAULT_VAL "0xFE20"
        DESCRIPTION "Defines the upper 16 bits of the hypervisor's UART0 base address (defaults to RPi4)"
        SKIP_VALIDATION
    )

    bf_add_config(
        CONFIG_NAME HYPERVISOR_SERIAL_PORTL
        CONFIG_TYPE STRING
        DEFAULT_VAL "0x1000"
        DESCRIPTION "Defines the lower 16 bits of the hypervisor's UART0 base address (defaults to RPi4)"
        SKIP_VALIDATION
    )
endif()

bf_add_config(
    CONFIG_NAME HYPERVISOR_DEBUG_RING_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x1FFF0"
    DESCRIPTION "Defines the hypervisor's debug ring size in bytes"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_VMEXIT_LOG_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "5"
    DESCRIPTION "Defines the hypervisor's vmexit log size in # of entries"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MAX_ELF_FILE_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x800000"
    DESCRIPTION "Defines the hypervisor's max ELF file size supported"
    OPTIONS 0x800000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MAX_SEGMENTS
    CONFIG_TYPE STRING
    DEFAULT_VAL "3"
    DESCRIPTION "Defines the hypervisor's max number of program segments per ELF file supported"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MAX_EXTENSIONS
    CONFIG_TYPE STRING
    DEFAULT_VAL "1"
    DESCRIPTION "Defines the hypervisor's max number of extensions supported"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MAX_PPS
    CONFIG_TYPE STRING
    DEFAULT_VAL "128"
    DESCRIPTION "Defines the hypervisor's max number of physical processors supported"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MAX_VMS
    CONFIG_TYPE STRING
    DEFAULT_VAL "16"
    DESCRIPTION "Defines the hypervisor's max number of virtual machines supported"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MAX_VPS
    CONFIG_TYPE STRING
    DEFAULT_VAL "256"
    DESCRIPTION "Defines the hypervisor's max number of virtual processors supported"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MAX_VPSS
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_MAX_VPS}
    DESCRIPTION "Defines the hypervisor's max number of virtual processor states"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MK_DIRECT_MAP_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x0000400000000000"
    DESCRIPTION "Defines an microkernel's default direct map address"
    OPTIONS 0x0000400000000000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MK_DIRECT_MAP_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x0000200000000000"
    DESCRIPTION "Defines an microkernel's default direct map size in bytes"
    OPTIONS 0x0000200000000000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MK_STACK_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x0000008000000000"
    DESCRIPTION "Defines the microkernel's default stack address"
    OPTIONS 0x0000008000000000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MK_STACK_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x8000"
    DESCRIPTION "Defines the microkernel's stack size in bytes"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MK_CODE_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x0000028000000000"
    DESCRIPTION "Defines the microkernel's default code address"
    OPTIONS 0x0000028000000000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MK_CODE_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_MAX_ELF_FILE_SIZE}
    DESCRIPTION "Defines the microkernel's default code max size in bytes"
    OPTIONS ${HYPERVISOR_MAX_ELF_FILE_SIZE}
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MK_PAGE_POOL_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_MK_DIRECT_MAP_ADDR}
    DESCRIPTION "Defines the hypervisor's default page pool address"
    OPTIONS ${HYPERVISOR_MK_DIRECT_MAP_ADDR}
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MK_PAGE_POOL_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x8000000"
    DESCRIPTION "Defines the hypervisor's default page pool size in bytes"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MK_HUGE_POOL_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_MK_DIRECT_MAP_ADDR}
    DESCRIPTION "Defines the microkernel's default huge pool address"
    OPTIONS ${HYPERVISOR_MK_DIRECT_MAP_ADDR}
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_MK_HUGE_POOL_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x10000"
    DESCRIPTION "Defines the microkernel's default huge pool size in bytes"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_DIRECT_MAP_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x0000600000000000"
    DESCRIPTION "Defines an extension's default direct map address"
    OPTIONS 0x0000600000000000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_DIRECT_MAP_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x0000200000000000"
    DESCRIPTION "Defines an extension's default direct map size in bytes"
    OPTIONS 0x0000200000000000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_STACK_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x0000308000000000"
    DESCRIPTION "Defines an extension's default stack address"
    OPTIONS 0x0000308000000000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_STACK_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x8000"
    DESCRIPTION "Defines an extension's stack size in bytes"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_CODE_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x0000328000000000"
    DESCRIPTION "Defines an extension's default code address"
    OPTIONS 0x0000328000000000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_CODE_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_MAX_ELF_FILE_SIZE}
    DESCRIPTION "Defines an extension's default code max size in bytes"
    OPTIONS ${HYPERVISOR_MAX_ELF_FILE_SIZE}
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_TLS_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x0000338000000000"
    DESCRIPTION "Defines an extension's default TLS address"
    OPTIONS 0x0000338000000000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_TLS_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x2000"
    DESCRIPTION "Defines an extension's default TLS size in bytes (not modifiable)"
    OPTIONS 0x2000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_PAGE_POOL_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_EXT_DIRECT_MAP_ADDR}
    DESCRIPTION "Defines an extension's default page pool address"
    OPTIONS ${HYPERVISOR_EXT_DIRECT_MAP_ADDR}
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_PAGE_POOL_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_MK_PAGE_POOL_SIZE}
    DESCRIPTION "Defines an extension's default page pool max size in bytes"
    OPTIONS ${HYPERVISOR_MK_PAGE_POOL_SIZE}
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_HUGE_POOL_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_EXT_DIRECT_MAP_ADDR}
    DESCRIPTION "Defines an extension's default huge pool address"
    OPTIONS ${HYPERVISOR_EXT_DIRECT_MAP_ADDR}
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_HUGE_POOL_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_MK_HUGE_POOL_SIZE}
    DESCRIPTION "Defines an extension's default huge pool max size in bytes"
    OPTIONS ${HYPERVISOR_MK_HUGE_POOL_SIZE}
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_HEAP_POOL_ADDR
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x0000348000000000"
    DESCRIPTION "Defines an extension's default heap pool address in bytes"
    OPTIONS 0x0000348000000000
)

bf_add_config(
    CONFIG_NAME HYPERVISOR_EXT_HEAP_POOL_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL ${HYPERVISOR_MK_PAGE_POOL_SIZE}
    DESCRIPTION "Defines an extension's default heap pool max size"
    OPTIONS ${HYPERVISOR_MK_PAGE_POOL_SIZE}
)
