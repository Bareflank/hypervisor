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

include(${bsl_SOURCE_DIR}/cmake/colors.cmake)
include(${bsl_SOURCE_DIR}/cmake/build_command.cmake)

# Add Info
#
# Adds hypervisor specific info to the info target
#
macro(hypervisor_add_info)
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_GRN} Hypervisor Configuration:${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   BSL                            ${BF_COLOR_CYN}${bsl_SOURCE_DIR}${BF_COLOR_RST}"
        VERBATIM
    )

    if(DEFINED hypervisor_SOURCE_DIR)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR                     ${BF_COLOR_CYN}${hypervisor_SOURCE_DIR}${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXTENSIONS          ${BF_COLOR_CYN}${HYPERVISOR_EXTENSIONS}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXTENSIONS_DIR      ${BF_COLOR_CYN}${HYPERVISOR_EXTENSIONS_DIR}${BF_COLOR_RST}"
        VERBATIM
    )

    if(HYPERVISOR_BUILD_LOADER)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_BUILD_LOADER        ${BF_COLOR_GRN}enabled${BF_COLOR_RST}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_BUILD_LOADER        ${BF_COLOR_RED}disabled${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    if(HYPERVISOR_BUILD_VMMCTL)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_BUILD_VMMCTL        ${BF_COLOR_GRN}enabled${BF_COLOR_RST}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_BUILD_VMMCTL        ${BF_COLOR_RED}disabled${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    if(HYPERVISOR_BUILD_MICROKERNEL)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_BUILD_MICROKERNEL   ${BF_COLOR_GRN}enabled${BF_COLOR_RST}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_BUILD_MICROKERNEL   ${BF_COLOR_RED}disabled${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    if(HYPERVISOR_BUILD_EFI)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_BUILD_EFI           ${BF_COLOR_GRN}enabled${BF_COLOR_RST}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_BUILD_EFI           ${BF_COLOR_RED}disabled${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_TARGET_ARCH         ${BF_COLOR_CYN}${HYPERVISOR_TARGET_ARCH}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_CXX_LINKER          ${BF_COLOR_CYN}${HYPERVISOR_CXX_LINKER}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EFI_LINKER          ${BF_COLOR_CYN}${HYPERVISOR_EFI_LINKER}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EFI_FS0             ${BF_COLOR_CYN}${HYPERVISOR_EFI_FS0}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_PAGE_SIZE           ${BF_COLOR_CYN}${HYPERVISOR_PAGE_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_PAGE_SHIFT          ${BF_COLOR_CYN}${HYPERVISOR_PAGE_SHIFT}${BF_COLOR_RST}"
        VERBATIM
    )

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_SERIAL_PORT         ${BF_COLOR_CYN}${HYPERVISOR_SERIAL_PORT}${BF_COLOR_RST}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_SERIAL_PORTH         ${BF_COLOR_CYN}${HYPERVISOR_SERIAL_PORTH}${BF_COLOR_RST}"
            VERBATIM
        )
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_SERIAL_PORTL         ${BF_COLOR_CYN}${HYPERVISOR_SERIAL_PORTL}${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_DEBUG_RING_SIZE     ${BF_COLOR_CYN}${HYPERVISOR_DEBUG_RING_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_VMEXIT_LOG_SIZE     ${BF_COLOR_CYN}${HYPERVISOR_VMEXIT_LOG_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MAX_ELF_FILE_SIZE   ${BF_COLOR_CYN}${HYPERVISOR_MAX_ELF_FILE_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MAX_SEGMENTS        ${BF_COLOR_CYN}${HYPERVISOR_MAX_SEGMENTS}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MAX_EXTENSIONS      ${BF_COLOR_CYN}${HYPERVISOR_MAX_EXTENSIONS}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MAX_PPS             ${BF_COLOR_CYN}${HYPERVISOR_MAX_PPS}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MAX_VMS             ${BF_COLOR_CYN}${HYPERVISOR_MAX_VMS}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MAX_VPS             ${BF_COLOR_CYN}${HYPERVISOR_MAX_VPS}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MAX_VSS             ${BF_COLOR_CYN}${HYPERVISOR_MAX_VSS}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MK_DIRECT_MAP_ADDR  ${BF_COLOR_CYN}${HYPERVISOR_MK_DIRECT_MAP_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MK_DIRECT_MAP_SIZE  ${BF_COLOR_CYN}${HYPERVISOR_MK_DIRECT_MAP_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MK_STACK_ADDR       ${BF_COLOR_CYN}${HYPERVISOR_MK_STACK_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MK_STACK_SIZE       ${BF_COLOR_CYN}${HYPERVISOR_MK_STACK_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MK_CODE_ADDR        ${BF_COLOR_CYN}${HYPERVISOR_MK_CODE_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MK_CODE_SIZE        ${BF_COLOR_CYN}${HYPERVISOR_MK_CODE_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MK_PAGE_POOL_ADDR   ${BF_COLOR_CYN}${HYPERVISOR_MK_PAGE_POOL_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MK_PAGE_POOL_SIZE   ${BF_COLOR_CYN}${HYPERVISOR_MK_PAGE_POOL_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MK_HUGE_POOL_ADDR   ${BF_COLOR_CYN}${HYPERVISOR_MK_HUGE_POOL_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_MK_HUGE_POOL_SIZE   ${BF_COLOR_CYN}${HYPERVISOR_MK_HUGE_POOL_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_DIRECT_MAP_ADDR ${BF_COLOR_CYN}${HYPERVISOR_EXT_DIRECT_MAP_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_DIRECT_MAP_SIZE ${BF_COLOR_CYN}${HYPERVISOR_EXT_DIRECT_MAP_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_STACK_ADDR      ${BF_COLOR_CYN}${HYPERVISOR_EXT_STACK_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_STACK_SIZE      ${BF_COLOR_CYN}${HYPERVISOR_EXT_STACK_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_FAIL_STACK_ADDR      ${BF_COLOR_CYN}${HYPERVISOR_EXT_FAIL_STACK_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_FAIL_STACK_SIZE      ${BF_COLOR_CYN}${HYPERVISOR_EXT_FAIL_STACK_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_CODE_ADDR       ${BF_COLOR_CYN}${HYPERVISOR_EXT_CODE_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_CODE_SIZE       ${BF_COLOR_CYN}${HYPERVISOR_EXT_CODE_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_TLS_ADDR        ${BF_COLOR_CYN}${HYPERVISOR_EXT_TLS_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_TLS_SIZE        ${BF_COLOR_CYN}${HYPERVISOR_EXT_TLS_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_PAGE_POOL_ADDR  ${BF_COLOR_CYN}${HYPERVISOR_EXT_PAGE_POOL_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_PAGE_POOL_SIZE  ${BF_COLOR_CYN}${HYPERVISOR_EXT_PAGE_POOL_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_HUGE_POOL_ADDR  ${BF_COLOR_CYN}${HYPERVISOR_EXT_HUGE_POOL_ADDR}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   HYPERVISOR_EXT_HUGE_POOL_SIZE  ${BF_COLOR_CYN}${HYPERVISOR_EXT_HUGE_POOL_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo " "
        VERBATIM
    )
endmacro(hypervisor_add_info)
