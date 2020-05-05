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

macro(hypervisor_add_info)
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Hypervisor Configuration:"
        VERBATIM
    )

    # ------------------------------------------------------------------------------
    # options
    # ------------------------------------------------------------------------------

    if(HYPERVISOR_BUILD_LOADER)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   HYPERVISOR_BUILD_LOADER        ${BF_ENABLED}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   HYPERVISOR_BUILD_LOADER        ${BF_DISABLED}"
            VERBATIM
        )
    endif()

    if(HYPERVISOR_BUILD_VMMCTL)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   HYPERVISOR_BUILD_VMMCTL        ${BF_ENABLED}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   HYPERVISOR_BUILD_VMMCTL        ${BF_DISABLED}"
            VERBATIM
        )
    endif()

    # ------------------------------------------------------------------------------
    # settings
    # ------------------------------------------------------------------------------

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   HYPERVISOR_TARGET_ARCH         ${BF_COLOR_CYN}${HYPERVISOR_TARGET_ARCH}"
        VERBATIM
    )

    # --------------------------------------------------------------------------
    # final newline
    # --------------------------------------------------------------------------

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
        VERBATIM
    )
endmacro(hypervisor_add_info)

# ------------------------------------------------------------------------------
# done
# ------------------------------------------------------------------------------

if(NOT DEFINED HYPERVISOR_IS_SUBPROJECT)
    add_custom_target(info)
    bsl_add_info()
    hypervisor_add_info()
endif()
