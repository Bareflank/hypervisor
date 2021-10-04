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

add_custom_target(integration)

# Add's An Integration Test Target
#
macro(hypervisor_add_integration_target NAME)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_custom_target(integration_${NAME}
            COMMAND sync
            COMMAND sudo vmmctl/vmmctl start ${CMAKE_BINARY_DIR}/kernel ${CMAKE_BINARY_DIR}/ext_cross_compile/build/integration/integration_${NAME} | true
            COMMAND sudo vmmctl/vmmctl dump
            VERBATIM
        )
        add_custom_target(${NAME}
            COMMAND sync
            COMMAND sudo vmmctl/vmmctl start ${CMAKE_BINARY_DIR}/kernel ${CMAKE_BINARY_DIR}/ext_cross_compile/build/integration/integration_${NAME} | true
            COMMAND sudo vmmctl/vmmctl dump
            VERBATIM
        )
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        add_custom_target(integration_${NAME}
            COMMAND vmmctl/vmmctl start ${CMAKE_BINARY_DIR}/kernel ${CMAKE_BINARY_DIR}/ext_cross_compile/build/integration/integration_${NAME} | true
            COMMAND vmmctl/vmmctl dump
            VERBATIM
        )
        add_custom_target(${NAME}
            COMMAND vmmctl/vmmctl start ${CMAKE_BINARY_DIR}/kernel ${CMAKE_BINARY_DIR}/ext_cross_compile/build/integration/integration_${NAME} | true
            COMMAND vmmctl/vmmctl dump
            VERBATIM
        )
    else()
        message(FATAL_ERROR "Unsupported CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
    endif()

    add_custom_command(TARGET integration
        COMMAND ${CMAKE_COMMAND} --build . --target integration_${NAME}
        VERBATIM
    )
endmacro(hypervisor_add_integration_target)
