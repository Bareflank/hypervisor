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

# Add's An Integration Test Target
#
macro(hypervisor_add_integration NAME HEADERS)
    add_executable(integration_${NAME})

    target_include_directories(integration_${NAME} PRIVATE
        support
        support/include
        support/src
    )

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        target_include_directories(integration_${NAME} PRIVATE
            support/include/x64
            support/include/x64/amd
            support/src/x64
            support/src/x64/amd
        )

        target_sources(integration_${NAME} PRIVATE
            support/src/x64/intrinsic_cpuid_impl.S
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        target_include_directories(integration_${NAME} PRIVATE
            support/include/x64
            support/include/x64/intel
            support/src/x64
            support/src/x64/intel
        )

        target_sources(integration_${NAME} PRIVATE
            support/src/x64/intrinsic_cpuid_impl.S
        )
    endif()

    target_sources(integration_${NAME} PRIVATE
        ${NAME}.cpp
    )

    target_compile_options(integration_${NAME} PRIVATE -Wframe-larger-than=4294967295)

    set_property(SOURCE ${NAME} APPEND PROPERTY OBJECT_DEPENDS ${${HEADERS}})

    target_link_libraries(integration_${NAME} PRIVATE
        runtime
        bsl
        loader
        syscall
        lib
    )

    if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
        add_custom_command(TARGET integration_${NAME} POST_BUILD COMMAND ${CMAKE_STRIP} integration_${NAME})
    endif()
endmacro(hypervisor_add_integration)
