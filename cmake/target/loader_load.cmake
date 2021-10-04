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

if(HYPERVISOR_BUILD_LOADER AND NOT HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_custom_target(loader_load
            COMMAND ${CMAKE_COMMAND} -E chdir ${hypervisor_SOURCE_DIR}/loader/linux sudo make load CMAKE_BINARY_DIR='${CMAKE_BINARY_DIR}'
            VERBATIM
        )
        add_custom_target(driver_load
            COMMAND ${CMAKE_COMMAND} -E chdir ${hypervisor_SOURCE_DIR}/loader/linux sudo make load CMAKE_BINARY_DIR='${CMAKE_BINARY_DIR}'
            VERBATIM
        )
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        add_custom_target(loader_load
            COMMAND ${CMAKE_COMMAND} -E chdir ${hypervisor_SOURCE_DIR}/loader/windows certmgr /add x64/Debug/loader.cer /s /r localMachine root
            COMMAND ${CMAKE_COMMAND} -E chdir ${hypervisor_SOURCE_DIR}/loader/windows certmgr /add x64/Debug/loader.cer /s /r localMachine trustedpublisher
            COMMAND ${CMAKE_COMMAND} -E chdir ${hypervisor_SOURCE_DIR}/loader/windows devcon remove ROOT\\loader
            COMMAND ${CMAKE_COMMAND} -E chdir ${hypervisor_SOURCE_DIR}/loader/windows devcon install x64/Debug/loader/loader.inf ROOT\\loader
            VERBATIM
        )
        add_custom_target(driver_load
            COMMAND ${CMAKE_COMMAND} -E chdir ${hypervisor_SOURCE_DIR}/loader/windows certmgr /add x64/Debug/loader.cer /s /r localMachine root
            COMMAND ${CMAKE_COMMAND} -E chdir ${hypervisor_SOURCE_DIR}/loader/windows certmgr /add x64/Debug/loader.cer /s /r localMachine trustedpublisher
            COMMAND ${CMAKE_COMMAND} -E chdir ${hypervisor_SOURCE_DIR}/loader/windows devcon remove ROOT\\loader
            COMMAND ${CMAKE_COMMAND} -E chdir ${hypervisor_SOURCE_DIR}/loader/windows devcon install x64/Debug/loader/loader.inf ROOT\\loader
            VERBATIM
        )
    else()
        message(FATAL_ERROR "Unsupported CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
    endif()
endif()
