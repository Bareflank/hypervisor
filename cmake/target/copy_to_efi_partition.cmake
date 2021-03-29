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

if(HYPERVISOR_BUILD_EFI)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_custom_target(copy_to_efi_partition
            COMMAND sudo cmake -E copy ${CMAKE_BINARY_DIR}/efi_cross_compile/bin/bareflank_efi_loader ${HYPERVISOR_EFI_FS0}/start_bareflank.efi
            COMMAND sudo cmake -E copy ${CMAKE_BINARY_DIR}/mk_cross_compile/bin/kernel ${HYPERVISOR_EFI_FS0}/bareflank_kernel
            COMMAND sudo cmake -E copy ${CMAKE_BINARY_DIR}/ext_cross_compile/bin/${HYPERVISOR_EXTENSIONS} ${HYPERVISOR_EFI_FS0}/bareflank_extension0
            COMMAND sudo cmake -E copy ${CMAKE_SOURCE_DIR}/utils/Shell.efi ${HYPERVISOR_EFI_FS0}/bareflank_efi_shell.efi
            VERBATIM
        )
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        add_custom_target(copy_to_efi_partition
            COMMAND mountvol X: /d | true
            COMMAND mountvol X: /s | true
            COMMAND cmake -E copy ${CMAKE_BINARY_DIR}/efi_cross_compile/bin/bareflank_efi_loader ${HYPERVISOR_EFI_FS0}/start_bareflank.efi
            COMMAND cmake -E copy ${CMAKE_BINARY_DIR}/mk_cross_compile/bin/kernel ${HYPERVISOR_EFI_FS0}/bareflank_kernel
            COMMAND cmake -E copy ${CMAKE_BINARY_DIR}/ext_cross_compile/bin/${HYPERVISOR_EXTENSIONS} ${HYPERVISOR_EFI_FS0}/bareflank_extension0
            COMMAND cmake -E copy ${CMAKE_SOURCE_DIR}/utils/Shell.efi ${HYPERVISOR_EFI_FS0}/bareflank_efi_shell.efi
            COMMAND mountvol X: /d | true
            VERBATIM
        )
    else()
        message(FATAL_ERROR "Unsupported CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
    endif()
endif()
