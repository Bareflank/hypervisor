#
# Copyright (C) 2019 Assured Information Security, Inc.
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

if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
    list(APPEND SOURCES
        arch/intel_x64/vmexit/control_register.cpp
        arch/intel_x64/vmexit/cpuid.cpp
        arch/intel_x64/vmexit/ept_misconfiguration.cpp
        arch/intel_x64/vmexit/ept_violation.cpp
        arch/intel_x64/vmexit/external_interrupt.cpp
        arch/intel_x64/vmexit/init_signal.cpp
        arch/intel_x64/vmexit/interrupt_window.cpp
        arch/intel_x64/vmexit/io_instruction.cpp
        arch/intel_x64/vmexit/monitor_trap.cpp
        arch/intel_x64/vmexit/nmi_window.cpp
        arch/intel_x64/vmexit/nmi.cpp
        arch/intel_x64/vmexit/rdmsr.cpp
        arch/intel_x64/vmexit/sipi_signal.cpp
        arch/intel_x64/vmexit/preemption_timer.cpp
        arch/intel_x64/vmexit/wrmsr.cpp
        arch/intel_x64/vmexit/xsetbv.cpp
        arch/intel_x64/check_vmcs_control_fields.cpp
        arch/intel_x64/check_vmcs_guest_fields.cpp
        arch/intel_x64/check_vmcs_host_fields.cpp
        arch/intel_x64/ept.cpp
        arch/intel_x64/exception.cpp
        arch/intel_x64/exit_handler.cpp
        arch/intel_x64/interrupt_queue.cpp
        arch/intel_x64/microcode.cpp
        arch/intel_x64/mtrrs.cpp
        arch/intel_x64/vcpu.cpp
        arch/intel_x64/vmcs.cpp
        arch/intel_x64/vmx.cpp
        arch/intel_x64/vpid.cpp
        arch/x64/unmapper.cpp
    )

    if(NOT ENABLE_MOCKING)
        if(NOT WIN32)
            list(APPEND SOURCES
                arch/intel_x64/exception.asm
                arch/intel_x64/exit_handler_entry.asm
                arch/intel_x64/vmcs_launch.asm
                arch/intel_x64/vmcs_promote.asm
                arch/intel_x64/vmcs_resume.asm
            )
        endif()
        list(APPEND SOURCES
            arch/intel_x64/vcpu_factory.cpp
        )
    endif()
elseif(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    message(WARNING "Unimplemented")
else()
    message(FATAL_ERROR "Unsupported archiecture")
endif()

add_static_library(
    bfvmm_hve
    SOURCES ${SOURCES}
    DEFINES STATIC_HVE
    DEFINES STATIC_VCPU
    DEFINES STATIC_MEMORY_MANAGER
    DEFINES STATIC_INTRINSICS
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(DIRECTORY ../../include/hve/ DESTINATION include/bfvmm/hve)
