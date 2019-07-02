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

add_library(bfvmm_hve)

target_link_libraries(bfvmm_hve PUBLIC ${PREFIX}::bfroot)
target_include_directories(bfvmm_hve PUBLIC
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/include>
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/../bfintrinsics/include>
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/../bfsdk/include>
)
target_sources(bfvmm_hve PRIVATE
    $<${X64}:arch/x64/unmapper.cpp>

    $<${X64}:arch/intel_x64/vmexit/control_register.cpp>
    $<${X64}:arch/intel_x64/vmexit/cpuid.cpp>
    $<${X64}:arch/intel_x64/vmexit/ept_violation.cpp>
    $<${X64}:arch/intel_x64/vmexit/external_interrupt.cpp>
    $<${X64}:arch/intel_x64/vmexit/init_signal.cpp>
    $<${X64}:arch/intel_x64/vmexit/interrupt_window.cpp>
    $<${X64}:arch/intel_x64/vmexit/io_instruction.cpp>
    $<${X64}:arch/intel_x64/vmexit/monitor_trap.cpp>
    $<${X64}:arch/intel_x64/vmexit/nmi.cpp>
    $<${X64}:arch/intel_x64/vmexit/nmi_window.cpp>
    $<${X64}:arch/intel_x64/vmexit/preemption_timer.cpp>
    $<${X64}:arch/intel_x64/vmexit/rdmsr.cpp>
    $<${X64}:arch/intel_x64/vmexit/sipi_signal.cpp>
    $<${X64}:arch/intel_x64/vmexit/wrmsr.cpp>
    $<${X64}:arch/intel_x64/vmexit/xsetbv.cpp>

    $<${X64}:arch/intel_x64/check_vmcs_control_fields.cpp>
    $<${X64}:arch/intel_x64/check_vmcs_guest_fields.cpp>
    $<${X64}:arch/intel_x64/check_vmcs_host_fields.cpp>
    $<${X64}:arch/intel_x64/ept.cpp>
    $<${X64}:arch/intel_x64/exception.cpp>
    $<${X64}:arch/intel_x64/exit_handler.cpp>
    $<${X64}:arch/intel_x64/interrupt_queue.cpp>
    $<${X64}:arch/intel_x64/microcode.cpp>
    $<${X64}:arch/intel_x64/mtrrs.cpp>
    $<${X64}:arch/intel_x64/vcpu.cpp>
    $<${X64}:arch/intel_x64/vcpu_factory.cpp>
    $<${X64}:arch/intel_x64/vmcs.cpp>
    $<${X64}:arch/intel_x64/vmx.cpp>
    $<${X64}:arch/intel_x64/vpid.cpp>

    $<${X64_ASM}:arch/intel_x64/exception.asm>
    $<${X64_ASM}:arch/intel_x64/exit_handler_entry.asm>
    $<${X64_ASM}:arch/intel_x64/vmcs_launch.asm>
    $<${X64_ASM}:arch/intel_x64/vmcs_promote.asm>
    $<${X64_ASM}:arch/intel_x64/vmcs_resume.asm>
)

install(TARGETS bfvmm_hve DESTINATION lib EXPORT bfvmm-${PREFIX}-targets)
