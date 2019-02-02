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

list(APPEND ARGN
    DEPENDS bfvmm_hve
    DEPENDS bfvmm_vcpu
    DEPENDS bfvmm_memory_manager
    DEFINES STATIC_HVE
    DEFINES STATIC_VCPU
    DEFINES STATIC_MEMORY_MANAGER
    DEFINES STATIC_INTRINSICS
)

do_test(test_gdt
    SOURCES arch/x64/test_gdt.cpp
    ${ARGN}
)

do_test(test_idt
    SOURCES arch/x64/test_idt.cpp
    ${ARGN}
)

do_test(test_control_register
    SOURCES arch/intel_x64/vmexit/test_control_register.cpp
    ${ARGN}
)

do_test(test_rdmsr
    SOURCES arch/intel_x64/vmexit/test_rdmsr.cpp
    ${ARGN}
)

do_test(test_wrmsr
    SOURCES arch/intel_x64/vmexit/test_wrmsr.cpp
    ${ARGN}
)

do_test(test_check_vmcs_controls_fields
    SOURCES arch/intel_x64/test_check_vmcs_controls_fields.cpp
    ${ARGN}
)

do_test(test_check_vmcs_guest_fields
    SOURCES arch/intel_x64/test_check_vmcs_guest_fields.cpp
    ${ARGN}
)

do_test(test_check_vmcs_host_fields
    SOURCES arch/intel_x64/test_check_vmcs_host_fields.cpp
    ${ARGN}
)

do_test(test_nmi
    SOURCES arch/intel_x64/test_nmi.cpp
    ${ARGN}
)

do_test(test_exception
    SOURCES arch/intel_x64/test_exception.cpp
    ${ARGN}
)

do_test(test_check
    SOURCES arch/intel_x64/test_check.cpp
    ${ARGN}
)

do_test(test_exit_handler
    SOURCES arch/intel_x64/test_exit_handler.cpp
    ${ARGN}
)

do_test(test_bfvmm_vcpu
    SOURCES arch/intel_x64/test_vcpu.cpp
    ${ARGN}
)

do_test(test_vmcs
    SOURCES arch/intel_x64/test_vmcs.cpp
    ${ARGN}
)

do_test(test_vmx
    SOURCES arch/intel_x64/test_vmx.cpp
    ${ARGN}
)
