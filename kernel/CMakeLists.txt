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

add_executable(kernel)

target_include_directories(kernel PRIVATE
    src
    src/x64
)

target_sources(kernel PRIVATE
    src/x64/__stack_chk_fail.S
    src/x64/call_ext.S
    src/x64/dispatch_esr_entry.S
    src/x64/dispatch_syscall_entry.S
    src/x64/fast_fail_entry.S
    src/x64/get_current_tls.S
    src/x64/mk_main_entry.S
    src/x64/return_to_current_fast_fail.S
    src/x64/return_to_mk.S
    src/x64/return_to_vmexit_loop.S
    src/x64/serial_write.S
    src/x64/set_esr.S
    src/x64/smap_guard_t.S
    src/x64/vmexit_loop_entry.S

    src/dispatch_esr_trampoline.cpp
    src/dispatch_syscall_trampoline.cpp
    src/fast_fail_trampoline.cpp
    src/mk_main_trampoline.cpp
    src/msg_halt.cpp
    src/msg_stack_chk_fail.cpp
    src/vmexit_loop_trampoline.cpp
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
    target_include_directories(kernel PRIVATE
        src/x64/amd
    )
    target_sources(kernel PRIVATE
        src/x64/amd/intrinsic_t.S
        src/x64/amd/promote.S
    )
elseif(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    target_include_directories(kernel PRIVATE
        src/x64/intel
    )
    target_sources(kernel PRIVATE
        src/x64/intel/intrinsic_t.S
        src/x64/intel/promote.S
    )
else()
    message(FATAL_ERROR "Unsupported HYPERVISOR_TARGET_ARCH: ${HYPERVISOR_TARGET_ARCH}")
endif()

target_link_libraries(kernel PRIVATE
    bsl
    loader
    syscall
    hypervisor
)

install(TARGETS kernel DESTINATION bin)
