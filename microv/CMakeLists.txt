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

add_executable(microv)

target_include_directories(microv PRIVATE
    include
    src
)

target_sources(microv PRIVATE
    src/execute.cpp
    src/init_handler.cpp
    src/start.s
    $<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:src/x64/intel/intel_cpuid.cpp>
    $<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:src/x64/intel/intel_instruction_pointer.cpp>
    src/main.cpp
)

target_link_libraries(microv PRIVATE
    bsl
    pal
    extension
)

target_compile_options(microv PRIVATE
    "-c"
    "-Wno-unused-command-line-argument"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:--target=amd64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:--target=aarch64-unknown-linux-gnu>"
)

target_link_options(microv PRIVATE
    "-Wno-unused-command-line-argument"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:--target=amd64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:--target=aarch64-unknown-linux-gnu>"
)
