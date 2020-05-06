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

add_library(syscall)

target_include_directories(syscall PUBLIC
    include
)

target_sources(syscall PRIVATE
    src/execute.cpp
    src/init_handler.cpp
    $<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:src/x64/intel/intel_cpuid.cpp>
    $<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:src/x64/intel/intel_instruction_pointer.cpp>
)

target_link_libraries(syscall PUBLIC
    bsl
    pal
)

target_compile_options(syscall PRIVATE
    "-c"
    "-Wno-unused-command-line-argument"
)

target_link_options(syscall PRIVATE
    "-Wno-unused-command-line-argument"
)

target_compile_options(syscall PUBLIC
    "-nostdlib"                  # TODO: Move to Clang
    "-ffreestanding"             # TODO: Move to Clang
    "-static"                    # TODO: Move to Clang
    "-fpie"                      # TODO: Move to Clang
    "-fpic"                      # TODO: Move to Clang
    "-fuse-ld=lld"               # TODO: Move to Clang
    "-D__bareflank__"            # TODO: Move to Clang
    "-Wl,--no-dynamic-linker"    # TODO: Move to Clang
    "-Wl,-zmax-page-size=0x1000" # TODO: Move to Clang
    "-Wl,-znoexecstack"          # TODO: Move to Clang
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:--target=amd64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:--target=aarch64-unknown-linux-gnu>"
)

target_link_options(syscall PUBLIC
    "-nostdlib"                  # TODO: Move to Clang
    "-ffreestanding"             # TODO: Move to Clang
    "-static"                    # TODO: Move to Clang
    "-fpie"                      # TODO: Move to Clang
    "-fpic"                      # TODO: Move to Clang
    "-fuse-ld=lld"               # TODO: Move to Clang
    "-D__bareflank__"            # TODO: Move to Clang
    "-Wl,--no-dynamic-linker"    # TODO: Move to Clang
    "-Wl,-zmax-page-size=0x1000" # TODO: Move to Clang
    "-Wl,-znoexecstack"          # TODO: Move to Clang
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:--target=amd64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:--target=aarch64-unknown-linux-gnu>"
)
