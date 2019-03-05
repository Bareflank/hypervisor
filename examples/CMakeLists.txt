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

cmake_minimum_required(VERSION 3.10)
project(examples C CXX)

init_project(examples INTERFACE)

if(PREFIX STREQUAL "vmm")
    add_executable(cpuidcount_vmm cpuidcount/vmm/main.cpp)
    add_executable(rdtsc_vmm rdtsc/vmm/main.cpp)
    add_executable(vpid_vmm vpid/vmm/main.cpp)
    add_executable(hook_vmm hook/vmm/main.cpp)

    target_link_libraries(cpuidcount_vmm PRIVATE vmm::bfvmm)
    target_link_libraries(rdtsc_vmm PRIVATE vmm::bfvmm)
    target_link_libraries(vpid_vmm PRIVATE vmm::bfvmm)
    target_link_libraries(hook_vmm PRIVATE vmm::bfvmm)

    install(TARGETS cpuidcount_vmm DESTINATION bin EXPORT examples-vmm-targets)
    install(TARGETS rdtsc_vmm DESTINATION bin EXPORT examples-vmm-targets)
    install(TARGETS vpid_vmm DESTINATION bin EXPORT examples-vmm-targets)
    install(TARGETS hook_vmm DESTINATION bin EXPORT examples-vmm-targets)
elseif(PREFIX STREQUAL "userspace")
    add_executable(hook hook/userspace/hook.cpp)
    target_link_libraries(hook PRIVATE userspace::bfintrinsics)
    target_include_directories(hook PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/../bfsdk/include
        ${CMAKE_CURRENT_LIST_DIR}/../bfintrinsics/include
    )
    install(TARGETS hook DESTINATION bin EXPORT examples-userspace-targets)
endif()

fini_project()








