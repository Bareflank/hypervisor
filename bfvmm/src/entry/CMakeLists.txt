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

add_library(bfvmm_entry)

target_sources(bfvmm_entry PRIVATE entry.cpp)
target_link_libraries(bfvmm_entry PUBLIC vmm::bfroot)
target_include_directories(bfvmm_entry PUBLIC
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/include>
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/../bfintrinsics/include>
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/../bfsdk/include>
)

install(TARGETS bfvmm_entry DESTINATION lib EXPORT bfvmm-vmm-targets)
