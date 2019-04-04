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

add_library(bfvmm_memory_manager)

target_link_libraries(bfvmm_memory_manager PUBLIC ${PREFIX}::bfroot)
target_include_directories(bfvmm_memory_manager PUBLIC
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/include>
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/../bfintrinsics/include>
    $<${BUILD_INCLUDE}:${PROJECT_ROOT}/../bfsdk/include>
)
target_sources(bfvmm_memory_manager PRIVATE
    memory_manager.cpp
    $<$<STREQUAL:${BUILD_TARGET_ARCH},x86_64>:arch/x64/cr3/helpers.cpp>
)

install(TARGETS bfvmm_memory_manager DESTINATION lib EXPORT bfvmm-${PREFIX}-targets)
