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

# macro(do_test str)
#     add_executable(test_${str} test_${str}.cpp)
#     target_compile_definitions(test_${str} PRIVATE STATIC_DEBUG_RING)
#     target_link_libraries(test_${str} bfvmm_debug_ring_static)
#     target_link_libraries(test_${str} test_catch)
#     add_test(test_${str} test_${str})
#     install(TARGETS test_${str} DESTINATION ${BUILD_SYSROOT_TEST}/bin/bfvmm)
# endmacro(do_test)

do_test(
    NAME test_debug_ring
    LIBS bfvmm_debug_ring_static
)
