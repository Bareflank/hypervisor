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

add_library(dummy_lib1 STATIC dummy_lib1.cpp)
add_library(dummy_lib2 STATIC dummy_lib2.cpp)

set_target_properties(dummy_lib1 PROPERTIES LINKER_LANGUAGE C)
set_target_properties(dummy_lib2 PROPERTIES LINKER_LANGUAGE C)

target_compile_definitions(dummy_lib1 INTERFACE STATIC_DUMMY)
target_compile_definitions(dummy_lib2 INTERFACE STATIC_DUMMY)

install(TARGETS dummy_lib1 DESTINATION lib)
install(TARGETS dummy_lib2 DESTINATION lib)
