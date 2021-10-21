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

add_custom_target(rust-clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/syscall/target
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_SOURCE_DIR}/syscall/Cargo.lock
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_SOURCE_DIR}/syscall/Cargo.toml
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_SOURCE_DIR}/syscall/constants.rs
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_SOURCE_DIR}/syscall/CMakeLists.txt
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/example/default_rust/target
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_SOURCE_DIR}/example/default_rust/Cargo.lock
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_SOURCE_DIR}/example/default_rust/Cargo.toml
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_SOURCE_DIR}/example/default_rust/CMakeLists.txt
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/rust/syscall_rust_files.txt
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/ext_cross_compile/build/rust_files.txt
    VERBATIM
)
