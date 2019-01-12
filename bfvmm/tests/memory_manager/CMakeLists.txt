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

do_test(test_memory_manager
    SOURCES test_memory_manager.cpp
    DEPENDS bfvmm_memory_manager
    DEFINES STATIC_MEMORY_MANAGER
)

do_test(test_buddy_allocator
    SOURCES test_buddy_allocator.cpp
    DEPENDS bfvmm_memory_manager
    DEFINES STATIC_MEMORY_MANAGER
)

if(NOT WIN32)
    do_test(test_object_allocator
        SOURCES test_object_allocator.cpp
        DEPENDS bfvmm_memory_manager
        DEFINES STATIC_MEMORY_MANAGER
    )
endif()

if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
    do_test(test_helpers
        SOURCES arch/x64/cr3/test_helpers.cpp
        DEPENDS bfvmm_memory_manager
        DEFINES STATIC_MEMORY_MANAGER
    )

    do_test(test_mmap
        SOURCES arch/x64/cr3/test_mmap.cpp
        DEPENDS bfvmm_memory_manager
        DEFINES STATIC_MEMORY_MANAGER
    )
elseif(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    message(WARNING "Unimplemented")
else()
    message(FATAL_ERROR "Unsupported archiecture")
endif()
