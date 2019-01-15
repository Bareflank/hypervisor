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

unset(BFFLAGS_USERSPACE)
unset(BFFLAGS_USERSPACE_C)
unset(BFFLAGS_USERSPACE_CXX)
unset(BFFLAGS_USERSPACE_X86_64)
unset(BFFLAGS_USERSPACE_AARCH64)

list(APPEND BFFLAGS_USERSPACE
    -DGSL_THROW_ON_CONTRACT_VIOLATION
    -DNATIVE
    -D${OSTYPE}
    -D${ABITYPE}
)

if(NOT WIN32)
    list(APPEND BFFLAGS_USERSPACE
        -fpic
        -fstack-protector-strong
        -fvisibility=hidden
        -Wno-deprecated-declarations
    )

    list(APPEND BFFLAGS_USERSPACE_C
        -std=c11
    )

    list(APPEND BFFLAGS_USERSPACE_CXX
        -std=c++17
        -fvisibility-inlines-hidden
    )

    list(APPEND BFFLAGS_USERSPACE_X86_64
        -msse
        -msse2
        -msse3
    )
else()
    list(APPEND BFFLAGS_USERSPACE
        /EHsc
        /bigobj
        /WX
        /D_SCL_SECURE_NO_WARNINGS
        /D_CRT_SECURE_NO_WARNINGS
        /DNOMINMAX
    )

    list(APPEND BFFLAGS_USERSPACE_C
        /std:c++17
    )

    list(APPEND BFFLAGS_USERSPACE_CXX
        /std:c++17
    )
endif()
