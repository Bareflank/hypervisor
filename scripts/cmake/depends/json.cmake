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

if(ENABLE_BUILD_VMM OR ENABLE_BUILD_USERSPACE OR ENABLE_BUILD_TEST)
    message(STATUS "Including dependency: json")

    download_dependency(
        json
        URL         ${JSON_URL}
        URL_MD5     ${JSON_URL_MD5}
    )
endif()

list(APPEND JSON_CONFIGURE_FLAGS
    -DJSON_BuildTests=OFF
)

if(ENABLE_BUILD_VMM)
    add_dependency(
        json vmm
        CMAKE_ARGS  ${JSON_CONFIGURE_FLAGS}
    )
endif()

if(ENABLE_BUILD_USERSPACE)
    add_dependency(
        json userspace
        CMAKE_ARGS  ${JSON_CONFIGURE_FLAGS}
    )
endif()

if(ENABLE_BUILD_TEST)
    add_dependency(
        json test
        CMAKE_ARGS  ${JSON_CONFIGURE_FLAGS}
    )
endif()
