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

if(BUILD_VMM OR BUILD_USERSPACE OR BUILD_TEST)
    message(STATUS "Including dependency: gsl")

    download_dependency(
        gsl
        URL         ${GSL_URL}
        URL_MD5     ${GSL_URL_MD5}
    )
endif()

list(APPEND GSL_CONFIGURE_FLAGS
    -DGSL_TEST=OFF
)

if(BUILD_VMM OR BUILD_TEST)
    add_dependency(
        gsl vmm
        CMAKE_ARGS  ${GSL_CONFIGURE_FLAGS}
    )
endif()

if(BUILD_USERSPACE)
    add_dependency(
        gsl userspace
        CMAKE_ARGS  ${GSL_CONFIGURE_FLAGS}
    )
endif()

if(BUILD_TEST)
    add_dependency(
        gsl test
        CMAKE_ARGS  ${GSL_CONFIGURE_FLAGS}
    )
endif()
