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

# NOTE:
# - Add the tests themselves here. There are several variables that you can
#   add to the bf_add_test macro including:
#   - SOURCES = any source files that should be included in the test
#   - INCLUDES = any include directories that should be included in the test
#   - SYSTEM_INCLUDES = any system include directories that should be included
#     in the test. System includes are not included in a Clang Tidy check.
#   - LIBRARIES = any libraries that should be included in the test
#   - DEFINES = any definitions that should be included in the test
#
# - The high level CMake file for the tests already configures a number of
#   these automatically for you. Each test needs to make sure it includes the
#   proper variable (for example, code that does not have arch specific) stuff
#   in it should use the COMMON_ versions, while code that has arch specific
#   stuff in it should use the arch specific versions of these variables.
#
# - You can also add do these variables however you want for each test. For
#   example, if you want to add the definition THE_ANSWER=42 to the behavior
#   unit test, create a BEHAVIOR_DEFINES, append THE_ANSWER=42 and append
#   ${COMMON_DEFINES}, and use BEHAVIOR_DEFINES instead of COMMON_DEFINES in
#   the call to bf_add_test. This can be done to any of these variables to
#   custom tailor a specific test as needed. If a test needs different versions
#   of any of these, break the test into different files and create the custom
#   tailor versions of each test as needed.
#
# - By default, we provide a "requirements" test and a "behavior" test. The
#   "requirements" test verifies things like the ability to define globally
#   using constinit, constness and noexcept. None of the code in this test
#   actually runs and instead it is there to ensure the code signatures make
#   sense. The "behavior" test is where the code is actually executed to make
#   sure it executes as expected.
#
# - Each test only includes the one thing that is trying to test. For example,
#   suppose we are testing the bootstrap_t logic. This file includes a number
#   of dependencies. We do not include the path to where these dependencies
#   are located in the include path for the unit test. Instead, we include
#   a folder than contains our MOCK. All of the dependencies must be mocked.
#   When the bootstrap_t code is compiled, it will not realize that it is
#   using the mocked versions of it's dependecies, similar to how a lot of this
#   code is unaware of which arch specific code it is using and the build
#   system figures out which version to use, unit tests do the same thing.
#

bf_add_test(requirements INCLUDES ${COMMON_INCLUDES} SYSTEM_INCLUDES ${COMMON_SYSTEM_INCLUDES} DEFINES ${COMMON_DEFINES})
bf_add_test(behavior INCLUDES ${COMMON_INCLUDES} SYSTEM_INCLUDES ${COMMON_SYSTEM_INCLUDES} DEFINES ${COMMON_DEFINES})
