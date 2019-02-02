//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <hippomocks.h>
#include <catch/catch.hpp>

#define GSL_ABORT ut_abort
void ut_abort()
{ std::cout << "test\n"; }

#define NEED_GSL_LITE
#include <bfgsl.h>
#include <bftypes.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("expects / ensures")
{
    ut_abort();

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(ut_abort);
        mocks.ExpectCallFunc(ut_abort);

        expects(true);
        ensures(true);

        expects(false);
        ensures(false);
    }

    // Note:
    //
    // Clang Tidy seems to have a bug and thinks that the Mock library
    // has a dangling pointer if this is not done. This might be able to
    // be removed when Clang Tidy is updated
    //
    HippoMocks::MockRepoInstanceHolder<0>::instance = nullptr;
}

TEST_CASE("narrow cast")
{
    auto var = gsl::narrow_cast<int>(42);
}

TEST_CASE("array")
{
    int count = 0;
    char buf[42] = {};

    for (int i = 0; i < 42; i++) {
        count += gsl::at(buf, i);
    }
}

TEST_CASE("const array")
{
    int count = 0;
    const char buf[42] = {};

    for (int i = 0; i < 42; i++) {
        count += gsl::at(buf, i);
    }
}

TEST_CASE("array with provided limit")
{
    int count = 0;
    char buf[42] = {};

    for (int i = 0; i < 42; i++) {
        count += gsl::at(static_cast<char *>(buf), 42, i);
    }
}

TEST_CASE("const array with provided limit")
{
    int count = 0;
    const char buf[42] = {};

    for (int i = 0; i < 42; i++) {
        count += gsl::at(static_cast<const char *>(buf), 42, i);
    }
}

#endif
