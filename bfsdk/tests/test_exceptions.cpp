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

#include <catch/catch.hpp>
#include <bfexception.h>

enum class test_case {
    throw_logic_error,
    throw_bad_alloc,
    throw_int,
    no_throw
};

test_case g_test = test_case::no_throw;

void test()
{
    switch (g_test) {
        case test_case::throw_logic_error:
            throw std::logic_error("error");
        case test_case::throw_bad_alloc:
            throw std::bad_alloc();
        case test_case::throw_int:
            throw 10;
        default:
            break;
    }
}

TEST_CASE("one function, no return")
{
    g_test = test_case::throw_logic_error;
    CHECK_NOTHROW(guard_exceptions(test));

    g_test = test_case::throw_bad_alloc;
    CHECK_NOTHROW(guard_exceptions(test));

    g_test = test_case::throw_int;
    CHECK_NOTHROW(guard_exceptions(test));

    g_test = test_case::no_throw;
    CHECK_NOTHROW(guard_exceptions(test));
}

TEST_CASE("one function, with return")
{
    g_test = test_case::throw_logic_error;
    CHECK(guard_exceptions(static_cast<int64_t>(10), test) == 10);

    g_test = test_case::throw_bad_alloc;
    CHECK(guard_exceptions(static_cast<int64_t>(10), test) == BF_BAD_ALLOC);

    g_test = test_case::throw_int;
    CHECK(guard_exceptions(static_cast<int64_t>(10), test) == 10);

    g_test = test_case::no_throw;
    CHECK(guard_exceptions(static_cast<int64_t>(10), test) == SUCCESS);
}

TEST_CASE("two functions, no return")
{
    g_test = test_case::throw_logic_error;
    CHECK_NOTHROW(guard_exceptions(test, [] {}));

    g_test = test_case::throw_bad_alloc;
    CHECK_NOTHROW(guard_exceptions(test, [] {}));

    g_test = test_case::throw_int;
    CHECK_NOTHROW(guard_exceptions(test, [] {}));

    g_test = test_case::no_throw;
    CHECK_NOTHROW(guard_exceptions(test, [] {}));
}

TEST_CASE("two functions, with return")
{
    g_test = test_case::throw_logic_error;
    CHECK(guard_exceptions(static_cast<int64_t>(10), test, [] {}) == 10);

    g_test = test_case::throw_bad_alloc;
    CHECK(guard_exceptions(static_cast<int64_t>(10), test, [] {}) == BF_BAD_ALLOC);

    g_test = test_case::throw_int;
    CHECK(guard_exceptions(static_cast<int64_t>(10), test, [] {}) == 10);

    g_test = test_case::no_throw;
    CHECK(guard_exceptions(static_cast<int64_t>(10), test, [] {}) == SUCCESS);
}
