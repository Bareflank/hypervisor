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
#include <bfvector.h>

TEST_CASE("find")
{
    std::vector<int> list = {1, 2, 3};

    CHECK_THROWS(bfn::find(list, -1));
    CHECK_THROWS(bfn::find(list, 10));
    CHECK(*bfn::find(list, 1) == 2);
}

TEST_CASE("cfind")
{
    std::vector<int> list = {1, 2, 3};

    CHECK_THROWS(bfn::cfind(list, -1));
    CHECK_THROWS(bfn::cfind(list, 10));
    CHECK(*bfn::cfind(list, 1) == 2);
}

TEST_CASE("take")
{
    std::vector<int> list = {1, 2, 3};

    CHECK_THROWS(bfn::take(list, -1));
    CHECK_THROWS(bfn::take(list, 10));
    CHECK(bfn::take(list, 1) == 2);
    CHECK(list.size() == 2);
}

TEST_CASE("remove")
{
    std::vector<int> list = {1, 2, 3};

    CHECK_THROWS(bfn::remove(list, -1));
    CHECK_THROWS(bfn::remove(list, 10));
    CHECK_NOTHROW(bfn::remove(list, 1));
    CHECK(list.size() == 2);
}
