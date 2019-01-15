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

#include <list>

#include <catch/catch.hpp>
#include <bfdelegate.h>

// -----------------------------------------------------------------------------
// Setup
// -----------------------------------------------------------------------------

constexpr auto modval = 10;
constexpr auto result = 11;

class test_class
{
public:

    test_class() = default;

    int foo(int val)
    { return val + mod; }

private:
    int mod{modval};
};

class test_const_class
{
public:
    test_const_class() = default;

    int foo(int val) const
    { return val + mod; }

private:
    int mod{modval};
};

int foo(int val)
{ return val + modval; }

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

TEST_CASE("segfault cases")
{
    // delegate<int(int)> d0;
    // d0(1);

    // test_class *t1 = nullptr;
    // auto d1 = delegate<int(int)>::create<test_class, &test_class::foo>(t1);
    // d1(1);
}

TEST_CASE("is valid")
{
    delegate<int(int)> d0;

    CHECK(!d0);
    CHECK(!d0.is_valid());
}

TEST_CASE("test class")
{
    test_class t;

    auto d = delegate<int(int)>::create<test_class, &test_class::foo>(t);
    CHECK(d(1) == result);
}

TEST_CASE("test class ptr")
{
    auto t = std::make_unique<test_class>();
    auto d = delegate<int(int)>::create<test_class, &test_class::foo>(t.get());
    CHECK(d(1) == result);
}

TEST_CASE("test unique class ptr")
{
    auto t = std::make_unique<test_class>();
    auto d = delegate<int(int)>::create<test_class, &test_class::foo>(t);
    CHECK(d(1) == result);
}

TEST_CASE("test const class")
{
    test_const_class t;

    auto d = delegate<int(int)>::create_const<test_const_class, &test_const_class::foo>(t);
    CHECK(d(1) == result);
}

TEST_CASE("free function")
{
    auto d = delegate<int(int)>::create<foo>();
    CHECK(d(1) == result);
}

TEST_CASE("lambda no capture")
{
    auto l = [](int val) -> int {
        return val + modval;
    };

    auto d = delegate<int(int)>::create(l);
    CHECK(d(1) == result);
}

TEST_CASE("lambda capture")
{
    auto capture = 42;

    auto l = [capture](int val) -> int {
        return val + modval + capture;
    };

    auto d = delegate<int(int)>::create(l);
    CHECK(d(1) == result + capture);

    capture = 0;
    CHECK(d(1) != result + capture);
}

TEST_CASE("lambda reference capture")
{
    auto capture = 42;

    auto l = [&capture](int val) -> int {
        return val + modval + capture;
    };

    auto d = delegate<int(int)>::create(l);
    CHECK(d(1) == result + capture);

    capture = 0;
    CHECK(d(1) == result);
}

TEST_CASE("list")
{
    test_class t;

    auto l = [](int val) -> int {
        return val + modval;
    };

    auto d1 = delegate<int(int)>::create(l);
    auto d2 = delegate<int(int)>::create<foo>();
    auto d3 = delegate<int(int)>::create<test_class, &test_class::foo>(t);

    std::list<delegate<int(int)>> delegates;
    delegates.push_back(d1);
    delegates.push_back(d2);
    delegates.push_back(d3);

    for (const auto &d : delegates) {
        CHECK(d(1) == result);
    }
}
