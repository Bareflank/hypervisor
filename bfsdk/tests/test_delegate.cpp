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

TEST_CASE("test class")
{
    test_class t;
    delegate d(&test_class::foo, &t);

    CHECK(d);
    CHECK(d(1) == result);
}

TEST_CASE("test class ptr")
{
    auto t = std::make_unique<test_class>();
    auto d = delegate(&test_class::foo, t.get());

    CHECK(d);
    CHECK(d(1) == result);
}

TEST_CASE("test const class")
{
    test_const_class t;

    auto d = delegate(&test_const_class::foo, &t);
    CHECK(d);
    CHECK(d(1) == result);
}

TEST_CASE("free function")
{
    delegate d(foo);

    CHECK(d);
    CHECK(d(1) == result);

    auto m = std::move(d);
    CHECK(m);
    CHECK(!d);
    CHECK(m(1) == result);
}

TEST_CASE("lambda no capture")
{
    auto l = [](int val) -> int {
        return val + modval;
    };

    auto d = delegate<int(int)>(l);
    CHECK(d);
    CHECK(d(1) == result);

    auto c = d;
    CHECK(c);
    CHECK(d);
    CHECK(c(1) == result);
}

TEST_CASE("lambda capture")
{
    auto capture = 42;

    auto l = [capture](int val) -> int {
        return val + modval + capture;
    };

    auto d = delegate<int(int)>(l);
    CHECK(d);
    CHECK(d(1) == result + capture);

    capture = 0;
    CHECK(d(1) != result + capture);

    auto m = std::move(d);
    CHECK(m);
    CHECK(!d);
    CHECK(m(1) != result + capture);
}

TEST_CASE("lambda reference capture")
{
    auto capture = 42;

    auto l = [&capture](int val) -> int {
        return val + modval + capture;
    };

    auto d = delegate<int(int)>(l);
    CHECK(d);
    CHECK(d(1) == result + capture);

    capture = 0;
    CHECK(d(1) == result);

    auto m = std::move(d);
    CHECK(m);
    CHECK(!d);
    CHECK(m(1) == result);

    auto c = m;
    CHECK(m);
    CHECK(c);
    CHECK(c(1) == result);
}

TEST_CASE("list copy")
{
    test_class t;

    auto d1 = delegate(+[](int val) -> int { return val + modval; });
    auto d2 = delegate(foo);
    auto d3 = delegate(&test_class::foo, &t);

    std::list<delegate<int(int)>> delegates;
    delegates.push_back(d1);
    delegates.push_back(d2);
    delegates.push_back(d3);

    for (const auto &d : delegates) {
        CHECK(d);
        CHECK(d(1) == result);
    }

    CHECK(d1);
    CHECK(d2);
    CHECK(d3);
}

TEST_CASE("list bracket")
{
    test_class t;
    std::list<delegate<int(int)>> delegates;

    delegates.push_back(+[](int val) -> int { return val + modval; });
    delegates.push_back({foo});
    delegates.push_back({&test_class::foo, &t});

    for (const auto &d : delegates) {
        CHECK(d);
        CHECK(d(1) == result);
    }
}

TEST_CASE("list move")
{
    test_class t;

    auto d1 = delegate(+[](int val) -> int { return val + modval; });
    auto d2 = delegate(foo);
    auto d3 = delegate(&test_class::foo, &t);

    std::list<delegate<int(int)>> delegates;

    CHECK(d1);
    CHECK(d2);
    CHECK(d3);

    delegates.push_back(std::move(d1));
    delegates.push_back(std::move(d2));
    delegates.push_back(std::move(d3));

    for (const auto &d : delegates) {
        CHECK(d(1) == result);
        CHECK(d);
    }

    CHECK(!d1);
    CHECK(!d2);
    CHECK(!d3);
}
