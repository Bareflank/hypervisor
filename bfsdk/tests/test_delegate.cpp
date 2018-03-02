//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

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
