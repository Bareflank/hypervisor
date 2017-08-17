//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <catch/catch.hpp>
#include <bfbuffer.h>

TEST_CASE("default constructor")
{
    CHECK_NOTHROW(bfn::buffer());
}

TEST_CASE("allocate constructor")
{
    CHECK_THROWS(bfn::buffer(0));
    CHECK_NOTHROW(bfn::buffer(42));
}

TEST_CASE("pre-allocated constructor")
{
    CHECK_THROWS(bfn::buffer(nullptr, 42));
    CHECK_THROWS(bfn::buffer(new char[42], 0));

    CHECK_NOTHROW(bfn::buffer(new char[42], 42));
    CHECK_NOTHROW(bfn::buffer(nullptr, 0));
}

TEST_CASE("initializer list")
{
    auto hello = {'h', 'e', 'l', 'l', 'o'};
    CHECK_NOTHROW(bfn::buffer(hello));
}

TEST_CASE("get")
{
    bfn::buffer buffer1(42);
    CHECK(buffer1.get() != nullptr);

    bfn::buffer buffer2;
    CHECK(buffer2.get() == nullptr);
}

auto
pass_through(bfn::buffer &buffer)
{ return buffer.data(); }

auto
const_pass_through(const bfn::buffer &buffer)
{ return buffer.data(); }

TEST_CASE("data")
{
    bfn::buffer buffer1(42);
    CHECK(pass_through(buffer1) != nullptr);
    CHECK(const_pass_through(buffer1) != nullptr);

    bfn::buffer buffer2;
    CHECK(pass_through(buffer2) == nullptr);
    CHECK(const_pass_through(buffer2) == nullptr);
}

TEST_CASE("empty")
{
    bfn::buffer buffer1(42);
    CHECK(!buffer1.empty());

    bfn::buffer buffer2;
    CHECK(buffer2.empty());
}

TEST_CASE("operator bool")
{
    bfn::buffer buffer1(42);
    CHECK(buffer1);

    bfn::buffer buffer2;
    CHECK(!buffer2);
}

TEST_CASE("size")
{
    bfn::buffer buffer1(42);
    CHECK(buffer1.size() == 42);

    bfn::buffer buffer2;
    CHECK(buffer2.empty());
}

TEST_CASE("release")
{
    bfn::buffer buffer(42);
    CHECK(buffer);
    CHECK(buffer.size() == 42);

    auto data = buffer.data();
    buffer.release();

    CHECK(!buffer);
    CHECK(buffer.empty());

    delete[] data;
}

TEST_CASE("swap")
{
    bfn::buffer buffer1;
    bfn::buffer buffer2(42);

    buffer1.swap(buffer2);

    CHECK(buffer1);
    CHECK(buffer1.size() == 42);

    bfn::swap(buffer1, buffer2);

    CHECK(buffer2);
    CHECK(buffer2.size() == 42);
}

TEST_CASE("span")
{
    bfn::buffer buffer1;
    CHECK(buffer1.empty());

    bfn::buffer buffer2(42);
    CHECK(buffer2.span().size() == 42);
}

TEST_CASE("equals / not equals")
{
    auto hello = {'h', 'e', 'l', 'l', 'o'};

    bfn::buffer buffer1;
    bfn::buffer buffer2(hello);
    bfn::buffer buffer3(hello);

    CHECK(buffer3 == buffer2);
    CHECK(buffer3 != buffer1);
}

TEST_CASE("resize")
{
    auto hello = {'h', 'e', 'l', 'l', 'o'};

    bfn::buffer buffer(hello);
    buffer.resize(50);

    CHECK(buffer.size() == 50);
    CHECK(buffer.span()[0] == 'h');

    buffer.resize(2);

    CHECK(buffer.size() == 2);
    CHECK(buffer.span()[0] == 'h');
}
