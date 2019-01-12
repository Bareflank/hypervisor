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

// TIDY_EXCLUSION=-cppcoreguidelines-owning-memory
//
// Reason:
//     This triggers during a test of release(), which is a function we wish
//     to support to stay inline with a unique_ptr, but is known to be
//     unsafe. Since this is a test, this is a false positive
//

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

TEST_CASE("ostream")
{
    bfn::buffer buffer;
    CHECK_NOTHROW(std::cout << buffer << '\n');
}
