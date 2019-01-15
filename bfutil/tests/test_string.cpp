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
#include <bfstring.h>

TEST_CASE("string operator")
{
    CHECK("10"_s == std::string("10"));
}

TEST_CASE("digits")
{
    CHECK(bfn::digits(42, 10) == 2);
    CHECK(bfn::digits(0x42, 16) == 2);
}

TEST_CASE("base 10")
{
    CHECK(bfn::to_string(static_cast<int>(10), 10) == "10");
    CHECK(bfn::to_string(static_cast<long>(10), 10) == "10");
    CHECK(bfn::to_string(static_cast<long long>(10), 10) == "10");
    CHECK(bfn::to_string(static_cast<unsigned>(10), 10) == "10");
    CHECK(bfn::to_string(static_cast<unsigned long>(10), 10) == "10");
    CHECK(bfn::to_string(static_cast<unsigned long long>(10), 10) == "10");
}

TEST_CASE("base 16")
{
    CHECK(bfn::to_string(static_cast<int>(10), 16) == "0xa");
    CHECK(bfn::to_string(static_cast<long>(10), 16) == "0xa");
    CHECK(bfn::to_string(static_cast<long long>(10), 16) == "0xa");
    CHECK(bfn::to_string(static_cast<unsigned>(10), 16) == "0xa");
    CHECK(bfn::to_string(static_cast<unsigned long>(10), 16) == "0xa");
    CHECK(bfn::to_string(static_cast<unsigned long long>(10), 16) == "0xa");
}

TEST_CASE("base 16 pad")
{
    CHECK(bfn::to_string(static_cast<int>(10), 16, true) == "0x000000000000000a");
    CHECK(bfn::to_string(static_cast<long>(10), 16, true) == "0x000000000000000a");
    CHECK(bfn::to_string(static_cast<long long>(10), 16, true) == "0x000000000000000a");
    CHECK(bfn::to_string(static_cast<unsigned>(10), 16, true) == "0x000000000000000a");
    CHECK(bfn::to_string(static_cast<unsigned long>(10), 16, true) == "0x000000000000000a");
    CHECK(bfn::to_string(static_cast<unsigned long long>(10), 16, true) == "0x000000000000000a");
}

TEST_CASE("split")
{
    std::vector<std::string> empty = {""};
    std::vector<std::string> no_delimiters = {"no_delimiters"};
    std::vector<std::string> no_strings = {"", "", ""};
    std::vector<std::string> strings = {"the", "cow", "is", "blue"};

    CHECK(bfn::split(nullptr, ';').empty());
    CHECK(bfn::split("", ';') == empty);
    CHECK(bfn::split("no_delimiters", ';') == no_delimiters);
    CHECK(bfn::split(";;", ';') == no_strings);
    CHECK(bfn::split("the;cow;is;blue", ';') == strings);
}
