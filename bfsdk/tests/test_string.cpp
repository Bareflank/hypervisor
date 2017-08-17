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
#include <bfstring.h>

TEST_CASE("string operator")
{
    CHECK("10"_s == std::string("10"));
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
    CHECK(bfn::to_string(static_cast<int>(10), 16) == "0x000000000000000A");
    CHECK(bfn::to_string(static_cast<long>(10), 16) == "0x000000000000000A");
    CHECK(bfn::to_string(static_cast<long long>(10), 16) == "0x000000000000000A");
    CHECK(bfn::to_string(static_cast<unsigned>(10), 16) == "0x000000000000000A");
    CHECK(bfn::to_string(static_cast<unsigned long>(10), 16) == "0x000000000000000A");
    CHECK(bfn::to_string(static_cast<unsigned long long>(10), 16) == "0x000000000000000A");
}

TEST_CASE("base 8")
{
    CHECK(bfn::to_string(static_cast<int>(10), 8) == "012");
    CHECK(bfn::to_string(static_cast<long>(10), 8) == "012");
    CHECK(bfn::to_string(static_cast<long long>(10), 8) == "012");
    CHECK(bfn::to_string(static_cast<unsigned>(10), 8) == "012");
    CHECK(bfn::to_string(static_cast<unsigned long>(10), 8) == "012");
    CHECK(bfn::to_string(static_cast<unsigned long long>(10), 8) == "012");
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
