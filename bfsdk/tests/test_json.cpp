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

#include <bfjson.h>
#include <catch/catch.hpp>

TEST_CASE("json_hex_or_dec: empty json")
{
    json j;

    CHECK_THROWS(json_hex_or_dec<uint64_t>(j, "field"));
}

TEST_CASE("json_hex_or_dec: unknown field")
{
    json j;
    j["field_hex"] = "0x2A";

    CHECK_THROWS(json_hex_or_dec<uint64_t>(j, "unknown"));
}

TEST_CASE("json_hex_or_dec: invalid number")
{
    json j;
    j["field"] = "0x2A";

    CHECK_THROWS(json_hex_or_dec<uint64_t>(j, "field"));
}

TEST_CASE("json_hex_or_dec: hex number")
{
    json j;
    j["field_hex"] = "0x2A";

    CHECK(json_hex_or_dec<uint64_t>(j, "field") == 42);
}

TEST_CASE("json_hex_or_dec: dec number")
{
    json j;
    j["field"] = 42;

    CHECK(json_hex_or_dec<uint64_t>(j, "field") == 42);
}

TEST_CASE("json_hex_or_dec_array: empty json")
{
    json j;

    CHECK_THROWS(json_hex_or_dec_array<uint64_t>(j, "field"));
}

TEST_CASE("json_hex_or_dec_array: unknown field")
{
    json j;
    j["field_hex"] = R"(["0x2A"])";

    CHECK_THROWS(json_hex_or_dec_array<uint64_t>(j, "unknown"));
}

TEST_CASE("json_hex_or_dec_array: invalid type")
{
    json j;
    j["field"] = true;

    CHECK_THROWS(json_hex_or_dec_array<uint64_t>(j, "field"));
}

TEST_CASE("json_hex_or_dec_array: invalid combination")
{
    json j;
    j["field"] = R"([42,"0x2A"])";

    CHECK_THROWS(json_hex_or_dec_array<uint64_t>(j, "field"));
}

TEST_CASE("json_hex_or_dec_array: hex number")
{
    json j;
    j["field_hex"] = {"0x2A"};

    CHECK(json_hex_or_dec_array<uint64_t>(j, "field").at(0) == 42);
}

TEST_CASE("json_hex_or_dec_array: dec number")
{
    json j;
    j["field"] = {42};

    CHECK(json_hex_or_dec_array<uint64_t>(j, "field").at(0) == 42);
}
