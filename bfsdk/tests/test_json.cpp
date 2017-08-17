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
