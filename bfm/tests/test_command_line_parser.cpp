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

#include <test_support.h>

TEST_CASE("test command line parser with no args")
{
    auto args = {""_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with empty args")
{
    auto args = {" "_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with unknown command")
{
    auto args = {"unknown"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with invalid command")
{
    auto args = {"invalid\t"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with unknown command resets state")
{
    auto args1 = {"unload"_s};
    auto args2 = {"unknown"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args1));
    CHECK(clp.cmd() == command_line_parser::command_type::unload);

    CHECK_THROWS(clp.parse(args2));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with unknown option single bar")
{
    auto args = {"-unknown"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with unknown option dual bar")
{
    auto args = {"--unknown"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with single bar help")
{
    auto args = {"-h"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with dual bar help")
{
    auto args = {"--help"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with single bar help unknown option")
{
    auto args = {"-h"_s, "unknown"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with dual bar help unknown option")
{
    auto args = {"--help"_s, "unknown"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser with load no modules")
{
    auto args = {"load"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::load);
    CHECK(clp.modules().empty());
}

TEST_CASE("test command line parser with valid load")
{
    auto args = {"load"_s, "filename"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::load);
    CHECK(clp.modules() == "filename");
}

TEST_CASE("test command line parser with valid unload")
{
    auto args = {"unload"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::unload);
}

TEST_CASE("test command line parser with valid start")
{
    auto args = {"start"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::start);
}

TEST_CASE("test command line parser with valid stop")
{
    auto args = {"stop"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::stop);
}

TEST_CASE("test command line parser with valid quick")
{
    auto args = {"quick"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::quick);
}

TEST_CASE("test command line parser with valid dump")
{
    auto args = {"dump"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::dump);
    CHECK(clp.vcpuid() == vcpuid::invalid);
}

TEST_CASE("test command line parser with valid status")
{
    auto args = {"status"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::status);
}

TEST_CASE("test command line parser no vcpuid")
{
    auto args = {"dump"_s, "--vcpuid"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::dump);
    CHECK(clp.vcpuid() == vcpuid::invalid);
}

TEST_CASE("test command line parser invalid vcpuid")
{
    auto args = {"dump"_s, "--vcpuid"_s, "not_a_number"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser valid vcpuid")
{
    auto args = {"dump"_s, "--vcpuid"_s, "2"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::dump);
    CHECK(clp.vcpuid() == 2);
}
