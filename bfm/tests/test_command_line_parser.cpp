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
