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
#include <bfvcpuid.h>
#include <command_line_parser.h>

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
    CHECK(clp.modules() == "");
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

TEST_CASE("test command line parser missing vmcall opcode")
{
    auto args = {"vmcall"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser unknown vmcall opcode")
{
    auto args = {"vmcall"_s, "unknown"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall versions missing index")
{
    auto args = {"vmcall"_s, "versions"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall versions invalid index")
{
    auto args = {"vmcall"_s, "versions"_s, "not_a_number"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall versions success")
{
    auto args = {"vmcall"_s, "versions"_s, "1"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);
    CHECK(clp.cpuid() == 0);

    CHECK(clp.registers().r00 == VMCALL_VERSIONS);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    CHECK(clp.registers().r02 == 1);
}

TEST_CASE("test command line parser vmcall versions success with missing cpuid")
{
    auto args = {"vmcall"_s, "versions"_s, "1"_s, "--cpuid"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);
    CHECK(clp.cpuid() == 0);

    CHECK(clp.registers().r00 == VMCALL_VERSIONS);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    CHECK(clp.registers().r02 == 1);
}

TEST_CASE("test command line parser vmcall versions success with invalid cpuid")
{
    auto args = {"vmcall"_s, "versions"_s, "1"_s, "--cpuid"_s, "not_a_number"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall versions success with cpuid")
{
    auto args = {"vmcall"_s, "versions"_s, "1"_s, "--cpuid"_s, "2"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);
    CHECK(clp.cpuid() == 2);

    CHECK(clp.registers().r00 == VMCALL_VERSIONS);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    CHECK(clp.registers().r02 == 1);
}

TEST_CASE("test command line parser vmcall registers missing registers")
{
    auto args = {"vmcall"_s, "registers"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);

    CHECK(clp.registers().r00 == VMCALL_REGISTERS);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
}

TEST_CASE("test command line parser vmcall registers one register invalid register")
{
    auto args = {"vmcall"_s, "registers"_s, "not_a_number"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall registers one register")
{
    auto args = {"vmcall"_s, "registers"_s, "2"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);

    CHECK(clp.registers().r00 == VMCALL_REGISTERS);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    CHECK(clp.registers().r02 == 2);
}

TEST_CASE("test command line parser vmcall registers all registers")
{
    auto args = {"vmcall"_s, "registers"_s, "2"_s, "3"_s, "4"_s, "5"_s, "6"_s, "7"_s, "8"_s, "9"_s, "10"_s, "11"_s, "12"_s, "13"_s, "14"_s, "15"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);

    CHECK(clp.registers().r00 == VMCALL_REGISTERS);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    CHECK(clp.registers().r02 == 0x2);
    CHECK(clp.registers().r03 == 0x3);
    CHECK(clp.registers().r04 == 0x4);
    CHECK(clp.registers().r05 == 0x5);
    CHECK(clp.registers().r06 == 0x6);
    CHECK(clp.registers().r07 == 0x7);
    CHECK(clp.registers().r08 == 0x8);
    CHECK(clp.registers().r09 == 0x9);
    CHECK(clp.registers().r10 == 0x10);
    CHECK(clp.registers().r11 == 0x11);
    CHECK(clp.registers().r12 == 0x12);
    CHECK(clp.registers().r13 == 0x13);
    CHECK(clp.registers().r14 == 0x14);
    CHECK(clp.registers().r15 == 0x15);
}

TEST_CASE("test command line parser vmcall string missing type")
{
    auto args = {"vmcall"_s, "string"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall string unknown type")
{
    auto args = {"vmcall"_s, "string"_s, "unknown"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall string missing string")
{
    auto args = {"vmcall"_s, "string"_s, "unformatted"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall string unformatted")
{
    auto args = {"vmcall"_s, "string"_s, "unformatted"_s, "hello world"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);

    CHECK(clp.registers().r00 == VMCALL_DATA);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    CHECK(clp.registers().r02 == 0);
    CHECK(clp.registers().r03 == 0);
    CHECK(clp.registers().r04 == VMCALL_DATA_STRING_UNFORMATTED);
    CHECK(clp.registers().r05 != 0);
    CHECK(clp.registers().r06 == 11);
}

TEST_CASE("test command line parser vmcall string json missing json")
{
    auto args = {"vmcall"_s, "string"_s, "json"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall string json invalid json")
{
    auto args = {"vmcall"_s, "string"_s, "json"_s, "hello world"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall string json")
{
    auto args = {"vmcall"_s, "string"_s, "json"_s, R"({"msg":"hello world"})"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);

    CHECK(clp.registers().r00 == VMCALL_DATA);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    CHECK(clp.registers().r02 == 0);
    CHECK(clp.registers().r03 == 0);
    CHECK(clp.registers().r04 == VMCALL_DATA_STRING_JSON);
    CHECK(clp.registers().r05 != 0);
    CHECK(clp.registers().r06 == 21);
}

TEST_CASE("test command line parser vmcall data missing type")
{
    auto args = {"vmcall"_s, "data"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall data unknown type")
{
    auto args = {"vmcall"_s, "data"_s, "unknown"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall data missing ifile")
{
    auto args = {"vmcall"_s, "data"_s, "unformatted"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall data missing ofile")
{
    auto args = {"vmcall"_s, "data"_s, "unformatted"_s, "ifile.txt"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall data")
{
    auto args = {"vmcall"_s, "data"_s, "unformatted"_s, "ifile.txt"_s, "ofile.txt"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);
    CHECK(clp.ifile() == "ifile.txt");
    CHECK(clp.ofile() == "ofile.txt");

    CHECK(clp.registers().r00 == VMCALL_DATA);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    CHECK(clp.registers().r02 == 0);
    CHECK(clp.registers().r03 == 0);
    CHECK(clp.registers().r04 == VMCALL_DATA_BINARY_UNFORMATTED);
}

TEST_CASE("test command line parser vmcall unittest missing index")
{
    auto args = {"vmcall"_s, "unittest"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall unittest invalid index")
{
    auto args = {"vmcall"_s, "unittest"_s, "not_a_number"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall unittest success")
{
    auto args = {"vmcall"_s, "unittest"_s, "1"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);
    CHECK(clp.cpuid() == 0);

    CHECK(clp.registers().r00 == VMCALL_UNITTEST);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    CHECK(clp.registers().r02 == 1);
}

TEST_CASE("test command line parser vmcall event missing index")
{
    auto args = {"vmcall"_s, "event"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall event invalid index")
{
    auto args = {"vmcall"_s, "event"_s, "not_a_number"_s};
    command_line_parser clp{};

    CHECK_THROWS(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::help);
}

TEST_CASE("test command line parser vmcall event success")
{
    auto args = {"vmcall"_s, "event"_s, "1"_s};
    command_line_parser clp{};

    CHECK_NOTHROW(clp.parse(args));
    CHECK(clp.cmd() == command_line_parser::command_type::vmcall);
    CHECK(clp.cpuid() == 0);

    CHECK(clp.registers().r00 == VMCALL_EVENT);
    CHECK(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    CHECK(clp.registers().r02 == 1);
}
