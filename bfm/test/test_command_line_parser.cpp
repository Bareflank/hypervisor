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

#include <string>

#include <test.h>
#include <exception.h>
#include <command_line_parser.h>

static auto operator"" _uce(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::unknown_command_error>(""); }

static auto operator"" _mae(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::missing_argument_error>(); }

static auto operator"" _uvte(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::unknown_vmcall_type_error>(""); }

static auto operator"" _uvste(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::unknown_vmcall_string_type_error>(""); }

static auto operator"" _uvdte(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::unknown_vmcall_data_type_error>(""); }

void
bfm_ut::test_command_line_parser_with_no_args()
{
    auto &&args = {""_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_empty_args()
{
    auto &&args = {" "_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_unknown_command()
{
    auto &&args = {"unknown"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_uce);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_unknown_command_resets_state()
{
    auto &&args1 = {"unload"_s};
    auto &&args2 = {"unknown"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args1); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::unload);

    this->expect_exception([&] { clp.parse(args2); }, ""_uce);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_unknown_option_single_bar()
{
    auto &&args = {"-unknown"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_unknown_option_dual_bar()
{
    auto &&args = {"--unknown"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_single_bar_help()
{
    auto &&args = {"-h"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_dual_bar_help()
{
    auto &&args = {"--help"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_single_bar_help_unknown_option()
{
    auto &&args = {"-h"_s, "unknown"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_dual_bar_help_unknown_option()
{
    auto &&args = {"--help"_s, "unknown"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_load_no_modules()
{
    auto &&args = {"load"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_load_no_modules_empty_arg()
{
    auto &&args = {"load"_s, " "_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_valid_load()
{
    auto &&args = {"load"_s, "filename"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::load);
    this->expect_true(clp.modules() == "filename");
}

void
bfm_ut::test_command_line_parser_with_valid_load_unknown_option()
{
    auto &&args = {"load"_s, "--unknow_option"_s, "filename"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::load);
    this->expect_true(clp.modules() == "filename");
}

void
bfm_ut::test_command_line_parser_with_unknown_command_before_valid_load()
{
    auto &&args = {"unknown_cmd"_s, "load"_s, "filename"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_uce);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_unknown_command_after_valid_load()
{
    auto &&args = {"load"_s, "filename"_s, "unknown_cmd"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::load);
    this->expect_true(clp.modules() == "filename");
}

void
bfm_ut::test_command_line_parser_with_help_and_valid_load()
{
    auto &&args = {"-h"_s, "load"_s, "filename"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_with_valid_unload()
{
    auto &&args = {"unload"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::unload);
}

void
bfm_ut::test_command_line_parser_with_valid_start()
{
    auto &&args = {"start"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::start);
}

void
bfm_ut::test_command_line_parser_with_valid_stop()
{
    auto &&args = {"stop"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::stop);
}

void
bfm_ut::test_command_line_parser_with_valid_dump()
{
    auto &&args = {"dump"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::dump);
    this->expect_true(clp.vcpuid() == 0);
}

void
bfm_ut::test_command_line_parser_with_valid_status()
{
    auto &&args = {"status"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::status);
}

void
bfm_ut::test_command_line_parser_no_vcpuid()
{
    auto &&args = {"dump"_s, "--vcpuid"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::dump);
    this->expect_true(clp.vcpuid() == 0);
}

void
bfm_ut::test_command_line_parser_invalid_vcpuid()
{
    auto &&args = {"dump"_s, "--vcpuid"_s, "not_a_number"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_ut_iae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_valid_vcpuid()
{
    auto &&args = {"dump"_s, "--vcpuid"_s, "2"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::dump);
    this->expect_true(clp.vcpuid() == 2);
}

void
bfm_ut::test_command_line_parser_missing_vmcall_opcode()
{
    auto &&args = {"vmcall"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_unknown_vmcall_opcode()
{
    auto &&args = {"vmcall"_s, "unknown"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_uvte);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_versions_missing_index()
{
    auto &&args = {"vmcall"_s, "versions"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_versions_invalid_index()
{
    auto &&args = {"vmcall"_s, "versions"_s, "not_a_number"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_ut_iae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_versions_success()
{
    auto &&args = {"vmcall"_s, "versions"_s, "1"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);
    this->expect_true(clp.cpuid() == 0);

    this->expect_true(clp.registers().r00 == VMCALL_VERSIONS);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    this->expect_true(clp.registers().r02 == 1);
}

void
bfm_ut::test_command_line_parser_vmcall_versions_success_with_missing_cpuid()
{
    auto &&args = {"vmcall"_s, "versions"_s, "1"_s, "--cpuid"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);
    this->expect_true(clp.cpuid() == 0);

    this->expect_true(clp.registers().r00 == VMCALL_VERSIONS);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    this->expect_true(clp.registers().r02 == 1);
}

void
bfm_ut::test_command_line_parser_vmcall_versions_success_with_invalid_cpuid()
{
    auto &&args = {"vmcall"_s, "versions"_s, "1"_s, "--cpuid"_s, "not_a_number"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_ut_iae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_versions_success_with_cpuid()
{
    auto &&args = {"vmcall"_s, "versions"_s, "1"_s, "--cpuid"_s, "2"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);
    this->expect_true(clp.cpuid() == 2);

    this->expect_true(clp.registers().r00 == VMCALL_VERSIONS);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    this->expect_true(clp.registers().r02 == 1);
}

void
bfm_ut::test_command_line_parser_vmcall_registers_missing_registers()
{
    auto &&args = {"vmcall"_s, "registers"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);

    this->expect_true(clp.registers().r00 == VMCALL_REGISTERS);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
}

void
bfm_ut::test_command_line_parser_vmcall_registers_one_register_invalid_register()
{
    auto &&args = {"vmcall"_s, "registers"_s, "not_a_number"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_ut_iae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_registers_one_register()
{
    auto &&args = {"vmcall"_s, "registers"_s, "2"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);

    this->expect_true(clp.registers().r00 == VMCALL_REGISTERS);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    this->expect_true(clp.registers().r02 == 2);
}

void
bfm_ut::test_command_line_parser_vmcall_registers_all_registers()
{
    auto &&args = {"vmcall"_s, "registers"_s, "2"_s, "3"_s, "4"_s, "5"_s, "6"_s, "7"_s, "8"_s, "9"_s, "10"_s, "11"_s, "12"_s, "13"_s, "14"_s, "15"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);

    this->expect_true(clp.registers().r00 == VMCALL_REGISTERS);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    this->expect_true(clp.registers().r02 == 0x2);
    this->expect_true(clp.registers().r03 == 0x3);
    this->expect_true(clp.registers().r04 == 0x4);
    this->expect_true(clp.registers().r05 == 0x5);
    this->expect_true(clp.registers().r06 == 0x6);
    this->expect_true(clp.registers().r07 == 0x7);
    this->expect_true(clp.registers().r08 == 0x8);
    this->expect_true(clp.registers().r09 == 0x9);
    this->expect_true(clp.registers().r10 == 0x10);
    this->expect_true(clp.registers().r11 == 0x11);
    this->expect_true(clp.registers().r12 == 0x12);
    this->expect_true(clp.registers().r13 == 0x13);
    this->expect_true(clp.registers().r14 == 0x14);
    this->expect_true(clp.registers().r15 == 0x15);
}

void
bfm_ut::test_command_line_parser_vmcall_string_missing_type()
{
    auto &&args = {"vmcall"_s, "string"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_string_unknown_type()
{
    auto &&args = {"vmcall"_s, "string"_s, "unknown"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_uvste);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_string_missing_string()
{
    auto &&args = {"vmcall"_s, "string"_s, "unformatted"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_string_unformatted()
{
    auto &&args = {"vmcall"_s, "string"_s, "unformatted"_s, "hello world"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);

    this->expect_true(clp.registers().r00 == VMCALL_DATA);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    this->expect_true(clp.registers().r02 == 0);
    this->expect_true(clp.registers().r03 == 0);
    this->expect_true(clp.registers().r04 == VMCALL_DATA_STRING_UNFORMATTED);
    this->expect_true(clp.registers().r05 != 0);
    this->expect_true(clp.registers().r06 == 11);
}

void
bfm_ut::test_command_line_parser_vmcall_string_json_missing_json()
{
    auto &&args = {"vmcall"_s, "string"_s, "json"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_string_json_invalid_json()
{
    auto &&args = {"vmcall"_s, "string"_s, "json"_s, "hello world"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_ut_iae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_string_json()
{
    auto &&args = {"vmcall"_s, "string"_s, "json"_s, "{\"msg\":\"hello world\"}"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);

    this->expect_true(clp.registers().r00 == VMCALL_DATA);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    this->expect_true(clp.registers().r02 == 0);
    this->expect_true(clp.registers().r03 == 0);
    this->expect_true(clp.registers().r04 == VMCALL_DATA_STRING_JSON);
    this->expect_true(clp.registers().r05 != 0);
    this->expect_true(clp.registers().r06 == 21);
}

void
bfm_ut::test_command_line_parser_vmcall_data_missing_type()
{
    auto &&args = {"vmcall"_s, "data"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_data_unknown_type()
{
    auto &&args = {"vmcall"_s, "data"_s, "unknown"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_uvdte);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_data_missing_ifile()
{
    auto &&args = {"vmcall"_s, "data"_s, "unformatted"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_data_missing_ofile()
{
    auto &&args = {"vmcall"_s, "data"_s, "unformatted"_s, "ifile.txt"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_data()
{
    auto &&args = {"vmcall"_s, "data"_s, "unformatted"_s, "ifile.txt"_s, "ofile.txt"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);
    this->expect_true(clp.ifile() == "ifile.txt");
    this->expect_true(clp.ofile() == "ofile.txt");

    this->expect_true(clp.registers().r00 == VMCALL_DATA);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    this->expect_true(clp.registers().r02 == 0);
    this->expect_true(clp.registers().r03 == 0);
    this->expect_true(clp.registers().r04 == VMCALL_DATA_BINARY_UNFORMATTED);
}

void
bfm_ut::test_command_line_parser_vmcall_unittest_missing_index()
{
    auto &&args = {"vmcall"_s, "unittest"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_unittest_invalid_index()
{
    auto &&args = {"vmcall"_s, "unittest"_s, "not_a_number"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_ut_iae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_unittest_success()
{
    auto &&args = {"vmcall"_s, "unittest"_s, "1"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);
    this->expect_true(clp.cpuid() == 0);

    this->expect_true(clp.registers().r00 == VMCALL_UNITTEST);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    this->expect_true(clp.registers().r02 == 1);
}

void
bfm_ut::test_command_line_parser_vmcall_event_missing_index()
{
    auto &&args = {"vmcall"_s, "event"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_mae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_event_invalid_index()
{
    auto &&args = {"vmcall"_s, "event"_s, "not_a_number"_s};
    auto &&clp = command_line_parser{};

    this->expect_exception([&] { clp.parse(args); }, ""_ut_iae);
    this->expect_true(clp.cmd() == command_line_parser::command_type::help);
}

void
bfm_ut::test_command_line_parser_vmcall_event_success()
{
    auto &&args = {"vmcall"_s, "event"_s, "1"_s};
    auto &&clp = command_line_parser{};

    this->expect_no_exception([&] { clp.parse(args); });
    this->expect_true(clp.cmd() == command_line_parser::command_type::vmcall);
    this->expect_true(clp.cpuid() == 0);

    this->expect_true(clp.registers().r00 == VMCALL_EVENT);
    this->expect_true(clp.registers().r01 == VMCALL_MAGIC_NUMBER);
    this->expect_true(clp.registers().r02 == 1);
}
