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

#include <test.h>

#include <command_line_parser.h>
#include <command_line_parser_base.h>

void
bfm_ut::test_command_line_parser_with_no_args()
{
    int argc = 1;
    const char *argv[] = {"app_name"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
}

void
bfm_ut::test_command_line_parser_with_unknown_command()
{
    int argc = 2;
    const char *argv[] = {"app_name", "unknown"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == false);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
}

void
bfm_ut::test_command_line_parser_with_unknown_option_single_bar()
{
    int argc = 2;
    const char *argv[] = {"app_name", "-unknown"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == false);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
}

void
bfm_ut::test_command_line_parser_with_unknown_option_dual_bar()
{
    int argc = 2;
    const char *argv[] = {"app_name", "--unknown"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == false);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
}

void
bfm_ut::test_command_line_parser_with_single_bar_help()
{
    int argc = 2;
    const char *argv[] = {"app_name", "-h"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
}

void
bfm_ut::test_command_line_parser_with_dual_bar_help()
{
    int argc = 2;
    const char *argv[] = {"app_name", "--help"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
}

void
bfm_ut::test_command_line_parser_with_start_no_modules()
{
    int argc = 2;
    const char *argv[] = {"app_name", "start"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == false);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
}

void
bfm_ut::test_command_line_parser_with_valid_start()
{
    int argc = 3;
    const char *argv[] = {"app_name", "start", "filename"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
    EXPECT_TRUE(clp.modules() == std::string("filename"));
}

void
bfm_ut::test_command_line_parser_with_valid_start_unknown_option()
{
    int argc = 4;
    const char *argv[] = {"app_name", "start", "--unknow_option", "filename"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
    EXPECT_TRUE(clp.modules() == std::string("filename"));
}

void
bfm_ut::test_command_line_parser_with_single_bar_help_unknown_option()
{
    int argc = 3;
    const char *argv[] = {"app_name", "-h", "unknown"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
}

void
bfm_ut::test_command_line_parser_with_dual_bar_help_unknown_option()
{
    int argc = 3;
    const char *argv[] = {"app_name", "--help", "unknown"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
}

void
bfm_ut::test_command_line_parser_with_unknown_command_before_valid_start()
{
    int argc = 4;
    const char *argv[] = {"app_name", "unknown_cmd", "start", "filename"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == false);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
}

void
bfm_ut::test_command_line_parser_with_unknown_command_after_valid_start()
{
    int argc = 4;
    const char *argv[] = {"app_name", "start", "filename", "unknown_cmd"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
    EXPECT_TRUE(clp.modules() == std::string("filename"));
}

void
bfm_ut::test_command_line_parser_with_help_and_valid_start()
{
    int argc = 4;
    const char *argv[] = {"app_name", "-h", "start", "filename"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
}

void
bfm_ut::test_command_line_parser_with_valid_stop()
{
    int argc = 2;
    const char *argv[] = {"app_name", "stop"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::stop);
}

void
bfm_ut::test_command_line_parser_with_valid_dump()
{
    int argc = 2;
    const char *argv[] = {"app_name", "dump"};
    command_line_parser clp(argc, argv);

    EXPECT_TRUE(clp.is_valid() == true);
    EXPECT_TRUE(clp.cmd() == command_line_parser_command::dump);
}
