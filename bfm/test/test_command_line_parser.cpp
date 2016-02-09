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
#include <exception.h>

#include <test.h>
#include <command_line_parser.h>

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

command_line_parser g_clp;

void
bfm_ut::test_command_line_parser_with_no_args()
{
    auto args = {""_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_unknown_command()
{
    auto args = {"unknown"_s};

    g_clp.reset();
    EXPECT_EXCEPTION(g_clp.parse(args), bfn::unknown_command_error);

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_unknown_command_maintains_state()
{
    auto args1 = {"unload"_s};
    auto args2 = {"unknown"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args1));
    EXPECT_EXCEPTION(g_clp.parse(args2), bfn::unknown_command_error);

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::unload);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_unknown_option_single_bar()
{
    auto args = {"-unknown"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_unknown_option_dual_bar()
{
    auto args = {"--unknown"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_single_bar_help()
{
    auto args = {"-h"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_dual_bar_help()
{
    auto args = {"--help"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_load_no_modules()
{
    auto args = {"load"_s};

    g_clp.reset();
    EXPECT_EXCEPTION(g_clp.parse(args), bfn::missing_argument_error);

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_load_no_modules_maintains_state()
{
    auto args1 = {"unload"_s};
    auto args2 = {"load"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args1));
    EXPECT_EXCEPTION(g_clp.parse(args2), bfn::missing_argument_error);

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::unload);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_valid_load()
{
    auto args = {"load"_s, "filename"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::load);
    EXPECT_TRUE(g_clp.modules() == "filename");
}

void
bfm_ut::test_command_line_parser_with_valid_load_unknown_option()
{
    auto args = {"load"_s, "--unknow_option"_s, "filename"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::load);
    EXPECT_TRUE(g_clp.modules() == "filename");
}

void
bfm_ut::test_command_line_parser_with_single_bar_help_unknown_option()
{
    auto args = {"-h"_s, "unknown"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_dual_bar_help_unknown_option()
{
    auto args = {"--help"_s, "unknown"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_unknown_command_before_valid_load()
{
    auto args = {"unknown_cmd"_s, "load"_s, "filename"_s};

    g_clp.reset();
    EXPECT_EXCEPTION(g_clp.parse(args), bfn::unknown_command_error);

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_unknown_command_after_valid_load()
{
    auto args = {"load"_s, "filename"_s, "unknown_cmd"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::load);
    EXPECT_TRUE(g_clp.modules() == "filename");
}

void
bfm_ut::test_command_line_parser_with_help_and_valid_load()
{
    auto args = {"-h"_s, "load"_s, "filename"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::help);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_valid_unload()
{
    auto args = {"unload"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::unload);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_valid_start()
{
    auto args = {"start"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::start);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_valid_stop()
{
    auto args = {"stop"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::stop);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_valid_dump()
{
    auto args = {"dump"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::dump);
    EXPECT_TRUE(g_clp.modules() == "");
}

void
bfm_ut::test_command_line_parser_with_valid_status()
{
    auto args = {"status"_s};

    g_clp.reset();
    EXPECT_NO_EXCEPTION(g_clp.parse(args));

    EXPECT_TRUE(g_clp.cmd() == command_line_parser_command::status);
    EXPECT_TRUE(g_clp.modules() == "");
}
