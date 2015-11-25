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

#include <ioctl.h>
#include <ioctl_arch.h>
#include <ioctl_driver.h>
#include <command_line_parser.h>

bfm_ut::bfm_ut()
{
}

bool
bfm_ut::init()
{
    return true;
}

bool
bfm_ut::fini()
{
    return true;
}

bool
bfm_ut::list()
{
    this->test_command_line_parser();
    this->test_ioctl_driver();

    return true;
}

void
bfm_ut::test_command_line_parser()
{
    command_line_parser clp;

    // There really is no way to validate the argc, argv paramters so we do
    // not unit test this part. The reality is, this should not need to be
    // tested.

    {
        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
        EXPECT_TRUE(clp.modules() == std::string());
    }

    {
        int argc = 1;
        const char* argv[] = {"app_name"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == true);
    }

    {
        int argc = 2;
        const char* argv[] = {"app_name", "unknown"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::unknown);
        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
    }

    {
        int argc = 2;
        const char* argv[] = {"app_name", "-unknown"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::unknown);
        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
    }

    {
        int argc = 2;
        const char* argv[] = {"app_name", "--unknown"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::unknown);
        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
    }

    {
        int argc = 2;
        const char* argv[] = {"app_name", "-h"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == true);
    }

    {
        int argc = 2;
        const char* argv[] = {"app_name", "--help"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == true);
    }

    {
        int argc = 2;
        const char* argv[] = {"app_name", "start"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::missing);
        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
    }

    {
        int argc = 3;
        const char* argv[] = {"app_name", "start", "filename"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
        EXPECT_TRUE(clp.modules() == std::string("filename"));
    }

    {
        int argc = 4;
        const char* argv[] = {"app_name", "--unknow_option", "start", "filename"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
        EXPECT_TRUE(clp.modules() == std::string("filename"));
    }

    {
        int argc = 4;
        const char* argv[] = {"app_name", "start", "--unknow_option", "filename"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
        EXPECT_TRUE(clp.modules() == std::string("filename"));
    }

    {
        int argc = 4;
        const char* argv[] = {"app_name", "start", "filename", "--unknow_option"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
        EXPECT_TRUE(clp.modules() == std::string("filename"));
    }

    {
        int argc = 3;
        const char* argv[] = {"app_name", "-h", "unknown"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == true);
    }

    {
        int argc = 3;
        const char* argv[] = {"app_name", "--help", "unknown"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == true);
    }

    {
        int argc = 4;
        const char* argv[] = {"app_name", "unknown_cmd", "start", "filename"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::unknown);
        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
    }

    {
        int argc = 4;
        const char* argv[] = {"app_name", "start", "filename", "unknown_cmd"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
        EXPECT_TRUE(clp.modules() == std::string("filename"));
    }

    {
        int argc = 4;
        const char* argv[] = {"app_name", "-h", "start", "filename"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == true);
    }

    {
        int argc = 4;
        const char* argv[] = {"app_name", "start", "-h", "filename"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == true);
    }

    {
        int argc = 4;
        const char* argv[] = {"app_name", "start", "filename", "-h"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == true);
    }

    {
        int argc = 2;
        const char* argv[] = {"app_name", "stop"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::stop);
    }

    {
        int argc = 3;
        const char* argv[] = {"app_name", "stop", "unknown_cmd"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::stop);
    }

    {
        int argc = 3;
        const char* argv[] = {"app_name", "-h", "stop"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == true);
    }

    {
        int argc = 3;
        const char* argv[] = {"app_name", "stop", "-h"};

        EXPECT_TRUE(clp.parse(argc, argv) == command_line_parser_error::success);
        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.help() == true);
    }
}

void
bfm_ut::test_ioctl_driver()
{
    ioctl_driver driver;

    {
        MockRepository mocks;
        ioctl *ctl = mocks.ClassMock<ioctl>();
        command_line_parser *clp = mocks.ClassMock<command_line_parser>();

        mocks.ExpectCall(clp, command_line_parser::is_valid).Return(false);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process(*ctl, *clp) == ioctl_driver_error::invalid_command_line_parser);
        });
    }

    {
        MockRepository mocks;
        ioctl *ctl = mocks.ClassMock<ioctl>();
        command_line_parser *clp = mocks.ClassMock<command_line_parser>();

        mocks.ExpectCall(clp, command_line_parser::is_valid).Return(true);
        mocks.ExpectCall(clp, command_line_parser::cmd).Return(command_line_parser_command::unknown);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process(*ctl, *clp) == ioctl_driver_error::unknown_command);
        });
    }

    {
        MockRepository mocks;
        ioctl *ctl = mocks.ClassMock<ioctl>();
        command_line_parser *clp = mocks.ClassMock<command_line_parser>();

        mocks.ExpectCall(clp, command_line_parser::is_valid).Return(true);
        mocks.ExpectCall(clp, command_line_parser::cmd).Return(command_line_parser_command::start);
        mocks.ExpectCall(clp, command_line_parser::modules).Return(std::string());

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process(*ctl, *clp) == ioctl_driver_error::invalid_module_filename);
        });
    }

    {
        MockRepository mocks;
        ioctl *ctl = mocks.ClassMock<ioctl>();
        command_line_parser *clp = mocks.ClassMock<command_line_parser>();

        mocks.ExpectCall(clp, command_line_parser::is_valid).Return(true);
        mocks.ExpectCall(clp, command_line_parser::cmd).Return(command_line_parser_command::start);
        mocks.ExpectCall(clp, command_line_parser::modules).Return(std::string("bad_filename"));

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process(*ctl, *clp) == ioctl_driver_error::invalid_module_filename);
        });
    }
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(bfm_ut);
}
