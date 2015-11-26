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
#include <debug.h>
#include <file.h>
#include <file_base.h>
#include <ioctl.h>
#include <ioctl_base.h>
#include <ioctl_driver.h>

bfm_ut::bfm_ut()
{
}

bool
bfm_ut::init()
{
    disable_debug();
    disable_error();

    return true;
}

bool
bfm_ut::fini()
{
    enable_debug();
    enable_error();

    return true;
}

bool
bfm_ut::list()
{
    this->test_split();
    this->test_command_line_parser();
    this->test_file();
    this->test_ioctl();
    this->test_ioctl_driver();

    return true;
}

void
bfm_ut::test_split()
{
    char delimiter = ' ';
    const char *str = "the cow is blue for this is true";

    {
        auto fields = split(std::string(), delimiter);

        EXPECT_TRUE(fields.empty() == true);
    }

    {
        auto fields = split(str, 'z');

        ASSERT_TRUE(fields.size() == 1);
        EXPECT_TRUE(fields[0] == str);
    }

    {
        auto fields = split(str, ' ');

        ASSERT_TRUE(fields.size() == 8);
        EXPECT_TRUE(fields[0] == "the");
        EXPECT_TRUE(fields[1] == "cow");
        EXPECT_TRUE(fields[2] == "is");
        EXPECT_TRUE(fields[3] == "blue");
        EXPECT_TRUE(fields[4] == "for");
        EXPECT_TRUE(fields[5] == "this");
        EXPECT_TRUE(fields[6] == "is");
        EXPECT_TRUE(fields[7] == "true");
    }
}

void
bfm_ut::test_command_line_parser()
{
    // There really is no way to validate the argc, argv paramters so we do
    // not unit test this part. The reality is, this should not need to be
    // tested.

    {
        int argc = 1;
        const char *argv[] = {"app_name"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
    }

    {
        int argc = 2;
        const char *argv[] = {"app_name", "unknown"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
    }

    {
        int argc = 2;
        const char *argv[] = {"app_name", "-unknown"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
    }

    {
        int argc = 2;
        const char *argv[] = {"app_name", "--unknown"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
    }

    {
        int argc = 2;
        const char *argv[] = {"app_name", "-h"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
    }

    {
        int argc = 2;
        const char *argv[] = {"app_name", "--help"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
    }

    {
        int argc = 2;
        const char *argv[] = {"app_name", "start"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
    }

    {
        int argc = 3;
        const char *argv[] = {"app_name", "start", "filename"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
        EXPECT_TRUE(clp.modules() == std::string("filename"));
    }

    {
        int argc = 4;
        const char *argv[] = {"app_name", "--unknow_option", "start", "filename"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
        EXPECT_TRUE(clp.modules() == std::string("filename"));
    }

    {
        int argc = 4;
        const char *argv[] = {"app_name", "start", "--unknow_option", "filename"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
        EXPECT_TRUE(clp.modules() == std::string("filename"));
    }

    {
        int argc = 4;
        const char *argv[] = {"app_name", "start", "filename", "--unknow_option"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
        EXPECT_TRUE(clp.modules() == std::string("filename"));
    }

    {
        int argc = 3;
        const char *argv[] = {"app_name", "-h", "unknown"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
    }

    {
        int argc = 3;
        const char *argv[] = {"app_name", "--help", "unknown"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
    }

    {
        int argc = 4;
        const char *argv[] = {"app_name", "unknown_cmd", "start", "filename"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == false);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::unknown);
    }

    {
        int argc = 4;
        const char *argv[] = {"app_name", "start", "filename", "unknown_cmd"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::start);
        EXPECT_TRUE(clp.modules() == std::string("filename"));
    }

    {
        int argc = 4;
        const char *argv[] = {"app_name", "-h", "start", "filename"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
    }

    {
        int argc = 4;
        const char *argv[] = {"app_name", "start", "-h", "filename"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
    }

    {
        int argc = 4;
        const char *argv[] = {"app_name", "start", "filename", "-h"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
    }

    {
        int argc = 2;
        const char *argv[] = {"app_name", "stop"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::stop);
    }

    {
        int argc = 3;
        const char *argv[] = {"app_name", "stop", "unknown_cmd"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::stop);
    }

    {
        int argc = 3;
        const char *argv[] = {"app_name", "-h", "stop"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
    }

    {
        int argc = 3;
        const char *argv[] = {"app_name", "stop", "-h"};
        command_line_parser clp(argc, argv);

        EXPECT_TRUE(clp.is_valid() == true);
        EXPECT_TRUE(clp.cmd() == command_line_parser_command::help);
    }
}

void
bfm_ut::test_file()
{
    // This is not a true unit test since we are not providing the file
    // class with a mock of fstream. Our attempts at doing that we not
    // successful. These tests at least help us prove that the file class
    // is going to work as intended.

    const char *text = "blah";
    const char *filename = "/tmp/bfm_test.txt";

    file f;

    std::ofstream tmp(filename);
    tmp << text;
    tmp.close();

    EXPECT_TRUE(f.exists(filename) == true);
    EXPECT_TRUE(f.read("bad_filename") == std::string());
    EXPECT_TRUE(f.read(filename) == std::string(text));

    std::remove(filename);

    EXPECT_TRUE(f.exists(filename) == false);
}

void
bfm_ut::test_ioctl()
{
    ioctl ctl;
    const char *msg = "hello world";

    // Since the IOCTL interface is OS specific, it's not easy to create a
    // unit test for this class that exercises all of the issues that can
    // occur when attempting to talk to the driver.

    EXPECT_TRUE(ctl.call(ioctl_commands::unknown, msg, ::strlen(msg)) == ioctl_error::invalid_arg);
    EXPECT_TRUE(ctl.call(ioctl_commands::add_module, NULL, ::strlen(msg)) == ioctl_error::invalid_arg);
    EXPECT_TRUE(ctl.call(ioctl_commands::add_module, msg, 0) == ioctl_error::invalid_arg);
}

void
bfm_ut::test_ioctl_driver()
{
    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();

        mocks.autoExpect = false;

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            ioctl_driver driver(NULL, ioctlb, clpb);
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            ioctl_driver driver(fb, NULL, clpb);
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            ioctl_driver driver(fb, ioctlb, NULL);
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.ExpectCall(clpb, command_line_parser_base::is_valid).Return(false);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.ExpectCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.ExpectCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::unknown);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.ExpectCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.ExpectCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::help);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.ExpectCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.ExpectCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::start);
        mocks.ExpectCall(clpb, command_line_parser_base::modules).Return(std::string());

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.OnCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.OnCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::start);
        mocks.OnCall(clpb, command_line_parser_base::modules).Return(std::string("bad_filename"));
        mocks.ExpectCall(fb, file_base::exists).Return(false);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.OnCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.OnCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::start);
        mocks.OnCall(clpb, command_line_parser_base::modules).Return(std::string("good_filename"));
        mocks.ExpectCall(fb, file_base::exists).Return(true);
        mocks.ExpectCall(fb, file_base::read).Return(std::string());

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.OnCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.OnCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::start);
        mocks.OnCall(clpb, command_line_parser_base::modules).Return(std::string("good_filename"));
        mocks.ExpectCall(fb, file_base::exists).With("good_filename").Return(true);
        mocks.ExpectCall(fb, file_base::read).Return(std::string("one_bad_file"));
        mocks.ExpectCall(fb, file_base::exists).With("one_bad_file").Return(false);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.OnCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.OnCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::start);
        mocks.OnCall(clpb, command_line_parser_base::modules).Return(std::string("good_filename"));
        mocks.ExpectCall(fb, file_base::exists).With("good_filename").Return(true);
        mocks.ExpectCall(fb, file_base::read).With("good_filename").Return(std::string("one\nbad\nfile"));
        mocks.ExpectCall(fb, file_base::exists).With("one").Return(false);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.OnCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.OnCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::start);
        mocks.OnCall(clpb, command_line_parser_base::modules).Return(std::string("good_filename"));
        mocks.ExpectCall(fb, file_base::exists).With("good_filename").Return(true);
        mocks.ExpectCall(fb, file_base::read).With("good_filename").Return(std::string("three\ngood\nfiles\n"));
        mocks.ExpectCall(fb, file_base::exists).With("three").Return(true);
        mocks.ExpectCall(fb, file_base::read).With("three").Return(std::string());

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.OnCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.OnCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::start);
        mocks.OnCall(clpb, command_line_parser_base::modules).Return(std::string("good_filename"));
        mocks.OnCall(fb, file_base::exists).With("good_filename").Return(true);
        mocks.OnCall(fb, file_base::read).With("good_filename").Return(std::string("three\ngood\nfiles\n"));
        mocks.OnCall(fb, file_base::exists).With("three").Return(true);
        mocks.OnCall(fb, file_base::read).With("three").Return(std::string("goood_contents"));
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::failed_add_module);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }


    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.OnCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.OnCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::start);
        mocks.OnCall(clpb, command_line_parser_base::modules).Return(std::string("good_filename"));
        mocks.OnCall(fb, file_base::exists).With("good_filename").Return(true);
        mocks.OnCall(fb, file_base::read).With("good_filename").Return(std::string("three\ngood\nfiles\n"));
        mocks.OnCall(fb, file_base::exists).With("three").Return(true);
        mocks.OnCall(fb, file_base::read).With("three").Return(std::string("goood_contents"));
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
        mocks.OnCall(fb, file_base::exists).With("good").Return(true);
        mocks.OnCall(fb, file_base::read).With("good").Return(std::string("goood_contents"));
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
        mocks.OnCall(fb, file_base::exists).With("files").Return(true);
        mocks.OnCall(fb, file_base::read).With("files").Return(std::string("goood_contents"));
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::start, _, _).Return(ioctl_error::failed_start);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.OnCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.OnCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::start);
        mocks.OnCall(clpb, command_line_parser_base::modules).Return(std::string("good_filename"));
        mocks.OnCall(fb, file_base::exists).With("good_filename").Return(true);
        mocks.OnCall(fb, file_base::read).With("good_filename").Return(std::string("three\ngood\nfiles\n"));
        mocks.OnCall(fb, file_base::exists).With("three").Return(true);
        mocks.OnCall(fb, file_base::read).With("three").Return(std::string("goood_contents"));
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
        mocks.OnCall(fb, file_base::exists).With("good").Return(true);
        mocks.OnCall(fb, file_base::read).With("good").Return(std::string("goood_contents"));
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
        mocks.OnCall(fb, file_base::exists).With("files").Return(true);
        mocks.OnCall(fb, file_base::read).With("files").Return(std::string("goood_contents"));
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::start, _, _).Return(ioctl_error::success);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::success);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.OnCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.OnCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::stop);
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::stop, _, _).Return(ioctl_error::failed_stop);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
        });
    }

    {
        MockRepository mocks;

        file_base *fb = mocks.Mock<file_base>();
        ioctl_base *ioctlb = mocks.Mock<ioctl_base>();
        command_line_parser_base *clpb = mocks.Mock<command_line_parser_base>();
        ioctl_driver driver(fb, ioctlb, clpb);

        mocks.OnCall(clpb, command_line_parser_base::is_valid).Return(true);
        mocks.OnCall(clpb, command_line_parser_base::cmd).Return(command_line_parser_command::stop);
        mocks.ExpectCall(ioctlb, ioctl_base::call).With(ioctl_commands::stop, _, _).Return(ioctl_error::success);

        RUN_UNITTEST_WITH_MOCKS(mocks, [&]
        {
            EXPECT_TRUE(driver.process() == ioctl_driver_error::success);
        });
    }
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(bfm_ut);
}
