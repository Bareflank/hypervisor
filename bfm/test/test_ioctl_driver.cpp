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
#include <file.h>
#include <ioctl.h>
#include <ioctl_driver.h>

void
bfm_ut::test_ioctl_driver_with_null_fb()
{
    MockRepository mocks;

    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();

    mocks.autoExpect = false;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ioctl_driver driver(NULL, ioctlb, clpb);
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_null_ioctlb()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();

    mocks.autoExpect = false;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ioctl_driver driver(fb, NULL, clpb);
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_null_clp()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();

    mocks.autoExpect = false;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ioctl_driver driver(fb, ioctlb, NULL);
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_invalid_clp()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.ExpectCall(clpb, command_line_parser::is_valid).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_unknown_command()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.ExpectCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.ExpectCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::unknown);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_help()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.ExpectCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.ExpectCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::help);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_start_and_no_modules()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.ExpectCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.ExpectCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.ExpectCall(clpb, command_line_parser::modules).Return(std::string());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_start_and_bad_module_filename()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clpb, command_line_parser::modules).Return(std::string("bad_filename"));
    mocks.ExpectCall(fb, file::exists).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_start_and_empty_list_of_modules()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clpb, command_line_parser::modules).Return(std::string("good_filename"));
    mocks.ExpectCall(fb, file::exists).Return(true);
    mocks.ExpectCall(fb, file::read).Return(std::string());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_start_and_one_bad_module_filename()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clpb, command_line_parser::modules).Return(std::string("good_filename"));
    mocks.ExpectCall(fb, file::exists).With("good_filename").Return(true);
    mocks.ExpectCall(fb, file::read).Return(std::string("one_bad_file"));
    mocks.ExpectCall(fb, file::exists).With("one_bad_file").Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_start_and_more_than_one_bad_module_filename()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clpb, command_line_parser::modules).Return(std::string("good_filename"));
    mocks.ExpectCall(fb, file::exists).With("good_filename").Return(true);
    mocks.ExpectCall(fb, file::read).With("good_filename").Return(std::string("one\nbad\nfile"));
    mocks.ExpectCall(fb, file::exists).With("one").Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_start_and_empty_module()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clpb, command_line_parser::modules).Return(std::string("good_filename"));
    mocks.ExpectCall(fb, file::exists).With("good_filename").Return(true);
    mocks.ExpectCall(fb, file::read).With("good_filename").Return(std::string("three\ngood\nfiles\n"));
    mocks.ExpectCall(fb, file::exists).With("three").Return(true);
    mocks.ExpectCall(fb, file::read).With("three").Return(std::string());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_start_and_ioctl_add_module_failure()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clpb, command_line_parser::modules).Return(std::string("good_filename"));
    mocks.OnCall(fb, file::exists).With("good_filename").Return(true);
    mocks.OnCall(fb, file::read).With("good_filename").Return(std::string("three\ngood\nfiles\n"));
    mocks.OnCall(fb, file::exists).With("three").Return(true);
    mocks.OnCall(fb, file::read).With("three").Return(std::string("goood_contents"));
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::failed_add_module);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_start_and_ioctl_start_vmm_failure()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clpb, command_line_parser::modules).Return(std::string("good_filename"));
    mocks.OnCall(fb, file::exists).With("good_filename").Return(true);
    mocks.OnCall(fb, file::read).With("good_filename").Return(std::string("three\ngood\nfiles\n"));
    mocks.OnCall(fb, file::exists).With("three").Return(true);
    mocks.OnCall(fb, file::read).With("three").Return(std::string("goood_contents"));
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
    mocks.OnCall(fb, file::exists).With("good").Return(true);
    mocks.OnCall(fb, file::read).With("good").Return(std::string("goood_contents"));
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
    mocks.OnCall(fb, file::exists).With("files").Return(true);
    mocks.OnCall(fb, file::read).With("files").Return(std::string("goood_contents"));
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::start, _, _).Return(ioctl_error::failed_start);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_start_and_ioctl_start_vmm_success()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clpb, command_line_parser::modules).Return(std::string("good_filename"));
    mocks.OnCall(fb, file::exists).With("good_filename").Return(true);
    mocks.OnCall(fb, file::read).With("good_filename").Return(std::string("three\ngood\nfiles\n"));
    mocks.OnCall(fb, file::exists).With("three").Return(true);
    mocks.OnCall(fb, file::read).With("three").Return(std::string("goood_contents"));
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
    mocks.OnCall(fb, file::exists).With("good").Return(true);
    mocks.OnCall(fb, file::read).With("good").Return(std::string("goood_contents"));
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
    mocks.OnCall(fb, file::exists).With("files").Return(true);
    mocks.OnCall(fb, file::read).With("files").Return(std::string("goood_contents"));
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::add_module, _, _).Return(ioctl_error::success);
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::start, _, _).Return(ioctl_error::success);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::success);
    });
}

void
bfm_ut::test_ioctl_driver_with_stop_and_ioctl_stop_vmm_failure()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::stop);
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::stop, _, _).Return(ioctl_error::failed_stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_stop_and_ioctl_stop_vmm_success()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::stop);
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::stop, _, _).Return(ioctl_error::success);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::success);
    });
}

void
bfm_ut::test_ioctl_driver_with_stop_and_ioctl_dump_vmm_failure()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::dump);
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::dump, _, _).Return(ioctl_error::failed_dump);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::failure);
    });
}

void
bfm_ut::test_ioctl_driver_with_stop_and_ioctl_dump_vmm_success()
{
    MockRepository mocks;

    file *fb = mocks.Mock<file>();
    ioctl *ioctlb = mocks.Mock<ioctl>();
    command_line_parser *clpb = mocks.Mock<command_line_parser>();
    ioctl_driver driver(fb, ioctlb, clpb);

    mocks.OnCall(clpb, command_line_parser::is_valid).Return(true);
    mocks.OnCall(clpb, command_line_parser::cmd).Return(command_line_parser_command::dump);
    mocks.ExpectCall(ioctlb, ioctl::call).With(ioctl_commands::dump, _, _).Return(ioctl_error::success);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(driver.process() == ioctl_driver_error::success);
    });
}
