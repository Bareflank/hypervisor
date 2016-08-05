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

ioctl_driver g_driver;

void
bfm_ut::test_ioctl_driver_process_invalid_file()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(NULL, ctl, clp), std::invalid_argument);
    });
}

void
bfm_ut::test_ioctl_driver_process_invalid_ioctl()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, NULL, clp), std::invalid_argument);
    });
}

void
bfm_ut::test_ioctl_driver_process_invalid_command_line_parser()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, NULL), std::invalid_argument);
    });
}

void
bfm_ut::test_ioctl_driver_process_help()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::help);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_load_vmm_running()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::load);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_stop_vmm);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_RUNNING;
    });

    mocks.OnCall(f.get(), file::read).Throw(
        invalid_file(""_s)
    );

    mocks.ExpectCall(ctl.get(), ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::invalid_file_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_vmm_loaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::load);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    mocks.OnCall(f.get(), file::read).Throw(
        invalid_file(""_s)
    );

    mocks.NeverCall(ctl.get(), ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::invalid_file_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_vmm_corrupt()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::load);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_CORRUPT;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::corrupt_vmm_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_vmm_unknown_status()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::load);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = -1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::unknown_status_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_bad_modules_filename()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::load);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_UNLOADED;
    });

    mocks.OnCall(f.get(), file::read).Throw(
        invalid_file(""_s)
    );

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::invalid_file_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_bad_module_filename()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::load);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return("modules"_s);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_add_module);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_UNLOADED;
    });

    mocks.OnCall(f.get(), file::read).Do([](auto filename) -> auto
    {
        if (filename.compare("modules"_s) == 0)
            return "1\n2\n3\n"_s;
        if (filename.compare("2"_s) == 0)
            throw invalid_file(""_s);
        return "good"_s;
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::invalid_file_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_add_module_failed()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::load);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return("modules"_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_UNLOADED;
    });

    mocks.OnCall(f.get(), file::read).Do([](auto filename) -> auto
    {
        if (filename.compare("modules"_s) == 0)
            return " \n1\n2\n3\n"_s;
        if (filename.compare("2"_s) == 0)
            return "bad"_s;
        return "good"_s;
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_add_module).Do([](auto data)
    {
        if (data.compare("bad"_s) == 0)
            throw ioctl_failed(IOCTL_ADD_MODULE);
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_load_failed()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::load);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return("modules"_s);
    mocks.OnCall(f.get(), file::read).Return(""_s);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_add_module);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_UNLOADED;
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_load_vmm).Throw(
        ioctl_failed(IOCTL_LOAD_VMM)
    );

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_success()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::load);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return("modules"_s);
    mocks.OnCall(f.get(), file::read).Return(""_s);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_add_module);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_load_vmm);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_UNLOADED;
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_vmm_running()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::unload);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_stop_vmm);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_RUNNING;
    });

    mocks.ExpectCall(ctl.get(), ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_vmm_loaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::unload);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    mocks.NeverCall(ctl.get(), ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_vmm_unloaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::unload);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_UNLOADED;
    });

    mocks.NeverCall(ctl.get(), ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_vmm_corrupt()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::unload);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_CORRUPT;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::corrupt_vmm_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_vmm_unknown_status()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::unload);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = -1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::unknown_status_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_unload_failed()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::unload);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm).Throw(
        ioctl_failed(IOCTL_UNLOAD_VMM)
    );

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_success()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::unload);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_unload_vmm);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_start_vmm_running()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_RUNNING;
    });

    mocks.ExpectCall(ctl.get(), ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl.get(), ioctl::call_ioctl_start_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_start_vmm_loaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    mocks.NeverCall(ctl.get(), ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl.get(), ioctl::call_ioctl_start_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_start_vmm_unloaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_UNLOADED;
    });

    mocks.NeverCall(ctl.get(), ioctl::call_ioctl_stop_vmm);
    mocks.NeverCall(ctl.get(), ioctl::call_ioctl_start_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::invalid_vmm_state_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_start_vmm_corrupt()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_CORRUPT;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::corrupt_vmm_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_start_vmm_unknown_status()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = -1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::unknown_status_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_start_start_failed()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_start_vmm).Throw(
        ioctl_failed(IOCTL_START_VMM)
    );

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_start_success()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::start);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_start_vmm);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_vmm_loaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::stop);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    mocks.NeverCall(ctl.get(), ioctl::call_ioctl_stop_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_vmm_unloaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::stop);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_UNLOADED;
    });

    mocks.NeverCall(ctl.get(), ioctl::call_ioctl_stop_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_vmm_corrupt()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::stop);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_CORRUPT;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::corrupt_vmm_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_vmm_unknown_status()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::stop);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = -1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::unknown_status_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_stop_failed()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::stop);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_RUNNING;
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_stop_vmm).Throw(
        ioctl_failed(IOCTL_STOP_VMM)
    );

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_success()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::stop);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(ctl.get(), ioctl::call_ioctl_stop_vmm);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_RUNNING;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_vmm_unloaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::dump);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(clp.get(), command_line_parser::vcpuid).Return(0);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_UNLOADED;
    });

    mocks.NeverCall(ctl.get(), ioctl::call_ioctl_dump_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::invalid_vmm_state_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_vmm_corrupted()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::dump);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(clp.get(), command_line_parser::vcpuid).Return(0);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_CORRUPT;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::corrupt_vmm_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_vmm_unknown_status()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::dump);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(clp.get(), command_line_parser::vcpuid).Return(0);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = -1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::unknown_status_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_dump_failed()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::dump);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(clp.get(), command_line_parser::vcpuid).Return(0);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_dump_vmm).Throw(
        ioctl_failed(IOCTL_DUMP_VMM)
    );

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_success_running()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::dump);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(clp.get(), command_line_parser::vcpuid).Return(0);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_dump_vmm).Do([](auto * drr, auto)
    {
        drr->spos = 0;
        drr->epos = 3;
        drr->buf[0] = 'h';
        drr->buf[1] = 'i';
        drr->buf[2] = '\n';
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_RUNNING;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_success_loaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::dump);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);
    mocks.OnCall(clp.get(), command_line_parser::vcpuid).Return(0);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_dump_vmm).Do([](auto * drr, auto)
    {
        drr->spos = 0;
        drr->epos = 3;
        drr->buf[0] = 'h';
        drr->buf[1] = 'i';
        drr->buf[2] = '\n';
    });

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_vmm_status_running()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::status);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_RUNNING;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_vmm_status_loaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::status);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_LOADED;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_vmm_status_unloaded()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::status);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_UNLOADED;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_vmm_status_corrupt()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::status);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = VMM_CORRUPT;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(g_driver.process(f, ctl, clp));
    });
}

void
bfm_ut::test_ioctl_driver_process_vmm_status_unknown_status()
{
    MockRepository mocks;

    auto f = bfn::mock_shared<file>(mocks);
    auto ctl = bfn::mock_shared<ioctl>(mocks);
    auto clp = bfn::mock_shared<command_line_parser>(mocks);

    mocks.OnCall(clp.get(), command_line_parser::cmd).Return(command_line_parser_command::status);
    mocks.OnCall(clp.get(), command_line_parser::modules).Return(""_s);

    mocks.OnCall(ctl.get(), ioctl::call_ioctl_vmm_status).Do([](auto * status)
    {
        *status = -1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_driver.process(f, ctl, clp), bfn::unknown_status_error);
    });
}
