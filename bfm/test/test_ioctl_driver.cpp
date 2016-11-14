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
#include <driver_entry_interface.h>

ioctl::status_type g_status = 0;

static auto operator"" _cve(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::corrupt_vmm_error>(); }

static auto operator"" _use(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::unknown_status_error>(); }

static auto operator"" _ivse(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::invalid_vmm_state_error>(""); }

static auto operator"" _ife(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::ioctl_failed_error>(""); }

static file *
setup_file(MockRepository &mocks)
{
    auto fil = mocks.Mock<file>();

    mocks.OnCall(fil, file::read_text).Return(""_s);
    mocks.OnCall(fil, file::read_binary).Return({});
    mocks.OnCall(fil, file::write_text);
    mocks.OnCall(fil, file::write_binary);

    return fil;
}

static ioctl *
setup_ioctl(MockRepository &mocks, ioctl::status_type status)
{
    auto ctl = mocks.Mock<ioctl>();

    g_status = status;

    mocks.OnCall(ctl, ioctl::open);
    mocks.OnCall(ctl, ioctl::call_ioctl_add_module);
    mocks.OnCall(ctl, ioctl::call_ioctl_load_vmm);
    mocks.OnCall(ctl, ioctl::call_ioctl_unload_vmm);
    mocks.OnCall(ctl, ioctl::call_ioctl_start_vmm);
    mocks.OnCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.OnCall(ctl, ioctl::call_ioctl_dump_vmm);
    mocks.OnCall(ctl, ioctl::call_ioctl_vmm_status);
    mocks.OnCall(ctl, ioctl::call_ioctl_vmcall);

    mocks.OnCall(ctl, ioctl::call_ioctl_vmm_status).Do([&](gsl::not_null<ioctl::status_pointer> s)
    { *s = g_status; });

    return ctl;
}

static command_line_parser *
setup_command_line_parser(MockRepository &mocks, command_line_parser::command_type type)
{
    auto clp = mocks.Mock<command_line_parser>();

    mocks.OnCall(clp, command_line_parser::cmd).Return(type);
    mocks.OnCall(clp, command_line_parser::modules).Return(""_s);
    mocks.OnCall(clp, command_line_parser::cpuid).Return(0);
    mocks.OnCall(clp, command_line_parser::vcpuid).Return(0);
    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type{});
    mocks.OnCall(clp, command_line_parser::ifile).Return(""_s);
    mocks.OnCall(clp, command_line_parser::ofile).Return(""_s);

    return clp;
}

void
bfm_ut::test_ioctl_driver_process_invalid_file()
{
    MockRepository mocks;

    auto &&fil = static_cast<file *>(nullptr);
    auto &&ctl = mocks.Mock<ioctl>();
    auto &&clp = mocks.Mock<command_line_parser>();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ioctl_driver(fil, ctl, clp); }, ""_ut_ffe);
    });
}

void
bfm_ut::test_ioctl_driver_process_invalid_ioctl()
{
    MockRepository mocks;

    auto &&fil = mocks.Mock<file>();
    auto &&ctl = static_cast<ioctl *>(nullptr);
    auto &&clp = mocks.Mock<command_line_parser>();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ioctl_driver(fil, ctl, clp); }, ""_ut_ffe);
    });
}

void
bfm_ut::test_ioctl_driver_process_invalid_command_line_parser()
{
    MockRepository mocks;

    auto &&fil = mocks.Mock<file>();
    auto &&ctl = mocks.Mock<ioctl>();
    auto &&clp = static_cast<command_line_parser *>(nullptr);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ioctl_driver(fil, ctl, clp); }, ""_ut_ffe);
    });
}

void
bfm_ut::test_ioctl_driver_process_help()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::help);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_load_vmm_running()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::load);

    mocks.OnCall(fil, file::read_text).Throw(std::runtime_error("error"));

    mocks.ExpectCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_vmm_loaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::load);

    mocks.OnCall(fil, file::read_text).Throw(std::runtime_error("error"));

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_vmm_corrupt()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::load);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_cve);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_vmm_unknown_status()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, -1);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::load);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_use);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_bad_modules_filename()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::load);

    mocks.OnCall(fil, file::read_text).Throw(std::runtime_error("error"));

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.NeverCall(ctl, ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_bad_module_filename()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::load);

    mocks.OnCall(clp, command_line_parser::modules).Return("modules"_s);

    mocks.OnCall(fil, file::read_text).Do([](auto) -> auto
    { return "{\"modules\":[\"1\",\"2\",\"3\"]}"_s; });

    mocks.OnCall(fil, file::read_binary).Do([](auto filename) -> auto
    {
        if (filename == "2")
            throw std::runtime_error("error");

        return file::binary_data{'g', 'o', 'o', 'd'};
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_add_module_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::load);

    mocks.OnCall(clp, command_line_parser::modules).Return("modules"_s);

    mocks.OnCall(fil, file::read_text).Do([](auto) -> auto
    { return "{\"modules\":[\"1\",\"2\",\"3\"]}"_s; });

    mocks.OnCall(fil, file::read_binary).Do([](auto filename) -> auto
    {
        if (filename == "2")
            return file::binary_data{'b', 'a', 'd'};

        return file::binary_data{'g', 'o', 'o', 'd'};
    });

    mocks.OnCall(ctl, ioctl::call_ioctl_add_module).Do([](auto data)
    {
        if (data == file::binary_data{'b', 'a', 'd'})
            throw std::runtime_error("error");
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_load_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::load);

    mocks.OnCall(clp, command_line_parser::modules).Return("modules"_s);

    mocks.OnCall(fil, file::read_text).Do([](auto) -> auto
    { return "{\"modules\":[\"1\",\"2\",\"3\"]}"_s; });

    mocks.OnCall(fil, file::read_binary).Do([](auto) -> auto
    { return file::binary_data{'g', 'o', 'o', 'd'}; });

    mocks.OnCall(ctl, ioctl::call_ioctl_load_vmm).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_load_success()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::load);

    mocks.OnCall(clp, command_line_parser::modules).Return("modules"_s);

    mocks.OnCall(fil, file::read_text).Do([](auto) -> auto
    { return "{\"modules\":[\"1\",\"2\",\"3\"]}"_s; });

    mocks.OnCall(fil, file::read_binary).Do([](auto) -> auto
    { return file::binary_data{'g', 'o', 'o', 'd'}; });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_vmm_running()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::unload);

    mocks.ExpectCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_vmm_loaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::unload);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_vmm_unloaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::unload);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_unload_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_vmm_corrupt()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::unload);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_cve);
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_vmm_unknown_status()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, -1);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::unload);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_use);
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_unload_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::unload);

    mocks.OnCall(ctl, ioctl::call_ioctl_unload_vmm).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_unload_success()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::unload);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_start_vmm_running()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::start);

    mocks.ExpectCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_start_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_start_vmm_loaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::start);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_start_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_start_vmm_unloaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::start);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.NeverCall(ctl, ioctl::call_ioctl_start_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ivse);
    });
}

void
bfm_ut::test_ioctl_driver_process_start_vmm_corrupt()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::start);

    mocks.NeverCall(ctl, ioctl::call_ioctl_start_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_cve);
    });
}

void
bfm_ut::test_ioctl_driver_process_start_vmm_unknown_status()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, -1);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::start);

    mocks.NeverCall(ctl, ioctl::call_ioctl_start_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_use);
    });
}

void
bfm_ut::test_ioctl_driver_process_start_start_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::start);

    mocks.OnCall(ctl, ioctl::call_ioctl_start_vmm).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_start_success()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::start);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_vmm_loaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::stop);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_vmm_unloaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::stop);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_vmm_corrupt()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::stop);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_cve);
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_vmm_unknown_status()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, -1);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::stop);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_use);
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_stop_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::stop);

    mocks.OnCall(ctl, ioctl::call_ioctl_stop_vmm).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_stop_success()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_vmm_unloaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::dump);

    mocks.NeverCall(ctl, ioctl::call_ioctl_dump_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ivse);
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_vmm_corrupted()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::dump);

    mocks.NeverCall(ctl, ioctl::call_ioctl_dump_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_cve);
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_vmm_unknown_status()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, -1);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::dump);

    mocks.NeverCall(ctl, ioctl::call_ioctl_dump_vmm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_use);
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_dump_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::dump);

    mocks.OnCall(ctl, ioctl::call_ioctl_dump_vmm).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_success_running()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::dump);

    mocks.OnCall(ctl, ioctl::call_ioctl_dump_vmm).Do([](gsl::not_null<ioctl::drr_pointer> drr, auto)
    {
        drr->spos = 0;
        drr->epos = 3;
        drr->buf[0] = 'h';
        drr->buf[1] = 'i';
        drr->buf[2] = '\n';
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_dump_success_loaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::dump);

    mocks.OnCall(ctl, ioctl::call_ioctl_dump_vmm).Do([](gsl::not_null<ioctl::drr_pointer> drr, auto)
    {
        drr->spos = 0;
        drr->epos = 3;
        drr->buf[0] = 'h';
        drr->buf[1] = 'i';
        drr->buf[2] = '\n';
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmm_status_running()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::status);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmm_status_loaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::status);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmm_status_unloaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::status);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmm_status_corrupt()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::status);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmm_status_unknown_status()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, -1);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::status);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_use);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_vmm_unloaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.NeverCall(ctl, ioctl::call_ioctl_vmcall);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ivse);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_vmm_loaded()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_LOADED);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.NeverCall(ctl, ioctl::call_ioctl_vmcall);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ivse);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_vmm_corrupt()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.NeverCall(ctl, ioctl::call_ioctl_vmcall);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_cve);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_vmm_unknown()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, -1);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.NeverCall(ctl, ioctl::call_ioctl_vmcall);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_use);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_unknown_vmcall()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        0xBAD,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_lee);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_versions_ioctl_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_VERSIONS,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_versions_ioctl_return_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_VERSIONS,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ife);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_versions_protocol_version()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_VERSIONS,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 0;
        regs->r02 = 0;
        regs->r03 = 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_versions_bareflank_version()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_VERSIONS,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 0;
        regs->r02 = 1;
        regs->r03 = 1;
        regs->r04 = 2;
        regs->r05 = 3;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_versions_user_version()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_VERSIONS,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 0;
        regs->r02 = 10;
        regs->r03 = 1;
        regs->r04 = 2;
        regs->r05 = 3;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_versions_unknown()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_VERSIONS,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 0;
        regs->r02 = 0x8000000000000000;
        regs->r03 = 1;
        regs->r04 = 2;
        regs->r05 = 3;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_registers_ioctl_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_REGISTERS,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_registers_ioctl_return_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_REGISTERS,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ife);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_registers_success()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_REGISTERS,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_unittest_ioctl_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_UNITTEST,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_unittest_ioctl_return_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_UNITTEST,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ife);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_unittest_success()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_UNITTEST,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_event_ioctl_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_EVENT,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_event_ioctl_return_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_EVENT,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ife);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_event_success()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_EVENT,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}














void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_unformatted_unknown_data_type()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        0xBAD,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.NeverCall(ctl, ioctl::call_ioctl_vmcall);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_lee);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_unformatted_ioctl_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_unformatted_ioctl_return_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ife);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_unformatted_out_of_range()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r07 = VMCALL_DATA_STRING_UNFORMATTED;
        regs->r09 = VMCALL_OUT_BUFFER_SIZE + 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ore);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_unformatted_success_no_return()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r07 = VMCALL_DATA_NONE;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_unformatted_success_unformatted()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r07 = VMCALL_DATA_STRING_UNFORMATTED;
        regs->r09 = 10;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_json_ioctl_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_JSON,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_json_ioctl_return_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_JSON,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ife);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_json_out_of_range()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_JSON,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r07 = VMCALL_DATA_STRING_JSON;
        regs->r09 = VMCALL_OUT_BUFFER_SIZE + 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ore);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_json_success_no_return()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_JSON,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r07 = VMCALL_DATA_NONE;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_json_parse_failure()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_JSON,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        auto &&output = "hello world"_s;
        __builtin_memcpy(reinterpret_cast<char *>(regs->r08), output.c_str(), output.size());

        regs->r07 = VMCALL_DATA_STRING_JSON;
        regs->r09 = output.size();
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_iae);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_string_json_success_json()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_STRING_JSON,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        auto &&output = "{\"msg\":\"hello world\"}"_s;
        __builtin_memcpy(reinterpret_cast<char *>(regs->r08), output.c_str(), output.size());

        regs->r07 = VMCALL_DATA_STRING_JSON;
        regs->r09 = output.size();
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_binary_unformatted_ifile_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, file::read_binary).Throw(std::runtime_error("error"));

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_BINARY_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_binary_unformatted_ioctl_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_BINARY_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ree);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_binary_unformatted_ioctl_return_failed()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_BINARY_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r01 = 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ife);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_binary_unformatted_out_of_range()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_BINARY_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r07 = VMCALL_DATA_BINARY_UNFORMATTED;
        regs->r09 = VMCALL_OUT_BUFFER_SIZE + 1;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_exception([&]{ driver.process(); }, ""_ut_ore);
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_binary_unformatted_success_no_return()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_BINARY_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r07 = VMCALL_DATA_NONE;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}

void
bfm_ut::test_ioctl_driver_process_vmcall_data_binary_unformatted_success_unformatted()
{
    MockRepository mocks;

    auto &&fil = setup_file(mocks);
    auto &&ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto &&clp = setup_command_line_parser(mocks, command_line_parser::command_type::vmcall);

    mocks.OnCall(clp, command_line_parser::registers).Return(ioctl::registers_type
    {
        VMCALL_DATA,
        0, 0, 0,
        VMCALL_DATA_BINARY_UNFORMATTED,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    });

    mocks.ExpectCall(ctl, ioctl::call_ioctl_vmcall).Do([](gsl::not_null<ioctl::registers_pointer> regs, auto)
    {
        regs->r07 = VMCALL_DATA_BINARY_UNFORMATTED;
        regs->r09 = 10;
    });

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&driver = ioctl_driver(fil, ctl, clp);
        this->expect_no_exception([&]{ driver.process(); });
    });
}
