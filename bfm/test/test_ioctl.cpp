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
#include <debug_ring_interface.h>

int g_ioctl_open = 0;
int g_send_ioctl = 0;
int g_read_ioctl = 0;
int g_write_ioctl = 0;

int64_t bf_ioctl_open()
{ return g_ioctl_open; }

int64_t bf_send_ioctl(int fd, unsigned long request)
{ (void) fd; (void) request; return g_send_ioctl; }

int64_t bf_read_ioctl(int fd, unsigned long request, void *data)
{ (void) fd; (void) request; (void) data; return g_read_ioctl; }

int64_t bf_write_ioctl(int fd, unsigned long request, const void *data)
{ (void) fd; (void) request; (void) data; return g_write_ioctl; }

static auto operator"" _die(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::driver_inaccessible_error>(); }

static auto operator"" _ife(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::ioctl_failed_error>(""); }

void
bfm_ut::test_ioctl_driver_inaccessible()
{
    auto &&ctl = ioctl{};

    g_ioctl_open = -1;
    auto ___ = gsl::finally([&] { g_ioctl_open = 0; });

    this->expect_exception([&] { ctl.open(); }, ""_die);
}

void
bfm_ut::test_ioctl_add_module_with_invalid_length()
{
    auto &&ctl = ioctl{};
    this->expect_exception([&] { ctl.call_ioctl_add_module({}); }, ""_ut_ffe);
}

void
bfm_ut::test_ioctl_add_module_failed()
{
    auto &&data = {'h', 'e', 'l', 'l', 'o'};
    auto &&ctl = ioctl{};

    g_write_ioctl = -1;
    auto ___ = gsl::finally([&] { g_write_ioctl = 0; });

    this->expect_exception([&] { ctl.call_ioctl_add_module(data); }, ""_ife);
}

void
bfm_ut::test_ioctl_load_vmm_failed()
{
    auto &&ctl = ioctl{};

    g_send_ioctl = -1;
    auto ___ = gsl::finally([&] { g_send_ioctl = 0; });

    this->expect_exception([&] { ctl.call_ioctl_load_vmm(); }, ""_ife);
}

void
bfm_ut::test_ioctl_unload_vmm_failed()
{
    auto &&ctl = ioctl{};

    g_send_ioctl = -1;
    auto ___ = gsl::finally([&] { g_send_ioctl = 0; });

    this->expect_exception([&] { ctl.call_ioctl_unload_vmm(); }, ""_ife);
}

void
bfm_ut::test_ioctl_start_vmm_failed()
{
    auto &&ctl = ioctl{};

    g_send_ioctl = -1;
    auto ___ = gsl::finally([&] { g_send_ioctl = 0; });

    this->expect_exception([&] { ctl.call_ioctl_start_vmm(); }, ""_ife);
}

void
bfm_ut::test_ioctl_stop_vmm_failed()
{
    auto &&ctl = ioctl{};

    g_send_ioctl = -1;
    auto ___ = gsl::finally([&] { g_send_ioctl = 0; });

    this->expect_exception([&] { ctl.call_ioctl_stop_vmm(); }, ""_ife);
}

void
bfm_ut::test_ioctl_dump_vmm_with_invalid_drr()
{
    auto &&drr = ioctl::drr_pointer{nullptr};
    auto &&ctl = ioctl{};

    this->expect_exception([&] { ctl.call_ioctl_dump_vmm(drr, 0); }, ""_ut_ffe);
}

void
bfm_ut::test_ioctl_dump_vmm_failed()
{
    auto &&drr = ioctl::drr_type{};
    auto &&ctl = ioctl{};

    g_read_ioctl = -1;
    auto ___ = gsl::finally([&] { g_read_ioctl = 0; });

    this->expect_exception([&] { ctl.call_ioctl_dump_vmm(&drr, 0); }, ""_ife);
}

void
bfm_ut::test_ioctl_vmm_status_with_invalid_status()
{
    auto &&status = ioctl::status_pointer{nullptr};
    auto &&ctl = ioctl{};

    this->expect_exception([&] { ctl.call_ioctl_vmm_status(status); }, ""_ut_ffe);
}

void
bfm_ut::test_ioctl_vmm_status_failed()
{
    auto &&status = ioctl::status_type{};
    auto &&ctl = ioctl{};

    g_read_ioctl = -1;
    auto ___ = gsl::finally([&] { g_read_ioctl = 0; });

    this->expect_exception([&] { ctl.call_ioctl_vmm_status(&status); }, ""_ife);
}

void
bfm_ut::test_ioctl_vmm_vmcall_with_invalid_registers()
{
    auto &&reigsters = ioctl::registers_pointer{nullptr};
    auto &&ctl = ioctl{};

    this->expect_exception([&] { ctl.call_ioctl_vmcall(reigsters, 0); }, ""_ut_ffe);
}

void
bfm_ut::test_ioctl_vmm_vmcall_failed()
{
    auto &&registers = ioctl::registers_type{};
    auto &&ctl = ioctl{};

    g_write_ioctl = -1;
    auto ___ = gsl::finally([&] { g_write_ioctl = 0; });

    this->expect_exception([&] { ctl.call_ioctl_vmcall(&registers, 0); }, ""_ife);
}
