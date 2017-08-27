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
#include <hippomocks.h>

#include <ioctl.h>
#include <bfdebugringinterface.h>

#ifdef WIN64
#include <windows.h>
HANDLE bfm_ioctl_open();
int64_t bfm_send_ioctl(HANDLE fd, DWORD request);
int64_t bfm_read_ioctl(HANDLE fd, DWORD request, void *data, DWORD size);
int64_t bfm_write_ioctl(HANDLE fd, DWORD request, const void *data, DWORD size);
int64_t bfm_read_write_ioctl(HANDLE fd, DWORD request, void *data, DWORD size);
HANDLE g_invalid = INVALID_HANDLE_VALUE;
HANDLE g_ioctl_open = nullptr;
int64_t g_send_ioctl = 0;
int64_t g_read_ioctl = 0;
int64_t g_write_ioctl = 0;
int64_t g_read_write_ioctl = 0;
#else
int bfm_ioctl_open();
int64_t bfm_send_ioctl(int fd, unsigned long request);
int64_t bfm_read_ioctl(int fd, unsigned long request, void *data);
int64_t bfm_write_ioctl(int fd, unsigned long request, const void *data);
int g_invalid = -1;
int g_ioctl_open = 0;
int64_t g_send_ioctl = 0;
int64_t g_read_ioctl = 0;
int64_t g_write_ioctl = 0;
#endif

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

void
setup_bffuncs(MockRepository &mocks)
{
#ifdef WIN64
    mocks.OnCallFunc(bfm_ioctl_open).Do([&] { return g_ioctl_open; });
    mocks.OnCallFunc(bfm_send_ioctl).Do([&](auto, auto) { return g_send_ioctl; });
    mocks.OnCallFunc(bfm_read_ioctl).Do([&](auto, auto, auto, auto) { return g_read_ioctl; });
    mocks.OnCallFunc(bfm_write_ioctl).Do([&](auto, auto, auto, auto) { return g_write_ioctl; });
    mocks.OnCallFunc(bfm_read_write_ioctl).Do([&](auto, auto, auto, auto) { return g_read_write_ioctl; });
#else
    mocks.OnCallFunc(bfm_ioctl_open).Do([&] { return g_ioctl_open; });
    mocks.OnCallFunc(bfm_send_ioctl).Do([&](auto, auto) { return g_send_ioctl; });
    mocks.OnCallFunc(bfm_read_ioctl).Do([&](auto, auto, auto) { return g_read_ioctl; });
    mocks.OnCallFunc(bfm_write_ioctl).Do([&](auto, auto, auto) { return g_write_ioctl; });
#endif
}

TEST_CASE("test ioctl driver inaccessible")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    ioctl ctl{};

    g_ioctl_open = g_invalid;
    auto ___ = gsl::finally([&] {
        g_ioctl_open = 0;
    });

    CHECK_THROWS(ctl.open());
}

TEST_CASE("test ioctl add module with invalid length")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    ioctl ctl{};
    CHECK_THROWS(ctl.call_ioctl_add_module({}));
}

TEST_CASE("test ioctl add module failed")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    auto data = {'h', 'e', 'l', 'l', 'o'};
    ioctl ctl{};

    g_write_ioctl = -1;
    auto ___ = gsl::finally([&] {
        g_write_ioctl = 0;
    });

    CHECK_THROWS(ctl.call_ioctl_add_module(data));
}

TEST_CASE("test ioctl load vmm failed")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    ioctl ctl{};

    g_send_ioctl = -1;
    auto ___ = gsl::finally([&] {
        g_send_ioctl = 0;
    });

    CHECK_THROWS(ctl.call_ioctl_load_vmm());
}

TEST_CASE("test ioctl unload vmm failed")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    ioctl ctl{};

    g_send_ioctl = -1;
    auto ___ = gsl::finally([&] {
        g_send_ioctl = 0;
    });

    CHECK_THROWS(ctl.call_ioctl_unload_vmm());
}

TEST_CASE("test ioctl start vmm failed")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    ioctl ctl{};

    g_send_ioctl = -1;
    auto ___ = gsl::finally([&] {
        g_send_ioctl = 0;
    });

    CHECK_THROWS(ctl.call_ioctl_start_vmm());
}

TEST_CASE("test ioctl stop vmm failed")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    ioctl ctl{};

    g_send_ioctl = -1;
    auto ___ = gsl::finally([&] {
        g_send_ioctl = 0;
    });

    CHECK_THROWS(ctl.call_ioctl_stop_vmm());
}

TEST_CASE("test ioctl dump vmm with invalid drr")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    auto drr = ioctl::drr_pointer{nullptr};
    ioctl ctl{};

    CHECK_THROWS(ctl.call_ioctl_dump_vmm(drr, 0));
}

TEST_CASE("test ioctl dump vmm failed")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    auto drr = ioctl::drr_type{};
    ioctl ctl{};

    g_read_ioctl = -1;
    auto ___ = gsl::finally([&] {
        g_read_ioctl = 0;
    });

    CHECK_THROWS(ctl.call_ioctl_dump_vmm(&drr, 0));
}

TEST_CASE("test ioctl vmm status with invalid status")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    auto status = ioctl::status_pointer{nullptr};
    ioctl ctl{};

    CHECK_THROWS(ctl.call_ioctl_vmm_status(status));
}

TEST_CASE("test ioctl vmm status failed")
{
    MockRepository mocks;
    setup_bffuncs(mocks);

    auto status = ioctl::status_type{};
    ioctl ctl{};

    g_read_ioctl = -1;
    auto ___ = gsl::finally([&] {
        g_read_ioctl = 0;
    });

    CHECK_THROWS(ctl.call_ioctl_vmm_status(&status));
}

#endif
