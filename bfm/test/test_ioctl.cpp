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

// -----------------------------------------------------------------------------
// Expose Private Functions
// -----------------------------------------------------------------------------

int64_t bf_ioctl_open();
int64_t bf_send_ioctl(int64_t fd, unsigned long request);
int64_t bf_read_ioctl(int64_t fd, unsigned long request, void *data);
int64_t bf_write_ioctl(int64_t fd, unsigned long request, const void *data);

// -----------------------------------------------------------------------------
// Global Data
// -----------------------------------------------------------------------------

ioctl g_ctl;
debug_ring_resources_t g_drr;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

void
bfm_ut::test_ioctl_driver_inaccessible()
{
    MockRepository mocks;

    mocks.OnCallFunc(bf_ioctl_open).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.open(), bfn::driver_inaccessible_error);
    });
}

void
bfm_ut::test_ioctl_add_module_with_invalid_length()
{
    MockRepository mocks;

    mocks.OnCallFunc(bf_send_ioctl).Return(0);
    mocks.OnCallFunc(bf_read_ioctl).Return(0);
    mocks.OnCallFunc(bf_write_ioctl).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.call_ioctl_add_module(""_s), std::invalid_argument);
    });
}

void
bfm_ut::test_ioctl_add_module_failed()
{
    auto data = "hello world"_s;
    MockRepository mocks;

    mocks.OnCallFunc(bf_send_ioctl).Return(-1);
    mocks.OnCallFunc(bf_read_ioctl).Return(-1);
    mocks.OnCallFunc(bf_write_ioctl).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.call_ioctl_add_module(data), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_load_vmm_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bf_send_ioctl).Return(-1);
    mocks.OnCallFunc(bf_read_ioctl).Return(-1);
    mocks.OnCallFunc(bf_write_ioctl).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.call_ioctl_load_vmm(), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_unload_vmm_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bf_send_ioctl).Return(-1);
    mocks.OnCallFunc(bf_read_ioctl).Return(-1);
    mocks.OnCallFunc(bf_write_ioctl).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.call_ioctl_unload_vmm(), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_start_vmm_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bf_send_ioctl).Return(-1);
    mocks.OnCallFunc(bf_read_ioctl).Return(-1);
    mocks.OnCallFunc(bf_write_ioctl).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.call_ioctl_start_vmm(), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_stop_vmm_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bf_send_ioctl).Return(-1);
    mocks.OnCallFunc(bf_read_ioctl).Return(-1);
    mocks.OnCallFunc(bf_write_ioctl).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.call_ioctl_stop_vmm(), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_dump_vmm_with_invalid_drr()
{
    MockRepository mocks;

    mocks.OnCallFunc(bf_send_ioctl).Return(0);
    mocks.OnCallFunc(bf_read_ioctl).Return(0);
    mocks.OnCallFunc(bf_write_ioctl).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.call_ioctl_dump_vmm(nullptr, 0), std::invalid_argument);
    });
}

void
bfm_ut::test_ioctl_dump_vmm_failed()
{
    MockRepository mocks;

    mocks.OnCallFunc(bf_send_ioctl).Return(-1);
    mocks.OnCallFunc(bf_read_ioctl).Return(-1);
    mocks.OnCallFunc(bf_write_ioctl).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.call_ioctl_dump_vmm(&g_drr, 0), bfn::ioctl_failed_error);
    });
}

void
bfm_ut::test_ioctl_vmm_status_with_invalid_drr()
{
    MockRepository mocks;

    mocks.OnCallFunc(bf_send_ioctl).Return(0);
    mocks.OnCallFunc(bf_read_ioctl).Return(0);
    mocks.OnCallFunc(bf_write_ioctl).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.call_ioctl_vmm_status(nullptr), std::invalid_argument);
    });
}

void
bfm_ut::test_ioctl_vmm_status_failed()
{
    int64_t status;
    MockRepository mocks;

    mocks.OnCallFunc(bf_send_ioctl).Return(-1);
    mocks.OnCallFunc(bf_read_ioctl).Return(-1);
    mocks.OnCallFunc(bf_write_ioctl).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(g_ctl.call_ioctl_vmm_status(&status), bfn::ioctl_failed_error);
    });
}
