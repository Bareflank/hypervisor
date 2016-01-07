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

void
bfm_ut::test_ioctl_with_unknown_command()
{
    ioctl ctl;
    auto msg = "hello world";

    EXPECT_TRUE(ctl.call(ioctl_commands::unknown, msg, ::strlen(msg)) == ioctl_error::invalid_arg);
}

void
bfm_ut::test_ioctl_with_null_msg()
{
    ioctl ctl;
    auto msg = "hello world";

    EXPECT_TRUE(ctl.call(ioctl_commands::add_module, NULL, ::strlen(msg)) == ioctl_error::invalid_arg);
}

void
bfm_ut::test_ioctl_with_zero_length()
{
    ioctl ctl;
    auto msg = "hello world";

    EXPECT_TRUE(ctl.call(ioctl_commands::add_module, msg, 0) == ioctl_error::invalid_arg);
}
