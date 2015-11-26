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

#include <ioctl.h>
#include <ioctl_private.h>

ioctl::ioctl()
{
    d = (void *) new ioctl_private();
}

ioctl::~ioctl()
{
    if (d != 0)
        delete(ioctl_private *)d;
}

ioctl_error::type
ioctl::call(ioctl_commands::type cmd, const void *const data, int32_t len) const
{
    if (d != 0)
        return ((ioctl_private *)d)->call(cmd, data, len);

    return ioctl_error::unknown;
}
