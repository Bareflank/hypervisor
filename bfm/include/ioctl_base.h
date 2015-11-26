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

#ifndef IOCTL_BASE_H
#define IOCTL_BASE_H

#include <stdint.h>

namespace ioctl_error
{
    enum type
    {
        success = 0,
        unknown = 1,
        invalid_arg = 2,
        failed_add_module = 3,
        failed_start = 4,
        failed_stop = 5
    };
}

namespace ioctl_commands
{
    enum type
    {
        unknown = 0,
        add_module = 1,
        start = 2,
        stop = 3
    };
}

class ioctl_base
{
public:

    ioctl_base() {}
    virtual ~ioctl_base() {}

    virtual ioctl_error::type call(ioctl_commands::type cmd,
                                   const void *const data,
                                   int32_t len) const
    { return ioctl_error::success; }
};

#endif
