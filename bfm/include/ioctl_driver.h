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

#ifndef IOCTL_DRIVER_H
#define IOCTL_DRIVER_H

#include <ioctl.h>
#include <command_line_parser.h>

namespace ioctl_driver_error
{
    enum type
    {
        success = 0,
        invalid_command_line_parser = 1,
        unknown_command = 2,
        invalid_module_filename = 3
    };
}

class ioctl_driver
{
public:

    ioctl_driver();
    virtual ~ioctl_driver();

    virtual ioctl_driver_error::type process(const ioctl& ctl,
                                             const command_line_parser& clp) const;
};

#endif
