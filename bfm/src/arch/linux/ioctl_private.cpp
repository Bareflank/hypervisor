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

#include <debug.h>
#include <ioctl_private.h>
#include <driver_entry_interface.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

ioctl_private::ioctl_private()
{
    if ((fd = open("/dev/bareflank", O_RDWR)) < 0)
        bfm_error << "failed to open bareflank device driver" << std::endl;
}

ioctl_private::~ioctl_private()
{
    if (fd >= 0)
        close(fd);
}

ioctl_error::type
ioctl_private::call(ioctl_commands::type cmd, const void *const data, int32_t len) const
{
    int ret;

    switch (cmd)
    {
        case ioctl_commands::add_module:
        {
            if (data == 0)
            {
                bfm_error << "invalid argument - data == NULL" << std::endl;
                return ioctl_error::invalid_arg;
            }

            if (len == 0)
            {
                bfm_error << "invalid argument - length == 0" << std::endl;
                return ioctl_error::invalid_arg;
            }

            if ((ret = ioctl(fd, IOCTL_ADD_MODULE_LENGTH, len)) < 0)
            {
                bfm_error << "failed IOCTL_ADD_MODULE_LENGTH" << std::endl;
                return ioctl_error::failed_add_module;
            }

            if ((ret = ioctl(fd, IOCTL_ADD_MODULE, data)) < 0)
            {
                bfm_error << "failed IOCTL_ADD_MODULE" << std::endl;
                return ioctl_error::failed_add_module;
            }

            return ioctl_error::success;
        }

        case ioctl_commands::start:
        {
            if ((ret = ioctl(fd, IOCTL_START_VMM, 0)) < 0)
            {
                bfm_error << "failed IOCTL_START_VMM" << std::endl;
                return ioctl_error::failed_start;
            }

            return ioctl_error::success;
        }

        case ioctl_commands::stop:
        {
            if ((ret = ioctl(fd, IOCTL_STOP_VMM, 0)) < 0)
            {
                bfm_error << "failed IOCTL_STOP_VMM" << std::endl;
                return ioctl_error::failed_stop;
            }

            return ioctl_error::success;
        }

        case ioctl_commands::dump:
        {
            if ((ret = ioctl(fd, IOCTL_DUMP_VMM, 0)) < 0)
            {
                bfm_error << "failed IOCTL_DUMP_VMM" << std::endl;
                return ioctl_error::failed_dump;
            }

            return ioctl_error::success;
        }

        default:
            bfm_error << "unknown command" << std::endl;
            return ioctl_error::invalid_arg;
    };
}
