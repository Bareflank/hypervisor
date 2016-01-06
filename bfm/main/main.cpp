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

#include <cstdlib>

#include <command_line_parser.h>
#include <debug.h>
#include <file.h>
#include <ioctl.h>
#include <ioctl_driver.h>

int main(int argc, const char *argv[])
{
    auto f = new file;
    auto ctl = new ioctl;
    auto clp = new command_line_parser(argc, argv);

    if (clp->cmd() == command_line_parser_command::help)
    {
        std::cout << "Usage: bfm [OPTION]... start list_of_modules" << std::endl;
        std::cout << "   or: bfm [OPTION]... stop" << std::endl;
        std::cout << "   or: bfm [OPTION]... dump" << std::endl;
        std::cout << std::endl;
        std::cout << "       -h, --help      help" << std::endl;

        return EXIT_SUCCESS;
    }

    auto driver = new ioctl_driver(f, ctl, clp);

    if (driver->process() != ioctl_driver_error::success)
    {
        bfm_error << "failed to process request" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
