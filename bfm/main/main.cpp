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

#include <vector>
#include <string>
#include <memory>
#include <iostream>
#include <exception.h>

#include <gsl/gsl>

#include <command_line_parser.h>
#include <file.h>
#include <ioctl.h>
#include <ioctl_driver.h>

void
terminate()
{
    std::cerr << "FATAL ERROR: terminate called" << '\n';
    abort();
}

void
new_handler()
{
    std::cerr << "FATAL ERROR: out of memory" << '\n';
    std::terminate();
}

void
help()
{
    std::cout << "Usage: bfm [OPTION]... load... list_of_modules..." << '\n';
    std::cout << "  or:  bfm [OPTION]... unload..." << '\n';
    std::cout << "  or:  bfm [OPTION]... start..." << '\n';
    std::cout << "  or:  bfm [OPTION]... stop..." << '\n';
    std::cout << "  or:  bfm [OPTION]... dump..." << '\n';
    std::cout << "  or:  bfm [OPTION]... status..." << '\n';
    std::cout << "Controls or queries the bareflank hypervisor" << '\n';
    std::cout << '\n';
    std::cout << "       -h, --help      show this help menu" << '\n';
}

int
protected_main(const std::vector<std::string> &args)
{
    // -------------------------------------------------------------------------
    // Command Line Parser

    auto clp = std::make_shared<command_line_parser>();

    try
    {
        clp->parse(args);
    }
    catch (bfn::general_exception &ge)
    {
        std::cerr << "bfm: " << ge << '\n';
        std::cerr << "Try `bfm --help' for more information." << '\n';

        return EXIT_FAILURE;
    }

    if (clp->cmd() == command_line_parser_command::help)
    {
        help();
        return EXIT_SUCCESS;
    }

    // -------------------------------------------------------------------------
    // IO Controller

    auto ctl = std::make_shared<ioctl>();

    try
    {
        ctl->open();
    }
    catch (bfn::general_exception &ge)
    {
        std::cerr << "bfm: " << ge << '\n';

        return EXIT_FAILURE;
    }

    // -------------------------------------------------------------------------
    // IOCTR Driver

    auto f = std::make_shared<file>();
    auto driver = std::make_shared<ioctl_driver>();

    try
    {
        driver->process(f, ctl, clp);
    }
    catch (bfn::general_exception &ge)
    {
        std::cerr << "bfm: " << ge << '\n';

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int
main(int argc, const char *argv[])
{
    std::set_terminate(terminate);
    std::set_new_handler(new_handler);

    try
    {
        std::vector<std::string> args;
        gsl::span<const char *> args_span{argv, argc};

        for (auto i = 1; i < argc; i++)
            args.push_back(args_span[i]);

        return protected_main(args);
    }
    catch (std::exception &e)
    {
        std::cerr << "Caught unhandled exception:" << '\n';
        std::cerr << "    - what(): " << e.what() << '\n';
    }
    catch (...)
    {
        std::cerr << "Caught unknown exception" << '\n';
    }

    return EXIT_FAILURE;
}
