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

#include <gsl/gsl>

#include <vector>
#include <string>
#include <memory>
#include <iostream>
#include <exception.h>

#include <command_line_parser.h>
#include <file.h>
#include <ioctl.h>
#include <ioctl_driver.h>

#if !defined(__CYGWIN__) && !defined(_WIN32)

#include <sys/mman.h>

void
flush()
{
    mlockall(MCL_CURRENT);
    munlockall();
}

#else

void
flush()
{
}

#endif

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
    std::cout << "Usage: bfm [OPTION]... load... list_of_modules..." << std::endl;
    std::cout << "  or:  bfm [OPTION]... unload..." << std::endl;
    std::cout << "  or:  bfm [OPTION]... start..." << std::endl;
    std::cout << "  or:  bfm [OPTION]... stop..." << std::endl;
    std::cout << "  or:  bfm [OPTION]... dump..." << std::endl;
    std::cout << "  or:  bfm [OPTION]... status..." << std::endl;
    std::cout << "  or:  bfm [OPTION]... vmcall versions index..." << std::endl;
    std::cout << "  or:  bfm [OPTION]... vmcall registers r2 r3...r15" << std::endl;
    std::cout << "  or:  bfm [OPTION]... vmcall string type \"\"..." << std::endl;
    std::cout << "  or:  bfm [OPTION]... vmcall data type ifile ofile..." << std::endl;
    std::cout << "  or:  bfm [OPTION]... vmcall unittest index..." << std::endl;
    std::cout << "  or:  bfm [OPTION]... vmcall event index..." << std::endl;
    std::cout << "Controls or queries the bareflank hypervisor" << std::endl;
    std::cout << std::endl;
    std::cout << "       -h, --help      show this help menu" << std::endl;
    std::cout << "           --cpuid     indicate the requested cpuid" << std::endl;
    std::cout << "           --vcpuid    indicate the requested vcpuid" << std::endl;
    std::cout << std::endl;
    std::cout << " vmcall string types:" << std::endl;
    std::cout << "       unformatted     unformatted string" << std::endl;
    std::cout << "       json            json formatted string" << std::endl;
    std::cout << std::endl;
    std::cout << " vmcall binary types:" << std::endl;
    std::cout << "       unformatted     unformatted binary data" << std::endl;
    std::cout << std::endl;
    std::cout << " vmcall notes:" << std::endl;
    std::cout << "       - registers are represented in hex" << std::endl;
    std::cout << "       - data / string uuids equal 0" << std::endl;
}

int
protected_main(const command_line_parser::arg_list_type &args)
{
    // -------------------------------------------------------------------------
    // Command Line Parser

    auto &&clp = std::make_unique<command_line_parser>();

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

    auto &&ctl = std::make_unique<ioctl>();

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
    // Page-In Memory

    // TODO: In the future, we should create an RAII class that locks just the
    // pages being mapped to the hypervisor, which will need to be page
    // aligned. For now, this should work on most system

    flush();

    // -------------------------------------------------------------------------
    // IOCTR Driver

    try
    {
        auto &&f = std::make_unique<file>();
        auto &&driver = std::make_unique<ioctl_driver>(f.get(), ctl.get(), clp.get());

        driver->process();
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
        command_line_parser::arg_list_type args;
        auto args_span = gsl::make_span(argv, argc);

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
