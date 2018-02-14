//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <ioctl.h>
#include <ioctl_driver.h>
#include <command_line_parser.h>

#include <bfgsl.h>
#include <bffile.h>

#ifndef MAIN
#define MAIN ut_main
int ut_main(int argc, const char *argv[]);
#endif

#ifndef ABORT
#define ABORT ut_abort
void ut_abort();
#endif

#ifndef WIN64

#include <sys/mman.h>

void
bfm_flush()
{
    mlockall(MCL_CURRENT);
    munlockall();
}

#else

void
bfm_flush()
{
}

#endif

void
bfm_terminate()
{
    std::cerr << "FATAL ERROR: terminate called" << '\n';
    ABORT();
}

void
bfm_new_handler()
{
    std::cerr << "FATAL ERROR: out of memory" << '\n';
    ABORT();
}

void
bfm_help()
{
    std::cout << R"(Usage: bfm [OPTION]... load...)" << std::endl;
    std::cout << R"(  or:  bfm [OPTION]... load... binary)" << std::endl;
    std::cout << R"(  or:  bfm [OPTION]... load... file.modules)" << std::endl;
    std::cout << R"(  or:  bfm [OPTION]... unload...)" << std::endl;
    std::cout << R"(  or:  bfm [OPTION]... start...)" << std::endl;
    std::cout << R"(  or:  bfm [OPTION]... quick...)" << std::endl;
    std::cout << R"(  or:  bfm [OPTION]... stop...)" << std::endl;
    std::cout << R"(  or:  bfm [OPTION]... dump...)" << std::endl;
    std::cout << R"(  or:  bfm [OPTION]... status...)" << std::endl;
    std::cout << R"(Controls or queries the bareflank hypervisor)" << std::endl;
    std::cout << std::endl;
    std::cout << R"(       -h, --help      show this help menu)" << std::endl;
    std::cout << R"(           --vcpuid    indicate the requested vcpuid)" << std::endl;
}

int
bfm_process(
    gsl::not_null<file *> f,
    gsl::not_null<ioctl *> ctl,
    gsl::not_null<command_line_parser *> clp)
{
    auto driver = std::make_unique<ioctl_driver>(f, ctl, clp);
    driver->process();

    return EXIT_SUCCESS;
}

int
protected_main(const command_line_parser::arg_list_type &args)
{
    // -------------------------------------------------------------------------
    // Command Line Parser

    auto clp = std::make_unique<command_line_parser>();
    clp->parse(args);

    if (clp->cmd() == command_line_parser_command::help) {
        bfm_help();
        return EXIT_SUCCESS;
    }

    // -------------------------------------------------------------------------
    // IO Controller

    auto ctl = std::make_unique<ioctl>();
    ctl->open();

    // -------------------------------------------------------------------------
    // Page-In Memory

    // TODO: In the future, we should create an RAII class that locks just the
    // pages being mapped to the hypervisor, which will need to be page
    // aligned. For now, this should work on most system

    bfm_flush();

    // -------------------------------------------------------------------------
    // File

    auto f = std::make_unique<file>();

    // -------------------------------------------------------------------------
    // Process

    return bfm_process(f.get(), ctl.get(), clp.get());
}

int
MAIN(int argc, const char *argv[])
{
    std::set_terminate(bfm_terminate);
    std::set_new_handler(bfm_new_handler);

    try {
        command_line_parser::arg_list_type args;
        auto args_span = gsl::make_span(argv, argc);

        for (auto i = 1; i < argc; i++) {
            args.emplace_back(args_span[i]);
        }

        return protected_main(args);
    }
    catch (std::exception &e) {
        std::cerr << "Caught unhandled exception:" << '\n';
        std::cerr << "    - what(): " << e.what() << '\n';
    }
    catch (...) {
        std::cerr << "Caught unknown exception" << '\n';
    }

    return EXIT_FAILURE;
}
