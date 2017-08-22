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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <ioctl.h>
#include <ioctl_driver.h>
#include <command_line_parser.h>

#include <bfaffinity.h>

void bfm_flush();
void bfm_terminate();
void bfm_new_handler();
void bfm_help();

int bfm_process(
    gsl::not_null<file *> f, gsl::not_null<ioctl *> ctl,
    gsl::not_null<command_line_parser *> clp);

int protected_main(const command_line_parser::arg_list_type &args);
int ut_main(int argc, const char *argv[]);

#ifdef WIN64
#include <windows.h>
HANDLE bfm_ioctl_open();
HANDLE g_valid = reinterpret_cast<HANDLE>(42);
#else
int bfm_ioctl_open();
int g_valid = 42;
#endif

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

void ut_abort()
{ }

TEST_CASE("flush")
{
    CHECK_NOTHROW(bfm_flush());
}

TEST_CASE("terminate")
{
    ut_abort();

    MockRepository mocks;
    mocks.OnCallFunc(ut_abort);

    CHECK_NOTHROW(bfm_terminate());
}

TEST_CASE("new handler")
{
    ut_abort();

    MockRepository mocks;
    mocks.OnCallFunc(ut_abort);

    CHECK_NOTHROW(bfm_new_handler());
}

TEST_CASE("process help")
{
    MockRepository mocks;
    auto fil = mocks.Mock<file>();
    auto ctl = mocks.Mock<ioctl>();
    auto clp = mocks.Mock<command_line_parser>();

    mocks.OnCall(clp, command_line_parser::cmd).Return(command_line_parser_command::help);

    CHECK_NOTHROW(bfm_process(fil, ctl, clp));
}

TEST_CASE("protected_main help")
{
    MockRepository mocks;
    mocks.OnCallFunc(bfm_process).Return(0);
    mocks.OnCallFunc(bfm_ioctl_open).Return(g_valid);

    CHECK_NOTHROW(protected_main({"-h"}));
}

TEST_CASE("protected_main affinity fail")
{
    MockRepository mocks;
    mocks.OnCallFunc(bfm_process).Return(0);
    mocks.OnCallFunc(bfm_ioctl_open).Return(g_valid);

    CHECK_THROWS(protected_main({"stop", "--cpuid", "31"}));
}

TEST_CASE("protected_main success")
{
    MockRepository mocks;
    mocks.OnCallFunc(bfm_process).Return(0);
    mocks.OnCallFunc(bfm_ioctl_open).Return(g_valid);

    CHECK_NOTHROW(protected_main({"stop"}));
}

TEST_CASE("main not args success")
{
    MockRepository mocks;
    mocks.OnCallFunc(protected_main).Return(0);

    CHECK_NOTHROW(ut_main(0, nullptr));
}

TEST_CASE("main throws known")
{
    MockRepository mocks;
    mocks.OnCallFunc(protected_main).Throw(std::runtime_error("error"));

    std::array<const char *, 4> argv{{"ut_main", "arg1", "arg2", "arg3"}};
    CHECK_NOTHROW(ut_main(gsl::narrow_cast<int>(argv.size()), argv.data()));
}

TEST_CASE("main throws unknown")
{
    MockRepository mocks;
    mocks.OnCallFunc(protected_main).Throw(42);

    std::array<const char *, 4> argv{{"ut_main", "arg1", "arg2", "arg3"}};
    CHECK_NOTHROW(ut_main(gsl::narrow_cast<int>(argv.size()), argv.data()));
}

TEST_CASE("main success")
{
    MockRepository mocks;
    mocks.OnCallFunc(protected_main).Return(0);

    std::array<const char *, 4> argv{{"ut_main", "arg1", "arg2", "arg3"}};
    CHECK_NOTHROW(ut_main(gsl::narrow_cast<int>(argv.size()), argv.data()));
}

#endif
