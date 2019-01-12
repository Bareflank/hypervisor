//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <test_support.h>

void bfm_flush();
void bfm_terminate();
void bfm_new_handler();
void bfm_help();

int bfm_process(
    gsl::not_null<file *> f, gsl::not_null<ioctl *> ctl,
    gsl::not_null<command_line_parser *> clp);

int protected_main(const command_line_parser::arg_list_type &args);
int ut_main(int argc, const char *argv[]);

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

    CHECK_NOTHROW(protected_main({"-h"}));
}

TEST_CASE("protected_main success")
{
    MockRepository mocks;
    mocks.OnCallFunc(bfm_process).Return(0);

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
