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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <test_real_elf.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("bfelf_binary: binary load fails")
{
    MockRepository mocks;
    mocks.OnCallFunc(bfelf_load).Return(-1);

    file f;
    CHECK_THROWS(binaries_info(&f, g_filenames.back(), {VMM_PREFIX_PATH + "/lib/"_s}));
}

TEST_CASE("bfelf_binary: binary success")
{
    file f;
    CHECK_NOTHROW(binaries_info(&f, g_filenames.back(), {VMM_PREFIX_PATH + "/lib/"_s}));
}

TEST_CASE("bfelf_binary: module list load fails")
{
    MockRepository mocks;
    mocks.OnCallFunc(bfelf_load).Return(-1);

    file f;
    CHECK_THROWS(binaries_info(&f, g_filenames));
}

TEST_CASE("bfelf_binary: module list success")
{
    file f;
    CHECK_NOTHROW(binaries_info(&f, g_filenames));
}

TEST_CASE("bfelf_binary: set args")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.set_args(0, nullptr));
}

TEST_CASE("bfelf_binary: ef")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.ef());
}

TEST_CASE("bfelf_binary: ef index")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.ef(0));
}

TEST_CASE("bfelf_binary: at")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.at(0));
}

TEST_CASE("bfelf_binary: front")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.front());
}

TEST_CASE("bfelf_binary: back")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.back());
}

TEST_CASE("bfelf_binary: binaries")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.binaries());
}

TEST_CASE("bfelf_binary: info")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.info());
}

TEST_CASE("bfelf_binary: entry")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.entry());
}

TEST_CASE("bfelf_binary: loader")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.loader());
}

#endif
