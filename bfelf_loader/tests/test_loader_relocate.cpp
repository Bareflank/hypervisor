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
#include <test_real_elf.h>

TEST_CASE("bfelf_loader_relocate: invalid loader")
{
    auto ret = bfelf_loader_relocate(nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_relocate: no files added")
{
    bfelf_loader_t loader = {};

    auto ret = bfelf_loader_relocate(&loader);
    CHECK(ret == BFELF_SUCCESS);
}

TEST_CASE("bfelf_loader_relocate: success")
{
    binaries_info binaries{&g_file, g_filenames};
}

TEST_CASE("bfelf_loader_relocate: twice")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    ret = bfelf_loader_relocate(&binaries.loader());
    CHECK(ret == BFELF_SUCCESS);
}

#ifndef WIN64

TEST_CASE("bfelf_loader_relocate: no such symbol")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    binaries.ef(0) = {};
    binaries.loader().relocated = 0;

    ret = bfelf_loader_relocate(&binaries.loader());
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

TEST_CASE("bfelf_loader_relocate: no such symbol in plt")
{
    int64_t ret = 0;
    binaries_info binaries{&g_file, g_filenames};

    binaries.ef(0) = {};
    binaries.loader().relocated = 0;

    for (auto i = 0ULL; i < 9; i++) {
        binaries.ef(i).relanum_dyn = 0;
    }

    ret = bfelf_loader_relocate(&binaries.loader());
    CHECK(ret == BFELF_ERROR_NO_SUCH_SYMBOL);
}

#endif
