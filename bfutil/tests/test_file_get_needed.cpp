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

TEST_CASE("bfelf_file_get_needed: invalid elf file")
{
    uint64_t index = 0;
    const char *needed = nullptr;

    auto ret = bfelf_file_get_needed(nullptr, index, &needed);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_needed: index")
{
    uint64_t index = 0;
    bfelf_file_t ef = {};
    const char *needed = nullptr;

    auto ret = bfelf_file_get_needed(&ef, index, &needed);
    CHECK(ret == BFELF_ERROR_INVALID_INDEX);
}

TEST_CASE("bfelf_file_get_needed: invalid size")
{
    uint64_t index = 0;
    bfelf_file_t ef = {};

    auto ret = bfelf_file_get_needed(&ef, index, nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_needed: success")
{
    uint64_t index = 0;
    const char *needed = nullptr;
    binaries_info binaries{&g_file, g_filenames};

    auto ret = bfelf_file_get_needed(&binaries.ef(), index, &needed);
    CHECK(ret == BFELF_SUCCESS);
}
