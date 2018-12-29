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

#include <test_fake_elf.h>
#include <test_real_elf.h>

TEST_CASE("bfelf_file_get_entry: invalid elf file")
{
    void *addr = nullptr;

    auto ret = bfelf_file_get_entry(nullptr, &addr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_entry: invalid addr")
{
    int64_t ret = 0;
    bfelf_file_t ef = {};

    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);

    ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_SUCCESS);

    ret = bfelf_file_get_entry(&ef, nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_entry: not added to loader")
{
    int64_t ret = 0;
    void *addr = nullptr;
    bfelf_file_t ef = {};

    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);

    ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_SUCCESS);

    ret = bfelf_file_get_entry(&ef, &addr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_entry: success")
{
    int64_t ret = 0;
    void *addr = nullptr;

    binaries_info binaries{&g_file, g_filenames};

    ret = bfelf_file_get_entry(&binaries.ef(), &addr);
    CHECK(ret == BFELF_SUCCESS);
}
