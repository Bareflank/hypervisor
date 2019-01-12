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

TEST_CASE("bfelf_file_get_section_info: invalid elf")
{
    section_info_t info = {};

    auto ret = bfelf_file_get_section_info(nullptr, &info);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_section_info: invalid info")
{
    bfelf_file_t ef = {};

    auto ret = bfelf_file_get_section_info(&ef, nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_section_info: not added to loader")
{
    bfelf_file_t ef = {};
    section_info_t info = {};

    auto ret = bfelf_file_get_section_info(&ef, &info);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_get_section_info: expected misc resources")
{
    binaries_info binaries{&g_file, g_filenames};

    section_info_t info = {};
    auto &dummy_main_ef = binaries.ef();

    dummy_main_ef.init = 42;
    dummy_main_ef.fini = 42;
    dummy_main_ef.fini_array = 42;
    dummy_main_ef.fini_arraysz = 42;

    auto ret = bfelf_file_get_section_info(&dummy_main_ef, &info);
    CHECK(ret == BFELF_SUCCESS);

    CHECK(info.init_array_addr != nullptr);
    CHECK(info.init_array_size != 0);

    CHECK(info.fini_array_addr != nullptr);
    CHECK(info.fini_array_size != 0);

    CHECK(info.eh_frame_addr != nullptr);
    CHECK(info.eh_frame_size != 0);
}
