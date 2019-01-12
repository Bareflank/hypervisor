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

#include <hippomocks.h>
#include <catch/catch.hpp>

#include <bfgsl.h>
#include <test_real_elf.h>

TEST_CASE("bfelf_set_integer_args: invalid info")
{
    file f;
    bfn::buffer buffer{};
    bfelf_binary_t binary{};
    std::string filename{"test.txt"};

    REQUIRE_NOTHROW(f.write_text(filename, "not an ELF file"));

    CHECK_THROWS(
        bfelf_read_binary_and_get_needed_list(&f, filename, {}, buffer, binary)
    );

    REQUIRE(std::remove(filename.c_str()) == 0);
}

TEST_CASE("bfelf_set_integer_args: no paths")
{
    file f;
    bfn::buffer buffer{};
    bfelf_binary_t binary{};

    CHECK_THROWS(
        bfelf_read_binary_and_get_needed_list(&f, g_filenames.back(), {"not a dir"}, buffer, binary)
    );
}

TEST_CASE("bfelf_set_integer_args: invalid filename")
{
    file f;
    bfn::buffer buffer{};
    bfelf_binary_t binary{};

    CHECK_THROWS(
        bfelf_read_binary_and_get_needed_list(&f, "not_a_real_file", {}, buffer, binary)
    );
}

TEST_CASE("bfelf_set_integer_args: success")
{
    file f;
    bfn::buffer buffer{};
    bfelf_binary_t binary{};

    CHECK_NOTHROW(
        bfelf_read_binary_and_get_needed_list(&f, g_filenames.back(), {VMM_PREFIX_PATH + "/lib/"_s}, buffer, binary)
    );
}
