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
