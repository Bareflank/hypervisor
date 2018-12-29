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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <catch/catch.hpp>
#include <test_fake_elf.h>

TEST_CASE("bfelf_file_init: success")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_SUCCESS);
}

TEST_CASE("bfelf_file_init: invalid file arg")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto size = std::get<1>(data);

    auto ret = bfelf_file_init(nullptr, size, &ef);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_init: invalid size arg")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);

    auto ret = bfelf_file_init(buf.get(), 0, &ef);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_init: invalid elf file")
{
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);

    auto ret = bfelf_file_init(buf.get(), size, nullptr);
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_file_init: invalid magic 0")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_ident[bfei_mag0] = 0;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

TEST_CASE("bfelf_file_init: invalid magic 1")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_ident[bfei_mag1] = 0;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

TEST_CASE("bfelf_file_init: invalid magic 2")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_ident[bfei_mag2] = 0;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

TEST_CASE("bfelf_file_init: invalid magic 3")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_ident[bfei_mag3] = 0;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

TEST_CASE("bfelf_file_init: invalid class")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_ident[bfei_class] = 0x4;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

TEST_CASE("bfelf_file_init: invalid data")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_ident[bfei_data] = 0x8;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

TEST_CASE("bfelf_file_init: invalid ident version")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_ident[bfei_version] = 0x15;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

TEST_CASE("bfelf_file_init: invalid osabi")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_ident[bfei_osabi] = 0x16;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

TEST_CASE("bfelf_file_init: invalid abiversion")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_ident[bfei_abiversion] = 0x23;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

TEST_CASE("bfelf_file_init: invalid type")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_type = 0xDEAD;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

TEST_CASE("bfelf_file_init: invalid machine")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_machine = 0xDEAD;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

TEST_CASE("bfelf_file_init: invalid version")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_version = 0xDEAD;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

TEST_CASE("bfelf_file_init: invalid flags")
{
    bfelf_file_t ef = {};
    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);
    auto test = reinterpret_cast<bfelf_test *>(buf.get());

    test->header.e_flags = 0xDEAD;

    auto ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}
