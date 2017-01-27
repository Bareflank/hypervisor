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

#include <test.h>

void
bfelf_loader_ut::test_bfelf_file_init_success()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_SUCCESS);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_file_arg()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&size = std::get<1>(data);

    auto ret = bfelf_file_init(nullptr, size, &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_file_size_arg()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);

    auto ret = bfelf_file_init(buff.get(), 0, &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_elf_file()
{
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);

    auto ret = bfelf_file_init(buff.get(), size, nullptr);
    this->expect_true(ret == BFELF_ERROR_INVALID_ARG);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_magic_0()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_ident[bfei_mag0] = 0;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_magic_1()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_ident[bfei_mag1] = 0;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_magic_2()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_ident[bfei_mag2] = 0;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_magic_3()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_ident[bfei_mag3] = 0;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_INVALID_SIGNATURE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_class()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_ident[bfei_class] = 0x4;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_data()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_ident[bfei_data] = 0x8;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_ident_version()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_ident[bfei_version] = 0x15;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_osabi()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_ident[bfei_osabi] = 0x16;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_abiversion()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_ident[bfei_abiversion] = 0x23;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_type()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_type = 0xDEAD;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_machine()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_machine = 0xDEAD;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_version()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_version = 0xDEAD;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}

void
bfelf_loader_ut::test_bfelf_file_init_invalid_flags()
{
    bfelf_file_t ef;
    auto &&data = get_test();
    auto &&buff = std::get<0>(data);
    auto &&size = std::get<1>(data);
    auto &&test = reinterpret_cast<bfelf_test *>(buff.get());

    test->header.e_flags = 0xDEAD;

    auto ret = bfelf_file_init(buff.get(), size, &ef);
    this->expect_true(ret == BFELF_ERROR_UNSUPPORTED_FILE);
}
