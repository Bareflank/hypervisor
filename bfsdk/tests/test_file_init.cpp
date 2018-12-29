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
