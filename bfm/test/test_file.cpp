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

#include <file.h>
#include <exception.h>

static auto operator"" _ife(const char *str, std::size_t len)
{ (void)str; (void)len; return std::make_shared<bfn::invalid_file_error>(""); }

void
bfm_ut::test_file_read_with_bad_filename()
{
    auto &&f = file{};
    auto &&filename = "/blah/bad_filename.txt"_s;

    this->expect_exception([&] { f.read_text(""); }, ""_ut_ffe);
    this->expect_exception([&] { f.read_binary(""); }, ""_ut_ffe);

    this->expect_exception([&] { f.read_text(filename); }, ""_ife);
    this->expect_exception([&] { f.read_binary(filename); }, ""_ife);
}

void
bfm_ut::test_file_write_with_bad_filename()
{
    auto &&f = file{};
    auto &&filename = "/blah/bad_filename.txt"_s;

    auto &&text_data = "hello"_s;
    auto &&binary_data = {'h', 'e', 'l', 'l', 'o'};

    this->expect_exception([&] { f.write_text("", text_data); }, ""_ut_ffe);
    this->expect_exception([&] { f.write_binary("", binary_data); }, ""_ut_ffe);

    this->expect_exception([&] { f.write_text(filename, ""); }, ""_ut_ffe);
    this->expect_exception([&] { f.write_binary(filename, {}); }, ""_ut_ffe);

    this->expect_exception([&] { f.write_text(filename, text_data); }, ""_ife);
    this->expect_exception([&] { f.write_binary(filename, binary_data); }, ""_ife);
}

void
bfm_ut::test_file_read_write_success()
{
    auto &&f = file{};
    auto &&filename = "/tmp/test_file.txt"_s;

    auto &&text_data = "hello"_s;
    auto &&binary_data = {'h', 'e', 'l', 'l', 'o'};

    this->expect_no_exception([&] { f.write_text(filename, text_data); });
    this->expect_true(f.read_text(filename) == text_data);

    this->expect_no_exception([&] { f.write_binary(filename, binary_data); });
    this->expect_true(f.read_binary(filename) == file::binary_data(binary_data));

    auto &&ret = std::remove(filename.c_str());
    (void) ret;
}
