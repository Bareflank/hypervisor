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

#include <exception.h>

#include <test.h>
#include <file.h>

// This is not a true unit test since we are not providing the file
// class with a mock of fstream. Our attempts at doing that were not
// successful. These tests at least help us prove that the file class
// is going to work as intended.

file g_f;

void
bfm_ut::test_file_read_with_bad_filename()
{
    auto filename = "/tmp/bad_filename.txt";
    auto e = std::make_shared<bfn::invalid_file_error>("file read with bad filename"_s);

    this->expect_exception([&] { g_f.read(filename); }, e);

}

void
bfm_ut::test_file_read_with_good_filename()
{
    auto text = "blah";
    auto filename = "/tmp/bfm_test.txt";

    std::ofstream tmp(filename);
    tmp << text;
    tmp.close();

    this->expect_true(g_f.read(filename) == std::string(text));
    this->expect_true(std::remove(filename) == 0);
}
