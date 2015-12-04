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
#include <file_base.h>

// This is not a true unit test since we are not providing the file
// class with a mock of fstream. Our attempts at doing that we not
// successful. These tests at least help us prove that the file class
// is going to work as intended.

void
bfm_ut::test_file_exists_with_bad_filename()
{
    file f;
    auto filename = "/tmp/bad_filename.txt";

    EXPECT_TRUE(f.exists(filename) == false);
}

void
bfm_ut::test_file_exists_with_good_filename()
{
    file f;
    auto text = "blah";
    auto filename = "/tmp/bfm_test.txt";

    std::ofstream tmp(filename);
    tmp << text;
    tmp.close();

    EXPECT_TRUE(f.exists(filename) == true);

    std::remove(filename);
}

void
bfm_ut::test_file_read_with_bad_filename()
{
    file f;
    auto filename = "/tmp/bad_filename.txt";

    EXPECT_TRUE(f.read(filename) == std::string());
}

void
bfm_ut::test_file_read_with_good_filename()
{
    file f;
    auto text = "blah";
    auto filename = "/tmp/bfm_test.txt";

    std::ofstream tmp(filename);
    tmp << text;
    tmp.close();

    EXPECT_TRUE(f.read(filename) == std::string(text));

    std::remove(filename);
}
