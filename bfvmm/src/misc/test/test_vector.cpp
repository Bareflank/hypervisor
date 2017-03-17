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
#include <vector>

void
misc_ut::test_vector_find()
{
    std::vector<int> list = {1, 2, 3};

    this->expect_exception([&] { bfn::find(list, -1); }, ""_ut_ffe);
    this->expect_exception([&] { bfn::find(list, 10); }, ""_ut_ffe);
    this->expect_true(*bfn::find(list, 1) == 2);
}

void
misc_ut::test_vector_cfind()
{
    std::vector<int> list = {1, 2, 3};

    this->expect_exception([&] { bfn::cfind(list, -1); }, ""_ut_ffe);
    this->expect_exception([&] { bfn::cfind(list, 10); }, ""_ut_ffe);
    this->expect_true(*bfn::cfind(list, 1) == 2);
}

void
misc_ut::test_vector_take()
{
    std::vector<int> list = {1, 2, 3};

    this->expect_exception([&] { bfn::take(list, -1); }, ""_ut_ffe);
    this->expect_exception([&] { bfn::take(list, 10); }, ""_ut_ffe);
    this->expect_true(bfn::take(list, 1) == 2);
    this->expect_true(list.size() == 2);
}

void
misc_ut::test_vector_remove()
{
    std::vector<int> list = {1, 2, 3};

    this->expect_exception([&] { bfn::remove(list, -1); }, ""_ut_ffe);
    this->expect_exception([&] { bfn::remove(list, 10); }, ""_ut_ffe);
    this->expect_no_exception([&] { bfn::remove(list, 1); });
    this->expect_true(list.size() == 2);
}
