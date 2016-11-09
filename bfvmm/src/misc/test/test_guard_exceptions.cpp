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
#include <guard_exceptions.h>

void
misc_ut::test_guard_exceptions_no_return()
{
    this->expect_no_exception([&] { guard_exceptions([&]{ throw bfn::general_exception(); }); });
    this->expect_no_exception([&] { guard_exceptions([&]{ throw std::logic_error("error"); }); });
    this->expect_no_exception([&] { guard_exceptions([&]{ throw std::bad_alloc(); }); });
    this->expect_no_exception([&] { guard_exceptions([&]{ throw 10; }); });
}

void
misc_ut::test_guard_exceptions_with_return()
{
    this->expect_true(guard_exceptions(10L, [&] { throw bfn::general_exception(); }) == 10L);
    this->expect_true(guard_exceptions(10L, [&] { throw std::logic_error("error"); }) == 10L);
    this->expect_true(guard_exceptions(10L, [&] { throw std::bad_alloc(); }) == BF_BAD_ALLOC);
    this->expect_true(guard_exceptions(10L, [&] { throw 10; }) == 10L);
}
