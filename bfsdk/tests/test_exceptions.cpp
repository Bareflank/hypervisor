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

#include <catch/catch.hpp>
#include <bfexception.h>

enum class test_case {
    throw_logic_error,
    throw_bad_alloc,
    throw_int,
    no_throw
};

test_case g_test = test_case::no_throw;

void test()
{
    switch (g_test) {
        case test_case::throw_logic_error:
            throw std::logic_error("error");
        case test_case::throw_bad_alloc:
            throw std::bad_alloc();
        case test_case::throw_int:
            throw 10;
        default:
            break;
    }
}

TEST_CASE("no return")
{
    g_test = test_case::throw_logic_error;
    CHECK_NOTHROW(guard_exceptions(test));

    g_test = test_case::throw_bad_alloc;
    CHECK_NOTHROW(guard_exceptions(test));

    g_test = test_case::throw_int;
    CHECK_NOTHROW(guard_exceptions(test));

    g_test = test_case::no_throw;
    CHECK_NOTHROW(guard_exceptions(test));
}

TEST_CASE("with return")
{
    g_test = test_case::throw_logic_error;
    CHECK(guard_exceptions(10L, test) == 10L);

    g_test = test_case::throw_bad_alloc;
    CHECK(guard_exceptions(10L, test) == BF_BAD_ALLOC);

    g_test = test_case::throw_int;
    CHECK(guard_exceptions(10L, test) == 10L);

    g_test = test_case::no_throw;
    CHECK(guard_exceptions(10L, test) == SUCCESS);
}
