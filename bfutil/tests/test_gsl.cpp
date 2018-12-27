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

#define NEED_GSL_LITE
#define GSL_ABORT ut_abort

void ut_abort()
{
    std::cout << "test\n";
}

#include <bfgsl.h>
#include <bftypes.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("expects / ensures")
{
    ut_abort();

    {
        MockRepository mocks;
        mocks.ExpectCallFunc(ut_abort);
        mocks.ExpectCallFunc(ut_abort);

        expects(true);
        ensures(true);

        expects(false);
        ensures(false);
    }

    // Note:
    //
    // Clang Tidy seems to have a bug and thinks that the Mock library
    // has a dangling pointer if this is not done. This might be able to
    // be removed when Clang Tidy is updated
    //
    HippoMocks::MockRepoInstanceHolder<0>::instance = nullptr;
}

TEST_CASE("narrow cast")
{
    auto var = gsl::narrow_cast<int>(42);
}

TEST_CASE("array")
{
    int count = 0;
    char buf[42] = {};

    for (int i = 0; i < 42; i++) {
        count += gsl::at(buf, i);
    }
}

TEST_CASE("const array")
{
    int count = 0;
    const char buf[42] = {};

    for (int i = 0; i < 42; i++) {
        count += gsl::at(buf, i);
    }
}

TEST_CASE("array with provided limit")
{
    int count = 0;
    char buf[42] = {};

    for (int i = 0; i < 42; i++) {
        count += gsl::at(static_cast<char *>(buf), 42, i);
    }
}

TEST_CASE("const array with provided limit")
{
    int count = 0;
    const char buf[42] = {};

    for (int i = 0; i < 42; i++) {
        count += gsl::at(static_cast<const char *>(buf), 42, i);
    }
}

#endif
