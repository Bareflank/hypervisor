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
#include <hippomocks.h>

#include <fstream>
#include <test_real_elf.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("bfelf_binary: binary load fails")
{
    MockRepository mocks;
    mocks.OnCallFunc(bfelf_load).Return(-1);

    file f;
    CHECK_THROWS(binaries_info(&f, g_filenames.back(), {BAREFLANK_SYSROOT_PATH + "/lib/"_s}));
}

TEST_CASE("bfelf_binary: binary success")
{
    file f;
    CHECK_NOTHROW(binaries_info(&f, g_filenames.back(), {BAREFLANK_SYSROOT_PATH + "/lib/"_s}));
}

TEST_CASE("bfelf_binary: module list load fails")
{
    MockRepository mocks;
    mocks.OnCallFunc(bfelf_load).Return(-1);

    file f;
    CHECK_THROWS(binaries_info(&f, g_filenames));
}

TEST_CASE("bfelf_binary: module list success")
{
    file f;
    CHECK_NOTHROW(binaries_info(&f, g_filenames));
}

TEST_CASE("bfelf_binary: set args")
{
    file f;
    binaries_info info(&f, g_filenames);

    CHECK_NOTHROW(info.set_args(0, nullptr));
}

#endif
