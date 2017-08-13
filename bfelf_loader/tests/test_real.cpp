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
#include <test_real_elf.h>

std::vector<char>fake_stack(0x8000);

TEST_CASE("bfelf_loader_resolve_symbol: real test (list)")
{
    binaries_info binaries{&g_file, g_filenames};

    std::array<const char *, 2> argv{{"1000", "2000"}};
    binaries.set_args(gsl::narrow_cast<int>(argv.size()), argv.data());

    auto func = reinterpret_cast<_start_t>(binaries.entry());
    CHECK(func(&fake_stack.at(0x7999), &binaries.info()) == 6000);
}

TEST_CASE("bfelf_loader_resolve_symbol: real test (needed)")
{
    binaries_info binaries{&g_file, g_filenames.back(), {BAREFLANK_SYSROOT_PATH + "/lib/"_s}};

    std::array<const char *, 2> argv{{"1000", "2000"}};
    binaries.set_args(gsl::narrow_cast<int>(argv.size()), argv.data());

    auto func = reinterpret_cast<_start_t>(binaries.entry());
    CHECK(func(&fake_stack.at(0x7999), &binaries.info()) == 6000);
}
