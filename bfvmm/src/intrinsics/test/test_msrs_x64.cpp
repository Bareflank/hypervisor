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
#include <intrinsics/msrs_x64.h>

using namespace x64;

std::map<msrs::field_type, msrs::value_type> g_msrs;

extern "C" uint64_t
__read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
__write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

void
intrinsics_ut::test_ia32_pat()
{
    msrs::ia32_pat::set(0xFFFFFFFFFFFFFFFFUL);
    this->expect_true(msrs::ia32_pat::get() == 0xFFFFFFFFFFFFFFFFUL);

    msrs::ia32_pat::dump();

    msrs::ia32_pat::set(0x0U);
    this->expect_true(msrs::ia32_pat::get() == 0x0U);
}

void
intrinsics_ut::test_ia32_pat_pa0()
{
    msrs::ia32_pat::pa0::set(6UL);
    this->expect_true(msrs::ia32_pat::pa0::get() == 6UL);
    this->expect_true(msrs::ia32_pat::pa0::get(0x0000000000000006UL) == 6UL);

    msrs::ia32_pat::pa0::set(4UL);
    this->expect_true(msrs::ia32_pat::pa0::get() == 4UL);
    this->expect_true(msrs::ia32_pat::pa0::get(0x0000000000000004UL) == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa1()
{
    msrs::ia32_pat::pa1::set(6UL);
    this->expect_true(msrs::ia32_pat::pa1::get() == 6UL);
    this->expect_true(msrs::ia32_pat::pa1::get(0x0000000000000600UL) == 6UL);

    msrs::ia32_pat::pa1::set(4UL);
    this->expect_true(msrs::ia32_pat::pa1::get() == 4UL);
    this->expect_true(msrs::ia32_pat::pa1::get(0x0000000000000400UL) == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa2()
{
    msrs::ia32_pat::pa2::set(6UL);
    this->expect_true(msrs::ia32_pat::pa2::get() == 6UL);
    this->expect_true(msrs::ia32_pat::pa2::get(0x0000000000060000UL) == 6UL);

    msrs::ia32_pat::pa2::set(4UL);
    this->expect_true(msrs::ia32_pat::pa2::get() == 4UL);
    this->expect_true(msrs::ia32_pat::pa2::get(0x0000000000040000UL) == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa3()
{
    msrs::ia32_pat::pa3::set(6UL);
    this->expect_true(msrs::ia32_pat::pa3::get() == 6UL);
    this->expect_true(msrs::ia32_pat::pa3::get(0x0000000006000000UL) == 6UL);

    msrs::ia32_pat::pa3::set(4UL);
    this->expect_true(msrs::ia32_pat::pa3::get() == 4UL);
    this->expect_true(msrs::ia32_pat::pa3::get(0x0000000004000000UL) == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa4()
{
    msrs::ia32_pat::pa4::set(6UL);
    this->expect_true(msrs::ia32_pat::pa4::get() == 6UL);
    this->expect_true(msrs::ia32_pat::pa4::get(0x0000000600000000UL) == 6UL);

    msrs::ia32_pat::pa4::set(4UL);
    this->expect_true(msrs::ia32_pat::pa4::get() == 4UL);
    this->expect_true(msrs::ia32_pat::pa4::get(0x0000000400000000UL) == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa5()
{
    msrs::ia32_pat::pa5::set(6UL);
    this->expect_true(msrs::ia32_pat::pa5::get() == 6UL);
    this->expect_true(msrs::ia32_pat::pa5::get(0x0000060000000000UL) == 6UL);

    msrs::ia32_pat::pa5::set(4UL);
    this->expect_true(msrs::ia32_pat::pa5::get() == 4UL);
    this->expect_true(msrs::ia32_pat::pa5::get(0x0000040000000000UL) == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa6()
{
    msrs::ia32_pat::pa6::set(6UL);
    this->expect_true(msrs::ia32_pat::pa6::get() == 6UL);
    this->expect_true(msrs::ia32_pat::pa6::get(0x0006000000000000UL) == 6UL);

    msrs::ia32_pat::pa6::set(4UL);
    this->expect_true(msrs::ia32_pat::pa6::get() == 4UL);
    this->expect_true(msrs::ia32_pat::pa6::get(0x0004000000000000UL) == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa7()
{
    msrs::ia32_pat::pa7::set(6UL);
    this->expect_true(msrs::ia32_pat::pa7::get() == 6UL);
    this->expect_true(msrs::ia32_pat::pa7::get(0x0600000000000000UL) == 6UL);

    msrs::ia32_pat::pa7::set(4UL);
    this->expect_true(msrs::ia32_pat::pa7::get() == 4UL);
    this->expect_true(msrs::ia32_pat::pa7::get(0x0400000000000000UL) == 4UL);
}

void
intrinsics_ut::test_ia32_pat_pa()
{
    msrs::ia32_pat::pa0::set(0UL);
    msrs::ia32_pat::pa1::set(1UL);
    msrs::ia32_pat::pa2::set(2UL);
    msrs::ia32_pat::pa3::set(3UL);
    msrs::ia32_pat::pa4::set(4UL);
    msrs::ia32_pat::pa5::set(5UL);
    msrs::ia32_pat::pa6::set(6UL);
    msrs::ia32_pat::pa7::set(7UL);

    this->expect_true(msrs::ia32_pat::pa(0UL) == 0UL);
    this->expect_true(msrs::ia32_pat::pa(1UL) == 1UL);
    this->expect_true(msrs::ia32_pat::pa(2UL) == 2UL);
    this->expect_true(msrs::ia32_pat::pa(3UL) == 3UL);
    this->expect_true(msrs::ia32_pat::pa(4UL) == 4UL);
    this->expect_true(msrs::ia32_pat::pa(5UL) == 5UL);
    this->expect_true(msrs::ia32_pat::pa(6UL) == 6UL);
    this->expect_true(msrs::ia32_pat::pa(7UL) == 7UL);

    this->expect_true(msrs::ia32_pat::pa(0x0000000000000000UL, 0UL) == 0UL);
    this->expect_true(msrs::ia32_pat::pa(0x0000000000000100UL, 1UL) == 1UL);
    this->expect_true(msrs::ia32_pat::pa(0x0000000000020000UL, 2UL) == 2UL);
    this->expect_true(msrs::ia32_pat::pa(0x0000000003000000UL, 3UL) == 3UL);
    this->expect_true(msrs::ia32_pat::pa(0x0000000400000000UL, 4UL) == 4UL);
    this->expect_true(msrs::ia32_pat::pa(0x0000050000000000UL, 5UL) == 5UL);
    this->expect_true(msrs::ia32_pat::pa(0x0006000000000000UL, 6UL) == 6UL);
    this->expect_true(msrs::ia32_pat::pa(0x0700000000000000UL, 7UL) == 7UL);

    this->expect_exception([&] { msrs::ia32_pat::pa(10UL); }, ""_ut_ree);
    this->expect_exception([&] { msrs::ia32_pat::pa(0x0000000000000000UL, 10UL); }, ""_ut_ree);
}
