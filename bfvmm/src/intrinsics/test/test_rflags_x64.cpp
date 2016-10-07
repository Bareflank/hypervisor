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
#include <intrinsics/rflags_x64.h>

using namespace intel_x64;

uint64_t g_rflags = 0;

extern "C" uint64_t
__read_rflags(void) noexcept
{ return g_rflags; }

void
intrinsics_ut::test_rflags_x64()
{
    g_rflags = 100UL;
    this->expect_true(rflags::get() == 100UL);
}

void
intrinsics_ut::test_rflags_x64_carry_flag()
{
    g_rflags = rflags::carry_flag::mask;
    this->expect_true(rflags::carry_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_parity_flag()
{
    g_rflags = rflags::parity_flag::mask;
    this->expect_true(rflags::parity_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_auxiliary_carry_flag()
{
    g_rflags = rflags::auxiliary_carry_flag::mask;
    this->expect_true(rflags::auxiliary_carry_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_zero_flag()
{
    g_rflags = rflags::zero_flag::mask;
    this->expect_true(rflags::zero_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_sign_flag()
{
    g_rflags = rflags::sign_flag::mask;
    this->expect_true(rflags::sign_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_trap_flag()
{
    g_rflags = rflags::trap_flag::mask;
    this->expect_true(rflags::trap_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_interrupt_enable_flag()
{
    g_rflags = rflags::interrupt_enable_flag::mask;
    this->expect_true(rflags::interrupt_enable_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_direction_flag()
{
    g_rflags = rflags::direction_flag::mask;
    this->expect_true(rflags::direction_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_overflow_flag()
{
    g_rflags = rflags::overflow_flag::mask;
    this->expect_true(rflags::overflow_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_privilege_level()
{
    g_rflags = rflags::privilege_level::mask;
    this->expect_true(rflags::privilege_level::get() == 3UL);
}

void
intrinsics_ut::test_rflags_x64_nested_task()
{
    g_rflags = rflags::nested_task::mask;
    this->expect_true(rflags::nested_task::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_resume_flag()
{
    g_rflags = rflags::resume_flag::mask;
    this->expect_true(rflags::resume_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_virtual_8086_mode()
{
    g_rflags = rflags::virtual_8086_mode::mask;
    this->expect_true(rflags::virtual_8086_mode::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_alignment_check_access_control()
{
    g_rflags = rflags::alignment_check_access_control::mask;
    this->expect_true(rflags::alignment_check_access_control::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_virtual_interupt_flag()
{
    g_rflags = rflags::virtual_interupt_flag::mask;
    this->expect_true(rflags::virtual_interupt_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_virtual_interupt_pending()
{
    g_rflags = rflags::virtual_interupt_pending::mask;
    this->expect_true(rflags::virtual_interupt_pending::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_id_flag()
{
    g_rflags = rflags::id_flag::mask;
    this->expect_true(rflags::id_flag::get() == 1UL);
}

void
intrinsics_ut::test_rflags_x64_reserved()
{
    g_rflags = rflags::reserved::mask;
    this->expect_true(rflags::reserved::get() == 0xFFFFFFFFFFC08028UL);
}

void
intrinsics_ut::test_rflags_x64_always_disabled()
{
    g_rflags = rflags::always_disabled::mask;
    this->expect_true(rflags::always_disabled::get() == 0xFFFFFFFFFFC08028UL);
}

void
intrinsics_ut::test_rflags_x64_always_enabled()
{
    g_rflags = rflags::always_enabled::mask;
    this->expect_true(rflags::always_enabled::get() == 0x00000000000000001L);
}
