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
#include <intrinsics/x86/common_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

rflags::value_type g_rflags = 0;

uint64_t
test_read_rflags() noexcept
{ return g_rflags; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_rflags).Do(test_read_rflags);
}

TEST_CASE("rflags_x64")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = 0xFFFFFFFFU;
    CHECK(rflags::get() == 0xFFFFFFFFU);

    rflags::dump();

    g_rflags = 0x0U;
    CHECK(rflags::get() == 0x0U);
}

TEST_CASE("rflags_x64_carry_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::carry_flag::mask;
    CHECK(rflags::carry_flag::get());

    g_rflags = ~rflags::carry_flag::mask;
    CHECK_FALSE(rflags::carry_flag::get());
}

TEST_CASE("rflags_x64_parity_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::parity_flag::mask;
    CHECK(rflags::parity_flag::get());

    g_rflags = ~rflags::parity_flag::mask;
    CHECK_FALSE(rflags::parity_flag::get());
}

TEST_CASE("rflags_x64_auxiliary_carry_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::auxiliary_carry_flag::mask;
    CHECK(rflags::auxiliary_carry_flag::get());

    g_rflags = ~rflags::auxiliary_carry_flag::mask;
    CHECK_FALSE(rflags::auxiliary_carry_flag::get());
}

TEST_CASE("rflags_x64_zero_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::zero_flag::mask;
    CHECK(rflags::zero_flag::get());

    g_rflags = ~rflags::auxiliary_carry_flag::mask;
    CHECK_FALSE(rflags::auxiliary_carry_flag::get());
}

TEST_CASE("rflags_x64_sign_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::sign_flag::mask;
    CHECK(rflags::sign_flag::get());

    g_rflags = ~rflags::auxiliary_carry_flag::mask;
    CHECK_FALSE(rflags::auxiliary_carry_flag::get());
}

TEST_CASE("rflags_x64_trap_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::trap_flag::mask;
    CHECK(rflags::trap_flag::get());

    g_rflags = ~rflags::auxiliary_carry_flag::mask;
    CHECK_FALSE(rflags::auxiliary_carry_flag::get());
}

TEST_CASE("rflags_x64_interrupt_enable_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::interrupt_enable_flag::mask;
    CHECK(rflags::interrupt_enable_flag::get());

    g_rflags = ~rflags::auxiliary_carry_flag::mask;
    CHECK_FALSE(rflags::auxiliary_carry_flag::get());
}

TEST_CASE("rflags_x64_direction_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::direction_flag::mask;
    CHECK(rflags::direction_flag::get());

    g_rflags = ~rflags::auxiliary_carry_flag::mask;
    CHECK_FALSE(rflags::auxiliary_carry_flag::get());
}

TEST_CASE("rflags_x64_overflow_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::overflow_flag::mask;
    CHECK(rflags::overflow_flag::get());

    g_rflags = ~rflags::auxiliary_carry_flag::mask;
    CHECK_FALSE(rflags::auxiliary_carry_flag::get());
}

TEST_CASE("rflags_x64_privilege_level")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::privilege_level::mask;
    CHECK(rflags::privilege_level::get() == 3UL);

    g_rflags = ~rflags::auxiliary_carry_flag::mask;
    CHECK(rflags::auxiliary_carry_flag::get() == 0UL);
}

TEST_CASE("rflags_x64_nested_task")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::nested_task::mask;
    CHECK(rflags::nested_task::get());

    g_rflags = ~rflags::nested_task::mask;
    CHECK_FALSE(rflags::nested_task::get());
}

TEST_CASE("rflags_x64_resume_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::resume_flag::mask;
    CHECK(rflags::resume_flag::get());

    g_rflags = ~rflags::nested_task::mask;
    CHECK_FALSE(rflags::nested_task::get());
}

TEST_CASE("rflags_x64_virtual_8086_mode")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::virtual_8086_mode::mask;
    CHECK(rflags::virtual_8086_mode::get());

    g_rflags = ~rflags::nested_task::mask;
    CHECK_FALSE(rflags::nested_task::get());
}

TEST_CASE("rflags_x64_alignment_check_access_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::alignment_check_access_control::mask;
    CHECK(rflags::alignment_check_access_control::get());

    g_rflags = ~rflags::nested_task::mask;
    CHECK_FALSE(rflags::nested_task::get());
}

TEST_CASE("rflags_x64_virtual_interupt_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::virtual_interupt_flag::mask;
    CHECK(rflags::virtual_interupt_flag::get());

    g_rflags = ~rflags::nested_task::mask;
    CHECK_FALSE(rflags::nested_task::get());
}

TEST_CASE("rflags_x64_virtual_interupt_pending")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::virtual_interupt_pending::mask;
    CHECK(rflags::virtual_interupt_pending::get());

    g_rflags = ~rflags::nested_task::mask;
    CHECK_FALSE(rflags::nested_task::get());
}

TEST_CASE("rflags_x64_id_flag")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::id_flag::mask;
    CHECK(rflags::id_flag::get());

    g_rflags = ~rflags::nested_task::mask;
    CHECK_FALSE(rflags::nested_task::get());
}

TEST_CASE("rflags_x64_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::reserved::mask;
    CHECK(rflags::reserved::get() == 0xFFFFFFFFFFC08028UL);

    g_rflags = ~rflags::reserved::mask;
    CHECK(rflags::reserved::get() == 0UL);
}

TEST_CASE("rflags_x64_always_disabled")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::always_disabled::mask;
    CHECK(rflags::always_disabled::get() == 0xFFFFFFFFFFC08028UL);

    g_rflags = ~rflags::always_disabled::mask;
    CHECK(rflags::always_disabled::get() == 0UL);
}

TEST_CASE("rflags_x64_always_enabled")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_rflags = rflags::always_enabled::mask;
    CHECK(rflags::always_enabled::get() == rflags::always_enabled::mask);

    g_rflags = ~rflags::always_enabled::mask;
    CHECK(rflags::always_enabled::get() == 0UL);
}

#endif
