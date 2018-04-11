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

#include <catch/catch.hpp>
#include <arch/x64/rflags.h>

using namespace x64;

rflags::value_type g_rflags = 0;

extern "C" uint64_t
_read_rflags() noexcept
{ return g_rflags; }

extern "C" void
_write_rflags(uint64_t val) noexcept
{ g_rflags = val; }

TEST_CASE("rflags")
{
    g_rflags = 0xFFFFFFFFU;
    CHECK(rflags::get() == 0xFFFFFFFFU);

    rflags::dump(0);

    g_rflags = 0x0U;
    CHECK(rflags::get() == 0x0U);
}

TEST_CASE("rflags_carry_flag")
{
    using namespace rflags;

    carry_flag::enable();
    CHECK(carry_flag::is_enabled());
    carry_flag::disable();
    CHECK(carry_flag::is_disabled());

    carry_flag::enable(carry_flag::mask);
    CHECK(carry_flag::is_enabled(carry_flag::mask));
    carry_flag::disable(0x0);
    CHECK(carry_flag::is_disabled(0x0));
}

TEST_CASE("rflags_parity_flag")
{
    using namespace rflags;

    parity_flag::enable();
    CHECK(parity_flag::is_enabled());
    parity_flag::disable();
    CHECK(parity_flag::is_disabled());

    parity_flag::enable(parity_flag::mask);
    CHECK(parity_flag::is_enabled(parity_flag::mask));
    parity_flag::disable(0x0);
    CHECK(parity_flag::is_disabled(0x0));
}

TEST_CASE("rflags_auxiliary_carry_flag")
{
    using namespace rflags;

    auxiliary_carry_flag::enable();
    CHECK(auxiliary_carry_flag::is_enabled());
    auxiliary_carry_flag::disable();
    CHECK(auxiliary_carry_flag::is_disabled());

    auxiliary_carry_flag::enable(auxiliary_carry_flag::mask);
    CHECK(auxiliary_carry_flag::is_enabled(auxiliary_carry_flag::mask));
    auxiliary_carry_flag::disable(0x0);
    CHECK(auxiliary_carry_flag::is_disabled(0x0));
}

TEST_CASE("rflags_zero_flag")
{
    using namespace rflags;

    zero_flag::enable();
    CHECK(zero_flag::is_enabled());
    zero_flag::disable();
    CHECK(zero_flag::is_disabled());

    zero_flag::enable(zero_flag::mask);
    CHECK(zero_flag::is_enabled(zero_flag::mask));
    zero_flag::disable(0x0);
    CHECK(zero_flag::is_disabled(0x0));
}

TEST_CASE("rflags_sign_flag")
{
    using namespace rflags;

    sign_flag::enable();
    CHECK(sign_flag::is_enabled());
    sign_flag::disable();
    CHECK(sign_flag::is_disabled());

    sign_flag::enable(sign_flag::mask);
    CHECK(sign_flag::is_enabled(sign_flag::mask));
    sign_flag::disable(0x0);
    CHECK(sign_flag::is_disabled(0x0));
}

TEST_CASE("rflags_trap_flag")
{
    using namespace rflags;

    trap_flag::enable();
    CHECK(trap_flag::is_enabled());
    trap_flag::disable();
    CHECK(trap_flag::is_disabled());

    trap_flag::enable(trap_flag::mask);
    CHECK(trap_flag::is_enabled(trap_flag::mask));
    trap_flag::disable(0x0);
    CHECK(trap_flag::is_disabled(0x0));
}

TEST_CASE("rflags_interrupt_enable_flag")
{
    using namespace rflags;

    interrupt_enable_flag::enable();
    CHECK(interrupt_enable_flag::is_enabled());
    interrupt_enable_flag::disable();
    CHECK(interrupt_enable_flag::is_disabled());

    interrupt_enable_flag::enable(interrupt_enable_flag::mask);
    CHECK(interrupt_enable_flag::is_enabled(interrupt_enable_flag::mask));
    interrupt_enable_flag::disable(0x0);
    CHECK(interrupt_enable_flag::is_disabled(0x0));
}

TEST_CASE("rflags_direction_flag")
{
    using namespace rflags;

    direction_flag::enable();
    CHECK(direction_flag::is_enabled());
    direction_flag::disable();
    CHECK(direction_flag::is_disabled());

    direction_flag::enable(direction_flag::mask);
    CHECK(direction_flag::is_enabled(direction_flag::mask));
    direction_flag::disable(0x0);
    CHECK(direction_flag::is_disabled(0x0));
}

TEST_CASE("rflags_overflow_flag")
{
    using namespace rflags;

    overflow_flag::enable();
    CHECK(overflow_flag::is_enabled());
    overflow_flag::disable();
    CHECK(overflow_flag::is_disabled());

    overflow_flag::enable(overflow_flag::mask);
    CHECK(overflow_flag::is_enabled(overflow_flag::mask));
    overflow_flag::disable(0x0);
    CHECK(overflow_flag::is_disabled(0x0));
}

TEST_CASE("rflags_privilege_level")
{
    using namespace rflags;

    privilege_level::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(privilege_level::get() == (privilege_level::mask >> privilege_level::from));

    privilege_level::set(privilege_level::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(privilege_level::get(privilege_level::mask) == (privilege_level::mask >> privilege_level::from));
}

TEST_CASE("rflags_nested_task")
{
    using namespace rflags;

    nested_task::enable();
    CHECK(nested_task::is_enabled());
    nested_task::disable();
    CHECK(nested_task::is_disabled());

    nested_task::enable(nested_task::mask);
    CHECK(nested_task::is_enabled(nested_task::mask));
    nested_task::disable(0x0);
    CHECK(nested_task::is_disabled(0x0));
}

TEST_CASE("rflags_resume_flag")
{
    using namespace rflags;

    resume_flag::enable();
    CHECK(resume_flag::is_enabled());
    resume_flag::disable();
    CHECK(resume_flag::is_disabled());

    resume_flag::enable(resume_flag::mask);
    CHECK(resume_flag::is_enabled(resume_flag::mask));
    resume_flag::disable(0x0);
    CHECK(resume_flag::is_disabled(0x0));
}

TEST_CASE("rflags_virtual_8086_mode")
{
    using namespace rflags;

    virtual_8086_mode::enable();
    CHECK(virtual_8086_mode::is_enabled());
    virtual_8086_mode::disable();
    CHECK(virtual_8086_mode::is_disabled());

    virtual_8086_mode::enable(virtual_8086_mode::mask);
    CHECK(virtual_8086_mode::is_enabled(virtual_8086_mode::mask));
    virtual_8086_mode::disable(0x0);
    CHECK(virtual_8086_mode::is_disabled(0x0));
}

TEST_CASE("rflags_alignment_check_access_control")
{
    using namespace rflags;

    alignment_check_access_control::enable();
    CHECK(alignment_check_access_control::is_enabled());
    alignment_check_access_control::disable();
    CHECK(alignment_check_access_control::is_disabled());

    alignment_check_access_control::enable(alignment_check_access_control::mask);
    CHECK(alignment_check_access_control::is_enabled(alignment_check_access_control::mask));
    alignment_check_access_control::disable(0x0);
    CHECK(alignment_check_access_control::is_disabled(0x0));
}

TEST_CASE("rflags_virtual_interupt_flag")
{
    using namespace rflags;

    virtual_interupt_flag::enable();
    CHECK(virtual_interupt_flag::is_enabled());
    virtual_interupt_flag::disable();
    CHECK(virtual_interupt_flag::is_disabled());

    virtual_interupt_flag::enable(virtual_interupt_flag::mask);
    CHECK(virtual_interupt_flag::is_enabled(virtual_interupt_flag::mask));
    virtual_interupt_flag::disable(0x0);
    CHECK(virtual_interupt_flag::is_disabled(0x0));
}

TEST_CASE("rflags_virtual_interupt_pending")
{
    using namespace rflags;

    virtual_interupt_pending::enable();
    CHECK(virtual_interupt_pending::is_enabled());
    virtual_interupt_pending::disable();
    CHECK(virtual_interupt_pending::is_disabled());

    virtual_interupt_pending::enable(virtual_interupt_pending::mask);
    CHECK(virtual_interupt_pending::is_enabled(virtual_interupt_pending::mask));
    virtual_interupt_pending::disable(0x0);
    CHECK(virtual_interupt_pending::is_disabled(0x0));
}

TEST_CASE("rflags_id_flag")
{
    using namespace rflags;

    id_flag::enable();
    CHECK(id_flag::is_enabled());
    id_flag::disable();
    CHECK(id_flag::is_disabled());

    id_flag::enable(id_flag::mask);
    CHECK(id_flag::is_enabled(id_flag::mask));
    id_flag::disable(0x0);
    CHECK(id_flag::is_disabled(0x0));
}
