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
#include <hippomocks.h>
#include <intrinsics/x86/common_x64.h>
#include <bfgsl.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

std::vector<idt_x64::interrupt_descriptor_type> g_idt = {
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF
};

idt_reg_x64_t g_idt_reg;

void
test_read_idt(idt_reg_x64_t *idt_reg) noexcept
{ *idt_reg = g_idt_reg; }

void
test_write_idt(idt_reg_x64_t *idt_reg) noexcept
{ g_idt_reg = *idt_reg; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_idt).Do(test_read_idt);
    mocks.OnCallFunc(_write_idt).Do(test_write_idt);
}

TEST_CASE("idt_reg_set_get")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    x64::idt::set(g_idt.data(), (4 << 3) - 1);

    CHECK(x64::idt::get().base == g_idt.data());
    CHECK(x64::idt::get().limit == (4 << 3) - 1);
}

TEST_CASE("idt_reg_base_set_get")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    x64::idt::base::set(g_idt.data());
    CHECK(x64::idt::base::get() == g_idt.data());
}

TEST_CASE("idt_reg_limit_set_get")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    x64::idt::limit::set((4 << 3) - 1);
    CHECK(x64::idt::limit::get() == (4 << 3) - 1);
}

TEST_CASE("idt_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    uint64_t bytes = 0;
    CHECK(x64::idt::size(bytes) == 0U);

    bytes = 0xfff;
    CHECK(x64::idt::size(bytes) == 1U);

    bytes = 0x1000;
    CHECK(x64::idt::size(bytes) == 1U * x64::page_size);

    bytes = 0x5001;
    CHECK(x64::idt::size(bytes) == 5U * x64::page_size + 1U);
}

TEST_CASE("idt_constructor_no_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    idt_x64 idt;
}

TEST_CASE("idt_constructor_zero_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(idt_x64{0});
}

TEST_CASE("idt_constructor_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    idt_x64 idt{4};

    CHECK(idt.base() != 0);
    CHECK(idt.limit() == (4 * sizeof(idt_x64::interrupt_descriptor_type)) - 1);
}

TEST_CASE("idt_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    idt_x64 idt;
    CHECK(idt.base() == reinterpret_cast<idt_x64::integer_pointer>(g_idt.data()));
}

TEST_CASE("idt_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    idt_x64 idt;
    CHECK(idt.limit() == (4 * sizeof(idt_x64::interrupt_descriptor_type)) - 1);
}

#endif
