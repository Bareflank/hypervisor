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

#include <gsl/gsl>

#include <test.h>
#include <intrinsics/idt_x64.h>

std::vector<idt_x64::interrupt_descriptor_type> g_idt =
{
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF
};

idt_reg_x64_t g_idt_reg;

extern "C" void
__read_idt(idt_reg_x64_t *idt_reg) noexcept
{ *idt_reg = g_idt_reg; }

extern "C" void
__write_idt(idt_reg_x64_t *idt_reg) noexcept
{ g_idt_reg = *idt_reg; }

void
intrinsics_ut::test_idt_reg_set_get()
{
    x64::idt::set(g_idt.data(), (4 << 3) - 1);

    this->expect_true(x64::idt::get().base == g_idt.data());
    this->expect_true(x64::idt::get().limit == (4 << 3) - 1);
}

void
intrinsics_ut::test_idt_reg_base_set_get()
{
    x64::idt::base::set(g_idt.data());
    this->expect_true(x64::idt::base::get() == g_idt.data());
}

void
intrinsics_ut::test_idt_reg_limit_set_get()
{
    x64::idt::limit::set((4 << 3) - 1);
    this->expect_true(x64::idt::limit::get() == (4 << 3) - 1);
}

void
intrinsics_ut::test_idt_constructor_no_size()
{
    idt_x64 idt;
}

void
intrinsics_ut::test_idt_constructor_zero_size()
{
    this->expect_no_exception([&] { idt_x64{0}; });
}

void
intrinsics_ut::test_idt_constructor_size()
{
    idt_x64 idt{4};

    this->expect_true(idt.base() != 0);
    this->expect_true(idt.limit() == (4 * sizeof(idt_x64::interrupt_descriptor_type)) - 1);
}

void
intrinsics_ut::test_idt_base()
{
    idt_x64 idt;
    this->expect_true(idt.base() == reinterpret_cast<idt_x64::integer_pointer>(g_idt.data()));
}

void
intrinsics_ut::test_idt_limit()
{
    idt_x64 idt;
    this->expect_true(idt.limit() == (4 * sizeof(idt_x64::interrupt_descriptor_type)) - 1);
}
