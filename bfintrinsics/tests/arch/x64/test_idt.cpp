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
#include <arch/x64/idt.h>

x64::idt_reg::reg_t g_idt_reg;

extern "C" void
_read_idt(void *idt_reg) noexcept
{ *reinterpret_cast<x64::idt_reg::reg_t *>(idt_reg) = g_idt_reg; }

extern "C" void
_write_idt(void *idt_reg) noexcept
{ g_idt_reg = *reinterpret_cast<x64::idt_reg::reg_t *>(idt_reg); }

TEST_CASE("idt_reg_set_get")
{
    x64::idt_reg::set(42, 42);

    CHECK(x64::idt_reg::get().base == 42);
    CHECK(x64::idt_reg::get().limit == 42);
}

TEST_CASE("idt_reg_base_set_get")
{
    x64::idt_reg::base::set(42);
    CHECK(x64::idt_reg::base::get() == 42);
}

TEST_CASE("idt_reg_limit_set_get")
{
    x64::idt_reg::limit::set(42);
    CHECK(x64::idt_reg::limit::get() == 42);
}
