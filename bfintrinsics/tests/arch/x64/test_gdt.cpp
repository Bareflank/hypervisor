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
#include <intrinsics.h>

x64::gdt_reg::reg_t g_gdt_reg;

extern "C" void
_read_gdt(void *gdt_reg) noexcept
{ *reinterpret_cast<x64::gdt_reg::reg_t *>(gdt_reg) = g_gdt_reg; }

extern "C" void
_write_gdt(void *gdt_reg) noexcept
{ g_gdt_reg = *reinterpret_cast<x64::gdt_reg::reg_t *>(gdt_reg); }

TEST_CASE("gdt_reg_set_get")
{
    x64::gdt_reg::set(42, 42);

    CHECK(x64::gdt_reg::get().base == 42);
    CHECK(x64::gdt_reg::get().limit == 42);
}

TEST_CASE("gdt_reg_base_set_get")
{
    x64::gdt_reg::base::set(42);
    CHECK(x64::gdt_reg::base::get() == 42);
}

TEST_CASE("gdt_reg_limit_set_get")
{
    x64::gdt_reg::limit::set(42);
    CHECK(x64::gdt_reg::limit::get() == 42);
}
