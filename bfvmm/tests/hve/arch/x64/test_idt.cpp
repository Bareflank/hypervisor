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

#include <support/arch/intel_x64/test_support.h>

TEST_CASE("idt_constructor_no_size")
{
    setup_idt();
    idt_x64 idt;
}

TEST_CASE("idt_constructor_zero_size")
{
    setup_idt();
    CHECK_NOTHROW(idt_x64{0});
}

TEST_CASE("idt_constructor_size")
{
    setup_idt();

    idt_x64 idt{4};
    CHECK(idt.base() != 0);
    CHECK(idt.limit() == (4 * sizeof(idt_x64::interrupt_descriptor_type)) - 1);
}

TEST_CASE("idt_base")
{
    setup_idt();

    idt_x64 idt;
    CHECK(idt.base() == reinterpret_cast<idt_x64::integer_pointer>(g_idt.data()));
}

TEST_CASE("idt_limit")
{
    setup_idt();

    idt_x64 idt;
    CHECK(idt.limit() == (4 * sizeof(idt_x64::interrupt_descriptor_type)) - 1);
}
