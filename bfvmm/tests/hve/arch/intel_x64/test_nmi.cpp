//
// Bareflank Hypervisor
//
// Copyright (C) 2018 Assured Information Security, Inc.
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

#include <hippomocks.h>
#include <catch/catch.hpp>
#include <hve/arch/x64/idt.h>
#include <hve/arch/intel_x64/nmi.h>
#include <arch/intel_x64/vmcs/32bit_control_fields.h>
#include <test/support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("set_nmi_handler")
{
    bfvmm::x64::idt idt{256};
    CHECK_NOTHROW(set_nmi_handler(&idt, 8));
}

TEST_CASE("inject_nmi")
{
    namespace int_info = ::intel_x64::vmcs::vm_entry_interruption_information;

    int_info::set(0);
    CHECK_NOTHROW(inject_nmi());

    CHECK(int_info::vector::get() == 2);
    CHECK(int_info::interruption_type::get() == int_info::interruption_type::non_maskable_interrupt);
    CHECK(int_info::valid_bit::is_enabled());
}

#endif
