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

#include <arch/intel_x64/vmcs/32bit_control_fields.h>
#include <arch/intel_x64/vmcs/32bit_guest_state_fields.h>
#include <hve/arch/intel_x64/nmi.h>

void set_nmi_handler(
    bfvmm::x64::idt *idt,
    bfvmm::x64::idt::selector_type selector) noexcept
{ idt->set(2, _handle_nmi, selector); }

void inject_nmi() noexcept
{
    namespace int_info = ::intel_x64::vmcs::vm_entry_interruption_information;
    uint64_t info = 0;

    int_info::vector::set(info, 2);
    int_info::interruption_type::set(info, int_info::interruption_type::non_maskable_interrupt);
    int_info::valid_bit::enable(info);
    int_info::set(info);
}
