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

/// @cond

#ifdef BF_X64

#include "../hve/arch/x64/gdt.h"
#include "../hve/arch/x64/idt.h"

std::vector<bfvmm::x64::gdt::segment_descriptor_type> g_gdt = {
    0x0,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFF8FFFFFFFFFFF,
    0x00000000FFFFFFFF,
};

std::vector<bfvmm::x64::idt::interrupt_descriptor_type> g_idt = {
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF
};

void
setup_gdt_x64()
{
    auto limit = g_gdt.size() * sizeof(bfvmm::x64::gdt::segment_descriptor_type) - 1;

    g_gdtr.base = reinterpret_cast<uint64_t>(&g_gdt.at(0));
    g_gdtr.limit = gsl::narrow_cast<uint16_t>(limit);
}

void
setup_idt_x64()
{
    auto limit = g_idt.size() * sizeof(bfvmm::x64::idt::interrupt_descriptor_type) - 1;

    g_idtr.base = reinterpret_cast<uint64_t>(&g_idt.at(0));
    g_idtr.limit = gsl::narrow_cast<uint16_t>(limit);
}

#endif

#ifdef BF_INTEL_X64

#include "../hve/arch/intel_x64/vmx.h"
#include "../hve/arch/intel_x64/vmcs.h"
#include "../hve/arch/intel_x64/check.h"
#include "../hve/arch/intel_x64/exit_handler.h"

bfvmm::intel_x64::save_state_t g_save_state{};

extern "C" void vmcs_launch(
    bfvmm::intel_x64::save_state_t *save_state) noexcept
{ bfignored(save_state); }

extern "C" void vmcs_promote(
    bfvmm::intel_x64::save_state_t *save_state, const void *gdt) noexcept
{ bfignored(save_state); bfignored(gdt); }

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept
{ bfignored(save_state); }

extern "C" void exit_handler_entry(void)
{ }

#endif

/// @endcond
