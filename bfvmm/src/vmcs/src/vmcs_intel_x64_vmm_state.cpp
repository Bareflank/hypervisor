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

#include <vmcs/vmcs_intel_x64_vmm_state.h>
#include <memory_manager/memory_manager.h>
#include <memory_manager/page_table_x64.h>

std::shared_ptr<page_table_x64> m_pml4;

vmcs_intel_x64_vmm_state::vmcs_intel_x64_vmm_state(const std::shared_ptr<state_save_intel_x64> &state_save) :
    m_gdt(6),
    m_idt(256)
{
    if (!state_save)
        throw std::invalid_argument("state_save == nullptr");

    m_thread_storage = std::make_unique<uintptr_t[]>(512);
    m_thread_storage[0] = reinterpret_cast<uintptr_t>(m_thread_storage.get());

    uint16_t cs_access_rights = 0;
    uint16_t ss_access_rights = 0;
    uint16_t ds_access_rights = 0;
    uint16_t tr_access_rights = 0;

    cs_access_rights |= SEGMENT_ACCESS_RIGHTS_TYPE_RE;
    cs_access_rights |= SEGMENT_ACCESS_RIGHTS_CODE_DATA_DESCRIPTOR;
    cs_access_rights |= SEGMENT_ACCESS_RIGHTS_PRESENT;
    cs_access_rights |= SEGMENT_ACCESS_RIGHTS_L;
    cs_access_rights |= SEGMENT_ACCESS_RIGHTS_GRANULARITY_PAGES;

    ss_access_rights |= SEGMENT_ACCESS_RIGHTS_TYPE_RW;
    ss_access_rights |= SEGMENT_ACCESS_RIGHTS_CODE_DATA_DESCRIPTOR;
    ss_access_rights |= SEGMENT_ACCESS_RIGHTS_PRESENT;
    ss_access_rights |= SEGMENT_ACCESS_RIGHTS_DB;
    ss_access_rights |= SEGMENT_ACCESS_RIGHTS_GRANULARITY_PAGES;

    ds_access_rights |= SEGMENT_ACCESS_RIGHTS_TYPE_RW;
    ds_access_rights |= SEGMENT_ACCESS_RIGHTS_CODE_DATA_DESCRIPTOR;
    ds_access_rights |= SEGMENT_ACCESS_RIGHTS_PRESENT;
    ds_access_rights |= SEGMENT_ACCESS_RIGHTS_GRANULARITY_PAGES;

    tr_access_rights |= SEGMENT_ACCESS_RIGHTS_TYPE_TSS_AVAILABLE;
    tr_access_rights |= SEGMENT_ACCESS_RIGHTS_PRESENT;

    m_gdt.set_access_rights(0, 0);
    m_gdt.set_access_rights(1, cs_access_rights);
    m_gdt.set_access_rights(2, ss_access_rights);
    m_gdt.set_access_rights(3, ds_access_rights);
    m_gdt.set_access_rights(4, tr_access_rights);

    m_gdt.set_base(0, 0);
    m_gdt.set_base(1, 0);
    m_gdt.set_base(2, 0);
    m_gdt.set_base(3, 0);
    m_gdt.set_base(4, reinterpret_cast<uint64_t>(&m_tss));

    m_gdt.set_limit(0, 0);
    m_gdt.set_limit(1, 0xFFFFFFFF);
    m_gdt.set_limit(2, 0xFFFFFFFF);
    m_gdt.set_limit(3, 0xFFFFFFFF);
    m_gdt.set_limit(4, sizeof(m_tss));

    m_cs_index = 1;
    m_ss_index = 2;
    m_fs_index = 3;
    m_gs_index = 3;
    m_tr_index = 4;

    m_cs = static_cast<uint16_t>(m_cs_index << 3);
    m_ss = static_cast<uint16_t>(m_ss_index << 3);
    m_fs = static_cast<uint16_t>(m_fs_index << 3);
    m_gs = static_cast<uint16_t>(m_gs_index << 3);
    m_tr = static_cast<uint16_t>(m_tr_index << 3);

    // TODO: We need to guard the additions to the page tables here. Just
    // in case more than one core attempts to change these at the same time.

    if (!m_pml4)
    {
        m_pml4 = std::make_shared<page_table_x64>();

        for (const auto &md : g_mm->virt_to_phys_map())
        {
            auto entry = m_pml4->add_page(md.second.virt);

            entry->set_phys_addr(md.second.phys);
            entry->set_present(true);

            if ((md.second.type & MEMORY_TYPE_W) != 0)
                entry->set_rw(true);
            else
                entry->set_rw(false);

            if ((md.second.type & MEMORY_TYPE_E) != 0)
                entry->set_nx(false);
            else
                entry->set_nx(true);
        }
    }

    m_cr0 = 0;
    m_cr0 |= CRO_PE_PROTECTION_ENABLE;
    m_cr0 |= CR0_MP_MONITOR_COPROCESSOR;
    m_cr0 |= CR0_NE_NUMERIC_ERROR;
    m_cr0 |= CR0_PG_PAGING;

    m_cr3 = m_pml4->phys_addr();

    m_cr4 = 0;
    m_cr4 |= CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS;
    m_cr4 |= CR4_VMXE_VMX_ENABLE_BIT;
    m_cr4 |= CR4_OSXSAVE;

    m_rflags = 0;

    m_ia32_pat_msr = 0;
    m_ia32_efer_msr = IA32_EFER_LME | IA32_EFER_LMA | IA32_EFER_NXE;
    m_ia32_fs_base_msr = reinterpret_cast<uintptr_t>(m_thread_storage.get());
    m_ia32_gs_base_msr = reinterpret_cast<uintptr_t>(state_save.get());
}
