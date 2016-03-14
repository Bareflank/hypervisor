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

#include <iomanip>
#include <iostream>

#include <vmcs/vmcs_intel_x64.h>

bool
vmcs_intel_x64::check_vmcs_host_state()
{
    auto result = true;

    result &= check_host_control_registers_and_msrs();
    result &= check_host_segment_and_descriptor_table_registers();
    result &= check_host_checks_related_to_address_space_size();

    return result;
}

bool
vmcs_intel_x64::check_host_control_registers_and_msrs()
{
    auto result = true;

    result &= check_host_cr0_for_unsupported_bits();
    result &= check_host_cr4_for_unsupported_bits();
    result &= check_host_cr3_for_unsupported_bits();
    result &= check_host_ia32_sysenter_esp_canonical_address();
    result &= check_host_ia32_sysenter_eip_canonical_address();
    result &= check_host_ia32_perf_global_ctrl_for_reserved_bits();
    result &= check_host_ia32_pat_for_unsupported_bits();
    result &= check_host_verify_load_ia32_efer_enabled();
    result &= check_host_ia32_efer_for_reserved_bits();
    result &= check_host_ia32_efer_set();

    return result;
}

bool
vmcs_intel_x64::check_host_cr0_for_unsupported_bits()
{
    auto cr0 = vmread(VMCS_HOST_CR0);
    auto ia32_vmx_cr0_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED0_MSR);
    auto ia32_vmx_cr0_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED1_MSR);

    if (0 != ((~cr0 & ia32_vmx_cr0_fixed0) | (cr0 & ~ia32_vmx_cr0_fixed1)))
    {
        std::cout << "check_host_cr0_for_unsupported_bits failed. "
                  << "host cr0 incorrectly setup: " << std::endl
                  << std::hex
                  << "    - cr0: 0x" << cr0 << " " << std::endl
                  << "    - ia32_vmx_cr0_fixed0: 0x" << ia32_vmx_cr0_fixed0 << std::endl
                  << "    - ia32_vmx_cr0_fixed1: 0x" << ia32_vmx_cr0_fixed1 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_cr4_for_unsupported_bits()
{
    auto cr4 = vmread(VMCS_HOST_CR4);
    auto ia32_vmx_cr4_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED0_MSR);
    auto ia32_vmx_cr4_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED1_MSR);

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1)))
    {
        std::cout << "check_host_cr4_for_unsupported_bits failed. "
                  << "host cr4 incorrectly setup: " << std::endl
                  << std::hex
                  << "    - cr4: 0x" << cr4 << " " << std::endl
                  << "    - ia32_vmx_cr4_fixed0: 0x" << ia32_vmx_cr4_fixed0 << std::endl
                  << "    - ia32_vmx_cr4_fixed1: 0x" << ia32_vmx_cr4_fixed1 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_cr3_for_unsupported_bits()
{
    auto cr3 = vmread(VMCS_HOST_CR3);

    // The manual states that CPUID will return the total number of bits that
    // are supported, which at the moment is 42, and is unlikely to change for
    // a while (256 terabytes). If this code triggers a failure do to being
    // hardcoded, cpuid(0x80000008) -> eax[7:0] will return the number of
    // bits that are supported on the system.

    if ((cr3 & ~0x3FFFFFFFFFF) != 0)
    {
        std::cout << "check_host_cr3_for_unsupported_bits failed. "
                  << "host cr3 has an unsupported address width: " << std::endl
                  << std::hex
                  << "    - cr3: 0x" << cr3 << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_ia32_sysenter_esp_canonical_address()
{
    auto esp = vmread(VMCS_HOST_IA32_SYSENTER_EIP);

    if (check_is_address_canonical(esp) == false)
    {
        std::cout << "check_host_ia32_sysenter_esp_canonical_address failed. "
                  << "host ia32_sysenter_esp has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - ia32_sysenter_esp: 0x" << esp << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_ia32_sysenter_eip_canonical_address()
{
    auto eip = vmread(VMCS_HOST_IA32_SYSENTER_EIP);

    if (check_is_address_canonical(eip) == false)
    {
        std::cout << "check_host_ia32_sysenter_eip_canonical_address failed. "
                  << "host ia32_sysenter_eip has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - ia32_sysenter_eip: 0x" << eip << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_ia32_perf_global_ctrl_for_reserved_bits()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    if ((controls & VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_host_ia32_perf_global_ctrl_for_reserved_bits"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_ia32_pat_for_unsupported_bits()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    if ((controls & VM_EXIT_CONTROL_LOAD_IA32_PAT) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_host_ia32_pat_for_unsupported_bits"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_verify_load_ia32_efer_enabled()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    if ((controls & VM_ENTRY_CONTROL_LOAD_IA32_EFER) == 0)
    {
        std::cout << "check_host_verify_load_ia32_efer_enabled: "
                  << "only 64bit hosts are supported. load_ia32_efer must be enabled"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_ia32_efer_for_reserved_bits()
{
    auto vmcs_host_ia32_efer_full = vmread(VMCS_HOST_IA32_EFER_FULL);

    if ((vmcs_host_ia32_efer_full & 0xFFFFFFFFFFFFF2FE) != 0)
    {
        std::cout << "check_host_ia32_efer_for_reserved_bits failed: "
                  << "the reserved bits in is32_efer must be zero"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_ia32_efer_set()
{
    auto vmcs_host_ia32_efer_full = vmread(VMCS_HOST_IA32_EFER_FULL);

    if ((vmcs_host_ia32_efer_full & 0x0000000000000500) != 0x0000000000000500)
    {
        std::cout << "check_host_ia32_efer_set failed. "
                  << "host ia32_efer msr does not have LME and LMA set: " << std::endl
                  << std::hex
                  << "    - ia32_efer: 0x" << vmcs_host_ia32_efer_full << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}


// -----------------------------------------------------------------------------
// Host Segment and Descriptor-Table Register Checks
// -----------------------------------------------------------------------------

bool
vmcs_intel_x64::check_host_segment_and_descriptor_table_registers()
{
    auto result = true;

    result &= check_host_es_selector_rpl_ti_equal_zero();
    result &= check_host_cs_selector_rpl_ti_equal_zero();
    result &= check_host_ss_selector_rpl_ti_equal_zero();
    result &= check_host_ds_selector_rpl_ti_equal_zero();
    result &= check_host_fs_selector_rpl_ti_equal_zero();
    result &= check_host_gs_selector_rpl_ti_equal_zero();
    result &= check_host_tr_selector_rpl_ti_equal_zero();
    result &= check_host_cs_not_equal_zero();
    result &= check_host_tr_not_equal_zero();
    result &= check_host_ss_not_equal_zero();
    result &= check_host_fs_canonical_base_address();
    result &= check_host_gs_canonical_base_address();
    result &= check_host_gdtr_canonical_base_address();
    result &= check_host_idtr_canonical_base_address();
    result &= check_host_tr_canonical_base_address();

    return result;
}

bool
vmcs_intel_x64::check_host_es_selector_rpl_ti_equal_zero()
{
    auto es = vmread(VMCS_HOST_ES_SELECTOR);

    if ((es & 0x0003) != 0)
    {
        std::cout << "check_host_es_selector_rpl_ti_equal_zero failed. "
                  << "RPL or TI not equal to 0: " << std::endl
                  << std::hex
                  << "    - es: 0x" << es << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_cs_selector_rpl_ti_equal_zero()
{
    auto cs = vmread(VMCS_HOST_CS_SELECTOR);

    if ((cs & 0x0003) != 0)
    {
        std::cout << "check_host_cs_selector_rpl_ti_equal_zero failed. "
                  << "RPL or TI not equal to 0: " << std::endl
                  << std::hex
                  << "    - cs: 0x" << cs << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_ss_selector_rpl_ti_equal_zero()
{
    auto ss = vmread(VMCS_HOST_SS_SELECTOR);

    if ((ss & 0x0003) != 0)
    {
        std::cout << "check_host_ss_selector_rpl_ti_equal_zero failed. "
                  << "RPL or TI not equal to 0: " << std::endl
                  << std::hex
                  << "    - ss: 0x" << ss << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_ds_selector_rpl_ti_equal_zero()
{
    auto ds = vmread(VMCS_HOST_DS_SELECTOR);

    if ((ds & 0x0003) != 0)
    {
        std::cout << "check_host_ds_selector_rpl_ti_equal_zero failed. "
                  << "RPL or TI not equal to 0: " << std::endl
                  << std::hex
                  << "    - ds: 0x" << ds << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_fs_selector_rpl_ti_equal_zero()
{
    auto fs = vmread(VMCS_HOST_FS_SELECTOR);

    if ((fs & 0x0003) != 0)
    {
        std::cout << "check_host_fs_selector_rpl_ti_equal_zero failed. "
                  << "RPL or TI not equal to 0: " << std::endl
                  << std::hex
                  << "    - fs: 0x" << fs << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_gs_selector_rpl_ti_equal_zero()
{
    auto gs = vmread(VMCS_HOST_GS_SELECTOR);

    if ((gs & 0x0003) != 0)
    {
        std::cout << "check_host_gs_selector_rpl_ti_equal_zero failed. "
                  << "RPL or TI not equal to 0: " << std::endl
                  << std::hex
                  << "    - gs: 0x" << gs << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_tr_selector_rpl_ti_equal_zero()
{
    auto tr = vmread(VMCS_HOST_TR_SELECTOR);

    if ((tr & 0x0003) != 0)
    {
        std::cout << "check_host_tr_selector_rpl_ti_equal_zero failed. "
                  << "RPL or TI not equal to 0: " << std::endl
                  << std::hex
                  << "    - tr: 0x" << tr << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_cs_not_equal_zero()
{
    auto cs = vmread(VMCS_HOST_CS_SELECTOR);

    if (cs == 0x0000)
    {
        std::cout << "check_host_cs_not_equal_zero failed. "
                  << "cs select equal to zero: " << std::endl
                  << std::hex
                  << "    - cs: 0x" << cs << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_tr_not_equal_zero()
{
    auto tr = vmread(VMCS_HOST_TR_SELECTOR);

    if (tr == 0x0000)
    {
        std::cout << "check_host_tr_not_equal_zero failed. "
                  << "tr select equal to zero: " << std::endl
                  << std::hex
                  << "    - tr: 0x" << tr << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_ss_not_equal_zero()
{
    auto ss = vmread(VMCS_HOST_SS_SELECTOR);
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    if ((controls & VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE) != 0)
        return true;

    if (ss == 0x0000)
    {
        std::cout << "check_host_ss_not_equal_zero failed. "
                  << "ss select equal to zero: " << std::endl
                  << std::hex
                  << "    - ss: 0x" << ss << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_fs_canonical_base_address()
{
    auto fs_base = vmread(VMCS_HOST_FS_BASE);

    if (check_is_address_canonical(fs_base) == false)
    {
        std::cout << "check_host_fs_canonical_base_address failed. "
                  << "host fs base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - fs base: 0x" << fs_base << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_gs_canonical_base_address()
{
    auto gs_base = vmread(VMCS_HOST_GS_BASE);

    if (check_is_address_canonical(gs_base) == false)
    {
        std::cout << "check_host_gs_canonical_base_address failed. "
                  << "host gs base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - gs base: 0x" << gs_base << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_gdtr_canonical_base_address()
{
    auto gdtr_base = vmread(VMCS_HOST_GDTR_BASE);

    if (check_is_address_canonical(gdtr_base) == false)
    {
        std::cout << "check_host_gdtr_canonical_base_address failed. "
                  << "host gdtr base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - gdtr base: 0x" << gdtr_base << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_idtr_canonical_base_address()
{
    auto idtr_base = vmread(VMCS_HOST_IDTR_BASE);

    if (check_is_address_canonical(idtr_base) == false)
    {
        std::cout << "check_host_idtr_canonical_base_address failed. "
                  << "host idtr base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - idtr base: 0x" << idtr_base << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_tr_canonical_base_address()
{
    auto tr_base = vmread(VMCS_HOST_FS_BASE);

    if (check_is_address_canonical(tr_base) == false)
    {
        std::cout << "check_host_tr_canonical_base_address failed. "
                  << "host tr base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - tr base: 0x" << tr_base << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_checks_related_to_address_space_size()
{
    auto result = true;

    result &= check_host_if_outside_ia32e_mode();
    result &= check_host_vmcs_host_address_space_size_is_set();
    result &= check_host_verify_pae_is_enabled();
    result &= check_host_verify_rip_has_canonical_address();

    return result;
}

bool
vmcs_intel_x64::check_host_if_outside_ia32e_mode()
{
    auto ia32_efer_msr = m_intrinsics->read_msr(IA32_EFER_MSR);

    if ((ia32_efer_msr & 0x0000000000000500) != 0x0000000000000500)
    {
        std::cout << "check_host_if_outside_ia32e_mode failed. "
                  << "attempted to use bareflank with an unsupported OS. bareflank only supports 64bit: " << std::endl
                  << std::hex
                  << "    - ia32_efer: 0x" << ia32_efer_msr << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_vmcs_host_address_space_size_is_set()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    if ((controls & VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE) == 0)
    {
        std::cout << "check_host_vmcs_host_address_space_size_is_set failed. "
                  << "in 64bit, the host address space size exit control must be enabled: " << std::endl
                  << std::hex
                  << "    - vm-exit controls: 0x" << controls << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_verify_pae_is_enabled()
{
    auto cr4 = vmread(VMCS_HOST_CR4);

    if ((cr4 & CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS) == 0)
    {
        std::cout << "check_host_verify_pae_is_enabled failed. "
                  << "in 64bit mode, PAE must be turned on: " << std::endl
                  << std::hex
                  << "    - cr4: 0x" << cr4 << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_host_verify_rip_has_canonical_address()
{
    auto rip = vmread(VMCS_HOST_RIP);

    if (check_is_address_canonical(rip) == false)
    {
        std::cout << "check_host_verify_rip_has_canonical_address failed. "
                  << "host idtr base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - rip: 0x" << rip << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}
