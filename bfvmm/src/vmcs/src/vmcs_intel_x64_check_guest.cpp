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
vmcs_intel_x64::check_guest_checks_on_guest_control_registers_debug_registers_and_msrs()
{
    auto result = true;

    result &= check_guest_cr0_for_unsupported_bits();
    result &= check_guest_cr0_verify_paging_enabled();
    result &= check_guest_cr0_verify_protected_mode_enabled();
    result &= check_guest_cr4_for_unsupported_bits();
    result &= check_guest_load_debug_controls_verify_reserved_bits_equal_zero();
    result &= check_guest_verify_ia_32e_mode_enabled();
    result &= check_guest_cr4_verify_pae_enabled();
    result &= check_guest_cr3_for_unsupported_bits();
    result &= check_guest_load_debug_controls_verify_verify_dr7();
    result &= check_guest_ia32_sysenter_esp_canonical_address();
    result &= check_guest_ia32_sysenter_eip_canonical_address();
    result &= check_guest_ia32_perf_global_ctrl_for_reserved_bits();
    result &= check_guest_ia32_pat_for_unsupported_bits();
    result &= check_guest_verify_load_ia32_efer_enabled();
    result &= check_guest_ia32_efer_for_reserved_bits();
    result &= check_guest_ia32_efer_set();

    return result;
}

bool
vmcs_intel_x64::check_guest_cr0_for_unsupported_bits()
{
    auto cr0 = vmread(VMCS_GUEST_CR0);
    auto ia32_vmx_cr0_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED0_MSR);
    auto ia32_vmx_cr0_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED1_MSR);

    if (0 != ((~cr0 & ia32_vmx_cr0_fixed0) | (cr0 & ~ia32_vmx_cr0_fixed1)))
    {
        std::cout << "check_guest_cr0_for_unsupported_bits failed. "
                  << "guest cr0 incorrectly setup: " << std::endl
                  << std::hex
                  << "    - cr0: 0x" << cr0 << std::endl
                  << "    - ia32_vmx_cr0_fixed0: 0x" << ia32_vmx_cr0_fixed0 << std::endl
                  << "    - ia32_vmx_cr0_fixed1: 0x" << ia32_vmx_cr0_fixed1 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cr0_verify_paging_enabled()
{
    auto cr0 = vmread(VMCS_GUEST_CR0);

    if ((cr0 & CR0_PG_PAGING) == 0)
    {
        std::cout << "check_guest_cr0_verify_paging_enabled failed. "
                  << "guest cr0 does not have paging enabled: " << std::endl
                  << std::hex
                  << "    - cr0: 0x" << cr0 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cr0_verify_protected_mode_enabled()
{
    auto cr0 = vmread(VMCS_GUEST_CR0);

    if ((cr0 & CRO_PE_PROTECTION_ENABLE) == 0)
    {
        std::cout << "check_guest_cr0_verify_protected_mode_enabled failed. "
                  << "guest cr0 does not have protected mode enabled: " << std::endl
                  << std::hex
                  << "    - cr0: 0x" << cr0 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cr4_for_unsupported_bits()
{
    auto cr4 = vmread(VMCS_GUEST_CR4);
    auto ia32_vmx_cr4_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED0_MSR);
    auto ia32_vmx_cr4_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED1_MSR);

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1)))
    {
        std::cout << "check_guest_cr4_for_unsupported_bits failed. "
                  << "guest cr4 incorrectly setup: " << std::endl
                  << std::hex
                  << "    - cr4: 0x" << cr4 << std::endl
                  << "    - ia32_vmx_cr4_fixed0: 0x" << ia32_vmx_cr4_fixed0 << std::endl
                  << "    - ia32_vmx_cr4_fixed1: 0x" << ia32_vmx_cr4_fixed1 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_load_debug_controls_verify_reserved_bits_equal_zero()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    if ((controls & VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_load_debug_controls_verify_reserved_bits_equal_zero"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_verify_ia_32e_mode_enabled()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    if ((controls & VM_ENTRY_CONTROL_IA_32E_MODE_GUEST) == 0)
    {
        std::cout << "check_guest_verify_ia_32e_mode_enabled failed: "
                  << "only 64bit guests are supported. ia_32e mode not enabled"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cr4_verify_pae_enabled()
{
    auto cr4 = vmread(VMCS_GUEST_CR4);

    if ((cr4 & CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS) == 0)
    {
        std::cout << "check_guest_cr4_verify_pae_enabled failed. "
                  << "guest cr4 does not have pae enabled: " << std::endl
                  << std::hex
                  << "    - cr4: 0x" << cr4 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cr3_for_unsupported_bits()
{
    auto cr3 = vmread(VMCS_GUEST_CR3);

    // The manual states that CPUID will return the total number of bits that
    // are supported, which at the moment is 42, and is unlikely to change for
    // a while (256 terabytes). If this code triggers a failure do to being
    // hardcoded, cpuid(0x80000008) -> eax[7:0] will return the number of
    // bits that are supported on the system.

    if ((cr3 & ~0x3FFFFFFFFFF) != 0)
    {
        std::cout << "check_guest_cr3_for_unsupported_bits failed. "
                  << "guest cr3 has an unsupported address width: " << std::endl
                  << std::hex
                  << "    - cr3: 0x" << cr3 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_load_debug_controls_verify_verify_dr7()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    if ((controls & VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_load_debug_controls_verify_verify_dr7"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_sysenter_esp_canonical_address()
{
    auto esp = vmread(VMCS_GUEST_IA32_SYSENTER_EIP);

    if (check_is_address_canonical(esp) == false)
    {
        std::cout << "check_guest_ia32_sysenter_esp_canonical_address failed. "
                  << "guest ia32_sysenter_esp has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - ia32_sysenter_esp: 0x" << esp << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_sysenter_eip_canonical_address()
{
    auto eip = vmread(VMCS_GUEST_IA32_SYSENTER_EIP);

    if (check_is_address_canonical(eip) == false)
    {
        std::cout << "check_guest_ia32_sysenter_eip_canonical_address failed. "
                  << "guest ia32_sysenter_eip has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - ia32_sysenter_eip: 0x" << eip << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_perf_global_ctrl_for_reserved_bits()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    if ((controls & VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_ia32_perf_global_ctrl_for_reserved_bits"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_pat_for_unsupported_bits()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    if ((controls & VM_EXIT_CONTROL_LOAD_IA32_PAT) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_ia32_pat_for_unsupported_bits"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_verify_load_ia32_efer_enabled()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    if ((controls & VM_ENTRY_CONTROL_LOAD_IA32_EFER) == 0)
    {
        std::cout << "check_guest_verify_load_ia32_efer_enabled: "
                  << "only 64bit guests are supported. load_ia32_efer must be enabled"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_efer_for_reserved_bits()
{
    auto vmcs_guest_ia32_efer_full = vmread(VMCS_GUEST_IA32_EFER_FULL);

    if ((vmcs_guest_ia32_efer_full & 0xFFFFFFFFFFFFF2FE) != 0)
    {
        std::cout << "check_guest_ia32_efer_for_reserved_bits failed: "
                  << "the reserved bits in is32_efer must be zero"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_efer_set()
{
    auto vmcs_guest_ia32_efer_full = vmread(VMCS_GUEST_IA32_EFER_FULL);

    if ((vmcs_guest_ia32_efer_full & 0x0000000000000500) != 0x0000000000000500)
    {
        std::cout << "check_guest_ia32_efer_set failed. "
                  << "guest ia32_efer msr does not have LME and LMA set: " << std::endl
                  << std::hex
                  << "    - ia32_efer: 0x" << vmcs_guest_ia32_efer_full << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_checks_on_guest_segment_registers()
{
    auto result = true;

    result &= check_guest_v8086_mode_disabled();
    result &= check_guest_unrestricted_guest_disabled();
    result &= check_guest_tr_ti_bit_equals_0();
    result &= check_guest_ldtr_ti_bit_equals_0();
    result &= check_guest_ss_and_cs_rpl_are_the_same();
    result &= check_guest_tr_base_is_canonical();
    result &= check_guest_fs_base_is_canonical();
    result &= check_guest_gs_base_is_canonical();
    result &= check_guest_ldtr_base_is_canonical();
    result &= check_guest_cs_base_upper_dword_0();
    result &= check_guest_ss_base_upper_dword_0();
    result &= check_guest_ds_base_upper_dword_0();
    result &= check_guest_es_base_upper_dword_0();
    result &= check_guest_cs_access_rights_type();
    result &= check_guest_ss_access_rights_type();
    result &= check_guest_ds_access_rights_type();
    result &= check_guest_es_access_rights_type();
    result &= check_guest_fs_access_rights_type();
    result &= check_guest_gs_access_rights_type();
    result &= check_guest_cs_is_not_a_system_descriptor();
    result &= check_guest_ss_is_not_a_system_descriptor();
    result &= check_guest_ds_is_not_a_system_descriptor();
    result &= check_guest_es_is_not_a_system_descriptor();
    result &= check_guest_fs_is_not_a_system_descriptor();
    result &= check_guest_gs_is_not_a_system_descriptor();
    result &= check_guest_cs_type_not_equal_3();
    result &= check_guest_cs_dpl_adheres_to_ss_dpl();
    result &= check_guest_ss_dpl_must_equal_rpl();
    result &= check_guest_ss_dpl_must_equal_zero();
    result &= check_guest_ds_dpl();
    result &= check_guest_es_dpl();
    result &= check_guest_fs_dpl();
    result &= check_guest_gs_dpl();
    result &= check_guest_cs_must_be_present();
    result &= check_guest_ss_must_be_present_if_usable();
    result &= check_guest_ds_must_be_present_if_usable();
    result &= check_guest_es_must_be_present_if_usable();
    result &= check_guest_fs_must_be_present_if_usable();
    result &= check_guest_gs_must_be_present_if_usable();
    result &= check_guest_cs_access_rights_reserved_must_be_0();
    result &= check_guest_ss_access_rights_reserved_must_be_0();
    result &= check_guest_ds_access_rights_reserved_must_be_0();
    result &= check_guest_es_access_rights_reserved_must_be_0();
    result &= check_guest_fs_access_rights_reserved_must_be_0();
    result &= check_guest_gs_access_rights_reserved_must_be_0();
    result &= check_guest_cs_db_must_be_0_if_l_equals_1();
    result &= check_guest_cs_granularity();
    result &= check_guest_ss_granularity();
    result &= check_guest_ds_granularity();
    result &= check_guest_es_granularity();
    result &= check_guest_fs_granularity();
    result &= check_guest_gs_granularity();
    result &= check_guest_cs_access_rights_remaining_reserved_bit_0();
    result &= check_guest_ss_access_rights_remaining_reserved_bit_0();
    result &= check_guest_ds_access_rights_remaining_reserved_bit_0();
    result &= check_guest_es_access_rights_remaining_reserved_bit_0();
    result &= check_guest_fs_access_rights_remaining_reserved_bit_0();
    result &= check_guest_gs_access_rights_remaining_reserved_bit_0();
    result &= check_guest_tr_type_must_be_11();
    result &= check_guest_tr_must_be_a_system_descriptor();
    result &= check_guest_tr_must_be_present();
    result &= check_guest_tr_access_rights_reserved_must_be_0();
    result &= check_guest_tr_granularity();
    result &= check_guest_tr_must_be_usable();
    result &= check_guest_tr_access_rights_remaining_reserved_bit_0();
    result &= check_guest_ldtr_type_must_be_2();
    result &= check_guest_ldtr_must_be_a_system_descriptor();
    result &= check_guest_ldtr_must_be_present();
    result &= check_guest_ldtr_access_rights_reserved_must_be_0();
    result &= check_guest_ldtr_granularity();
    result &= check_guest_ldtr_access_rights_remaining_reserved_bit_0();

    return result;
}

bool
vmcs_intel_x64::check_guest_v8086_mode_disabled()
{
    auto rflags = vmread(VMCS_GUEST_RFLAGS);

    if ((rflags & RFLAGS_VM_VIRTUAL_8086_MODE) != 0)
    {
        std::cout << "check_guest_v8086_mode_disabled failed. "
                  << "guests in v8086 mode are not supported: " << std::endl
                  << std::hex
                  << "    - rflags: 0x" << rflags << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_unrestricted_guest_disabled()
{
    auto controls = vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

    if ((controls & VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST) != 0)
    {
        std::cout << "check_guest_unrestricted_guest_disabled: "
                  << "only 64bit guests are supported. unrestricted guests are not supported"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_tr_ti_bit_equals_0()
{
    auto tr = vmread(VMCS_GUEST_TR_SELECTOR);

    if ((tr & SELECTOR_TI_FLAG) != 0)
    {
        std::cout << "check_guest_tr_ti_bit_equals_0 failed. "
                  << "tr's ti flag is not equal to zero: " << std::endl
                  << std::hex
                  << "    - tr: 0x" << tr << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ldtr_ti_bit_equals_0()
{
    auto ldtr = vmread(VMCS_GUEST_LDTR_SELECTOR);
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if ((ldtr_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ldtr & SELECTOR_TI_FLAG) != 0)
    {
        std::cout << "check_guest_ldtr_ti_bit_equals_0 failed. "
                  << "ldtr is usable, and the ti flag is not equal to zero: " << std::endl
                  << std::hex
                  << "    - ldtr: 0x" << ldtr << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ss_and_cs_rpl_are_the_same()
{
    auto ss = vmread(VMCS_GUEST_SS_SELECTOR);
    auto cs = vmread(VMCS_GUEST_CS_SELECTOR);

    if ((ss & SELECTOR_RPL_FLAG) != (cs & SELECTOR_RPL_FLAG))
    {
        std::cout << "check_guest_ss_and_cs_rpl_are_the_same failed. "
                  << "ss and cs requested privilage level (rpl) must be the same: " << std::endl
                  << std::hex
                  << "    - ss: 0x" << ss << std::endl
                  << "    - cs: 0x" << cs << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_tr_base_is_canonical()
{
    auto tr_base = vmread(VMCS_GUEST_TR_BASE);

    if (check_is_address_canonical(tr_base) == false)
    {
        std::cout << "check_guest_tr_base_is_canonical failed. "
                  << "guest tr base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - tr_base: 0x" << tr_base << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_fs_base_is_canonical()
{
    auto fs_base = vmread(VMCS_GUEST_FS_BASE);
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if ((fs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if (check_is_address_canonical(fs_base) == false)
    {
        std::cout << "check_guest_fs_base_is_canonical failed. "
                  << "guest fs base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - fs_base: 0x" << fs_base << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_gs_base_is_canonical()
{
    auto gs_base = vmread(VMCS_GUEST_GS_BASE);
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if ((gs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if (check_is_address_canonical(gs_base) == false)
    {
        std::cout << "check_guest_gs_base_is_canonical failed. "
                  << "guest gs base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - gs_base: 0x" << gs_base << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ldtr_base_is_canonical()
{
    auto ldtr_base = vmread(VMCS_GUEST_LDTR_BASE);
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if ((ldtr_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if (check_is_address_canonical(ldtr_base) == false)
    {
        std::cout << "check_guest_ldtr_base_is_canonical failed. "
                  << "guest ldtr base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - ldtr_base: 0x" << ldtr_base << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cs_base_upper_dword_0()
{
    auto cs_base = vmread(VMCS_GUEST_CS_BASE);

    if ((cs_base & 0xFFFFFFFF00000000) != 0)
    {
        std::cout << "check_guest_cs_base_upper_dword_0 failed. "
                  << "guest cs base bits 63:32 must be 0: " << std::endl
                  << std::hex
                  << "    - cs_base: 0x" << cs_base << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ss_base_upper_dword_0()
{
    auto ss_base = vmread(VMCS_GUEST_SS_BASE);
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if ((ss_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ss_base & 0xFFFFFFFF00000000) != 0)
    {
        std::cout << "check_guest_ss_base_upper_dword_0 failed. "
                  << "guest ss base bits 63:32 must be 0: " << std::endl
                  << std::hex
                  << "    - ss_base: 0x" << ss_base << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ds_base_upper_dword_0()
{
    auto ds_base = vmread(VMCS_GUEST_DS_BASE);
    auto ds_acceds = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if ((ds_acceds & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ds_base & 0xFFFFFFFF00000000) != 0)
    {
        std::cout << "check_guest_ds_base_upper_dword_0 failed. "
                  << "guest ds base bits 63:32 must be 0: " << std::endl
                  << std::hex
                  << "    - ds_base: 0x" << ds_base << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_es_base_upper_dword_0()
{
    auto es_base = vmread(VMCS_GUEST_ES_BASE);
    auto es_accees = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if ((es_accees & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((es_base & 0xFFFFFFFF00000000) != 0)
    {
        std::cout << "check_guest_es_base_upper_dword_0 failed. "
                  << "guest es base bits 63:32 must be 0: " << std::endl
                  << std::hex
                  << "    - es_base: 0x" << es_base << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cs_access_rights_type()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    switch (cs_access & 0x000F)
    {
        case 9:
        case 11:
        case 13:
        case 15:
            break;

        default:

            std::cout << "check_guest_cs_access_right_type failed. "
                      << "guest cs type must be 9, 11, 13 or 15: " << std::endl
                      << std::hex
                      << "    - cs_access: 0x" << cs_access << std::endl
                      << std::dec;

            return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ss_access_rights_type()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if ((ss_access & SELECTOR_UNUSABLE) != 0)
        return true;

    switch (ss_access & 0x000F)
    {
        case 3:
        case 7:
            break;

        default:

            std::cout << "check_guest_ss_access_right_type failed. "
                      << "guest ss type must be 3 or 7: " << std::endl
                      << std::hex
                      << "    - ss_access: 0x" << ss_access << std::endl
                      << std::dec;

            return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ds_access_rights_type()
{
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if ((ds_access & SELECTOR_UNUSABLE) != 0)
        return true;

    switch (ds_access & 0x000F)
    {
        case 1:
        case 3:
        case 5:
        case 7:
        case 11:
        case 15:
            break;

        default:

            std::cout << "check_guest_ds_access_right_type failed. "
                      << "guest ds type must be 1, 3, 5, 7, 11 or 15: " << std::endl
                      << std::hex
                      << "    - ds_access: 0x" << ds_access << std::endl
                      << std::dec;

            return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_es_access_rights_type()
{
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if ((es_access & SELECTOR_UNUSABLE) != 0)
        return true;

    switch (es_access & 0x000F)
    {
        case 1:
        case 3:
        case 5:
        case 7:
        case 11:
        case 15:
            break;

        default:

            std::cout << "check_guest_es_access_right_type failed. "
                      << "guest es type must be 1, 3, 5, 7, 11 or 15: " << std::endl
                      << std::hex
                      << "    - es_access: 0x" << es_access << std::endl
                      << std::dec;

            return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_fs_access_rights_type()
{
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if ((fs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    switch (fs_access & 0x000F)
    {
        case 1:
        case 3:
        case 5:
        case 7:
        case 11:
        case 15:
            break;

        default:

            std::cout << "check_guest_fs_access_right_type failed. "
                      << "guest fs type must be 1, 3, 5, 7, 11 or 15: " << std::endl
                      << std::hex
                      << "    - fs_access: 0x" << fs_access << std::endl
                      << std::dec;

            return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_gs_access_rights_type()
{
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if ((gs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    switch (gs_access & 0x000F)
    {
        case 1:
        case 3:
        case 5:
        case 7:
        case 11:
        case 15:
            break;

        default:

            std::cout << "check_guest_gs_access_right_type failed. "
                      << "guest gs type must be 1, 3, 5, 7, 11 or 15: " << std::endl
                      << std::hex
                      << "    - gs_access: 0x" << gs_access << std::endl
                      << std::dec;

            return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cs_is_not_a_system_descriptor()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & 0x0010) == 0)
    {
        std::cout << "check_guest_cs_is_not_a_system_descriptor failed. "
                  << "cs must be a code / data descriptor. S should equal 1: " << std::endl
                  << std::hex
                  << "    - cs_access: 0x" << cs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ss_is_not_a_system_descriptor()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if ((ss_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ss_access & 0x0010) == 0)
    {
        std::cout << "check_guest_ss_is_not_a_system_descriptor failed. "
                  << "ss must be a code / data descriptor. S should equal 1: " << std::endl
                  << std::hex
                  << "    - ss_access: 0x" << ss_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ds_is_not_a_system_descriptor()
{
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if ((ds_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ds_access & 0x0010) == 0)
    {
        std::cout << "check_guest_ds_is_not_a_system_descriptor failed. "
                  << "ds must be a code / data descriptor. S should equal 1: " << std::endl
                  << std::hex
                  << "    - ds_access: 0x" << ds_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_es_is_not_a_system_descriptor()
{
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if ((es_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((es_access & 0x0010) == 0)
    {
        std::cout << "check_guest_es_is_not_a_system_descriptor failed. "
                  << "es must be a code / data descriptor. S should equal 1: " << std::endl
                  << std::hex
                  << "    - es_access: 0x" << es_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_fs_is_not_a_system_descriptor()
{
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if ((fs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((fs_access & 0x0010) == 0)
    {
        std::cout << "check_guest_fs_is_not_a_system_descriptor failed. "
                  << "fs must be a code / data descriptor. S should equal 1: " << std::endl
                  << std::hex
                  << "    - fs_access: 0x" << fs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_gs_is_not_a_system_descriptor()
{
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if ((gs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((gs_access & 0x0010) == 0)
    {
        std::cout << "check_guest_gs_is_not_a_system_descriptor failed. "
                  << "gs must be a code / data descriptor. S should equal 1: " << std::endl
                  << std::hex
                  << "    - gs_access: 0x" << gs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cs_type_not_equal_3()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & 0x000F) == 3)
    {
        std::cout << "check_guest_cs_type_not_equal_3 failed. "
                  << "unrestricted guests are not supported. CS type cannot equal 3: " << std::endl
                  << std::hex
                  << "    - cs_access: 0x" << cs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cs_dpl_adheres_to_ss_dpl()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    switch (cs_access & 0x000F)
    {
        case 9:
        case 11:
            if ((cs_access & 0x60) != (ss_access & 0x60))
            {
                std::cout << "check_guest_cs_dpl_adheres_to_ss_dpl failed. "
                          << "guest cs dpl must equal ss dpl if type is 9 or 11: " << std::endl
                          << std::hex
                          << "    - cs_access: 0x" << cs_access << std::endl
                          << "    - ss_access: 0x" << ss_access << std::endl
                          << std::dec;
                return false;
            }

            break;

        case 13:
        case 15:
            if ((cs_access & 0x60) > (ss_access & 0x60))
            {
                std::cout << "check_guest_cs_dpl_adheres_to_ss_dpl failed. "
                          << "guest cs dpl must not be greater than ss dpl if type is 13 or 15: " << std::endl
                          << std::hex
                          << "    - cs_access: 0x" << cs_access << std::endl
                          << "    - ss_access: 0x" << ss_access << std::endl
                          << std::dec;
                return false;
            }

            break;

        default:
            break;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ss_dpl_must_equal_rpl()
{
    auto ss = vmread(VMCS_GUEST_SS_SELECTOR);
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if ((ss_access & 0x0060) != (ss & SELECTOR_RPL_FLAG))
    {
        std::cout << "check_guest_ss_dpl_must_equal_rpl failed. "
                  << "ss dpl must equal ss rpl: " << std::endl
                  << std::hex
                  << "    - ss: 0x" << ss << std::endl
                  << "    - ss_access: 0x" << ss_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ss_dpl_must_equal_zero()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if ((ss_access & 0x0060) != 0 && (cs_access & 0x000F) == 3)
    {
        std::cout << "check_guest_ss_dpl_must_equal_zero failed. "
                  << "if cs type == 3, ss dpl must equal 0: " << std::endl
                  << std::hex
                  << "    - cs_access: 0x" << cs_access << std::endl
                  << "    - ss_access: 0x" << ss_access << std::endl
                  << std::dec;

        return false;
    }

    // No need to check for CRE.PE == 0, since protected mode and 64bit mode
    // must be enabled, and are already checked.

    return true;
}

bool
vmcs_intel_x64::check_guest_ds_dpl()
{
    auto ds = vmread(VMCS_GUEST_DS_SELECTOR);
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if ((ds_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ds_access & 0x000F) >= 12)
        return true;

    if ((ds_access & 0x0060) < (ds & SELECTOR_RPL_FLAG))
    {
        std::cout << "check_guest_ds_dpl failed. "
                  << "ds dpl cannot be less then rpl if usable, and type between 0 - 11: " << std::endl
                  << std::hex
                  << "    - ds: 0x" << ds << std::endl
                  << "    - ds_access: 0x" << ds_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_es_dpl()
{
    auto es = vmread(VMCS_GUEST_ES_SELECTOR);
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if ((es_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((es_access & 0x000F) >= 12)
        return true;

    if ((es_access & 0x0060) < (es & SELECTOR_RPL_FLAG))
    {
        std::cout << "check_guest_es_dpl failed. "
                  << "es dpl cannot be less then rpl if usable, and type between 0 - 11: " << std::endl
                  << std::hex
                  << "    - es: 0x" << es << std::endl
                  << "    - es_access: 0x" << es_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_fs_dpl()
{
    auto fs = vmread(VMCS_GUEST_FS_SELECTOR);
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if ((fs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((fs_access & 0x000F) >= 12)
        return true;

    if ((fs_access & 0x0060) < (fs & SELECTOR_RPL_FLAG))
    {
        std::cout << "check_guest_fs_dpl failed. "
                  << "fs dpl cannot be less then rpl if usable, and type between 0 - 11: " << std::endl
                  << std::hex
                  << "    - fs: 0x" << fs << std::endl
                  << "    - fs_access: 0x" << fs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_gs_dpl()
{
    auto gs = vmread(VMCS_GUEST_GS_SELECTOR);
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if ((gs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((gs_access & 0x000F) >= 12)
        return true;

    if ((gs_access & 0x0060) < (gs & SELECTOR_RPL_FLAG))
    {
        std::cout << "check_guest_gs_dpl failed. "
                  << "gs dpl cannot be less then rpl if usable, and type between 0 - 11: " << std::endl
                  << std::hex
                  << "    - gs: 0x" << gs << std::endl
                  << "    - gs_access: 0x" << gs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cs_must_be_present()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & 0x0080) == 0)
    {
        std::cout << "check_guest_cs_must_be_present failed. "
                  << "cs must be present, p == 0: " << std::endl
                  << std::hex
                  << "    - cs_access: 0x" << cs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ss_must_be_present_if_usable()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if ((ss_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ss_access & 0x0080) == 0)
    {
        std::cout << "check_guest_ss_must_be_present failed. "
                  << "ss must be present, p == 0: " << std::endl
                  << std::hex
                  << "    - ss_access: 0x" << ss_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ds_must_be_present_if_usable()
{
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if ((ds_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ds_access & 0x0080) == 0)
    {
        std::cout << "check_guest_ds_must_be_present failed. "
                  << "ds must be present, p == 0: " << std::endl
                  << std::hex
                  << "    - ds_access: 0x" << ds_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_es_must_be_present_if_usable()
{
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if ((es_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((es_access & 0x0080) == 0)
    {
        std::cout << "check_guest_es_must_be_present failed. "
                  << "es must be present, p == 0: " << std::endl
                  << std::hex
                  << "    - es_access: 0x" << es_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_fs_must_be_present_if_usable()
{
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if ((fs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((fs_access & 0x0080) == 0)
    {
        std::cout << "check_guest_fs_must_be_present failed. "
                  << "fs must be present, p == 0: " << std::endl
                  << std::hex
                  << "    - fs_access: 0x" << fs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_gs_must_be_present_if_usable()
{
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if ((gs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((gs_access & 0x0080) == 0)
    {
        std::cout << "check_guest_gs_must_be_present failed. "
                  << "gs must be present, p == 0: " << std::endl
                  << std::hex
                  << "    - gs_access: 0x" << gs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cs_access_rights_reserved_must_be_0()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & 0x0F00) != 0)
    {
        std::cout << "check_guest_cs_access_rights_reserved_must_be_0 failed. "
                  << "cs reserved bits must be 0" << std::endl
                  << std::hex
                  << "    - cs_access: 0x" << cs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ss_access_rights_reserved_must_be_0()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if ((ss_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ss_access & 0x0F00) != 0)
    {
        std::cout << "check_guest_ss_access_rights_reserved_must_be_0 failed. "
                  << "ss reserved bits must be 0" << std::endl
                  << std::hex
                  << "    - ss_access: 0x" << ss_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ds_access_rights_reserved_must_be_0()
{
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if ((ds_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ds_access & 0x0F00) != 0)
    {
        std::cout << "check_guest_ds_access_rights_reserved_must_be_0 failed. "
                  << "ds reserved bits must be 0" << std::endl
                  << std::hex
                  << "    - ds_access: 0x" << ds_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_es_access_rights_reserved_must_be_0()
{
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if ((es_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((es_access & 0x0F00) != 0)
    {
        std::cout << "check_guest_es_access_rights_reserved_must_be_0 failed. "
                  << "es reserved bits must be 0" << std::endl
                  << std::hex
                  << "    - es_access: 0x" << es_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_fs_access_rights_reserved_must_be_0()
{
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if ((fs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((fs_access & 0x0F00) != 0)
    {
        std::cout << "check_guest_fs_access_rights_reserved_must_be_0 failed. "
                  << "fs reserved bits must be 0" << std::endl
                  << std::hex
                  << "    - fs_access: 0x" << fs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_gs_access_rights_reserved_must_be_0()
{
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if ((gs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((gs_access & 0x0F00) != 0)
    {
        std::cout << "check_guest_gs_access_rights_reserved_must_be_0 failed. "
                  << "gs reserved bits must be 0" << std::endl
                  << std::hex
                  << "    - gs_access: 0x" << gs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cs_db_must_be_0_if_l_equals_1()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & 0x2000) != 0 && (cs_access & 0x4000) != 0)
    {
        std::cout << "check_guest_cs_db_must_be_0_if_l_equals_1 failed. "
                  << "for cs, db must be 0 if l is 1" << std::endl
                  << std::hex
                  << "    - cs_access: 0x" << cs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cs_granularity()
{
    auto cs_limit = vmread(VMCS_GUEST_CS_LIMIT);
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_limit & 0x00000FFF) == 0 && (cs_access & 0x8000) != 0)
    {
        std::cout << "check_guest_cs_granularity failed. "
                  << "for cs, if any limit bit in 11:0 == 0, g must be 0" << std::endl
                  << std::hex
                  << "    - cs_limit: 0x" << cs_limit << std::endl
                  << "    - cs_access: 0x" << cs_access << std::endl
                  << std::dec;

        return false;
    }

    if ((cs_limit & 0xFFF00000) != 0 && (cs_access & 0x8000) == 0)
    {
        std::cout << "check_guest_cs_granularity failed. "
                  << "for cs, if any limit bit in 31:20 == 1, g must be 1" << std::endl
                  << std::hex
                  << "    - cs_limit: 0x" << cs_limit << std::endl
                  << "    - cs_access: 0x" << cs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ss_granularity()
{
    auto ss_limit = vmread(VMCS_GUEST_SS_LIMIT);
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if ((ss_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ss_limit & 0x00000FFF) == 0 && (ss_access & 0x8000) != 0)
    {
        std::cout << "check_guest_ss_granularity failed. "
                  << "for ss, if any limit bit in 11:0 == 0, g must be 0" << std::endl
                  << std::hex
                  << "    - ss_limit: 0x" << ss_limit << std::endl
                  << "    - ss_access: 0x" << ss_access << std::endl
                  << std::dec;

        return false;
    }

    if ((ss_limit & 0xFFF00000) != 0 && (ss_access & 0x8000) == 0)
    {
        std::cout << "check_guest_ss_granularity failed. "
                  << "for ss, if any limit bit in 31:20 == 1, g must be 1" << std::endl
                  << std::hex
                  << "    - ss_limit: 0x" << ss_limit << std::endl
                  << "    - ss_access: 0x" << ss_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ds_granularity()
{
    auto ds_limit = vmread(VMCS_GUEST_DS_LIMIT);
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if ((ds_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ds_limit & 0x00000FFF) == 0 && (ds_access & 0x8000) != 0)
    {
        std::cout << "check_guest_ds_granularity failed. "
                  << "for ds, if any limit bit in 11:0 == 0, g must be 0" << std::endl
                  << std::hex
                  << "    - ds_limit: 0x" << ds_limit << std::endl
                  << "    - ds_access: 0x" << ds_access << std::endl
                  << std::dec;

        return false;
    }

    if ((ds_limit & 0xFFF00000) != 0 && (ds_access & 0x8000) == 0)
    {
        std::cout << "check_guest_ds_granularity failed. "
                  << "for ds, if any limit bit in 31:20 == 1, g must be 1" << std::endl
                  << std::hex
                  << "    - ds_limit: 0x" << ds_limit << std::endl
                  << "    - ds_access: 0x" << ds_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_es_granularity()
{
    auto es_limit = vmread(VMCS_GUEST_ES_LIMIT);
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if ((es_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((es_limit & 0x00000FFF) == 0 && (es_access & 0x8000) != 0)
    {
        std::cout << "check_guest_es_granularity failed. "
                  << "for es, if any limit bit in 11:0 == 0, g must be 0" << std::endl
                  << std::hex
                  << "    - es_limit: 0x" << es_limit << std::endl
                  << "    - es_access: 0x" << es_access << std::endl
                  << std::dec;

        return false;
    }

    if ((es_limit & 0xFFF00000) != 0 && (es_access & 0x8000) == 0)
    {
        std::cout << "check_guest_es_granularity failed. "
                  << "for es, if any limit bit in 31:20 == 1, g must be 1" << std::endl
                  << std::hex
                  << "    - es_limit: 0x" << es_limit << std::endl
                  << "    - es_access: 0x" << es_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_fs_granularity()
{
    auto fs_limit = vmread(VMCS_GUEST_FS_LIMIT);
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if ((fs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((fs_limit & 0x00000FFF) == 0 && (fs_access & 0x8000) != 0)
    {
        std::cout << "check_guest_fs_granularity failed. "
                  << "for fs, if any limit bit in 11:0 == 0, g must be 0" << std::endl
                  << std::hex
                  << "    - fs_limit: 0x" << fs_limit << std::endl
                  << "    - fs_access: 0x" << fs_access << std::endl
                  << std::dec;

        return false;
    }

    if ((fs_limit & 0xFFF00000) != 0 && (fs_access & 0x8000) == 0)
    {
        std::cout << "check_guest_fs_granularity failed. "
                  << "for fs, if any limit bit in 31:20 == 1, g must be 1" << std::endl
                  << std::hex
                  << "    - fs_limit: 0x" << fs_limit << std::endl
                  << "    - fs_access: 0x" << fs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_gs_granularity()
{
    auto gs_limit = vmread(VMCS_GUEST_GS_LIMIT);
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if ((gs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((gs_limit & 0x00000FFF) == 0 && (gs_access & 0x8000) != 0)
    {
        std::cout << "check_guest_gs_granularity failed. "
                  << "for gs, if any limit bit in 11:0 == 0, g must be 0" << std::endl
                  << std::hex
                  << "    - gs_limit: 0x" << gs_limit << std::endl
                  << "    - gs_access: 0x" << gs_access << std::endl
                  << std::dec;

        return false;
    }

    if ((gs_limit & 0xFFF00000) != 0 && (gs_access & 0x8000) == 0)
    {
        std::cout << "check_guest_gs_granularity failed. "
                  << "for gs, if any limit bit in 31:20 == 1, g must be 1" << std::endl
                  << std::hex
                  << "    - gs_limit: 0x" << gs_limit << std::endl
                  << "    - gs_access: 0x" << gs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cs_access_rights_remaining_reserved_bit_0()
{
    auto cs_access = vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    if ((cs_access & 0xFFFE0000) != 0)
    {
        std::cout << "check_guest_cs_access_rights_remaining_reserved_bit_0 failed. "
                  << "cs bits 31:17 in the access rights must be 0" << std::endl
                  << std::hex
                  << "    - cs_access: 0x" << cs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ss_access_rights_remaining_reserved_bit_0()
{
    auto ss_access = vmread(VMCS_GUEST_SS_ACCESS_RIGHTS);

    if ((ss_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ss_access & 0xFFFE0000) != 0)
    {
        std::cout << "check_guest_ss_access_rights_remaining_reserved_bit_0 failed. "
                  << "ss bits 31:17 in the access rights must be 0" << std::endl
                  << std::hex
                  << "    - ss_access: 0x" << ss_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ds_access_rights_remaining_reserved_bit_0()
{
    auto ds_access = vmread(VMCS_GUEST_DS_ACCESS_RIGHTS);

    if ((ds_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ds_access & 0xFFFE0000) != 0)
    {
        std::cout << "check_guest_ds_access_rights_remaining_reserved_bit_0 failed. "
                  << "ds bits 31:17 in the access rights must be 0" << std::endl
                  << std::hex
                  << "    - ds_access: 0x" << ds_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_es_access_rights_remaining_reserved_bit_0()
{
    auto es_access = vmread(VMCS_GUEST_ES_ACCESS_RIGHTS);

    if ((es_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((es_access & 0xFFFE0000) != 0)
    {
        std::cout << "check_guest_es_access_rights_remaining_reserved_bit_0 failed. "
                  << "es bits 31:17 in the access rights must be 0" << std::endl
                  << std::hex
                  << "    - es_access: 0x" << es_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_fs_access_rights_remaining_reserved_bit_0()
{
    auto fs_access = vmread(VMCS_GUEST_FS_ACCESS_RIGHTS);

    if ((fs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((fs_access & 0xFFFE0000) != 0)
    {
        std::cout << "check_guest_fs_access_rights_remaining_reserved_bit_0 failed. "
                  << "fs bits 31:17 in the access rights must be 0" << std::endl
                  << std::hex
                  << "    - fs_access: 0x" << fs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_gs_access_rights_remaining_reserved_bit_0()
{
    auto gs_access = vmread(VMCS_GUEST_GS_ACCESS_RIGHTS);

    if ((gs_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((gs_access & 0xFFFE0000) != 0)
    {
        std::cout << "check_guest_gs_access_rights_remaining_reserved_bit_0 failed. "
                  << "gs bits 31:17 in the access rights must be 0" << std::endl
                  << std::hex
                  << "    - gs_access: 0x" << gs_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_tr_type_must_be_11()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_access & 0x000F) != 11)
    {
        std::cout << "check_guest_tr_type_must_be_11 failed. "
                  << "tr type must be 11" << std::endl
                  << std::hex
                  << "    - tr_access: 0x" << tr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_tr_must_be_a_system_descriptor()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_access & 0x0010) != 0)
    {
        std::cout << "check_guest_tr_must_be_a_system_descriptor failed. "
                  << "tr must be a system descsriptor, yet s == 1" << std::endl
                  << std::hex
                  << "    - tr_access: 0x" << tr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_tr_must_be_present()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_access & 0x0080) == 0)
    {
        std::cout << "check_guest_tr_must_be_present failed. "
                  << "tr must be present, yet p == 0" << std::endl
                  << std::hex
                  << "    - tr_access: 0x" << tr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_tr_access_rights_reserved_must_be_0()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_access & 0x0F00) != 0)
    {
        std::cout << "check_guest_tr_access_rights_reserved_must_be_0 failed. "
                  << "tr reserved access rights must be 0" << std::endl
                  << std::hex
                  << "    - tr_access: 0x" << tr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_tr_granularity()
{
    auto tr_limit = vmread(VMCS_GUEST_TR_LIMIT);
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_limit & 0x00000FFF) == 0 && (tr_access & 0x8000) != 0)
    {
        std::cout << "check_guest_tr_granularity failed. "
                  << "for tr, if any limit bit in 11:0 == 0, g must be 0" << std::endl
                  << std::hex
                  << "    - tr_limit: 0x" << tr_limit << std::endl
                  << "    - tr_access: 0x" << tr_access << std::endl
                  << std::dec;

        return false;
    }

    if ((tr_limit & 0xFFF00000) != 0 && (tr_access & 0x8000) == 0)
    {
        std::cout << "check_guest_tr_granularity failed. "
                  << "for tr, if any limit bit in 31:20 == 1, g must be 1" << std::endl
                  << std::hex
                  << "    - tr_limit: 0x" << tr_limit << std::endl
                  << "    - tr_access: 0x" << tr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_tr_must_be_usable()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_access & SELECTOR_UNUSABLE) != 0)
    {
        std::cout << "check_guest_tr_must_be_usable failed. "
                  << "tr must be usable" << std::endl
                  << std::hex
                  << "    - tr_access: 0x" << tr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_tr_access_rights_remaining_reserved_bit_0()
{
    auto tr_access = vmread(VMCS_GUEST_TR_ACCESS_RIGHTS);

    if ((tr_access & 0xFFFE0000) != 0)
    {
        std::cout << "check_guest_tr_access_rights_remaining_reserved_bit_0 failed. "
                  << "tr bits 31:17 in the access rights must be 0" << std::endl
                  << std::hex
                  << "    - tr_access: 0x" << tr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ldtr_type_must_be_2()
{
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if ((ldtr_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ldtr_access & 0x000F) != 2)
    {
        std::cout << "check_guest_ldtr_type_must_be_11 failed. "
                  << "ldtr type must be 2" << std::endl
                  << std::hex
                  << "    - ldtr_access: 0x" << ldtr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ldtr_must_be_a_system_descriptor()
{
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if ((ldtr_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ldtr_access & 0x0010) != 0)
    {
        std::cout << "check_guest_ldtr_must_be_a_system_descriptor failed. "
                  << "ldtr must be a system descsriptor, yet s == 1" << std::endl
                  << std::hex
                  << "    - ldtr_access: 0x" << ldtr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ldtr_must_be_present()
{
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if ((ldtr_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ldtr_access & 0x0080) == 0)
    {
        std::cout << "check_guest_ldtr_must_be_present failed. "
                  << "ldtr must be present, yet p == 0" << std::endl
                  << std::hex
                  << "    - ldtr_access: 0x" << ldtr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ldtr_access_rights_reserved_must_be_0()
{
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if ((ldtr_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ldtr_access & 0x0F00) != 0)
    {
        std::cout << "check_guest_ldtr_access_rights_reserved_must_be_0 failed. "
                  << "ldtr reserved access rights must be 0" << std::endl
                  << std::hex
                  << "    - ldtr_access: 0x" << ldtr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ldtr_granularity()
{
    auto ldtr_limit = vmread(VMCS_GUEST_LDTR_LIMIT);
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if ((ldtr_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ldtr_limit & 0x00000FFF) == 0 && (ldtr_access & 0x8000) != 0)
    {
        std::cout << "check_guest_ldtr_granularity failed. "
                  << "for ldtr, if any limit bit in 11:0 == 0, g must be 0" << std::endl
                  << std::hex
                  << "    - ldtr_limit: 0x" << ldtr_limit << std::endl
                  << "    - ldtr_access: 0x" << ldtr_access << std::endl
                  << std::dec;

        return false;
    }

    if ((ldtr_limit & 0xFFF00000) != 0 && (ldtr_access & 0x8000) == 0)
    {
        std::cout << "check_guest_ldtr_granularity failed. "
                  << "for ldtr, if any limit bit in 31:20 == 1, g must be 1" << std::endl
                  << std::hex
                  << "    - ldtr_limit: 0x" << ldtr_limit << std::endl
                  << "    - ldtr_access: 0x" << ldtr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ldtr_access_rights_remaining_reserved_bit_0()
{
    auto ldtr_access = vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS);

    if ((ldtr_access & SELECTOR_UNUSABLE) != 0)
        return true;

    if ((ldtr_access & 0xFFFE0000) != 0)
    {
        std::cout << "check_guest_ldtr_access_rights_remaining_reserved_bit_0 failed. "
                  << "ldtr bits 31:17 in the access rights must be 0" << std::endl
                  << std::hex
                  << "    - ldtr_access: 0x" << ldtr_access << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_checks_on_guest_descriptor_table_registers()
{
    auto result = true;

    result &= check_guest_gdtr_base_must_be_canonical();
    result &= check_guest_idtr_base_must_be_canonical();
    result &= check_guest_gdtr_limit_reserved_bits();
    result &= check_guest_idtr_limit_reserved_bits();

    return result;
}

bool
vmcs_intel_x64::check_guest_gdtr_base_must_be_canonical()
{
    auto gdtr_base = vmread(VMCS_GUEST_GDTR_BASE);

    if (check_is_address_canonical(gdtr_base) == false)
    {
        std::cout << "check_guest_gdtr_base_must_be_canonical failed. "
                  << "guest gdtr_base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - gdtr_base: 0x" << gdtr_base << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_idtr_base_must_be_canonical()
{
    auto idtr_base = vmread(VMCS_GUEST_IDTR_BASE);

    if (check_is_address_canonical(idtr_base) == false)
    {
        std::cout << "check_guest_idtr_base_must_be_canonical failed. "
                  << "guest idtr_base has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - idtr_base: 0x" << idtr_base << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_gdtr_limit_reserved_bits()
{
    auto gdtr_limit = vmread(VMCS_GUEST_GDTR_LIMIT);

    if ((gdtr_limit & 0xFFFF0000) != 0)
    {
        std::cout << "check_guest_gdtr_limit_reserved_bits failed. "
                  << "guest gdtr_limit reserved bits must be 0: " << std::endl
                  << std::hex
                  << "    - gdtr_limit: 0x" << gdtr_limit << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_idtr_limit_reserved_bits()
{
    auto idtr_limit = vmread(VMCS_GUEST_IDTR_LIMIT);

    if ((idtr_limit & 0xFFFF0000) != 0)
    {
        std::cout << "check_guest_idtr_limit_reserved_bits failed. "
                  << "guest idtr_limit reserved bits must be 0: " << std::endl
                  << std::hex
                  << "    - idtr_limit: 0x" << idtr_limit << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_checks_on_guest_rip_and_rflags()
{
    auto result = true;

    result &= check_guest_rflags_reserved_bits();
    result &= check_guest_rflag_interrupt_enable();

    return result;
}

bool
vmcs_intel_x64::check_guest_rflags_reserved_bits()
{
    auto rflags = vmread(VMCS_GUEST_RFLAGS);

    if ((rflags & 0xFFC08028) != 0 || (rflags & 0x2) == 0)
    {
        std::cout << "check_guest_rflags_reserved_bits failed. "
                  << "reserved bits in rflags must be 0, and bit 1 must be 1: " << std::endl
                  << std::hex
                  << "    - rflags: 0x" << rflags << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_rflag_interrupt_enable()
{
    auto event_injection = vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if (event_injection != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_rflag_interrupt_enable"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_checks_on_guest_non_register_state()
{
    auto result = true;

    result &= check_guest_valid_activity_state();
    result &= check_guest_activity_state_not_hlt_when_dpl_not_0();
    result &= check_guest_must_be_active_if_injecting_blocking_state();
    result &= check_guest_valid_interruptability_and_activity_state_combo();
    result &= check_guest_valid_activity_state_and_smm();
    result &= check_guest_all_interruptability_state_fields();
    result &= check_guest_all_vmcs_link_pointerchecks();

    return result;
}

bool
vmcs_intel_x64::check_guest_valid_activity_state()
{
    auto activity = vmread(VMCS_GUEST_ACTIVITY_STATE);

    if (activity > 3)
    {
        std::cout << "check_guest_valid_activity_state failed. "
                  << "guest activity state must be between 0 - 3: " << std::endl
                  << std::hex
                  << "    - activity: 0x" << activity << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_activity_state_not_hlt_when_dpl_not_0()
{
    auto activity = vmread(VMCS_GUEST_ACTIVITY_STATE);

    if (activity != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_activity_state_not_hlt_when_dpl_not_0"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_must_be_active_if_injecting_blocking_state()
{
    auto event_injection = vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if (event_injection != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_must_be_active_if_injecting_blocking_state"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_valid_interruptability_and_activity_state_combo()
{
    auto event_injection = vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    if (event_injection != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_valid_interruptability_and_activity_state_combo"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_valid_activity_state_and_smm()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    if ((controls & VM_ENTRY_CONTROL_ENTRY_TO_SMM) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_valid_activity_state_and_smm"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_all_interruptability_state_fields()
{
    auto event_injection = vmread(VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD);

    // Note that chapter 26.3.1.5 has a section on interruptability state
    // that this test was written for. This one check represents all of the
    // checks, thus if this field is used, these checks will need to be
    // implemented (i.e. there is more than one of them)
    //
    // This also includes the pending debug exceptions as they are related
    // to the interruptability state

    if (event_injection != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_all_interruptability_state_fields"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_all_vmcs_link_pointerchecks()
{
    auto link_pointer = vmread(VMCS_VMCS_LINK_POINTER_FULL);

    // Note that chapter 26.3.1.5 has a section on the vmcs link pointer
    // that this test was written for. This one check represents all of the
    // checks, thus if this field is used, these checks will need to be
    // implemented (i.e. there is more than one of them)

    if (link_pointer != 0xFFFFFFFFFFFFFFFF)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_all_vmcs_link_pointerchecks"
                  << std::endl;
        return false;
    }

    return true;
}
