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
#include <exit_handler/exit_handler.h>

// =============================================================================
//  Helper Structs
// =============================================================================

struct vmcs_region
{
    uint32_t revision_id;
};

// =============================================================================
//  Implementation
// =============================================================================

vmcs_intel_x64::vmcs_intel_x64() :
    m_intrinsics(0),
    m_memory_manager(0)
{
}

vmcs_error::type
vmcs_intel_x64::init(intrinsics *intrinsics,
                     memory_manager *memory_manager)
{
    if (intrinsics == 0 || memory_manager == 0)
        return vmcs_error::failure;

    // Ideally we would use dynamic_cast to get access to the intrinics
    // for this archiecture, simply to validate that we were passed the
    // correct class. Since the VMM does not have RTTI, we cannot use this
    // function.

    m_intrinsics = reinterpret_cast<intrinsics_intel_x64 *>(intrinsics);
    m_memory_manager = memory_manager;

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::launch()
{
    vmcs_error::type ret;

    if (m_intrinsics == 0 || m_memory_manager == 0)
        return vmcs_error::failure;

    // Before we can do anything, we need to save the state of the CPU. This
    // information will be used to fill in the VMCS fields, and prevents a
    // lot of duplication.

    ret = save_state();
    if (ret != vmcs_error::success)
        return ret;

    // The process for luanching a virtual machine can be found in the
    // Intel Software Developers Manual, in section 31.6. This process is
    // a complete nightmare, so make sure you take a look at this
    // documentation for trying to make sense of the code in this class.

    ret = create_vmcs_region();
    if (ret != vmcs_error::success)
        return ret;

    ret = clear_vmcs_region();
    if (ret != vmcs_error::success)
        return ret;

    ret = load_vmcs_region();
    if (ret != vmcs_error::success)
        return ret;

    // The next set of steps fills in the previously loaded VMCS with
    // information about the guest / host. In this case, the guest is the
    // host OS that is running this code, and the host, is the VMM exit
    // handler that we provide. Note that if something goes wrong, it's
    // likely in the code below. For more information about how to debug
    // issues with this code, see Chapter 27 in the Intel Software Developers
    // Manual.

    // Also, note that the VMCS fields are fully documented in appendix
    // B of the Intel Software Developers Manual.

    ret = write_16bit_control_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_16bit_guest_state_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_16bit_host_state_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_64bit_control_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_64bit_guest_state_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_64bit_host_state_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_32bit_control_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_32bit_guest_state_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_32bit_host_state_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_natural_width_control_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_natural_width_guest_state_fields();
    if (ret != vmcs_error::success)
        return ret;

    ret = write_natural_width_host_state_fields();
    if (ret != vmcs_error::success)
        return ret;

    // Once the VMCS is setup, we need to turn on certain bits within the VMCS
    // that tell VT-x how to treat out VMM as well as the guest VM that we plan
    // to launch. Note that we could put these calls in the above code, but
    // this makes it more explicit about what we plan to enable, outside of
    // the bare minimum, which is what the above code is doing.

    ret = default_pin_based_vm_execution_controls();
    if (ret != vmcs_error::success)
        return ret;

    ret = default_primary_processor_based_vm_execution_controls();
    if (ret != vmcs_error::success)
        return ret;

    ret = default_secondary_processor_based_vm_execution_controls();
    if (ret != vmcs_error::success)
        return ret;

    ret = default_vm_exit_controls();
    if (ret != vmcs_error::success)
        return ret;

    ret = default_vm_entry_controls();
    if (ret != vmcs_error::success)
        return ret;

    // The last step is to launch the VMCS. If the launch fails, we must
    // go through a series of error checks to identify why the failure
    // occured. If the launch succeeds, we should continue execution as
    // normal, not this code will be in a virtual machine when finished.

    // ret = launch_vmcs();
    // if (ret != vmcs_error::success)
    // {
    std::cout << "launch failed!!!" << std::endl;
    return vmcs_error::success;
    // }
    // else
    // {
    //     std::cout << "WOOT, launch was succesfull!!!" << std::endl;
    //     return vmcs_error::success;
    // }
}

vmcs_error::type
vmcs_intel_x64::launch_vmcs()
{
    vmwrite(VMCS_GUEST_RIP, (uint64_t) && success);
    vmwrite(VMCS_GUEST_RSP, m_intrinsics->read_rsp());

    if (m_valid == false)
    {
        std::cout << "unable to launch VMCS, a failure invalidated the VMCS.";
        std::cout << std::endl;

        return vmcs_error::failure;
    }

    if (m_intrinsics->vmlaunch() == false)
    {
        std::cout << "vmlaunch instruction failed with CF = 1 or ZF = 1";
        std::cout << std::endl;

        return vmcs_error::failure;
    }

    std::cout << "vmlaunch instruction succeeded, but failed to launch VM";
    std::cout << std::endl;

    return vmcs_error::failure;

success:

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::resume_vmcs()
{
    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::save_state()
{
    m_es = m_intrinsics->read_es();
    m_cs = m_intrinsics->read_cs();
    m_ss = m_intrinsics->read_ss();
    m_ds = m_intrinsics->read_ds();
    m_fs = m_intrinsics->read_fs();
    m_gs = m_intrinsics->read_gs();
    m_ldtr = m_intrinsics->read_ldtr();
    m_tr = m_intrinsics->read_tr();

    m_cr0 = m_intrinsics->read_cr0();
    m_cr3 = m_intrinsics->read_cr3();
    m_cr4 = m_intrinsics->read_cr4();
    m_rflags = m_intrinsics->read_rflags();

    m_intrinsics->read_gdt(&m_gdt_reg);
    m_intrinsics->read_idt(&m_idt_reg);

    m_es_limit = m_intrinsics->segment_descriptor_limit(m_es);
    m_cs_limit = m_intrinsics->segment_descriptor_limit(m_cs);
    m_ss_limit = m_intrinsics->segment_descriptor_limit(m_ss);
    m_ds_limit = m_intrinsics->segment_descriptor_limit(m_ds);
    m_fs_limit = m_intrinsics->segment_descriptor_limit(m_fs);
    m_gs_limit = m_intrinsics->segment_descriptor_limit(m_gs);
    m_ldtr_limit = m_intrinsics->segment_descriptor_limit(m_ldtr);
    m_tr_limit = m_intrinsics->segment_descriptor_limit(m_tr);

    m_es_access = m_intrinsics->segment_descriptor_access(m_es);
    m_cs_access = m_intrinsics->segment_descriptor_access(m_cs);
    m_ss_access = m_intrinsics->segment_descriptor_access(m_ss);
    m_ds_access = m_intrinsics->segment_descriptor_access(m_ds);
    m_fs_access = m_intrinsics->segment_descriptor_access(m_fs);
    m_gs_access = m_intrinsics->segment_descriptor_access(m_gs);
    m_ldtr_access = m_intrinsics->segment_descriptor_access(m_ldtr);
    m_tr_access = m_intrinsics->segment_descriptor_access(m_tr);

    m_es_base = m_intrinsics->segment_descriptor_base(m_es);
    m_cs_base = m_intrinsics->segment_descriptor_base(m_cs);
    m_ss_base = m_intrinsics->segment_descriptor_base(m_ss);
    m_ds_base = m_intrinsics->segment_descriptor_base(m_ds);
    m_fs_base = m_intrinsics->segment_descriptor_base(m_fs);
    m_gs_base = m_intrinsics->segment_descriptor_base(m_gs);
    m_ldtr_base = m_intrinsics->segment_descriptor_base(m_ldtr);
    m_tr_base = m_intrinsics->segment_descriptor_base(m_tr);

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::create_vmcs_region()
{
    if (m_memory_manager->alloc_page(&m_vmcs_region) != memory_manager_error::success)
    {
        std::cout << "create_vmcs_region failed: "
                  << "out of memory" << std::endl;
        return vmcs_error::out_of_memory;
    }

    if (m_vmcs_region.size() < vmcs_region_size())
    {
        std::cout << "create_vmcs_region failed: "
                  << "the allocated page is not large enough:" << std::endl
                  << "    - page size: " << m_vmcs_region.size() << " "
                  << "    - vmxon/vmcs region size: " << vmcs_region_size()
                  << std::endl;
        return vmcs_error::not_supported;
    }

    if (((uintptr_t)m_vmcs_region.phys_addr() & 0x0000000000000FFF) != 0)
    {
        std::cout << "create_vmcs_region failed: "
                  << "the allocated page is not page aligned:" << std::endl
                  << "    - page phys: " << m_vmcs_region.phys_addr()
                  << std::endl;
        return vmcs_error::not_supported;
    }

    auto buf = (char *)m_vmcs_region.virt_addr();
    auto reg = (vmcs_region *)m_vmcs_region.virt_addr();

    // The information regading this MSR can be found in appendix A.1. For
    // the VMX capabilities check, we need the following:
    //
    // - Bits 30:0 contain the 31-bit VMCS revision identifier used by the
    //   processor. Processors that use the same VMCS revision identifier use
    //   the same size for VMCS regions (see subsequent item on bits 44:32)

    for (auto i = 0; i < m_vmcs_region.size(); i++)
        buf[i] = 0;

    reg->revision_id = (m_intrinsics->read_msr(IA32_VMX_BASIC_MSR) & 0x7FFFFFFFF);

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::release_vmxon_region()
{
    m_memory_manager->free_page(m_vmcs_region);

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::clear_vmcs_region()
{
    auto phys = m_vmcs_region.phys_addr();

    // For some reason, the VMCLEAR instruction takes the address of a memory
    // location that has the address of the VMCS region, which sadly is not
    // well documented in the Intel manual.

    if (m_intrinsics->vmclear(&phys) == false)
    {
        std::cout << "vmclear failed" << std::endl;
        return vmcs_error::failure;
    }

    m_valid = true;

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::load_vmcs_region()
{
    auto phys = m_vmcs_region.phys_addr();

    // For some reason, the VMPTRLD instruction takes the address of a memory
    // location that has the address of the VMCS region, which sadly is not
    // well documented in the Intel manual.

    if (m_intrinsics->vmptrld(&phys) == false)
    {
        std::cout << "vmptrld failed" << std::endl;
        return vmcs_error::failure;
    }

    return vmcs_error::success;
}

uint64_t
vmcs_intel_x64::vmcs_region_size()
{
    auto vmx_basic_msr = m_intrinsics->read_msr(IA32_VMX_BASIC_MSR);

    // The information regading this MSR can be found in appendix A.1. For
    // the VMX capabilities check, we need the following:
    //
    // - Bits 44:32 report the number of bytes that software should allocate
    //   for the VMXON region and any VMCS region. It is a value greater
    //   than 0 and at most 4096 (bit 44 is set if and only if bits 43:32 are
    //   clear).
    //
    //   Note: We basically ignore the above bits and just allocate 4K for each
    //   VMX region. The only thing we do with this function is ensure that
    //   the page that we were given is at least this big

    return (vmx_basic_msr >> 32) & 0x1FFF;
}

vmcs_error::type
vmcs_intel_x64::write_16bit_control_fields()
{
    // unused: VMCS_VIRTUAL_PROCESSOR_IDENTIFIER
    // unused: VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR
    // unused: VMCS_EPTP_INDEX

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_16bit_guest_state_fields()
{
    vmwrite(VMCS_GUEST_ES_SELECTOR, m_es);
    vmwrite(VMCS_GUEST_CS_SELECTOR, m_cs);
    vmwrite(VMCS_GUEST_SS_SELECTOR, m_ss);
    vmwrite(VMCS_GUEST_DS_SELECTOR, m_ds);
    vmwrite(VMCS_GUEST_FS_SELECTOR, m_fs);
    vmwrite(VMCS_GUEST_GS_SELECTOR, m_gs);
    vmwrite(VMCS_GUEST_LDTR_SELECTOR, m_ldtr);
    vmwrite(VMCS_GUEST_TR_SELECTOR, m_tr);

    // unused: VMCS_GUEST_INTERRUPT_STATUS

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_16bit_host_state_fields()
{
    vmwrite(VMCS_HOST_ES_SELECTOR, m_es);
    vmwrite(VMCS_HOST_CS_SELECTOR, m_cs);
    vmwrite(VMCS_HOST_SS_SELECTOR, m_ss);
    vmwrite(VMCS_HOST_DS_SELECTOR, m_ds);
    vmwrite(VMCS_HOST_FS_SELECTOR, m_fs);
    vmwrite(VMCS_HOST_GS_SELECTOR, m_gs);
    vmwrite(VMCS_HOST_TR_SELECTOR, m_tr);

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_64bit_control_fields()
{
    // Note: Since we are in 64bit mode, we do not need to load both the
    //       high and full fields. We simply need to load the full field
    //       with 64bit writes, which will fill in the high field for us.

    // unused: VMCS_ADDRESS_OF_IO_BITMAP_A_FULL
    // unused: VMCS_ADDRESS_OF_IO_BITMAP_B_FULL
    // unused: VMCS_ADDRESS_OF_MSR_BITMAPS_FULL
    // unused: VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL
    // unused: VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL
    // unused: VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL
    // unused: VMCS_EXECUTIVE_VMCS_POINTER_FULL
    // unused: VMCS_TSC_OFFSET_FULL
    // unused: VMCS_VIRTUAL_APIC_ADDRESS_FULL
    // unused: VMCS_APIC_ACCESS_ADDRESS_FULL
    // unused: VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL
    // unused: VMCS_VM_FUNCTION_CONTROLS_FULL
    // unused: VMCS_EPT_POINTER_FULL
    // unused: VMCS_EOI_EXIT_BITMAP_0_FULL
    // unused: VMCS_EOI_EXIT_BITMAP_1_FULL
    // unused: VMCS_EOI_EXIT_BITMAP_2_FULL
    // unused: VMCS_EOI_EXIT_BITMAP_3_FULL
    // unused: VMCS_EPTP_LIST_ADDRESS_FULL
    // unused: VMCS_VMREAD_BITMAP_ADDRESS_FULL
    // unused: VMCS_VMWRITE_BITMAP_ADDRESS_FULL
    // unused: VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL
    // unused: VMCS_XSS_EXITING_BITMAP_FULL

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_64bit_guest_state_fields()
{
    // Note: Since we are in 64bit mode, we do not need to load both the
    //       high and full fields. We simply need to load the full field
    //       with 64bit writes, which will fill in the high field for us.

    vmwrite(VMCS_VMCS_LINK_POINTER_FULL, 0xFFFFFFFFFFFFFFFF);
    vmwrite(VMCS_GUEST_IA32_EFER_FULL, m_intrinsics->read_msr(IA32_EFER_MSR));

    // unused: VMCS_GUEST_IA32_DEBUGCTL_FULL
    // unused: VMCS_GUEST_IA32_PAT_FULL
    // unused: VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL
    // unused: VMCS_GUEST_PDPTE0_FULL
    // unused: VMCS_GUEST_PDPTE1_FULL
    // unused: VMCS_GUEST_PDPTE2_FULL
    // unused: VMCS_GUEST_PDPTE3_FULL

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_64bit_host_state_fields()
{
    // Note: Since we are in 64bit mode, we do not need to load both the
    //       high and full fields. We simply need to load the full field
    //       with 64bit writes, which will fill in the high field for us.

    vmwrite(VMCS_HOST_IA32_EFER_FULL, m_intrinsics->read_msr(IA32_EFER_MSR));

    // unused: VMCS_HOST_IA32_PAT_FULL
    // unused: VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_32bit_control_fields()
{
    uint64_t lower;
    uint64_t upper;

    // For the following fields, there is a complex, algorithm that is used
    // to determine what these values of these fields actually should be.
    //
    // - VMCS_PIN_BASED_VM_EXECUTION_CONTROLS
    // - VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS
    // - VMCS_VM_EXIT_CONTROLS
    // - VMCS_VM_ENTRY_CONTROLS
    //
    // These algorithms are defined in section 31.5.1 Algorithms for
    // Determining VMX Capabilities. We use a subset of algorithm #3.
    //
    // Basically, the way this works is for each of the fields is:
    //     - a 1 in the lower 32bits of the associated MSR means that the
    //       field must contain a 1.
    //     - a 0 in the upper 32bits of the associated MSR means that the
    //       field must contain a 0.

    if ((m_intrinsics->read_msr(IA32_VMX_BASIC_MSR) & (0x1ll << 55)) == 0)
    {
        std::cout << "bit 55 in IA32_VMX_BASIC_MSR is cleared. "
                  << "hardware not supported" << std::endl;
        return vmcs_error::not_supported;
    }

    lower = (m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR) >> 0);
    upper = (m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR) >> 32);
    vmwrite(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS, lower & upper);

    lower = (m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR) >> 0);
    upper = (m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR) >> 32);
    vmwrite(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, lower & upper);

    lower = (m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR) >> 0);
    upper = (m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR) >> 32);
    vmwrite(VMCS_VM_EXIT_CONTROLS, lower & upper);

    lower = (m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR) >> 0);
    upper = (m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR) >> 32);
    vmwrite(VMCS_VM_ENTRY_CONTROLS, lower & upper);

    // unused: VMCS_EXCEPTION_BITMAP
    // unused: VMCS_PAGE_FAULT_ERROR_CODE_MASK
    // unused: VMCS_PAGE_FAULT_ERROR_CODE_MATCH
    // unused: VMCS_CR3_TARGET_COUNT
    // unused: VMCS_VM_EXIT_MSR_STORE_COUNT
    // unused: VMCS_VM_EXIT_MSR_LOAD_COUNT
    // unused: VMCS_VM_ENTRY_MSR_LOAD_COUNT
    // unused: VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD
    // unused: VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE
    // unused: VMCS_VM_ENTRY_INSTRUCTION_LENGTH
    // unused: VMCS_TPR_THRESHOLD
    // unused: VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS
    // unused: VMCS_PLE_GAP
    // unused: VMCS_PLE_WINDOW

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_32bit_guest_state_fields()
{
    // Not sure why but the limit is always set to all f's for both the guest
    // and the host. Both VMXCPU, and KVM do this.

    vmwrite(VMCS_GUEST_ES_LIMIT, m_es_limit);
    vmwrite(VMCS_GUEST_CS_LIMIT, m_cs_limit);
    vmwrite(VMCS_GUEST_SS_LIMIT, m_ss_limit);
    vmwrite(VMCS_GUEST_DS_LIMIT, m_ds_limit);
    vmwrite(VMCS_GUEST_FS_LIMIT, m_fs_limit);
    vmwrite(VMCS_GUEST_GS_LIMIT, m_gs_limit);
    vmwrite(VMCS_GUEST_LDTR_LIMIT, m_ldtr_limit);
    vmwrite(VMCS_GUEST_TR_LIMIT, m_tr_limit);

    vmwrite(VMCS_GUEST_GDTR_LIMIT, m_gdt_reg.limit);
    vmwrite(VMCS_GUEST_IDTR_LIMIT, m_idt_reg.limit);

    vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, m_es_access);
    vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, m_cs_access);
    vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, m_ss_access);
    vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, m_ds_access);
    vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, m_fs_access);
    vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, m_gs_access);
    vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, m_ldtr_access);
    vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, m_tr_access);

    vmwrite(VMCS_GUEST_IA32_SYSENTER_CS, m_intrinsics->read_msr32(IA32_SYSENTER_CS_MSR));

    // unused: VMCS_GUEST_INTERRUPTIBILITY_STATE
    // unused: VMCS_GUEST_ACTIVITY_STATE
    // unused: VMCS_GUEST_SMBASE
    // unused: VMCS_VMX_PREEMPTION_TIMER_VALUE

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_32bit_host_state_fields()
{
    vmwrite(VMCS_HOST_IA32_SYSENTER_CS, m_intrinsics->read_msr32(IA32_SYSENTER_CS_MSR));

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_natural_width_control_fields()
{
    // unused: VMCS_CR0_GUEST_HOST_MASK
    // unused: VMCS_CR4_GUEST_HOST_MASK
    // unused: VMCS_CR0_READ_SHADOW
    // unused: VMCS_CR4_READ_SHADOW
    // unused: VMCS_CR3_TARGET_VALUE_0
    // unused: VMCS_CR3_TARGET_VALUE_1
    // unused: VMCS_CR3_TARGET_VALUE_2
    // unused: VMCS_CR3_TARGET_VALUE_31

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_natural_width_guest_state_fields()
{
    vmwrite(VMCS_GUEST_CR0, m_cr0);
    vmwrite(VMCS_GUEST_CR3, m_cr3);
    vmwrite(VMCS_GUEST_CR4, m_cr4);
    vmwrite(VMCS_GUEST_ES_BASE, m_es_base);
    vmwrite(VMCS_GUEST_CS_BASE, m_cs_base);
    vmwrite(VMCS_GUEST_SS_BASE, m_ss_base);
    vmwrite(VMCS_GUEST_DS_BASE, m_ds_base);
    vmwrite(VMCS_GUEST_FS_BASE, m_fs_base);
    vmwrite(VMCS_GUEST_GS_BASE, m_gs_base);
    vmwrite(VMCS_GUEST_LDTR_BASE, m_ldtr_base);
    vmwrite(VMCS_GUEST_TR_BASE, m_tr_base);

    vmwrite(VMCS_GUEST_GDTR_BASE, m_gdt_reg.base);
    vmwrite(VMCS_GUEST_IDTR_BASE, m_idt_reg.base);

    vmwrite(VMCS_GUEST_RFLAGS, m_rflags);

    vmwrite(VMCS_GUEST_IA32_SYSENTER_ESP, m_intrinsics->read_msr32(IA32_SYSENTER_ESP_MSR));
    vmwrite(VMCS_GUEST_IA32_SYSENTER_EIP, m_intrinsics->read_msr32(IA32_SYSENTER_EIP_MSR));

    // unused: VMCS_GUEST_DR7
    // unused: VMCS_GUEST_RSP, see launch_vmcs()
    // unused: VMCS_GUEST_RIP, see launch_vmcs()
    // unused: VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::write_natural_width_host_state_fields()
{
    vmwrite(VMCS_HOST_CR0, m_cr0);
    vmwrite(VMCS_HOST_CR3, m_cr3);
    vmwrite(VMCS_HOST_CR4, m_cr4);
    vmwrite(VMCS_HOST_FS_BASE, m_fs_base);
    vmwrite(VMCS_HOST_GS_BASE, m_gs_base);
    vmwrite(VMCS_HOST_TR_BASE, m_tr_base);

    vmwrite(VMCS_HOST_GDTR_BASE, m_gdt_reg.base);
    vmwrite(VMCS_HOST_IDTR_BASE, m_idt_reg.base);

    vmwrite(VMCS_HOST_RSP, (uint64_t)exit_handler_stack());
    vmwrite(VMCS_HOST_RIP, (uint64_t)exit_handler);

    vmwrite(VMCS_HOST_IA32_SYSENTER_ESP, m_intrinsics->read_msr32(IA32_SYSENTER_ESP_MSR));
    vmwrite(VMCS_HOST_IA32_SYSENTER_EIP, m_intrinsics->read_msr32(IA32_SYSENTER_EIP_MSR));

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::default_pin_based_vm_execution_controls()
{
    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::default_primary_processor_based_vm_execution_controls()
{
    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::default_secondary_processor_based_vm_execution_controls()
{
    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::default_vm_exit_controls()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    controls |= VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE;
    controls |= VM_EXIT_CONTROL_SAVE_IA32_EFER;
    controls |= VM_EXIT_CONTROL_LOAD_IA32_EFER;

    vmwrite(VMCS_VM_EXIT_CONTROLS, controls);

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::default_vm_entry_controls()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    controls |= VM_ENTRY_CONTROL_IA_32E_MODE_GUEST;
    controls |= VM_ENTRY_CONTROL_LOAD_IA32_EFER;

    vmwrite(VMCS_VM_ENTRY_CONTROLS, controls);

    return vmcs_error::success;
}

void
vmcs_intel_x64::vmwrite(uint64_t field, uint64_t value)
{
    if (m_intrinsics->vmwrite(field, value) == false)
    {
        std::cout << std::hex;
        std::cout << "vmwrite failed: "
                  << "field = " << field << ", "
                  << "value = " << value << std::endl;
        std::cout << std::dec;

        m_valid = false;
    }
}

uint64_t
vmcs_intel_x64::vmread(uint64_t field)
{
    uint64_t value = 0;

    if (m_intrinsics->vmread(field, &value) == false)
    {
        std::cout << std::hex;
        std::cout << "vmread failed: "
                  << "field = " << field << ", "
                  << "value = " << value << std::endl;
        std::cout << std::dec;

        m_valid = false;
    }

    return value;
}
