//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_H
#define VMCS_INTEL_X64_H

#include <type_traits>
#include <vmcs/vmcs_intel_x64_state.h>
#include <exit_handler/state_save_intel_x64.h>

#include <intrinsics/vmx_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>


/// Intel x86_64 VMCS
///
/// The following provides the basic VMCS implementation as defined by the
/// Intel Software Developer's Manual (chapters 24-33). To best understand
/// this code, the manual should first be read.
///
/// This class provides the bare minimum to get a virtual machine to execute.
/// It assumes a 64bit VMM, and a 64bit guest. It does not trap on anything
/// by default, and thus the guest is allowed to execute unfettered. If
/// an error should occur, it contains the logic needed to help identify the
/// issue, including a complete implementation of chapter 26 in the Intel
/// manual, that describes all of the checks the CPU will perform prior to
/// a VM launch.
///
/// To use this class, subclass vmcs_intel_x64, and overload the protected
/// functions for setting up the guest / host state to provide the desired
/// functionality. Don't forget to call the base class function when complete
/// unless you intend to provide the same functionality. For an example of
/// how to do this, please see:
///
/// <a href="https://github.com/Bareflank/hypervisor_example_vpid">Bareflank Hypervisor VPID Example</a>
///
/// @note This VMCS does not support SMM / Dual Monitor Mode, and the missing
/// logic will have to be provided by the user if such support is needed.
///
/// This class is managed by vcpu_intel_x64
///
class vmcs_intel_x64
{
public:

    /// Default Constructor
    ///
    vmcs_intel_x64();

    /// Destructor
    ///
    virtual ~vmcs_intel_x64() = default;

    /// Launch
    ///
    /// Launches the VMCS. Note that this will create a new guest VM when
    /// it is complete. If this function is run more than once, it will clear
    /// the VMCS and its state, starting the VM over again. For this reason
    /// it should only be called once, unless you intend to clear the VM.
    ///
    /// @throws invalid_vmcs thrown if the VMCS was created without
    ///     intrinsics
    ///
    virtual void launch(const std::shared_ptr<vmcs_intel_x64_state> &host_state,
                        const std::shared_ptr<vmcs_intel_x64_state> &guest_state);

    /// Resume
    ///
    /// Resumes the VMCS. Note that this should only be called after a launch,
    /// otherwise the system will crash. This function should be called
    /// whenever the exit handler needs to execute a VM. Note that there are
    /// two different times that this might happen: when the exit handler is
    /// done emulating an instruction and needs to return back to the VM,
    /// or it's time to schedule a different VM to execute (that has
    /// obviously already been launched)
    ///
    /// @note if you are going to resume a VMCS, you must make sure that
    ///       VMCS has been loaded first. Otherwise, you will end up resuming
    ///       the currently loaded VMCS with a different state save area. We
    ///       don't check for this issue as it would require us to query
    ///       VMX for the currently loaded VMCS which is slow, and it's likely
    ///       this function will get executed a lot.
    ///
    /// @note this function is implemented mainly in assembly as we need to
    ///       restore the register state very carefully.
    ///
    virtual void resume();

    /// Promote
    ///
    /// Promotes this guest to VMX root. This is used to transition out of
    /// VMX operation as the guest that this VMCS defines is likely about to
    /// disable VMX operation, and needs to be in VMX root to do so. Note
    /// that this function doesn't actually return if it is successful.
    /// Instead, the CPU resumes execution on the last instruction executed
    /// by the guest.
    ///
    /// @note this function is mainly implemented in raw assembly. The reason
    ///       for this is, GCC was optimizing errors in its implementation
    ///       when "-O3" was enabled. The order of each instruction is very
    ///       important
    ///
    virtual void promote();

    /// Load
    ///
    /// The main purpose of this function is to execute VMPTRLD. Specifically,
    /// this function loads the VMCS that this class contains into the CPU.
    /// There are two different times that this is mainly needed. When the
    /// VMCS is first created, a VM launch is needed to get this VMCS up and
    /// running. Before the launch can occur, the VMCS needs to be loaded so
    /// that vm reads / writes are successful (as the CPU needs to know which
    /// VMCS to read / write to). Once a launch has been done, the VMCS
    /// contains the VM's state. The next time it needs to be run, a VMRESUME
    /// must be executed. Once gain, the CPU needs to know which VMCS to use,
    /// and thus a load is needed.
    ///
    virtual void load();

    /// Clear
    ///
    /// Clears the VMCS. This should only be needed before a VM launch. But
    /// can be used to "reset" a guest prior to launching it again. If you
    /// run a clear, you must run load again as the clear will remove the
    /// valid bit in the VMCS, rendering future reads / writes to this VMCS
    /// invalid.
    ///
    virtual void clear();

protected:

    virtual void create_vmcs_region();
    virtual void release_vmcs_region() noexcept;

    virtual void create_exit_handler_stack();
    virtual void release_exit_handler_stack() noexcept;

    virtual void write_16bit_control_state(const std::shared_ptr<vmcs_intel_x64_state> &state);
    virtual void write_64bit_control_state(const std::shared_ptr<vmcs_intel_x64_state> &state);
    virtual void write_32bit_control_state(const std::shared_ptr<vmcs_intel_x64_state> &state);
    virtual void write_natural_control_state(const std::shared_ptr<vmcs_intel_x64_state> &state);

    virtual void write_16bit_guest_state(const std::shared_ptr<vmcs_intel_x64_state> &state);
    virtual void write_64bit_guest_state(const std::shared_ptr<vmcs_intel_x64_state> &state);
    virtual void write_32bit_guest_state(const std::shared_ptr<vmcs_intel_x64_state> &state);
    virtual void write_natural_guest_state(const std::shared_ptr<vmcs_intel_x64_state> &state);

    virtual void write_16bit_host_state(const std::shared_ptr<vmcs_intel_x64_state> &state);
    virtual void write_64bit_host_state(const std::shared_ptr<vmcs_intel_x64_state> &state);
    virtual void write_32bit_host_state(const std::shared_ptr<vmcs_intel_x64_state> &state);
    virtual void write_natural_host_state(const std::shared_ptr<vmcs_intel_x64_state> &state);

    virtual void pin_based_vm_execution_controls();
    virtual void primary_processor_based_vm_execution_controls();
    virtual void secondary_processor_based_vm_execution_controls();
    virtual void vm_exit_controls();
    virtual void vm_entry_controls();

protected:

    // REMOVE ME: These should be placed in their own check class and
    // created on error instead of being in the VMCS itself which increases
    // the size of the vTable.
    virtual void check_vmcs_host_state();
    virtual void check_vmcs_guest_state();
    virtual void check_vmcs_control_state();

    virtual void check_host_control_registers_and_msrs();
    virtual void check_host_cr0_for_unsupported_bits();
    virtual void check_host_cr4_for_unsupported_bits();
    virtual void check_host_cr3_for_unsupported_bits();
    virtual void check_host_ia32_sysenter_esp_canonical_address();
    virtual void check_host_ia32_sysenter_eip_canonical_address();
    virtual void check_host_verify_load_ia32_perf_global_ctrl();
    virtual void check_host_verify_load_ia32_pat();
    virtual void check_host_verify_load_ia32_efer();

    virtual void check_host_segment_and_descriptor_table_registers();
    virtual void check_host_es_selector_rpl_ti_equal_zero();
    virtual void check_host_cs_selector_rpl_ti_equal_zero();
    virtual void check_host_ss_selector_rpl_ti_equal_zero();
    virtual void check_host_ds_selector_rpl_ti_equal_zero();
    virtual void check_host_fs_selector_rpl_ti_equal_zero();
    virtual void check_host_gs_selector_rpl_ti_equal_zero();
    virtual void check_host_tr_selector_rpl_ti_equal_zero();
    virtual void check_host_cs_not_equal_zero();
    virtual void check_host_tr_not_equal_zero();
    virtual void check_host_ss_not_equal_zero();
    virtual void check_host_fs_canonical_base_address();
    virtual void check_host_gs_canonical_base_address();
    virtual void check_host_gdtr_canonical_base_address();
    virtual void check_host_idtr_canonical_base_address();
    virtual void check_host_tr_canonical_base_address();

    virtual void check_host_checks_related_to_address_space_size();
    virtual void check_host_if_outside_ia32e_mode();
    virtual void check_host_vmcs_host_address_space_size_is_set();
    virtual void check_host_host_address_space_disabled();
    virtual void check_host_host_address_space_enabled();

    virtual void checks_on_guest_control_registers_debug_registers_and_msrs();
    virtual void check_guest_cr0_for_unsupported_bits();
    virtual void check_guest_cr0_verify_paging_enabled();
    virtual void check_guest_cr4_for_unsupported_bits();
    virtual void check_guest_load_debug_controls_verify_reserved();
    virtual void check_guest_verify_ia_32e_mode_enabled();
    virtual void check_guest_verify_ia_32e_mode_disabled();
    virtual void check_guest_cr3_for_unsupported_bits();
    virtual void check_guest_load_debug_controls_verify_dr7();
    virtual void check_guest_ia32_sysenter_esp_canonical_address();
    virtual void check_guest_ia32_sysenter_eip_canonical_address();
    virtual void check_guest_verify_load_ia32_perf_global_ctrl();
    virtual void check_guest_verify_load_ia32_pat();
    virtual void check_guest_verify_load_ia32_efer();

    virtual void checks_on_guest_segment_registers();
    virtual void check_guest_tr_ti_bit_equals_0();
    virtual void check_guest_ldtr_ti_bit_equals_0();
    virtual void check_guest_ss_and_cs_rpl_are_the_same();
    virtual void check_guest_cs_base_is_shifted();
    virtual void check_guest_ss_base_is_shifted();
    virtual void check_guest_ds_base_is_shifted();
    virtual void check_guest_es_base_is_shifted();
    virtual void check_guest_fs_base_is_shifted();
    virtual void check_guest_gs_base_is_shifted();
    virtual void check_guest_tr_base_is_canonical();
    virtual void check_guest_fs_base_is_canonical();
    virtual void check_guest_gs_base_is_canonical();
    virtual void check_guest_ldtr_base_is_canonical();
    virtual void check_guest_cs_base_upper_dword_0();
    virtual void check_guest_ss_base_upper_dword_0();
    virtual void check_guest_ds_base_upper_dword_0();
    virtual void check_guest_es_base_upper_dword_0();
    virtual void check_guest_cs_limit();
    virtual void check_guest_ss_limit();
    virtual void check_guest_ds_limit();
    virtual void check_guest_es_limit();
    virtual void check_guest_gs_limit();
    virtual void check_guest_fs_limit();
    virtual void check_guest_v8086_cs_access_rights();
    virtual void check_guest_v8086_ss_access_rights();
    virtual void check_guest_v8086_ds_access_rights();
    virtual void check_guest_v8086_es_access_rights();
    virtual void check_guest_v8086_fs_access_rights();
    virtual void check_guest_v8086_gs_access_rights();
    virtual void check_guest_cs_access_rights_type();
    virtual void check_guest_ss_access_rights_type();
    virtual void check_guest_ds_access_rights_type();
    virtual void check_guest_es_access_rights_type();
    virtual void check_guest_fs_access_rights_type();
    virtual void check_guest_gs_access_rights_type();
    virtual void check_guest_cs_is_not_a_system_descriptor();
    virtual void check_guest_ss_is_not_a_system_descriptor();
    virtual void check_guest_ds_is_not_a_system_descriptor();
    virtual void check_guest_es_is_not_a_system_descriptor();
    virtual void check_guest_fs_is_not_a_system_descriptor();
    virtual void check_guest_gs_is_not_a_system_descriptor();
    virtual void check_guest_cs_type_not_equal_3();
    virtual void check_guest_cs_dpl_adheres_to_ss_dpl();
    virtual void check_guest_ss_dpl_must_equal_rpl();
    virtual void check_guest_ss_dpl_must_equal_zero();
    virtual void check_guest_ds_dpl();
    virtual void check_guest_es_dpl();
    virtual void check_guest_fs_dpl();
    virtual void check_guest_gs_dpl();
    virtual void check_guest_cs_must_be_present();
    virtual void check_guest_ss_must_be_present_if_usable();
    virtual void check_guest_ds_must_be_present_if_usable();
    virtual void check_guest_es_must_be_present_if_usable();
    virtual void check_guest_fs_must_be_present_if_usable();
    virtual void check_guest_gs_must_be_present_if_usable();
    virtual void check_guest_cs_access_rights_reserved_must_be_0();
    virtual void check_guest_ss_access_rights_reserved_must_be_0();
    virtual void check_guest_ds_access_rights_reserved_must_be_0();
    virtual void check_guest_es_access_rights_reserved_must_be_0();
    virtual void check_guest_fs_access_rights_reserved_must_be_0();
    virtual void check_guest_gs_access_rights_reserved_must_be_0();
    virtual void check_guest_cs_db_must_be_0_if_l_equals_1();
    virtual void check_guest_cs_granularity();
    virtual void check_guest_ss_granularity();
    virtual void check_guest_ds_granularity();
    virtual void check_guest_es_granularity();
    virtual void check_guest_fs_granularity();
    virtual void check_guest_gs_granularity();
    virtual void check_guest_tr_type_must_be_11();
    virtual void check_guest_tr_must_be_a_system_descriptor();
    virtual void check_guest_tr_must_be_present();
    virtual void check_guest_tr_access_rights_reserved_must_be_0();
    virtual void check_guest_tr_granularity();
    virtual void check_guest_tr_must_be_usable();
    virtual void check_guest_ldtr_type_must_be_2();
    virtual void check_guest_ldtr_must_be_a_system_descriptor();
    virtual void check_guest_ldtr_must_be_present();
    virtual void check_guest_ldtr_access_rights_reserved_must_be_0();
    virtual void check_guest_ldtr_granularity();

    virtual void checks_on_guest_descriptor_table_registers();
    virtual void check_guest_gdtr_base_must_be_canonical();
    virtual void check_guest_idtr_base_must_be_canonical();
    virtual void check_guest_gdtr_limit_reserved_bits();
    virtual void check_guest_idtr_limit_reserved_bits();

    virtual void checks_on_guest_rip_and_rflags();
    virtual void check_guest_rip_upper_bits();
    virtual void check_guest_rip_valid_addr();
    virtual void check_guest_rflags_reserved_bits();
    virtual void check_guest_rflags_vm_bit();
    virtual void check_guest_rflag_interrupt_enable();

    virtual void checks_on_guest_non_register_state();
    virtual void check_guest_valid_activity_state();
    virtual void check_guest_activity_state_not_hlt_when_dpl_not_0();
    virtual void check_guest_must_be_active_if_injecting_blocking_state();
    virtual void check_guest_hlt_valid_interrupts();
    virtual void check_guest_shutdown_valid_interrupts();
    virtual void check_guest_sipi_valid_interrupts();
    virtual void check_guest_valid_activity_state_and_smm();
    virtual void check_guest_interruptibility_state_reserved();
    virtual void check_guest_interruptibility_state_sti_mov_ss();
    virtual void check_guest_interruptibility_state_sti();
    virtual void check_guest_interruptibility_state_external_interrupt();
    virtual void check_guest_interruptibility_state_nmi();
    virtual void check_guest_interruptibility_not_in_smm();
    virtual void check_guest_interruptibility_entry_to_smm();
    virtual void check_guest_interruptibility_state_sti_and_nmi();
    virtual void check_guest_interruptibility_state_virtual_nmi();
    virtual void check_guest_pending_debug_exceptions_reserved();
    virtual void check_guest_pending_debug_exceptions_dbg_ctl();
    virtual void check_guest_vmcs_link_pointer_bits_11_0();
    virtual void check_guest_vmcs_link_pointer_valid_addr();
    virtual void check_guest_vmcs_link_pointer_first_word();
    virtual void check_guest_vmcs_link_pointer_not_in_smm();
    virtual void check_guest_vmcs_link_pointer_in_smm();

    virtual void checks_on_vm_execution_control_fields();
    virtual void check_control_ctls_reserved_properly_set(uint64_t msr_addr, uint64_t ctls, const std::string &ctls_name);
    virtual void check_control_pin_based_ctls_reserved_properly_set();
    virtual void check_control_proc_based_ctls_reserved_properly_set();
    virtual void check_control_proc_based_ctls2_reserved_properly_set();
    virtual void check_control_cr3_count_less_then_4();
    virtual void check_control_io_bitmap_address_bits();
    virtual void check_control_msr_bitmap_address_bits();
    virtual void check_control_tpr_shadow_and_virtual_apic();
    virtual void check_control_nmi_exiting_and_virtual_nmi();
    virtual void check_control_virtual_nmi_and_nmi_window();
    virtual void check_control_virtual_apic_address_bits();
    virtual void check_control_x2apic_mode_and_virtual_apic_access();
    virtual void check_control_virtual_interrupt_and_external_interrupt();
    virtual void check_control_process_posted_interrupt_checks();
    virtual void check_control_vpid_checks();
    virtual void check_control_enable_ept_checks();
    virtual void check_control_unrestricted_guests();
    virtual void check_control_enable_vm_functions();
    virtual void check_control_enable_vmcs_shadowing();
    virtual void check_control_enable_ept_violation_checks();
    virtual void check_control_enable_pml_checks();

    virtual void checks_on_vm_exit_control_fields();
    virtual void check_control_vm_exit_ctls_reserved_properly_set();
    virtual void check_control_activate_and_save_preemption_timer_must_be_0();
    virtual void check_control_exit_msr_store_address();
    virtual void check_control_exit_msr_load_address();

    virtual void checks_on_vm_entry_control_fields();
    virtual void check_control_vm_entry_ctls_reserved_properly_set();
    virtual void check_control_event_injection_type_vector_checks();
    virtual void check_control_event_injection_delivery_ec_checks();
    virtual void check_control_event_injection_reserved_bits_checks();
    virtual void check_control_event_injection_ec_checks();
    virtual void check_control_event_injection_instr_length_checks();
    virtual void check_control_entry_msr_load_address();

    virtual bool check_pat(uint64_t pat);

protected:

    friend class vcpu_ut;
    friend class vmcs_ut;
    friend class vcpu_intel_x64;
    friend class exit_handler_intel_x64;
    friend class exit_handler_intel_x64_ut;

    uintptr_t m_vmcs_region_phys;
    std::unique_ptr<uint32_t[]> m_vmcs_region;

    std::unique_ptr<char[]> m_exit_handler_stack;
    std::shared_ptr<state_save_intel_x64> m_state_save;

private:

    virtual void set_state_save(const std::shared_ptr<state_save_intel_x64> &state_save)
    { m_state_save = state_save; }
};

template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
auto get_vmcs_field(T addr, const char *name, bool exists)
{
    if (!exists)
        throw std::logic_error("get_vmcs_field failed: "_s + name + " field doesn't exist");

    return intel_x64::vm::read(addr, name);
}

template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
auto get_vmcs_field_if_exists(T addr, const char *name, bool verbose, bool exists)
{
    if (exists)
        return intel_x64::vm::read(addr, name);

    if (!exists && verbose)
        bfwarning << "get_vmcs_field_if_exists failed: " << name << " field doesn't exist" << bfendl;

    return 0UL;
}

template <class V, class A,
          class = typename std::enable_if<std::is_integral<V>::value>::type,
          class = typename std::enable_if<std::is_integral<A>::value>::type>
auto set_vmcs_field(V val, A addr, const char *name, bool exists)
{
    if (!exists)
        throw std::logic_error("set_vmcs_field failed: "_s + name + " field doesn't exist");

    intel_x64::vm::write(addr, val, name);
}

template <class V, class A,
          class = typename std::enable_if<std::is_integral<V>::value>::type,
          class = typename std::enable_if<std::is_integral<A>::value>::type>
auto set_vmcs_field_if_exists(V val, A addr, const char *name, bool verbose, bool exists) noexcept
{
    if (exists)
        intel_x64::vm::write(addr, val, name);

    if (!exists && verbose)
        bfwarning << "set_vmcs_field failed: " << name << " field doesn't exist" << bfendl;
}

template <class MA, class CA, class M,
          class = typename std::enable_if<std::is_integral<MA>::value>::type,
          class = typename std::enable_if<std::is_integral<CA>::value>::type,
          class = typename std::enable_if<std::is_integral<M>::value>::type>
auto set_vm_control(bool val, MA msr_addr, CA ctls_addr,
                    const char *name, M mask, bool field_exists)
{
    if (!field_exists)
        throw std::logic_error("set_vm_control failed: "_s + name + " control doesn't exist");

    if (!val)
    {
        auto is_allowed0 = (intel_x64::msrs::get(msr_addr) & mask) == 0;

        if (!is_allowed0)
        {
            throw std::logic_error("set_vm_control failed: "_s + name
                                   + " control is not allowed to be cleared to 0");
        }

        intel_x64::vm::write(ctls_addr, (intel_x64::vm::read(ctls_addr, name) & ~mask), name);
    }
    else
    {
        auto is_allowed1 = (intel_x64::msrs::get(msr_addr) & (mask << 32)) != 0;

        if (!is_allowed1)
        {
            throw std::logic_error("set_vm_control failed: "_s + name
                                   + " control is not allowed to be set to 1");
        }

        intel_x64::vm::write(ctls_addr, (intel_x64::vm::read(ctls_addr, name) | mask), name);
    }
}

template <class MA, class CA, class M,
          class = typename std::enable_if<std::is_integral<MA>::value>::type,
          class = typename std::enable_if<std::is_integral<CA>::value>::type,
          class = typename std::enable_if<std::is_integral<M>::value>::type>
auto set_vm_control_if_allowed(bool val, MA msr_addr, CA ctls_addr, const char *name,
                               M mask, bool verbose, bool field_exists) noexcept
{
    if (!field_exists)
    {
        bfwarning << "set_vm_control_if_allowed failed: " << name << " control doesn't exist" << bfendl;
        return;
    }

    if (!val)
    {
        auto is_allowed0 = (intel_x64::msrs::get(msr_addr) & mask) == 0;

        if (is_allowed0)
        {
            intel_x64::vm::write(ctls_addr, (intel_x64::vm::read(ctls_addr, name) & ~mask), name);
        }
        else
        {
            if (verbose)
            {
                bfwarning << "set_vm_control_if_allowed failed: " << name
                          << "control is not allowed to be cleared to 0" << bfendl;
            }
        }
    }
    else
    {
        auto is_allowed1 = (intel_x64::msrs::get(msr_addr) & (mask << 32)) != 0;

        if (is_allowed1)
        {
            intel_x64::vm::write(ctls_addr, (intel_x64::vm::read(ctls_addr, name) | mask), name);
        }
        else
        {
            if (verbose)
            {
                bfwarning << "set_vm_control_if_allowed failed: " << name
                          << "control is not allowed to be set to 1" << bfendl;
            }
        }
    }
}

namespace intel_x64
{
namespace vmcs
{

using field_type = uint64_t;
using value_type = uint64_t;

}
}

#endif
