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

#ifndef VMCS_INTEL_X64_H
#define VMCS_INTEL_X64_H

#include <memory>
#include <vmcs/vmcs_intel_x64_state.h>
#include <intrinsics/intrinsics_intel_x64.h>

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
    vmcs_intel_x64(const std::shared_ptr<intrinsics_intel_x64> &intrinsics = nullptr);

    /// Destructor
    ///
    virtual ~vmcs_intel_x64() {}

    /// Launch
    ///
    /// Launches the VMCS. Note that this will create a new guest VM when
    /// it is complete. If this function is run more than once, it will clear
    /// the VMCS and it's state, starting the VM over again. For this reason
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
    /// whenever the eixt handler needs to execute a VM. Note that there are
    /// two different times that this might happen: when the exit handler is
    /// done emulating an instruction and needs to return back to the VM,
    /// or it is time to schedule a different VM to execute (that has
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
    ///       for this is, GCC was optimizing errors in it's implementation
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
    virtual void release_vmcs_region();

    virtual void create_exit_handler_stack();
    virtual void release_exit_handler_stack();

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

    virtual uint64_t vmread(uint64_t field) const;
    virtual void vmwrite(uint64_t field, uint64_t value);

    virtual void filter_unsupported(uint64_t msr, uint64_t &ctrl);

protected:

    virtual void dump_vmcs();

    virtual void print_execution_controls();
    virtual void print_pin_based_vm_execution_controls();
    virtual void print_primary_processor_based_vm_execution_controls();
    virtual void print_secondary_processor_based_vm_execution_controls();
    virtual void print_vm_exit_control_fields();
    virtual void print_vm_entry_control_fields();

    virtual std::string get_vm_instruction_error();

    virtual uint64_t get_pin_ctls() const;
    virtual uint64_t get_proc_ctls() const;
    virtual uint64_t get_proc2_ctls() const;
    virtual uint64_t get_exit_ctls() const;
    virtual uint64_t get_entry_ctls() const;

    virtual bool is_address_canonical(uint64_t addr);
    virtual bool is_linear_address_valid(uint64_t addr);
    virtual bool is_physical_address_valid(uint64_t addr);

    virtual bool is_cs_usable();
    virtual bool is_ss_usable();
    virtual bool is_ds_usable();
    virtual bool is_es_usable();
    virtual bool is_gs_usable();
    virtual bool is_fs_usable();
    virtual bool is_tr_usable();
    virtual bool is_ldtr_usable();

    virtual bool is_enabled_v8086() const;

    virtual bool is_enabled_external_interrupt_exiting() const;
    virtual bool is_enabled_nmi_exiting() const;
    virtual bool is_enabled_virtual_nmis() const;
    virtual bool is_enabled_vmx_preemption_timer() const;
    virtual bool is_enabled_posted_interrupts() const;

    virtual bool is_enabled_interrupt_window_exiting() const;
    virtual bool is_enabled_tsc_offsetting() const;
    virtual bool is_enabled_hlt_exiting() const;
    virtual bool is_enabled_invlpg_exiting() const;
    virtual bool is_enabled_mwait_exiting() const;
    virtual bool is_enabled_rdpmc_exiting() const;
    virtual bool is_enabled_rdtsc_exiting() const;
    virtual bool is_enabled_cr3_load_exiting() const;
    virtual bool is_enabled_cr3_store_exiting() const;
    virtual bool is_enabled_cr8_load_exiting() const;
    virtual bool is_enabled_cr8_store_exiting() const;
    virtual bool is_enabled_tpr_shadow() const;
    virtual bool is_enabled_nmi_window_exiting() const;
    virtual bool is_enabled_mov_dr_exiting() const;
    virtual bool is_enabled_unconditional_io_exiting() const;
    virtual bool is_enabled_io_bitmaps() const;
    virtual bool is_enabled_monitor_trap_flag() const;
    virtual bool is_enabled_msr_bitmaps() const;
    virtual bool is_enabled_monitor_exiting() const;
    virtual bool is_enabled_pause_exiting() const;
    virtual bool is_enabled_secondary_controls() const;

    virtual bool is_enabled_virtualized_apic() const;
    virtual bool is_enabled_ept() const;
    virtual bool is_enabled_descriptor_table_exiting() const;
    virtual bool is_enabled_rdtscp() const;
    virtual bool is_enabled_x2apic_mode() const;
    virtual bool is_enabled_vpid() const;
    virtual bool is_enabled_wbinvd_exiting() const;
    virtual bool is_enabled_unrestricted_guests() const;
    virtual bool is_enabled_apic_register_virtualization() const;
    virtual bool is_enabled_virtual_interrupt_delivery() const;
    virtual bool is_enabled_pause_loop_exiting() const;
    virtual bool is_enabled_rdrand_exiting() const;
    virtual bool is_enabled_invpcid() const;
    virtual bool is_enabled_vm_functions() const;
    virtual bool is_enabled_vmcs_shadowing() const;
    virtual bool is_enabled_rdseed_exiting() const;
    virtual bool is_enabled_ept_violation_ve() const;
    virtual bool is_enabled_xsave_xrestore() const;

    virtual bool is_enabled_save_debug_controls_on_exit() const;
    virtual bool is_enabled_host_address_space_size() const;
    virtual bool is_enabled_load_ia32_perf_global_ctrl_on_exit() const;
    virtual bool is_enabled_ack_interrupt_on_exit() const;
    virtual bool is_enabled_save_ia32_pat_on_exit() const;
    virtual bool is_enabled_load_ia32_pat_on_exit() const;
    virtual bool is_enabled_save_ia32_efer_on_exit() const;
    virtual bool is_enabled_load_ia32_efer_on_exit() const;
    virtual bool is_enabled_save_vmx_preemption_timer_on_exit() const;

    virtual bool is_enabled_load_debug_controls_on_entry() const;
    virtual bool is_enabled_ia_32e_mode_guest() const;
    virtual bool is_enabled_entry_to_smm() const;
    virtual bool is_enabled_deactivate_dual_monitor_treatment() const;
    virtual bool is_enabled_load_ia32_perf_global_ctrl_on_entry() const;
    virtual bool is_enabled_load_ia32_pat_on_entry() const;
    virtual bool is_enabled_load_ia32_efer_on_entry() const;

    virtual bool is_supported_external_interrupt_exiting() const;
    virtual bool is_supported_nmi_exiting() const;
    virtual bool is_supported_virtual_nmis() const;
    virtual bool is_supported_vmx_preemption_timer() const;
    virtual bool is_supported_posted_interrupts() const;

    virtual bool is_supported_interrupt_window_exiting() const;
    virtual bool is_supported_tsc_offsetting() const;
    virtual bool is_supported_hlt_exiting() const;
    virtual bool is_supported_invlpg_exiting() const;
    virtual bool is_supported_mwait_exiting() const;
    virtual bool is_supported_rdpmc_exiting() const;
    virtual bool is_supported_rdtsc_exiting() const;
    virtual bool is_supported_cr3_load_exiting() const;
    virtual bool is_supported_cr3_store_exiting() const;
    virtual bool is_supported_cr8_load_exiting() const;
    virtual bool is_supported_cr8_store_exiting() const;
    virtual bool is_supported_tpr_shadow() const;
    virtual bool is_supported_nmi_window_exiting() const;
    virtual bool is_supported_mov_dr_exiting() const;
    virtual bool is_supported_unconditional_io_exiting() const;
    virtual bool is_supported_io_bitmaps() const;
    virtual bool is_supported_monitor_trap_flag() const;
    virtual bool is_supported_msr_bitmaps() const;
    virtual bool is_supported_monitor_exiting() const;
    virtual bool is_supported_pause_exiting() const;
    virtual bool is_supported_secondary_controls() const;

    virtual bool is_supported_virtualized_apic() const;
    virtual bool is_supported_ept() const;
    virtual bool is_supported_descriptor_table_exiting() const;
    virtual bool is_supported_rdtscp() const;
    virtual bool is_supported_x2apic_mode() const;
    virtual bool is_supported_vpid() const;
    virtual bool is_supported_wbinvd_exiting() const;
    virtual bool is_supported_unrestricted_guests() const;
    virtual bool is_supported_apic_register_virtualization() const;
    virtual bool is_supported_virtual_interrupt_delivery() const;
    virtual bool is_supported_pause_loop_exiting() const;
    virtual bool is_supported_rdrand_exiting() const;
    virtual bool is_supported_invpcid() const;
    virtual bool is_supported_vm_functions() const;
    virtual bool is_supported_vmcs_shadowing() const;
    virtual bool is_supported_rdseed_exiting() const;
    virtual bool is_supported_ept_violation_ve() const;
    virtual bool is_supported_xsave_xrestore() const;

    virtual bool is_supported_save_debug_controls_on_exit() const;
    virtual bool is_supported_host_address_space_size() const;
    virtual bool is_supported_load_ia32_perf_global_ctrl_on_exit() const;
    virtual bool is_supported_ack_interrupt_on_exit() const;
    virtual bool is_supported_save_ia32_pat_on_exit() const;
    virtual bool is_supported_load_ia32_pat_on_exit() const;
    virtual bool is_supported_save_ia32_efer_on_exit() const;
    virtual bool is_supported_load_ia32_efer_on_exit() const;
    virtual bool is_supported_save_vmx_preemption_timer_on_exit() const;

    virtual bool is_supported_load_debug_controls_on_entry() const;
    virtual bool is_supported_ia_32e_mode_guest() const;
    virtual bool is_supported_entry_to_smm() const;
    virtual bool is_supported_deactivate_dual_monitor_treatment() const;
    virtual bool is_supported_load_ia32_perf_global_ctrl_on_entry() const;
    virtual bool is_supported_load_ia32_pat_on_entry() const;
    virtual bool is_supported_load_ia32_efer_on_entry() const;

    virtual bool is_supported_eptp_switching() const;

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
    virtual void check_guest_cs_access_rights_remaining_reserved_bit_0();
    virtual void check_guest_ss_access_rights_remaining_reserved_bit_0();
    virtual void check_guest_ds_access_rights_remaining_reserved_bit_0();
    virtual void check_guest_es_access_rights_remaining_reserved_bit_0();
    virtual void check_guest_fs_access_rights_remaining_reserved_bit_0();
    virtual void check_guest_gs_access_rights_remaining_reserved_bit_0();
    virtual void check_guest_tr_type_must_be_11();
    virtual void check_guest_tr_must_be_a_system_descriptor();
    virtual void check_guest_tr_must_be_present();
    virtual void check_guest_tr_access_rights_reserved_must_be_0();
    virtual void check_guest_tr_granularity();
    virtual void check_guest_tr_must_be_usable();
    virtual void check_guest_tr_access_rights_remaining_reserved_bit_0();
    virtual void check_guest_ldtr_type_must_be_2();
    virtual void check_guest_ldtr_must_be_a_system_descriptor();
    virtual void check_guest_ldtr_must_be_present();
    virtual void check_guest_ldtr_access_rights_reserved_must_be_0();
    virtual void check_guest_ldtr_granularity();
    virtual void check_guest_ldtr_access_rights_remaining_reserved_bit_0();

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
    virtual void check_guest_interruptability_state_reserved();
    virtual void check_guest_interruptability_state_sti_mov_ss();
    virtual void check_guest_interruptability_state_sti();
    virtual void check_guest_interruptability_state_external_interrupt();
    virtual void check_guest_interruptability_state_nmi();
    virtual void check_guest_interruptability_not_in_smm();
    virtual void check_guest_interruptability_entry_to_smm();
    virtual void check_guest_interruptability_state_sti_and_nmi();
    virtual void check_guest_interruptability_state_virtual_nmi();
    virtual void check_guest_pending_debug_exceptions_reserved();
    virtual void check_guest_pending_debug_exceptions_dbg_ctl();
    virtual void check_guest_vmcs_link_pointer_bits_11_0();
    virtual void check_guest_vmcs_link_pointer_valid_addr();
    virtual void check_guest_vmcs_link_pointer_first_word();
    virtual void check_guest_vmcs_link_pointer_not_in_smm();
    virtual void check_guest_vmcs_link_pointer_in_smm();

    virtual void checks_on_vm_execution_control_fields();
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

    virtual void checks_on_vm_exit_control_fields();
    virtual void check_control_vm_exit_ctls_reserved_properly_set();
    virtual void check_control_activate_and_save_premeption_timer_must_be_0();
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

    friend class vmcs_ut;
    friend class vcpu_intel_x64;
    friend class exit_handler_intel_x64;

    std::shared_ptr<intrinsics_intel_x64> m_intrinsics;

    uint64_t m_vmcs_region_phys;
    std::unique_ptr<uint32_t> m_vmcs_region;

    std::unique_ptr<char[]> m_exit_handler_stack;
    std::shared_ptr<state_save_intel_x64> m_state_save;

private:

    void set_state_save(const std::shared_ptr<state_save_intel_x64> &state_save)
    { m_state_save = state_save; }
};

#endif
