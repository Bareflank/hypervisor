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
#include <view_as_pointer.h>
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
    vmcs_intel_x64(std::shared_ptr<intrinsics_intel_x64> intrinsics = nullptr);

    /// Destructor
    ///
    virtual ~vmcs_intel_x64() = default;

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

    virtual uint64_t vmread(uint64_t field) const;
    virtual void vmwrite(uint64_t field, uint64_t value);

    virtual void filter_unsupported(uint32_t msr, uint64_t &ctrl);

protected:

#if 0

    virtual void dump_vmcs();
    virtual void dump_vmcs_16bit_control_state();
    virtual void dump_vmcs_16bit_guest_state();
    virtual void dump_vmcs_16bit_host_state();
    virtual void dump_vmcs_64bit_control_state();
    virtual void dump_vmcs_64bit_readonly_state();
    virtual void dump_vmcs_64bit_guest_state();
    virtual void dump_vmcs_64bit_host_state();
    virtual void dump_vmcs_32bit_control_state();
    virtual void dump_vmcs_32bit_readonly_state();
    virtual void dump_vmcs_32bit_guest_state();
    virtual void dump_vmcs_32bit_host_state();
    virtual void dump_vmcs_natural_control_state();
    virtual void dump_vmcs_natural_readonly_state();
    virtual void dump_vmcs_natural_guest_state();
    virtual void dump_vmcs_natural_host_state();

    virtual void print_execution_controls();
    virtual void print_pin_based_vm_execution_controls();
    virtual void print_primary_processor_based_vm_execution_controls();
    virtual void print_secondary_processor_based_vm_execution_controls();
    virtual void print_vm_exit_control_fields();
    virtual void print_vm_entry_control_fields();

#endif

    virtual std::string get_vm_instruction_error();

    virtual uint64_t get_pin_ctls() const;
    virtual uint64_t get_proc_ctls() const;
    virtual uint64_t get_proc2_ctls() const;
    virtual uint64_t get_exit_ctls() const;
    virtual uint64_t get_entry_ctls() const;

    virtual bool is_address_canonical(uint64_t addr);
    virtual bool is_linear_address_valid(uint64_t addr);
    virtual bool is_physical_address_valid(uint64_t addr);

    // REMOVE ME: This should be moved to the VMCS namespace code into a
    // function called is_usable()
    virtual bool is_cs_usable();
    virtual bool is_ss_usable();
    virtual bool is_ds_usable();
    virtual bool is_es_usable();
    virtual bool is_gs_usable();
    virtual bool is_fs_usable();
    virtual bool is_tr_usable();
    virtual bool is_ldtr_usable();

    // REMOVE ME: All is enabled functions should be removed as they are
    // not needed once we have a get() function for each bit
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
    virtual bool is_enabled_pml() const;

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

    // REMOVE ME: All is_supported functions should be removed as they are
    // not needed once the VMCS fields have their own is_supported
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
    virtual bool is_supported_pml() const;

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
    virtual bool is_supported_event_injection_instr_length_of_0() const;

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

    std::shared_ptr<intrinsics_intel_x64> m_intrinsics;

    uintptr_t m_vmcs_region_phys;
    std::unique_ptr<uint32_t[]> m_vmcs_region;

    std::unique_ptr<char[]> m_exit_handler_stack;
    std::shared_ptr<state_save_intel_x64> m_state_save;

private:

    virtual void set_state_save(const std::shared_ptr<state_save_intel_x64> &state_save)
    { m_state_save = state_save; }
};

// -----------------------------------------------------------------------------
// VMCS Fields
// -----------------------------------------------------------------------------

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

inline uint64_t
vmread(uint64_t field, const std::string &name)
{
    uint64_t value;

    if (!__vmread(field, &value))
    {
        bferror << "vmread failed:" << bfendl;
        bferror << "    - field: " << name << bfendl;

        throw std::runtime_error("vmread failed");
    }

    return value;
}

inline void
vmwrite(uint64_t field, uint64_t value, const std::string &name)
{
    if (!__vmwrite(field, value))
    {
        bferror << "vmwrite failed:" << bfendl;
        bferror << "    - field: " << name << bfendl;
        bferror << "    - value: " << view_as_pointer(value) << bfendl;

        throw std::runtime_error("vmwrite failed");
    }
}

// -----------------------------------------------------------------------------
// 16bit Control Fields
// -----------------------------------------------------------------------------

namespace virtual_processor_identifier
{
    constexpr const auto addr = 0x0000000000000000UL;
    constexpr const auto name = "virtual_processor_identifier";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> constexpr void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return msrs::ia32_vmx_procbased_ctls2::enable_vpid::get() == 1; }
}

namespace posted_interrupt_notification_vector
{
    constexpr const auto addr = 0x0000000000000002UL;
    constexpr const auto name = "posted_interrupt_notification_vector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::get() == 1; }
}

namespace eptp_index
{
    constexpr const auto addr = 0x0000000000000004UL;
    constexpr const auto name = "eptp_index";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::get() == 1; }
}

// -----------------------------------------------------------------------------
// 16bit Guest State Fields
// -----------------------------------------------------------------------------

namespace guest_es_selector
{
    constexpr const auto addr = 0x0000000000000800UL;
    constexpr const auto name = "guest_es_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace guest_cs_selector
{
    constexpr const auto addr = 0x0000000000000802UL;
    constexpr const auto name = "guest_cs_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace guest_ss_selector
{
    constexpr const auto addr = 0x0000000000000804UL;
    constexpr const auto name = "guest_ss_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace guest_ds_selector
{
    constexpr const auto addr = 0x0000000000000806UL;
    constexpr const auto name = "guest_ds_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace guest_fs_selector
{
    constexpr const auto addr = 0x0000000000000808UL;
    constexpr const auto name = "guest_fs_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace guest_gs_selector
{
    constexpr const auto addr = 0x000000000000080AUL;
    constexpr const auto name = "guest_gs_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace guest_ldtr_selector
{
    constexpr const auto addr = 0x000000000000080CUL;
    constexpr const auto name = "guest_ldtr_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace guest_tr_selector
{
    constexpr const auto addr = 0x000000000000080EUL;
    constexpr const auto name = "guest_tr_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace guest_interrupt_status
{
    constexpr const auto addr = 0x0000000000000810UL;
    constexpr const auto name = "guest_interrupt_status";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::get() == 1; }
}

// -----------------------------------------------------------------------------
// 16bit Host State Fields
// -----------------------------------------------------------------------------

namespace host_es_selector
{
    constexpr const auto addr = 0x0000000000000C00UL;
    constexpr const auto name = "host_es_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace host_cs_selector
{
    constexpr const auto addr = 0x0000000000000C02UL;
    constexpr const auto name = "host_cs_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace host_ss_selector
{
    constexpr const auto addr = 0x0000000000000C04UL;
    constexpr const auto name = "host_ss_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace host_ds_selector
{
    constexpr const auto addr = 0x0000000000000C06UL;
    constexpr const auto name = "host_ds_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace host_fs_selector
{
    constexpr const auto addr = 0x0000000000000C08UL;
    constexpr const auto name = "host_fs_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace host_gs_selector
{
    constexpr const auto addr = 0x0000000000000C0AUL;
    constexpr const auto name = "host_gs_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace host_tr_selector
{
    constexpr const auto addr = 0x0000000000000C0CUL;
    constexpr const auto name = "host_tr_selector";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

}
}

// -----------------------------------------------------------------------------
// 64bit Control Fields
// -----------------------------------------------------------------------------

constexpr const auto VMCS_ADDRESS_OF_IO_BITMAP_A                          = 0x0000000000002000UL;
constexpr const auto VMCS_ADDRESS_OF_IO_BITMAP_B                          = 0x0000000000002002UL;
constexpr const auto VMCS_ADDRESS_OF_MSR_BITMAPS                          = 0x0000000000002004UL;
constexpr const auto VMCS_VM_EXIT_MSR_STORE_ADDRESS                       = 0x0000000000002006UL;
constexpr const auto VMCS_VM_EXIT_MSR_LOAD_ADDRESS                        = 0x0000000000002008UL;
constexpr const auto VMCS_VM_ENTRY_MSR_LOAD_ADDRESS                       = 0x000000000000200AUL;
constexpr const auto VMCS_EXECUTIVE_VMCS_POINTER                          = 0x000000000000200CUL;
constexpr const auto VMCS_PML_ADDRESS                                     = 0x000000000000200EUL;
constexpr const auto VMCS_TSC_OFFSET                                      = 0x0000000000002010UL;
constexpr const auto VMCS_VIRTUAL_APIC_ADDRESS                            = 0x0000000000002012UL;
constexpr const auto VMCS_APIC_ACCESS_ADDRESS                             = 0x0000000000002014UL;
constexpr const auto VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS             = 0x0000000000002016UL;
constexpr const auto VMCS_VM_FUNCTION_CONTROLS                            = 0x0000000000002018UL;
constexpr const auto VMCS_EPT_POINTER                                     = 0x000000000000201AUL;
constexpr const auto VMCS_EOI_EXIT_BITMAP_0                               = 0x000000000000201CUL;
constexpr const auto VMCS_EOI_EXIT_BITMAP_1                               = 0x000000000000201EUL;
constexpr const auto VMCS_EOI_EXIT_BITMAP_2                               = 0x0000000000002020UL;
constexpr const auto VMCS_EOI_EXIT_BITMAP_3                               = 0x0000000000002022UL;
constexpr const auto VMCS_EPTP_LIST_ADDRESS                               = 0x0000000000002024UL;
constexpr const auto VMCS_VMREAD_BITMAP_ADDRESS                           = 0x0000000000002026UL;
constexpr const auto VMCS_VMWRITE_BITMAP_ADDRESS                          = 0x0000000000002028UL;
constexpr const auto VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS    = 0x000000000000202AUL;
constexpr const auto VMCS_XSS_EXITING_BITMAP                              = 0x000000000000202CUL;

// -----------------------------------------------------------------------------
// 64bit Read-Only Data Fields
// -----------------------------------------------------------------------------

constexpr const auto VMCS_GUEST_PHYSICAL_ADDRESS                          = 0x0000000000002400UL;

// -----------------------------------------------------------------------------
// 64bit Guest State Fields
// -----------------------------------------------------------------------------

constexpr const auto VMCS_VMCS_LINK_POINTER                               = 0x0000000000002800UL;

namespace intel_x64
{
namespace vmcs
{

namespace guest_ia32_debugctl
{
    constexpr const auto addr = 0x0000000000002802UL;
    constexpr const auto name = "guest_ia32_debugctl";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }

    namespace lbr
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "lbr";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace btf
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "btf";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace tr
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "tr";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace bts
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "bts";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace btint
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "btint";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace bt_off_os
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "bt_off_os";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace bt_off_user
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "bt_off_user";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace freeze_lbrs_on_pmi
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "freeze_lbrs_on_pmi";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace freeze_perfmon_on_pmi
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "freeze_perfmon_on_pmi";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace enable_uncore_pmi
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "enable_uncore_pmi";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace freeze_while_smm
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "freeze_while_smm";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace rtm_debug
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "rtm_debug";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF003CUL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

}
}

constexpr const auto VMCS_GUEST_IA32_PAT                                  = 0x0000000000002804UL;

namespace intel_x64
{
namespace vmcs
{

namespace guest_ia32_efer
{
    constexpr const auto addr = 0x0000000000002806UL;
    constexpr const auto name = "guest_ia32_efer";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::get() == 1; }

    namespace sce
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "sce";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace lme
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "lme";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace lma
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "lma";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace nxe
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "nxe";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFF2FEUL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

}
}

constexpr const auto VMCS_GUEST_IA32_PERF_GLOBAL_CTRL                     = 0x0000000000002808UL;
constexpr const auto VMCS_GUEST_PDPTE0                                    = 0x000000000000280AUL;
constexpr const auto VMCS_GUEST_PDPTE1                                    = 0x000000000000280CUL;
constexpr const auto VMCS_GUEST_PDPTE2                                    = 0x000000000000280EUL;
constexpr const auto VMCS_GUEST_PDPTE3                                    = 0x0000000000002810UL;

// -----------------------------------------------------------------------------
// 64bit Host State Fields
// -----------------------------------------------------------------------------

constexpr const auto VMCS_HOST_IA32_PAT                                   = 0x0000000000002C00UL;

namespace intel_x64
{
namespace vmcs
{

namespace host_ia32_efer
{
    constexpr const auto addr = 0x0000000000002C02UL;
    constexpr const auto name = "host_ia32_efer";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::get() == 1; }

    namespace sce
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "sce";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace lme
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "lme";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace lma
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "lma";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace nxe
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "nxe";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFF2FEUL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

}
}

constexpr const auto VMCS_HOST_IA32_PERF_GLOBAL_CTRL                      = 0x0000000000002C04UL;

// -----------------------------------------------------------------------------
// 32bit Control Fields
// -----------------------------------------------------------------------------

constexpr const auto VMCS_PIN_BASED_VM_EXECUTION_CONTROLS                      = 0x0000000000004000UL;
constexpr const auto VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS        = 0x0000000000004002UL;
constexpr const auto VMCS_EXCEPTION_BITMAP                                     = 0x0000000000004004UL;
constexpr const auto VMCS_PAGE_FAULT_ERROR_CODE_MASK                           = 0x0000000000004006UL;
constexpr const auto VMCS_PAGE_FAULT_ERROR_CODE_MATCH                          = 0x0000000000004008UL;
constexpr const auto VMCS_CR3_TARGET_COUNT                                     = 0x000000000000400AUL;
constexpr const auto VMCS_VM_EXIT_CONTROLS                                     = 0x000000000000400CUL;
constexpr const auto VMCS_VM_EXIT_MSR_STORE_COUNT                              = 0x000000000000400EUL;
constexpr const auto VMCS_VM_EXIT_MSR_LOAD_COUNT                               = 0x0000000000004010UL;
constexpr const auto VMCS_VM_ENTRY_CONTROLS                                    = 0x0000000000004012UL;
constexpr const auto VMCS_VM_ENTRY_MSR_LOAD_COUNT                              = 0x0000000000004014UL;
constexpr const auto VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD              = 0x0000000000004016UL;
constexpr const auto VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE                        = 0x0000000000004018UL;
constexpr const auto VMCS_VM_ENTRY_INSTRUCTION_LENGTH                          = 0x000000000000401AUL;
constexpr const auto VMCS_TPR_THRESHOLD                                        = 0x000000000000401CUL;
constexpr const auto VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS      = 0x000000000000401EUL;
constexpr const auto VMCS_PLE_GAP                                              = 0x0000000000004020UL;
constexpr const auto VMCS_PLE_WINDOW                                           = 0x0000000000004022UL;

// -----------------------------------------------------------------------------
// 32bit Read-Only Fields
// -----------------------------------------------------------------------------

constexpr const auto VMCS_VM_INSTRUCTION_ERROR                                 = 0x0000000000004400UL;
constexpr const auto VMCS_EXIT_REASON                                          = 0x0000000000004402UL;
constexpr const auto VMCS_VM_EXIT_INTERRUPTION_INFORMATION                     = 0x0000000000004404UL;
constexpr const auto VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE                      = 0x0000000000004406UL;
constexpr const auto VMCS_IDT_VECTORING_INFORMATION_FIELD                      = 0x0000000000004408UL;
constexpr const auto VMCS_IDT_VECTORING_ERROR_CODE                             = 0x000000000000440AUL;
constexpr const auto VMCS_VM_EXIT_INSTRUCTION_LENGTH                           = 0x000000000000440CUL;
constexpr const auto VMCS_VM_EXIT_INSTRUCTION_INFORMATION                      = 0x000000000000440EUL;

// -----------------------------------------------------------------------------
// 32bit Read-Only Fields
// -----------------------------------------------------------------------------

constexpr const auto VMCS_GUEST_ES_LIMIT                                       = 0x0000000000004800UL;
constexpr const auto VMCS_GUEST_CS_LIMIT                                       = 0x0000000000004802UL;
constexpr const auto VMCS_GUEST_SS_LIMIT                                       = 0x0000000000004804UL;
constexpr const auto VMCS_GUEST_DS_LIMIT                                       = 0x0000000000004806UL;
constexpr const auto VMCS_GUEST_FS_LIMIT                                       = 0x0000000000004808UL;
constexpr const auto VMCS_GUEST_GS_LIMIT                                       = 0x000000000000480AUL;
constexpr const auto VMCS_GUEST_LDTR_LIMIT                                     = 0x000000000000480CUL;
constexpr const auto VMCS_GUEST_TR_LIMIT                                       = 0x000000000000480EUL;
constexpr const auto VMCS_GUEST_GDTR_LIMIT                                     = 0x0000000000004810UL;
constexpr const auto VMCS_GUEST_IDTR_LIMIT                                     = 0x0000000000004812UL;
constexpr const auto VMCS_GUEST_ES_ACCESS_RIGHTS                               = 0x0000000000004814UL;
constexpr const auto VMCS_GUEST_CS_ACCESS_RIGHTS                               = 0x0000000000004816UL;
constexpr const auto VMCS_GUEST_SS_ACCESS_RIGHTS                               = 0x0000000000004818UL;
constexpr const auto VMCS_GUEST_DS_ACCESS_RIGHTS                               = 0x000000000000481AUL;
constexpr const auto VMCS_GUEST_FS_ACCESS_RIGHTS                               = 0x000000000000481CUL;
constexpr const auto VMCS_GUEST_GS_ACCESS_RIGHTS                               = 0x000000000000481EUL;
constexpr const auto VMCS_GUEST_LDTR_ACCESS_RIGHTS                             = 0x0000000000004820UL;
constexpr const auto VMCS_GUEST_TR_ACCESS_RIGHTS                               = 0x0000000000004822UL;
constexpr const auto VMCS_GUEST_INTERRUPTIBILITY_STATE                         = 0x0000000000004824UL;
constexpr const auto VMCS_GUEST_ACTIVITY_STATE                                 = 0x0000000000004826UL;
constexpr const auto VMCS_GUEST_SMBASE                                         = 0x0000000000004828UL;
constexpr const auto VMCS_GUEST_IA32_SYSENTER_CS                               = 0x000000000000482AUL;
constexpr const auto VMCS_VMX_PREEMPTION_TIMER_VALUE                           = 0x000000000000482EUL;

// -----------------------------------------------------------------------------
// 32bit Host State Fields
// -----------------------------------------------------------------------------

constexpr const auto VMCS_HOST_IA32_SYSENTER_CS                                = 0x0000000000004C00UL;

// -----------------------------------------------------------------------------
// Natural Width Control Fields
// -----------------------------------------------------------------------------

constexpr const auto VMCS_CR0_GUEST_HOST_MASK                                  = 0x0000000000006000UL;
constexpr const auto VMCS_CR4_GUEST_HOST_MASK                                  = 0x0000000000006002UL;
constexpr const auto VMCS_CR0_READ_SHADOW                                      = 0x0000000000006004UL;
constexpr const auto VMCS_CR4_READ_SHADOW                                      = 0x0000000000006006UL;
constexpr const auto VMCS_CR3_TARGET_VALUE_0                                   = 0x0000000000006008UL;
constexpr const auto VMCS_CR3_TARGET_VALUE_1                                   = 0x000000000000600AUL;
constexpr const auto VMCS_CR3_TARGET_VALUE_2                                   = 0x000000000000600CUL;
constexpr const auto VMCS_CR3_TARGET_VALUE_31                                  = 0x000000000000600EUL;

// -----------------------------------------------------------------------------
// Natural Width Read-Only Fields
// -----------------------------------------------------------------------------

constexpr const auto VMCS_EXIT_QUALIFICATION                                   = 0x0000000000006400UL;
constexpr const auto VMCS_IO_RCX                                               = 0x0000000000006402UL;
constexpr const auto VMCS_IO_RSI                                               = 0x0000000000006404UL;
constexpr const auto VMCS_IO_RDI                                               = 0x0000000000006406UL;
constexpr const auto VMCS_IO_RIP                                               = 0x0000000000006408UL;
constexpr const auto VMCS_GUEST_LINEAR_ADDRESS                                 = 0x000000000000640AUL;

// -----------------------------------------------------------------------------
// Natural Width Guest State Fields
// -----------------------------------------------------------------------------

namespace intel_x64
{
namespace vmcs
{

namespace guest_cr0
{
    constexpr const auto addr = 0x0000000000006800UL;
    constexpr const auto name = "guest_cr0";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }

    namespace protection_enable
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "protection_enable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace monitor_coprocessor
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "monitor_coprocessor";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace emulation
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "emulation";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace task_switched
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "task_switched";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace extension_type
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "extension_type";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace numeric_error
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "numeric_error";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace write_protect
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "write_protect";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace alignment_mask
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_mask";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace not_write_through
    {
        constexpr const auto mask = 0x0000000020000000UL;
        constexpr const auto from = 29;
        constexpr const auto name = "not_write_through";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace cache_disable
    {
        constexpr const auto mask = 0x0000000040000000UL;
        constexpr const auto from = 30;
        constexpr const auto name = "cache_disable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace paging
    {
        constexpr const auto mask = 0x0000000080000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "paging";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

namespace guest_cr3
{
    constexpr const auto addr = 0x0000000000006802UL;
    constexpr const auto name = "guest_cr3";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace guest_cr4
{
    constexpr const auto addr = 0x0000000000006804UL;
    constexpr const auto name = "guest_cr4";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }

    namespace v8086_mode_extensions
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "v8086_mode_extensions";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace protected_mode_virtual_interrupts
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "protected_mode_virtual_interrupts";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace time_stamp_disable
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "time_stamp_disable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace debugging_extensions
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "debugging_extensions";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace page_size_extensions
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "page_size_extensions";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace physical_address_extensions
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "physical_address_extensions";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace machine_check_enable
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "machine_check_enable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace page_global_enable
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "page_global_enable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace performance_monitor_counter_enable
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "performance_monitor_counter_enable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osfxsr
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "osfxsr";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osxmmexcpt
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "osxmmexcpt";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace vmx_enable_bit
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "vmx_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smx_enable_bit
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "smx_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace fsgsbase_enable_bit
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "fsgsbase_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace pcid_enable_bit
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "pcid_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osxsave
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "osxsave";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smep_enable_bit
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "smep_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smap_enable_bit
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "smap_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace protection_key_enable_bit
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "protection_key_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

}
}

constexpr const auto VMCS_GUEST_ES_BASE                                        = 0x0000000000006806UL;
constexpr const auto VMCS_GUEST_CS_BASE                                        = 0x0000000000006808UL;
constexpr const auto VMCS_GUEST_SS_BASE                                        = 0x000000000000680AUL;
constexpr const auto VMCS_GUEST_DS_BASE                                        = 0x000000000000680CUL;
constexpr const auto VMCS_GUEST_FS_BASE                                        = 0x000000000000680EUL;
constexpr const auto VMCS_GUEST_GS_BASE                                        = 0x0000000000006810UL;
constexpr const auto VMCS_GUEST_LDTR_BASE                                      = 0x0000000000006812UL;
constexpr const auto VMCS_GUEST_TR_BASE                                        = 0x0000000000006814UL;
constexpr const auto VMCS_GUEST_GDTR_BASE                                      = 0x0000000000006816UL;
constexpr const auto VMCS_GUEST_IDTR_BASE                                      = 0x0000000000006818UL;
constexpr const auto VMCS_GUEST_DR7                                            = 0x000000000000681AUL;
constexpr const auto VMCS_GUEST_RSP                                            = 0x000000000000681CUL;
constexpr const auto VMCS_GUEST_RIP                                            = 0x000000000000681EUL;

// REMOVE ME
//
// Once all of these VMCS fields have been converted over to the new sceme,
// there should just be one overall namespace. This is only here so that the
// guest rflags is in the right order for now, without causing the other
// definitions from being placed in the namespace.
//
namespace intel_x64
{
namespace vmcs
{

namespace guest_rflags
{
    constexpr const auto addr = 0x0000000000006820UL;
    constexpr const auto name = "guest_rflags";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }

    namespace carry_flag
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "carry_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace parity_flag
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "parity_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace auxiliary_carry_flag
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "auxiliary_carry_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace zero_flag
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "zero_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace sign_flag
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "sign_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace trap_flag
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "trap_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace interrupt_enable_flag
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "interrupt_enable_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace direction_flag
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "direction_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace overflow_flag
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "overflow_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace privilege_level
    {
        constexpr const auto mask = 0x0000000000003000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "privilege_level";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace nested_task
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "nested_task";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace resume_flag
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "resume_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace virtual_8086_mode
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "virtual_8086_mode";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace alignment_check_access_control
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_check_access_control";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace virtual_interupt_flag
    {
        constexpr const auto mask = 0x0000000000080000UL;
        constexpr const auto from = 19;
        constexpr const auto name = "virtual_interupt_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace virtual_interupt_pending
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "virtual_interupt_pending";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace id_flag
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "id_flag";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFC08028UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace always_disabled
    {
        constexpr const auto mask = 0xFFFFFFFFFFC08028UL;
        constexpr const auto from = 0;
        constexpr const auto name = "always_disabled";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace always_enabled
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 0;
        constexpr const auto name = "always_enabled";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

}
}

constexpr const auto VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS                       = 0x0000000000006822UL;
constexpr const auto VMCS_GUEST_IA32_SYSENTER_ESP                              = 0x0000000000006824UL;
constexpr const auto VMCS_GUEST_IA32_SYSENTER_EIP                              = 0x0000000000006826UL;

// -----------------------------------------------------------------------------
// Natural Width Host State Fields
// -----------------------------------------------------------------------------

namespace intel_x64
{
namespace vmcs
{

namespace host_cr0
{
    constexpr const auto addr = 0x0000000000006C00UL;
    constexpr const auto name = "host_cr0";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }

    namespace protection_enable
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "protection_enable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace monitor_coprocessor
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "monitor_coprocessor";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace emulation
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "emulation";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace task_switched
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "task_switched";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace extension_type
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "extension_type";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace numeric_error
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "numeric_error";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace write_protect
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "write_protect";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace alignment_mask
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_mask";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace not_write_through
    {
        constexpr const auto mask = 0x0000000020000000UL;
        constexpr const auto from = 29;
        constexpr const auto name = "not_write_through";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace cache_disable
    {
        constexpr const auto mask = 0x0000000040000000UL;
        constexpr const auto from = 30;
        constexpr const auto name = "cache_disable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace paging
    {
        constexpr const auto mask = 0x0000000080000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "paging";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

namespace host_cr3
{
    constexpr const auto addr = 0x0000000000006C02UL;
    constexpr const auto name = "host_cr3";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }
}

namespace host_cr4
{
    constexpr const auto addr = 0x0000000000006C04UL;
    constexpr const auto name = "host_cr4";

    inline auto get()
    { return vmread(addr, name); }

    template<class T> void set(T val)
    { vmwrite(addr, val, name); }

    inline bool is_supported() noexcept
    { return true; }

    namespace v8086_mode_extensions
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "v8086_mode_extensions";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace protected_mode_virtual_interrupts
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "protected_mode_virtual_interrupts";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace time_stamp_disable
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "time_stamp_disable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace debugging_extensions
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "debugging_extensions";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace page_size_extensions
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "page_size_extensions";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace physical_address_extensions
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "physical_address_extensions";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace machine_check_enable
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "machine_check_enable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace page_global_enable
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "page_global_enable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace performance_monitor_counter_enable
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "performance_monitor_counter_enable";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osfxsr
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "osfxsr";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osxmmexcpt
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "osxmmexcpt";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace vmx_enable_bit
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "vmx_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smx_enable_bit
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "smx_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace fsgsbase_enable_bit
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "fsgsbase_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace pcid_enable_bit
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "pcid_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osxsave
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "osxsave";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smep_enable_bit
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "smep_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smap_enable_bit
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "smap_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace protection_key_enable_bit
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "protection_key_enable_bit";

        inline auto get()
        { return (vmread(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vmwrite(addr, (vmread(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

}
}

constexpr const auto VMCS_HOST_FS_BASE                                         = 0x0000000000006C06UL;
constexpr const auto VMCS_HOST_GS_BASE                                         = 0x0000000000006C08UL;
constexpr const auto VMCS_HOST_TR_BASE                                         = 0x0000000000006C0AUL;
constexpr const auto VMCS_HOST_GDTR_BASE                                       = 0x0000000000006C0CUL;
constexpr const auto VMCS_HOST_IDTR_BASE                                       = 0x0000000000006C0EUL;
constexpr const auto VMCS_HOST_IA32_SYSENTER_ESP                               = 0x0000000000006C10UL;
constexpr const auto VMCS_HOST_IA32_SYSENTER_EIP                               = 0x0000000000006C12UL;
constexpr const auto VMCS_HOST_RSP                                             = 0x0000000000006C14UL;
constexpr const auto VMCS_HOST_RIP                                             = 0x0000000000006C16UL;

// *INDENT-ON*

#endif
