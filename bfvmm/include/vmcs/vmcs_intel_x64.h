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
#include <bitmanip.h>
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

    // REMOVE ME: These should be placed in the x64 namespace instead
    virtual bool is_address_canonical(uint64_t addr);
    virtual bool is_linear_address_valid(uint64_t addr);
    virtual bool is_physical_address_valid(uint64_t addr);

    // REMOVE ME: All is enabled functions should be removed as they are
    // not needed once we have a get() function for each bit
    virtual bool is_enabled_v8086() const;

    virtual bool is_supported_eptp_switching() const;
    virtual bool is_supported_event_injection_instr_length_of_0() const;

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

inline auto
get_vmcs_field(uint64_t addr, const std::string &name, bool exists)
{
    auto what = std::string("get_vmcs_field failed: ") + name + " field doesn't exist";

    if (!exists)
        throw std::logic_error(what);

    return intel_x64::vm::read(addr, name);
}

inline auto
get_vmcs_field_if_exists(uint64_t addr, const std::string &name, bool verbose, bool exists)
{
    if (!exists && verbose)
        bfwarning << "get_vmcs_field_if_exists failed: " << name << " field doesn't exist" << '\n';

    if (exists)
        return intel_x64::vm::read(addr, name);

    return 0UL;
}

template <class T> void
set_vmcs_field(T val, uint64_t addr, const std::string &name, bool exists)
{
    auto what = std::string("set_vmcs_field failed: ") + name + " field doesn't exist";

    if (!exists)
        throw std::logic_error(what);

    intel_x64::vm::write(addr, val, name);
}

template <class T> void
set_vmcs_field_if_exists(T val, uint64_t addr, const std::string &name, bool verbose, bool exists)
{
    if (!exists && verbose)
        bfwarning << "set_vmcs_field_if_exists failed: " << name << " field doesn't exist" << '\n';

    if (exists)
        intel_x64::vm::write(addr, val, name);
}

inline auto
get_vm_control(uint64_t addr, const std::string &name, uint64_t mask, bool exists)
{
    auto what = std::string("can't get ") + name + ": corresponding vmcs field doesn't exist";

    if (!exists)
        throw std::logic_error(what);

    return (intel_x64::vm::read(addr, name) & mask);
}

inline auto
get_vm_control_if_exists(uint64_t addr, const std::string &name, uint64_t mask, bool verbose, bool exists)
{
    auto what = std::string("getting ") + name + " not allowed: corresponding vmcs field doesn't exist";

    if (!exists && verbose)
        bfwarning << what << '\n';

    if (exists)
        return (intel_x64::vm::read(addr, name) & mask);

    return 0UL;
}

template <class T> void
set_vm_control(T val, uint64_t msr_addr, uint64_t ctls_addr,
               const std::string &name, uint64_t mask, bool field_exists)
{
    using namespace intel_x64;

    auto what = std::string("setting ") + name + " failed: corresponding vmcs field doesn't exist";

    if (!field_exists)
        throw std::logic_error(what);

    bool is_allowed0 = (msrs::get(msr_addr) & mask) == 0;
    bool is_allowed1 = (msrs::get(msr_addr) & (mask << 32)) != 0;

    if (val == 0)
    {
        if (!is_allowed0)
            throw std::logic_error(std::string(name) + " is not allowed to be cleared to 0");

        vm::write(ctls_addr, (vm::read(ctls_addr, name) & ~mask), name);
    }
    else
    {
        if (!is_allowed1)
            throw std::logic_error(std::string(name) + " is not allowed to be set to 1");

        vm::write(ctls_addr, (vm::read(ctls_addr, name) | mask), name);
    }
}

template <class T> void
set_vm_control_if_allowed(T val, uint64_t msr_addr, uint64_t ctls_addr,
                          const std::string &name, uint64_t mask,
                          bool verbose, bool field_exists) noexcept
{
    using namespace intel_x64;

    if (!field_exists)
    {
        bfwarning << "setting " << name << " failed: corresponding vmcs field doesn't exist" << '\n';
        return;
    }

    bool is_allowed0 = (msrs::get(msr_addr) & mask) == 0;
    bool is_allowed1 = (msrs::get(msr_addr) & (mask << 32)) != 0;

    if (val == 0)
    {
        if (is_allowed0)
        {
            vm::write(ctls_addr, (vm::read(ctls_addr, name) & ~mask), name);
        }
        else
        {
            if (verbose)
                bfwarning << std::string(name) + " is not allowed to be cleared to 0" << bfendl;
        }
    }
    else
    {
        if (is_allowed1)
        {
            vm::write(ctls_addr, (vm::read(ctls_addr, name) | mask), name);
        }
        else
        {
            if (verbose)
                bfwarning << std::string(name) + " is not allowed to be set to 1" << bfendl;
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

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

using field_type = uint64_t;
using value_type = uint64_t;

namespace guest_ia32_debugctl
{
    constexpr const auto addr = 0x0000000000002802UL;
    constexpr const auto name = "guest_ia32_debugctl";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace lbr
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "lbr";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace btf
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "btf";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace tr
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "tr";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace bts
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "bts";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace btint
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "btint";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace bt_off_os
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "bt_off_os";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace bt_off_user
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "bt_off_user";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace freeze_lbrs_on_pmi
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "freeze_lbrs_on_pmi";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace freeze_perfmon_on_pmi
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "freeze_perfmon_on_pmi";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace enable_uncore_pmi
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "enable_uncore_pmi";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace freeze_while_smm
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "freeze_while_smm";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace rtm_debug
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "rtm_debug";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF003CUL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
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
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::get() == 1; }

    namespace sce
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "sce";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace lme
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "lme";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace lma
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "lma";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace nxe
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "nxe";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFF2FEUL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
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
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::get() == 1; }

    namespace sce
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "sce";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace lme
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "lme";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace lma
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "lma";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace nxe
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "nxe";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFF2FEUL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

}
}

constexpr const auto VMCS_HOST_IA32_PERF_GLOBAL_CTRL                      = 0x0000000000002C04UL;

// -----------------------------------------------------------------------------
// 32bit Control Fields
// -----------------------------------------------------------------------------

namespace intel_x64
{
namespace vmcs
{

namespace pin_based_vm_execution_controls
{
    constexpr const auto addr = 0x0000000000004000UL;
    constexpr const auto name = "pin_based_vm_execution_controls";
    constexpr const auto msr_addr = msrs::ia32_vmx_true_pinbased_ctls::addr;

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace external_interrupt_exiting
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "external_interrupt_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace nmi_exiting
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "nmi_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace virtual_nmis
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "virtual_nmis";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace activate_vmx_preemption_timer
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "activate_vmx_preemption_timer";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace process_posted_interrupts
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "process_posted_interrupts";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }
}

namespace primary_processor_based_vm_execution_controls
{
    constexpr const auto addr = 0x0000000000004002UL;
    constexpr const auto name = "primary_processor_based_vm_execution_controls";
    constexpr const auto msr_addr = msrs::ia32_vmx_true_procbased_ctls::addr;

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace interrupt_window_exiting
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "interrupt_window_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace use_tsc_offsetting
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "use_tsc_offsetting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace hlt_exiting
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "hlt_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace invlpg_exiting
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "invlpg_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace mwait_exiting
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "mwait_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace rdpmc_exiting
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "rdpmc_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace rdtsc_exiting
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "rdtsc_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace cr3_load_exiting
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "cr3_load_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace cr3_store_exiting
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "cr3_store_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace cr8_load_exiting
    {
        constexpr const auto mask = 0x0000000000080000UL;
        constexpr const auto from = 19;
        constexpr const auto name = "cr8_load_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace cr8_store_exiting
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "cr8_store_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace use_tpr_shadow
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "use_tpr_shadow";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace nmi_window_exiting
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "nmi_window_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace mov_dr_exiting
    {
        constexpr const auto mask = 0x0000000000800000UL;
        constexpr const auto from = 23;
        constexpr const auto name = "mov_dr_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace unconditional_io_exiting
    {
        constexpr const auto mask = 0x0000000001000000UL;
        constexpr const auto from = 24;
        constexpr const auto name = "unconditional_io_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace use_io_bitmaps
    {
        constexpr const auto mask = 0x0000000002000000UL;
        constexpr const auto from = 25;
        constexpr const auto name = "use_io_bitmaps";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace monitor_trap_flag
    {
        constexpr const auto mask = 0x0000000008000000UL;
        constexpr const auto from = 27;
        constexpr const auto name = "monitor_trap_flag";

        inline bool
        is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace use_msr_bitmaps
    {
        constexpr const auto mask = 0x0000000010000000UL;
        constexpr const auto from = 28;
        constexpr const auto name = "use_msr_bitmaps";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool
        is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace monitor_exiting
    {
        constexpr const auto mask = 0x0000000020000000UL;
        constexpr const auto from = 29;
        constexpr const auto name = "monitor_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace pause_exiting
    {
        constexpr const auto mask = 0x0000000040000000UL;
        constexpr const auto from = 30;
        constexpr const auto name = "pause_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace activate_secondary_controls
    {
        constexpr const auto mask = 0x0000000080000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "activate_secondary_controls";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }
}

namespace exception_bitmap
{
    constexpr const auto addr = 0x0000000000004004UL;
    constexpr const auto name = "execption_bitmap";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace page_fault_error_code_mask
{
    constexpr const auto addr = 0x0000000000004006UL;
    constexpr const auto name = "page_fault_error_code_mask";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace page_fault_error_code_match
{
    constexpr const auto addr = 0x0000000000004008UL;
    constexpr const auto name = "page_fault_error_code_match";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace cr3_target_count
{
    constexpr const auto addr = 0x000000000000400AUL;
    constexpr const auto name = "cr3_target_count";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vm_exit_controls
{
    constexpr const auto addr = 0x000000000000400CUL;
    constexpr const auto name = "vm_exit_controls";
    constexpr const auto msr_addr = msrs::ia32_vmx_true_exit_ctls::addr;

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace save_debug_controls
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "save_debug_controls";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace host_address_space_size
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "host_address_space_size";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_perf_global_ctrl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "load_ia32_perf_global_ctrl";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace acknowledge_interrupt_on_exit
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "acknowledge_interrupt_on_exit";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace save_ia32_pat
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "save_ia32_pat";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_pat
    {
        constexpr const auto mask = 0x0000000000080000UL;
        constexpr const auto from = 19;
        constexpr const auto name = "load_ia32_pat";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace save_ia32_efer
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "save_ia32_efer";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_efer
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "load_ia32_efer";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace save_vmx_preemption_timer_value
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "save_vmx_preemption_timer_value";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }
}

namespace vm_exit_msr_store_count
{
    constexpr const auto addr = 0x000000000000400EUL;
    constexpr const auto name = "vm_exit_msr_store_count";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vm_exit_msr_load_count
{
    constexpr const auto addr = 0x0000000000004010UL;
    constexpr const auto name = "vm_exit_msr_load_count";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vm_entry_controls
{
    constexpr const auto addr = 0x0000000000004012UL;
    constexpr const auto name = "vm_entry_controls";
    constexpr const auto msr_addr = msrs::ia32_vmx_true_entry_ctls::addr;

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace load_debug_controls
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "load_debug_controls";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace ia_32e_mode_guest
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "ia_32e_mode_guest";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace entry_to_smm
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "entry_to_smm";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace deactivate_dual_monitor_treatment
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "deactivate_dual_monitor_treatment";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_perf_global_ctrl
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "load_ia32_perf_global_ctrl";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_pat
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "load_ia32_pat";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_efer
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "load_ia32_efer";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }
}

namespace vm_entry_msr_load_count
{
    constexpr const auto addr = 0x0000000000004014UL;
    constexpr const auto name = "vm_entry_msr_load_count";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vm_entry_interruption_information_field
{
    constexpr const auto addr = 0x0000000000004016UL;
    constexpr const auto name = "vm_entry_interruption_information_field";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace vector
    {
        constexpr const auto mask = 0x000000FFUL;
        constexpr const auto from = 0;
        constexpr const auto name = "vector";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T> void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T> void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from ) & mask), addr, name, verbose, exists());
        }
    }

    namespace interruption_type
    {
        constexpr const auto mask = 0x00000700UL;
        constexpr const auto from = 8;
        constexpr const auto name = "interruption_type";

        constexpr const auto external_interrupt = 0UL;
        constexpr const auto reserved = 1UL;
        constexpr const auto non_maskable_interrupt = 2UL;
        constexpr const auto hardware_exception = 3UL;
        constexpr const auto software_interrupt = 4UL;
        constexpr const auto privileged_software_exception = 5UL;
        constexpr const auto software_exception = 6UL;
        constexpr const auto other_event = 7UL;

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T> void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T> void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from ) & mask), addr, name, verbose, exists());
        }
    }

    namespace deliver_error_code_bit
    {
        constexpr const auto mask = 0x00000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "deliver_error_code_bit";

        inline bool is_enabled()
        { return (get_vmcs_field(addr, name, exists()) & mask) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) != 0U; }

        inline bool is_disabled()
        { return (get_vmcs_field(addr, name, exists()) & mask) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) == 0U; }

        inline void enable()
        { set_vmcs_field((get_vmcs_field(addr, name, exists()) | mask), addr, name, exists()); }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field | mask), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0x7FFFF000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T> void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T> void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from ) & mask), addr, name, verbose, exists());
        }
    }

    namespace valid_bit
    {
        constexpr const auto mask = 0x80000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "valid_bit";

        inline bool is_enabled()
        { return (get_vmcs_field(addr, name, exists()) & mask) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) != 0U; }

        inline bool is_disabled()
        { return (get_vmcs_field(addr, name, exists()) & mask) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) == 0U; }

        inline void enable()
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field| mask), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field | mask), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask), addr, name, verbose, exists());
        }
    }
}

namespace vm_entry_exception_error_code
{
    constexpr const auto addr = 0x0000000000004018UL;
    constexpr const auto name = "vm_entry_exception_error_code";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vm_entry_instruction_length
{
    constexpr const auto addr = 0x000000000000401AUL;
    constexpr const auto name = "vm_entry_instruction_length";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace tpr_threshold
{
    constexpr const auto addr = 0x000000000000401CUL;
    constexpr const auto name = "tpr_threshold";

    inline bool exists() noexcept
    { return msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace secondary_processor_based_vm_execution_controls
{
    constexpr const auto addr = 0x000000000000401EUL;
    constexpr const auto name = "secondary_processor_based_vm_execution_controls";
    constexpr const auto msr_addr = msrs::ia32_vmx_procbased_ctls2::addr;

    inline bool exists() noexcept
    { return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T> void set(T val)
    { set_vmcs_field(val, addr, name, exists()); }

    template <class T> void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace virtualize_apic_accesses
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "virtualize_apic_accesses";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_ept
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "enable_ept";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace descriptor_table_exiting
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "descriptor_table_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_rdtscp
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "enable_rdtscp";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace virtualize_x2apic_mode
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "virtualize_x2apic_mode";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_vpid
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "enable_vpid";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace wbinvd_exiting
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "wbinvd_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace unrestricted_guest
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "unrestricted_guest";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace apic_register_virtualization
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "apic_register_virtualization";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace virtual_interrupt_delivery
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "virtual_interrupt_delivery";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace pause_loop_exiting
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "pause_loop_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace rdrand_exiting
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "rdrand_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_invpcid
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "enable_invpcid";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_vm_functions
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "enable_vm_functions";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace vmcs_shadowing
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "vmcs_shadowing";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace rdseed_exiting
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "rdseed_exiting";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_pml
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "enable_pml";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace ept_violation_ve
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "ept_violation_ve";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_xsaves_xrstors
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20 ;
        constexpr const auto name = "enable_xsaves_xrstors";

        inline bool is_enabled()
        { return get_vm_control(addr, name, mask, exists()) != 0U; }

        inline bool is_enabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) != 0U; }

        inline bool is_disabled()
        { return get_vm_control(addr, name, mask, exists()) == 0U; }

        inline bool
        is_disabled_if_exists(bool verbose = false) noexcept
        { return get_vm_control_if_exists(addr, name, mask, verbose, exists()) == 0U; }

        inline void enable()
        { set_vm_control(1UL, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(1UL, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(0UL, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(0UL, msr_addr, addr, name, mask, verbose, exists()); }
    }
}


} //vmcs
} //intel_x64

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

namespace intel_x64
{
namespace vmcs
{

namespace guest_es_access_rights
{
    constexpr const auto addr = 0x0000000000004814UL;
    constexpr const auto name = "guest_es_access_rights";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

namespace guest_cs_access_rights
{
    constexpr const auto addr = 0x0000000000004816UL;
    constexpr const auto name = "guest_cs_access_rights";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

namespace guest_ss_access_rights
{
    constexpr const auto addr = 0x0000000000004818UL;
    constexpr const auto name = "guest_ss_access_rights";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

namespace guest_ds_access_rights
{
    constexpr const auto addr = 0x000000000000481AUL;
    constexpr const auto name = "guest_ds_access_rights";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

namespace guest_fs_access_rights
{
    constexpr const auto addr = 0x000000000000481CUL;
    constexpr const auto name = "guest_fs_access_rights";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

namespace guest_gs_access_rights
{
    constexpr const auto addr = 0x000000000000481EUL;
    constexpr const auto name = "guest_gs_access_rights";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

namespace guest_ldtr_access_rights
{
    constexpr const auto addr = 0x0000000000004820UL;
    constexpr const auto name = "guest_ldtr_access_rights";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

namespace guest_tr_access_rights
{
    constexpr const auto addr = 0x0000000000004822UL;
    constexpr const auto name = "guest_tr_access_rights";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }
}

}
}

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
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace protection_enable
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "protection_enable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace monitor_coprocessor
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "monitor_coprocessor";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace emulation
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "emulation";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace task_switched
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "task_switched";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace extension_type
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "extension_type";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace numeric_error
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "numeric_error";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace write_protect
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "write_protect";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace alignment_mask
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_mask";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace not_write_through
    {
        constexpr const auto mask = 0x0000000020000000UL;
        constexpr const auto from = 29;
        constexpr const auto name = "not_write_through";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace cache_disable
    {
        constexpr const auto mask = 0x0000000040000000UL;
        constexpr const auto from = 30;
        constexpr const auto name = "cache_disable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace paging
    {
        constexpr const auto mask = 0x0000000080000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "paging";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    inline void dump() noexcept
    {
        bfdebug << "guest cr0 enabled flags:" << bfendl;

        if (protection_enable::get() == 1)
            bfdebug << "    - protection_enable" << bfendl;

        if (monitor_coprocessor::get() == 1)
            bfdebug << "    - monitor_coprocessor" << bfendl;

        if (emulation::get() == 1)
            bfdebug << "    - emulation" << bfendl;

        if (task_switched::get() == 1)
            bfdebug << "    - task_switched" << bfendl;

        if (extension_type::get() == 1)
            bfdebug << "    - extension_type" << bfendl;

        if (numeric_error::get() == 1)
            bfdebug << "    - numeric_error" << bfendl;

        if (write_protect::get() == 1)
            bfdebug << "    - write_protect" << bfendl;

        if (alignment_mask::get() == 1)
            bfdebug << "    - alignment_mask" << bfendl;

        if (not_write_through::get() == 1)
            bfdebug << "    - not_write_through" << bfendl;

        if (cache_disable::get() == 1)
            bfdebug << "    - cache_disable" << bfendl;

        if (paging::get() == 1)
            bfdebug << "    - paging" << bfendl;
    }
}

namespace guest_cr3
{
    constexpr const auto addr = 0x0000000000006802UL;
    constexpr const auto name = "guest_cr3";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }
}

namespace guest_cr4
{
    constexpr const auto addr = 0x0000000000006804UL;
    constexpr const auto name = "guest_cr4";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace v8086_mode_extensions
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "v8086_mode_extensions";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace protected_mode_virtual_interrupts
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "protected_mode_virtual_interrupts";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace time_stamp_disable
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "time_stamp_disable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace debugging_extensions
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "debugging_extensions";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace page_size_extensions
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "page_size_extensions";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace physical_address_extensions
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "physical_address_extensions";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace machine_check_enable
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "machine_check_enable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace page_global_enable
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "page_global_enable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace performance_monitor_counter_enable
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "performance_monitor_counter_enable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osfxsr
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "osfxsr";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osxmmexcpt
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "osxmmexcpt";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace vmx_enable_bit
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "vmx_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smx_enable_bit
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "smx_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace fsgsbase_enable_bit
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "fsgsbase_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace pcid_enable_bit
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "pcid_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osxsave
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "osxsave";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smep_enable_bit
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "smep_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smap_enable_bit
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "smap_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace protection_key_enable_bit
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "protection_key_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    inline void dump() noexcept
    {
        bfdebug << "guest cr4 enabled flags:" << bfendl;

        if (v8086_mode_extensions::get() == 1)
            bfdebug << "    - v8086_mode_extensions" << bfendl;

        if (protected_mode_virtual_interrupts::get() == 1)
            bfdebug << "    - protected_mode_virtual_interrupts" << bfendl;

        if (time_stamp_disable::get() == 1)
            bfdebug << "    - time_stamp_disable" << bfendl;

        if (debugging_extensions::get() == 1)
            bfdebug << "    - debugging_extensions" << bfendl;

        if (page_size_extensions::get() == 1)
            bfdebug << "    - page_size_extensions" << bfendl;

        if (physical_address_extensions::get() == 1)
            bfdebug << "    - physical_address_extensions" << bfendl;

        if (machine_check_enable::get() == 1)
            bfdebug << "    - machine_check_enable" << bfendl;

        if (page_global_enable::get() == 1)
            bfdebug << "    - page_global_enable" << bfendl;

        if (performance_monitor_counter_enable::get() == 1)
            bfdebug << "    - performance_monitor_counter_enable" << bfendl;

        if (osfxsr::get() == 1)
            bfdebug << "    - osfxsr" << bfendl;

        if (osxmmexcpt::get() == 1)
            bfdebug << "    - osxmmexcpt" << bfendl;

        if (vmx_enable_bit::get() == 1)
            bfdebug << "    - vmx_enable_bit" << bfendl;

        if (smx_enable_bit::get() == 1)
            bfdebug << "    - smx_enable_bit" << bfendl;

        if (smx_enable_bit::get() == 1)
            bfdebug << "    - smx_enable_bit" << bfendl;

        if (fsgsbase_enable_bit::get() == 1)
            bfdebug << "    - fsgsbase_enable_bit" << bfendl;

        if (pcid_enable_bit::get() == 1)
            bfdebug << "    - pcid_enable_bit" << bfendl;

        if (osxsave::get() == 1)
            bfdebug << "    - osxsave" << bfendl;

        if (smep_enable_bit::get() == 1)
            bfdebug << "    - smep_enable_bit" << bfendl;

        if (smap_enable_bit::get() == 1)
            bfdebug << "    - smap_enable_bit" << bfendl;

        if (protection_key_enable_bit::get() == 1)
            bfdebug << "    - protection_key_enable_bit" << bfendl;
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
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace carry_flag
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "carry_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace parity_flag
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "parity_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace auxiliary_carry_flag
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "auxiliary_carry_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace zero_flag
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "zero_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace sign_flag
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "sign_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace trap_flag
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "trap_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace interrupt_enable_flag
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "interrupt_enable_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace direction_flag
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "direction_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace overflow_flag
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "overflow_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace privilege_level
    {
        constexpr const auto mask = 0x0000000000003000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "privilege_level";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace nested_task
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "nested_task";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace resume_flag
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "resume_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace virtual_8086_mode
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "virtual_8086_mode";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace alignment_check_access_control
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_check_access_control";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace virtual_interupt_flag
    {
        constexpr const auto mask = 0x0000000000080000UL;
        constexpr const auto from = 19;
        constexpr const auto name = "virtual_interupt_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace virtual_interupt_pending
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "virtual_interupt_pending";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace id_flag
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "id_flag";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFC08028UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace always_disabled
    {
        constexpr const auto mask = 0xFFFFFFFFFFC08028UL;
        constexpr const auto from = 0;
        constexpr const auto name = "always_disabled";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace always_enabled
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 0;
        constexpr const auto name = "always_enabled";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
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
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace protection_enable
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "protection_enable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace monitor_coprocessor
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "monitor_coprocessor";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace emulation
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "emulation";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace task_switched
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "task_switched";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace extension_type
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "extension_type";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace numeric_error
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "numeric_error";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace write_protect
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "write_protect";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace alignment_mask
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_mask";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace not_write_through
    {
        constexpr const auto mask = 0x0000000020000000UL;
        constexpr const auto from = 29;
        constexpr const auto name = "not_write_through";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace cache_disable
    {
        constexpr const auto mask = 0x0000000040000000UL;
        constexpr const auto from = 30;
        constexpr const auto name = "cache_disable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace paging
    {
        constexpr const auto mask = 0x0000000080000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "paging";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    inline void dump() noexcept
    {
        bfdebug << "host cr0 enabled flags:" << bfendl;

        if (protection_enable::get() == 1)
            bfdebug << "    - protection_enable" << bfendl;

        if (monitor_coprocessor::get() == 1)
            bfdebug << "    - monitor_coprocessor" << bfendl;

        if (emulation::get() == 1)
            bfdebug << "    - emulation" << bfendl;

        if (task_switched::get() == 1)
            bfdebug << "    - task_switched" << bfendl;

        if (extension_type::get() == 1)
            bfdebug << "    - extension_type" << bfendl;

        if (numeric_error::get() == 1)
            bfdebug << "    - numeric_error" << bfendl;

        if (write_protect::get() == 1)
            bfdebug << "    - write_protect" << bfendl;

        if (alignment_mask::get() == 1)
            bfdebug << "    - alignment_mask" << bfendl;

        if (not_write_through::get() == 1)
            bfdebug << "    - not_write_through" << bfendl;

        if (cache_disable::get() == 1)
            bfdebug << "    - cache_disable" << bfendl;

        if (paging::get() == 1)
            bfdebug << "    - paging" << bfendl;
    }
}

namespace host_cr3
{
    constexpr const auto addr = 0x0000000000006C02UL;
    constexpr const auto name = "host_cr3";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }
}

namespace host_cr4
{
    constexpr const auto addr = 0x0000000000006C04UL;
    constexpr const auto name = "host_cr4";

    inline auto get()
    { return vm::read(addr, name); }

    template<class T> void set(T val)
    { vm::write(addr, val, name); }

    inline bool exists() noexcept
    { return true; }

    namespace v8086_mode_extensions
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "v8086_mode_extensions";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace protected_mode_virtual_interrupts
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "protected_mode_virtual_interrupts";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace time_stamp_disable
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "time_stamp_disable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace debugging_extensions
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "debugging_extensions";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace page_size_extensions
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "page_size_extensions";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace physical_address_extensions
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "physical_address_extensions";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace machine_check_enable
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "machine_check_enable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace page_global_enable
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "page_global_enable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace performance_monitor_counter_enable
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "performance_monitor_counter_enable";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osfxsr
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "osfxsr";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osxmmexcpt
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "osxmmexcpt";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace vmx_enable_bit
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "vmx_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smx_enable_bit
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "smx_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace fsgsbase_enable_bit
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "fsgsbase_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace pcid_enable_bit
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "pcid_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace osxsave
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "osxsave";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smep_enable_bit
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "smep_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace smap_enable_bit
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "smap_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    namespace protection_key_enable_bit
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "protection_key_enable_bit";

        inline auto get()
        { return (vm::read(addr, name) & mask) >> from; }

        template<class T> void set(T val)
        { vm::write(addr, (vm::read(addr, name) & ~mask) | ((val << from) & mask), name); }
    }

    inline void dump() noexcept
    {
        bfdebug << "cr4 enabled flags:" << bfendl;

        if (v8086_mode_extensions::get() == 1)
            bfdebug << "    - v8086_mode_extensions" << bfendl;

        if (protected_mode_virtual_interrupts::get() == 1)
            bfdebug << "    - protected_mode_virtual_interrupts" << bfendl;

        if (time_stamp_disable::get() == 1)
            bfdebug << "    - time_stamp_disable" << bfendl;

        if (debugging_extensions::get() == 1)
            bfdebug << "    - debugging_extensions" << bfendl;

        if (page_size_extensions::get() == 1)
            bfdebug << "    - page_size_extensions" << bfendl;

        if (physical_address_extensions::get() == 1)
            bfdebug << "    - physical_address_extensions" << bfendl;

        if (machine_check_enable::get() == 1)
            bfdebug << "    - machine_check_enable" << bfendl;

        if (page_global_enable::get() == 1)
            bfdebug << "    - page_global_enable" << bfendl;

        if (performance_monitor_counter_enable::get() == 1)
            bfdebug << "    - performance_monitor_counter_enable" << bfendl;

        if (osfxsr::get() == 1)
            bfdebug << "    - osfxsr" << bfendl;

        if (osxmmexcpt::get() == 1)
            bfdebug << "    - osxmmexcpt" << bfendl;

        if (vmx_enable_bit::get() == 1)
            bfdebug << "    - vmx_enable_bit" << bfendl;

        if (smx_enable_bit::get() == 1)
            bfdebug << "    - smx_enable_bit" << bfendl;

        if (smx_enable_bit::get() == 1)
            bfdebug << "    - smx_enable_bit" << bfendl;

        if (fsgsbase_enable_bit::get() == 1)
            bfdebug << "    - fsgsbase_enable_bit" << bfendl;

        if (pcid_enable_bit::get() == 1)
            bfdebug << "    - pcid_enable_bit" << bfendl;

        if (osxsave::get() == 1)
            bfdebug << "    - osxsave" << bfendl;

        if (smep_enable_bit::get() == 1)
            bfdebug << "    - smep_enable_bit" << bfendl;

        if (smap_enable_bit::get() == 1)
            bfdebug << "    - smap_enable_bit" << bfendl;

        if (protection_key_enable_bit::get() == 1)
            bfdebug << "    - protection_key_enable_bit" << bfendl;
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







//////////////
//////////////
///
///
/// REMOVE ME
///
///
//////////////
//////////////


// VM-Function Control Fields
#define VM_FUNCTION_CONTROL_EPTP_SWITCHING                        (1ULL << 0)

// VM Activity State
// intel's software developers manual, volume 3, 24.4.2
#define VM_ACTIVITY_STATE_ACTIVE                                  (0)
#define VM_ACTIVITY_STATE_HLT                                     (1)
#define VM_ACTIVITY_STATE_SHUTDOWN                                (2)
#define VM_ACTIVITY_STATE_WAIT_FOR_SIPI                           (3)

// VM Interrupability State
// intel's software developers manual, volume 3, 24.4.2
#define VM_INTERRUPTABILITY_STATE_STI                             (1 << 0)
#define VM_INTERRUPTABILITY_STATE_MOV_SS                          (1 << 1)
#define VM_INTERRUPTABILITY_STATE_SMI                             (1 << 2)
#define VM_INTERRUPTABILITY_STATE_NMI                             (1 << 3)


// MTF VM Exit
// intel's software developers manual, volume 3, 26.5.2
#define MTF_VM_EXIT                                               (0)

// Pending Debug Exceptions
// intel's software developers manual, volume 3, 24.4.2
#define PENDING_DEBUG_EXCEPTION_B0                                (1 << 0)
#define PENDING_DEBUG_EXCEPTION_B1                                (1 << 1)
#define PENDING_DEBUG_EXCEPTION_B2                                (1 << 2)
#define PENDING_DEBUG_EXCEPTION_B3                                (1 << 3)
#define PENDING_DEBUG_EXCEPTION_ENABLED_BREAKPOINT                (1 << 12)
#define PENDING_DEBUG_EXCEPTION_BS                                (1 << 14)

// VPID and EPT Capabilities
// intel's software developer's manual, volume 3, appendix A.10
#define IA32_VMX_EPT_VPID_CAP_UC                                  (1ULL << 8)
#define IA32_VMX_EPT_VPID_CAP_WB                                  (1ULL << 14)
#define IA32_VMX_EPT_VPID_CAP_AD                                  (1ULL << 21)

// EPTP Format
// intel's software developer's manual, volume 3, appendix 24.6.11
#define EPTP_MEMORY_TYPE                                   0x0000000000000007
#define EPTP_PAGE_WALK_LENGTH                              0x0000000000000038
#define EPTP_ACCESSED_DIRTY_FLAGS_ENABLED                  0x0000000000000040

// REMOVE ME
//
// This code needs to be cleaned up so that it's just part of getting this
// VMCS field. The call to it should be in the dump function in the VMCS
// code.
//
// std::string
// get_vm_instruction_error()
// {
//     switch (vm::read(VMCS_VM_INSTRUCTION_ERROR))
//     {
//         case 1:
//             return "VMCALL executed in VMX root operation";

//         case 2:
//             return "VMCLEAR with invalid physical address";

//         case 3:
//             return "VMCLEAR with VMXON pointer";

//         case 4:
//             return "VMLAUNCH with non-clear VMCS";

//         case 5:
//             return "VMRESUME with non-launched VMCS";

//         case 6:
//             return "VMRESUME after VMXOFF (VMXOFF and VMXON between "
//                    "VMLAUNCH and VMRESUME)";

//         case 7:
//             return "VM entry with invalid control field(s)";

//         case 8:
//             return "VM entry with invalid host-state field(s)";

//         case 9:
//             return "VMPTRLD with invalid physical address";

//         case 10:
//             return "VMPTRLD with VMXON pointer";

//         case 11:
//             return "VMPTRLD with incorrect VMCS revision identifier";

//         case 12:
//             return "VMREAD/VMWRITE from/to unsupported VMCS component";

//         case 13:
//             return "VMWRITE to read-only VMCS component";

//         case 15:
//             return "VMXON executed in VMX root operation";

//         case 16:
//             return "VM entry with invalid executive-VMCS pointer";

//         case 17:
//             return "VM entry with non-launched executive VMCS";

//         case 18:
//             return "VM entry with executive-VMCS pointer not VMXON "
//                    "pointer (when attempting to deactivate the "
//                    "dual-monitor treatment of SMIs and SMM)";

//         case 19:
//             return "VMCALL with non-clear VMCS (when attempting to "
//                    "activate the dual-monitor treatment of SMIs and "
//                    "SMM)";

//         case 20:
//             return "VMCALL with invalid VM-exit control fields";

//         case 22:
//             return "VMCALL with incorrect MSEG revision identifier "
//                    "(when attempting to activate the dual-monitor "
//                    "treatment of SMIs and SMM)";

//         case 23:
//             return "VMXOFF under dual-monitor treatment of SMIs and "
//                    "SMM";

//         case 24:
//             return "VMCALL with invalid SMM-monitor features (when "
//                    "attempting to activate the dual-monitor treatment "
//                    "of SMIs and SMM)";

//         case 25:
//             return "VM entry with invalid VM-execution control fields "
//                    "in executive VMCS (when attempting to return from "
//                    "SMM)";

//         case 26:
//             return "VM entry with events blocked by MOV SS.";

//         case 28:
//             return "Invalid operand to INVEPT/INVVPID.";

//         default:
//             return "Unknown VM instruction error";
//     }
// }

#endif
