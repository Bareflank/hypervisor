//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <bfcallonce.h>
#include <bfthreadcontext.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/exception.h>

//==============================================================================
// C Prototypes
//==============================================================================

extern "C" void exit_handler_entry(void) noexcept;

//==============================================================================
// Global State
//==============================================================================

static bfn::once_flag g_once_flag{};
static ::intel_x64::cr0::value_type g_cr0_reg{};
static ::intel_x64::cr3::value_type g_cr3_reg{};
static ::intel_x64::cr4::value_type g_cr4_reg{};
static ::intel_x64::msrs::value_type g_ia32_pat_msr{};
static ::intel_x64::msrs::value_type g_ia32_efer_msr{};

static void
setup()
{
    using namespace ::intel_x64;
    using namespace ::intel_x64::cpuid;

    using namespace bfvmm::x64;
    using attr_type = bfvmm::x64::cr3::mmap::attr_type;

    for (const auto &md : g_mm->descriptors()) {
        if (md.type == (MEMORY_TYPE_R | MEMORY_TYPE_E)) {
            g_cr3->map_4k(md.virt, md.phys, attr_type::read_execute);
            continue;
        }

        g_cr3->map_4k(md.virt, md.phys, attr_type::read_write);
    }

    g_ia32_efer_msr |= msrs::ia32_efer::lme::mask;
    g_ia32_efer_msr |= msrs::ia32_efer::lma::mask;
    g_ia32_efer_msr |= msrs::ia32_efer::nxe::mask;

    g_cr0_reg |= cr0::protection_enable::mask;
    g_cr0_reg |= cr0::monitor_coprocessor::mask;
    g_cr0_reg |= cr0::extension_type::mask;
    g_cr0_reg |= cr0::numeric_error::mask;
    g_cr0_reg |= cr0::write_protect::mask;
    g_cr0_reg |= cr0::paging::mask;

    g_cr3_reg = g_cr3->cr3();
    g_ia32_pat_msr = g_cr3->pat();

    g_cr4_reg |= cr4::v8086_mode_extensions::mask;
    g_cr4_reg |= cr4::protected_mode_virtual_interrupts::mask;
    g_cr4_reg |= cr4::time_stamp_disable::mask;
    g_cr4_reg |= cr4::debugging_extensions::mask;
    g_cr4_reg |= cr4::page_size_extensions::mask;
    g_cr4_reg |= cr4::physical_address_extensions::mask;
    g_cr4_reg |= cr4::machine_check_enable::mask;
    g_cr4_reg |= cr4::page_global_enable::mask;
    g_cr4_reg |= cr4::performance_monitor_counter_enable::mask;
    g_cr4_reg |= cr4::osfxsr::mask;
    g_cr4_reg |= cr4::osxmmexcpt::mask;
    g_cr4_reg |= cr4::vmx_enable_bit::mask;

    if (feature_information::ecx::xsave::is_enabled()) {
        g_cr4_reg |= ::intel_x64::cr4::osxsave::mask;
    }

    if (extended_feature_flags::subleaf0::ebx::smep::is_enabled()) {
        g_cr4_reg |= ::intel_x64::cr4::smep_enable_bit::mask;
    }

    if (extended_feature_flags::subleaf0::ebx::smap::is_enabled()) {
        g_cr4_reg |= ::intel_x64::cr4::smap_enable_bit::mask;
    }
}

//==============================================================================
// Implementation
//==============================================================================

namespace bfvmm::intel_x64
{

vcpu::vcpu(
    vcpuid::type id,
    vcpu_global_state_t *global_state
) :
    bfvmm::vcpu{id},
    m_global_state{global_state != nullptr ? global_state : & g_vcpu_global_state},
    m_state{std::make_unique<vcpu_state_t>()},

    m_msr_bitmap{make_page<uint8_t>()},
    m_io_bitmap_a{make_page<uint8_t>()},
    m_io_bitmap_b{make_page<uint8_t>()},

    m_ist1{std::make_unique<gsl::byte[]>(STACK_SIZE * 2)},
    m_stack{std::make_unique<gsl::byte[]>(STACK_SIZE * 2)},

    m_vmx{is_host_vcpu() ? std::make_unique<vmx>() : nullptr},

    m_vmcs{this},
    m_exit_handler{this},

    m_control_register_handler{this},
    m_cpuid_handler{this},
    m_ept_violation_handler{this},
    m_external_interrupt_handler{this},
    m_init_signal_handler{this},
    m_interrupt_window_handler{this},
    m_io_instruction_handler{this},
    m_monitor_trap_handler{this},
    m_nmi_window_handler{this},
    m_nmi_handler{this},
    m_preemption_timer_handler{this},
    m_rdmsr_handler{this},
    m_sipi_signal_handler{this},
    m_wrmsr_handler{this},
    m_xsetbv_handler{this},

    m_ept_handler{this},
    m_microcode_handler{this},
    m_vpid_handler{this}
{
    bfn::call_once(g_once_flag, setup);

    m_state->vcpu_ptr =
        reinterpret_cast<uintptr_t>(this);

    m_state->exit_handler_ptr =
        reinterpret_cast<uintptr_t>(&m_exit_handler);

    // Note:
    //
    // Up to this point, no modifications to the VMCS have been made. The only
    // thing that is done in the vCPU is the software state has been
    // initialized and set up. The remaining code, which is our last step is
    // to actually initialize the VMCS to its initial state. All of the VMCS
    // initialization logic can be found below. Also note that load() has
    // not been called yet, so any attempt to touch the VMCS prior to this
    // point will fail, ensuring that all of the initialization logic is
    // simple to follow.
    //

    this->load();

    this->write_host_state();
    this->write_control_state();

    if (this->is_host_vcpu()) {
        this->write_guest_state();
    }

    m_vpid_handler.enable();
    m_nmi_handler.enable_exiting();
    m_control_register_handler.enable_wrcr0_exiting(0);
    m_control_register_handler.enable_wrcr4_exiting(0);
}

void
vcpu::run()
{
    if (m_launched) {

        for (const auto &d : m_resume_delegates) {
            d(this);
        }

        m_vmcs.resume();
    }
    else {

        try {

            for (const auto &d : m_launch_delegates) {
                d(this);
            }

            m_launched = true;
            m_vmcs.launch();
        }
        catch (...) {
            m_launched = false;
            throw;
        }
    }
}

//==============================================================================
// Initial VMCS State
//==============================================================================

void
vcpu::write_host_state()
{
    using namespace ::intel_x64::vmcs;
    using namespace ::x64::access_rights;

    m_host_gdt.set(1, nullptr, 0xFFFFFFFF, ring0_cs_descriptor);
    m_host_gdt.set(2, nullptr, 0xFFFFFFFF, ring0_ss_descriptor);
    m_host_gdt.set(3, nullptr, 0xFFFFFFFF, ring0_fs_descriptor);
    m_host_gdt.set(4, nullptr, 0xFFFFFFFF, ring0_gs_descriptor);
    m_host_gdt.set(5, &m_host_tss, sizeof(m_host_tss), ring0_tr_descriptor);

    host_cs_selector::set(1 << 3);
    host_ss_selector::set(2 << 3);
    host_fs_selector::set(3 << 3);
    host_gs_selector::set(4 << 3);
    host_tr_selector::set(5 << 3);

    host_ia32_pat::set(g_ia32_pat_msr);
    host_ia32_efer::set(g_ia32_efer_msr);

    host_cr0::set(g_cr0_reg);
    host_cr3::set(g_cr3_reg);
    host_cr4::set(g_cr4_reg);

    host_gs_base::set(reinterpret_cast<uintptr_t>(m_state.get()));
    host_tr_base::set(m_host_gdt.base(5));

    host_gdtr_base::set(m_host_gdt.base());
    host_idtr_base::set(m_host_idt.base());

    m_host_tss.ist1 = setup_stack(m_ist1.get(), this->id());
    set_default_esrs(&m_host_idt, 8);

    host_rip::set(exit_handler_entry);
    host_rsp::set(setup_stack(m_stack.get(), this->id()));
}

void
vcpu::write_guest_state()
{
    using namespace ::intel_x64;
    using namespace ::intel_x64::vmcs;
    using namespace ::intel_x64::cpuid;

    using namespace ::x64::access_rights;
    using namespace ::x64::segment_register;

    x64::gdt guest_gdt;
    x64::idt guest_idt;

    auto es_index = es::index::get();
    auto cs_index = cs::index::get();
    auto ss_index = ss::index::get();
    auto ds_index = ds::index::get();
    auto fs_index = fs::index::get();
    auto gs_index = gs::index::get();
    auto ldtr_index = ldtr::index::get();
    auto tr_index = tr::index::get();

    vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFF);

    guest_es_selector::set(es::get());
    guest_cs_selector::set(cs::get());
    guest_ss_selector::set(ss::get());
    guest_ds_selector::set(ds::get());
    guest_fs_selector::set(fs::get());
    guest_gs_selector::set(gs::get());
    guest_ldtr_selector::set(ldtr::get());
    guest_tr_selector::set(tr::get());

    guest_ia32_debugctl::set(msrs::ia32_debugctl::get());
    guest_ia32_pat::set(::x64::msrs::ia32_pat::get());
    guest_ia32_efer::set(msrs::ia32_efer::get());

    if (arch_perf_monitoring::eax::version_id::get() >= 2) {
        guest_ia32_perf_global_ctrl::set_if_exists(
            msrs::ia32_perf_global_ctrl::get()
        );
    }

    guest_gdtr_limit::set(guest_gdt.limit());
    guest_idtr_limit::set(guest_idt.limit());

    guest_gdtr_base::set(guest_gdt.base());
    guest_idtr_base::set(guest_idt.base());

    guest_es_limit::set(es_index != 0 ? guest_gdt.limit(es_index) : 0);
    guest_cs_limit::set(cs_index != 0 ? guest_gdt.limit(cs_index) : 0);
    guest_ss_limit::set(ss_index != 0 ? guest_gdt.limit(ss_index) : 0);
    guest_ds_limit::set(ds_index != 0 ? guest_gdt.limit(ds_index) : 0);
    guest_fs_limit::set(fs_index != 0 ? guest_gdt.limit(fs_index) : 0);
    guest_gs_limit::set(gs_index != 0 ? guest_gdt.limit(gs_index) : 0);
    guest_ldtr_limit::set(ldtr_index != 0 ? guest_gdt.limit(ldtr_index) : 0);
    guest_tr_limit::set(tr_index != 0 ? guest_gdt.limit(tr_index) : 0);

    guest_es_access_rights::set(es_index != 0 ? guest_gdt.access_rights(es_index) : unusable);
    guest_cs_access_rights::set(cs_index != 0 ? guest_gdt.access_rights(cs_index) : unusable);
    guest_ss_access_rights::set(ss_index != 0 ? guest_gdt.access_rights(ss_index) : unusable);
    guest_ds_access_rights::set(ds_index != 0 ? guest_gdt.access_rights(ds_index) : unusable);
    guest_fs_access_rights::set(fs_index != 0 ? guest_gdt.access_rights(fs_index) : unusable);
    guest_gs_access_rights::set(gs_index != 0 ? guest_gdt.access_rights(gs_index) : unusable);
    guest_ldtr_access_rights::set(ldtr_index != 0 ? guest_gdt.access_rights(ldtr_index) : unusable);
    guest_tr_access_rights::set(tr_index != 0 ? guest_gdt.access_rights(tr_index) : type::tss_busy | 0x80U);

    guest_es_base::set(es_index != 0 ? guest_gdt.base(es_index) : 0);
    guest_cs_base::set(cs_index != 0 ? guest_gdt.base(cs_index) : 0);
    guest_ss_base::set(ss_index != 0 ? guest_gdt.base(ss_index) : 0);
    guest_ds_base::set(ds_index != 0 ? guest_gdt.base(ds_index) : 0);
    guest_fs_base::set(msrs::ia32_fs_base::get());
    guest_gs_base::set(msrs::ia32_gs_base::get());
    guest_ldtr_base::set(ldtr_index != 0 ? guest_gdt.base(ldtr_index) : 0);
    guest_tr_base::set(tr_index != 0 ? guest_gdt.base(tr_index) : 0);

    this->set_cr0(cr0::get());
    guest_cr3::set(cr3::get());
    this->set_cr4(cr4::get());
    guest_dr7::set(dr7::get());

    guest_rflags::set(::x64::rflags::get());

    guest_ia32_sysenter_cs::set(msrs::ia32_sysenter_cs::get());
    guest_ia32_sysenter_esp::set(msrs::ia32_sysenter_esp::get());
    guest_ia32_sysenter_eip::set(msrs::ia32_sysenter_eip::get());
}

void
vcpu::write_control_state()
{
    using namespace ::intel_x64::vmcs;

    auto ia32_vmx_pinbased_ctls_msr =
        ::intel_x64::msrs::ia32_vmx_true_pinbased_ctls::get();
    auto ia32_vmx_procbased_ctls_msr =
        ::intel_x64::msrs::ia32_vmx_true_procbased_ctls::get();
    auto ia32_vmx_exit_ctls_msr =
        ::intel_x64::msrs::ia32_vmx_true_exit_ctls::get();
    auto ia32_vmx_entry_ctls_msr =
        ::intel_x64::msrs::ia32_vmx_true_entry_ctls::get();

    pin_based_vm_execution_controls::set(
        ((ia32_vmx_pinbased_ctls_msr >> 0) & 0x00000000FFFFFFFF) &
        ((ia32_vmx_pinbased_ctls_msr >> 32) & 0x00000000FFFFFFFF)
    );

    primary_processor_based_vm_execution_controls::set(
        ((ia32_vmx_procbased_ctls_msr >> 0) & 0x00000000FFFFFFFF) &
        ((ia32_vmx_procbased_ctls_msr >> 32) & 0x00000000FFFFFFFF)
    );

    vm_exit_controls::set(
        ((ia32_vmx_exit_ctls_msr >> 0) & 0x00000000FFFFFFFF) &
        ((ia32_vmx_exit_ctls_msr >> 32) & 0x00000000FFFFFFFF)
    );

    vm_entry_controls::set(
        ((ia32_vmx_entry_ctls_msr >> 0) & 0x00000000FFFFFFFF) &
        ((ia32_vmx_entry_ctls_msr >> 32) & 0x00000000FFFFFFFF)
    );

    using namespace pin_based_vm_execution_controls;
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
    address_of_io_bitmap_a::set(g_mm->virtptr_to_physint(m_io_bitmap_a.get()));
    address_of_io_bitmap_b::set(g_mm->virtptr_to_physint(m_io_bitmap_b.get()));

    use_msr_bitmap::enable();
    use_io_bitmaps::enable();

    activate_secondary_controls::enable_if_allowed();

    if (this->is_host_vcpu()) {
        enable_rdtscp::enable_if_allowed();
        enable_invpcid::enable_if_allowed();
        enable_xsaves_xrstors::enable_if_allowed();
    }

    vm_exit_controls::save_debug_controls::enable();
    vm_exit_controls::host_address_space_size::enable();
    vm_exit_controls::load_ia32_perf_global_ctrl::enable_if_allowed();
    vm_exit_controls::save_ia32_pat::enable();
    vm_exit_controls::load_ia32_pat::enable();
    vm_exit_controls::save_ia32_efer::enable();
    vm_exit_controls::load_ia32_efer::enable();

    vm_entry_controls::load_debug_controls::enable();
    vm_entry_controls::ia_32e_mode_guest::enable();
    vm_entry_controls::load_ia32_perf_global_ctrl::enable_if_allowed();
    vm_entry_controls::load_ia32_pat::enable();
    vm_entry_controls::load_ia32_efer::enable();
}

//==============================================================================
// VMCS Operations
//==============================================================================

void
vcpu::load()
{ m_vmcs.load(); }

void
vcpu::clear()
{
    for (const auto &d : m_clear_delegates) {
        d(this);
    }

    m_vmcs.clear();
    m_launched = false;
}

void
vcpu::promote()
{ m_vmcs.promote(); }

bool
vcpu::advance()
{
    using namespace ::intel_x64::vmcs;

    this->set_rip(this->rip() + vm_exit_instruction_length::get());
    return true;
}

//==============================================================================
// Handler Operations
//==============================================================================

void
vcpu::add_exit_handler(
    const handler_delegate_t &d)
{ m_exit_handler.add_exit_handler(d); }

void
vcpu::add_exit_handler_for_reason(
    ::intel_x64::vmcs::value_type reason,
    const handler_delegate_t &d)
{ m_exit_handler.add_handler(reason, d); }

//==============================================================================
// Fault Handling
//==============================================================================

void
vcpu::dump(const char *str)
{
    using namespace ::intel_x64::vmcs;

    bfdebug_transaction(0, [&](std::string * msg) {

        bferror_lnbr(0, msg);
        bferror_info(0, str, msg);
        bferror_brk1(0, msg);

        bferror_lnbr(0, msg);
        bferror_info(0, "general purpose registers", msg);
        bferror_subnhex(0, "rax", this->rax(), msg);
        bferror_subnhex(0, "rbx", this->rbx(), msg);
        bferror_subnhex(0, "rcx", this->rcx(), msg);
        bferror_subnhex(0, "rdx", this->rdx(), msg);
        bferror_subnhex(0, "rbp", this->rbp(), msg);
        bferror_subnhex(0, "rsi", this->rsi(), msg);
        bferror_subnhex(0, "rdi", this->rdi(), msg);
        bferror_subnhex(0, "r08", this->r08(), msg);
        bferror_subnhex(0, "r09", this->r09(), msg);
        bferror_subnhex(0, "r10", this->r10(), msg);
        bferror_subnhex(0, "r11", this->r11(), msg);
        bferror_subnhex(0, "r12", this->r12(), msg);
        bferror_subnhex(0, "r13", this->r13(), msg);
        bferror_subnhex(0, "r14", this->r14(), msg);
        bferror_subnhex(0, "r15", this->r15(), msg);
        bferror_subnhex(0, "rip", this->rip(), msg);
        bferror_subnhex(0, "rsp", this->rsp(), msg);
        bferror_subnhex(0, "gr1", this->gr1(), msg);
        bferror_subnhex(0, "gr2", this->gr2(), msg);
        bferror_subnhex(0, "gr3", this->gr3(), msg);
        bferror_subnhex(0, "gr4", this->gr4(), msg);

        bferror_lnbr(0, msg);
        bferror_info(0, "control registers", msg);
        bferror_subnhex(0, "cr0", guest_cr0::get(), msg);
        bferror_subnhex(0, "cr2", ::intel_x64::cr2::get(), msg);
        bferror_subnhex(0, "cr3", guest_cr3::get(), msg);
        bferror_subnhex(0, "cr4", guest_cr4::get(), msg);

        bferror_lnbr(0, msg);
        bferror_info(0, "addressing", msg);
        bferror_subnhex(0, "linear address", guest_linear_address::get(), msg);
        bferror_subnhex(0, "physical address", guest_physical_address::get(), msg);

        bferror_lnbr(0, msg);
        bferror_info(0, "exit info", msg);
        bferror_subnhex(0, "reason", exit_reason::get(), msg);
        bferror_subtext(0, "description", exit_reason::basic_exit_reason::description(), msg);
        bferror_subnhex(0, "qualification", exit_qualification::get(), msg);
    });

    if (exit_reason::vm_entry_failure::is_enabled()) {
        m_vmcs.check();
    }
}

void
vcpu::halt(const std::string &str)
{
    this->dump(("halting vcpu: " + str).c_str());
    ::x64::pm::stop();
}

//==========================================================================
// VMExit
//==========================================================================

//--------------------------------------------------------------------------
// Control Register
//--------------------------------------------------------------------------

void
vcpu::add_wrcr0_handler(
    vmcs_n::value_type mask, const handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr0_handler(d);
    m_control_register_handler.enable_wrcr0_exiting(mask);
}

void
vcpu::add_rdcr3_handler(
    const handler_delegate_t &d)
{
    m_control_register_handler.add_rdcr3_handler(d);
    m_control_register_handler.enable_rdcr3_exiting();
}

void
vcpu::add_wrcr3_handler(
    const handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr3_handler(d);
    m_control_register_handler.enable_wrcr3_exiting();
}

void
vcpu::add_wrcr4_handler(
    vmcs_n::value_type mask, const handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr4_handler(d);
    m_control_register_handler.enable_wrcr4_exiting(mask);
}

void
vcpu::execute_wrcr0()
{ m_control_register_handler.execute_wrcr0(this); }

void
vcpu::execute_rdcr3()
{ m_control_register_handler.execute_rdcr3(this); }

void
vcpu::execute_wrcr3()
{ m_control_register_handler.execute_wrcr3(this); }

void
vcpu::execute_wrcr4()
{ m_control_register_handler.execute_wrcr4(this); }

//--------------------------------------------------------------------------
// CPUID
//--------------------------------------------------------------------------

void
vcpu::add_cpuid_handler(
    cpuid_handler::leaf_t leaf, const handler_delegate_t &d)
{ m_cpuid_handler.add_handler(leaf, d); }

void
vcpu::add_cpuid_emulator(
    cpuid_handler::leaf_t leaf, const handler_delegate_t &d)
{ m_cpuid_handler.add_emulator(leaf, d); }

void
vcpu::execute_cpuid()
{ m_cpuid_handler.execute(this); }

void
vcpu::enable_cpuid_whitelisting() noexcept
{ m_cpuid_handler.enable_whitelisting(); }

//--------------------------------------------------------------------------
// EPT Violation
//--------------------------------------------------------------------------

void
vcpu::add_ept_read_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_read_handler(d); }

void
vcpu::add_ept_write_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_write_handler(d); }

void
vcpu::add_ept_execute_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_execute_handler(d); }

void
vcpu::add_default_ept_read_violation_handler(
    const ::handler_delegate_t &d)
{ m_ept_violation_handler.set_default_read_handler(d); }

void
vcpu::add_default_ept_write_violation_handler(
    const ::handler_delegate_t &d)
{ m_ept_violation_handler.set_default_write_handler(d); }

void
vcpu::add_default_ept_execute_violation_handler(
    const ::handler_delegate_t &d)
{ m_ept_violation_handler.set_default_execute_handler(d); }

//--------------------------------------------------------------------------
// External Interrupt
//--------------------------------------------------------------------------

void
vcpu::add_external_interrupt_handler(
    const external_interrupt_handler::handler_delegate_t &d)
{
    m_external_interrupt_handler.add_handler(d);
    m_external_interrupt_handler.enable_exiting();
}

void
vcpu::disable_external_interrupts()
{ m_external_interrupt_handler.disable_exiting(); }

//--------------------------------------------------------------------------
// Interrupt Window
//--------------------------------------------------------------------------

void
vcpu::queue_external_interrupt(uint64_t vector)
{ m_interrupt_window_handler.queue_external_interrupt(vector); }

void
vcpu::inject_exception(uint64_t vector, uint64_t ec)
{ m_interrupt_window_handler.inject_exception(vector, ec); }

void
vcpu::inject_external_interrupt(uint64_t vector)
{ m_interrupt_window_handler.inject_external_interrupt(vector); }

//--------------------------------------------------------------------------
// IO Instruction
//--------------------------------------------------------------------------

void
vcpu::trap_on_all_io_instruction_accesses()
{ m_io_instruction_handler.trap_on_all_accesses(); }

void
vcpu::pass_through_all_io_instruction_accesses()
{ m_io_instruction_handler.pass_through_all_accesses(); }

void
vcpu::pass_through_io_accesses(vmcs_n::value_type port)
{ m_io_instruction_handler.pass_through_access(port); }

void
vcpu::add_io_instruction_handler(
    vmcs_n::value_type port,
    const io_instruction_handler::handler_delegate_t &in_d,
    const io_instruction_handler::handler_delegate_t &out_d)
{
    m_io_instruction_handler.trap_on_access(port);
    m_io_instruction_handler.add_handler(port, in_d, out_d);
}

void
vcpu::emulate_io_instruction(
    vmcs_n::value_type port,
    const io_instruction_handler::handler_delegate_t &in_d,
    const io_instruction_handler::handler_delegate_t &out_d)
{
    this->add_io_instruction_handler(port, in_d, out_d);
    m_io_instruction_handler.emulate(port);
}

void
vcpu::add_default_io_instruction_handler(
    const ::handler_delegate_t &d)
{ m_io_instruction_handler.set_default_handler(d); }

//--------------------------------------------------------------------------
// Monitor Trap
//--------------------------------------------------------------------------

void
vcpu::add_monitor_trap_handler(
    const ::handler_delegate_t &d)
{ m_monitor_trap_handler.add_handler(d); }

void
vcpu::enable_monitor_trap_flag()
{ m_monitor_trap_handler.enable(); }

//--------------------------------------------------------------------------
// Non-Maskable Interrupt Window
//--------------------------------------------------------------------------

void
vcpu::queue_nmi()
{ m_nmi_window_handler.queue_nmi(); }

void
vcpu::inject_nmi()
{ m_nmi_window_handler.inject_nmi(); }

//--------------------------------------------------------------------------
// Non-Maskable Interrupts
//--------------------------------------------------------------------------

void
vcpu::add_nmi_handler(
    const nmi_handler::handler_delegate_t &d)
{
    m_nmi_handler.add_handler(d);
    m_nmi_handler.enable_exiting();
}

void
vcpu::enable_nmis()
{ m_nmi_handler.enable_exiting(); }

void
vcpu::disable_nmis()
{ m_nmi_handler.disable_exiting(); }

//--------------------------------------------------------------------------
// Read MSR
//--------------------------------------------------------------------------

void
vcpu::trap_on_rdmsr_access(vmcs_n::value_type msr)
{ m_rdmsr_handler.trap_on_access(msr); }

void
vcpu::trap_on_all_rdmsr_accesses()
{ m_rdmsr_handler.trap_on_all_accesses(); }

void
vcpu::pass_through_rdmsr_access(vmcs_n::value_type msr)
{ m_rdmsr_handler.pass_through_access(msr); }

void
vcpu::pass_through_all_rdmsr_accesses()
{ m_rdmsr_handler.pass_through_all_accesses(); }

void
vcpu::add_rdmsr_handler(
    vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d)
{
    m_rdmsr_handler.trap_on_access(msr);
    m_rdmsr_handler.add_handler(msr, d);
}

void
vcpu::emulate_rdmsr(
    vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d)
{
    this->add_rdmsr_handler(msr, d);
    m_rdmsr_handler.emulate(msr);
}

void
vcpu::add_default_rdmsr_handler(
    const ::handler_delegate_t &d)
{ m_rdmsr_handler.set_default_handler(d); }

//--------------------------------------------------------------------------
// Write MSR
//--------------------------------------------------------------------------

void
vcpu::trap_on_wrmsr_access(vmcs_n::value_type msr)
{ m_wrmsr_handler.trap_on_access(msr); }

void
vcpu::trap_on_all_wrmsr_accesses()
{ m_wrmsr_handler.trap_on_all_accesses(); }

void
vcpu::pass_through_wrmsr_access(vmcs_n::value_type msr)
{ m_wrmsr_handler.pass_through_access(msr); }

void
vcpu::pass_through_all_wrmsr_accesses()
{ m_wrmsr_handler.pass_through_all_accesses(); }

void
vcpu::add_wrmsr_handler(
    vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d)
{
    m_wrmsr_handler.trap_on_access(msr);
    m_wrmsr_handler.add_handler(msr, d);
}

void
vcpu::emulate_wrmsr(
    vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d)
{
    this->add_wrmsr_handler(msr, d);
    m_wrmsr_handler.emulate(msr);
}

void
vcpu::add_default_wrmsr_handler(
    const ::handler_delegate_t &d)
{ m_wrmsr_handler.set_default_handler(d); }

//--------------------------------------------------------------------------
// XSetBV
//--------------------------------------------------------------------------

void
vcpu::add_xsetbv_handler(
    const xsetbv_handler::handler_delegate_t &d)
{ m_xsetbv_handler.add_handler(d); }

//--------------------------------------------------------------------------
// VMX preemption timer
//--------------------------------------------------------------------------

void
vcpu::add_preemption_timer_handler(
    const preemption_timer_handler::handler_delegate_t &d)
{ m_preemption_timer_handler.add_handler(d); }

void
vcpu::set_preemption_timer(
    const preemption_timer_handler::value_t val)
{
    m_preemption_timer_handler.enable_exiting();
    m_preemption_timer_handler.set_timer(val);
}

preemption_timer_handler::value_t
vcpu::get_preemption_timer()
{ return m_preemption_timer_handler.get_timer(); }

void
vcpu::enable_preemption_timer()
{ m_preemption_timer_handler.enable_exiting(); }

void
vcpu::disable_preemption_timer()
{ m_preemption_timer_handler.disable_exiting(); }

//==========================================================================
// EPT
//==========================================================================

void
vcpu::set_eptp(ept::mmap &map)
{
    m_ept_handler.set_eptp(&map);
    m_mmap = &map;
}

void
vcpu::disable_ept()
{
    m_ept_handler.set_eptp(nullptr);
    m_mmap = nullptr;
}

//==========================================================================
// VPID
//==========================================================================

void
vcpu::enable_vpid()
{ m_vpid_handler.enable(); }

void
vcpu::disable_vpid()
{ m_vpid_handler.disable(); }

//==========================================================================
// Helpers
//==========================================================================

void
vcpu::trap_on_msr_access(vmcs_n::value_type msr)
{
    this->trap_on_rdmsr_access(msr);
    this->trap_on_wrmsr_access(msr);
}

void
vcpu::pass_through_msr_access(vmcs_n::value_type msr)
{
    this->pass_through_rdmsr_access(msr);
    this->pass_through_wrmsr_access(msr);
}

//==============================================================================
// Memory Mapping
//==============================================================================

/// TODO
///
/// There are several things that still need to be implemented for memory
/// mapping to make this a complete set of APIs.
/// - Currently, there is no support for a 32bit guest. We currently assume
///   that CR3 is 64bit.
/// - Currently, we have a lot of support for the different page sizes, but
///   we do not handle them in the guest WRT to mapping a GVA to the VMM. We
///   only support 4k granularity.

std::pair<uintptr_t, uintptr_t>
vcpu::gpa_to_hpa(uintptr_t gpa)
{
    if (m_mmap == nullptr) {
        return {gpa, 0};
    }

    return m_mmap->virt_to_phys(gpa);
}

std::pair<uintptr_t, uintptr_t>
vcpu::gva_to_gpa(uint64_t gva)
{
    using namespace ::x64;
    using namespace vmcs_n;

    if (guest_cr0::paging::is_disabled()) {
        return {gva, 0};
    }

    // -------------------------------------------------------------------------
    // PML4

    auto pml4_pte =
        get_entry(bfn::upper(this->cr3()), pml4::index(gva));

    if (pml4::entry::present::is_disabled(pml4_pte)) {
        throw std::runtime_error("pml4_pte is not present");
    }

    // -------------------------------------------------------------------------
    // PDPT

    auto pdpt_pte =
        get_entry(pml4::entry::phys_addr::get(pml4_pte), pdpt::index(gva));

    if (pdpt::entry::present::is_disabled(pdpt_pte)) {
        throw std::runtime_error("pdpt_pte is not present");
    }

    if (pdpt::entry::ps::is_enabled(pdpt_pte)) {
        return {
            pdpt::entry::phys_addr::get(pdpt_pte) | bfn::lower(gva, pdpt::from),
            pdpt::from
        };
    }

    // -------------------------------------------------------------------------
    // PD

    auto pd_pte =
        get_entry(pdpt::entry::phys_addr::get(pdpt_pte), pd::index(gva));

    if (pd::entry::present::is_disabled(pd_pte)) {
        throw std::runtime_error("pd_pte is not present");
    }

    if (pd::entry::ps::is_enabled(pd_pte)) {
        return {
            pd::entry::phys_addr::get(pd_pte) | bfn::lower(gva, pd::from),
            pd::from
        };
    }

    // -------------------------------------------------------------------------
    // PT

    auto pt_pte =
        get_entry(pd::entry::phys_addr::get(pd_pte), pt::index(gva));

    if (pt::entry::present::is_disabled(pt_pte)) {
        throw std::runtime_error("pt_pte is not present");
    }

    return {
        pt::entry::phys_addr::get(pt_pte) | bfn::lower(gva, pt::from),
        pt::from
    };
}

std::pair<uintptr_t, uintptr_t>
vcpu::gva_to_hpa(uint64_t gva)
{
    auto ret = this->gva_to_gpa(gva);

    if (m_mmap == nullptr) {
        return ret;
    }

    return this->gpa_to_hpa(ret.first);
}

void
vcpu::map_1g_ro(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_1g(gpa, hpa, ept::mmap::attr_type::read_only);
}

void
vcpu::map_2m_ro(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_2m(gpa, hpa, ept::mmap::attr_type::read_only);
}

void
vcpu::map_4k_ro(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_4k(gpa, hpa, ept::mmap::attr_type::read_only);
}

void
vcpu::map_1g_rw(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_1g(gpa, hpa, ept::mmap::attr_type::read_write);
}

void
vcpu::map_2m_rw(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_2m(gpa, hpa, ept::mmap::attr_type::read_write);
}

void
vcpu::map_4k_rw(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_4k(gpa, hpa, ept::mmap::attr_type::read_write);
}

void
vcpu::map_1g_rwe(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_1g(gpa, hpa, ept::mmap::attr_type::read_write_execute);
}

void
vcpu::map_2m_rwe(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_2m(gpa, hpa, ept::mmap::attr_type::read_write_execute);
}

void
vcpu::map_4k_rwe(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_4k(gpa, hpa, ept::mmap::attr_type::read_write_execute);
}

uintptr_t
vcpu::get_entry(uintptr_t tble_gpa, std::ptrdiff_t index)
{
    auto tble = this->map_gpa_4k<uintptr_t>(tble_gpa);
    auto span = gsl::span(tble.get(), ::x64::pt::num_entries);

    return span[index];
}

//==============================================================================
// Registers
//==============================================================================

uint64_t
vcpu::rax() const noexcept
{ return m_state->rax; }

void
vcpu::set_rax(uint64_t val) noexcept
{ m_state->rax = val; }

uint64_t
vcpu::rbx() const noexcept
{ return m_state->rbx; }

void
vcpu::set_rbx(uint64_t val) noexcept
{ m_state->rbx = val; }

uint64_t
vcpu::rcx() const noexcept
{ return m_state->rcx; }

void
vcpu::set_rcx(uint64_t val) noexcept
{ m_state->rcx = val; }

uint64_t
vcpu::rdx() const noexcept
{ return m_state->rdx; }

void
vcpu::set_rdx(uint64_t val) noexcept
{ m_state->rdx = val; }

uint64_t
vcpu::rbp() const noexcept
{ return m_state->rbp; }

void
vcpu::set_rbp(uint64_t val) noexcept
{ m_state->rbp = val; }

uint64_t
vcpu::rsi() const noexcept
{ return m_state->rsi; }

void
vcpu::set_rsi(uint64_t val) noexcept
{ m_state->rsi = val; }

uint64_t
vcpu::rdi() const noexcept
{ return m_state->rdi; }

void
vcpu::set_rdi(uint64_t val) noexcept
{ m_state->rdi = val; }

uint64_t
vcpu::r08() const noexcept
{ return m_state->r08; }

void
vcpu::set_r08(uint64_t val) noexcept
{ m_state->r08 = val; }

uint64_t
vcpu::r09() const noexcept
{ return m_state->r09; }

void
vcpu::set_r09(uint64_t val) noexcept
{ m_state->r09 = val; }

uint64_t
vcpu::r10() const noexcept
{ return m_state->r10; }

void
vcpu::set_r10(uint64_t val) noexcept
{ m_state->r10 = val; }

uint64_t
vcpu::r11() const noexcept
{ return m_state->r11; }

void
vcpu::set_r11(uint64_t val) noexcept
{ m_state->r11 = val; }

uint64_t
vcpu::r12() const noexcept
{ return m_state->r12; }

void
vcpu::set_r12(uint64_t val) noexcept
{ m_state->r12 = val; }

uint64_t
vcpu::r13() const noexcept
{ return m_state->r13; }

void
vcpu::set_r13(uint64_t val) noexcept
{ m_state->r13 = val; }

uint64_t
vcpu::r14() const noexcept
{ return m_state->r14; }

void
vcpu::set_r14(uint64_t val) noexcept
{ m_state->r14 = val; }

uint64_t
vcpu::r15() const noexcept
{ return m_state->r15; }

void
vcpu::set_r15(uint64_t val) noexcept
{ m_state->r15 = val; }

uint64_t
vcpu::rip() const noexcept
{ return m_state->rip; }

void
vcpu::set_rip(uint64_t val) noexcept
{ m_state->rip = val; }

uint64_t
vcpu::rsp() const noexcept
{ return m_state->rsp; }

void
vcpu::set_rsp(uint64_t val) noexcept
{ m_state->rsp = val; }

uint64_t
vcpu::gdt_base() const noexcept
{ return vmcs_n::guest_gdtr_base::get(); }

void
vcpu::set_gdt_base(uint64_t val) noexcept
{ vmcs_n::guest_gdtr_base::set(val); }

uint64_t
vcpu::gdt_limit() const noexcept
{ return vmcs_n::guest_gdtr_limit::get(); }

void
vcpu::set_gdt_limit(uint64_t val) noexcept
{ vmcs_n::guest_gdtr_limit::set(val); }

uint64_t
vcpu::idt_base() const noexcept
{ return vmcs_n::guest_idtr_base::get(); }

void
vcpu::set_idt_base(uint64_t val) noexcept
{ vmcs_n::guest_idtr_base::set(val); }

uint64_t
vcpu::idt_limit() const noexcept
{ return vmcs_n::guest_idtr_limit::get(); }

void
vcpu::set_idt_limit(uint64_t val) noexcept
{ vmcs_n::guest_idtr_limit::set(val); }

uint64_t
vcpu::cr0() const noexcept
{ return vmcs_n::cr0_read_shadow::get(); }

void
vcpu::set_cr0(uint64_t val) noexcept
{
    vmcs_n::cr0_read_shadow::set(val);

    ::intel_x64::cr0::extension_type::enable(val);
    ::intel_x64::cr0::not_write_through::disable(val);
    ::intel_x64::cr0::cache_disable::disable(val);

    vmcs_n::guest_cr0::set(val | m_global_state->ia32_vmx_cr0_fixed0);
}

uint64_t
vcpu::cr3() const noexcept
{ return vmcs_n::guest_cr3::get(); }

void
vcpu::set_cr3(uint64_t val) noexcept
{
    vmcs_n::guest_cr3::set(val & 0x7FFFFFFFFFFFFFFF);
}

uint64_t
vcpu::cr4() const noexcept
{ return vmcs_n::cr4_read_shadow::get(); }

void
vcpu::set_cr4(uint64_t val) noexcept
{
    vmcs_n::cr4_read_shadow::set(val);
    vmcs_n::guest_cr4::set(val | m_global_state->ia32_vmx_cr4_fixed0);
}

uint64_t
vcpu::ia32_efer() const noexcept
{ return vmcs_n::guest_ia32_efer::get(); }

void
vcpu::set_ia32_efer(uint64_t val) noexcept
{ vmcs_n::guest_ia32_efer::set(val); }

uint64_t
vcpu::ia32_pat() const noexcept
{ return vmcs_n::guest_ia32_pat::get(); }

void
vcpu::set_ia32_pat(uint64_t val) noexcept
{ vmcs_n::guest_ia32_pat::set(val); }


uint64_t
vcpu::es_selector() const noexcept
{ return vmcs_n::guest_es_selector::get(); }

void
vcpu::set_es_selector(uint64_t val) noexcept
{ vmcs_n::guest_es_selector::set(val); }

uint64_t
vcpu::es_base() const noexcept
{ return vmcs_n::guest_es_base::get(); }

void
vcpu::set_es_base(uint64_t val) noexcept
{ vmcs_n::guest_es_base::set(val); }

uint64_t
vcpu::es_limit() const noexcept
{ return vmcs_n::guest_es_limit::get(); }

void
vcpu::set_es_limit(uint64_t val) noexcept
{ vmcs_n::guest_es_limit::set(val); }

uint64_t
vcpu::es_access_rights() const noexcept
{ return vmcs_n::guest_es_access_rights::get(); }

void
vcpu::set_es_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_es_access_rights::set(val); }

uint64_t
vcpu::cs_selector() const noexcept
{ return vmcs_n::guest_cs_selector::get(); }

void
vcpu::set_cs_selector(uint64_t val) noexcept
{ vmcs_n::guest_cs_selector::set(val); }

uint64_t
vcpu::cs_base() const noexcept
{ return vmcs_n::guest_cs_base::get(); }

void
vcpu::set_cs_base(uint64_t val) noexcept
{ vmcs_n::guest_cs_base::set(val); }

uint64_t
vcpu::cs_limit() const noexcept
{ return vmcs_n::guest_cs_limit::get(); }

void
vcpu::set_cs_limit(uint64_t val) noexcept
{ vmcs_n::guest_cs_limit::set(val); }

uint64_t
vcpu::cs_access_rights() const noexcept
{ return vmcs_n::guest_cs_access_rights::get(); }

void
vcpu::set_cs_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_cs_access_rights::set(val); }

uint64_t
vcpu::ss_selector() const noexcept
{ return vmcs_n::guest_ss_selector::get(); }

void
vcpu::set_ss_selector(uint64_t val) noexcept
{ vmcs_n::guest_ss_selector::set(val); }

uint64_t
vcpu::ss_base() const noexcept
{ return vmcs_n::guest_ss_base::get(); }

void
vcpu::set_ss_base(uint64_t val) noexcept
{ vmcs_n::guest_ss_base::set(val); }

uint64_t
vcpu::ss_limit() const noexcept
{ return vmcs_n::guest_ss_limit::get(); }

void
vcpu::set_ss_limit(uint64_t val) noexcept
{ vmcs_n::guest_ss_limit::set(val); }

uint64_t
vcpu::ss_access_rights() const noexcept
{ return vmcs_n::guest_ss_access_rights::get(); }

void
vcpu::set_ss_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_ss_access_rights::set(val); }

uint64_t
vcpu::ds_selector() const noexcept
{ return vmcs_n::guest_ds_selector::get(); }

void
vcpu::set_ds_selector(uint64_t val) noexcept
{ vmcs_n::guest_ds_selector::set(val); }

uint64_t
vcpu::ds_base() const noexcept
{ return vmcs_n::guest_ds_base::get(); }

void
vcpu::set_ds_base(uint64_t val) noexcept
{ vmcs_n::guest_ds_base::set(val); }

uint64_t
vcpu::ds_limit() const noexcept
{ return vmcs_n::guest_ds_limit::get(); }

void
vcpu::set_ds_limit(uint64_t val) noexcept
{ vmcs_n::guest_ds_limit::set(val); }

uint64_t
vcpu::ds_access_rights() const noexcept
{ return vmcs_n::guest_ds_access_rights::get(); }

void
vcpu::set_ds_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_ds_access_rights::set(val); }

uint64_t
vcpu::fs_selector() const noexcept
{ return vmcs_n::guest_fs_selector::get(); }

void
vcpu::set_fs_selector(uint64_t val) noexcept
{ vmcs_n::guest_fs_selector::set(val); }

uint64_t
vcpu::fs_base() const noexcept
{ return vmcs_n::guest_fs_base::get(); }

void
vcpu::set_fs_base(uint64_t val) noexcept
{ vmcs_n::guest_fs_base::set(val); }

uint64_t
vcpu::fs_limit() const noexcept
{ return vmcs_n::guest_fs_limit::get(); }

void
vcpu::set_fs_limit(uint64_t val) noexcept
{ vmcs_n::guest_fs_limit::set(val); }

uint64_t
vcpu::fs_access_rights() const noexcept
{ return vmcs_n::guest_fs_access_rights::get(); }

void
vcpu::set_fs_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_fs_access_rights::set(val); }

uint64_t
vcpu::gs_selector() const noexcept
{ return vmcs_n::guest_gs_selector::get(); }

void
vcpu::set_gs_selector(uint64_t val) noexcept
{ vmcs_n::guest_gs_selector::set(val); }

uint64_t
vcpu::gs_base() const noexcept
{ return vmcs_n::guest_gs_base::get(); }

void
vcpu::set_gs_base(uint64_t val) noexcept
{ vmcs_n::guest_gs_base::set(val); }

uint64_t
vcpu::gs_limit() const noexcept
{ return vmcs_n::guest_gs_limit::get(); }

void
vcpu::set_gs_limit(uint64_t val) noexcept
{ vmcs_n::guest_gs_limit::set(val); }

uint64_t
vcpu::gs_access_rights() const noexcept
{ return vmcs_n::guest_gs_access_rights::get(); }

void
vcpu::set_gs_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_gs_access_rights::set(val); }

uint64_t
vcpu::tr_selector() const noexcept
{ return vmcs_n::guest_tr_selector::get(); }

void
vcpu::set_tr_selector(uint64_t val) noexcept
{ vmcs_n::guest_tr_selector::set(val); }

uint64_t
vcpu::tr_base() const noexcept
{ return vmcs_n::guest_tr_base::get(); }

void
vcpu::set_tr_base(uint64_t val) noexcept
{ vmcs_n::guest_tr_base::set(val); }

uint64_t
vcpu::tr_limit() const noexcept
{ return vmcs_n::guest_tr_limit::get(); }

void
vcpu::set_tr_limit(uint64_t val) noexcept
{ vmcs_n::guest_tr_limit::set(val); }

uint64_t
vcpu::tr_access_rights() const noexcept
{ return vmcs_n::guest_tr_access_rights::get(); }

void
vcpu::set_tr_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_tr_access_rights::set(val); }

uint64_t
vcpu::ldtr_selector() const noexcept
{ return vmcs_n::guest_ldtr_selector::get(); }

void
vcpu::set_ldtr_selector(uint64_t val) noexcept
{ vmcs_n::guest_ldtr_selector::set(val); }

uint64_t
vcpu::ldtr_base() const noexcept
{ return vmcs_n::guest_ldtr_base::get(); }

void
vcpu::set_ldtr_base(uint64_t val) noexcept
{ vmcs_n::guest_ldtr_base::set(val); }

uint64_t
vcpu::ldtr_limit() const noexcept
{ return vmcs_n::guest_ldtr_limit::get(); }

void
vcpu::set_ldtr_limit(uint64_t val) noexcept
{ vmcs_n::guest_ldtr_limit::set(val); }

uint64_t
vcpu::ldtr_access_rights() const noexcept
{ return vmcs_n::guest_ldtr_access_rights::get(); }

void
vcpu::set_ldtr_access_rights(uint64_t val) noexcept
{ vmcs_n::guest_ldtr_access_rights::set(val); }

//==============================================================================
// General Registers
//==============================================================================

uint64_t
vcpu::gr1() const noexcept
{ return m_gr1; }

void
vcpu::set_gr1(uint64_t val) noexcept
{ m_gr1 = val; }

uint64_t
vcpu::gr2() const noexcept
{ return m_gr2; }

void
vcpu::set_gr2(uint64_t val) noexcept
{ m_gr2 = val; }

uint64_t
vcpu::gr3() const noexcept
{ return m_gr3; }

void
vcpu::set_gr3(uint64_t val) noexcept
{ m_gr3 = val; }

uint64_t
vcpu::gr4() const noexcept
{ return m_gr4; }

void
vcpu::set_gr4(uint64_t val) noexcept
{ m_gr4 = val; }

}
