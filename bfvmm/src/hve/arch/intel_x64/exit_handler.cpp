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

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfcallonce.h>
#include <bfconstants.h>
#include <bfexception.h>
#include <bferrorcodes.h>
#include <bfthreadcontext.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/check.h>
#include <hve/arch/intel_x64/exception.h>
#include <hve/arch/intel_x64/nmi.h>
#include <hve/arch/intel_x64/exit_handler.h>

#include <memory_manager/arch/x64/cr3.h>
#include <memory_manager/memory_manager.h>

// -----------------------------------------------------------------------------
// C Prototypes
// -----------------------------------------------------------------------------

extern "C" void exit_handler_entry(void) noexcept;

// -----------------------------------------------------------------------------
// Global Variables
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

::x64::msrs::value_type
emulate_rdmsr(::x64::msrs::field_type msr)
{
    using namespace ::intel_x64::vmcs;

    switch (msr) {
        case ::intel_x64::msrs::ia32_debugctl::addr:
            return guest_ia32_debugctl::get();

        case ::x64::msrs::ia32_pat::addr:
            return guest_ia32_pat::get();

        case ::intel_x64::msrs::ia32_efer::addr:
            return guest_ia32_efer::get();

        case ::intel_x64::msrs::ia32_perf_global_ctrl::addr:
            return guest_ia32_perf_global_ctrl::get_if_exists();

        case ::intel_x64::msrs::ia32_sysenter_cs::addr:
            return guest_ia32_sysenter_cs::get();

        case ::intel_x64::msrs::ia32_sysenter_esp::addr:
            return guest_ia32_sysenter_esp::get();

        case ::intel_x64::msrs::ia32_sysenter_eip::addr:
            return guest_ia32_sysenter_eip::get();

        case ::intel_x64::msrs::ia32_fs_base::addr:
            return guest_fs_base::get();

        case ::intel_x64::msrs::ia32_gs_base::addr:
            return guest_gs_base::get();

        default:
            return ::intel_x64::msrs::get(msr);

        // QUIRK:
        //
        // The following is specifically for CPU-Z. For whatever reason, it is
        // reading the following undefined MSRs, which causes the system to
        // freeze since attempting to read these MSRs in the exit handler
        // will cause a GPF which is not being caught. The result is, the core
        // that runs RDMSR on these freezes, the other cores receive an
        // INIT signal to reset, and the system dies.
        //

        case 0x31:
        case 0x39:
        case 0x1ae:
        case 0x1af:
        case 0x602:
            return 0;
    }
}

void
emulate_wrmsr(::x64::msrs::field_type msr, ::x64::msrs::value_type val)
{
    using namespace ::intel_x64::vmcs;

    switch (msr) {
        case ::intel_x64::msrs::ia32_debugctl::addr:
            guest_ia32_debugctl::set(val);
            return;

        case ::x64::msrs::ia32_pat::addr:
            guest_ia32_pat::set(val);
            return;

        case ::intel_x64::msrs::ia32_efer::addr:
            guest_ia32_efer::set(val);
            return;

        case ::intel_x64::msrs::ia32_perf_global_ctrl::addr:
            guest_ia32_perf_global_ctrl::set_if_exists(val);
            return;

        case ::intel_x64::msrs::ia32_sysenter_cs::addr:
            guest_ia32_sysenter_cs::set(val);
            return;

        case ::intel_x64::msrs::ia32_sysenter_esp::addr:
            guest_ia32_sysenter_esp::set(val);
            return;

        case ::intel_x64::msrs::ia32_sysenter_eip::addr:
            guest_ia32_sysenter_eip::set(val);
            return;

        case ::intel_x64::msrs::ia32_fs_base::addr:
            guest_fs_base::set(val);
            return;

        case ::intel_x64::msrs::ia32_gs_base::addr:
            guest_gs_base::set(val);
            return;

        default:
            ::intel_x64::msrs::set(msr, val);
            return;
    }
}

uintptr_t
emulate_rdgpr(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{
    using namespace ::intel_x64::vmcs;
    using namespace exit_qualification::control_register_access;

    switch (general_purpose_register::get()) {
        case general_purpose_register::rax:
            return vcpu->rax();

        case general_purpose_register::rbx:
            return vcpu->rbx();

        case general_purpose_register::rcx:
            return vcpu->rcx();

        case general_purpose_register::rdx:
            return vcpu->rdx();

        case general_purpose_register::rsp:
            return vcpu->rsp();

        case general_purpose_register::rbp:
            return vcpu->rbp();

        case general_purpose_register::rsi:
            return vcpu->rsi();

        case general_purpose_register::rdi:
            return vcpu->rdi();

        case general_purpose_register::r8:
            return vcpu->r08();

        case general_purpose_register::r9:
            return vcpu->r09();

        case general_purpose_register::r10:
            return vcpu->r10();

        case general_purpose_register::r11:
            return vcpu->r11();

        case general_purpose_register::r12:
            return vcpu->r12();

        case general_purpose_register::r13:
            return vcpu->r13();

        case general_purpose_register::r14:
            return vcpu->r14();

        default:
            return vcpu->r15();
    }
}

void
emulate_wrgpr(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu, uintptr_t val)
{
    using namespace ::intel_x64::vmcs;
    using namespace exit_qualification::control_register_access;

    switch (general_purpose_register::get()) {
        case general_purpose_register::rax:
            vcpu->set_rax(val);
            return;

        case general_purpose_register::rbx:
            vcpu->set_rbx(val);
            return;

        case general_purpose_register::rcx:
            vcpu->set_rcx(val);
            return;

        case general_purpose_register::rdx:
            vcpu->set_rdx(val);
            return;

        case general_purpose_register::rsp:
            vcpu->set_rsp(val);
            return;

        case general_purpose_register::rbp:
            vcpu->set_rbp(val);
            return;

        case general_purpose_register::rsi:
            vcpu->set_rsi(val);
            return;

        case general_purpose_register::rdi:
            vcpu->set_rdi(val);
            return;

        case general_purpose_register::r8:
            vcpu->set_r08(val);
            return;

        case general_purpose_register::r9:
            vcpu->set_r09(val);
            return;

        case general_purpose_register::r10:
            vcpu->set_r10(val);
            return;

        case general_purpose_register::r11:
            vcpu->set_r11(val);
            return;

        case general_purpose_register::r12:
            vcpu->set_r12(val);
            return;

        case general_purpose_register::r13:
            vcpu->set_r13(val);
            return;

        case general_purpose_register::r14:
            vcpu->set_r14(val);
            return;

        default:
            vcpu->set_r15(val);
            return;
    }
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

static bool
handle_nmi(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{
    bfignored(vcpu);
    using namespace ::intel_x64::vmcs;
    using namespace primary_processor_based_vm_execution_controls;

    nmi_window_exiting::enable();
    return true;
}

static bool
handle_nmi_window(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{
    bfignored(vcpu);
    using namespace ::intel_x64::vmcs;
    using namespace primary_processor_based_vm_execution_controls;

    inject_nmi();
    nmi_window_exiting::disable();

    return true;
}

static bool
handle_invd(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{
    ::x64::cache::wbinvd();
    return vcpu->advance();
}

static bool
handle_rdmsr(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{
    auto val =
        emulate_rdmsr(
            gsl::narrow_cast<::x64::msrs::field_type>(vcpu->rcx())
        );

    vcpu->set_rax(((val >> 0x00) & 0x00000000FFFFFFFF));
    vcpu->set_rdx(((val >> 0x20) & 0x00000000FFFFFFFF));

    return vcpu->advance();
}

static bool
handle_wrmsr(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{
    auto val = 0ULL;

    val |= ((vcpu->rax() & 0x00000000FFFFFFFF) << 0x00);
    val |= ((vcpu->rdx() & 0x00000000FFFFFFFF) << 0x20);

    emulate_wrmsr(
        gsl::narrow_cast<::x64::msrs::field_type>(vcpu->rcx()),
        val
    );

    return vcpu->advance();
}

static bool
handle_wrcr4(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{
    using namespace ::intel_x64::vmcs;
    using namespace exit_qualification::control_register_access;

    switch (control_register_number::get()) {
        case 4: {
            auto val = emulate_rdgpr(vcpu);
            cr4_read_shadow::set(val);

            val |= ::intel_x64::cr4::vmx_enable_bit::mask;
            guest_cr4::set(val);

            return vcpu->advance();
        }

        default:
            break;
    }

    return false;
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm
{
namespace intel_x64
{

exit_handler::exit_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_ist1{std::make_unique<gsl::byte[]>(STACK_SIZE * 2)},
    m_stack{std::make_unique<gsl::byte[]>(STACK_SIZE * 2)}
{
    using namespace bfvmm::x64;
    using namespace ::intel_x64::vmcs;
    using namespace ::x64::access_rights;

    vcpu->load();
    bfn::call_once(g_once_flag, setup);

    m_host_gdt.set(1, nullptr, 0xFFFFFFFF, ring0_cs_descriptor);
    m_host_gdt.set(2, nullptr, 0xFFFFFFFF, ring0_ss_descriptor);
    m_host_gdt.set(3, nullptr, 0xFFFFFFFF, ring0_fs_descriptor);
    m_host_gdt.set(4, nullptr, 0xFFFFFFFF, ring0_gs_descriptor);
    m_host_gdt.set(5, &m_host_tss, sizeof(m_host_tss), ring0_tr_descriptor);

    this->write_host_state();
    this->write_control_state();

    if (vcpuid::is_host_vm_vcpu(vcpu->id())) {
        this->write_guest_state();
    }

    this->add_handler(
        exit_reason::basic_exit_reason::exception_or_non_maskable_interrupt,
        handler_delegate_t::create<handle_nmi>()
    );

    this->add_handler(
        exit_reason::basic_exit_reason::nmi_window,
        handler_delegate_t::create<handle_nmi_window>()
    );

    this->add_handler(
        exit_reason::basic_exit_reason::invd,
        handler_delegate_t::create<handle_invd>()
    );

    this->add_handler(
        exit_reason::basic_exit_reason::rdmsr,
        handler_delegate_t::create<handle_rdmsr>()
    );

    this->add_handler(
        exit_reason::basic_exit_reason::wrmsr,
        handler_delegate_t::create<handle_wrmsr>()
    );

    this->add_handler(
        exit_reason::basic_exit_reason::control_register_accesses,
        handler_delegate_t::create<handle_wrcr4>()
    );

    this->add_handler(
        exit_reason::basic_exit_reason::cpuid,
        handler_delegate_t::create<exit_handler, &exit_handler::handle_cpuid>(this)
    );
}

void
exit_handler::add_handler(
    ::intel_x64::vmcs::value_type reason,
    const handler_delegate_t &d)
{ m_exit_handlers_array.at(reason).push_front(d); }

void
exit_handler::add_exit_handler(
    const handler_delegate_t &d)
{ m_exit_handlers.push_front(d); }

void
exit_handler::add_init_handler(
    const handler_delegate_t &d)
{ m_init_handlers.push_front(d); }

void
exit_handler::add_fini_handler(
    const handler_delegate_t &d)
{ m_fini_handlers.push_front(d); }

void
exit_handler::write_host_state()
{
    using namespace ::intel_x64::vmcs;

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

    host_gs_base::set(reinterpret_cast<uintptr_t>(m_vcpu->save_state().get()));
    host_tr_base::set(m_host_gdt.base(5));

    host_gdtr_base::set(m_host_gdt.base());
    host_idtr_base::set(m_host_idt.base());

    m_host_tss.ist1 = setup_stack(m_ist1.get(), m_vcpu->id());
    set_default_esrs(&m_host_idt, 8);
    set_nmi_handler(&m_host_idt, 8);

    host_rip::set(exit_handler_entry);
    host_rsp::set(setup_stack(m_stack.get(), m_vcpu->id()));
}

void
exit_handler::write_guest_state()
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

    guest_cr0::set(cr0::get() | ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get());
    guest_cr3::set(cr3::get());
    guest_cr4::set(cr4::get() | ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get());
    guest_dr7::set(dr7::get());

    guest_rflags::set(::x64::rflags::get());

    guest_ia32_sysenter_cs::set(msrs::ia32_sysenter_cs::get());
    guest_ia32_sysenter_esp::set(msrs::ia32_sysenter_esp::get());
    guest_ia32_sysenter_eip::set(msrs::ia32_sysenter_eip::get());

    cr4_read_shadow::set(cr4::get());
}

void
exit_handler::write_control_state()
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

    nmi_exiting::enable();
    virtual_nmis::enable();

    activate_secondary_controls::enable_if_allowed();
    enable_rdtscp::enable_if_allowed();
    enable_invpcid::enable_if_allowed();
    enable_xsaves_xrstors::enable_if_allowed();

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

    cr4_guest_host_mask::set(::intel_x64::cr4::vmx_enable_bit::mask);
}

void
exit_handler::handle(
    bfvmm::intel_x64::exit_handler *exit_handler) noexcept
{
    using namespace ::intel_x64::vmcs;

    guard_exceptions([&]() {

        for (const auto &d : exit_handler->m_exit_handlers) {
            d(exit_handler->m_vcpu);
        }

        const auto &handlers =
            exit_handler->m_exit_handlers_array.at(
                exit_reason::basic_exit_reason::get()
            );

        for (const auto &d : handlers) {
            if (d(exit_handler->m_vcpu)) {
                exit_handler->m_vcpu->run();
            }
        }

        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_lnbr(0, msg);
            bferror_info(0, "unhandled exit reason", msg);
            bferror_brk1(0, msg);

            bferror_subtext(
                0, "exit_reason",
                exit_reason::basic_exit_reason::description(), msg
            );
        });

        if (exit_reason::vm_entry_failure::is_enabled()) {
            debug::dump();
            check::all();
        }
    });

    exit_handler->m_vcpu->halt();
}

bool
exit_handler::handle_cpuid(
    gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{
    using namespace ::x64::cpuid;

    /// Ack
    ///
    /// This can be used by an application to ack the existence of the
    /// hypervisor. This is useful because vmcall only exists if the hypervisor
    /// is running while cpuid can be run from any ring, and always exists
    /// which means it can be used to ack safely from any application.
    ///
    if (vcpu->rax() == 0x4BF00000) {
        vcpu->set_rax(0x4BF00001);
        return vcpu->advance();
    }

    /// Init
    ///
    /// Some initialization is required after the hypervisor has started. For
    /// example, any memory mapped resources such as ACPI or VT-d need to be
    /// initalized using the VMM's CR3, and not the hosts.
    ///
    if (vcpu->rax() == 0x4BF00010) {
        for (const auto &d : m_init_handlers) {
            d(vcpu);
        }

        return vcpu->advance();
    }

    /// Fini
    ///
    /// Some teardown logic is required before the hypervisor stops running.
    /// These handlers can be used in these scenarios.
    ///
    if (vcpu->rax() == 0x4BF00020) {
        for (const auto &d : m_fini_handlers) {
            d(vcpu);
        }

        return vcpu->advance();
    }

    /// Say Hi
    ///
    /// If the vCPU is a host vCPU and not a guest vCPU, we should say hi
    /// so that the user of Bareflank has a simple, reliable way to know
    /// that the hypervisor is running.
    ///
    if (vcpu->rax() == 0x4BF00011) {
        bfdebug_info(0, "host os is" bfcolor_green " now " bfcolor_end "in a vm");
        return vcpu->advance();
    }

    /// Say Goobye
    ///
    /// The most reliable method for turning off the hypervisor is from the
    /// exit handler as it ensures that all of the destructors are executed
    /// after a promote, and not during. Also, say goodbye before we promote
    /// and turn off the hypervisor.
    ///
    if (vcpu->rax() == 0x4BF00021) {
        bfdebug_info(0, "host os is" bfcolor_red " not " bfcolor_end "in a vm");
        vcpu->promote();
    }

    /// Emulate
    ///
    /// Emulate a normal cpuid instruction. If we get here, which is the likely
    /// case, emulate the cpuid instruction.
    ///
    auto ret =
        ::x64::cpuid::get(
            gsl::narrow_cast<field_type>(vcpu->rax()),
            gsl::narrow_cast<field_type>(vcpu->rbx()),
            gsl::narrow_cast<field_type>(vcpu->rcx()),
            gsl::narrow_cast<field_type>(vcpu->rdx())
        );

    vcpu->set_rax(ret.rax);
    vcpu->set_rbx(ret.rbx);
    vcpu->set_rcx(ret.rcx);
    vcpu->set_rdx(ret.rdx);

    return vcpu->advance();
}

}
}
