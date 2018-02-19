//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfconstants.h>
#include <bfexception.h>
#include <bferrorcodes.h>
#include <bfthreadcontext.h>

#include <hve/arch/intel_x64/check/check.h>
#include <hve/arch/intel_x64/exit_handler/exit_handler.h>

#include <memory_manager/memory_manager.h>
#include <memory_manager/arch/x64/root_page_table.h>

bool g_guest_perf_glbl_ctrl_field_exists;

// -----------------------------------------------------------------------------
// C Prototypes
// -----------------------------------------------------------------------------

extern "C" void exit_handler_entry(void) noexcept;

// -----------------------------------------------------------------------------
// Static Variables
// -----------------------------------------------------------------------------

::intel_x64::cr0::value_type bfvmm::intel_x64::exit_handler::s_cr0 = 0;
::intel_x64::cr3::value_type bfvmm::intel_x64::exit_handler::s_cr3 = 0;
::intel_x64::cr4::value_type bfvmm::intel_x64::exit_handler::s_cr4 = 0;
::intel_x64::msrs::value_type bfvmm::intel_x64::exit_handler::s_ia32_pat_msr = 0;
::intel_x64::msrs::value_type bfvmm::intel_x64::exit_handler::s_ia32_efer_msr = 0;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

void
halt(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) noexcept
{
    bferror_lnbr(0);
    bferror_info(0, "halting vcpu");
    bferror_brk1(0);

    bferror_subnhex(0, "rax", vmcs->save_state()->rax);
    bferror_subnhex(0, "rbx", vmcs->save_state()->rbx);
    bferror_subnhex(0, "rcx", vmcs->save_state()->rcx);
    bferror_subnhex(0, "rdx", vmcs->save_state()->rdx);
    bferror_subnhex(0, "rbp", vmcs->save_state()->rbp);
    bferror_subnhex(0, "rsi", vmcs->save_state()->rsi);
    bferror_subnhex(0, "rdi", vmcs->save_state()->rdi);
    bferror_subnhex(0, "r08", vmcs->save_state()->r08);
    bferror_subnhex(0, "r09", vmcs->save_state()->r09);
    bferror_subnhex(0, "r10", vmcs->save_state()->r10);
    bferror_subnhex(0, "r11", vmcs->save_state()->r11);
    bferror_subnhex(0, "r12", vmcs->save_state()->r12);
    bferror_subnhex(0, "r13", vmcs->save_state()->r13);
    bferror_subnhex(0, "r14", vmcs->save_state()->r14);
    bferror_subnhex(0, "r15", vmcs->save_state()->r15);
    bferror_subnhex(0, "rip", vmcs->save_state()->rip);
    bferror_subnhex(0, "rsp", vmcs->save_state()->rsp);

    ::x64::pm::stop();
}

bool
advance(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) noexcept
{
    vmcs->save_state()->rip += ::intel_x64::vmcs::vm_exit_instruction_length::get();
    return true;
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

static bool
handle_cpuid(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    auto ret =
        ::x64::cpuid::get(
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rax),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rbx),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rcx),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rdx)
        );

    vmcs->save_state()->rax = ret.rax;
    vmcs->save_state()->rbx = ret.rbx;
    vmcs->save_state()->rcx = ret.rcx;
    vmcs->save_state()->rdx = ret.rdx;

    return advance(vmcs);
}

static bool
handle_invd(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    ::x64::cache::wbinvd();
    return advance(vmcs);
}

static bool
handle_vmxoff(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    vmcs->promote();
    return true;        // Only executed during unit tests
}

static bool
handle_rdmsr(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    auto val = 0ULL;
    auto msr = gsl::narrow_cast<::x64::msrs::field_type>(vmcs->save_state()->rcx);

    switch (msr) {
        case ::intel_x64::msrs::ia32_debugctl::addr:
            val = ::intel_x64::vmcs::guest_ia32_debugctl::get();
            break;

        case ::x64::msrs::ia32_pat::addr:
            val = ::intel_x64::vmcs::guest_ia32_pat::get();
            break;

        case ::intel_x64::msrs::ia32_efer::addr:
            val = ::intel_x64::vmcs::guest_ia32_efer::get();
            break;

        case ::intel_x64::msrs::ia32_perf_global_ctrl::addr:
            if (g_guest_perf_glbl_ctrl_field_exists) {
                val = ::intel_x64::vmcs::guest_ia32_perf_global_ctrl::get();
            } else {
                val = ::intel_x64::msrs::ia32_perf_global_ctrl::get();
            }
            break;

        case ::intel_x64::msrs::ia32_sysenter_cs::addr:
            val = ::intel_x64::vmcs::guest_ia32_sysenter_cs::get();
            break;

        case ::intel_x64::msrs::ia32_sysenter_esp::addr:
            val = ::intel_x64::vmcs::guest_ia32_sysenter_esp::get();
            break;

        case ::intel_x64::msrs::ia32_sysenter_eip::addr:
            val = ::intel_x64::vmcs::guest_ia32_sysenter_eip::get();
            break;

        case ::intel_x64::msrs::ia32_fs_base::addr:
            val = ::intel_x64::vmcs::guest_fs_base::get();
            break;

        case ::intel_x64::msrs::ia32_gs_base::addr:
            val = ::intel_x64::vmcs::guest_gs_base::get();
            break;

        default:
            val = ::intel_x64::msrs::get(msr);
            break;

        // QUIRK:
        //
        // The following is specifically for CPU-Z. For whatever reason, it is
        // reading the following undefined MSRs, which causes the system to
        // freeze since attempting to read these MSRs in the exit handler
        // will cause a GP which is not being caught. The result is, the core
        // that runs RDMSR on these freezes, the other cores receive an
        // INIT signal to reset, and the system dies.
        //

        case 0x31:
        case 0x39:
        case 0x1ae:
        case 0x1af:
        case 0x602:
            val = 0;
            break;
    }

    vmcs->save_state()->rax = ((val >> 0x00) & 0x00000000FFFFFFFF);
    vmcs->save_state()->rdx = ((val >> 0x20) & 0x00000000FFFFFFFF);

    return advance(vmcs);
}

static bool
handle_wrmsr(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    auto val = 0ULL;
    auto msr = gsl::narrow_cast<::x64::msrs::field_type>(vmcs->save_state()->rcx);

    val |= ((vmcs->save_state()->rax & 0x00000000FFFFFFFF) << 0x00);
    val |= ((vmcs->save_state()->rdx & 0x00000000FFFFFFFF) << 0x20);

    switch (msr) {
        case ::intel_x64::msrs::ia32_debugctl::addr:
            ::intel_x64::vmcs::guest_ia32_debugctl::set(val);
            break;

        case ::x64::msrs::ia32_pat::addr:
            ::intel_x64::vmcs::guest_ia32_pat::set(val);
            break;

        case ::intel_x64::msrs::ia32_efer::addr:
            ::intel_x64::vmcs::guest_ia32_efer::set(val);
            break;

        case ::intel_x64::msrs::ia32_perf_global_ctrl::addr:
            if (g_guest_perf_glbl_ctrl_field_exists) {
                ::intel_x64::vmcs::guest_ia32_perf_global_ctrl::set(val);
            } else {
                ::intel_x64::msrs::ia32_perf_global_ctrl::set(val);
            }
            break;

        case ::intel_x64::msrs::ia32_sysenter_cs::addr:
            ::intel_x64::vmcs::guest_ia32_sysenter_cs::set(val);
            break;

        case ::intel_x64::msrs::ia32_sysenter_esp::addr:
            ::intel_x64::vmcs::guest_ia32_sysenter_esp::set(val);
            break;

        case ::intel_x64::msrs::ia32_sysenter_eip::addr:
            ::intel_x64::vmcs::guest_ia32_sysenter_eip::set(val);
            break;

        case ::intel_x64::msrs::ia32_fs_base::addr:
            ::intel_x64::vmcs::guest_fs_base::set(val);
            break;

        case ::intel_x64::msrs::ia32_gs_base::addr:
            ::intel_x64::vmcs::guest_gs_base::set(val);
            break;

        default:
            ::intel_x64::msrs::set(msr, val);
            break;
    }

    return advance(vmcs);
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm
{
namespace intel_x64
{

exit_handler::exit_handler(
    gsl::not_null<vmcs *> vmcs
) :
    m_vmcs{vmcs},
    m_stack{std::make_unique<gsl::byte[]>(STACK_SIZE * 2)}
{
    using namespace ::intel_x64::vmcs;

    m_vmcs->load();
    m_vmcs->save_state()->exit_handler_ptr = reinterpret_cast<uintptr_t>(this);

    auto id = m_vmcs->save_state()->vcpuid;

    m_host_gdt.set(1, nullptr, 0xFFFFFFFF, ::x64::access_rights::ring0_cs_descriptor);
    m_host_gdt.set(2, nullptr, 0xFFFFFFFF, ::x64::access_rights::ring0_ss_descriptor);
    m_host_gdt.set(3, nullptr, 0xFFFFFFFF, ::x64::access_rights::ring0_fs_descriptor);
    m_host_gdt.set(4, nullptr, 0xFFFFFFFF, ::x64::access_rights::ring0_gs_descriptor);
    m_host_gdt.set(5, &m_host_tss, sizeof(m_host_tss), ::x64::access_rights::ring0_tr_descriptor);

    if (vcpuid::is_bootstrap_vcpu(id)) {
        s_ia32_pat_msr |= ::x64::pat::pat_value;

        s_ia32_efer_msr |= ::intel_x64::msrs::ia32_efer::lme::mask;
        s_ia32_efer_msr |= ::intel_x64::msrs::ia32_efer::lma::mask;
        s_ia32_efer_msr |= ::intel_x64::msrs::ia32_efer::nxe::mask;

        s_cr0 |= ::intel_x64::cr0::protection_enable::mask;
        s_cr0 |= ::intel_x64::cr0::monitor_coprocessor::mask;
        s_cr0 |= ::intel_x64::cr0::extension_type::mask;
        s_cr0 |= ::intel_x64::cr0::numeric_error::mask;
        s_cr0 |= ::intel_x64::cr0::write_protect::mask;
        s_cr0 |= ::intel_x64::cr0::paging::mask;

        s_cr3 = g_pt->cr3();

        s_cr4 |= ::intel_x64::cr4::v8086_mode_extensions::mask;
        s_cr4 |= ::intel_x64::cr4::protected_mode_virtual_interrupts::mask;
        s_cr4 |= ::intel_x64::cr4::time_stamp_disable::mask;
        s_cr4 |= ::intel_x64::cr4::debugging_extensions::mask;
        s_cr4 |= ::intel_x64::cr4::page_size_extensions::mask;
        s_cr4 |= ::intel_x64::cr4::physical_address_extensions::mask;
        s_cr4 |= ::intel_x64::cr4::machine_check_enable::mask;
        s_cr4 |= ::intel_x64::cr4::page_global_enable::mask;
        s_cr4 |= ::intel_x64::cr4::performance_monitor_counter_enable::mask;
        s_cr4 |= ::intel_x64::cr4::osfxsr::mask;
        s_cr4 |= ::intel_x64::cr4::osxmmexcpt::mask;
        s_cr4 |= ::intel_x64::cr4::vmx_enable_bit::mask;

        if (::intel_x64::cpuid::feature_information::ecx::xsave::is_enabled()) {
            s_cr4 |= ::intel_x64::cr4::osxsave::mask;
        }

        if (::intel_x64::cpuid::extended_feature_flags::subleaf0::ebx::smep::is_enabled()) {
            s_cr4 |= ::intel_x64::cr4::smep_enable_bit::mask;
        }

        if (::intel_x64::cpuid::extended_feature_flags::subleaf0::ebx::smap::is_enabled()) {
            s_cr4 |= ::intel_x64::cr4::smap_enable_bit::mask;
        }
    }

    g_guest_perf_glbl_ctrl_field_exists = ::intel_x64::vmcs::guest_ia32_perf_global_ctrl::exists();

    this->write_host_state();
    this->write_control_state();

    if (vcpuid::is_hvm_vcpu(id)) {
        this->write_guest_state();
    }

    add_dispatch_delegate(
        exit_reason::basic_exit_reason::cpuid,
        dispatch_delegate_t::create<handle_cpuid>()
    );

    add_dispatch_delegate(
        exit_reason::basic_exit_reason::invd,
        dispatch_delegate_t::create<handle_invd>()
    );

    add_dispatch_delegate(
        exit_reason::basic_exit_reason::vmxoff,
        dispatch_delegate_t::create<handle_vmxoff>()
    );

    add_dispatch_delegate(
        exit_reason::basic_exit_reason::rdmsr,
        dispatch_delegate_t::create<handle_rdmsr>()
    );

    add_dispatch_delegate(
        exit_reason::basic_exit_reason::wrmsr,
        dispatch_delegate_t::create<handle_wrmsr>()
    );
}

void
exit_handler::add_dispatch_delegate(
    ::intel_x64::vmcs::value_type reason,
    dispatch_delegate_t &&d)
{ m_handlers.at(reason).push_front(std::move(d)); }

void
exit_handler::write_host_state()
{
    using namespace ::intel_x64::vmcs;

    host_cs_selector::set(
        gsl::narrow_cast<::x64::segment_register::value_type>(1 << 3));
    host_ss_selector::set(
        gsl::narrow_cast<::x64::segment_register::value_type>(2 << 3));
    host_fs_selector::set(
        gsl::narrow_cast<::x64::segment_register::value_type>(3 << 3));
    host_gs_selector::set(
        gsl::narrow_cast<::x64::segment_register::value_type>(4 << 3));
    host_tr_selector::set(
        gsl::narrow_cast<::x64::segment_register::value_type>(5 << 3));

    host_ia32_pat::set(s_ia32_pat_msr);
    host_ia32_efer::set(s_ia32_efer_msr);

    host_cr0::set(s_cr0);
    host_cr3::set(s_cr3);
    host_cr4::set(s_cr4);

    host_gs_base::set(reinterpret_cast<uintptr_t>(m_vmcs->save_state()));
    host_tr_base::set(m_host_gdt.base(5));

    host_gdtr_base::set(m_host_gdt.base());
    host_idtr_base::set(m_host_idt.base());

    host_rip::set(exit_handler_entry);
    host_rsp::set(setup_stack(m_stack.get()));
}

void
exit_handler::write_guest_state()
{
    using namespace ::intel_x64::vmcs;

    x64::gdt guest_gdt;
    x64::idt guest_idt;

    auto es_index = ::x64::segment_register::es::index::get();
    auto cs_index = ::x64::segment_register::cs::index::get();
    auto ss_index = ::x64::segment_register::ss::index::get();
    auto ds_index = ::x64::segment_register::ds::index::get();
    auto fs_index = ::x64::segment_register::fs::index::get();
    auto gs_index = ::x64::segment_register::gs::index::get();
    auto ldtr_index = ::x64::segment_register::ldtr::index::get();
    auto tr_index = ::x64::segment_register::tr::index::get();

    vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFF);

    guest_es_selector::set(::x64::segment_register::es::get());
    guest_cs_selector::set(::x64::segment_register::cs::get());
    guest_ss_selector::set(::x64::segment_register::ss::get());
    guest_ds_selector::set(::x64::segment_register::ds::get());
    guest_fs_selector::set(::x64::segment_register::fs::get());
    guest_gs_selector::set(::x64::segment_register::gs::get());
    guest_ldtr_selector::set(::x64::segment_register::ldtr::get());
    guest_tr_selector::set(::x64::segment_register::tr::get());

    guest_ia32_debugctl::set(::intel_x64::msrs::ia32_debugctl::get());
    guest_ia32_pat::set(::x64::msrs::ia32_pat::get());
    guest_ia32_efer::set(::intel_x64::msrs::ia32_efer::get());

    if (::intel_x64::cpuid::arch_perf_monitoring::eax::version_id::get() >= 2) {
        guest_ia32_perf_global_ctrl::set_if_exists(::intel_x64::msrs::ia32_perf_global_ctrl::get());
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

    guest_es_access_rights::set(
        es_index != 0 ? guest_gdt.access_rights(es_index) : ::x64::access_rights::unusable);
    guest_cs_access_rights::set(
        cs_index != 0 ? guest_gdt.access_rights(cs_index) : ::x64::access_rights::unusable);
    guest_ss_access_rights::set(
        ss_index != 0 ? guest_gdt.access_rights(ss_index) : ::x64::access_rights::unusable);
    guest_ds_access_rights::set(
        ds_index != 0 ? guest_gdt.access_rights(ds_index) : ::x64::access_rights::unusable);
    guest_fs_access_rights::set(
        fs_index != 0 ? guest_gdt.access_rights(fs_index) : ::x64::access_rights::unusable);
    guest_gs_access_rights::set(
        gs_index != 0 ? guest_gdt.access_rights(gs_index) : ::x64::access_rights::unusable);
    guest_ldtr_access_rights::set(
        ldtr_index != 0 ? guest_gdt.access_rights(ldtr_index) : ::x64::access_rights::unusable);
    guest_tr_access_rights::set(
        tr_index != 0 ? guest_gdt.access_rights(tr_index) : ::x64::access_rights::unusable);

    guest_es_base::set(es_index != 0 ? guest_gdt.base(es_index) : 0);
    guest_cs_base::set(cs_index != 0 ? guest_gdt.base(cs_index) : 0);
    guest_ss_base::set(ss_index != 0 ? guest_gdt.base(ss_index) : 0);
    guest_ds_base::set(ds_index != 0 ? guest_gdt.base(ds_index) : 0);
    guest_fs_base::set(::intel_x64::msrs::ia32_fs_base::get());
    guest_gs_base::set(::intel_x64::msrs::ia32_gs_base::get());
    guest_ldtr_base::set(ldtr_index != 0 ? guest_gdt.base(ldtr_index) : 0);
    guest_tr_base::set(tr_index != 0 ? guest_gdt.base(tr_index) : 0);

    guest_cr0::set(::intel_x64::cr0::get());
    guest_cr3::set(::intel_x64::cr3::get());
    guest_cr4::set(::intel_x64::cr4::get() | ::intel_x64::cr4::vmx_enable_bit::mask);
    guest_dr7::set(::intel_x64::dr7::get());

    guest_rflags::set(::x64::rflags::get());

    guest_ia32_sysenter_cs::set(::intel_x64::msrs::ia32_sysenter_cs::get());
    guest_ia32_sysenter_esp::set(::intel_x64::msrs::ia32_sysenter_esp::get());
    guest_ia32_sysenter_eip::set(::intel_x64::msrs::ia32_sysenter_eip::get());
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

    primary_processor_based_vm_execution_controls::activate_secondary_controls::enable_if_allowed();
    secondary_processor_based_vm_execution_controls::enable_rdtscp::enable_if_allowed();
    secondary_processor_based_vm_execution_controls::enable_invpcid::enable_if_allowed();
    secondary_processor_based_vm_execution_controls::enable_xsaves_xrstors::enable_if_allowed();

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

void
exit_handler::dispatch(
    bfvmm::intel_x64::exit_handler *exit_handler) noexcept
{
    auto reason = ::intel_x64::vmcs::exit_reason::basic_exit_reason::get();

    guard_exceptions([&]() {
        for (const auto &d : exit_handler->m_handlers.at(reason)) {
            if (d(exit_handler->m_vmcs)) {
                exit_handler->m_vmcs->resume();
            }
        }

        bfdebug_transaction(1, [&](std::string * msg) {
            bferror_lnbr(0, msg);
            bferror_info(0, "unhandled exit reason", msg);
            bferror_brk1(0, msg);

            bferror_subtext(
                0, "exit_reason",
                ::intel_x64::vmcs::exit_reason::basic_exit_reason::description(), msg
            );
        });

        if (::intel_x64::vmcs::exit_reason::vm_entry_failure::is_enabled()) {
            ::intel_x64::vmcs::debug::dump();
            check::all();
        }
    });

    halt(exit_handler->m_vmcs);
}

}
}
