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

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfconstants.h>
#include <bfthreadcontext.h>
#include <bfcallonce.h>

#include <hve/arch/intel_x64/vmcs.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/nmi.h>
#include <hve/arch/intel_x64/exception.h>
#include <intrinsics.h>
#include <memory_manager/arch/x64/cr3.h>
#include <memory_manager/memory_manager.h>

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

extern "C" void vmcs_launch(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

extern "C" void vmcs_promote(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

extern "C" void vmexit_entry(void) noexcept;

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
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

vmcs::vmcs(vcpu_t vcpu) :
    m_save_state{make_page<save_state_t>()},
    m_vmcs_region{make_page<uint32_t>()},
    m_vmcs_region_phys{g_mm->virtptr_to_physint(m_vmcs_region.get())},
    m_msr_bitmap{make_page<uint8_t>()},
    m_io_bitmap_a{make_page<uint8_t>()},
    m_io_bitmap_b{make_page<uint8_t>()},
    m_ist1{std::make_unique<gsl::byte[]>(STACK_SIZE * 2)},
    m_stack{std::make_unique<gsl::byte[]>(STACK_SIZE * 2)}
{
    m_save_state->vcpuid = vcpu->id();
    m_save_state->vcpu_ptr = reinterpret_cast<uintptr_t>(vcpu.get());

    bfn::call_once(g_once_flag, setup);
}

void
vmcs::init()
{
    using namespace bfvmm::x64;
    using namespace ::intel_x64::vmcs;
    using namespace ::x64::access_rights;

    gsl::span<uint32_t> id{m_vmcs_region.get(), 1024};
    id[0] = gsl::narrow<uint32_t>(::intel_x64::msrs::ia32_vmx_basic::revision_id::get());

    this->load();

    m_host_gdt.set(1, nullptr, 0xFFFFFFFF, ring0_cs_descriptor);
    m_host_gdt.set(2, nullptr, 0xFFFFFFFF, ring0_ss_descriptor);
    m_host_gdt.set(3, nullptr, 0xFFFFFFFF, ring0_fs_descriptor);
    m_host_gdt.set(4, nullptr, 0xFFFFFFFF, ring0_gs_descriptor);
    m_host_gdt.set(5, &m_host_tss, sizeof(m_host_tss), ring0_tr_descriptor);

    auto vcpuid = m_save_state->vcpuid;
    this->write_host_state(vcpuid);
    this->write_control_state();

    if (vcpuid::is_host_vm_vcpu(vcpuid)) {
        this->write_guest_state();
    }

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "vmcs region", msg);
        bfdebug_subnhex(1, "virt address", m_vmcs_region.get(), msg);
        bfdebug_subnhex(1, "phys address", m_vmcs_region_phys, msg);
        bfdebug_pass(1, "save state", msg);
        bfdebug_subnhex(1, "virt address", m_save_state.get(), msg);
    });

    this->clear();
}

void
vmcs::launch()
{
    try {
        if (vcpuid::is_host_vm_vcpu(m_save_state->vcpuid)) {
            ::intel_x64::vm::launch_demote();
        }
        else {
            vmcs_launch(m_save_state.get());
            throw std::runtime_error("vmcs launch failed");
        }
    }
    catch (...) {
        auto e = std::current_exception();

        this->check();
        std::rethrow_exception(e);
    }
}

void
vmcs::promote()
{
    vmcs_promote(m_save_state.get());
    throw std::runtime_error("vmcs promote failed");
}

void
vmcs::resume()
{
    vmcs_resume(m_save_state.get());

    this->check();
    throw std::runtime_error("vmcs resume failed");
}

void
vmcs::load()
{
    ::intel_x64::vm::load(&m_vmcs_region_phys);
}

void
vmcs::clear()
{
    ::intel_x64::vm::clear(&m_vmcs_region_phys);
}

bool
vmcs::check() const noexcept
{
    try {
        check::all();
    }
    catch (std::exception &e) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_lnbr(0, msg);
            bferror_brk1(0, msg);
            bferror_info(0, typeid(e).name(), msg);
            bferror_brk1(0, msg);
            bferror_info(0, e.what(), msg);
        });

        return false;
    }

    return true;
}

void
vmcs::write_host_state(vcpuid::type vcpuid)
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

    host_gs_base::set(reinterpret_cast<uintptr_t>(m_save_state.get()));
    host_tr_base::set(m_host_gdt.base(5));

    host_gdtr_base::set(m_host_gdt.base());
    host_idtr_base::set(m_host_idt.base());

    m_host_tss.ist1 = setup_stack(m_ist1.get(), vcpuid);
    set_default_esrs(&m_host_idt, 8);
    set_nmi_handler(&m_host_idt, 8);

    host_rip::set(vmexit_entry);
    host_rsp::set(setup_stack(m_stack.get(), vcpuid));

}

void
vmcs::write_guest_state()
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
vmcs::write_control_state()
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

    // <TODO>: Move these to the VMCS
    address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
    address_of_io_bitmap_a::set(g_mm->virtptr_to_physint(m_io_bitmap_a.get()));
    address_of_io_bitmap_b::set(g_mm->virtptr_to_physint(m_io_bitmap_b.get()));

    primary_processor_based_vm_execution_controls::use_msr_bitmap::enable();
    primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();
    // </TODO>


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

}
