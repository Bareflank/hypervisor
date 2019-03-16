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

#include <hve/arch/intel_x64/vcpu.h>

namespace bfvmm::intel_x64
{

static uintptr_t
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

static void
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
static bool
emulate_ia_32e_mode_switch(
    control_register_handler::info_t &info)
{
    using namespace vmcs_n::guest_cr0;
    using namespace vmcs_n::guest_ia32_efer;
    using namespace vmcs_n::vm_entry_controls;
    using namespace vmcs_n::secondary_processor_based_vm_execution_controls;

    if (unrestricted_guest::is_disabled() || lme::is_disabled()) {
        return true;
    }

    if (paging::is_enabled(info.val)) {
        lma::enable();
        ia_32e_mode_guest::enable();
        ::intel_x64::vmx::invept_global();
    }
    else {
        lma::disable();
        ia_32e_mode_guest::disable();
        ::intel_x64::vmx::invept_global();
    }

    return true;
}

static bool
default_wrcr0_handler(
    vcpu_t vcpu, control_register_handler::info_t &info)
{
    using namespace vmcs_n::guest_cr0;
    bfignored(vcpu);

    if (paging::is_enabled() != paging::is_enabled(info.val)) {
        return emulate_ia_32e_mode_switch(info);
    }

    return true;
}

static bool
default_rdcr3_handler(
    vcpu_t vcpu, control_register_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

static bool
default_wrcr3_handler(
    vcpu_t vcpu, control_register_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    ::intel_x64::vmx::invept_global();
    return true;
}

static bool
default_wrcr4_handler(
    vcpu_t vcpu, control_register_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

control_register_handler::control_register_handler(
    vcpu_t vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::control_register_accesses,
        ::handler_delegate_t::create<control_register_handler, &control_register_handler::handle>(this)
    );

    this->add_wrcr0_handler(
        handler_delegate_t::create<default_wrcr0_handler>()
    );

    this->add_rdcr3_handler(
        handler_delegate_t::create<default_rdcr3_handler>()
    );

    this->add_wrcr3_handler(
        handler_delegate_t::create<default_wrcr3_handler>()
    );

    this->add_wrcr4_handler(
        handler_delegate_t::create<default_wrcr4_handler>()
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
control_register_handler::add_wrcr0_handler(
    const handler_delegate_t &d)
{ m_wrcr0_handlers.push_front(d); }

void
control_register_handler::add_rdcr3_handler(
    const handler_delegate_t &d)
{ m_rdcr3_handlers.push_front(d); }

void
control_register_handler::add_wrcr3_handler(
    const handler_delegate_t &d)
{ m_wrcr3_handlers.push_front(d); }

void
control_register_handler::add_wrcr4_handler(
    const handler_delegate_t &d)
{ m_wrcr4_handlers.push_front(d); }

void
control_register_handler::enable_wrcr0_exiting(vmcs_n::value_type mask)
{
    using namespace vmcs_n;
    mask |= m_vcpu->global_state()->ia32_vmx_cr0_fixed0;

    cr0_guest_host_mask::set(mask);
    cr0_read_shadow::set(guest_cr0::get());
}

void
control_register_handler::enable_rdcr3_exiting()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::cr3_store_exiting::enable();
}

void
control_register_handler::enable_wrcr3_exiting()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::cr3_load_exiting::enable();
}

void
control_register_handler::enable_wrcr4_exiting(
    vmcs_n::value_type mask)
{
    using namespace vmcs_n;
    mask |= m_vcpu->global_state()->ia32_vmx_cr4_fixed0;

    cr4_guest_host_mask::set(mask);
    cr4_read_shadow::set(guest_cr4::get());
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
control_register_handler::handle(vcpu_t vcpu)
{
    using namespace vmcs_n::exit_qualification::control_register_access;

    switch (control_register_number::get()) {
        case 0:
            return handle_cr0(vcpu);

        case 3:
            return handle_cr3(vcpu);

        case 4:
            return handle_cr4(vcpu);

        default:
            throw std::runtime_error(
                "control_register_handler::handle: invalid cr number"
            );
    }
}

bool
control_register_handler::handle_cr0(vcpu_t vcpu)
{
    using namespace vmcs_n::exit_qualification::control_register_access;

    switch (access_type::get()) {
        case access_type::mov_to_cr:
            return handle_wrcr0(vcpu);

        case access_type::mov_from_cr:
            throw std::runtime_error(
                "control_register_handler::handle_cr0: mov_from_cr not supported"
            );

        case access_type::clts:
            throw std::runtime_error(
                "control_register_handler::handle_cr0: clts not supported"
            );

        default:
            throw std::runtime_error(
                "control_register_handler::handle_cr0: lmsw not supported"
            );
    }
}

bool
control_register_handler::handle_cr3(vcpu_t vcpu)
{
    using namespace vmcs_n::exit_qualification::control_register_access;

    switch (access_type::get()) {
        case access_type::mov_to_cr:
            return handle_wrcr3(vcpu);

        case access_type::mov_from_cr:
            return handle_rdcr3(vcpu);

        case access_type::clts:
            throw std::runtime_error(
                "control_register_handler::handle_cr3: clts not supported"
            );

        default:
            throw std::runtime_error(
                "control_register_handler::handle_cr3: lmsw not supported"
            );
    }
}

bool
control_register_handler::handle_cr4(vcpu_t vcpu)
{
    using namespace vmcs_n::exit_qualification::control_register_access;

    switch (access_type::get()) {
        case access_type::mov_to_cr:
            return handle_wrcr4(vcpu);

        case access_type::mov_from_cr:
            throw std::runtime_error(
                "control_register_handler::handle_cr4: mov_from_cr not supported"
            );

        case access_type::clts:
            throw std::runtime_error(
                "control_register_handler::handle_cr4: clts not supported"
            );

        default:
            throw std::runtime_error(
                "control_register_handler::handle_cr4: lmsw not supported"
            );
    }
}

bool
control_register_handler::handle_wrcr0(vcpu_t vcpu)
{
    struct info_t info = {
        emulate_rdgpr(vcpu),
        vmcs_n::cr0_read_shadow::get(),
        false,
        false
    };

    info.shadow = info.val;
    info.val |= m_vcpu->global_state()->ia32_vmx_cr0_fixed0;

    for (const auto &d : m_wrcr0_handlers) {
        if (d(vcpu, info)) {
            break;
        }
    }

    if (!info.ignore_write) {
        vmcs_n::guest_cr0::set(info.val);
        vmcs_n::cr0_read_shadow::set(info.shadow);
    }

    if (!info.ignore_advance) {
        return vcpu->advance();
    }

    return true;
}

bool
control_register_handler::handle_rdcr3(vcpu_t vcpu)
{
    struct info_t info = {
        vmcs_n::guest_cr3::get(),
        0,
        false,
        false
    };

    for (const auto &d : m_rdcr3_handlers) {
        if (d(vcpu, info)) {
            break;
        }
    }

    if (!info.ignore_write) {
        emulate_wrgpr(vcpu, info.val);
    }

    if (!info.ignore_advance) {
        return vcpu->advance();
    }

    return true;
}

bool
control_register_handler::handle_wrcr3(vcpu_t vcpu)
{
    struct info_t info = {
        emulate_rdgpr(vcpu),
        0,
        false,
        false
    };

    for (const auto &d : m_wrcr3_handlers) {
        if (d(vcpu, info)) {
            break;
        }
    }

    if (!info.ignore_write) {
        vmcs_n::guest_cr3::set(info.val & 0x7FFFFFFFFFFFFFFF);
    }

    if (!info.ignore_advance) {
        return vcpu->advance();
    }

    return true;
}

bool
control_register_handler::handle_wrcr4(vcpu_t vcpu)
{
    struct info_t info = {
        emulate_rdgpr(vcpu),
        vmcs_n::cr4_read_shadow::get(),
        false,
        false
    };

    info.shadow = info.val;
    info.val |= m_vcpu->global_state()->ia32_vmx_cr4_fixed0;

    for (const auto &d : m_wrcr4_handlers) {
        if (d(vcpu, info)) {
            break;
        }
    }

    if (!info.ignore_write) {
        vmcs_n::guest_cr4::set(info.val);
        vmcs_n::cr4_read_shadow::set(info.shadow);
    }

    if (!info.ignore_advance) {
        return vcpu->advance();
    }

    return true;
}

}
