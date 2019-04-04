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

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

void
emulate_rdgpr(vcpu *vcpu)
{
    using namespace ::intel_x64::vmcs;
    using namespace exit_qualification::control_register_access;

    switch (general_purpose_register::get()) {
        case general_purpose_register::rax:
            vcpu->set_gr1(vcpu->rax());
            return;

        case general_purpose_register::rbx:
            vcpu->set_gr1(vcpu->rbx());
            return;

        case general_purpose_register::rcx:
            vcpu->set_gr1(vcpu->rcx());
            return;

        case general_purpose_register::rdx:
            vcpu->set_gr1(vcpu->rdx());
            return;

        case general_purpose_register::rsp:
            vcpu->set_gr1(vcpu->rsp());
            return;

        case general_purpose_register::rbp:
            vcpu->set_gr1(vcpu->rbp());
            return;

        case general_purpose_register::rsi:
            vcpu->set_gr1(vcpu->rsi());
            return;

        case general_purpose_register::rdi:
            vcpu->set_gr1(vcpu->rdi());
            return;

        case general_purpose_register::r8:
            vcpu->set_gr1(vcpu->r08());
            return;

        case general_purpose_register::r9:
            vcpu->set_gr1(vcpu->r09());
            return;

        case general_purpose_register::r10:
            vcpu->set_gr1(vcpu->r10());
            return;

        case general_purpose_register::r11:
            vcpu->set_gr1(vcpu->r11());
            return;

        case general_purpose_register::r12:
            vcpu->set_gr1(vcpu->r12());
            return;

        case general_purpose_register::r13:
            vcpu->set_gr1(vcpu->r13());
            return;

        case general_purpose_register::r14:
            vcpu->set_gr1(vcpu->r14());
            return;

        default:
            vcpu->set_gr1(vcpu->r15());
            return;
    }
}

void
emulate_wrgpr(vcpu *vcpu)
{
    using namespace ::intel_x64::vmcs;
    using namespace exit_qualification::control_register_access;

    switch (general_purpose_register::get()) {
        case general_purpose_register::rax:
            vcpu->set_rax(vcpu->gr1());
            return;

        case general_purpose_register::rbx:
            vcpu->set_rbx(vcpu->gr1());
            return;

        case general_purpose_register::rcx:
            vcpu->set_rcx(vcpu->gr1());
            return;

        case general_purpose_register::rdx:
            vcpu->set_rdx(vcpu->gr1());
            return;

        case general_purpose_register::rsp:
            vcpu->set_rsp(vcpu->gr1());
            return;

        case general_purpose_register::rbp:
            vcpu->set_rbp(vcpu->gr1());
            return;

        case general_purpose_register::rsi:
            vcpu->set_rsi(vcpu->gr1());
            return;

        case general_purpose_register::rdi:
            vcpu->set_rdi(vcpu->gr1());
            return;

        case general_purpose_register::r8:
            vcpu->set_r08(vcpu->gr1());
            return;

        case general_purpose_register::r9:
            vcpu->set_r09(vcpu->gr1());
            return;

        case general_purpose_register::r10:
            vcpu->set_r10(vcpu->gr1());
            return;

        case general_purpose_register::r11:
            vcpu->set_r11(vcpu->gr1());
            return;

        case general_purpose_register::r12:
            vcpu->set_r12(vcpu->gr1());
            return;

        case general_purpose_register::r13:
            vcpu->set_r13(vcpu->gr1());
            return;

        case general_purpose_register::r14:
            vcpu->set_r14(vcpu->gr1());
            return;

        default:
            vcpu->set_r15(vcpu->gr1());
            return;
    }
}

static void
emulate_ia_32e_mode_switch(vcpu *vcpu)
{
    using namespace vmcs_n::guest_cr0;
    using namespace vmcs_n::guest_ia32_efer;
    using namespace vmcs_n::vm_entry_controls;
    using namespace vmcs_n::secondary_processor_based_vm_execution_controls;

    if (unrestricted_guest::is_disabled() || lme::is_disabled()) {
        return;
    }

    if (paging::is_enabled(vcpu->gr1())) {
        lma::enable();
        ia_32e_mode_guest::enable();
        ::intel_x64::vmx::invept_global();
    }
    else {
        lma::disable();
        ia_32e_mode_guest::disable();
        ::intel_x64::vmx::invept_global();
    }
}

static bool
default_wrcr0_handler(vcpu *vcpu)
{
    using namespace vmcs_n::guest_cr0;

    if (paging::is_enabled(vcpu->gr1()) != paging::is_enabled(vcpu->gr2())) {
        emulate_ia_32e_mode_switch(vcpu);
    }

    return false;
}

static bool
default_rdcr3_handler(vcpu *vcpu)
{
    bfignored(vcpu);
    return false;
}

static bool
default_wrcr3_handler(vcpu *vcpu)
{
    bfignored(vcpu);

    // Note:
    //
    // Just like with CR0, we need to emulate the entire instruction, including
    // the instruction's side effects. For a write to CR3, this includes
    // flushing the TLB, minus the global entires. For now we do this using
    // an EPT global flush. In the future, we should figure out if there is a
    // more granular way to do this.
    //

    ::intel_x64::vmx::invept_global();
    return false;
}

static bool
default_wrcr4_handler(vcpu *vcpu)
{
    bfignored(vcpu);
    return false;
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

control_register_handler::control_register_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::control_register_accesses,
    {&control_register_handler::handle, this}
    );

    this->add_wrcr0_handler(default_wrcr0_handler);
    this->add_rdcr3_handler(default_rdcr3_handler);
    this->add_wrcr3_handler(default_wrcr3_handler);
    this->add_wrcr4_handler(default_wrcr4_handler);
}

// -----------------------------------------------------------------------------
// Add Handler Functions
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

// -----------------------------------------------------------------------------
// Enablers
// -----------------------------------------------------------------------------

void
control_register_handler::enable_wrcr0_exiting(
    vmcs_n::value_type mask)
{
    mask |= ::intel_x64::cr0::extension_type::mask;
    mask |= ::intel_x64::cr0::not_write_through::mask;
    mask |= ::intel_x64::cr0::cache_disable::mask;

    mask |= m_vcpu->global_state()->ia32_vmx_cr0_fixed0;
    vmcs_n::cr0_guest_host_mask::set(mask);
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
    mask |= m_vcpu->global_state()->ia32_vmx_cr4_fixed0;
    vmcs_n::cr4_guest_host_mask::set(mask);
}

// -----------------------------------------------------------------------------
// Execute Functions
// -----------------------------------------------------------------------------

void
control_register_handler::execute_wrcr0(
    gsl::not_null<vcpu *> vcpu)
{
    emulate_rdgpr(vcpu);
    vcpu->set_gr2(vcpu->cr0());
    vcpu->set_cr0(vcpu->gr1());
}

void
control_register_handler::execute_rdcr3(
    gsl::not_null<vcpu *> vcpu)
{
    vcpu->set_gr1(vcpu->cr3());
    emulate_wrgpr(vcpu);
}

void
control_register_handler::execute_wrcr3(
    gsl::not_null<vcpu *> vcpu)
{
    emulate_rdgpr(vcpu);
    vcpu->set_gr2(vcpu->cr3());
    vcpu->set_cr3(vcpu->gr1());
}

void
control_register_handler::execute_wrcr4(
    gsl::not_null<vcpu *> vcpu)
{
    emulate_rdgpr(vcpu);
    vcpu->set_gr2(vcpu->cr4());
    vcpu->set_cr4(vcpu->gr1());
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
control_register_handler::handle(vcpu *vcpu)
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
control_register_handler::handle_cr0(vcpu *vcpu)
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
control_register_handler::handle_cr3(vcpu *vcpu)
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
control_register_handler::handle_cr4(vcpu *vcpu)
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
control_register_handler::handle_wrcr0(vcpu *vcpu)
{
    this->execute_wrcr0(vcpu);

    for (const auto &d : m_wrcr0_handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    return vcpu->advance();
}

bool
control_register_handler::handle_rdcr3(vcpu *vcpu)
{
    auto ___ = gsl::finally([&] {
        this->execute_rdcr3(vcpu);
    });

    vcpu->set_gr2(vcpu->cr3());

    for (const auto &d : m_rdcr3_handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    return vcpu->advance();
}

bool
control_register_handler::handle_wrcr3(vcpu *vcpu)
{
    this->execute_wrcr3(vcpu);

    for (const auto &d : m_wrcr3_handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    return vcpu->advance();
}

bool
control_register_handler::handle_wrcr4(vcpu *vcpu)
{
    this->execute_wrcr4(vcpu);

    for (const auto &d : m_wrcr4_handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    return vcpu->advance();
}

}
