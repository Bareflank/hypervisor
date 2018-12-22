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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <hve/arch/intel_x64/vcpu.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

vcpu::vcpu(vcpuid::type id) :
    bfvmm::vcpu{id}
{
    if (this->is_host_vm_vcpu()) {
        m_vmx = std::make_unique<intel_x64::vmx>();
    }

    m_vmcs = std::make_unique<bfvmm::intel_x64::vmcs>(id);
    m_exit_handler = std::make_unique<bfvmm::intel_x64::exit_handler>(this);

    this->add_run_delegate(
        run_delegate_t::create<intel_x64::vcpu, &intel_x64::vcpu::run_delegate>(this)
    );

    this->add_hlt_delegate(
        hlt_delegate_t::create<intel_x64::vcpu, &intel_x64::vcpu::hlt_delegate>(this)
    );

    m_vmcs->save_state()->vcpu_ptr =
        reinterpret_cast<uintptr_t>(this);

    m_vmcs->save_state()->exit_handler_ptr =
        reinterpret_cast<uintptr_t>(m_exit_handler.get());
}

void
vcpu::run_delegate(bfobject *obj)
{
    bfignored(obj);

    if (m_launched) {
        m_vmcs->resume();
    }
    else {

        m_launched = true;

        try {
            m_vmcs->load();
            m_vmcs->launch();
        }
        catch (...) {
            m_launched = false;
            throw;
        }

        ::x64::cpuid::get(0xBF10, 0, 0, 0);
        ::x64::cpuid::get(0xBF11, 0, 0, 0);
    }
}

void
vcpu::hlt_delegate(bfobject *obj)
{
    bfignored(obj);

    ::x64::cpuid::get(0xBF20, 0, 0, 0);
    ::x64::cpuid::get(0xBF21, 0, 0, 0);
}

void
vcpu::load()
{ m_vmcs->load(); }

void
vcpu::promote()
{ m_vmcs->promote(); }

void
vcpu::add_handler(
    ::intel_x64::vmcs::value_type reason,
    const handler_delegate_t &d)
{ m_exit_handler->add_handler(reason, d); }

void
vcpu::add_exit_handler(
    const handler_delegate_t &d)
{ m_exit_handler->add_exit_handler(d); }

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
        bferror_subnhex(0, "exit reason", exit_reason::get(), msg);
        bferror_subnhex(0, "exit qualification", exit_qualification::get(), msg);
    });
}

void
vcpu::halt(const std::string &str)
{
    this->dump(("halting vcpu: " + str).c_str());
    ::x64::pm::stop();
}

bool
vcpu::advance()
{
    using namespace ::intel_x64::vmcs;

    this->set_rip(this->rip() + vm_exit_instruction_length::get());
    return true;
}

uint64_t
vcpu::rax() const
{ return m_vmcs->save_state()->rax; }

void
vcpu::set_rax(uint64_t val)
{ m_vmcs->save_state()->rax = val; }

uint64_t
vcpu::rbx() const
{ return m_vmcs->save_state()->rbx; }

void
vcpu::set_rbx(uint64_t val)
{ m_vmcs->save_state()->rbx = val; }

uint64_t
vcpu::rcx() const
{ return m_vmcs->save_state()->rcx; }

void
vcpu::set_rcx(uint64_t val)
{ m_vmcs->save_state()->rcx = val; }

uint64_t
vcpu::rdx() const
{ return m_vmcs->save_state()->rdx; }

void
vcpu::set_rdx(uint64_t val)
{ m_vmcs->save_state()->rdx = val; }

uint64_t
vcpu::rbp() const
{ return m_vmcs->save_state()->rbp; }

void
vcpu::set_rbp(uint64_t val)
{ m_vmcs->save_state()->rbp = val; }

uint64_t
vcpu::rsi() const
{ return m_vmcs->save_state()->rsi; }

void
vcpu::set_rsi(uint64_t val)
{ m_vmcs->save_state()->rsi = val; }

uint64_t
vcpu::rdi() const
{ return m_vmcs->save_state()->rdi; }

void
vcpu::set_rdi(uint64_t val)
{ m_vmcs->save_state()->rdi = val; }

uint64_t
vcpu::r08() const
{ return m_vmcs->save_state()->r08; }

void
vcpu::set_r08(uint64_t val)
{ m_vmcs->save_state()->r08 = val; }

uint64_t
vcpu::r09() const
{ return m_vmcs->save_state()->r09; }

void
vcpu::set_r09(uint64_t val)
{ m_vmcs->save_state()->r09 = val; }

uint64_t
vcpu::r10() const
{ return m_vmcs->save_state()->r10; }

void
vcpu::set_r10(uint64_t val)
{ m_vmcs->save_state()->r10 = val; }

uint64_t
vcpu::r11() const
{ return m_vmcs->save_state()->r11; }

void
vcpu::set_r11(uint64_t val)
{ m_vmcs->save_state()->r11 = val; }

uint64_t
vcpu::r12() const
{ return m_vmcs->save_state()->r12; }

void
vcpu::set_r12(uint64_t val)
{ m_vmcs->save_state()->r12 = val; }

uint64_t
vcpu::r13() const
{ return m_vmcs->save_state()->r13; }

void
vcpu::set_r13(uint64_t val)
{ m_vmcs->save_state()->r13 = val; }

uint64_t
vcpu::r14() const
{ return m_vmcs->save_state()->r14; }

void
vcpu::set_r14(uint64_t val)
{ m_vmcs->save_state()->r14 = val; }

uint64_t
vcpu::r15() const
{ return m_vmcs->save_state()->r15; }

void
vcpu::set_r15(uint64_t val)
{ m_vmcs->save_state()->r15 = val; }

uint64_t
vcpu::rip() const
{ return m_vmcs->save_state()->rip; }

void
vcpu::set_rip(uint64_t val)
{ m_vmcs->save_state()->rip = val; }

uint64_t
vcpu::rsp() const
{ return m_vmcs->save_state()->rsp; }

void
vcpu::set_rsp(uint64_t val)
{ m_vmcs->save_state()->rsp = val; }

gsl::not_null<save_state_t *>
vcpu::save_state() const
{ return m_vmcs->save_state(); }

}
