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

namespace bfvmm::intel_x64
{

exit_handler::exit_handler():
    m_cpuid_delegator{std::make_unique<cpuid::delegator>()},
    m_nmi_delegator{std::make_unique<nmi::delegator>()},
    m_cr_delegator{std::make_unique<cr::delegator>()},
    m_invd_delegator{std::make_unique<invd::delegator>()},
    m_msr_delegator{std::make_unique<msr::delegator>()},
    m_fallback_delegator{std::make_unique<fallback::delegator>()}
{
    using namespace ::intel_x64::vmcs::exit_reason;

    auto exit_delegate = handler_delegate_t::create<fallback::delegator,
         &fallback::delegator::handle>(m_fallback_delegator);
    m_exit_delegates.fill(exit_delegate);

    exit_delegate = handler_delegate_t::create<cpuid::delegator,
    &cpuid::delegator::handle>(m_cpuid_delegator);
    m_exit_delegates.at(basic_exit_reason::cpuid) = exit_delegate;

    exit_delegate = handler_delegate_t::create<nmi::delegator,
    &nmi::delegator::handle_nmi>(m_nmi_delegator);
    m_exit_delegates.at(basic_exit_reason::exception_or_non_maskable_interrupt) = exit_delegate;

    exit_delegate = handler_delegate_t::create<nmi::delegator,
    &nmi::delegator::handle_nmi_window>(m_nmi_delegator);
    m_exit_delegates.at(basic_exit_reason::nmi_window) = exit_delegate;

    exit_delegate = handler_delegate_t::create<invd::delegator,
    &invd::delegator::handle>(m_invd_delegator);
    m_exit_delegates.at(basic_exit_reason::invd) = exit_delegate;

    exit_delegate = handler_delegate_t::create<msr::delegator,
    &msr::delegator::handle_rdmsr>(m_msr_delegator);
    m_exit_delegates.at(basic_exit_reason::rdmsr) = exit_delegate;

    exit_delegate = handler_delegate_t::create<msr::delegator,
    &msr::delegator::handle_wrmsr>(m_msr_delegator);
    m_exit_delegates.at(basic_exit_reason::wrmsr) = exit_delegate;

    exit_delegate = handler_delegate_t::create<cr::delegator,
    &cr::delegator::handle>(m_cr_delegator);
    m_exit_delegates.at(basic_exit_reason::control_register_accesses) = exit_delegate;
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

bool
exit_handler::handle(vcpu_t vcpu)
{
    // Handlers for all vmexits all run first
    for (const auto &d : this->m_exit_handlers) {
        d(vcpu);
    }

    auto reason = ::intel_x64::vmcs::exit_reason::basic_exit_reason::get();

    // Preffer the new delegator mechanism
    auto exit_delegate = m_exit_delegates.at(reason);
    if (exit_delegate(vcpu)) {
        return true;
    }

    // Fall back to legacy mechanism until refactor is complete
    const auto &handlers = this->m_exit_handlers_array.at(reason);
    for (const auto &d : handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    return m_fallback_delegator->handle(vcpu);
}

}
