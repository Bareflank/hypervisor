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

// TODO
//
// The NMI logic is not safe, and it could result in corruption (although the
// chances of this a very low). There is no clean way to disable NMIs which
// means that at any given time, an NMI could fire. If the enable CTL is
// being modified when an NMI fires, this code could corrupt said operation.
//
// The only real way to prevent this is to ensure that both this code, and any
// code that touches this CTL only uses atomic bit sets which can be done:
// https://stackoverflow.com/questions/30467638/cheapest-least-intrusive-way-to-atomically-update-a-bit
//
// If atomic bit setting is done for this field, we can ensure that at no time,
// the CTL becomes corrupt if an NMI happens to fire.
//

nmi_window_handler::nmi_window_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::nmi_window,
    {&nmi_window_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
nmi_window_handler::queue_nmi()
{
    // Notes:
    //
    // Like interrupt injecting, a lot of work has been done to ensure that
    // this code is as safe as possible. Here are some notes:
    // - The enable exiting function will change the primary processor CTL
    //   and it is possible that this modification could result in corruption
    //   as explained above. Eventually this will be changed to an atomic bit
    //   set and as a result, we should be completely safe
    // - There is no reason to queue up additional NMIs. That is, once an NMI
    //   is queued, you cannot queue another one until the first one has been
    //   delivered. Any attempt to queue an additional NMI will simply result
    //   in the second NMI being dropped. This prevents the need to maintain
    //   a count, which in turn reduces the complexity of this function.
    // - It should be noted that this function could be executed by the same
    //   vCPU more than once. For example, the VMM could attempt to inject
    //   an NMI into the guest by queuing an NMI and while this function is
    //   modifying the CTL, an NMI could fire, which would cause the VMM's
    //   exception handler to execute and call this function again, before the
    //   original call had a chance to execute. For this reason, we need to
    //   keep this logic as simple as possible.
    // - Like interrupt injection, the inject_nmi should only ever be executed
    //   during an open window exit. This prevents the injection field from
    //   being overwritten as interrupts remain mutually exclusive.

    this->enable_exiting();
}

void
nmi_window_handler::inject_nmi()
{
    namespace info_n = vmcs_n::vm_entry_interruption_information;
    using namespace info_n::interruption_type;

    uint64_t info = 0;

    info_n::vector::set(info, 2);
    info_n::interruption_type::set(info, non_maskable_interrupt);
    info_n::valid_bit::enable(info);

    info_n::set(info);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
nmi_window_handler::handle(vcpu *vcpu)
{
    bfignored(vcpu);

    this->disable_exiting();
    this->inject_nmi();

    return true;
}

// -----------------------------------------------------------------------------
// Private
// -----------------------------------------------------------------------------

void
nmi_window_handler::enable_exiting()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::nmi_window_exiting::enable();
}

void
nmi_window_handler::disable_exiting()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::nmi_window_exiting::disable();
}

}
