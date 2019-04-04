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

init_signal_handler::init_signal_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::init_signal,
    {&init_signal_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
init_signal_handler::handle(vcpu *vcpu)
{
    bfignored(vcpu);

    // NOTE:
    //
    // Linux has a default setting for new CPUs that disables the delay
    // between INIT/SIPI. As a result, this handler may never be called
    // which in turn will prevent the SIPI handler from ever getting
    // called. To prevent this issue, use the cpu_init_udelay kernel param
    // in Linux to turn the delay back on. The default is 10000 which
    // seems to work.
    //
    // For the same reason above, do not add any code to this routine.
    // The INIT/SIPI process is really fragile and as a result, all INIT
    // logic should actually be placed in the SIPI handler as that handler
    // can take as long as it needs to. INIT has to return ASAP.
    //

    vmcs_n::guest_activity_state::set(
        vmcs_n::guest_activity_state::wait_for_sipi
    );

    return true;
}

}
