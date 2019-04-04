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

#include <vmm.h>

void
global_init()
{
    bfdebug_info(0, "running rdtsc example");
    bfdebug_lnbr(0);
}

bool
handle_rdtsc(vcpu_t *vcpu)
{
    // NOTE:
    //
    // For completeness, CR4.TSD, CPL and CR0.PE should all be checked, otherwise
    // the execution of this instruction might bypass these checks by hardware.
    // For more information, please see the pseudo code for these instructions in
    // the Intel SDM.

    auto ret = x64::tsc::get();
    vcpu->set_rax((ret >> 0) & 0x00000000FFFFFFFF);
    vcpu->set_rdx((ret >> 32) & 0x00000000FFFFFFFF);

    return vcpu->advance();
}

bool
handle_rdtscp(vcpu_t *vcpu)
{
    // NOTE:
    //
    // For completeness, CR4.TSD, CPL and CR0.PE should all be checked, otherwise
    // the execution of this instruction might bypass these checks by hardware.
    // For more information, please see the pseudo code for these instructions in
    // the Intel SDM.

    auto ret = x64::tscp::get();
    vcpu->set_rax((ret >> 0) & 0x00000000FFFFFFFF);
    vcpu->set_rdx((ret >> 32) & 0x00000000FFFFFFFF);
    vcpu->set_rcx(x64::msrs::ia32_tsc_aux::get() & 0x00000000FFFFFFFF);

    return vcpu->advance();
}

void
vcpu_init_nonroot(vcpu_t *vcpu)
{
    using namespace vmcs_n;
    using namespace vmcs_n::exit_reason::basic_exit_reason;
    primary_processor_based_vm_execution_controls::rdtsc_exiting::enable();

    vcpu->add_exit_handler_for_reason(rdtsc, handle_rdtsc);
    vcpu->add_exit_handler_for_reason(rdtscp, handle_rdtscp);
}

// Expected Output (make dump)
//
// [0x0] DEBUG: running cpuidcount example
// [0x0] DEBUG:
// [0x0] DEBUG: host os is now in a vm
// [0x1] DEBUG: host os is now in a vm
// ...
// [0x1] DEBUG: host os is not in a vm
// [0x0] DEBUG: host os is not in a vm
// [0x0] DEBUG: count                                                           444
