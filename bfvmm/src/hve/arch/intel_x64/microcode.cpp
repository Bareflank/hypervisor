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

static bool
ia32_bios_updt_trig__rdmsr_handler(
    vcpu *vcpu, rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

static bool
ia32_bios_updt_trig__wrmsr_handler(
    vcpu *vcpu, wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.ignore_write = true;
    return true;
}

static bool
ia32_bios_sign_id__rdmsr_handler(
    vcpu *vcpu, rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    // QUIRK
    //
    // The Intel SDM states that VMMs should return 0 to ignore
    // a microcode update, but the Linux kernel doesn't seem to
    // respect this on the APs (for some reason the BSP is fine)
    // and as a result, the APs end up in an endless loop. To
    // prevent this, we return all Fs, and as a result, the Linux
    // kernel thinks that a better version of the microcode is
    // already present.

    info.val = 0xFFFFFFFFFFFFFFFF;
    return true;
}

static bool
ia32_bios_sign_id__wrmsr_handler(
    vcpu *vcpu, wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.ignore_write = true;
    return true;
}

microcode_handler::microcode_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_rdmsr_handler(
        ::intel_x64::msrs::ia32_bios_updt_trig::addr,
        ia32_bios_updt_trig__rdmsr_handler
    );

    vcpu->add_wrmsr_handler(
        ::intel_x64::msrs::ia32_bios_updt_trig::addr,
        ia32_bios_updt_trig__wrmsr_handler
    );

    vcpu->add_rdmsr_handler(
        ::intel_x64::msrs::ia32_bios_sign_id::addr,
        ia32_bios_sign_id__rdmsr_handler
    );

    vcpu->add_wrmsr_handler(
        ::intel_x64::msrs::ia32_bios_sign_id::addr,
        ia32_bios_sign_id__wrmsr_handler
    );
}

}
