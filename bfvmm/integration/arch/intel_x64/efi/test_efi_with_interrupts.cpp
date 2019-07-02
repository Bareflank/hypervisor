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

// TIDY_EXCLUSION=-cert-err58-cpp
//
// Reason:
//     This test triggers on the use of a std::mutex being globally defined
//     from the EPT map.
//

#include <bfcallonce.h>

#include <vcpu/vcpu_factory.h>
#include <hve/arch/intel_x64/vcpu.h>

using namespace bfvmm::intel_x64;

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

bfn::once_flag flag;
ept::mmap g_guest_map;

class vcpu : public bfvmm::intel_x64::vcpu
{
public:
    explicit vcpu(vcpuid::type id) :
        bfvmm::intel_x64::vcpu{id}
    {
        bfn::call_once(flag, [&] {
            ept::identity_map(
                g_guest_map,
                MAX_PHYS_ADDR
            );
        });

        this->add_wrmsr_handler(
            ::intel_x64::msrs::ia32_apic_base::addr,
        {&vcpu::ia32_apic_base__wrmsr_handler, this});

        this->set_eptp(g_guest_map);
    }

    ~vcpu() override = default;

    bool
    external_interrupt_handler(
        vcpu_t *vcpu, external_interrupt_handler::info_t &info)
    {
        vcpu->queue_external_interrupt(info.vector);
        return true;
    }

    bool
    ia32_apic_base__wrmsr_handler(
        vcpu_t *v, wrmsr_handler::info_t &info)
    {
        if (::intel_x64::msrs::ia32_apic_base::extd::is_enabled(info.val)) {
            v->add_external_interrupt_handler(
            {&vcpu::external_interrupt_handler, this});
        }
        else {
            bferror_info(0, "local xAPIC mode is not supported");
        }

        return true;
    }

public:

    /// @cond

    vcpu(vcpu &&) = delete;
    vcpu &operator=(vcpu &&) = delete;

    vcpu(const vcpu &) = delete;
    vcpu &operator=(const vcpu &) = delete;

    /// @endcond
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make(vcpuid::type vcpuid, void *data)
{
    bfignored(data);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
