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

#include <bfvmm/vcpu/vcpu_factory.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>

using namespace bfvmm::intel_x64;

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

uint64_t g_cr4;

bool
test_handler(
    gsl::not_null<vcpu_t *> vcpu, control_register_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    info.val = g_cr4;
    info.shadow = g_cr4;

    return false;
}

void
test_hlt_delegate(bfobject *obj)
{
    bfignored(obj);

    g_cr4 = ::intel_x64::cr4::get();
    ::intel_x64::cr4::set(0);

    if (::intel_x64::cr4::get() == g_cr4) {
        bfdebug_pass(0, "test");
    }
}

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

class vcpu : public bfvmm::intel_x64::vcpu
{
public:
    explicit vcpu(vcpuid::type id) :
        bfvmm::intel_x64::vcpu{id}
    {
        this->add_hlt_delegate(
            hlt_delegate_t::create<test_hlt_delegate>()
        );

        this->add_wrcr4_handler(
            0xFFFFFFFFFFFFFFFF,
            control_register_handler::handler_delegate_t::create<test_handler>()
        );
    }

    ~vcpu() override = default;

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
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
