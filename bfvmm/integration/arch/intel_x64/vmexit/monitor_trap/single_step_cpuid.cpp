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
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

class vcpu : public bfvmm::intel_x64::vcpu
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    explicit vcpu(vcpuid::type id) :
        bfvmm::intel_x64::vcpu{id}
    {
        this->add_cpuid_handler(
            42,
            cpuid_handler::handler_delegate_t::create<vcpu, &vcpu::cpuid_handler>(this)
        );

        this->add_monitor_trap_handler(
            monitor_trap_handler::handler_delegate_t::create<vcpu, &vcpu::monitor_trap_handler>(this)
        );
    }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() override
    {
        ::x64::cpuid::get(42, 0, 0, 0);
    }

    bool cpuid_handler(
        gsl::not_null<vcpu_t *> vcpu, cpuid_handler::info_t &info)
    {
        bfignored(vcpu);

        info.rax = 42;
        info.rbx = 42;
        info.rcx = 42;
        info.rdx = 42;

        this->enable_monitor_trap_flag();
        return false;
    }

    bool monitor_trap_handler(
        gsl::not_null<vcpu_t *> vcpu, monitor_trap_handler::info_t &info)
    {
        bfignored(vcpu);
        bfignored(info);

        bfdebug_info(0, "instrution after cpuid trapped");
        return false;
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
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
