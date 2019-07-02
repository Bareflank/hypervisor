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

alignas(0x200000) std::array<uint8_t, 0x200000> buffer;

void
vcpu_fini_nonroot_running(vcpu_t *vcpu)
{
    bfignored(vcpu);
    buffer.at(0)++;
}

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

        this->add_ept_read_violation_handler(
        {&vcpu::test_read_violation_handler, this});

        auto [pte, unused] =
            g_guest_map.entry(
                g_mm->virtptr_to_physint(buffer.data())
            );

        ::intel_x64::ept::pd::entry::read_access::disable(pte);
        ::intel_x64::ept::pd::entry::write_access::disable(pte);
        ::intel_x64::ept::pd::entry::execute_access::disable(pte);

        this->set_eptp(g_guest_map);
    }

    ~vcpu() override = default;

    bool
    test_read_violation_handler(
        vcpu_t *vcpu, ept_violation_handler::info_t &info)
    {
        bfignored(vcpu);
        bfignored(info);

        bfdebug_info(0, "disabling EPT");
        this->disable_ept();

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
