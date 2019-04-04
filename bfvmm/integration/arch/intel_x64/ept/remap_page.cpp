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

alignas(0x1000) std::array<uint8_t, 0x1000> buffer1;
alignas(0x1000) std::array<uint8_t, 0x1000> buffer2;

void
vcpu_fini_nonroot_running(vcpu_t *vcpu)
{
    bfignored(vcpu);

    ::x64::cpuid::get(
        42, 0, 0, 0
    );

    bfdebug_ndec(0, "A: buffer1.at(0)", buffer1.at(0));
    bfdebug_ndec(0, "A: buffer2.at(0)", buffer2.at(0));
}

class vcpu : public bfvmm::intel_x64::vcpu
{
public:
    explicit vcpu(vcpuid::type id) :
        bfvmm::intel_x64::vcpu{id}
    {
        this->add_cpuid_emulator(42, {&vcpu::test_cpuid_handler, this});

        for (auto &elem : buffer1) {
            elem = 42;
        }

        for (auto &elem : buffer2) {
            elem = 43;
        }

        bfdebug_ndec(0, "B: buffer1.at(0)", buffer1.at(0));
        bfdebug_ndec(0, "B: buffer2.at(0)", buffer2.at(0));
    }

    ~vcpu() override = default;

    bool
    test_cpuid_handler(vcpu_t *vcpu)
    {
        bfignored(vcpu);

        bfn::call_once(flag, [&] {
            auto [gpa1, unused1] = this->gva_to_gpa(buffer1.data());
            auto [gpa2, unused2] = this->gva_to_gpa(buffer2.data());

            auto gpa1_2m = bfn::upper(gpa1, ::intel_x64::ept::pd::from);
            auto gpa1_4k = bfn::upper(gpa1, ::intel_x64::ept::pt::from);
            auto gpa2_4k = bfn::upper(gpa2, ::intel_x64::ept::pt::from);

            ept::identity_map(
                g_guest_map,
                MAX_PHYS_ADDR
            );

            ept::identity_map_convert_2m_to_4k(
                g_guest_map,
                gpa1_2m
            );

            auto [pte, unused] = g_guest_map.entry(gpa1_4k);
            ::intel_x64::ept::pt::entry::phys_addr::set(pte, gpa2_4k);
        });

        this->set_eptp(g_guest_map);

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
