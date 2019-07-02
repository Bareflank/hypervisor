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

#include <vcpu/vcpu_factory.h>
#include <hve/arch/intel_x64/vcpu.h>

using namespace bfvmm::intel_x64;

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
test_handler(
    vcpu_t *vcpu, io_instruction_handler::info_t &info)
{ bfignored(vcpu); bfignored(info); return true; }

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
        this->add_io_instruction_handler(0xCF8, test_handler, test_handler);
        this->add_io_instruction_handler(0xCFC, test_handler, test_handler);
    }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() override
    {
        uint32_t addr = 0x80000800;
        uint32_t data[10] = {};

        ::x64::portio::outd(0xCF8, 0x80000000);
        bfdebug_nhex(0, "PCI Configuration Space (addr)", ::x64::portio::ind(0xCF8));
        bfdebug_nhex(0, "PCI Configuration Space (data)", ::x64::portio::ind(0xCFC));

        ::x64::portio::outsd(0xCF8, &addr);
        ::x64::portio::insd(0xCFC, &data[0]);
        bfdebug_nhex(0, "PCI Configuration Space (addr)", ::x64::portio::ind(0xCF8));
        bfdebug_nhex(0, "PCI Configuration Space (data)", data[0]);
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
