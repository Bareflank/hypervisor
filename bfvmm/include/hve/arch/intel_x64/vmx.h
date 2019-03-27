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

#ifndef VMXON_INTEL_X64_H
#define VMXON_INTEL_X64_H

#include <memory>
#include "../../../memory_manager/memory_manager.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

/// VMXON (Intel x86_64)
///
/// This class is respobsible for turning Intel's VMX (also know as VT-x)
/// on / off. To do that, it performs a series of checks that are described
/// in the Intel manual, and then runs either vmxon or vmxoff.
///
/// This class is managed by vcpu_intel_x64
///
class vmx
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    vmx();

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~vmx();

private:

    void check_cpuid_vmx_supported();
    void check_vmx_capabilities_msr();
    void check_ia32_vmx_cr0_fixed_msr();
    void check_ia32_vmx_cr4_fixed_msr();
    void check_ia32_feature_control_msr();
    void check_v8086_disabled();

    void setup_vmx_region();

    void enable_vmx();
    void disable_vmx();
    void reset_vmx();

    void execute_vmxon();
    void execute_vmxoff();

private:

    page_ptr<uint32_t> m_vmx_region;
    uintptr_t m_vmx_region_phys;

public:

    /// @cond

    vmx(vmx &&) noexcept = default;
    vmx &operator=(vmx &&) noexcept = default;

    vmx(const vmx &) = delete;
    vmx &operator=(const vmx &) = delete;

    /// @endcond
};

}

#endif
