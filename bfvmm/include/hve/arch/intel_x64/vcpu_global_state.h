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

#ifndef VCPU_GLOBAL_STATE_INTEL_X64_H
#define VCPU_GLOBAL_STATE_INTEL_X64_H

#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HVE
#ifdef SHARED_HVE
#define EXPORT_HVE EXPORT_SYM
#else
#define EXPORT_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

/// VM Global State
///
/// The APIs require global variables that "group" up vcpus into VMs.
/// This allows vcpus to be grouped up into logical VMs that share a
/// common global state.
///
struct vcpu_global_state_t {

    /// Init Called
    ///
    /// Synchronization flag used during the INIT/SIPI process. Specifically
    /// this is used to ensure SIPI is not sent before INIT is finished.
    ///
    std::atomic<bool> init_called{false};

    /// CR0 Fixed Bits
    ///
    /// Defines the bits that must be fixed to 1. Note that these could change
    /// depending on how the system is configured.
    ///
    uint64_t ia32_vmx_cr0_fixed0 {
        ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get()
    };

    /// CR4 Fixed Bits
    ///
    /// Defines the bits that must be fixed to 1. Note that these could change
    /// depending on how the system is configured.
    ///
    uint64_t ia32_vmx_cr4_fixed0 {
        ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get()
    };
};

/// VM Global State Instance
///
/// The default global state. This is needed for host vCPUs. Guest vCPUs
/// need to create and store an instance for each guest VM.
///
inline vcpu_global_state_t g_vcpu_global_state;

}

#endif
