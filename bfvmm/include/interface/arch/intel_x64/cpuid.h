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

#ifndef BFVMM_INTERFACE_CPUID_INTEL_X64_H
#define BFVMM_INTERFACE_CPUID_INTEL_X64_H

namespace bfvmm::intel_x64
{

/// vCPU CPUID Interface
///
/// vCPUs that support CPUID virtualization must implement this interface
///
class vcpu_cpuid_interface
{

public:

    /// CPUID leaf type
    ///
    ///
    using leaf_t = uint64_t;

    /// CPUID Add Handler
    ///
    /// Add a handler for a CPUID VM exit caused by the given CPUID leaf.
    ///
    /// @param leaf the CPUID leaf register handler @param h for
    /// @param h the handler to call upon a VM exit
    ///
    VIRTUAL void cpuid_add_handler(leaf_t leaf, const handler_delegate_t &h) PURE;

    /// CPUID Add Emulator
    ///
    /// Add an emulator for a CPUID VM exit caused by the given CPUID leaf.
    ///
    /// @param leaf the CPUID leaf register handler @param e for
    /// @param e the emulator to call upon a VM exit
    ///
    VIRTUAL void cpuid_add_emulator(leaf_t leaf, const handler_delegate_t &e) PURE;

    /// CPUID Execute
    ///
    /// Execute the CPUID instruction on a physical CPU using the register state
    /// of a vCPU as inputs and outputs
    ///
    /// This function should be called in the context of a CPUID VM exit handler
    ///
    VIRTUAL void cpuid_execute() PURE;

    /// CPUID Emulate
    ///
    /// Emulate the result of a CPUID instruction using the register state of a
    /// vCPU as outputs.
    ///
    /// This function should be called in the context of a CPUID VM exit handler
    ///
    /// @param rax the emulated CPUID output for rax
    /// @param rbx the emulated CPUID output for rbx
    /// @param rcx the emulated CPUID output for rcx
    /// @param rdx the emulated CPUID output for rdx
    ///
    VIRTUAL void cpuid_emulate(
        uint64_t rax, uint64_t rbx, uint64_t rcx, uint64_t rdx) PURE;

    /// CPUID VM Exit Leaf
    ///
    /// Get the CPUID leaf (rax) that caused the current VM exit handler to run.
    ///
    /// This function should be called in the context of a CPUID VM exit handler
    ///
    /// @return the leaf that caused a VM exit to occur
    ///
    VIRTUAL leaf_t cpuid_vmexit_leaf() const PURE;

    /// CPUID VM Exit Subleaf
    ///
    /// Get the CPUID subleaf (rcx) that caused the current VM exit handler to
    /// run.
    ///
    /// This function should be called in the context of a CPUID VM exit handler
    ///
    /// @return the subleaf that caused a VM exit to occur
    ///
    VIRTUAL leaf_t cpuid_vmexit_subleaf() const PURE;
};

}

#endif
