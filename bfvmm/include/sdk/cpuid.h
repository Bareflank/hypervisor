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

#ifndef BFVMM_SDK_CPUID_INTEL_X64_H
#define BFVMM_SDK_CPUID_INTEL_X64_H

namespace bfvmm::intel_x64::cpuid
{

using leaf_t = ::bfvmm::intel_x64::cpuid_handler::leaf_t;

/// Add Handler
///
/// Adds a VM exit handler for a CPUID leaf.
///
/// @param vcpu the vcpu to add a handler to
/// @param leaf the cpuid leaf that @param handler is registered for
/// @param handler the handler to call when a VM exit occurs
///
void add_handler(vcpu *vcpu, leaf_t leaf, handler_delegate_t handler);

/// Add Emulator
///
/// Adds a VM exit emulator for a CPUID leaf.
///
/// @param vcpu the vcpu to add a handler to
/// @param leaf the cpuid leaf that @param handler is registered for
/// @param handler the handler to call when a VM exit occurs
///
void add_emulator(vcpu *vcpu, leaf_t leaf, handler_delegate_t handler);

/// Execute
///
/// Executes the CPUID instruction using the vCPU's registers as inputs and
/// outputs
///
/// vCPU Inputs:    rax, rcx
/// vCPU Outputs:   rax, rbx, rcx, rdx
///
/// @param vcpu the vcpu to execute CPUID on
///
void execute(vcpu *vcpu);

/// Emulate
///
/// Emulates the result of a CPUID instruction on the given vcpu using the given
/// output values (masked to 32-bits).
///
/// vCPU Outputs: rax, rbx, rcx, rdx
///
/// @param vcpu the vcpu to emulate a CPUID instruction on
/// @param rax the emulated output value for vcpu->rax
/// @param rbx the emulated output value for vcpu->rbx
/// @param rcx the emulated output value for vcpu->rcx
/// @param rdx the emulated output value for vcpu->rdx
///
void emulate(vcpu *vcpu, uint64_t rax, uint64_t rbx, uint64_t rcx, uint64_t rdx);

/// get_leaf
///
/// Get the CPUID leaf (rax) that caused the current VM exit handler to run,
/// regardless of the current value of vcpu->rax().
///
/// @param vcpu the vcpu on which to get the CPUID leaf that caused a VM exit
///
/// @return leaf_t the CPUID leaf that caused a VM exit
///
leaf_t get_leaf(vcpu *vcpu);

/// get_subleaf
///
/// Get the CPUID subleaf (rcx) that caused the current VM exit handler to run,
/// regardless of the current value of vcpu->rcx().
///
/// @param vcpu the vcpu on which to get the CPUID subleaf that caused a VM exit
///
/// @return leaf_t the CPUID subleaf that caused a VM exit
///
leaf_t get_subleaf(vcpu *vcpu);

}

#endif
