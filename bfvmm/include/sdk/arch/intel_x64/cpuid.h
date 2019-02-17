//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef BFVMM_SDK_INTEL_X64_CPUID
#define BFVMM_SDK_INTEL_X64_CPUID

#include "../../../bfvmm.h"
#include "../../../hve/arch/intel_x64/delegator/cpuid.h"

namespace bfvmm::intel_x64::cpuid
{

/// Handle the given cpuid leaf using the given cpuid handler on
/// the given vcpu
///
/// @param vcpu the vcpu to register @param handler to
/// @param leaf the cpuid leaf to emulate
/// @param handler the handler to be called for the emulation of @param leaf
///
void handle(vcpu_t vcpu, leaf_t leaf, delegate_t handler);

/// Emulate a cpuid leaf for the the given vcpu. The upper 32-bits of each
/// emulated value are masked.
///
/// @param vcpu the vcpu to apply emulation to
/// @param rax the emulated value to be returned in rax
/// @param rbx the emulated value to be returned in rbx
/// @param rcx the emulated value to be returned in rcx
/// @param rdx the emulated value to be returned in rdx
///
void emulate(vcpu_t vcpu, uint64_t rax, uint64_t rbx, uint64_t rcx, uint64_t rdx);

/// Pass through a cpuid instruction for the given vcpu, using the current state
/// of the vcpu's rax, rbx, rcx, and rdx registers
///
/// @param vcpu the vcpu to pass cpuid access through for
void pass_through(vcpu_t vcpu);

}

#endif
