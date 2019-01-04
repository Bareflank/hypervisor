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

/// Emulate the given cpuid leaf using the given cpuid handler on
/// the given vcpu
///
/// @param vcpu the vcpu to apply emulation to
/// @param leaf the cpuid leaf to emulate
/// @param handler the handler to be called for the emulation of @param leaf
///
void emulate(vcpu_t vcpu, leaf_t leaf, delegate_t handler);

}

#endif
