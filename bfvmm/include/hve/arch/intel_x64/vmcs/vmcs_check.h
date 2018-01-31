//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef VMCS_INTEL_X64_CHECK_H
#define VMCS_INTEL_X64_CHECK_H

#include "vmcs_check_host.h"
#include "vmcs_check_guest.h"
#include "vmcs_check_controls.h"

/// Intel x86_64 VMCS Check
///
/// This namespace implements the checks found in sections 26.1 through
/// 26.3, Vol. 3 of the SDM.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{
namespace check
{

inline void
all()
{
    host_state_all();
    guest_state_all();
    vmx_controls_all();
}

}
}
}

// *INDENT-ON*

#endif
