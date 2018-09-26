//
// Bareflank Hypervisor
//
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

#ifndef NMI_INTEL_X64_H
#define NMI_INTEL_X64_H

#include <bfexports.h>
#include "../x64/idt.h"

/// _handle_nmi
///
/// The NMI handler referenced by vector 2 of the IDT
/// Enables NMI-window exiting
///
extern "C" void _handle_nmi(void) noexcept;

/// set_nmi_handler
///
/// @param idt the address of the IDT
/// @param selector the selector of the IDT descriptor
///
void set_nmi_handler(
    bfvmm::x64::idt *idt,
    bfvmm::x64::idt::selector_type selector
) noexcept;

/// inject_nmi
///
/// Program the VMCS to inject an NMI on VM-entry.
/// This should only be called from an NMI-window exit handler.
///
void inject_nmi() noexcept;

#endif
