//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifndef EXIT_HANDLER_INTEL_X64_SUPPORT_H
#define EXIT_HANDLER_INTEL_X64_SUPPORT_H

#include <stdint.h>

/// Exit Handler Entry
///
/// This is the starting point of the VMM. It is written in pure assembly
/// in order to ensure the state of the guest is handled properly. This
/// code saves / restores the guest's CPU state, and then hands control off
/// to the "C" portion of the code to continue execution, and begin the
/// process of handling the VM exit.
///
extern "C" void exit_handler_entry(void);

/// Promote Guest VMCS state to VMX root mode
///
/// Abandon the host state, and jump into the guest state
/// from the host.
extern "C" void promote_vmcs_to_root(void);

/// Guest State
///
/// The following exposes the guest state to the rest of the exit handler.
/// Note that this guest state actually exists in the assembly code to
/// provide it easy access to save / restore the guest state on exits.
///
extern "C" { extern uint64_t g_guest_rax; }
extern "C" { extern uint64_t g_guest_rbx; }
extern "C" { extern uint64_t g_guest_rcx; }
extern "C" { extern uint64_t g_guest_rdx; }
extern "C" { extern uint64_t g_guest_rbp; }
extern "C" { extern uint64_t g_guest_rsi; }
extern "C" { extern uint64_t g_guest_rdi; }
extern "C" { extern uint64_t g_guest_r08; }
extern "C" { extern uint64_t g_guest_r09; }
extern "C" { extern uint64_t g_guest_r10; }
extern "C" { extern uint64_t g_guest_r11; }
extern "C" { extern uint64_t g_guest_r12; }
extern "C" { extern uint64_t g_guest_r13; }
extern "C" { extern uint64_t g_guest_r14; }
extern "C" { extern uint64_t g_guest_r15; }
extern "C" { extern uint64_t g_guest_rsp; }
extern "C" { extern uint64_t g_guest_rip; }

#endif
