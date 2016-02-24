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

#ifndef EXIT_HANDLER
#define EXIT_HANDLER

#include <stdint.h>

extern "C"
{

    /// Exit Handler
    ///
    /// This is the "C" portion of the exit handler. Once the entry point has
    /// finished it's job, it hands control to this function, which trampolines
    /// to a C++ exit handler dispatch which will ultamitely handle the VM exit
    ///
    void exit_handler(void);

    /// Exit Handler Stack
    ///
    /// The exit handler must be given a stack as it will be executing in it's
    /// own context while a virtual machine is running, and thus cannot shre the
    /// same stack.
    ///
    void *exit_handler_stack(void);

    /// Exit Handler Entry
    ///
    /// This is the starting point of the VMM. It is written in pure assembly
    /// in order to ensure the state of the guest is handled properly. This
    /// code saves / restores the guest's CPU state, and then hands control off
    /// to the "C" portion of the code to continue execution, and begin the
    /// process of handling the VM exit.
    ///
    void exit_handler_entry(void);

    /// Promote Guest VMCS state to VMX root mode
    ///
    /// Abandon the host state, and jump into the guest state
    /// from the host.
    void promote_vmcs_to_root(void);

    /// Guest State
    ///
    /// The following exposes the guest state to the rest of the exit handler.
    /// Note that this guest state actually exists in the assembly code to
    /// provide it easy access to save / restore the guest state on exits.
    ///
    extern uint64_t g_guest_rax;
    extern uint64_t g_guest_rbx;
    extern uint64_t g_guest_rcx;
    extern uint64_t g_guest_rdx;
    extern uint64_t g_guest_rbp;
    extern uint64_t g_guest_rsi;
    extern uint64_t g_guest_rdi;
    extern uint64_t g_guest_r08;
    extern uint64_t g_guest_r09;
    extern uint64_t g_guest_r10;
    extern uint64_t g_guest_r11;
    extern uint64_t g_guest_r12;
    extern uint64_t g_guest_r13;
    extern uint64_t g_guest_r14;
    extern uint64_t g_guest_r15;
    extern uint64_t g_guest_rsp;
    extern uint64_t g_guest_rip;

    /// Guest CPUID
    ///
    /// Executes the CPUID instruction using the guest state instead of the
    /// host register state. The result of the instruction is stored back into
    /// the guest state, which can then be used by the exit handler as needed.
    ///
    void guest_cpuid(void);

    /// Guest Read MSR
    ///
    /// Executes the RDMSR instruction using the guest state instead of the
    /// host register state. The result of the instruction is stored back into
    /// the guest state, which can then be used by the exit handler as needed.
    ///
    void guest_read_msr(void);

    /// Guest Read MSR
    ///
    /// Executes the RDMSR instruction using the guest state instead of the
    /// host register state. The result of the instruction is stored back into
    /// the guest state, which can then be used by the exit handler as needed.
    ///
    void guest_write_msr(void);

}

#endif
