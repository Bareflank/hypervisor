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

#ifndef INTRINSICS_INTEL_X64_H
#define INTRINSICS_INTEL_X64_H

#include <stdint.h>
#include <iostream>
#include <intrinsics/msrs_intel_x64.h>
#include <intrinsics/intrinsics_x64.h>

// -----------------------------------------------------------------------------
// Intrinsics
// -----------------------------------------------------------------------------

extern "C" bool __vmxon(void *vmxon_region) noexcept;
extern "C" bool __vmxoff(void) noexcept;
extern "C" bool __vmcall(uint64_t value) noexcept;
extern "C" bool __vmclear(void *vmcs_region) noexcept;
extern "C" bool __vmptrld(void *vmcs_region) noexcept;
extern "C" bool __vmptrst(void *vmcs_region) noexcept;
extern "C" bool __vmwrite(uint64_t field, uint64_t val) noexcept;
extern "C" bool __vmread(uint64_t field, uint64_t *val) noexcept;
extern "C" bool __vmlaunch(void) noexcept;

// -----------------------------------------------------------------------------
// State Save
// -----------------------------------------------------------------------------

// When ever an exit occurs, the CPU saves portions of the CPU state, but
// for whatever reason, it does not save the general purpose registers. We
// have to do this ourselves. So, the very first thing the exit handler has to
// do is save the guest's register state. The problem is, each CPU has it's
// own register state, and thus must have it's own state save area. To handle
// this, we define this state save area and then each exit handler creates
// it's own state save area. To get access to this quickly, we store the
// address of the state save area in the GS base MSR. This way, we can use
// [gs:xxx] to save the general purpose registers.

#pragma pack(push, 1)

struct state_save_intel_x64
{
    uint64_t rax;                   // 0x000
    uint64_t rbx;                   // 0x008
    uint64_t rcx;                   // 0x010
    uint64_t rdx;                   // 0x018
    uint64_t rbp;                   // 0x020
    uint64_t rsi;                   // 0x028
    uint64_t rdi;                   // 0x030
    uint64_t r08;                   // 0x038
    uint64_t r09;                   // 0x040
    uint64_t r10;                   // 0x048
    uint64_t r11;                   // 0x050
    uint64_t r12;                   // 0x058
    uint64_t r13;                   // 0x060
    uint64_t r14;                   // 0x068
    uint64_t r15;                   // 0x070
    uint64_t rip;                   // 0x078
    uint64_t rsp;                   // 0x080

    uint64_t vcpuid;                // 0x088
    uint64_t vmxon_ptr;             // 0x090
    uint64_t vmcs_ptr;              // 0x098
    uint64_t exit_handler_ptr;      // 0x0A0

    uint64_t reserved1;             // 0x0A8
    uint64_t reserved2;             // 0x0B0
    uint64_t reserved3;             // 0x0B8

    uint64_t ymm00[4];              // 0x0C0
    uint64_t ymm01[4];              // 0x0E0
    uint64_t ymm02[4];              // 0x100
    uint64_t ymm03[4];              // 0x120
    uint64_t ymm04[4];              // 0x140
    uint64_t ymm05[4];              // 0x160
    uint64_t ymm06[4];              // 0x180
    uint64_t ymm07[4];              // 0x1A0
    uint64_t ymm08[4];              // 0x1C0
    uint64_t ymm09[4];              // 0x1E0
    uint64_t ymm10[4];              // 0x200
    uint64_t ymm11[4];              // 0x220
    uint64_t ymm12[4];              // 0x240
    uint64_t ymm13[4];              // 0x260
    uint64_t ymm14[4];              // 0x280
    uint64_t ymm15[4];              // 0x2A0

    uint64_t remaining_space_in_page[0x1A8];
};

#pragma pack(pop)

// -----------------------------------------------------------------------------
// C++ Wrapper
// -----------------------------------------------------------------------------

/// Intrinsics (x86_64)
///
/// Wraps all of the intrinsics functions that are specific to Intel
/// 64bit CPUs.
///
class intrinsics_intel_x64 : public intrinsics_x64
{
public:

    intrinsics_intel_x64() noexcept = default;
    ~intrinsics_intel_x64() override = default;

    virtual bool vmxon(void *vmxon_region) const noexcept
    { return __vmxon(vmxon_region); }

    virtual bool vmxoff() const noexcept
    { return __vmxoff(); }

    virtual bool vmcall(uint64_t value) const noexcept
    { return __vmcall(value); }

    virtual bool vmclear(void *vmcs_region) const noexcept
    { return __vmclear(vmcs_region); }

    virtual bool vmptrld(void *vmcs_region) const noexcept
    { return __vmptrld(vmcs_region); }

    virtual bool vmptrst(void *vmcs_region) const noexcept
    { return __vmptrst(vmcs_region); }

    virtual bool vmwrite(uint64_t field, uint64_t val) const noexcept
    { return __vmwrite(field, val); }

    virtual bool vmread(uint64_t field, uint64_t *val) const noexcept
    { return __vmread(field, val); }

    virtual bool vmlaunch() const noexcept
    { return __vmlaunch(); }
};



// Pin-Based VM-Execution Controls
// intel's software developers manual, volume 3, chapter 24.6.1.
#define VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING              (1ULL << 0)
#define VM_EXEC_PIN_BASED_NMI_EXITING                             (1ULL << 3)
#define VM_EXEC_PIN_BASED_VIRTUAL_NMIS                            (1ULL << 5)
#define VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER           (1ULL << 6)
#define VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS               (1ULL << 7)

// Primary Processor-Based VM-Execution Controls
// intel's software developers manual, volume 3, chapter 24.6.2
#define VM_EXEC_P_PROC_BASED_INTERRUPT_WINDOW_EXITING             (1ULL << 2)
#define VM_EXEC_P_PROC_BASED_USE_TSC_OFFSETTING                   (1ULL << 3)
#define VM_EXEC_P_PROC_BASED_HLT_EXITING                          (1ULL << 7)
#define VM_EXEC_P_PROC_BASED_INVLPG_EXITING                       (1ULL << 9)
#define VM_EXEC_P_PROC_BASED_MWAIT_EXITING                        (1ULL << 10)
#define VM_EXEC_P_PROC_BASED_RDPMC_EXITING                        (1ULL << 11)
#define VM_EXEC_P_PROC_BASED_RDTSC_EXITING                        (1ULL << 12)
#define VM_EXEC_P_PROC_BASED_CR3_LOAD_EXITING                     (1ULL << 15)
#define VM_EXEC_P_PROC_BASED_CR3_STORE_EXITING                    (1ULL << 16)
#define VM_EXEC_P_PROC_BASED_CR8_LOAD_EXITING                     (1ULL << 19)
#define VM_EXEC_P_PROC_BASED_CR8_STORE_EXITING                    (1ULL << 20)
#define VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW                       (1ULL << 21)
#define VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING                   (1ULL << 22)
#define VM_EXEC_P_PROC_BASED_MOV_DR_EXITING                       (1ULL << 23)
#define VM_EXEC_P_PROC_BASED_UNCONDITIONAL_IO_EXITING             (1ULL << 24)
#define VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS                       (1ULL << 25)
#define VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG                    (1ULL << 27)
#define VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS                      (1ULL << 28)
#define VM_EXEC_P_PROC_BASED_MONITOR_EXITING                      (1ULL << 29)
#define VM_EXEC_P_PROC_BASED_PAUSE_EXITING                        (1ULL << 30)
#define VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS          (1ULL << 31)

// Secondary Processor-Based VM-Execution Controls
// intel's software developers manual, volume 3, chapter 24.6.2
#define VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES             (1ULL << 0)
#define VM_EXEC_S_PROC_BASED_ENABLE_EPT                           (1ULL << 1)
#define VM_EXEC_S_PROC_BASED_DESCRIPTOR_TABLE_EXITING             (1ULL << 2)
#define VM_EXEC_S_PROC_BASED_ENABLE_RDTSCP                        (1ULL << 3)
#define VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE               (1ULL << 4)
#define VM_EXEC_S_PROC_BASED_ENABLE_VPID                          (1ULL << 5)
#define VM_EXEC_S_PROC_BASED_WBINVD_EXITING                       (1ULL << 6)
#define VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST                   (1ULL << 7)
#define VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION         (1ULL << 8)
#define VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY           (1ULL << 9)
#define VM_EXEC_S_PROC_BASED_PAUSE_LOOP_EXITING                   (1ULL << 10)
#define VM_EXEC_S_PROC_BASED_RDRAND_EXITING                       (1ULL << 11)
#define VM_EXEC_S_PROC_BASED_ENABLE_INVPCID                       (1ULL << 12)
#define VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS                  (1ULL << 13)
#define VM_EXEC_S_PROC_BASED_VMCS_SHADOWING                       (1ULL << 14)
#define VM_EXEC_S_PROC_BASED_RDSEED_EXITING                       (1ULL << 16)
#define VM_EXEC_S_PROC_BASED_ENABLE_PML                           (1ULL << 17)
#define VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE                     (1ULL << 18)
#define VM_EXEC_S_PROC_BASED_ENABLE_XSAVES_XRSTORS                (1ULL << 20)

// VM-Exit Control Fields
// intel's software developers manual, volume 3, chapter 24.7.1
#define VM_EXIT_CONTROL_SAVE_DEBUG_CONTROLS                       (1ULL << 2)
#define VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE                   (1ULL << 9)
#define VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL                (1ULL << 12)
#define VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT             (1ULL << 15)
#define VM_EXIT_CONTROL_SAVE_IA32_PAT                             (1ULL << 18)
#define VM_EXIT_CONTROL_LOAD_IA32_PAT                             (1ULL << 19)
#define VM_EXIT_CONTROL_SAVE_IA32_EFER                            (1ULL << 20)
#define VM_EXIT_CONTROL_LOAD_IA32_EFER                            (1ULL << 21)
#define VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE           (1ULL << 22)

// VM-Entry Control Fields
// intel's software developers manual, volume 3, chapter 24.8.1
#define VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS                      (1ULL << 2)
#define VM_ENTRY_CONTROL_IA_32E_MODE_GUEST                        (1ULL << 9)
#define VM_ENTRY_CONTROL_ENTRY_TO_SMM                             (1ULL << 10)
#define VM_ENTRY_CONTROL_DEACTIVATE_DUAL_MONITOR_TREATMENT        (1ULL << 11)
#define VM_ENTRY_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL               (1ULL << 13)
#define VM_ENTRY_CONTROL_LOAD_IA32_PAT                            (1ULL << 14)
#define VM_ENTRY_CONTROL_LOAD_IA32_EFER                           (1ULL << 15)

// VM-Function Control Fields
#define VM_FUNCTION_CONTROL_EPTP_SWITCHING                        (1ULL << 0)

// VM Exit Reasons
// intel's software developers manual, volume 3, appendix c
#define VM_EXIT_REASON_EXCEPTION_OR_NON_MASKABLE_INTERRUPT        (0)
#define VM_EXIT_REASON_EXTERNAL_INTERRUPT                         (1)
#define VM_EXIT_REASON_TRIPLE_FAULT                               (2)
#define VM_EXIT_REASON_INIT_SIGNAL                                (3)
#define VM_EXIT_REASON_SIPI                                       (4)
#define VM_EXIT_REASON_SMI                                        (5)
#define VM_EXIT_REASON_OTHER_SMI                                  (6)
#define VM_EXIT_REASON_INTERRUPT_WINDOW                           (7)
#define VM_EXIT_REASON_NMI_WINDOW                                 (8)
#define VM_EXIT_REASON_TASK_SWITCH                                (9)
#define VM_EXIT_REASON_CPUID                                      (10)
#define VM_EXIT_REASON_GETSEC                                     (11)
#define VM_EXIT_REASON_HLT                                        (12)
#define VM_EXIT_REASON_INVD                                       (13)
#define VM_EXIT_REASON_INVLPG                                     (14)
#define VM_EXIT_REASON_RDPMC                                      (15)
#define VM_EXIT_REASON_RDTSC                                      (16)
#define VM_EXIT_REASON_RSM                                        (17)
#define VM_EXIT_REASON_VMCALL                                     (18)
#define VM_EXIT_REASON_VMCLEAR                                    (19)
#define VM_EXIT_REASON_VMLAUNCH                                   (20)
#define VM_EXIT_REASON_VMPTRLD                                    (21)
#define VM_EXIT_REASON_VMPTRST                                    (22)
#define VM_EXIT_REASON_VMREAD                                     (23)
#define VM_EXIT_REASON_VMRESUME                                   (24)
#define VM_EXIT_REASON_VMWRITE                                    (25)
#define VM_EXIT_REASON_VMXOFF                                     (26)
#define VM_EXIT_REASON_VMXON                                      (27)
#define VM_EXIT_REASON_CONTROL_REGISTER_ACCESSES                  (28)
#define VM_EXIT_REASON_MOV_DR                                     (29)
#define VM_EXIT_REASON_IO_INSTRUCTION                             (30)
#define VM_EXIT_REASON_RDMSR                                      (31)
#define VM_EXIT_REASON_WRMSR                                      (32)
#define VM_EXIT_REASON_VM_ENTRY_FAILURE_INVALID_GUEST_STATE       (33)
#define VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOADING               (34)
#define VM_EXIT_REASON_MWAIT                                      (36)
#define VM_EXIT_REASON_MONITOR_TRAP_FLAG                          (37)
#define VM_EXIT_REASON_MONITOR                                    (39)
#define VM_EXIT_REASON_PAUSE                                      (40)
#define VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT       (41)
#define VM_EXIT_REASON_TPR_BELOW_THRESHOLD                        (43)
#define VM_EXIT_REASON_APIC_ACCESS                                (44)
#define VM_EXIT_REASON_VIRTUALIZED_EOI                            (45)
#define VM_EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR                     (46)
#define VM_EXIT_REASON_ACCESS_TO_LDTR_OR_TR                       (47)
#define VM_EXIT_REASON_EPT_VIOLATION                              (48)
#define VM_EXIT_REASON_EPT_MISCONFIGURATION                       (49)
#define VM_EXIT_REASON_INVEPT                                     (50)
#define VM_EXIT_REASON_RDTSCP                                     (51)
#define VM_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED               (52)
#define VM_EXIT_REASON_INVVPID                                    (53)
#define VM_EXIT_REASON_WBINVD                                     (54)
#define VM_EXIT_REASON_XSETBV                                     (55)
#define VM_EXIT_REASON_APIC_WRITE                                 (56)
#define VM_EXIT_REASON_RDRAND                                     (57)
#define VM_EXIT_REASON_INVPCID                                    (58)
#define VM_EXIT_REASON_VMFUNC                                     (59)
#define VM_EXIT_REASON_RDSEED                                     (61)
#define VM_EXIT_REASON_XSAVES                                     (63)
#define VM_EXIT_REASON_XRSTORS                                    (64)

// VM Activity State
// intel's software developers manual, volume 3, 24.4.2
#define VM_ACTIVITY_STATE_ACTIVE                                  (0)
#define VM_ACTIVITY_STATE_HLT                                     (1)
#define VM_ACTIVITY_STATE_SHUTDOWN                                (2)
#define VM_ACTIVITY_STATE_WAIT_FOR_SIPI                           (3)

// VM Interrupability State
// intel's software developers manual, volume 3, 24.4.2
#define VM_INTERRUPTABILITY_STATE_STI                             (1 << 0)
#define VM_INTERRUPTABILITY_STATE_MOV_SS                          (1 << 1)
#define VM_INTERRUPTABILITY_STATE_SMI                             (1 << 2)
#define VM_INTERRUPTABILITY_STATE_NMI                             (1 << 3)

// VM Interrupt Information Fields
// intel's software developers manual, volume 3, 24.8.3
#define VM_INTERRUPT_INFORMATION_VECTOR                           (0x000000FF)
#define VM_INTERRUPT_INFORMATION_TYPE                             (0x00000700)
#define VM_INTERRUPT_INFORMATION_DELIVERY_ERROR                   (0x00000800)
#define VM_INTERRUPT_INFORMATION_VALID                            (0x80000000)

// VM Interruption Types
// intel's software developers manual, volume 3, 24.8.3
#define VM_INTERRUPTION_TYPE_EXTERNAL                             (0)
#define VM_INTERRUPTION_TYPE_NMI                                  (2)
#define VM_INTERRUPTION_TYPE_HARDWARE                             (3)
#define VM_INTERRUPTION_TYPE_SOFTWARE_INTERRUPT                   (4)
#define VM_INTERRUPTION_TYPE_PRIVILEGED_SOFTWARE_EXCEPTION        (5)
#define VM_INTERRUPTION_TYPE_SOFTWARE_EXCEPTION                   (6)
#define VM_INTERRUPTION_TYPE_OTHER                                (7)

// MTF VM Exit
// intel's software developers manual, volume 3, 26.5.2
#define MTF_VM_EXIT                                               (0)

// Pending Debug Exceptions
// intel's software developers manual, volume 3, 24.4.2
#define PENDING_DEBUG_EXCEPTION_B0                                (1 << 0)
#define PENDING_DEBUG_EXCEPTION_B1                                (1 << 1)
#define PENDING_DEBUG_EXCEPTION_B2                                (1 << 2)
#define PENDING_DEBUG_EXCEPTION_B3                                (1 << 3)
#define PENDING_DEBUG_EXCEPTION_ENABLED_BREAKPOINT                (1 << 12)
#define PENDING_DEBUG_EXCEPTION_BS                                (1 << 14)

// VPID and EPT Capabilities
// intel's software developer's manual, volume 3, appendix A.10
#define IA32_VMX_EPT_VPID_CAP_UC                                  (1ULL << 8)
#define IA32_VMX_EPT_VPID_CAP_WB                                  (1ULL << 14)
#define IA32_VMX_EPT_VPID_CAP_AD                                  (1ULL << 21)

// EPTP Format
// intel's software developer's manual, volume 3, appendix 24.6.11
#define EPTP_MEMORY_TYPE                                   0x0000000000000007
#define EPTP_PAGE_WALK_LENGTH                              0x0000000000000038
#define EPTP_ACCESSED_DIRTY_FLAGS_ENABLED                  0x0000000000000040

// // EPTP Format
// // intel's software developer's manual, volume 3, appendix 24.6.11
// template<class T> constexpr auto
// eptp_ept_paging_structure_memory_type(T eptp) -> auto
// { return (eptp & static_cast<T>(0x0000000000000007)) >> 0; }

// template<class T> constexpr auto
// eptp_ept_page_walk_length(T eptp) -> auto
// { return (eptp & static_cast<T>(0x0000000000000038)) >> 3; }

// template<class T> constexpr auto
// eptp_ept_accessed_dirty_flags_enabled(T eptp) -> auto
// { return (eptp & static_cast<T>(0x0000000000000040)) != 0; }

// template<class T> constexpr auto
// eptp_reserved_are_cleared(T eptp) -> auto
// { return (eptp & static_cast<T>(0x0000000000000F80)) == 0; }

#endif
