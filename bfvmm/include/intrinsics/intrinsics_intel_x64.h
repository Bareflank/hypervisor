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
#include <intrinsics/intrinsics_x64.h>

// -----------------------------------------------------------------------------
// Intrinsics
// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

bool __vmxon(void *vmxon_region) noexcept;
bool __vmxoff(void) noexcept;
bool __vmcall(uint64_t value) noexcept;
bool __vmclear(void *vmcs_region) noexcept;
bool __vmptrld(void *vmcs_region) noexcept;
bool __vmptrst(void *vmcs_region) noexcept;
bool __vmwrite(uint64_t field, uint64_t val) noexcept;
bool __vmread(uint64_t field, uint64_t *val) noexcept;
bool __vmlaunch(void) noexcept;

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

#ifdef __cplusplus
}
#endif

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

// -----------------------------------------------------------------------------
// VMCS Fields
// -----------------------------------------------------------------------------

// VMX MSRs
// intel's software developer's manual, volume 3, appendix A.1
#define IA32_VMX_BASIC_MSR                                        0x00000480
#define IA32_VMX_MISC_MSR                                         0x00000485
#define IA32_VMX_CR0_FIXED0_MSR                                   0x00000486
#define IA32_VMX_CR0_FIXED1_MSR                                   0x00000487
#define IA32_VMX_CR4_FIXED0_MSR                                   0x00000488
#define IA32_VMX_CR4_FIXED1_MSR                                   0x00000489
#define IA32_FEATURE_CONTROL_MSR                                  0x0000003A
#define IA32_VMX_TRUE_PINBASED_CTLS_MSR                           0x0000048D
#define IA32_VMX_TRUE_PROCBASED_CTLS_MSR                          0x0000048E
#define IA32_VMX_TRUE_EXIT_CTLS_MSR                               0x0000048F
#define IA32_VMX_TRUE_ENTRY_CTLS_MSR                              0x00000490
#define IA32_VMX_PROCBASED_CTLS2_MSR                              0x0000048B
#define IA32_VMX_EPT_VPID_CAP_MSR                                 0x0000048C
#define IA32_VMX_VMFUNC_MSR                                       0x00000491

// The VMCS fields are defined in the intel's software developer's manual,
// volume 3, appendix B. An explaination of these fields can be found in
// volume 3, chapter 24

// 16bit Control Fields
#define VMCS_VIRTUAL_PROCESSOR_IDENTIFIER                         0x00000000
#define VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR                 0x00000002
#define VMCS_EPTP_INDEX                                           0x00000004

// 16bit Guest State Fields
#define VMCS_GUEST_ES_SELECTOR                                    0x00000800
#define VMCS_GUEST_CS_SELECTOR                                    0x00000802
#define VMCS_GUEST_SS_SELECTOR                                    0x00000804
#define VMCS_GUEST_DS_SELECTOR                                    0x00000806
#define VMCS_GUEST_FS_SELECTOR                                    0x00000808
#define VMCS_GUEST_GS_SELECTOR                                    0x0000080A
#define VMCS_GUEST_LDTR_SELECTOR                                  0x0000080C
#define VMCS_GUEST_TR_SELECTOR                                    0x0000080E
#define VMCS_GUEST_INTERRUPT_STATUS                               0x00000810

// 16bit Host State Fields
#define VMCS_HOST_ES_SELECTOR                                     0x00000C00
#define VMCS_HOST_CS_SELECTOR                                     0x00000C02
#define VMCS_HOST_SS_SELECTOR                                     0x00000C04
#define VMCS_HOST_DS_SELECTOR                                     0x00000C06
#define VMCS_HOST_FS_SELECTOR                                     0x00000C08
#define VMCS_HOST_GS_SELECTOR                                     0x00000C0A
#define VMCS_HOST_TR_SELECTOR                                     0x00000C0C

// 64bit Control Fields
#define VMCS_ADDRESS_OF_IO_BITMAP_A_FULL                          0x00002000
#define VMCS_ADDRESS_OF_IO_BITMAP_A_HIGH                          0x00002001
#define VMCS_ADDRESS_OF_IO_BITMAP_B_FULL                          0x00002002
#define VMCS_ADDRESS_OF_IO_BITMAP_B_HIGH                          0x00002003
#define VMCS_ADDRESS_OF_MSR_BITMAPS_FULL                          0x00002004
#define VMCS_ADDRESS_OF_MSR_BITMAPS_HIGH                          0x00002005
#define VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL                       0x00002006
#define VMCS_VM_EXIT_MSR_STORE_ADDRESS_HIGH                       0x00002007
#define VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL                        0x00002008
#define VMCS_VM_EXIT_MSR_LOAD_ADDRESS_HIGH                        0x00002009
#define VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL                       0x0000200A
#define VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_HIGH                       0x0000200B
#define VMCS_EXECUTIVE_VMCS_POINTER_FULL                          0x0000200C
#define VMCS_EXECUTIVE_VMCS_POINTER_HIGH                          0x0000200D
#define VMCS_PML_ADDRESS_FULL                                     0x0000200E
#define VMCS_PML_ADDRESS_HIGH                                     0x0000200F
#define VMCS_TSC_OFFSET_FULL                                      0x00002010
#define VMCS_TSC_OFFSET_HIGH                                      0x00002011
#define VMCS_VIRTUAL_APIC_ADDRESS_FULL                            0x00002012
#define VMCS_VIRTUAL_APIC_ADDRESS_HIGH                            0x00002013
#define VMCS_APIC_ACCESS_ADDRESS_FULL                             0x00002014
#define VMCS_APIC_ACCESS_ADDRESS_HIGH                             0x00002015
#define VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL             0x00002016
#define VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_HIGH             0x00002017
#define VMCS_VM_FUNCTION_CONTROLS_FULL                            0x00002018
#define VMCS_VM_FUNCTION_CONTROLS_HIGH                            0x00002019
#define VMCS_EPT_POINTER_FULL                                     0x0000201A
#define VMCS_EPT_POINTER_HIGH                                     0x0000201B
#define VMCS_EOI_EXIT_BITMAP_0_FULL                               0x0000201C
#define VMCS_EOI_EXIT_BITMAP_0_HIGH                               0x0000201D
#define VMCS_EOI_EXIT_BITMAP_1_FULL                               0x0000201E
#define VMCS_EOI_EXIT_BITMAP_1_HIGH                               0x0000201F
#define VMCS_EOI_EXIT_BITMAP_2_FULL                               0x00002020
#define VMCS_EOI_EXIT_BITMAP_2_HIGH                               0x00002021
#define VMCS_EOI_EXIT_BITMAP_3_FULL                               0x00002022
#define VMCS_EOI_EXIT_BITMAP_3_HIGH                               0x00002023
#define VMCS_EPTP_LIST_ADDRESS_FULL                               0x00002024
#define VMCS_EPTP_LIST_ADDRESS_HIGH                               0x00002025
#define VMCS_VMREAD_BITMAP_ADDRESS_FULL                           0x00002026
#define VMCS_VMREAD_BITMAP_ADDRESS_HIGH                           0x00002027
#define VMCS_VMWRITE_BITMAP_ADDRESS_FULL                          0x00002028
#define VMCS_VMWRITE_BITMAP_ADDRESS_HIGH                          0x00002029
#define VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL    0x0000202A
#define VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_HIGH    0x0000202B
#define VMCS_XSS_EXITING_BITMAP_FULL                              0x0000202C
#define VMCS_XSS_EXITING_BITMAP_HIGH                              0x0000202D

// 64bit Read-Only Data Fields
#define VMCS_GUEST_PHYSICAL_ADDRESS_FULL                          0x00002400
#define VMCS_GUEST_PHYSICAL_ADDRESS_HIGH                          0x00002401

// 64bit Guest State Fields
#define VMCS_VMCS_LINK_POINTER_FULL                               0x00002800
#define VMCS_VMCS_LINK_POINTER_HIGH                               0x00002801
#define VMCS_GUEST_IA32_DEBUGCTL_FULL                             0x00002802
#define VMCS_GUEST_IA32_DEBUGCTL_HIGH                             0x00002803
#define VMCS_GUEST_IA32_PAT_FULL                                  0x00002804
#define VMCS_GUEST_IA32_PAT_HIGH                                  0x00002805
#define VMCS_GUEST_IA32_EFER_FULL                                 0x00002806
#define VMCS_GUEST_IA32_EFER_HIGH                                 0x00002807
#define VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL                     0x00002808
#define VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_HIGH                     0x00002809
#define VMCS_GUEST_PDPTE0_FULL                                    0x0000280A
#define VMCS_GUEST_PDPTE0_HIGH                                    0x0000280B
#define VMCS_GUEST_PDPTE1_FULL                                    0x0000280C
#define VMCS_GUEST_PDPTE1_HIGH                                    0x0000280D
#define VMCS_GUEST_PDPTE2_FULL                                    0x0000280E
#define VMCS_GUEST_PDPTE2_HIGH                                    0x0000280F
#define VMCS_GUEST_PDPTE3_FULL                                    0x00002810
#define VMCS_GUEST_PDPTE3_HIGH                                    0x00002811

// 64bit Host State Fields
#define VMCS_HOST_IA32_PAT_FULL                                   0x00002C00
#define VMCS_HOST_IA32_PAT_HIGH                                   0x00002C01
#define VMCS_HOST_IA32_EFER_FULL                                  0x00002C02
#define VMCS_HOST_IA32_EFER_HIGH                                  0x00002C03
#define VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL                      0x00002C04
#define VMCS_HOST_IA32_PERF_GLOBAL_CTRL_HIGH                      0x00002C05

// 32bit Control Fields
#define VMCS_PIN_BASED_VM_EXECUTION_CONTROLS                      0x00004000
#define VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS        0x00004002
#define VMCS_EXCEPTION_BITMAP                                     0x00004004
#define VMCS_PAGE_FAULT_ERROR_CODE_MASK                           0x00004006
#define VMCS_PAGE_FAULT_ERROR_CODE_MATCH                          0x00004008
#define VMCS_CR3_TARGET_COUNT                                     0x0000400A
#define VMCS_VM_EXIT_CONTROLS                                     0x0000400C
#define VMCS_VM_EXIT_MSR_STORE_COUNT                              0x0000400E
#define VMCS_VM_EXIT_MSR_LOAD_COUNT                               0x00004010
#define VMCS_VM_ENTRY_CONTROLS                                    0x00004012
#define VMCS_VM_ENTRY_MSR_LOAD_COUNT                              0x00004014
#define VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD              0x00004016
#define VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE                        0x00004018
#define VMCS_VM_ENTRY_INSTRUCTION_LENGTH                          0x0000401A
#define VMCS_TPR_THRESHOLD                                        0x0000401C
#define VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS      0x0000401E
#define VMCS_PLE_GAP                                              0x00004020
#define VMCS_PLE_WINDOW                                           0x00004022

// 32bit Read-Only Fields
#define VMCS_VM_INSTRUCTION_ERROR                                 0x00004400
#define VMCS_EXIT_REASON                                          0x00004402
#define VMCS_VM_EXIT_INTERRUPTION_INFORMATION                     0x00004404
#define VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE                      0x00004406
#define VMCS_IDT_VECTORING_INFORMATION_FIELD                      0x00004408
#define VMCS_IDT_VECTORING_ERROR_CODE                             0x0000440A
#define VMCS_VM_EXIT_INSTRUCTION_LENGTH                           0x0000440C
#define VMCS_VM_EXIT_INSTRUCTION_INFORMATION                      0x0000440E

// 32bit Guest State Fields
#define VMCS_GUEST_ES_LIMIT                                       0x00004800
#define VMCS_GUEST_CS_LIMIT                                       0x00004802
#define VMCS_GUEST_SS_LIMIT                                       0x00004804
#define VMCS_GUEST_DS_LIMIT                                       0x00004806
#define VMCS_GUEST_FS_LIMIT                                       0x00004808
#define VMCS_GUEST_GS_LIMIT                                       0x0000480A
#define VMCS_GUEST_LDTR_LIMIT                                     0x0000480C
#define VMCS_GUEST_TR_LIMIT                                       0x0000480E
#define VMCS_GUEST_GDTR_LIMIT                                     0x00004810
#define VMCS_GUEST_IDTR_LIMIT                                     0x00004812
#define VMCS_GUEST_ES_ACCESS_RIGHTS                               0x00004814
#define VMCS_GUEST_CS_ACCESS_RIGHTS                               0x00004816
#define VMCS_GUEST_SS_ACCESS_RIGHTS                               0x00004818
#define VMCS_GUEST_DS_ACCESS_RIGHTS                               0x0000481A
#define VMCS_GUEST_FS_ACCESS_RIGHTS                               0x0000481C
#define VMCS_GUEST_GS_ACCESS_RIGHTS                               0x0000481E
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS                             0x00004820
#define VMCS_GUEST_TR_ACCESS_RIGHTS                               0x00004822
#define VMCS_GUEST_INTERRUPTIBILITY_STATE                         0x00004824
#define VMCS_GUEST_ACTIVITY_STATE                                 0x00004826
#define VMCS_GUEST_SMBASE                                         0x00004828
#define VMCS_GUEST_IA32_SYSENTER_CS                               0x0000482A
#define VMCS_VMX_PREEMPTION_TIMER_VALUE                           0x0000482E

// 32bit Host State Fields
#define VMCS_HOST_IA32_SYSENTER_CS                                0x00004C00

// Natural Width Control Fields
#define VMCS_CR0_GUEST_HOST_MASK                                  0x00006000
#define VMCS_CR4_GUEST_HOST_MASK                                  0x00006002
#define VMCS_CR0_READ_SHADOW                                      0x00006004
#define VMCS_CR4_READ_SHADOW                                      0x00006006
#define VMCS_CR3_TARGET_VALUE_0                                   0x00006008
#define VMCS_CR3_TARGET_VALUE_1                                   0x0000600A
#define VMCS_CR3_TARGET_VALUE_2                                   0x0000600C
#define VMCS_CR3_TARGET_VALUE_31                                  0x0000600E

// Natural Width Read-Only Fields
#define VMCS_EXIT_QUALIFICATION                                   0x00006400
#define VMCS_IO_RCX                                               0x00006402
#define VMCS_IO_RSI                                               0x00006404
#define VMCS_IO_RDI                                               0x00006406
#define VMCS_IO_RIP                                               0x00006408
#define VMCS_GUEST_LINEAR_ADDRESS                                 0x0000640A

// Natural Width Guest State Fields
#define VMCS_GUEST_CR0                                            0x00006800
#define VMCS_GUEST_CR3                                            0x00006802
#define VMCS_GUEST_CR4                                            0x00006804
#define VMCS_GUEST_ES_BASE                                        0x00006806
#define VMCS_GUEST_CS_BASE                                        0x00006808
#define VMCS_GUEST_SS_BASE                                        0x0000680A
#define VMCS_GUEST_DS_BASE                                        0x0000680C
#define VMCS_GUEST_FS_BASE                                        0x0000680E
#define VMCS_GUEST_GS_BASE                                        0x00006810
#define VMCS_GUEST_LDTR_BASE                                      0x00006812
#define VMCS_GUEST_TR_BASE                                        0x00006814
#define VMCS_GUEST_GDTR_BASE                                      0x00006816
#define VMCS_GUEST_IDTR_BASE                                      0x00006818
#define VMCS_GUEST_DR7                                            0x0000681A
#define VMCS_GUEST_RSP                                            0x0000681C
#define VMCS_GUEST_RIP                                            0x0000681E
#define VMCS_GUEST_RFLAGS                                         0x00006820
#define VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS                       0x00006822
#define VMCS_GUEST_IA32_SYSENTER_ESP                              0x00006824
#define VMCS_GUEST_IA32_SYSENTER_EIP                              0x00006826

// Natural Width Host State Fields
#define VMCS_HOST_CR0                                             0x00006C00
#define VMCS_HOST_CR3                                             0x00006C02
#define VMCS_HOST_CR4                                             0x00006C04
#define VMCS_HOST_FS_BASE                                         0x00006C06
#define VMCS_HOST_GS_BASE                                         0x00006C08
#define VMCS_HOST_TR_BASE                                         0x00006C0A
#define VMCS_HOST_GDTR_BASE                                       0x00006C0C
#define VMCS_HOST_IDTR_BASE                                       0x00006C0E
#define VMCS_HOST_IA32_SYSENTER_ESP                               0x00006C10
#define VMCS_HOST_IA32_SYSENTER_EIP                               0x00006C12
#define VMCS_HOST_RSP                                             0x00006C14
#define VMCS_HOST_RIP                                             0x00006C16

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

// Miscellaneous Data
// intel's software developer's manual, volume 3, appendix A.6
#define IA32_VMX_MISC_INJECTION_WITH_INSTR_LENGTH_0        0x0000000040000000
#endif
