/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef INTRINSICS_INTEL_X64_H
#define INTRINSICS_INTEL_X64_H

#include <stdint.h>
#include <intrinsics/intrinsics_x64.h>

// =============================================================================
// Intrinsics
// =============================================================================

#ifdef __cplusplus
extern "C" {
#endif

uint64_t __vmxon(void *vmxon_region);
uint64_t __vmxoff(void);
uint64_t __vmclear(void *vmcs_region);
uint64_t __vmptrld(void *vmcs_region);
uint64_t __vmptrst(void *vmcs_region);
uint64_t __vmwrite(uint64_t field, uint64_t val);
uint64_t __vmread(uint64_t field, uint64_t *val);
uint64_t __vmlaunch(void);

// =============================================================================
// C++ Wrapper
// =============================================================================

#ifdef __cplusplus
}
#endif

class intrinsics_intel_x64 : public intrinsics_x64
{
public:

    intrinsics_intel_x64() {}
    virtual ~intrinsics_intel_x64() {}

    virtual bool vmxon(void *vmxon_region)
    { return __vmxon(vmxon_region); }

    virtual bool vmxoff()
    { return __vmxoff(); }

    virtual bool vmclear(void *vmcs_region)
    { return __vmclear(vmcs_region); }

    virtual bool vmptrld(void *vmcs_region)
    { return __vmptrld(vmcs_region); }

    virtual bool vmptrst(void *vmcs_region)
    { return __vmptrst(vmcs_region); }

    virtual bool vmwrite(uint64_t field, uint64_t val)
    { return __vmwrite(field, val); }

    virtual bool vmread(uint64_t field, uint64_t *val)
    { return __vmread(field, val); }

    virtual bool vmlaunch()
    { return __vmlaunch(); }
};

// =============================================================================
// VMCS Fields
// =============================================================================

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
#define VMCS_I_O_RCX                                              0x00006402
#define VMCS_I_O_RSI                                              0x00006404
#define VMCS_I_O_RDI                                              0x00006406
#define VMCS_I_O_RIP                                              0x00006408
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

#endif
