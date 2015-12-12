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

#ifndef INTRINSICS_X64_H
#define INTRINSICS_X64_H

#include <stdint.h>
#include <intrinsics/intrinsics.h>

// =============================================================================
// Intrinsics
// =============================================================================

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

uint32_t __cpuid_eax(uint32_t val);
uint32_t __cpuid_ebx(uint32_t val);
uint32_t __cpuid_ecx(uint32_t val);
uint32_t __cpuid_edx(uint32_t val);

uint64_t __read_rflags(void);

uint64_t __read_msr(uint32_t msr);
uint32_t __read_msr32(uint32_t msr);
void __write_msr(uint32_t msr, uint64_t val);

uint64_t __read_cr0(void);
void __write_cr0(uint64_t val);

uint64_t __read_cr3(void);
void __write_cr3(uint64_t val);

uint64_t __read_cr4(void);
void __write_cr4(uint64_t val);

uint16_t __read_es(void);
uint16_t __read_cs(void);
uint16_t __read_ss(void);
uint16_t __read_ds(void);
uint16_t __read_fs(void);
uint16_t __read_gs(void);
uint16_t __read_tr(void);
uint16_t __read_ldtr(void);
uint64_t __read_rsp(void);

struct gdt_t
{
    uint64_t limit : 16;
    uint64_t base  : 64;
};

struct idt_t
{
    uint64_t limit : 16;
    uint64_t base  : 64;
};

struct segment_descriptor_t
{
    uint64_t limit_15_00         : 16;
    uint64_t base_15_00          : 16;
    uint64_t base_23_16          : 8;
    uint64_t access_rights_07_00 : 8;
    uint64_t limit_19_16         : 4;
    uint64_t access_rights_15_12 : 4;
    uint64_t base_31_24          : 8;
};

#define SEGMENT_DESCRIPTOR_LIMIT(a) ((a.limit_19_16 << 16) | \
                                     (a.limit_15_00 << 0))
#define SEGMENT_DESCRIPTOR_BASE(a) ((a.base_31_24 << 24) | \
                                    (a.base_23_16 << 16) | \
                                    (a.base_15_00 << 0))
#define SEGMENT_DESCRIPTOR_ACCESS(a) ((a.access_rights_15_12 << 12) | \
                                      (a.access_rights_07_00 << 0))

void __read_gdt(gdt_t *gdt);
void __read_idt(idt_t *idt);

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

// =============================================================================
// C++ Wrapper
// =============================================================================

class intrinsics_x64 : public intrinsics
{
public:

    intrinsics_x64() {}
    virtual ~intrinsics_x64() {}

    virtual uint32_t cpuid_eax(uint32_t val)
    { return __cpuid_eax(val); }

    virtual uint32_t cpuid_ebx(uint32_t val)
    { return __cpuid_ebx(val); }

    virtual uint32_t cpuid_ecx(uint32_t val)
    { return __cpuid_ecx(val); }

    virtual uint32_t cpuid_edx(uint32_t val)
    { return __cpuid_edx(val); }

    virtual uint64_t read_rflags(void)
    { return __read_rflags(); }

    virtual uint64_t read_msr(uint32_t msr)
    { return __read_msr(msr); }

    virtual uint32_t read_msr32(uint32_t msr)
    { return __read_msr32(msr); }

    virtual void write_msr(uint32_t msr, uint64_t val)
    { __write_msr(msr, val); }

    virtual uint64_t read_cr0()
    { return __read_cr0(); }

    virtual void write_cr0(uint64_t val)
    { __write_cr0(val); }

    virtual uint64_t read_cr3()
    { return __read_cr3(); }

    virtual void write_cr3(uint64_t val)
    { __write_cr3(val); }

    virtual uint64_t read_cr4()
    { return __read_cr4(); }

    virtual void write_cr4(uint64_t val)
    { __write_cr4(val); }

    virtual uint16_t read_es()
    { return __read_es(); }

    virtual uint16_t read_cs()
    { return __read_cs(); }

    virtual uint16_t read_ss()
    { return __read_ss(); }

    virtual uint16_t read_ds()
    { return __read_ds(); }

    virtual uint16_t read_fs()
    { return __read_fs(); }

    virtual uint16_t read_gs()
    { return __read_gs(); }

    virtual uint16_t read_tr()
    { return __read_tr(); }

    virtual uint16_t read_ldtr()
    { return __read_ldtr(); }

    virtual uint64_t read_rsp()
    { return __read_rsp(); }

    virtual void read_gdt(gdt_t *gdt)
    { __read_gdt(gdt); }

    virtual void read_idt(idt_t *idt)
    { __read_idt(idt); }
};

// =============================================================================
// Masks
// =============================================================================

// RFLAGS
// 64-ia-32-architectures-software-developer-manual, section 3.4.3
#define RFLAGS_CF_CARRY_FLAG (1 << 0)
#define RFLAGS_PF_PARITY_FLAG (1 << 2)
#define RFLAGS_AF_AUXILIARY_CARRY_FLAG (1 << 4)
#define RFLAGS_ZF_ZERO_FLAG (1 << 6)
#define RFLAGS_SF_SIGN_FLAG (1 << 7)
#define RFLAGS_TF_TRAP_FLAG (1 << 8)
#define RFLAGS_IF_INTERRUPT_ENABLE_FLAG (1 << 9)
#define RFLAGS_DF_DIRECTION_FLAG (1 << 10)
#define RFLAGS_OF_OVERFLOW_FLAG (1 << 11)
#define RFLAGS_IOPL_PRIVILEGE_LEVEL (2 << 12)
#define RFLAGS_NT_NESTED_TASK (1 << 14)
#define RFLAGS_RF_RESUME_FLAG (1 << 16)
#define RFLAGS_VM_VIRTUAL_8086_MODE (1 << 17)
#define RFLAGS_AC_ALIGNMENT_CHECK_ACCESS_CONTROL (1 << 18)
#define RFLAGS_VIF_VIRTUAL_INTERUPT_FLAG (1 << 19)
#define RFLAGS_VIP_VIRTUAL_INTERUPT_PENDING (1 << 20)
#define RFLAGS_ID_ID_FLAG (1 << 21)

// CR0
// 64-ia-32-architectures-software-developer-manual, section 2.5
#define CRO_PE_PROTECTION_ENABLE (1 << 0)
#define CR0_MP_MONITOR_COPROCESSOR (1 << 1)
#define CR0_EM_EMULATION (1 << 2)
#define CR0_TS_TASK_SWITCHED (1 << 3)
#define CR0_ET_EXTENSION_TYPE (1 << 4)
#define CR0_NE_NUMERIC_ERROR (1 << 5)
#define CR0_WP_WRITE_PROTECT (1 << 16)
#define CR0_AM_ALIGNMENT_MASK (1 << 18)
#define CR0_NW_NOT_WRITE_THROUGH (1 << 29)
#define CR0_CD_CACHE_DISABLE (1 << 30)
#define CR0_PG_PAGING (1 << 31)

// CR4
// 64-ia-32-architectures-software-developer-manual, section 2.5
#define CR4_VME_VIRTUAL8086_MODE_EXTENSIONS (1 << 0)
#define CR4_PVI_PROTECTED_MODE_VIRTUAL_INTERRUPTS (1 << 1)
#define CR4_TSD_TIME_STAMP_DISABLE (1 << 2)
#define CR4_DE_DEBUGGING_EXTENSIONS (1 << 3)
#define CR4_PSE_PAGE_SIZE_EXTENSIONS (1 << 4)
#define CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS (1 << 5)
#define CR4_MACHINE_CHECK_ENABLE (1 << 6)
#define CR4_PGE_PAGE_GLOBAL_ENABLE (1 << 7)
#define CR4_PCE_PERFORMANCE_MONITOR_COUNTER_ENABLE (1 << 8)
#define CR4_OSFXSR (1 << 9)
#define CR4_OSXMMEXCPT (1 << 10)
#define CR4_VMXE_VMX_ENABLE_BIT (1 << 13)
#define CR4_SMXE_SMX_ENABLE_BIT (1 << 14)
#define CR4_FSGSBASE_FSGSBASE_ENABLE_BIT (1 << 16)
#define CR4_PCIDE_PCID_ENABLE_BIT (1 << 17)
#define CR4_OSXSAVE (1 << 18)
#define CR4_SMEP_SMEP_ENABLE_BIT (1 << 20)
#define CR4_SMAP_SMAP_ENABLE_BIT (1 << 21)
#define CR4_PKE_PROTECTION_KEY_ENABLE_BIT (1 << 22)

// VMX MSRs
// 64-ia-32-architectures-software-developer-manual, appendix A.1
#define IA32_VMX_BASIC_MSR (0x480)
#define IA32_VMX_CR0_FIXED0_MSR (0x486)
#define IA32_VMX_CR0_FIXED1_MSR (0x487)
#define IA32_VMX_CR4_FIXED0_MSR (0x488)
#define IA32_VMX_CR4_FIXED1_MSR (0x489)
#define IA32_FEATURE_CONTROL_MSR (0x3A)
#define IA32_VMX_TRUE_PINBASED_CTLS_MSR (0x48D)
#define IA32_VMX_TRUE_PROCBASED_CTLS_MSR (0x48E)
#define IA32_VMX_TRUE_EXIT_CTLS_MSR (0x48F)
#define IA32_VMX_TRUE_ENTRY_CTLS_MSR (0x490)

// 64-ia-32-architectures-software-developer-manual, section 35.1
// IA-32 Architectural MSRs
#define IA32_DEBUGCTL_MSR (0x1D9)
#define IA32_SYSENTER_CS_MSR (0x174)
#define IA32_SYSENTER_ESP_MSR (0x175)
#define IA32_SYSENTER_EIP_MSR (0x176)

#endif
