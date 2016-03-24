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

void __halt(void);
void __stop(void);

uint32_t __cpuid_eax(uint32_t val);
uint32_t __cpuid_ebx(uint32_t val);
uint32_t __cpuid_ecx(uint32_t val);
uint32_t __cpuid_edx(uint32_t val);

void __cpuid(uint64_t *rax,
             uint64_t *rbx,
             uint64_t *rcx,
             uint64_t *rdx);

uint64_t __read_rflags(void);

uint64_t __read_msr(uint32_t msr);
uint32_t __read_msr32(uint32_t msr);
void __write_msr(uint32_t msr, uint64_t val);

uint64_t __read_rip(void);

uint64_t __read_cr0(void);
void __write_cr0(uint64_t val);

uint64_t __read_cr3(void);
void __write_cr3(uint64_t val);

uint64_t __read_cr4(void);
void __write_cr4(uint64_t val);

uint64_t __read_dr7(void);
void __write_dr7(uint64_t val);

uint16_t __read_es(void);
void __write_es(uint16_t val);

uint16_t __read_cs(void);
void __write_cs(uint16_t val);

uint16_t __read_ss(void);
void __write_ss(uint16_t val);

uint16_t __read_ds(void);
void __write_ds(uint16_t val);

uint16_t __read_fs(void);
void __write_fs(uint16_t val);

uint16_t __read_gs(void);
void __write_gs(uint16_t val);

uint16_t __read_tr(void);
void __write_tr(uint16_t val);

uint16_t __read_ldtr(void);
void __write_ldtr(uint16_t val);

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

void __read_gdt(gdt_t *gdt);
void __read_idt(idt_t *idt);
void __write_gdt(gdt_t *gdt);
void __write_idt(idt_t *idt);

void __outb(uint16_t val, uint16_t port);
void __outw(uint16_t val, uint16_t port);

uint8_t __inb(uint16_t port);
uint16_t __inw(uint16_t port);

uint32_t __load_segment_limit(uint16_t selector);

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

    virtual void halt()
    { __halt(); }

    virtual void stop()
    { __stop(); }

    virtual uint32_t cpuid_eax(uint32_t val)
    { return __cpuid_eax(val); }

    virtual uint32_t cpuid_ebx(uint32_t val)
    { return __cpuid_ebx(val); }

    virtual uint32_t cpuid_ecx(uint32_t val)
    { return __cpuid_ecx(val); }

    virtual uint32_t cpuid_edx(uint32_t val)
    { return __cpuid_edx(val); }

    virtual void cpuid(uint64_t *rax,
                       uint64_t *rbx,
                       uint64_t *rcx,
                       uint64_t *rdx)
    { __cpuid(rax, rbx, rcx, rdx); }

    virtual uint64_t read_rflags()
    { return __read_rflags(); }

    virtual uint64_t read_msr(uint32_t msr)
    { return __read_msr(msr); }

    virtual uint32_t read_msr32(uint32_t msr)
    { return __read_msr32(msr); }

    virtual void write_msr(uint32_t msr, uint64_t val)
    { __write_msr(msr, val); }

    virtual uint64_t read_rip()
    { return __read_rip(); }

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

    virtual uint64_t read_dr7()
    { return __read_dr7(); }

    virtual void write_dr7(uint64_t val)
    { __write_dr7(val); }

    virtual uint16_t read_es()
    { return __read_es(); }

    virtual void write_es(uint16_t val)
    { __write_es(val); }

    virtual uint16_t read_cs()
    { return __read_cs(); }

    virtual void write_cs(uint16_t val)
    { __write_cs(val); }

    virtual uint16_t read_ss()
    { return __read_ss(); }

    virtual void write_ss(uint16_t val)
    { __write_ss(val); }

    virtual uint16_t read_ds()
    { return __read_ds(); }

    virtual void write_ds(uint16_t val)
    { __write_ds(val); }

    virtual uint16_t read_fs()
    { return __read_fs(); }

    virtual void write_fs(uint16_t val)
    { __write_fs(val); }

    virtual uint16_t read_gs()
    { return __read_gs(); }

    virtual void write_gs(uint16_t val)
    { __write_gs(val); }

    virtual uint16_t read_tr()
    { return __read_tr(); }

    virtual void write_tr(uint16_t val)
    { __write_tr(val); }

    virtual uint16_t read_ldtr()
    { return __read_ldtr(); }

    virtual void write_ldtr(uint16_t val)
    { return __write_ldtr(val); }

    virtual uint64_t read_rsp()
    { return __read_rsp(); }

    virtual void read_gdt(gdt_t *gdt)
    { __read_gdt(gdt); }

    virtual void write_gdt(gdt_t *gdt)
    { __write_gdt(gdt); }

    virtual void read_idt(idt_t *idt)
    { __read_idt(idt); }

    virtual void write_idt(idt_t *idt)
    { __write_idt(idt); }

    virtual void write_portio_8(uint16_t port, uint8_t value)
    { __outb(value, port); }

    virtual void write_portio_16(uint16_t port, uint16_t value)
    { __outw(value, port); }

    virtual uint8_t read_portio_8(uint16_t port)
    { return __inb(port); }

    virtual uint16_t read_portio_16(uint16_t port)
    { return __inw(port); }

    virtual uint32_t load_segment_limit(uint16_t selector)
    { return __load_segment_limit(selector); }

    uint64_t
    segment_descriptor(uint16_t selector)
    {
        gdt_t gdt_reg;
        read_gdt(&gdt_reg);

        // Intel defines a null selector as a selector = 0. Basically, the
        // first entry in the GDT is not used, and the processor views the
        // 0 index as a "null selector". In 32bit mode, this would cause a
        // GP fault if you attempted to use this type of selector. In 64bit
        // mode, most of the selectors are null.
        if (selector == 0)
            return 0;

        // The global descriptor table is a table of segement descriptors.
        // The decriptors can take on different forms, and their definition
        // is in the intel's software developer's manual, volume 3, chapter
        // 3.5. In 64bit mode, code / data segments are still 32bits, while
        // TSS descriptors (defined in chapter 7.2.3), states that a
        // TSS descriptor is actually 16 bytes long, as more space is needed
        // for the 64bit base address.In general, even though there are
        // different types of descriptors, they all take on a similar form,
        // which is best described in chapter 3.4.5.
        uint64_t *gdt = (uint64_t *)gdt_reg.base;

        // Each selector is 16bits, with bit 1-0 indicating the requested
        // privilege level (RPL) and bit 2 indicating the table indicator (TI).
        // The index into the GDT is the remaining bits, thus, to get to the
        // index we remove the RPL and TI bit.
        selector = (selector >> 3);

        // Finally, return the 8-byte segment descriptor
        return gdt[selector];
    }

    uint32_t
    segment_descriptor_limit(uint16_t selector)
    {
        // The segment limit description can be found in the intel's software
        // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
        // chapter 24.4.1.
        //
        // ------------------------------------------------------------------
        // |               | Limit 19-16 |                                  |
        // ------------------------------------------------------------------
        // |                             |            Limit 15-00           |
        // ------------------------------------------------------------------
        //
        // Note that for the limit, we use LSL because it translates the limit
        // field for us. If the granularity bit in the segment descriptor is
        // set to 1, the limit is measured in pages, while if the granularity
        // bit is set to 0, it's measured in bytes. a VMCS however only takes
        // bytes, so we return the limit from LSL as it will do this
        // translation for us.

        return load_segment_limit(selector);
    }

    uint64_t
    segment_descriptor_base(uint16_t selector)
    {
        uint64_t sd1 = segment_descriptor(selector);
        uint64_t sd2 = segment_descriptor(selector + (1 << 3));
        uint64_t base_15_00 = ((sd1 & 0x00000000FFFF0000) >> 16);
        uint64_t base_23_16 = ((sd1 & 0x000000FF00000000) >> 16);
        uint64_t base_31_24 = ((sd1 & 0xFF00000000000000) >> 32);
        uint64_t base_63_32 = ((sd2 & 0x00000000FFFFFFFF) << 32);

        // If we have a null selector, we return 0 since this is not a valid
        // selector into the GDT
        if (selector == 0)
            return 0;

        // The segment base description can be found in the intel's software
        // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
        // chapter 24.4.1.
        //
        // Note that in 64bit mode, system descriptors are 16 bytes long
        // instread of the traditional 8 bytes. A system descriptor has the
        // system flag set to 0. Most of the time, this is going to be the
        // TSS descriptor. Even though Intel Tasks don't exist in 64 bit mode,
        // the TSS descriptor is still used, and thus, TR must still be loaded.
        //
        // Note that the selector index starts in bit 3 in the segment
        // selector register, so to add 1 to the register, you are actually
        // adding 0x8, or (1 << 3) to get the next descriptor in the GDT.
        //
        // ------------------------------------------------------------------
        // |                       Base 63-32                               |
        // ------------------------------------------------------------------
        // |   Base 31-24   |                              |   Base 23-16   |
        // ------------------------------------------------------------------
        // |          Base 15-00         |                                  |
        // ------------------------------------------------------------------
        //

        if ((sd1 & 0x100000000000) == 0)
        {
            return base_63_32 | base_31_24 | base_23_16 | base_15_00;
        }
        else
        {
            return base_31_24 | base_23_16 | base_15_00;
        }
    }

    uint32_t
    segment_descriptor_access(uint16_t selector)
    {
        uint64_t sd = segment_descriptor(selector);
        uint64_t access_07_00 = ((sd & 0x0000FF0000000000) >> 40);
        uint64_t access_15_12 = ((sd & 0x00F0000000000000) >> 40);

        // Note that the Intel manual, in chapter 24.4.1, states that there is
        // an extra "usable" bit that we need to account for. Specifically they
        // state: "Bit 16 indicates an unusable segment. Attempts to use such
        // a segment fault except in 64-bit mode. In general, a segment
        // register is unusable if it has been loaded with a null selector."
        //
        if (selector == 0)
            return 0x10000;

        // The segment access description can be found in the intel's software
        // developer's manual, volume 3, chapter 3.4.5 as well as volume 3,
        // chapter 24.4.1.
        //
        // ------------------------------------------------------------------
        // |           | A 15-12 |       |  Access 07-00   |                |
        // ------------------------------------------------------------------
        // |                             |                                  |
        // ------------------------------------------------------------------
        //

        return access_15_12 | access_07_00;
    }
};

// =============================================================================
// Masks
// =============================================================================

// Selector Fields
#define SELECTOR_TI_FLAG                                          (0x0004)
#define SELECTOR_RPL_FLAG                                         (0x0003)
#define SELECTOR_INDEX                                            (0xFFF8)
#define SELECTOR_UNUSABLE                                         (1 << 16)

// Segment Access Rights
#define SEGMENT_ACCESS_RIGHTS_TYPE                                (0x000F)
#define SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR                   (0x0010)
#define SEGMENT_ACCESS_RIGHTS_DPL                                 (0x0060)
#define SEGMENT_ACCESS_RIGHTS_PRESENT                             (0x0080)
#define SEGMENT_ACCESS_RIGHTS_RESERVED                            (0x0F00)
#define SEGMENT_ACCESS_RIGHTS_L                                   (0x2000)
#define SEGMENT_ACCESS_RIGHTS_DB                                  (0x4000)
#define SEGMENT_ACCESS_RIGHTS_GRANULARITY                         (0x8000)

// RFLAGS
// 64-ia-32-architectures-software-developer-manual, section 3.4.3
#define RFLAGS_CF_CARRY_FLAG                                      (1 << 0)
#define RFLAGS_PF_PARITY_FLAG                                     (1 << 2)
#define RFLAGS_AF_AUXILIARY_CARRY_FLAG                            (1 << 4)
#define RFLAGS_ZF_ZERO_FLAG                                       (1 << 6)
#define RFLAGS_SF_SIGN_FLAG                                       (1 << 7)
#define RFLAGS_TF_TRAP_FLAG                                       (1 << 8)
#define RFLAGS_IF_INTERRUPT_ENABLE_FLAG                           (1 << 9)
#define RFLAGS_DF_DIRECTION_FLAG                                  (1 << 10)
#define RFLAGS_OF_OVERFLOW_FLAG                                   (1 << 11)
#define RFLAGS_IOPL_PRIVILEGE_LEVEL                               (3 << 12)
#define RFLAGS_NT_NESTED_TASK                                     (1 << 14)
#define RFLAGS_RF_RESUME_FLAG                                     (1 << 16)
#define RFLAGS_VM_VIRTUAL_8086_MODE                               (1 << 17)
#define RFLAGS_AC_ALIGNMENT_CHECK_ACCESS_CONTROL                  (1 << 18)
#define RFLAGS_VIF_VIRTUAL_INTERUPT_FLAG                          (1 << 19)
#define RFLAGS_VIP_VIRTUAL_INTERUPT_PENDING                       (1 << 20)
#define RFLAGS_ID_ID_FLAG                                         (1 << 21)

// CR0
// 64-ia-32-architectures-software-developer-manual, section 2.5
#define CRO_PE_PROTECTION_ENABLE                                  (1 << 0)
#define CR0_MP_MONITOR_COPROCESSOR                                (1 << 1)
#define CR0_EM_EMULATION                                          (1 << 2)
#define CR0_TS_TASK_SWITCHED                                      (1 << 3)
#define CR0_ET_EXTENSION_TYPE                                     (1 << 4)
#define CR0_NE_NUMERIC_ERROR                                      (1 << 5)
#define CR0_WP_WRITE_PROTECT                                      (1 << 16)
#define CR0_AM_ALIGNMENT_MASK                                     (1 << 18)
#define CR0_NW_NOT_WRITE_THROUGH                                  (1 << 29)
#define CR0_CD_CACHE_DISABLE                                      (1 << 30)
#define CR0_PG_PAGING                                             (1 << 31)

// CR4
// 64-ia-32-architectures-software-developer-manual, section 2.5
#define CR4_VME_VIRTUAL8086_MODE_EXTENSIONS                       (1 << 0)
#define CR4_PVI_PROTECTED_MODE_VIRTUAL_INTERRUPTS                 (1 << 1)
#define CR4_TSD_TIME_STAMP_DISABLE                                (1 << 2)
#define CR4_DE_DEBUGGING_EXTENSIONS                               (1 << 3)
#define CR4_PSE_PAGE_SIZE_EXTENSIONS                              (1 << 4)
#define CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS                       (1 << 5)
#define CR4_MACHINE_CHECK_ENABLE                                  (1 << 6)
#define CR4_PGE_PAGE_GLOBAL_ENABLE                                (1 << 7)
#define CR4_PCE_PERFORMANCE_MONITOR_COUNTER_ENABLE                (1 << 8)
#define CR4_OSFXSR                                                (1 << 9)
#define CR4_OSXMMEXCPT                                            (1 << 10)
#define CR4_VMXE_VMX_ENABLE_BIT                                   (1 << 13)
#define CR4_SMXE_SMX_ENABLE_BIT                                   (1 << 14)
#define CR4_FSGSBASE_ENABLE_BIT                                   (1 << 16)
#define CR4_PCIDE_PCID_ENABLE_BIT                                 (1 << 17)
#define CR4_OSXSAVE                                               (1 << 18)
#define CR4_SMEP_SMEP_ENABLE_BIT                                  (1 << 20)
#define CR4_SMAP_SMAP_ENABLE_BIT                                  (1 << 21)
#define CR4_PKE_PROTECTION_KEY_ENABLE_BIT                         (1 << 22)

// 64-ia-32-architectures-software-developer-manual, section 35.1
// IA-32 Architectural MSRs
#define IA32_DEBUGCTL_MSR                                         0x000001D9
#define IA32_SYSENTER_CS_MSR                                      0x00000174
#define IA32_SYSENTER_ESP_MSR                                     0x00000175
#define IA32_SYSENTER_EIP_MSR                                     0x00000176
#define IA32_PAT_MSR                                              0x00000277
#define IA32_EFER_MSR                                             0xC0000080
#define IA32_FS_BASE_MSR                                          0xC0000100
#define IA32_GS_BASE_MSR                                          0xC0000101

// 64-ia-32-architectures-software-developer-manual, section 6.3.1
// IA-32 Interrupts and Exceptions
#define INTERRUPT_DIVIDE_ERROR                                        (0)
#define INTERRUPT_DEBUG_EXCEPTION                                     (1)
#define INTERRUPT_NMI_INTERRUPT                                       (2)
#define INTERRUPT_BREAKPOINT                                          (3)
#define INTERRUPT_OVERFLOW                                            (4)
#define INTERRUPT_BOUND_RANGE_EXCEEDED                                (5)
#define INTERRUPT_INVALID_OPCODE                                      (6)
#define INTERRUPT_DEVICE_NOT_AVAILABLE                                (7)
#define INTERRUPT_DOUBLE_FAULT                                        (8)
#define INTERRUPT_COPROCESSOR_SEGMENT_OVERRUN                         (9)
#define INTERRUPT_INVALID_TSS                                         (10)
#define INTERRUPT_SEGMENT_NOT_PRESENT                                 (11)
#define INTERRUPT_STACK_SEGMENT_FAULT                                 (12)
#define INTERRUPT_GENERAL_PROTECTION                                  (13)
#define INTERRUPT_PAGE_FAULT                                          (14)
#define INTERRUPT_FLOATING_POINT_ERROR                                (16)
#define INTERRUPT_ALIGNMENT_CHECK                                     (17)
#define INTERRUPT_MACHINE_CHECK                                       (18)
#define INTERRUPT_SIMD_FLOATING_POINT_EXCEPTION                       (19)
#define INTERRUPT_VIRTUALIZATION_EXCEPTION                            (20)

// Debug Control
// 64-ia-32-architectures-software-developer-manual, section 35.1
#define IA32_DEBUGCTL_LBR                                             (1 << 0)
#define IA32_DEBUGCTL_BTF                                             (1 << 1)
#define IA32_DEBUGCTL_TR                                              (1 << 6)
#define IA32_DEBUGCTL_BTS                                             (1 << 7)
#define IA32_DEBUGCTL_BTINT                                           (1 << 8)
#define IA32_DEBUGCTL_BTS_OFF_OS                                      (1 << 9)
#define IA32_DEBUGCTL_BTS_OFF_USER                                    (1 << 10)
#define IA32_DEBUGCTL_FREEZE_LBRS_ON_PMI                              (1 << 11)
#define IA32_DEBUGCTL_FREEZE_PERFMON_ON_PMI                           (1 << 12)
#define IA32_DEBUGCTL_ENABLE_UNCORE_PMI                               (1 << 13)
#define IA32_DEBUGCTL_FREEZE_WHILE_SMM                                (1 << 14)
#define IA32_DEBUGCTL_RTM_DEBUG                                       (1 << 15)

// EFER
// 64-ia-32-architectures-software-developer-manual, section 35.1
#define IA32_EFER_SCE                                                 (1 << 0)
#define IA32_EFER_LME                                                 (1 << 8)
#define IA32_EFER_LMA                                                 (1 << 10)
#define IA32_EFER_NXE                                                 (1 << 11)

#endif
