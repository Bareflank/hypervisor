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

#ifndef INTRINSICS_X64_H
#define INTRINSICS_X64_H

#include <stdint.h>

// -----------------------------------------------------------------------------
// Intrinsics
// -----------------------------------------------------------------------------

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

void __halt(void);
void __stop(void);

void __invd(void);
void __wbinvd(void);

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
void __write_msr(uint32_t msr, uint64_t val);

void __read_msr_reg(uint32_t msr, uint32_t *edx, uint32_t *eax);
void __write_msr_reg(uint32_t msr, uint32_t edx, uint32_t eax);

uint64_t __read_rip(void);

uint64_t __read_cr0(void);
void __write_cr0(uint64_t val);

uint64_t __read_cr3(void);
void __write_cr3(uint64_t val);

uint64_t __read_cr4(void);
void __write_cr4(uint64_t val);

uint64_t __read_xcr0(void);
void __write_xcr0(uint64_t val);

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

void __read_gdt(void *gdt);
void __write_gdt(void *gdt);

void __read_idt(void *idt);
void __write_idt(void *idt);

void __outb(uint16_t val, uint16_t port);
void __outw(uint16_t val, uint16_t port);

uint8_t __inb(uint16_t port);
uint16_t __inw(uint16_t port);

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

// -----------------------------------------------------------------------------
// C++ Wrapper
// -----------------------------------------------------------------------------

/// Intrinsics (x64)
///
/// Wraps all of the intrinsics functions that are shared between Intel and
/// AMD 64bit CPUs.
///
class intrinsics_x64
{
public:

    intrinsics_x64() noexcept {}
    virtual ~intrinsics_x64() {}

    virtual void halt() const noexcept
    { __halt(); }

    virtual void stop() const noexcept
    { __stop(); }

    virtual void invd() const noexcept
    { __invd(); }

    virtual void wbinvd() const noexcept
    { __wbinvd(); }

    virtual uint32_t cpuid_eax(uint32_t val) const noexcept
    { return __cpuid_eax(val); }

    virtual uint32_t cpuid_ebx(uint32_t val) const noexcept
    { return __cpuid_ebx(val); }

    virtual uint32_t cpuid_ecx(uint32_t val) const noexcept
    { return __cpuid_ecx(val); }

    virtual uint32_t cpuid_edx(uint32_t val) const noexcept
    { return __cpuid_edx(val); }

    virtual void cpuid(uint64_t *rax,
                       uint64_t *rbx,
                       uint64_t *rcx,
                       uint64_t *rdx) const noexcept
    { __cpuid(rax, rbx, rcx, rdx); }

    virtual uint64_t read_rflags() const noexcept
    { return __read_rflags(); }

    virtual uint64_t read_msr(uint32_t msr) const noexcept
    { return __read_msr(msr); }

    virtual void write_msr(uint32_t msr, uint64_t val) const noexcept
    { __write_msr(msr, val); }

    virtual void read_msr_reg(uint32_t msr, uint32_t *edx, uint32_t *eax)
    { __read_msr_reg(msr, edx, eax); }

    virtual void read_msr_reg(uint32_t msr, uint64_t *edx, uint64_t *eax)
    { __read_msr_reg(msr, (uint32_t *)edx, (uint32_t *)eax); }

    virtual void write_msr_reg(uint32_t msr, uint32_t edx, uint32_t eax)
    { __write_msr_reg(msr, edx, eax); }

    virtual uint64_t read_rip() const noexcept
    { return __read_rip(); }

    virtual uint64_t read_cr0() const noexcept
    { return __read_cr0(); }

    virtual void write_cr0(uint64_t val) const noexcept
    { __write_cr0(val); }

    virtual uint64_t read_cr3() const noexcept
    { return __read_cr3(); }

    virtual void write_cr3(uint64_t val) const noexcept
    { __write_cr3(val); }

    virtual uint64_t read_cr4() const noexcept
    { return __read_cr4(); }

    virtual void write_cr4(uint64_t val) const noexcept
    { __write_cr4(val); }

    virtual uint64_t read_xcr0() const noexcept
    { return __read_xcr0(); }

    virtual void write_xcr0(uint64_t val) const noexcept
    { __write_xcr0(val); }

    virtual uint64_t read_dr7() const noexcept
    { return __read_dr7(); }

    virtual void write_dr7(uint64_t val) const noexcept
    { __write_dr7(val); }

    virtual uint16_t read_es() const noexcept
    { return __read_es(); }

    virtual void write_es(uint16_t val) const noexcept
    { __write_es(val); }

    virtual uint16_t read_cs() const noexcept
    { return __read_cs(); }

    virtual void write_cs(uint16_t val) const noexcept
    { __write_cs(val); }

    virtual uint16_t read_ss() const noexcept
    { return __read_ss(); }

    virtual void write_ss(uint16_t val) const noexcept
    { __write_ss(val); }

    virtual uint16_t read_ds() const noexcept
    { return __read_ds(); }

    virtual void write_ds(uint16_t val) const noexcept
    { __write_ds(val); }

    virtual uint16_t read_fs() const noexcept
    { return __read_fs(); }

    virtual void write_fs(uint16_t val) const noexcept
    { __write_fs(val); }

    virtual uint16_t read_gs() const noexcept
    { return __read_gs(); }

    virtual void write_gs(uint16_t val) const noexcept
    { __write_gs(val); }

    virtual uint16_t read_tr() const noexcept
    { return __read_tr(); }

    virtual void write_tr(uint16_t val) const noexcept
    { __write_tr(val); }

    virtual uint16_t read_ldtr() const noexcept
    { return __read_ldtr(); }

    virtual void write_ldtr(uint16_t val) const noexcept
    { return __write_ldtr(val); }

    virtual uint64_t read_rsp() const noexcept
    { return __read_rsp(); }

    virtual void read_gdt(void *gdt) const noexcept
    { __read_gdt(gdt); }

    virtual void write_gdt(void *gdt) const noexcept
    { __write_gdt(gdt); }

    virtual void read_idt(void *idt) const noexcept
    { __read_idt(idt); }

    virtual void write_idt(void *idt) const noexcept
    { __write_idt(idt); }

    virtual void write_portio_8(uint16_t port, uint8_t value) const noexcept
    { __outb(value, port); }

    virtual void write_portio_16(uint16_t port, uint16_t value) const noexcept
    { __outw(value, port); }

    virtual uint8_t read_portio_8(uint16_t port) const noexcept
    { return __inb(port); }

    virtual uint16_t read_portio_16(uint16_t port) const noexcept
    { return __inw(port); }
};

// -----------------------------------------------------------------------------
// Masks
// -----------------------------------------------------------------------------

// Selector Fields
#define SELECTOR_TI_FLAG                                            (0x0004)
#define SELECTOR_RPL_FLAG                                           (0x0003)
#define SELECTOR_INDEX                                              (0xFFF8)
#define SELECTOR_UNUSABLE                                           (1 << 16)

// Segment Access Rights
#define SEGMENT_ACCESS_RIGHTS_TYPE                                  (0x000F)
#define SEGMENT_ACCESS_RIGHTS_TYPE_TSS_BUSY                         (0x0002)
#define SEGMENT_ACCESS_RIGHTS_TYPE_RW                               (0x0002)
#define SEGMENT_ACCESS_RIGHTS_TYPE_RWA                              (0x0003)
#define SEGMENT_ACCESS_RIGHTS_TYPE_RE                               (0x000A)
#define SEGMENT_ACCESS_RIGHTS_TYPE_REA                              (0x000B)
#define SEGMENT_ACCESS_RIGHTS_TYPE_TSS_AVAILABLE                    (0x0009)
#define SEGMENT_ACCESS_RIGHTS_CODE_DATA_DESCRIPTOR                  (0x0010)
#define SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR                     (0x0010)
#define SEGMENT_ACCESS_RIGHTS_DPL                                   (0x0060)
#define SEGMENT_ACCESS_RIGHTS_PRESENT                               (0x0080)
#define SEGMENT_ACCESS_RIGHTS_RESERVED                              (0x0F00)
#define SEGMENT_ACCESS_RIGHTS_L                                     (0x2000)
#define SEGMENT_ACCESS_RIGHTS_DB                                    (0x4000)
#define SEGMENT_ACCESS_RIGHTS_GRANULARITY                           (0x8000)
#define SEGMENT_ACCESS_RIGHTS_GRANULARITY_PAGES                     (0x8000)

// RFLAGS
// 64-ia-32-architectures-software-developer-manual, section 3.4.3
#define RFLAGS_CF_CARRY_FLAG                                        (1ULL << 0)
#define RFLAGS_PF_PARITY_FLAG                                       (1ULL << 2)
#define RFLAGS_AF_AUXILIARY_CARRY_FLAG                              (1ULL << 4)
#define RFLAGS_ZF_ZERO_FLAG                                         (1ULL << 6)
#define RFLAGS_SF_SIGN_FLAG                                         (1ULL << 7)
#define RFLAGS_TF_TRAP_FLAG                                         (1ULL << 8)
#define RFLAGS_IF_INTERRUPT_ENABLE_FLAG                             (1ULL << 9)
#define RFLAGS_DF_DIRECTION_FLAG                                    (1ULL << 10)
#define RFLAGS_OF_OVERFLOW_FLAG                                     (1ULL << 11)
#define RFLAGS_IOPL_PRIVILEGE_LEVEL                                 (3ULL << 12)
#define RFLAGS_NT_NESTED_TASK                                       (1ULL << 14)
#define RFLAGS_RF_RESUME_FLAG                                       (1ULL << 16)
#define RFLAGS_VM_VIRTUAL_8086_MODE                                 (1ULL << 17)
#define RFLAGS_AC_ALIGNMENT_CHECK_ACCESS_CONTROL                    (1ULL << 18)
#define RFLAGS_VIF_VIRTUAL_INTERUPT_FLAG                            (1ULL << 19)
#define RFLAGS_VIP_VIRTUAL_INTERUPT_PENDING                         (1ULL << 20)
#define RFLAGS_ID_ID_FLAG                                           (1ULL << 21)

// CR0
// 64-ia-32-architectures-software-developer-manual, section 2.5
#define CRO_PE_PROTECTION_ENABLE                                    (1ULL << 0)
#define CR0_MP_MONITOR_COPROCESSOR                                  (1ULL << 1)
#define CR0_EM_EMULATION                                            (1ULL << 2)
#define CR0_TS_TASK_SWITCHED                                        (1ULL << 3)
#define CR0_ET_EXTENSION_TYPE                                       (1ULL << 4)
#define CR0_NE_NUMERIC_ERROR                                        (1ULL << 5)
#define CR0_WP_WRITE_PROTECT                                        (1ULL << 16)
#define CR0_AM_ALIGNMENT_MASK                                       (1ULL << 18)
#define CR0_NW_NOT_WRITE_THROUGH                                    (1ULL << 29)
#define CR0_CD_CACHE_DISABLE                                        (1ULL << 30)
#define CR0_PG_PAGING                                               (1ULL << 31)

// CR4
// 64-ia-32-architectures-software-developer-manual, section 2.5
#define CR4_VME_VIRTUAL8086_MODE_EXTENSIONS                         (1ULL << 0)
#define CR4_PVI_PROTECTED_MODE_VIRTUAL_INTERRUPTS                   (1ULL << 1)
#define CR4_TSD_TIME_STAMP_DISABLE                                  (1ULL << 2)
#define CR4_DE_DEBUGGING_EXTENSIONS                                 (1ULL << 3)
#define CR4_PSE_PAGE_SIZE_EXTENSIONS                                (1ULL << 4)
#define CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS                         (1ULL << 5)
#define CR4_MACHINE_CHECK_ENABLE                                    (1ULL << 6)
#define CR4_PGE_PAGE_GLOBAL_ENABLE                                  (1ULL << 7)
#define CR4_PCE_PERFORMANCE_MONITOR_COUNTER_ENABLE                  (1ULL << 8)
#define CR4_OSFXSR                                                  (1ULL << 9)
#define CR4_OSXMMEXCPT                                              (1ULL << 10)
#define CR4_VMXE_VMX_ENABLE_BIT                                     (1ULL << 13)
#define CR4_SMXE_SMX_ENABLE_BIT                                     (1ULL << 14)
#define CR4_FSGSBASE_ENABLE_BIT                                     (1ULL << 16)
#define CR4_PCIDE_PCID_ENABLE_BIT                                   (1ULL << 17)
#define CR4_OSXSAVE                                                 (1ULL << 18)
#define CR4_SMEP_SMEP_ENABLE_BIT                                    (1ULL << 20)
#define CR4_SMAP_SMAP_ENABLE_BIT                                    (1ULL << 21)
#define CR4_PKE_PROTECTION_KEY_ENABLE_BIT                           (1ULL << 22)

// 64-ia-32-architectures-software-developer-manual, section 35.1
// IA-32 Architectural MSRs
#define IA32_PERF_GLOBAL_CTRL_MSR                                   0x0000038F
#define IA32_DEBUGCTL_MSR                                           0x000001D9
#define IA32_SYSENTER_CS_MSR                                        0x00000174
#define IA32_SYSENTER_ESP_MSR                                       0x00000175
#define IA32_SYSENTER_EIP_MSR                                       0x00000176
#define IA32_PAT_MSR                                                0x00000277
#define IA32_EFER_MSR                                               0xC0000080
#define IA32_FS_BASE_MSR                                            0xC0000100
#define IA32_GS_BASE_MSR                                            0xC0000101
#define IA32_XSS_MSR                                                0x00000DA0

// 64-ia-32-architectures-software-developer-manual, section 6.3.1
// IA-32 Interrupts and Exceptions
#define INTERRUPT_DIVIDE_ERROR                                      (0)
#define INTERRUPT_DEBUG_EXCEPTION                                   (1)
#define INTERRUPT_NMI_INTERRUPT                                     (2)
#define INTERRUPT_BREAKPOINT                                        (3)
#define INTERRUPT_OVERFLOW                                          (4)
#define INTERRUPT_BOUND_RANGE_EXCEEDED                              (5)
#define INTERRUPT_INVALID_OPCODE                                    (6)
#define INTERRUPT_DEVICE_NOT_AVAILABLE                              (7)
#define INTERRUPT_DOUBLE_FAULT                                      (8)
#define INTERRUPT_COPROCESSOR_SEGMENT_OVERRUN                       (9)
#define INTERRUPT_INVALID_TSS                                       (10)
#define INTERRUPT_SEGMENT_NOT_PRESENT                               (11)
#define INTERRUPT_STACK_SEGMENT_FAULT                               (12)
#define INTERRUPT_GENERAL_PROTECTION                                (13)
#define INTERRUPT_PAGE_FAULT                                        (14)
#define INTERRUPT_FLOATING_POINT_ERROR                              (16)
#define INTERRUPT_ALIGNMENT_CHECK                                   (17)
#define INTERRUPT_MACHINE_CHECK                                     (18)
#define INTERRUPT_SIMD_FLOATING_POINT_EXCEPTION                     (19)
#define INTERRUPT_VIRTUALIZATION_EXCEPTION                          (20)

// Debug Control
// 64-ia-32-architectures-software-developer-manual, section 35.1
#define IA32_DEBUGCTL_LBR                                           (1ULL << 0)
#define IA32_DEBUGCTL_BTF                                           (1ULL << 1)
#define IA32_DEBUGCTL_TR                                            (1ULL << 6)
#define IA32_DEBUGCTL_BTS                                           (1ULL << 7)
#define IA32_DEBUGCTL_BTINT                                         (1ULL << 8)
#define IA32_DEBUGCTL_BTS_OFF_OS                                    (1ULL << 9)
#define IA32_DEBUGCTL_BTS_OFF_USER                                  (1ULL << 10)
#define IA32_DEBUGCTL_FREEZE_LBRS_ON_PMI                            (1ULL << 11)
#define IA32_DEBUGCTL_FREEZE_PERFMON_ON_PMI                         (1ULL << 12)
#define IA32_DEBUGCTL_ENABLE_UNCORE_PMI                             (1ULL << 13)
#define IA32_DEBUGCTL_FREEZE_WHILE_SMM                              (1ULL << 14)
#define IA32_DEBUGCTL_RTM_DEBUG                                     (1ULL << 15)

// EFER
// 64-ia-32-architectures-software-developer-manual, section 35.1
#define IA32_EFER_SCE                                               (1ULL << 0)
#define IA32_EFER_LME                                               (1ULL << 8)
#define IA32_EFER_LMA                                               (1ULL << 10)
#define IA32_EFER_NXE                                               (1ULL << 11)

// Serial COM Port Addresses
// http://wiki.osdev.org/Serial_Ports
#define COM1_PORT                                                   0x3f8
#define COM2_PORT                                                   0x2f8
#define COM3_PORT                                                   0x3e8
#define COM4_PORT                                                   0x2e8

#endif
