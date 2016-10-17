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
#include <intrinsics/x64.h>
#include <intrinsics/rflags_x64.h>

// -----------------------------------------------------------------------------
// Intrinsics
// -----------------------------------------------------------------------------

extern "C" void __halt(void) noexcept;
extern "C" void __stop(void) noexcept;

extern "C" void __invd(void) noexcept;
extern "C" void __wbinvd(void) noexcept;

extern "C" uint32_t __cpuid_eax(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_ebx(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_ecx(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_edx(uint32_t val) noexcept;
extern "C" void __cpuid(uint64_t *rax, uint64_t *rbx, uint64_t *rcx, uint64_t *rdx) noexcept;

extern "C" uint64_t __read_dr7(void) noexcept;
extern "C" void __write_dr7(uint64_t val) noexcept;

extern "C" uint16_t __read_es(void) noexcept;
extern "C" void __write_es(uint16_t val) noexcept;

extern "C" uint16_t __read_cs(void) noexcept;
extern "C" void __write_cs(uint16_t val) noexcept;

extern "C" uint16_t __read_ss(void) noexcept;
extern "C" void __write_ss(uint16_t val) noexcept;

extern "C" uint16_t __read_ds(void) noexcept;
extern "C" void __write_ds(uint16_t val) noexcept;

extern "C" uint16_t __read_fs(void) noexcept;
extern "C" void __write_fs(uint16_t val) noexcept;

extern "C" uint16_t __read_gs(void) noexcept;
extern "C" void __write_gs(uint16_t val) noexcept;

extern "C" uint16_t __read_tr(void) noexcept;
extern "C" void __write_tr(uint16_t val) noexcept;

extern "C" uint16_t __read_ldtr(void) noexcept;
extern "C" void __write_ldtr(uint16_t val) noexcept;

extern "C" void __outb(uint16_t port, uint8_t val) noexcept;
extern "C" void __outw(uint16_t port, uint16_t val) noexcept;

extern "C" uint8_t __inb(uint16_t port) noexcept;
extern "C" uint16_t __inw(uint16_t port) noexcept;

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

    intrinsics_x64() noexcept = default;
    virtual ~intrinsics_x64() = default;

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

    virtual void write_portio_8(uint16_t port, uint8_t value) const noexcept
    { __outb(port, value); }

    virtual void write_portio_16(uint16_t port, uint16_t value) const noexcept
    { __outw(port, value); }

    virtual uint8_t read_portio_8(uint16_t port) const noexcept
    { return __inb(port); }

    virtual uint16_t read_portio_16(uint16_t port) const noexcept
    { return __inw(port); }
};

// -----------------------------------------------------------------------------
// Masks
// -----------------------------------------------------------------------------

// Selector Fields
#define SELECTOR_TI_FLAG                                            (0x0004UL)
#define SELECTOR_RPL_FLAG                                           (0x0003UL)
#define SELECTOR_INDEX                                              (0xFFF8)
#define SELECTOR_UNUSABLE                                           (1 << 16)

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

#endif
