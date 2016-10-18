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
};

#endif
