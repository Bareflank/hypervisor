//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef IDT_X64_H
#define IDT_X64_H

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_INTRINSICS
#ifdef SHARED_INTRINSICS
#define EXPORT_INTRINSICS EXPORT_SYM
#else
#define EXPORT_INTRINSICS IMPORT_SYM
#endif
#else
#define EXPORT_INTRINSICS
#endif

#pragma pack(push, 1)

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" void _read_idt(void *idt_reg) noexcept;
extern "C" void _write_idt(void *idt_reg) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace idt_reg
{

struct reg_t {
    uint16_t limit{0};
    uint64_t base{0};
};

inline auto get() noexcept
{
    reg_t reg;
    _read_idt(&reg);

    return reg;
}

inline void set(uint64_t base, uint16_t limit) noexcept
{
    reg_t reg;

    reg.base = base;
    reg.limit = limit;

    _write_idt(&reg);
}

namespace base
{
    inline auto get() noexcept
    {
        reg_t reg;
        _read_idt(&reg);

        return reg.base;
    }

    inline void set(uint64_t base) noexcept
    {
        reg_t reg;
        _read_idt(&reg);

        reg.base = base;
        _write_idt(&reg);
    }
}

namespace limit
{
    inline auto get() noexcept
    {
        reg_t reg;
        _read_idt(&reg);

        return reg.limit;
    }

    inline void set(uint16_t limit) noexcept
    {
        reg_t reg;
        _read_idt(&reg);

        reg.limit = limit;
        _write_idt(&reg);
    }
}

}
}

// *INDENT-ON*

#pragma pack(pop)

#endif
