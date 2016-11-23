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

#ifndef IDT_X64_H
#define IDT_X64_H

#include <gsl/gsl>

#include <vector>
#include <algorithm>
#include <exception>

#include <guard_exceptions.h>

// -----------------------------------------------------------------------------
// Interrupt Descriptor Table Register
// -----------------------------------------------------------------------------

#pragma pack(push, 1)

struct idt_reg_x64_t
{
    using limit_type = uint16_t;
    using base_type = uint64_t *;

    limit_type limit;
    base_type base;

    idt_reg_x64_t() noexcept :
        limit(0),
        base(nullptr)
    {}

    idt_reg_x64_t(base_type b, limit_type l) noexcept :
        limit(l),
        base(b)
    {}
};

#pragma pack(pop)

// -----------------------------------------------------------------------------
// Intrinsics
// -----------------------------------------------------------------------------

extern "C" void __read_idt(idt_reg_x64_t *idt_reg) noexcept;
extern "C" void __write_idt(idt_reg_x64_t *idt_reg) noexcept;

// -----------------------------------------------------------------------------
// IDT Functions
// -----------------------------------------------------------------------------

// *INDENT-OFF*

namespace x64
{
namespace idt
{
    inline auto get() noexcept
    {
        auto &&reg = idt_reg_x64_t{};
        __read_idt(&reg);

        return reg;
    }

    inline void set(idt_reg_x64_t::base_type base, idt_reg_x64_t::limit_type limit) noexcept
    {
        auto &&reg = idt_reg_x64_t{base, limit};
        __write_idt(&reg);
    }

    namespace base
    {
        inline auto get() noexcept
        {
            auto &&reg = idt_reg_x64_t{};
            __read_idt(&reg);

            return reg.base;
        }

        inline void set(idt_reg_x64_t::base_type base) noexcept
        {
            auto &&reg = idt_reg_x64_t{};
            __read_idt(&reg);

            reg.base = base;
            __write_idt(&reg);
        }
    }

    namespace limit
    {
        inline auto get() noexcept
        {
            auto &&reg = idt_reg_x64_t{};
            __read_idt(&reg);

            return reg.limit;
        }

        inline void set(idt_reg_x64_t::limit_type limit) noexcept
        {
            auto &&reg = idt_reg_x64_t{};
            __read_idt(&reg);

            reg.limit = limit;
            __write_idt(&reg);
        }
    }
}
}
// *INDENT-ON*

// -----------------------------------------------------------------------------
// Interrupt Descriptor Table
// -----------------------------------------------------------------------------

/// Interrupt Descriptor Table
///
/// The interrupt descriptor tables is like the GDT. Each descriptor in
/// 64bit mode is 16 bytes with the upper 64bits containing the upper 32bit
/// offset (like like a TSS descriptor). Unlike the GDT, entry 0 is used,
/// and there "should be" 256 entries, which means it consumes 4k. We left
/// the implementation in a way where you can decide how big you want it, but
/// it really should be 256.
///
/// For more information on the IDT, please see Volume 3, section 6.10
/// of the Intel Manual. For 64bit, see section 6.14.
///
/// @note For now, the IDT is global, and blank as we have interrupts
///     disabled. At some point when we decide to add support for
///     interrupts we will need to implement this class completely.
///
class idt_x64
{
public:

    using size_type = uint16_t;
    using integer_pointer = uintptr_t;
    using interrupt_descriptor_type = uint64_t;

    /// Constructor
    ///
    /// Wraps around the IDT that is currently stored in the hardware.
    ///
    /// @expects none
    /// @ensures none
    ///
    idt_x64() noexcept
    {
        guard_exceptions([&]
        {
            m_idt_reg.base = x64::idt::base::get();
            m_idt_reg.limit = x64::idt::limit::get();
        });
    }

    /// Constructor
    ///
    /// Creates a new IDT, with size defining the number of descriptors
    /// in the IDT.
    ///
    /// @expects size != 0
    /// @ensures none
    ///
    /// @param size number of entries in the IDT
    ///
    idt_x64(size_type size) noexcept :
        m_idt(size)
    {
        guard_exceptions([&]
        {
            m_idt_reg.base = m_idt.data();
            m_idt_reg.limit = gsl::narrow_cast<size_type>((size << 3) - 1);
        });
    }

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~idt_x64() = default;

    /// IDT Base Address
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the base address of the IDT itself.
    ///
    auto base() const
    { return reinterpret_cast<integer_pointer>(m_idt_reg.base); }

    /// IDT Limit
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the size of the IDT itself in bytes
    ///
    auto limit() const
    { return m_idt_reg.limit; }

private:

    friend class intrinsics_ut;

    idt_reg_x64_t m_idt_reg;
    std::vector<interrupt_descriptor_type> m_idt;
};

#endif
