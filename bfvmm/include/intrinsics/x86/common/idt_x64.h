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

#include <vector>
#include <algorithm>

#include <bfgsl.h>
#include <bftypes.h>
#include <bfexception.h>
#include <bfupperlower.h>

#include <intrinsics/x86/common/x64.h>

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Interrupt Descriptor Table Register
// -----------------------------------------------------------------------------

#pragma pack(push, 1)

struct EXPORT_INTRINSICS idt_reg_x64_t {
    using limit_type = uint16_t;
    using base_type = uint64_t *;

    limit_type limit{0};
    base_type base{nullptr};

    idt_reg_x64_t() noexcept = default;

    idt_reg_x64_t(base_type b, limit_type l) noexcept :
        limit(l),
        base(b)
    { }
};

#pragma pack(pop)

// -----------------------------------------------------------------------------
// Intrinsics
// -----------------------------------------------------------------------------

extern "C" EXPORT_INTRINSICS void _read_idt(idt_reg_x64_t *idt_reg) noexcept;
extern "C" EXPORT_INTRINSICS void _write_idt(idt_reg_x64_t *idt_reg) noexcept;

// -----------------------------------------------------------------------------
// IDT Functions
// -----------------------------------------------------------------------------

// *INDENT-OFF*

namespace x64
{
namespace idt
{
    using size_type = uint64_t;

    inline auto get() noexcept
    {
        auto reg = idt_reg_x64_t{};
        _read_idt(&reg);

        return reg;
    }

    inline void set(idt_reg_x64_t::base_type base, idt_reg_x64_t::limit_type limit) noexcept
    {
        auto reg = idt_reg_x64_t{base, limit};
        _write_idt(&reg);
    }

    namespace base
    {
        inline auto get() noexcept
        {
            auto reg = idt_reg_x64_t{};
            _read_idt(&reg);

            return reg.base;
        }

        inline void set(idt_reg_x64_t::base_type base) noexcept
        {
            auto reg = idt_reg_x64_t{};
            _read_idt(&reg);

            reg.base = base;
            _write_idt(&reg);
        }
    }

    namespace limit
    {
        inline auto get() noexcept
        {
            auto reg = idt_reg_x64_t{};
            _read_idt(&reg);

            return reg.limit;
        }

        inline void set(idt_reg_x64_t::limit_type limit) noexcept
        {
            auto reg = idt_reg_x64_t{};
            _read_idt(&reg);

            reg.limit = limit;
            _write_idt(&reg);
        }
    }

    inline auto size(size_type bytes)
    {
        if (bfn::lower(bytes) == 0) {
            return bfn::upper(bytes);
        }

        return bfn::upper(bytes) + 1U;
    }
}
}

// *INDENT-ON*

// -----------------------------------------------------------------------------
// Interrupt Descriptor Table
// -----------------------------------------------------------------------------

/// Interrupt Descriptor Table
///
///
class EXPORT_INTRINSICS idt_x64
{
public:

    using pointer = void(*)();
    using size_type = uint16_t;
    using index_type = uint32_t;
    using integer_pointer = uintptr_t;
    using interrupt_descriptor_type = uint64_t;
    using offset_type = uint64_t;
    using selector_type = uint64_t;

    /// Constructor
    ///
    /// Wraps around the IDT that is currently stored in the hardware.
    ///
    /// @expects none
    /// @ensures none
    ///
    idt_x64() noexcept
    {
        guard_exceptions([&] {
            m_idt_reg.base = x64::idt::base::get();
            m_idt_reg.limit = x64::idt::limit::get();

            std::copy_n(m_idt_reg.base, (m_idt_reg.limit + 1) >> 3, std::back_inserter(m_idt));
        });
    }

    /// Constructor
    ///
    /// Creates a new IDT, with size defining the number of descriptors
    /// in the IDT.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param size number of entries in the IDT
    ///
    idt_x64(size_type size) noexcept :
        m_idt(size * 2U)
    {
        guard_exceptions([&] {
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

    /// Set Descriptor Offset
    ///
    /// @expects index < m_idt.size() + 1
    /// @expects offset is canonical
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @param offset the RIP address of the ISR.
    ///
    void set_offset(index_type index, offset_type off)
    {
        expects(x64::is_address_canonical(off));

        auto sd1 = m_idt.at((index * 2U) + 0U) & 0x0000FFFFFFFF0000ULL;
        auto sd2 = m_idt.at((index * 2U) + 1U) & 0xFFFFFFFF00000000ULL;

        auto offset_15_00 = ((off & 0x000000000000FFFFULL) << 0);
        auto offset_31_16 = ((off & 0x00000000FFFF0000ULL) << 32);
        auto offset_63_32 = ((off & 0xFFFFFFFF00000000ULL) >> 32);

        m_idt.at((index * 2U) + 0U) = sd1 | offset_31_16 | offset_15_00;
        m_idt.at((index * 2U) + 1U) = sd2 | offset_63_32;
    }

    /// Set Descriptor Offset
    ///
    /// @expects index < m_idt.size() + 1
    /// @expects offset is canonical
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @param offset the RIP address of the ISR.
    ///
    void set_offset(index_type index, pointer off)
    { set_offset(index, reinterpret_cast<offset_type>(off)); }

    /// Get Descriptor Offset
    ///
    /// @expects index < m_idt.size() + 1
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @return the offset
    ///
    offset_type offset(index_type index) const
    {
        auto sd1 = m_idt.at((index * 2U) + 0U);
        auto sd2 = m_idt.at((index * 2U) + 1U);

        auto base_15_00 = ((sd1 & 0x000000000000FFFFULL) >> 0);
        auto base_31_16 = ((sd1 & 0xFFFF000000000000ULL) >> 32);
        auto base_63_32 = ((sd2 & 0x00000000FFFFFFFFULL) << 32);

        return base_63_32 | base_31_16 | base_15_00;
    }

    /// Set Descriptor Segment Selector
    ///
    /// @expects index < m_idt.size()
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @param selector the descriptor
    ///
    void set_selector(index_type index, selector_type selector)
    {
        auto sd1 = m_idt.at(index * 2U) & 0xFFFFFFFF0000FFFFULL;
        m_idt.at(index * 2U) = sd1 | ((selector & 0x000000000000FFFFULL) << 16);
    }

    /// Get Descriptor Segment Selector
    ///
    /// @expects index < m_idt.size()
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @return the selector
    ///
    selector_type selector(index_type index) const
    {
        auto sd1 = m_idt.at(index * 2U);
        return ((sd1 & 0x00000000FFFF0000ULL) >> 16);
    }

    /// Set Present
    ///
    /// Sets the present bit. Since the IDT is only used by the hypervisor,
    /// this also sets DPL = 0 and type = interrupt gate when enabling the
    /// descriptor
    ///
    /// @expects index < m_idt.size()
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @param p true if present, false otherwise
    ///
    void set_present(index_type index, bool selector)
    {
        auto sd1 = m_idt.at(index * 2U) & 0xFFFF0000FFFFFFFFULL;
        m_idt.at(index * 2U) = selector ? sd1 | 0x00008E0100000000ULL : sd1;
    }

    /// Get Present
    ///
    /// @expects index < m_idt.size()
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @return the selector
    ///
    bool present(index_type index) const
    {
        return (m_idt.at(index * 2U) & 0x0000800000000000ULL) != 0;
    }

    /// Set All Fields
    ///
    /// @expects index < m_idt.size()
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @param offset the RIP address of the ISR.
    /// @param selector the descriptor
    ///
    void set(
        index_type index, offset_type off, selector_type selector)
    {
        this->set_offset(index, off);
        this->set_selector(index, selector);
        this->set_present(index, true);
    }

    /// Set All Fields
    ///
    /// @expects index < m_idt.size()
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @param offset the RIP address of the ISR.
    /// @param selector the descriptor
    ///
    void set(
        index_type index, pointer off, selector_type selector)
    {
        this->set_offset(index, off);
        this->set_selector(index, selector);
        this->set_present(index, true);
    }

private:

    idt_reg_x64_t m_idt_reg;
    std::vector<interrupt_descriptor_type> m_idt;

public:

    idt_x64(idt_x64 &&) noexcept = delete;
    idt_x64 &operator=(idt_x64 &&) noexcept = delete;

    idt_x64(const idt_x64 &) = delete;
    idt_x64 &operator=(const idt_x64 &) = delete;
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
