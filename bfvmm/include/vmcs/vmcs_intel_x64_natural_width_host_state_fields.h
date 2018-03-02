//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_NATURAL_WIDTH_HOST_STATE_FIELDS_H
#define VMCS_INTEL_X64_NATURAL_WIDTH_HOST_STATE_FIELDS_H

#include <vmcs/vmcs_intel_x64.h>

/// Intel x86_64 VMCS Natural-Width Host-State Fields
///
/// The following provides the interface for the natural-width host-state VMCS
/// fields as defined in Appendix B.4.4, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace host_cr0
{
    constexpr const auto addr = 0x0000000000006C00UL;
    constexpr const auto name = "host_cr0";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace protection_enable
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "protection_enable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace monitor_coprocessor
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "monitor_coprocessor";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace emulation
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "emulation";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace task_switched
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "task_switched";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace extension_type
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "extension_type";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace numeric_error
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "numeric_error";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace write_protect
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "write_protect";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace alignment_mask
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_mask";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace not_write_through
    {
        constexpr const auto mask = 0x0000000020000000UL;
        constexpr const auto from = 29;
        constexpr const auto name = "not_write_through";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace cache_disable
    {
        constexpr const auto mask = 0x0000000040000000UL;
        constexpr const auto from = 30;
        constexpr const auto name = "cache_disable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace paging
    {
        constexpr const auto mask = 0x0000000080000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "paging";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    inline void dump() noexcept
    {
        bfdebug << "host cr0 enabled flags:" << bfendl;

        if (protection_enable::is_enabled())
            bfdebug << "    - " << protection_enable::name << bfendl;
        if (monitor_coprocessor::is_enabled())
            bfdebug << "    - " << monitor_coprocessor::name << bfendl;
        if (emulation::is_enabled())
            bfdebug << "    - " << emulation::name << bfendl;
        if (task_switched::is_enabled())
            bfdebug << "    - " << task_switched::name << bfendl;
        if (extension_type::is_enabled())
            bfdebug << "    - " << extension_type::name << bfendl;
        if (numeric_error::is_enabled())
            bfdebug << "    - " << numeric_error::name << bfendl;
        if (write_protect::is_enabled())
            bfdebug << "    - " << write_protect::name << bfendl;
        if (alignment_mask::is_enabled())
            bfdebug << "    - " << alignment_mask::name << bfendl;
        if (not_write_through::is_enabled())
            bfdebug << "    - " << not_write_through::name << bfendl;
        if (cache_disable::is_enabled())
            bfdebug << "    - " << cache_disable::name << bfendl;
        if (paging::is_enabled())
            bfdebug << "    - " << paging::name << bfendl;
    }
}

namespace host_cr3
{
    constexpr const auto addr = 0x0000000000006C02UL;
    constexpr const auto name = "host_cr3";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace host_cr4
{
    constexpr const auto addr = 0x0000000000006C04UL;
    constexpr const auto name = "host_cr4";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace v8086_mode_extensions
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "v8086_mode_extensions";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace protected_mode_virtual_interrupts
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "protected_mode_virtual_interrupts";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace time_stamp_disable
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "time_stamp_disable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace debugging_extensions
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "debugging_extensions";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace page_size_extensions
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "page_size_extensions";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace physical_address_extensions
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "physical_address_extensions";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace machine_check_enable
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "machine_check_enable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace page_global_enable
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "page_global_enable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace performance_monitor_counter_enable
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "performance_monitor_counter_enable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace osfxsr
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "osfxsr";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace osxmmexcpt
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "osxmmexcpt";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace vmx_enable_bit
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "vmx_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace smx_enable_bit
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "smx_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace fsgsbase_enable_bit
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "fsgsbase_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace pcid_enable_bit
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "pcid_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace osxsave
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "osxsave";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace smep_enable_bit
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "smep_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace smap_enable_bit
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "smap_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace protection_key_enable_bit
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "protection_key_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    inline void dump() noexcept
    {
        bfdebug << "host cr4 enabled flags:" << bfendl;

        if (v8086_mode_extensions::is_enabled())
            bfdebug << "    - " << v8086_mode_extensions::name << bfendl;
        if (protected_mode_virtual_interrupts::is_enabled())
            bfdebug << "    - " << protected_mode_virtual_interrupts::name << bfendl;
        if (time_stamp_disable::is_enabled())
            bfdebug << "    - " << time_stamp_disable::name << bfendl;
        if (debugging_extensions::is_enabled())
            bfdebug << "    - " << debugging_extensions::name << bfendl;
        if (page_size_extensions::is_enabled())
            bfdebug << "    - " << page_size_extensions::name << bfendl;
        if (physical_address_extensions::is_enabled())
            bfdebug << "    - " << physical_address_extensions::name << bfendl;
        if (machine_check_enable::is_enabled())
            bfdebug << "    - " << machine_check_enable::name << bfendl;
        if (page_global_enable::is_enabled())
            bfdebug << "    - " << page_global_enable::name << bfendl;
        if (performance_monitor_counter_enable::is_enabled())
            bfdebug << "    - " << performance_monitor_counter_enable::name << bfendl;
        if (osfxsr::is_enabled())
            bfdebug << "    - " << osfxsr::name << bfendl;
        if (osxmmexcpt::is_enabled())
            bfdebug << "    - " << osxmmexcpt::name << bfendl;
        if (vmx_enable_bit::is_enabled())
            bfdebug << "    - " << vmx_enable_bit::name << bfendl;
        if (smx_enable_bit::is_enabled())
            bfdebug << "    - " << smx_enable_bit::name << bfendl;
        if (smx_enable_bit::is_enabled())
            bfdebug << "    - " << smx_enable_bit::name << bfendl;
        if (fsgsbase_enable_bit::is_enabled())
            bfdebug << "    - " << fsgsbase_enable_bit::name << bfendl;
        if (pcid_enable_bit::is_enabled())
            bfdebug << "    - " << pcid_enable_bit::name << bfendl;
        if (osxsave::is_enabled())
            bfdebug << "    - " << osxsave::name << bfendl;
        if (smep_enable_bit::is_enabled())
            bfdebug << "    - " << smep_enable_bit::name << bfendl;
        if (smap_enable_bit::is_enabled())
            bfdebug << "    - " << smap_enable_bit::name << bfendl;
        if (protection_key_enable_bit::is_enabled())
            bfdebug << "    - " << protection_key_enable_bit::name << bfendl;
    }
}

namespace host_fs_base
{
    constexpr const auto addr = 0x0000000000006C06UL;
    constexpr const auto name = "host_fs_base";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace host_gs_base
{
    constexpr const auto addr = 0x0000000000006C08UL;
    constexpr const auto name = "host_gs_base";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace host_tr_base
{
    constexpr const auto addr = 0x0000000000006C0AUL;
    constexpr const auto name = "host_tr_base";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace host_gdtr_base
{
    constexpr const auto addr = 0x0000000000006C0CUL;
    constexpr const auto name = "host_gdtr_base";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace host_idtr_base
{
    constexpr const auto addr = 0x0000000000006C0EUL;
    constexpr const auto name = "host_idtr_base";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace host_ia32_sysenter_esp
{
    constexpr const auto addr = 0x0000000000006C10UL;
    constexpr const auto name = "host_ia32_sysenter_esp";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace host_ia32_sysenter_eip
{
    constexpr const auto addr = 0x0000000000006C12UL;
    constexpr const auto name = "host_ia32_sysenter_eip";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace host_rsp
{
    constexpr const auto addr = 0x0000000000006C14UL;
    constexpr const auto name = "host_rsp";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace host_rip
{
    constexpr const auto addr = 0x0000000000006C16UL;
    constexpr const auto name = "host_rip";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

}
}

// *INDENT-ON*

#endif
