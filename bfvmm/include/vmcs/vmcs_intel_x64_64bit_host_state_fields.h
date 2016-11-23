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

#ifndef VMCS_INTEL_X64_64BIT_HOST_STATE_FIELDS_H
#define VMCS_INTEL_X64_64BIT_HOST_STATE_FIELDS_H

#include <vmcs/vmcs_intel_x64.h>

/// Intel x86_64 VMCS 64-bit Host-State Fields
///
/// The following provides the interface for the 64-bit host-state VMCS
/// fields as defined in Appendix B.2.4, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace host_ia32_pat
{
    constexpr const auto addr = 0x0000000000002C00UL;
    constexpr const auto name = "host_ia32_pat";

    inline auto exists() noexcept
    { return msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace pa0
    {
        constexpr const auto mask = 0x00000000000000FFUL;
        constexpr const auto from = 0;
        constexpr const auto name = "pa0";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000000007UL;
            constexpr const auto from = 0;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x00000000000000F8UL;
            constexpr const auto from = 3;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }
    }

    namespace pa1
    {
        constexpr const auto mask = 0x000000000000FF00UL;
        constexpr const auto from = 8;
        constexpr const auto name = "pa1";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000000700UL;
            constexpr const auto from = 8;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x000000000000F800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }
    }

    namespace pa2
    {
        constexpr const auto mask = 0x0000000000FF0000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "pa2";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000070000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x0000000000F80000UL;
            constexpr const auto from = 19;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }
    }

    namespace pa3
    {
        constexpr const auto mask = 0x00000000FF000000UL;
        constexpr const auto from = 24;
        constexpr const auto name = "pa3";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000007000000UL;
            constexpr const auto from = 24;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x00000000F8000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }
    }

    namespace pa4
    {
        constexpr const auto mask = 0x000000FF00000000UL;
        constexpr const auto from = 32;
        constexpr const auto name = "pa4";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000700000000UL;
            constexpr const auto from = 32;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x000000F800000000UL;
            constexpr const auto from = 35;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }
    }

    namespace pa5
    {
        constexpr const auto mask = 0x0000FF0000000000UL;
        constexpr const auto from = 40;
        constexpr const auto name = "pa5";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000070000000000UL;
            constexpr const auto from = 40;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x0000F80000000000UL;
            constexpr const auto from = 43;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }
    }

    namespace pa6
    {
        constexpr const auto mask = 0x00FF000000000000UL;
        constexpr const auto from = 48;
        constexpr const auto name = "pa6";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0007000000000000UL;
            constexpr const auto from = 48;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x00F8000000000000UL;
            constexpr const auto from = 51;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }
    }

    namespace pa7
    {
        constexpr const auto mask = 0xFF00000000000000UL;
        constexpr const auto from = 56;
        constexpr const auto name = "pa7";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x0700000000000000UL;
            constexpr const auto from = 56;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xF800000000000000UL;
            constexpr const auto from = 59;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set(T val)
            {
                auto&& field = get_vmcs_field(addr, name, exists());
                set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
            }

            template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
            void set_if_exists(T val, bool verbose = false) noexcept
            {
                auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
                set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
            }
        }
    }
}

namespace host_ia32_efer
{
    constexpr const auto addr = 0x0000000000002C02UL;
    constexpr const auto name = "host_ia32_efer";

    inline auto exists() noexcept
    { return msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace sce
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "sce";

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

    namespace lme
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "lme";

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

    namespace lma
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "lma";

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

    namespace nxe
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "nxe";

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

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFF2FEUL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }
}

namespace host_ia32_perf_global_ctrl
{
    constexpr const auto addr = 0x0000000000002C04UL;
    constexpr const auto name = "host_ia32_perf_global_ctrl";

    inline auto exists() noexcept
    { return msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFF8FFFFFFFCUL;
        constexpr const auto from = 0;

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }
}

}
}

// *INDENT-ON*

#endif
