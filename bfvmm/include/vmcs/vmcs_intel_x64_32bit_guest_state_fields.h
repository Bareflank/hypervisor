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

#ifndef VMCS_INTEL_X64_32BIT_GUEST_STATE_FIELDS_H
#define VMCS_INTEL_X64_32BIT_GUEST_STATE_FIELDS_H

#include <memory>
#include <type_traits>
#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_state.h>
#include <exit_handler/state_save_intel_x64.h>

#include <intrinsics/vmx_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace guest_es_limit
{
    constexpr const auto addr = 0x0000000000004800UL;
    constexpr const auto name = "guest_es_limit";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_cs_limit
{
    constexpr const auto addr = 0x0000000000004802UL;
    constexpr const auto name = "guest_cs_limit";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_ss_limit
{
    constexpr const auto addr = 0x0000000000004804UL;
    constexpr const auto name = "guest_ss_limit";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_ds_limit
{
    constexpr const auto addr = 0x0000000000004806UL;
    constexpr const auto name = "guest_ds_limit";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_fs_limit
{
    constexpr const auto addr = 0x0000000000004808UL;
    constexpr const auto name = "guest_fs_limit";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_gs_limit
{
    constexpr const auto addr = 0x000000000000480AUL;
    constexpr const auto name = "guest_gs_limit";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}


namespace guest_ldtr_limit
{
    constexpr const auto addr = 0x000000000000480CUL;
    constexpr const auto name = "guest_ldtr_limit";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_tr_limit
{
    constexpr const auto addr = 0x000000000000480EUL;
    constexpr const auto name = "guest_tr_limit";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_gdtr_limit
{
    constexpr const auto addr = 0x0000000000004810UL;
    constexpr const auto name = "guest_gdtr_limit";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_idtr_limit
{
    constexpr const auto addr = 0x0000000000004812UL;
    constexpr const auto name = "guest_idtr_limit";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_es_access_rights
{
    constexpr const auto addr = 0x0000000000004814UL;
    constexpr const auto name = "guest_es_access_rights";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }
}

namespace guest_cs_access_rights
{
    constexpr const auto addr = 0x0000000000004816UL;
    constexpr const auto name = "guest_cs_access_rights";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }
}

namespace guest_ss_access_rights
{
    constexpr const auto addr = 0x0000000000004818UL;
    constexpr const auto name = "guest_ss_access_rights";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }
}

namespace guest_ds_access_rights
{
    constexpr const auto addr = 0x000000000000481AUL;
    constexpr const auto name = "guest_ds_access_rights";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }
}

namespace guest_fs_access_rights
{
    constexpr const auto addr = 0x000000000000481CUL;
    constexpr const auto name = "guest_fs_access_rights";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }
}

namespace guest_gs_access_rights
{
    constexpr const auto addr = 0x000000000000481EUL;
    constexpr const auto name = "guest_gs_access_rights";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }
}

namespace guest_ldtr_access_rights
{
    constexpr const auto addr = 0x0000000000004820UL;
    constexpr const auto name = "guest_ldtr_access_rights";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }
}

namespace guest_tr_access_rights
{
    constexpr const auto addr = 0x0000000000004822UL;
    constexpr const auto name = "guest_tr_access_rights";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace type
    {
        constexpr const auto mask = 0x000000000000000FUL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace s
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "s";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace dpl
    {
        constexpr const auto mask = 0x0000000000000060UL;
        constexpr const auto from = 5;
        constexpr const auto name = "dpl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "present";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace avl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "avl";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace l
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "l";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace db
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "db";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace granularity
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "granularity";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF0F00UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace unusable
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "unusable";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }
}

namespace guest_interruptibility_state
{
    constexpr const auto addr = 0x0000000000004824UL;
    constexpr const auto name = "guest_interruptibility_state";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace blocking_by_sti
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "blocking_by_sti";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace blocking_by_mov_ss
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "blocking_by_mov_ss";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace blocking_by_smi
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "blocking_by_smi";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace blocking_by_nmi
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "blocking_by_nmi";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace enclave_interruption
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "enclave_interruption";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0x00000000FFFFFFE0UL;
        constexpr const auto from = 5;
        constexpr const auto name = "reserved";

        inline auto get()
        { return (get_vmcs_field(addr, name, exists()) & mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return (get_vmcs_field_if_exists(addr, name, verbose, exists()) & mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto field = get_vmcs_field(addr, name, exists());
            set_vmcs_field((field & ~mask) | ((val << from) & mask), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists((field & ~mask) | ((val << from) & mask), addr, name, verbose, exists());
        }
    }
}

namespace guest_activity_state
{
    constexpr const auto addr = 0x0000000000004826UL;
    constexpr const auto name = "guest_activity_state";

    constexpr const auto active = 0U;
    constexpr const auto hlt = 1U;
    constexpr const auto shutdown = 2U;
    constexpr const auto wait_for_sipi = 3U;

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_smbase
{
    constexpr const auto addr = 0x0000000000004828UL;
    constexpr const auto name = "guest_smbase";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace guest_ia32_sysenter_cs
{
    constexpr const auto addr = 0x000000000000482AUL;
    constexpr const auto name = "guest_ia32_sysenter_cs";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vmx_preemption_timer_value
{
    constexpr const auto addr = 0x000000000000482EUL;
    constexpr const auto name = "vmx_preemption_timer_value";

    inline auto exists()
    { return msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

}
}

// *INDENT-ON*

#endif
